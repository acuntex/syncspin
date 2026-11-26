//! The group one server serves: its members, its state and the stream fan-out.
//!
//! One [`Server`](crate::Server) owns one group. A client joins it when `server/activate` grants it
//! roles and leaves when its connection ends; the group holds the volume, the mute state, the
//! playback state and the stream, and every change goes out to the members whose roles make it
//! relevant: `server/state` to the controller and metadata roles, `stream/*` and audio to the
//! player role, `group/update` to everyone.
//!
//! Everything here is synchronous and guarded by one mutex, which is never held across an await:
//! the connection tasks read their messages from an unbounded channel, so a client that stopped
//! reading cannot block the host that pushes audio. The channel can still grow with control
//! messages, but the audio outstanding to one member is bounded by the `buffer_capacity` its
//! `client/hello` announced: a chunk that would overrun it is not started, and the member hears a
//! hole instead.
//!
//! Two rules the specification states govern when a member hears anything. A stream is announced
//! only to a member whose `client/state` reports both the `player` object the activation requires
//! and `available: true`; a member that reports itself unavailable keeps its group but receives no
//! audio until it reports again. And `stream/start` carrying the `player` object requires the
//! `playback` activity on the connection, so the group declares it on every member while the group
//! plays and drops it when playback stops.
//!
//! The send-ahead rules of the specification are kept: a restart with a ready member starts from
//! the reported lead, anchored on the transmit time of the trigger; with none, no anchor is armed
//! and the provisional timeline stands. What this milestone does not keep is the live queue
//! duration, the optional `required_lead_time_ms` hint and the 15 ms lower bound of a chunk, which
//! belongs to the host's chunking (see `docs/spec-deviations.md` #17).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use syncspin_core::messages::{
    AudioChunkHeader, ClientState, ControllerCommand, ControllerState, GroupUpdate, Incoming,
    Metadata, Progress, ServerActivate, ServerState, StreamClear, StreamEnd, StreamStart,
};
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use crate::stream::{AudioFormat, Codec, TrackInfo, WriteError, WriteOutcome};
use crate::Event;

/// The role a client outputs audio with.
pub(crate) const PLAYER_ROLE: &str = "player@v1";

/// The role a client controls the group with.
pub(crate) const CONTROLLER_ROLE: &str = "controller@v1";

/// The role a client displays text metadata with.
pub(crate) const METADATA_ROLE: &str = "metadata@v1";

/// Role name the stream messages carry in their `roles` array.
const PLAYER_STREAM: &str = "player";

/// The `server/activate` activity that says the group of this connection is playing.
///
/// The specification forbids a `stream/start` that carries the `player` object on a connection
/// without it, whatever roles are active, so the group declares it on every member while it plays
/// and drops it once playback stops.
const PLAYBACK_ACTIVITY: &str = "playback";

/// How long a restart waits for the ready members' trigger reports before it starts anyway.
///
/// The anchor holds the host's audio until every ready member has been told that the stream
/// starts, or until this much server time has passed. The same second bounds the held queue, so a
/// member that never reports costs at most one second of host audio; after that it is gated and
/// misses the opening.
const ANCHOR_DEADLINE: Duration = Duration::from_secs(1);

/// The most outstanding audio the server counts toward one member, whatever its `client/hello`
/// announced. A client that reports a huge `buffer_capacity` would otherwise get an effectively
/// unbounded queue and a sent list that grows with it. One MiB is eight times the 128 KiB this
/// project's own client announces.
const MAX_BUFFER_CAPACITY: u64 = 1 << 20;

/// The longest chunk the server may send, as the player role states it.
///
/// `roles/player/v1.md` forbids a chunk longer than 150 ms, because a player would have to buffer
/// more than it promised. The server refuses a longer chunk before the timeline moves, so a
/// rejected chunk leaves no hole.
const MAX_CHUNK_DURATION: Duration = Duration::from_millis(150);

/// The controller commands the group acts on itself.
///
/// `next`, `previous`, `seek` and the repeat and shuffle commands need the queue, which belongs to
/// the host, so the server does not advertise them and ignores them if a client sends one anyway.
const GROUP_COMMANDS: [&str; 5] = ["play", "pause", "stop", "volume", "mute"];

/// One message the group hands to a member's connection.
#[derive(Debug)]
pub(crate) enum Outbound {
    /// A control message, to be sent as JSON under the transport keys.
    ///
    /// Boxed because an `Incoming` is an order of magnitude larger than an audio chunk and the
    /// queue carries both.
    Message(Box<Incoming>),
    /// A control message whose send the group must learn about.
    ///
    /// A `stream/start`, `stream/clear` or `stream/end` belongs to an epoch; the connection reports
    /// its send so the group can anchor a restart on the real transmit time and reset the member's
    /// sent chunks. A report for another epoch is ignored.
    Trigger {
        /// The message to send.
        message: Box<Incoming>,
        /// The epoch the message belongs to.
        epoch: u64,
        /// Whether this trigger restarts the timeline and the group waits for its report.
        anchor: bool,
        /// Whether the report clears this member's sent-chunk list.
        reset: bool,
    },
    /// One audio chunk, already framed with its message id and header.
    Audio {
        /// The framed chunk.
        chunk: Vec<u8>,
        /// Set by the connection task once the socket write finished.
        transmitted: Arc<AtomicBool>,
    },
}

/// One chunk this member was sent, kept until its transmission and its playtime have passed.
///
/// The per-member capacity accounting reads these fields on every send: a chunk counts while its
/// transmission is unfinished or its completion is in the future, and it is kept until its raw
/// playtime has passed, because a changed output delay can make it count again.
#[derive(Debug)]
struct SentChunk {
    /// Server clock time of the chunk's first sample, in microseconds.
    timestamp_us: i64,
    /// Playtime of the chunk.
    duration: Duration,
    /// Framed length of the chunk on the wire, the 13-byte header included.
    bytes: usize,
    /// Set by the connection task once the socket write finished.
    transmitted: Arc<AtomicBool>,
}

/// One active connection that belongs to the group.
#[derive(Debug)]
struct Member {
    /// Distinguishes members, including two connections of one client.
    id: u64,
    /// Versioned roles the connection may use.
    roles: Vec<String>,
    /// The connection task's queue.
    sender: mpsc::UnboundedSender<Outbound>,
    /// Whether the latest `client/state` of this member reports it available for playback.
    ///
    /// A member starts unavailable: nothing may be announced to it before it has spoken.
    available: bool,
    /// Whether the member reported the `player` object its activation requires.
    ///
    /// The specification forbids starting the stream of a role with a `client/state` object before
    /// that object has arrived, because the stream configuration is derived from it.
    player_reported: bool,
    /// Whether a player stream is currently announced to this member.
    ///
    /// It is set by `stream/start` and cleared by `stream/end`, so the group never sends audio,
    /// a clear or an end for a stream the member does not have.
    stream_announced: bool,
    /// Whether this member's activation carries the `playback` activity in force.
    playback_declared: bool,
    /// The minimum startup lead the member reported, in milliseconds.
    min_buffer_ms: u32,
    /// The output delay the member reported, in milliseconds.
    output_delay_ms: u32,
    /// The largest outstanding audio size the member announced in `client/hello`, in bytes.
    capacity: u64,
    /// Server clock time before which this member must not receive audio, in microseconds.
    ///
    /// Zero means no floor. It is set by a start whose report gives the member its own lead on the
    /// timeline, and cleared at the first delivered chunk.
    start_at: i64,
    /// Whether a `stream/start` went out and its send report has not arrived yet.
    start_gate: bool,
    /// The chunks sent to this member that may still count against its capacity.
    sent: Vec<SentChunk>,
}

impl Member {
    /// Whether the connection may use `role`.
    fn has(&self, role: &str) -> bool {
        self.roles.iter().any(|held| held == role)
    }

    /// Whether a player stream may be started for this member.
    fn plays(&self) -> bool {
        self.has(PLAYER_ROLE) && self.available && self.player_reported
    }

    /// Whether this member's player stream is open and may carry audio.
    fn streams(&self) -> bool {
        self.plays() && self.stream_announced
    }

    /// The member's own start-from-empty lead in microseconds.
    fn member_lead_us(&self) -> i64 {
        let millis = u64::from(self.min_buffer_ms).saturating_add(u64::from(self.output_delay_ms));
        i64::try_from(millis.saturating_mul(1_000)).unwrap_or(i64::MAX)
    }

    /// The framed bytes this member's sent chunks still occupy at `now_us`.
    ///
    /// A chunk counts until its transmission report arrives and its completion - the raw end less
    /// the member's current output delay - has passed. The delay is re-read here, so a report
    /// that changes it re-computes the count from the list.
    fn counted_bytes(&self, now_us: i64) -> u64 {
        let delay_us = i64::from(self.output_delay_ms).saturating_mul(1_000);
        self.sent.iter().fold(0u64, |total, sent| {
            let completion = sent
                .timestamp_us
                .saturating_add(micros_i64(sent.duration))
                .saturating_sub(delay_us);
            if sent.transmitted.load(Ordering::Relaxed) && completion <= now_us {
                total
            } else {
                total.saturating_add(u64::try_from(sent.bytes).unwrap_or(u64::MAX))
            }
        })
    }

    /// Drops the sent chunks whose transmission is confirmed and whose raw playtime has passed.
    ///
    /// The raw end ignores the output delay on purpose: a chunk whose completion moved into the
    /// past only because the delay rose must stay while its raw end is still future, so a later
    /// delay decrease can count it again.
    fn prune_sent(&mut self, now_us: i64) {
        self.sent.retain(|sent| {
            let raw_end = sent.timestamp_us.saturating_add(micros_i64(sent.duration));
            raw_end > now_us || !sent.transmitted.load(Ordering::Relaxed)
        });
    }
}

/// The ready members a restart waits for, with the transmit times they reported.
#[derive(Debug)]
struct Anchor {
    /// Members whose trigger report the group still waits for.
    pending: Vec<u64>,
    /// The reports that arrived, by member id.
    reported: Vec<(u64, i64)>,
    /// Server clock time at which the anchor flushes even without every report.
    deadline_us: i64,
}

impl Anchor {
    /// The latest transmit time reported so far.
    fn max_reported(&self) -> Option<i64> {
        self.reported.iter().map(|(_, t)| *t).max()
    }

    /// Drops a member from the pending set, keeping a report it already sent.
    fn drop_pending(&mut self, member: u64) {
        self.pending.retain(|held| *held != member);
    }

    /// Drops every trace of a member that left.
    fn drop_member(&mut self, member: u64) {
        self.drop_pending(member);
        self.reported.retain(|(held, _)| *held != member);
    }
}

/// The stream the group is serving.
#[derive(Debug)]
struct Stream {
    /// What the stream carries; the metadata role reports it.
    track: TrackInfo,
    /// Whether the timeline is running. It stops when the group pauses and between `stream/end`
    /// and the next `stream/start`.
    active: bool,
    /// Server clock time of the next sample to send, in microseconds.
    next_us: i64,
    /// Position in the track of the next sample to send.
    position: Duration,
    /// Server clock time of the first sample of the current segment, in microseconds.
    start_us: i64,
    /// Source position of the first sample of the current segment.
    start_position: Duration,
    /// The latest trigger transmit time that anchored the segment, in server microseconds.
    anchor_us: i64,
    /// Whether a chunk has been assigned a timestamp since the last restart.
    wrote_any: bool,
    /// The sub-microsecond remainder of the PCM playtime written so far, in units of
    /// `1 / sample_rate` microseconds, so chunk durations add up without a rounding drift.
    pcm_carry: u64,
    /// The ready members whose trigger reports the anchor still waits for.
    anchor: Option<Anchor>,
    /// Host payloads held until the anchor completes.
    held: VecDeque<(Vec<u8>, Duration)>,
}

impl Stream {
    /// Returns the position a listener hears at `now_us`.
    ///
    /// The chunks between `now_us` and [`Self::next_us`] are already sent and not yet played, so
    /// the audible position is the timeline position minus that lead. A writer that fell behind
    /// reports the timestamp of the last chunk it sent rather than extrapolating past it.
    fn position_at(&self, now_us: i64) -> Duration {
        let lead = u64::try_from(self.next_us.saturating_sub(now_us)).unwrap_or_default();
        self.position.saturating_sub(Duration::from_micros(lead))
    }

    /// Returns the position to freeze when playback stops at `now_us`.
    ///
    /// Before the first sample of a segment is due, the client's buffer is empty and the next
    /// sample is the segment start, so a pause freezes there instead of at the not-yet-started
    /// timeline.
    fn audible_position(&self, now_us: i64) -> Duration {
        if now_us < self.start_us {
            self.start_position
        } else {
            self.position_at(now_us)
        }
    }
}

/// The state every member shares.
#[derive(Debug)]
struct Inner {
    /// The format every stream of this group announces.
    format: AudioFormat,
    group_name: String,
    group_id: String,
    volume: u8,
    muted: bool,
    playing: bool,
    members: Vec<Member>,
    stream: Option<Stream>,
    next_member_id: u64,
    /// Increments on every superseding restart or stop.
    epoch: u64,
    /// The host's event stream, for what only a flush under the lock can tell it.
    events: mpsc::UnboundedSender<Event>,
}

/// The group of one server.
#[derive(Debug)]
pub(crate) struct Group {
    clock: Clock,
    events: mpsc::UnboundedSender<Event>,
    /// The runtime the group was built in, when it was built in one.
    ///
    /// The anchor deadline timer is spawned on it; a group built outside a runtime has no timer,
    /// and the tests drive the deadline through the inner check instead.
    runtime: Option<Handle>,
    /// A weak handle to the group, so the timer does not keep it alive while it sleeps.
    me: Weak<Group>,
    inner: Mutex<Inner>,
}

impl Group {
    /// Builds the group of a server that serves `format` under `name`.
    pub(crate) fn new(
        name: String,
        format: AudioFormat,
        events: mpsc::UnboundedSender<Event>,
    ) -> anyhow::Result<Arc<Group>> {
        let group_id = group_id()?;
        let runtime = Handle::try_current().ok();
        Ok(Arc::new_cyclic(|me| Group {
            clock: Clock::new(),
            events: events.clone(),
            runtime,
            me: me.clone(),
            inner: Mutex::new(Inner {
                format,
                group_name: name,
                group_id,
                volume: 100,
                muted: false,
                playing: false,
                members: Vec::new(),
                stream: None,
                next_member_id: 0,
                epoch: 0,
                events,
            }),
        }))
    }

    /// Returns the group state, recovering from a panic in another thread.
    ///
    /// A host that panics while holding the lock must not take the server with it: the state it
    /// left behind is still the state every connection reads.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Adds a connection to the group and sends it everything it needs to start.
    ///
    /// The snapshot - `server/state`, `group/update` and, while the group plays, the `playback`
    /// activity - goes into the member's queue before it becomes visible to broadcasts, and the
    /// lock keeps a change from slipping between the snapshot and the join. The stream itself
    /// waits for the `client/state` that declares the member ready; [`Group::report_client_state`]
    /// announces it then. `buffer_capacity` is the hello's largest outstanding audio size, which the
    /// server holds to at most [`MAX_BUFFER_CAPACITY`]: the client's number is not a license for an
    /// unbounded queue.
    pub(crate) fn join(
        &self,
        roles: Vec<String>,
        sender: mpsc::UnboundedSender<Outbound>,
        buffer_capacity: u64,
    ) -> u64 {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        // A join during an anchor must read the timeline the anchor leaves behind, not a
        // provisional one the check is about to move.
        inner.check_anchor_at(now);
        let id = inner.next_member_id;
        inner.next_member_id = inner.next_member_id.wrapping_add(1);

        let mut state = ServerState::default();
        if roles.iter().any(|role| role == CONTROLLER_ROLE) {
            state.controller = Some(inner.controller());
        }
        if roles.iter().any(|role| role == METADATA_ROLE) {
            // The first state of a metadata role must be dated in the past or present. The check
            // above has already moved the timeline an armed anchor would leave behind, so build
            // it against that state; while the segment has not started, the scheduled update
            // follows as a second state and corrects the joiner rather than letting it
            // extrapolate across the lead.
            state.metadata = Some(inner.metadata_at(now));
        }
        if state.controller.is_some() || state.metadata.is_some() {
            send_to(&sender, Incoming::ServerState(state));
        }
        if roles.iter().any(|role| role == METADATA_ROLE) {
            if let Some(scheduled) = inner.scheduled_metadata(now) {
                send_to(
                    &sender,
                    Incoming::ServerState(ServerState {
                        controller: None,
                        metadata: Some(scheduled),
                        ..Default::default()
                    }),
                );
            }
        }
        send_to(&sender, Incoming::GroupUpdate(inner.group_update()));

        inner.members.push(Member {
            id,
            roles,
            sender,
            available: false,
            player_reported: false,
            stream_announced: false,
            playback_declared: false,
            min_buffer_ms: 0,
            output_delay_ms: 0,
            capacity: buffer_capacity.min(MAX_BUFFER_CAPACITY),
            start_at: 0,
            start_gate: false,
            sent: Vec::new(),
        });
        let index = inner.members.len() - 1;
        inner.declare_playback(index);
        id
    }

    /// Records the `client/state` one member reported.
    ///
    /// A report is not a command: volume, mute and playback belong to the server, so a member's
    /// numbers describe its own output and never change the group. What the group takes from the
    /// report is the two facts the specification requires before a stream may be announced -
    /// whether the member is available and whether its `player` object has arrived - and the
    /// timing the group lead is derived from. A member that becomes ready while a stream runs
    /// receives that stream from here.
    pub(crate) fn report_client_state(&self, member: u64, state: &ClientState) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let Some(index) = inner.members.iter().position(|held| held.id == member) else {
            return;
        };
        let was_available = inner.members[index].available;
        let old_lead = inner.group_lead_us();
        {
            let held = &mut inner.members[index];
            held.available = state.available;
            if let Some(player) = &state.player {
                held.player_reported = true;
                held.min_buffer_ms = player.min_buffer_ms;
                held.output_delay_ms = player.output_delay_ms;
            }
        }
        // A member that stops being available must not stall an armed anchor; a report it already
        // sent still names a trigger that was transmitted, so it keeps anchoring.
        if !state.available {
            if let Some(anchor) = inner
                .stream
                .as_mut()
                .and_then(|stream| stream.anchor.as_mut())
            {
                anchor.drop_pending(member);
            }
        }
        let new_lead = inner.group_lead_us();
        if new_lead > old_lead {
            inner.raise_lead(now, new_lead);
        }
        if state.available && !was_available {
            inner.report_returning(index, now);
        }
        inner.start_member_stream(index, now);
        inner.check_anchor_at(now);
    }

    /// Removes a connection from the group.
    ///
    /// Its role reports are gone with it; the group state itself is the server's and survives. A
    /// member that was still anchoring a restart is dropped from it, and an anchor that loses its
    /// last member flushes without it.
    pub(crate) fn leave(&self, member: u64) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        inner.members.retain(|held| held.id != member);
        if let Some(anchor) = inner
            .stream
            .as_mut()
            .and_then(|stream| stream.anchor.as_mut())
        {
            anchor.drop_member(member);
        }
        inner.check_anchor_at(now);
    }

    /// Returns the group's clock reading in microseconds.
    ///
    /// It is the one timestamp every message of this server carries: stream playout, metadata and
    /// the `server/time` replies a client measures its offset with.
    pub(crate) fn now_us(&self) -> i64 {
        self.clock.now_us()
    }

    /// Converts an instant of this machine's monotonic clock into the group's microseconds.
    ///
    /// A `server/time` reply is stamped when the request arrived, not when the task got around to
    /// answering it, so the connection hands over the instant its WebSocket delivered the frame.
    pub(crate) fn server_us(&self, at: Instant) -> i64 {
        self.clock.at(at)
    }

    /// Sets the volume of the group, clamped to the range the protocol allows.
    ///
    /// Returns the level that is now in force; a level above 100 is reported as 100 rather than
    /// rejected. Volume and mute are independent, so this never changes the mute state.
    pub(crate) fn set_volume(&self, level: u8) -> u8 {
        let applied = level.min(100);
        let mut inner = self.lock();
        inner.volume = applied;
        inner.send_controller();
        applied
    }

    /// Sets the mute state of the group and returns it.
    pub(crate) fn set_muted(&self, muted: bool) -> bool {
        let mut inner = self.lock();
        inner.muted = muted;
        inner.send_controller();
        muted
    }

    /// Starts or resumes group playback.
    ///
    /// A stream that is still open but no longer running is announced again, because a paused group
    /// ends the player stream and a resumed one needs a new `stream/start` before its audio. The
    /// restart anchors its first sample on the transmit times of those starts.
    pub(crate) fn play(&self) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let restart = inner.stream.as_ref().is_some_and(|stream| !stream.active);
        inner.playing = true;
        if restart {
            inner.supersede();
            if let Some(stream) = inner.stream.as_mut() {
                stream.active = true;
                stream.start_position = stream.position;
            }
            inner.restart_clock(now);
            let pending = inner.start_pending();
            if let Some(deadline) = inner.arm_anchor(now, pending) {
                let epoch = inner.epoch;
                self.spawn_anchor_timer(epoch, deadline);
            }
            inner.start_streams(now, &[]);
            let _ = self.events.send(Event::StreamStarted);
        } else {
            // No stream to announce, but the members still have to learn that the group plays.
            inner.declare_playback_for_all();
        }
        inner.send_metadata(now);
        inner.send_group_update();
    }

    /// Pauses group playback at the current position.
    ///
    /// The player stream ends, as the specification requires of a pausing group. The bytes a host
    /// writes while the group is paused are dropped; it resumes from the position the group
    /// reports, which is the one the pause froze.
    pub(crate) fn pause(&self) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        // The stream ends before the activity does: the specification requires `stream/end` for an
        // active player stream before `server/activate` drops `playback`.
        let running = inner.end_player_stream(now);
        inner.playing = false;
        inner.declare_playback_for_all();
        if running {
            let _ = self.events.send(Event::StreamEnded);
        }
        inner.send_metadata(now);
        inner.send_group_update();
    }

    /// Stops group playback and rewinds the position to the beginning.
    pub(crate) fn stop(&self) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let running = inner.end_player_stream(now);
        inner.playing = false;
        inner.declare_playback_for_all();
        if let Some(stream) = inner.stream.as_mut() {
            stream.position = Duration::ZERO;
            stream.next_us = now;
        }
        if running {
            let _ = self.events.send(Event::StreamEnded);
        }
        inner.send_metadata(now);
        inner.send_group_update();
    }

    /// Applies one controller command the group owns.
    ///
    /// Returns whether the command was one of [`GROUP_COMMANDS`] with the parameter it needs; a
    /// command for the host's queue, such as `next` or `seek`, is left to the host and stays
    /// unanswered, which is why it is not advertised.
    pub(crate) fn apply_controller_command(&self, command: &ControllerCommand) -> bool {
        match command.command.as_str() {
            "play" => {
                self.play();
                true
            }
            "pause" => {
                self.pause();
                true
            }
            "stop" => {
                self.stop();
                true
            }
            "volume" => match command.volume {
                Some(level) => {
                    self.set_volume(level);
                    true
                }
                None => false,
            },
            "mute" => match command.mute {
                Some(muted) => {
                    self.set_muted(muted);
                    true
                }
                None => false,
            },
            _ => false,
        }
    }

    /// Announces a new stream to every player and reports the track to the metadata role.
    ///
    /// A stream that is already running is cleared first: `stream/start` on an active stream updates
    /// it in place and must continue its timeline, which is not what a new track wants. Clearing
    /// first is the specification's treatment of a track jump; the clear is the restart trigger,
    /// and the start that follows it is the in-place configuration update.
    ///
    /// Opening a stream means audio is playing, so the group reports `playing` from here on; the
    /// host does not have to call [`Group::play`] as well.
    pub(crate) fn open_stream(&self, track: TrackInfo) {
        let track = track.limited();
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let advanced = inner.stream.as_ref().is_some_and(|stream| stream.active);
        // A track jump's clear restarts the timeline for the players that have the old stream;
        // the start that follows is sent only to those, and only as long as they still play.
        let in_place = if advanced {
            inner
                .members
                .iter()
                .filter(|member| member.stream_announced && member.plays())
                .map(|member| member.id)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let was_playing = inner.playing;
        inner.playing = true;
        inner.supersede();
        if advanced {
            inner.send_stream_clear(now);
            // The players keep their stream open across the clear, but the new track announces its
            // format again, so every ready player is told once more.
            inner.forget_stream_starts();
        }
        inner.stream = Some(Stream {
            track,
            active: true,
            next_us: 0,
            position: Duration::ZERO,
            start_us: 0,
            start_position: Duration::ZERO,
            anchor_us: now,
            wrote_any: false,
            pcm_carry: 0,
            anchor: None,
            held: VecDeque::new(),
        });
        inner.restart_clock(now);
        let pending = if advanced {
            in_place.clone()
        } else {
            inner.start_pending()
        };
        if let Some(deadline) = inner.arm_anchor(now, pending) {
            let epoch = inner.epoch;
            self.spawn_anchor_timer(epoch, deadline);
        }
        if !was_playing {
            inner.send_group_update();
        }
        inner.start_streams(now, &in_place);
        inner.send_metadata(now);
        let _ = self.events.send(Event::StreamStarted);
    }

    /// Sends one chunk to every player that can take it and advances the timeline.
    ///
    /// The chunk is checked before the timeline moves, so a refused chunk leaves no hole for the
    /// next one. `duration` is the host's playtime for a compressed format, and must be absent for
    /// PCM, whose playtime follows from its frame count. Bytes written to a paused or ended stream
    /// are dropped, because there is no timeline to place them on.
    ///
    /// A member gated by its start, or without room for the framed chunk inside the
    /// `buffer_capacity` it announced, is skipped: the chunk keeps its place on the shared timeline,
    /// so that member hears a hole instead of a delayed chunk.
    ///
    /// While a restart anchors the timeline, the payload is held instead of scheduled; the anchor
    /// flush assigns its timestamp from the trigger's real transmit time. A host that starves the
    /// timeline is re-seeded a lead ahead rather than fed past timestamps.
    pub(crate) fn write_audio(&self, bytes: &[u8], duration: Option<Duration>) -> WriteOutcome {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        // A late flush must not wait for this chunk, whatever becomes of it.
        inner.check_anchor_at(now);
        if bytes.is_empty() || duration == Some(Duration::ZERO) {
            return WriteOutcome::Dropped(WriteError::Empty);
        }
        let format = inner.format.clone();
        let mut next_carry = None;
        let duration = match (&format.codec, duration) {
            (Codec::Pcm, None) => {
                if bytes.len() % format.frame_bytes() != 0 {
                    return WriteOutcome::Dropped(WriteError::Incomplete);
                }
                // The remainder is only kept once the chunk is accepted, so a refused chunk that
                // the host writes again does not move the timeline by its fraction each time.
                let mut carry = inner.stream.as_ref().map_or(0, |stream| stream.pcm_carry);
                let duration = format.duration_carrying(bytes.len(), &mut carry);
                next_carry = Some(carry);
                duration
            }
            (Codec::Pcm, Some(_)) => return WriteOutcome::Dropped(WriteError::WrongMethod),
            (_, None) => return WriteOutcome::Dropped(WriteError::WrongMethod),
            (_, Some(duration)) => duration,
        };
        if duration.is_zero() {
            return WriteOutcome::Dropped(WriteError::Empty);
        }
        if duration > MAX_CHUNK_DURATION {
            return WriteOutcome::Dropped(WriteError::TooLong);
        }
        let lead = inner.group_lead_us();
        // Only a player that can take this chunk at all sets the bound: one whose capacity is
        // below a single framed chunk is skipped for every chunk and gains nothing from it.
        let framed_len =
            u64::try_from(bytes.len().saturating_add(AudioChunkHeader::LEN)).unwrap_or(u64::MAX);
        let room = inner
            .members
            .iter()
            .filter(|member| member.plays() && member.capacity >= framed_len)
            .map(|member| member.capacity)
            .min();
        let reseeded = {
            let Some(stream) = inner.stream.as_mut() else {
                return WriteOutcome::Dropped(WriteError::Ended);
            };
            if !stream.active {
                return WriteOutcome::Dropped(WriteError::Paused);
            }
            if stream.anchor.is_some() {
                let queued = stream.held.iter().fold(0i64, |total, (_, held)| {
                    total.saturating_add(micros_i64(*held))
                });
                if queued.saturating_add(micros_i64(duration)) > micros_i64(ANCHOR_DEADLINE) {
                    return WriteOutcome::Dropped(WriteError::Backpressure);
                }
                // The flush is subject to each player's `buffer_capacity`: a chunk it could not
                // take would be assigned a timestamp and skipped, and the host would only have
                // seen `Held`. The queue is therefore also bounded by the framed bytes the
                // smallest ready player that can take a chunk. The first chunk is always accepted.
                // A player that joins during the anchor with less room, or is gated at its
                // deadline, can still miss held chunks at the flush; `Event::HeldAudioSkipped`
                // reports that.
                let framed = |len: usize| {
                    u64::try_from(len.saturating_add(AudioChunkHeader::LEN)).unwrap_or(u64::MAX)
                };
                let held_bytes = stream.held.iter().fold(0u64, |total, (held, _)| {
                    total.saturating_add(framed(held.len()))
                });
                if let Some(room) = room {
                    if !stream.held.is_empty()
                        && held_bytes.saturating_add(framed(bytes.len())) > room
                    {
                        return WriteOutcome::Dropped(WriteError::Backpressure);
                    }
                }
                if let Some(carry) = next_carry {
                    stream.pcm_carry = carry;
                }
                stream.held.push_back((bytes.to_vec(), duration));
                return WriteOutcome::Held;
            }
            if let Some(carry) = next_carry {
                stream.pcm_carry = carry;
            }
            if stream.next_us < now {
                let old_next = stream.next_us;
                // A zero lead still keeps the first timestamp in the future rather than
                // accumulating lateness.
                let next = now.saturating_add(lead).max(now.saturating_add(1));
                let jump = next.saturating_sub(old_next);
                stream.next_us = next;
                stream.start_us = next;
                stream.anchor_us = now;
                stream.start_position = stream.position;
                Some(jump > micros_i64(duration))
            } else {
                None
            }
        };
        if reseeded == Some(true) {
            // The jump is more than one chunk; the metadata has to describe the new segment
            // before the audio it describes.
            inner.send_metadata(now);
        }
        inner.assign_and_send(bytes, duration, now)
    }

    /// Moves the stream to `position` and drops what the players have buffered.
    ///
    /// A seek is a `stream/clear` without `from_timestamp`, and the specification prices the
    /// restart as a disturbance: the first chunk after it is scheduled a full lead ahead. A seek
    /// while the group is paused sends no clear and arms no anchor; the next `play` restarts from
    /// the new position.
    pub(crate) fn seek(&self, position: Duration) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let Some(stream) = inner.stream.as_ref() else {
            return;
        };
        let active = stream.active;
        let position = stream
            .track
            .duration
            .map_or(position, |duration| position.min(duration));
        inner.supersede();
        if let Some(stream) = inner.stream.as_mut() {
            stream.position = position;
            stream.start_position = position;
        }
        inner.restart_clock(now);
        if active {
            let pending = inner.clear_pending();
            if let Some(deadline) = inner.arm_anchor(now, pending) {
                let epoch = inner.epoch;
                self.spawn_anchor_timer(epoch, deadline);
            }
            inner.send_stream_clear(now);
        }
        inner.send_metadata(now);
    }

    /// Ends the stream without touching the playback state.
    ///
    /// The host may end a track and open the next one, so the group keeps playing and the position
    /// stays where the audio stopped.
    pub(crate) fn end_stream(&self) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        if inner.end_player_stream(now) {
            inner.send_metadata(now);
            let _ = self.events.send(Event::StreamEnded);
        }
    }

    /// Reports that one member's trigger was sent and applies what its epoch and flags allow.
    ///
    /// A report for another epoch belongs to a superseded segment and changes nothing. Every
    /// report clears the member's start gate, because the start it waited for has gone out. A
    /// member still in an armed anchor set contributes its transmit time and is released with the
    /// shared timeline. A member that was gated on this start gets its own start lead, so a late
    /// joiner's start from empty holds even when the group's timeline is behind (at the price of
    /// a hole), also when it is unavailable at the time and takes the floor back with it. A
    /// streaming member that was not gated keeps the timeline it is already on.
    pub(crate) fn trigger_sent(
        &self,
        member: u64,
        epoch: u64,
        anchor: bool,
        reset: bool,
        t: Option<i64>,
    ) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let Some(index) = inner.members.iter().position(|held| held.id == member) else {
            return;
        };
        if reset {
            // The reset describes what the client discarded on the wire, so it holds whatever
            // epoch the trigger belonged to. The connection sends its queue in order and marks a
            // chunk transmitted right after the write, so at this point exactly the chunks queued
            // before the trigger are marked: the ones queued behind it are still outstanding.
            inner.members[index]
                .sent
                .retain(|sent| !sent.transmitted.load(Ordering::Relaxed));
        }
        if inner.epoch != epoch {
            return;
        }
        let was_gated = inner.members[index].start_gate;
        inner.members[index].start_gate = false;

        let mut recorded = false;
        if anchor {
            if let Some(held) = inner
                .stream
                .as_mut()
                .and_then(|stream| stream.anchor.as_mut())
            {
                if held.pending.contains(&member) {
                    if let Some(t) = t {
                        held.reported.push((member, t));
                    }
                    held.pending.retain(|id| *id != member);
                    recorded = true;
                }
            }
        }
        if !recorded {
            if let Some(t) = t {
                if !inner.members[index].plays() {
                    if was_gated {
                        // Not ready now, but it waited for this start: keep the floor for when it
                        // returns. `start_at` only matters to a streaming member.
                        let floor = t.saturating_add(inner.members[index].member_lead_us());
                        let old = inner.members[index].start_at;
                        inner.members[index].start_at = old.max(floor);
                    }
                } else {
                    // Only a member that waited for this start takes its own lead from the
                    // report: one that already streams again (it left and returned during the
                    // anchor) would otherwise skip chunks the group has been sending it, an
                    // audible hole in a running stream.
                    let member_lead = if was_gated {
                        t.saturating_add(inner.members[index].member_lead_us())
                    } else {
                        0
                    };
                    let next_us = inner.stream.as_ref().map_or(0, |stream| stream.next_us);
                    let old = inner.members[index].start_at;
                    inner.members[index].start_at =
                        old.max(next_us).max(member_lead).max(now.saturating_add(1));
                }
            }
        }
        inner.check_anchor_at(now);
    }

    /// Runs the anchor deadline timer for `epoch`.
    ///
    /// A completed anchor or a superseded epoch makes this a no-op; the group checks both under
    /// the lock.
    pub(crate) fn check_anchor(&self, epoch: u64) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        if inner.epoch != epoch {
            return;
        }
        inner.check_anchor_at(now);
    }

    /// Spawns the one-shot task that flushes a due anchor.
    ///
    /// It sleeps on the runtime the group was built in, so a host that writes one chunk and then
    /// waits is not stuck behind a missing report. It carries the epoch, so an anchor superseded
    /// while it sleeps is left alone, and it re-sleeps when it wakes before the deadline.
    fn spawn_anchor_timer(&self, epoch: u64, deadline_us: i64) {
        let Some(runtime) = self.runtime.clone() else {
            return;
        };
        let me = self.me.clone();
        runtime.spawn(async move {
            loop {
                let Some(group) = me.upgrade() else {
                    return;
                };
                let remaining = deadline_us.saturating_sub(group.now_us());
                if remaining <= 0 {
                    group.check_anchor(epoch);
                    return;
                }
                let wait = Duration::from_micros(u64::try_from(remaining).unwrap_or(u64::MAX));
                drop(group);
                tokio::time::sleep(wait).await;
            }
        });
    }
}

impl Inner {
    /// Returns the `controller` object of `server/state`.
    fn controller(&self) -> ControllerState {
        ControllerState {
            supported_commands: GROUP_COMMANDS
                .iter()
                .map(|command| (*command).to_owned())
                .collect(),
            volume: Some(self.volume),
            muted: Some(self.muted),
            repeat: None,
            shuffle: None,
            seek_max_ms: None,
        }
    }

    /// Returns the `metadata` object of `server/state` for the state at `now_us`.
    ///
    /// While a segment has not started yet, the state is the specification's scheduled update: it
    /// carries the segment's first timestamp and source position, so a client holds it until the
    /// audio starts instead of extrapolating across the lead. Once the segment is under way the
    /// state describes `now`, and an inactive stream reports the position its pause froze.
    fn metadata(&self, now_us: i64) -> Metadata {
        self.scheduled_metadata(now_us)
            .unwrap_or_else(|| self.metadata_at(now_us))
    }

    /// Returns the scheduled update for a segment that has not started, or `None` once it has.
    fn scheduled_metadata(&self, now_us: i64) -> Option<Metadata> {
        let stream = self.stream.as_ref()?;
        if !stream.active || now_us >= stream.start_us {
            return None;
        }
        Some(self.metadata_state(stream.start_us, Some(stream.start_position)))
    }

    /// Returns the state at `now_us` with a past or present timestamp.
    ///
    /// This is also the first state a joining metadata role gets: `messaging.md` requires a past
    /// or present timestamp there. [`Self::scheduled_metadata`] follows it while the segment has
    /// not started, so a joiner that arrives during the lead is corrected rather than left to
    /// extrapolate the first state.
    fn metadata_at(&self, now_us: i64) -> Metadata {
        let position = self.stream.as_ref().map(|stream| {
            if stream.active {
                stream.position_at(now_us)
            } else {
                stream.position
            }
        });
        self.metadata_state(now_us, position)
    }

    /// Builds a `metadata` object for one timestamp and source position.
    fn metadata_state(&self, timestamp: i64, position: Option<Duration>) -> Metadata {
        let (title, artist, album_artist, album, duration) = match &self.stream {
            Some(stream) => (
                stream.track.title.clone(),
                stream.track.artist.clone(),
                stream.track.album_artist.clone(),
                stream.track.album.clone(),
                stream.track.duration,
            ),
            None => (None, None, None, None, None),
        };
        Metadata {
            timestamp: Some(timestamp),
            title,
            artist,
            album_artist,
            album,
            artwork_url: None,
            year: None,
            track: None,
            progress: position.map(|position| Progress {
                track_progress: Some(u64::try_from(position.as_millis()).unwrap_or(u64::MAX)),
                track_duration: Some(duration.map_or(0, |duration| {
                    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
                })),
                playback_speed: Some(
                    if self.playing && self.stream.as_ref().is_none_or(|stream| stream.active) {
                        1000
                    } else {
                        0
                    },
                ),
            }),
        }
    }

    /// Returns the `group/update` message for the current group state.
    fn group_update(&self) -> GroupUpdate {
        GroupUpdate {
            playback_state: if self.playing { "playing" } else { "stopped" }.to_owned(),
            group_id: self.group_id.clone(),
            group_name: self.group_name.clone(),
        }
    }

    /// Returns the `stream/start` message for the current format.
    ///
    /// The `server_transmitted` value is a placeholder: the connection task stamps the real
    /// transmit time immediately before encryption, and that reading is the `T` the trigger reports
    /// to the anchor.
    fn stream_start(&self, now_us: i64) -> Incoming {
        Incoming::StreamStart(StreamStart {
            server_transmitted: now_us,
            player: Some(self.format.stream_start()),
            ..Default::default()
        })
    }

    /// Sends the controller half of `server/state` to every controller.
    fn send_controller(&self) {
        let state = Incoming::ServerState(ServerState {
            controller: Some(self.controller()),
            metadata: None,
            ..Default::default()
        });
        self.send(&state, |member| member.has(CONTROLLER_ROLE));
    }

    /// Sends the metadata half of `server/state` to every metadata role.
    fn send_metadata(&self, now_us: i64) {
        let state = Incoming::ServerState(ServerState {
            controller: None,
            metadata: Some(self.metadata(now_us)),
            ..Default::default()
        });
        self.send(&state, |member| member.has(METADATA_ROLE));
    }

    /// Sends `group/update` to every member.
    fn send_group_update(&self) {
        self.send(&Incoming::GroupUpdate(self.group_update()), |_| true);
    }

    /// Declares the playback activity and announces the running stream to every ready player.
    ///
    /// `in_place` names the members that already have the old stream and only need the in-place
    /// configuration update after a track jump; every other ready player gets a start trigger. A
    /// member whose activation is older than the playback state gets a `server/activate` first,
    /// because a `stream/start` carrying the `player` object is only allowed on a connection that
    /// declares `playback`. The caller has already set [`Inner::playing`].
    fn start_streams(&mut self, now_us: i64, in_place: &[u64]) {
        for index in 0..self.members.len() {
            if in_place.contains(&self.members[index].id) {
                self.start_in_place(index, now_us);
            } else {
                self.start_member_stream(index, now_us);
            }
        }
    }

    /// Sends the in-place `stream/start` of a track jump to one member.
    ///
    /// The clear was the restart trigger, so this start re-applies neither the lead nor the count
    /// and sets no gate. A member that went unavailable between the clear and this send gets no
    /// start; it is unannounced and receives the new stream's start when it returns.
    fn start_in_place(&mut self, index: usize, now_us: i64) {
        if !self.playing {
            return;
        }
        self.declare_playback(index);
        if self.members[index].stream_announced || !self.members[index].plays() {
            return;
        }
        let start = self.stream_start(now_us);
        self.members[index].stream_announced = true;
        let _ = self.members[index]
            .sender
            .send(Outbound::Message(Box::new(start)));
    }

    /// Announces the running stream to one member, if that member may receive it now.
    ///
    /// The start is a trigger: its send is reported back so the group can anchor a restart on its
    /// transmit time. A member that becomes ready while an anchor is armed joins that anchor
    /// without arming a second deadline. After the anchor, the start gives the member its own lead
    /// on the existing timeline.
    fn start_member_stream(&mut self, index: usize, now_us: i64) {
        if !self.playing {
            return;
        }
        self.declare_playback(index);
        let Some(stream) = self.stream.as_ref() else {
            return;
        };
        // A member becoming ready after `stream/end` waits for the next stream, not this one.
        if !stream.active || self.members[index].stream_announced || !self.members[index].plays() {
            return;
        }
        let anchoring = stream.anchor.is_some();
        let epoch = self.epoch;
        let start = self.stream_start(now_us);
        self.members[index].stream_announced = true;
        self.members[index].start_gate = true;
        let id = self.members[index].id;
        let _ = self.members[index].sender.send(Outbound::Trigger {
            message: Box::new(start),
            epoch,
            anchor: anchoring,
            reset: anchoring,
        });
        if anchoring {
            if let Some(anchor) = self
                .stream
                .as_mut()
                .and_then(|stream| stream.anchor.as_mut())
            {
                if !anchor.pending.contains(&id) {
                    anchor.pending.push(id);
                }
            }
        }
    }

    /// Drops the announced stream of every player without ending it.
    ///
    /// A track jump clears the buffers and then announces the new format again, which is an update
    /// of the stream the players still have open.
    fn forget_stream_starts(&mut self) {
        for member in self.members.iter_mut() {
            member.stream_announced = false;
        }
    }

    /// Brings the activation of every member in line with the playback state of the group.
    fn declare_playback_for_all(&mut self) {
        for index in 0..self.members.len() {
            self.declare_playback(index);
        }
    }

    /// Tells one member whether the group is playing, when that changed for it.
    fn declare_playback(&mut self, index: usize) {
        let playing = self.playing;
        let member = &mut self.members[index];
        if member.playback_declared == playing {
            return;
        }
        member.playback_declared = playing;
        let activate = Incoming::ServerActivate(ServerActivate {
            activities: if playing {
                vec![PLAYBACK_ACTIVITY.to_owned()]
            } else {
                Vec::new()
            },
            // The roles of the initial activation stay in force.
            active_roles: None,
            pairing: None,
        });
        let _ = member.sender.send(Outbound::Message(Box::new(activate)));
    }

    /// Sends a `stream/clear` for the player stream to every player that has one.
    ///
    /// The clear is a restart trigger: it anchors the new segment and resets the member's sent
    /// chunks on its report. An announced but unavailable member still gets it, because the client
    /// must discard its buffers; it is not part of the anchor's pending set because it does not
    /// `plays()`. The queued `server_transmitted` is a placeholder the connection overwrites at the
    /// send, like the start's.
    fn send_stream_clear(&self, now_us: i64) {
        let message = Incoming::StreamClear(StreamClear {
            server_transmitted: now_us,
            from_timestamp: None,
            roles: Some(vec![PLAYER_STREAM.to_owned()]),
        });
        let epoch = self.epoch;
        for member in self.members.iter().filter(|member| member.stream_announced) {
            let _ = member.sender.send(Outbound::Trigger {
                message: Box::new(message.clone()),
                epoch,
                anchor: true,
                reset: true,
            });
        }
    }

    /// Sends a `stream/end` for the player stream to every player that has one.
    ///
    /// The end is a trigger because its report resets the member's sent chunks; it anchors
    /// nothing. It carries no timestamp, so its report is a bare reset.
    fn send_stream_end(&mut self) {
        let message = Incoming::StreamEnd(StreamEnd {
            roles: Some(vec![PLAYER_STREAM.to_owned()]),
        });
        let epoch = self.epoch;
        for member in self.members.iter_mut() {
            if !member.stream_announced {
                continue;
            }
            member.stream_announced = false;
            let _ = member.sender.send(Outbound::Trigger {
                message: Box::new(message.clone()),
                epoch,
                anchor: false,
                reset: true,
            });
        }
    }

    /// Sends one control message to every member `wanted` selects.
    fn send(&self, message: &Incoming, wanted: impl Fn(&Member) -> bool) {
        for member in self.members.iter().filter(|member| wanted(member)) {
            let _ = member
                .sender
                .send(Outbound::Message(Box::new(message.clone())));
        }
    }

    /// Sends one framed audio chunk to every player with an announced stream.
    ///
    /// The chunk is the same for every member: one timeline, one set of timestamps. Each client
    /// translates them with its own clock estimate. Whether a member gets it is per member: a
    /// gated one or one whose own start is still ahead is skipped, and so is one whose capacity
    /// is used up by chunks it has not finished playing. The count is rebuilt from the sent list
    /// on every chunk, so an ack, a passing playtime or a reported output delay all take effect
    /// without a separate pass. A skipped member hears a hole while the group timeline moves on;
    /// the wire has no per-member skip signal. Returns how many streaming members were skipped.
    fn send_audio(
        &mut self,
        chunk: &[u8],
        timestamp_us: i64,
        duration: Duration,
        now_us: i64,
    ) -> usize {
        let mut skipped = 0;
        let framed = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        for member in self.members.iter_mut().filter(|member| member.streams()) {
            if member.start_gate || member.start_at > timestamp_us {
                skipped += 1;
                continue;
            }
            member.prune_sent(now_us);
            let count = member.counted_bytes(now_us);
            if framed > member.capacity.saturating_sub(count) {
                skipped += 1;
                continue;
            }
            let transmitted = Arc::new(AtomicBool::new(false));
            let _ = member.sender.send(Outbound::Audio {
                chunk: chunk.to_vec(),
                transmitted: Arc::clone(&transmitted),
            });
            member.sent.push(SentChunk {
                timestamp_us,
                duration,
                bytes: chunk.len(),
                transmitted,
            });
            member.start_at = 0;
        }
        skipped
    }

    /// Stops the player stream if it is running and freezes its position.
    ///
    /// A pause during the lead freezes at the segment start, because the client's buffer is empty
    /// and the next sample is the first of the segment. Ending moves the epoch, so a report of the
    /// end cannot clear the gate of a start that superseded it.
    ///
    /// Returns whether there was a stream to end.
    fn end_player_stream(&mut self, now_us: i64) -> bool {
        let running = self.stream.as_ref().is_some_and(|stream| stream.active);
        if !running {
            return false;
        }
        if let Some(stream) = self.stream.as_mut() {
            stream.position = stream.audible_position(now_us);
            stream.active = false;
        }
        self.supersede();
        self.send_stream_end();
        true
    }

    /// Moves the group to a new epoch and drops everything the old one held.
    ///
    /// Every superseding restart or stop calls this once: a new stream (with the clear that may
    /// precede it), the `play` restart, a seek, pause, stop and end. The held audio and the armed
    /// anchor belong to the old epoch, and every member's gate waits for a start of the old one, so
    /// none of it may survive.
    fn supersede(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        if let Some(stream) = self.stream.as_mut() {
            stream.anchor = None;
            stream.held.clear();
            stream.wrote_any = false;
        }
        for member in self.members.iter_mut() {
            member.start_at = 0;
            member.start_gate = false;
        }
    }

    /// Sets the provisional timeline a restart starts from before its anchor arms.
    ///
    /// The anchor flush overwrites these values with the transmitted timeline; with no ready
    /// member they stand. A zero lead still keeps the first timestamp in the future.
    fn restart_clock(&mut self, now_us: i64) {
        let lead = self.group_lead_us();
        if let Some(stream) = self.stream.as_mut() {
            stream.next_us = now_us.saturating_add(lead).max(now_us.saturating_add(1));
            stream.start_us = stream.next_us;
            stream.anchor_us = now_us;
        }
    }

    /// The ready members that a restart's start triggers will reach.
    fn start_pending(&self) -> Vec<u64> {
        self.members
            .iter()
            .filter(|member| member.plays() && !member.stream_announced)
            .map(|member| member.id)
            .collect()
    }

    /// The ready members that a restart's clear reaches.
    fn clear_pending(&self) -> Vec<u64> {
        self.members
            .iter()
            .filter(|member| member.stream_announced && member.plays())
            .map(|member| member.id)
            .collect()
    }

    /// Arms the anchor with `pending` and returns its deadline, if it has a member to wait for.
    ///
    /// An empty pending set arms nothing: the clear or start still goes out and the provisional
    /// timeline stands. The caller spawns the deadline timer with the returned deadline.
    fn arm_anchor(&mut self, now_us: i64, pending: Vec<u64>) -> Option<i64> {
        if pending.is_empty() {
            return None;
        }
        let deadline_us = now_us.saturating_add(micros_i64(ANCHOR_DEADLINE));
        let stream = self.stream.as_mut()?;
        stream.anchor = Some(Anchor {
            pending,
            reported: Vec::new(),
            deadline_us,
        });
        Some(deadline_us)
    }

    /// The common start lead: the largest `min_buffer_ms + output_delay_ms` of the ready members.
    ///
    /// The specification requires the group maximum for grouped playback. The sum is computed in
    /// `u64`, because the fields are `u32` and a 32-bit target must not overflow, then clamped into
    /// the `i64` the timeline uses. No ready member means no lead.
    fn group_lead_us(&self) -> i64 {
        self.members
            .iter()
            .filter(|member| member.plays())
            .map(|member| {
                u64::from(member.min_buffer_ms).saturating_add(u64::from(member.output_delay_ms))
            })
            .max()
            .map_or(0, |millis| {
                i64::try_from(millis.saturating_mul(1_000)).unwrap_or(i64::MAX)
            })
    }

    /// Moves the segment start to a raised group lead before the first chunk was assigned.
    ///
    /// A raise is re-seeded from the segment's anchor transmit while that is still in the future,
    /// and from `now` otherwise; after the first chunk it keeps the timeline, because the restore
    /// the specification asks for is the live queue, not a timeline move. While an anchor is
    /// armed there is no re-seed: the flush reads the new lead. Members waiting for their first
    /// chunk keep their own lead and are never moved before the new segment start.
    fn raise_lead(&mut self, now_us: i64, lead: i64) {
        let next_us = {
            let Some(stream) = self.stream.as_mut() else {
                return;
            };
            if !stream.active || stream.anchor.is_some() || stream.wrote_any {
                return;
            }
            let from_anchor = stream.anchor_us.saturating_add(lead);
            stream.next_us = if from_anchor > now_us {
                from_anchor
            } else {
                now_us.saturating_add(lead).max(now_us.saturating_add(1))
            };
            stream.start_us = stream.next_us;
            stream.next_us
        };
        for member in self.members.iter_mut() {
            if member.plays() && (member.start_gate || member.start_at > 0) {
                member.start_at = member.start_at.max(next_us);
            }
        }
        // The scheduled update moves with the segment start, so the metadata role sees where the
        // audio will now begin.
        self.send_metadata(now_us);
    }

    /// Gives a member that returns from unavailable its own lead on the running segment.
    ///
    /// It keeps its announcement, so it gets no second start; its own start-from-empty lead and
    /// the segment's trigger lead still hold. The old `start_at` is never lowered, so a late
    /// joiner's lead survives a later report.
    fn report_returning(&mut self, index: usize, now_us: i64) {
        let Some(stream) = self.stream.as_ref() else {
            return;
        };
        if !stream.active || !self.members[index].stream_announced {
            return;
        }
        let next_us = stream.next_us;
        let anchor_us = stream.anchor_us;
        let lead = self.members[index].member_lead_us();
        let member = &mut self.members[index];
        let floor = next_us
            .max(anchor_us.saturating_add(lead))
            .max(now_us.saturating_add(1));
        member.start_at = member.start_at.max(floor);
    }

    /// Flushes the anchor when its pending set is empty or its deadline has passed.
    ///
    /// A member still pending at the deadline is dropped from the set but stays gated, so the flush
    /// does not send to it while its `stream/start` is still queued; its late report then gives it
    /// its own lead. The segment starts at the latest reported transmit plus the group lead, or
    /// re-leads from `now` when that is already past. The metadata state is queued before the held
    /// audio it describes.
    fn check_anchor_at(&mut self, now_us: i64) {
        let Some(anchor) = ({
            let Some(stream) = self.stream.as_mut() else {
                return;
            };
            let Some(anchor) = stream.anchor.as_ref() else {
                return;
            };
            if !anchor.pending.is_empty() && now_us < anchor.deadline_us {
                return;
            }
            stream.anchor.take()
        }) else {
            return;
        };

        for id in &anchor.pending {
            if let Some(member) = self.members.iter_mut().find(|member| member.id == *id) {
                member.start_gate = true;
            }
        }

        let lead = self.group_lead_us();
        let base = anchor
            .max_reported()
            .map(|reported| (reported, reported.saturating_add(lead)));
        let (next_us, anchor_us) = match base {
            Some((reported, base)) if base > now_us => (base, reported),
            _ => (
                now_us.saturating_add(lead).max(now_us.saturating_add(1)),
                now_us,
            ),
        };
        if let Some(stream) = self.stream.as_mut() {
            stream.next_us = next_us;
            stream.start_us = next_us;
            stream.anchor_us = anchor_us;
            stream.position = stream.start_position;
        }
        self.send_metadata(now_us);
        let held = self
            .stream
            .as_mut()
            .map(|stream| stream.held.drain(..).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut skipped_chunks = 0;
        for (payload, duration) in held {
            // The flush assigns each held chunk's timestamp now, never provisionally.
            if matches!(
                self.assign_and_send(&payload, duration, now_us),
                WriteOutcome::Partial { .. }
            ) {
                skipped_chunks += 1;
            }
        }
        if skipped_chunks > 0 {
            // The host was told `Held` for these chunks, so the flush is where it can still learn
            // that some player did not get them.
            let _ = self.events.send(Event::HeldAudioSkipped {
                chunks: skipped_chunks,
            });
        }
    }

    /// Assigns the next timestamp to one payload, advances the timeline and sends it.
    fn assign_and_send(&mut self, payload: &[u8], duration: Duration, now_us: i64) -> WriteOutcome {
        let (chunk, timestamp_us) = {
            let Some(stream) = self.stream.as_mut() else {
                return WriteOutcome::Dropped(WriteError::Ended);
            };
            if !stream.active {
                return WriteOutcome::Dropped(WriteError::Paused);
            }
            let timestamp_us = stream.next_us;
            stream.next_us = timestamp_us.saturating_add(micros_i64(duration));
            stream.position = stream.position.saturating_add(duration);
            stream.wrote_any = true;
            let chunk = AudioChunkHeader {
                timestamp_us,
                // The connection stamps the real interval immediately before encryption; the
                // group has not sent anything yet and leaves the placeholder.
                send_ahead: 0,
            }
            .encode(payload);
            (chunk, timestamp_us)
        };
        match self.send_audio(&chunk, timestamp_us, duration, now_us) {
            0 => WriteOutcome::Written,
            skipped => WriteOutcome::Partial { skipped },
        }
    }
}

/// Queues one message for a connection.
fn send_to(sender: &mpsc::UnboundedSender<Outbound>, message: Incoming) {
    let _ = sender.send(Outbound::Message(Box::new(message)));
}

/// Builds the group identifier: 32 random bytes as the wire wants them.
///
/// A group outlives every connection and never changes while it exists, so a client can compare
/// what it is part of. The value identifies the group, not the server; a restart may pick a new one.
fn group_id() -> anyhow::Result<String> {
    let mut id = [0u8; 32];
    getrandom::fill(&mut id).map_err(|_| {
        anyhow::anyhow!("failed to draw the group identifier from the operating system CSPRNG")
    })?;
    Ok(URL_SAFE_NO_PAD.encode(id))
}

/// The whole microseconds of `duration`, saturating at the `i64` range.
fn micros_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

/// The server's clock: monotonic microseconds since the server started.
///
/// The epoch is this server's own; a client only needs the rate, because its time filter measures
/// the offset to whatever the server reports. Monotonic means a stream never jumps backwards when
/// the wall clock is corrected.
#[derive(Debug)]
struct Clock {
    start: Instant,
}

impl Clock {
    /// Starts a clock at the current monotonic instant.
    fn new() -> Clock {
        Clock {
            start: Instant::now(),
        }
    }

    /// Returns the clock reading in microseconds for `at`.
    fn at(&self, at: Instant) -> i64 {
        i64::try_from(at.saturating_duration_since(self.start).as_micros()).unwrap_or(i64::MAX)
    }

    /// Returns the server clock reading in microseconds.
    fn now_us(&self) -> i64 {
        self.at(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::StreamWriter;
    use syncspin_core::messages::PlayerState;

    /// Builds the group the group tests drive.
    ///
    /// Built outside a runtime, as every test but the anchor timer's is, it spawns no timer and the
    /// test drives the deadline through `Inner::check_anchor_at`.
    fn test_group() -> Arc<Group> {
        let (events, _receiver) = mpsc::unbounded_channel();
        Group::new("g".into(), AudioFormat::pcm(48_000, 2, 16), events).expect("a group builds")
    }

    /// The capacity of a test member that should receive every chunk it is offered.
    const ROOMY: u64 = 1 << 20;

    /// Joins a ready player with `min_buffer_ms` and `output_delay_ms` and returns its queue.
    fn add_player(
        group: &Group,
        min_buffer_ms: u32,
        output_delay_ms: u32,
    ) -> (u64, mpsc::UnboundedReceiver<Outbound>) {
        add_player_with_capacity(group, min_buffer_ms, output_delay_ms, ROOMY)
    }

    /// Joins a ready player with a chosen buffer capacity and returns its queue.
    fn add_player_with_capacity(
        group: &Group,
        min_buffer_ms: u32,
        output_delay_ms: u32,
        capacity: u64,
    ) -> (u64, mpsc::UnboundedReceiver<Outbound>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let id = group.join(vec![PLAYER_ROLE.to_owned()], sender, capacity);
        report_timing(group, id, min_buffer_ms, output_delay_ms);
        (id, receiver)
    }

    /// Joins a metadata-only member and returns its queue.
    fn add_metadata(group: &Group) -> (u64, mpsc::UnboundedReceiver<Outbound>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let id = group.join(vec![METADATA_ROLE.to_owned()], sender, 0);
        (id, receiver)
    }

    /// Joins a member that both plays and displays metadata and returns its queue.
    fn add_player_and_metadata(
        group: &Group,
        min_buffer_ms: u32,
        output_delay_ms: u32,
    ) -> (u64, mpsc::UnboundedReceiver<Outbound>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let id = group.join(
            vec![PLAYER_ROLE.to_owned(), METADATA_ROLE.to_owned()],
            sender,
            ROOMY,
        );
        report_timing(group, id, min_buffer_ms, output_delay_ms);
        (id, receiver)
    }

    /// Reports one ready player's timing again.
    fn report_timing(group: &Group, id: u64, min_buffer_ms: u32, output_delay_ms: u32) {
        group.report_client_state(
            id,
            &ClientState {
                available: true,
                player: Some(PlayerState {
                    volume: None,
                    muted: None,
                    output_delay_ms,
                    required_lead_time_ms: 0,
                    min_buffer_ms,
                    supported_commands: Vec::new(),
                    format: None,
                }),
                ..Default::default()
            },
        );
    }

    /// Opens a stream, reports the ready member's start trigger and returns the epoch.
    fn open_stream_reported(
        group: &Group,
        id: u64,
        receiver: &mut mpsc::UnboundedReceiver<Outbound>,
    ) -> u64 {
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(receiver);
        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 1_000_000));
        epoch
    }

    /// Takes the next trigger from a member's queue, skipping the other messages it receives.
    fn next_trigger(
        receiver: &mut mpsc::UnboundedReceiver<Outbound>,
    ) -> (Incoming, u64, bool, bool) {
        loop {
            match receiver.try_recv().expect("a trigger is queued") {
                Outbound::Trigger {
                    message,
                    epoch,
                    anchor,
                    reset,
                } => return (*message, epoch, anchor, reset),
                Outbound::Message(_) | Outbound::Audio { .. } => {}
            }
        }
    }

    /// Takes the next audio chunk from a member's queue.
    fn next_audio(receiver: &mut mpsc::UnboundedReceiver<Outbound>) -> (Vec<u8>, Arc<AtomicBool>) {
        loop {
            if let Outbound::Audio { chunk, transmitted } =
                receiver.try_recv().expect("audio is queued")
            {
                return (chunk, transmitted);
            }
        }
    }

    /// Marks everything queued to a member as written to its socket, as its connection does for
    /// the chunks that precede a trigger in its queue.
    fn mark_transmitted(group: &Group, id: u64) {
        let inner = group.lock();
        let member = inner
            .members
            .iter()
            .find(|member| member.id == id)
            .expect("the member");
        for sent in &member.sent {
            sent.transmitted.store(true, Ordering::Relaxed);
        }
    }

    /// Returns every audio chunk queued for a member.
    fn drain_audio(
        receiver: &mut mpsc::UnboundedReceiver<Outbound>,
    ) -> Vec<(Vec<u8>, Arc<AtomicBool>)> {
        let mut chunks = Vec::new();
        while let Ok(outbound) = receiver.try_recv() {
            if let Outbound::Audio { chunk, transmitted } = outbound {
                chunks.push((chunk, transmitted));
            }
        }
        chunks
    }

    /// Returns every queued message, in order.
    fn drain_outbound(receiver: &mut mpsc::UnboundedReceiver<Outbound>) -> Vec<Outbound> {
        let mut outbound = Vec::new();
        while let Ok(message) = receiver.try_recv() {
            outbound.push(message);
        }
        outbound
    }

    /// Returns the queued stream lifecycle messages, in order, triggers and plain messages alike.
    fn stream_messages(receiver: &mut mpsc::UnboundedReceiver<Outbound>) -> Vec<Incoming> {
        drain_outbound(receiver)
            .into_iter()
            .filter_map(|outbound| match outbound {
                Outbound::Message(message) => Some(*message),
                Outbound::Trigger { message, .. } => Some(*message),
                Outbound::Audio { .. } => None,
            })
            .filter(|message| {
                matches!(
                    message,
                    Incoming::StreamStart(_) | Incoming::StreamClear(_) | Incoming::StreamEnd(_)
                )
            })
            .collect()
    }

    /// Returns the metadata states a member was sent, in order.
    fn drain_metadata(receiver: &mut mpsc::UnboundedReceiver<Outbound>) -> Vec<Metadata> {
        drain_outbound(receiver)
            .into_iter()
            .filter_map(|outbound| match outbound {
                Outbound::Message(message) => match *message {
                    Incoming::ServerState(state) => state.metadata,
                    _ => None,
                },
                Outbound::Trigger { .. } | Outbound::Audio { .. } => None,
            })
            .collect()
    }

    /// Returns one member's start floor.
    fn member_start_at(group: &Group, id: u64) -> i64 {
        group
            .lock()
            .members
            .iter()
            .find(|member| member.id == id)
            .expect("the member")
            .start_at
    }

    /// Returns the number of chunks one member still accounts for.
    fn sent_len(group: &Group, id: u64) -> usize {
        group
            .lock()
            .members
            .iter()
            .find(|member| member.id == id)
            .expect("the member")
            .sent
            .len()
    }

    #[test]
    fn a_pcm_writer_requires_whole_frames_and_respects_the_150_ms_bound() {
        let (events, _rx) = mpsc::unbounded_channel();
        let group = Group::new("g".into(), AudioFormat::pcm(48_000, 2, 16), events).unwrap();
        group.open_stream(TrackInfo::default());
        let mut writer = StreamWriter::new(group.clone());
        // 480 stereo frames = 10 ms = 480*4 bytes.
        assert_eq!(writer.write(&[0u8; 480 * 4]), WriteOutcome::Written);
        assert_eq!(
            writer.write(&[0u8; 480 * 4 + 1]),
            WriteOutcome::Dropped(WriteError::Incomplete)
        );
        // 150 ms exactly is 7_200 frames = 7200*4 bytes.
        assert_eq!(writer.write(&[0u8; 7200 * 4]), WriteOutcome::Written);
        assert_eq!(
            writer.write(&[0u8; 7200 * 4 + 4]),
            WriteOutcome::Dropped(WriteError::TooLong)
        );
        assert_eq!(writer.write(&[]), WriteOutcome::Dropped(WriteError::Empty));
        assert_eq!(
            writer.write_encoded(&[0u8; 480 * 4], Duration::from_millis(10)),
            WriteOutcome::Dropped(WriteError::WrongMethod),
            "PCM audio uses write, not write_encoded"
        );
    }

    #[test]
    fn an_encoded_format_refuses_plain_write_and_a_zero_duration() {
        let (events, _rx) = mpsc::unbounded_channel();
        let group = Group::new("g".into(), AudioFormat::opus(48_000, 2), events).unwrap();
        group.open_stream(TrackInfo::default());
        let mut writer = StreamWriter::new(group.clone());
        assert_eq!(
            writer.write(&[0u8; 10]),
            WriteOutcome::Dropped(WriteError::WrongMethod)
        );
        assert_eq!(
            writer.write_encoded(&[0u8; 10], Duration::ZERO),
            WriteOutcome::Dropped(WriteError::Empty)
        );
        assert_eq!(
            writer.write_encoded(&[0u8; 10], Duration::from_millis(10)),
            WriteOutcome::Written
        );
        assert_eq!(
            writer.write_encoded(&[0u8; 10], Duration::from_millis(151)),
            WriteOutcome::Dropped(WriteError::TooLong),
            "a supplied playtime past 150 ms is refused too"
        );
    }

    #[test]
    fn a_one_frame_chunk_at_an_absurd_rate_has_no_playtime() {
        let (events, _receiver) = mpsc::unbounded_channel();
        let group = Group::new(
            "a group".to_owned(),
            AudioFormat::pcm(u32::MAX, 2, 16),
            events,
        )
        .expect("a group builds");
        group.open_stream(TrackInfo::default());
        let next_us = group.lock().stream.as_ref().expect("a stream").next_us;
        let mut writer = StreamWriter::new(group.clone());
        assert_eq!(
            writer.write(&[0u8; 4]),
            WriteOutcome::Dropped(WriteError::Empty),
            "one frame at the highest rate truncates to a zero duration"
        );
        assert_eq!(
            group.lock().stream.as_ref().expect("a stream").next_us,
            next_us,
            "a chunk without playtime leaves no hole"
        );
    }

    #[test]
    fn a_writer_that_ended_refuses_further_chunks() {
        let group = test_group();
        group.open_stream(TrackInfo::default());
        let mut writer = StreamWriter::new(group.clone());
        assert_eq!(writer.write(&[0u8; 480 * 4]), WriteOutcome::Written);
        writer.end();
        assert_eq!(
            writer.write(&[0u8; 480 * 4]),
            WriteOutcome::Dropped(WriteError::Ended),
            "the writer reports Ended after end, not Paused"
        );
        assert_eq!(
            writer.write_encoded(&[0u8; 480 * 4], Duration::from_millis(10)),
            WriteOutcome::Dropped(WriteError::Ended)
        );
        assert!(
            !group.lock().stream.as_ref().expect("a stream").active,
            "end() makes the stream inactive"
        );
    }

    #[test]
    fn the_group_lead_is_the_maximum_of_the_ready_members() {
        let group = test_group();
        assert_eq!(
            group.lock().group_lead_us(),
            0,
            "a group without a ready member has no lead"
        );
        let _first = add_player(&group, 100, 0);
        let _second = add_player(&group, 3000, 500);
        assert_eq!(group.lock().group_lead_us(), 3_500_000);
    }

    #[test]
    fn a_refused_chunk_leaves_no_hole_in_the_timeline() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);
        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 1_000_000));

        let first = group.lock().stream.as_ref().expect("a stream").next_us;
        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        let second = group.lock().stream.as_ref().expect("a stream").next_us;
        assert_eq!(second - first, 10_000);

        assert_eq!(
            group.write_audio(&[0u8; 7200 * 4 + 4], None),
            WriteOutcome::Dropped(WriteError::TooLong)
        );
        assert_eq!(
            group.lock().stream.as_ref().expect("a stream").next_us,
            second,
            "a refused chunk does not move the timeline"
        );

        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        let third = group.lock().stream.as_ref().expect("a stream").next_us;
        assert_eq!(
            third - second,
            10_000,
            "the accepted chunks stay one chunk apart"
        );
    }

    #[test]
    fn a_stalled_timeline_re_seeds_a_lead_ahead_and_states_it_before_the_audio() {
        let group = test_group();
        let (id, mut receiver) = add_player_and_metadata(&group, 0, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);
        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 500_000));
        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        let _ = drain_outbound(&mut receiver);

        // Pretend the host starved the queue: the timeline now lies behind the clock.
        let now = group.now_us();
        group.lock().stream.as_mut().expect("a stream").next_us = now - 50_000;
        let before = group.now_us();
        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        let after = group.now_us();

        let outbound = drain_outbound(&mut receiver);
        let order = outbound
            .iter()
            .map(|message| match message {
                Outbound::Message(message) if matches!(**message, Incoming::ServerState(_)) => {
                    "state"
                }
                Outbound::Audio { .. } => "audio",
                _ => "other",
            })
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            ["state", "audio"],
            "the state describing the new segment precedes its audio"
        );
        let metadata = match &outbound[0] {
            Outbound::Message(message) => match &**message {
                Incoming::ServerState(state) => state.metadata.clone().expect("a metadata state"),
                _ => panic!("expected a server state"),
            },
            _ => panic!("expected a server state"),
        };
        let chunk = match &outbound[1] {
            Outbound::Audio { chunk, .. } => chunk,
            _ => panic!("expected audio"),
        };
        let (header, _) = AudioChunkHeader::parse(chunk).expect("a framed chunk");
        let inner = group.lock();
        let stream = inner.stream.as_ref().expect("a stream");
        assert_eq!(header.timestamp_us, stream.start_us);
        assert_eq!(metadata.timestamp, Some(stream.start_us));
        assert_eq!(
            metadata
                .progress
                .as_ref()
                .and_then(|progress| progress.track_progress),
            Some(10),
            "the re-seed keeps the position of the next sample"
        );
        assert_eq!(
            metadata
                .progress
                .as_ref()
                .and_then(|progress| progress.playback_speed),
            Some(1000)
        );
        assert_eq!(stream.start_position, Duration::from_millis(10));
        assert_eq!(stream.next_us, stream.start_us + 10_000);
        assert!(stream.anchor_us >= before && stream.anchor_us <= after);
        assert_eq!(
            stream.start_us,
            stream.anchor_us.saturating_add(1),
            "a zero lead still starts one microsecond in the future"
        );
    }

    #[test]
    fn the_anchor_waits_for_every_report_and_starts_at_the_maximum() {
        let group = test_group();
        let (first, mut first_rx) = add_player(&group, 100, 0);
        let (second, mut second_rx) = add_player(&group, 3000, 500);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut first_rx);
        let (_, second_epoch, second_anchor, second_reset) = next_trigger(&mut second_rx);
        assert_eq!(
            (second_epoch, second_anchor, second_reset),
            (epoch, anchor, reset),
            "both starts share the epoch and the trigger flags"
        );
        assert!(anchor && reset, "a stream start is the restart trigger");

        let now = group.now_us();
        group.trigger_sent(first, epoch, anchor, reset, Some(now + 500_000));
        assert!(
            group
                .lock()
                .stream
                .as_ref()
                .expect("a stream")
                .anchor
                .is_some(),
            "one report does not complete the anchor"
        );
        group.trigger_sent(
            second,
            second_epoch,
            second_anchor,
            second_reset,
            Some(now + 800_000),
        );

        let inner = group.lock();
        let stream = inner.stream.as_ref().expect("a stream");
        assert_eq!(
            stream.next_us,
            now + 800_000 + 3_500_000,
            "the timeline starts at the latest reported transmit plus the group lead"
        );
        assert!(stream.anchor.is_none());
    }

    #[test]
    fn a_report_later_than_the_lead_re_leads_from_now() {
        let group = test_group();
        let (first, mut first_rx) = add_player(&group, 100, 0);
        let (second, mut second_rx) = add_player(&group, 3000, 500);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut first_rx);
        let _ = next_trigger(&mut second_rx);

        let stale = group.now_us() - 10_000_000;
        group.trigger_sent(first, epoch, anchor, reset, Some(stale));
        let before = group.now_us();
        group.trigger_sent(second, epoch, anchor, reset, Some(stale));

        let inner = group.lock();
        let stream = inner.stream.as_ref().expect("a stream");
        assert!(
            stream.next_us >= before + 3_500_000,
            "a stale report re-leads from now instead of keeping a past timestamp"
        );
        assert!(
            stream.next_us <= group.now_us() + 3_500_000,
            "the fallback uses the report's clock reading"
        );
        assert!(
            stream.anchor_us >= before && stream.anchor_us <= group.now_us(),
            "the fallback anchors at now"
        );
    }

    #[test]
    fn a_member_ready_during_an_anchor_joins_the_pending_set() {
        let group = test_group();
        let (first, mut first_rx) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut first_rx);
        let deadline = group
            .lock()
            .stream
            .as_ref()
            .expect("a stream")
            .anchor
            .as_ref()
            .expect("an anchor")
            .deadline_us;

        let (second, mut second_rx) = add_player(&group, 3000, 500);
        let (_, second_epoch, second_anchor, second_reset) = next_trigger(&mut second_rx);
        assert!(second_anchor && second_reset);
        assert_eq!(second_epoch, epoch);
        {
            let inner = group.lock();
            let held = inner
                .stream
                .as_ref()
                .expect("a stream")
                .anchor
                .as_ref()
                .expect("an anchor");
            assert_eq!(
                held.pending,
                vec![first, second],
                "a ready member joins the armed anchor"
            );
            assert_eq!(
                held.deadline_us, deadline,
                "joining an armed anchor does not arm a second deadline"
            );
        }

        let now = group.now_us();
        group.trigger_sent(first, epoch, anchor, reset, Some(now + 400_000));
        group.trigger_sent(
            second,
            second_epoch,
            second_anchor,
            second_reset,
            Some(now + 700_000),
        );
        assert_eq!(
            group.lock().stream.as_ref().expect("a stream").next_us,
            now + 700_000 + 3_500_000
        );
    }

    #[test]
    fn a_member_pending_at_the_deadline_stays_gated_and_re_leads_late() {
        let group = test_group();
        let (first, mut first_rx) = add_player(&group, 100, 0);
        let (second, mut second_rx) = add_player(&group, 3000, 500);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut first_rx);
        let _ = next_trigger(&mut second_rx);

        let now = group.now_us();
        group.trigger_sent(first, epoch, anchor, reset, Some(now + 100_000));
        let deadline = group
            .lock()
            .stream
            .as_ref()
            .expect("a stream")
            .anchor
            .as_ref()
            .expect("an anchor")
            .deadline_us;
        {
            let mut inner = group.lock();
            inner.check_anchor_at(deadline);
            let stream = inner.stream.as_ref().expect("a stream");
            assert!(stream.anchor.is_none(), "the deadline flushes the anchor");
            assert_eq!(stream.next_us, now + 100_000 + 3_500_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == second)
                .expect("the second member");
            assert!(
                member.start_gate,
                "a member whose report is missing stays gated"
            );
        }

        let late = group.now_us() + 2_000_000;
        group.trigger_sent(second, epoch, true, true, Some(late));
        {
            let inner = group.lock();
            let member = inner
                .members
                .iter()
                .find(|member| member.id == second)
                .expect("the second member");
            assert!(!member.start_gate, "the late report clears the gate");
            assert_eq!(
                member.start_at,
                late + 3_500_000,
                "the late member keeps its own lead from the trigger's transmit"
            );
            assert!(
                member.start_at > inner.stream.as_ref().expect("a stream").next_us,
                "its own lead exceeds the shared timeline, at the price of a hole"
            );
        }

        // A stale transmit time on a report that joins the running segment falls to the timeline
        // floor, so the member is never given a past `start_at`.
        let stale = group.now_us() - 10_000_000;
        group.trigger_sent(first, epoch, true, true, Some(stale));
        let inner = group.lock();
        let member = inner
            .members
            .iter()
            .find(|member| member.id == first)
            .expect("the first member");
        let next_us = inner.stream.as_ref().expect("a stream").next_us;
        assert_eq!(
            member.start_at, next_us,
            "a stale T falls back to the next sample's timestamp"
        );
        assert!(
            stale + 100_000 < member.start_at,
            "the member's own lead would be in the past and cannot be the floor"
        );
    }

    #[test]
    fn held_audio_flushes_at_the_anchor_and_the_bound_is_one_second() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);

        let hundred_ms = vec![0u8; 4800 * 4];
        for _ in 0..10 {
            assert_eq!(
                group.write_audio(&hundred_ms, None),
                WriteOutcome::Held,
                "exactly one second fits in the held queue"
            );
        }
        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Dropped(WriteError::Backpressure),
            "the new chunk is dropped, not the beginning of the track"
        );

        let t = group.now_us() + 500_000;
        group.trigger_sent(id, epoch, anchor, reset, Some(t));

        let chunks = drain_audio(&mut receiver);
        assert_eq!(chunks.len(), 10, "the refused chunk is not queued");
        let (first, _) = AudioChunkHeader::parse(&chunks[0].0).expect("a framed chunk");
        assert_eq!(
            first.timestamp_us,
            t + 100_000,
            "the flush assigns the first timestamp from max(T) + lead"
        );
        for (index, (chunk, _)) in chunks.iter().enumerate() {
            let (header, _) = AudioChunkHeader::parse(chunk).expect("a framed chunk");
            assert_eq!(
                header.timestamp_us,
                first.timestamp_us + 100_000 * index as i64,
                "the held chunks keep their order and playtime"
            );
        }
        let inner = group.lock();
        let member = inner
            .members
            .iter()
            .find(|member| member.id == id)
            .expect("the member");
        assert_eq!(member.sent.len(), 10);
        let stream = inner.stream.as_ref().expect("a stream");
        assert!(stream.held.is_empty(), "the flush empties the held queue");
        assert_eq!(stream.start_us, first.timestamp_us);
        assert_eq!(
            stream.next_us,
            first.timestamp_us + 1_000_000,
            "ten held chunks advance the timeline by their playtime"
        );
    }

    #[test]
    fn a_reset_report_keeps_the_chunks_queued_behind_its_trigger() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 0, 0);
        open_stream_reported(&group, id, &mut receiver);
        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        mark_transmitted(&group, id);
        group.seek(Duration::from_secs(1));
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);
        assert!(reset);

        // The member drops out of the anchor and returns before its clear is written, so it
        // streams again, ungated, with the clear still ahead of it in its queue.
        group.report_client_state(
            id,
            &ClientState {
                available: false,
                player: None,
                ..Default::default()
            },
        );
        group.report_client_state(
            id,
            &ClientState {
                available: true,
                player: None,
                ..Default::default()
            },
        );
        // `report_returning` floors the member's next chunk at the report instant plus 1 µs, so a
        // chunk scheduled at that same microsecond is skipped. A fast host usually crosses the
        // floor before the write below; a loaded CI runner does not, and the write then lands on
        // the floor. Sleep past it so the test does not depend on the scheduler.
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written,
            "the returned member takes the chunk behind its clear"
        );
        assert_eq!(sent_len(&group, id), 2, "the old chunk and the new one");

        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 100_000));
        assert_eq!(
            sent_len(&group, id),
            1,
            "the reset drops what preceded the clear and counts what follows it"
        );
    }

    #[test]
    fn the_timeline_follows_the_sample_count_at_a_rate_that_does_not_divide_a_chunk() {
        let (events, _receiver) = mpsc::unbounded_channel();
        let group = Group::new("g".into(), AudioFormat::pcm(44_100, 2, 16), events)
            .expect("a group builds");
        let (id, mut receiver) = add_player(&group, 0, 0);
        open_stream_reported(&group, id, &mut receiver);
        let start = group.lock().stream.as_ref().expect("a stream").next_us;

        let chunk = [0u8; 480 * 4];
        for _ in 0..1_000 {
            let _ = group.write_audio(&chunk, None);
        }
        let end = group.lock().stream.as_ref().expect("a stream").next_us;
        assert_eq!(
            end - start,
            480_000 * 1_000_000 / 44_100,
            "a thousand 480-frame chunks span the exact playtime of 480 000 frames"
        );
    }

    #[test]
    fn a_reported_buffer_capacity_is_held_to_the_server_cap() {
        let group = test_group();
        let (id, _receiver) = add_player_with_capacity(&group, 0, 0, u64::MAX);
        let inner = group.lock();
        let member = inner
            .members
            .iter()
            .find(|member| member.id == id)
            .expect("the member");
        assert_eq!(member.capacity, MAX_BUFFER_CAPACITY);
    }

    #[test]
    fn open_stream_cuts_long_metadata_text() {
        let group = test_group();
        let (_id, _receiver) = add_player(&group, 0, 0);
        group.open_stream(TrackInfo {
            title: Some("t".repeat(400)),
            ..TrackInfo::default()
        });
        let inner = group.lock();
        let title = inner
            .stream
            .as_ref()
            .and_then(|stream| stream.track.title.as_deref());
        assert_eq!(title.map(str::len), Some(255));
    }

    #[test]
    fn a_refused_chunk_does_not_move_the_pcm_remainder() {
        let (events, _receiver) = mpsc::unbounded_channel();
        let group = Group::new("g".into(), AudioFormat::pcm(44_100, 2, 16), events)
            .expect("a group builds");
        let (id, mut receiver) = add_player(&group, 0, 0);
        open_stream_reported(&group, id, &mut receiver);
        group.pause();

        // A paused stream refuses the chunk; retrying must not accumulate its fraction.
        for _ in 0..1_000 {
            assert_eq!(
                group.write_audio(&[0u8; 480 * 4], None),
                WriteOutcome::Dropped(WriteError::Paused)
            );
        }
        assert_eq!(
            group.lock().stream.as_ref().expect("a stream").pcm_carry,
            0,
            "refused chunks leave the carry where it was"
        );
    }

    #[test]
    fn a_flush_that_skips_a_player_is_reported_as_an_event() {
        let (events, mut event_receiver) = mpsc::unbounded_channel();
        let group = Group::new("g".into(), AudioFormat::pcm(48_000, 2, 16), events)
            .expect("a group builds");
        let (first, mut first_receiver) = add_player(&group, 0, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut first_receiver);
        let chunk = [0u8; 480 * 4];
        for _ in 0..3 {
            assert_eq!(group.write_audio(&chunk, None), WriteOutcome::Held);
        }
        // A player that joins during the anchor is pending, and one that has not reported by the
        // deadline stays gated, so the flush does not feed it the held chunks.
        let (_second, _second_receiver) = add_player(&group, 0, 0);
        while event_receiver.try_recv().is_ok() {}

        group.trigger_sent(first, epoch, anchor, reset, Some(group.now_us() + 100_000));
        assert!(
            event_receiver.try_recv().is_err(),
            "the anchor still waits for the second player"
        );
        let deadline = group.now_us() + 2_000_000;
        group.lock().check_anchor_at(deadline);
        assert_eq!(
            event_receiver.try_recv(),
            Ok(Event::HeldAudioSkipped { chunks: 3 }),
            "the host learns that the held chunks did not reach every player"
        );
        assert_eq!(drain_audio(&mut first_receiver).len(), 3);
    }

    #[test]
    fn a_late_clear_report_does_not_open_a_hole_for_a_member_that_already_streams_again() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 100, 0);
        open_stream_reported(&group, id, &mut receiver);
        mark_transmitted(&group, id);
        group.seek(Duration::from_secs(1));
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);
        for available in [false, true] {
            group.report_client_state(
                id,
                &ClientState {
                    available,
                    player: None,
                    ..Default::default()
                },
            );
        }
        let chunk = [0u8; 480 * 4];
        assert_eq!(group.write_audio(&chunk, None), WriteOutcome::Written);

        // The clear is written late; its transmit time plus the member's lead is past the
        // timeline the member is already being fed from.
        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 5_000_000));
        assert_eq!(
            group.write_audio(&chunk, None),
            WriteOutcome::Written,
            "a member that is already streaming is not skipped by a late report"
        );
    }

    #[test]
    fn a_stale_clear_report_still_resets_what_the_client_discarded() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 0, 0);
        open_stream_reported(&group, id, &mut receiver);
        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        mark_transmitted(&group, id);
        group.seek(Duration::from_secs(1));
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);
        group.pause();

        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 100_000));
        assert_eq!(
            sent_len(&group, id),
            0,
            "the clear reached the client even though a pause superseded it"
        );
    }

    #[test]
    fn held_audio_is_bounded_by_the_smallest_ready_capacity() {
        // The client announces 131_072 bytes; one second of 48 kHz stereo PCM is 192 kB.
        let group = test_group();
        let (id, mut receiver) = add_player_with_capacity(&group, 100, 0, 131_072);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);

        let ten_ms = [0u8; 480 * 4];
        let framed = (ten_ms.len() + AudioChunkHeader::LEN) as u64;
        let fits = usize::try_from(131_072 / framed).expect("a small count");
        for _ in 0..fits {
            assert_eq!(group.write_audio(&ten_ms, None), WriteOutcome::Held);
        }
        assert_eq!(
            group.write_audio(&ten_ms, None),
            WriteOutcome::Dropped(WriteError::Backpressure),
            "a chunk the flush could not hand to the player is refused while it is held"
        );

        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 500_000));
        assert_eq!(
            drain_audio(&mut receiver).len(),
            fits,
            "everything the host was told was held reaches the player"
        );
    }

    #[test]
    fn held_audio_is_discarded_when_a_pause_supersedes_the_anchor() {
        let group = test_group();
        let (_id, mut receiver) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let _ = next_trigger(&mut receiver);

        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Held,
            "the stream is not anchored yet"
        );
        group.pause();

        assert!(
            group
                .lock()
                .stream
                .as_ref()
                .is_some_and(|stream| stream.held.is_empty()),
            "the chunk the host was told was held is gone after the pause"
        );
        assert!(
            drain_audio(&mut receiver).is_empty(),
            "and it never reaches the player"
        );
    }

    #[test]
    fn a_play_restart_moves_the_epoch_and_a_stale_end_report_cannot_clear_its_gate() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);
        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 1_000_000));

        group.pause();
        let (end, paused_epoch, end_anchor, end_reset) = next_trigger(&mut receiver);
        assert!(matches!(end, Incoming::StreamEnd(_)));
        assert!(!end_anchor && end_reset);

        group.play();
        let (start, playing_epoch, start_anchor, start_reset) = next_trigger(&mut receiver);
        assert!(matches!(start, Incoming::StreamStart(_)));
        assert!(start_anchor && start_reset);
        assert_ne!(
            playing_epoch, paused_epoch,
            "the play restart moves the epoch"
        );

        group.trigger_sent(id, paused_epoch, false, true, None);
        {
            let inner = group.lock();
            assert_eq!(inner.epoch, playing_epoch);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert!(
                member.start_gate,
                "a superseded end report cannot clear the new start's gate"
            );
        }

        group.trigger_sent(
            id,
            playing_epoch,
            start_anchor,
            start_reset,
            Some(group.now_us() + 1_000_000),
        );
        assert!(
            !group
                .lock()
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member")
                .start_gate
        );
    }

    #[test]
    fn a_track_jump_clears_as_the_anchor_and_starts_in_place() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);
        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 1_000_000));

        group.open_stream(TrackInfo {
            title: Some("the next track".to_owned()),
            ..TrackInfo::default()
        });
        let epoch = group.lock().epoch;

        let mut clear = None;
        let mut starts = 0;
        while let Ok(outbound) = receiver.try_recv() {
            match outbound {
                Outbound::Trigger {
                    message,
                    epoch,
                    anchor,
                    reset,
                } => match *message {
                    Incoming::StreamClear(_) => clear = Some((epoch, anchor, reset)),
                    other => panic!("unexpected trigger {other:?}"),
                },
                Outbound::Message(message) => {
                    if matches!(*message, Incoming::StreamStart(_)) {
                        starts += 1;
                    }
                }
                Outbound::Audio { .. } => {}
            }
        }
        assert_eq!(
            clear,
            Some((epoch, true, true)),
            "the clear is the anchor and the reset of the jump"
        );
        assert_eq!(
            starts, 1,
            "the start after the clear is an in-place message, not a trigger"
        );
    }

    #[test]
    fn a_seek_clears_as_the_anchor_and_resets_the_count() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 100, 0);
        open_stream_reported(&group, id, &mut receiver);
        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        assert_eq!(sent_len(&group, id), 1);
        let old_epoch = group.lock().epoch;

        group.seek(Duration::from_secs(30));
        let (clear, epoch, anchor, reset) = next_trigger(&mut receiver);
        assert!(matches!(clear, Incoming::StreamClear(_)));
        assert!(
            anchor && reset,
            "a seek's clear restarts the timeline and resets the count"
        );
        assert_ne!(epoch, old_epoch, "a seek moves the epoch");
        assert_eq!(sent_len(&group, id), 1, "the report resets, not the send");

        let t = group.now_us() + 100_000;
        mark_transmitted(&group, id);
        group.trigger_sent(id, epoch, anchor, reset, Some(t));
        let inner = group.lock();
        let member = inner
            .members
            .iter()
            .find(|member| member.id == id)
            .expect("the member");
        assert_eq!(member.sent.len(), 0, "the clear's report resets the count");
        let stream = inner.stream.as_ref().expect("a stream");
        assert_eq!(stream.start_position, Duration::from_secs(30));
        assert_eq!(stream.position, Duration::from_secs(30));
        assert_eq!(stream.next_us, t + 100_000);
        assert_eq!(stream.start_us, stream.next_us);
        assert_eq!(stream.anchor_us, t);
    }

    #[test]
    fn a_seek_below_the_lead_is_a_scheduled_update_at_the_segment_start() {
        let group = test_group();
        let (id, mut receiver) = add_player_and_metadata(&group, 3000, 500);
        open_stream_reported(&group, id, &mut receiver);
        let _ = drain_metadata(&mut receiver);

        group.seek(Duration::from_secs(1));
        let now = group.now_us();
        let states = drain_metadata(&mut receiver);
        assert_eq!(states.len(), 1, "a seek reports the new segment once");
        let (start_us, start_position) = {
            let inner = group.lock();
            let stream = inner.stream.as_ref().expect("a stream");
            (stream.start_us, stream.start_position)
        };
        assert_eq!(start_position, Duration::from_secs(1));
        assert!(
            start_us > now,
            "the seek's provisional start is a full lead ahead"
        );
        assert_eq!(states[0].timestamp, Some(start_us));
        assert_eq!(
            states[0]
                .progress
                .as_ref()
                .and_then(|progress| progress.track_progress),
            Some(1_000),
            "a seek below the lead is not clamped to zero"
        );
        assert_eq!(
            states[0]
                .progress
                .as_ref()
                .and_then(|progress| progress.playback_speed),
            Some(1000)
        );
    }

    #[test]
    fn the_first_state_of_a_join_is_past_or_present_and_the_scheduled_one_follows() {
        let group = test_group();
        let (first, mut first_rx) = add_player(&group, 100, 0);
        let (second, mut second_rx) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut first_rx);
        let _ = next_trigger(&mut second_rx);
        let t = group.now_us() + 100_000;
        group.trigger_sent(first, epoch, anchor, reset, Some(t));
        group.trigger_sent(second, epoch, true, true, Some(t));

        // A seek to 10 s arms a fresh anchor. One member reports a transmit 5 s ahead while the
        // other stays pending, so the deadline check moves the timeline the join must build on.
        group.seek(Duration::from_secs(10));
        let (clear, clear_epoch, clear_anchor, clear_reset) = next_trigger(&mut first_rx);
        assert!(matches!(clear, Incoming::StreamClear(_)));
        let _ = next_trigger(&mut second_rx);
        let future = group.now_us() + 5_000_000;
        group.trigger_sent(first, clear_epoch, clear_anchor, clear_reset, Some(future));
        {
            let mut inner = group.lock();
            let now = group.now_us();
            inner
                .stream
                .as_mut()
                .expect("a stream")
                .anchor
                .as_mut()
                .expect("an anchor")
                .deadline_us = now - 1;
        }

        let before = group.now_us();
        let (_metadata, mut receiver) = add_metadata(&group);
        let after = group.now_us();
        let states = drain_metadata(&mut receiver);
        assert_eq!(
            states.len(),
            2,
            "a join sends its state and, during the lead, the scheduled one"
        );
        assert!(
            states[0]
                .timestamp
                .is_some_and(|timestamp| (before..=after).contains(&timestamp)),
            "the first state of a join is dated past or present"
        );
        let (start_us, position) = {
            let inner = group.lock();
            let stream = inner.stream.as_ref().expect("a stream");
            assert!(stream.anchor.is_none(), "the due anchor was flushed");
            (stream.start_us, stream.position)
        };
        assert!(start_us > after, "the segment starts a lead ahead");
        assert_eq!(states[1].timestamp, Some(start_us));
        assert_eq!(
            states[1]
                .progress
                .as_ref()
                .and_then(|progress| progress.track_progress),
            Some(10_000),
            "the scheduled state carries the seek target"
        );
        let first_timestamp = states[0].timestamp.expect("the first state is dated");
        let heard = position
            .saturating_sub(Duration::from_micros(
                u64::try_from(start_us - first_timestamp).unwrap_or_default(),
            ))
            .as_millis();
        assert_eq!(
            states[0]
                .progress
                .as_ref()
                .and_then(|progress| progress.track_progress),
            Some(u64::try_from(heard).unwrap_or(u64::MAX)),
            "the first state is built against the flushed timeline, not the provisional one"
        );
        assert!(
            heard < 9_000,
            "the pending report moved the timeline well past the provisional start"
        );
        for state in &states {
            assert_eq!(
                state
                    .progress
                    .as_ref()
                    .and_then(|progress| progress.playback_speed),
                Some(1000)
            );
        }
    }

    #[test]
    fn a_seek_while_paused_sends_no_clear() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);
        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 1_000_000));
        group.pause();
        let (end, ..) = next_trigger(&mut receiver);
        assert!(matches!(end, Incoming::StreamEnd(_)));

        group.seek(Duration::from_secs(30));
        let mut saw_clear = false;
        while let Ok(outbound) = receiver.try_recv() {
            if let Outbound::Trigger { message, .. } = outbound {
                if matches!(*message, Incoming::StreamClear(_)) {
                    saw_clear = true;
                }
            }
        }
        assert!(!saw_clear, "a seek while paused sends no clear");
        assert_eq!(
            group.lock().stream.as_ref().expect("a stream").position,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn a_leaving_member_drops_out_of_the_anchor() {
        let group = test_group();
        let (first, mut first_rx) = add_player(&group, 100, 0);
        let (second, mut second_rx) = add_player(&group, 3000, 500);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut first_rx);
        let _ = next_trigger(&mut second_rx);

        let now = group.now_us();
        group.trigger_sent(first, epoch, anchor, reset, Some(now + 9_000_000));
        group.leave(first);
        {
            let inner = group.lock();
            let held = inner
                .stream
                .as_ref()
                .expect("a stream")
                .anchor
                .as_ref()
                .expect("the second member still waits");
            assert_eq!(held.pending, vec![second]);
            assert!(
                held.reported.is_empty(),
                "the leaving member's report is dropped"
            );
        }

        let now = group.now_us();
        group.trigger_sent(second, epoch, true, true, Some(now + 200_000));
        let inner = group.lock();
        let stream = inner.stream.as_ref().expect("a stream");
        assert_eq!(
            stream.next_us,
            now + 200_000 + 3_500_000,
            "the dropped report cannot anchor the segment"
        );
        assert!(stream.anchor.is_none());
    }

    #[test]
    fn an_anchor_that_loses_every_member_re_leads_from_now() {
        let group = test_group();
        let (first, mut first_rx) = add_player(&group, 3000, 500);
        let (second, mut second_rx) = add_player(&group, 3000, 500);
        group.open_stream(TrackInfo::default());
        let _ = next_trigger(&mut first_rx);
        let _ = next_trigger(&mut second_rx);

        let before = group.now_us();
        group.leave(first);
        assert!(
            group
                .lock()
                .stream
                .as_ref()
                .expect("a stream")
                .anchor
                .is_some(),
            "one member still waits"
        );
        group.leave(second);

        let after = group.now_us();
        let inner = group.lock();
        let stream = inner.stream.as_ref().expect("a stream");
        assert!(inner.members.is_empty());
        assert!(stream.anchor.is_none(), "the empty pending set flushes");
        assert!(stream.anchor_us >= before && stream.anchor_us <= after);
        assert_eq!(
            stream.next_us,
            stream.anchor_us.saturating_add(1),
            "a zero lead still starts one microsecond in the future"
        );
    }

    #[test]
    fn a_report_from_a_non_ready_member_applies_only_its_reset() {
        let group = test_group();
        let (first, mut first_rx) = add_player(&group, 100, 0);
        let (second, mut second_rx) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut first_rx);
        let (_, second_epoch, second_anchor, second_reset) = next_trigger(&mut second_rx);
        let t = group.now_us() + 100_000;
        group.trigger_sent(first, epoch, anchor, reset, Some(t));
        group.trigger_sent(second, second_epoch, second_anchor, second_reset, Some(t));
        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        assert_eq!(sent_len(&group, second), 1);

        group.open_stream(TrackInfo {
            title: Some("the next track".to_owned()),
            ..TrackInfo::default()
        });
        let jump_epoch = group.lock().epoch;
        let (clear, clear_epoch, clear_anchor, clear_reset) = next_trigger(&mut first_rx);
        assert!(matches!(clear, Incoming::StreamClear(_)));
        assert_eq!(clear_epoch, jump_epoch);
        assert!(clear_anchor && clear_reset);
        let (second_clear, second_clear_epoch, ..) = next_trigger(&mut second_rx);
        assert!(matches!(second_clear, Incoming::StreamClear(_)));
        assert_eq!(second_clear_epoch, jump_epoch);

        group.report_client_state(
            second,
            &ClientState {
                available: false,
                player: None,
                ..Default::default()
            },
        );
        let future = group.now_us() + 5_000_000;
        mark_transmitted(&group, second);
        group.trigger_sent(second, jump_epoch, true, true, Some(future));
        {
            let inner = group.lock();
            let member = inner
                .members
                .iter()
                .find(|member| member.id == second)
                .expect("the second member");
            assert_eq!(
                member.sent.len(),
                0,
                "the reset is applied even though the member is not ready"
            );
            assert_eq!(member.start_at, 0, "a non-ready report sets no start floor");
            let held = inner
                .stream
                .as_ref()
                .expect("a stream")
                .anchor
                .as_ref()
                .expect("the ready member still anchors");
            assert_eq!(held.pending, vec![first]);
            assert!(
                held.reported.is_empty(),
                "the unavailable member's transmit time is not used"
            );
        }

        let first_t = group.now_us() + 200_000;
        group.trigger_sent(first, jump_epoch, true, true, Some(first_t));
        let inner = group.lock();
        assert_eq!(
            inner.stream.as_ref().expect("a stream").next_us,
            first_t + 100_000,
            "the anchor uses only the ready member's transmit time"
        );
    }

    #[test]
    fn a_superseded_anchors_old_reports_cannot_anchor_the_next_segment() {
        let group = test_group();
        let (first, mut first_rx) = add_player(&group, 100, 0);
        let (second, mut second_rx) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut first_rx);
        let _ = next_trigger(&mut second_rx);

        let old_t = group.now_us() + 60_000_000;
        group.trigger_sent(first, epoch, anchor, reset, Some(old_t));
        assert!(
            group
                .lock()
                .stream
                .as_ref()
                .expect("a stream")
                .anchor
                .is_some(),
            "one report leaves the other member pending, so the old anchor is still armed"
        );

        group.seek(Duration::from_secs(5));
        let (clear, seek_epoch, clear_anchor, clear_reset) = next_trigger(&mut first_rx);
        assert!(matches!(clear, Incoming::StreamClear(_)));
        let (_, second_epoch, second_anchor, second_reset) = next_trigger(&mut second_rx);
        assert_eq!(second_epoch, seek_epoch);
        assert!(clear_anchor && clear_reset && second_anchor && second_reset);

        let now = group.now_us();
        let first_t = now + 100_000;
        let second_t = now + 200_000;
        group.trigger_sent(first, seek_epoch, clear_anchor, clear_reset, Some(first_t));
        group.trigger_sent(
            second,
            second_epoch,
            second_anchor,
            second_reset,
            Some(second_t),
        );

        let inner = group.lock();
        let stream = inner.stream.as_ref().expect("a stream");
        assert_eq!(
            stream.next_us,
            second_t + 100_000,
            "the new segment anchors only on the new reports"
        );
        assert_eq!(stream.anchor_us, second_t);
        assert!(
            stream.next_us < old_t,
            "the superseded anchor's transmit time cannot appear in the new segment"
        );
    }

    #[test]
    fn a_completed_anchor_makes_the_anchor_check_a_no_op() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut receiver);
        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 1_000_000));
        let next_us = group.lock().stream.as_ref().expect("a stream").next_us;

        let (_metadata, mut metadata_rx) = add_metadata(&group);
        let _ = drain_metadata(&mut metadata_rx);
        group.lock().check_anchor_at(group.now_us() + 10_000_000);
        {
            let inner = group.lock();
            let stream = inner.stream.as_ref().expect("a stream");
            assert_eq!(
                stream.next_us, next_us,
                "a finished anchor is not re-flushed"
            );
            assert!(stream.anchor.is_none());
        }
        assert!(
            drain_metadata(&mut metadata_rx).is_empty(),
            "a finished anchor is not re-flushed as a second state"
        );
    }

    #[test]
    fn a_lead_raise_before_the_first_chunk_moves_the_segment_and_resends_one_state() {
        let group = test_group();
        let (first, mut first_rx) = add_player(&group, 100, 0);
        let (second, mut second_rx) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut first_rx);
        let _ = next_trigger(&mut second_rx);
        let t = group.now_us() + 500_000;
        group.trigger_sent(first, epoch, anchor, reset, Some(t));
        group.trigger_sent(second, epoch, true, true, Some(t));
        assert_eq!(
            group.lock().stream.as_ref().expect("a stream").start_us,
            t + 100_000
        );

        let (late, mut late_rx) = add_player(&group, 100, 0);
        let (_, late_epoch, late_anchor, late_reset) = next_trigger(&mut late_rx);
        assert_eq!(late_epoch, epoch);
        assert!(
            !late_anchor && !late_reset,
            "a late joiner moves no timeline"
        );
        let (_metadata, mut metadata_rx) = add_metadata(&group);
        let _ = drain_outbound(&mut metadata_rx);
        assert!(!group.lock().stream.as_ref().expect("a stream").wrote_any);

        report_timing(&group, first, 3000, 500);
        let first_start = {
            let inner = group.lock();
            let stream = inner.stream.as_ref().expect("a stream");
            assert_eq!(stream.anchor_us, t);
            stream.start_us
        };
        assert_eq!(
            first_start,
            t + 3_500_000,
            "the raise re-seeds from the anchor's transmit and the new lead"
        );
        let states = drain_metadata(&mut metadata_rx);
        assert_eq!(
            states.len(),
            1,
            "a raise resends exactly one scheduled state"
        );
        assert_eq!(states[0].timestamp, Some(first_start));
        assert_eq!(member_start_at(&group, late), first_start);

        report_timing(&group, second, 5000, 500);
        let second_start = group.lock().stream.as_ref().expect("a stream").start_us;
        assert_eq!(second_start, t + 5_500_000, "a second raise moves it again");
        let states = drain_metadata(&mut metadata_rx);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].timestamp, Some(second_start));
        assert_eq!(member_start_at(&group, late), second_start);
    }

    #[test]
    fn a_returning_member_keeps_its_larger_old_start_at_and_gets_no_second_start() {
        let group = test_group();
        let (base, mut base_rx) = add_player(&group, 3000, 500);
        group.open_stream(TrackInfo::default());
        let (_, epoch, anchor, reset) = next_trigger(&mut base_rx);
        let t = group.now_us() + 100_000;
        group.trigger_sent(base, epoch, anchor, reset, Some(t));
        let next_us = group.lock().stream.as_ref().expect("a stream").next_us;
        assert_eq!(next_us, t + 3_500_000);

        let (late, mut late_rx) = add_player_and_metadata(&group, 3000, 500);
        let joined = drain_outbound(&mut late_rx);
        assert!(
            joined.iter().any(|outbound| matches!(
                outbound,
                Outbound::Message(message) if matches!(**message, Incoming::ServerState(_))
            )),
            "the metadata role's join queued its server/state"
        );
        let (late_epoch, late_anchor, late_reset) = joined
            .iter()
            .find_map(|outbound| match outbound {
                Outbound::Trigger {
                    message,
                    epoch,
                    anchor,
                    reset,
                } if matches!(**message, Incoming::StreamStart(_)) => {
                    Some((*epoch, *anchor, *reset))
                }
                _ => None,
            })
            .expect("the late joiner's start is a trigger");
        assert_eq!(late_epoch, epoch);
        assert!(!late_anchor && !late_reset);
        let late_t = group.now_us() + 1_000_000;
        group.trigger_sent(late, late_epoch, late_anchor, late_reset, Some(late_t));
        let own_floor = late_t + 3_500_000;
        assert_eq!(member_start_at(&group, late), own_floor);
        assert!(
            own_floor > next_us,
            "the late joiner's own lead leaves a hole"
        );

        group.report_client_state(
            late,
            &ClientState {
                available: false,
                player: None,
                ..Default::default()
            },
        );
        report_timing(&group, late, 3000, 500);
        assert_eq!(
            member_start_at(&group, late),
            own_floor,
            "a return never lowers the lead a late joiner already had"
        );
        let mut outbound = joined;
        outbound.extend(drain_outbound(&mut late_rx));
        let starts = outbound
            .iter()
            .filter(|outbound| match outbound {
                Outbound::Trigger { message, .. } => {
                    matches!(**message, Incoming::StreamStart(_))
                }
                Outbound::Message(message) => matches!(**message, Incoming::StreamStart(_)),
                Outbound::Audio { .. } => false,
            })
            .count();
        assert_eq!(
            starts, 1,
            "the late join was announced once and an announced returning member gets no second start"
        );
        let inner = group.lock();
        let member = inner
            .members
            .iter()
            .find(|member| member.id == late)
            .expect("the late member");
        assert!(
            member.stream_announced,
            "the announcement survives the absence"
        );
    }

    #[test]
    fn a_member_ready_after_stream_end_gets_no_trigger() {
        let group = test_group();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let id = group.join(vec![PLAYER_ROLE.to_owned()], sender, ROOMY);
        group.open_stream(TrackInfo::default());
        group.end_stream();

        report_timing(&group, id, 100, 0);
        assert!(
            stream_messages(&mut receiver).is_empty(),
            "a member that becomes ready after stream/end waits for the next stream"
        );
        assert!(
            !group
                .lock()
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member")
                .stream_announced,
            "the ended stream was never announced to the member"
        );

        group.open_stream(TrackInfo::default());
        let starts = stream_messages(&mut receiver);
        assert!(
            matches!(starts.as_slice(), [Incoming::StreamStart(_)]),
            "the next stream starts the member: {starts:?}"
        );
    }

    #[test]
    fn a_timer_with_a_superseded_epoch_is_a_no_op() {
        let group = test_group();
        let (_id, mut receiver) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let (_, epoch, ..) = next_trigger(&mut receiver);
        let provisional = group.lock().stream.as_ref().expect("a stream").next_us;
        {
            let mut inner = group.lock();
            let now = group.now_us();
            inner
                .stream
                .as_mut()
                .expect("a stream")
                .anchor
                .as_mut()
                .expect("an anchor")
                .deadline_us = now - 1;
        }

        group.check_anchor(epoch.wrapping_sub(1));
        {
            let inner = group.lock();
            assert!(
                inner.stream.as_ref().expect("a stream").anchor.is_some(),
                "a timer of a superseded epoch leaves the anchor alone"
            );
            assert_eq!(
                inner.stream.as_ref().expect("a stream").next_us,
                provisional
            );
        }
        group.check_anchor(epoch);
        assert!(
            group
                .lock()
                .stream
                .as_ref()
                .expect("a stream")
                .anchor
                .is_none(),
            "the timer of the current epoch flushes the due anchor"
        );
    }

    #[tokio::test]
    async fn the_anchor_timer_flushes_when_no_report_arrives() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 100, 0);
        group.open_stream(TrackInfo::default());
        let _ = next_trigger(&mut receiver);

        // The start is sent and never reported; the deadline timer is what releases the stream.
        tokio::time::sleep(ANCHOR_DEADLINE + Duration::from_millis(200)).await;
        let inner = group.lock();
        let stream = inner.stream.as_ref().expect("a stream");
        assert!(
            stream.anchor.is_none(),
            "the deadline timer flushes an anchor whose report never arrives"
        );
        let member = inner
            .members
            .iter()
            .find(|member| member.id == id)
            .expect("the member");
        assert!(
            member.start_gate,
            "a member that never reported stays gated for its late report"
        );
    }

    #[test]
    fn the_group_identifier_is_43_base64url_characters() {
        let id = group_id().expect("the operating system CSPRNG is available");
        assert_eq!(id.len(), 43);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(URL_SAFE_NO_PAD.decode(&id).expect("valid base64url")),
            id
        );
        assert_ne!(
            group_id().expect("the operating system CSPRNG is available"),
            id,
            "every group draws its own identifier"
        );
    }

    #[test]
    fn a_paused_stream_reports_the_position_the_pause_froze() {
        let stream = Stream {
            track: TrackInfo::default(),
            active: true,
            next_us: 1_000_000,
            position: Duration::from_millis(500),
            start_us: 0,
            start_position: Duration::ZERO,
            anchor_us: 0,
            wrote_any: true,
            pcm_carry: 0,
            anchor: None,
            held: VecDeque::new(),
        };
        assert_eq!(
            stream.position_at(800_000),
            Duration::from_millis(300),
            "200 ms of audio is still buffered and has not been heard yet"
        );
        assert_eq!(
            stream.position_at(1_200_000),
            Duration::from_millis(500),
            "a writer that fell behind does not extrapolate past the last chunk"
        );

        let during_lead = Stream {
            next_us: 1_000_000,
            start_us: 1_000_000,
            start_position: Duration::from_millis(100),
            position: Duration::from_millis(100),
            ..stream
        };
        assert_eq!(
            during_lead.audible_position(800_000),
            Duration::from_millis(100),
            "a pause before the segment starts freezes at its start position"
        );
    }

    #[test]
    fn bytes_are_dropped_without_a_running_stream() {
        let (events, _receiver) = mpsc::unbounded_channel();
        let group = Group::new(
            "a group".to_owned(),
            AudioFormat::pcm(48_000, 2, 16),
            events,
        )
        .expect("a group builds");
        assert_eq!(
            group.write_audio(&[], None),
            WriteOutcome::Dropped(WriteError::Empty),
            "an empty chunk has no playtime to schedule"
        );
        assert_eq!(
            group.write_audio(&[0u8; 4], None),
            WriteOutcome::Dropped(WriteError::Ended),
            "no stream is open, so there is no timeline to place bytes on"
        );

        group.open_stream(TrackInfo::default());
        group.pause();
        assert_eq!(
            group.write_audio(&[0u8; 4], None),
            WriteOutcome::Dropped(WriteError::Paused),
            "bytes written while the group is paused are dropped"
        );
    }

    #[test]
    fn a_controller_command_without_its_parameter_is_ignored() {
        let (events, _receiver) = mpsc::unbounded_channel();
        let group = Group::new(
            "a group".to_owned(),
            AudioFormat::pcm(48_000, 2, 16),
            events,
        )
        .expect("a group builds");

        let volume = ControllerCommand {
            command: "volume".to_owned(),
            ..ControllerCommand::default()
        };
        assert!(
            !group.apply_controller_command(&volume),
            "a volume command without a level is refused"
        );
        let mute = ControllerCommand {
            command: "mute".to_owned(),
            ..ControllerCommand::default()
        };
        assert!(
            !group.apply_controller_command(&mute),
            "a mute command without a state is refused"
        );
        let next = ControllerCommand {
            command: "next".to_owned(),
            ..ControllerCommand::default()
        };
        assert!(
            !group.apply_controller_command(&next),
            "a queue command belongs to the host, not to the group"
        );
    }

    #[test]
    fn a_member_with_capacity_one_is_skipped_for_every_chunk() {
        let group = test_group();
        let (id, mut receiver) = add_player_with_capacity(&group, 0, 0, 1);
        open_stream_reported(&group, id, &mut receiver);
        {
            let inner = group.lock();
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert!(
                !member.start_gate,
                "the start was reported, so the gate is not why nothing arrives"
            );
            assert_eq!(member.start_at, 0, "nor is the member's own start floor");
        }

        for _ in 0..2 {
            assert_eq!(
                group.write_audio(&[0u8; 480 * 4], None),
                WriteOutcome::Partial { skipped: 1 },
                "the group still schedules the chunk and says the member did not get it"
            );
        }
        assert!(
            drain_audio(&mut receiver).is_empty(),
            "not even one framed chunk fits into a one-byte capacity"
        );
        assert_eq!(sent_len(&group, id), 0, "a skipped chunk is not recorded");
    }

    #[test]
    fn a_member_with_room_receives_the_chunk_and_records_its_framed_length() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 0, 0);
        open_stream_reported(&group, id, &mut receiver);
        let timestamp_us = group.lock().stream.as_ref().expect("a stream").next_us;

        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        let (chunk, transmitted) = next_audio(&mut receiver);
        assert_eq!(
            chunk.len(),
            AudioChunkHeader::LEN + 480 * 4,
            "the accounted length is the framed one"
        );
        assert!(
            !transmitted.load(Ordering::Relaxed),
            "the connection task sets the ack after the socket write"
        );

        let inner = group.lock();
        let member = inner
            .members
            .iter()
            .find(|member| member.id == id)
            .expect("the member");
        assert_eq!(member.sent.len(), 1);
        assert_eq!(member.sent[0].timestamp_us, timestamp_us);
        assert_eq!(member.sent[0].duration, Duration::from_millis(10));
        assert_eq!(member.sent[0].bytes, chunk.len());
        assert!(
            Arc::ptr_eq(&member.sent[0].transmitted, &transmitted),
            "the member holds the same ack handle the connection task sets"
        );
    }

    #[test]
    fn a_chunk_that_exceeds_the_remaining_capacity_is_skipped_and_the_timeline_advances() {
        let group = test_group();
        let framed = AudioChunkHeader::LEN + 480 * 4;
        let (id, mut receiver) = add_player_with_capacity(&group, 0, 0, 2_000);
        open_stream_reported(&group, id, &mut receiver);
        let first = group.lock().stream.as_ref().expect("a stream").next_us;

        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        let (chunk, transmitted) = next_audio(&mut receiver);
        assert_eq!(chunk.len(), framed);
        let second = group.lock().stream.as_ref().expect("a stream").next_us;
        assert_eq!(second - first, 10_000);

        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Partial { skipped: 1 },
            "the host's write is scheduled and told that the member was skipped"
        );
        let third = group.lock().stream.as_ref().expect("a stream").next_us;
        assert_eq!(
            third - second,
            10_000,
            "the timeline advances for the whole group, not per member"
        );
        assert!(
            drain_audio(&mut receiver).is_empty(),
            "the second chunk does not fit behind the unacked first"
        );
        assert_eq!(sent_len(&group, id), 1);

        transmitted.store(true, Ordering::Relaxed);
        let retry = vec![0u8; framed];
        group.lock().send_audio(
            &retry,
            first + 20_000,
            Duration::from_millis(10),
            first + 20_000,
        );
        assert_eq!(
            sent_len(&group, id),
            1,
            "the acked past chunk is pruned before the count"
        );
        let (retried, _) = next_audio(&mut receiver);
        assert_eq!(
            retried.len(),
            framed,
            "a later chunk is tried again once the old one no longer counts"
        );
    }

    #[test]
    fn a_past_acked_chunk_is_pruned_and_a_future_one_stays() {
        let group = test_group();
        let framed = AudioChunkHeader::LEN + 480 * 4;
        let chunk = vec![0u8; framed];
        let (id, mut receiver) = add_player(&group, 0, 0);
        open_stream_reported(&group, id, &mut receiver);

        {
            let mut inner = group.lock();
            inner.send_audio(&chunk, 1_000_000, Duration::from_millis(10), 1_000_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert_eq!(member.sent.len(), 1);
            member.sent[0].transmitted.store(true, Ordering::Relaxed);
            // The raw end is 1_010_000, exactly now and therefore not in the future.
            inner.send_audio(&chunk, 2_000_000, Duration::from_millis(10), 1_010_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert_eq!(
                member.sent.len(),
                1,
                "the acked chunk whose playtime passed is pruned"
            );
            assert_eq!(member.sent[0].timestamp_us, 2_000_000);
        }

        {
            let mut inner = group.lock();
            // A 100 ms chunk whose raw end is still future at 3_050_000.
            inner.send_audio(&chunk, 3_000_000, Duration::from_millis(100), 3_000_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            for sent in &member.sent {
                sent.transmitted.store(true, Ordering::Relaxed);
            }
            inner.send_audio(&chunk, 3_050_000, Duration::from_millis(10), 3_050_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert_eq!(
                member.sent.len(),
                2,
                "the past chunk is pruned and the future one stays"
            );
            assert!(
                member
                    .sent
                    .iter()
                    .any(|sent| sent.timestamp_us == 3_000_000),
                "a chunk whose raw end is future stays for a possible delay change"
            );
        }
    }

    #[test]
    fn a_delay_decrease_re_counts_a_chunk_whose_raw_end_is_future() {
        let group = test_group();
        let framed = AudioChunkHeader::LEN + 480 * 4;
        let chunk = vec![0u8; framed];
        let (id, mut receiver) = add_player_with_capacity(&group, 0, 0, framed as u64 + 100);
        open_stream_reported(&group, id, &mut receiver);

        {
            let mut inner = group.lock();
            inner.send_audio(&chunk, 1_000_000, Duration::from_millis(100), 1_000_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            member.sent[0].transmitted.store(true, Ordering::Relaxed);
        }
        // With a 90 ms output delay the completion (1_010_000) is past at 1_050_000, so the
        // acked chunk does not count - but its raw end (1_100_000) is still future.
        report_timing(&group, id, 0, 90);
        {
            let mut inner = group.lock();
            inner.send_audio(&chunk, 1_050_000, Duration::from_millis(100), 1_050_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert_eq!(
                member.sent.len(),
                2,
                "a chunk that could count again is kept until its raw end passes"
            );
            member.sent[1].transmitted.store(true, Ordering::Relaxed);
        }

        // Dropping the delay back to zero makes both completions future again: together they
        // exceed the capacity, so the next chunk is skipped.
        report_timing(&group, id, 0, 0);
        {
            let mut inner = group.lock();
            inner.send_audio(&chunk, 1_100_000, Duration::from_millis(100), 1_050_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert_eq!(
                member.sent.len(),
                2,
                "the delay decrease re-counts the retained chunk and leaves no room"
            );
        }
    }

    #[test]
    fn the_count_uses_the_members_current_output_delay() {
        let group = test_group();
        let framed = AudioChunkHeader::LEN + 480 * 4;
        let chunk = vec![0u8; framed];
        let (id, mut receiver) = add_player_with_capacity(&group, 0, 0, framed as u64);
        open_stream_reported(&group, id, &mut receiver);

        {
            let mut inner = group.lock();
            inner.send_audio(&chunk, 1_000_000, Duration::from_millis(100), 1_000_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            member.sent[0].transmitted.store(true, Ordering::Relaxed);
            // Completion 1_100_000 > 1_050_000: the chunk still counts and fills the capacity.
            inner.send_audio(&chunk, 1_050_000, Duration::from_millis(100), 1_050_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert_eq!(member.sent.len(), 1, "the counted chunk leaves no room");
        }

        // A 90 ms delay moves the completion to 1_010_000, past at 1_050_000, so the same chunk
        // no longer counts and the next one fits.
        report_timing(&group, id, 0, 90);
        {
            let mut inner = group.lock();
            inner.send_audio(&chunk, 1_050_000, Duration::from_millis(100), 1_050_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert_eq!(
                member.sent.len(),
                2,
                "the count follows the member's current output delay"
            );
        }
    }

    #[test]
    fn a_reset_report_clears_the_sent_list_and_an_in_place_start_does_not() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 0, 0);
        open_stream_reported(&group, id, &mut receiver);
        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        assert_eq!(sent_len(&group, id), 1);

        group.open_stream(TrackInfo {
            title: Some("the next track".to_owned()),
            ..TrackInfo::default()
        });
        let (clear, epoch, anchor, reset) = next_trigger(&mut receiver);
        assert!(matches!(clear, Incoming::StreamClear(_)));
        assert!(anchor && reset);
        assert_eq!(
            sent_len(&group, id),
            1,
            "neither the clear's send nor the in-place start resets the list"
        );
        mark_transmitted(&group, id);
        group.trigger_sent(id, epoch, anchor, reset, Some(group.now_us() + 1_000_000));
        assert_eq!(sent_len(&group, id), 0, "the clear's report is the reset");

        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        assert_eq!(sent_len(&group, id), 1);
        group.end_stream();
        let (end, epoch, anchor, reset) = next_trigger(&mut receiver);
        assert!(matches!(end, Incoming::StreamEnd(_)));
        assert!(!anchor && reset);
        assert_eq!(sent_len(&group, id), 1, "the end's send does not reset yet");
        mark_transmitted(&group, id);
        group.trigger_sent(id, epoch, anchor, reset, None);
        assert_eq!(sent_len(&group, id), 0, "the end's report is a reset");
    }

    #[test]
    fn a_gated_or_not_yet_started_member_is_skipped_until_its_start_passes() {
        let group = test_group();
        let framed = AudioChunkHeader::LEN + 480 * 4;
        let chunk = vec![0u8; framed];
        let (id, mut receiver) = add_player(&group, 0, 0);
        open_stream_reported(&group, id, &mut receiver);

        {
            let mut inner = group.lock();
            let member = inner
                .members
                .iter_mut()
                .find(|member| member.id == id)
                .expect("the member");
            member.start_gate = true;
            inner.send_audio(&chunk, 1_000_000, Duration::from_millis(10), 1_000_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert_eq!(member.sent.len(), 0, "a gated member receives nothing");

            let member = inner
                .members
                .iter_mut()
                .find(|member| member.id == id)
                .expect("the member");
            member.start_gate = false;
            member.start_at = 2_000_000;
            inner.send_audio(&chunk, 1_999_999, Duration::from_millis(10), 2_000_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert_eq!(
                member.sent.len(),
                0,
                "a chunk before the member's own start is skipped"
            );

            inner.send_audio(&chunk, 2_000_000, Duration::from_millis(10), 2_000_000);
            let member = inner
                .members
                .iter()
                .find(|member| member.id == id)
                .expect("the member");
            assert_eq!(
                member.sent.len(),
                1,
                "the chunk at the member's start is delivered"
            );
            assert_eq!(
                member.start_at, 0,
                "the first delivered chunk clears the floor"
            );
        }
        let (received, _) = next_audio(&mut receiver);
        assert_eq!(received.len(), framed);
    }

    #[test]
    fn an_unavailable_member_receives_nothing_and_adds_nothing() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 0, 0);
        open_stream_reported(&group, id, &mut receiver);
        group.report_client_state(
            id,
            &ClientState {
                available: false,
                player: None,
                ..Default::default()
            },
        );

        assert_eq!(
            group.write_audio(&[0u8; 480 * 4], None),
            WriteOutcome::Written
        );
        assert!(
            drain_audio(&mut receiver).is_empty(),
            "an announced but unavailable member receives no audio"
        );
        assert_eq!(
            sent_len(&group, id),
            0,
            "nothing is added to a member that receives nothing"
        );
    }

    #[test]
    fn an_unavailable_member_misses_a_jumps_start_and_the_next_pause_end() {
        let group = test_group();
        let (id, mut receiver) = add_player(&group, 100, 0);
        open_stream_reported(&group, id, &mut receiver);
        group.report_client_state(
            id,
            &ClientState {
                available: false,
                player: None,
                ..Default::default()
            },
        );

        // A track jump still reaches the announced member with the clear, because it must discard
        // its buffers, but the unavailable member gets no start for the new stream.
        group.open_stream(TrackInfo {
            title: Some("the next track".to_owned()),
            ..TrackInfo::default()
        });
        let jump = stream_messages(&mut receiver);
        assert_eq!(
            jump.len(),
            1,
            "a jump sends one stream message to the member"
        );
        assert!(
            matches!(jump[0], Incoming::StreamClear(_)),
            "the announced member is cleared"
        );

        // The pause ends only the streams the group has announced, and this member lost its
        // announcement at the jump, so it hears no end for the stream it does not have.
        group.pause();
        assert!(
            stream_messages(&mut receiver).is_empty(),
            "an unavailable member that lost the announced stream hears no pause end"
        );

        // The play restart also skips it while it stays unavailable.
        group.play();
        assert!(
            stream_messages(&mut receiver).is_empty(),
            "the unavailable member gets no start from the play restart"
        );

        // Its return is what gets the new stream's start.
        report_timing(&group, id, 100, 0);
        let returned = stream_messages(&mut receiver);
        assert_eq!(returned.len(), 1, "the returning member is announced once");
        assert!(
            matches!(returned[0], Incoming::StreamStart(_)),
            "the return gets the new stream's start, not the old track's"
        );
    }

    #[test]
    fn a_report_for_a_member_that_already_left_is_dropped() {
        let (events, _receiver) = mpsc::unbounded_channel();
        let group = Group::new(
            "a group".to_owned(),
            AudioFormat::pcm(48_000, 2, 16),
            events,
        )
        .expect("a group builds");

        group.report_client_state(
            123,
            &ClientState {
                available: true,
                player: None,
                ..Default::default()
            },
        );
        group.open_stream(TrackInfo::default());
        assert_eq!(
            group.write_audio(&[0u8; 4], None),
            WriteOutcome::Written,
            "a stale report must not disturb the group's stream"
        );
    }
}
