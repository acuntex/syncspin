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
//! reading cannot block the host that pushes audio. A queue that grows without bound is the price;
//! bounding it, and deciding which chunks a slow client loses, is the next milestone's problem.
//!
//! Two rules the specification states govern when a member hears anything. A stream is announced
//! only to a member whose `client/state` reports both the `player` object the activation requires
//! and `available: true`; a member that reports itself unavailable keeps its group but receives no
//! audio until it reports again. And `stream/start` carrying the `player` object requires the
//! `playback` activity on the connection, so the group declares it on every member while the group
//! plays and drops it when playback stops.
//!
//! One rule this milestone does not keep: the start lead is one fixed value instead of each
//! player's reported buffer and lead time (see `docs/spec-deviations.md`).

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use syncspin_core::messages::{
    AudioChunkHeader, ClientState, ControllerCommand, ControllerState, GroupUpdate, Incoming,
    Metadata, Progress, ServerActivate, ServerState, StreamClear, StreamEnd, StreamStart,
};
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

/// How far ahead of now the first sample of a stream is scheduled.
///
/// The specification requires at least `min_buffer_ms` + `output_delay_ms` per player, and the
/// maximum across the group for grouped playback; the group schedules one shared timeline for every
/// member, so it uses one fixed lead for all of them. Doing better means deriving the lead from
/// the largest of those values among the ready players, which is the change
/// `docs/spec-deviations.md` names.
pub(crate) const START_LEAD: Duration = Duration::from_millis(200);

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
    /// One audio chunk, already framed with its message id and header.
    Audio(Vec<u8>),
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
}

/// The group of one server.
#[derive(Debug)]
pub(crate) struct Group {
    clock: Clock,
    events: mpsc::UnboundedSender<Event>,
    inner: Mutex<Inner>,
}

impl Group {
    /// Builds the group of a server that serves `format` under `name`.
    pub(crate) fn new(
        name: String,
        format: AudioFormat,
        events: mpsc::UnboundedSender<Event>,
    ) -> anyhow::Result<Arc<Group>> {
        Ok(Arc::new(Group {
            clock: Clock::new(),
            events,
            inner: Mutex::new(Inner {
                format,
                group_name: name,
                group_id: group_id()?,
                volume: 100,
                muted: false,
                playing: false,
                members: Vec::new(),
                stream: None,
                next_member_id: 0,
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
    /// announces it then.
    pub(crate) fn join(&self, roles: Vec<String>, sender: mpsc::UnboundedSender<Outbound>) -> u64 {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let id = inner.next_member_id;
        inner.next_member_id = inner.next_member_id.wrapping_add(1);

        let mut state = ServerState::default();
        if roles.iter().any(|role| role == CONTROLLER_ROLE) {
            state.controller = Some(inner.controller());
        }
        if roles.iter().any(|role| role == METADATA_ROLE) {
            state.metadata = Some(inner.metadata(now));
        }
        if state.controller.is_some() || state.metadata.is_some() {
            send_to(&sender, Incoming::ServerState(state));
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
    /// whether the member is available and whether its `player` object has arrived - and a member
    /// that becomes ready while a stream runs receives that stream from here.
    pub(crate) fn report_client_state(&self, member: u64, state: &ClientState) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let Some(index) = inner.members.iter().position(|held| held.id == member) else {
            return;
        };
        let held = &mut inner.members[index];
        held.available = state.available;
        if state.player.is_some() {
            held.player_reported = true;
        }
        inner.start_member_stream(index, now);
    }

    /// Removes a connection from the group.
    ///
    /// Its role reports are gone with it; the group state itself is the server's and survives.
    pub(crate) fn leave(&self, member: u64) {
        self.lock().members.retain(|held| held.id != member);
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
    /// ends the player stream and a resumed one needs a new `stream/start` before its audio.
    pub(crate) fn play(&self) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let restart = inner.stream.as_ref().is_some_and(|stream| !stream.active);
        inner.playing = true;
        if restart {
            if let Some(stream) = inner.stream.as_mut() {
                stream.active = true;
                stream.next_us = now.saturating_add(lead_us());
            }
            inner.start_streams(now);
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
    /// first is the specification's treatment of a track jump.
    ///
    /// Opening a stream means audio is playing, so the group reports `playing` from here on; the
    /// host does not have to call [`Group::play`] as well.
    pub(crate) fn open_stream(&self, track: TrackInfo) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        if inner.stream.as_ref().is_some_and(|stream| stream.active) {
            inner.send_stream_clear(now);
            // The players keep their stream open across the clear, but the new track announces its
            // format again, so every ready player is told once more.
            inner.forget_stream_starts();
        }
        let was_playing = inner.playing;
        inner.playing = true;
        inner.stream = Some(Stream {
            track,
            active: true,
            next_us: now.saturating_add(lead_us()),
            position: Duration::ZERO,
        });
        if !was_playing {
            inner.send_group_update();
        }
        inner.start_streams(now);
        inner.send_metadata(now);
        let _ = self.events.send(Event::StreamStarted);
    }

    /// Sends one chunk to every player and advances the timeline.
    ///
    /// The chunk is checked before the timeline moves, so a refused chunk leaves no hole for the
    /// next one. `duration` is the host's playtime for a compressed format, and must be absent for
    /// PCM, whose playtime follows from its frame count. Bytes written to a paused or ended stream
    /// are dropped, because there is no timeline to place them on.
    pub(crate) fn write_audio(&self, bytes: &[u8], duration: Option<Duration>) -> WriteOutcome {
        if bytes.is_empty() || duration == Some(Duration::ZERO) {
            return WriteOutcome::Dropped(WriteError::Empty);
        }
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let format = inner.format.clone();
        let duration = match (&format.codec, duration) {
            (Codec::Pcm, None) => {
                if bytes.len() % format.frame_bytes() != 0 {
                    return WriteOutcome::Dropped(WriteError::Incomplete);
                }
                format.duration(bytes.len())
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
        let chunk = {
            let Some(stream) = inner.stream.as_mut() else {
                return WriteOutcome::Dropped(WriteError::Ended);
            };
            if !stream.active {
                return WriteOutcome::Dropped(WriteError::Paused);
            }
            let timestamp_us = stream.next_us;
            stream.next_us = timestamp_us.saturating_add(micros_i64(duration));
            stream.position = stream.position.saturating_add(duration);
            AudioChunkHeader {
                timestamp_us,
                send_ahead: send_ahead(timestamp_us, now),
            }
            .encode(bytes)
        };
        inner.send_audio(&chunk);
        WriteOutcome::Written
    }

    /// Moves the stream to `position` and drops what the players have buffered.
    ///
    /// A seek is a `stream/clear` without `from_timestamp`, and the specification prices the
    /// restart as a disturbance: the first chunk after it is scheduled a full lead ahead.
    pub(crate) fn seek(&self, position: Duration) {
        let now = self.clock.now_us();
        let mut inner = self.lock();
        let Some(stream) = inner.stream.as_mut() else {
            return;
        };
        let position = stream
            .track
            .duration
            .map_or(position, |duration| position.min(duration));
        let active = stream.active;
        stream.position = position;
        stream.next_us = now.saturating_add(lead_us());
        if active {
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
    /// The timestamp is always present and never in the future, so the first state of a role brings
    /// a client up to date instead of scheduling an update.
    fn metadata(&self, now_us: i64) -> Metadata {
        let (title, artist, album_artist, album, duration, position) = match &self.stream {
            Some(stream) => {
                let track = &stream.track;
                let position = if stream.active {
                    stream.position_at(now_us)
                } else {
                    stream.position
                };
                (
                    track.title.clone(),
                    track.artist.clone(),
                    track.album_artist.clone(),
                    track.album.clone(),
                    track.duration,
                    Some(position),
                )
            }
            None => (None, None, None, None, None, None),
        };
        Metadata {
            timestamp: Some(now_us),
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
    fn stream_start(&self, now_us: i64) -> Incoming {
        Incoming::StreamStart(StreamStart {
            server_transmitted: now_us,
            player: Some(self.format.stream_start()),
        })
    }

    /// Sends the controller half of `server/state` to every controller.
    fn send_controller(&self) {
        let state = Incoming::ServerState(ServerState {
            controller: Some(self.controller()),
            metadata: None,
        });
        self.send(&state, |member| member.has(CONTROLLER_ROLE));
    }

    /// Sends the metadata half of `server/state` to every metadata role.
    fn send_metadata(&self, now_us: i64) {
        let state = Incoming::ServerState(ServerState {
            controller: None,
            metadata: Some(self.metadata(now_us)),
        });
        self.send(&state, |member| member.has(METADATA_ROLE));
    }

    /// Sends `group/update` to every member.
    fn send_group_update(&self) {
        self.send(&Incoming::GroupUpdate(self.group_update()), |_| true);
    }

    /// Declares the playback activity and announces the running stream to every ready player.
    ///
    /// A member whose activation is older than the playback state gets a `server/activate` first,
    /// because a `stream/start` carrying the `player` object is only allowed on a connection that
    /// declares `playback`. The caller has already set [`Inner::playing`].
    fn start_streams(&mut self, now_us: i64) {
        for index in 0..self.members.len() {
            self.start_member_stream(index, now_us);
        }
    }

    /// Announces the running stream to one member, if that member may receive it now.
    fn start_member_stream(&mut self, index: usize, now_us: i64) {
        if !self.playing {
            return;
        }
        self.declare_playback(index);
        let start = self.stream_start(now_us);
        let member = &mut self.members[index];
        if member.stream_announced || !member.plays() {
            return;
        }
        member.stream_announced = true;
        let _ = member.sender.send(Outbound::Message(Box::new(start)));
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
    fn send_stream_clear(&self, now_us: i64) {
        let message = Incoming::StreamClear(StreamClear {
            server_transmitted: now_us,
            from_timestamp: None,
            roles: Some(vec![PLAYER_STREAM.to_owned()]),
        });
        self.send(&message, |member| member.stream_announced);
    }

    /// Sends a `stream/end` for the player stream to every player that has one.
    fn send_stream_end(&mut self) {
        let message = Incoming::StreamEnd(StreamEnd {
            roles: Some(vec![PLAYER_STREAM.to_owned()]),
        });
        for member in self.members.iter_mut() {
            if !member.stream_announced {
                continue;
            }
            member.stream_announced = false;
            let _ = member
                .sender
                .send(Outbound::Message(Box::new(message.clone())));
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
    /// translates them with its own clock estimate.
    fn send_audio(&self, chunk: &[u8]) {
        for member in self.members.iter().filter(|member| member.streams()) {
            let _ = member.sender.send(Outbound::Audio(chunk.to_vec()));
        }
    }

    /// Stops the player stream if it is running and freezes its position.
    ///
    /// Returns whether there was a stream to end.
    fn end_player_stream(&mut self, now_us: i64) -> bool {
        let running = self.stream.as_ref().is_some_and(|stream| stream.active);
        if !running {
            return false;
        }
        if let Some(stream) = self.stream.as_mut() {
            stream.position = stream.position_at(now_us);
            stream.active = false;
        }
        self.send_stream_end();
        true
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

/// The lead from a chunk's timestamp back to its transmission, saturating as the wire requires.
fn send_ahead(timestamp_us: i64, now_us: i64) -> u32 {
    match timestamp_us.saturating_sub(now_us) {
        lead if lead <= 0 => 0,
        lead => u32::try_from(lead).unwrap_or(u32::MAX),
    }
}

/// The configured start lead in microseconds.
fn lead_us() -> i64 {
    micros_i64(START_LEAD)
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
    }

    #[test]
    fn the_start_lead_is_what_a_player_can_buffer() {
        assert_eq!(lead_us(), 200_000);
    }

    #[test]
    fn send_ahead_saturates_instead_of_wrapping() {
        assert_eq!(send_ahead(1_000, 500), 500);
        assert_eq!(send_ahead(500, 500), 0, "no lead measures as zero");
        assert_eq!(send_ahead(400, 500), 0, "a late chunk reports no lead");
        assert_eq!(send_ahead(i64::MAX, 0), u32::MAX);
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
