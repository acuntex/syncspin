//! The connection state machine: Noise handshake, clock estimate, dispatch and audio delivery.
//!
//! The session is created after the WebSocket is open and runs until the connection ends. It
//! never speaks to a server without Noise: only the init exchange and the two Noise handshake
//! messages travel as cleartext text, and every application message is a Noise transport message.
//! A server that does not start the handshake times out; there is no plaintext path to fall back
//! to.

use std::future::pending;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use syncspin_core::clock::{ClockFilter, TimeSample};
use syncspin_core::framing::{
    encode_binary, Reassembler, BINARY_MESSAGE_ID_JSON, MAX_REASSEMBLED_LEN,
};
use syncspin_core::messages::{
    AudioChunkHeader, ClientCommand, ClientHello, ClientInit, ClientState, ClientTime,
    ControllerCommand, Incoming, NoiseHandshake, PairingPskMethod, PlayerState, PlayerSupport,
    ServerActivate, ServerCommand, ServerState, ServerTime, StreamClear, StreamStart,
    SupportedFormat, SupportedPairMethods, UnpairedAccess, AUDIO_CHUNK_ID, NOISE_SUITE,
    PROTOCOL_VERSION,
};
use syncspin_core::noise::{
    psk_id_for, Responder, TransportState as NoiseTransport, SENTINEL_PSK, SENTINEL_PSK_ID,
};

use crate::client::{clamp_volume, ControlAction, ControlRequest, Event, PlaybackState};
use crate::config::{AudioMode, ClientConfig, PskCategory, StoredPsk};
use crate::sink::{AudioFormat, AudioFrame, Codec, Sink};

/// How long the Noise handshake may take, from `client/init` to the first `server/activate`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of `client/time` round trips in one clock-sync burst.
const SYNC_MESSAGES: usize = 8;

/// How long to wait for one `server/time` reply before sending the next request.
///
/// The spec allows the client to move on without a reply after a timeout of its choosing.
const SYNC_REPLY_TIMEOUT: Duration = Duration::from_millis(250);

/// Overall cap on one burst, so a peer that stalls cannot hold the session loop.
const SYNC_BURST_TIMEOUT: Duration = Duration::from_secs(2);

/// Minimum spacing between consecutive sync bursts, so a long stream keeps tracking the clock.
const RESYNC_INTERVAL: Duration = Duration::from_secs(5);

/// Versioned role identifier of the audio player.
const PLAYER_ROLE: &str = "player@v1";

/// Versioned role identifier of the now-playing metadata.
const METADATA_ROLE: &str = "metadata@v1";

/// Versioned role identifier of the group controller state.
const CONTROLLER_ROLE: &str = "controller@v1";

/// Largest output delay reported to the server, in milliseconds.
const MAX_OUTPUT_DELAY_MS: u32 = 5_000;

/// Startup lead time reported to the server, in milliseconds.
const REQUIRED_LEAD_TIME_MS: u32 = 250;

/// Buffer the server should keep filled, in milliseconds.
const MIN_BUFFER_MS: u32 = 250;

/// Largest total size of outstanding audio chunks this client accepts.
const BUFFER_CAPACITY: u64 = 131_072;

/// Sample rate of the formats this client advertises, in hertz.
const SUPPORTED_SAMPLE_RATE: u32 = 48_000;

/// Channel count of the formats this client advertises.
const SUPPORTED_CHANNELS: u8 = 2;

/// Bit depth of the formats this client advertises.
const SUPPORTED_BIT_DEPTH: u8 = 16;

/// Length of a canonical unpadded base64url key id.
const PSK_ID_LEN: usize = 43;

/// Player commands this client accepts from the server.
const PLAYER_COMMANDS: [&str; 2] = ["volume", "mute"];

/// An established WebSocket connection to a server.
///
/// This is the socket layer only: cleartext JSON during the handshake, one Noise transport
/// message per binary frame afterwards. Control frames are answered here so the session only sees
/// application messages.
pub(crate) struct Transport {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

/// One application message read from the socket.
pub(crate) enum SocketMessage {
    /// A cleartext JSON text frame.
    Text(String),
    /// One Noise transport message.
    Binary(Vec<u8>),
    /// The peer closed the connection.
    Closed,
}

impl Transport {
    /// Opens a plain WebSocket connection to `url`.
    pub(crate) async fn connect(url: &str) -> Result<Transport> {
        let (socket, _response) = tokio_tungstenite::connect_async(url)
            .await
            .with_context(|| format!("failed to connect to the server at {url}"))?;
        Ok(Transport { socket })
    }

    /// Reads the next application message, answering pings on the way.
    pub(crate) async fn read(&mut self) -> Result<SocketMessage> {
        loop {
            let message = self
                .socket
                .next()
                .await
                .transpose()
                .context("the WebSocket read failed")?;
            match message {
                Some(Message::Text(text)) => {
                    return Ok(SocketMessage::Text(text.as_str().to_owned()))
                }
                Some(Message::Binary(bytes)) => return Ok(SocketMessage::Binary(bytes.to_vec())),
                Some(Message::Ping(payload)) => {
                    self.socket
                        .send(Message::Pong(payload))
                        .await
                        .context("the WebSocket pong failed")?;
                }
                Some(Message::Pong(_)) | Some(Message::Frame(_)) => continue,
                Some(Message::Close(_)) | None => return Ok(SocketMessage::Closed),
            }
        }
    }

    /// Sends one cleartext JSON text frame.
    pub(crate) async fn send_text(&mut self, text: &str) -> Result<()> {
        self.socket
            .send(Message::text(text))
            .await
            .context("the WebSocket send failed")
    }

    /// Sends one binary frame.
    pub(crate) async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.socket
            .send(Message::binary(bytes))
            .await
            .context("the WebSocket send failed")
    }
}

/// A handshake result: the connection is encrypted and the roles are known.
struct Ready {
    transport: Transport,
    noise: NoiseTransport,
    server_id: String,
    active_roles: Vec<String>,
}

/// State a connection keeps across attempts.
pub(crate) struct Carried {
    /// Audio output, moved into each session and returned when it ends.
    pub(crate) sink: Box<dyn Sink>,
    /// Control requests, or `None` once every handle was dropped.
    pub(crate) control: Option<mpsc::UnboundedReceiver<ControlRequest>>,
    /// Level in force, in the protocol's 0-100 range.
    pub(crate) volume: u8,
    /// Mute state in force.
    pub(crate) muted: bool,
    /// Roles the last session had active.
    pub(crate) active_roles: Vec<String>,
}

/// How one connection attempt ended.
pub(crate) enum Ending {
    /// The server closed the connection.
    Closed,
    /// The attempt failed.
    Failed(anyhow::Error),
}

impl Ending {
    /// The reason reported in [`Event::Disconnected`], without key material.
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::Closed => "the server closed the connection".to_owned(),
            Self::Failed(error) => format!("{error:#}"),
        }
    }
}

/// The result of one connection attempt.
pub(crate) struct Attempt {
    /// State the next attempt starts from.
    pub(crate) carried: Carried,
    /// Whether the attempt reported [`Event::Connected`].
    pub(crate) connected: bool,
    /// Whether the audio sink failed; a new attempt cannot repair it.
    pub(crate) sink_failed: bool,
    /// How the attempt ended.
    pub(crate) ending: Ending,
}

/// One wake-up of the session loop.
enum Wakeup {
    /// A control handle sent a request, or every handle was dropped.
    Control(Option<ControlRequest>),
    /// The socket produced a message, or the read failed.
    Socket(Result<SocketMessage>),
    /// The clock deadline elapsed.
    Clock,
}

/// A running session.
pub(crate) struct Session<'a> {
    transport: Transport,
    noise: NoiseTransport,
    config: &'a ClientConfig,
    sink: Box<dyn Sink>,
    events: &'a mpsc::UnboundedSender<Event>,
    /// Level shared with every control handle; the session is its only writer.
    reported_volume: &'a AtomicU8,
    clock: ClockFilter,
    reassembler: Reassembler,
    active_roles: Vec<String>,
    stream: Option<AudioFormat>,
    /// Remaining `client/time` messages of the current burst (0 = no burst running).
    sync_remaining: usize,
    /// Deadline for the current burst, or `None` when no burst is running.
    burst_deadline: Option<Instant>,
    /// Deadline for the reply to the request on the wire, or `None` when no reply is outstanding.
    reply_deadline: Option<Instant>,
    /// Transmit timestamp of the request on the wire, used to recognise its reply.
    outstanding_sent_us: Option<i64>,
    /// When the current or last burst started, for periodic re-sync spacing.
    burst_started: Option<Instant>,
    /// Samples collected during the current burst; only the best one is pushed.
    burst_samples: Vec<TimeSample>,
    /// Whether the player state was reported since the player role last became active.
    state_sent: bool,
    /// Requests from a [`crate::ControlHandle`], or `None` once every handle was dropped.
    control: Option<mpsc::UnboundedReceiver<ControlRequest>>,
    /// Output level in force, in the protocol's 0-100 range.
    volume: u8,
    /// Mute state in force.
    muted: bool,
    /// Whether a sink call failed, which the host has to repair before another attempt.
    sink_failed: bool,
    /// Controller commands the server last advertised, or `None` before its first controller
    /// state.
    controller_commands: Option<Vec<String>>,
}

/// Runs one connection attempt: the handshake, then the session loop.
///
/// Every failure after the WebSocket is open - handshake, protocol, transport or sink - ends the
/// attempt and is reported by the caller as one [`Event::Disconnected`]. The state the next
/// attempt starts from comes back in the result, so the sink, the level, the mute state and the
/// roles survive the drop.
pub(crate) async fn attempt(
    transport: Transport,
    config: &ClientConfig,
    events: &mpsc::UnboundedSender<Event>,
    psks: &[StoredPsk],
    reported_volume: &AtomicU8,
    carried: Carried,
) -> Attempt {
    let handshake = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake(transport, config, psks, &carried.active_roles),
    )
    .await;
    let ready = match handshake {
        Ok(result) => result,
        Err(_elapsed) => Err(anyhow!("timed out during the Noise handshake")),
    };
    let ready = match ready {
        Ok(ready) => ready,
        Err(error) => {
            return Attempt {
                carried,
                connected: false,
                sink_failed: false,
                ending: Ending::Failed(error),
            };
        }
    };

    let mut session = Session {
        transport: ready.transport,
        noise: ready.noise,
        config,
        sink: carried.sink,
        events,
        reported_volume,
        clock: ClockFilter::new(),
        reassembler: Reassembler::new(MAX_REASSEMBLED_LEN),
        active_roles: ready.active_roles,
        stream: None,
        sync_remaining: 0,
        burst_deadline: None,
        reply_deadline: None,
        outstanding_sent_us: None,
        burst_started: None,
        burst_samples: Vec::new(),
        state_sent: false,
        control: carried.control,
        volume: carried.volume,
        muted: carried.muted,
        sink_failed: false,
        controller_commands: None,
    };
    session.publish_volume();

    session.emit(Event::Connected {
        server_id: ready.server_id,
        encrypted: true,
    });
    if session.player_active() {
        session.start_burst();
    }

    let ending = match session.serve().await {
        Ok(()) => Ending::Closed,
        Err(error) => Ending::Failed(error),
    };
    let sink_failed = session.sink_failed;
    let carried = session.into_carried();
    Attempt {
        carried,
        connected: true,
        sink_failed,
        ending,
    }
}

impl Session<'_> {
    /// Returns the state the next attempt starts from.
    fn into_carried(self) -> Carried {
        Carried {
            sink: self.sink,
            control: self.control,
            volume: self.volume,
            muted: self.muted,
            active_roles: self.active_roles,
        }
    }

    /// Reads, dispatches and delivers until the connection ends.
    async fn serve(&mut self) -> Result<()> {
        loop {
            if self.events.is_closed() {
                return Ok(());
            }

            self.drive_clock().await?;

            // While a request is on the wire the read has its reply deadline; the overall burst
            // deadline is the backstop. Any other frame still arrives normally, and a control
            // request is served between frames.
            let deadline = match (self.reply_deadline, self.burst_deadline) {
                (Some(reply), Some(burst)) => Some(reply.min(burst)),
                (Some(reply), None) => Some(reply),
                (None, Some(burst)) => Some(burst),
                (None, None) => None,
            };

            // The control receiver outlives individual handles: dropping the last one disables the
            // branch instead of ending the session.
            let control = &mut self.control;
            let wakeup = tokio::select! {
                biased;
                request = async {
                    match control {
                        Some(receiver) => receiver.recv().await,
                        None => pending().await,
                    }
                } => Wakeup::Control(request),
                message = self.transport.read() => Wakeup::Socket(message),
                () = async {
                    match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                        None => pending().await,
                    }
                } => Wakeup::Clock,
            };

            match wakeup {
                Wakeup::Control(Some(request)) => self.handle_control(request).await?,
                Wakeup::Control(None) => self.control = None,
                Wakeup::Socket(message) => match message? {
                    SocketMessage::Text(_) => {
                        bail!("cleartext text after the Noise transport is a protocol error")
                    }
                    // The caller turns the end into a Disconnected event and schedules the next
                    // attempt, so the sink, the level and the roles survive the drop.
                    SocketMessage::Closed => return Ok(()),
                    SocketMessage::Binary(ciphertext) => self.receive(&ciphertext).await?,
                },
                Wakeup::Clock => self.handle_clock_timeout().await?,
            }
        }
    }

    /// Sends the next `client/time` request of the current burst when one is due.
    ///
    /// The spec requires one request at a time: the next goes out after the reply arrives or after
    /// a short per-message timeout, whichever comes first. The burst's measurements are buffered
    /// and only the one with the smallest positive error bound reaches the clock filter.
    async fn drive_clock(&mut self) -> Result<()> {
        if self.sync_remaining == 0
            && self.burst_deadline.is_none()
            && self.reply_deadline.is_none()
            && self.player_active()
            && self.burst_due()
        {
            self.start_burst();
        }

        if self.sync_remaining > 0 && self.reply_deadline.is_none() {
            let client_transmitted = now_us();
            let request = Incoming::ClientTime(ClientTime { client_transmitted });
            self.send_json(&request).await?;
            self.outstanding_sent_us = Some(client_transmitted);
            self.sync_remaining -= 1;
            self.reply_deadline = Some(Instant::now() + SYNC_REPLY_TIMEOUT);
        }
        Ok(())
    }

    /// Whether a burst is due.
    ///
    /// The clock needs more than one burst to be usable, so the first bursts follow each other
    /// immediately; afterwards a burst is due when the player state has not been reported yet, and
    /// then on the re-sync interval.
    fn burst_due(&self) -> bool {
        !self.clock.is_ready() || !self.state_sent || self.resync_due()
    }

    /// Whether a periodic re-sync burst is due.
    fn resync_due(&self) -> bool {
        match self.burst_started {
            None => true,
            Some(started) => started.elapsed() >= RESYNC_INTERVAL,
        }
    }

    /// Starts a sync burst of [`SYNC_MESSAGES`] `client/time` round trips.
    fn start_burst(&mut self) {
        self.sync_remaining = SYNC_MESSAGES;
        self.burst_deadline = Some(Instant::now() + SYNC_BURST_TIMEOUT);
        self.reply_deadline = None;
        self.outstanding_sent_us = None;
        self.burst_started = Some(Instant::now());
        self.burst_samples.clear();
    }

    /// Handles the deadline that fired while waiting for a reply.
    ///
    /// A per-message timeout moves the burst on to its next request; when the last request has no
    /// reply, or the overall burst deadline elapsed, the burst ends with the measurements it has.
    async fn handle_clock_timeout(&mut self) -> Result<()> {
        let burst_expired = self
            .burst_deadline
            .is_some_and(|deadline| deadline <= Instant::now());
        if burst_expired {
            return self.finish_burst().await;
        }
        self.reply_deadline = None;
        self.outstanding_sent_us = None;
        if self.sync_remaining == 0 {
            self.finish_burst().await?;
        }
        Ok(())
    }

    /// Ends the current burst: pushes its best measurement and reports the state if it is still
    /// owed (a burst with no usable reply reports nothing).
    async fn finish_burst(&mut self) -> Result<()> {
        self.burst_deadline = None;
        self.reply_deadline = None;
        self.outstanding_sent_us = None;
        if let Some(sample) = best_sample(&self.burst_samples) {
            self.clock.push(sample);
        }
        self.burst_samples.clear();
        if !self.state_sent && self.clock.sample_count() >= 1 && self.player_active() {
            self.send_client_state().await?;
        }
        Ok(())
    }

    /// Decrypts one transport message and dispatches the message it carries.
    async fn receive(&mut self, ciphertext: &[u8]) -> Result<()> {
        let plaintext = self.noise.decrypt(ciphertext)?;
        let Some((id, body)) = self.reassembler.push(&plaintext)? else {
            return Ok(());
        };
        match id {
            BINARY_MESSAGE_ID_JSON => {
                let text =
                    std::str::from_utf8(&body).context("decrypted JSON is not valid UTF-8")?;
                self.handle_json(text).await
            }
            AUDIO_CHUNK_ID => self.handle_audio(&body),
            // A message id belongs to a role this client does not implement.
            _ => Ok(()),
        }
    }

    /// Dispatches one decrypted control message.
    async fn handle_json(&mut self, text: &str) -> Result<()> {
        match Incoming::parse(text)? {
            None => Ok(()), // A type this revision does not implement is ignored.
            Some(Incoming::ServerActivate(activate)) => self.apply_activate(activate).await,
            Some(Incoming::ServerTime(time)) => self.handle_server_time(time).await,
            Some(Incoming::ServerState(state)) => {
                self.handle_state(state);
                Ok(())
            }
            Some(Incoming::ServerCommand(command)) => self.handle_command(command).await,
            Some(Incoming::StreamStart(start)) => self.handle_stream_start(start),
            Some(Incoming::StreamEnd(end)) if !affects_player(end.roles.as_deref()) => Ok(()),
            Some(Incoming::StreamEnd(_)) => self.stop_stream(),
            Some(Incoming::StreamClear(clear)) if !affects_player(clear.roles.as_deref()) => Ok(()),
            Some(Incoming::StreamClear(clear)) => self.handle_stream_clear(clear),
            // A message for a role or direction this client does not act on.
            Some(_) => Ok(()),
        }
    }

    /// Applies a `server/activate`: role changes, stream teardown and state reporting.
    async fn apply_activate(&mut self, activate: ServerActivate) -> Result<()> {
        let had_player = self.player_active();
        if let Some(roles) = activate.active_roles {
            self.active_roles = roles;
        }
        let has_player = self.player_active();

        if had_player && !has_player {
            // The player role is gone: nothing that is still buffered may become audible.
            self.state_sent = false;
            self.sync_remaining = 0;
            self.burst_deadline = None;
            self.reply_deadline = None;
            self.outstanding_sent_us = None;
            self.burst_samples.clear();
            self.stop_stream()?;
        } else if !had_player && has_player {
            // A re-added role reports itself again, from the existing estimate when there is one.
            if self.clock.sample_count() >= 1 {
                self.send_client_state().await?;
            } else {
                self.start_burst();
            }
        }
        Ok(())
    }

    /// Feeds one `server/time` reply into the current burst.
    ///
    /// Only the reply to the request on the wire is used: its `client_transmitted` has to match
    /// the request. An unsolicited, late or mis-echoed `server_time` is ignored, because the next
    /// request may already be on the wire.
    async fn handle_server_time(&mut self, time: ServerTime) -> Result<()> {
        if self.reply_deadline.is_none()
            || self.outstanding_sent_us != Some(time.client_transmitted)
        {
            return Ok(());
        }
        self.outstanding_sent_us = None;
        self.burst_samples.push(TimeSample {
            client_sent_us: time.client_transmitted,
            server_received_us: time.server_received,
            server_sent_us: time.server_transmitted,
            client_received_us: now_us(),
        });
        self.reply_deadline = None;

        // The state is reported by `finish_burst`, once the filter has a measurement: the spec
        // does not allow a player to report before its clock estimate has one.
        if self.sync_remaining == 0 {
            self.finish_burst().await?;
        }
        Ok(())
    }

    /// Reports the player state: the level and mute state in force plus the commands this client
    /// accepts.
    ///
    /// Sent when the first burst completes after the player role became active, again after the
    /// role was removed and re-added, and on every change to the level or mute state. The
    /// `supported_commands` list is what makes a conformant server send player commands at all.
    async fn send_client_state(&mut self) -> Result<()> {
        self.state_sent = true;
        let output_delay_ms = self.sink.latency().map_or(0, |latency| {
            u32::try_from(latency.as_millis())
                .map_or(MAX_OUTPUT_DELAY_MS, |delay| delay.min(MAX_OUTPUT_DELAY_MS))
        });
        let state = Incoming::ClientState(ClientState {
            available: true,
            player: Some(PlayerState {
                volume: Some(self.volume),
                muted: Some(self.muted),
                output_delay_ms,
                required_lead_time_ms: REQUIRED_LEAD_TIME_MS,
                min_buffer_ms: MIN_BUFFER_MS,
                supported_commands: PLAYER_COMMANDS
                    .iter()
                    .map(|command| (*command).to_owned())
                    .collect(),
                format: None,
            }),
        });
        self.send_json(&state).await
    }

    /// Opens the sink for a newly announced player stream.
    fn handle_stream_start(&mut self, start: StreamStart) -> Result<()> {
        if !self.player_active() {
            return Ok(());
        }
        let Some(player) = start.player else {
            // The announcement targets a role this client does not have.
            return Ok(());
        };
        let codec_header = player
            .codec_header
            .as_deref()
            .map(|encoded| {
                STANDARD
                    .decode(encoded)
                    .context("the stream's codec_header is not standard base64")
            })
            .transpose()?;
        let format = AudioFormat {
            codec: Codec::from(player.codec),
            sample_rate: player.sample_rate,
            channels: player.channels,
            bit_depth: player.bit_depth,
            codec_header,
        };
        if self.config.audio_mode == AudioMode::Decode && format.codec != Codec::Pcm {
            bail!(
                "the server announced a `{}` stream although only pcm was requested",
                format.codec
            );
        }

        self.flush_sink()?;
        self.open_sink(format.clone())?;
        self.stream = Some(format.clone());
        self.emit(Event::StreamStart { format });
        Ok(())
    }

    /// Delivers one audio chunk whose 13-byte header the reassembler handed over separately.
    ///
    /// The header is protocol syntax even when the frame is not playable: a short or malformed
    /// chunk closes the connection whether or not a stream is open.
    fn handle_audio(&mut self, body: &[u8]) -> Result<()> {
        // The reassembler removes the message id, which the chunk parser expects.
        let mut message = Vec::with_capacity(1 + body.len());
        message.push(AUDIO_CHUNK_ID);
        message.extend_from_slice(body);
        let (header, data) = AudioChunkHeader::parse(&message)?;

        if !self.player_active() {
            return Ok(());
        }
        let Some(format) = self.stream.clone() else {
            // Audio cannot be classified before a stream announced its format.
            return Ok(());
        };

        let frame = match (self.config.audio_mode, &format.codec) {
            (_, Codec::Pcm) => AudioFrame::Pcm(data),
            (AudioMode::Passthrough, codec) => AudioFrame::Encoded {
                codec: codec.clone(),
                data,
            },
            (AudioMode::Decode, codec) => {
                bail!("the server sent a `{codec}` frame although only pcm was requested")
            }
        };

        let due = self.playout_deadline(header.timestamp_us);
        self.write_sink(frame, due)
    }

    /// Drops buffered audio and forgets the open stream.
    ///
    /// A sink that fails to flush ends the session, like any other sink error.
    fn stop_stream(&mut self) -> Result<()> {
        self.stream = None;
        self.flush_sink()
    }

    /// Drops buffered audio without ending the stream.
    ///
    /// The client holds no timestamped audio queue of its own - the sink does - so the only
    /// granularity it can offer is a full flush: a clear with a `from_timestamp` also drops the
    /// frames after it. The announced format stays open, because the spec lets the stream continue
    /// and the chunks that follow a seek still belong to it.
    fn handle_stream_clear(&mut self, _clear: StreamClear) -> Result<()> {
        self.flush_sink()
    }

    /// Flushes the sink, recording a failure the caller has to treat as fatal.
    fn flush_sink(&mut self) -> Result<()> {
        match self.sink.flush() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.sink_failed = true;
                Err(error).context("the audio sink rejected a flush")
            }
        }
    }

    /// Opens the sink for a stream, recording a failure the caller has to treat as fatal.
    fn open_sink(&mut self, format: AudioFormat) -> Result<()> {
        match self.sink.open(format) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.sink_failed = true;
                Err(error).context("the audio sink rejected the stream format")
            }
        }
    }

    /// Writes one frame, recording a failure the caller has to treat as fatal.
    fn write_sink(&mut self, frame: AudioFrame<'_>, due: Instant) -> Result<()> {
        match self.sink.write(frame, due) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.sink_failed = true;
                Err(error).context("the audio sink rejected a frame")
            }
        }
    }

    /// Converts a server timestamp into a local playout deadline.
    ///
    /// Without a clock estimate the frame is delivered immediately and the deadline carries no
    /// guarantee. A deadline that already passed is reported as now, not as a time in the past, so
    /// a sink can compare it directly with its own clock.
    fn playout_deadline(&self, server_us: i64) -> Instant {
        let now = Instant::now();
        let Some(local_us) = self.clock.client_time_us(server_us) else {
            return now;
        };
        let delta = local_us.saturating_sub(now_us());
        if delta <= 0 {
            return now;
        }
        // A timestamp far outside the local clock range must not overflow the instant arithmetic;
        // playing it now is the conservative outcome of an estimate this uncertain.
        now.checked_add(Duration::from_micros(delta.unsigned_abs()))
            .unwrap_or(now)
    }

    /// Reports one `server/state` message for the roles this client has active.
    fn handle_state(&mut self, state: ServerState) {
        if self.role_active(METADATA_ROLE) {
            if let Some(metadata) = state.metadata {
                let (progress_ms, duration_ms) = match metadata.progress {
                    Some(progress) => (progress.track_progress, progress.track_duration),
                    None => (None, None),
                };
                self.emit(Event::Track {
                    title: metadata.title.unwrap_or_default(),
                    artist: metadata.artist.unwrap_or_default(),
                    album: metadata.album.unwrap_or_default(),
                    album_artist: metadata.album_artist.unwrap_or_default(),
                    artwork_url: metadata.artwork_url.unwrap_or_default(),
                    progress_ms,
                    duration_ms,
                });
            }
        }
        if self.role_active(CONTROLLER_ROLE) {
            if let Some(controller) = state.controller {
                self.controller_commands = Some(controller.supported_commands.clone());
                self.emit(Event::State(PlaybackState {
                    supported_commands: controller.supported_commands,
                    volume: controller.volume,
                    muted: controller.muted,
                }));
            }
        }
    }

    /// Applies a volume or mute request from the server and reports the result.
    ///
    /// The volume is limited by [`clamp_volume`], which also caps a level the server cannot
    /// legally send, and the applied value - not the requested one - is what [`Event::Volume`]
    /// carries and what the following `client/state` reports. A mute request changes only the mute
    /// field, so it never looks like a request for volume zero.
    async fn handle_command(&mut self, command: ServerCommand) -> Result<()> {
        if !self.player_active() {
            return Ok(());
        }
        let Some(player) = command.player else {
            return Ok(());
        };
        match player.command.as_str() {
            "volume" => {
                let Some(level) = player.volume else {
                    return Ok(());
                };
                self.record_volume(clamp_volume(self.volume, level));
                self.emit(Event::Volume {
                    level: Some(self.volume),
                    muted: None,
                });
                self.report_state().await?;
            }
            "mute" => {
                let Some(muted) = player.mute else {
                    return Ok(());
                };
                self.muted = muted;
                self.emit(Event::Volume {
                    level: None,
                    muted: Some(muted),
                });
                self.report_state().await?;
            }
            // A command this client does not advertise, such as `set_output_delay`.
            _ => {}
        }
        Ok(())
    }

    /// Applies one request from a control handle and answers it with the level in force.
    ///
    /// A command the connection cannot send is refused without touching the connection. A failure
    /// to write it ends the session, because the connection is no longer usable.
    async fn handle_control(&mut self, request: ControlRequest) -> Result<()> {
        let ControlRequest { action, reply } = request;
        if let Err(error) = self.check_control(&action) {
            let _ = reply.send(Err(error));
            return Ok(());
        }

        let result = match action {
            ControlAction::Transport(command) => self
                .send_transport_command(command)
                .await
                .map(|()| self.volume),
            ControlAction::Volume(level) => self.apply_volume(level).await,
            ControlAction::Mute(muted) => self.apply_mute(muted).await.map(|()| self.volume),
        };
        match result {
            Ok(level) => {
                let _ = reply.send(Ok(level));
                Ok(())
            }
            Err(error) => {
                let _ = reply.send(Err(anyhow!("{error:#}")));
                Err(error)
            }
        }
    }

    /// Rejects a control request the connection cannot carry out right now.
    ///
    /// Transport commands need the controller role, and once the server reported the commands it
    /// accepts, a command outside that set is refused as well: a server ignores what it did not
    /// advertise, so sending it would only look like it worked. The window before the first
    /// controller state is left open, because nothing is known yet.
    fn check_control(&self, action: &ControlAction) -> Result<()> {
        match action {
            ControlAction::Transport(command) => {
                if !self.role_active(CONTROLLER_ROLE) {
                    bail!("the server did not activate {CONTROLLER_ROLE}");
                }
                if let Some(commands) = &self.controller_commands {
                    if !commands.iter().any(|supported| supported == command) {
                        bail!("the server does not accept the command {command:?}");
                    }
                }
                Ok(())
            }
            ControlAction::Volume(_) | ControlAction::Mute(_) => {
                if !self.player_active() {
                    bail!("the server did not activate {PLAYER_ROLE}");
                }
                Ok(())
            }
        }
    }

    /// Sends one controller command as a `client/command` envelope.
    async fn send_transport_command(&mut self, command: &'static str) -> Result<()> {
        let message = Incoming::ClientCommand(ClientCommand {
            controller: Some(ControllerCommand {
                command: command.to_owned(),
                ..ControllerCommand::default()
            }),
        });
        self.send_json(&message).await
    }

    /// Applies a level the host asked for, reports it and returns what reached the output.
    async fn apply_volume(&mut self, level: u8) -> Result<u8> {
        self.record_volume(clamp_volume(self.volume, level));
        self.report_state().await?;
        Ok(self.volume)
    }

    /// Applies a mute state the host asked for, leaving the level untouched.
    async fn apply_mute(&mut self, muted: bool) -> Result<()> {
        self.muted = muted;
        self.report_state().await
    }

    /// Records the level in force and publishes it to the control handles.
    fn record_volume(&mut self, level: u8) {
        self.volume = level;
        self.publish_volume();
    }

    /// Publishes the level in force to the control handles.
    fn publish_volume(&self) {
        self.reported_volume.store(self.volume, Ordering::Relaxed);
    }

    /// Reports a state change the host made, or leaves it to the pending initial report.
    ///
    /// The player may not send its initial state before its first clock measurement, so a change
    /// that arrives earlier is recorded and the burst that is already running carries it; once the
    /// initial report exists every change goes out immediately.
    async fn report_state(&mut self) -> Result<()> {
        if self.state_sent {
            self.send_client_state().await
        } else {
            Ok(())
        }
    }

    /// Whether a versioned role is active for this connection.
    fn role_active(&self, role: &str) -> bool {
        self.active_roles.iter().any(|active| active == role)
    }

    /// Whether the server activated the player role for this connection.
    fn player_active(&self) -> bool {
        self.role_active(PLAYER_ROLE)
    }

    /// Queues one event for the caller.
    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    /// Encrypts and sends one control message.
    async fn send_json(&mut self, message: &Incoming) -> Result<()> {
        let ciphertext = encrypt_json(&mut self.noise, message)?;
        self.transport.send_binary(ciphertext).await
    }
}

/// Runs the cleartext exchange and the Noise handshake.
///
/// The Noise metadata in message 1 decides which key seals message 2. A malformed announcement
/// closes the connection without sending message 2: the peer learns nothing beyond the close, and
/// the caller reports the reason locally.
async fn handshake(
    mut transport: Transport,
    config: &ClientConfig,
    psks: &[StoredPsk],
    previous_roles: &[String],
) -> Result<Ready> {
    // 1. client/init. Its exact bytes are the first half of the Noise prologue.
    let client_init = Incoming::ClientInit(ClientInit {
        client_id: config.identity.public_base64(),
        version: PROTOCOL_VERSION,
        suite: NOISE_SUITE.to_owned(),
    });
    let client_init_text =
        serde_json::to_string(&client_init).context("failed to encode client/init")?;
    transport.send_text(&client_init_text).await?;
    let client_init_bytes = client_init_text.into_bytes();

    // 2. server/init. Its exact bytes are the second half of the prologue.
    let server_init_text = read_cleartext(&mut transport).await?;
    let server_init = match Incoming::parse(&server_init_text)? {
        Some(Incoming::ServerInit(server_init)) => server_init,
        _ => bail!("expected a cleartext server/init"),
    };
    if server_init.version != PROTOCOL_VERSION {
        bail!("unsupported server version {}", server_init.version);
    }
    let server_init_bytes = server_init_text.into_bytes();

    // 3. Noise message 1, sent by the server as the initiator.
    let message_1_text = read_cleartext(&mut transport).await?;
    let message_1 = match Incoming::parse(&message_1_text)? {
        Some(Incoming::NoiseHandshake(handshake)) => URL_SAFE_NO_PAD
            .decode(&handshake.data)
            .context("noise/handshake data is not unpadded base64url")?,
        _ => bail!("expected noise/handshake message 1"),
    };

    // 4. Read message 1, validate its PSK metadata and seal message 2 with the selected key.
    let mut prologue = client_init_bytes;
    prologue.extend_from_slice(&server_init_bytes);
    let mut responder = Responder::new(&config.identity, &prologue)?;
    let metadata_payload = responder
        .read_message(&message_1)
        .context("failed to read Noise handshake message 1")?;
    let metadata = PskMetadata::parse(&metadata_payload)?;
    let psk = select_psk(&metadata, psks, &server_init.server_id, true)?;
    responder.set_psk(&psk)?;

    let message_2 = responder.write_message()?;
    let message_2 = Incoming::NoiseHandshake(NoiseHandshake {
        data: URL_SAFE_NO_PAD.encode(message_2),
    });
    let message_2_text =
        serde_json::to_string(&message_2).context("failed to encode noise/handshake message 2")?;
    transport.send_text(&message_2_text).await?;
    let mut noise = responder.into_transport()?;

    // 5. server/hello, the first encrypted message.
    let hello = read_encrypted_json(&mut transport, &mut noise).await?;
    match Incoming::parse(&hello)? {
        Some(Incoming::ServerHello(_)) => {}
        _ => bail!("expected an encrypted server/hello after the Noise handshake"),
    }

    // 6. client/hello.
    let hello = client_hello(config);
    let ciphertext = encrypt_json(&mut noise, &hello)?;
    transport.send_binary(ciphertext).await?;

    // 7. The first server/activate, which completes the handshake.
    let activate = read_encrypted_json(&mut transport, &mut noise).await?;
    // The first activation of a connection must carry the roles. If it does not, the previous
    // session's set is the safer starting point than none, because the server is already breaking
    // its own rule and a player that forgets it could drop audio.
    let active_roles = match Incoming::parse(&activate)? {
        Some(Incoming::ServerActivate(activate)) => activate
            .active_roles
            .unwrap_or_else(|| previous_roles.to_vec()),
        _ => bail!("expected an encrypted server/activate after client/hello"),
    };

    Ok(Ready {
        transport,
        noise,
        server_id: server_init.server_id,
        active_roles,
    })
}

/// Builds the `client/hello` the client announces itself with.
fn client_hello(config: &ClientConfig) -> Incoming {
    let codec = match config.audio_mode {
        AudioMode::Decode => "pcm",
        AudioMode::Passthrough => "flac",
    };
    Incoming::ClientHello(ClientHello {
        name: config.player_name.clone(),
        device_info: None,
        supported_roles: vec![
            PLAYER_ROLE.to_owned(),
            CONTROLLER_ROLE.to_owned(),
            METADATA_ROLE.to_owned(),
        ],
        player_support: Some(PlayerSupport {
            supported_formats: vec![SupportedFormat {
                codec: codec.to_owned(),
                channels: SUPPORTED_CHANNELS,
                sample_rate: SUPPORTED_SAMPLE_RATE,
                bit_depth: SUPPORTED_BIT_DEPTH,
            }],
            buffer_capacity: BUFFER_CAPACITY,
        }),
        supported_pair_methods: SupportedPairMethods {
            pairing_psk: Some(PairingPskMethod {}),
        },
        unpaired_access: UnpairedAccess { enabled: true },
    })
}

/// Reads cleartext text frames, ignoring binary frames and answering pings.
async fn read_cleartext(transport: &mut Transport) -> Result<String> {
    loop {
        match transport.read().await? {
            SocketMessage::Text(text) => return Ok(text),
            SocketMessage::Binary(_) => continue,
            SocketMessage::Closed => bail!("the connection closed during the Noise handshake"),
        }
    }
}

/// Reads frames until the next encrypted JSON control message.
async fn read_encrypted_json(
    transport: &mut Transport,
    noise: &mut NoiseTransport,
) -> Result<String> {
    loop {
        match transport.read().await? {
            SocketMessage::Text(_) => {
                bail!("cleartext text after the Noise transport is a protocol error")
            }
            SocketMessage::Binary(ciphertext) => {
                let plaintext = noise.decrypt(&ciphertext)?;
                match plaintext.first() {
                    None => bail!("empty Noise plaintext is a protocol error"),
                    Some(&BINARY_MESSAGE_ID_JSON) => {
                        return String::from_utf8(plaintext[1..].to_vec())
                            .context("decrypted JSON is not valid UTF-8")
                    }
                    Some(_) => continue,
                }
            }
            SocketMessage::Closed => bail!("the connection closed during the Noise handshake"),
        }
    }
}

/// Encrypts one control message as a Noise transport message.
fn encrypt_json(noise: &mut NoiseTransport, message: &Incoming) -> Result<Vec<u8>> {
    let text = serde_json::to_string(message).context("failed to encode a control message")?;
    noise.encrypt(&encode_binary(BINARY_MESSAGE_ID_JSON, text.as_bytes()))
}

/// The PSK metadata the server puts into Noise message 1.
#[derive(Debug, Deserialize)]
struct PskMetadataWire {
    psk_id: String,
    psk_category: String,
}

/// A validated PSK announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PskMetadata {
    /// Canonical 43-character base64url id of the key the server used.
    psk_id: String,
    /// Category the id belongs to.
    category: PskCategory,
}

impl PskMetadata {
    /// Parses and validates the decrypted payload of Noise message 1.
    ///
    /// A payload that is not a JSON object with a canonical key id and a known category is
    /// rejected. Rejection is silent on the wire: the connection is closed without message 2.
    fn parse(payload: &[u8]) -> Result<PskMetadata> {
        let wire: PskMetadataWire = serde_json::from_slice(payload)
            .context("the Noise handshake metadata is not a PSK announcement")?;
        if !is_canonical_psk_id(&wire.psk_id) {
            bail!(
                "the Noise handshake metadata carries a psk_id that is not a canonical \
                 {PSK_ID_LEN}-character base64url key id"
            );
        }
        let category = PskCategory::from_wire(&wire.psk_category).ok_or_else(|| {
            anyhow!("the Noise handshake metadata carries an unknown psk_category")
        })?;
        Ok(PskMetadata {
            psk_id: wire.psk_id,
            category,
        })
    }
}

/// Whether a `stream/end` or `stream/clear` role list affects the player stream.
///
/// An absent list means every role; otherwise it has to name `player@v1`.
fn affects_player(roles: Option<&[String]>) -> bool {
    match roles {
        None => true,
        Some(roles) => roles.iter().any(|role| role == PLAYER_ROLE),
    }
}

/// Whether `value` is the canonical unpadded base64url encoding of a 32-byte key id.
fn is_canonical_psk_id(value: &str) -> bool {
    if value.len() != PSK_ID_LEN {
        return false;
    }
    match URL_SAFE_NO_PAD.decode(value) {
        Ok(bytes) => bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == value,
        Err(_) => false,
    }
}

/// Chooses the key that seals Noise message 2.
///
/// A stored record matches only when both its category and its derived id equal the announcement;
/// its `server_id` must then equal the one in `server/init`, so a key recorded for a different
/// server can never seal this handshake. A plain lookup miss is the documented unpaired path during
/// the initial handshake; during a re-handshake it is an error, because falling back would silently
/// drop a pairing the previous connection authenticated.
fn select_psk(
    metadata: &PskMetadata,
    stored: &[StoredPsk],
    server_id: &str,
    initial: bool,
) -> Result<[u8; 32]> {
    if metadata.category == PskCategory::Sentinel && metadata.psk_id == SENTINEL_PSK_ID {
        return Ok(SENTINEL_PSK);
    }
    let matched = stored.iter().find(|candidate| {
        candidate.category == metadata.category && psk_id_for(&candidate.psk) == metadata.psk_id
    });
    if let Some(candidate) = matched {
        if candidate.server_id != server_id {
            bail!("the stored key for the announced PSK id belongs to another server");
        }
        return Ok(candidate.psk);
    }
    if initial {
        return Ok(SENTINEL_PSK);
    }
    bail!("no stored key matches the announced PSK id, so a re-handshake cannot continue")
}

/// Picks the burst measurement with the smallest positive error bound.
///
/// The protocol defines `max_error = ((t4 - t1) - (t3 - t2)) / 2`; a sample whose bound is not
/// positive carries no usable information and is skipped. Ties keep the earlier sample.
fn best_sample(samples: &[TimeSample]) -> Option<TimeSample> {
    samples
        .iter()
        .copied()
        .filter_map(|sample| {
            let error = max_error_us(&sample);
            (error > 0).then_some((error, sample))
        })
        .min_by_key(|(error, _sample)| *error)
        .map(|(_error, sample)| sample)
}

/// The error bound of one measurement, in microseconds.
fn max_error_us(sample: &TimeSample) -> i128 {
    let t1 = sample.client_sent_us as i128;
    let t2 = sample.server_received_us as i128;
    let t3 = sample.server_sent_us as i128;
    let t4 = sample.client_received_us as i128;
    ((t4 - t1) - (t3 - t2)) / 2
}

/// Current wall clock in microseconds since the Unix epoch, the domain of server timestamps.
fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a metadata payload with the Sentinel id and the given category.
    fn sentinel_metadata(category: &str) -> String {
        format!(r#"{{"psk_id":"{SENTINEL_PSK_ID}","psk_category":"{category}"}}"#)
    }

    /// The server id used by the selection tests.
    const SERVER_ID: &str = "B1y4w7z0c3f6i9l2o5r8u1x4a7d0g3j6m9p2s5v8y1b";

    /// Builds a stored record for `psk` in `category`.
    fn stored(category: PskCategory, psk: [u8; 32], server_id: &str) -> StoredPsk {
        StoredPsk {
            category,
            psk,
            server_id: server_id.to_owned(),
        }
    }

    #[test]
    fn a_sentinel_announcement_selects_the_published_key() {
        let metadata = PskMetadata::parse(sentinel_metadata("sn").as_bytes()).unwrap();
        assert_eq!(metadata.category, PskCategory::Sentinel);
        assert_eq!(
            select_psk(&metadata, &[], SERVER_ID, true).unwrap(),
            SENTINEL_PSK
        );
        assert_eq!(
            select_psk(&metadata, &[], SERVER_ID, false).unwrap(),
            SENTINEL_PSK
        );
    }

    #[test]
    fn a_stored_key_wins_and_a_miss_only_falls_back_on_the_initial_handshake() {
        let psk: [u8; 32] = std::array::from_fn(|index| index as u8);
        let announcement = format!(r#"{{"psk_id":"{}","psk_category":"pr"}}"#, psk_id_for(&psk));
        let metadata = PskMetadata::parse(announcement.as_bytes()).unwrap();
        let candidates = [stored(PskCategory::Pairing, psk, SERVER_ID)];
        assert_eq!(
            select_psk(&metadata, &candidates, SERVER_ID, true).unwrap(),
            psk
        );
        assert_eq!(
            select_psk(&metadata, &candidates, SERVER_ID, false).unwrap(),
            psk
        );

        let unknown = format!(
            r#"{{"psk_id":"{}","psk_category":"lt"}}"#,
            psk_id_for(b"a key this client does not have")
        );
        let metadata = PskMetadata::parse(unknown.as_bytes()).unwrap();
        assert_eq!(
            select_psk(&metadata, &candidates, SERVER_ID, true).unwrap(),
            SENTINEL_PSK
        );
        assert!(
            select_psk(&metadata, &candidates, SERVER_ID, false).is_err(),
            "a re-handshake must not silently drop the established key"
        );
    }

    #[test]
    fn a_stored_key_only_matches_its_own_category_and_server() {
        let psk: [u8; 32] = std::array::from_fn(|index| index as u8 ^ 0x5a);
        let announcement = format!(r#"{{"psk_id":"{}","psk_category":"pr"}}"#, psk_id_for(&psk));
        let metadata = PskMetadata::parse(announcement.as_bytes()).unwrap();

        // The id matches, but the record was filed under another category.
        let wrong_category = [stored(PskCategory::LongTerm, psk, SERVER_ID)];
        assert_eq!(
            select_psk(&metadata, &wrong_category, SERVER_ID, true).unwrap(),
            SENTINEL_PSK,
            "a category mismatch is a miss, not a match"
        );
        assert!(
            select_psk(&metadata, &wrong_category, SERVER_ID, false).is_err(),
            "a category mismatch is an error during a re-handshake"
        );

        // The category and id match, but the record belongs to another server.
        let other_server = [stored(PskCategory::Pairing, psk, "wrong-server")];
        assert!(
            select_psk(&metadata, &other_server, SERVER_ID, true).is_err(),
            "a key recorded for another server must never seal this handshake"
        );
    }

    #[test]
    fn the_best_sample_has_the_smallest_positive_error_bound() {
        assert_eq!(best_sample(&[]), None, "an empty burst has no measurement");

        // t4 - t1 = round trip; t3 - t2 = server processing. Bounds: 1000, 1500 and 100 us.
        let sample =
            |client_sent_us, server_received_us, server_sent_us, client_received_us| TimeSample {
                client_sent_us,
                server_received_us,
                server_sent_us,
                client_received_us,
            };
        let broad = sample(1_000, 2_000, 2_000, 3_000);
        let broadest = sample(4_000, 5_000, 5_000, 7_000);
        let tight = sample(8_000, 8_100, 8_100, 8_200);

        assert_eq!(
            best_sample(&[broad, broadest, tight]),
            Some(tight),
            "the tightest round trip wins"
        );

        // A non-positive bound is unusable; the filter would reject it anyway. It claims more
        // server processing time than the whole round trip.
        let impossible = sample(10_000, 10_000, 11_000, 10_500);
        assert!(max_error_us(&impossible) <= 0);
        assert_eq!(
            best_sample(&[impossible]),
            None,
            "a non-positive error bound carries no information"
        );
        assert_eq!(
            best_sample(&[impossible, broad]),
            Some(broad),
            "the unusable sample is skipped"
        );

        // Equal bounds keep the earlier measurement.
        let first_tie = sample(20_000, 20_100, 20_100, 20_300);
        let second_tie = sample(30_000, 30_100, 30_100, 30_300);
        assert_eq!(max_error_us(&first_tie), max_error_us(&second_tie));
        assert_eq!(
            best_sample(&[first_tie, second_tie]),
            Some(first_tie),
            "a tie keeps the earlier sample"
        );
    }

    #[test]
    fn malformed_psk_metadata_is_rejected() {
        for payload in [
            "",
            "not json",
            "{}",
            r#"{"psk_id":"abc","psk_category":"sn"}"#,
            r#"{"psk_id":42,"psk_category":"sn"}"#,
            r#"{"psk_id":"@invalid@invalid@invalid@invalid@invalid@invalid@"}"#,
            r#"{"psk_category":"sn"}"#,
            r#"{"psk_id":"abc","psk_category":7}"#,
        ] {
            assert!(
                PskMetadata::parse(payload.as_bytes()).is_err(),
                "{payload:?} must not be accepted"
            );
        }

        // A canonical id with an unknown category is rejected too.
        let unknown = sentinel_metadata("xx");
        assert!(PskMetadata::parse(unknown.as_bytes()).is_err());
    }

    #[test]
    fn a_psk_id_must_be_the_canonical_encoding() {
        assert!(is_canonical_psk_id(SENTINEL_PSK_ID));
        assert!(
            !is_canonical_psk_id(&format!("{SENTINEL_PSK_ID}=")),
            "padding is not canonical"
        );
        assert!(!is_canonical_psk_id(""));
        assert!(!is_canonical_psk_id(&"a".repeat(42)));

        // The last character of a 43-character id carries four real bits and two spare bits that
        // must be zero; setting one of them makes a string that is not the canonical encoding.
        let mut non_canonical = SENTINEL_PSK_ID.to_owned();
        non_canonical.pop();
        non_canonical.push('p');
        assert!(!is_canonical_psk_id(&non_canonical));
    }
}
