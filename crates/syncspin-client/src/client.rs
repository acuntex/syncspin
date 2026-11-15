//! Public client surface: events, handles and the connection entry point.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::{ClientConfig, StoredPsk};
use crate::session::{Session, Transport};
use crate::sink::{AudioFormat, Sink};

/// How long the TCP and WebSocket handshake may take before it is treated as unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Delay before the first reconnect attempt, and the value the backoff resets to.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Highest level that is always applied as requested, in the protocol's 0-100 volume range.
const VOLUME_ALWAYS_APPLIED: u8 = 40;

/// Largest increase one request may apply above that level.
const MAX_VOLUME_STEP: u8 = 20;

/// Returns the volume level to apply for `requested` while `current` is in force.
///
/// A request to 40 or below is applied as asked, whether it raises or lowers the level. Above 40,
/// one request may raise the level by at most 20; a lower request is applied as asked, because the
/// limit bounds raises only.
///
/// ```
/// # use syncspin_client::clamp_volume;
/// assert_eq!(clamp_volume(40, 100), 60);
/// assert_eq!(clamp_volume(40, 10), 10);
/// assert_eq!(clamp_volume(100, 90), 90);
/// ```
#[must_use]
pub fn clamp_volume(current: u8, requested: u8) -> u8 {
    if requested <= VOLUME_ALWAYS_APPLIED {
        return requested;
    }
    requested.min(current.saturating_add(MAX_VOLUME_STEP))
}

/// Returns the delay to wait before the next connection attempt.
///
/// The delay starts at [`INITIAL_BACKOFF`] and doubles with every attempt that never reached
/// [`Event::Connected`], saturating at `max`. `previous` is the delay used before the failed
/// attempt, or [`Duration::ZERO`] for the first one. A `connected` session resets the delay: the
/// address and the handshake worked, so a later failure is retried without a growing penalty.
///
/// The reconnect loop belongs to the host; this function only makes its policy explicit and lets
/// [`Event::Disconnected`] report a delay that follows it.
///
/// ```
/// # use std::time::Duration;
/// # use syncspin_client::next_backoff;
/// let max = Duration::from_secs(30);
/// assert_eq!(next_backoff(Duration::ZERO, false, max), Duration::from_secs(1));
/// assert_eq!(next_backoff(Duration::from_secs(1), false, max), Duration::from_secs(2));
/// assert_eq!(next_backoff(Duration::from_secs(16), true, max), Duration::from_secs(1));
/// ```
#[must_use]
pub fn next_backoff(previous: Duration, connected: bool, max: Duration) -> Duration {
    let next = if connected || previous.is_zero() {
        INITIAL_BACKOFF
    } else {
        previous.saturating_mul(2)
    };
    next.min(max)
}

/// Something that happened on the connection.
///
/// Events are ordered as the connection produced them, and a session reports at most one
/// [`Event::Disconnected`], as its last event. The enum is non-exhaustive: a later revision adds
/// events without breaking a host's match.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The Noise handshake finished and the session is ready for playback.
    ///
    /// `encrypted` is always `true`: this client has no path that speaks to a server without
    /// Noise, so the field documents the property rather than hedging it.
    Connected {
        /// The server's static public key as 43 base64url characters.
        server_id: String,
        /// Whether the connection is encrypted; always `true`.
        encrypted: bool,
    },
    /// The session ended.
    ///
    /// `reason` is human-readable and never contains key material. `retry_in` is the delay the
    /// session recommends before a new connection, computed by [`next_backoff`]: a session that
    /// connected reports the initial delay, and one that failed earlier reports the next step of
    /// the growing sequence. The session schedules no retry itself, so the host owns the loop and
    /// keeps the sequence across attempts, bounded by [`ClientConfig::max_backoff`].
    Disconnected {
        /// Why the session ended.
        reason: String,
        /// How long to wait before reconnecting.
        retry_in: Duration,
    },
    /// A stream was announced with the given format.
    ///
    /// The sink has been opened for this format before the event is emitted.
    StreamStart {
        /// Format of the new stream.
        format: AudioFormat,
    },
    /// Now-playing metadata changed.
    ///
    /// Absent text fields are reported as empty strings, so a host can clear its display; absent
    /// progress fields are `None`.
    Track {
        /// Track title.
        title: String,
        /// Track artist.
        artist: String,
        /// Album title.
        album: String,
        /// Album artist.
        album_artist: String,
        /// URL of the artwork image, empty when the server sent none.
        artwork_url: String,
        /// Position within the track in milliseconds, when the server reports one.
        progress_ms: Option<u64>,
        /// Track length in milliseconds, when the server reports one.
        duration_ms: Option<u64>,
    },
    /// The server's view of playback state changed.
    State(PlaybackState),
    /// The server asked this player to change its volume or mute state.
    ///
    /// The session applies the limits of [`clamp_volume`] and reports the result back to the
    /// server in `client/state`; the event carries that applied value, not the requested one, so a
    /// host keeps its output in step with the server without repeating the limit. Exactly one of
    /// the two fields is present: a volume command carries the applied level, a mute command the
    /// requested state. A mute command therefore never looks like a request to set the volume to
    /// zero, and the level in force is unchanged by it.
    Volume {
        /// Applied volume in the range 0-100.
        level: Option<u8>,
        /// Mute state that was requested.
        muted: Option<bool>,
    },
}

/// Playback state as the server describes it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlaybackState {
    /// Commands the server accepts from clients in the same group.
    pub supported_commands: Vec<String>,
    /// Group volume in the range 0-100, when the server reports one.
    pub volume: Option<u8>,
    /// Group mute state, when the server reports one.
    pub muted: Option<bool>,
}

/// A live connection.
///
/// The handle is independent of the event stream: dropping the stream ends the session, while
/// dropping the handle only detaches from it. Keep the handle to wait for the session's outcome.
#[derive(Debug)]
pub struct ClientHandle {
    task: JoinHandle<Result<()>>,
    control: ControlHandle,
}

impl ClientHandle {
    /// Returns a handle for the playback controls of this session.
    ///
    /// The handle is a cheap clone; every copy controls the same session.
    #[must_use]
    pub fn control(&self) -> ControlHandle {
        self.control.clone()
    }

    /// Waits for the session to end and returns its outcome.
    ///
    /// A clean server close is `Ok(())`; a handshake, transport, protocol or sink failure is the
    /// error that ended the session. The matching [`Event::Disconnected`] has already been
    /// delivered when this returns.
    pub async fn finished(self) -> Result<()> {
        self.task.await.context("the session task panicked")?
    }
}

/// Playback controls for a live session.
///
/// A call returns once the session has handled it: a transport command has been written to the
/// connection, and a level or mute change has been recorded and included in the next state report.
/// It is an error when the session has ended, and when the server did not activate the role the
/// command belongs to: transport commands need `controller@v1`, volume and mute state need
/// `player@v1`. The server ignores a command it did not advertise in its own
/// `supported_commands`, so a host that wants to know before offering a button reads
/// [`PlaybackState::supported_commands`] from [`Event::State`].
#[derive(Debug, Clone)]
pub struct ControlHandle {
    commands: mpsc::UnboundedSender<ControlRequest>,
}

impl ControlHandle {
    /// Resumes playback.
    pub async fn play(&self) -> Result<()> {
        self.transport("play").await
    }

    /// Pauses playback at the current position.
    pub async fn pause(&self) -> Result<()> {
        self.transport("pause").await
    }

    /// Skips to the next track.
    pub async fn next(&self) -> Result<()> {
        self.transport("next").await
    }

    /// Skips to the previous track.
    pub async fn previous(&self) -> Result<()> {
        self.transport("previous").await
    }

    /// Sets the output level, limited by [`clamp_volume`] against the level in force.
    ///
    /// The session reports the value it applied to the server with its next state report, which is
    /// the initial report when the first clock measurement is still pending. The call returns no
    /// value, so a host that has to apply the same level to its output either keeps the level it
    /// last reported and passes the request through [`clamp_volume`] itself, or applies the level
    /// it asked for when it is already allowed. A host that starts at another level reports it here
    /// once, so the server sees the level that is really in force.
    pub async fn set_volume(&self, level: u8) -> Result<()> {
        self.send(ControlAction::Volume(level)).await
    }

    /// Sets the mute state without changing the level.
    ///
    /// The reported level therefore stays what it was, and the server sees the mute in the
    /// `muted` field alone.
    pub async fn set_muted(&self, muted: bool) -> Result<()> {
        self.send(ControlAction::Mute(muted)).await
    }

    /// Sends one controller command.
    async fn transport(&self, command: &'static str) -> Result<()> {
        self.send(ControlAction::Transport(command)).await
    }

    /// Queues one request and waits for the session to answer it.
    async fn send(&self, action: ControlAction) -> Result<()> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(ControlRequest { action, reply })
            .map_err(|_| anyhow!("the session has ended"))?;
        response
            .await
            .map_err(|_| anyhow!("the session ended before it answered"))?
    }
}

/// What a [`ControlHandle`] asks the session to do.
#[derive(Debug)]
pub(crate) enum ControlAction {
    /// A controller command, by wire name.
    Transport(&'static str),
    /// Set the output level, subject to the volume limit.
    Volume(u8),
    /// Set the mute state, keeping the level.
    Mute(bool),
}

/// One request from a [`ControlHandle`], with the channel its answer travels back on.
pub(crate) struct ControlRequest {
    /// Operation to perform.
    pub(crate) action: ControlAction,
    /// Answer for the waiting call.
    pub(crate) reply: oneshot::Sender<Result<()>>,
}

/// The receiving end of a session's [`Event`] stream.
///
/// [`EventStream::next`] returns `None` after the last event, which follows
/// [`Event::Disconnected`]. Dropping the stream stops the session: the next time it would emit an
/// event, it ends instead.
#[derive(Debug)]
pub struct EventStream {
    events: mpsc::UnboundedReceiver<Event>,
}

impl EventStream {
    /// Waits for the next event.
    pub async fn next(&mut self) -> Option<Event> {
        self.events.recv().await
    }
}

/// Namespaced entry point, for callers that prefer a type to the free function.
#[derive(Debug, Clone, Copy, Default)]
pub struct Client;

impl Client {
    /// Connects to `config.server` and returns the handle and event stream.
    ///
    /// See [`connect`] for the details.
    pub async fn connect(
        config: ClientConfig,
        sink: Box<dyn Sink>,
    ) -> Result<(ClientHandle, EventStream)> {
        connect(config, sink).await
    }

    /// Connects with pairing keys the host stores for known servers.
    ///
    /// See [`connect_with_psks`] for the details.
    pub async fn connect_with_psks(
        config: ClientConfig,
        sink: Box<dyn Sink>,
        psks: Vec<StoredPsk>,
    ) -> Result<(ClientHandle, EventStream)> {
        connect_with_psks(config, sink, psks).await
    }
}

/// Connects to a server, hands the sink to the session and returns its handle and event stream.
///
/// The configuration is validated and the WebSocket is opened before this returns, so an
/// unreachable server is an error here rather than an event. Everything after that - the Noise
/// handshake, the clock estimate and playback - runs in a spawned task and is reported through the
/// event stream. [`Event::Connected`] is the first event of a successful connection.
///
/// The sink moves into the session and is dropped when the connection ends.
///
/// # Errors
/// Returns an error for an invalid [`ClientConfig`], for a server address this build cannot use
/// (including a TLS URL), and when the connection cannot be established within ten seconds.
///
/// # Panics
/// Panics when called outside a Tokio runtime, because the session is spawned.
pub async fn connect(
    config: ClientConfig,
    sink: Box<dyn Sink>,
) -> Result<(ClientHandle, EventStream)> {
    connect_with_psks(config, sink, Vec::new()).await
}

/// Connects with pairing keys the host stores for known servers.
///
/// The server announces a `psk_id` and `psk_category` in Noise message 1. A candidate matches when
/// its category and derived id both match the announcement; its `server_id` must then equal the one
/// in `server/init`. On a lookup miss the initial handshake continues with the published Sentinel
/// key, which is why [`connect`] is the same call with no candidates.
///
/// The keys are used for the handshake only; they are not stored or logged.
///
/// # Errors
/// Same as [`connect`], plus a handshake error when a matched record belongs to another server.
pub async fn connect_with_psks(
    config: ClientConfig,
    sink: Box<dyn Sink>,
    psks: Vec<StoredPsk>,
) -> Result<(ClientHandle, EventStream)> {
    config.validate()?;
    let endpoint = endpoint(&config.server)?;
    let transport = tokio::time::timeout(CONNECT_TIMEOUT, Transport::connect(&endpoint))
        .await
        .with_context(|| format!("timed out connecting to {endpoint}"))??;

    let (events, receiver) = mpsc::unbounded_channel();
    let (commands, control) = mpsc::unbounded_channel();
    let task = tokio::spawn(Session::start(
        transport, config, sink, events, psks, control,
    ));
    let handle = ClientHandle {
        task,
        control: ControlHandle { commands },
    };
    Ok((handle, EventStream { events: receiver }))
}

/// Splits a URL tail into the part before a query or fragment and the marker onward.
fn split_marker(value: &str) -> (&str, &str) {
    match value.find(['?', '#']) {
        Some(index) => value.split_at(index),
        None => (value, ""),
    }
}

/// Builds the WebSocket URL for a configured server address.
///
/// A bare `host:port` uses the default `/sendspin` path, and so does a `ws://` URL without a path.
/// A URL with an explicit path is used unchanged. TLS is rejected: this build carries no TLS
/// stack, and pretending otherwise would end in a confusing connection error.
fn endpoint(server: &str) -> Result<String> {
    let server = server.trim();
    if server.is_empty() {
        bail!("the server address is empty");
    }
    if server.starts_with("wss://") {
        bail!("TLS is not supported by this build; use a ws:// address or host:port");
    }
    if let Some(rest) = server.strip_prefix("ws://") {
        if rest.is_empty() {
            bail!("the WebSocket address {server:?} names no host");
        }
        // A query or fragment belongs after the path, so the default path has to be inserted
        // before it rather than appended to the whole URL.
        let (before_marker, after_marker) = split_marker(rest);
        let Some((authority, path)) = before_marker.split_once('/') else {
            if before_marker.is_empty() {
                bail!("the WebSocket address {server:?} names no host");
            }
            return Ok(format!("ws://{before_marker}/sendspin{after_marker}"));
        };
        if authority.is_empty() {
            bail!("the WebSocket address {server:?} names no host");
        }
        if path.is_empty() {
            return Ok(format!("ws://{authority}/sendspin{after_marker}"));
        }
        return Ok(format!("ws://{before_marker}{after_marker}"));
    }
    if server.contains("://") {
        bail!("unsupported URL scheme in {server:?}; use ws:// or host:port");
    }
    let (before_marker, after_marker) = split_marker(server);
    if before_marker.is_empty() {
        bail!("the server address is empty");
    }
    Ok(format!("ws://{before_marker}/sendspin{after_marker}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_address_gets_the_default_websocket_endpoint() {
        assert_eq!(
            endpoint("192.0.2.10:8927").unwrap(),
            "ws://192.0.2.10:8927/sendspin"
        );
        assert_eq!(
            endpoint(" 192.0.2.10:8927 ").unwrap(),
            "ws://192.0.2.10:8927/sendspin"
        );
        assert_eq!(
            endpoint("ws://example.test:1").unwrap(),
            "ws://example.test:1/sendspin"
        );
        assert_eq!(
            endpoint("ws://example.test:1/").unwrap(),
            "ws://example.test:1/sendspin"
        );
        assert_eq!(
            endpoint("ws://example.test:1/player").unwrap(),
            "ws://example.test:1/player"
        );
    }

    #[test]
    fn a_query_or_fragment_stays_after_the_default_path() {
        assert_eq!(
            endpoint("ws://example.test:1?token=1").unwrap(),
            "ws://example.test:1/sendspin?token=1"
        );
        assert_eq!(
            endpoint("ws://example.test:1#frag").unwrap(),
            "ws://example.test:1/sendspin#frag"
        );
        assert_eq!(
            endpoint("ws://example.test:1/?token=1").unwrap(),
            "ws://example.test:1/sendspin?token=1"
        );
        assert_eq!(
            endpoint("ws://example.test:1/player?token=1").unwrap(),
            "ws://example.test:1/player?token=1"
        );
        assert_eq!(
            endpoint("example.test:1?token=1").unwrap(),
            "ws://example.test:1/sendspin?token=1"
        );
    }

    #[test]
    fn an_address_this_build_cannot_use_is_rejected() {
        for server in [
            "",
            "   ",
            "wss://example.test",
            "https://example.test",
            "ws://",
        ] {
            assert!(
                endpoint(server).is_err(),
                "{server:?} must not be turned into a cleartext endpoint"
            );
        }
    }
}
