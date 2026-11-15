//! Public client surface: events, handles and the connection entry point.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::{ClientConfig, StoredPsk};
use crate::session::{self, Carried, Transport};
use crate::sink::{AudioFormat, Sink};

/// How long the TCP and WebSocket handshake may take before it is treated as unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Delay before the first reconnect attempt, and the value the backoff resets to.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Highest level the protocol defines, in its 0-100 volume range.
pub(crate) const MAX_VOLUME: u8 = 100;

/// Highest level that is always applied as requested.
const VOLUME_ALWAYS_APPLIED: u8 = 40;

/// Largest increase one request may apply above that level.
const MAX_VOLUME_STEP: u8 = 20;

/// Returns the volume level to apply for `requested` while `current` is in force.
///
/// Both values are first limited to the protocol's 0-100 range, so the result is always a level
/// the server accepts. A request to 40 or below is applied as asked, whether it raises or lowers
/// the level. Above 40, one request may raise the level by at most 20; a lower request is applied
/// as asked, because the limit bounds raises only.
///
/// ```
/// # use syncspin_client::clamp_volume;
/// assert_eq!(clamp_volume(40, 100), 60);
/// assert_eq!(clamp_volume(40, 10), 10);
/// assert_eq!(clamp_volume(100, 90), 90);
/// assert_eq!(clamp_volume(100, 150), 100);
/// ```
#[must_use]
pub fn clamp_volume(current: u8, requested: u8) -> u8 {
    let current = current.min(MAX_VOLUME);
    let requested = requested.min(MAX_VOLUME);
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
/// The crate keeps the sequence across the attempts it makes itself and reports each step in
/// [`Event::Disconnected`]. A host that drives its own loop, for example because it wants to stop
/// retrying, can use this function for the same policy.
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
/// Events are ordered as the connection produced them. A connection attempt ends with at most one
/// [`Event::Disconnected`], and the crate then reconnects on its own, so a later event belongs to
/// the next attempt. The enum is non-exhaustive: a later revision adds events without breaking a
/// host's match.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The Noise handshake finished and the session is ready for playback.
    ///
    /// Reported once per successful attempt. `encrypted` is always `true`: this client has no path
    /// that speaks to a server without Noise, so the field documents the property rather than
    /// hedging it.
    Connected {
        /// The server's static public key as 43 base64url characters.
        server_id: String,
        /// Whether the connection is encrypted; always `true`.
        encrypted: bool,
    },
    /// The attempt ended.
    ///
    /// Another attempt follows unless the audio sink failed or the host dropped the connection.
    /// `reason` is human-readable and never contains key material. `retry_in` is the delay
    /// before the next attempt, one step of the reconnect policy: it is two seconds after an
    /// attempt that never reached [`Event::Connected`], doubles with every further failed attempt
    /// up to [`ClientConfig::max_backoff`], and drops to one second again after a session that
    /// connected.
    Disconnected {
        /// Why the attempt ended.
        reason: String,
        /// How long to wait before the next attempt.
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
/// The connection reconnects on its own after a drop, so the handle and the event stream outlive
/// an individual session. Dropping the handle or the event stream ends it; [`ClientHandle::finished`]
/// waits without ending it.
#[derive(Debug)]
pub struct ClientHandle {
    task: Option<JoinHandle<Result<()>>>,
    control: ControlHandle,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ClientHandle {
    /// Returns a handle for the playback controls of this connection.
    ///
    /// The handle is a cheap clone; every copy controls the same connection.
    #[must_use]
    pub fn control(&self) -> ControlHandle {
        self.control.clone()
    }

    /// Waits for the connection to end and returns its outcome.
    ///
    /// The connection ends when the handle or the event stream is dropped, or when the audio sink
    /// fails; a dropped session is reconnected, not returned. Awaiting this keeps the handle alive,
    /// so dropping the event stream is the usual way to stop.
    pub async fn finished(mut self) -> Result<()> {
        let task = self.task.take().expect("the handle owns its task");
        task.await.context("the connection task panicked")?
    }
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        // `finished` takes the task, so a handle that is only waiting on the connection does not
        // stop it; a handle that is dropped asks the connection to end.
        if self.task.is_some() {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
        }
    }
}

/// Playback controls for a live connection.
///
/// A call returns once the connection has handled it: a transport command has been written to the
/// server, and a level or mute change has been recorded and included in the next state report. It
/// is an error when the connection has ended, when no session is established at that moment, and
/// when the server did not activate the role the command belongs to: transport commands need
/// `controller@v1`, volume and mute state need `player@v1`. A transport command the server did not
/// list in its controller state is refused as well, so a host can offer exactly the buttons the
/// server accepts.
#[derive(Debug, Clone)]
pub struct ControlHandle {
    commands: mpsc::UnboundedSender<ControlRequest>,
    volume: Arc<AtomicU8>,
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

    /// Sets the output level, limited by [`clamp_volume`] against the level in force, and returns
    /// the level that was applied.
    ///
    /// The level belongs to the connection: the session reports the applied value to the server
    /// with its next state report, which is the initial report when the first clock measurement is
    /// still pending, and every reconnect keeps it. A new connection starts from
    /// [`ClientConfig::volume`], so a host passes the level it restored there and uses this call
    /// for changes after that. [`ControlHandle::volume`] answers what is in force without a call.
    pub async fn set_volume(&self, level: u8) -> Result<u8> {
        self.send(ControlAction::Volume(level)).await
    }

    /// Sets the mute state without changing the level.
    ///
    /// The reported level therefore stays what it was, and the server sees the mute in the
    /// `muted` field alone.
    pub async fn set_muted(&self, muted: bool) -> Result<()> {
        self.send(ControlAction::Mute(muted)).await.map(|_level| ())
    }

    /// Returns the volume level in force.
    ///
    /// The value follows every change the connection made or received, including a mute, which
    /// leaves it untouched. It is available without a call, so a host can render its slider while
    /// the connection is reconnecting.
    #[must_use]
    pub fn volume(&self) -> u8 {
        self.volume.load(Ordering::Relaxed)
    }

    /// Sends one controller command.
    async fn transport(&self, command: &'static str) -> Result<()> {
        self.send(ControlAction::Transport(command))
            .await
            .map(|_level| ())
    }

    /// Queues one request and waits for the level in force after it.
    async fn send(&self, action: ControlAction) -> Result<u8> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(ControlRequest { action, reply })
            .map_err(|_| anyhow!("the connection has ended"))?;
        response
            .await
            .map_err(|_| anyhow!("the connection ended before it answered"))?
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
///
/// The answer is the volume level in force after the request; a transport command and a mute
/// leave it unchanged.
pub(crate) struct ControlRequest {
    /// Operation to perform.
    pub(crate) action: ControlAction,
    /// Answer for the waiting call.
    pub(crate) reply: oneshot::Sender<Result<u8>>,
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

/// Connects to a server and returns its handle and event stream.
///
/// The configuration is validated before this returns; the connection itself runs in a spawned
/// task and is reported through the event stream, with [`Event::Connected`] as the first event of a
/// successful attempt.
///
/// The task owns the sink and every attempt, so it reconnects after a drop with the same identity
/// and sink and with the level, mute state and roles the previous session had. Each drop is
/// reported as [`Event::Disconnected`] together with the delay before the next attempt. The
/// connection ends when the sink fails, which the host has to repair, or when the handle or the
/// event stream is dropped.
///
/// # Errors
/// Returns an error for an invalid [`ClientConfig`] and for a server address this build cannot use
/// (including a TLS URL). An unreachable server is not an error: the connection reports it as
/// [`Event::Disconnected`] and keeps retrying.
///
/// # Panics
/// Panics when called outside a Tokio runtime, because the connection is spawned.
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
/// The keys are used for the handshake only; they are not stored or logged. A reconnect uses them
/// again, so a pairing that worked keeps working.
///
/// # Errors
/// Same as [`connect`]. A record that belongs to another server fails the handshake of that
/// attempt and is reported as [`Event::Disconnected`].
pub async fn connect_with_psks(
    config: ClientConfig,
    sink: Box<dyn Sink>,
    psks: Vec<StoredPsk>,
) -> Result<(ClientHandle, EventStream)> {
    config.validate()?;
    let endpoint = endpoint(&config.server)?;

    let (events, receiver) = mpsc::unbounded_channel();
    let (commands, control) = mpsc::unbounded_channel();
    let (shutdown, shutdown_rx) = oneshot::channel();
    let reported_volume = Arc::new(AtomicU8::new(config.volume));

    let carried = Carried {
        sink,
        control: Some(control),
        volume: config.volume,
        muted: config.muted,
        active_roles: Vec::new(),
    };
    let connection = Connection {
        endpoint,
        config,
        psks,
        events: events.clone(),
        reported_volume: Arc::clone(&reported_volume),
    };

    let task = tokio::spawn(async move {
        tokio::select! {
            result = serve_until_dropped(connection, carried) => result,
            _ = shutdown_rx => Ok(()),
        }
    });

    let handle = ClientHandle {
        task: Some(task),
        control: ControlHandle {
            commands,
            volume: reported_volume,
        },
        shutdown: Some(shutdown),
    };
    Ok((handle, EventStream { events: receiver }))
}

/// Opens one WebSocket, treating an address that does not answer as an error.
async fn open(endpoint: &str) -> Result<Transport> {
    tokio::time::timeout(CONNECT_TIMEOUT, Transport::connect(endpoint))
        .await
        .with_context(|| format!("timed out connecting to {endpoint}"))?
}

/// The parts of a connection that do not change across attempts.
struct Connection {
    endpoint: String,
    config: ClientConfig,
    psks: Vec<StoredPsk>,
    events: mpsc::UnboundedSender<Event>,
    /// Level shared with every [`ControlHandle`].
    reported_volume: Arc<AtomicU8>,
}

impl Connection {
    /// Delivers one event, ignoring a stream the host dropped.
    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }
}

/// One wake-up while no session is established.
enum Wakeup {
    /// A control handle sent a request.
    Control(Option<ControlRequest>),
    /// The delay elapsed.
    Deadline,
    /// The host dropped the event stream.
    Closed,
}

/// Answers a request that arrived while no session was established.
fn refuse(request: ControlRequest) {
    let _ = request
        .reply
        .send(Err(anyhow!("no connection is established")));
}

/// Waits before the next attempt, refusing control requests meanwhile.
///
/// Returns `false` when the host dropped the event stream and the connection should end.
async fn wait_before_retry(
    connection: &Connection,
    carried: &mut Carried,
    delay: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + delay;
    loop {
        if connection.events.is_closed() {
            return false;
        }
        let control = &mut carried.control;
        let wakeup = tokio::select! {
            biased;
            request = async {
                match control {
                    Some(receiver) => receiver.recv().await,
                    None => std::future::pending().await,
                }
            } => Wakeup::Control(request),
            () = tokio::time::sleep_until(deadline) => Wakeup::Deadline,
            () = connection.events.closed() => Wakeup::Closed,
        };
        match wakeup {
            Wakeup::Control(Some(request)) => refuse(request),
            Wakeup::Control(None) => *control = None,
            Wakeup::Deadline => return true,
            Wakeup::Closed => return false,
        }
    }
}

/// Runs connection attempts until the host drops the connection or the sink fails.
///
/// Every attempt, including the first, is opened here. A failed one is followed by the next after
/// the delay [`next_backoff`] computes, with the sink, the level, the mute state and the roles
/// carried over.
async fn serve_until_dropped(connection: Connection, mut carried: Carried) -> Result<()> {
    // The first attempt is not preceded by a wait, but the policy starts at the initial delay, so a
    // failure before any session connected reports two seconds: one growth step from that value.
    let mut delay = INITIAL_BACKOFF;

    loop {
        let transport = match open(&connection.endpoint).await {
            Ok(transport) => transport,
            Err(error) => {
                delay = next_backoff(delay, false, connection.config.max_backoff);
                connection.emit(Event::Disconnected {
                    reason: format!("cannot connect to {}: {error:#}", connection.endpoint),
                    retry_in: delay,
                });
                if !wait_before_retry(&connection, &mut carried, delay).await {
                    return Ok(());
                }
                continue;
            }
        };

        let attempt = session::attempt(
            transport,
            &connection.config,
            &connection.events,
            &connection.psks,
            &connection.reported_volume,
            carried,
        )
        .await;
        carried = attempt.carried;

        // Nothing buffered for the session that ended may become audible later; the flush runs
        // before the host hears about the drop so the output stops even if the next attempt takes
        // a while.
        let flush_error = carried.sink.flush().err().map(|error| {
            error.context("the audio sink rejected a flush after the connection ended")
        });

        delay = next_backoff(delay, attempt.connected, connection.config.max_backoff);
        connection.emit(Event::Disconnected {
            reason: attempt.ending.reason(),
            retry_in: delay,
        });

        if attempt.sink_failed {
            // A broken output cannot be repaired by reconnecting; the host has to fix the sink.
            return match attempt.ending {
                session::Ending::Failed(error) => Err(error),
                session::Ending::Closed => Err(anyhow!("the audio sink failed")),
            };
        }
        if let Some(error) = flush_error {
            return Err(error);
        }

        if !wait_before_retry(&connection, &mut carried, delay).await {
            return Ok(());
        }
    }
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
