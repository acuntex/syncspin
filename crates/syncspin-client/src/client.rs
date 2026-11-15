//! Public client surface: events, handles and the connection entry point.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::{ClientConfig, StoredPsk};
use crate::session::{Session, Transport};
use crate::sink::{AudioFormat, Sink};

/// How long the TCP and WebSocket handshake may take before it is treated as unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// session recommends before a new connection: this revision schedules no retries itself and
    /// reports [`Duration::ZERO`], so a host applies its own backoff, bounded by
    /// [`ClientConfig::max_backoff`]. A later revision may compute the value.
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
    /// The session reports the request unchanged; applying platform limits and reporting the
    /// applied value back to the server is the host's decision. Exactly one of the two fields is
    /// present: a volume command carries the requested level, a mute command the requested state.
    /// A mute command therefore never looks like a request to set the volume to zero.
    Volume {
        /// Volume in the range 0-100 that was requested.
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
}

impl ClientHandle {
    /// Waits for the session to end and returns its outcome.
    ///
    /// A clean server close is `Ok(())`; a handshake, transport, protocol or sink failure is the
    /// error that ended the session. The matching [`Event::Disconnected`] has already been
    /// delivered when this returns.
    pub async fn finished(self) -> Result<()> {
        self.task.await.context("the session task panicked")?
    }
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
    let task = tokio::spawn(Session::start(transport, config, sink, events, psks));
    Ok((ClientHandle { task }, EventStream { events: receiver }))
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
