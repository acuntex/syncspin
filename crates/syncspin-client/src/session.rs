//! The connection state machine: Noise handshake, clock estimate, dispatch and audio delivery.
//!
//! The session is created after the WebSocket is open and runs until the connection ends. It
//! never speaks to a server without Noise: only the init exchange and the two Noise handshake
//! messages travel as cleartext text, and every application message is a Noise transport message.
//! A server that does not start the handshake times out; there is no plaintext path to fall back
//! to.
//!
//! The server may repeat the Noise handshake inside the encrypted channel to rotate the session
//! keys; that second handshake keeps the WebSocket, the open stream, the buffered audio and the
//! clock estimate, and changes nothing but the keys and the pairing index. See
//! `Session::begin_rehandshake`.

use std::collections::BTreeSet;
use std::future::pending;
#[cfg(feature = "pairing-code")]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(feature = "pairing-code")]
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use syncspin_core::clock::{ClockFilter, TimeSample};
use syncspin_core::framing::{
    encode_binary, Reassembler, BINARY_MESSAGE_ID_JSON, MAX_REASSEMBLED_LEN,
};
use syncspin_core::messages::{
    AudioChunkHeader, ClientCommand, ClientGoodbye, ClientHello, ClientInit, ClientPairFinalize,
    ClientPairInit, ClientState, ClientTime, ControllerCommand, DeviceInfo, GroupUpdate, Incoming,
    NoiseHandshake, PairAbort, PairingActivation, PairingPskMethod, PlayerState, PlayerSupport,
    ServerActivate, ServerCommand, ServerState, ServerTime, StreamClear, StreamStart,
    SupportedFormat, SupportedPairMethods, UnpairedAccess, AUDIO_CHUNK_ID, NOISE_SUITE,
    PROTOCOL_VERSION,
};
#[cfg(feature = "pairing-code")]
use syncspin_core::messages::{
    ClientPairAuth, ClientPairConfirm, ClientPairPending, ClientPairRetry,
    DynamicPairingCodeMethod, ServerPairAuth, ServerPairConfirm, ServerPairInit,
    StaticPairingCodeMethod,
};
use syncspin_core::noise::{
    psk_id_for, Responder, TransportState as NoiseTransport, SENTINEL_PSK, SENTINEL_PSK_ID,
};
#[cfg(feature = "pairing-code")]
use syncspin_core::pairing::pake::TAG_LEN;

use crate::client::{
    check_reported_level, clamp_volume_with, ControlAction, ControlRequest, Event, GoodbyeReason,
    PairingFailure, PairingRequiredReason, PlaybackState, StreamEndReason, NORMAL_PLAYBACK_SPEED,
};
#[cfg(feature = "pairing-code")]
use crate::config::CodeFormat;
use crate::config::{AudioMode, ClientConfig, PskCategory, StoredPsk};
#[cfg(feature = "pairing-code")]
use crate::pairing::{
    pake_sid, TagOutcome, METHOD_DYNAMIC_PAIRING_CODE, METHOD_STATIC_PAIRING_CODE,
};
use crate::pairing::{Candidates, MatchedPsk, PairingAttempt, PairingPsk, METHOD_PAIRING_PSK};
use crate::sink::{AudioFormat, AudioFrame, Codec, Sink};
use crate::storage::persist_pairing;

/// How long the Noise handshake may take, from `client/init` to the first `server/activate`.
///
/// The same bound applies to a re-handshake: from the moment message 2 puts the new keys in place,
/// the server has this long to send the activation they belong to.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of `client/time` round trips in one clock-sync burst.
const SYNC_MESSAGES: usize = 8;

/// How long to wait for one `server/time` reply before sending the next request.
///
/// The spec allows the client to move on without a reply after a timeout of its choosing.
const SYNC_REPLY_TIMEOUT: Duration = Duration::from_millis(250);

/// How long a `client/goodbye` may take before the connection is closed anyway.
///
/// The message is a courtesy that belongs to a graceful close: a peer that does not read its
/// window must not be able to hold a deliberate shutdown open.
const GOODBYE_TIMEOUT: Duration = Duration::from_millis(500);

/// Overall cap on one burst, so a peer that stalls cannot hold the session loop.
const SYNC_BURST_TIMEOUT: Duration = Duration::from_secs(2);

/// Minimum spacing between consecutive sync bursts, so a long stream keeps tracking the clock.
const RESYNC_INTERVAL: Duration = Duration::from_secs(5);

/// Versioned role identifier of the audio player.
const PLAYER_ROLE: &str = "player@v1";
/// Bare role name used by `stream/end` and `stream/clear` (see `messaging.md`).
const PLAYER_STREAM_ROLE: &str = "player";

/// Versioned role identifier of the now-playing metadata.
const METADATA_ROLE: &str = "metadata@v1";

/// Versioned role identifier of the group controller state.
const CONTROLLER_ROLE: &str = "controller@v1";

/// The roles this client advertises in `client/hello`.
///
/// The list is written here once, so the roles the client announces cannot drift apart from the
/// roles its activation check admits: both read this constant.
const SUPPORTED_ROLES: [&str; 3] = [PLAYER_ROLE, CONTROLLER_ROLE, METADATA_ROLE];

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

/// Length of a canonical unpadded base64url group identifier.
const GROUP_ID_LEN: usize = 43;

/// Longest non-canonical group identifier the tolerance accepts, in bytes of UTF-8.
///
/// The spec does not define a length for a foreign value, so this bound keeps an absurd identifier
/// from filling memory while leaving room for the UUID a real server sends.
const MAX_GROUP_ID_LEN: usize = 128;

/// How many failed key confirmations one pairing window admits.
///
/// `pairing.md`: the window closes on its fifth failed attempt, where a failure is the client's
/// verification of `server_kc`. Any other way an attempt ends leaves the window open.
#[cfg(feature = "pairing-code")]
const WINDOW_FAILURE_LIMIT: u8 = 5;

/// How many rounds the Dynamic Pairing Code Flow runs without a verified `server_kc`.
///
/// `pairing.md`: after twenty rounds since the last verified `server_kc`, the client MUST abort
/// instead of retrying, and holds further attempts back until a deliberate operator action. The
/// count is per process, not per server, so it lives beside the connection rather than in it.
#[cfg(feature = "pairing-code")]
const ROUND_LIMIT: u32 = 20;

/// Player commands this client accepts from the server.
const PLAYER_COMMANDS: [&str; 2] = ["volume", "mute"];

/// Control message types that belong to pairing, whose malformed form is a protocol error.
///
/// `pairing.md` treats a malformed or missing pairing field as a protocol error: the connection
/// closes without an application-level message and nothing is persisted. Every other malformed
/// control message keeps the lenient path, because one bad optional field must not silence
/// playback. `server/pair-init` belongs to the dynamic flow; the client's own `client/pair-retry`
/// never arrives, so it needs no entry here.
const PAIRING_MESSAGE_TYPES: [&str; 5] = [
    "server/pair-init",
    "server/pair-auth",
    "server/pair-confirm",
    "server/pair-finalize",
    "pair/abort",
];

/// An established WebSocket connection to a server.
///
/// This is the socket layer only: cleartext JSON during the handshake, one Noise transport
/// message per binary frame afterwards. Control frames are answered here so the session only sees
/// application messages.
pub(crate) struct Transport {
    socket: Socket,
}

/// The WebSocket a session runs on, and which side opened it.
///
/// The connection mode changes who dials, not who starts the Noise handshake: the server is the
/// initiator either way (`connection.md`, _Encryption_). Only the socket type differs, so the
/// session above this sees one transport.
enum Socket {
    /// The client dialled a server it found, the client-initiated mode.
    Dialled(WebSocketStream<MaybeTlsStream<TcpStream>>),
    /// A server dialled the endpoint this client advertised, the server-initiated mode.
    #[cfg(feature = "discovery")]
    Accepted(WebSocketStream<TcpStream>),
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
        Ok(Transport {
            socket: Socket::Dialled(socket),
        })
    }

    /// Wraps a WebSocket a server opened on this client's advertised endpoint.
    #[cfg(feature = "discovery")]
    pub(crate) fn accept(socket: WebSocketStream<TcpStream>) -> Transport {
        Transport {
            socket: Socket::Accepted(socket),
        }
    }

    /// Reads the next application message, answering pings on the way.
    pub(crate) async fn read(&mut self) -> Result<SocketMessage> {
        loop {
            let message = match &mut self.socket {
                Socket::Dialled(socket) => socket.next().await,
                #[cfg(feature = "discovery")]
                Socket::Accepted(socket) => socket.next().await,
            }
            .transpose()
            .context("the WebSocket read failed")?;
            match message {
                Some(Message::Text(text)) => {
                    return Ok(SocketMessage::Text(text.as_str().to_owned()))
                }
                Some(Message::Binary(bytes)) => return Ok(SocketMessage::Binary(bytes.to_vec())),
                Some(Message::Ping(payload)) => {
                    self.send(Message::Pong(payload)).await?;
                }
                Some(Message::Pong(_)) | Some(Message::Frame(_)) => continue,
                Some(Message::Close(_)) | None => return Ok(SocketMessage::Closed),
            }
        }
    }

    /// Sends one cleartext JSON text frame.
    pub(crate) async fn send_text(&mut self, text: &str) -> Result<()> {
        self.send(Message::text(text)).await
    }

    /// Sends one binary frame.
    pub(crate) async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.send(Message::binary(bytes)).await
    }

    /// Sends a WebSocket close frame.
    #[cfg(feature = "discovery")]
    pub(crate) async fn close(&mut self) -> Result<()> {
        self.send(Message::Close(None)).await
    }

    /// Writes one WebSocket message on whichever socket this connection runs on.
    async fn send(&mut self, message: Message) -> Result<()> {
        match &mut self.socket {
            Socket::Dialled(socket) => socket.send(message).await,
            #[cfg(feature = "discovery")]
            Socket::Accepted(socket) => socket.send(message).await,
        }
        .context("the WebSocket send failed")
    }
}

/// A handshake result: the connection is encrypted and the roles are known.
struct Ready {
    transport: Transport,
    noise: NoiseTransport,
    server_id: String,
    /// Roles the first `server/activate` declares, with the previous set when it omits them.
    active_roles: Vec<String>,
    /// The first `server/activate` itself, applied by the session once it is running.
    activate: ServerActivate,
    /// Which key sealed the handshake, which decides the pairing methods this connection allows.
    matched: MatchedPsk,
    /// Whether the handshake fell back to the Sentinel key although the server named another
    /// credential, which is the server's authenticated credential-mismatch signal.
    credential_mismatch: bool,
}

/// A re-handshake whose keys are already in place, waiting for its activation.
///
/// The client is the responder, as in the initial handshake, but the two `noise/handshake`
/// messages travel inside the encrypted channel: message 1 arrives under the keys in force,
/// message 2 goes back the same way, and the keys change as soon as it is written. This window
/// spans the gap between those new keys and the `server/activate` that must be their first
/// message; while it is open the client sends no application message and acts on none.
struct Rehandshake {
    /// The keys of the previous handshake, kept only to recognise and discard a message the server
    /// sent before it processed message 2. Dropped when the activation ends the window.
    previous: NoiseTransport,
    /// Deadline for the activation under the new keys.
    deadline: Instant,
}

/// The pairing window of this connection.
///
/// The window belongs to the connection that carried its opening gesture: it is opened by a
/// [`ControlHandle`](crate::ControlHandle) request on that connection and closes when the session
/// ends, so it can never admit an attempt on a later connection. The lifetime runs from the
/// gesture without pausing during attempts, and the fifth failed key confirmation closes it too.
#[cfg(feature = "pairing-code")]
struct PairingWindow {
    /// When the operator's gesture opened the window.
    opened: Instant,
    /// Failed `server_kc` verifications this window has seen.
    failed_attempts: u8,
}

/// A code-flow activation whose attempt waits for an operator gesture or a released hold-back.
///
/// `client/pair-pending` is on the wire and no attempt is running: the timeout starts with
/// `client/pair-init`, so a server that waits for the gesture is not racing it.
#[cfg(feature = "pairing-code")]
struct PendingPairing {
    /// The pairing index its activation gave `client/pair-init`.
    pairing_index: u32,
    /// The method whose gesture releases the attempt.
    method: AdmittedMethod,
    /// The emission format the dynamic flow was activated with; `None` for the static flow.
    format: Option<CodeFormat>,
}

/// The pairing methods an activation can admit on this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmittedMethod {
    /// The Pairing PSK flow.
    PairingPsk,
    /// The Static Pairing Code flow.
    #[cfg(feature = "pairing-code")]
    StaticCode,
    /// The Dynamic Pairing Code flow.
    #[cfg(feature = "pairing-code")]
    DynamicCode,
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
    /// Failed dynamic pairing rounds since the last verified `server_kc`.
    ///
    /// The count belongs to the process, not to the connection: `pairing.md` does not partition it
    /// by server, and a reconnect must not reset it. Only a verified `server_kc` or
    /// [`ControlHandle::release_holdback`](crate::ControlHandle::release_holdback) resets it.
    #[cfg(feature = "pairing-code")]
    pub(crate) failed_rounds: Arc<AtomicU32>,
}

/// How one connection attempt ended.
#[derive(Debug)]
pub(crate) enum Ending {
    /// The server closed the connection.
    Closed,
    /// The server dropped this client's pairing record, so the client ended the connection.
    Unpaired,
    /// The server wanted an unpaired session and this client does not admit one.
    PairingRequired,
    /// The server's activation is not allowed for the key that sealed this connection.
    Unauthorized,
    /// The host closed the connection deliberately, after saying why.
    Shutdown,
    /// The attempt failed.
    Failed(anyhow::Error),
}

impl Ending {
    /// The reason reported in [`Event::Disconnected`], without key material.
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::Closed => "the server closed the connection".to_owned(),
            Self::Unpaired => "the server dropped this client's pairing record".to_owned(),
            Self::PairingRequired => {
                "the server wanted an unpaired session and this client does not admit one"
                    .to_owned()
            }
            Self::Unauthorized => {
                "the server's activation is not allowed for the key that sealed this connection"
                    .to_owned()
            }
            Self::Shutdown => "the client closed the connection".to_owned(),
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
    /// The host closed the connection and gave the reason to send.
    Shutdown(GoodbyeReason),
    /// The clock deadline elapsed.
    Clock,
}

/// The kind of one decrypted transport message, decided by its binary message id.
///
/// The kind decides how strict the session is: a control message that does not decode is ignored,
/// while a malformed audio chunk stays a protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    /// A control or state message: a JSON body under [`BINARY_MESSAGE_ID_JSON`].
    Control,
    /// A player audio chunk under [`AUDIO_CHUNK_ID`].
    Audio,
    /// A message id this revision does not implement.
    Unknown,
}

impl MessageKind {
    /// Classifies one binary message by its id byte.
    fn of(id: u8) -> MessageKind {
        match id {
            BINARY_MESSAGE_ID_JSON => MessageKind::Control,
            AUDIO_CHUNK_ID => MessageKind::Audio,
            _ => MessageKind::Unknown,
        }
    }
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
    /// Transmit timestamps of the `client/time` requests the current burst has sent.
    ///
    /// A reply is accepted for any of these, not only the request on the wire: a reply that arrives
    /// after its per-message timeout is still a valid measurement of the burst, and the filter's
    /// error bound decides how much weight it carries. A timestamp is removed when its reply is
    /// consumed, so one request yields at most one sample even if the peer echoes it twice.
    burst_sent_us: BTreeSet<i64>,
    /// When the current or last burst started, for periodic re-sync spacing.
    burst_started: Option<Instant>,
    /// Samples collected during the current burst; only the best one is pushed.
    burst_samples: Vec<TimeSample>,
    /// Whether the player state was reported since the player role last became active.
    state_sent: bool,
    /// Requests from a [`crate::ControlHandle`], or `None` once every handle was dropped.
    control: Option<mpsc::UnboundedReceiver<ControlRequest>>,
    /// The host's deliberate close, with the reason to send before the connection ends.
    shutdown: &'a mut oneshot::Receiver<GoodbyeReason>,
    /// Output level in force, in the protocol's 0-100 range.
    volume: u8,
    /// Mute state in force.
    muted: bool,
    /// Whether a sink call failed, which the host has to repair before another attempt.
    sink_failed: bool,
    /// Whether this connection already reported a non-canonical `group_id`.
    ///
    /// The tolerance reports the departure once per connection, so a server that repeats the same
    /// foreign identifier does not produce a stream of events.
    group_id_tolerance_reported: bool,
    /// Controller commands the server last advertised, or `None` before its first controller
    /// state.
    controller_commands: Option<Vec<String>>,
    /// The state last reported to the host, merged from `group/update` and `server/state`.
    ///
    /// `group/update` supplies the group fields and `server/state` the controller ones, so either
    /// message can complete the picture the other has already filled in.
    playback: PlaybackState,
    /// Static public key of the server this connection talks to.
    server_id: String,
    /// Which key sealed the handshake.
    matched: MatchedPsk,
    /// A pairing requirement this connection still has to report, or `None` once it has.
    ///
    /// The handshake decides it once. Taking the value is what makes a second report of that reason
    /// impossible; the refused-activation reason is reported by `refuse_activation` instead and
    /// never touches this field.
    pairing_required: Option<PairingRequiredReason>,
    /// Why this connection has to end after the current wake-up, when a handler ended it instead of
    /// the peer. `serve` returns it on its next iteration.
    ending: Option<Ending>,
    /// The keys this connection may seal a re-handshake with, and the records a pairing completed
    /// on this connection adds to them.
    candidates: Candidates,
    /// Pairing `server/activate` messages received since the last handshake, the `pairing_index` a
    /// `client/pair-init` carries.
    pairing_index: u32,
    /// The pairing attempt in progress, or `None` when this connection is not pairing.
    pairing: Option<PairingAttempt>,
    /// Whether an attempt ended under the current activation, so its late messages are discarded.
    ///
    /// `pairing: None` means one of two things: no attempt was admitted since the last activation
    /// (a pairing message out of sequence is a protocol error), or an attempt ended and messages
    /// still in flight must be ignored until the next `server/activate` (the spec's silent-discard
    /// rule). This flag is what tells them apart. `apply_activate` and a re-handshake clear it.
    discarding_pairing_messages: bool,
    /// The pairing window the operator opened on this connection, or `None` when it is closed.
    #[cfg(feature = "pairing-code")]
    pairing_window: Option<PairingWindow>,
    /// A code-flow activation whose attempt waits for an operator gesture.
    #[cfg(feature = "pairing-code")]
    pending_pairing: Option<PendingPairing>,
    /// Failed dynamic pairing rounds since the last verified `server_kc`, shared by the process.
    #[cfg(feature = "pairing-code")]
    failed_rounds: Arc<AtomicU32>,
    /// A re-handshake whose new keys are in place, or `None` when the connection is not switching
    /// keys.
    rehandshake: Option<Rehandshake>,
}

/// Runs one connection attempt: the handshake, then the session loop.
///
/// Every failure after the WebSocket is open - handshake, protocol, transport or sink - ends the
/// attempt and is reported by the caller as one [`Event::Disconnected`]. The state the next
/// attempt starts from comes back in the result, so the sink, the level, the mute state and the
/// roles survive the drop. `shutdown` carries the host's deliberate close; it is polled by the
/// session loop, which says goodbye and ends the attempt without a reconnect.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn attempt(
    transport: Transport,
    config: &ClientConfig,
    events: &mpsc::UnboundedSender<Event>,
    psks: &[StoredPsk],
    pairing_psk: Option<PairingPsk>,
    reported_volume: &AtomicU8,
    carried: Carried,
    shutdown: &mut oneshot::Receiver<GoodbyeReason>,
) -> Attempt {
    // The store's records are read for every attempt, so a record a completed pairing wrote is a
    // candidate for the next connection. A store that cannot be read fails this attempt rather
    // than letting the handshake continue with fewer keys.
    let candidates = match Candidates::load(config.storage.as_deref(), psks, pairing_psk) {
        Ok(candidates) => candidates,
        Err(error) => {
            return Attempt {
                carried,
                connected: false,
                sink_failed: false,
                ending: Ending::Failed(error),
            };
        }
    };

    let handshake = tokio::select! {
        result = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            handshake(transport, config, &candidates, &carried.active_roles),
        ) => result,
        // The host closed while the handshake was running. There is no session to say goodbye on
        // yet, and the attempt must not report a failure or schedule a reconnect.
        reason = &mut *shutdown => {
            let _ = reason;
            return Attempt {
                carried,
                connected: false,
                sink_failed: false,
                ending: Ending::Shutdown,
            };
        }
    };
    let ready = match handshake {
        Ok(result) => result,
        Err(_elapsed) => Err(HandshakeError::Failed(anyhow!(
            "timed out during the Noise handshake"
        ))),
    };
    let ready = match ready {
        Ok(ready) => ready,
        // The server said why it refused `client/init`. The host hears the reason verbatim before
        // the attempt is reported as failed.
        Err(HandshakeError::ServerRejected(reason)) => {
            let _ = events.send(Event::ServerError {
                reason: reason.clone(),
            });
            return Attempt {
                carried,
                connected: false,
                sink_failed: false,
                ending: Ending::Failed(anyhow!("the server rejected client/init: {reason}")),
            };
        }
        Err(HandshakeError::Failed(error)) => {
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
        burst_sent_us: BTreeSet::new(),
        burst_started: None,
        burst_samples: Vec::new(),
        state_sent: false,
        control: carried.control,
        shutdown,
        volume: carried.volume,
        muted: carried.muted,
        sink_failed: false,
        group_id_tolerance_reported: false,
        controller_commands: None,
        playback: PlaybackState::default(),
        server_id: ready.server_id.clone(),
        matched: ready.matched,
        pairing_required: ready
            .credential_mismatch
            .then_some(PairingRequiredReason::CredentialMismatch),
        ending: None,
        candidates,
        pairing_index: 0,
        pairing: None,
        discarding_pairing_messages: false,
        #[cfg(feature = "pairing-code")]
        pairing_window: None,
        #[cfg(feature = "pairing-code")]
        pending_pairing: None,
        #[cfg(feature = "pairing-code")]
        failed_rounds: carried.failed_rounds,
        rehandshake: None,
    };
    session.publish_volume();

    session.emit(Event::Connected {
        server_id: ready.server_id,
        encrypted: true,
    });
    // The handshake's credential decision reaches the host before anything the session does with
    // it, and exactly once per connection.
    session.report_pairing_required();

    // The handshake consumed the first activation; it is applied here, now that the session can
    // answer it. A pairing activation in it starts the attempt just as a later one does.
    let prepared = session.apply_activate(ready.activate).await;
    if prepared.is_ok() && session.player_active() {
        session.start_burst();
    }

    let ending = match prepared {
        Err(error) => Ending::Failed(error),
        Ok(()) => match session.serve().await {
            Ok(ending) => ending,
            Err(error) => Ending::Failed(error),
        },
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
            #[cfg(feature = "pairing-code")]
            failed_rounds: self.failed_rounds,
        }
    }

    /// Reads, dispatches and delivers until the connection ends.
    async fn serve(&mut self) -> Result<Ending> {
        loop {
            if self.events.is_closed() {
                return Ok(Ending::Closed);
            }
            // A handler that ends the connection - `server/unpair` and a refused activation - set
            // the reason while the frame was dispatched; the connection is closed here.
            if let Some(ending) = self.ending.take() {
                return Ok(ending);
            }

            // A re-handshake suspends the clock work: no application message may be sent until the
            // new activation arrives, so a burst is not started and no request is put on the wire.
            if self.rehandshake.is_none() {
                self.drive_clock().await?;
            }

            // While a request is on the wire the read has its reply deadline; the overall burst
            // deadline and the pairing attempt's deadline are the backstops. Any other frame still
            // arrives normally, and a control request is served between frames. A re-handshake
            // replaces all of them with its own deadline for the activation.
            let deadline = match &self.rehandshake {
                Some(window) => Some(window.deadline),
                None => [
                    self.reply_deadline,
                    self.burst_deadline,
                    self.pairing_deadline(),
                ]
                .into_iter()
                .flatten()
                .min(),
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
                reason = &mut *self.shutdown => {
                    Wakeup::Shutdown(reason.unwrap_or(GoodbyeReason::Shutdown))
                }
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
                // The host closed the connection: say why, then end the attempt. Neither a failed
                // goodbye nor a socket that is already gone turns this into a reconnect.
                Wakeup::Shutdown(reason) => {
                    self.send_goodbye(reason).await;
                    return Ok(Ending::Shutdown);
                }
                Wakeup::Socket(message) => match message? {
                    SocketMessage::Text(_) => {
                        bail!("cleartext text after the Noise transport is a protocol error")
                    }
                    // The caller turns the end into a Disconnected event and schedules the next
                    // attempt, so the sink, the level and the roles survive the drop.
                    SocketMessage::Closed => return Ok(Ending::Closed),
                    SocketMessage::Binary(ciphertext) => self.receive(&ciphertext).await?,
                },
                Wakeup::Clock => {
                    if self.rehandshake.is_some() {
                        // The server must send its activation under the new keys; staying silent
                        // leaves the client with no channel it may use.
                        bail!("timed out waiting for the server/activate of a re-handshake")
                    }
                    self.handle_clock_timeout().await?;
                }
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
            self.burst_sent_us.insert(client_transmitted);
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
        self.burst_sent_us.clear();
        self.burst_started = Some(Instant::now());
        self.burst_samples.clear();
    }

    /// Handles a deadline that fired while the session was waiting.
    ///
    /// A per-message clock timeout moves the burst on to its next request. When the last request
    /// times out the burst ends unless it holds no sample yet: a sample already in hand cannot be
    /// beaten by a later reply's larger error bound, while a burst with nothing buffered has
    /// everything to gain from waiting for late replies until its deadline. The pairing attempt's
    /// timeout is checked first, because it ends the attempt instead of continuing it.
    async fn handle_clock_timeout(&mut self) -> Result<()> {
        if self
            .pairing_deadline()
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            return self.abort_pairing(PairingFailure::AttemptTimeout).await;
        }
        let burst_expired = self
            .burst_deadline
            .is_some_and(|deadline| deadline <= Instant::now());
        if burst_expired {
            return self.finish_burst().await;
        }
        // A per-message timeout only releases the request on the wire so the next one can go out.
        self.reply_deadline = None;
        self.outstanding_sent_us = None;
        if self.sync_remaining == 0 {
            // The last request just timed out. A sample already buffered cannot be beaten by a
            // later reply's larger error bound, so the burst ends now instead of idling to the
            // burst deadline. With nothing buffered, a late reply is the only hope of a sample, so
            // the burst stays open until its deadline.
            if !self.burst_samples.is_empty() {
                self.finish_burst().await?;
            }
        }
        Ok(())
    }

    /// Ends the current burst: pushes its best measurement and reports the state if it is still
    /// owed (a burst with no usable reply reports nothing).
    async fn finish_burst(&mut self) -> Result<()> {
        self.burst_deadline = None;
        self.reply_deadline = None;
        self.outstanding_sent_us = None;
        self.burst_sent_us.clear();
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
    ///
    /// While a re-handshake waits for its activation, the only message the client may act on is
    /// that activation. A message that still authenticates under the previous keys was sent by the
    /// server before it processed message 2: the spec allows discarding it, and it must not end a
    /// connection that is otherwise fine.
    async fn receive(&mut self, ciphertext: &[u8]) -> Result<()> {
        let plaintext = match self.noise.decrypt(ciphertext) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                let tolerated = self
                    .rehandshake
                    .as_mut()
                    .is_some_and(|window| window.previous.decrypt(ciphertext).is_ok());
                if tolerated {
                    return Ok(());
                }
                return Err(error);
            }
        };
        let Some((id, body)) = self.reassembler.push(&plaintext)? else {
            return Ok(());
        };
        if self.rehandshake.is_some() {
            return self.handle_activation_message(id, &body).await;
        }
        // The kind of the message decides how strict the dispatch is: a control message that does
        // not decode is ignored, while a malformed audio chunk stays a protocol error.
        match MessageKind::of(id) {
            MessageKind::Control => self.handle_control_message(&body).await,
            MessageKind::Audio => self.handle_audio(&body),
            // A message id belongs to a role this client does not implement.
            MessageKind::Unknown => Ok(()),
        }
    }

    /// Acts on the one message a re-handshake window admits: its `server/activate`.
    ///
    /// The spec makes that activation the server's first message under the new keys and forbids
    /// every other application message until it arrives, so anything else ends the attempt. The
    /// failure is silent on the wire, like every other handshake failure.
    async fn handle_activation_message(&mut self, id: u8, body: &[u8]) -> Result<()> {
        if id != BINARY_MESSAGE_ID_JSON {
            bail!("the server sent a non-control message instead of activating a re-handshake")
        }
        let text = std::str::from_utf8(body).context("decrypted JSON is not valid UTF-8")?;
        match Incoming::parse(text) {
            Ok(Some(Incoming::ServerActivate(activate))) => self.finish_rehandshake(activate).await,
            Ok(_) => {
                bail!("the server sent an application message before activating a re-handshake")
            }
            Err(error) => {
                bail!(
                    "the server sent a malformed message before activating a re-handshake: {error}"
                )
            }
        }
    }

    /// Dispatches one decrypted control or state message.
    ///
    /// A `type` this revision does not implement is ignored, as the protocol requires. A message
    /// that does not decode is ignored as well, with a line on stderr, instead of ending the
    /// session: one malformed field must not silence playback, and a message the client cannot
    /// decode carries nothing it could act on. The audio path keeps the strict rule - a malformed
    /// chunk header is a protocol error. See `docs/spec-deviations.md`, "A malformed control
    /// message is ignored, not fatal".
    ///
    /// A body that is not valid UTF-8 is a framing error and still closes the connection.
    async fn handle_control_message(&mut self, body: &[u8]) -> Result<()> {
        let text = std::str::from_utf8(body).context("decrypted JSON is not valid UTF-8")?;
        match Incoming::parse(text) {
            Ok(None) => Ok(()), // A type this revision does not implement is ignored.
            // `noise/handshake` inside the transport is the server starting a re-handshake.
            Ok(Some(Incoming::NoiseHandshake(handshake))) => {
                self.begin_rehandshake(handshake).await
            }
            Ok(Some(message)) => self.dispatch(message).await,
            Err(error) => {
                if names_pairing_message(text) {
                    // A pairing message that does not decode is a protocol error: the flow cannot
                    // continue without the field, and ignoring it would leave a half-open attempt.
                    return Err(error.into());
                }
                eprintln!("ignoring a malformed control message: {error}");
                Ok(())
            }
        }
    }

    /// Acts on one decoded control message.
    async fn dispatch(&mut self, message: Incoming) -> Result<()> {
        match message {
            Incoming::ServerActivate(activate) => self.apply_activate(activate).await,
            Incoming::ServerTime(time) => self.handle_server_time(time).await,
            Incoming::ServerState(state) => {
                self.handle_state(state);
                Ok(())
            }
            Incoming::GroupUpdate(update) => self.handle_group_update(update),
            Incoming::ServerCommand(command) => self.handle_command(command).await,
            Incoming::StreamStart(start) => self.handle_stream_start(start),
            Incoming::StreamEnd(end) if !affects_player(end.roles.as_deref()) => Ok(()),
            Incoming::StreamEnd(_) => self.stop_stream(StreamEndReason::End),
            Incoming::StreamClear(clear) if !affects_player(clear.roles.as_deref()) => Ok(()),
            Incoming::StreamClear(clear) => self.handle_stream_clear(clear),
            Incoming::ServerPairFinalize(_) => self.confirm_pairing(),
            Incoming::ServerUnpair(_) => self.handle_unpair().await,
            Incoming::PairAbort(abort) => self.handle_pairing_abort(abort),
            #[cfg(feature = "pairing-code")]
            Incoming::ServerPairInit(init) => self.handle_server_init(init).await,
            #[cfg(feature = "pairing-code")]
            Incoming::ServerPairAuth(auth) => self.handle_server_auth(auth).await,
            #[cfg(feature = "pairing-code")]
            Incoming::ServerPairConfirm(confirm) => self.handle_server_confirm(confirm).await,
            // A message for a role or direction this client does not act on.
            _ => Ok(()),
        }
    }

    /// Starts the in-band re-handshake a `noise/handshake` message 1 announces.
    ///
    /// The new handshake's prologue is the hash of the handshake that established the current keys,
    /// and the client answers with message 2 without waiting for anything: both messages travel
    /// inside the channel the previous keys encrypt, and no init exchange is repeated. The new keys
    /// take over as soon as message 2 is written; from then until the `server/activate` that must
    /// follow, the client sends no application message and acts on none.
    ///
    /// A key none of the candidates matches ends the connection: a re-handshake has no Sentinel
    /// fallback, because falling back would silently drop the pairing the previous handshake
    /// authenticated. The failure is silent on the wire, like every other handshake failure.
    async fn begin_rehandshake(&mut self, handshake: NoiseHandshake) -> Result<()> {
        if self.rehandshake.is_some() {
            bail!("the server started a second Noise handshake before the first was activated");
        }
        let message_1 = URL_SAFE_NO_PAD
            .decode(&handshake.data)
            .context("noise/handshake data is not unpadded base64url")?;
        let peer = decode_server_key(&self.server_id)?;
        let prologue = *self.noise.handshake_hash();
        // A re-handshake keeps the suite of the connection it replaces: the peer derives the new
        // keys under the same one.
        let mut responder = Responder::with_peer_suite(
            &self.config.identity,
            &peer,
            self.noise.suite(),
            &prologue,
        )?;
        let metadata_payload = responder
            .read_message(&message_1)
            .context("failed to read Noise re-handshake message 1")?;
        let metadata = PskMetadata::parse(&metadata_payload)?;
        let selected = select_psk(&metadata, &self.candidates, &self.server_id, false)?;
        responder.set_psk(&selected.psk)?;

        // Message 2 is the last message the client sends under the previous keys.
        let message_2 = Incoming::NoiseHandshake(NoiseHandshake {
            data: URL_SAFE_NO_PAD.encode(responder.write_message()?),
        });
        self.send_json(&message_2).await?;
        let previous = std::mem::replace(&mut self.noise, responder.into_transport()?);

        // The burst belonged to the previous keys. The estimate itself stays: suspension only drops
        // the requests in flight, so playout deadlines keep their meaning across the swap.
        self.suspend_burst();
        // The index counts pairing activations since the last handshake, and this is a new one.
        self.pairing_index = 0;
        self.matched = selected.matched;
        self.discarding_pairing_messages = false;
        // An attempt belongs to the activation and the `h` that admitted it; the new handshake gives
        // both a new value, so the attempt and anything it was holding for are discarded. A server
        // that still wants to pair admits a new attempt under the new keys.
        self.pairing = None;
        #[cfg(feature = "pairing-code")]
        {
            self.pending_pairing = None;
        }
        self.rehandshake = Some(Rehandshake {
            previous,
            deadline: Instant::now() + HANDSHAKE_TIMEOUT,
        });
        Ok(())
    }

    /// Ends a re-handshake with the server's first activation under the new keys.
    async fn finish_rehandshake(&mut self, activate: ServerActivate) -> Result<()> {
        self.rehandshake = None;
        self.apply_activate(activate).await
    }

    /// Drops the run of clock requests while keeping the estimate they produced.
    ///
    /// Used whenever the connection has to stop sending for a moment: removing the player role and
    /// swapping session keys both cancel the requests an older state put on the wire.
    fn suspend_burst(&mut self) {
        self.sync_remaining = 0;
        self.burst_deadline = None;
        self.reply_deadline = None;
        self.outstanding_sent_us = None;
        self.burst_sent_us.clear();
        self.burst_samples.clear();
    }

    /// Applies a `server/activate`: role changes, stream teardown, pairing and state reporting.
    ///
    /// An activation that adds the `pairing` activity admits one pairing attempt; one that does not
    /// cancels the attempt in progress and persists nothing, which is how the spec lets a server
    /// end a pairing without finalizing it.
    async fn apply_activate(&mut self, activate: ServerActivate) -> Result<()> {
        // A refused activation ends the connection, so it is decided before anything is changed:
        // an activation this client will not honour must leave no half-applied state behind.
        //
        // Rule 1's counterfactual - "would enabling unpaired access admit this?" - needs the whole
        // of admissibility, pairing method included, so the guard is told before it decides whether
        // the declared method is acceptable on this connection. A malformed pairing activation
        // (declares `pairing` without its parameters) stays `true` so the guard decides first and
        // the protocol error still surfaces below.
        let pairing_admissible = match admits_pairing(&activate) {
            Ok(None) => true,
            Ok(Some(activation)) => self.admitted_method(&activation).is_some(),
            Err(_) => true,
        };
        if let Some(refusal) = admit_activation(
            self.matched,
            self.config.unpaired_access,
            pairing_admissible,
            &activate,
        )
        .refusal()
        {
            return self.refuse_activation(refusal).await;
        }

        // Every activation starts a new regime: messages from an attempt that ended before it are
        // stale, and a new attempt has not started yet.
        self.discarding_pairing_messages = false;
        let pairing = admits_pairing(&activate)?;
        if pairing.is_none() {
            // A cancelling activation discards the attempt and anything it already received. An
            // attempt that existed may still have messages on the wire, and those are discarded;
            // with no attempt at all, a pairing message is a sequence violation.
            self.discarding_pairing_messages = self.pairing.take().is_some();
            #[cfg(feature = "pairing-code")]
            {
                self.pending_pairing = None;
            }
        }

        let had_player = self.player_active();
        // The spec re-evaluates playback capability against the persisted roles instead of rejecting
        // a later activation for them: a connection that can no longer carry playback loses its
        // roles, and `had_player` above is what turns that loss into `StreamEnd` below.
        if activate.active_roles.is_none()
            && !playback_capable_for(
                self.matched,
                self.config.unpaired_access,
                &activate.activities,
            )
        {
            self.active_roles.clear();
        }
        if let Some(roles) = activate.active_roles {
            self.active_roles = roles;
        }
        let has_player = self.player_active();

        if had_player && !has_player {
            // The player role is gone: nothing that is still buffered may become audible.
            self.state_sent = false;
            self.suspend_burst();
            self.stop_stream(StreamEndReason::RoleRemoved)?;
        } else if !had_player && has_player {
            // A re-added role reports itself again, from the existing estimate when there is one.
            if self.clock.sample_count() >= 1 {
                self.send_client_state().await?;
            } else {
                self.start_burst();
            }
        }

        if let Some(activation) = pairing {
            // Each pairing activation gets its own index, so a server can discard an attempt that
            // belongs to a superseded activation.
            self.pairing_index = self.pairing_index.saturating_add(1);
            self.start_pairing(activation).await?;
        }
        Ok(())
    }

    /// Ends a connection whose `server/activate` this client will not honour.
    ///
    /// `messaging.md` orders the two reasons: `pairing_required` when enabling unpaired access would
    /// have made the activation admissible, `unauthorized` for everything else. The goodbye goes out
    /// before the close so the server can tell "pair against me" from "you sent something I forbid".
    async fn refuse_activation(&mut self, refusal: Refusal) -> Result<()> {
        let (goodbye, ending) = match refusal {
            Refusal::PairingRequired => (GoodbyeReason::PairingRequired, Ending::PairingRequired),
            Refusal::Unauthorized => (GoodbyeReason::Unauthorized, Ending::Unauthorized),
        };
        if refusal == Refusal::PairingRequired {
            self.emit(Event::PairingRequired {
                server_id: self.server_id.clone(),
                reason: PairingRequiredReason::UnpairedAccessDisabled,
            });
        }
        self.send_goodbye(goodbye).await;
        self.ending = Some(ending);
        Ok(())
    }

    /// The deadline of the pairing attempt in progress, for the session's wait.
    fn pairing_deadline(&self) -> Option<Instant> {
        self.pairing.as_ref().map(|attempt| attempt.deadline)
    }

    /// The method an activation may run on this connection, or `None` when it is inadmissible.
    ///
    /// The Pairing PSK method needs a store and is admissible only on a connection the pairing PSK
    /// sealed. The static code needs a configured code and a store for the record it produces. The
    /// dynamic code needs the formats and out-channels the host advertised, the emission format the
    /// server picked among them, and a store as well. Both code methods are admissible only while
    /// the connection is *not* keyed by the pairing PSK - the spec's invariant, since a code round
    /// authenticates a Sentinel-keyed or long-term-keyed channel.
    fn admitted_method(&self, activation: &PairingActivation) -> Option<AdmittedMethod> {
        match activation.method.as_str() {
            METHOD_PAIRING_PSK => (self.config.storage.is_some()
                && self.matched == MatchedPsk::PairingPsk)
                .then_some(AdmittedMethod::PairingPsk),
            #[cfg(feature = "pairing-code")]
            METHOD_STATIC_PAIRING_CODE => (self.config.storage.is_some()
                && self.config.static_pairing_code.is_some()
                && self.matched != MatchedPsk::PairingPsk
                && activation.format.is_none())
            .then_some(AdmittedMethod::StaticCode),
            #[cfg(feature = "pairing-code")]
            METHOD_DYNAMIC_PAIRING_CODE => (self.config.storage.is_some()
                && self.matched != MatchedPsk::PairingPsk
                && self.dynamic_format(activation).is_some())
            .then_some(AdmittedMethod::DynamicCode),
            _ => None,
        }
    }

    /// The emission format an activation selected, when the client offers it.
    ///
    /// A method the client would offer with formats but no channel is refused here too: the
    /// protocol treats such a descriptor as unrecognized, so no server should have picked it, and
    /// a client that runs it anyway would emit a code nowhere.
    #[cfg(feature = "pairing-code")]
    fn dynamic_format(&self, activation: &PairingActivation) -> Option<CodeFormat> {
        if self.config.code_out_channels.is_empty() || self.config.code_formats.is_empty() {
            return None;
        }
        let format = CodeFormat::from_wire(activation.format.as_deref()?)?;
        self.config.code_formats.contains(&format).then_some(format)
    }

    /// Whether the pairing window of this connection is open right now.
    ///
    /// An expired window closes silently, as the spec requires; expiry is noticed here rather than
    /// by a timer, because the only thing it changes is whether a future attempt may start. An
    /// attempt already in progress runs to its own end either way.
    #[cfg(feature = "pairing-code")]
    fn window_is_open(&mut self) -> bool {
        let expired = self
            .pairing_window
            .as_ref()
            .is_some_and(|window| window.opened.elapsed() >= self.config.pairing_window);
        if expired {
            self.pairing_window = None;
        }
        self.pairing_window.is_some()
    }

    /// Counts a failed `server_kc` verification against the window, closing it at the limit.
    #[cfg(feature = "pairing-code")]
    fn record_window_failure(&mut self) {
        if !self.window_is_open() {
            return;
        }
        let window = self
            .pairing_window
            .as_mut()
            .expect("the window was just found open");
        window.failed_attempts = window.failed_attempts.saturating_add(1);
        if window.failed_attempts >= WINDOW_FAILURE_LIMIT {
            self.pairing_window = None;
        }
    }

    /// Whether the dynamic flow's round limit holds new attempts back.
    #[cfg(feature = "pairing-code")]
    fn rounds_are_exhausted(&self) -> bool {
        self.failed_rounds.load(Ordering::SeqCst) >= ROUND_LIMIT
    }

    /// The rounds counted since the last verified `server_kc`.
    #[cfg(feature = "pairing-code")]
    fn failed_rounds(&self) -> u32 {
        self.failed_rounds.load(Ordering::SeqCst)
    }

    /// Counts one dynamic round that began, returning the count after it.
    ///
    /// A round counts from the moment the code is emitted, so an attempt that ends later - by a
    /// cancelling activation, a timeout or a failed key confirmation - leaves its round counted.
    /// That is what stops a peer from starting rounds forever without ever confirming one.
    #[cfg(feature = "pairing-code")]
    fn record_round(&self) -> u32 {
        self.failed_rounds.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Opens a pairing window for the connection, and starts the attempt that was waiting for it.
    ///
    /// The gesture belongs to the host; this only records the window and, when a static-code
    /// activation is already pending, sends the `client/pair-init` it was holding back. A fresh
    /// gesture starts a fresh window: its lifetime runs from now and its failure count is its own,
    /// so an operator can deliberately try again after five failures.
    #[cfg(feature = "pairing-code")]
    async fn open_pairing_window(&mut self) -> Result<()> {
        self.pairing_window = Some(PairingWindow {
            opened: Instant::now(),
            failed_attempts: 0,
        });
        self.start_pending(AdmittedMethod::StaticCode).await
    }

    /// Releases the dynamic flow's round limit and starts the attempt it held back.
    ///
    /// The count is per process, so the operator action also clears it without a connection; this
    /// is the session's half, for a gesture that arrives while one is established.
    #[cfg(feature = "pairing-code")]
    async fn release_holdback(&mut self) -> Result<()> {
        self.failed_rounds.store(0, Ordering::SeqCst);
        self.start_pending(AdmittedMethod::DynamicCode).await
    }

    /// Starts the held-back activation whose method is `method`, if one is waiting.
    #[cfg(feature = "pairing-code")]
    async fn start_pending(&mut self, method: AdmittedMethod) -> Result<()> {
        let Some(pending) = self.pending_pairing.take() else {
            return Ok(());
        };
        if pending.method != method {
            // The gesture belongs to the other method: the activation keeps waiting for its own.
            self.pending_pairing = Some(pending);
            return Ok(());
        }
        if self.pairing.is_some() {
            // An activation that superseded the pending one owns the attempt now.
            return Ok(());
        }
        self.start_code_attempt(pending.pairing_index, pending.method, pending.format)
            .await
    }

    /// Sends `client/pair-init` and starts the attempt whose timeout runs from it.
    #[cfg(feature = "pairing-code")]
    async fn start_code_attempt(
        &mut self,
        pairing_index: u32,
        method: AdmittedMethod,
        format: Option<CodeFormat>,
    ) -> Result<()> {
        let attempt = match method {
            AdmittedMethod::StaticCode => PairingAttempt::static_code(
                pairing_index,
                self.config.pairing_timeout,
                self.candidates.pairing(),
            ),
            AdmittedMethod::DynamicCode => {
                let Some(format) = format else {
                    // The activation decided the format; without one no code can be derived, and
                    // starting an attempt that cannot emit would only waste the operator's time.
                    return self.abort_pairing(PairingFailure::MethodNotSupported).await;
                };
                PairingAttempt::dynamic_code(
                    pairing_index,
                    self.config.pairing_timeout,
                    self.candidates.pairing(),
                    format,
                )
            }
            AdmittedMethod::PairingPsk => {
                bail!("the Pairing PSK flow does not start a code attempt")
            }
        };
        let init = Incoming::ClientPairInit(ClientPairInit {
            pairing_index,
            commit_b: attempt.commit_b(),
        });
        self.send_json(&init).await?;
        self.pairing = Some(attempt);
        Ok(())
    }

    /// Starts the one attempt a pairing activation admits, or aborts it as unsupported.
    ///
    /// The Pairing PSK flow sends `client/pair-init` and `client/pair-finalize` back to back,
    /// without waiting for a server response. A code flow sends only `client/pair-init`, and only
    /// once its gate is open: the static flow waits for a pairing window, the dynamic flow for a
    /// round count below the limit. While the gate is closed the client sends
    /// `client/pair-pending` instead, and the attempt starts with a later operator action. Before
    /// either, the activation has to be admissible; anything else is a `pair/abort` with reason
    /// `method_not_supported`, which leaves the connection open.
    async fn start_pairing(&mut self, activation: PairingActivation) -> Result<()> {
        // A second activation supersedes an attempt that is still running; its state is discarded
        // without an abort, exactly as a cancelling activation does.
        self.pairing = None;
        #[cfg(feature = "pairing-code")]
        {
            self.pending_pairing = None;
        }

        let Some(method) = self.admitted_method(&activation) else {
            return self.abort_pairing(PairingFailure::MethodNotSupported).await;
        };

        match method {
            AdmittedMethod::PairingPsk => {
                let attempt = PairingAttempt::new(
                    self.pairing_index,
                    self.config.pairing_timeout,
                    self.candidates.pairing(),
                );
                let init = Incoming::ClientPairInit(ClientPairInit {
                    pairing_index: attempt.pairing_index,
                    commit_b: None,
                });
                self.send_json(&init).await?;
                let finalize = Incoming::ClientPairFinalize(ClientPairFinalize {
                    long_term_psk: Some(attempt.psk_base64()),
                    wrapped_psk: None,
                });
                self.send_json(&finalize).await?;
                // The attempt begins with `client/pair-init`; its timeout runs from there.
                self.pairing = Some(attempt);
                Ok(())
            }
            #[cfg(feature = "pairing-code")]
            AdmittedMethod::StaticCode => {
                if !self.window_is_open() {
                    return self
                        .hold_pairing_back(self.pairing_index, AdmittedMethod::StaticCode, None)
                        .await;
                }
                self.start_code_attempt(self.pairing_index, AdmittedMethod::StaticCode, None)
                    .await
            }
            #[cfg(feature = "pairing-code")]
            AdmittedMethod::DynamicCode => {
                let Some(format) = self.dynamic_format(&activation) else {
                    // `admitted_method` checked it; nothing can change between the two calls.
                    return self.abort_pairing(PairingFailure::MethodNotSupported).await;
                };
                if self.rounds_are_exhausted() {
                    return self
                        .hold_pairing_back(
                            self.pairing_index,
                            AdmittedMethod::DynamicCode,
                            Some(format),
                        )
                        .await;
                }
                self.start_code_attempt(
                    self.pairing_index,
                    AdmittedMethod::DynamicCode,
                    Some(format),
                )
                .await
            }
        }
    }

    /// Sends `client/pair-pending` and remembers the activation until its gate opens.
    #[cfg(feature = "pairing-code")]
    async fn hold_pairing_back(
        &mut self,
        pairing_index: u32,
        method: AdmittedMethod,
        format: Option<CodeFormat>,
    ) -> Result<()> {
        let pending = Incoming::ClientPairPending(ClientPairPending {
            pairing_index,
            message: self.config.pairing_pending_text.clone(),
        });
        self.send_json(&pending).await?;
        self.pending_pairing = Some(PendingPairing {
            pairing_index,
            method,
            format,
        });
        Ok(())
    }

    /// Handles `server/pair-init`: begins a round of the dynamic flow and emits the code.
    ///
    /// The first round carries `nonce_A`; the client derives the code from it, the handshake hash
    /// and its own nonce, and emits it through [`Event::PairingCode`]. A later round repeats the
    /// same code with a higher round number: the binding values do not change within an attempt.
    ///
    /// A message that arrives when no attempt is running belongs to an attempt the client already
    /// ended and is discarded silently. A message at the wrong point of a running attempt, a
    /// missing first-round nonce or a changed one is a protocol error: the connection closes
    /// without an application-level message, as `pairing.md` requires.
    #[cfg(feature = "pairing-code")]
    async fn handle_server_init(&mut self, init: ServerPairInit) -> Result<()> {
        let Some(mut attempt) = self.pairing.take() else {
            return self.discard_or_reject_pairing_message("server/pair-init");
        };
        if !attempt.awaiting_server_init() {
            self.pairing = Some(attempt);
            bail!("the server sent server/pair-init out of sequence");
        }
        let nonce_a = match init.nonce_a.as_deref() {
            Some(value) => Some(decode_pairing_field::<32>(value, "nonce_A")?),
            None => None,
        };
        let emission = attempt.begin_round(nonce_a, self.noise.handshake_hash())?;
        self.emit(Event::PairingCode {
            code: emission.code,
            format: emission.format,
            round: emission.round,
        });
        // The round counts from here: the code is emitted, so the operator and the server have
        // everything one round needs. An attempt that ends later leaves this round counted.
        self.record_round();
        self.pairing = Some(attempt);
        Ok(())
    }

    /// Answers `server/pair-auth`: runs the client half of the CPace round.
    ///
    /// The reply, `client/pair-auth`, carries this client's share `Yb`. The round's `PRS` is the
    /// configured static code, or the code the dynamic flow derived for this attempt. A message
    /// that arrives when no attempt is running belongs to an attempt the client already ended, and
    /// is discarded silently as the spec requires. A message at the wrong point of a running
    /// attempt is a sequence violation, and a share that is malformed or encodes a low-order point
    /// is a protocol error: both close the connection without an application-level message.
    #[cfg(feature = "pairing-code")]
    async fn handle_server_auth(&mut self, auth: ServerPairAuth) -> Result<()> {
        let Some(mut attempt) = self.pairing.take() else {
            return self.discard_or_reject_pairing_message("server/pair-auth");
        };
        if !attempt.awaiting_server_auth() {
            self.pairing = Some(attempt);
            bail!("the server sent server/pair-auth out of sequence");
        }
        let prs = if attempt.is_dynamic_code() {
            match attempt.prs() {
                Some(prs) => prs,
                None => {
                    // The code is derived in `server/pair-init`, so this cannot happen unless the
                    // attempt was started without one.
                    self.pairing = Some(attempt);
                    bail!("the dynamic pairing code was never derived");
                }
            }
        } else {
            let Some(code) = self.config.static_pairing_code.as_deref() else {
                // The method is only admitted with a code, so this is a configuration changed
                // during the connection; failing loudly beats deriving a round from nothing.
                self.pairing = Some(attempt);
                bail!("the static pairing code is no longer configured");
            };
            code.as_bytes().to_vec()
        };
        let peer_share: [u8; 32] = decode_pairing_field(&auth.pake_msg_1, "pake_msg_1")?;
        let sid = pake_sid(
            self.noise.handshake_hash(),
            attempt.pairing_index,
            attempt.round()?,
        );
        let share = attempt.accept_server_share(&prs, &sid, &peer_share, self.noise.suite())?;
        let reply = Incoming::ClientPairAuth(ClientPairAuth {
            pake_msg_2: URL_SAFE_NO_PAD.encode(share),
        });
        self.send_json(&reply).await?;
        self.pairing = Some(attempt);
        Ok(())
    }

    /// Handles `server/pair-confirm`: verifies `server_kc` before anything is revealed.
    ///
    /// A verified tag releases the client's tag and the seals, which travel back to back with no
    /// server response awaited; it also clears the round count, because the spec counts rounds
    /// since the last verified `server_kc`. A mismatch ends the static flow's attempt with
    /// `pairing_code_mismatch` - it has no retry - while the dynamic flow answers with
    /// `client/pair-retry` and keeps the attempt, its code and its deadline. At the twentieth
    /// failed round the dynamic flow aborts with the same reason instead of retrying.
    #[cfg(feature = "pairing-code")]
    async fn handle_server_confirm(&mut self, confirm: ServerPairConfirm) -> Result<()> {
        let Some(mut attempt) = self.pairing.take() else {
            return self.discard_or_reject_pairing_message("server/pair-confirm");
        };
        if !attempt.awaiting_server_confirm() {
            self.pairing = Some(attempt);
            bail!("the server sent server/pair-confirm out of sequence");
        }
        let received: [u8; TAG_LEN] = decode_pairing_field(&confirm.server_kc, "server_kc")?;
        let confirmation = match attempt.verify_server_tag(&received) {
            TagOutcome::Confirmed(confirmation) => confirmation,
            TagOutcome::Mismatch => {
                if attempt.is_dynamic_code() {
                    // The round was counted when it began. Below the limit the client retries;
                    // at the limit it aborts, as `pairing.md` requires.
                    if self.failed_rounds() < ROUND_LIMIT {
                        let retry = Incoming::ClientPairRetry(ClientPairRetry {});
                        self.send_json(&retry).await?;
                        // The attempt keeps its binding values, its code and its deadline; the
                        // server begins the next round with `server/pair-init`.
                        self.pairing = Some(attempt);
                        return Ok(());
                    }
                } else {
                    self.record_window_failure();
                }
                return self
                    .abort_pairing(PairingFailure::PairingCodeMismatch)
                    .await;
            }
        };
        // A verified tag is the one thing besides an operator action that clears the round count.
        self.failed_rounds.store(0, Ordering::SeqCst);

        let reply = Incoming::ClientPairConfirm(ClientPairConfirm {
            client_kc: confirmation.client_kc,
            wrapped_nonce_b: confirmation.wrapped_nonce_b,
        });
        self.send_json(&reply).await?;
        let finalize = Incoming::ClientPairFinalize(ClientPairFinalize {
            long_term_psk: None,
            wrapped_psk: Some(confirmation.wrapped_psk),
        });
        self.send_json(&finalize).await?;
        // The key is on the wire; the attempt keeps only the long-term PSK the record needs.
        self.pairing = Some(attempt);
        Ok(())
    }

    /// Discards a late pairing message, or rejects one that has no attempt behind it.
    ///
    /// The spec's silent-discard rule covers messages a peer sent before it observed the end of an
    /// attempt; it does not cover a pairing message while no attempt was ever admitted, which is a
    /// sequence violation and a protocol error. `pairing: None` alone cannot tell the two apart,
    /// so [`Session::discarding_pairing_messages`] decides.
    fn discard_or_reject_pairing_message(&self, message: &'static str) -> Result<()> {
        if self.discarding_pairing_messages {
            return Ok(());
        }
        bail!("the server sent {message} without an active pairing attempt")
    }

    /// Ends the attempt with `reason`: sends `pair/abort` and reports it.
    ///
    /// The connection stays open, as the spec requires for every reason but `concurrent_attempt`:
    /// playback continues in whatever roles the activation left active.
    async fn abort_pairing(&mut self, reason: PairingFailure) -> Result<()> {
        self.pairing = None;
        // Pairing messages already on their way may still arrive before the next activation; the
        // spec says to discard them instead of treating them as a sequence violation.
        self.discarding_pairing_messages = true;
        let abort = Incoming::PairAbort(PairAbort {
            reason: reason.as_str().to_owned(),
        });
        self.send_json(&abort).await?;
        self.emit(Event::PairingFailed { reason });
        Ok(())
    }

    /// Persists the record after `server/pair-finalize`, the server's confirmation.
    ///
    /// Only now may the client write its side: the server has persisted the new long-term PSK, so a
    /// client that never receives this message - because the server cancelled instead - stores
    /// nothing and stays a guest on this connection. A completed pairing of either method closes
    /// the pairing window.
    fn confirm_pairing(&mut self) -> Result<()> {
        let Some(attempt) = self.pairing.take() else {
            return self.discard_or_reject_pairing_message("server/pair-finalize");
        };
        #[cfg(feature = "pairing-code")]
        if (attempt.is_static_code() || attempt.is_dynamic_code()) && !attempt.awaiting_finalize() {
            self.pairing = Some(attempt);
            bail!("the server finalized a code-flow attempt before confirming its tag");
        }
        let Some(storage) = self.config.storage.as_deref() else {
            // An attempt only starts when a store exists, so this is unreachable; failing loudly
            // beats storing a key nowhere and reporting a pairing that cannot survive a restart.
            bail!("the server finalized a pairing on a client without a pairing store");
        };
        let record = StoredPsk {
            category: PskCategory::LongTerm,
            psk: attempt.psk(),
            server_id: self.server_id.clone(),
        };
        persist_pairing(storage, record.clone(), Some(&self.server_id))
            .context("cannot store the pairing record")?;
        // The server rotates this connection to the key it just persisted, and the candidate set
        // was read before that record existed.
        self.candidates.remember(record);
        self.discarding_pairing_messages = true;
        #[cfg(feature = "pairing-code")]
        {
            self.pairing_window = None;
        }
        self.emit(Event::Paired {
            server_id: self.server_id.clone(),
        });
        Ok(())
    }

    /// Ends the attempt a server's `pair/abort` names, if one is running.
    ///
    /// An abort that arrives after the client ended the attempt - because it timed out, paired, or
    /// saw a cancelling activation - has no effect, so no second event is reported.
    fn handle_pairing_abort(&mut self, abort: PairAbort) -> Result<()> {
        if self.pairing.take().is_some() {
            self.discarding_pairing_messages = true;
            self.emit(Event::PairingFailed {
                reason: PairingFailure::from_wire(&abort.reason),
            });
        }
        Ok(())
    }

    /// Handles `server/unpair`: drops this client's record for the server and ends the connection.
    ///
    /// The message is valid under any activity set, but only a paired session - one the handshake
    /// keyed with a stored long-term record - has a record to drop. A session keyed by the Sentinel
    /// key or by the pairing PSK is unpaired, and the spec says to ignore the message there: the
    /// record it could drop would not be the one the server means.
    ///
    /// The record is removed through [`Storage`], so the host owns the file and the crate owns the
    /// rule. A store that refuses the removal leaves the record in place, and the connection ends
    /// with the store's error: reporting [`Event::Unpaired`] for a record that is still there would
    /// be a lie. A record the host passed through
    /// [`connect_with_psks`](crate::connect_with_psks) is not in a store the client may write, so
    /// the event is reported without removing it - that record belongs to the host.
    ///
    /// The client then says goodbye with reason `unpaired` and closes the connection. The goodbye
    /// is best effort: a write that fails does not turn the deliberate close into a failed attempt.
    async fn handle_unpair(&mut self) -> Result<()> {
        if self.matched != MatchedPsk::Stored(PskCategory::LongTerm) {
            return Ok(());
        }
        if let Some(storage) = self.config.storage.as_deref() {
            storage
                .remove_pairing(&self.server_id)
                .context("cannot remove the pairing record")?;
        }
        self.emit(Event::Unpaired {
            server_id: self.server_id.clone(),
        });
        self.send_goodbye(GoodbyeReason::Unpaired).await;
        self.ending = Some(Ending::Unpaired);
        Ok(())
    }

    /// Reports the handshake's pairing requirement, at most once.
    ///
    /// [`Event::Connected`] goes out first, so the host knows which server the requirement belongs
    /// to. The handshake decides the credential mismatch once per connection; taking the value here
    /// is what makes a second report of that reason impossible, however many messages the session
    /// goes on to handle.
    fn report_pairing_required(&mut self) {
        if let Some(reason) = self.pairing_required.take() {
            self.emit(Event::PairingRequired {
                server_id: self.server_id.clone(),
                reason,
            });
        }
    }

    /// Feeds one `server/time` reply into the current burst.
    ///
    /// A reply is accepted when the current burst sent its request, not only when the request is
    /// the one on the wire: a reply that arrives after its per-message timeout is still a valid
    /// measurement of the burst, and the filter's error bound decides how much weight it carries.
    /// An unsolicited or mis-echoed `server_time` - one whose `client_transmitted` the burst never
    /// sent - is ignored. Consuming a timestamp removes it, so one request yields at most one
    /// sample even if the peer echoes it twice.
    async fn handle_server_time(&mut self, time: ServerTime) -> Result<()> {
        if !self.burst_sent_us.remove(&time.client_transmitted) {
            return Ok(());
        }
        self.burst_samples.push(TimeSample {
            client_sent_us: time.client_transmitted,
            server_received_us: time.server_received,
            server_sent_us: time.server_transmitted,
            client_received_us: now_us(),
        });

        // Only the reply to the request on the wire ends its wait; a late reply for an earlier
        // request of the same burst leaves the next request in flight, so its deadline stands.
        if self.outstanding_sent_us == Some(time.client_transmitted) {
            self.outstanding_sent_us = None;
            self.reply_deadline = None;
        }

        // The state is reported by `finish_burst`, once the filter has a measurement: the spec
        // does not allow a player to report before its clock estimate has one. The burst ends early
        // only once every request it sent has been answered; a request that timed out keeps the set
        // non-empty, so the burst stays open for late replies until its deadline.
        if self.sync_remaining == 0
            && self.reply_deadline.is_none()
            && self.burst_sent_us.is_empty()
        {
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
    /// The event goes out before the flush, so a host can mute or stop its output while the
    /// client is still dropping the audio it buffered. A sink that fails to flush ends the
    /// session, like any other sink error.
    fn stop_stream(&mut self, reason: StreamEndReason) -> Result<()> {
        self.stream = None;
        self.emit(Event::StreamEnd { reason });
        self.flush_sink()
    }

    /// Drops buffered audio without ending the stream.
    ///
    /// The client holds no timestamped audio queue of its own - the sink does - so the only
    /// granularity it can offer is a full flush: a clear with a `from_timestamp` also drops the
    /// frames after it. The announced format stays open, because the spec lets the stream continue
    /// and the chunks that follow a seek still belong to it.
    ///
    /// The event goes out before the flush, so a host can restart its output and re-prime a
    /// decoder before the buffered audio is dropped.
    fn handle_stream_clear(&mut self, clear: StreamClear) -> Result<()> {
        self.emit(Event::StreamClear {
            from_timestamp: clear.from_timestamp,
        });
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
                let (progress_ms, duration_ms, playback_speed) = match metadata.progress {
                    Some(progress) => (
                        progress.track_progress,
                        progress.track_duration,
                        progress.playback_speed.unwrap_or(NORMAL_PLAYBACK_SPEED),
                    ),
                    // Without a progress object the track is at its start, at normal speed.
                    None => (None, None, NORMAL_PLAYBACK_SPEED),
                };
                self.emit(Event::Track {
                    title: metadata.title.unwrap_or_default(),
                    artist: metadata.artist.unwrap_or_default(),
                    album: metadata.album.unwrap_or_default(),
                    album_artist: metadata.album_artist.unwrap_or_default(),
                    artwork_url: metadata.artwork_url.unwrap_or_default(),
                    progress_ms,
                    duration_ms,
                    playback_speed,
                });
            }
        }
        if self.role_active(CONTROLLER_ROLE) {
            if let Some(controller) = state.controller {
                self.controller_commands = Some(controller.supported_commands.clone());
                self.playback.supported_commands = controller.supported_commands;
                self.playback.volume = controller.volume;
                self.playback.muted = controller.muted;
                self.emit(Event::State(self.playback.clone()));
            }
        }
    }

    /// Reports one `group/update`: the authoritative source of the group's playback state.
    ///
    /// The message is a core one and valid whatever roles are active, so it is not gated on a role.
    /// Its fields complete the picture `server/state` fills in for the roles: the group fields are
    /// replaced, the controller fields stay. The spec gives `group_id` as 32 bytes in 43 unpadded
    /// base64url characters and calls any other value a protocol error. By default this client
    /// tolerates a well-formed foreign value instead, because a real server sends a UUID: it
    /// reports [`Event::GroupIdNotCanonical`] once per connection and keeps the identifier as an
    /// opaque string. An empty, oversized or control-character value is still an error, and
    /// [`ClientConfig::strict_group_id`] restores the spec's close for any non-canonical value. A
    /// `playback_state` this revision does not name is carried to the host verbatim.
    fn handle_group_update(&mut self, update: GroupUpdate) -> Result<()> {
        let canonical = is_canonical_group_id(&update.group_id);
        if self.config.strict_group_id {
            if !canonical {
                bail!(
                    "group/update carries a group_id that is not a canonical {GROUP_ID_LEN}-character \
                     base64url identifier"
                );
            }
        } else if !is_tolerable_group_id(&update.group_id) {
            bail!(
                "group/update carries a group_id that is empty, longer than {MAX_GROUP_ID_LEN} \
                 bytes or contains a control character"
            );
        } else if !canonical && !self.group_id_tolerance_reported {
            // Once per connection: the departure is a property of the server, not of this message,
            // and a repeating update must not flood the host's log.
            self.group_id_tolerance_reported = true;
            self.emit(Event::GroupIdNotCanonical {
                len: update.group_id.len(),
            });
        }
        self.playback.playback_state = Some(update.playback_state);
        self.playback.group_id = Some(update.group_id);
        self.playback.group_name = Some(update.group_name);
        self.emit(Event::State(self.playback.clone()));
        Ok(())
    }

    /// Applies a volume or mute request from the server and reports the result.
    ///
    /// The volume is limited by [`ClientConfig::volume_policy`], which also caps a level the
    /// server cannot legally send. [`Event::Volume`] carries both the requested and the applied
    /// number, and the following `client/state` reports the applied one. A mute request changes
    /// only the mute field, so it never looks like a request for volume zero; its event repeats
    /// the level in force for both numbers.
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
                let applied = clamp_volume_with(self.config.volume_policy, self.volume, level);
                self.record_volume(applied);
                self.emit(Event::Volume {
                    requested: level,
                    applied,
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
                    requested: self.volume,
                    applied: self.volume,
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
            ControlAction::ReportVolume(level) => {
                self.apply_report_volume(level).await.map(|()| self.volume)
            }
            ControlAction::Mute(muted) => self.apply_mute(muted).await.map(|()| self.volume),
            #[cfg(feature = "pairing-code")]
            ControlAction::OpenPairingWindow => {
                self.open_pairing_window().await.map(|()| self.volume)
            }
            #[cfg(feature = "pairing-code")]
            ControlAction::ReleaseHoldback => self.release_holdback().await.map(|()| self.volume),
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
    /// controller state is left open, because nothing is known yet. A level the host reports above
    /// the protocol range is refused here as well, since `client/state` cannot carry it.
    fn check_control(&self, action: &ControlAction) -> Result<()> {
        if self.rehandshake.is_some() {
            bail!("the connection is switching keys and cannot send yet");
        }
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
            ControlAction::ReportVolume(level) => {
                // The handle refuses an out-of-range level before it queues the request; the
                // check stays here so a refused value can never reach `client/state`.
                check_reported_level(*level)?;
                if !self.player_active() {
                    bail!("the server did not activate {PLAYER_ROLE}");
                }
                Ok(())
            }
            // The window and the hold-back release are local state: neither sends anything itself,
            // and whatever they start needs no role.
            #[cfg(feature = "pairing-code")]
            ControlAction::OpenPairingWindow | ControlAction::ReleaseHoldback => Ok(()),
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
        self.record_volume(clamp_volume_with(
            self.config.volume_policy,
            self.volume,
            level,
        ));
        self.report_state().await?;
        Ok(self.volume)
    }

    /// Records a level the host reports as the one the output is actually at, and reports it.
    ///
    /// The policy guards requests, not the measured state: a device the user raised to 70 while
    /// the policy would have limited a request to 60 is recorded and sent as 70, so the server's
    /// view matches what is audible. The protocol's range still applies, but
    /// [`check_reported_level`] refuses an out-of-range value before this runs, so nothing
    /// impossible can be recorded or written.
    async fn apply_report_volume(&mut self, level: u8) -> Result<()> {
        self.record_volume(level);
        self.report_state().await
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

    /// Sends `client/goodbye` with `reason`, best effort and time-bounded.
    ///
    /// The message belongs to a graceful close. A write that fails or does not complete within
    /// [`GOODBYE_TIMEOUT`] is ignored: the connection is ending anyway, and turning either into an
    /// error or a reconnect would punish a deliberate shutdown for a courtesy. A goodbye during a
    /// re-handshake is refused by [`Self::send_json`] and ignored for the same reason - there is no
    /// application-message window to use.
    async fn send_goodbye(&mut self, reason: GoodbyeReason) {
        let goodbye = Incoming::ClientGoodbye(ClientGoodbye {
            reason: reason.as_str().to_owned(),
        });
        let _ = tokio::time::timeout(GOODBYE_TIMEOUT, self.send_json(&goodbye)).await;
    }

    /// Encrypts and sends one control message.
    ///
    /// During a re-handshake the client may send nothing but message 2, so a send here is a bug;
    /// failing loudly is better than putting a frame under the wrong keys on the wire.
    async fn send_json(&mut self, message: &Incoming) -> Result<()> {
        if self.rehandshake.is_some() {
            bail!("the client may not send an application message during a re-handshake");
        }
        let ciphertext = encrypt_json(&mut self.noise, message)?;
        self.transport.send_binary(ciphertext).await
    }
}

/// Why the cleartext exchange or the Noise handshake did not produce a session.
///
/// The two cases are kept apart because only one of them carries something the host has to hear:
/// `server/error` is the server's own explanation, while every other failure is local.
#[derive(Debug)]
enum HandshakeError {
    /// The server answered `client/init` with `server/error` and closed.
    ///
    /// The reason is the wire value, preserved verbatim, and never key material.
    ServerRejected(String),
    /// A transport failure, a refused message or a missing one.
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for HandshakeError {
    /// Wraps every ordinary failure, so `?` keeps working inside the handshake.
    fn from(error: anyhow::Error) -> Self {
        Self::Failed(error)
    }
}

impl From<syncspin_core::messages::DecodeError> for HandshakeError {
    /// Wraps a malformed handshake message as an ordinary failure.
    fn from(error: syncspin_core::messages::DecodeError) -> Self {
        Self::Failed(error.into())
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
    candidates: &Candidates,
    previous_roles: &[String],
) -> Result<Ready, HandshakeError> {
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
        // The server refused `client/init` and named why; it closes the connection next.
        Some(Incoming::ServerError(error)) => {
            return Err(HandshakeError::ServerRejected(error.reason))
        }
        _ => {
            return Err(HandshakeError::Failed(anyhow!(
                "expected a cleartext server/init"
            )))
        }
    };
    if server_init.version != PROTOCOL_VERSION {
        return Err(HandshakeError::Failed(anyhow!(
            "unsupported server version {}",
            server_init.version
        )));
    }
    let server_init_bytes = server_init_text.into_bytes();

    // 3. Noise message 1, sent by the server as the initiator.
    let message_1_text = read_cleartext(&mut transport).await?;
    let message_1 = match Incoming::parse(&message_1_text)? {
        Some(Incoming::NoiseHandshake(handshake)) => URL_SAFE_NO_PAD
            .decode(&handshake.data)
            .context("noise/handshake data is not unpadded base64url")?,
        _ => {
            return Err(HandshakeError::Failed(anyhow!(
                "expected noise/handshake message 1"
            )))
        }
    };

    // 4. Read message 1, validate its PSK metadata and seal message 2 with the selected key.
    let mut prologue = client_init_bytes;
    prologue.extend_from_slice(&server_init_bytes);
    let mut responder = Responder::new(&config.identity, &prologue)?;
    let metadata_payload = responder
        .read_message(&message_1)
        .context("failed to read Noise handshake message 1")?;
    let metadata = PskMetadata::parse(&metadata_payload)?;
    let selected = select_psk(&metadata, candidates, &server_init.server_id, true)?;
    responder.set_psk(&selected.psk)?;

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
        _ => {
            return Err(HandshakeError::Failed(anyhow!(
                "expected an encrypted server/hello after the Noise handshake"
            )))
        }
    }

    // 6. client/hello.
    let hello = client_hello(config);
    let ciphertext = encrypt_json(&mut noise, &hello)?;
    transport.send_binary(ciphertext).await?;

    // 7. The first server/activate, which completes the handshake.
    let activate = read_encrypted_json(&mut transport, &mut noise).await?;
    let activate = match Incoming::parse(&activate)? {
        Some(Incoming::ServerActivate(activate)) => activate,
        _ => {
            return Err(HandshakeError::Failed(anyhow!(
                "expected an encrypted server/activate after client/hello"
            )))
        }
    };
    // The first activation of a connection must carry the roles. If it does not, the previous
    // session's set is the safer starting point than none, because the server is already breaking
    // its own rule and a player that forgets it could drop audio.
    let active_roles = activate
        .active_roles
        .clone()
        .unwrap_or_else(|| previous_roles.to_vec());

    Ok(Ready {
        transport,
        noise,
        server_id: server_init.server_id,
        active_roles,
        activate,
        matched: selected.matched,
        credential_mismatch: selected.credential_mismatch,
    })
}

/// Completes the handshake of a server that cannot be admitted, then rejects it.
///
/// `connection.md`, _Multiple servers (server-initiated)_: the client lets the handshake complete
/// before it applies admission, so the loser of an arbitration learns why on an encrypted channel.
/// This client admits one server at a time; while that one is live, every activation on a
/// provisional connection conflicts with it and is rejected. The activation's `pairing` activity
/// decides the message: a rejected pairing attempt gets `pair/abort` with reason
/// `concurrent_attempt`, every other activation `client/goodbye` with the same reason, and then
/// the socket closes.
///
/// A handshake that fails gets no message: the peer never became a connection, and the ordinary
/// silent-failure rule applies.
#[cfg(feature = "discovery")]
pub(crate) async fn reject_concurrent(
    transport: Transport,
    config: &ClientConfig,
    pairing_psk: Option<PairingPsk>,
    previous_roles: &[String],
) -> Result<()> {
    let candidates = Candidates::load(config.storage.as_deref(), &[], pairing_psk)?;
    let mut ready = match handshake(transport, config, &candidates, previous_roles).await {
        Ok(ready) => ready,
        Err(HandshakeError::ServerRejected(_) | HandshakeError::Failed(_)) => return Ok(()),
    };
    let reason = PairingFailure::ConcurrentAttempt.as_str().to_owned();
    let rejection = if ready
        .activate
        .activities
        .iter()
        .any(|role| role == "pairing")
    {
        Incoming::PairAbort(PairAbort { reason })
    } else {
        Incoming::ClientGoodbye(ClientGoodbye { reason })
    };
    // The connection is closing either way; a write that fails changes nothing the host has to
    // hear, so the attempt to explain is best effort.
    if let Ok(ciphertext) = encrypt_json(&mut ready.noise, &rejection) {
        let _ = ready.transport.send_binary(ciphertext).await;
    }
    let _ = ready.transport.close().await;
    Ok(())
}

/// Builds the `client/hello` the client announces itself with.
fn client_hello(config: &ClientConfig) -> Incoming {
    let codec = match config.audio_mode {
        AudioMode::Decode => "pcm",
        AudioMode::Passthrough => "flac",
    };
    Incoming::ClientHello(ClientHello {
        name: config.player_name.clone(),
        device_info: config.device_info.as_ref().map(|info| DeviceInfo {
            product_name: Some(info.product_name.clone()),
            manufacturer: Some(info.manufacturer.clone()),
            software_version: info.software_version.clone(),
            mac_address: info.mac_address.clone(),
        }),
        supported_roles: SUPPORTED_ROLES
            .iter()
            .map(|role| (*role).to_owned())
            .collect(),
        player_support: Some(PlayerSupport {
            supported_formats: vec![SupportedFormat {
                codec: codec.to_owned(),
                channels: SUPPORTED_CHANNELS,
                sample_rate: SUPPORTED_SAMPLE_RATE,
                bit_depth: SUPPORTED_BIT_DEPTH,
            }],
            buffer_capacity: BUFFER_CAPACITY,
        }),
        supported_pair_methods: pair_methods(config),
        unpaired_access: UnpairedAccess {
            enabled: config.unpaired_access,
        },
    })
}

/// Derives the pairing methods this client currently offers from its configuration.
///
/// `pairing_psk` is offered exactly when a store is configured, because the method needs a pairing
/// PSK that survives restarts and a place to write the record. `static_pairing_code` is offered
/// exactly when the feature is on, a code is configured and a store exists: the code is the
/// method's whole credential, and the record it produces has to be persisted. `dynamic_pairing_code`
/// is offered exactly when the feature is on, the host advertised at least one emission format and
/// one out-channel, and a store exists: the code is derived per attempt and needs somewhere to go.
/// A method the client cannot complete is never offered.
fn pair_methods(config: &ClientConfig) -> SupportedPairMethods {
    SupportedPairMethods {
        pairing_psk: config.storage.is_some().then_some(PairingPskMethod {}),
        #[cfg(feature = "pairing-code")]
        static_pairing_code: config
            .static_pairing_code
            .as_ref()
            .filter(|_| config.storage.is_some())
            .map(|_| StaticPairingCodeMethod::default()),
        #[cfg(not(feature = "pairing-code"))]
        static_pairing_code: None,
        #[cfg(feature = "pairing-code")]
        dynamic_pairing_code: (config.storage.is_some()
            && !config.code_formats.is_empty()
            && !config.code_out_channels.is_empty())
        .then(|| DynamicPairingCodeMethod {
            out_channels: config
                .code_out_channels
                .iter()
                .map(|channel| channel.as_wire().to_owned())
                .collect(),
            formats: config
                .code_formats
                .iter()
                .map(|format| format.as_wire().to_owned())
                .collect(),
        }),
        #[cfg(not(feature = "pairing-code"))]
        dynamic_pairing_code: None,
    }
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

/// The activity a session declares to play audio.
const PLAYBACK: &str = "playback";

/// The activity a session declares to run a pairing attempt.
const PAIRING: &str = "pairing";

/// The verdict of `messaging.md`'s admissibility rules for one `server/activate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admitted {
    /// The matched key and the setting allow the activation.
    Admissible,
    /// Unpaired access is off, and enabling it is the only thing that would admit the activation.
    PairingRequired,
    /// No setting makes the activation admissible on this connection.
    Unauthorized,
}

/// The two ways an activation can be refused, each naming its own goodbye.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The setting is the only obstacle: pairing would admit the activation.
    PairingRequired,
    /// No setting makes the activation admissible on this connection.
    Unauthorized,
}

impl Admitted {
    /// The refusal this verdict carries, or `None` when the activation is admissible.
    ///
    /// Expressing the admissible verdict as `None` leaves the caller no arm that could close a
    /// connection the verdict just admitted.
    pub(crate) fn refusal(self) -> Option<Refusal> {
        match self {
            Admitted::Admissible => None,
            Admitted::PairingRequired => Some(Refusal::PairingRequired),
            Admitted::Unauthorized => Some(Refusal::Unauthorized),
        }
    }
}

/// Reads the activities of a `server/activate` as the set the rules are written against.
///
/// `messaging.md` names the members of a set, so an unknown member and a repeated one are equally
/// malformed. `None` is that malformed case, and no rule admits it.
fn normalise(activities: &[String]) -> Option<BTreeSet<&str>> {
    let mut set = BTreeSet::new();
    for activity in activities {
        if activity != PLAYBACK && activity != PAIRING {
            return None;
        }
        if !set.insert(activity.as_str()) {
            return None;
        }
    }
    Some(set)
}

/// Whether the key that sealed this connection carries a pairing record.
fn is_paired(matched: MatchedPsk) -> bool {
    matched == MatchedPsk::Stored(PskCategory::LongTerm)
}

/// Whether an activity set is allowed for the key that sealed the connection.
///
/// The set is one [`normalise`] produced, so every member is a known activity.
fn allowed(activities: Option<&BTreeSet<&str>>, paired: bool, unpaired_access: bool) -> bool {
    let Some(activities) = activities else {
        return false;
    };
    if paired {
        // A paired connection plays or does nothing: `pairing` belongs to the guest path, and the
        // spec gives a connection keyed by a long-term PSK no reason to run one.
        return activities.is_empty() || (activities.len() == 1 && activities.contains(PLAYBACK));
    }
    // A guest may always pair - that is what keeps the switch from locking the client out of a
    // server for good - and plays only while the host admits unpaired access.
    !activities.contains(PLAYBACK) || unpaired_access
}

/// Whether `activities` plus `playback` is an allowed set.
///
/// `messaging.md` calls a connection playback-capable exactly when its activity set with `playback`
/// added is admissible, which is why roles use this rather than the set the server sent.
fn capable_of_playback(
    activities: Option<&BTreeSet<&str>>,
    paired: bool,
    unpaired_access: bool,
) -> bool {
    let Some(activities) = activities else {
        return false;
    };
    let mut with_playback = activities.clone();
    with_playback.insert(PLAYBACK);
    allowed(Some(&with_playback), paired, unpaired_access)
}

/// Whether a `server/activate`'s activity list leaves the connection playback-capable.
pub(crate) fn playback_capable_for(
    matched: MatchedPsk,
    unpaired_access: bool,
    activities: &[String],
) -> bool {
    capable_of_playback(
        normalise(activities).as_ref(),
        is_paired(matched),
        unpaired_access,
    )
}

/// Applies all three admissibility rules for one setting.
fn activation_admissible(
    matched: MatchedPsk,
    unpaired_access: bool,
    activate: &ServerActivate,
) -> bool {
    let paired = is_paired(matched);
    let activities = normalise(&activate.activities);
    if !allowed(activities.as_ref(), paired, unpaired_access) {
        return false;
    }
    let roles = activate.active_roles.as_deref().unwrap_or_default();
    if !roles
        .iter()
        .all(|role| SUPPORTED_ROLES.contains(&role.as_str()))
    {
        return false;
    }
    roles.is_empty() || playback_capable_for(matched, unpaired_access, &activate.activities)
}

/// Decides whether this client honours a `server/activate`.
///
/// `pairing_admissible` is whether the declared pairing method is acceptable on this connection,
/// `true` also when the activation declares no pairing activity. It belongs in rule 1's
/// counterfactual because admissibility includes it: an activation whose method the matched key or
/// this client would refuse stays refused whatever the setting, so answering `pairing_required`
/// there would invite a host into a pairing flow no setting can admit.
///
/// The two refusal reasons are ordered as `messaging.md` orders them. Rule 1 asks whether the
/// setting is the only obstacle, rule 2 covers everything else; reversing them turns every guest
/// refusal into `unauthorized` and leaves a server unable to tell "pair with me" from "you sent
/// something I forbid", which is the whole point of the switch.
pub(crate) fn admit_activation(
    matched: MatchedPsk,
    unpaired_access: bool,
    pairing_admissible: bool,
    activate: &ServerActivate,
) -> Admitted {
    if activation_admissible(matched, unpaired_access, activate) {
        return Admitted::Admissible;
    }
    // Rule 1: unpaired access is off, and turning it on would have admitted this activation -
    // activity set, roles and pairing method together.
    if !unpaired_access
        && !is_paired(matched)
        && pairing_admissible
        && activation_admissible(matched, true, activate)
    {
        return Admitted::PairingRequired;
    }
    // Rule 2: no setting admits it - the activity set is wrong for the key, or a role was never
    // offered, or roles are declared on a connection that cannot play.
    Admitted::Unauthorized
}

/// The pairing attempt a `server/activate` admits, if it declares the pairing activity.
///
/// An activation that declares `pairing` without its parameters is malformed: no conformant server
/// produces it, and guessing what it meant would leave the server waiting for a `client/pair-init`
/// the client never sends. `pairing` stays ignored when the activity is absent, as the spec allows.
fn admits_pairing(activate: &ServerActivate) -> Result<Option<PairingActivation>> {
    if !activate
        .activities
        .iter()
        .any(|activity| activity == PAIRING)
    {
        return Ok(None);
    }
    let activation = activate.pairing.clone().ok_or_else(|| {
        anyhow!("server/activate declares the pairing activity without pairing parameters")
    })?;
    Ok(Some(activation))
}

/// Whether a `stream/end` or `stream/clear` role list affects the player stream.
///
/// An absent list means every role. Otherwise it has to name the player: `messaging.md` lists the
/// role names in this message as bare `'player'`, `'artwork'` and `'visualizer'`, while
/// `server/activate` uses the versioned `player@v1` form. Both spellings are accepted so a server
/// that reuses the versioned identifier is not silently ignored.
fn affects_player(roles: Option<&[String]>) -> bool {
    match roles {
        None => true,
        Some(roles) => roles
            .iter()
            .any(|role| role == PLAYER_STREAM_ROLE || role == PLAYER_ROLE),
    }
}

/// Decodes the server's static public key from the `server_id` it announced.
///
/// A re-handshake does not repeat `server/init`, so the key the responder needs comes from the
/// initial handshake's announcement. The value is a public key, not key material.
fn decode_server_key(server_id: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(server_id)
        .context("server_id is not unpadded base64url")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("server_id does not decode to a 32-byte X25519 key"))
}

/// Decodes one fixed-length base64url field of a pairing message.
///
/// The spec gives every such field as unpadded base64url, so the canonical re-encoding has to match
/// the received text; a value with spare bits set is not a field a conformant peer sends. The error
/// names the field but never repeats its value: one of these fields is a key-confirmation tag.
#[cfg(feature = "pairing-code")]
fn decode_pairing_field<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("{name} is not unpadded base64url"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        bail!("{name} is not the canonical base64url encoding");
    }
    bytes
        .try_into()
        .map_err(|_| anyhow!("{name} does not decode to {N} bytes"))
}

/// Returns whether a control frame names a pairing message, even when it does not decode.
///
/// The envelope's `type` survives a malformed payload, which is what lets the session tell a
/// pairing protocol error from a control message this revision may ignore. A frame that is not a
/// JSON object with a string `type` names nothing and keeps the lenient path.
fn names_pairing_message(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    value
        .get("type")
        .and_then(|message_type| message_type.as_str())
        .is_some_and(|message_type| PAIRING_MESSAGE_TYPES.contains(&message_type))
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

/// Whether `value` is the canonical unpadded base64url encoding of a 32-byte group id.
///
/// The spec gives a group id as 32 server-chosen bytes in 43 base64url characters, so both a wrong
/// length and a character outside the alphabet are violations. The group id is public, not key
/// material, but the canonical check is the same one the handshake applies to a `psk_id`.
fn is_canonical_group_id(value: &str) -> bool {
    if value.len() != GROUP_ID_LEN {
        return false;
    }
    match URL_SAFE_NO_PAD.decode(value) {
        Ok(bytes) => bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == value,
        Err(_) => false,
    }
}

/// Whether a non-canonical group id is still safe to carry as an opaque string.
///
/// The tolerance keeps the shape a host can log and compare - non-empty, at most
/// [`MAX_GROUP_ID_LEN`] bytes, valid UTF-8 without control characters - while dropping the
/// base64url and length rules the spec imposes. A `String` is always valid UTF-8; the check is
/// named here so the rule stands on its own. An empty or absurd value stays a protocol error.
fn is_tolerable_group_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_GROUP_ID_LEN && !value.chars().any(char::is_control)
}

/// The key that seals a handshake, and what kind of key it is.
struct Selected {
    /// The 32-byte key the responder seals message 2 with.
    psk: [u8; 32],
    /// Which key it is, which decides the pairing methods this connection allows.
    matched: MatchedPsk,
    /// Whether the Sentinel key stands in for a credential the server named and this client does
    /// not hold, which is the server's authenticated credential-mismatch signal.
    credential_mismatch: bool,
}

/// Chooses the key that seals Noise message 2.
///
/// A record matches only when its category and its derived id equal the announcement; its
/// `server_id` must then equal the one in `server/init`, so a record recorded for a different
/// server can never seal this handshake. The pairing PSK is checked first and belongs to no server:
/// it pairs this client with any server, which is what makes one token usable everywhere. A plain
/// lookup miss is the documented unpaired path during the initial handshake; during a re-handshake
/// it is an error, because falling back would silently drop a pairing the previous connection
/// authenticated.
fn select_psk(
    metadata: &PskMetadata,
    candidates: &Candidates,
    server_id: &str,
    initial: bool,
) -> Result<Selected> {
    if metadata.category == PskCategory::Sentinel && metadata.psk_id == SENTINEL_PSK_ID {
        return Ok(Selected {
            psk: SENTINEL_PSK,
            matched: MatchedPsk::Sentinel,
            credential_mismatch: false,
        });
    }
    if metadata.category == PskCategory::Pairing {
        if let Some(pairing) = candidates.pairing() {
            if psk_id_for(&pairing) == metadata.psk_id {
                return Ok(Selected {
                    psk: pairing,
                    matched: MatchedPsk::PairingPsk,
                    credential_mismatch: false,
                });
            }
        }
    }
    let matched = candidates.records().iter().find(|candidate| {
        candidate.category == metadata.category && psk_id_for(&candidate.psk) == metadata.psk_id
    });
    if let Some(candidate) = matched {
        if candidate.server_id != server_id {
            bail!("the stored key for the announced PSK id belongs to another server");
        }
        return Ok(Selected {
            psk: candidate.psk,
            matched: MatchedPsk::Stored(candidate.category),
            credential_mismatch: false,
        });
    }
    if initial {
        // The announcement named a credential this client cannot use: either it holds no record
        // for it, or it holds the key under another category. The fallback is what turns that into
        // the server's credential-mismatch signal, and the session reports it once per connection.
        return Ok(Selected {
            psk: SENTINEL_PSK,
            matched: MatchedPsk::Sentinel,
            credential_mismatch: true,
        });
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
    #[cfg(feature = "pairing-code")]
    use crate::config::CodeOutChannel;

    #[test]
    fn a_refused_session_reports_why_it_refused() {
        assert_eq!(
            Ending::PairingRequired.reason(),
            "the server wanted an unpaired session and this client does not admit one"
        );
        assert_eq!(
            Ending::Unauthorized.reason(),
            "the server's activation is not allowed for the key that sealed this connection"
        );
    }

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

    /// Builds a candidate set without a store, as `connect_with_psks` would.
    fn candidates(records: &[StoredPsk], pairing: Option<[u8; 32]>) -> Candidates {
        Candidates::load(None, records, pairing.map(PairingPsk))
            .expect("a candidate set without a store always builds")
    }

    #[test]
    fn a_sentinel_announcement_selects_the_published_key() {
        let metadata = PskMetadata::parse(sentinel_metadata("sn").as_bytes()).unwrap();
        let candidates = candidates(&[], None);
        assert_eq!(metadata.category, PskCategory::Sentinel);
        for initial in [true, false] {
            let selected = select_psk(&metadata, &candidates, SERVER_ID, initial).unwrap();
            assert_eq!(selected.psk, SENTINEL_PSK);
            assert_eq!(selected.matched, MatchedPsk::Sentinel);
            assert!(
                !selected.credential_mismatch,
                "a Sentinel announcement names the key every client holds"
            );
        }
    }

    #[test]
    fn a_stored_key_wins_and_a_miss_only_falls_back_on_the_initial_handshake() {
        let psk: [u8; 32] = std::array::from_fn(|index| index as u8);
        let announcement = format!(r#"{{"psk_id":"{}","psk_category":"pr"}}"#, psk_id_for(&psk));
        let metadata = PskMetadata::parse(announcement.as_bytes()).unwrap();
        let candidates = candidates(&[stored(PskCategory::Pairing, psk, SERVER_ID)], None);
        for initial in [true, false] {
            let selected = select_psk(&metadata, &candidates, SERVER_ID, initial).unwrap();
            assert_eq!(selected.psk, psk);
            assert_eq!(
                selected.matched,
                MatchedPsk::Stored(PskCategory::Pairing),
                "a host-supplied pairing key is not this client's pairing PSK"
            );
        }

        let unknown = format!(
            r#"{{"psk_id":"{}","psk_category":"lt"}}"#,
            psk_id_for(b"a key this client does not have")
        );
        let metadata = PskMetadata::parse(unknown.as_bytes()).unwrap();
        let selected = select_psk(&metadata, &candidates, SERVER_ID, true).unwrap();
        assert_eq!(selected.psk, SENTINEL_PSK);
        assert!(
            selected.credential_mismatch,
            "the fallback stands in for a credential the server named and this client lacks"
        );
        assert!(
            select_psk(&metadata, &candidates, SERVER_ID, false).is_err(),
            "a re-handshake must not silently drop the established key"
        );
    }

    #[test]
    fn the_pairing_psk_matches_its_own_announcement_for_any_server() {
        let pairing: [u8; 32] = std::array::from_fn(|index| index as u8 ^ 0x11);
        let announcement = format!(
            r#"{{"psk_id":"{}","psk_category":"pr"}}"#,
            psk_id_for(&pairing)
        );
        let metadata = PskMetadata::parse(announcement.as_bytes()).unwrap();
        let candidates = candidates(&[], Some(pairing));

        for server_id in [SERVER_ID, "any other server"] {
            let selected = select_psk(&metadata, &candidates, server_id, true).unwrap();
            assert_eq!(selected.psk, pairing);
            assert_eq!(
                selected.matched,
                MatchedPsk::PairingPsk,
                "the pairing PSK is not tied to one server"
            );
            assert!(!selected.credential_mismatch);
        }

        // The same key announced as a long-term key is not the pairing PSK, and there is no record
        // for it: the initial handshake falls back to the Sentinel key.
        let as_long_term = format!(
            r#"{{"psk_id":"{}","psk_category":"lt"}}"#,
            psk_id_for(&pairing)
        );
        let metadata = PskMetadata::parse(as_long_term.as_bytes()).unwrap();
        let selected = select_psk(&metadata, &candidates, SERVER_ID, true).unwrap();
        assert_eq!(selected.matched, MatchedPsk::Sentinel);

        // A pairing key that is not this client's is a miss as well; it belongs to another
        // device, and only the record lookup could match it.
        let foreign = format!(
            r#"{{"psk_id":"{}","psk_category":"pr"}}"#,
            psk_id_for(b"a pairing key this client does not hold")
        );
        let metadata = PskMetadata::parse(foreign.as_bytes()).unwrap();
        let selected = select_psk(&metadata, &candidates, SERVER_ID, true).unwrap();
        assert_eq!(selected.matched, MatchedPsk::Sentinel);
        assert!(
            selected.credential_mismatch,
            "a pairing key that is not this client's is the credential-mismatch signal"
        );
    }

    #[test]
    fn a_stored_key_only_matches_its_own_category_and_server() {
        let psk: [u8; 32] = std::array::from_fn(|index| index as u8 ^ 0x5a);
        let announcement = format!(r#"{{"psk_id":"{}","psk_category":"pr"}}"#, psk_id_for(&psk));
        let metadata = PskMetadata::parse(announcement.as_bytes()).unwrap();

        // The id matches, but the record was filed under another category.
        let wrong_category = candidates(&[stored(PskCategory::LongTerm, psk, SERVER_ID)], None);
        assert_eq!(
            select_psk(&metadata, &wrong_category, SERVER_ID, true)
                .unwrap()
                .psk,
            SENTINEL_PSK,
            "a category mismatch is a miss, not a match"
        );
        assert!(
            select_psk(&metadata, &wrong_category, SERVER_ID, true)
                .unwrap()
                .credential_mismatch,
            "a key held under another category is exactly what the signal is for"
        );
        assert!(
            select_psk(&metadata, &wrong_category, SERVER_ID, false).is_err(),
            "a category mismatch is an error during a re-handshake"
        );

        // The category and id match, but the record belongs to another server.
        let other_server = candidates(&[stored(PskCategory::Pairing, psk, "wrong-server")], None);
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

    use crate::test_support::NullSink;
    use syncspin_core::noise::Identity;

    /// A configuration for a session that is never connected to a real server.
    fn test_config() -> ClientConfig {
        ClientConfig {
            server: "127.0.0.1:1".to_owned(),
            player_name: "Test player".to_owned(),
            device_info: None,
            identity: Identity::generate(),
            storage: None,
            audio_mode: AudioMode::Passthrough,
            volume: 50,
            muted: false,
            volume_policy: crate::config::VolumePolicy::default(),
            max_backoff: Duration::from_secs(1),
            strict_group_id: false,
            unpaired_access: true,
            pairing_timeout: crate::client::DEFAULT_PAIRING_TIMEOUT,
            #[cfg(feature = "discovery")]
            inbound: None,
            #[cfg(feature = "pairing-code")]
            static_pairing_code: None,
            #[cfg(feature = "pairing-code")]
            pairing_window: crate::config::DEFAULT_PAIRING_WINDOW,
            #[cfg(feature = "pairing-code")]
            pairing_pending_text: None,
            #[cfg(feature = "pairing-code")]
            code_formats: Vec::new(),
            #[cfg(feature = "pairing-code")]
            code_out_channels: Vec::new(),
        }
    }

    /// A shutdown channel no test closes, leaked so a session can borrow it.
    fn idle_shutdown() -> &'static mut oneshot::Receiver<GoodbyeReason> {
        let (sender, receiver) = oneshot::channel();
        Box::leak(Box::new(sender));
        Box::leak(Box::new(receiver))
    }

    /// Builds a session around the given transport and control receiver.
    fn test_session<'a>(
        config: &'a ClientConfig,
        events: &'a mpsc::UnboundedSender<Event>,
        reported_volume: &'a AtomicU8,
        transport: Transport,
        noise: NoiseTransport,
        control: Option<mpsc::UnboundedReceiver<ControlRequest>>,
    ) -> Session<'a> {
        Session {
            transport,
            noise,
            config,
            sink: Box::new(NullSink),
            events,
            reported_volume,
            clock: ClockFilter::new(),
            reassembler: Reassembler::new(MAX_REASSEMBLED_LEN),
            active_roles: vec![CONTROLLER_ROLE.to_owned()],
            stream: None,
            sync_remaining: 0,
            burst_deadline: None,
            reply_deadline: None,
            outstanding_sent_us: None,
            burst_sent_us: BTreeSet::new(),
            burst_started: None,
            burst_samples: Vec::new(),
            state_sent: false,
            control,
            shutdown: idle_shutdown(),
            volume: 50,
            muted: false,
            sink_failed: false,
            group_id_tolerance_reported: false,
            controller_commands: None,
            playback: PlaybackState::default(),
            server_id: SERVER_ID.to_owned(),
            matched: MatchedPsk::Sentinel,
            pairing_required: None,
            ending: None,
            candidates: Candidates::load(None, &[], None).expect("an empty candidate set builds"),
            pairing_index: 0,
            pairing: None,
            discarding_pairing_messages: false,
            #[cfg(feature = "pairing-code")]
            pairing_window: None,
            #[cfg(feature = "pairing-code")]
            pending_pairing: None,
            #[cfg(feature = "pairing-code")]
            failed_rounds: Arc::new(AtomicU32::new(0)),
            rehandshake: None,
        }
    }

    /// A client WebSocket whose peer was reset, so the next write fails.
    ///
    /// `SO_LINGER` with a zero timeout makes the dropped peer send a reset instead of a clean
    /// close, which is what a server that vanished mid-session looks like. It is the only way to
    /// exercise the write-failure path; the deprecation note is about a blocking drop, which a
    /// zero timeout avoids.
    #[allow(deprecated)]
    async fn reset_socket() -> Transport {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a loopback listener");
        let address = listener.local_addr().expect("the bound address");
        let client = TcpStream::connect(address)
            .await
            .expect("a loopback connection");
        let (server_side, _peer) = listener.accept().await.expect("the accepted connection");
        let (client_handshake, server_handshake) = tokio::join!(
            tokio_tungstenite::client_async(
                format!("ws://{address}/"),
                tokio_tungstenite::MaybeTlsStream::Plain(client),
            ),
            tokio_tungstenite::accept_async(server_side),
        );
        let (socket, _response) = client_handshake.expect("the client WebSocket handshake");
        let server_socket = server_handshake.expect("the server WebSocket upgrade");
        server_socket
            .get_ref()
            .set_linger(Some(Duration::ZERO))
            .expect("the socket accepts SO_LINGER");
        drop(server_socket);
        tokio::time::sleep(Duration::from_millis(50)).await;
        Transport {
            socket: Socket::Dialled(socket),
        }
    }

    /// Runs a complete Noise handshake locally and returns the responder's transport.
    fn local_noise_transport() -> NoiseTransport {
        const PROLOGUE: &[u8] = b"syncspin unit-test prologue";
        let identity = Identity::generate();
        let peer = Identity::generate();
        let mut responder =
            Responder::with_peer(&identity, &peer.public, PROLOGUE).expect("the responder builds");
        let mut initiator = snow::Builder::new(
            syncspin_core::noise::NOISE_PARAMS
                .parse()
                .expect("the protocol name parses"),
        )
        .local_private_key(&peer.secret)
        .expect("the initiator key is set")
        .remote_public_key(&identity.public)
        .expect("the responder key is set")
        .psk(2, &SENTINEL_PSK)
        .expect("the PSK is set")
        .prologue(PROLOGUE)
        .expect("the prologue is set")
        .build_initiator()
        .expect("the initiator builds");

        let mut buffer = vec![0u8; syncspin_core::noise::MAX_MESSAGE_LEN];
        let len = initiator
            .write_message(b"{}", &mut buffer)
            .expect("message 1 is written");
        responder
            .read_message(&buffer[..len])
            .expect("message 1 is read");
        let message_2 = responder.write_message().expect("message 2 is written");
        initiator
            .read_message(&message_2, &mut buffer)
            .expect("message 2 is read");
        responder.into_transport().expect("the handshake finishes")
    }

    #[tokio::test]
    async fn a_closed_control_channel_is_disabled_instead_of_polled_forever() {
        let config = test_config();
        let (events, _receiver) = mpsc::unbounded_channel();
        let reported_volume = AtomicU8::new(50);
        let (commands, control) = mpsc::unbounded_channel();
        drop(commands);
        let mut session = test_session(
            &config,
            &events,
            &reported_volume,
            reset_socket().await,
            local_noise_transport(),
            Some(control),
        );

        let outcome = session.serve().await;
        assert!(
            outcome.is_err(),
            "the reset socket must end the session: {outcome:?}"
        );
        assert!(
            session.control.is_none(),
            "a control channel without senders is cleared, not selected forever"
        );
    }

    #[tokio::test]
    async fn a_control_request_that_cannot_be_written_ends_the_session() {
        let config = test_config();
        let (events, _receiver) = mpsc::unbounded_channel();
        let reported_volume = AtomicU8::new(50);
        let mut session = test_session(
            &config,
            &events,
            &reported_volume,
            reset_socket().await,
            local_noise_transport(),
            None,
        );

        let (reply, response) = tokio::sync::oneshot::channel();
        let request = ControlRequest {
            action: ControlAction::Transport("play"),
            reply,
        };
        let error = session
            .handle_control(request)
            .await
            .expect_err("a failed write must end the session");
        assert!(
            format!("{error:#}").contains("WebSocket send failed"),
            "the error must name the failed write, got: {error:#}"
        );

        let answer = response
            .await
            .expect("the waiting call is answered")
            .expect_err("the call does not succeed");
        assert!(
            format!("{answer:#}").contains("WebSocket send failed"),
            "the caller sees the write failure, got: {answer:#}"
        );
    }

    #[test]
    fn only_an_activation_that_declares_pairing_admits_an_attempt() {
        let playing = ServerActivate {
            activities: vec!["playback".to_owned()],
            ..ServerActivate::default()
        };
        assert_eq!(admits_pairing(&playing).unwrap(), None);

        // A pairing object without the pairing activity is ignored, as the spec requires.
        let stray = ServerActivate {
            activities: vec!["playback".to_owned()],
            pairing: Some(PairingActivation {
                method: "pairing_psk".to_owned(),
                format: None,
            }),
            ..ServerActivate::default()
        };
        assert_eq!(admits_pairing(&stray).unwrap(), None);

        let pairing = ServerActivate {
            activities: vec!["pairing".to_owned()],
            pairing: Some(PairingActivation {
                method: "pairing_psk".to_owned(),
                format: None,
            }),
            ..ServerActivate::default()
        };
        assert_eq!(
            admits_pairing(&pairing).unwrap().map(|a| a.method),
            Some("pairing_psk".to_owned())
        );

        // The activity without its parameters is malformed, not an attempt with defaults.
        let missing = ServerActivate {
            activities: vec!["pairing".to_owned()],
            ..ServerActivate::default()
        };
        let error = admits_pairing(&missing).expect_err("a missing object is a protocol error");
        assert!(
            format!("{error:#}").contains("pairing parameters"),
            "got: {error:#}"
        );
    }

    /// Builds a `server/activate` with the given activities and roles.
    fn activation(activities: &[&str], roles: Option<&[&str]>) -> ServerActivate {
        ServerActivate {
            activities: activities.iter().map(|a| (*a).to_owned()).collect(),
            active_roles: roles.map(|roles| roles.iter().map(|r| (*r).to_owned()).collect()),
            pairing: None,
        }
    }

    /// A long-term-keyed connection, the only kind `messaging.md` leaves fully paired.
    const LONG_TERM: MatchedPsk = MatchedPsk::Stored(PskCategory::LongTerm);

    #[test]
    fn a_paired_session_admits_playback_with_roles_whatever_the_setting() {
        let activate = activation(
            &["playback"],
            Some(&["player@v1", "controller@v1", "metadata@v1"]),
        );
        for unpaired_access in [true, false] {
            assert_eq!(
                admit_activation(LONG_TERM, unpaired_access, true, &activate),
                Admitted::Admissible
            );
        }
    }

    #[test]
    fn a_paired_session_may_not_declare_the_pairing_activity() {
        assert_eq!(
            admit_activation(LONG_TERM, true, true, &activation(&["pairing"], None)),
            Admitted::Unauthorized,
            "a connection keyed by a long-term PSK has nothing left to pair"
        );
    }

    #[test]
    fn a_paired_session_may_not_declare_an_unknown_activity() {
        assert_eq!(
            admit_activation(
                LONG_TERM,
                true,
                true,
                &activation(&["playback", "kiosk"], None)
            ),
            Admitted::Unauthorized
        );
    }

    #[test]
    fn a_repeated_activity_is_not_a_set() {
        assert_eq!(
            admit_activation(
                LONG_TERM,
                true,
                true,
                &activation(&["playback", "playback"], None)
            ),
            Admitted::Unauthorized,
            "the spec calls the activities a set, so a repeat is not a member"
        );
    }

    #[test]
    fn an_empty_activation_is_admissible_for_every_psk() {
        let activate = activation(&[], None);
        for matched in [MatchedPsk::Sentinel, MatchedPsk::PairingPsk, LONG_TERM] {
            for unpaired_access in [true, false] {
                assert_eq!(
                    admit_activation(matched, unpaired_access, true, &activate),
                    Admitted::Admissible,
                    "{matched:?} with unpaired access {unpaired_access}"
                );
            }
        }
    }

    #[test]
    fn a_guest_may_pair_with_unpaired_access_off() {
        assert_eq!(
            admit_activation(
                MatchedPsk::Sentinel,
                false,
                true,
                &activation(&["pairing"], None)
            ),
            Admitted::Admissible,
            "both pairing flows run over a Sentinel-keyed session"
        );
    }

    #[test]
    fn a_guest_may_not_play_with_unpaired_access_off() {
        assert_eq!(
            admit_activation(
                MatchedPsk::Sentinel,
                false,
                true,
                &activation(&["playback"], Some(&["player@v1"]))
            ),
            Admitted::PairingRequired
        );
    }

    #[test]
    fn a_guest_with_roles_and_no_activity_still_needs_unpaired_access() {
        assert_eq!(
            admit_activation(
                MatchedPsk::Sentinel,
                false,
                true,
                &activation(&[], Some(&["player@v1"]))
            ),
            Admitted::PairingRequired,
            "roles alone make the connection playback-capable"
        );
    }

    #[test]
    fn an_unoffered_role_is_unauthorized_not_pairing_required() {
        assert_eq!(
            admit_activation(
                MatchedPsk::Sentinel,
                false,
                true,
                &activation(&["playback"], Some(&["source@v1"]))
            ),
            Admitted::Unauthorized,
            "enabling unpaired access would not have made this role admissible"
        );
    }

    #[test]
    fn a_pairing_psk_session_behaves_like_a_sentinel_one() {
        assert_eq!(
            admit_activation(
                MatchedPsk::PairingPsk,
                false,
                true,
                &activation(&["playback"], Some(&["player@v1"]))
            ),
            Admitted::PairingRequired
        );
    }

    #[test]
    fn rule_1_requires_an_admissible_pairing_method() {
        // The doubly-bad shape: `playback` needs unpaired access, and the declared method is not
        // admissible on a Sentinel-keyed connection (it is the Pairing PSK method, and there is no
        // store). Enabling unpaired access would still not admit it, so rule 1 must not answer.
        let activate = ServerActivate {
            activities: vec!["playback".to_owned(), "pairing".to_owned()],
            active_roles: Some(vec!["player@v1".to_owned()]),
            pairing: Some(PairingActivation {
                method: "pairing_psk".to_owned(),
                format: None,
            }),
        };
        assert_eq!(
            admit_activation(MatchedPsk::Sentinel, false, true, &activate),
            Admitted::PairingRequired,
            "with the method assumed acceptable, enabling unpaired access admits the activation"
        );
        assert_eq!(
            admit_activation(MatchedPsk::Sentinel, false, false, &activate),
            Admitted::Unauthorized,
            "the wrong method keeps the activation refused whatever the setting"
        );
    }

    #[test]
    fn unpaired_access_makes_roles_admissible_without_an_activity() {
        assert_eq!(
            admit_activation(
                MatchedPsk::Sentinel,
                true,
                true,
                &activation(&[], Some(&["player@v1"]))
            ),
            Admitted::Admissible
        );
    }

    #[test]
    fn a_paired_session_keeps_roles_without_the_playback_activity() {
        assert_eq!(
            admit_activation(
                LONG_TERM,
                false,
                true,
                &activation(&[], Some(&["player@v1"]))
            ),
            Admitted::Admissible
        );
    }

    #[test]
    fn a_verdict_names_its_refusal() {
        assert_eq!(Admitted::Admissible.refusal(), None);
        assert_eq!(
            Admitted::PairingRequired.refusal(),
            Some(Refusal::PairingRequired)
        );
        assert_eq!(
            Admitted::Unauthorized.refusal(),
            Some(Refusal::Unauthorized)
        );
    }

    #[test]
    fn playback_capable_for_follows_the_key_and_the_setting() {
        assert!(
            playback_capable_for(LONG_TERM, false, &[]),
            "a paired connection is playback-capable whatever the setting"
        );
        assert!(
            playback_capable_for(MatchedPsk::Sentinel, true, &[]),
            "unpaired access alone makes a guest playback-capable"
        );
        assert!(
            playback_capable_for(MatchedPsk::Sentinel, true, &["pairing".to_owned()]),
            "declaring pairing does not take playback capability away"
        );
        assert!(
            !playback_capable_for(MatchedPsk::Sentinel, false, &[]),
            "a guest without unpaired access is not playback-capable"
        );
        assert!(
            !playback_capable_for(MatchedPsk::Sentinel, false, &["pairing".to_owned()]),
            "declaring pairing does not add playback capability"
        );
    }

    #[test]
    fn the_pairing_method_is_offered_exactly_with_a_store() {
        let mut config = test_config();
        assert!(
            pair_methods(&config).pairing_psk.is_none(),
            "a client without a store cannot pair and must not offer the method"
        );
        config.storage = Some(std::sync::Arc::new(
            crate::test_support::MemoryStore::holding([7u8; 32]),
        ));
        assert!(
            pair_methods(&config).pairing_psk.is_some(),
            "a configured store makes the Pairing PSK method available"
        );
    }

    /// The static code is configuration, and its record needs a store to live in.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn the_static_code_is_offered_exactly_with_a_configured_code_and_a_store() {
        let mut config = test_config();
        assert!(
            pair_methods(&config).static_pairing_code.is_none(),
            "a client without a code must not offer the method"
        );

        config.static_pairing_code = Some("12345678".to_owned());
        assert!(
            pair_methods(&config).static_pairing_code.is_none(),
            "a client that cannot persist the record must not offer the method"
        );

        config.storage = Some(std::sync::Arc::new(
            crate::test_support::MemoryStore::holding([7u8; 32]),
        ));
        assert!(
            pair_methods(&config).static_pairing_code.is_some(),
            "a configured code and a store make the method available"
        );

        config.static_pairing_code = None;
        assert!(
            pair_methods(&config).static_pairing_code.is_none(),
            "the code is the method's credential and cannot be absent"
        );
    }

    /// The method is admissible on an unauthenticated connection, not on the pairing PSK's.
    #[cfg(feature = "pairing-code")]
    #[tokio::test]
    async fn the_static_code_is_admissible_only_without_the_pairing_psk() {
        let plain_config = test_config();
        let coded_config = ClientConfig {
            static_pairing_code: Some("12345678".to_owned()),
            storage: Some(std::sync::Arc::new(
                crate::test_support::MemoryStore::holding([7u8; 32]),
            )),
            ..test_config()
        };
        let (events, _receiver) = mpsc::unbounded_channel();
        let reported_volume = AtomicU8::new(50);
        let mut session = test_session(
            &plain_config,
            &events,
            &reported_volume,
            reset_socket().await,
            local_noise_transport(),
            None,
        );

        let activation = PairingActivation {
            method: "static_pairing_code".to_owned(),
            format: None,
        };
        assert_eq!(
            session.admitted_method(&activation),
            None,
            "a client without a code cannot run the method"
        );

        session.config = &coded_config;
        assert_eq!(
            session.admitted_method(&activation),
            Some(AdmittedMethod::StaticCode),
            "a Sentinel-keyed connection admits the code flow"
        );
        session.matched = MatchedPsk::Stored(PskCategory::LongTerm);
        assert_eq!(
            session.admitted_method(&activation),
            Some(AdmittedMethod::StaticCode),
            "a long-term-keyed connection admits the code flow as well"
        );
        session.matched = MatchedPsk::PairingPsk;
        assert_eq!(
            session.admitted_method(&activation),
            None,
            "the method and the matched pairing PSK are an inadmissible combination"
        );

        // A format belongs to the dynamic flow; a static activation that carries one was not offered.
        session.matched = MatchedPsk::Sentinel;
        let formatted = PairingActivation {
            method: "static_pairing_code".to_owned(),
            format: Some("digits".to_owned()),
        };
        assert_eq!(session.admitted_method(&formatted), None);
    }

    /// The dynamic method needs its descriptor, the format the server picked and a store.
    #[cfg(feature = "pairing-code")]
    #[tokio::test]
    async fn the_dynamic_code_needs_formats_channels_and_a_store() {
        let empty_config = test_config();
        let formatted_config = ClientConfig {
            code_formats: vec![CodeFormat::Digits],
            code_out_channels: vec![CodeOutChannel::Display],
            ..test_config()
        };
        let offered_config = ClientConfig {
            storage: Some(std::sync::Arc::new(
                crate::test_support::MemoryStore::holding([7u8; 32]),
            )),
            ..formatted_config.clone()
        };
        let (events, _receiver) = mpsc::unbounded_channel();
        let reported_volume = AtomicU8::new(50);
        let mut session = test_session(
            &empty_config,
            &events,
            &reported_volume,
            reset_socket().await,
            local_noise_transport(),
            None,
        );
        let activation = PairingActivation {
            method: "dynamic_pairing_code".to_owned(),
            format: Some("digits".to_owned()),
        };

        assert_eq!(
            session.admitted_method(&activation),
            None,
            "without formats and a channel the method is not offered"
        );
        assert_eq!(
            session.dynamic_format(&activation),
            None,
            "no descriptor, no emission format"
        );

        // A descriptor without a store is not offerable: the record could not be persisted.
        assert!(
            pair_methods(&formatted_config)
                .dynamic_pairing_code
                .is_none(),
            "the advertisement follows the same rule"
        );
        session.config = &formatted_config;
        assert_eq!(session.admitted_method(&activation), None);

        let descriptor = pair_methods(&offered_config)
            .dynamic_pairing_code
            .expect("formats, a channel and a store make the method offerable");
        assert_eq!(descriptor.formats, vec!["digits"]);
        assert_eq!(descriptor.out_channels, vec!["display"]);

        session.config = &offered_config;
        assert_eq!(
            session.admitted_method(&activation),
            Some(AdmittedMethod::DynamicCode),
            "an offered format on a Sentinel-keyed connection is admissible"
        );
        assert_eq!(
            session.dynamic_format(&activation),
            Some(CodeFormat::Digits),
            "the activation's format is the one the attempt runs"
        );

        for format in ["qr_code", "nfc", ""] {
            let other = PairingActivation {
                method: "dynamic_pairing_code".to_owned(),
                format: Some(format.to_owned()),
            };
            assert_eq!(
                session.admitted_method(&other),
                None,
                "{format:?} is not an offered format"
            );
        }
        let unformatted = PairingActivation {
            method: "dynamic_pairing_code".to_owned(),
            format: None,
        };
        assert_eq!(
            session.admitted_method(&unformatted),
            None,
            "the dynamic flow always names its emission format"
        );

        session.matched = MatchedPsk::PairingPsk;
        assert_eq!(
            session.admitted_method(&activation),
            None,
            "the method and the matched pairing PSK are an inadmissible combination"
        );
    }

    /// The round limit is twenty, and only a release or a verified tag resets it.
    #[cfg(feature = "pairing-code")]
    #[tokio::test]
    async fn the_round_limit_holds_attempts_back_and_a_release_resets_it() {
        let config = test_config();
        let (events, _receiver) = mpsc::unbounded_channel();
        let reported_volume = AtomicU8::new(50);
        let mut session = test_session(
            &config,
            &events,
            &reported_volume,
            reset_socket().await,
            local_noise_transport(),
            None,
        );

        assert!(
            !session.rounds_are_exhausted(),
            "a fresh process is below the limit"
        );
        for round in 1..20 {
            assert_eq!(session.record_round(), round);
            assert!(
                !session.rounds_are_exhausted(),
                "round {round} must still admit another one"
            );
        }
        assert_eq!(session.record_round(), 20);
        assert!(
            session.rounds_are_exhausted(),
            "the twentieth begun round reaches the limit"
        );

        // The release is the operator action the spec requires, and it clears the count.
        session
            .release_holdback()
            .await
            .expect("a release needs no connection and no pending attempt");
        assert!(!session.rounds_are_exhausted());
        assert_eq!(session.failed_rounds.load(Ordering::SeqCst), 0);
    }

    /// The window closes on its fifth failed verification, and expiry closes it as well.
    #[cfg(feature = "pairing-code")]
    #[tokio::test]
    async fn the_fifth_failed_verification_closes_the_pairing_window() {
        let config = test_config();
        // A window that expires while the test runs; the default is minutes.
        let short_config = ClientConfig {
            pairing_window: Duration::from_millis(1),
            ..test_config()
        };
        let (events, _receiver) = mpsc::unbounded_channel();
        let reported_volume = AtomicU8::new(50);
        let mut session = test_session(
            &config,
            &events,
            &reported_volume,
            reset_socket().await,
            local_noise_transport(),
            None,
        );

        assert!(!session.window_is_open(), "no gesture, no window");
        session.open_pairing_window().await.expect("a window opens");
        assert!(session.window_is_open());

        for attempt in 1..5 {
            session.record_window_failure();
            assert!(
                session.window_is_open(),
                "failure {attempt} must leave the window open"
            );
        }
        session.record_window_failure();
        assert!(
            !session.window_is_open(),
            "the fifth failed verification closes the window"
        );

        // Expiry is silent and only noticed the next time the window is consulted.
        session.config = &short_config;
        session.open_pairing_window().await.expect("a window opens");
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(
            !session.window_is_open(),
            "a window past its lifetime is closed"
        );
        assert!(
            session.pairing_window.is_none(),
            "the expired window is dropped rather than kept"
        );
    }

    #[test]
    fn only_pairing_message_types_are_fatal_when_malformed() {
        for text in [
            r#"{"type":"server/pair-init"}"#,
            r#"{"type":"server/pair-auth"}"#,
            r#"{"type":"server/pair-confirm"}"#,
            r#"{"type":"server/pair-finalize"}"#,
            r#"{"type":"pair/abort","payload":{}}"#,
        ] {
            assert!(
                names_pairing_message(text),
                "{text} names a pairing message"
            );
        }

        for text in [
            r#"{"type":"server/state","payload":{}}"#,
            r#"{"type":"future/message","payload":{}}"#,
            "{}",
            "not json",
            "",
        ] {
            assert!(
                !names_pairing_message(text),
                "{text} must stay on the lenient path"
            );
        }
    }

    /// A pairing requirement reaches the host once per connection, not once per frame.
    #[tokio::test]
    async fn a_credential_mismatch_is_reported_once_per_connection() {
        let config = test_config();
        let (events, mut receiver) = mpsc::unbounded_channel();
        let reported_volume = AtomicU8::new(50);
        let mut session = test_session(
            &config,
            &events,
            &reported_volume,
            reset_socket().await,
            local_noise_transport(),
            None,
        );
        session.pairing_required = Some(PairingRequiredReason::CredentialMismatch);

        session.report_pairing_required();
        session.report_pairing_required();

        let mut seen = Vec::new();
        while let Ok(event) = receiver.try_recv() {
            seen.push(event);
        }
        assert_eq!(
            seen,
            vec![Event::PairingRequired {
                server_id: SERVER_ID.to_owned(),
                reason: PairingRequiredReason::CredentialMismatch,
            }],
            "one connection, one requirement"
        );
        assert!(
            session.pairing_required.is_none(),
            "the requirement is consumed, so nothing can report it again"
        );
    }

    /// A guest session has no record to drop, so `server/unpair` leaves it untouched.
    #[tokio::test]
    async fn an_unpair_on_an_unpaired_session_is_ignored() {
        let config = test_config();
        let (events, mut receiver) = mpsc::unbounded_channel();
        let reported_volume = AtomicU8::new(50);
        let mut session = test_session(
            &config,
            &events,
            &reported_volume,
            reset_socket().await,
            local_noise_transport(),
            None,
        );
        assert_eq!(session.matched, MatchedPsk::Sentinel);

        session
            .handle_unpair()
            .await
            .expect("an ignored unpair is not an error");

        assert!(
            receiver.try_recv().is_err(),
            "the client must not report a record it never held"
        );
        assert!(
            session.ending.is_none(),
            "the connection stays open, as the spec requires for an unpaired session"
        );

        // A session keyed by the pairing PSK is unpaired as well: the record it would drop would
        // be the client's own pairing credential, which no server owns.
        session.matched = MatchedPsk::PairingPsk;
        session
            .handle_unpair()
            .await
            .expect("an ignored unpair is not an error");
        assert!(receiver.try_recv().is_err());
        assert!(session.ending.is_none());
    }

    #[tokio::test]
    async fn a_finalize_without_a_store_is_an_error_instead_of_a_silent_pairing() {
        // The attempt only starts with a store, so this guard is unreachable through the wire; it
        // must still fail loudly rather than report a pairing whose record went nowhere.
        let config = test_config();
        let (events, _receiver) = mpsc::unbounded_channel();
        let reported_volume = AtomicU8::new(50);
        let mut session = test_session(
            &config,
            &events,
            &reported_volume,
            reset_socket().await,
            local_noise_transport(),
            None,
        );
        session.pairing = Some(PairingAttempt::new(1, Duration::from_secs(120), None));

        let error = session
            .confirm_pairing()
            .expect_err("a finalize without a store cannot be recorded");
        assert!(
            format!("{error:#}").contains("without a pairing store"),
            "got: {error:#}"
        );
        assert!(
            session.pairing.is_none(),
            "the attempt is consumed even when the record cannot be stored"
        );
    }

    #[tokio::test]
    async fn a_repeated_time_reply_yields_one_sample() {
        let config = test_config();
        let (events, _receiver) = mpsc::unbounded_channel();
        let reported_volume = AtomicU8::new(50);
        let mut session = test_session(
            &config,
            &events,
            &reported_volume,
            reset_socket().await,
            local_noise_transport(),
            None,
        );
        session.start_burst();
        let transmitted = now_us();
        session.burst_sent_us.insert(transmitted);

        let reply = ServerTime {
            client_transmitted: transmitted,
            server_received: transmitted + 1,
            server_transmitted: transmitted + 1,
        };
        session
            .handle_server_time(reply)
            .await
            .expect("a reply for a request this burst sent is accepted");
        session
            .handle_server_time(reply)
            .await
            .expect("a duplicate reply is ignored, not an error");

        assert_eq!(
            session.burst_samples.len(),
            1,
            "one request yields at most one sample even if the peer echoes it twice"
        );
    }
}
