//! Accepting clients: the WebSocket upgrade, the init exchange, the Noise handshake, the
//! hello/activate sequence, and the session that follows it.
//!
//! One task per connection, each with its own handshake state, so a client that stalls or fails
//! never holds up the listener or another client. The sequence is the specification's: the client
//! sends `client/init`, the server answers `server/init` and Noise message 1 without waiting in
//! between, the client answers with Noise message 2, and the server then sends `server/hello`,
//! waits for `client/hello` and sends `server/activate`.
//!
//! The PSK of the first handshake is chosen from the client's `client_id`: a record the host's
//! [`PairingStore`](crate::PairingStore) holds seals a paired connection, and the published
//! Sentinel key seals every other one. A client that holds no usable record seals message 2 with
//! the Sentinel key; when the announced record did not seal it, the server retries the same message
//! under the Sentinel key ([`Initiator::read_message_with_sentinel`]). If that authenticates, the
//! connection is admitted without roles and the mismatch is reported: the client does not hold the
//! record, and the record stays where it is until the operator replaces it.
//!
//! A failure decided from `client/init` alone is answered with `server/error` and a close; every
//! later failure is silent, which is why the handshake paths here close without a message.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use syncspin_core::framing::{
    decode_frame, encode_binary, Frame as PlaintextFrame, BINARY_MESSAGE_ID_JSON,
};
use syncspin_core::messages::{
    ClientHello, ClientPairAuth, ClientPairConfirm, ClientPairFinalize, ClientPairInit,
    ClientPairPending, ClientPairRetry, Incoming, NoiseHandshake, PairingActivation,
    ServerActivate, ServerError, ServerHello, ServerInit, ServerTime, PROTOCOL_VERSION,
};
use syncspin_core::noise::{
    psk_id_for, Initiator, PskOutcome, Suite, TransportState, SENTINEL_PSK,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{accept_hdr_async, connect_async, MaybeTlsStream, WebSocketStream};

use crate::group::{Group, Outbound, CONTROLLER_ROLE, METADATA_ROLE, PLAYER_ROLE};
use crate::pairing::{self, Attempt, CodeFormat, PairingMethod};
use crate::stream::AudioFormat;
use crate::{Command, Event, Registry, ServerConfig};

/// The PSK category of the published Sentinel key.
const CATEGORY_SENTINEL: &str = "sn";

/// The PSK category of a long-term pairing record.
const CATEGORY_LONG_TERM: &str = "lt";

/// The PSK category of a client's pairing PSK.
const CATEGORY_PAIRING: &str = "pr";

/// The `server/activate` activity that admits one pairing attempt.
const PAIRING_ACTIVITY: &str = "pairing";

/// Payload of Noise handshake message 2: the literal empty JSON object, not zero bytes.
const HANDSHAKE_MESSAGE_2: &[u8] = b"{}";

/// Unpadded base64url length of a 32-byte key.
const KEY_CHARS: usize = 43;

/// How long the link may stay silent before the server sends a WebSocket ping.
///
/// The same window as the client's keepalive: the protocol has no application-level liveness
/// message, so an idle session is silent in both directions, and a client that vanished without
/// closing its socket would otherwise be noticed only when the server writes and TCP fails -
/// possibly never, for a player that receives nothing. The ping is the only traffic this adds, and
/// it appears only when nothing has arrived for this window. A pairing wait is silence too, so the
/// server pings every 15 s during one, and a peer that answers nothing at all is diagnosed as a
/// dead link at 25 s rather than reaching the pairing timeout.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);

/// How long the link may stay silent after a keepalive ping before the connection is treated as
/// dead.
///
/// Any received frame counts as the answer, not only a pong: a `client/time` request, a state
/// report or a command that arrives while the ping is outstanding proves the link is alive just as
/// well. A half-open link is therefore detected within 25 s of the last frame the server received,
/// and the connection ends as an `Event::ClientLeft` that names the keepalive.
const KEEPALIVE_PONG_TIMEOUT: Duration = Duration::from_secs(10);

/// The socket one connection runs on, whichever side opened it.
///
/// A client-initiated connection is accepted as a plain TCP stream; a server-initiated one is
/// dialled and therefore arrives in the TLS-capable wrapper, even though the advertised address is
/// `ws://`. The Noise layer inside the payloads is what encrypts, so the difference is only which
/// handshake built the WebSocket.
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Accepts connections until the listener is told to stop.
pub(crate) async fn run(
    listener: TcpListener,
    config: ServerConfig,
    group: Arc<Group>,
    events: mpsc::UnboundedSender<Event>,
    registry: Arc<Registry>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _address) = accepted.context("failed to accept a connection")?;
                let config = config.clone();
                let group = group.clone();
                let events = events.clone();
                let registry = registry.clone();
                let shutdown = shutdown.clone();
                connections.spawn(serve(stream, config, group, events, registry, shutdown));
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                // A task that failed has already reported what the host has to know through the
                // event stream; a listener that stopped accepting over one broken client would
                // take the whole server with it.
                let _ = joined;
            }
        }
    }
    // Every connection reads with the shutdown signal in its select, so the tasks end on their
    // own and a live client sees a close frame rather than a dropped socket.
    while connections.join_next().await.is_some() {}
    Ok(())
}

/// Serves one accepted TCP connection to its end.
async fn serve(
    stream: TcpStream,
    config: ServerConfig,
    group: Arc<Group>,
    events: mpsc::UnboundedSender<Event>,
    registry: Arc<Registry>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let Some(socket) = upgrade(stream, &config.path).await? else {
        return Ok(());
    };
    serve_socket(socket, config, group, events, registry, shutdown).await
}

/// Dials one advertised client and serves the WebSocket it accepts.
///
/// `connection.md`, _Server Initiated Connections_: the request goes to the advertised `ws://`
/// address and path, and carries no `Origin` header - a client refuses one, because the header is
/// a browser's cross-origin authorisation and not part of this protocol. Who opened the WebSocket
/// does not change who starts Noise: the server is the initiator in both directions, so the
/// conversion after the upgrade is the one an accepted connection runs.
pub(crate) async fn connect(
    url: &str,
    config: ServerConfig,
    group: Arc<Group>,
    events: mpsc::UnboundedSender<Event>,
    registry: Arc<Registry>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let (socket, _response) = connect_async(url)
        .await
        .with_context(|| format!("failed to connect to the client at {url}"))?;
    serve_socket(socket, config, group, events, registry, shutdown).await
}

/// Runs the protocol on a socket whose WebSocket handshake is already done.
async fn serve_socket(
    socket: Socket,
    config: ServerConfig,
    group: Arc<Group>,
    events: mpsc::UnboundedSender<Event>,
    registry: Arc<Registry>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut connection = Connection {
        socket,
        shutdown,
        last_received: tokio::time::Instant::now(),
        frames_received: 0,
    };
    converse(&mut connection, &config, &group, &events, &registry).await
}

/// Upgrades `stream` to a WebSocket if it asks for the endpoint the server serves.
///
/// `accept_hdr_async` is `accept_async` with a look at the request, which is the only way the
/// configured path can be honoured: a request for another path is answered with a 404 instead of
/// being served.
// Error responses are the handshake crate's large `http::Response` type; a rejection happens once
// per refused upgrade, so boxing it would buy nothing.
#[allow(clippy::result_large_err)]
async fn upgrade(stream: TcpStream, path: &str) -> Result<Option<Socket>> {
    let expected = path.to_owned();
    let callback = move |request: &Request, response: Response| {
        if request.uri().path() == expected {
            Ok(response)
        } else {
            let mut error =
                ErrorResponse::new(Some("this endpoint is not a Sendspin endpoint".to_owned()));
            *error.status_mut() = StatusCode::NOT_FOUND;
            Err(error)
        }
    };
    match accept_hdr_async(MaybeTlsStream::Plain(stream), callback).await {
        Ok(socket) => Ok(Some(socket)),
        // The peer asked for another path and was answered with the 404 above.
        Err(WsError::Http(response)) if response.status() == StatusCode::NOT_FOUND => Ok(None),
        Err(error) => Err(error).context("the WebSocket upgrade failed"),
    }
}

/// Runs one connection from `client/init` to its close.
async fn converse(
    connection: &mut Connection,
    config: &ServerConfig,
    group: &Arc<Group>,
    events: &mpsc::UnboundedSender<Event>,
    registry: &Arc<Registry>,
) -> Result<()> {
    // 1. `client/init`, the first message of every connection and cleartext.
    let accepted = match connection.read_cleartext().await? {
        Cleartext::Text(text) => match accept_init(&text) {
            Ok(accepted) => accepted,
            Err(failure) => {
                // An init failure is the one refusal the specification lets the server explain.
                let error = Incoming::ServerError(ServerError {
                    reason: failure.reason().to_owned(),
                });
                connection.send_text(&encode(&error)?).await?;
                let _ = connection.close().await;
                return Ok(());
            }
        },
        Cleartext::Closed => return Ok(()),
        Cleartext::Shutdown => {
            let _ = connection.close().await;
            return Ok(());
        }
    };

    // 2. `server/init` immediately followed by Noise message 1, with nothing in between.
    let server_init = Incoming::ServerInit(ServerInit {
        server_id: config.identity.public_base64(),
        version: PROTOCOL_VERSION,
    });
    let server_init_text = encode(&server_init)?;
    connection.send_text(&server_init_text).await?;

    // The suite is the one the client announced: there is no negotiation and no fallback to the
    // default, and a suite this build does not have was refused above.
    let mut prologue = accepted.bytes;
    prologue.extend_from_slice(server_init_text.as_bytes());

    // 3. The first handshake, sealed by the record the store holds or by the Sentinel key.
    //
    // A store that cannot be read ends the connection: continuing would announce the Sentinel key
    // to a client whose record exists, which is a silent downgrade to an unpaired session.
    let record = pairing::record_for(config.storage.as_deref(), &accepted.client_id)?;
    let has_record = record.is_some();
    let (psk, category) = match record {
        Some(psk) => (psk, CATEGORY_LONG_TERM),
        None => (SENTINEL_PSK, CATEGORY_SENTINEL),
    };
    let mut initiator =
        Initiator::with_announced_suite(&config.identity, &accepted.key, &prologue)?;
    initiator.set_psk(&psk)?;
    let metadata = serde_json::json!({
        "psk_id": psk_id_for(&psk),
        "psk_category": category,
    });
    let message_1 = initiator
        .write_message(metadata.to_string().as_bytes())
        .context("failed to write Noise handshake message 1")?;
    let message_1 = Incoming::NoiseHandshake(NoiseHandshake {
        data: URL_SAFE_NO_PAD.encode(&message_1),
    });
    connection.send_text(&encode(&message_1)?).await?;

    // 4. Noise message 2. Every failure from here on is silent.
    //
    // The announcement is the record's, whatever key the client actually sealed with. Only a
    // connection whose record exists is offered the retry under the Sentinel key: without one the
    // announced key already is the Sentinel key, and there is nothing to retry.
    let Some(message_2) = connection.read_handshake_message().await? else {
        return Ok(());
    };
    let read = if has_record {
        initiator.read_message_with_sentinel(&message_2)
    } else {
        initiator
            .read_message(&message_2)
            .map(|payload| (PskOutcome::SelectedKey, payload))
    };
    let (outcome, payload) = match read {
        Ok(read) => read,
        // A message that authenticates under neither key is a silent failure. The record is left
        // alone, so a client that lost its key cannot erase the server's.
        Err(_) => {
            let _ = connection.close().await;
            return Ok(());
        }
    };
    if payload != HANDSHAKE_MESSAGE_2 {
        let _ = connection.close().await;
        return Ok(());
    }
    let mut noise = match initiator.into_transport() {
        Ok(noise) => noise,
        Err(_) => {
            let _ = connection.close().await;
            return Ok(());
        }
    };

    // 5. `server/hello`, the first message under the new keys, followed by `client/hello`.
    let hello = Incoming::ServerHello(ServerHello {
        name: config.name.clone(),
        languages: None,
    });
    connection.send_json(&mut noise, &hello).await?;
    let Some(client_hello) = connection.read_client_hello(&mut noise).await? else {
        return Ok(());
    };
    let client_id = accepted.client_id.clone();
    let paired = has_record && outcome == PskOutcome::SelectedKey;
    // The record exists, but the client sealed with the Sentinel key: it does not hold the record
    // and must not be treated as paired, however the operator's approval stands.
    let credential_mismatch = has_record && outcome == PskOutcome::SentinelFallback;
    let approved = paired || registry.is_approved(&client_id);

    // 6. The session owns the connection from here: the activation, the group, the commands and
    // the pairing attempt all travel through it. The registration goes first, so a host that
    // reacts to `CredentialMismatch` already finds the session; the command channel is unbounded
    // and a command sent before the loop starts waits there.
    let session_id = registry.next_session();
    let (commands, command_stream) = mpsc::unbounded_channel();
    registry.register(&client_id, session_id, commands);
    let _ = events.send(Event::ClientConnected {
        client_id: client_id.clone(),
        name: client_hello.name.clone(),
        approved: paired || (approved && !credential_mismatch),
    });
    if credential_mismatch {
        let _ = events.send(Event::CredentialMismatch {
            client_id: client_id.clone(),
        });
    }
    let session = Session {
        connection,
        config,
        group,
        events,
        registry,
        client_id: client_id.clone(),
        client_key: accepted.key,
        hello: client_hello,
        paired,
        approved,
        credential_mismatch,
        roles: Vec::new(),
        member: None,
        outbound: None,
        pairing_index: 0,
        attempt: None,
        discarding_pairing_messages: false,
        connection_psk: None,
        pending_pair_reply: None,
        commands: command_stream,
        commands_open: true,
        ending: None,
        keepalive_ping: None,
        keepalive_nonce: 0,
    };
    let outcome = session.run(&mut noise).await;
    registry.unregister(&client_id, session_id);
    outcome
}

/// Encodes one control message as the JSON text of its envelope.
fn encode(message: &Incoming) -> Result<String> {
    serde_json::to_string(message).context("failed to encode a control message")
}

/// One frame read from the socket.
struct Frame {
    /// What the frame carried.
    body: FrameBody,
    /// When the WebSocket delivered it, for the receive stamp of a `server/time` reply.
    arrived: Instant,
}

/// The payload of one [`Frame`].
enum FrameBody {
    /// A cleartext text frame.
    Text(String),
    /// One binary frame, a Noise transport message once the handshake is done.
    Binary(Vec<u8>),
    /// The peer closed the connection.
    Closed,
}

/// The outcome of waiting for a cleartext message.
enum Cleartext {
    /// One JSON text frame.
    Text(String),
    /// The peer closed the connection.
    Closed,
    /// The server is shutting down.
    Shutdown,
}

/// The outcome of waiting for a transport-mode message.
enum Encrypted {
    /// A JSON message body (message id 0).
    Json(String),
    /// A binary message of another id, which this revision does not handle yet.
    Other,
    /// A cleartext text frame after the transport started: a silent failure.
    Cleartext,
    /// A ciphertext that does not authenticate or does not decode: a silent failure.
    Refused,
    /// The peer closed the connection.
    Closed,
    /// The server is shutting down.
    Shutdown,
}

/// An established WebSocket connection to one client.
struct Connection {
    socket: Socket,
    shutdown: watch::Receiver<bool>,
    /// When a WebSocket frame of any kind was last received.
    ///
    /// The keepalive measures silence from here. A pong, a ping, a text frame and a binary frame all
    /// count alike: the question is whether the link still delivers anything, not what it delivers.
    last_received: tokio::time::Instant,
    /// How many WebSocket frames of any kind have been received.
    ///
    /// Whether a ping was answered is decided by this count, not by the timestamps: a pong can come
    /// back within the same clock tick as the ping that asked for it, and two equal instants must
    /// not read as "no frame arrived".
    frames_received: u64,
}

impl Connection {
    /// Reads the next frame, answering pings on the way.
    ///
    /// `Ok(None)` means the server is shutting down; the caller closes the connection and stops.
    async fn read(&mut self) -> Result<Option<Frame>> {
        loop {
            if *self.shutdown.borrow() {
                return Ok(None);
            }
            let message = tokio::select! {
                changed = self.shutdown.changed() => {
                    if changed.is_err() || *self.shutdown.borrow() {
                        return Ok(None);
                    }
                    continue;
                }
                // Reading a message is cancel-safe, so losing the race to the shutdown branch
                // does not drop a frame the peer already sent.
                message = self.socket.next() => message,
            };
            // Every frame is liveness, including the control frames handled below: the keepalive
            // asks whether the link still delivers anything, not whether it delivers audio. A
            // control frame is consumed inside this loop and must not need a wake-up to be counted.
            if matches!(message, Some(Ok(_))) {
                self.last_received = tokio::time::Instant::now();
                self.frames_received = self.frames_received.wrapping_add(1);
            }
            match message {
                Some(Ok(Message::Text(text))) => {
                    return Ok(Some(Frame {
                        body: FrameBody::Text(text.as_str().to_owned()),
                        arrived: Instant::now(),
                    }))
                }
                Some(Ok(Message::Binary(bytes))) => {
                    return Ok(Some(Frame {
                        body: FrameBody::Binary(bytes.to_vec()),
                        arrived: Instant::now(),
                    }))
                }
                Some(Ok(Message::Ping(payload))) => self
                    .socket
                    .send(Message::Pong(payload))
                    .await
                    .context("the WebSocket pong failed")?,
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => continue,
                Some(Ok(Message::Close(_))) | None => {
                    return Ok(Some(Frame {
                        body: FrameBody::Closed,
                        arrived: Instant::now(),
                    }))
                }
                Some(Err(error)) => return Err(error).context("the WebSocket read failed"),
            }
        }
    }

    /// When a WebSocket frame was last received, of any kind.
    fn last_received(&self) -> tokio::time::Instant {
        self.last_received
    }

    /// How many WebSocket frames of any kind have been received.
    fn frames_received(&self) -> u64 {
        self.frames_received
    }

    /// Waits for the next cleartext text frame, skipping binary frames.
    ///
    /// A binary frame before the transport carries nothing, which the client side skips as well.
    async fn read_cleartext(&mut self) -> Result<Cleartext> {
        loop {
            let Some(frame) = self.read().await? else {
                return Ok(Cleartext::Shutdown);
            };
            match frame.body {
                FrameBody::Closed => return Ok(Cleartext::Closed),
                FrameBody::Text(text) => return Ok(Cleartext::Text(text)),
                FrameBody::Binary(_) => continue,
            }
        }
    }

    /// Waits for Noise handshake message 2 and returns its bytes.
    ///
    /// `Ok(None)` means the connection ended or the frame was not a well-formed `noise/handshake`;
    /// both are silent failures the caller answers by closing.
    async fn read_handshake_message(&mut self) -> Result<Option<Vec<u8>>> {
        let text = match self.read_cleartext().await? {
            Cleartext::Text(text) => text,
            Cleartext::Closed | Cleartext::Shutdown => return Ok(None),
        };
        match Incoming::parse(&text) {
            Ok(Some(Incoming::NoiseHandshake(handshake))) => {
                Ok(URL_SAFE_NO_PAD.decode(&handshake.data).ok())
            }
            _ => Ok(None),
        }
    }

    /// Waits for the next transport-mode message, with the instant of its frame.
    async fn read_encrypted(&mut self, noise: &mut TransportState) -> Result<(Encrypted, Instant)> {
        let Some(frame) = self.read().await? else {
            return Ok((Encrypted::Shutdown, Instant::now()));
        };
        let arrived = frame.arrived;
        let ciphertext = match frame.body {
            FrameBody::Closed => return Ok((Encrypted::Closed, arrived)),
            FrameBody::Text(_) => return Ok((Encrypted::Cleartext, arrived)),
            FrameBody::Binary(ciphertext) => ciphertext,
        };
        let plaintext = match noise.decrypt(&ciphertext) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok((Encrypted::Refused, arrived)),
        };
        match decode_frame(&plaintext) {
            Ok(PlaintextFrame::Json(text)) => Ok((Encrypted::Json(text.to_owned()), arrived)),
            Ok(PlaintextFrame::Binary { .. }) => Ok((Encrypted::Other, arrived)),
            Err(_) => Ok((Encrypted::Refused, arrived)),
        }
    }

    /// Waits for `client/hello`, closing the connection on every failure.
    ///
    /// `Ok(None)` means the connection ended before the message arrived; nothing more is sent.
    async fn read_client_hello(
        &mut self,
        noise: &mut TransportState,
    ) -> Result<Option<ClientHello>> {
        loop {
            match self.read_encrypted(noise).await?.0 {
                Encrypted::Json(text) => match Incoming::parse(&text) {
                    Ok(Some(Incoming::ClientHello(hello))) => return Ok(Some(hello)),
                    // Another message, or one this revision does not have, is not `client/hello`;
                    // the specification has the client send it first, and ignoring what arrives
                    // before it keeps a chatty client connected.
                    Ok(_) => continue,
                    Err(_) => {
                        let _ = self.close().await;
                        return Ok(None);
                    }
                },
                Encrypted::Other => continue,
                Encrypted::Cleartext | Encrypted::Refused => {
                    let _ = self.close().await;
                    return Ok(None);
                }
                Encrypted::Closed => return Ok(None),
                Encrypted::Shutdown => {
                    let _ = self.close().await;
                    return Ok(None);
                }
            }
        }
    }

    /// Sends one WebSocket ping with `payload`.
    ///
    /// The payload is a keepalive nonce, never application data: it exists so two pings are
    /// distinguishable on a capture, and the server asks nothing of its contents.
    async fn send_ping(&mut self, payload: &[u8]) -> Result<()> {
        self.socket
            .send(Message::Ping(payload.to_vec().into()))
            .await
            .context("the WebSocket send failed")
    }

    /// Sends one cleartext JSON text frame.
    async fn send_text(&mut self, text: &str) -> Result<()> {
        self.socket
            .send(Message::text(text))
            .await
            .context("the WebSocket send failed")
    }

    /// Sends one transport-mode message under the current keys.
    async fn send_json(&mut self, noise: &mut TransportState, message: &Incoming) -> Result<()> {
        let text = encode(message)?;
        let plaintext = encode_binary(BINARY_MESSAGE_ID_JSON, text.as_bytes());
        self.send_plaintext(noise, plaintext).await
    }

    /// Encrypts one plaintext and sends it as a binary WebSocket message.
    async fn send_plaintext(
        &mut self,
        noise: &mut TransportState,
        plaintext: Vec<u8>,
    ) -> Result<()> {
        let ciphertext = noise.encrypt(&plaintext)?;
        self.socket
            .send(Message::binary(ciphertext))
            .await
            .context("the WebSocket send failed")
    }

    /// Sends a WebSocket close frame.
    async fn close(&mut self) -> Result<()> {
        self.socket
            .send(Message::Close(None))
            .await
            .context("the WebSocket close failed")
    }
}

/// The keepalive ping on the wire.
struct KeepalivePing {
    /// When the ping went out.
    sent: tokio::time::Instant,
    /// How many frames had been received then; a later count means the link answered.
    seen: u64,
}

/// One connection after `client/hello`: roles, group membership, commands and pairing.
///
/// The session owns everything the connection does after the handshake. It is one task, because
/// the transport keys are one state: the group's output, the host's commands and the client's
/// messages cannot be served from two places.
struct Session<'a> {
    connection: &'a mut Connection,
    config: &'a ServerConfig,
    group: &'a Arc<Group>,
    events: &'a mpsc::UnboundedSender<Event>,
    registry: &'a Arc<Registry>,
    /// The client's static public key, which every event carries.
    client_id: String,
    /// The same key as bytes, which a re-handshake needs.
    client_key: [u8; 32],
    /// What the client announced in `client/hello`.
    hello: ClientHello,
    /// Whether a pairing record sealed the connection.
    paired: bool,
    /// Whether the operator approved the client.
    approved: bool,
    /// Whether the store holds a record the connection did not seal with.
    ///
    /// The server retried message 2 under the Sentinel key and it authenticated, so the client does
    /// not hold the record. The session is admitted without roles and the record is left alone.
    credential_mismatch: bool,
    /// Versioned roles the connection may use.
    roles: Vec<String>,
    /// The group membership, once the connection has roles.
    member: Option<u64>,
    /// The group's queue for this connection, once it joined.
    outbound: Option<mpsc::UnboundedReceiver<Outbound>>,
    /// Pairing activations sent since the last handshake, the `pairing_index` a client reports.
    pairing_index: u32,
    /// The attempt in progress.
    attempt: Option<Attempt>,
    /// Whether pairing messages left over from an ended attempt are discarded silently.
    discarding_pairing_messages: bool,
    /// The pairing PSK the connection is currently keyed by, when it is keyed by one.
    connection_psk: Option<[u8; 32]>,
    /// The reply `ServerHandle::pair` is waiting for.
    pending_pair_reply: Option<oneshot::Sender<Result<()>>>,
    /// The host's requests.
    commands: mpsc::UnboundedReceiver<Command>,
    /// Whether the command queue still has a sender.
    ///
    /// A second connection of the same client replaces this one in the registry, which drops the
    /// only sender; the branch is disabled then instead of polling a closed channel.
    commands_open: bool,
    /// Why the connection is ending, once a handler decided it.
    ending: Option<String>,
    /// The keepalive ping on the wire, or `None` when none is outstanding.
    keepalive_ping: Option<KeepalivePing>,
    /// Nonce of the next keepalive ping; its payload is the big-endian 8 bytes of this counter.
    keepalive_nonce: u64,
}

impl Session<'_> {
    /// Runs the connection until it ends and reports the leave.
    async fn run(mut self, noise: &mut TransportState) -> Result<()> {
        // The first activation: roles for a paired or approved client, and nothing for one that
        // still waits for the operator.
        self.activate_roles(noise).await?;

        let reason = loop {
            if let Some(reason) = self.ending.take() {
                let _ = self.connection.close().await;
                break reason;
            }
            // A frame that arrived after the ping answered it, whatever its kind: a pong to this
            // ping, a pong to another one, a clock request or a command all prove the link is
            // alive. This is checked again when the keepalive deadline fires, because a control
            // frame is consumed inside the connection's read and does not wake the loop.
            if self.keepalive_answered() {
                self.keepalive_ping = None;
            }
            let deadline = self.attempt.as_ref().map(Attempt::deadline);
            // The keepalive is a deadline of its own and is never replaced by the pairing attempt:
            // it runs with every role combination, so an idle connection notices a dead link just
            // as a playing one does. Before the ping it is the idle window from the last frame;
            // after the ping it is the shorter window a peer has to prove the link still delivers.
            let keepalive = self.keepalive_deadline();
            // `biased` polls the branches in declaration order and takes the first that is ready.
            // `outgoing` comes first so inbound traffic cannot starve the audio it carries; the
            // read and the keepalive branches are polled in every gap between chunks. Only a host
            // that feeds faster than the socket drains - the unbounded-queue case the group already
            // documents - can hold them off, which is a pre-existing limit of the queue, not of this
            // ordering. `frame` (the read) comes before the keepalive branch so a frame already
            // waiting on the wire is consumed and counted before the pong window is judged: a frame
            // that arrives at the deadline keeps the connection, instead of the deadline branch
            // winning the coin flip and dropping a healthy client.
            tokio::select! {
                biased;
                outgoing = async {
                    match self.outbound.as_mut() {
                        Some(outbound) => outbound.recv().await,
                        None => std::future::pending().await,
                    }
                } => match outgoing {
                    Some(Outbound::Message(message)) => {
                        if self.connection.send_json(noise, &message).await.is_err() {
                            break "connection lost".to_owned();
                        }
                    }
                    Some(Outbound::Audio(chunk)) => {
                        if self.connection.send_plaintext(noise, chunk).await.is_err() {
                            break "connection lost".to_owned();
                        }
                    }
                    // The group is dropped only when the server is, so this is the shutdown path.
                    None => {
                        let _ = self.connection.close().await;
                        break "server shutdown".to_owned();
                    }
                },
                command = self.commands.recv(), if self.commands_open => {
                    let Some(command) = command else {
                        // Another connection of this client took the registry entry; playback
                        // continues, the host just cannot address this one any more.
                        self.commands_open = false;
                        continue;
                    };
                    if self.handle_command(noise, command).await.is_err() {
                        break "connection lost".to_owned();
                    }
                }
                frame = self.connection.read_encrypted(noise) => {
                    let (frame, arrived) = match frame {
                        Ok(frame) => frame,
                        // A link that fails here is a dropped connection, not a message the peer
                        // sent.
                        Err(_) => break "connection lost".to_owned(),
                    };
                    match frame {
                        Encrypted::Json(text) => {
                            if self.handle_text(noise, &text, arrived).await.is_err() {
                                break "connection lost".to_owned();
                            }
                        }
                        Encrypted::Other => continue,
                        Encrypted::Cleartext | Encrypted::Refused => {
                            self.protocol_error();
                        }
                        Encrypted::Closed => break "connection closed".to_owned(),
                        Encrypted::Shutdown => {
                            let _ = self.connection.close().await;
                            break "server shutdown".to_owned();
                        }
                    }
                }
                () = async {
                    match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                        None => std::future::pending().await,
                    }
                } => {
                    if self.handle_attempt_timeout(noise).await.is_err() {
                        break "connection lost".to_owned();
                    }
                }
                () = tokio::time::sleep_until(keepalive) => {
                    if self.handle_keepalive_timeout().await.is_err() {
                        break "connection lost".to_owned();
                    }
                }
            }
        };

        self.leave();
        // A client that said goodbye closes next; every other ending has already been closed
        // above, so this is the one place that makes the connection end with a close frame in
        // every case.
        let _ = self.connection.close().await;
        if let Some(reply) = self.pending_pair_reply.take() {
            let _ = reply.send(Err(anyhow::anyhow!(
                "the connection ended before it paired"
            )));
        }
        let _ = self.events.send(Event::ClientLeft { reason });
        Ok(())
    }

    /// Whether a frame arrived after the keepalive ping went out.
    ///
    /// Any frame counts, not only a pong, and the payload is never inspected: the question is
    /// whether the link still delivers something.
    fn keepalive_answered(&self) -> bool {
        self.keepalive_ping
            .as_ref()
            .is_some_and(|ping| self.connection.frames_received() != ping.seen)
    }

    /// When the keepalive next has work: the ping is due after the idle window, and the pong window
    /// closes when a ping is outstanding.
    fn keepalive_deadline(&self) -> tokio::time::Instant {
        match &self.keepalive_ping {
            Some(ping) if !self.keepalive_answered() => ping.sent + KEEPALIVE_PONG_TIMEOUT,
            _ => self.connection.last_received() + KEEPALIVE_IDLE,
        }
    }

    /// Sends a keepalive ping when the link has been silent, or ends the connection when a ping went
    /// unanswered.
    ///
    /// Any frame received after the ping cancels it before the deadline is judged, so a pong that
    /// raced the deadline - or a clock request that arrived while the ping was on the wire - keeps
    /// the connection. Ending here reports an [`Event::ClientLeft`] that names the keepalive, which
    /// is what the operator sees.
    async fn handle_keepalive_timeout(&mut self) -> Result<()> {
        if self.keepalive_answered() {
            self.keepalive_ping = None;
        }
        if tokio::time::Instant::now() < self.keepalive_deadline() {
            // A frame arrived after this wait's deadline was computed; the loop recomputes it.
            return Ok(());
        }
        if self.keepalive_ping.is_some() {
            self.ending = Some(
                "no frame arrived within the pong window of a keepalive ping, so the connection \
                 is dead"
                    .to_owned(),
            );
            return Ok(());
        }
        let payload = self.keepalive_nonce.to_be_bytes();
        self.keepalive_nonce = self.keepalive_nonce.wrapping_add(1);
        self.connection.send_ping(&payload).await?;
        self.keepalive_ping = Some(KeepalivePing {
            sent: tokio::time::Instant::now(),
            seen: self.connection.frames_received(),
        });
        Ok(())
    }

    /// Sends `server/activate` with the roles this connection may use, and joins the group.
    ///
    /// An unapproved, unpaired client gets an empty role list: `pairing.md` forbids activating
    /// roles on an unpaired connection its operator has not approved. A client that admits no
    /// unpaired access gets none either, because it would have to reject the activation. A
    /// connection whose record did not seal the handshake gets none either, approval or not: it
    /// holds no credential the server trusts, so re-pairing is the way back. A paired client needs
    /// no approval and no unpaired access.
    async fn activate_roles(&mut self, noise: &mut TransportState) -> Result<()> {
        let (roles, withheld) = self.effective_roles();
        self.roles = roles.clone();
        let activate = ServerActivate {
            activities: Vec::new(),
            active_roles: Some(roles.clone()),
            pairing: None,
        };
        self.connection
            .send_json(noise, &Incoming::ServerActivate(activate))
            .await?;
        let _ = self.events.send(Event::ClientActivated {
            client_id: self.client_id.clone(),
            roles: roles.clone(),
        });
        // The host has to know why a client it can reach will never play its stream, and the
        // reason is about the format rather than about the client's connection.
        if let Some(reason) = withheld {
            let _ = self.events.send(Event::PlayerRoleWithheld {
                client_id: self.client_id.clone(),
                reason,
            });
        }
        if !roles.is_empty() {
            self.join_group(roles);
        }
        Ok(())
    }

    /// Returns the roles this connection may use now, and why the player role is missing.
    fn effective_roles(&self) -> (Vec<String>, Option<String>) {
        // A connection whose record did not seal the handshake holds no credential the server
        // trusts, so an approval cannot turn it into a member either: re-pairing is the way back.
        if self.credential_mismatch {
            return (Vec::new(), None);
        }
        if !self.paired && (!self.approved || !self.hello.unpaired_access.enabled) {
            return (Vec::new(), None);
        }
        active_roles(&self.hello, &self.config.format)
    }

    /// Joins the group, so the connection starts receiving state and, while it plays, audio.
    fn join_group(&mut self, roles: Vec<String>) {
        if self.member.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::unbounded_channel();
        self.member = Some(self.group.join(roles, sender));
        self.outbound = Some(receiver);
    }

    /// Removes the connection from the group, if it joined.
    fn leave(&mut self) {
        if let Some(member) = self.member.take() {
            self.group.leave(member);
        }
        self.outbound = None;
    }

    /// Marks the connection as a protocol error, which closes it without a message.
    fn protocol_error(&mut self) {
        self.ending = Some("protocol error".to_owned());
    }

    /// Handles one decrypted JSON message.
    async fn handle_text(
        &mut self,
        noise: &mut TransportState,
        text: &str,
        arrived: Instant,
    ) -> Result<()> {
        let message = match Incoming::parse(text) {
            Ok(Some(message)) => message,
            // A type this revision does not have carries nothing to act on.
            Ok(None) => return Ok(()),
            // A known type whose payload does not decode is a protocol error, and a pairing
            // message's missing field would leave a half-open attempt.
            Err(_) => {
                self.protocol_error();
                return Ok(());
            }
        };
        match message {
            Incoming::ClientGoodbye(goodbye) => self.ending = Some(goodbye.reason),
            // Every request gets its own reply: one timeline is what a client measures its offset
            // against, so the two stamps are the receive time of this frame and the moment before
            // the answer leaves.
            Incoming::ClientTime(time) => {
                let reply = Incoming::ServerTime(ServerTime {
                    client_transmitted: time.client_transmitted,
                    server_received: self.group.server_us(arrived),
                    server_transmitted: self.group.now_us(),
                });
                self.connection.send_json(noise, &reply).await?;
            }
            // A `client/state` is a report: the group records what it says about the member and
            // keeps its own volume, mute and playback.
            Incoming::ClientState(state) => {
                if let Some(member) = self.member {
                    self.group.report_client_state(member, &state);
                }
            }
            // The group owns volume, mute and playback, so a controller command for one of them
            // needs no trip through the host.
            Incoming::ClientCommand(command)
                if self.roles.iter().any(|role| role == CONTROLLER_ROLE) =>
            {
                if let Some(controller_command) = &command.controller {
                    self.group.apply_controller_command(controller_command);
                }
            }
            Incoming::ClientPairPending(pending) => {
                self.on_pair_pending(&pending);
            }
            Incoming::ClientPairInit(init) => self.on_pair_init(noise, &init).await?,
            Incoming::ClientPairAuth(auth) => self.on_pair_auth(noise, &auth).await?,
            Incoming::ClientPairRetry(retry) => self.on_pair_retry(noise, &retry).await?,
            Incoming::ClientPairConfirm(confirm) => self.on_pair_confirm(noise, &confirm).await?,
            Incoming::ClientPairFinalize(finalize) => {
                self.on_pair_finalize(noise, &finalize).await?
            }
            Incoming::PairAbort(abort) => self.on_pair_abort(abort.reason),
            // A message of the cleartext phase has no place under the transport keys. The one a
            // peer reaches by accident is a second `client/init`.
            Incoming::ClientInit(_)
            | Incoming::ServerInit(_)
            | Incoming::ServerError(_)
            | Incoming::NoiseHandshake(_) => self.protocol_error(),
            // A message for a role or direction this server does not serve.
            _ => {}
        }
        Ok(())
    }

    /// Handles one host request.
    async fn handle_command(&mut self, noise: &mut TransportState, command: Command) -> Result<()> {
        match command {
            Command::Approve { reply } => {
                let outcome = self.approve(noise).await;
                let _ = reply.send(outcome);
            }
            Command::PairToken { pairing_psk, reply } => {
                // The refusals a healthy connection survives are decided before anything is
                // written; only a transport failure ends the connection.
                let refused = if self.attempt.is_some() {
                    Some("a pairing attempt is already in progress")
                } else if self.hello.supported_pair_methods.pairing_psk.is_none() {
                    Some("the client did not offer the Pairing PSK method")
                } else {
                    None
                };
                match refused {
                    Some(reason) => {
                        let _ = reply.send(Err(anyhow::anyhow!(reason)));
                    }
                    None => match self.begin_token_flow(noise, pairing_psk).await {
                        Ok(()) => self.pending_pair_reply = Some(reply),
                        Err(error) => {
                            let _ = reply.send(Err(error));
                            self.ending = Some("pairing failed".to_owned());
                        }
                    },
                }
            }
            Command::RevokeApproval { reply } => {
                let outcome = self.revoke_approval(noise).await;
                let _ = reply.send(outcome);
            }
            #[cfg(feature = "pairing-code")]
            Command::StartPairing {
                method,
                format,
                reply,
            } => {
                let outcome = self.begin_code_flow(noise, method, format).await;
                let _ = reply.send(outcome);
            }
            Command::SubmitCode { code, reply } => {
                let outcome = self.submit_code(noise, &code).await;
                let _ = reply.send(outcome);
            }
            Command::Unpair { reply } => {
                let outcome = self.unpair(noise).await;
                let _ = reply.send(outcome);
            }
        }
        Ok(())
    }

    /// Activates the roles the operator's approval admits.
    ///
    /// A connection whose record did not seal the handshake is not approved while the store still
    /// holds that record: its approval is refused with an error naming the mismatch, because the
    /// client holds no credential the server trusts. Once the record is gone from the store, the
    /// flag is cleared and the approval activates the roles - the recovery path for a live session
    /// whose record the host removed.
    async fn approve(&mut self, noise: &mut TransportState) -> Result<()> {
        if self.credential_mismatch {
            if pairing::record_for(self.config.storage.as_deref(), &self.client_id)?.is_some() {
                bail!(
                    "the client's pairing record did not seal this connection (a credential \
                     mismatch), so an approval is refused; re-pair the client, or remove the \
                     record through the store and approve again"
                );
            }
            self.credential_mismatch = false;
            self.approved = true;
            return self.activate_roles(noise).await;
        }
        if self.approved {
            return Ok(());
        }
        self.approved = true;
        self.activate_roles(noise).await
    }

    /// Revokes the operator's approval and deactivates the connection's roles.
    async fn revoke_approval(&mut self, noise: &mut TransportState) -> Result<()> {
        if self.paired {
            bail!("this client is paired; unpair it instead of revoking an approval");
        }
        self.approved = false;
        self.roles.clear();
        self.leave();
        let activate = ServerActivate {
            activities: Vec::new(),
            active_roles: Some(Vec::new()),
            pairing: None,
        };
        self.connection
            .send_json(noise, &Incoming::ServerActivate(activate))
            .await?;
        let _ = self.events.send(Event::ClientActivated {
            client_id: self.client_id.clone(),
            roles: Vec::new(),
        });
        Ok(())
    }

    /// Re-handshakes to the pairing PSK and admits the Pairing PSK flow.
    async fn begin_token_flow(
        &mut self,
        noise: &mut TransportState,
        pairing_psk: [u8; 32],
    ) -> Result<()> {
        // A connection already keyed by this client's pairing PSK needs no swap; any other one
        // does, because the client admits the method only there.
        if self.connection_psk != Some(pairing_psk) {
            self.rehandshake(noise, pairing_psk, CATEGORY_PAIRING)
                .await
                .context("failed to re-handshake to the pairing PSK")?;
            self.connection_psk = Some(pairing_psk);
        }
        // A re-handshake resets the client's counter; without one the previous attempt's
        // activations still count, and the client reports that number back.
        self.pairing_index = self.pairing_index.saturating_add(1);
        self.discarding_pairing_messages = false;
        self.send_pairing_activation(noise, PairingMethod::PairingPsk, None)
            .await?;
        let attempt = Attempt::token(self.pairing_index, self.config.pairing_timeout);
        self.pairing_index = attempt.index();
        self.attempt = Some(attempt);
        Ok(())
    }

    /// Sends the activation that admits one code-flow attempt.
    #[cfg(feature = "pairing-code")]
    async fn begin_code_flow(
        &mut self,
        noise: &mut TransportState,
        method: PairingMethod,
        format: Option<CodeFormat>,
    ) -> Result<()> {
        if !method.needs_code() {
            bail!("the Pairing PSK flow is started by a token, not by a code activation");
        }
        if self.attempt.is_some() {
            bail!("a pairing attempt is already in progress");
        }
        if self.connection_psk.is_some() {
            bail!("the client admits a code flow only on a connection keyed by something else");
        }
        if !self.offers_method(method, format) {
            bail!("the client did not offer this pairing method and format");
        }
        if self.config.storage.is_none() {
            bail!("this server has no pairing store, so it cannot keep the record a code flow produces");
        }
        #[cfg(not(feature = "pairing-code"))]
        {
            let _ = (noise, method, format);
            bail!("this server was built without the `pairing-code` feature")
        }
        #[cfg(feature = "pairing-code")]
        {
            let attempt = Attempt::code(
                method,
                format,
                // Saturating on both sides: the client's counter saturates, so a server that
                // wrapped would report an index the client cannot reach and the two would
                // disagree about which activation is current.
                self.pairing_index.saturating_add(1),
                self.config.pairing_timeout,
            )?;
            self.pairing_index = attempt.index();
            self.discarding_pairing_messages = false;
            self.send_pairing_activation(noise, method, format).await?;
            self.attempt = Some(attempt);
            // The static code is printed on the device, so the operator can type it as soon as
            // the activation is out. The dynamic code needs the server's nonce first, which the
            // client's `client/pair-init` triggers.
            if method == PairingMethod::StaticCode {
                self.request_code(method, format);
            }
            Ok(())
        }
    }
    /// Whether the client's `client/hello` offers `method` and, for a dynamic attempt, `format`.
    #[cfg(feature = "pairing-code")]
    fn offers_method(&self, method: PairingMethod, format: Option<CodeFormat>) -> bool {
        let methods = &self.hello.supported_pair_methods;
        match method {
            PairingMethod::PairingPsk => methods.pairing_psk.is_some(),
            PairingMethod::StaticCode => methods.static_pairing_code.is_some(),
            PairingMethod::DynamicCode => {
                let Some(descriptor) = &methods.dynamic_pairing_code else {
                    return false;
                };
                let Some(format) = format else {
                    return false;
                };
                !descriptor.out_channels.is_empty()
                    && descriptor
                        .formats
                        .iter()
                        .any(|offered| offered == format.wire_name())
            }
        }
    }

    /// Sends a pairing activation, which admits one attempt.
    async fn send_pairing_activation(
        &mut self,
        noise: &mut TransportState,
        method: PairingMethod,
        format: Option<CodeFormat>,
    ) -> Result<()> {
        let activate = ServerActivate {
            activities: vec![PAIRING_ACTIVITY.to_owned()],
            // The roles the connection already has stay in force.
            active_roles: None,
            pairing: Some(PairingActivation {
                method: method.wire_name().to_owned(),
                format: format.map(CodeFormat::wire_name).map(str::to_owned),
            }),
        };
        self.connection
            .send_json(noise, &Incoming::ServerActivate(activate))
            .await
    }

    /// Tells the host that the operator has to enter a code.
    fn request_code(&mut self, method: PairingMethod, _format: Option<CodeFormat>) {
        let _ = self.events.send(Event::PairingRequested {
            client_id: self.client_id.clone(),
            method,
            // The client owns the code; the server learns it only through `submit_code`.
            code: None,
        });
    }

    /// Handles `client/pair-pending`: an attempt the client is holding back.
    fn on_pair_pending(&mut self, pending: &ClientPairPending) {
        if self.attempt.is_none() {
            if !self.discarding_pairing_messages {
                self.protocol_error();
            }
            return;
        }
        self.check_pairing_index(pending.pairing_index);
        // The message carries the operator's next step; there is nothing to answer.
    }

    /// Rejects an index that belongs to a superseded or an impossible activation.
    fn check_pairing_index(&mut self, index: u32) {
        if index > self.pairing_index {
            self.protocol_error();
        }
        // A lower index is a leftover of a superseded pairing and is discarded silently.
    }

    /// Handles `client/pair-init`: starts the attempt's CPace side.
    async fn on_pair_init(
        &mut self,
        noise: &mut TransportState,
        init: &ClientPairInit,
    ) -> Result<()> {
        let Some(attempt) = self.attempt.as_mut() else {
            if !self.discarding_pairing_messages {
                self.protocol_error();
            }
            return Ok(());
        };
        if init.pairing_index < self.pairing_index {
            // A leftover from a superseded activation.
            return Ok(());
        }
        if init.pairing_index > self.pairing_index {
            self.protocol_error();
            return Ok(());
        }
        let handshake_hash = *noise.handshake_hash();
        let outcome = attempt.on_pair_init(init, &handshake_hash);
        let method = attempt.method();
        let format = attempt.format();
        match outcome {
            Ok(step) => self.send_step(noise, step, method, format).await,
            Err(_) => {
                self.protocol_error();
                Ok(())
            }
        }
    }

    /// Sends what a pairing step produced, and asks for a code when the client now emits one.
    async fn send_step(
        &mut self,
        noise: &mut TransportState,
        step: pairing::Step,
        method: PairingMethod,
        format: Option<CodeFormat>,
    ) -> Result<()> {
        for message in step.messages {
            self.connection.send_json(noise, &message).await?;
        }
        if step.announce_code {
            self.request_code(method, format);
        }
        Ok(())
    }

    /// Handles `client/pair-auth`: completes the CPace round on the server side.
    async fn on_pair_auth(
        &mut self,
        noise: &mut TransportState,
        auth: &ClientPairAuth,
    ) -> Result<()> {
        #[cfg(not(feature = "pairing-code"))]
        {
            let _ = (noise, auth);
            self.protocol_error();
            return Ok(());
        }
        #[cfg(feature = "pairing-code")]
        {
            let Some(attempt) = self.attempt.as_mut() else {
                if !self.discarding_pairing_messages {
                    self.protocol_error();
                }
                return Ok(());
            };
            match attempt.on_client_auth(auth) {
                Ok(step) => {
                    let method = attempt.method();
                    let format = attempt.format();
                    self.send_step(noise, step, method, format).await
                }
                Err(_) => {
                    self.protocol_error();
                    Ok(())
                }
            }
        }
    }

    /// Handles `client/pair-retry`: begins the next round of the dynamic flow.
    async fn on_pair_retry(
        &mut self,
        noise: &mut TransportState,
        _retry: &ClientPairRetry,
    ) -> Result<()> {
        #[cfg(not(feature = "pairing-code"))]
        {
            let _ = noise;
            self.protocol_error();
            return Ok(());
        }
        #[cfg(feature = "pairing-code")]
        {
            let Some(attempt) = self.attempt.as_mut() else {
                if !self.discarding_pairing_messages {
                    self.protocol_error();
                }
                return Ok(());
            };
            match attempt.on_client_retry() {
                Ok(pairing::RetryOutcome::NextRound(step)) => {
                    let method = attempt.method();
                    let format = attempt.format();
                    self.send_step(noise, step, method, format).await
                }
                Ok(pairing::RetryOutcome::Exhausted) => {
                    self.end_attempt(noise, Attempt::code_mismatch_reason())
                        .await
                }
                Err(_) => {
                    self.protocol_error();
                    Ok(())
                }
            }
        }
    }

    /// Handles `client/pair-confirm`: verifies the tag and, in the dynamic flow, the binding.
    async fn on_pair_confirm(
        &mut self,
        noise: &mut TransportState,
        confirm: &ClientPairConfirm,
    ) -> Result<()> {
        #[cfg(not(feature = "pairing-code"))]
        {
            let _ = (noise, confirm);
            self.protocol_error();
            return Ok(());
        }
        #[cfg(feature = "pairing-code")]
        {
            let Some(attempt) = self.attempt.as_mut() else {
                if !self.discarding_pairing_messages {
                    self.protocol_error();
                }
                return Ok(());
            };
            let handshake_hash = *noise.handshake_hash();
            let suite = noise.suite();
            match attempt.on_client_confirm(confirm, &handshake_hash, suite) {
                Ok(pairing::ConfirmOutcome::Confirmed) => Ok(()),
                // The tag did not verify: the spec answers with `pair/abort` and keeps the
                // connection.
                Ok(pairing::ConfirmOutcome::Mismatch) => {
                    self.end_attempt(noise, Attempt::code_mismatch_reason())
                        .await
                }
                // A failure of the binding checks is a protocol error: the connection closes and
                // no record is written.
                Err(_) => {
                    self.protocol_error();
                    Ok(())
                }
            }
        }
    }

    /// Handles `client/pair-finalize`: opens the PSK, stores the record and promotes the link.
    async fn on_pair_finalize(
        &mut self,
        noise: &mut TransportState,
        finalize: &ClientPairFinalize,
    ) -> Result<()> {
        let Some(attempt) = self.attempt.as_mut() else {
            if !self.discarding_pairing_messages {
                self.protocol_error();
            }
            return Ok(());
        };
        let suite = noise.suite();
        let key = match attempt.on_finalize(finalize, suite, self.connection_psk) {
            Ok(key) => key,
            Err(_) => {
                self.protocol_error();
                return Ok(());
            }
        };
        if let Err(error) =
            pairing::store_record(self.config.storage.as_deref(), &self.client_id, key)
        {
            return self.fail_attempt(error).await;
        }
        self.connection
            .send_json(noise, &Attempt::finalized())
            .await?;
        self.complete_pairing(noise, key).await
    }

    /// Handles `pair/abort` from the client: ends the attempt and keeps the connection.
    fn on_pair_abort(&mut self, reason: String) {
        if self.attempt.take().is_some() {
            self.discarding_pairing_messages = true;
            let _ = self.events.send(Event::PairingFailed {
                client_id: self.client_id.clone(),
                reason,
            });
            if let Some(reply) = self.pending_pair_reply.take() {
                let _ = reply.send(Err(anyhow::anyhow!("the client aborted the pairing")));
            }
        }
    }

    /// Enters the operator's code and, when the client is ready, starts the CPace round.
    async fn submit_code(&mut self, noise: &mut TransportState, code: &str) -> Result<()> {
        #[cfg(not(feature = "pairing-code"))]
        {
            let _ = (noise, code);
            bail!("this server was built without the `pairing-code` feature");
        }
        #[cfg(feature = "pairing-code")]
        {
            let Some(attempt) = self.attempt.as_mut() else {
                bail!("this connection has no pairing attempt");
            };
            let handshake_hash = *noise.handshake_hash();
            let method = attempt.method();
            let format = attempt.format();
            match attempt.on_entered_code(code, &handshake_hash) {
                Ok(step) => self.send_step(noise, step, method, format).await,
                Err(error) => Err(error),
            }
        }
    }

    /// Persists the record and promotes the live connection to its long-term PSK.
    ///
    /// `server/pair-finalize` is already on the wire, so the client has stored its side. The
    /// re-handshake follows immediately and its activation is the first message under the new
    /// keys, as `connection.md` requires. The record is stored by now, so `approved`, the dropped
    /// approval and [`Event::Paired`] are true before it; `paired` and the cleared mismatch are
    /// not, until the new key has actually sealed the connection.
    async fn complete_pairing(&mut self, noise: &mut TransportState, psk: [u8; 32]) -> Result<()> {
        self.attempt = None;
        self.discarding_pairing_messages = true;
        self.approved = true;
        // `pairing.md` discards an approval when a pairing succeeds: the record replaces it.
        self.registry.forget_approval(&self.client_id);
        // The record sealed the connection; the pairing PSK no longer does.
        self.connection_psk = None;
        let _ = self.events.send(Event::Paired {
            client_id: self.client_id.clone(),
        });

        if let Err(error) = self.rehandshake(noise, psk, CATEGORY_LONG_TERM).await {
            let _ = error;
            if let Some(reply) = self.pending_pair_reply.take() {
                let _ = reply.send(Err(anyhow::anyhow!(
                    "the pairing record was stored, but the connection could not be moved to it"
                )));
            }
            self.ending = Some("connection lost".to_owned());
            return Ok(());
        }
        // The new key sealed the connection, so the record now authenticates it and the
        // credential mismatch it recovered from is over.
        self.paired = true;
        self.credential_mismatch = false;
        self.pairing_index = 0;
        self.activate_roles(noise).await?;
        if let Some(reply) = self.pending_pair_reply.take() {
            let _ = reply.send(Ok(()));
        }
        Ok(())
    }

    /// Ends an attempt that answers with `pair/abort`, keeping the connection.
    #[cfg(feature = "pairing-code")]
    async fn end_attempt(&mut self, noise: &mut TransportState, reason: &str) -> Result<()> {
        self.attempt = None;
        self.discarding_pairing_messages = true;
        self.connection
            .send_json(noise, &Attempt::abort(reason))
            .await?;
        let _ = self.events.send(Event::PairingFailed {
            client_id: self.client_id.clone(),
            reason: reason.to_owned(),
        });
        if let Some(reply) = self.pending_pair_reply.take() {
            let _ = reply.send(Err(anyhow::anyhow!("the pairing attempt failed: {reason}")));
        }
        Ok(())
    }

    /// Ends an attempt that cannot continue: no message the peer could act on, then a close.
    async fn fail_attempt(&mut self, error: anyhow::Error) -> Result<()> {
        self.attempt = None;
        self.discarding_pairing_messages = true;
        let message = format!("{error:#}");
        let _ = self.events.send(Event::PairingFailed {
            client_id: self.client_id.clone(),
            reason: message.clone(),
        });
        if let Some(reply) = self.pending_pair_reply.take() {
            let _ = reply.send(Err(anyhow::anyhow!("the pairing failed: {message}")));
        }
        self.protocol_error();
        Ok(())
    }

    /// Cancels an attempt that ran past its deadline, as `pairing.md` requires.
    ///
    /// The cancellation is a `server/activate` without the pairing activity: the attempt is gone,
    /// the connection and its roles stay.
    async fn handle_attempt_timeout(&mut self, noise: &mut TransportState) -> Result<()> {
        if self.attempt.take().is_none() {
            return Ok(());
        }
        self.discarding_pairing_messages = true;
        let _ = self.events.send(Event::PairingFailed {
            client_id: self.client_id.clone(),
            reason: "the pairing attempt timed out".to_owned(),
        });
        if let Some(reply) = self.pending_pair_reply.take() {
            let _ = reply.send(Err(anyhow::anyhow!("the pairing attempt timed out")));
        }
        let activate = ServerActivate {
            activities: Vec::new(),
            active_roles: None,
            pairing: None,
        };
        self.connection
            .send_json(noise, &Incoming::ServerActivate(activate))
            .await
    }

    /// Removes the record, tells the client and ends the connection.
    ///
    /// A connection whose record did not seal the handshake may not remove that record: the
    /// mismatch is a signal, and a session that never authenticated with the record must not
    /// destroy it. The removal is refused with an error naming the mismatch. Once the record is
    /// gone from the store, there is nothing left to remove and the unpair only ends the
    /// connection.
    async fn unpair(&mut self, noise: &mut TransportState) -> Result<()> {
        if self.credential_mismatch {
            if pairing::record_for(self.config.storage.as_deref(), &self.client_id)?.is_some() {
                bail!(
                    "the client's pairing record did not seal this connection (a credential \
                     mismatch), so the record is left alone; re-pair the client, or remove the \
                     record through the store and unpair again"
                );
            }
            self.credential_mismatch = false;
        } else {
            pairing::remove_record(self.config.storage.as_deref(), &self.client_id)?;
        }
        self.connection
            .send_json(noise, &Incoming::ServerUnpair(Default::default()))
            .await?;
        // The client answers with `client/goodbye` reason `unpaired` if it had a record; the
        // server does not wait for it, because the message is valid under any activity set.
        self.ending = Some("unpaired".to_owned());
        Ok(())
    }

    /// Runs the in-band Noise re-handshake to `psk` and keeps the connection open.
    ///
    /// Both handshake messages travel under the keys being replaced, the prologue is the previous
    /// handshake hash, and `client/init`/`server/init` are not repeated. The next application
    /// message has to be a `server/activate`, which the caller sends.
    async fn rehandshake(
        &mut self,
        noise: &mut TransportState,
        psk: [u8; 32],
        category: &str,
    ) -> Result<()> {
        let prologue = *noise.handshake_hash();
        let suite = noise.suite();
        let mut initiator =
            Initiator::new(&self.config.identity, &self.client_key, suite, &prologue)?;
        initiator.set_psk(&psk)?;
        let metadata = serde_json::json!({
            "psk_id": psk_id_for(&psk),
            "psk_category": category,
        });
        let message_1 = initiator
            .write_message(metadata.to_string().as_bytes())
            .context("failed to write re-handshake message 1")?;
        let message_1 = Incoming::NoiseHandshake(NoiseHandshake {
            data: URL_SAFE_NO_PAD.encode(&message_1),
        });
        self.connection.send_json(noise, &message_1).await?;

        // The peer may still have valid old-key application messages in flight before message 2;
        // dropping them is allowed and is what a key swap leaves possible.
        let message_2 = loop {
            match self.connection.read_encrypted(noise).await? {
                (Encrypted::Json(text), _) => match Incoming::parse(&text) {
                    Ok(Some(Incoming::NoiseHandshake(handshake))) => {
                        break URL_SAFE_NO_PAD
                            .decode(&handshake.data)
                            .context("re-handshake message 2 is not base64url")?
                    }
                    _ => continue,
                },
                (Encrypted::Other, _) => continue,
                (Encrypted::Closed, _) | (Encrypted::Shutdown, _) => {
                    bail!("the connection ended during a re-handshake")
                }
                (Encrypted::Cleartext | Encrypted::Refused, _) => {
                    bail!("the peer sent a message that does not decrypt during a re-handshake")
                }
            }
        };
        let payload = initiator
            .read_message(&message_2)
            .context("re-handshake message 2 does not authenticate")?;
        if payload != HANDSHAKE_MESSAGE_2 {
            bail!("re-handshake message 2 does not carry the empty object");
        }
        *noise = initiator
            .into_transport()
            .context("failed to finish the re-handshake")?;
        // The client counts pairing activations since its last handshake, and this is a new one.
        self.pairing_index = 0;
        Ok(())
    }
}

/// Why a `client/init` was refused, as the `reason` of `server/error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitFailure {
    /// The client speaks another core message format.
    UnsupportedVersion,
    /// The client announced a cipher suite this build does not have.
    UnsupportedSuite,
    /// The message is not a `client/init` of the defined shape.
    Malformed,
}

impl InitFailure {
    /// Returns the wire value `server/error` carries.
    fn reason(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnsupportedSuite => "unsupported_suite",
            Self::Malformed => "malformed",
        }
    }
}

/// An accepted `client/init`.
struct Accepted {
    /// Static public key of the client, as the wire spelled it.
    client_id: String,
    /// The same key as 32 bytes, which the handshake needs.
    key: [u8; 32],
    /// The exact bytes of the message, the first half of the Noise prologue.
    bytes: Vec<u8>,
}

/// Classifies one `client/init` text, or names why it is refused.
///
/// `version` comes first: a message whose version is an integer other than this one is
/// `unsupported_version` whatever else it carries, because a later revision may define the rest
/// differently. `suite` follows, and only then the remaining fields.
fn accept_init(text: &str) -> Result<Accepted, InitFailure> {
    let document: serde_json::Value =
        serde_json::from_str(text).map_err(|_| InitFailure::Malformed)?;
    if document.get("type").and_then(serde_json::Value::as_str) != Some("client/init") {
        return Err(InitFailure::Malformed);
    }
    let payload = document
        .get("payload")
        .and_then(serde_json::Value::as_object)
        .ok_or(InitFailure::Malformed)?;
    let version = payload
        .get("version")
        .and_then(serde_json::Value::as_i64)
        .ok_or(InitFailure::Malformed)?;
    if version != i64::from(PROTOCOL_VERSION) {
        return Err(InitFailure::UnsupportedVersion);
    }
    let suite = payload
        .get("suite")
        .and_then(serde_json::Value::as_str)
        .ok_or(InitFailure::Malformed)?;
    if Suite::from_wire_name(suite).is_none() {
        return Err(InitFailure::UnsupportedSuite);
    }
    match Incoming::parse(text) {
        Ok(Some(Incoming::ClientInit(message))) => {
            let key = client_key(&message.client_id).ok_or(InitFailure::Malformed)?;
            Ok(Accepted {
                client_id: message.client_id,
                key,
                bytes: text.as_bytes().to_vec(),
            })
        }
        _ => Err(InitFailure::Malformed),
    }
}

/// Decodes a canonical 32-byte unpadded base64url key.
///
/// `client_id` is the client's static public key, so it must be exactly that encoding: a truncated,
/// padded or non-canonical string names no key and is a shape failure.
fn client_key(client_id: &str) -> Option<[u8; 32]> {
    if client_id.len() != KEY_CHARS {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(client_id).ok()?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != client_id {
        return None;
    }
    bytes.try_into().ok()
}

/// The roles a connection may use, drawn from what the client offers and what the server streams.
///
/// `player@v1` is activated only when the client's support object lists the configured format. A
/// client that offers the role without it is activated without the role, so the server never sends
/// it a stream it cannot decode, and the `Some` reason tells the host why.
///
/// The caller decides whether roles may be active at all; this function only reads the offers.
fn active_roles(hello: &ClientHello, format: &AudioFormat) -> (Vec<String>, Option<String>) {
    let offers = |role: &str| hello.supported_roles.iter().any(|offered| offered == role);
    let mut roles = Vec::new();
    let mut withheld = None;
    if offers(PLAYER_ROLE) {
        match &hello.player_support {
            None => {
                withheld = Some(
                    "the client offered `player@v1` without its support object, so the server \
                     cannot tell which formats it plays"
                        .to_owned(),
                );
            }
            Some(support) if !format.supported_by(support) => {
                withheld = Some(format!(
                    "the client's `player@v1_support` does not list the configured stream format \
                     ({format})"
                ));
            }
            Some(_) => roles.push(PLAYER_ROLE.to_owned()),
        }
    }
    for role in [CONTROLLER_ROLE, METADATA_ROLE] {
        if offers(role) {
            roles.push(role.to_owned());
        }
    }
    (roles, withheld)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncspin_core::messages::{ClientHello, SupportedPairMethods, UnpairedAccess};
    use syncspin_core::noise::Identity;

    fn init_text(version: u32, suite: &str, client_id: &str) -> String {
        format!(
            r#"{{"type":"client/init","payload":{{"client_id":"{client_id}","version":{version},"suite":"{suite}"}}}}"#
        )
    }

    fn hello(roles: &[&str], player_support: bool, unpaired_access: bool) -> ClientHello {
        ClientHello {
            name: "a client".to_owned(),
            device_info: None,
            supported_roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            player_support: player_support.then(|| syncspin_core::messages::PlayerSupport {
                supported_formats: vec![syncspin_core::messages::SupportedFormat {
                    codec: "pcm".to_owned(),
                    sample_rate: 48_000,
                    channels: 2,
                    bit_depth: 16,
                }],
                buffer_capacity: 1,
            }),
            supported_pair_methods: SupportedPairMethods::default(),
            unpaired_access: UnpairedAccess {
                enabled: unpaired_access,
            },
        }
    }

    /// The format the tests configure, which [`hello`] lists when it offers player support.
    fn format() -> AudioFormat {
        AudioFormat::pcm(48_000, 2, 16)
    }

    #[test]
    fn a_well_formed_init_is_accepted_with_its_exact_bytes() {
        let identity = Identity::generate();
        let text = init_text(
            PROTOCOL_VERSION,
            Suite::ChaChaPoly.wire_name(),
            &identity.public_base64(),
        );
        let accepted = accept_init(&text).expect("a conformant client/init is accepted");
        assert_eq!(accepted.client_id, identity.public_base64());
        assert_eq!(accepted.key, identity.public);
        assert_eq!(
            accepted.bytes,
            text.as_bytes(),
            "the prologue needs the bytes as sent, not a re-encoding"
        );
    }

    #[test]
    fn an_init_failure_carries_the_reason_the_specification_names() {
        let identity = Identity::generate();
        let client_id = identity.public_base64();
        let suite = Suite::ChaChaPoly.wire_name();

        let cases = [
            (
                init_text(2, suite, &client_id),
                InitFailure::UnsupportedVersion,
                "unsupported_version",
            ),
            (
                init_text(PROTOCOL_VERSION, "25519_Unobtainium_SHA256", &client_id),
                InitFailure::UnsupportedSuite,
                "unsupported_suite",
            ),
            (
                r#"{"type":"client/init","payload":"not an object"}"#.to_owned(),
                InitFailure::Malformed,
                "malformed",
            ),
            (
                "not json at all".to_owned(),
                InitFailure::Malformed,
                "malformed",
            ),
            (
                r#"{"type":"server/init","payload":{}}"#.to_owned(),
                InitFailure::Malformed,
                "malformed",
            ),
            (
                init_text(PROTOCOL_VERSION, suite, "short"),
                InitFailure::Malformed,
                "malformed",
            ),
        ];
        for (text, failure, reason) in cases {
            assert_eq!(accept_init(&text).err(), Some(failure), "for {text}");
            assert_eq!(failure.reason(), reason);
        }
    }

    #[test]
    fn the_version_is_checked_before_the_suite() {
        let identity = Identity::generate();
        let text = init_text(2, "25519_Unobtainium_SHA256", &identity.public_base64());
        assert_eq!(
            accept_init(&text).err(),
            Some(InitFailure::UnsupportedVersion),
            "a later revision's message is reported by its version, not by its suite"
        );
    }

    #[test]
    fn the_roles_come_from_what_the_client_offers() {
        let all = ["player@v1", "controller@v1", "metadata@v1"];
        assert_eq!(
            active_roles(&hello(&all, true, true), &format()),
            (all.map(str::to_owned).to_vec(), None)
        );
        assert_eq!(
            active_roles(&hello(&all, false, true), &format()),
            (
                vec!["controller@v1".to_owned(), "metadata@v1".to_owned()],
                Some(
                    "the client offered `player@v1` without its support object, so the server \
                     cannot tell which formats it plays"
                        .to_owned()
                )
            ),
            "player@v1 without its support object must not be activated"
        );
        assert_eq!(
            active_roles(&hello(&["artwork@v1", "player@v1"], true, true), &format()),
            (vec!["player@v1".to_owned()], None),
            "a role this server does not serve is not activated"
        );
        assert!(
            !hello(&all, true, false).unpaired_access.enabled,
            "the unpaired-access gate is the session's, not this function's"
        );
    }

    #[test]
    fn a_client_without_the_configured_format_gets_no_player_role() {
        let mut hello = hello(&["player@v1", "controller@v1"], true, true);
        hello.player_support = Some(syncspin_core::messages::PlayerSupport {
            supported_formats: vec![syncspin_core::messages::SupportedFormat {
                codec: "opus".to_owned(),
                sample_rate: 48_000,
                channels: 2,
                bit_depth: 16,
            }],
            buffer_capacity: 1,
        });
        let (roles, withheld) = active_roles(&hello, &format());
        assert_eq!(roles, vec!["controller@v1".to_owned()]);
        let reason = withheld.expect("the host is told why the player role is missing");
        assert!(
            reason.contains("pcm, 48000 Hz, 2 channel(s), 16 bit"),
            "the reason names the format the server would have sent: {reason}"
        );
    }
}
