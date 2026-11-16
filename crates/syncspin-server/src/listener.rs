//! Accepting clients: the WebSocket upgrade, the init exchange, the Noise handshake and the
//! hello/activate sequence.
//!
//! One task per connection, each with its own handshake state, so a client that stalls or fails
//! never holds up the listener or another client. The sequence is the specification's: the client
//! sends `client/init`, the server answers `server/init` and Noise message 1 without waiting in
//! between, the client answers with Noise message 2, and the server then sends `server/hello`,
//! waits for `client/hello` and sends `server/activate`.
//!
//! A failure decided from `client/init` alone is answered with `server/error` and a close; every
//! later failure is silent, which is why the handshake paths here close without a message.

use std::sync::Arc;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use syncspin_core::framing::{
    decode_frame, encode_binary, Frame as PlaintextFrame, BINARY_MESSAGE_ID_JSON,
};
use syncspin_core::messages::{
    ClientHello, Incoming, NoiseHandshake, ServerActivate, ServerError, ServerHello, ServerInit,
    PROTOCOL_VERSION,
};
use syncspin_core::noise::{Initiator, Suite, TransportState, SENTINEL_PSK_ID};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};

use crate::group::{Group, Outbound, CONTROLLER_ROLE, METADATA_ROLE, PLAYER_ROLE};
use crate::stream::AudioFormat;
use crate::{Event, ServerConfig};

/// The category the server announces when it mixes in the published Sentinel key.
///
/// Pairing, and with it a long-term or pairing PSK, arrives with the pairing milestone; until then
/// every connection is unpaired and the Sentinel key is the only one there is.
const PSK_CATEGORY: &str = "sn";

/// Payload of Noise handshake message 2: the literal empty JSON object, not zero bytes.
const HANDSHAKE_MESSAGE_2: &[u8] = b"{}";

/// Unpadded base64url length of a 32-byte key.
const KEY_CHARS: usize = 43;

/// Accepts connections until the listener is told to stop.
pub(crate) async fn run(
    listener: TcpListener,
    config: ServerConfig,
    group: Arc<Group>,
    events: mpsc::UnboundedSender<Event>,
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
                let shutdown = shutdown.clone();
                connections.spawn(serve(stream, config, group, events, shutdown));
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
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let Some(socket) = upgrade(stream, &config.path).await? else {
        return Ok(());
    };
    let mut connection = Connection { socket, shutdown };
    converse(&mut connection, &config, &group, &events).await
}

/// Upgrades `stream` to a WebSocket if it asks for the endpoint the server serves.
///
/// `accept_hdr_async` is `accept_async` with a look at the request, which is the only way the
/// configured path can be honoured: a request for another path is answered with a 404 instead of
/// being served.
// Error responses are the handshake crate's large `http::Response` type; a rejection happens once
// per refused upgrade, so boxing it would buy nothing.
#[allow(clippy::result_large_err)]
async fn upgrade(stream: TcpStream, path: &str) -> Result<Option<WebSocketStream<TcpStream>>> {
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
    match accept_hdr_async(stream, callback).await {
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
    let mut initiator =
        Initiator::with_announced_suite(&config.identity, &accepted.key, &prologue)?;

    let metadata = serde_json::json!({ "psk_id": SENTINEL_PSK_ID, "psk_category": PSK_CATEGORY });
    let message_1 = initiator
        .write_message(metadata.to_string().as_bytes())
        .context("failed to write Noise handshake message 1")?;
    let message_1 = Incoming::NoiseHandshake(NoiseHandshake {
        data: URL_SAFE_NO_PAD.encode(&message_1),
    });
    connection.send_text(&encode(&message_1)?).await?;

    // 3. Noise message 2. Every failure from here on is silent.
    let Some(message_2) = connection.read_handshake_message().await? else {
        return Ok(());
    };
    let payload = match initiator.read_message(&message_2) {
        Ok(payload) => payload,
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

    // 4. `server/hello`, the first message under the new keys, followed by `client/hello`.
    let hello = Incoming::ServerHello(ServerHello {
        name: config.name.clone(),
        languages: None,
    });
    connection.send_json(&mut noise, &hello).await?;
    let Some(client_hello) = connection.read_client_hello(&mut noise).await? else {
        return Ok(());
    };
    let client_id = accepted.client_id.clone();
    let _ = events.send(Event::ClientConnected {
        client_id: client_id.clone(),
        name: client_hello.name.clone(),
    });

    // 5. `server/activate`, which declares the roles this connection may use.
    //
    // `activities` stays empty until there is a group to report: `playback` says the client's group
    // is playing, and a paused group reports `stopped` without it. The roles are active all the
    // same, which the specification allows on a playback-capable connection.
    let (roles, withheld) = active_roles(&client_hello, &config.format);
    let activate = ServerActivate {
        activities: Vec::new(),
        active_roles: Some(roles.clone()),
        pairing: None,
    };
    connection
        .send_json(&mut noise, &Incoming::ServerActivate(activate))
        .await?;
    let _ = events.send(Event::ClientActivated {
        roles: roles.clone(),
    });
    // The host has to know why a client it can reach will never play its stream, and the reason is
    // about the format rather than about the client's connection.
    if let Some(reason) = withheld {
        let _ = events.send(Event::PlayerRoleWithheld {
            client_id: client_id.clone(),
            reason,
        });
    }

    // 6. The connection joins the group, which hands it the current `server/state`,
    // `group/update` and, for a player, the format of a stream that is already running.
    let controller = roles.iter().any(|role| role == CONTROLLER_ROLE);
    let (sender, mut outbound) = mpsc::unbounded_channel();
    let member = group.join(roles, sender);

    // 7. The connection runs until it ends: messages from the socket and the group's state and
    // audio travel in one task, because the transport keys are one state and cannot be split.
    let reason = loop {
        tokio::select! {
            outgoing = outbound.recv() => match outgoing {
                Some(Outbound::Message(message)) => {
                    if connection.send_json(&mut noise, &message).await.is_err() {
                        break "connection lost".to_owned();
                    }
                }
                Some(Outbound::Audio(chunk)) => {
                    if connection.send_plaintext(&mut noise, chunk).await.is_err() {
                        break "connection lost".to_owned();
                    }
                }
                // The group is dropped only when the server is, so this is the shutdown path.
                None => {
                    let _ = connection.close().await;
                    break "server shutdown".to_owned();
                }
            },
            frame = connection.read_encrypted(&mut noise) => {
                let frame = match frame {
                    Ok(frame) => frame,
                    // A link that fails here is a dropped connection, not a message the peer sent.
                    Err(_) => break "connection lost".to_owned(),
                };
                match frame {
                    Encrypted::Json(text) => match Incoming::parse(&text) {
                        Ok(Some(Incoming::ClientGoodbye(goodbye))) => break goodbye.reason,
                        // The group owns volume, mute and playback, so a controller command for one
                        // of them needs no trip through the host.
                        Ok(Some(Incoming::ClientCommand(command))) => {
                            if controller {
                                if let Some(controller_command) = &command.controller {
                                    group.apply_controller_command(controller_command);
                                }
                            }
                            continue;
                        }
                        // A message of the cleartext phase has no place under the transport keys. The
                        // one a peer reaches by accident is a second `client/init`.
                        Ok(Some(Incoming::ClientInit(_)))
                        | Ok(Some(Incoming::ServerInit(_)))
                        | Ok(Some(Incoming::ServerError(_)))
                        | Ok(Some(Incoming::NoiseHandshake(_))) => {
                            let _ = connection.close().await;
                            break "protocol error".to_owned();
                        }
                        Ok(_) => continue,
                        Err(_) => {
                            let _ = connection.close().await;
                            break "protocol error".to_owned();
                        }
                    },
                    Encrypted::Other => continue,
                    Encrypted::Cleartext | Encrypted::Refused => {
                        let _ = connection.close().await;
                        break "protocol error".to_owned();
                    }
                    Encrypted::Closed => break "connection closed".to_owned(),
                    Encrypted::Shutdown => {
                        let _ = connection.close().await;
                        break "server shutdown".to_owned();
                    }
                }
            }
        }
    };
    group.leave(member);
    // A client that said goodbye closes next; every other ending has already been closed above, so
    // this is the one place that makes the connection end with a close frame in every case.
    let _ = connection.close().await;
    let _ = events.send(Event::ClientLeft { reason });
    Ok(())
}

/// Encodes one control message as the JSON text of its envelope.
fn encode(message: &Incoming) -> Result<String> {
    serde_json::to_string(message).context("failed to encode a control message")
}

/// One frame read from the socket.
enum Frame {
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
    socket: WebSocketStream<TcpStream>,
    shutdown: watch::Receiver<bool>,
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
            match message {
                Some(Ok(Message::Text(text))) => {
                    return Ok(Some(Frame::Text(text.as_str().to_owned())))
                }
                Some(Ok(Message::Binary(bytes))) => return Ok(Some(Frame::Binary(bytes.to_vec()))),
                Some(Ok(Message::Ping(payload))) => self
                    .socket
                    .send(Message::Pong(payload))
                    .await
                    .context("the WebSocket pong failed")?,
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => continue,
                Some(Ok(Message::Close(_))) | None => return Ok(Some(Frame::Closed)),
                Some(Err(error)) => return Err(error).context("the WebSocket read failed"),
            }
        }
    }

    /// Waits for the next cleartext text frame, skipping binary frames.
    ///
    /// A binary frame before the transport carries nothing, which the client side skips as well.
    async fn read_cleartext(&mut self) -> Result<Cleartext> {
        loop {
            match self.read().await? {
                None => return Ok(Cleartext::Shutdown),
                Some(Frame::Closed) => return Ok(Cleartext::Closed),
                Some(Frame::Text(text)) => return Ok(Cleartext::Text(text)),
                Some(Frame::Binary(_)) => continue,
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

    /// Waits for the next transport-mode message.
    async fn read_encrypted(&mut self, noise: &mut TransportState) -> Result<Encrypted> {
        let ciphertext = match self.read().await? {
            None => return Ok(Encrypted::Shutdown),
            Some(Frame::Closed) => return Ok(Encrypted::Closed),
            Some(Frame::Text(_)) => return Ok(Encrypted::Cleartext),
            Some(Frame::Binary(ciphertext)) => ciphertext,
        };
        let plaintext = match noise.decrypt(&ciphertext) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok(Encrypted::Refused),
        };
        match decode_frame(&plaintext) {
            Ok(PlaintextFrame::Json(text)) => Ok(Encrypted::Json(text.to_owned())),
            Ok(PlaintextFrame::Binary { .. }) => Ok(Encrypted::Other),
            Err(_) => Ok(Encrypted::Refused),
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
            match self.read_encrypted(noise).await? {
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
/// The Sentinel-keyed session this milestone runs may carry active roles only when the client
/// admits unpaired access (`messaging.md`, `server/activate`); with unpaired access off, roles would
/// make an activation the client has to reject, so it gets none until pairing exists.
///
/// `player@v1` is activated only when the client's support object lists the configured format. A
/// client that offers the role without it is activated without the role, so the server never sends
/// it a stream it cannot decode, and the `Some` reason tells the host why.
fn active_roles(hello: &ClientHello, format: &AudioFormat) -> (Vec<String>, Option<String>) {
    if !hello.unpaired_access.enabled {
        return (Vec::new(), None);
    }
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
            active_roles(&hello(&all, true, false), &format())
                .0
                .is_empty(),
            "a client that admits no unpaired access gets no roles on a Sentinel-keyed session"
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
