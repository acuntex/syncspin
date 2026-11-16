//! A client that speaks the specification, used to drive the server's listener.
//!
//! The fake client is deliberately independent of the server's internals: it walks `client/init`,
//! `server/init`, both Noise handshake messages, `server/hello`, `client/hello` and
//! `server/activate` in the order `connection.md` and `messaging.md` define, and asserts what the
//! server must announce. The Noise half is `syncspin_core::noise::Responder`, the same type the
//! client crate uses, so the responder side is not written twice.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use syncspin_core::framing::{decode_frame, encode_binary, Frame, BINARY_MESSAGE_ID_JSON};
use syncspin_core::messages::{
    AudioChunkHeader, ClientCommand, ClientGoodbye, ClientHello, ClientInit, ControllerCommand,
    DeviceInfo, Incoming, NoiseHandshake, PlayerSupport, ServerActivate, ServerError, ServerHello,
    ServerInit, ServerState, StreamEnd, StreamStart, SupportedFormat, SupportedPairMethods,
    UnpairedAccess, AUDIO_CHUNK_ID, PROTOCOL_VERSION,
};
use syncspin_core::noise::{
    Identity, Responder, Suite, TransportState, SENTINEL_PSK, SENTINEL_PSK_ID,
};
use syncspin_server::{
    AudioFormat, Event, EventStream, Server, ServerConfig, ServerHandle, TrackInfo, DEFAULT_PATH,
};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

/// How long a test waits for anything at all.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The name the fake client announces in `client/hello`.
const CLIENT_NAME: &str = "A fake client";

/// The name the test server is configured with.
const SERVER_NAME: &str = "A test server";

/// Starts a server on a port the operating system picks and returns it with its event stream.
async fn start() -> Result<(ServerHandle, u16, EventStream)> {
    start_with(AudioFormat::pcm(48_000, 2, 16)).await
}

/// Starts a server that streams `format`.
async fn start_with(format: AudioFormat) -> Result<(ServerHandle, u16, EventStream)> {
    let config = ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        format,
        ..ServerConfig::new(SERVER_NAME, Identity::generate())
    };
    let mut server = Server::start(config).await?;
    let port = server.local_addr().port();
    let events = server.events();
    Ok((server, port, events))
}

/// Waits for the next event, failing the test if none arrives.
async fn next_event(events: &mut EventStream) -> Event {
    match tokio::time::timeout(TIMEOUT, events.next()).await {
        Ok(Some(event)) => event,
        Ok(None) => panic!("the event stream ended"),
        Err(_) => panic!("no event within {TIMEOUT:?}"),
    }
}

/// Asserts that no event arrives within `within`.
async fn expect_no_event(events: &mut EventStream, within: Duration) {
    match tokio::time::timeout(within, events.next()).await {
        Err(_) => {}
        Ok(Some(event)) => panic!("expected no event, got {event:?}"),
        Ok(None) => panic!("the event stream ended"),
    }
}

/// The `client/init` text of a conformant client.
fn init_text(client_id: &str, version: u32, suite: &str) -> String {
    serde_json::to_string(&Incoming::ClientInit(ClientInit {
        client_id: client_id.to_owned(),
        version,
        suite: suite.to_owned(),
    }))
    .expect("a client/init encodes")
}

/// The `pcm` format the test server streams and the fake client plays.
fn pcm_format() -> SupportedFormat {
    SupportedFormat {
        codec: "pcm".to_owned(),
        channels: 2,
        sample_rate: 48_000,
        bit_depth: 16,
    }
}

/// The `client/hello` of a player that offers the three roles the server serves.
fn client_hello() -> Incoming {
    client_hello_with_formats(vec![pcm_format()])
}

/// The `client/hello` of a client that plays `formats`.
fn client_hello_with_formats(formats: Vec<SupportedFormat>) -> Incoming {
    Incoming::ClientHello(ClientHello {
        name: CLIENT_NAME.to_owned(),
        device_info: Some(DeviceInfo {
            product_name: Some("Fake product".to_owned()),
            manufacturer: None,
            software_version: None,
            mac_address: None,
        }),
        supported_roles: vec![
            "player@v1".to_owned(),
            "controller@v1".to_owned(),
            "metadata@v1".to_owned(),
        ],
        player_support: Some(PlayerSupport {
            supported_formats: formats,
            buffer_capacity: 1 << 20,
        }),
        supported_pair_methods: SupportedPairMethods::default(),
        unpaired_access: UnpairedAccess { enabled: true },
    })
}

/// One message the fake client received after the handshake.
#[derive(Debug)]
enum Received {
    /// One JSON control message.
    Json(Box<Incoming>),
    /// One audio chunk, with its header and the encoded bytes that follow it.
    Audio(AudioChunkHeader, Vec<u8>),
}

/// A spec-speaking Sendspin client.
struct FakeClient {
    identity: Identity,
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    noise: Option<TransportState>,
    server_name: Option<String>,
}

impl FakeClient {
    /// Opens the upgrade against `path` on the server at `port`.
    async fn connect_at(port: u16, path: &str) -> Result<FakeClient> {
        let url = format!("ws://127.0.0.1:{port}{path}");
        let (socket, _response) = tokio::time::timeout(TIMEOUT, connect_async(&url))
            .await
            .with_context(|| format!("the server did not answer the upgrade at {url}"))??;
        Ok(FakeClient {
            identity: Identity::generate(),
            socket,
            noise: None,
            server_name: None,
        })
    }

    /// Opens the upgrade against the configured endpoint path.
    async fn connect(port: u16) -> Result<FakeClient> {
        FakeClient::connect_at(port, DEFAULT_PATH).await
    }

    /// Reads the next frame, failing the test if the server stays silent.
    async fn next_message(&mut self) -> Result<Option<Message>> {
        match tokio::time::timeout(TIMEOUT, self.socket.next()).await {
            Ok(message) => Ok(message.transpose()?),
            Err(_) => bail!("the server sent nothing within {TIMEOUT:?}"),
        }
    }

    async fn send_text(&mut self, text: &str) -> Result<()> {
        self.socket.send(Message::text(text)).await?;
        Ok(())
    }

    /// Reads the next cleartext JSON text frame.
    async fn read_text(&mut self) -> Result<String> {
        loop {
            match self.next_message().await? {
                Some(Message::Text(text)) => return Ok(text.as_str().to_owned()),
                Some(Message::Binary(_))
                | Some(Message::Ping(_))
                | Some(Message::Pong(_))
                | Some(Message::Frame(_)) => continue,
                Some(Message::Close(_)) | None => bail!("the server closed the connection"),
            }
        }
    }

    /// Reads the next JSON message of the Noise transport.
    async fn read_json(&mut self) -> Result<String> {
        loop {
            match self.next_message().await? {
                Some(Message::Text(_)) => {
                    bail!("cleartext text after the Noise transport is a protocol error")
                }
                Some(Message::Binary(ciphertext)) => {
                    let plaintext = self.decrypt(&ciphertext)?;
                    match plaintext.first() {
                        Some(&BINARY_MESSAGE_ID_JSON) => {
                            return String::from_utf8(plaintext[1..].to_vec())
                                .context("the decrypted JSON is not valid UTF-8")
                        }
                        Some(_) => continue,
                        None => bail!("an empty Noise plaintext is a protocol error"),
                    }
                }
                Some(Message::Ping(_)) | Some(Message::Pong(_)) | Some(Message::Frame(_)) => {
                    continue
                }
                Some(Message::Close(_)) | None => bail!("the server closed the connection"),
            }
        }
    }

    /// Encrypts and sends one control message.
    async fn send_json(&mut self, message: &Incoming) -> Result<()> {
        let text = serde_json::to_string(message)?;
        self.send_raw_json(&text).await
    }

    /// Encrypts and sends one JSON body, including a type this revision does not have.
    async fn send_raw_json(&mut self, text: &str) -> Result<()> {
        let plaintext = encode_binary(BINARY_MESSAGE_ID_JSON, text.as_bytes());
        let ciphertext = self
            .noise
            .as_mut()
            .expect("the handshake finished before a control message")
            .encrypt(&plaintext)?;
        self.socket.send(Message::binary(ciphertext)).await?;
        Ok(())
    }

    /// Sends `client/init` and reads `server/init` and Noise message 1.
    ///
    /// The server must send both without waiting in between, so nothing is sent after
    /// `client/init`. The returned responder has the Sentinel key set, which is the key the
    /// metadata announced.
    async fn begin_handshake(&mut self, suite: Suite) -> Result<Responder> {
        let init = init_text(
            &self.identity.public_base64(),
            PROTOCOL_VERSION,
            suite.wire_name(),
        );
        self.send_text(&init).await?;

        let server_init_text = self.read_text().await?;
        match Incoming::parse(&server_init_text)? {
            // `Responder::new` below reads and validates the `server_id` from the prologue, so a
            // server that names a key that is not one fails the handshake rather than this check.
            Some(Incoming::ServerInit(ServerInit { version, .. })) => {
                assert_eq!(version, PROTOCOL_VERSION, "the server speaks this revision");
            }
            other => bail!("expected server/init, got {other:?}"),
        }

        let message_1_text = self.read_text().await?;
        let message_1 = match Incoming::parse(&message_1_text)? {
            Some(Incoming::NoiseHandshake(NoiseHandshake { data })) => URL_SAFE_NO_PAD
                .decode(&data)
                .context("noise/handshake data is not unpadded base64url")?,
            other => bail!("expected noise/handshake message 1, got {other:?}"),
        };

        let mut prologue = init.into_bytes();
        prologue.extend_from_slice(server_init_text.as_bytes());
        let mut responder = Responder::new(&self.identity, &prologue)?;
        let metadata = responder.read_message(&message_1)?;
        let announcement: serde_json::Value = serde_json::from_slice(&metadata)
            .context("the Noise handshake metadata is not a JSON object")?;
        assert_eq!(
            announcement["psk_id"].as_str(),
            Some(SENTINEL_PSK_ID),
            "an unpaired server announces the Sentinel key"
        );
        assert_eq!(announcement["psk_category"].as_str(), Some("sn"));
        responder.set_psk(&SENTINEL_PSK)?;
        Ok(responder)
    }

    /// Writes Noise message 2 and reads `server/hello`.
    async fn finish_handshake(&mut self, mut responder: Responder) -> Result<()> {
        let message_2 = responder.write_message()?;
        let message_2 = Incoming::NoiseHandshake(NoiseHandshake {
            data: URL_SAFE_NO_PAD.encode(&message_2),
        });
        self.send_text(&serde_json::to_string(&message_2)?).await?;
        self.noise = Some(responder.into_transport()?);

        match Incoming::parse(&self.read_json().await?)? {
            Some(Incoming::ServerHello(ServerHello { name, .. })) => {
                self.server_name = Some(name);
            }
            other => bail!("expected server/hello, got {other:?}"),
        }
        Ok(())
    }

    /// Runs the whole handshake up to and including `server/hello`.
    async fn handshake(&mut self, suite: Suite) -> Result<()> {
        let responder = self.begin_handshake(suite).await?;
        self.finish_handshake(responder).await
    }

    /// Sends `client/hello` and returns the first `server/activate`.
    async fn activate(&mut self) -> Result<ServerActivate> {
        self.activate_with(client_hello()).await
    }

    /// Sends `hello` and returns the first `server/activate`.
    async fn activate_with(&mut self, hello: Incoming) -> Result<ServerActivate> {
        self.send_json(&hello).await?;
        match Incoming::parse(&self.read_json().await?)? {
            Some(Incoming::ServerActivate(activate)) => Ok(activate),
            other => bail!("expected server/activate, got {other:?}"),
        }
    }

    /// Walks the handshake and the activation and returns the activation.
    async fn connect_and_activate(&mut self, suite: Suite) -> Result<ServerActivate> {
        self.handshake(suite).await?;
        self.activate().await
    }

    /// Sends `client/goodbye` and waits for the server to close.
    async fn goodbye(&mut self, reason: &str) -> Result<()> {
        self.send_json(&Incoming::ClientGoodbye(ClientGoodbye {
            reason: reason.to_owned(),
        }))
        .await?;
        self.expect_closed().await
    }

    /// Sends a WebSocket close frame.
    async fn close(&mut self) -> Result<()> {
        self.socket.send(Message::Close(None)).await?;
        Ok(())
    }

    /// Waits for the server to close the connection.
    ///
    /// Role state and group updates may still be in flight when a client leaves, so anything other
    /// than the close is skipped.
    async fn expect_closed(&mut self) -> Result<()> {
        loop {
            match tokio::time::timeout(TIMEOUT, self.socket.next()).await {
                Err(_) => bail!("the server kept the connection open"),
                Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return Ok(()),
                Ok(Some(Ok(_))) => continue,
            }
        }
    }

    /// Reads the next transport-mode message, JSON or audio.
    async fn next_received(&mut self) -> Result<Received> {
        loop {
            match self.next_message().await? {
                Some(Message::Text(_)) => {
                    bail!("cleartext text after the Noise transport is a protocol error")
                }
                Some(Message::Binary(ciphertext)) => {
                    let plaintext = self.decrypt(&ciphertext)?;
                    match decode_frame(&plaintext)? {
                        Frame::Json(text) => {
                            let message = Incoming::parse(text)?.context(
                                "the server sent a message type this revision does not have",
                            )?;
                            return Ok(Received::Json(Box::new(message)));
                        }
                        Frame::Binary {
                            id: AUDIO_CHUNK_ID, ..
                        } => {
                            let (header, audio) = AudioChunkHeader::parse(&plaintext)?;
                            return Ok(Received::Audio(header, audio.to_vec()));
                        }
                        Frame::Binary { .. } => continue,
                    }
                }
                Some(Message::Ping(_)) | Some(Message::Pong(_)) | Some(Message::Frame(_)) => {
                    continue
                }
                Some(Message::Close(_)) | None => bail!("the server closed the connection"),
            }
        }
    }

    /// Reads messages until one satisfies `want`.
    ///
    /// Audio is skipped, so a test can pick the control message it is about out of the stream.
    async fn read_until<T>(&mut self, mut want: impl FnMut(Incoming) -> Option<T>) -> Result<T> {
        loop {
            if let Received::Json(message) = self.next_received().await? {
                if let Some(value) = want(*message) {
                    return Ok(value);
                }
            }
        }
    }

    /// Reads the next audio chunk.
    async fn read_audio(&mut self) -> Result<(AudioChunkHeader, Vec<u8>)> {
        loop {
            match self.next_received().await? {
                Received::Audio(header, audio) => return Ok((header, audio)),
                Received::Json(_) => continue,
            }
        }
    }

    /// Reads the next `server/state`.
    async fn read_state(&mut self) -> Result<ServerState> {
        self.read_until(|message| match message {
            Incoming::ServerState(state) => Some(state),
            _ => None,
        })
        .await
    }

    /// Reads the next `stream/start`.
    async fn read_stream_start(&mut self) -> Result<StreamStart> {
        self.read_until(|message| match message {
            Incoming::StreamStart(start) => Some(start),
            _ => None,
        })
        .await
    }

    /// Fails when a stream message or audio arrives within `within`.
    async fn expect_no_stream(&mut self, within: Duration) -> Result<()> {
        let outcome = tokio::time::timeout(within, async {
            loop {
                match self.next_received().await? {
                    Received::Audio(..) => bail!("a client without the player role received audio"),
                    Received::Json(message)
                        if matches!(
                            *message,
                            Incoming::StreamStart(_)
                                | Incoming::StreamClear(_)
                                | Incoming::StreamEnd(_)
                        ) =>
                    {
                        bail!("a client without the player role received a stream message")
                    }
                    Received::Json(_) => continue,
                }
            }
        })
        .await;
        match outcome {
            Err(_) => Ok(()),
            Ok(result) => result,
        }
    }

    /// Decrypts one transport message.
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.noise
            .as_mut()
            .expect("the handshake finished before a transport message")
            .decrypt(ciphertext)
    }
}

#[tokio::test]
async fn a_client_connects_and_is_activated() -> Result<()> {
    for suite in Suite::ALL {
        let (server, port, mut events) = start().await?;
        let mut client = FakeClient::connect(port).await?;
        let activate = client.connect_and_activate(suite).await?;

        assert_eq!(
            client.server_name.as_deref(),
            Some(SERVER_NAME),
            "`server/hello` carries the configured name with suite {suite}"
        );
        let roles = activate.active_roles.unwrap_or_default();
        assert_eq!(
            roles,
            ["player@v1", "controller@v1", "metadata@v1"],
            "every role the client offered is active with suite {suite}"
        );
        assert!(
            activate.activities.is_empty(),
            "a server with no group declares no activity, with suite {suite}"
        );

        assert_eq!(
            next_event(&mut events).await,
            Event::ClientConnected {
                client_id: client.identity.public_base64(),
                name: CLIENT_NAME.to_owned(),
            }
        );
        assert_eq!(
            next_event(&mut events).await,
            Event::ClientActivated {
                roles: roles.clone(),
            }
        );

        client.goodbye("shutdown").await?;
        assert_eq!(
            next_event(&mut events).await,
            Event::ClientLeft {
                reason: "shutdown".to_owned(),
            },
            "the goodbye reason reaches the host verbatim"
        );
        server.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_handshake_that_does_not_authenticate_is_refused() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;

    // The same exchange, sealed with a key the server does not use: the initiator cannot
    // authenticate message 2, so the server closes without a further message.
    let mut responder = client.begin_handshake(Suite::ChaChaPoly).await?;
    responder.set_psk(&[7u8; 32])?;
    let outcome = client.finish_handshake(responder).await;
    assert!(
        outcome.is_err(),
        "the server must not answer a handshake it cannot authenticate"
    );

    client.expect_closed().await?;
    expect_no_event(&mut events, Duration::from_millis(200)).await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_client_that_never_completes_the_handshake_is_not_reported() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;

    // `client/init`, then the socket goes away without message 2.
    let init = init_text(
        &client.identity.public_base64(),
        PROTOCOL_VERSION,
        Suite::ChaChaPoly.wire_name(),
    );
    client.send_text(&init).await?;
    client.read_text().await?;
    drop(client);

    expect_no_event(&mut events, Duration::from_millis(200)).await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_refused_init_is_answered_with_server_error_and_the_matching_reason() -> Result<()> {
    let cases = [
        (
            "an unknown version",
            init_text("a-client", 2, Suite::ChaChaPoly.wire_name()),
            "unsupported_version",
        ),
        (
            "an unknown suite",
            init_text("a-client", PROTOCOL_VERSION, "25519_Unobtainium_SHA256"),
            "unsupported_suite",
        ),
        (
            "an envelope this revision does not have",
            r#"{"type":"server/init","payload":{}}"#.to_owned(),
            "malformed",
        ),
        ("not JSON at all", "not json at all".to_owned(), "malformed"),
    ];

    for (case, init, reason) in cases {
        let (server, port, _events) = start().await?;
        let mut client = FakeClient::connect(port).await?;
        client.send_text(&init).await?;

        match Incoming::parse(&client.read_text().await?)? {
            Some(Incoming::ServerError(ServerError { reason: announced })) => {
                assert_eq!(announced, reason, "{case}")
            }
            other => bail!("{case}: expected server/error, got {other:?}"),
        }
        client.expect_closed().await?;
        server.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_cleartext_message_after_the_handshake_closes_the_connection() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;

    // `client/hello` must travel under the transport keys.
    let hello = serde_json::to_string(&client_hello())?;
    client.send_text(&hello).await?;

    client.expect_closed().await?;
    expect_no_event(&mut events, Duration::from_millis(200)).await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_second_client_init_closes_the_connection() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.connect_and_activate(Suite::ChaChaPoly).await?;

    let init = init_text(
        &client.identity.public_base64(),
        PROTOCOL_VERSION,
        Suite::ChaChaPoly.wire_name(),
    );
    let init = Incoming::parse(&init)?.expect("client/init is a known message");
    client.send_json(&init).await?;

    client.expect_closed().await?;
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientConnected {
            client_id: client.identity.public_base64(),
            name: CLIENT_NAME.to_owned(),
        }
    );
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "protocol error".to_owned(),
        }
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_closed_socket_is_reported_as_a_leave() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.connect_and_activate(Suite::ChaChaPoly).await?;
    client.close().await?;

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "connection closed".to_owned(),
        }
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn shutdown_closes_the_connection_and_ends_the_event_stream() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.connect_and_activate(Suite::ChaChaPoly).await?;
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));

    server.shutdown().await?;

    client.expect_closed().await?;
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "server shutdown".to_owned(),
        }
    );
    assert!(
        tokio::time::timeout(TIMEOUT, events.next())
            .await?
            .is_none(),
        "the stream ends once the server is gone"
    );
    Ok(())
}

#[tokio::test]
async fn only_the_configured_path_is_served() -> Result<()> {
    let (server, port, _events) = start().await?;

    let result = tokio::time::timeout(
        TIMEOUT,
        connect_async(format!("ws://127.0.0.1:{port}/elsewhere")),
    )
    .await?;
    match result {
        Ok(_) => bail!("another path must not be served"),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 404);
        }
        Err(error) => bail!("expected an HTTP refusal, got {error:?}"),
    }

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_message_for_another_role_or_of_an_unknown_type_is_ignored() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.connect_and_activate(Suite::ChaChaPoly).await?;

    // A command for a role the server does not serve yet, and a type this revision does not have:
    // both leave the connection open, which the goodbye proves.
    client
        .send_json(&Incoming::ClientCommand(ClientCommand::default()))
        .await?;
    client
        .send_raw_json(r#"{"type":"colour/update","payload":{"hue":1}}"#)
        .await?;
    client.goodbye("shutdown").await?;

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "shutdown".to_owned(),
        }
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_player_receives_the_stream_with_playout_timestamps() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    let activate = client.connect_and_activate(Suite::ChaChaPoly).await?;
    assert!(
        activate
            .active_roles
            .unwrap_or_default()
            .contains(&"player@v1".to_owned()),
        "a client that plays the configured format is a player"
    );

    let mut writer = server.open_stream(TrackInfo {
        title: Some("A title".to_owned()),
        duration: Some(Duration::from_secs(200)),
        ..TrackInfo::default()
    });
    let start = client.read_stream_start().await?;
    let player = start
        .player
        .expect("an active player stream carries its format");
    assert_eq!(player.codec, "pcm");
    assert_eq!(player.sample_rate, 48_000);
    assert_eq!(player.channels, 2);
    assert_eq!(player.bit_depth, 16);
    assert_eq!(player.codec_header, None);
    assert!(start.server_transmitted > 0);

    // 480 stereo frames of 16-bit PCM are 10 ms at 48 kHz.
    let chunk = [7u8; 480 * 4];
    writer.write(&chunk);
    writer.write(&chunk);

    let (first, payload) = client.read_audio().await?;
    assert_eq!(payload, chunk, "the server forwards the bytes unchanged");
    let (second, _) = client.read_audio().await?;
    assert_eq!(
        second.timestamp_us - first.timestamp_us,
        10_000,
        "the timeline advances by the playtime of the chunk"
    );
    assert!(
        first.send_ahead > 0,
        "the first chunk is transmitted before it is due"
    );

    writer.seek(Duration::from_secs(30));
    let clear = client
        .read_until(|message| match message {
            Incoming::StreamClear(clear) => Some(clear),
            _ => None,
        })
        .await?;
    assert_eq!(clear.roles, Some(vec!["player".to_owned()]));
    assert_eq!(clear.from_timestamp, None, "a seek drops every buffer");
    assert!(clear.server_transmitted >= start.server_transmitted);

    writer.end();
    let end: StreamEnd = client
        .read_until(|message| match message {
            Incoming::StreamEnd(end) => Some(end),
            _ => None,
        })
        .await?;
    assert_eq!(end.roles, Some(vec!["player".to_owned()]));

    assert_eq!(
        next_event(&mut events).await,
        Event::ClientConnected {
            client_id: client.identity.public_base64(),
            name: CLIENT_NAME.to_owned(),
        }
    );
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(next_event(&mut events).await, Event::StreamStarted);
    assert_eq!(
        next_event(&mut events).await,
        Event::StreamEnded,
        "the host learns that the stream it opened has ended"
    );

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_client_without_the_stream_format_gets_no_player_role_and_no_stream() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    let hello = client_hello_with_formats(vec![SupportedFormat {
        codec: "opus".to_owned(),
        channels: 2,
        sample_rate: 48_000,
        bit_depth: 16,
    }]);
    let activate = client.activate_with(hello).await?;
    assert_eq!(
        activate.active_roles.unwrap_or_default(),
        ["controller@v1", "metadata@v1"],
        "a client that cannot play the format keeps the roles that do not stream"
    );

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientActivated {
            roles: vec!["controller@v1".to_owned(), "metadata@v1".to_owned()],
        }
    );
    match next_event(&mut events).await {
        Event::PlayerRoleWithheld { client_id, reason } => {
            assert_eq!(client_id, client.identity.public_base64());
            assert!(
                reason.contains("pcm, 48000 Hz, 2 channel(s), 16 bit"),
                "the reason names the format the server streams: {reason}"
            );
        }
        other => bail!("expected the player role to be reported as withheld, got {other:?}"),
    }

    let mut writer = server.open_stream(TrackInfo::default());
    writer.write(&[0u8; 480 * 4]);
    client.expect_no_stream(Duration::from_millis(300)).await?;
    writer.end();

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn server_state_carries_the_group_and_the_track() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.connect_and_activate(Suite::ChaChaPoly).await?;

    let state = client.read_state().await?;
    let controller = state
        .controller
        .expect("the controller role is active, so its state is present");
    assert_eq!(controller.volume, Some(100));
    assert_eq!(controller.muted, Some(false));
    assert_eq!(
        controller.supported_commands,
        ["play", "pause", "stop", "volume", "mute"]
    );
    let metadata = state
        .metadata
        .expect("the metadata role is active, so its state is present");
    assert!(
        metadata.timestamp.is_some(),
        "the first state of a role is dated, so a client is up to date"
    );
    assert_eq!(metadata.title, None, "no stream has started yet");

    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "stopped");
    assert_eq!(group.group_name, SERVER_NAME);
    assert_eq!(
        group.group_id.len(),
        43,
        "the group identifier is 32 bytes as unpadded base64url"
    );

    server.play();
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "playing");

    server.open_stream(TrackInfo {
        title: Some("A title".to_owned()),
        artist: Some("An artist".to_owned()),
        album: Some("An album".to_owned()),
        duration: Some(Duration::from_secs(200)),
        ..TrackInfo::default()
    });
    let state = client.read_state().await?;
    let metadata = state.metadata.expect("the metadata role is active");
    assert_eq!(metadata.title.as_deref(), Some("A title"));
    assert_eq!(metadata.artist.as_deref(), Some("An artist"));
    assert_eq!(metadata.album.as_deref(), Some("An album"));
    let progress = metadata
        .progress
        .expect("a running stream reports progress");
    assert_eq!(progress.track_duration, Some(200_000));
    assert_eq!(progress.playback_speed, Some(1000));
    assert_eq!(progress.track_progress, Some(0));

    server.pause();
    assert!(
        matches!(next_event(&mut events).await, Event::ClientConnected { .. }),
        "the connection events still lead the stream events"
    );
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(next_event(&mut events).await, Event::StreamStarted);
    assert_eq!(
        next_event(&mut events).await,
        Event::StreamEnded,
        "a paused group ends its player stream"
    );
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "stopped");

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn set_volume_reaches_the_client_and_a_controller_command_does_too() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.connect_and_activate(Suite::ChaChaPoly).await?;
    assert_eq!(
        client.read_state().await?.controller.unwrap().volume,
        Some(100)
    );

    assert_eq!(server.set_volume(40), 40);
    let controller = client.read_state().await?.controller.unwrap();
    assert_eq!(controller.volume, Some(40));
    assert_eq!(
        controller.muted,
        Some(false),
        "a volume change never touches the mute state"
    );

    assert_eq!(
        server.set_volume(200),
        100,
        "a level above the range is clamped, not rejected"
    );
    assert_eq!(
        client.read_state().await?.controller.unwrap().volume,
        Some(100)
    );

    client
        .send_json(&Incoming::ClientCommand(ClientCommand {
            controller: Some(ControllerCommand {
                command: "volume".to_owned(),
                volume: Some(25),
                ..ControllerCommand::default()
            }),
        }))
        .await?;
    assert_eq!(
        client.read_state().await?.controller.unwrap().volume,
        Some(25),
        "the group applies a controller command it advertised"
    );

    client.goodbye("shutdown").await?;
    Ok(())
}

#[tokio::test]
async fn a_client_that_never_answers_does_not_stall_the_writer() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.connect_and_activate(Suite::ChaChaPoly).await?;
    let mut writer = server.open_stream(TrackInfo::default());

    // The client reads nothing while the host pushes: a write only queues the chunk.
    let chunk = [0u8; 480 * 4];
    let started = Instant::now();
    for _ in 0..100 {
        writer.write(&chunk);
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "100 writes took {:?}, so a silent client held the host up",
        started.elapsed()
    );

    let mut last = i64::MIN;
    for _ in 0..100 {
        let (header, audio) = client.read_audio().await?;
        assert_eq!(audio.len(), chunk.len());
        assert!(
            header.timestamp_us > last,
            "every chunk is later than the one before it"
        );
        last = header.timestamp_us;
    }

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn pausing_ends_the_stream_and_playing_announces_it_again() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.connect_and_activate(Suite::ChaChaPoly).await?;
    let mut writer = server.open_stream(TrackInfo::default());
    client.read_stream_start().await?;

    server.pause();
    let end: StreamEnd = client
        .read_until(|message| match message {
            Incoming::StreamEnd(end) => Some(end),
            _ => None,
        })
        .await?;
    assert_eq!(
        end.roles,
        Some(vec!["player".to_owned()]),
        "a paused group ends its player stream"
    );
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "stopped");

    server.play();
    client.read_stream_start().await?;
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "playing");

    // Audio written after the resume goes out again.
    writer.write(&[0u8; 480 * 4]);
    client.read_audio().await?;

    server.stop();
    client
        .read_until(|message| match message {
            Incoming::StreamEnd(_) => Some(()),
            _ => None,
        })
        .await?;
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "stopped");

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}
