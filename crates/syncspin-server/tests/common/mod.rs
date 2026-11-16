//! A client that speaks the specification, used to drive the server's listener.
//!
//! The fake client is deliberately independent of the server's internals: it walks `client/init`,
//! `server/init`, both Noise handshake messages, `server/hello`, `client/hello` and
//! `server/activate` in the order `connection.md` and `messaging.md` define, and asserts what the
//! server must announce. The Noise half is `syncspin_core::noise::Responder`, the same type the
//! client crate uses, so the responder side is not written twice.
//!
//! The module is shared by the test binaries, so a helper one of them does not use is not dead
//! code.
#![allow(dead_code)]

use std::time::Duration;

pub use anyhow::{bail, Context, Result};
pub use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub use base64::Engine as _;
pub use futures_util::{SinkExt, StreamExt};
pub use syncspin_core::framing::{decode_frame, encode_binary, Frame, BINARY_MESSAGE_ID_JSON};
pub use syncspin_core::messages::{
    AudioChunkHeader, ClientGoodbye, ClientHello, ClientInit, ClientState, ClientTime, DeviceInfo,
    GroupUpdate, Incoming, NoiseHandshake, PlayerState, PlayerSupport, ServerActivate, ServerHello,
    ServerInit, ServerState, ServerTime, StreamStart, SupportedFormat, SupportedPairMethods,
    UnpairedAccess, AUDIO_CHUNK_ID, PROTOCOL_VERSION,
};
pub use syncspin_core::noise::{
    Identity, Responder, Suite, TransportState, SENTINEL_PSK, SENTINEL_PSK_ID,
};
pub use syncspin_server::{
    AudioFormat, Event, EventStream, Server, ServerConfig, ServerHandle, TrackInfo, DEFAULT_PATH,
};
pub use tokio::net::TcpStream;
pub use tokio_tungstenite::tungstenite::Message;
pub use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

/// How long a test waits for anything at all.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The name the fake client announces in `client/hello`.
pub const CLIENT_NAME: &str = "A fake client";

/// The name the test server is configured with.
pub const SERVER_NAME: &str = "A test server";

/// Starts a server that streams `format` and returns it with its event stream.
pub async fn start_with(format: AudioFormat) -> Result<(ServerHandle, u16, EventStream)> {
    start_with_config(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        format,
        ..ServerConfig::new(SERVER_NAME, Identity::generate())
    })
    .await
}

/// Starts a server on the default test format.
pub async fn start() -> Result<(ServerHandle, u16, EventStream)> {
    start_with(AudioFormat::pcm(48_000, 2, 16)).await
}

/// Starts a server from a configuration and returns it with its event stream.
pub async fn start_with_config(config: ServerConfig) -> Result<(ServerHandle, u16, EventStream)> {
    let mut server = Server::start(config).await?;
    let port = server.local_addr().port();
    let events = server.events();
    Ok((server, port, events))
}

/// Waits for the next event, failing the test if none arrives.
pub async fn next_event(events: &mut EventStream) -> Event {
    match tokio::time::timeout(TIMEOUT, events.next()).await {
        Ok(Some(event)) => event,
        Ok(None) => panic!("the event stream ended"),
        Err(_) => panic!("no event within {TIMEOUT:?}"),
    }
}

/// Asserts that no event arrives within `within`.
pub async fn expect_no_event(events: &mut EventStream, within: Duration) {
    match tokio::time::timeout(within, events.next()).await {
        Err(_) => {}
        Ok(Some(event)) => panic!("expected no event, got {event:?}"),
        Ok(None) => panic!("the event stream ended"),
    }
}

/// The `client/init` text of a conformant client.
pub fn init_text(client_id: &str, version: u32, suite: &str) -> String {
    serde_json::to_string(&Incoming::ClientInit(ClientInit {
        client_id: client_id.to_owned(),
        version,
        suite: suite.to_owned(),
    }))
    .expect("a client/init encodes")
}

/// The `pcm` format the test server streams and the fake client plays.
pub fn pcm_format() -> SupportedFormat {
    SupportedFormat {
        codec: "pcm".to_owned(),
        channels: 2,
        sample_rate: 48_000,
        bit_depth: 16,
    }
}

/// The `client/hello` of a player that offers the three roles the server serves.
pub fn client_hello() -> Incoming {
    client_hello_with_formats(vec![pcm_format()])
}

/// The `client/hello` of a client that plays `formats`.
pub fn client_hello_with_formats(formats: Vec<SupportedFormat>) -> Incoming {
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

/// The `client/state` a client reports for its player role.
///
/// The specification requires it after the player role becomes active and before the server may
/// announce a stream, so every test that expects audio sends it.
pub fn player_state(available: bool, volume: u8, muted: bool) -> Incoming {
    Incoming::ClientState(ClientState {
        available,
        player: Some(PlayerState {
            volume: Some(volume),
            muted: Some(muted),
            output_delay_ms: 0,
            required_lead_time_ms: 200,
            min_buffer_ms: 100,
            supported_commands: vec!["volume".to_owned(), "mute".to_owned()],
            format: None,
        }),
    })
}

/// One message the fake client received after the handshake.
#[derive(Debug)]
pub enum Received {
    /// One JSON control message.
    Json(Box<Incoming>),
    /// One audio chunk, with its header and the encoded bytes that follow it.
    Audio(AudioChunkHeader, Vec<u8>),
}

/// A spec-speaking Sendspin client.
pub struct FakeClient {
    pub identity: Identity,
    pub socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    pub noise: Option<TransportState>,
    pub server_name: Option<String>,
}

impl FakeClient {
    /// Opens the upgrade against `path` on the server at `port`.
    pub async fn connect_at(port: u16, path: &str) -> Result<FakeClient> {
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
    pub async fn connect(port: u16) -> Result<FakeClient> {
        FakeClient::connect_at(port, DEFAULT_PATH).await
    }

    /// Reads the next frame, failing the test if the server stays silent.
    pub async fn next_message(&mut self) -> Result<Option<Message>> {
        match tokio::time::timeout(TIMEOUT, self.socket.next()).await {
            Ok(message) => Ok(message.transpose()?),
            Err(_) => bail!("the server sent nothing within {TIMEOUT:?}"),
        }
    }

    pub async fn send_text(&mut self, text: &str) -> Result<()> {
        self.socket.send(Message::text(text)).await?;
        Ok(())
    }

    /// Reads the next cleartext JSON text frame.
    pub async fn read_text(&mut self) -> Result<String> {
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
    pub async fn read_json(&mut self) -> Result<String> {
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
    pub async fn send_json(&mut self, message: &Incoming) -> Result<()> {
        let text = serde_json::to_string(message)?;
        self.send_raw_json(&text).await
    }

    /// Encrypts and sends one JSON body, including a type this revision does not have.
    pub async fn send_raw_json(&mut self, text: &str) -> Result<()> {
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
    /// metadata announced, unless the announced key is another one; the caller can replace it.
    pub async fn begin_handshake(&mut self, suite: Suite) -> Result<Responder> {
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

    /// Sends `client/init`, reads message 1 and answers with message 2 under `psk`.
    ///
    /// The announcement is not asserted here; a caller that expects a private key checks the
    /// `psk_id` and `psk_category` it reads from `begin_handshake_any`.
    pub async fn handshake_with_psk(&mut self, suite: Suite, psk: &[u8; 32]) -> Result<String> {
        let (mut responder, announcement) = self.begin_handshake_any(suite).await?;
        responder.set_psk(psk)?;
        self.finish_handshake(responder).await?;
        Ok(announcement)
    }

    /// Sends `client/init` and reads message 1 without assuming the announced key.
    pub async fn begin_handshake_any(&mut self, suite: Suite) -> Result<(Responder, String)> {
        let init = init_text(
            &self.identity.public_base64(),
            PROTOCOL_VERSION,
            suite.wire_name(),
        );
        self.send_text(&init).await?;
        let server_init_text = self.read_text().await?;
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
        let category = serde_json::from_slice::<serde_json::Value>(&metadata)
            .context("the Noise handshake metadata is not a JSON object")?
            .get("psk_category")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok((responder, category))
    }

    /// Writes Noise message 2 and reads `server/hello`.
    pub async fn finish_handshake(&mut self, mut responder: Responder) -> Result<()> {
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
    pub async fn handshake(&mut self, suite: Suite) -> Result<()> {
        let responder = self.begin_handshake(suite).await?;
        self.finish_handshake(responder).await
    }

    /// Sends `client/hello` and returns the first `server/activate`.
    pub async fn activate(&mut self) -> Result<ServerActivate> {
        self.activate_with(client_hello()).await
    }

    /// Sends `hello` and returns the first `server/activate`.
    pub async fn activate_with(&mut self, hello: Incoming) -> Result<ServerActivate> {
        self.send_json(&hello).await?;
        match Incoming::parse(&self.read_json().await?)? {
            Some(Incoming::ServerActivate(activate)) => Ok(activate),
            other => bail!("expected server/activate, got {other:?}"),
        }
    }

    /// Connects, is activated as an unapproved client, requests approval and reports its state.
    ///
    /// The host has to approve an unpaired client, so every test that expects roles or audio goes
    /// through here: the first activation must be empty, the second carries the roles.
    pub async fn connect_and_activate(
        &mut self,
        server: &ServerHandle,
        suite: Suite,
    ) -> Result<ServerActivate> {
        self.handshake(suite).await?;
        let first = self.activate().await?;
        assert!(
            first.active_roles.unwrap_or_default().is_empty(),
            "an unapproved client must not be activated with roles"
        );
        server.approve(&self.identity.public_base64()).await?;
        let activate = self
            .read_activate(|activities| {
                assert!(
                    activities.is_empty(),
                    "an approval activates roles without declaring an activity"
                );
                true
            })
            .await?;
        self.send_json(&player_state(true, 100, false)).await?;
        Ok(activate)
    }

    /// Sends `client/goodbye` and waits for the server to close.
    pub async fn goodbye(&mut self, reason: &str) -> Result<()> {
        self.send_json(&Incoming::ClientGoodbye(ClientGoodbye {
            reason: reason.to_owned(),
        }))
        .await?;
        self.expect_closed().await
    }

    /// Sends a WebSocket close frame.
    pub async fn close(&mut self) -> Result<()> {
        self.socket.send(Message::Close(None)).await?;
        Ok(())
    }

    /// Waits for the server to close the connection.
    ///
    /// Role state and group updates may still be in flight when a client leaves, so anything other
    /// than the close is skipped.
    pub async fn expect_closed(&mut self) -> Result<()> {
        loop {
            match tokio::time::timeout(TIMEOUT, self.socket.next()).await {
                Err(_) => bail!("the server kept the connection open"),
                Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return Ok(()),
                Ok(Some(Ok(_))) => continue,
            }
        }
    }

    /// Reads the next transport-mode message, JSON or audio.
    pub async fn next_received(&mut self) -> Result<Received> {
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
    pub async fn read_until<T>(
        &mut self,
        mut want: impl FnMut(Incoming) -> Option<T>,
    ) -> Result<T> {
        loop {
            if let Received::Json(message) = self.next_received().await? {
                if let Some(value) = want(*message) {
                    return Ok(value);
                }
            }
        }
    }

    /// Reads the next audio chunk.
    pub async fn read_audio(&mut self) -> Result<(AudioChunkHeader, Vec<u8>)> {
        loop {
            match self.next_received().await? {
                Received::Audio(header, audio) => return Ok((header, audio)),
                Received::Json(_) => continue,
            }
        }
    }

    /// Reads the next `server/state`.
    pub async fn read_state(&mut self) -> Result<ServerState> {
        self.read_until(|message| match message {
            Incoming::ServerState(state) => Some(state),
            _ => None,
        })
        .await
    }

    /// Reads the next `stream/start`.
    pub async fn read_stream_start(&mut self) -> Result<StreamStart> {
        self.read_until(|message| match message {
            Incoming::StreamStart(start) => Some(start),
            _ => None,
        })
        .await
    }

    /// Sends one `client/time` and returns the `server/time` reply.
    pub async fn round_trip_time(&mut self, client_transmitted: i64) -> Result<ServerTime> {
        self.send_json(&Incoming::ClientTime(ClientTime { client_transmitted }))
            .await?;
        self.read_until(|message| match message {
            Incoming::ServerTime(time) => Some(time),
            _ => None,
        })
        .await
    }

    /// Reads the next `group/update`.
    pub async fn read_group_update(&mut self) -> Result<GroupUpdate> {
        self.read_until(|message| match message {
            Incoming::GroupUpdate(update) => Some(update),
            _ => None,
        })
        .await
    }

    /// Reads the next `server/activate` whose activities satisfy `want`.
    pub async fn read_activate(
        &mut self,
        want: impl Fn(&[String]) -> bool,
    ) -> Result<ServerActivate> {
        self.read_until(|message| match message {
            Incoming::ServerActivate(activate) if want(&activate.activities) => Some(activate),
            _ => None,
        })
        .await
    }

    /// Reads messages until `want` selects one, failing when a `pair/abort` arrives first.
    ///
    /// An abort ends the search with an error, so a test cannot hang on a server that refused the
    /// attempt; every other message the test does not want is skipped like audio.
    pub async fn read_pairing<T>(
        &mut self,
        mut want: impl FnMut(Incoming) -> Option<T>,
    ) -> Result<T> {
        loop {
            if let Received::Json(message) = self.next_received().await? {
                if let Incoming::PairAbort(abort) = &*message {
                    bail!("the server aborted the pairing: {}", abort.reason);
                }
                if let Some(value) = want(*message) {
                    return Ok(value);
                }
            }
        }
    }

    /// Fails when an audio chunk arrives within `within`.
    pub async fn expect_no_audio(&mut self, within: Duration) -> Result<()> {
        let outcome = tokio::time::timeout(within, async {
            loop {
                match self.next_received().await? {
                    Received::Audio(..) => bail!("a member that may not play received audio"),
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

    /// Fails when a `server/state` arrives within `within`.
    pub async fn expect_no_state(&mut self, within: Duration) -> Result<()> {
        match tokio::time::timeout(within, self.read_state()).await {
            Err(_) => Ok(()),
            Ok(Ok(state)) => bail!("expected no server/state, got {state:?}"),
            Ok(Err(error)) => Err(error),
        }
    }

    /// Fails when a stream message or audio arrives within `within`.
    pub async fn expect_no_stream(&mut self, within: Duration) -> Result<()> {
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
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.noise
            .as_mut()
            .expect("the handshake finished before a transport message")
            .decrypt(ciphertext)
    }
}
