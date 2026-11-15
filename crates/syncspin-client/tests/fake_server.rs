//! A hermetic server for the client integration tests.
//!
//! It binds `127.0.0.1:0`, accepts one WebSocket connection and runs the Noise **initiator** side
//! with `snow`, exactly as a real server does: `server/init`, Noise message 1, read message 2,
//! `server/hello`, `server/activate`, then a command loop that sends streams, metadata and audio.
//! Nothing leaves the loopback interface and no audio device is involved.
//!
//! The file is also compiled as its own test target (it has no tests of its own), so not every
//! helper is used by every binary.
#![allow(dead_code)]

use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use snow::{Builder, HandshakeState, Keypair, TransportState as SnowTransport};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{accept_async, WebSocketStream};

use syncspin_core::framing::{split_binary, MAX_PLAINTEXT_LEN};
use syncspin_core::messages::{
    ClientCommand, ClientHello, ClientState, ClientTime, Incoming, Metadata, NoiseHandshake,
    PairingActivation, ServerActivate, ServerHello, ServerPairFinalize, ServerState, ServerTime,
    StreamClear, StreamEnd, StreamStart, StreamStartPlayer,
};
use syncspin_core::noise::{
    psk_id_for, MAX_MESSAGE_LEN, NOISE_PARAMS, SENTINEL_PSK, SENTINEL_PSK_ID,
};

type Socket = WebSocketStream<TcpStream>;

/// How the fake server announces its key and which key it actually uses.
pub struct ServerOptions {
    /// PSK id announced in Noise message 1; defaults to the Sentinel id.
    pub psk_id: String,
    /// Category announced in Noise message 1.
    pub psk_category: String,
    /// Key the initiator actually seals the handshake with.
    pub psk: [u8; 32],
    /// Raw message 1 payload, overriding `psk_id`/`psk_category` when set.
    pub metadata: Option<String>,
    /// Whether the Noise handshake starts at all.
    ///
    /// With `false` the server answers `server/init` and then waits, which is the "a server that
    /// does not speak the protocol" case.
    pub start_handshake: bool,
    /// Roles the first `server/activate` announces.
    pub active_roles: Vec<String>,
    /// How many `client/time` requests to answer; `None` answers all, `Some(0)` none.
    pub answer_time_limit: Option<usize>,
    /// Whether `client/time` requests are reported but not answered until the test asks.
    pub manual_time: bool,
    /// How many connections the server accepts before it stops listening.
    ///
    /// The client reconnects on its own, so a test that exercises that sets this above one.
    pub connections: usize,
    /// Whether connections after the first omit `active_roles` in their first `server/activate`.
    ///
    /// The first connection always announces them, so a test can seed the client with roles and
    /// then reconnect into an activation that carries none.
    pub omit_active_roles_after_the_first: bool,
    /// Text sent instead of the normal `server/init` document.
    pub server_init_override: Option<String>,
    /// Version written into `server/init`; the protocol defines one.
    pub server_version: u32,
    /// Text sent instead of the normal `noise/handshake` message 1.
    pub message_1_override: Option<String>,
    /// Whether an empty binary frame is sent before `server/init`, which the handshake must skip.
    pub binary_before_init: bool,
    /// Whether the connection is closed right after `client/init`, before `server/init`.
    pub close_before_init: bool,
    /// Plaintexts sent as encrypted frames after message 2 and before `server/hello`.
    pub pre_hello_plaintexts: Vec<Vec<u8>>,
    /// Whether a cleartext text frame is sent after message 2 and before `server/hello`.
    pub cleartext_after_message_2: bool,
    /// Whether the connection is closed after message 2 instead of sending `server/hello`.
    pub close_after_message_2: bool,
    /// Text sent as the first encrypted message instead of `server/hello`.
    pub hello_override: Option<String>,
    /// Text sent as the activation instead of the normal `server/activate`.
    pub activate_override: Option<String>,
    /// Full activation sent as the first `server/activate`, overriding the built one.
    ///
    /// A typed alternative to [`activate_override`](ServerOptions::activate_override), for the
    /// activation that carries a pairing attempt.
    pub first_activate: Option<ServerActivate>,
    /// Whether `client/pair-finalize` is answered with `server/pair-finalize`.
    ///
    /// With `false` the attempt hangs, which is what a server that went silent looks like.
    pub acknowledge_pairing: bool,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            psk_id: SENTINEL_PSK_ID.to_owned(),
            psk_category: "sn".to_owned(),
            psk: SENTINEL_PSK,
            metadata: None,
            start_handshake: true,
            active_roles: vec![
                "player@v1".to_owned(),
                "controller@v1".to_owned(),
                "metadata@v1".to_owned(),
            ],
            answer_time_limit: None,
            manual_time: false,
            connections: 1,
            omit_active_roles_after_the_first: false,
            server_init_override: None,
            server_version: 1,
            message_1_override: None,
            binary_before_init: false,
            close_before_init: false,
            pre_hello_plaintexts: Vec::new(),
            cleartext_after_message_2: false,
            close_after_message_2: false,
            hello_override: None,
            activate_override: None,
            first_activate: None,
            acknowledge_pairing: true,
        }
    }
}

/// One instruction for the running server.
pub enum Command {
    /// Sends an arbitrary JSON control message, encrypted.
    Json(String),
    /// Sends `stream/start`.
    StreamStart {
        codec: &'static str,
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
        codec_header: Option<String>,
    },
    /// Sends `stream/end` for the given roles (`None` means every role).
    StreamEnd { roles: Option<Vec<String>> },
    /// Sends `stream/clear`.
    StreamClear { from_timestamp: Option<i64> },
    /// Sends `server/activate` with a new role set.
    Activate(Vec<String>),
    /// Sends a complete `server/activate`, including a pairing attempt.
    ActivateMessage(Box<ServerActivate>),
    /// Sends `server/state` with title and artist.
    Metadata {
        title: &'static str,
        artist: &'static str,
    },
    /// Sends one audio chunk.
    Audio {
        timestamp_us: i64,
        send_ahead: u32,
        data: Vec<u8>,
    },
    /// Sends a raw transport plaintext, for malformed frames a structured command cannot build.
    Binary(Vec<u8>),
    /// Sends a cleartext WebSocket text frame.
    Text(String),
    /// Sends a WebSocket ping.
    Ping(Vec<u8>),
    /// Sends an unsolicited WebSocket pong.
    Pong(Vec<u8>),
    /// Answers the outstanding `client/time` request with this transmit timestamp.
    AnswerTime(i64),
    /// Closes the WebSocket cleanly.
    Close,
}

/// The long-term PSK a pairing delivered, as the harness sees it.
///
/// The raw bytes are what a test compares against the client's record; `Debug` prints `<redacted>`
/// so a failing assertion that formats an [`Observation`] cannot write key material into a log.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PairingKey(pub [u8; 32]);

impl fmt::Debug for PairingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Something the server observed on the connection.
#[derive(Debug)]
pub enum Observation {
    /// Noise message 2 arrived and authenticated with the server's key.
    HandshakeMessage2,
    /// Noise message 2 arrived but did not authenticate.
    HandshakeMessage2Rejected(String),
    /// The client closed before sending Noise message 2.
    ClosedBeforeMessage2,
    /// The client announced itself.
    ClientHello(Box<ClientHello>),
    /// The client reported its state.
    ClientState(Box<ClientState>),
    /// The client sent a command for one of its active roles.
    ClientCommand(Box<ClientCommand>),
    /// The server answered the nth `client/time` request.
    TimeReply(usize),
    /// A `client/time` request arrived and is waiting for a manual answer.
    TimeRequest(i64),
    /// The client started a pairing attempt.
    PairInit {
        /// Index the client reported for the activation that admitted the attempt.
        pairing_index: u32,
    },
    /// The client delivered the long-term PSK of a pairing.
    PairFinalize {
        /// The key the client proposed; the server stores it as its record.
        long_term_psk: PairingKey,
    },
    /// The client aborted a pairing attempt, with the reason it reported.
    PairingAborted(String),
    /// The connection closed.
    Closed,
}

/// A started fake server.
pub struct FakeServer {
    address: SocketAddr,
    server_id: String,
    commands: UnboundedSender<Command>,
    observations: UnboundedReceiver<Observation>,
    task: JoinHandle<()>,
}

impl FakeServer {
    /// Binds an ephemeral loopback port and starts serving in the background.
    pub async fn start(options: ServerOptions) -> Result<FakeServer> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("failed to bind the loopback listener")?;
        let address = listener.local_addr()?;
        let keypair = Builder::new(NOISE_PARAMS.parse()?)
            .generate_keypair()
            .context("failed to generate the server keypair")?;
        let server_id = URL_SAFE_NO_PAD.encode(&keypair.public);

        let (commands, command_rx) = mpsc::unbounded_channel();
        let (observation_tx, observations) = mpsc::unbounded_channel();
        // The server-side record of one completed pairing: the key the next handshake announces.
        let paired = Arc::new(Mutex::new(None));
        let task = tokio::spawn(async move {
            if let Err(error) = serve(
                listener,
                keypair,
                options,
                command_rx,
                observation_tx,
                paired,
            )
            .await
            {
                // A test that waits for an observation fails with its own timeout; the reason is
                // printed to make that failure diagnosable.
                eprintln!("fake server stopped: {error:#}");
            }
        });

        Ok(FakeServer {
            address,
            server_id,
            commands,
            observations,
            task,
        })
    }

    /// The `host:port` address to put into [`syncspin_client::ClientConfig::server`].
    pub fn endpoint(&self) -> String {
        self.address.to_string()
    }

    /// The server's static public key, as the client should report it.
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Sends one arbitrary control message.
    pub fn json(&self, body: impl Into<String>) {
        let _ = self.commands.send(Command::Json(body.into()));
    }

    /// Sends `stream/start` with the given format and no codec header.
    pub fn stream_start(&self, codec: &'static str, sample_rate: u32, channels: u8, bit_depth: u8) {
        self.stream_start_with_header(codec, sample_rate, channels, bit_depth, None);
    }

    /// Sends `stream/start` with a codec header, encoded as standard base64.
    pub fn stream_start_with_header(
        &self,
        codec: &'static str,
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
        codec_header: Option<&[u8]>,
    ) {
        let _ = self.commands.send(Command::StreamStart {
            codec,
            sample_rate,
            channels,
            bit_depth,
            codec_header: codec_header.map(|header| STANDARD.encode(header)),
        });
    }

    /// Sends `stream/end` for every role.
    pub fn stream_end(&self) {
        let _ = self.commands.send(Command::StreamEnd { roles: None });
    }

    /// Sends `stream/end` for the given roles only.
    pub fn stream_end_for(&self, roles: &[&str]) {
        let _ = self.commands.send(Command::StreamEnd {
            roles: Some(roles.iter().map(|role| (*role).to_owned()).collect()),
        });
    }

    /// Answers the outstanding clock request manually.
    pub fn answer_time(&self, client_transmitted: i64) {
        let _ = self.commands.send(Command::AnswerTime(client_transmitted));
    }

    /// Waits until a `client/time` request arrives and returns its transmit timestamp.
    pub async fn next_time_request(&mut self) -> Option<i64> {
        loop {
            match self.observation().await {
                Some(Observation::TimeRequest(client_transmitted)) => {
                    return Some(client_transmitted)
                }
                Some(_) => continue,
                None => return None,
            }
        }
    }

    /// Sends `stream/clear`, optionally from a server timestamp.
    pub fn stream_clear(&self, from_timestamp: Option<i64>) {
        let _ = self.commands.send(Command::StreamClear { from_timestamp });
    }

    /// Sends `server/activate` with a new role set.
    pub fn activate(&self, roles: &[&str]) {
        let _ = self.commands.send(Command::Activate(
            roles.iter().map(|role| (*role).to_owned()).collect(),
        ));
    }

    /// Sends `server/activate` that admits a pairing attempt with `method`.
    ///
    /// The activation declares the pairing activity, no roles, and the method; the client answers
    /// with `client/pair-init` or with `pair/abort`.
    pub fn activate_pairing(&self, method: &str) {
        let _ = self
            .commands
            .send(Command::ActivateMessage(Box::new(ServerActivate {
                activities: vec!["pairing".to_owned()],
                active_roles: Some(Vec::new()),
                pairing: Some(PairingActivation {
                    method: method.to_owned(),
                    format: None,
                }),
            })));
    }

    /// Sends `server/activate` that ends the pairing transition without finalizing it.
    pub fn cancel_pairing(&self, roles: &[&str]) {
        let _ = self
            .commands
            .send(Command::ActivateMessage(Box::new(ServerActivate {
                activities: vec!["playback".to_owned()],
                active_roles: Some(roles.iter().map(|role| (*role).to_owned()).collect()),
                pairing: None,
            })));
    }

    /// Sends `server/state` with the given metadata.
    pub fn metadata(&self, title: &'static str, artist: &'static str) {
        let _ = self.commands.send(Command::Metadata { title, artist });
    }

    /// Sends one audio chunk.
    pub fn audio(&self, timestamp_us: i64, send_ahead: u32, data: Vec<u8>) {
        let _ = self.commands.send(Command::Audio {
            timestamp_us,
            send_ahead,
            data,
        });
    }

    /// Sends a WebSocket ping control frame.
    pub fn ping(&self, payload: Vec<u8>) {
        let _ = self.commands.send(Command::Ping(payload));
    }

    /// Sends an unsolicited WebSocket pong control frame.
    pub fn pong(&self, payload: Vec<u8>) {
        let _ = self.commands.send(Command::Pong(payload));
    }

    /// Sends a cleartext text frame after the handshake.
    pub fn text(&self, text: impl Into<String>) {
        let _ = self.commands.send(Command::Text(text.into()));
    }

    /// Sends a raw plaintext as one Noise transport message.
    pub fn binary(&self, plaintext: Vec<u8>) {
        let _ = self.commands.send(Command::Binary(plaintext));
    }

    /// Closes the connection cleanly.
    pub fn close(&self) {
        let _ = self.commands.send(Command::Close);
    }

    /// Waits for the next thing the server observed.
    pub async fn observation(&mut self) -> Option<Observation> {
        self.observations.recv().await
    }

    /// Waits until at least `count` clock requests were answered.
    pub async fn wait_for_time_replies(&mut self, count: usize) -> bool {
        loop {
            match self.observation().await {
                Some(Observation::TimeReply(answered)) if answered >= count => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    }

    /// Waits until the client announces itself.
    pub async fn wait_for_client_hello(&mut self) -> Option<ClientHello> {
        loop {
            match self.observation().await {
                Some(Observation::ClientHello(hello)) => return Some(*hello),
                Some(_) => continue,
                None => return None,
            }
        }
    }

    /// Waits until the client reports its player state.
    pub async fn wait_for_client_state(&mut self) -> Option<ClientState> {
        loop {
            match self.observation().await {
                Some(Observation::ClientState(state)) => return Some(*state),
                Some(_) => continue,
                None => return None,
            }
        }
    }

    /// Waits until the client sends a command for one of its active roles.
    pub async fn wait_for_client_command(&mut self) -> Option<ClientCommand> {
        loop {
            match self.observation().await {
                Some(Observation::ClientCommand(command)) => return Some(*command),
                Some(_) => continue,
                None => return None,
            }
        }
    }

    /// Waits until Noise message 2 arrives and authenticates.
    pub async fn wait_for_message_2(&mut self) -> bool {
        loop {
            match self.observation().await {
                Some(Observation::HandshakeMessage2) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    }

    /// Waits until the client starts a pairing attempt and returns its `pairing_index`.
    pub async fn wait_for_pair_init(&mut self) -> Option<u32> {
        loop {
            match self.observation().await {
                Some(Observation::PairInit { pairing_index }) => return Some(pairing_index),
                Some(_) => continue,
                None => return None,
            }
        }
    }

    /// Waits until the client delivers a pairing's long-term PSK.
    pub async fn wait_for_pair_finalize(&mut self) -> Option<PairingKey> {
        loop {
            match self.observation().await {
                Some(Observation::PairFinalize { long_term_psk }) => return Some(long_term_psk),
                Some(_) => continue,
                None => return None,
            }
        }
    }

    /// Waits until the client aborts a pairing attempt and returns the reason it sent.
    pub async fn wait_for_pairing_abort(&mut self) -> Option<String> {
        loop {
            match self.observation().await {
                Some(Observation::PairingAborted(reason)) => return Some(reason),
                Some(_) => continue,
                None => return None,
            }
        }
    }

    /// Waits until the server task ends.
    pub async fn finished(self) {
        let _ = self.task.await;
    }
}

/// Accepts the configured number of connections and serves each until it closes.
async fn serve(
    listener: TcpListener,
    keypair: Keypair,
    options: ServerOptions,
    mut commands: UnboundedReceiver<Command>,
    observations: UnboundedSender<Observation>,
    paired: Arc<Mutex<Option<[u8; 32]>>>,
) -> Result<()> {
    for index in 0..options.connections {
        let (tcp, _peer) = listener
            .accept()
            .await
            .context("the client never connected")?;
        let socket = accept_async(tcp)
            .await
            .context("the WebSocket upgrade failed")?;
        let announce_roles = index == 0 || !options.omit_active_roles_after_the_first;
        serve_connection(
            socket,
            &keypair,
            &options,
            &mut commands,
            &observations,
            announce_roles,
            &paired,
        )
        .await?;
    }
    Ok(())
}

/// Serves one accepted WebSocket until it closes.
async fn serve_connection(
    mut socket: Socket,
    keypair: &Keypair,
    options: &ServerOptions,
    commands: &mut UnboundedReceiver<Command>,
    observations: &UnboundedSender<Observation>,
    announce_roles: bool,
    paired: &Arc<Mutex<Option<[u8; 32]>>>,
) -> Result<()> {
    // 1. client/init, whose exact bytes start the Noise prologue.
    let client_init_text = read_text(&mut socket).await?;
    let client_init = match Incoming::parse(&client_init_text)? {
        Some(Incoming::ClientInit(client_init)) => client_init,
        _ => bail!("expected client/init"),
    };
    let client_public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&client_init.client_id)
        .context("client_id is not unpadded base64url")?
        .try_into()
        .map_err(|_| anyhow!("client_id does not decode to 32 bytes"))?;

    if options.close_before_init {
        socket.close(None).await?;
        let _ = observations.send(Observation::Closed);
        return Ok(());
    }
    if options.binary_before_init {
        // A binary frame before the Noise transport carries nothing and has to be skipped.
        socket.send(Message::binary(vec![0, 1, 2])).await?;
    }

    // 2. server/init, whose exact bytes complete the prologue.
    let server_init_text = options.server_init_override.clone().unwrap_or_else(|| {
        serde_json::json!({
            "type": "server/init",
            "payload": {
                "server_id": URL_SAFE_NO_PAD.encode(&keypair.public),
                "version": options.server_version,
            },
        })
        .to_string()
    });
    send_text(&mut socket, &server_init_text).await?;

    if !options.start_handshake {
        // Stay connected without starting Noise. The client must give up instead of downgrading.
        while let Some(message) = socket.next().await {
            match message {
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        let _ = observations.send(Observation::Closed);
        return Ok(());
    }

    // 3. Noise message 1, sent as the initiator. A completed pairing promotes the announced key:
    // the server persists the record and the next handshake references it as a long-term key.
    let paired_psk = *paired
        .lock()
        .expect("the fake server's record lock is not poisoned");
    let (psk, psk_id, psk_category) = match paired_psk {
        Some(psk) => (psk, psk_id_for(&psk), "lt".to_owned()),
        None => (
            options.psk,
            options.psk_id.clone(),
            options.psk_category.clone(),
        ),
    };
    let mut prologue = client_init_text.into_bytes();
    prologue.extend_from_slice(server_init_text.as_bytes());
    let mut initiator = Builder::new(NOISE_PARAMS.parse()?)
        .local_private_key(&keypair.private)?
        .remote_public_key(&client_public)?
        .psk(2, &psk)?
        .prologue(&prologue)?
        .build_initiator()
        .context("failed to build the Noise initiator")?;

    let metadata = match options.metadata.as_deref() {
        Some(metadata) => metadata.to_owned(),
        None => format!(r#"{{"psk_id":"{psk_id}","psk_category":"{psk_category}"}}"#),
    };
    let message_1 = write_handshake(&mut initiator, metadata.as_bytes())?;
    let message_1 = options.message_1_override.clone().unwrap_or_else(|| {
        serde_json::to_string(&Incoming::NoiseHandshake(NoiseHandshake {
            data: URL_SAFE_NO_PAD.encode(message_1),
        }))
        .expect("a handshake envelope encodes")
    });
    send_text(&mut socket, &message_1).await?;

    // 4. Noise message 2. A client that rejects the metadata closes without sending it.
    let message_2_text = match socket.next().await {
        Some(Ok(Message::Text(text))) => text.as_str().to_owned(),
        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
            let _ = observations.send(Observation::ClosedBeforeMessage2);
            return Ok(());
        }
        Some(Ok(other)) => bail!("expected noise/handshake message 2, got {other:?}"),
    };
    let message_2 = match Incoming::parse(&message_2_text)? {
        Some(Incoming::NoiseHandshake(handshake)) => URL_SAFE_NO_PAD
            .decode(&handshake.data)
            .context("message 2 is not unpadded base64url")?,
        _ => bail!("expected noise/handshake message 2"),
    };
    let mut payload = vec![0u8; MAX_MESSAGE_LEN];
    match initiator.read_message(&message_2, &mut payload) {
        Ok(_) => {
            let _ = observations.send(Observation::HandshakeMessage2);
        }
        Err(error) => {
            let _ = observations.send(Observation::HandshakeMessage2Rejected(error.to_string()));
            return Ok(());
        }
    }
    let mut noise = initiator
        .into_transport_mode()
        .context("failed to finish the Noise handshake")?;

    if options.close_after_message_2 {
        socket.close(None).await?;
        let _ = observations.send(Observation::Closed);
        return Ok(());
    }
    for plaintext in &options.pre_hello_plaintexts {
        let ciphertext = encrypt(&mut noise, plaintext)?;
        socket.send(Message::binary(ciphertext)).await?;
    }
    if options.cleartext_after_message_2 {
        send_text(&mut socket, "{}").await?;
    }

    // 5. server/hello.
    match options.hello_override.as_deref() {
        Some(hello) => send_raw_json(&mut socket, &mut noise, hello).await?,
        None => {
            send_encrypted(
                &mut socket,
                &mut noise,
                &Incoming::ServerHello(ServerHello {
                    name: "Test server".to_owned(),
                    languages: None,
                }),
            )
            .await?
        }
    }

    // 6. client/hello.
    let hello = read_encrypted_json(&mut socket, &mut noise).await?;
    match Incoming::parse(&hello)? {
        Some(Incoming::ClientHello(hello)) => {
            let _ = observations.send(Observation::ClientHello(Box::new(hello)));
        }
        _ => bail!("expected client/hello"),
    }

    // 7. server/activate with the announced roles. A typed first activation belongs to the
    // connection before a record exists: once the server holds a pairing, the connection is a
    // normal playback connection and activating the pairing activity on it would be inadmissible.
    if let Some(activate) = options
        .first_activate
        .clone()
        .filter(|_| paired_psk.is_none())
    {
        send_encrypted(&mut socket, &mut noise, &Incoming::ServerActivate(activate)).await?;
    } else if let Some(activate) = options.activate_override.as_deref() {
        send_raw_json(&mut socket, &mut noise, activate).await?;
    } else {
        send_encrypted(
            &mut socket,
            &mut noise,
            &Incoming::ServerActivate(ServerActivate {
                activities: vec!["playback".to_owned()],
                active_roles: announce_roles.then(|| options.active_roles.clone()),
                pairing: None,
            }),
        )
        .await?;
    }

    // 8. Serve until a close.
    let mut answered_time = 0usize;
    loop {
        // The two sources are turned into one event first, so the socket is only borrowed by the
        // select itself and the handlers can still write to it.
        let event = tokio::select! {
            message = socket.next() => LinkEvent::Socket(message),
            command = commands.recv() => LinkEvent::Command(command),
        };
        match event {
            LinkEvent::Socket(Some(Ok(Message::Binary(bytes)))) => {
                let plaintext = decrypt(&mut noise, &bytes)?;
                handle_client_message(
                    &plaintext,
                    &mut socket,
                    &mut noise,
                    options,
                    &mut answered_time,
                    observations,
                    paired,
                )
                .await?;
            }
            LinkEvent::Socket(Some(Ok(Message::Ping(payload)))) => {
                socket.send(Message::Pong(payload)).await?;
            }
            LinkEvent::Socket(Some(Ok(Message::Close(_))) | None | Some(Err(_))) => {
                let _ = observations.send(Observation::Closed);
                return Ok(());
            }
            LinkEvent::Socket(Some(Ok(_))) => {}
            LinkEvent::Command(Some(Command::Json(body))) => {
                // Sent verbatim so a test can put a malformed or unknown message on the wire.
                send_raw_json(&mut socket, &mut noise, &body).await?;
            }
            LinkEvent::Command(Some(Command::StreamStart {
                codec,
                sample_rate,
                channels,
                bit_depth,
                codec_header,
            })) => {
                send_encrypted(
                    &mut socket,
                    &mut noise,
                    &Incoming::StreamStart(StreamStart {
                        server_transmitted: now_us(),
                        player: Some(StreamStartPlayer {
                            codec: codec.to_owned(),
                            sample_rate,
                            channels,
                            bit_depth,
                            codec_header,
                        }),
                    }),
                )
                .await?;
            }
            LinkEvent::Command(Some(Command::StreamEnd { roles })) => {
                send_encrypted(
                    &mut socket,
                    &mut noise,
                    &Incoming::StreamEnd(StreamEnd { roles }),
                )
                .await?;
            }
            LinkEvent::Command(Some(Command::AnswerTime(client_transmitted))) => {
                let reply = answer_time(ClientTime { client_transmitted });
                send_encrypted(&mut socket, &mut noise, &reply).await?;
            }
            LinkEvent::Command(Some(Command::StreamClear { from_timestamp })) => {
                send_encrypted(
                    &mut socket,
                    &mut noise,
                    &Incoming::StreamClear(StreamClear {
                        server_transmitted: now_us(),
                        from_timestamp,
                        roles: None,
                    }),
                )
                .await?;
            }
            LinkEvent::Command(Some(Command::Activate(roles))) => {
                send_encrypted(
                    &mut socket,
                    &mut noise,
                    &Incoming::ServerActivate(ServerActivate {
                        activities: Vec::new(),
                        active_roles: Some(roles),
                        pairing: None,
                    }),
                )
                .await?;
            }
            LinkEvent::Command(Some(Command::ActivateMessage(activate))) => {
                send_encrypted(
                    &mut socket,
                    &mut noise,
                    &Incoming::ServerActivate(*activate),
                )
                .await?;
            }
            LinkEvent::Command(Some(Command::Metadata { title, artist })) => {
                send_encrypted(
                    &mut socket,
                    &mut noise,
                    &Incoming::ServerState(ServerState {
                        metadata: Some(Metadata {
                            title: Some(title.to_owned()),
                            artist: Some(artist.to_owned()),
                            ..Metadata::default()
                        }),
                        controller: None,
                    }),
                )
                .await?;
            }
            LinkEvent::Command(Some(Command::Audio {
                timestamp_us,
                send_ahead,
                data,
            })) => {
                // The header plus audio travels as one message, fragmented when it does not fit
                // one Noise plaintext, exactly as the framing layer specifies.
                let mut payload = Vec::with_capacity(12 + data.len());
                payload.extend_from_slice(&timestamp_us.to_be_bytes());
                payload.extend_from_slice(&send_ahead.to_be_bytes());
                payload.extend_from_slice(&data);
                for frame in split_binary(
                    syncspin_core::messages::AUDIO_CHUNK_ID,
                    &payload,
                    MAX_PLAINTEXT_LEN,
                ) {
                    let ciphertext = encrypt(&mut noise, &frame)?;
                    socket.send(Message::binary(ciphertext)).await?;
                }
            }
            LinkEvent::Command(Some(Command::Binary(plaintext))) => {
                let ciphertext = encrypt(&mut noise, &plaintext)?;
                socket.send(Message::binary(ciphertext)).await?;
            }
            LinkEvent::Command(Some(Command::Text(text))) => {
                send_text(&mut socket, &text).await?;
            }
            LinkEvent::Command(Some(Command::Ping(payload))) => {
                socket.send(Message::Ping(payload.into())).await?;
            }
            LinkEvent::Command(Some(Command::Pong(payload))) => {
                socket.send(Message::Pong(payload.into())).await?;
            }
            LinkEvent::Command(Some(Command::Close)) | LinkEvent::Command(None) => {
                socket.close(None).await?;
                let _ = observations.send(Observation::Closed);
                return Ok(());
            }
        }
    }
}

/// One wake-up of the server's select loop.
enum LinkEvent {
    /// A frame arrived from the client.
    Socket(Option<std::result::Result<Message, WsError>>),
    /// A test asked for something to be sent.
    Command(Option<Command>),
}

/// Answers the messages a client sends after the handshake.
#[allow(clippy::too_many_arguments)]
async fn handle_client_message(
    plaintext: &[u8],
    socket: &mut Socket,
    noise: &mut SnowTransport,
    options: &ServerOptions,
    answered_time: &mut usize,
    observations: &UnboundedSender<Observation>,
    paired: &Arc<Mutex<Option<[u8; 32]>>>,
) -> Result<()> {
    let Some(&0) = plaintext.first() else {
        return Ok(());
    };
    let text = std::str::from_utf8(&plaintext[1..]).context("client JSON is not UTF-8")?;
    match Incoming::parse(text)? {
        Some(Incoming::ClientTime(request)) => {
            if options.manual_time {
                let _ = observations.send(Observation::TimeRequest(request.client_transmitted));
            } else if options
                .answer_time_limit
                .is_none_or(|limit| *answered_time < limit)
            {
                *answered_time += 1;
                let reply = answer_time(request);
                send_encrypted(socket, noise, &reply).await?;
                let _ = observations.send(Observation::TimeReply(*answered_time));
            }
        }
        Some(Incoming::ClientState(state)) => {
            let _ = observations.send(Observation::ClientState(Box::new(state)));
        }
        Some(Incoming::ClientCommand(command)) => {
            let _ = observations.send(Observation::ClientCommand(Box::new(command)));
        }
        Some(Incoming::ClientPairInit(init)) => {
            let _ = observations.send(Observation::PairInit {
                pairing_index: init.pairing_index,
            });
        }
        Some(Incoming::ClientPairFinalize(finalize)) => {
            // The Pairing PSK flow carries the key directly; the wrapped form belongs to the code
            // flows this harness does not speak.
            let Some(encoded) = finalize.long_term_psk.as_deref() else {
                bail!(
                    "client/pair-finalize carried no long_term_psk; this harness speaks the \
                     Pairing PSK flow only"
                );
            };
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .context("long_term_psk is not unpadded base64url")?;
            let long_term_psk: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("long_term_psk is not 32 bytes"))?;
            if long_term_psk == SENTINEL_PSK {
                bail!("the client delivered the published Sentinel key as a long-term PSK");
            }
            // The server persists its record: the next handshake announces this key as `lt`.
            *paired
                .lock()
                .expect("the fake server's record lock is not poisoned") = Some(long_term_psk);
            let _ = observations.send(Observation::PairFinalize {
                long_term_psk: PairingKey(long_term_psk),
            });
            if options.acknowledge_pairing {
                send_encrypted(
                    socket,
                    noise,
                    &Incoming::ServerPairFinalize(ServerPairFinalize {}),
                )
                .await?;
            }
        }
        Some(Incoming::PairAbort(abort)) => {
            let _ = observations.send(Observation::PairingAborted(abort.reason));
        }
        // `client/hello`, `client/time` while answers are disabled, and future types.
        _ => {}
    }
    Ok(())
}

/// Builds a `server/time` reply whose two server timestamps read the local clock.
fn answer_time(request: ClientTime) -> Incoming {
    Incoming::ServerTime(ServerTime {
        client_transmitted: request.client_transmitted,
        server_received: now_us(),
        server_transmitted: now_us(),
    })
}

/// Reads the next text frame, answering pings.
async fn read_text(socket: &mut Socket) -> Result<String> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => return Ok(text.as_str().to_owned()),
            Some(Ok(Message::Ping(payload))) => socket.send(Message::Pong(payload)).await?,
            Some(Ok(Message::Close(_))) | None => bail!("the client closed during the handshake"),
            Some(Ok(other)) => bail!("expected a text frame, got {other:?}"),
            Some(Err(error)) => return Err(error.into()),
        }
    }
}

/// Reads frames until the next encrypted JSON control message.
async fn read_encrypted_json(socket: &mut Socket, noise: &mut SnowTransport) -> Result<String> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                let plaintext = decrypt(noise, &bytes)?;
                if plaintext.first() == Some(&0) {
                    return String::from_utf8(plaintext[1..].to_vec())
                        .context("client JSON is not UTF-8");
                }
            }
            Some(Ok(Message::Ping(payload))) => socket.send(Message::Pong(payload)).await?,
            Some(Ok(Message::Close(_))) | None => {
                bail!("the client closed before client/hello")
            }
            Some(Ok(other)) => bail!("expected an encrypted frame, got {other:?}"),
            Some(Err(error)) => return Err(error.into()),
        }
    }
}

/// Sends one control message through the Noise transport.
async fn send_encrypted(
    socket: &mut Socket,
    noise: &mut SnowTransport,
    message: &Incoming,
) -> Result<()> {
    let text = serde_json::to_string(message).context("failed to encode a server message")?;
    send_raw_json(socket, noise, &text).await
}

/// Sends one JSON body through the Noise transport, verbatim.
async fn send_raw_json(socket: &mut Socket, noise: &mut SnowTransport, body: &str) -> Result<()> {
    let mut plaintext = vec![0u8];
    plaintext.extend_from_slice(body.as_bytes());
    let ciphertext = encrypt(noise, &plaintext)?;
    socket.send(Message::binary(ciphertext)).await?;
    Ok(())
}

/// Sends one cleartext JSON text frame.
async fn send_text(socket: &mut Socket, text: &str) -> Result<()> {
    socket.send(Message::text(text)).await?;
    Ok(())
}

/// Writes one Noise handshake message.
fn write_handshake(handshake: &mut HandshakeState, payload: &[u8]) -> Result<Vec<u8>> {
    let mut message = vec![0u8; MAX_MESSAGE_LEN];
    let len = handshake
        .write_message(payload, &mut message)
        .context("failed to write a Noise handshake message")?;
    message.truncate(len);
    Ok(message)
}

/// Encrypts one Noise transport message.
fn encrypt(noise: &mut SnowTransport, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut message = vec![0u8; MAX_MESSAGE_LEN];
    let len = noise
        .write_message(plaintext, &mut message)
        .context("failed to encrypt a transport message")?;
    message.truncate(len);
    Ok(message)
}

/// Decrypts one Noise transport message.
fn decrypt(noise: &mut SnowTransport, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut plaintext = vec![0u8; MAX_MESSAGE_LEN];
    let len = noise
        .read_message(ciphertext, &mut plaintext)
        .context("failed to decrypt a transport message")?;
    plaintext.truncate(len);
    Ok(plaintext)
}

/// Current wall clock in microseconds since the Unix epoch.
fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_observation_formats_without_the_paired_key() {
        let key = PairingKey([0x5a; 32]);
        let text = format!("{:?}", Observation::PairFinalize { long_term_psk: key });
        assert!(text.contains("<redacted>"), "unexpected format: {text}");
        assert!(
            !text.contains("0x5a"),
            "not even the raw bytes may appear: {text}"
        );
        assert!(
            !text.contains(&format!("{:?}", [0x5a; 32])),
            "not even the raw bytes may appear: {text}"
        );
    }
}
