//! Server side of Sendspin.
//!
//! A server accepts client connections, runs the Noise handshake as its initiator and owns what
//! happens on the connection afterwards. This crate is the protocol and the transport; a host that
//! has audio to distribute drives the handle [`Server::start`] returns and follows the connections
//! through the [`Event`] stream.
//!
//! What exists today: the listener, the three roles a player needs, one group and one stream, the
//! three pairing methods and the approval gate. A client connects, `client/init` is answered with
//! `server/init` and Noise message 1, the handshake completes, and the server sends `server/hello`,
//! `server/activate` with the roles that connection may use, `server/state` and `group/update`.
//! Every member of the group receives the same stream frames with the same playout timestamps, and
//! each one measures its own offset by sending `client/time`, which the server answers with the
//! receive and transmit stamps of the request. The host pushes audio into a [`StreamWriter`]; the
//! server stamps every chunk with the server-clock playout timestamp and fans it out. Volume, mute
//! and playback belong to the group, and a member's `client/state` is a report rather than a
//! command: the group takes from it only whether the member is available and has reported the
//! `player` object its activation requires, which is what a stream waits for.
//!
//! # Pairing and approval
//!
//! A client whose `client_id` the host's [`PairingStore`] holds a record for is authenticated by
//! that record and activated at once. Every other client is unpaired: `pairing.md` requires the
//! operator to approve it before the server may activate roles or declare `playback`, so it is
//! admitted at empty activities, reported to the host with `approved: false`, and activated by
//! [`ServerHandle::approve`]. Approval is remembered per `client_id` and dropped on a successful
//! pairing.
//!
//! All three methods are here. [`ServerHandle::pair`] takes the version-0 token an operator copies
//! from the client, re-handshakes the live connection to the pairing PSK it carries and runs the
//! Pairing PSK flow. [`ServerHandle::start_pairing`] admits a static or dynamic code attempt, the
//! client emits its code, and [`ServerHandle::submit_code`] runs the CPace round with the server as
//! role `A`. The code flows need CPace, so they are behind the `pairing-code` feature; a build
//! without it refuses them.
//!
//! Several groups do not exist yet. Discovery does: a host supplies a [`Discovery`] backend and
//! the server advertises `_sendspin-server._tcp`, browses `_sendspin._tcp` and dials every client
//! it finds. The `mdns` feature carries the mDNS implementation.
//!
//! Every connection is encrypted. A client that does not complete the Noise handshake is refused
//! and there is no plaintext path, not behind a flag, not in a test. A `client/init` the server
//! cannot accept is answered with `server/error` and a close; every later handshake failure is
//! silent, as the specification requires.
//!
//! The crate is published from the same tag as `syncspin-core` and `syncspin-client`; see the
//! workspace README for the release order.

mod discovery;
mod group;
mod listener;
mod pairing;
mod stream;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::group::Group;

// The identity is part of [`ServerConfig`], so a host that builds a configuration needs it. A
// re-export keeps a consumer from having to depend on the protocol crate directly.
pub use syncspin_core::noise::Identity;

#[cfg(feature = "mdns")]
pub use crate::discovery::MdnsDiscovery;
pub use crate::discovery::{
    discover_clients, DiscoveredClient, Discovery, ServiceAdvertisement, CLIENT_SERVICE_TYPE,
    DEFAULT_SENDSPIN_PATH, SERVER_SERVICE_TYPE,
};
pub use crate::pairing::{
    CodeFormat, PairingMethod, PairingRecord, PairingStore, DEFAULT_PAIRING_TIMEOUT,
};
pub use crate::stream::{AudioFormat, Codec, StreamWriter, TrackInfo};

/// The address the listener binds when the configuration does not narrow it.
///
/// Encryption is the boundary, not the bind address: a server that listens on every interface is
/// still only reachable by a client that completes the handshake.
pub const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8927);

/// The WebSocket endpoint the listener serves when the configuration does not name one.
pub const DEFAULT_PATH: &str = "/sendspin";

/// Longest server name `server/hello` may carry, in bytes of UTF-8.
pub const MAX_SERVER_NAME_LEN: usize = 64;

/// Everything a server needs to listen, identify itself and keep its pairing records.
///
/// [`ServerConfig::new`] fills in the defaults for the address, the endpoint path and the stream
/// format; the identity belongs to the host, which stores it and keeps it across restarts because
/// the public half is the `server_id` every client associates its pairing record with.
///
/// `storage` is the host's pairing store. Without one the server can still run the Pairing PSK
/// flow's authentication, but it has nowhere to keep the record and refuses to persist one, so
/// only a paired client - one whose record the store holds - is authenticated. The crate never
/// writes into a store it did not receive.
pub struct ServerConfig {
    /// Friendly name the server announces in `server/hello`.
    pub name: String,
    /// Address the listener binds.
    pub bind: SocketAddr,
    /// WebSocket endpoint the listener serves; every other path is refused.
    pub path: String,
    /// Static keypair of the server. The public half is the `server_id`.
    pub identity: Identity,
    /// Format of every stream this server sends.
    ///
    /// The host picks one; a client is activated as a player only when its `player@v1_support`
    /// lists this exact format. [`ServerConfig::new`] defaults to stereo 48 kHz 16-bit PCM, the
    /// format the specification requires every player to support.
    pub format: AudioFormat,
    /// The host's pairing records, or `None` for a server that pairs with nobody.
    pub storage: Option<Arc<dyn PairingStore>>,
    /// How long one pairing attempt may stay unfinished before the server cancels it.
    pub pairing_timeout: Duration,
    /// The host's discovery backend, or `None` for a server that only accepts connections.
    ///
    /// With a backend the server publishes `_sendspin-server._tcp` and dials the clients that
    /// advertise `_sendspin._tcp`; without one it neither advertises nor dials, and a client has to
    /// know the address. The backend is the host's, so `syncspin-server` can also run where
    /// multicast is unavailable.
    pub discovery: Option<Arc<dyn Discovery>>,
}

impl fmt::Debug for ServerConfig {
    /// Formats the configuration without the store, which holds key material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerConfig")
            .field("name", &self.name)
            .field("bind", &self.bind)
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("format", &self.format)
            .field("storage", &self.storage.as_ref().map(|_| "<host store>"))
            .field("pairing_timeout", &self.pairing_timeout)
            .field(
                "discovery",
                &self.discovery.as_ref().map(|_| "<host discovery>"),
            )
            .finish()
    }
}

impl Clone for ServerConfig {
    fn clone(&self) -> Self {
        ServerConfig {
            name: self.name.clone(),
            bind: self.bind,
            path: self.path.clone(),
            identity: self.identity,
            format: self.format.clone(),
            storage: self.storage.clone(),
            pairing_timeout: self.pairing_timeout,
            discovery: self.discovery.clone(),
        }
    }
}

impl ServerConfig {
    /// Builds a configuration with the default address, endpoint path and stream format.
    ///
    /// The configuration starts without a pairing store, so a host that wants pairing sets
    /// [`ServerConfig::storage`] before [`Server::start`].
    pub fn new(name: impl Into<String>, identity: Identity) -> ServerConfig {
        ServerConfig {
            name: name.into(),
            bind: DEFAULT_BIND,
            path: DEFAULT_PATH.to_owned(),
            identity,
            format: AudioFormat::pcm(48_000, 2, 16),
            storage: None,
            pairing_timeout: DEFAULT_PAIRING_TIMEOUT,
            discovery: None,
        }
    }

    /// Rejects a name `server/hello` may not carry, a path that is not a `path-absolute`, and a
    /// stream format the server cannot schedule.
    fn validate(self) -> Result<ServerConfig> {
        if self.name.len() > MAX_SERVER_NAME_LEN {
            bail!(
                "the server name is {} bytes of UTF-8, longer than the {MAX_SERVER_NAME_LEN} bytes \
                 `server/hello` allows",
                self.name.len()
            );
        }
        if !self.path.starts_with('/') || self.path.starts_with("//") {
            bail!(
                "the endpoint path {:?} is not a `path-absolute` (RFC 3986, section 3.3): it must \
                 start with one `/` and not with `//`",
                self.path
            );
        }
        if self.path.contains('?') || self.path.contains('#') {
            bail!(
                "the endpoint path {:?} carries a query or a fragment, which is not part of a \
                 `path-absolute`",
                self.path
            );
        }
        self.format.validate()?;
        if self.pairing_timeout.is_zero() {
            bail!("the pairing timeout must not be zero");
        }
        Ok(self)
    }
}

/// One change the host has to know about.
///
/// The stream carries the lifecycle of a connection and of the stream, not its content: a client is
/// reported once it has said who it is, again once the server has decided its roles, and once when
/// it leaves; a stream is reported when it starts and when it ends, whoever ended it. Pairing is
/// reported when the operator has something to do and when a record is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A client completed the handshake and sent `client/hello`.
    ///
    /// `client_id` is the client's static public key and stays the same across reconnections;
    /// `name` is the friendly name from `client/hello`. `approved` is whether the connection is
    /// authenticated by a pairing record or by an approval the operator gave; an unapproved
    /// client is held at empty activities until [`ServerHandle::approve`] or a pairing.
    ClientConnected {
        /// Static public key of the client, as 43 unpadded base64url characters.
        client_id: String,
        /// Friendly name the client announced.
        name: String,
        /// Whether the connection may carry roles now.
        approved: bool,
    },
    /// A `server/activate` declaring roles was sent to the client.
    ///
    /// The first one of a connection carries an empty role list for an unapproved client; an
    /// approval and a completed pairing each send another one, with the roles that follow from it.
    ClientActivated {
        /// Static public key of the client.
        client_id: String,
        /// Versioned roles the connection may use; empty when it may use none.
        roles: Vec<String>,
    },
    /// A client offered `player@v1` but the server did not grant it, so it receives no stream.
    ///
    /// Sent right after the [`Event::ClientActivated`] of the same connection. The usual cause is a
    /// `player@v1_support` that does not list the configured [`AudioFormat`]; the host may change
    /// the configuration or leave the client as a controller.
    PlayerRoleWithheld {
        /// Static public key of the client.
        client_id: String,
        /// Why the role is missing, in a sentence the host can show.
        reason: String,
    },
    /// The operator has to act for a pairing attempt to continue.
    ///
    /// Sent when the client has been admitted to a code flow and is emitting its code, or as soon
    /// as the activation of a static-code attempt is out. `code` is always `None`: the client owns
    /// the code, and the server learns it only when the operator enters it with
    /// [`ServerHandle::submit_code`]. A host shows the request, collects the entry and submits it;
    /// the dynamic flow asks again after every retry of a round.
    PairingRequested {
        /// Static public key of the client.
        client_id: String,
        /// Method the attempt runs.
        method: PairingMethod,
        /// A code the server could show, which it never has; reserved for a future out-channel.
        code: Option<String>,
    },
    /// A pairing completed and the server stored its record.
    ///
    /// Sent after `server/pair-finalize`; the client stores its side on that message and the
    /// server re-handshakes the live connection to the new long-term PSK right afterwards.
    Paired {
        /// Static public key of the client.
        client_id: String,
    },
    /// A pairing attempt ended without a record.
    PairingFailed {
        /// Static public key of the client.
        client_id: String,
        /// Why it ended, in a sentence the host can show.
        reason: String,
    },
    /// The connection ended.
    ClientLeft {
        /// Why it ended: the `reason` of a `client/goodbye`, or a short description of a close
        /// the server observed, such as `connection closed` or `server shutdown`.
        reason: String,
    },
    /// A stream was announced to the group.
    StreamStarted,
    /// The stream ended: by the host, or because the group paused or stopped.
    StreamEnded,
}

/// The receiving end of a server's [`Event`] stream.
///
/// [`EventStream::next`] returns `None` once the server has shut down and no connection is left to
/// report. Dropping the stream does not end the server; only [`ServerHandle::shutdown`] does.
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
pub struct Server;

impl Server {
    /// Binds the configured address and starts accepting clients.
    ///
    /// The listener runs in a task of its own and every connection in one more, so this returns as
    /// soon as the address is bound. A failure to bind is reported here; a client that cannot
    /// complete the handshake is not an error of the server and only shows up as the absence of a
    /// [`Event::ClientConnected`].
    ///
    /// # Errors
    /// Returns an error for a configuration the protocol forbids - a name longer than
    /// [`MAX_SERVER_NAME_LEN`], a path that is not a `path-absolute`, a stream format that has no
    /// sample rate or channels - when an address cannot be bound, and when the group identifier
    /// cannot be drawn from the operating system's CSPRNG.
    ///
    /// # Panics
    /// Panics when called outside a Tokio runtime, because the listener is spawned.
    pub async fn start(config: ServerConfig) -> Result<ServerHandle> {
        let config = config.validate()?;
        let bound = TcpListener::bind(config.bind)
            .await
            .with_context(|| format!("failed to bind the listener to {}", config.bind))?;
        let local_addr = bound
            .local_addr()
            .context("failed to read the listener's address")?;
        let (events, event_stream) = mpsc::unbounded_channel();
        let (shutdown, shutdown_signal) = watch::channel(false);
        let group = Group::new(config.name.clone(), config.format.clone(), events.clone())?;
        let registry = Arc::new(Registry::new());
        // The record names the bound port, not the configured one, so `bind` with port zero still
        // advertises the endpoint a client can actually dial. A backend that cannot publish is
        // reported here, before any task runs: a server that silently failed to advertise would
        // look like one nobody chose.
        let outbound = match config.discovery.clone() {
            Some(discovery) => {
                let record = ServiceAdvertisement::server(
                    local_addr.port(),
                    config.path.clone(),
                    config.name.clone(),
                );
                discovery
                    .advertise(record.clone())
                    .context("the discovery backend refused to advertise this server")?;
                Some(tokio::spawn(crate::discovery::run(
                    config.clone(),
                    group.clone(),
                    events.clone(),
                    registry.clone(),
                    shutdown_signal.clone(),
                    discovery,
                    record,
                )))
            }
            None => None,
        };
        let task = tokio::spawn(listener::run(
            bound,
            config.clone(),
            group.clone(),
            events,
            registry.clone(),
            shutdown_signal,
        ));
        Ok(ServerHandle {
            task: Some(task),
            outbound,
            event_stream: Some(event_stream),
            shutdown,
            local_addr,
            group,
            registry,
            storage: config.storage,
        })
    }
}

/// One session's live place in the registry, so two connections of one client cannot confuse it.
#[derive(Debug)]
struct Live {
    /// The registration this entry belongs to.
    session: u64,
    /// The connection task's command queue.
    sender: mpsc::UnboundedSender<Command>,
}

/// The connections a handle can reach, and the approvals the operator has given.
///
/// Approval belongs to the `client_id`, not to the connection: the spec wants it to survive a
/// reconnect, and a client that comes back must be served again without the operator repeating the
/// grant. It is dropped on a successful pairing, because a paired connection needs no approval.
#[derive(Debug)]
pub(crate) struct Registry {
    approved: Mutex<HashSet<String>>,
    live: Mutex<HashMap<String, Live>>,
    next_session: AtomicU64,
}

impl Registry {
    fn new() -> Registry {
        Registry {
            approved: Mutex::new(HashSet::new()),
            live: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(0),
        }
    }

    /// Returns a session id for one connection, unique within this server.
    pub(crate) fn next_session(&self) -> u64 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }

    /// Records a connection under its `client_id`, replacing an older one of the same client.
    pub(crate) fn register(
        &self,
        client_id: &str,
        session: u64,
        sender: mpsc::UnboundedSender<Command>,
    ) {
        let mut live = self.live.lock().unwrap_or_else(|error| error.into_inner());
        live.insert(client_id.to_owned(), Live { session, sender });
    }

    /// Drops the registration, if it is still the one `session` made.
    pub(crate) fn unregister(&self, client_id: &str, session: u64) {
        let mut live = self.live.lock().unwrap_or_else(|error| error.into_inner());
        if live
            .get(client_id)
            .is_some_and(|held| held.session == session)
        {
            live.remove(client_id);
        }
    }

    /// Returns the command queue of the live connection of `client_id`.
    pub(crate) fn sender_for(&self, client_id: &str) -> Option<mpsc::UnboundedSender<Command>> {
        self.live
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(client_id)
            .map(|live| live.sender.clone())
    }

    /// Returns whether the operator approved `client_id`.
    pub(crate) fn is_approved(&self, client_id: &str) -> bool {
        self.approved
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains(client_id)
    }

    /// Records an approval and returns whether it is new.
    pub(crate) fn approve(&self, client_id: &str) -> bool {
        self.approved
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(client_id.to_owned())
    }

    /// Drops an approval and returns whether one was held: a successful pairing replaces it and
    /// an unpair ends it.
    pub(crate) fn forget_approval(&self, client_id: &str) -> bool {
        self.approved
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(client_id)
    }
}

/// One request a handle makes of a live connection.
///
/// A connection owns its socket, its Noise keys and its pairing attempt, so everything that
/// changes them runs in its task and reports back through the reply channel.
///
/// The enum has no `Debug`: one variant carries the pairing PSK a token decoded, which is a
/// credential.
pub(crate) enum Command {
    /// Activates the connection's roles now that the operator approved the client.
    Approve { reply: oneshot::Sender<Result<()>> },
    /// Removes the operator's approval and deactivates the connection's roles.
    RevokeApproval { reply: oneshot::Sender<Result<()>> },
    /// Runs the Pairing PSK flow with the key a token carried.
    PairToken {
        pairing_psk: [u8; 32],
        reply: oneshot::Sender<Result<()>>,
    },
    /// Sends the activation that admits one code-flow attempt.
    #[cfg(feature = "pairing-code")]
    StartPairing {
        method: PairingMethod,
        format: Option<CodeFormat>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Enters the code the operator read or scanned for the current round.
    SubmitCode {
        code: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Drops the record, sends `server/unpair` and ends the connection.
    Unpair { reply: oneshot::Sender<Result<()>> },
}

/// A running server.
///
/// The handle owns the listener task, the event stream and the group. [`ServerHandle::events`]
/// hands the stream out once; the group operations are what a host calls while it plays, and the
/// pairing and approval methods reach the connections by `client_id`. [`ServerHandle::shutdown`]
/// ends the server, and dropping the handle does the same without waiting for it.
pub struct ServerHandle {
    task: Option<JoinHandle<Result<()>>>,
    /// The discovery loop, when the host supplied a backend.
    outbound: Option<JoinHandle<Result<()>>>,
    event_stream: Option<mpsc::UnboundedReceiver<Event>>,
    shutdown: watch::Sender<bool>,
    local_addr: SocketAddr,
    group: Arc<Group>,
    registry: Arc<Registry>,
    storage: Option<Arc<dyn PairingStore>>,
}

impl fmt::Debug for ServerHandle {
    /// Formats the handle without the registry or the store, both of which hold secrets.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerHandle")
            .field("local_addr", &self.local_addr)
            .field("stopped", &self.task.is_none())
            .finish()
    }
}

impl ServerHandle {
    /// Returns the address the listener is bound to.
    ///
    /// It differs from [`ServerConfig::bind`] when the configuration asked for port 0, which is
    /// what a test does to leave the choice of port to the operating system.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Hands out the event stream.
    ///
    /// There is one consumer of the lifecycle, so this can be called once; a second call returns a
    /// stream that has already ended.
    pub fn events(&mut self) -> EventStream {
        let events = self.event_stream.take().unwrap_or_else(|| {
            let (events, receiver) = mpsc::unbounded_channel();
            drop(events);
            receiver
        });
        EventStream { events }
    }

    /// Opens a stream for `track` and returns the writer that feeds it.
    ///
    /// The group is told before the host writes anything: every player receives `stream/start` with
    /// the configured format, the metadata role receives the track, and the writer's first chunk is
    /// scheduled 200 ms ahead of now. A stream that is still running is cleared first, so opening a
    /// track while another plays is a track jump rather than an in-place format change.
    ///
    /// A group with no player still accepts the writer: a stream that nobody hears is the host's
    /// business, and its timestamps stay consistent for a player that joins later.
    pub fn open_stream(&self, track: TrackInfo) -> StreamWriter {
        self.group.open_stream(track);
        StreamWriter::new(self.group.clone())
    }

    /// Sets the volume of the group and returns the level in force.
    ///
    /// A level above 100 is clamped rather than rejected. The new level reaches every client with
    /// the controller role in a `server/state`; volume and mute are independent.
    pub fn set_volume(&self, level: u8) -> u8 {
        self.group.set_volume(level)
    }

    /// Starts or resumes playback and reports the new group state.
    pub fn play(&self) {
        self.group.play();
    }

    /// Pauses playback at the current position.
    ///
    /// A paused group ends its player stream, as the specification requires; a later
    /// [`ServerHandle::play`] announces it again and continues from the paused position.
    pub fn pause(&self) {
        self.group.pause();
    }

    /// Stops playback and rewinds the position to the beginning.
    pub fn stop(&self) {
        self.group.stop();
    }

    /// Approves an unpaired client, which activates its roles.
    ///
    /// `pairing.md` lets the operator extend unpaired access per `client_id`, and the server holds
    /// every unapproved client at empty activities until then. The approval is remembered for as
    /// long as this server runs, so the next connection of the same client is served without
    /// asking again, and it is dropped when a pairing completes. A client that is already paired,
    /// or already approved, keeps its roles.
    ///
    /// # Errors
    /// Returns an error when the activation cannot be sent, which means the connection ended while
    /// the approval arrived. The approval itself is remembered either way, for the next connection.
    pub async fn approve(&self, client_id: &str) -> Result<()> {
        self.registry.approve(client_id);
        if let Some(sender) = self.registry.sender_for(client_id) {
            let (reply, response) = oneshot::channel();
            if sender.send(Command::Approve { reply }).is_ok() {
                // A connection that ended between the lookup and the send has nothing left to
                // activate; the approval stands for its next one.
                if let Ok(result) = response.await {
                    result?;
                }
            }
        }
        Ok(())
    }

    /// Revokes an approval and takes the client's roles away again.
    ///
    /// `pairing.md` requires an approval to be revocable by the operator. The connection stays
    /// open and the client falls back to empty activities; its audio stops and it leaves the
    /// group. An approval is also dropped by [`ServerHandle::unpair`] and by a successful pairing.
    ///
    /// # Errors
    /// Returns an error for a client the operator never approved, for a paired client (whose
    /// record, not an approval, authenticates it - `unpair` is the call for that), and when the
    /// connection ended before the revocation arrived.
    pub async fn revoke_approval(&self, client_id: &str) -> Result<()> {
        if !self.registry.forget_approval(client_id) {
            bail!("the operator never approved the client {client_id}");
        }
        self.request(
            client_id,
            |reply| Command::RevokeApproval { reply },
            "revoke an approval",
        )
        .await
    }

    /// Pairs with the client a version-0 pairing token names and returns once it is done.
    ///
    /// The token carries the client's static public key and its pairing PSK. The server confirms
    /// that the key is the `client_id` of a live connection, re-handshakes that connection to the
    /// pairing PSK, admits the Pairing PSK flow, stores the long-term PSK the client delivers and
    /// re-handshakes the connection to it. The client persists its own record on
    /// `server/pair-finalize`, which arrives before the second handshake.
    ///
    /// # Errors
    /// Returns an error for a token that does not decode, for a token that is not version 0 (a
    /// version-1 token carries a dynamic code, not a pairing credential), for a client that has no
    /// live connection, for a server without a [`PairingStore`], and for any failure of the flow
    /// itself. An unknown token's key names no live connection, so it is refused without changing
    /// any record.
    pub async fn pair(&self, token: &str) -> Result<()> {
        if self.storage.is_none() {
            bail!("this server has no pairing store, so it cannot pair a client");
        }
        let decoded = syncspin_core::pairing::token::decode(token)
            .context("the pairing token does not decode")?;
        if decoded.version != 0 {
            bail!(
                "a version-{} pairing token is not a credential; the Pairing PSK flow needs a \
                 version-0 token",
                decoded.version
            );
        }
        let (client_key, pairing_psk) = decoded.payload.split_at(32);
        let client_key: [u8; 32] = client_key
            .try_into()
            .expect("a version-0 token carries a 32-byte client key");
        let pairing_psk: [u8; 32] = pairing_psk
            .try_into()
            .expect("a version-0 token carries a 32-byte pairing PSK");
        let client_id = URL_SAFE_NO_PAD.encode(client_key);
        let sender = self.registry.sender_for(&client_id).ok_or_else(|| {
            anyhow::anyhow!(
                "the token's client key names no live connection, so there is nobody to pair"
            )
        })?;
        let (reply, response) = oneshot::channel();
        sender
            .send(Command::PairToken { pairing_psk, reply })
            .map_err(|_| anyhow::anyhow!("the connection ended before the pairing started"))?;
        response
            .await
            .map_err(|_| anyhow::anyhow!("the connection ended before the pairing finished"))?
    }

    /// Sends the activation that admits one code-flow attempt and returns once it is on the wire.
    ///
    /// The client answers with `client/pair-pending` (its gate is closed), with `client/pair-init`
    /// (the attempt started) or with `pair/abort`. The outcome reaches the host as
    /// [`Event::PairingRequested`], [`Event::Paired`] or [`Event::PairingFailed`]; this call only
    /// reports whether the activation itself left.
    ///
    /// # Errors
    /// Returns an error for a client without a live connection or approval, for a method the
    /// client did not offer, for a dynamic attempt without an emission format or a static one
    /// with one, and for a build without the `pairing-code` feature.
    pub async fn start_pairing(
        &self,
        client_id: &str,
        method: PairingMethod,
        format: Option<CodeFormat>,
    ) -> Result<()> {
        match (method, format) {
            (PairingMethod::PairingPsk, _) => bail!(
                "the Pairing PSK flow is started by ServerHandle::pair with the token the client \
                 shows"
            ),
            (PairingMethod::StaticCode, Some(_)) => {
                bail!("the Static Pairing Code flow takes no emission format")
            }
            (PairingMethod::DynamicCode, None) => {
                bail!("the Dynamic Pairing Code flow needs an emission format")
            }
            _ => {}
        }
        #[cfg(not(feature = "pairing-code"))]
        {
            let _ = client_id;
            bail!(
                "this server was built without the `pairing-code` feature, so it cannot run a \
                 code flow"
            )
        }
        #[cfg(feature = "pairing-code")]
        self.request(
            client_id,
            |reply| Command::StartPairing {
                method,
                format,
                reply,
            },
            "start a pairing",
        )
        .await
    }

    /// Enters the code the operator read from the client for the current round.
    ///
    /// The static code is the device's fixed eight digits; the dynamic one is six digits in the
    /// `digits` format or a version-1 token in `qr_code`. Separators a person types - spaces and
    /// hyphens - are stripped. The CPace round runs immediately when the client is ready, and its
    /// outcome reaches the host as [`Event::Paired`] or [`Event::PairingFailed`].
    ///
    /// # Errors
    /// Returns an error for a client without a live connection, for an attempt that is not waiting
    /// for a code, and for text that is not a code of the method and format the activation chose.
    pub async fn submit_code(&self, client_id: &str, code: &str) -> Result<()> {
        self.request(
            client_id,
            |reply| Command::SubmitCode {
                code: code.to_owned(),
                reply,
            },
            "enter a pairing code",
        )
        .await
    }

    /// Drops the pairing record of `client_id`, tells the client and disconnects it.
    ///
    /// `server/unpair` is valid under any activity set; a client that is paired removes its record
    /// and closes with `client/goodbye` reason `unpaired`. A client with no live connection has its
    /// record removed if the store holds one.
    ///
    /// # Errors
    /// Returns an error when the store refuses the removal.
    pub async fn unpair(&self, client_id: &str) -> Result<()> {
        self.registry.forget_approval(client_id);
        match self.registry.sender_for(client_id) {
            Some(sender) => {
                let (reply, response) = oneshot::channel();
                sender
                    .send(Command::Unpair { reply })
                    .map_err(|_| anyhow::anyhow!("the connection ended before it answered"))?;
                response
                    .await
                    .map_err(|_| anyhow::anyhow!("the connection ended before it answered"))?
            }
            None => pairing::remove_record(self.storage.as_deref(), client_id),
        }
    }

    /// Sends one command to the live connection of `client_id` and awaits its answer.
    async fn request(
        &self,
        client_id: &str,
        make: impl FnOnce(oneshot::Sender<Result<()>>) -> Command,
        what: &str,
    ) -> Result<()> {
        let sender = self
            .registry
            .sender_for(client_id)
            .ok_or_else(|| anyhow::anyhow!("no live connection to {what} for {client_id}"))?;
        let (reply, response) = oneshot::channel();
        sender
            .send(make(reply))
            .map_err(|_| anyhow::anyhow!("the connection ended before it could {what}"))?;
        response
            .await
            .map_err(|_| anyhow::anyhow!("the connection ended before it could {what}"))?
    }

    /// Stops the listener and closes every live connection.
    ///
    /// A connection that is still open receives a WebSocket close before its task ends, and the
    /// listener waits for the tasks it spawned. The handle is consumed: after this, the event
    /// stream reports the connections that left and then ends.
    ///
    /// # Errors
    /// Returns an error when the listener task failed, for example because an accept call failed.
    pub async fn shutdown(mut self) -> Result<()> {
        let _ = self.shutdown.send(true);
        let task = self.task.take().expect("the handle owns its task");
        let listener = task.await.context("the listener task panicked")?;
        // The discovery loop withdraws the record and waits for the connections it dialled, so it
        // is awaited after the listener has stopped accepting new ones.
        let outbound = match self.outbound.take() {
            Some(task) => task.await.context("the discovery task panicked")?,
            None => Ok(()),
        };
        listener?;
        outbound
    }
}

impl Drop for ServerHandle {
    /// Signals the listener and drops its task, which closes the port.
    ///
    /// Dropping is the abrupt way out: a connection is closed without the graceful close frame
    /// [`ServerHandle::shutdown`] sends. It exists so that a handle that is dropped cannot leave a
    /// listener behind on the address.
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(task) = self.outbound.take() {
            task.abort();
        }
    }
}

/// Returns the version of this crate as recorded in its manifest.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_the_workspace_version() {
        assert_eq!(version(), "0.3.1");
    }

    #[test]
    fn a_configuration_with_defaults_uses_the_server_defaults() {
        let config = ServerConfig::new("a server", Identity::generate());
        assert_eq!(config.bind, DEFAULT_BIND);
        assert_eq!(config.bind.port(), 8927);
        assert!(config.bind.ip().is_unspecified());
        assert_eq!(config.path, "/sendspin");
        assert_eq!(
            config.format,
            AudioFormat::pcm(48_000, 2, 16),
            "the default stream format is the one every player must support"
        );
        assert!(
            config.discovery.is_none(),
            "a server with no backend neither advertises nor dials"
        );
    }

    #[test]
    fn a_stream_format_that_cannot_be_scheduled_is_rejected() {
        let mut config = ServerConfig::new("a server", Identity::generate());
        config.format = AudioFormat::pcm(0, 2, 16);
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_name_longer_than_server_hello_allows_is_rejected() {
        let mut config =
            ServerConfig::new("a".repeat(MAX_SERVER_NAME_LEN + 1), Identity::generate());
        assert!(config.clone().validate().is_err());
        config.name = "a".repeat(MAX_SERVER_NAME_LEN);
        assert!(
            config.validate().is_ok(),
            "a name of exactly the limit is accepted"
        );
    }

    #[test]
    fn a_path_that_is_not_absolute_is_rejected() {
        for path in ["", "sendspin", "//sendspin", "/sendspin?x=1", "/sendspin#f"] {
            let mut config = ServerConfig::new("a server", Identity::generate());
            config.path = path.to_owned();
            assert!(
                config.validate().is_err(),
                "{path:?} must not be accepted as an endpoint path"
            );
        }
        let mut config = ServerConfig::new("a server", Identity::generate());
        config.path = "/".to_owned();
        assert!(config.validate().is_ok(), "the root path is absolute");
    }

    #[test]
    fn a_zero_pairing_timeout_is_rejected() {
        let mut config = ServerConfig::new("a server", Identity::generate());
        config.pairing_timeout = Duration::ZERO;
        assert!(
            config.validate().is_err(),
            "an attempt with no deadline could never be cancelled"
        );
    }

    /// A store that keeps nothing, for the configuration and handle `Debug` checks.
    struct TestStore;

    impl PairingStore for TestStore {
        fn load_pairings(&self) -> Result<Vec<PairingRecord>> {
            unimplemented!("a Debug check never reads the store")
        }

        fn store_pairing(&self, _record: PairingRecord) -> Result<()> {
            unimplemented!("a Debug check never writes the store")
        }

        fn remove_pairing(&self, _client_id: &str) -> Result<()> {
            unimplemented!("a Debug check never removes from the store")
        }
    }

    /// A discovery backend that does nothing, for the configuration `Debug` check.
    struct TestDiscovery;

    impl Discovery for TestDiscovery {
        fn advertise(&self, _record: ServiceAdvertisement) -> Result<()> {
            unimplemented!("a Debug check never advertises")
        }

        fn withdraw(&self, _service_type: &str) -> Result<()> {
            unimplemented!("a Debug check never withdraws")
        }

        fn browse(&self, _service_type: &str) -> Result<Vec<DiscoveredClient>> {
            unimplemented!("a Debug check never browses")
        }
    }

    #[test]
    fn the_configuration_debug_redacts_the_store_and_the_discovery() {
        let mut config = ServerConfig::new("a server", Identity::generate());
        config.storage = Some(std::sync::Arc::new(TestStore));
        config.discovery = Some(std::sync::Arc::new(TestDiscovery));

        let text = format!("{config:?}");
        assert!(text.contains("<host store>"), "got: {text}");
        assert!(text.contains("<host discovery>"), "got: {text}");
        assert!(!text.contains("TestStore"), "got: {text}");
        assert!(!text.contains("TestDiscovery"), "got: {text}");

        let bare = ServerConfig::new("a server", Identity::generate());
        let text = format!("{bare:?}");
        assert!(text.contains("storage: None"), "got: {text}");
        assert!(text.contains("discovery: None"), "got: {text}");
    }

    async fn started() -> ServerHandle {
        let mut config = ServerConfig::new("a server", Identity::generate());
        config.bind = "127.0.0.1:0".parse().expect("a literal address parses");
        Server::start(config)
            .await
            .expect("the listener starts on a loopback port")
    }

    #[tokio::test]
    async fn the_handle_debug_reports_the_address_without_secrets() {
        let server = started().await;
        let text = format!("{server:?}");
        assert!(text.contains("local_addr"), "got: {text}");
        assert!(text.contains("stopped: false"), "got: {text}");
        server.shutdown().await.expect("the listener shuts down");
    }

    #[tokio::test]
    async fn the_event_stream_is_single_consumer() {
        let mut server = started().await;
        let _first = server.events();
        let mut second = server.events();
        assert!(
            second.next().await.is_none(),
            "the second stream has already ended"
        );
        server.shutdown().await.expect("the listener shuts down");
    }

    #[tokio::test]
    async fn pairing_without_a_store_is_refused() {
        let server = started().await;
        let error = server
            .pair("SP:any-token")
            .await
            .expect_err("a server without a store cannot pair anyone");
        assert!(
            format!("{error:#}").contains("no pairing store"),
            "got: {error:#}"
        );
        server.shutdown().await.expect("the listener shuts down");
    }

    #[tokio::test]
    async fn a_static_code_attempt_with_an_emission_format_is_refused() {
        let server = started().await;
        let error = server
            .start_pairing(
                "a-client",
                PairingMethod::StaticCode,
                Some(CodeFormat::Digits),
            )
            .await
            .expect_err("the static flow carries no emission format");
        assert!(
            format!("{error:#}").contains("takes no emission format"),
            "got: {error:#}"
        );
        server.shutdown().await.expect("the listener shuts down");
    }
}
