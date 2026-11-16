//! Discovery-facing side of the client: the trait a host implements, and the server-initiated
//! connection mode.
//!
//! `connection.md` lets a client establish connections in exactly one of two ways. In the
//! client-initiated way it dials the address of a server it found; in the server-initiated way it
//! advertises `_sendspin._tcp` over mDNS and accepts the server that connects to it. This module
//! holds the seam for both: the [`Discovery`] trait, the records it carries, and - behind the
//! `discovery` feature - the inbound listener that serves the WebSocket the advertisement leads to.
//! Without that feature the module is the trait and the records alone: nothing listens.
//!
//! The mDNS backend lives behind the `mdns` feature; without it, [`Discovery`] is the seam and the
//! host supplies the implementation. The protocol logic here opens no socket of its own: a browse
//! asks the host's backend, and [`discover_reachable_endpoint`] only probes an address the backend
//! already reported. The tests drive the advertising with a fake instead of a network. The inbound
//! listener binds a real address, because it has to: it is the endpoint the advertisement names.
//!
//! The inbound connection runs the same session as a dialled one. Only the WebSocket is different:
//! the server opened it, so the client answers the upgrade instead of sending it, and it rejects
//! every request that carries an `Origin` header. `connection.md`: a client that advertises
//! "MUST reject a WebSocket upgrade request to its Sendspin endpoint that carries an `Origin`
//! header"; a server that dials in knows the address it dialled, and the header is the browser's
//! cross-origin authorisation, not the protocol's. The Noise handshake is unchanged, because the
//! server is its initiator in both directions.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::net::TcpStream;

/// Service type a client publishes when it waits for a server to connect.
///
/// `connection.md`, _Server Initiated Connections_: the port, the `path` TXT record and the
/// optional `name` TXT record travel with it.
pub const CLIENT_SERVICE_TYPE: &str = "_sendspin._tcp.local.";

/// Service type a server publishes for client-initiated connections.
pub const SERVER_SERVICE_TYPE: &str = "_sendspin-server._tcp.local.";

/// WebSocket endpoint `connection.md` recommends for both directions.
pub const DEFAULT_SENDSPIN_PATH: &str = "/sendspin";

/// One service to publish over mDNS.
///
/// The record is what a peer needs to reach the endpoint: the service type, the port, and the
/// `path` TXT record the WebSocket lives on. `name` is the optional friendly-name hint; it is not
/// an identity and a peer that has the connection takes the name from `client/hello`
/// (`server/hello` in the other direction) instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAdvertisement {
    /// Service type the record is published under, for example [`CLIENT_SERVICE_TYPE`].
    pub service_type: String,
    /// Port the endpoint listens on.
    pub port: u16,
    /// The `path` TXT record: the WebSocket endpoint, an absolute path such as `/sendspin`.
    pub path: String,
    /// The `name` TXT record, when the advertiser sets one.
    pub name: Option<String>,
}

impl ServiceAdvertisement {
    /// Returns the record a client publishes: `_sendspin._tcp`, its port, `path` and `name`.
    ///
    /// The name is the player's, which is the value `client/hello` repeats; the spec only asks it to
    /// match, and calls the `client/hello` value authoritative when the two differ.
    #[must_use]
    pub fn client(
        port: u16,
        path: impl Into<String>,
        name: impl Into<String>,
    ) -> ServiceAdvertisement {
        ServiceAdvertisement {
            service_type: CLIENT_SERVICE_TYPE.to_owned(),
            port,
            path: path.into(),
            name: Some(name.into()),
        }
    }
}

/// One server a browser reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredServer {
    /// `host:port` addresses the browser resolved for the service.
    ///
    /// [`endpoints`](DiscoveredServer::endpoints) orders them IPv4 first; the vector itself keeps
    /// whatever order the backend reported.
    pub addresses: Vec<String>,
    /// The `path` TXT record the service published.
    pub path: String,
    /// The `name` TXT record, when the service published one.
    pub name: Option<String>,
}

impl DiscoveredServer {
    /// Returns the `ws://` endpoint to dial, or `None` when the record cannot name one.
    ///
    /// This is the first of [`endpoints`](DiscoveredServer::endpoints), so it is the IPv4 address
    /// when the record has one.
    #[must_use]
    pub fn endpoint(&self) -> Option<String> {
        self.endpoints().into_iter().next()
    }

    /// Returns every `ws://` endpoint the record names, IPv4 addresses first.
    ///
    /// The scheme is `ws://` even though the path is advertised: `connection.md` requires a
    /// connection to an advertised address to use plain `ws://`, with confidentiality and integrity
    /// provided by the Noise layer inside the payloads. An address that carries a scheme already,
    /// a missing address and a path that is not `path-absolute` (RFC 3986) all yield nothing,
    /// because dialling them would mean guessing what the advertiser meant.
    ///
    /// An mDNS record commonly resolves to several addresses for one service - a dual-stack host
    /// publishes both. The IPv4 addresses come first so a server that listens on a single IPv4
    /// wildcard is reached before a client spends a timeout on an IPv6 address nothing accepts; the
    /// relative order within each family is kept. A record with no valid address yields an empty
    /// list.
    #[must_use]
    pub fn endpoints(&self) -> Vec<String> {
        self.ordered_addresses()
            .into_iter()
            .map(|address| format!("ws://{address}{}", self.path))
            .collect()
    }

    /// Returns the usable addresses, IPv4 first.
    ///
    /// The path rule is part of the address rule because an endpoint is only dialable when both
    /// hold; a record with a relative path yields no candidates at all.
    fn ordered_addresses(&self) -> Vec<&str> {
        if !self.path.starts_with('/') || self.path.starts_with("//") {
            return Vec::new();
        }
        let mut addresses: Vec<&str> = self
            .addresses
            .iter()
            .map(String::as_str)
            .filter(|address| !address.contains("://"))
            .collect();
        // A stable sort keeps the browser's order inside each family. A host name that is not a
        // literal socket address sorts with IPv6, after the addresses that are certainly IPv4.
        addresses.sort_by_key(|address| match address.parse::<SocketAddr>() {
            Ok(address) if address.is_ipv4() => 0u8,
            _ => 1u8,
        });
        addresses
    }
}

/// How long one advertised address gets to accept before the next one is tried.
///
/// A refused connection returns at once; the timeout only bounds an address that silently drops
/// the attempt, such as a stale IPv6 entry on a network without a route to it.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Returns the first endpoint `discovery` reports that accepts a TCP connection.
///
/// A browse can report one service with several addresses, and a dual-stack host commonly does.
/// Trying only the first means an IPv6 address the server does not listen on hides an IPv4 address
/// it does, and the client retries the same unreachable one forever. This walks the candidates in
/// the order [`DiscoveredServer::endpoints`] gives - IPv4 first - and stops at the first address
/// that accepts. A failure moves to the next address immediately instead of waiting for a retry
/// tick.
///
/// The probe is a TCP connection only: it decides reachability, and the session dials the returned
/// endpoint itself. A host therefore sees one closed probe connection before the real one.
///
/// # Errors
/// Returns the backend's error, an error when nothing advertises a dialable endpoint, and an error
/// naming every attempt once all addresses refused or timed out. A backend error is not retried
/// here; the caller decides whether to browse again.
pub async fn discover_reachable_endpoint(discovery: &dyn Discovery) -> Result<String> {
    let servers = discover_servers(discovery)?;
    let candidates: Vec<(String, String)> = servers
        .iter()
        .flat_map(|server| {
            server
                .ordered_addresses()
                .into_iter()
                .map(|address| (address.to_owned(), format!("ws://{address}{}", server.path)))
                .collect::<Vec<_>>()
        })
        .collect();
    if candidates.is_empty() {
        bail!(
            "no server advertised {SERVER_SERVICE_TYPE} with a dialable address; start one with \
             `server-demo --mdns` or pass --server"
        );
    }
    let mut failures = Vec::new();
    for (address, endpoint) in candidates {
        match probe(&address).await {
            Ok(()) => return Ok(endpoint),
            Err(error) => failures.push(format!("{address}: {error:#}")),
        }
    }
    bail!(
        "none of the discovered servers accepted a connection ({})",
        failures.join("; ")
    )
}

/// Opens and immediately drops one TCP connection, to tell a reachable address from a dead one.
async fn probe(address: &str) -> Result<()> {
    // Dropping the stream closes the probe; it only decides reachability.
    tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(address))
        .await
        .with_context(|| format!("no answer within {} s", PROBE_TIMEOUT.as_secs()))??;
    Ok(())
}

/// How a service is published and how remote ones are found.
///
/// A host implements this over its mDNS library of choice; the crate decides what the record
/// contains and what an announcement obliges it to do, so the two stay in one place. The trait never
/// reports a record it has not published: [`advertise`](Discovery::advertise) returning `Ok` means
/// a server can find the endpoint, and the whole server-initiated mode rests on that.
///
/// A client that advertises must not dial a server itself (`connection.md`, _Server Initiated
/// Connections_). This crate enforces that: [`connect`](crate::connect) refuses a configuration
/// that advertises.
pub trait Discovery: Send + Sync {
    /// Publishes `service` until its service type is withdrawn.
    ///
    /// # Errors
    /// Returns an error when the record could not be published. The client then refuses to start,
    /// because accepting connections nobody can find is not the mode it was asked for.
    fn advertise(&self, service: ServiceAdvertisement) -> Result<()>;

    /// Withdraws the advertisement of `service_type`.
    ///
    /// Called when the inbound listener closes: a record that outlives its listener points at a
    /// closed port. Withdrawing a type that was never advertised is not an error.
    fn withdraw(&self, service_type: &str) -> Result<()>;

    /// Returns the services currently advertised under `service_type`.
    fn browse(&self, service_type: &str) -> Result<Vec<DiscoveredServer>>;
}

/// Returns the servers `discovery` currently reports.
///
/// This is the browsing half of the client-initiated mode: the caller picks one
/// [`DiscoveredServer::endpoint`] and passes it to [`connect`](crate::connect). Browsing is a
/// client-initiated act, so a host that browses must not advertise at the same time; a
/// configuration with [`ClientConfig::inbound`](crate::ClientConfig) set cannot dial at all.
///
/// # Errors
/// Returns the backend's error, and nothing when it cannot browse at all; an empty list means no
/// server is advertising.
pub fn discover_servers(discovery: &dyn Discovery) -> Result<Vec<DiscoveredServer>> {
    discovery.browse(SERVER_SERVICE_TYPE)
}

#[cfg(feature = "discovery")]
pub use inbound::{advertise, Inbound, DEFAULT_INBOUND_ADDR, DEFAULT_INBOUND_PORT};

#[cfg(feature = "mdns")]
mod mdns;

#[cfg(feature = "mdns")]
pub use mdns::MdnsDiscovery;

#[cfg(feature = "discovery")]
mod inbound {
    use std::fmt;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU8;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{anyhow, Context, Result};
    use syncspin_core::pairing::token::encode_v0;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinSet;
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    use tokio_tungstenite::tungstenite::http::header::ORIGIN;
    use tokio_tungstenite::tungstenite::http::StatusCode;
    use tokio_tungstenite::tungstenite::Error as WsError;

    use super::{ServiceAdvertisement, DEFAULT_SENDSPIN_PATH};
    use crate::client::{
        answer_without_session, ClientHandle, ControlHandle, ControlRequest, Event, EventStream,
        GoodbyeReason, PairingToken,
    };
    use crate::config::ClientConfig;
    use crate::pairing::{load_or_draw_pairing_psk, PairingPsk};
    use crate::session::{self, Carried, Transport};
    use crate::sink::Sink;
    use crate::Discovery;

    /// Port `connection.md` recommends for a client's Sendspin endpoint.
    pub const DEFAULT_INBOUND_PORT: u16 = 8928;

    /// Address the inbound listener binds unless the host narrows it.
    ///
    /// Encryption is the boundary, not the bind address: a peer that cannot complete the Noise
    /// handshake is refused whatever interface it reached.
    pub const DEFAULT_INBOUND_ADDR: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DEFAULT_INBOUND_PORT);

    /// How long the rejection of a second server may take before its socket is dropped.
    ///
    /// The provisional connection has to reach its first `server/activate` before admission can be
    /// applied. A server that never gets there is not worth keeping: the cap already rejected it,
    /// and the spec's own provisional timeout is 30 seconds.
    const REJECT_TIMEOUT: Duration = Duration::from_secs(30);

    /// The server-initiated half of the connection mode.
    ///
    /// Setting [`ClientConfig::inbound`] puts the client in this mode: [`advertise`] publishes
    /// [`CLIENT_SERVICE_TYPE`](super::CLIENT_SERVICE_TYPE) with the bound port, the configured path
    /// and the player name, and then accepts the servers that connect. A manual
    /// [`connect`](crate::connect) is refused while this is set, because `connection.md` lets a
    /// client use one of the two methods at a time.
    #[derive(Clone)]
    pub struct Inbound {
        /// Backend that publishes the record and browses for servers.
        pub discovery: Arc<dyn Discovery>,
        /// Address the listener binds.
        pub listen: SocketAddr,
        /// WebSocket path the listener serves, as the `path` TXT record states it.
        pub path: String,
    }

    impl Inbound {
        /// Returns the server-initiated mode for `discovery`, with the spec's defaults.
        ///
        /// The listener binds [`DEFAULT_INBOUND_ADDR`] - every interface on
        /// [`DEFAULT_INBOUND_PORT`] - and serves `/sendspin`. A host that narrows the address or
        /// moves the path sets the fields before placing the value in [`ClientConfig::inbound`].
        #[must_use]
        pub fn new(discovery: Arc<dyn Discovery>) -> Inbound {
            Inbound {
                discovery,
                listen: DEFAULT_INBOUND_ADDR,
                path: DEFAULT_SENDSPIN_PATH.to_owned(),
            }
        }
    }

    impl fmt::Debug for Inbound {
        /// Names the backend without delegating to it: its `Debug` belongs to the host.
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("Inbound")
                .field("discovery", &"<host discovery>")
                .field("listen", &self.listen)
                .field("path", &self.path)
                .finish()
        }
    }

    /// Advertises this client and serves the servers that connect to it.
    ///
    /// The advertisement is published before this returns, so a caller learns about a backend that
    /// cannot publish instead of running a listener nobody can find. The port in the record is the
    /// one that was actually bound, which is how a listen address with port zero becomes reachable.
    ///
    /// One server is admitted at a time: while a session is live the loop runs it, and when it ends
    /// the client reports [`Event::Disconnected`] with a `retry_in` of zero - it schedules nothing,
    /// because the next connection is the server's decision - and accepts the next one. The
    /// advertisement is withdrawn when the handle or the event stream is dropped, when
    /// [`ClientHandle::close`] is called, or when the audio sink fails.
    ///
    /// # Errors
    /// Returns an error for an invalid configuration, for a configuration without
    /// [`ClientConfig::inbound`], for a [`Storage`](crate::storage::Storage) that cannot hold the
    /// pairing PSK, for a listen address this build cannot bind, and for a backend that refuses the
    /// advertisement.
    ///
    /// # Panics
    /// Panics when called outside a Tokio runtime, because the listener is spawned.
    ///
    /// Pairing records come from [`ClientConfig::storage`]; this revision has no advertising
    /// counterpart to [`connect_with_psks`](crate::connect_with_psks).
    pub async fn advertise(
        config: ClientConfig,
        sink: Box<dyn Sink>,
    ) -> Result<(ClientHandle, EventStream)> {
        let inbound = config.inbound.clone().ok_or_else(|| {
            anyhow!(
                "this configuration has no ClientConfig::inbound, so there is nothing to \
                 advertise and no address to accept a server on"
            )
        })?;
        // An advertising client names no server address, so only the shared fields are checked.
        config.validate_common()?;

        // The pairing PSK is settled before anything is published, so a store that cannot hold it
        // is reported here rather than to whichever server happens to connect first.
        let (pairing, pairing_token) = match config.storage.as_deref() {
            Some(storage) => {
                let psk = load_or_draw_pairing_psk(storage)?;
                let token = PairingToken(encode_v0(&config.identity.public, psk.as_bytes()));
                (Some(psk), Some(token))
            }
            None => (None, None),
        };

        // The listener comes next: a record that names a port nothing accepts on is a record a
        // server dials into a closed socket. Nothing after the advertisement can fail, so a client
        // never stays advertised without a listener behind it.
        let listener = TcpListener::bind(inbound.listen).await.with_context(|| {
            format!("failed to bind the inbound listener on {}", inbound.listen)
        })?;
        let port = listener
            .local_addr()
            .context("failed to read the inbound listener's address")?
            .port();
        let record = ServiceAdvertisement::client(port, inbound.path.clone(), &config.player_name);
        inbound
            .discovery
            .advertise(record.clone())
            .context("the discovery backend refused to advertise this client")?;

        let (events, receiver) = mpsc::unbounded_channel();
        let (commands, control) = mpsc::unbounded_channel();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let reported_volume = Arc::new(AtomicU8::new(config.volume));
        // The dynamic flow's round counter belongs to the process, not to a connection: it starts
        // clean here and is carried across every inbound session.
        #[cfg(feature = "pairing-code")]
        let failed_rounds = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let carried = Carried {
            sink,
            control: Some(control),
            volume: config.volume,
            muted: config.muted,
            active_roles: Vec::new(),
            #[cfg(feature = "pairing-code")]
            failed_rounds,
        };

        let task = tokio::spawn(serve(
            listener,
            config,
            inbound,
            record,
            pairing,
            carried,
            events,
            Arc::clone(&reported_volume),
            shutdown_rx,
        ));

        let handle = ClientHandle {
            task: Some(task),
            control: ControlHandle {
                commands,
                volume: reported_volume,
                pairing_token,
            },
            shutdown: Some(shutdown),
        };
        Ok((handle, EventStream { events: receiver }))
    }

    /// Runs the listener until the host is done, then withdraws the advertisement.
    #[allow(clippy::too_many_arguments)]
    async fn serve(
        listener: TcpListener,
        config: ClientConfig,
        inbound: Inbound,
        record: ServiceAdvertisement,
        pairing: Option<PairingPsk>,
        carried: Carried,
        events: mpsc::UnboundedSender<Event>,
        reported_volume: Arc<AtomicU8>,
        mut shutdown: oneshot::Receiver<GoodbyeReason>,
    ) -> Result<()> {
        let outcome = accept_loop(
            &listener,
            &config,
            &inbound.path,
            pairing,
            carried,
            &events,
            &reported_volume,
            &mut shutdown,
        )
        .await;
        // An advertisement that outlives the listener points a server at a closed port, so it goes
        // away whatever ended the loop.
        let withdrawn = inbound
            .discovery
            .withdraw(&record.service_type)
            .context("the discovery backend refused to withdraw the advertisement");
        match outcome {
            Ok(()) => withdrawn,
            Err(error) => Err(error),
        }
    }

    /// Accepts and serves one connection at a time until the host ends the client.
    #[allow(clippy::too_many_arguments)]
    async fn accept_loop(
        listener: &TcpListener,
        config: &ClientConfig,
        path: &str,
        pairing: Option<PairingPsk>,
        mut carried: Carried,
        events: &mpsc::UnboundedSender<Event>,
        reported_volume: &AtomicU8,
        shutdown: &mut oneshot::Receiver<GoodbyeReason>,
    ) -> Result<()> {
        loop {
            let Some(stream) =
                wait_for_connection(listener, &mut carried, events, shutdown).await?
            else {
                return Ok(());
            };
            // The upgrade answers every request it refuses, so neither a wrong path nor a rejected
            // `Origin` reaches the protocol. A peer that breaks the upgrade itself - a truncated
            // request, a hello for another protocol - is equally not a connection, and neither
            // stops the listener for the servers that follow.
            let transport = match upgrade(stream, path).await {
                Ok(Some(transport)) => transport,
                Ok(None) | Err(_) => continue,
            };

            // The server-initiated mode admits one server at a time. A second one that arrives
            // while this session runs is not left in the listen backlog: its handshake is completed
            // in a task of its own and it is rejected with `concurrent_attempt`, as `connection.md`
            // requires. The task owns no state of the admitted session, so a slow rejection cannot
            // hold up playback.
            let mut rejections = JoinSet::new();
            let mut attempt = Box::pin(session::attempt(
                transport,
                config,
                events,
                &[],
                pairing,
                reported_volume,
                carried,
                shutdown,
            ));
            let attempt = loop {
                tokio::select! {
                    attempt = &mut attempt => break attempt,
                    // Accepting is cancel-safe: a connection that arrives while another branch is
                    // busy waits in the backlog for the next round.
                    accepted = listener.accept() => {
                        let (stream, _address) =
                            accepted.context("failed to accept an inbound connection")?;
                        rejections.spawn(reject_connection(
                            stream,
                            config.clone(),
                            path.to_owned(),
                            pairing,
                        ));
                    }
                    joined = rejections.join_next(), if !rejections.is_empty() => {
                        // A rejection that failed changed nothing: the admitted session is the one
                        // the host hears about.
                        let _ = joined;
                    }
                }
            };
            // A rejection that has not finished belongs to a client that is already ending; it is
            // dropped with the set, which closes its socket.
            drop(rejections);
            carried = attempt.carried;

            // Nothing buffered for the session that ended may become audible later; the flush runs
            // before the host hears about the drop. A deliberate close is not a drop.
            let flush_error = carried.sink.flush().err().map(|error| {
                error.context("the audio sink rejected a flush after the connection ended")
            });
            if matches!(&attempt.ending, session::Ending::Shutdown) {
                return Ok(());
            }
            // No attempt follows: the next connection is the server's decision, not the client's,
            // so there is no delay to recommend.
            let _ = events.send(Event::Disconnected {
                reason: attempt.ending.reason(),
                retry_in: Duration::ZERO,
            });

            // A broken output cannot be repaired by another connection, and neither can a flush
            // that fails after the session; both end the client so the host can repair it.
            if attempt.sink_failed {
                return match attempt.ending {
                    session::Ending::Failed(error) => Err(error),
                    session::Ending::Closed
                    | session::Ending::Unpaired
                    | session::Ending::Shutdown => Err(anyhow!("the audio sink failed")),
                };
            }
            if let Some(error) = flush_error {
                return Err(error);
            }
        }
    }

    /// Rejects one connection that arrived while another server is admitted.
    ///
    /// The upgrade rules are the same as for the admitted connection - the path must match and an
    /// `Origin` header is refused - because a rejected server learns nothing a browser could use.
    async fn reject_connection(
        stream: TcpStream,
        config: ClientConfig,
        path: String,
        pairing: Option<PairingPsk>,
    ) {
        let Ok(Some(transport)) = upgrade(stream, &path).await else {
            return;
        };
        let _ = tokio::time::timeout(
            REJECT_TIMEOUT,
            session::reject_concurrent(transport, &config, pairing, &[]),
        )
        .await;
    }

    /// Waits for the next inbound connection, answering control requests meanwhile.
    ///
    /// Returns `None` when the host ended the client: the handle was closed or the event stream was
    /// dropped. There is no session to say goodbye on while the listener waits, exactly as in the
    /// reconnect wait of a dialling client.
    async fn wait_for_connection(
        listener: &TcpListener,
        carried: &mut Carried,
        events: &mpsc::UnboundedSender<Event>,
        shutdown: &mut oneshot::Receiver<GoodbyeReason>,
    ) -> Result<Option<TcpStream>> {
        loop {
            if events.is_closed() {
                return Ok(None);
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
                // Accepting is cancel-safe: a connection that arrives while this select is busy
                // waits in the backlog.
                accepted = listener.accept() => Wakeup::Accepted(accepted),
                reason = &mut *shutdown => {
                    let _ = reason;
                    return Ok(None);
                }
                () = events.closed() => Wakeup::Closed,
            };
            match wakeup {
                Wakeup::Control(Some(request)) => answer_without_session(carried, request),
                Wakeup::Control(None) => *control = None,
                Wakeup::Accepted(Ok((stream, _address))) => return Ok(Some(stream)),
                Wakeup::Accepted(Err(error)) => {
                    return Err(anyhow!(error).context("failed to accept an inbound connection"))
                }
                Wakeup::Closed => return Ok(None),
            }
        }
    }

    /// One wake-up while the listener waits for a server.
    enum Wakeup {
        /// A control handle sent a request, or every handle was dropped.
        Control(Option<ControlRequest>),
        /// The listener accepted a TCP connection.
        Accepted(std::io::Result<(TcpStream, SocketAddr)>),
        /// The host dropped the event stream.
        Closed,
    }

    /// Serves `stream` if it asks for `path` and carries no `Origin` header.
    ///
    /// `Ok(None)` means the request was refused with an HTTP answer and its socket is closed; the
    /// caller keeps listening.
    // Error responses are the handshake crate's large `http::Response` type; a rejection happens
    // once per refused upgrade, so boxing it would buy nothing.
    #[allow(clippy::result_large_err)]
    async fn upgrade(stream: TcpStream, path: &str) -> Result<Option<Transport>> {
        let expected = path.to_owned();
        let callback = move |request: &Request, response: Response| {
            // `connection.md`: a client must reject an upgrade that carries an `Origin` header. A
            // server that dials in knows the address it dialled, so the header can only come from
            // something acting for a page - which is what the rule exists to refuse.
            if request.headers().contains_key(ORIGIN) {
                let mut error = ErrorResponse::new(Some(
                    "a server-initiated Sendspin upgrade must not carry an Origin header"
                        .to_owned(),
                ));
                *error.status_mut() = StatusCode::FORBIDDEN;
                return Err(error);
            }
            if request.uri().path() == expected {
                return Ok(response);
            }
            let mut error =
                ErrorResponse::new(Some("this endpoint is not a Sendspin endpoint".to_owned()));
            *error.status_mut() = StatusCode::NOT_FOUND;
            Err(error)
        };
        match accept_hdr_async(stream, callback).await {
            Ok(socket) => Ok(Some(Transport::accept(socket))),
            // The two answers above: the peer was told why and the socket is closed.
            Err(WsError::Http(response))
                if response.status() == StatusCode::FORBIDDEN
                    || response.status() == StatusCode::NOT_FOUND =>
            {
                Ok(None)
            }
            Err(error) => Err(error).context("the WebSocket upgrade failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`Discovery`] that answers from memory, so the record shape is tested without a network.
    #[derive(Default)]
    struct MemoryDiscovery {
        browsed: std::sync::Mutex<Vec<String>>,
        servers: Vec<DiscoveredServer>,
    }

    impl Discovery for MemoryDiscovery {
        fn advertise(&self, _service: ServiceAdvertisement) -> Result<()> {
            Ok(())
        }

        fn withdraw(&self, _service_type: &str) -> Result<()> {
            Ok(())
        }

        fn browse(&self, service_type: &str) -> Result<Vec<DiscoveredServer>> {
            self.browsed
                .lock()
                .expect("the query list is not poisoned")
                .push(service_type.to_owned());
            Ok(self.servers.clone())
        }
    }

    /// The record a client publishes carries the three things a server dials with, plus its name.
    #[test]
    fn a_client_record_names_the_service_the_port_the_path_and_the_player() {
        let record = ServiceAdvertisement::client(8928, DEFAULT_SENDSPIN_PATH, "Test player");
        assert_eq!(record.service_type, CLIENT_SERVICE_TYPE);
        assert_eq!(record.port, 8928);
        assert_eq!(record.path, "/sendspin");
        assert_eq!(record.name.as_deref(), Some("Test player"));
        assert_ne!(
            CLIENT_SERVICE_TYPE, SERVER_SERVICE_TYPE,
            "the two directions use two service types"
        );
    }

    /// A discovered record becomes a plain `ws://` endpoint, and nothing else.
    #[test]
    fn a_discovered_server_builds_a_plain_ws_endpoint() {
        let server = DiscoveredServer {
            addresses: vec!["192.0.2.7:8927".to_owned()],
            path: "/sendspin".to_owned(),
            name: Some("A server".to_owned()),
        };
        assert_eq!(
            server.endpoint().as_deref(),
            Some("ws://192.0.2.7:8927/sendspin"),
            "connection.md requires plain ws:// to an advertised address"
        );

        // A record that cannot name an endpoint is refused here rather than guessed at later.
        for broken in [
            DiscoveredServer {
                addresses: Vec::new(),
                ..server.clone()
            },
            DiscoveredServer {
                path: "sendspin".to_owned(),
                ..server.clone()
            },
            DiscoveredServer {
                path: "//sendspin".to_owned(),
                ..server.clone()
            },
            DiscoveredServer {
                addresses: vec!["wss://192.0.2.7:8927".to_owned()],
                ..server
            },
        ] {
            assert_eq!(
                broken.endpoint(),
                None,
                "a record that does not name a ws:// endpoint is not dialled"
            );
        }
    }

    /// A record with several addresses names the IPv4 ones first, keeping each family's order.
    #[test]
    fn a_dual_stack_record_lists_its_ipv4_addresses_first() {
        let server = DiscoveredServer {
            addresses: vec![
                "[fd41::2]:8927".to_owned(),
                "[fd41::1]:8927".to_owned(),
                "192.0.2.8:8927".to_owned(),
                "192.0.2.7:8927".to_owned(),
            ],
            path: "/sendspin".to_owned(),
            name: None,
        };
        assert_eq!(
            server.endpoints(),
            vec![
                "ws://192.0.2.8:8927/sendspin".to_owned(),
                "ws://192.0.2.7:8927/sendspin".to_owned(),
                "ws://[fd41::2]:8927/sendspin".to_owned(),
                "ws://[fd41::1]:8927/sendspin".to_owned(),
            ],
            "IPv4 comes first and the browser's order within each family is kept"
        );
        assert_eq!(
            server.endpoint().as_deref(),
            Some("ws://192.0.2.8:8927/sendspin"),
            "endpoint is the first of the ordered list"
        );
    }

    /// An address that refuses does not consume the attempt: the next one is tried at once.
    #[tokio::test]
    async fn the_next_address_is_tried_when_the_first_refuses() {
        // A listener that accepts the probe, so the second address is the one that works.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the loopback listener binds");
        let accepting = listener
            .local_addr()
            .expect("the bound address is readable");
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        // A port nobody listens on: binding it and dropping the listener makes the connect refuse.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the second loopback listener binds");
        let refusing = closed.local_addr().expect("the bound address is readable");
        drop(closed);

        let discovery = MemoryDiscovery {
            servers: vec![DiscoveredServer {
                addresses: vec![refusing.to_string(), accepting.to_string()],
                path: "/sendspin".to_owned(),
                name: Some("A server".to_owned()),
            }],
            ..MemoryDiscovery::default()
        };
        let endpoint = discover_reachable_endpoint(&discovery)
            .await
            .expect("the second address accepts");
        assert_eq!(endpoint, format!("ws://{accepting}/sendspin"));
        accept.await.expect("the accepting task finishes");
    }

    /// When every address refuses, the error names all of them instead of only the first.
    #[tokio::test]
    async fn an_error_names_every_address_that_refused() {
        let first_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the first loopback listener binds");
        let second_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the second loopback listener binds");
        let first = first_listener
            .local_addr()
            .expect("the bound address is readable");
        let second = second_listener
            .local_addr()
            .expect("the bound address is readable");
        assert_ne!(first, second, "two ephemeral listeners get two ports");
        // Releasing both makes every connect to them refuse.
        drop(first_listener);
        drop(second_listener);

        let discovery = MemoryDiscovery {
            servers: vec![DiscoveredServer {
                addresses: vec![first.to_string(), second.to_string()],
                path: "/sendspin".to_owned(),
                name: None,
            }],
            ..MemoryDiscovery::default()
        };
        let Err(error) = discover_reachable_endpoint(&discovery).await else {
            panic!("both addresses refuse");
        };
        let text = format!("{error:#}");
        assert!(text.contains(&first.to_string()), "got: {text}");
        assert!(text.contains(&second.to_string()), "got: {text}");
    }

    /// Browsing always asks for the server service type; the client never looks for clients.
    #[test]
    fn browsing_asks_the_backend_for_servers() {
        let discovery = MemoryDiscovery::default();
        let servers = discover_servers(&discovery).expect("the backend answers");
        assert!(servers.is_empty());
        assert_eq!(
            discovery
                .browsed
                .lock()
                .expect("the query list is not poisoned")
                .as_slice(),
            &[SERVER_SERVICE_TYPE.to_owned()]
        );
    }
}
