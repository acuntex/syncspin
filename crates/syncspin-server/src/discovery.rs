//! Discovery-facing side of the server: the trait a host implements, the records it carries and
//! the one deviation-free place where the protocol learns about clients it did not accept.
//!
//! `connection.md` lets a server establish connections in two ways. It admits the WebSocket a
//! client dials, and it finds clients that advertise `_sendspin._tcp` over mDNS and dials them. This
//! module holds the seam for the second way: the [`Discovery`] trait, the records it carries and
//! the endpoint rule. The server that accepts inbound connections is in [`crate::listener`].
//!
//! The mDNS backend lives behind the `mdns` feature; without it, [`Discovery`] is the seam and the
//! host supplies the implementation. No protocol logic here opens a socket or joins a multicast
//! group, and the tests drive the server with a fake instead of a network.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

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
/// an identity and a peer that has the connection takes the name from `server/hello`
/// (`client/hello` in the other direction) instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAdvertisement {
    /// Service type the record is published under, for example [`SERVER_SERVICE_TYPE`].
    pub service_type: String,
    /// Port the endpoint listens on.
    pub port: u16,
    /// The `path` TXT record: the WebSocket endpoint, an absolute path such as `/sendspin`.
    pub path: String,
    /// The `name` TXT record, when the advertiser sets one.
    pub name: Option<String>,
}

impl ServiceAdvertisement {
    /// Returns the record a server publishes: `_sendspin-server._tcp`, its port, `path` and `name`.
    ///
    /// The name is the server's, which is the value `server/hello` repeats; the spec only asks it
    /// to match, and calls the `server/hello` value authoritative when the two differ.
    #[must_use]
    pub fn server(
        port: u16,
        path: impl Into<String>,
        name: impl Into<String>,
    ) -> ServiceAdvertisement {
        ServiceAdvertisement {
            service_type: SERVER_SERVICE_TYPE.to_owned(),
            port,
            path: path.into(),
            name: Some(name.into()),
        }
    }
}

/// One client a browser reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredClient {
    /// `host:port` addresses the browser resolved for the service, most suitable first.
    pub addresses: Vec<String>,
    /// The `path` TXT record the service published.
    pub path: String,
    /// The `name` TXT record, when the service published one.
    pub name: Option<String>,
}

impl DiscoveredClient {
    /// Returns the `ws://` endpoint to dial, or `None` when the record cannot name one.
    ///
    /// The scheme is `ws://` even though the path is advertised: `connection.md` requires a
    /// connection to an advertised address to use plain `ws://`, with confidentiality and integrity
    /// provided by the Noise layer inside the payloads. An address that carries a scheme already,
    /// a missing address and a path that is not `path-absolute` (RFC 3986) all yield `None`,
    /// because dialling them would mean guessing what the advertiser meant.
    #[must_use]
    pub fn endpoint(&self) -> Option<String> {
        let address = self.addresses.first()?;
        if address.contains("://") {
            return None;
        }
        if !self.path.starts_with('/') || self.path.starts_with("//") {
            return None;
        }
        Some(format!("ws://{address}{}", self.path))
    }
}

/// How a service is published and how remote ones are found.
///
/// A host implements this over its mDNS library of choice; the crate decides what the record
/// contains and what an announcement obliges it to do, so the two stay in one place. The trait never
/// reports a record it has not published: [`advertise`](Discovery::advertise) returning `Ok` means
/// a client can find the endpoint, and the whole client-initiated mode rests on that.
pub trait Discovery: Send + Sync {
    /// Publishes `service` until its service type is withdrawn.
    ///
    /// # Errors
    /// Returns an error when the record could not be published. The server then refuses to start,
    /// because accepting connections nobody can find is not the mode it was asked for.
    fn advertise(&self, service: ServiceAdvertisement) -> Result<()>;

    /// Withdraws the advertisement of `service_type`.
    ///
    /// Called when the server stops listening: a record that outlives its listener points at a
    /// closed port. Withdrawing a type that was never advertised is not an error.
    fn withdraw(&self, service_type: &str) -> Result<()>;

    /// Returns the services currently advertised under `service_type`.
    fn browse(&self, service_type: &str) -> Result<Vec<DiscoveredClient>>;
}

/// Returns the clients `discovery` currently reports.
///
/// This is the browsing half of the server-initiated mode: the server dials every
/// [`DiscoveredClient::endpoint`] it does not already serve. A host that implements the trait over
/// mDNS should filter loopback and unspecified addresses, as `connection.md` recommends; the
/// crate does not filter here, because a test's fake may deliberately report a loopback endpoint.
///
/// # Errors
/// Returns the backend's error, and nothing when it cannot browse at all; an empty list means no
/// client is advertising.
pub fn discover_clients(discovery: &dyn Discovery) -> Result<Vec<DiscoveredClient>> {
    discovery.browse(CLIENT_SERVICE_TYPE)
}

/// How often the server asks the backend which clients are advertising.
///
/// A browse is a snapshot, not a subscription: a client that appears between two ticks is dialled
/// on the next one. The interval is short enough for a person to see a new device join and long
/// enough that the backend is not queried continuously.
const BROWSE_INTERVAL: Duration = Duration::from_secs(10);

/// Advertises the server, dials discovered clients, and withdraws the record when it stops.
///
/// One task owns every outbound connection, so shutdown closes them and the advertisement goes
/// away only after the listener it names has stopped. A browse that fails is retried on the next
/// tick instead of ending discovery: an mDNS hiccup must not stop a server that is still reachable
/// on its own address.
pub(crate) async fn run(
    config: crate::ServerConfig,
    group: Arc<crate::group::Group>,
    events: mpsc::UnboundedSender<crate::Event>,
    registry: Arc<crate::Registry>,
    mut shutdown: watch::Receiver<bool>,
    discovery: Arc<dyn Discovery>,
    record: ServiceAdvertisement,
) -> Result<()> {
    let outcome = dial_loop(
        &config,
        &group,
        &events,
        &registry,
        &mut shutdown,
        discovery.as_ref(),
    )
    .await;
    // A record that outlives the listener points a client at a closed port, so it goes away
    // whatever ended the loop.
    let withdrawn = discovery
        .withdraw(&record.service_type)
        .context("the discovery backend refused to withdraw the advertisement");
    match outcome {
        Ok(()) => withdrawn,
        Err(error) => Err(error),
    }
}

/// Dials every advertised client that this server is not already serving.
async fn dial_loop(
    config: &crate::ServerConfig,
    group: &Arc<crate::group::Group>,
    events: &mpsc::UnboundedSender<crate::Event>,
    registry: &Arc<crate::Registry>,
    shutdown: &mut watch::Receiver<bool>,
    discovery: &dyn Discovery,
) -> Result<()> {
    let mut connections = JoinSet::new();
    // Endpoint URL by task id, so a client is not dialled twice while its connection lives and is
    // tried again once it ended.
    let mut dialled: HashMap<tokio::task::Id, String> = HashMap::new();
    let mut interval = tokio::time::interval(BROWSE_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                // The backend is synchronous; a bounded browse is its own cost and this task
                // exists only for discovery.
                let found = match discovery.browse(CLIENT_SERVICE_TYPE) {
                    Ok(found) => found,
                    Err(_) => continue,
                };
                for client in found {
                    let Some(url) = client.endpoint() else { continue };
                    if dialled.values().any(|held| held == &url) {
                        continue;
                    }
                    let config = config.clone();
                    let group = Arc::clone(group);
                    let events = events.clone();
                    let registry = Arc::clone(registry);
                    let shutdown = shutdown.clone();
                    let endpoint = url.clone();
                    let abort = connections.spawn(async move {
                        // A client that refuses the upgrade, fails the handshake or closes at
                        // once is not an error of the server; the next browse tries it again.
                        let _ = crate::listener::connect(
                            &endpoint, config, group, events, registry, shutdown,
                        )
                        .await;
                    });
                    dialled.insert(abort.id(), url);
                }
            }
            joined = connections.join_next_with_id(), if !connections.is_empty() => {
                match joined {
                    Some(Ok((id, ()))) => {
                        dialled.remove(&id);
                    }
                    Some(Err(error)) => {
                        dialled.remove(&error.id());
                    }
                    None => {}
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    // Every connection reads with the shutdown signal, so the tasks end on their own and a client
    // sees a close frame rather than a dropped socket.
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[cfg(feature = "mdns")]
mod mdns;

#[cfg(feature = "mdns")]
pub use mdns::MdnsDiscovery;

#[cfg(test)]
mod tests {
    use super::*;

    /// The record a server publishes carries the three things a client dials with, plus its name.
    #[test]
    fn a_server_record_names_the_service_the_port_the_path_and_the_name() {
        let record = ServiceAdvertisement::server(8927, DEFAULT_SENDSPIN_PATH, "Test server");
        assert_eq!(record.service_type, SERVER_SERVICE_TYPE);
        assert_eq!(record.port, 8927);
        assert_eq!(record.path, "/sendspin");
        assert_eq!(record.name.as_deref(), Some("Test server"));
        assert_ne!(
            CLIENT_SERVICE_TYPE, SERVER_SERVICE_TYPE,
            "the two directions use two service types"
        );
    }

    /// A discovered record becomes a plain `ws://` endpoint, and nothing else.
    #[test]
    fn a_discovered_client_builds_a_plain_ws_endpoint() {
        let client = DiscoveredClient {
            addresses: vec!["192.0.2.7:8928".to_owned()],
            path: "/sendspin".to_owned(),
            name: Some("A client".to_owned()),
        };
        assert_eq!(
            client.endpoint().as_deref(),
            Some("ws://192.0.2.7:8928/sendspin"),
            "connection.md requires plain ws:// to an advertised address"
        );

        for broken in [
            DiscoveredClient {
                addresses: Vec::new(),
                ..client.clone()
            },
            DiscoveredClient {
                path: "sendspin".to_owned(),
                ..client.clone()
            },
            DiscoveredClient {
                path: "//sendspin".to_owned(),
                ..client.clone()
            },
            DiscoveredClient {
                addresses: vec!["wss://192.0.2.7:8928".to_owned()],
                ..client
            },
        ] {
            assert_eq!(
                broken.endpoint(),
                None,
                "a record that does not name a ws:// endpoint is not dialled"
            );
        }
    }
}
