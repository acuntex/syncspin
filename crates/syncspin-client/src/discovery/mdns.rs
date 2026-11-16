//! The `mdns-sd` backend for [`Discovery`](super::Discovery).
//!
//! It is the one place in this crate that opens a socket for discovery: [`MdnsDiscovery::new`]
//! starts the library's daemon thread, [`advertise`](Discovery::advertise) publishes a record and
//! [`browse`](Discovery::browse) joins the multicast group for one bounded window. No protocol
//! code reaches this module; it implements the same trait a fake does, so the tests can drive the
//! session without multicast.
//!
//! The records are the spec's: a client publishes `_sendspin._tcp` with the `path` and `name` TXT
//! records, a server publishes `_sendspin-server._tcp` with the same keys. Addresses are the
//! daemon's own: the host record is a process-scoped name and the library fills in the interface
//! addresses, so no hostname of this machine is written into the source.
//!
//! A record that resolves to loopback or an unspecified address is dropped rather than offered to
//! the caller: the specification says a peer SHOULD only connect to an address that is neither.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mdns_sd::{
    Receiver, RecvTimeoutError, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo,
};

use super::{DiscoveredServer, Discovery, ServiceAdvertisement};

/// How long one [`Discovery::browse`] waits for resolved records.
///
/// mDNS is asynchronous; a browse that returned at once would report only what a previous query
/// had already cached. One second is long enough for a local answer and short enough to call from
/// a caller that expects a list.
const BROWSE_WINDOW: Duration = Duration::from_secs(1);

/// The mDNS implementation of [`Discovery`].
///
/// One daemon serves both directions. A host creates it once, passes it to
/// [`ClientConfig::inbound`](crate::ClientConfig::inbound) or to
/// [`discover_servers`](super::discover_servers), and keeps it alive for as long as discovery
/// should work: dropping it shuts the daemon down.
pub struct MdnsDiscovery {
    /// The library's daemon, cloned into every call that talks to it.
    daemon: ServiceDaemon,
    /// Full names of the records this handle published, keyed by service type.
    registered: Mutex<HashMap<String, String>>,
}

impl MdnsDiscovery {
    /// Starts the mDNS daemon.
    ///
    /// # Errors
    /// Returns an error when the daemon cannot create its sockets. A build that does not use
    /// discovery never calls this.
    pub fn new() -> Result<MdnsDiscovery> {
        let daemon = ServiceDaemon::new().context("failed to start the mDNS daemon")?;
        Ok(MdnsDiscovery {
            daemon,
            registered: Mutex::new(HashMap::new()),
        })
    }
}

impl fmt::Debug for MdnsDiscovery {
    /// Names the backend without reaching into the daemon.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MdnsDiscovery")
            .field("registered", &self.registered)
            .finish_non_exhaustive()
    }
}

impl Drop for MdnsDiscovery {
    /// Ends the daemon thread; a dropped backend must not keep a multicast socket open.
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}

impl Discovery for MdnsDiscovery {
    fn advertise(&self, service: ServiceAdvertisement) -> Result<()> {
        let info = service_info(&service)?;
        let fullname = info.get_fullname().to_owned();
        self.daemon
            .register(info)
            .with_context(|| format!("failed to publish {}", service.service_type))?;
        let previous = self
            .registered
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(service.service_type.clone(), fullname);
        // One record per service type: publishing a second one under the same type would leave
        // the first pointing at an endpoint that may no longer exist.
        if let Some(previous) = previous {
            let _ = self.daemon.unregister(&previous);
        }
        Ok(())
    }

    fn withdraw(&self, service_type: &str) -> Result<()> {
        let fullname = self
            .registered
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(service_type);
        if let Some(fullname) = fullname {
            self.daemon
                .unregister(&fullname)
                .with_context(|| format!("failed to withdraw {service_type}"))?;
        }
        Ok(())
    }

    fn browse(&self, service_type: &str) -> Result<Vec<DiscoveredServer>> {
        let receiver = self
            .daemon
            .browse(service_type)
            .with_context(|| format!("failed to browse {service_type}"))?;
        let servers = collect(&receiver, BROWSE_WINDOW);
        // The query is per call; leaving it running would keep the daemon answering a browse the
        // caller no longer collects.
        let _ = self.daemon.stop_browse(service_type);
        Ok(servers)
    }
}

/// Collects the resolved records that arrive within `window`.
fn collect(receiver: &Receiver<ServiceEvent>, window: Duration) -> Vec<DiscoveredServer> {
    let deadline = Instant::now() + window;
    let mut found: Vec<DiscoveredServer> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return found;
        }
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(resolved)) => {
                if let Some(server) = discovered(&resolved) {
                    if seen.iter().any(|name| name == resolved.get_fullname()) {
                        continue;
                    }
                    seen.push(resolved.get_fullname().to_owned());
                    found.push(server);
                }
            }
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return found,
        }
    }
}

/// Turns one resolved service into the record the protocol can dial.
///
/// The `path` TXT record is required; a record without one, or one that resolves to no address
/// this peer may use, is not offered at all.
fn discovered(resolved: &ResolvedService) -> Option<DiscoveredServer> {
    let path = resolved.get_property_val_str("path")?.to_owned();
    let name = resolved
        .get_property_val_str("name")
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    let mut addresses: Vec<String> = resolved
        .get_addresses()
        .iter()
        .map(mdns_sd::ScopedIp::to_ip_addr)
        .filter(|address| !address.is_loopback() && !address.is_unspecified())
        .map(|address| std::net::SocketAddr::new(address, resolved.get_port()).to_string())
        .collect();
    addresses.sort();
    if addresses.is_empty() {
        return None;
    }
    Some(DiscoveredServer {
        addresses,
        path,
        name,
    })
}

/// Builds the mDNS record a [`ServiceAdvertisement`] describes.
///
/// Pure, so the TXT records are testable without a daemon or a socket.
fn service_info(service: &ServiceAdvertisement) -> Result<ServiceInfo> {
    let instance = service
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or("Sendspin");
    let mut properties = HashMap::new();
    properties.insert("path".to_owned(), service.path.clone());
    if let Some(name) = &service.name {
        properties.insert("name".to_owned(), name.clone());
    }
    // The host record is process-scoped, so two instances on one machine do not merge their
    // address sets, and no hostname from this machine enters the source or a log.
    let host = format!("sendspin-{}.local.", std::process::id());
    let info = ServiceInfo::new(
        &service.service_type,
        instance,
        &host,
        "",
        service.port,
        properties,
    )
    .with_context(|| format!("failed to build the record for {}", service.service_type))?;
    Ok(info.enable_addr_auto())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CLIENT_SERVICE_TYPE, DEFAULT_SENDSPIN_PATH, SERVER_SERVICE_TYPE};

    /// The client record carries the service type, port, path and name, without a socket.
    #[test]
    fn a_client_record_has_the_service_the_port_the_path_and_the_name() {
        let record = ServiceAdvertisement::client(8928, DEFAULT_SENDSPIN_PATH, "A player");
        let info = service_info(&record).expect("the record is valid");
        assert_eq!(info.get_type(), CLIENT_SERVICE_TYPE);
        assert_eq!(info.get_port(), 8928);
        assert_eq!(
            info.get_property_val_str("path"),
            Some(DEFAULT_SENDSPIN_PATH),
            "the path TXT record is required"
        );
        assert_eq!(
            info.get_property_val_str("name"),
            Some("A player"),
            "the name TXT record repeats the player name"
        );
        assert!(info.is_addr_auto(), "the addresses come from the host");
    }

    /// A record with no name still publishes the path and uses an instance name.
    #[test]
    fn a_record_without_a_name_keeps_the_required_path_record() {
        let record = ServiceAdvertisement {
            service_type: SERVER_SERVICE_TYPE.to_owned(),
            port: 8927,
            path: "/sendspin".to_owned(),
            name: None,
        };
        let info = service_info(&record).expect("the record is valid");
        assert_eq!(info.get_type(), SERVER_SERVICE_TYPE);
        assert_eq!(info.get_property_val_str("path"), Some("/sendspin"));
        assert_eq!(
            info.get_property_val_str("name"),
            None,
            "an optional TXT record is absent, not empty"
        );
        assert!(
            !info.get_fullname().starts_with('.'),
            "an unnamed record still gets an instance name"
        );
    }
}
