//! Discovery helpers: pick this run's record, probe what it advertises, name the stage that failed.
//!
//! A browse blocks, so it is not here. Everything that happens to a record after it arrives is, so
//! the filter, the endpoint parse and the diagnostics are decided without a daemon.

use std::time::Duration;

use syncspin_client::DiscoveredServer;
use tokio::net::TcpStream;

/// How long one advertised address gets to accept before the next one is tried.
///
/// A refused connection returns at once; the timeout only bounds an address that silently drops the
/// attempt, such as a stale entry on a family the server never bound.
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// Returns the records whose TXT `name` is exactly `run_name`.
///
/// The match is exact on purpose: the run name carries the PID, so a stale record from an earlier
/// run and a differently cased look-alike both stay out, and only the service this run published is
/// ever dialled.
pub(crate) fn matching_servers<'a>(
    servers: &'a [DiscoveredServer],
    run_name: &str,
) -> Vec<&'a DiscoveredServer> {
    servers
        .iter()
        .filter(|server| server.name.as_deref() == Some(run_name))
        .collect()
}

/// Returns the `host:port` a `ws://` endpoint names, or `None` when it names none.
///
/// [`DiscoveredServer::endpoints`] yields `ws://host:port/path`; the probe needs the authority half,
/// so this strips the scheme and keeps what precedes the first `/`. A missing `ws://`, an empty
/// authority (`ws:///sendspin`) and a scheme this example does not speak all yield `None` rather
/// than a guess.
fn probe_address(endpoint: &str) -> Option<&str> {
    let rest = endpoint.strip_prefix("ws://")?;
    let address = match rest.split_once('/') {
        Some((address, _)) => address,
        None => rest,
    };
    if address.is_empty() {
        None
    } else {
        Some(address)
    }
}

/// Returns the first endpoint of `server` that accepts a TCP connection, walking them in order.
///
/// [`DiscoveredServer::endpoints`] already orders IPv4 first. What it cannot know is whether the
/// first address is still served: a previous run's record, or a host that bound one family only,
/// can leave a dead entry at the front. The probe is one TCP connect with a short timeout, and the
/// returned endpoint is the one the session then dials, so the choice is not made twice.
pub(crate) async fn reachable_endpoint(server: &DiscoveredServer) -> Option<String> {
    for endpoint in server.endpoints() {
        let Some(address) = probe_address(&endpoint) else {
            continue;
        };
        // Dropping the accepted stream closes the probe; it only decides reachability.
        let accepted = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(address))
            .await
            .is_ok_and(|result| result.is_ok());
        if accepted {
            return Some(endpoint);
        }
    }
    None
}

/// The stage the flow had reached when the deadline ended it.
///
/// The flow records the stage in a shared counter while it runs and reads it back in the timeout's
/// error arm. [`Stage::as_u8`] and [`Stage::from_u8`] are the only place the encoding lives, so a
/// reordered variant cannot silently mislabel a timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Discovery,
    Connection,
    Stream,
}

impl Stage {
    /// Encodes the stage for the shared counter.
    pub(crate) const fn as_u8(self) -> u8 {
        match self {
            Stage::Discovery => 0,
            Stage::Connection => 1,
            Stage::Stream => 2,
        }
    }

    /// Decodes a stage the flow recorded; an unknown code reads as the start state, so a
    /// corrupted counter cannot claim the flow got further than it did.
    pub(crate) const fn from_u8(code: u8) -> Stage {
        match code {
            1 => Stage::Connection,
            2 => Stage::Stream,
            _ => Stage::Discovery,
        }
    }
}

/// The diagnostic for a browse that never saw this run's record.
///
/// The named causes are the ones that produce this failure on a real host: no multicast, or no
/// non-loopback IPv4 interface for the advertisement to leave on. A connection or stream failure is
/// reported under its own stage instead.
pub(crate) fn no_service_message(run_name: &str, budget: Duration) -> String {
    format!(
        "no service named {run_name} found within {} s; multicast and one non-loopback IPv4 \
         interface are required",
        budget.as_secs()
    )
}

/// The diagnostic for a flow that timed out in `stage`; `frames` is the gate the run waits for.
pub(crate) fn timeout_message(
    stage: Stage,
    run_name: &str,
    budget: Duration,
    frames: usize,
) -> String {
    match stage {
        Stage::Discovery => no_service_message(run_name, budget),
        Stage::Connection => format!(
            "discovered the service, but no connection was established within {} s",
            budget.as_secs()
        ),
        Stage::Stream => format!(
            "connected, but {frames} audio frames did not arrive within {} s",
            budget.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: Option<&str>, address: &str) -> DiscoveredServer {
        DiscoveredServer {
            addresses: vec![address.to_owned()],
            path: "/sendspin".to_owned(),
            name: name.map(str::to_owned),
        }
    }

    #[test]
    fn only_the_run_name_matches() {
        let records = vec![
            record(Some("mdns-pair-1"), "192.0.2.1:8927"),
            record(Some("other"), "192.0.2.2:8927"),
            record(None, "192.0.2.3:8927"),
        ];
        let matching = matching_servers(&records, "mdns-pair-1");
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].addresses, ["192.0.2.1:8927"]);

        assert!(
            matching_servers(&records, "MDNS-PAIR-1").is_empty(),
            "the match is exact"
        );
    }

    #[test]
    fn the_probe_address_comes_from_the_endpoint() {
        assert_eq!(
            probe_address("ws://192.0.2.10:8927/sendspin"),
            Some("192.0.2.10:8927")
        );
        assert_eq!(
            probe_address("ws://[2001:db8::1]:8927/sendspin"),
            Some("[2001:db8::1]:8927")
        );
        assert_eq!(probe_address("http://192.0.2.10:8927/sendspin"), None);
        assert_eq!(probe_address("ws:///sendspin"), None);
    }

    #[test]
    fn the_messages_name_the_stage_and_the_budget() {
        let discovery = no_service_message("mdns-pair-7", Duration::from_secs(10));
        assert_eq!(
            discovery,
            "no service named mdns-pair-7 found within 10 s; multicast and one non-loopback IPv4 \
             interface are required"
        );

        let connection = timeout_message(
            Stage::Connection,
            "mdns-pair-7",
            Duration::from_secs(10),
            crate::GATE_FRAMES,
        );
        assert!(connection.contains("no connection"));
        let stream = timeout_message(
            Stage::Stream,
            "mdns-pair-7",
            Duration::from_secs(10),
            crate::GATE_FRAMES,
        );
        assert!(stream.contains("20 audio frames"));
        assert_eq!(
            timeout_message(
                Stage::Discovery,
                "mdns-pair-7",
                Duration::from_secs(10),
                crate::GATE_FRAMES
            ),
            discovery
        );
    }

    #[test]
    fn the_stage_encoding_round_trips() {
        for stage in [Stage::Discovery, Stage::Connection, Stage::Stream] {
            assert_eq!(Stage::from_u8(stage.as_u8()), stage);
        }
        assert_eq!(
            Stage::from_u8(9),
            Stage::Discovery,
            "an unknown code must not claim progress"
        );
    }
}
