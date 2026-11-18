//! Discovery helpers: pick this run's record, probe what it advertises, name the stage that failed.
//!
//! A browse blocks, so it is not here. Everything that happens to a record after it arrives is, so
//! the filter, the endpoint parse and the diagnostics are decided without a daemon.

use std::time::Duration;

use syncspin_client::DiscoveredServer;

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

/// Returns the first endpoint of `server` that accepts a TCP connection, or `None`.
///
/// The walk and the probe are the client library's ([`syncspin_client::reachable_endpoint`]); only
/// the per-address budget is shorter, because a run has a few seconds in all. The returned endpoint
/// is the one the session dials, so the choice is not made twice. The probe never reaches the
/// server's event stream: the server reports a connection only after the WebSocket upgrade and the
/// Noise handshake.
pub(crate) async fn reachable(server: &DiscoveredServer) -> Option<String> {
    syncspin_client::reachable_endpoint(server, PROBE_TIMEOUT)
        .await
        .ok()
}

/// The stage a deadline ended in, named by the call that awaited it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Connection,
    Stream,
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
pub(crate) fn timeout_message(stage: Stage, budget: Duration, frames: usize) -> String {
    match stage {
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
    fn the_messages_name_the_stage_and_the_budget() {
        let discovery = no_service_message("mdns-pair-7", Duration::from_secs(10));
        assert_eq!(
            discovery,
            "no service named mdns-pair-7 found within 10 s; multicast and one non-loopback IPv4 \
             interface are required"
        );

        let connection = timeout_message(
            Stage::Connection,
            Duration::from_secs(10),
            crate::GATE_FRAMES,
        );
        assert!(connection.contains("no connection"));
        let stream = timeout_message(Stage::Stream, Duration::from_secs(10), crate::GATE_FRAMES);
        assert!(stream.contains("20 audio frames"));
    }
}
