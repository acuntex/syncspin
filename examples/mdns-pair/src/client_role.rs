//! The client half of the run: browse for this run's record, dial it, wait for the session.
//!
//! The browse is a synchronous call that takes up to the backend's one-second window, so it runs on
//! the blocking pool instead of an async worker. `connect` only schedules the attempt; the outcome
//! arrives on the event stream, and this module turns the first `Connected` into the handle the
//! run drives.

#[cfg(feature = "mdns")]
use std::sync::Arc;
#[cfg(feature = "mdns")]
use std::time::Duration;

#[cfg(feature = "mdns")]
use anyhow::Context;
use anyhow::{bail, Result};
#[cfg(feature = "mdns")]
use syncspin_client::discover_servers;
use syncspin_client::{connect, ClientConfig, ClientHandle, Event, EventStream, Identity, Sink};

// The client crate and the server crate both export an `MdnsDiscovery`; each side of the run
// starts its own daemon, so the alias says which role this one plays.
#[cfg(feature = "mdns")]
use syncspin_client::MdnsDiscovery as ClientMdns;

#[cfg(feature = "mdns")]
use crate::find::{matching_servers, reachable_endpoint};
use crate::sink::Counters;
use crate::PLAYER_SUFFIX;

/// How long the loop waits between two browse attempts.
///
/// A browse already blocks for one second, so this is only the pause that keeps the loop from
/// spinning when the backend answers at once.
#[cfg(feature = "mdns")]
const RETRY_PAUSE: Duration = Duration::from_millis(200);

/// Browses until a record named `run_name` answers on one of its endpoints.
///
/// Only the record this run published is dialled: the exact TXT `name` filter keeps a stale record
/// and a differently cased look-alike out. The endpoint that answered the probe is the one returned,
/// so the session does not choose again between addresses.
#[cfg(feature = "mdns")]
pub async fn discover(run_name: &str) -> Result<String> {
    // This is the client's own daemon, a separate mDNS stack from the server's: the run exists to
    // exercise the advertisement and the browse as two peers see them.
    let discovery = Arc::new(ClientMdns::new().context("failed to start the mDNS daemon")?);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        // One browse blocks for the backend's one-second window. It runs on the blocking pool so
        // the server keeps serving; the outer deadline cannot cancel it, which is why this loop
        // also checks the deadline itself between attempts.
        let servers = tokio::task::spawn_blocking({
            let discovery = Arc::clone(&discovery);
            move || discover_servers(discovery.as_ref())
        })
        .await
        .context("the discovery task ended")??;
        for server in matching_servers(&servers, run_name) {
            if let Some(endpoint) = reachable_endpoint(server).await {
                println!("discovered {endpoint} on browse {attempt}");
                return Ok(endpoint);
            }
        }
        println!("browse {attempt}: no reachable service named {run_name} yet");
        tokio::time::sleep(RETRY_PAUSE).await;
        // The caller's deadline bounds this loop; one browse is not cancellable, so the loop owns
        // no clock of its own.
    }
}

/// Waits for the frame gate while still watching the session.
///
/// The session reports a disconnect or a server error on the same stream the gate runs beside; a
/// gate that only waited for the counter would let either become a misleading stream timeout. The
/// outer deadline bounds this call, so no branch needs a timer of its own.
pub async fn wait_for_gate(events: &mut EventStream, counters: &Counters) -> Result<()> {
    loop {
        tokio::select! {
            biased;
            _ = counters.wait() => return Ok(()),
            event = events.next() => match event {
                Some(Event::Disconnected { reason, .. }) => {
                    bail!("the connection ended before the frame gate: {reason}")
                }
                Some(Event::ServerError { reason }) => {
                    bail!("the server refused the session before the frame gate: {reason}")
                }
                Some(_) => {}
                None => bail!("the event stream ended before the frame gate"),
            },
        }
    }
}

/// Starts the session against `endpoint` and hands the handle back at once.
///
/// The identity is generated once by the run and handed here, so the session presents the key whose
/// public half the server approves; nothing is stored, and the server sees a client it has never
/// approved, which is the approval gate the run demonstrates. Handing the handle back before the
/// handshake completes is what lets the run say goodbye when the wait for `Connected` is cut short:
/// the session exists from this call on.
pub async fn connect_session(
    run_name: &str,
    endpoint: &str,
    identity: Identity,
    sink: Box<dyn Sink>,
) -> Result<(ClientHandle, EventStream)> {
    // The player gets its own name, so the server's log lines tell the two roles apart; the
    // identity is the key the server decides on.
    let config = ClientConfig::new(endpoint, format!("{run_name}{PLAYER_SUFFIX}"), identity);
    connect(config, sink).await
}

/// Waits for the session to report [`Event::Connected`].
///
/// A disconnect and a server error are fatal here - the endpoint is pinned and this run has no
/// second attempt to offer.
pub async fn wait_for_connection(events: &mut EventStream, endpoint: &str) -> Result<()> {
    loop {
        match events.next().await {
            Some(Event::Connected {
                server_id,
                encrypted,
            }) => {
                // The library has no unencrypted path; asserting it here keeps a future downgrade
                // from turning this smoke test green.
                if !encrypted {
                    bail!("the connection to {server_id} is not encrypted");
                }
                println!("connected to {server_id} at {endpoint} (encrypted)");
                return Ok(());
            }
            Some(Event::Disconnected { reason, .. }) => {
                bail!("the connection ended before it was established: {reason}")
            }
            Some(Event::ServerError { reason }) => {
                bail!("the server refused the session: {reason}")
            }
            // Events of the session's lifecycle that this run does not print: nothing before
            // `Connected` carries something the run acts on.
            Some(_) => {}
            None => bail!("the connection ended before it was established"),
        }
    }
}
