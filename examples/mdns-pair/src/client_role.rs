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
use crate::find::{matching_servers, reachable};
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
///
/// Returns `None` once `deadline` has passed without a match, or once `interrupt` has latched. A
/// browse that is in flight cannot be cancelled, so it is awaited to its end; the loop then stops
/// instead of starting another, and the daemon is dropped before this returns. The deadline and an
/// interrupt are therefore both honoured at most one browse window late. The caller tells the two
/// `None`s apart by reading `interrupt`.
///
/// # Errors
/// A record that matched but whose addresses all refused or timed out is an error once the deadline
/// passes, carrying the last attempt's per-address causes: discovery worked and the dial did not,
/// which is a different failure from a record that never appeared.
#[cfg(feature = "mdns")]
pub async fn discover(
    run_name: &str,
    deadline: tokio::time::Instant,
    interrupt: &tokio::sync::watch::Receiver<bool>,
) -> Result<Option<String>> {
    // This is the client's own daemon, a separate mDNS stack from the server's: the run exists to
    // exercise the advertisement and the browse as two peers see them.
    let discovery = Arc::new(ClientMdns::new().context("failed to start the mDNS daemon")?);
    let mut attempt = 0u32;
    // The newest probe failure for a record that matched; it replaces "never appeared" at the end.
    let mut last_refusal: Option<String> = None;
    loop {
        if *interrupt.borrow() {
            return Ok(None);
        }
        attempt += 1;
        // One browse blocks for the backend's one-second window. It runs on the blocking pool so
        // the server keeps serving, and it is always awaited: dropping the future would leave the
        // browse and its daemon running behind the caller's teardown.
        let browsed = tokio::task::spawn_blocking({
            let discovery = Arc::clone(&discovery);
            move || discover_servers(discovery.as_ref())
        })
        .await
        .context("the discovery task ended")?;
        // A browse that fails is retried like one that finds nothing: the daemon can report an
        // error on its first window while the record is not yet on the wire, and the caller's
        // deadline bounds the loop either way.
        let servers = match browsed {
            Ok(servers) => servers,
            Err(error) => {
                println!("browse {attempt} failed: {error:#}");
                if tokio::time::Instant::now() >= deadline {
                    return end_without_match(last_refusal);
                }
                tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + RETRY_PAUSE))
                    .await;
                continue;
            }
        };
        for server in matching_servers(&servers, run_name) {
            match reachable(server).await {
                Ok(endpoint) => {
                    // The path comes from a TXT record any LAN host can publish; `Debug` escapes
                    // it.
                    println!("discovered {endpoint:?} on browse {attempt}");
                    return Ok(Some(endpoint));
                }
                Err(error) => {
                    // The causes name addresses from a record any LAN host can publish.
                    let cause = format!("{error:#}");
                    println!("browse {attempt}: {run_name} is not reachable: {cause:?}");
                    last_refusal = Some(cause);
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return end_without_match(last_refusal);
        }
        println!("browse {attempt}: no reachable service named {run_name} yet");
        tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + RETRY_PAUSE)).await;
    }
}

/// The end of a discovery that found no endpoint: an error when a record matched and could not be
/// dialled, `None` when none ever appeared.
#[cfg(feature = "mdns")]
fn end_without_match(last_refusal: Option<String>) -> Result<Option<String>> {
    match last_refusal {
        Some(cause) => bail!("found the service, but no address accepted a connection: {cause:?}"),
        None => Ok(None),
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

/// Waits for the session to report [`Event::Connected`] from the server whose key is
/// `expected_server_id`.
///
/// A disconnect and a server error are fatal here - the endpoint is pinned and this run has no
/// second attempt to offer.
pub async fn wait_for_connection(
    events: &mut EventStream,
    endpoint: &str,
    expected_server_id: &str,
) -> Result<()> {
    loop {
        match events.next().await {
            Some(Event::Connected {
                server_id,
                encrypted,
            }) => {
                // The library has no unencrypted path; asserting it here keeps a future downgrade
                // from turning this smoke test green.
                if !encrypted {
                    bail!("the connection to {server_id:?} is not encrypted");
                }
                // The TXT `name` is only a discovery hint that any LAN host can copy; the server's
                // static key is what the handshake proves. A different key means the record led to
                // another host, and a green run would not have exercised this run's server.
                if server_id != expected_server_id {
                    bail!(
                        "the server at {endpoint:?} is {server_id:?}, not this run's server \
                         {expected_server_id:?}"
                    );
                }
                println!(
                    "connected to {} at {endpoint:?} (encrypted)",
                    crate::server_role::short_id(&server_id)
                );
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
