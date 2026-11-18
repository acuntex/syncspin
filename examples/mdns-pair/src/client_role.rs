//! The client half of the run: browse for this run's record, dial it, wait for the session.
//!
//! The browse blocks its worker for one second per attempt, which is why the run's runtime has a
//! second worker for the server. `connect` only schedules the attempt; the outcome arrives on the
//! event stream, and this module turns the first `Connected` into the handle the run drives.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use syncspin_client::{
    connect, discover_servers, ClientConfig, ClientHandle, Event, EventStream, Identity, Sink,
};

// The client crate and the server crate both export an `MdnsDiscovery`; each side of the run
// starts its own daemon, so the alias says which role this one plays.
use syncspin_client::MdnsDiscovery as ClientMdns;

use crate::find::{matching_servers, no_service_message, reachable_endpoint};

/// How long the loop waits between two browse attempts.
///
/// A browse already blocks for one second, so this is only the pause that keeps the loop from
/// spinning when the backend answers at once.
const RETRY_PAUSE: Duration = Duration::from_millis(200);

/// Browses until a record named `run_name` answers on one of its endpoints, or `budget` is spent.
///
/// Only the record this run published is dialled: the exact TXT `name` filter keeps a stale record
/// and a differently cased look-alike out. The endpoint that answered the probe is the one returned,
/// so the session does not choose again between addresses.
pub async fn discover(run_name: &str, budget: Duration) -> Result<String> {
    // This is the client's own daemon, a separate mDNS stack from the server's: the run exists to
    // exercise the advertisement and the browse as two peers see them.
    let discovery = ClientMdns::new().context("failed to start the mDNS daemon")?;
    let deadline = Instant::now() + budget;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        // One browse blocks for the backend's one-second window; the outer deadline cannot cancel
        // it, which is why this loop checks the deadline itself between attempts.
        let servers = discover_servers(&discovery)?;
        for server in matching_servers(&servers, run_name) {
            if let Some(endpoint) = reachable_endpoint(server).await {
                println!("discovered {endpoint} on browse {attempt}");
                return Ok(endpoint);
            }
        }
        println!("browse {attempt}: no reachable service named {run_name} yet");
        tokio::time::sleep(RETRY_PAUSE).await;
        if Instant::now() >= deadline {
            return Err(anyhow!(no_service_message(run_name, budget)));
        }
    }
}

/// Connects to `endpoint` and waits for the session to report [`Event::Connected`].
///
/// The identity is generated per run: nothing is stored, so the server sees a client it has never
/// approved and the approval gate is part of what the run demonstrates. A disconnect and a server
/// error are fatal here - the endpoint is pinned and this run has no second attempt to offer.
pub async fn await_connected(
    run_name: &str,
    endpoint: &str,
    sink: Box<dyn Sink>,
) -> Result<(ClientHandle, EventStream)> {
    // The run name is also the player name: the server approves the `client/hello` name, and the
    // two must be equal for the connection to be the one the server publishes for.
    let config = ClientConfig::new(endpoint, run_name, Identity::generate());
    let (handle, mut events) = connect(config, sink).await?;
    loop {
        match events.next().await {
            Some(Event::Connected {
                server_id,
                encrypted,
            }) => {
                println!("connected to {server_id} at {endpoint} (encrypted: {encrypted})");
                return Ok((handle, events));
            }
            Some(Event::Disconnected { reason, .. }) => {
                bail!("the connection ended before the stream arrived: {reason}")
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
