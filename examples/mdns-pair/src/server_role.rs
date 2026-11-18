//! The server half of the run: publish, approve this run's client, stream silence, withdraw.
//!
//! [`Server::start`] advertises before it returns, so the record exists by the time the bound
//! address is handed to the run. This module is the host loop around the handle: it approves only
//! the client whose static public key the run generated, opens one stream once the player role is
//! active, and writes 20 ms silent chunks until the run stops it. It ends by withdrawing the record
//! in [`ServerHandle::shutdown`](syncspin_server::ServerHandle::shutdown).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use syncspin_server::{Event, Server, ServerConfig, StreamWriter, TrackInfo};
use tokio::sync::oneshot;
use tokio::time::{interval, MissedTickBehavior};

use crate::{CHUNK_BYTES, CHUNK_COUNT, CHUNK_MS};

/// Versioned role a connection needs before the run opens the stream.
const PLAYER_ROLE: &str = "player@v1";

/// Starts the server, reports its address on `ready`, and serves until `stop` fires.
///
/// The run waits for `ready` before it browses, so a listener that cannot start is an error here
/// rather than a discovery timeout there. The loop ends only on the stop signal or when the event
/// stream ends: `ClientLeft` carries no client id, so it cannot tell this run's departure from any
/// other LAN client's, and a foreign departure must not end the server. A departure is printed and
/// reported on `departure` (best effort) after the goodbye that produced it.
pub async fn serve(
    config: ServerConfig,
    ready: oneshot::Sender<SocketAddr>,
    mut stop: oneshot::Receiver<()>,
    departure: oneshot::Sender<()>,
    expected_client_id: String,
) -> Result<()> {
    let run_name = config.name.clone();
    let mut server = Server::start(config).await?;
    let address = server.local_addr();
    // The wildcard address carries the port the record names; the daemon resolves the record to
    // this host's interface addresses. The full service type is `_sendspin-server._tcp.local.`;
    // the line names the service without the `local.` suffix the daemon appends.
    println!("published _sendspin-server._tcp as {run_name} on {address}");
    let _ = ready.send(address);

    let mut events = server.events();
    let mut stream: Option<StreamWriter> = None;
    let mut written = 0;
    // One departure is all the run listens for, so the sender is taken on the first `ClientLeft`.
    // The loop keeps serving whether or not anyone is waiting for it.
    let mut departure = Some(departure);
    let silence = vec![0u8; CHUNK_BYTES];
    let mut pace = interval(Duration::from_millis(CHUNK_MS));
    // A late wakeup writes one chunk, not a burst: the frames are meaningless once the run is over.
    pace.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = &mut stop => break,
            event = events.next() => match event {
                Some(Event::ClientConnected {
                    client_id,
                    name,
                    approved,
                }) => {
                    // The TXT `name` is on the LAN and anyone can claim it; the static public key
                    // is what the handshake proves, so only that decides who joins. A foreign
                    // connection is printed and stays unapproved.
                    if client_id == expected_client_id {
                        match server.approve(&client_id).await {
                            Ok(()) => println!(
                                "approved {name} as {client_id} (approved on arrival: {approved})"
                            ),
                            Err(error) => println!("could not approve {name}: {error:#}"),
                        }
                    } else {
                        println!(
                            "ignored {name} ({client_id}): this run approves only \
                             {expected_client_id}"
                        );
                    }
                }
                Some(Event::ClientActivated { roles, .. }) => {
                    println!("activated with roles: {}", roles.join(", "));
                    if stream.is_none() && roles.iter().any(|role| role == PLAYER_ROLE) {
                        stream = Some(server.open_stream(TrackInfo {
                            title: Some("mdns-pair smoke test".to_owned()),
                            ..TrackInfo::default()
                        }));
                        written = 0;
                        println!(
                            "streaming {CHUNK_COUNT} silent chunks of {CHUNK_BYTES} bytes, one \
                             every {CHUNK_MS} ms"
                        );
                    }
                }
                Some(Event::ClientLeft { reason }) => {
                    println!("client left: {reason}");
                    if let Some(departure) = departure.take() {
                        let _ = departure.send(());
                    }
                }
                Some(other) => println!("server event: {other:?}"),
                None => break,
            },
            _ = pace.tick(), if stream.is_some() => {
                if written < CHUNK_COUNT {
                    if let Some(writer) = stream.as_mut() {
                        writer.write(&silence);
                        written += 1;
                    }
                }
            }
        }
    }

    server.shutdown().await
}
