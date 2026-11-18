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
                        // A peer chooses its own name; `Debug` escapes control characters
                        // instead of letting them reach the terminal.
                        println!(
                            "ignored {name:?} ({client_id}): this run approves only \
                             {expected_client_id}"
                        );
                    }
                }
                Some(Event::ClientActivated { client_id, roles }) => {
                    println!("activated with roles: {}", roles.join(", "));
                    // Only this run's client opens the stream; another connection's activation
                    // must not start one.
                    if stream.is_none()
                        && client_id == expected_client_id
                        && roles.iter().any(|role| role == PLAYER_ROLE) {
                        stream = Some(server.open_stream(TrackInfo {
                            title: Some("mdns-pair smoke test".to_owned()),
                            ..TrackInfo::default()
                        }));
                        written = 0;
                        // The writer stamps each chunk with the group's fixed start lead, so a
                        // chunk is on the wire well before the instant it must play; the pacing
                        // here only keeps the host from sending the whole stream at once.
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
                // Never print an event's payload: a later event may carry pairing material.
                Some(_) => println!("server event"),
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

    // A stream that stops sending without a `stream/end` leaves any remaining player waiting for
    // audio that never comes; end it before the listener goes away.
    if let Some(mut writer) = stream.take() {
        writer.end();
    }
    server.shutdown().await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Result;
    use syncspin_client::{AudioFormat, GoodbyeReason, Identity as ClientIdentity};
    use syncspin_server::{DiscoveredClient, Discovery, ServiceAdvertisement};
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    use super::*;
    use crate::client_role::{connect_session, wait_for_connection, wait_for_gate};
    use crate::sink::CountingSink;
    use crate::{GATE_FRAMES, TEARDOWN};

    /// A backend that publishes nothing and browses nothing, so the test opens no multicast socket.
    struct NoDiscovery;

    impl Discovery for NoDiscovery {
        fn advertise(&self, _service: ServiceAdvertisement) -> Result<()> {
            Ok(())
        }

        fn withdraw(&self, _service_type: &str) -> Result<()> {
            Ok(())
        }

        fn browse(&self, _service_type: &str) -> Result<Vec<DiscoveredClient>> {
            Ok(Vec::new())
        }
    }

    /// The run's core promise: only the client whose static key this run generated is approved, and
    /// only that client receives a stream. Loopback only; no daemon, no multicast.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_the_expected_key_is_approved() {
        let identity = ClientIdentity::generate();
        let expected = identity.public_base64();
        let mut config = ServerConfig::new(
            "mdns-pair-test".to_owned(),
            syncspin_server::Identity::generate(),
        );
        config.bind = SocketAddr::from(([127, 0, 0, 1], 0));
        config.discovery = Some(Arc::new(NoDiscovery));

        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let (departure_tx, _departure_rx) = oneshot::channel();
        let server = tokio::spawn(serve(config, ready_tx, stop_rx, departure_tx, expected));
        let address = ready_rx.await.expect("the server published its address");
        let endpoint = format!("ws://{address}/sendspin");
        let format = AudioFormat::pcm(48_000, 2, 16);

        // The approved client: the key the server compares against.
        let (sink, counters) = CountingSink::new(GATE_FRAMES, format.clone());
        let (mut handle, mut events) =
            connect_session("approved", &endpoint, identity, Box::new(sink))
                .await
                .expect("the approved session starts");
        wait_for_connection(&mut events, &endpoint)
            .await
            .expect("the approved handshake completes");
        timeout(
            Duration::from_secs(5),
            wait_for_gate(&mut events, &counters),
        )
        .await
        .expect("the gate arrives")
        .expect("the gate passes");

        // Another key is admitted to the connection but never to the stream.
        let (sink, counters) = CountingSink::new(1, format);
        let (_other, mut other_events) = connect_session(
            "foreign",
            &endpoint,
            ClientIdentity::generate(),
            Box::new(sink),
        )
        .await
        .expect("the foreign session starts");
        // The handshake completing proves the server processed this connection; the gate it never
        // reaches is what would prove approval.
        wait_for_connection(&mut other_events, &endpoint)
            .await
            .expect("the foreign handshake completes");
        assert!(
            timeout(
                Duration::from_millis(500),
                wait_for_gate(&mut other_events, &counters)
            )
            .await
            .is_err(),
            "a foreign key must not be approved"
        );

        handle.close(GoodbyeReason::Shutdown);
        let _ = timeout(TEARDOWN, handle.finished()).await;
        let _ = stop_tx.send(());
        timeout(TEARDOWN, server)
            .await
            .expect("the server stops")
            .expect("the server task does not panic")
            .expect("the shutdown is clean");
    }
}
