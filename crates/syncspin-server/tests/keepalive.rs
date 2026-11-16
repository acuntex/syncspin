//! The server's WebSocket keepalive: a silent link is pinged, an unanswered ping drops the peer,
//! and a normal frame keeps the connection alive.
//!
//! The first five tests drive the listener with the fake client in `common`, which is the only peer
//! that can leave a ping unanswered while keeping the socket open (the real client always answers a
//! ping). They measure the shipped 15 s and 10 s windows on a paused clock: the clock is frozen only
//! while the test waits for the server's timer, and every frame exchange runs on the real clock,
//! because a paused clock does not wake a socket read promptly. The last two are the cross-crate
//! proof that the two halves' keepalives interoperate: a real client on a real server must keep a
//! silent link alive, and neither side may go silent and survive.
//!
//! The server's pong to a client ping is pinned by `a_client_ping_is_answered_with_a_pong`, not by
//! the cross-crate pair: there both sides ping on the same window, so each side's ping keeps the
//! other's keepalive satisfied.

mod common;

use std::time::{Duration, Instant};

use common::*;
use syncspin_client::{
    Client, ClientConfig, Event as ClientEvent, EventStream as ClientEventStream, GoodbyeReason,
    Sink,
};

/// How long the integration test lets the frames cross loopback after resuming the clock.
const CROSS: Duration = Duration::from_millis(200);

/// A sink that discards what it is given.
struct NullSink;

impl Sink for NullSink {
    fn open(&mut self, _format: syncspin_client::AudioFormat) -> Result<()> {
        Ok(())
    }

    fn write(&mut self, _frame: syncspin_client::AudioFrame<'_>, _due: Instant) -> Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Asserts that no client disconnect arrived within `within`, draining any other event.
async fn expect_no_disconnect(events: &mut ClientEventStream, within: Duration) {
    loop {
        match tokio::time::timeout(within, events.next()).await {
            Err(_) => return,
            Ok(Some(ClientEvent::Disconnected { reason, .. })) => {
                panic!("the client disconnected during an idle round: {reason}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("the client event stream ended"),
        }
    }
}

/// Asserts that no client left within `within`, draining any other event.
async fn expect_no_client_left(events: &mut EventStream, within: Duration) {
    loop {
        match tokio::time::timeout(within, events.next()).await {
            Err(_) => return,
            Ok(Some(Event::ClientLeft { reason })) => {
                panic!("the server dropped the client during an idle round: {reason}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("the server event stream ended"),
        }
    }
}

/// Asserts that the server sent no ping within `within`.
async fn expect_no_ping(client: &mut FakeClient, within: Duration) {
    match tokio::time::timeout(within, client.socket.next()).await {
        Err(_) => {}
        Ok(Some(Ok(Message::Ping(payload)))) => {
            panic!("no ping may arrive inside the idle window, got {payload:?}")
        }
        Ok(_) => {}
    }
}

/// Connects and activates a fake client that the server leaves silent: no roles, so nothing is sent
/// in either direction until the keepalive pings.
async fn silent_client(port: u16) -> Result<FakeClient> {
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    client.activate().await?;
    Ok(client)
}

#[tokio::test]
async fn a_silent_connection_is_pinged_after_the_idle_window_and_survives_a_pong() -> Result<()> {
    let (server, port, _) = start().await?;
    let mut client = silent_client(port).await?;

    // The idle window is 15 s. The test cannot read the socket on a paused clock, so it measures
    // the window in two steps instead of the client suite's auto-advance: no ping may arrive at
    // 14 s, and one must arrive by 16 s, which bounds the window to the same 1 s slack the client
    // suite's assertion allows.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(14)).await;
    tokio::time::resume();
    tokio::time::sleep(CROSS).await;
    expect_no_ping(&mut client, Duration::from_millis(50)).await;

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::time::resume();
    tokio::time::sleep(CROSS).await;
    let (mut client, payload) = client.wait_for_ping().await?;
    assert_eq!(
        payload.len(),
        8,
        "the ping carries the 8-byte keepalive nonce"
    );

    // Answer the ping, then prove the server still serves this connection: a clock request still
    // gets its reply.
    client.send_pong(&payload).await?;
    let reply = client.round_trip_time(1_000).await?;
    assert_eq!(
        reply.client_transmitted, 1_000,
        "the server still serves the connection after the pong"
    );

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn an_unanswered_ping_drops_the_client_and_the_server_keeps_serving() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let client = silent_client(port).await?;

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::resume();
    tokio::time::sleep(CROSS).await;
    let (client, payload) = client.wait_for_ping().await?;
    assert_eq!(
        payload.len(),
        8,
        "the ping carries the 8-byte keepalive nonce"
    );

    // The ping stays unanswered while the socket stays open: exactly what a client that dropped the
    // session leaves behind.
    let holder = tokio::spawn(client.hold_unanswered_ping());

    // Past the pong window (15 s + 10 s), the server must end the connection and say why.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::resume();

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    match next_event(&mut events).await {
        Event::ClientLeft { reason } => {
            assert!(
                reason.contains("keepalive"),
                "the reason names the keepalive, got: {reason}"
            );
        }
        other => panic!("expected ClientLeft, got {other:?}"),
    }

    // The server still serves a second, healthy connection afterwards.
    let mut second = silent_client(port).await?;
    let reply = second.round_trip_time(2_000).await?;
    assert_eq!(
        reply.client_transmitted, 2_000,
        "the server still serves a healthy connection after dropping the silent one"
    );

    second.goodbye("shutdown").await?;
    holder.await.expect("the held socket task must not panic")?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_normal_frame_inside_the_pong_window_keeps_the_connection_alive() -> Result<()> {
    let (server, port, _) = start().await?;
    let client = silent_client(port).await?;

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::resume();
    tokio::time::sleep(CROSS).await;
    let (mut client, payload) = client.wait_for_ping().await?;
    assert_eq!(
        payload.len(),
        8,
        "the ping carries the 8-byte keepalive nonce"
    );

    // Five virtual seconds later - still inside the 10 s pong window - a normal frame, not a pong,
    // is the answer: the server asks whether the link delivers anything, not whether it delivers the
    // pong. Only the wait is virtual; the exchange runs on the real clock.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::time::resume();
    let reply = client.round_trip_time(1_000).await?;
    assert_eq!(reply.client_transmitted, 1_000);

    // The answer counts only if the server is still there once the bail would have fired: about 28 s,
    // with the ping 13 s old. A server that only accepted a pong ended the connection at 25 s, so
    // this request could not be answered at all.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(8)).await;
    tokio::time::resume();
    let reply = client.round_trip_time(2_000).await?;
    assert_eq!(reply.client_transmitted, 2_000);

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_client_ping_is_answered_with_a_pong() -> Result<()> {
    let (server, port, _) = start().await?;
    let mut client = silent_client(port).await?;

    // The server must answer a WebSocket ping it receives, with the payload it was sent. The
    // cross-crate test cannot pin this: there the two sides' own pings keep each other's keepalive
    // satisfied, so mutating the server's pong leaves it green.
    let payload = vec![9, 8, 7];
    client.send_ping(&payload).await?;
    let pong = loop {
        match client.next_message().await? {
            Some(Message::Pong(pong)) => break pong.to_vec(),
            Some(_) => continue,
            None => panic!("the connection closed before the pong"),
        }
    };
    assert_eq!(pong, payload, "the pong echoes the ping payload");

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_frame_waiting_at_the_pong_deadline_keeps_the_connection() -> Result<()> {
    let (server, port, _) = start().await?;
    let client = silent_client(port).await?;

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::resume();
    tokio::time::sleep(CROSS).await;
    let (mut client, payload) = client.wait_for_ping().await?;
    assert_eq!(
        payload.len(),
        8,
        "the ping carries the 8-byte keepalive nonce"
    );

    // A frame is now waiting on the wire, unread, while the pong window is about to close. Advance
    // to the deadline: the frame and the deadline are ready in the same instant, and the server must
    // read the frame (and count it) before it judges the window. `advance` jumps the clock, so the
    // ping above was recorded at the 16 s endpoint and its pong window closes at 26 s; the 10 s step
    // crosses it.
    tokio::time::pause();
    client.send_json(&player_state(true, 100, false)).await?;
    tokio::time::advance(Duration::from_secs(10)).await;
    tokio::time::resume();

    // The server did not drop the connection at the deadline; it still serves a clock request.
    let reply = client.round_trip_time(2_000).await?;
    assert_eq!(
        reply.client_transmitted, 2_000,
        "the server still serves the connection after the frame at the deadline"
    );

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn both_sides_keep_a_silent_link_alive() -> Result<()> {
    let config = ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        format: AudioFormat::pcm(48_000, 2, 16),
        ..ServerConfig::new("A test server", Identity::generate())
    };
    let mut server = Server::start(config).await?;
    let port = server.local_addr().port();
    let mut server_events = server.events();

    // The client connects unapproved, so it gets no roles and the link is silent in both
    // directions: the only traffic is the keepalive.
    let identity = Identity::generate();
    let client_config = ClientConfig::new(format!("127.0.0.1:{port}"), "A test player", identity);
    let (mut handle, mut client_events) =
        Client::connect(client_config, Box::new(NullSink)).await?;

    match client_events.next().await {
        Some(ClientEvent::Connected { encrypted, .. }) => {
            assert!(encrypted, "the connection is encrypted")
        }
        other => panic!("expected Connected, got {other:?}"),
    }
    assert!(matches!(
        next_event(&mut server_events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut server_events).await,
        Event::ClientActivated { .. }
    ));

    // Three rounds: advance past the idle window on the paused clock, resume long enough for the
    // pings and pongs to cross loopback, and require that neither side ended anything. Because both
    // sides ping on the same 15 s window, each side's ping keeps the other side's keepalive
    // satisfied, so this pins bidirectional liveness - neither side can go silent and survive - not
    // the pong paths, which the fake-client suite pins. The stream announcement the brief suggested
    // for this finish is not reachable here (see the approve step below).
    for _ in 0..3 {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(16)).await;
        tokio::time::resume();
        tokio::time::sleep(CROSS).await;
        expect_no_disconnect(&mut client_events, Duration::from_millis(100)).await;
        expect_no_client_left(&mut server_events, Duration::from_millis(100)).await;
    }

    // The link still works, not merely "has not failed yet": approve the client so the server
    // activates its roles and sends the group state, then require the client to report it. The
    // stream announcement the brief suggested needs the client's clock sync, and the paused-clock
    // rounds have advanced the tokio clock 48 s past the real one, which the client's reply
    // deadlines (std time) would read as already expired; a group update needs no clock sync and
    // still proves the server can reach the client and the client can report it.
    server.approve(&identity.public_base64()).await?;
    loop {
        match tokio::time::timeout(Duration::from_secs(20), client_events.next()).await {
            Err(_) => panic!("the client did not report the group state"),
            Ok(Some(ClientEvent::State(state))) => {
                if state.group_name.as_deref() == Some("A test server") {
                    break;
                }
            }
            Ok(Some(ClientEvent::Disconnected { reason, .. })) => {
                panic!("the client disconnected: {reason}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("the client event stream ended"),
        }
    }

    handle.close(GoodbyeReason::Shutdown);
    drop(client_events);
    drop(handle);
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_peer_that_answers_nothing_is_dropped() -> Result<()> {
    // The real client always answers a ping, so it cannot play the half-open peer this test is
    // about: the fake client holds its pong instead, and the server must still drop it and go on.
    let (server, port, mut events) = start().await?;
    let client = silent_client(port).await?;

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::resume();
    tokio::time::sleep(CROSS).await;
    let (client, _payload) = client.wait_for_ping().await?;
    let holder = tokio::spawn(client.hold_unanswered_ping());

    // Past both the idle window and the pong window, the server must end the connection with the
    // keepalive reason.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(26)).await;
    tokio::time::resume();

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    match next_event(&mut events).await {
        Event::ClientLeft { reason } => {
            assert!(
                reason.contains("keepalive"),
                "the reason names the keepalive, got: {reason}"
            );
        }
        other => panic!("expected ClientLeft, got {other:?}"),
    }

    // A second, healthy connection is still served afterwards.
    let mut second = silent_client(port).await?;
    let reply = second.round_trip_time(3_000).await?;
    assert_eq!(
        reply.client_transmitted, 3_000,
        "the server still serves a healthy connection after the drop"
    );

    second.goodbye("shutdown").await?;
    holder.await.expect("the held socket task must not panic")?;
    server.shutdown().await?;
    Ok(())
}
