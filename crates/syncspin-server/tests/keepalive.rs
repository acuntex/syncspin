//! The server's WebSocket keepalive: a silent link is pinged, an unanswered ping drops the peer,
//! and a normal frame keeps the connection alive.
//!
//! These tests drive the listener with the fake client in `common`, which is the only peer that can
//! leave a ping unanswered while keeping the socket open (the real client always answers a ping).
//! They measure the shipped 15 s and 10 s windows on a paused clock: the clock is frozen only while
//! the test waits for the server's timer, and every frame exchange runs on the real clock, because
//! a paused clock does not wake a socket read promptly.

mod common;

use std::time::Duration;

use common::*;

/// How long the test lets the frames cross loopback after resuming the clock.
const CROSS: Duration = Duration::from_millis(200);

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

    // The idle window is 15 s: inside it the link is silent, and only after it does the server ping.
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
