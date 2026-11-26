//! A client without an audio sink: it offers no player role, reports no player state, still takes
//! part in the other roles, and sends its first `client/state` without waiting for a player's clock.

#[path = "fake_server.rs"]
mod fake_server;

use std::time::Duration;

use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{connect_headless, ClientConfig, ClientHandle, Event, EventStream, Identity};

/// Builds a configuration for `server`.
fn config_for(server: &FakeServer) -> ClientConfig {
    ClientConfig::new(server.endpoint(), "Test display", Identity::generate())
}

/// The roles every test in this file activates: exactly what a headless client supports.
fn headless_roles() -> ServerOptions {
    ServerOptions {
        active_roles: vec!["controller@v1".to_owned(), "metadata@v1".to_owned()],
        ..ServerOptions::default()
    }
}

/// Connects a headless client to `server`.
async fn connect_to(server: &FakeServer) -> (EventStream, ClientHandle) {
    let (handle, events) = connect_headless(config_for(server))
        .await
        .expect("the configuration is valid");
    (events, handle)
}

/// Waits for one event, failing instead of hanging.
async fn next_event(stream: &mut EventStream) -> Event {
    match tokio::time::timeout(Duration::from_secs(8), stream.next()).await {
        Ok(Some(event)) => event,
        Ok(None) => panic!("the event stream ended"),
        Err(_) => panic!("timed out waiting for an event"),
    }
}

#[tokio::test]
async fn a_headless_hello_omits_the_player_role_and_its_support_object() {
    let mut server = FakeServer::start(headless_roles()).await.unwrap();
    let (_events, _handle) = connect_to(&server).await;

    let text = tokio::time::timeout(Duration::from_secs(8), server.wait_for_client_hello_text())
        .await
        .expect("the client announces itself")
        .expect("a client/hello arrived");
    let hello: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        hello["payload"]["supported_roles"],
        serde_json::json!(["controller@v1", "metadata@v1"]),
        "a client without a sink must not offer a role it cannot carry out"
    );
    assert!(
        hello["payload"].get("player@v1_support").is_none(),
        "the support object belongs to the player role only"
    );
}

#[tokio::test]
async fn a_headless_client_reports_its_state_without_a_player_object() {
    let mut server = FakeServer::start(headless_roles()).await.unwrap();
    let (_events, _handle) = connect_to(&server).await;

    let state = tokio::time::timeout(Duration::from_secs(8), server.wait_for_client_state())
        .await
        .expect("a headless client reports as soon as its roles are active")
        .expect("a client/state arrived");
    assert!(state.available, "the client is available");
    assert!(state.player.is_none(), "there is no player to report");
}

#[tokio::test]
async fn a_headless_client_delivers_metadata() {
    let server = FakeServer::start(headless_roles()).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    assert!(matches!(
        next_event(&mut events).await,
        Event::Connected { .. }
    ));

    server.metadata("A title", "An artist");
    loop {
        match next_event(&mut events).await {
            Event::Track { title, artist, .. } => {
                assert_eq!(title, "A title");
                assert_eq!(artist, "An artist");
                return;
            }
            Event::State(_) => {}
            other => panic!("expected Track, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_headless_client_refuses_the_player_role() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_events, _handle) = connect_to(&server).await;

    let reason = tokio::time::timeout(Duration::from_secs(8), server.wait_for_goodbye())
        .await
        .expect("the client answers an activation it will not honour");
    assert_eq!(
        reason.as_deref(),
        Some("unauthorized"),
        "the default roles include player@v1, which a headless client never offered"
    );
}

#[tokio::test]
async fn a_headless_handle_has_no_volume_to_set() {
    let server = FakeServer::start(headless_roles()).await.unwrap();
    let (mut events, handle) = connect_to(&server).await;
    assert!(matches!(
        next_event(&mut events).await,
        Event::Connected { .. }
    ));

    let error = handle
        .control()
        .set_volume(40)
        .await
        .expect_err("there is no player role to set a volume on");
    assert!(
        format!("{error:#}").contains("player@v1"),
        "the refusal names the missing role: {error:#}"
    );
}
