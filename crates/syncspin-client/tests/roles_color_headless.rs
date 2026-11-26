//! The color role on a headless client: a scheme is delivered, removal reports `ColorCleared`, an
//! object for an inactive role is ignored, and an out-of-range component leaves the connection up.

#![cfg(feature = "color")]

#[path = "fake_server.rs"]
mod fake_server;

use std::time::Duration;

use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{connect_headless, ClientConfig, Event, EventStream, Identity};

async fn start(roles: &[&str]) -> (FakeServer, EventStream, syncspin_client::ClientHandle) {
    let server = FakeServer::start(ServerOptions {
        active_roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let config = ClientConfig::new(server.endpoint(), "Test lamp", Identity::generate());
    let (handle, events) = connect_headless(config).await.unwrap();
    (server, events, handle)
}

async fn next(events: &mut EventStream, ms: u64) -> Option<Event> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(deadline, events.next()).await {
            Ok(Some(
                event @ (Event::Color(_) | Event::ColorCleared | Event::Disconnected { .. }),
            )) => return Some(event),
            Ok(Some(_)) => continue,
            _ => return None,
        }
    }
}

const COLOR: &str = r#"{"type":"server/state","payload":{"color":{"timestamp":0,"primary":[255,0,10],"on_dark":[1,2,3]}}}"#;

#[tokio::test]
async fn a_color_scheme_is_delivered() {
    let (server, mut events, _handle) = start(&["color@v1"]).await;
    server.json(COLOR);
    match next(&mut events, 2000).await {
        Some(Event::Color(scheme)) => {
            assert_eq!(scheme.primary, Some([255, 0, 10]));
            assert_eq!(scheme.on_dark, Some([1, 2, 3]));
            assert_eq!(scheme.accent, None);
        }
        other => panic!("expected Color, got {other:?}"),
    }
}

#[tokio::test]
async fn removing_the_role_reports_a_cleared_scheme() {
    let (server, mut events, _handle) = start(&["color@v1"]).await;
    server.json(COLOR);
    assert!(matches!(
        next(&mut events, 2000).await,
        Some(Event::Color(_))
    ));
    server.activate(&[]);
    assert!(matches!(
        next(&mut events, 2000).await,
        Some(Event::ColorCleared)
    ));
}

#[tokio::test]
async fn a_color_object_without_the_role_is_ignored() {
    // No role is active, so the color object changes nothing.
    let (server, mut events, _handle) = start(&[]).await;
    server.json(COLOR);
    assert!(next(&mut events, 600).await.is_none());
}

#[tokio::test]
async fn an_out_of_range_component_closes_the_connection() {
    let (server, mut events, _handle) = start(&["color@v1"]).await;
    server
        .json(r#"{"type":"server/state","payload":{"color":{"timestamp":0,"primary":[256,0,0]}}}"#);
    assert!(
        matches!(
            next(&mut events, 3000).await,
            Some(Event::Disconnected { .. })
        ),
        "a value outside 0-255 is a protocol error"
    );
}

#[tokio::test]
async fn a_triple_of_the_wrong_length_closes_the_connection() {
    let (server, mut events, _handle) = start(&["color@v1"]).await;
    server.json(r#"{"type":"server/state","payload":{"color":{"timestamp":0,"primary":[1,2]}}}"#);
    assert!(matches!(
        next(&mut events, 3000).await,
        Some(Event::Disconnected { .. })
    ));
}
