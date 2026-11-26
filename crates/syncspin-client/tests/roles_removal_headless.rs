//! Role state is reconciled when roles change: removing a role drops its state and says so, the
//! group fields survive, and an object for a role that is not active changes nothing.

#![cfg(all(feature = "controller", feature = "metadata"))]

#[path = "fake_server.rs"]
mod fake_server;

use std::time::Duration;

use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{connect_headless, ClientConfig, Event, EventStream, Identity};

fn options(roles: &[&str]) -> ServerOptions {
    ServerOptions {
        active_roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        ..ServerOptions::default()
    }
}

async fn connect_to(server: &FakeServer) -> (EventStream, syncspin_client::ClientHandle) {
    let config = ClientConfig::new(server.endpoint(), "Test display", Identity::generate());
    let (handle, events) = connect_headless(config).await.unwrap();
    (events, handle)
}

/// The next event within a short window, or `None`.
async fn next(events: &mut EventStream) -> Option<Event> {
    tokio::time::timeout(Duration::from_millis(800), events.next())
        .await
        .ok()
        .flatten()
}

async fn expect_event(events: &mut EventStream, wanted: impl Fn(&Event) -> bool) -> Event {
    for _ in 0..20 {
        match next(events).await {
            Some(event) if wanted(&event) => return event,
            Some(_) => {}
            None => panic!("the expected event never arrived"),
        }
    }
    panic!("the expected event never arrived");
}

const GROUP: &str = r#"{"type":"group/update","payload":{"playback_state":"playing","group_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","group_name":"Room"}}"#;
const CONTROLLER: &str = r#"{"type":"server/state","payload":{"controller":{"supported_commands":["play","pause"],"volume":30,"muted":false,"seek_max_ms":1000}}}"#;
const METADATA: &str =
    r#"{"type":"server/state","payload":{"metadata":{"timestamp":0,"title":"T"}}}"#;

#[tokio::test]
async fn removing_metadata_reports_a_cleared_track() {
    let server = FakeServer::start(options(&["controller@v1", "metadata@v1"]))
        .await
        .unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    server.json(METADATA);
    expect_event(&mut events, |e| matches!(e, Event::Track { .. })).await;

    server.activate(&["controller@v1"]);
    expect_event(&mut events, |e| matches!(e, Event::TrackCleared)).await;
    // The state that was cleared is not a Track with empty text.
    server.json(METADATA);
    assert!(
        !matches!(next(&mut events).await, Some(Event::Track { .. })),
        "an object for an inactive role is ignored"
    );
}

#[tokio::test]
async fn removing_the_controller_resets_its_fields_and_keeps_the_group() {
    let server = FakeServer::start(options(&["controller@v1", "metadata@v1"]))
        .await
        .unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    server.json(GROUP);
    server.json(CONTROLLER);
    let state = expect_event(
        &mut events,
        |e| matches!(e, Event::State(s) if s.volume == Some(30)),
    )
    .await;
    assert!(matches!(state, Event::State(_)));

    server.activate(&["metadata@v1"]);
    match expect_event(
        &mut events,
        |e| matches!(e, Event::State(s) if s.volume.is_none()),
    )
    .await
    {
        Event::State(state) => {
            assert!(state.supported_commands.is_empty());
            assert_eq!(state.seek_max_ms, None);
            assert_eq!(
                state.playback_state.as_deref(),
                Some("playing"),
                "group kept"
            );
            assert_eq!(state.group_name.as_deref(), Some("Room"), "group kept");
        }
        other => panic!("expected State, got {other:?}"),
    }
    server.json(CONTROLLER);
    assert!(
        !matches!(next(&mut events).await, Some(Event::State(s)) if s.volume == Some(30)),
        "a controller object with no controller role is ignored"
    );
}

#[tokio::test]
async fn an_activation_that_keeps_the_roles_clears_nothing() {
    let server = FakeServer::start(options(&["controller@v1", "metadata@v1"]))
        .await
        .unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    server.json(METADATA);
    expect_event(&mut events, |e| matches!(e, Event::Track { .. })).await;
    server.activate(&["metadata@v1", "controller@v1"]);
    assert!(
        !matches!(next(&mut events).await, Some(Event::TrackCleared)),
        "re-sending the same set is not a removal"
    );
}

#[tokio::test]
async fn null_role_objects_change_nothing() {
    let server = FakeServer::start(options(&["controller@v1", "metadata@v1"]))
        .await
        .unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    server.json(r#"{"type":"server/state","payload":{"controller":null,"metadata":null}}"#);
    server.json(METADATA);
    // The first event after the null message is the real track: the nulls produced nothing.
    expect_event(&mut events, |e| matches!(e, Event::Track { .. })).await;
}
