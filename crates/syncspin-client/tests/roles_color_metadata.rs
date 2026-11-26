//! An out-of-range color in a `server/state` closes the connection when the color role is active
//! (`messaging.md`, out-of-range values), and is ignored, unvalidated, when it is not. The message
//! with the bad color is not partly applied: metadata in it is not delivered.

#![cfg(all(feature = "color", feature = "metadata"))]

#[path = "fake_server.rs"]
mod fake_server;

use std::time::Duration;

use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{connect_headless, ClientConfig, Event, EventStream, Identity};

const BAD: &str = r#"{"type":"server/state","payload":{"metadata":{"timestamp":0,"title":"Lost"},"color":{"timestamp":0,"accent":[0,300,0]}}}"#;

async fn start(roles: &[&str]) -> (FakeServer, EventStream, syncspin_client::ClientHandle) {
    let server = FakeServer::start(ServerOptions {
        active_roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let config = ClientConfig::new(server.endpoint(), "Test", Identity::generate());
    let (handle, events) = connect_headless(config).await.unwrap();
    (server, events, handle)
}

#[tokio::test]
async fn an_out_of_range_color_closes_the_connection_when_the_role_is_active() {
    let (server, mut events, _handle) = start(&["metadata@v1", "color@v1"]).await;
    server.json(BAD);
    loop {
        match tokio::time::timeout(Duration::from_secs(3), events.next())
            .await
            .expect("the connection must close")
            .expect("the stream stays open for the report")
        {
            Event::Disconnected { reason, .. } => {
                assert!(
                    reason.contains("0-255"),
                    "the reason names the rule: {reason}"
                );
                return;
            }
            Event::Track { .. } => panic!("the metadata in the bad message must not be delivered"),
            _ => continue,
        }
    }
}

#[tokio::test]
async fn an_out_of_range_color_is_ignored_when_the_color_role_is_inactive() {
    // Only metadata is active: the color object is an inactive role's, so its values are not
    // validated and the connection stays. The whole message is still dropped as malformed.
    let (server, mut events, _handle) = start(&["metadata@v1"]).await;
    server.json(BAD);
    server.json(r#"{"type":"server/state","payload":{"metadata":{"timestamp":0,"title":"Kept"}}}"#);
    loop {
        match tokio::time::timeout(Duration::from_secs(3), events.next())
            .await
            .expect("the next state arrives")
            .expect("the stream is open")
        {
            Event::Track { title, .. } => {
                assert_eq!(title, "Kept");
                return;
            }
            Event::Disconnected { reason, .. } => {
                panic!("an inactive role must not close: {reason}")
            }
            _ => continue,
        }
    }
}
