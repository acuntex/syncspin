//! The controller commands beyond play, pause, next, previous and seek: each is one
//! `client/command` carrying only the fields that belong to it, and each is refused when the server
//! did not advertise it. Headless clients are used: the commands need no audio.

#![cfg(feature = "controller")]

#[path = "fake_server.rs"]
mod fake_server;

use std::time::Duration;

use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    connect_headless, ClientConfig, ClientHandle, Event, EventStream, Identity, RepeatMode,
};

async fn start() -> (FakeServer, EventStream, ClientHandle) {
    let server = FakeServer::start(ServerOptions {
        active_roles: vec!["controller@v1".to_owned()],
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let config = ClientConfig::new(server.endpoint(), "Test remote", Identity::generate());
    let (handle, events) = connect_headless(config).await.unwrap();
    (server, events, handle)
}

async fn sent(server: &mut FakeServer) -> serde_json::Value {
    let command = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_command())
        .await
        .expect("a command reaches the server")
        .expect("the connection stays open");
    serde_json::to_value(command).unwrap()
}

#[tokio::test]
async fn each_command_carries_only_its_own_fields() {
    let (mut server, _events, handle) = start().await;
    let control = handle.control();

    control.stop().await.unwrap();
    assert_eq!(
        sent(&mut server).await,
        serde_json::json!({"controller": {"command": "stop"}})
    );
    control.switch().await.unwrap();
    assert_eq!(
        sent(&mut server).await,
        serde_json::json!({"controller": {"command": "switch"}})
    );
    for (mode, name) in [
        (RepeatMode::Off, "repeat_off"),
        (RepeatMode::One, "repeat_one"),
        (RepeatMode::All, "repeat_all"),
    ] {
        control.repeat(mode).await.unwrap();
        assert_eq!(
            sent(&mut server).await,
            serde_json::json!({"controller": {"command": name}})
        );
    }
    control.shuffle(true).await.unwrap();
    assert_eq!(
        sent(&mut server).await,
        serde_json::json!({"controller": {"command": "shuffle"}})
    );
    control.shuffle(false).await.unwrap();
    assert_eq!(
        sent(&mut server).await,
        serde_json::json!({"controller": {"command": "unshuffle"}})
    );
    control.set_group_volume(35).await.unwrap();
    assert_eq!(
        sent(&mut server).await,
        serde_json::json!({"controller": {"command": "volume", "volume": 35}})
    );
    control.set_group_mute(true).await.unwrap();
    assert_eq!(
        sent(&mut server).await,
        serde_json::json!({"controller": {"command": "mute", "mute": true}})
    );
}

#[tokio::test]
async fn a_command_the_server_did_not_advertise_is_refused() {
    let (server, mut events, handle) = start().await;
    server.json(
        r#"{"type":"server/state","payload":{"controller":{"supported_commands":["play","repeat_all"],"volume":10,"muted":false,"repeat":"off","shuffle":true}}}"#,
    );
    loop {
        match tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .unwrap()
            .unwrap()
        {
            Event::State(state) => {
                assert_eq!(state.repeat.as_deref(), Some("off"));
                assert_eq!(state.shuffle, Some(true));
                break;
            }
            _ => continue,
        }
    }
    let control = handle.control();
    assert!(control.stop().await.is_err(), "stop is not advertised");
    assert!(
        control.set_group_volume(5).await.is_err(),
        "volume is not advertised"
    );
    assert!(
        control.repeat(RepeatMode::All).await.is_ok(),
        "repeat_all is advertised"
    );
}

#[tokio::test]
async fn a_group_volume_above_100_is_refused_before_anything_is_sent() {
    let (_server, _events, handle) = start().await;
    let error = handle.control().set_group_volume(101).await.unwrap_err();
    assert!(format!("{error:#}").contains("0-100"), "{error:#}");
}
