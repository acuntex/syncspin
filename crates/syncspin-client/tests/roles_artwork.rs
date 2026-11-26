//! The artwork role next to a player: a `stream/start` that carries only an artwork object leaves
//! the open player stream alone, a bare or versioned role list in `stream/end` reaches the right
//! role, and an artwork object for a role that is not active changes nothing.

#![cfg(all(feature = "player", feature = "artwork"))]

#[path = "fake_server.rs"]
mod fake_server;

use std::time::{Duration, Instant};

use anyhow::Result;
use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    connect, ArtworkChannel, ArtworkSource, AudioFormat, AudioFrame, ClientConfig, Event,
    EventStream, Identity, ImageFormat, Sink,
};
use syncspin_core::messages::ArtworkMessage;

struct NullSink;

impl Sink for NullSink {
    fn open(&mut self, _format: AudioFormat) -> Result<()> {
        Ok(())
    }
    fn write(&mut self, _frame: AudioFrame<'_>, _due: Instant) -> Result<()> {
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

const ARTWORK_ONLY: &str = r#"{"type":"stream/start","payload":{"server_transmitted":0,"artwork":{"channels":[{"source":"album","format":"png","width":8,"height":8}]}}}"#;

async fn start(roles: &[&str]) -> (FakeServer, EventStream, syncspin_client::ClientHandle) {
    let mut server = FakeServer::start(ServerOptions {
        active_roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let config = ClientConfig::new(server.endpoint(), "Test", Identity::generate())
        .with_artwork_channels(vec![Some(ArtworkChannel {
            source: ArtworkSource::Album,
            format: ImageFormat::Png,
            width: 8,
            height: 8,
        })]);
    let (handle, events) = connect(config, Box::new(NullSink)).await.unwrap();
    server.wait_for_client_state().await.unwrap();
    (server, events, handle)
}

async fn events_within(events: &mut EventStream, window: Duration) -> Vec<Event> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.next()).await {
        seen.push(event);
    }
    seen
}

#[tokio::test]
async fn an_artwork_only_stream_start_leaves_the_player_stream_alone() {
    let (server, mut events, _handle) = start(&["player@v1", "artwork@v1"]).await;
    server.stream_start("pcm", 48_000, 2, 16);
    server.json(ARTWORK_ONLY);
    server.stream_end_for(&["artwork@v1"]);
    let seen = events_within(&mut events, Duration::from_millis(700)).await;
    let starts = seen
        .iter()
        .filter(|e| matches!(e, Event::StreamStart { .. }))
        .count();
    assert_eq!(
        starts, 1,
        "only the player's own stream/start opened a stream: {seen:?}"
    );
    assert!(
        !seen.iter().any(|e| matches!(e, Event::StreamEnd { .. })),
        "ending artwork, by its versioned name, does not end the player: {seen:?}"
    );
}

#[tokio::test]
async fn a_bare_player_end_leaves_artwork_alone() {
    let (server, mut events, _handle) = start(&["player@v1", "artwork@v1"]).await;
    server.json(ARTWORK_ONLY);
    server.stream_start("pcm", 48_000, 2, 16);
    server.binary(
        ArtworkMessage::Announce {
            channel: 0,
            timestamp_us: 0,
            total_size: 1,
        }
        .encode(),
    );
    server.binary(
        ArtworkMessage::Part {
            channel: 0,
            data: &[1],
        }
        .encode(),
    );
    server.stream_end_for(&["player"]);
    let seen = events_within(&mut events, Duration::from_millis(700)).await;
    assert!(seen.iter().any(|e| matches!(e, Event::StreamEnd { .. })));
    assert!(
        !seen
            .iter()
            .any(|e| matches!(e, Event::Artwork { image: None, .. })),
        "a pause must not clear artwork: {seen:?}"
    );
    assert!(seen
        .iter()
        .any(|e| matches!(e, Event::Artwork { image: Some(_), .. })));
}

#[tokio::test]
async fn an_artwork_object_for_an_inactive_role_changes_nothing() {
    let (server, mut events, _handle) = start(&["player@v1"]).await;
    server.json(ARTWORK_ONLY);
    server.binary(
        ArtworkMessage::Announce {
            channel: 0,
            timestamp_us: 0,
            total_size: 1,
        }
        .encode(),
    );
    server.binary(
        ArtworkMessage::Part {
            channel: 0,
            data: &[1],
        }
        .encode(),
    );
    let seen = events_within(&mut events, Duration::from_millis(600)).await;
    assert!(
        !seen
            .iter()
            .any(|e| matches!(e, Event::Artwork { .. } | Event::Disconnected { .. })),
        "{seen:?}"
    );
}
