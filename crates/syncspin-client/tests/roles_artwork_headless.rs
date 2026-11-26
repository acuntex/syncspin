//! The artwork role on a headless client: `client/state` with its channels, transfers, scheduling,
//! cancel, the stream lifecycle, the size cap and the protocol errors. Images are synthetic bytes.

#![cfg(feature = "artwork")]

#[path = "fake_server.rs"]
mod fake_server;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    connect_headless, ArtworkChannel, ArtworkSource, ClientConfig, ClientHandle, Event,
    EventStream, Identity, ImageFormat,
};
use syncspin_core::messages::ArtworkMessage;

const START: &str = r#"{"type":"stream/start","payload":{"server_transmitted":0,"artwork":{"channels":[{"source":"album","format":"png","width":8,"height":8},{"source":"none"},{"source":"artist","format":"jpeg","width":4,"height":4}]}}}"#;

fn roles() -> Vec<String> {
    // The artwork role alone, plus metadata where this build has it.
    #[allow(unused_mut)]
    let mut roles = vec!["artwork@v1".to_owned()];
    #[cfg(feature = "metadata")]
    roles.push("metadata@v1".to_owned());
    roles
}

fn config(server: &FakeServer, max: usize) -> ClientConfig {
    ClientConfig::new(server.endpoint(), "Test frame", Identity::generate())
        .with_artwork_channels(vec![
            Some(ArtworkChannel {
                source: ArtworkSource::Album,
                format: ImageFormat::Png,
                width: 8,
                height: 8,
            }),
            None,
            Some(ArtworkChannel {
                source: ArtworkSource::Artist,
                format: ImageFormat::Jpeg,
                width: 4,
                height: 4,
            }),
        ])
        .with_max_artwork_bytes(max)
}

async fn start(max: usize) -> (FakeServer, EventStream, ClientHandle) {
    let server = FakeServer::start(ServerOptions {
        active_roles: roles(),
        connections: 2,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (handle, events) = connect_headless(config(&server, max)).await.unwrap();
    (server, events, handle)
}

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn send_image(server: &FakeServer, channel: u8, timestamp_us: i64, data: &[u8]) {
    server.binary(
        ArtworkMessage::Announce {
            channel,
            timestamp_us,
            total_size: data.len() as u32,
        }
        .encode(),
    );
    for part in data.chunks(3) {
        server.binary(
            ArtworkMessage::Part {
                channel,
                data: part,
            }
            .encode(),
        );
    }
}

async fn artwork(events: &mut EventStream, within: Duration) -> Option<(u8, Option<Vec<u8>>)> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, events.next()).await {
            Ok(Some(Event::Artwork { channel, image })) => {
                return Some((channel, image.map(|image| image.data)))
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("the stream ended"),
            Err(_) => return None,
        }
    }
}

/// Waits for the client's `client/state` so the server may start streaming.
async fn ready(server: &mut FakeServer) {
    server
        .wait_for_client_state()
        .await
        .expect("a client/state");
}

#[tokio::test]
async fn client_state_carries_the_channels_with_holes() {
    let (mut server, _events, _handle) = start(1024).await;
    let state = server.wait_for_client_state().await.unwrap();
    assert!(state.player.is_none());
    let artwork = state.artwork.expect("the artwork object");
    assert_eq!(
        artwork.channels.len(),
        3,
        "trimmed after the last configured channel"
    );
    assert_eq!(artwork.channels[0].source, "album");
    assert_eq!(artwork.channels[1].source, "none");
    assert_eq!(
        artwork.channels[1].format, None,
        "a hole carries only its source"
    );
    assert_eq!(artwork.channels[2].format.as_deref(), Some("jpeg"));
}

#[tokio::test]
async fn an_image_arrives_with_exact_bytes() {
    let (mut server, mut events, _handle) = start(1024).await;
    ready(&mut server).await;
    server.json(START);
    send_image(&server, 0, now_us() - 1_000, &[1, 2, 3, 4, 5, 6, 7]);
    let (channel, image) = artwork(&mut events, Duration::from_secs(3))
        .await
        .expect("an image");
    assert_eq!((channel, image), (0, Some(vec![1, 2, 3, 4, 5, 6, 7])));
}

#[tokio::test]
async fn an_empty_image_clears_the_channel() {
    let (mut server, mut events, _handle) = start(1024).await;
    ready(&mut server).await;
    server.json(START);
    send_image(&server, 2, now_us() - 1_000, &[5]);
    assert_eq!(
        artwork(&mut events, Duration::from_secs(3)).await,
        Some((2, Some(vec![5])))
    );
    send_image(&server, 2, now_us() - 1_000, &[]);
    assert_eq!(
        artwork(&mut events, Duration::from_secs(3)).await,
        Some((2, None))
    );
}

#[tokio::test]
async fn a_stream_end_clears_the_channels_and_stops_the_stream() {
    let (mut server, mut events, _handle) = start(1024).await;
    ready(&mut server).await;
    server.json(START);
    send_image(&server, 0, now_us() - 1_000, &[1]);
    artwork(&mut events, Duration::from_secs(3))
        .await
        .expect("an image");
    // A pause ends the player stream only and leaves artwork alone.
    server.stream_end_for(&["player"]);
    assert!(artwork(&mut events, Duration::from_millis(400))
        .await
        .is_none());
    server.stream_end_for(&["artwork"]);
    assert_eq!(
        artwork(&mut events, Duration::from_secs(3)).await,
        Some((0, None))
    );
    // Data after the end is discarded until the next stream/start.
    send_image(&server, 0, now_us() - 1_000, &[2]);
    assert!(artwork(&mut events, Duration::from_millis(400))
        .await
        .is_none());
}

#[tokio::test]
async fn an_image_over_the_cap_is_discarded_without_an_event() {
    let (mut server, mut events, _handle) = start(4).await;
    ready(&mut server).await;
    server.json(START);
    send_image(&server, 0, now_us() - 1_000, &[0; 10]);
    assert!(artwork(&mut events, Duration::from_millis(600))
        .await
        .is_none());
    // The sequence rules held, so the next image on the same stream still arrives.
    send_image(&server, 0, now_us() - 1_000, &[7, 7]);
    assert_eq!(
        artwork(&mut events, Duration::from_secs(3)).await,
        Some((0, Some(vec![7, 7])))
    );
}

#[tokio::test]
async fn data_outside_an_active_stream_is_discarded_without_closing() {
    let (mut server, mut events, _handle) = start(1024).await;
    ready(&mut server).await;
    // No stream/start yet: well-formed messages are dropped and the connection stays up.
    send_image(&server, 0, now_us() - 1_000, &[1]);
    assert!(artwork(&mut events, Duration::from_millis(500))
        .await
        .is_none());
    server.json(START);
    send_image(&server, 0, now_us() - 1_000, &[3]);
    assert_eq!(
        artwork(&mut events, Duration::from_secs(3)).await,
        Some((0, Some(vec![3])))
    );
}

#[tokio::test]
async fn a_mismatching_stream_start_is_ignored() {
    let (mut server, mut events, _handle) = start(1024).await;
    ready(&mut server).await;
    server.json(r#"{"type":"stream/start","payload":{"server_transmitted":0,"artwork":{"channels":[{"source":"album","format":"png","width":9,"height":8}]}}}"#);
    send_image(&server, 0, now_us() - 1_000, &[1]);
    assert!(artwork(&mut events, Duration::from_millis(500))
        .await
        .is_none());
}

#[tokio::test]
async fn a_malformed_message_closes_the_connection_even_without_a_stream() {
    for bad in [
        vec![8u8, 0b100],      // reserved bit
        vec![8u8, 0b11],       // cancel and announce
        vec![8u8, 1, 0],       // long cancel
        vec![9u8, 0b10, 0, 0], // short announce
    ] {
        let (mut server, mut events, _handle) = start(1024).await;
        ready(&mut server).await;
        server.binary(bad.clone());
        let mut closed = false;
        for _ in 0..10 {
            match tokio::time::timeout(Duration::from_secs(3), events.next()).await {
                Ok(Some(Event::Disconnected { .. })) => {
                    closed = true;
                    break;
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        assert!(closed, "{bad:?} must close the connection");
    }
}

#[tokio::test]
async fn a_sequence_error_closes_the_connection() {
    let (mut server, mut events, _handle) = start(1024).await;
    ready(&mut server).await;
    server.json(START);
    server.binary(
        ArtworkMessage::Part {
            channel: 0,
            data: &[1],
        }
        .encode(),
    );
    let mut closed = false;
    for _ in 0..10 {
        match tokio::time::timeout(Duration::from_secs(3), events.next()).await {
            Ok(Some(Event::Disconnected { .. })) => {
                closed = true;
                break;
            }
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    assert!(closed, "a part with no transfer in flight closes");
}

#[tokio::test]
async fn the_debug_form_of_an_image_has_no_bytes() {
    let event = Event::Artwork {
        channel: 1,
        image: Some(syncspin_client::ArtworkImage {
            format: ImageFormat::Png,
            data: vec![0xAB; 4],
        }),
    };
    let text = format!("{event:?}");
    assert!(text.contains("bytes: 4") && !text.contains("171"), "{text}");
}
