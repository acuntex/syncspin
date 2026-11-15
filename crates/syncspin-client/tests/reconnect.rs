//! The reconnect policy: the delay a session recommends when it ends.
//!
//! The crate schedules no retry itself, so the sequence is a pure function and the event only
//! carries one step of it. These tests pin both.

#[path = "fake_server.rs"]
mod fake_server;

use std::time::{Duration, Instant};

use anyhow::Result;
use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    connect, next_backoff, AudioFormat, AudioFrame, AudioMode, ClientConfig, Event, EventStream,
    Identity, Sink, INITIAL_BACKOFF,
};

/// Ceiling the tests use, low enough that saturation is visible in a few steps.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// A sink that accepts every frame and records nothing; these tests never play audio.
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

/// Builds a configuration for the fake server.
fn config_for(server: &FakeServer) -> ClientConfig {
    ClientConfig {
        server: server.endpoint(),
        player_name: "Test player".to_owned(),
        identity: Identity::generate(),
        audio_mode: AudioMode::Passthrough,
        max_backoff: MAX_BACKOFF,
    }
}

/// Connects to `server` with a fresh identity.
async fn connect_to(server: &FakeServer) -> (EventStream, syncspin_client::ClientHandle) {
    let (handle, events) = connect(config_for(server), Box::new(NullSink))
        .await
        .expect("the client must connect to the fake server");
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

#[test]
fn disconnect_carries_a_backoff_value_that_grows_and_resets() {
    let delay = next_backoff(Duration::ZERO, false, MAX_BACKOFF);
    assert_eq!(
        delay, INITIAL_BACKOFF,
        "the first delay after a failure is one second"
    );

    let mut delay = next_backoff(delay, false, MAX_BACKOFF);
    assert_eq!(delay, Duration::from_secs(2));
    delay = next_backoff(delay, false, MAX_BACKOFF);
    assert_eq!(delay, Duration::from_secs(4));
    delay = next_backoff(delay, false, MAX_BACKOFF);
    assert_eq!(delay, Duration::from_secs(8));
    delay = next_backoff(delay, false, MAX_BACKOFF);
    assert_eq!(delay, Duration::from_secs(16));

    delay = next_backoff(delay, false, MAX_BACKOFF);
    assert_eq!(delay, MAX_BACKOFF, "the sequence saturates at the cap");
    delay = next_backoff(delay, false, MAX_BACKOFF);
    assert_eq!(delay, MAX_BACKOFF, "a saturated sequence stays at the cap");

    // A smaller cap takes effect as soon as the sequence reaches it.
    assert_eq!(
        next_backoff(Duration::from_secs(4), false, Duration::from_secs(5)),
        Duration::from_secs(5)
    );
    assert_eq!(
        next_backoff(Duration::ZERO, false, Duration::from_millis(250)),
        Duration::from_millis(250),
        "the cap also bounds the first delay"
    );

    assert_eq!(
        next_backoff(Duration::from_secs(16), true, MAX_BACKOFF),
        INITIAL_BACKOFF,
        "a session that connected resets the sequence"
    );
    assert_eq!(
        next_backoff(Duration::ZERO, true, MAX_BACKOFF),
        INITIAL_BACKOFF
    );
}

#[tokio::test]
async fn a_session_that_connected_recommends_the_initial_delay() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;

    match next_event(&mut events).await {
        Event::Connected { .. } => {}
        other => panic!("expected Connected, got {other:?}"),
    }

    server.close();
    loop {
        match next_event(&mut events).await {
            Event::Disconnected { retry_in, .. } => {
                assert_eq!(
                    retry_in, INITIAL_BACKOFF,
                    "a session that worked resets the delay instead of growing it"
                );
                return;
            }
            _ => continue,
        }
    }
}

#[tokio::test]
async fn a_session_that_never_connected_recommends_a_grown_delay() {
    // Malformed Noise metadata fails the handshake before `server/activate`, so this session never
    // reports Connected and its recommendation is one growth step above the initial delay.
    let options = ServerOptions {
        metadata: Some(r#"{"psk_id":42,"psk_category":"sn"}"#.to_owned()),
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;

    loop {
        match next_event(&mut events).await {
            Event::Disconnected { retry_in, .. } => {
                assert_eq!(
                    retry_in,
                    Duration::from_secs(2),
                    "a session without a connection reports the next backoff step"
                );
                return;
            }
            _ => continue,
        }
    }
}
