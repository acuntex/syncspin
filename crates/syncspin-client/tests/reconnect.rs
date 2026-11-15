//! The reconnect policy: the delay between attempts and the state that survives a drop.
//!
//! The crate owns the loop, so these tests cover both the pure backoff sequence and what a drop
//! does to the sink and to the event stream.

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    connect, next_backoff, AudioFormat, AudioFrame, AudioMode, ClientConfig, ClientHandle, Codec,
    Event, EventStream, Identity, Sink, INITIAL_BACKOFF,
};

/// Ceiling the tests use, low enough that saturation is visible in a few steps.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// One call the recording sink received, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SinkEvent {
    /// The sink was opened for a codec.
    Open(Codec),
    /// The sink was asked to drop everything buffered.
    Flush,
}

/// What a recording sink was asked to do, shared with the test.
#[derive(Clone, Default)]
struct Recordings(Arc<Mutex<Vec<SinkEvent>>>);

impl Recordings {
    /// Returns the recorded calls, in order.
    fn events(&self) -> Vec<SinkEvent> {
        self.0
            .lock()
            .expect("the recordings lock is not poisoned")
            .clone()
    }

    /// Records one call.
    fn push(&self, event: SinkEvent) {
        self.0
            .lock()
            .expect("the recordings lock is not poisoned")
            .push(event);
    }
}

/// A sink that records its calls instead of playing audio.
struct RecordingSink {
    recordings: Recordings,
}

impl Sink for RecordingSink {
    fn open(&mut self, format: AudioFormat) -> Result<()> {
        self.recordings.push(SinkEvent::Open(format.codec));
        Ok(())
    }

    fn write(&mut self, _frame: AudioFrame<'_>, _due: std::time::Instant) -> Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.recordings.push(SinkEvent::Flush);
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
        volume: 100,
        muted: false,
        max_backoff: MAX_BACKOFF,
    }
}

/// Connects to `server` with a fresh identity and a recording sink.
async fn connect_recording(server: &FakeServer) -> (Recordings, EventStream, ClientHandle) {
    let recordings = Recordings::default();
    let sink = Box::new(RecordingSink {
        recordings: recordings.clone(),
    });
    let (handle, events) = connect(config_for(server), sink)
        .await
        .expect("the client must connect to the fake server");
    (recordings, events, handle)
}

/// Connects to `server` with a fresh identity.
async fn connect_to(server: &FakeServer) -> (EventStream, ClientHandle) {
    let (recordings, events, handle) = connect_recording(server).await;
    drop(recordings);
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

/// Asserts that the next event is a successful encrypted connection.
async fn expect_connected(stream: &mut EventStream, server: &FakeServer) {
    match next_event(stream).await {
        Event::Connected {
            server_id,
            encrypted,
        } => {
            assert!(encrypted, "the connection must be reported as encrypted");
            assert_eq!(server_id, server.server_id());
        }
        other => panic!("expected Connected, got {other:?}"),
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
    expect_connected(&mut events, &server).await;

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

#[tokio::test]
async fn an_unreachable_server_is_an_event_and_not_an_error() {
    // Bind and release a loopback port so nothing listens on it; the attempt fails, and the
    // connection keeps retrying instead of returning from `connect` with an error.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a loopback port");
    let address = listener.local_addr().expect("the bound address");
    drop(listener);

    let recordings = Recordings::default();
    let config = ClientConfig {
        server: address.to_string(),
        player_name: "Test player".to_owned(),
        identity: Identity::generate(),
        audio_mode: AudioMode::Passthrough,
        volume: 100,
        muted: false,
        max_backoff: MAX_BACKOFF,
    };
    let (handle, mut events) = connect(
        config,
        Box::new(RecordingSink {
            recordings: recordings.clone(),
        }),
    )
    .await
    .expect("an unreachable server is not a connect error");

    match next_event(&mut events).await {
        Event::Disconnected { reason, retry_in } => {
            assert!(
                reason.contains("cannot connect"),
                "unexpected reason: {reason}"
            );
            assert_eq!(
                retry_in,
                Duration::from_secs(2),
                "the first failed attempt reports the first growth step"
            );
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }

    drop(handle);
}

#[tokio::test]
async fn the_session_reconnects_after_a_drop_and_flushes_the_sink() {
    let options = ServerOptions {
        connections: 2,
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (recordings, mut events, _handle) = connect_recording(&server).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    match next_event(&mut events).await {
        Event::StreamStart { format } => assert_eq!(format.codec, Codec::Pcm),
        other => panic!("expected StreamStart, got {other:?}"),
    }

    // The first session ends; the connection reports it and reconnects on its own.
    server.close();
    match next_event(&mut events).await {
        Event::Disconnected { retry_in, .. } => assert_eq!(retry_in, INITIAL_BACKOFF),
        other => panic!("expected Disconnected, got {other:?}"),
    }
    expect_connected(&mut events, &server).await;

    server.stream_start("flac", 48_000, 2, 16);
    match next_event(&mut events).await {
        Event::StreamStart { format } => assert_eq!(format.codec, Codec::Flac),
        other => panic!("expected StreamStart, got {other:?}"),
    }

    let recorded = recordings.events();
    let opens: Vec<Codec> = recorded
        .iter()
        .filter_map(|event| match event {
            SinkEvent::Open(codec) => Some(codec.clone()),
            SinkEvent::Flush => None,
        })
        .collect();
    assert_eq!(
        opens,
        vec![Codec::Pcm, Codec::Flac],
        "the second session must open only the format its own stream announced"
    );

    let first_open = recorded
        .iter()
        .position(|event| *event == SinkEvent::Open(Codec::Pcm))
        .expect("the first format must be opened");
    let second_open = recorded
        .iter()
        .position(|event| *event == SinkEvent::Open(Codec::Flac))
        .expect("the second format must be opened");
    assert!(
        recorded[first_open + 1..second_open].contains(&SinkEvent::Flush),
        "the drop must flush the audio of the session that ended: {recorded:?}"
    );
}

#[tokio::test]
async fn the_connection_keeps_the_level_across_a_reconnect() {
    // A drop must not reset the level to the configured baseline, because the server would then be
    // told a level the output is not at.
    let options = ServerOptions {
        connections: 2,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (mut events, handle) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    assert_eq!(
        control
            .set_volume(30)
            .await
            .expect("the level must be applied"),
        30
    );
    let state = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_state())
        .await
        .expect("the client must report its state")
        .expect("the connection must not close before the state report");
    assert_eq!(
        state.player.expect("the player role is active").volume,
        Some(30)
    );

    server.close();
    loop {
        if let Event::Disconnected { .. } = next_event(&mut events).await {
            break;
        }
    }
    expect_connected(&mut events, &server).await;

    assert_eq!(control.volume(), 30, "the level in force survives the drop");
    let state = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_state())
        .await
        .expect("the second session must report its state")
        .expect("the second connection must stay open");
    assert_eq!(
        state.player.expect("the player role is active").volume,
        Some(30),
        "the second session must report the level the output is at"
    );
}
