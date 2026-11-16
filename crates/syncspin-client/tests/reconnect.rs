//! The reconnect policy: the delay between attempts and the state that survives a drop.
//!
//! The crate owns the loop, so these tests cover both the pure backoff sequence and what a drop
//! does to the sink and to the event stream.

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    connect, next_backoff, AudioFormat, AudioFrame, AudioMode, ClientConfig, ClientHandle, Codec,
    Event, EventStream, Identity, Sink, VolumePolicy, DEFAULT_PAIRING_TIMEOUT, INITIAL_BACKOFF,
};
use syncspin_core::messages::ClientState;

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

/// One recorded call with the stream it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Recorded {
    /// Number of streams the sink had opened when the call arrived.
    ///
    /// A call made for the session's own stream therefore carries that stream's number, while a
    /// call made after the session ended keeps it until the next stream opens.
    stream: usize,
    /// The call.
    call: SinkEvent,
}

/// What a recording sink was asked to do, shared with the test.
#[derive(Clone, Default)]
struct Recordings(Arc<Mutex<Vec<Recorded>>>);

impl Recordings {
    /// Returns the recorded calls, in order.
    fn recorded(&self) -> Vec<Recorded> {
        self.0
            .lock()
            .expect("the recordings lock is not poisoned")
            .clone()
    }

    /// Records one call.
    fn push(&self, recorded: Recorded) {
        self.0
            .lock()
            .expect("the recordings lock is not poisoned")
            .push(recorded);
    }
}

/// A sink that records its calls instead of playing audio.
struct RecordingSink {
    recordings: Recordings,
    /// Number of streams opened so far.
    stream: usize,
}

impl RecordingSink {
    /// Creates a sink that records into `recordings`.
    fn new(recordings: Recordings) -> RecordingSink {
        RecordingSink {
            recordings,
            stream: 0,
        }
    }
}

impl Sink for RecordingSink {
    fn open(&mut self, format: AudioFormat) -> Result<()> {
        self.stream += 1;
        self.recordings.push(Recorded {
            stream: self.stream,
            call: SinkEvent::Open(format.codec),
        });
        Ok(())
    }

    fn write(&mut self, _frame: AudioFrame<'_>, _due: Instant) -> Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.recordings.push(Recorded {
            stream: self.stream,
            call: SinkEvent::Flush,
        });
        Ok(())
    }
}

/// Builds a configuration for the fake server.
fn config_for(server: &FakeServer) -> ClientConfig {
    ClientConfig {
        server: server.endpoint(),
        player_name: "Test player".to_owned(),
        device_info: None,
        identity: Identity::generate(),
        storage: None,
        audio_mode: AudioMode::Passthrough,
        volume: 100,
        muted: false,
        volume_policy: VolumePolicy::default(),
        max_backoff: MAX_BACKOFF,
        pairing_timeout: DEFAULT_PAIRING_TIMEOUT,
        #[cfg(feature = "discovery")]
        inbound: None,
        #[cfg(feature = "pairing-code")]
        static_pairing_code: None,
        #[cfg(feature = "pairing-code")]
        pairing_window: syncspin_client::DEFAULT_PAIRING_WINDOW,
        #[cfg(feature = "pairing-code")]
        pairing_pending_text: None,
        #[cfg(feature = "pairing-code")]
        code_formats: Vec::new(),
        #[cfg(feature = "pairing-code")]
        code_out_channels: Vec::new(),
    }
}

/// Connects to `server` with a fresh identity and a recording sink.
async fn connect_recording(server: &FakeServer) -> (Recordings, EventStream, ClientHandle) {
    let recordings = Recordings::default();
    let sink = Box::new(RecordingSink::new(recordings.clone()));
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

/// Waits for the next `client/state` the fake server receives.
async fn next_client_state(server: &mut FakeServer) -> ClientState {
    tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_state())
        .await
        .expect("the client must report its state")
        .expect("the connection must not close before the state report")
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
        device_info: None,
        identity: Identity::generate(),
        storage: None,
        audio_mode: AudioMode::Passthrough,
        volume: 100,
        muted: false,
        volume_policy: VolumePolicy::default(),
        max_backoff: MAX_BACKOFF,
        pairing_timeout: DEFAULT_PAIRING_TIMEOUT,
        #[cfg(feature = "discovery")]
        inbound: None,
        #[cfg(feature = "pairing-code")]
        static_pairing_code: None,
        #[cfg(feature = "pairing-code")]
        pairing_window: syncspin_client::DEFAULT_PAIRING_WINDOW,
        #[cfg(feature = "pairing-code")]
        pairing_pending_text: None,
        #[cfg(feature = "pairing-code")]
        code_formats: Vec::new(),
        #[cfg(feature = "pairing-code")]
        code_out_channels: Vec::new(),
    };
    let (handle, mut events) = connect(config, Box::new(RecordingSink::new(recordings.clone())))
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

    // Snapshot between the two connections: the only call that can have followed the first
    // stream's open is the flush the client makes when an attempt ends. A `flush` from the next
    // `stream/start` cannot be here yet, because that message is only sent after the new
    // activation.
    let after_drop = recordings.recorded();
    assert_eq!(
        after_drop.last(),
        Some(&Recorded {
            stream: 1,
            call: SinkEvent::Flush,
        }),
        "the end of a session must flush its audio before the next connection: {after_drop:?}"
    );

    expect_connected(&mut events, &server).await;

    server.stream_start("flac", 48_000, 2, 16);
    match next_event(&mut events).await {
        Event::StreamStart { format } => assert_eq!(format.codec, Codec::Flac),
        other => panic!("expected StreamStart, got {other:?}"),
    }

    let recorded = recordings.recorded();
    let opens: Vec<Codec> = recorded
        .iter()
        .filter_map(|entry| match &entry.call {
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
        .position(|entry| entry.call == SinkEvent::Open(Codec::Pcm))
        .expect("the first format must be opened");
    let second_open = recorded
        .iter()
        .position(|entry| entry.call == SinkEvent::Open(Codec::Flac))
        .expect("the second format must be opened");
    assert!(
        recorded[first_open + 1..second_open]
            .iter()
            .any(|entry| entry.call == SinkEvent::Flush),
        "the drop must flush the audio of the session that ended: {recorded:?}"
    );
}

#[tokio::test]
async fn an_activation_without_roles_keeps_the_roles_of_the_previous_connection() {
    let options = ServerOptions {
        connections: 2,
        omit_active_roles_after_the_first: true,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;

    // The first connection announces the roles, so the player reports its state.
    assert!(
        next_client_state(&mut server).await.player.is_some(),
        "the first activation makes the player role active"
    );

    server.close();
    loop {
        if let Event::Disconnected { .. } = next_event(&mut events).await {
            break;
        }
    }
    expect_connected(&mut events, &server).await;

    // The second activation omits active_roles. The client keeps the set of the session that
    // ended, so the player role is still active and the new session reports its state; a client
    // that treated the omission as an empty set would stay silent. The crate has no `client/state`
    // object for the metadata or controller roles, so the report carries nothing for them.
    assert!(
        next_client_state(&mut server).await.player.is_some(),
        "the roles of the previous connection seed the next attempt"
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
    let state = next_client_state(&mut server).await;
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
    let state = next_client_state(&mut server).await;
    assert_eq!(
        state.player.expect("the player role is active").volume,
        Some(30),
        "the second session must report the level the output is at"
    );
}

#[tokio::test]
async fn the_connection_keeps_the_mute_state_across_a_reconnect() {
    // The configured mute state is not enough to pin this: the host changes it after connecting,
    // so a reconnect that fell back to the configuration would report the wrong state.
    let options = ServerOptions {
        connections: 2,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (mut events, handle) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    let state = next_client_state(&mut server).await;
    assert_eq!(
        state.player.expect("the player role is active").muted,
        Some(false)
    );
    control
        .set_muted(true)
        .await
        .expect("the mute must be applied");
    assert_eq!(
        next_client_state(&mut server)
            .await
            .player
            .expect("the player role is active")
            .muted,
        Some(true)
    );

    server.close();
    loop {
        if let Event::Disconnected { .. } = next_event(&mut events).await {
            break;
        }
    }
    expect_connected(&mut events, &server).await;

    assert_eq!(
        next_client_state(&mut server)
            .await
            .player
            .expect("the player role is active")
            .muted,
        Some(true),
        "the second session must report the mute state the output is at"
    );
}

#[tokio::test]
async fn dropping_the_handle_ends_the_event_stream() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (mut events, handle) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;

    drop(handle);
    loop {
        match tokio::time::timeout(Duration::from_secs(5), events.next()).await {
            Ok(Some(_)) => continue,
            Ok(None) => return,
            Err(_) => panic!("dropping the handle must end the event stream"),
        }
    }
}

#[tokio::test]
async fn the_retry_delay_is_awaited_before_the_next_attempt() {
    // Nothing listens on the released port, so every attempt fails immediately and the only time
    // between two reports is the delay the first one recommended.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a loopback port");
    let address = listener.local_addr().expect("the bound address");
    drop(listener);

    let retry = Duration::from_millis(300);
    let config = ClientConfig {
        server: address.to_string(),
        player_name: "Test player".to_owned(),
        device_info: None,
        identity: Identity::generate(),
        storage: None,
        audio_mode: AudioMode::Passthrough,
        volume: 100,
        muted: false,
        volume_policy: VolumePolicy::default(),
        max_backoff: retry,
        pairing_timeout: DEFAULT_PAIRING_TIMEOUT,
        #[cfg(feature = "discovery")]
        inbound: None,
        #[cfg(feature = "pairing-code")]
        static_pairing_code: None,
        #[cfg(feature = "pairing-code")]
        pairing_window: syncspin_client::DEFAULT_PAIRING_WINDOW,
        #[cfg(feature = "pairing-code")]
        pairing_pending_text: None,
        #[cfg(feature = "pairing-code")]
        code_formats: Vec::new(),
        #[cfg(feature = "pairing-code")]
        code_out_channels: Vec::new(),
    };
    let (handle, mut events) = connect(config, Box::new(RecordingSink::new(Recordings::default())))
        .await
        .expect("an unreachable server is not a connect error");

    let started = Instant::now();
    let first = match next_event(&mut events).await {
        Event::Disconnected { retry_in, .. } => retry_in,
        other => panic!("expected Disconnected, got {other:?}"),
    };
    assert_eq!(
        first, retry,
        "the cap applies to the first failed attempt as well"
    );

    match next_event(&mut events).await {
        Event::Disconnected { .. } => {}
        other => panic!("expected a second Disconnected, got {other:?}"),
    }
    assert!(
        started.elapsed() >= first,
        "the connection must wait {first:?} before retrying, waited {:?}",
        started.elapsed()
    );

    drop(handle);
}
