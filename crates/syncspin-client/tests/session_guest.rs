//! End-to-end tests of the session against the hermetic fake server.
//!
//! Every test binds one loopback port, runs the Noise initiator with `snow` on the server side and
//! records the frames a [`Sink`] receives. No test touches an audio device or another host.

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use syncspin_client::{
    connect, AudioFormat, AudioFrame, ClientConfig, ClientHandle, Codec, Event, EventStream,
    PlaybackState, Sink,
};
use syncspin_core::messages::{
    ControllerState, Incoming, PlayerCommand, ServerCommand, ServerState,
};
use syncspin_core::noise::{psk_id_for, Identity};

use fake_server::{FakeServer, Observation, ServerOptions};

/// One frame the recording sink received.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Written {
    Pcm(Vec<u8>),
    Encoded(Codec, Vec<u8>),
}

/// A received frame with its playout deadline.
#[derive(Debug, Clone)]
struct WrittenFrame {
    frame: Written,
    due: Instant,
}

/// What the sink recorded, shared with the test that owns the assertion.
#[derive(Clone, Default)]
struct Recordings {
    opened: Arc<Mutex<Vec<AudioFormat>>>,
    written: Arc<Mutex<Vec<WrittenFrame>>>,
    flushes: Arc<Mutex<usize>>,
}

impl Recordings {
    fn opened(&self) -> Vec<AudioFormat> {
        self.opened
            .lock()
            .expect("the recordings lock is not poisoned")
            .clone()
    }

    fn written(&self) -> Vec<WrittenFrame> {
        self.written
            .lock()
            .expect("the recordings lock is not poisoned")
            .clone()
    }

    fn flushes(&self) -> usize {
        *self
            .flushes
            .lock()
            .expect("the recordings lock is not poisoned")
    }
}

/// A sink that records instead of playing, and can fail on a chosen write.
struct RecordingSink {
    recordings: Recordings,
    fail_on_write: Option<usize>,
    writes: usize,
}

impl RecordingSink {
    fn new(recordings: Recordings) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            writes: 0,
        }
    }

    fn failing_on(recordings: Recordings, write: usize) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: Some(write),
            writes: 0,
        }
    }
}

impl Sink for RecordingSink {
    fn open(&mut self, format: AudioFormat) -> Result<()> {
        self.recordings
            .opened
            .lock()
            .expect("the recordings lock is not poisoned")
            .push(format);
        Ok(())
    }

    fn write(&mut self, frame: AudioFrame<'_>, due: Instant) -> Result<()> {
        self.writes += 1;
        if self.fail_on_write == Some(self.writes) {
            bail!(
                "the recording sink was told to fail on write {}",
                self.writes
            );
        }
        let frame = match frame {
            AudioFrame::Pcm(data) => Written::Pcm(data.to_vec()),
            AudioFrame::Encoded { codec, data } => Written::Encoded(codec.clone(), data.to_vec()),
        };
        self.recordings
            .written
            .lock()
            .expect("the recordings lock is not poisoned")
            .push(WrittenFrame { frame, due });
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        *self
            .recordings
            .flushes
            .lock()
            .expect("the recordings lock is not poisoned") += 1;
        Ok(())
    }
}

/// Creates a recording sink and the shared record it writes to.
fn recording_sink() -> (Recordings, Box<dyn Sink>) {
    let recordings = Recordings::default();
    (recordings.clone(), Box::new(RecordingSink::new(recordings)))
}

/// Connects to `server` with a fresh identity.
async fn connect_to(
    server: &FakeServer,
    mode: syncspin_client::AudioMode,
    sink: Box<dyn Sink>,
) -> (EventStream, ClientHandle) {
    let config = ClientConfig {
        server: server.endpoint(),
        player_name: "Test player".to_owned(),
        identity: Identity::generate(),
        audio_mode: mode,
        max_backoff: Duration::from_secs(1),
    };
    let (handle, events) = connect(config, sink)
        .await
        .expect("the client must connect to the fake server");
    (events, handle)
}

/// Waits for one event, failing instead of hanging.
async fn next_event_within(stream: &mut EventStream, timeout: Duration) -> Event {
    match tokio::time::timeout(timeout, stream.next()).await {
        Ok(Some(event)) => event,
        Ok(None) => panic!("the event stream ended"),
        Err(_) => panic!("timed out waiting for an event"),
    }
}

/// Waits for one event with the default timeout.
async fn next_event(stream: &mut EventStream) -> Event {
    next_event_within(stream, Duration::from_secs(5)).await
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

/// Waits until the sink recorded `count` writes.
async fn wait_for_writes(recordings: &Recordings, count: usize) -> Vec<WrittenFrame> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let written = recordings.written();
        if written.len() >= count {
            return written;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {count} sink writes"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Waits until the sink was opened at least once.
async fn wait_for_open(recordings: &Recordings) -> AudioFormat {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(format) = recordings.opened().first() {
            return format.clone();
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the sink to open"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Current wall clock in microseconds, the domain of server timestamps.
fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros() as i64)
        .unwrap_or(0)
}

#[tokio::test]
async fn connects_and_reports_an_encrypted_connection() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;

    expect_connected(&mut events, &server).await;
}

#[tokio::test]
async fn stream_start_opens_the_sink_with_the_announced_format() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("flac", 48_000, 2, 16);
    server.metadata("A title", "An artist");

    let format = AudioFormat {
        codec: Codec::Flac,
        sample_rate: 48_000,
        channels: 2,
        bit_depth: 16,
    };
    assert_eq!(
        next_event(&mut events).await,
        Event::StreamStart {
            format: format.clone()
        }
    );
    assert_eq!(
        next_event(&mut events).await,
        Event::Track {
            title: "A title".to_owned(),
            artist: "An artist".to_owned(),
        }
    );
    assert_eq!(
        wait_for_open(&recordings).await,
        format,
        "the sink must be opened with the announced format"
    );
    assert_eq!(
        recordings.flushes(),
        1,
        "a new stream must flush the previous output first"
    );
}

#[tokio::test]
async fn audio_chunks_reach_the_sink_with_the_announced_length() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("flac", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    let data = vec![0x5a; 4096];
    server.audio(1_760_000_000_000_000, 250_000, data.clone());

    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(
        written[0].frame,
        Written::Encoded(Codec::Flac, data.clone())
    );
    match &written[0].frame {
        Written::Encoded(_, bytes) => assert_eq!(bytes.len(), data.len()),
        other => panic!("expected an encoded frame, got {other:?}"),
    }
}

#[tokio::test]
async fn a_sink_error_ends_the_session_with_a_disconnect_event() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let recordings = Recordings::default();
    let sink = Box::new(RecordingSink::failing_on(recordings, 2));
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    server.audio(now_us(), 0, vec![0x11; 64]);
    server.audio(now_us(), 0, vec![0x22; 64]);

    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => {
            assert!(reason.contains("sink"), "unexpected reason: {reason}");
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }

    let outcome = tokio::time::timeout(Duration::from_secs(5), handle.finished())
        .await
        .expect("the session must not hang after a sink error");
    assert!(
        outcome.is_err(),
        "a sink failure must be returned from the session task"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("the event stream must end")
            .is_none(),
        "the stream ends after the disconnect"
    );
}

#[tokio::test]
async fn unknown_message_types_are_ignored() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(r#"{"type":"future/telemetry","payload":{"value":1}}"#);
    server.metadata("Still here", "An artist");

    assert_eq!(
        next_event(&mut events).await,
        Event::Track {
            title: "Still here".to_owned(),
            artist: "An artist".to_owned(),
        },
        "an unknown type must not close the connection"
    );

    // The connection is still usable after the unknown message.
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
}

#[tokio::test]
async fn malformed_known_message_closes_the_connection() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // `codec` is a string in stream/start; a number makes the known message malformed.
    server.json(r#"{"type":"stream/start","payload":{"player":{"codec":42}}}"#);

    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => {
            assert!(reason.contains("malformed"), "unexpected reason: {reason}");
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
    let outcome = tokio::time::timeout(Duration::from_secs(5), handle.finished())
        .await
        .expect("the session must not hang after a protocol error");
    assert!(outcome.is_err(), "a malformed message must end the session");
}

#[tokio::test]
async fn a_server_that_never_starts_the_handshake_is_refused() {
    let options = ServerOptions {
        start_handshake: false,
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;

    // The handshake timeout is five seconds; the assertion below must not be the first timeout.
    let event = next_event_within(&mut events, Duration::from_secs(8)).await;
    match event {
        Event::Disconnected { reason, .. } => {
            assert!(
                reason.contains("handshake"),
                "the refusal must name the handshake, got: {reason}"
            );
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
    let outcome = tokio::time::timeout(Duration::from_secs(2), handle.finished())
        .await
        .expect("the session must not hang");
    assert!(
        outcome.is_err(),
        "a server without a handshake must be an error, not a downgrade"
    );
    assert!(
        recordings.opened().is_empty(),
        "nothing may be played without an encrypted handshake"
    );
}

#[tokio::test]
async fn a_wrong_psk_id_falls_back_to_the_sentinel_psk() {
    // The server announces a pairing key the client does not have, but seals the handshake with
    // the published key. Only a client that falls back can complete message 2.
    let unknown: [u8; 32] = std::array::from_fn(|index| (index as u8) ^ 0xa5);
    let options = ServerOptions {
        psk_id: psk_id_for(&unknown),
        psk_category: "pr".to_owned(),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;

    expect_connected(&mut events, &server).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), server.wait_for_message_2())
            .await
            .expect("the server must observe message 2"),
        "message 2 must authenticate with the Sentinel key"
    );
}

#[tokio::test]
async fn malformed_psk_metadata_closes_without_a_second_handshake_message() {
    let options = ServerOptions {
        metadata: Some(r#"{"psk_id":42,"psk_category":"sn"}"#.to_owned()),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;

    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => {
            assert!(reason.contains("metadata"), "unexpected reason: {reason}");
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
    let observed = tokio::time::timeout(Duration::from_secs(3), server.observation())
        .await
        .expect("the fake server must notice the close");
    assert!(
        matches!(observed, Some(Observation::ClosedBeforeMessage2) | None),
        "message 2 must never be sent after malformed metadata"
    );
    let outcome = tokio::time::timeout(Duration::from_secs(2), handle.finished())
        .await
        .expect("the session must not hang");
    assert!(outcome.is_err());
}

#[tokio::test]
async fn audio_chunks_carry_a_playout_deadline_once_the_clock_is_ready() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // The client reports its state once its clock estimate is ready, which pins the ordering of
    // the sync replies before the audio below.
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_state())
            .await
            .expect("the client must report its state"),
        "the clock estimate never became ready"
    );

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    let timestamp = now_us() + 250_000;
    server.audio(timestamp, 250_000, vec![0x33; 64]);

    let written = wait_for_writes(&recordings, 1).await;
    let due = written[0].due;
    let now = Instant::now();
    assert!(
        due > now + Duration::from_millis(100),
        "the deadline {due:?} must be ahead of now {now:?}"
    );
    assert!(
        due < now + Duration::from_millis(700),
        "the deadline {due:?} must be near the announced timestamp"
    );
}

#[tokio::test]
async fn audio_is_delivered_before_the_clock_is_ready() {
    let options = ServerOptions {
        answer_time: false,
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    server.audio(now_us(), 0, vec![0x44; 32]);

    let written = wait_for_writes(&recordings, 1).await;
    assert!(
        written[0].due <= Instant::now(),
        "without a clock estimate the deadline must not be scheduled into the future"
    );
}

#[tokio::test]
async fn a_volume_command_is_reported() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let command = serde_json::to_string(&Incoming::ServerCommand(ServerCommand {
        player: Some(PlayerCommand {
            command: "volume".to_owned(),
            volume: Some(25),
            mute: None,
            output_delay_ms: None,
        }),
    }))
    .unwrap();
    server.json(command);

    assert_eq!(
        next_event(&mut events).await,
        Event::Volume {
            level: 25,
            muted: false
        }
    );
}

#[tokio::test]
async fn an_invalid_configuration_is_rejected_before_connecting() {
    let (_recordings, sink) = recording_sink();
    let config = ClientConfig {
        server: "127.0.0.1:1".to_owned(),
        player_name: String::new(),
        identity: Identity::generate(),
        audio_mode: syncspin_client::AudioMode::Passthrough,
        max_backoff: Duration::from_secs(1),
    };
    match connect(config, sink).await {
        Ok(_) => panic!("an empty player name must be rejected"),
        Err(error) => assert!(
            format!("{error:#}").contains("player_name"),
            "the error should name the field, got: {error:#}"
        ),
    }
}
#[tokio::test]
async fn the_client_announces_the_player_role_and_the_requested_format() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let hello = tokio::time::timeout(Duration::from_secs(2), server.wait_for_client_hello())
        .await
        .expect("the fake server must see client/hello")
        .expect("the connection must not close before client/hello");
    assert_eq!(hello.name, "Test player");
    assert!(
        hello.supported_roles.iter().any(|role| role == "player@v1"),
        "the player role must be announced: {:?}",
        hello.supported_roles
    );
    let support = hello
        .player_support
        .expect("the player role needs support data");
    assert_eq!(support.supported_formats[0].codec, "flac");
    assert_eq!(support.supported_formats[0].sample_rate, 48_000);
    assert!(hello.unpaired_access.enabled);
}

#[tokio::test]
async fn a_decode_client_rejects_an_encoded_stream() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) = connect_to(&server, syncspin_client::AudioMode::Decode, sink).await;
    expect_connected(&mut events, &server).await;

    let hello = tokio::time::timeout(Duration::from_secs(2), server.wait_for_client_hello())
        .await
        .expect("the fake server must see client/hello")
        .expect("the connection must not close before client/hello");
    let support = hello
        .player_support
        .expect("the player role needs support data");
    assert_eq!(
        support.supported_formats[0].codec, "pcm",
        "a decode client must only ask for samples it can hand to the sink"
    );

    // A server that ignores the advertisement must not get encoded bytes written to a sink that
    // expects samples.
    server.stream_start("flac", 48_000, 2, 16);
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => {
            assert!(reason.contains("flac"), "unexpected reason: {reason}");
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
}

#[tokio::test]
async fn controller_state_is_reported() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let state = serde_json::to_string(&Incoming::ServerState(ServerState {
        metadata: None,
        controller: Some(ControllerState {
            supported_commands: vec!["play".to_owned()],
            volume: Some(40),
            muted: Some(false),
            repeat: None,
            shuffle: None,
        }),
    }))
    .unwrap();
    server.json(state);

    assert_eq!(
        next_event(&mut events).await,
        Event::State(PlaybackState {
            supported_commands: vec!["play".to_owned()],
            volume: Some(40),
            muted: Some(false),
        })
    );
}
#[tokio::test]
async fn a_fragmented_audio_chunk_reassembles_before_the_sink_sees_it() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // More than one Noise plaintext: the server has to fragment it and the client has to
    // reassemble it into one frame.
    let data: Vec<u8> = (0..100 * 1024).map(|index| (index % 251) as u8).collect();
    server.audio(now_us(), 0, data.clone());

    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(written.len(), 1, "a fragmented chunk is one frame");
    assert_eq!(written[0].frame, Written::Pcm(data));
}
