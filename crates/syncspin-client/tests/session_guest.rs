//! End-to-end tests of the session against the hermetic fake server.
//!
//! Every test binds one loopback port, runs the Noise initiator with `snow` on the server side and
//! records the frames a [`Sink`] receives. No test touches an audio device or another host.

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use syncspin_client::{
    connect, connect_with_psks, AudioFormat, AudioFrame, ClientConfig, ClientHandle, Codec, Event,
    EventStream, PskCategory, Sink, StoredPsk,
};
use syncspin_core::messages::{
    ClientState, ControllerState, Incoming, PlayerCommand, Progress, ServerCommand, ServerState,
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
    latency: Option<Duration>,
    writes: usize,
}

impl RecordingSink {
    fn new(recordings: Recordings) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            latency: None,
            writes: 0,
        }
    }

    fn failing_on(recordings: Recordings, write: usize) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: Some(write),
            latency: None,
            writes: 0,
        }
    }

    fn with_latency(recordings: Recordings, latency: Duration) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            latency: Some(latency),
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

    fn latency(&self) -> Option<Duration> {
        self.latency
    }
}

/// Creates a recording sink and the shared record it writes to.
fn recording_sink() -> (Recordings, Box<dyn Sink>) {
    let recordings = Recordings::default();
    (recordings.clone(), Box::new(RecordingSink::new(recordings)))
}

/// Creates a recording sink that reports a fixed output delay.
fn sink_with_latency(latency: Duration) -> (Recordings, Box<dyn Sink>) {
    let recordings = Recordings::default();
    (
        recordings.clone(),
        Box::new(RecordingSink::with_latency(recordings, latency)),
    )
}

/// Builds a configuration for `server`.
fn config_for(server: &FakeServer, mode: syncspin_client::AudioMode) -> ClientConfig {
    ClientConfig {
        server: server.endpoint(),
        player_name: "Test player".to_owned(),
        identity: Identity::generate(),
        audio_mode: mode,
        max_backoff: Duration::from_secs(1),
    }
}

/// Connects to `server` with a fresh identity.
async fn connect_to(
    server: &FakeServer,
    mode: syncspin_client::AudioMode,
    sink: Box<dyn Sink>,
) -> (EventStream, ClientHandle) {
    let (handle, events) = connect(config_for(server, mode), sink)
        .await
        .expect("the client must connect to the fake server");
    (events, handle)
}

/// Connects with stored pairing keys.
async fn connect_with_stored_psks(
    server: &FakeServer,
    mode: syncspin_client::AudioMode,
    sink: Box<dyn Sink>,
    psks: Vec<StoredPsk>,
) -> (EventStream, ClientHandle) {
    let (handle, events) = connect_with_psks(config_for(server, mode), sink, psks)
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

/// Waits until the sink recorded `count` flushes.
async fn wait_for_flushes(recordings: &Recordings, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if recordings.flushes() >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {count} sink flushes, saw {}",
            recordings.flushes()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Waits for the client's player state report.
async fn wait_for_client_state(server: &mut FakeServer) -> ClientState {
    tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_state())
        .await
        .expect("the client must report its state")
        .expect("the connection must not close before the state report")
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

    let format = match next_event(&mut events).await {
        Event::StreamStart { format } => format,
        other => panic!("expected StreamStart, got {other:?}"),
    };
    assert_eq!(format.codec, Codec::Flac);
    assert_eq!(format.sample_rate, 48_000);
    assert_eq!(format.channels, 2);
    assert_eq!(format.bit_depth, 16);
    assert_eq!(format.codec_header, None);

    match next_event(&mut events).await {
        Event::Track {
            title,
            artist,
            album,
            album_artist,
            artwork_url,
            progress_ms,
            duration_ms,
        } => {
            assert_eq!(title, "A title");
            assert_eq!(artist, "An artist");
            assert_eq!(album, "");
            assert_eq!(album_artist, "");
            assert_eq!(artwork_url, "");
            assert_eq!(progress_ms, None);
            assert_eq!(duration_ms, None);
        }
        other => panic!("expected Track, got {other:?}"),
    }

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
async fn a_codec_header_is_delivered_to_the_sink() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // 40 bytes is not a multiple of three, so its standard base64 carries `==` padding; the
    // client has to accept the padded form the protocol specifies.
    let header: Vec<u8> = (0..40).map(|index| index as u8).collect();
    assert!(
        STANDARD.encode(&header).ends_with("=="),
        "the header must exercise base64 padding"
    );
    server.stream_start_with_header("flac", 48_000, 2, 16, Some(&header));

    let format = match next_event(&mut events).await {
        Event::StreamStart { format } => format,
        other => panic!("expected StreamStart, got {other:?}"),
    };
    assert_eq!(
        format.codec_header.as_deref(),
        Some(header.as_slice()),
        "the announced codec header must be decoded verbatim"
    );
    let opened = wait_for_open(&recordings).await;
    assert_eq!(
        opened.codec_header.as_deref(),
        Some(header.as_slice()),
        "the sink must receive exactly the announced codec header"
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
async fn stream_end_flushes_the_sink() {
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
    assert_eq!(recordings.flushes(), 1);

    server.stream_end();
    wait_for_flushes(&recordings, 2).await;
}

#[tokio::test]
async fn no_audio_is_written_after_stream_end() {
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
    server.stream_end();
    // The flush proves the end was processed; the audio below is sent after it.
    wait_for_flushes(&recordings, 2).await;

    server.audio(now_us(), 0, vec![0x55; 64]);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        recordings.written().is_empty(),
        "a chunk after stream/end must not reach the sink"
    );
}

#[tokio::test]
async fn stream_clear_flushes_the_sink() {
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
    server.stream_clear(Some(now_us() - 1_000_000));
    wait_for_flushes(&recordings, 2).await;

    // A clear is a seek, not an end: the announced format stays open and later chunks still play.
    server.audio(now_us(), 0, vec![0x66; 64]);
    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(written[0].frame, Written::Pcm(vec![0x66; 64]));
}

#[tokio::test]
async fn removing_the_player_role_flushes_the_sink() {
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
    server.activate(&["metadata@v1"]);
    wait_for_flushes(&recordings, 2).await;

    server.audio(now_us(), 0, vec![0x77; 64]);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        recordings.written().is_empty(),
        "audio for an inactive player role must not reach the sink"
    );
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

    match next_event(&mut events).await {
        Event::Track { title, artist, .. } => {
            assert_eq!(title, "Still here");
            assert_eq!(artist, "An artist");
        }
        other => panic!("an unknown type must not close the connection, got {other:?}"),
    }

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
async fn a_short_audio_chunk_without_a_stream_is_a_protocol_error() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // Message id 4 with fewer than the 13 header bytes, and no stream announced.
    server.binary(vec![4, 0, 0]);

    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => {
            assert!(
                reason.contains("truncated"),
                "the header is validated even without a stream, got: {reason}"
            );
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
    let outcome = tokio::time::timeout(Duration::from_secs(5), handle.finished())
        .await
        .expect("the session must not hang after a protocol error");
    assert!(outcome.is_err());
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
async fn a_stored_key_seals_the_handshake() {
    // The server announces and uses a private key. Removing `Responder::set_psk` leaves the
    // responder on the Sentinel key, message 2 fails to authenticate, and this test fails.
    let psk: [u8; 32] = std::array::from_fn(|index| (index as u8) ^ 0x3c);
    let options = ServerOptions {
        psk_id: psk_id_for(&psk),
        psk_category: "pr".to_owned(),
        psk,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let stored = StoredPsk {
        category: PskCategory::Pairing,
        psk,
        server_id: server.server_id().to_owned(),
    };
    let (mut events, _handle) = connect_with_stored_psks(
        &server,
        syncspin_client::AudioMode::Passthrough,
        sink,
        vec![stored],
    )
    .await;

    expect_connected(&mut events, &server).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), server.wait_for_message_2())
            .await
            .expect("the server must observe message 2"),
        "message 2 must authenticate with the stored key"
    );
}

#[tokio::test]
async fn a_stored_key_for_another_server_is_refused() {
    let psk: [u8; 32] = std::array::from_fn(|index| (index as u8) ^ 0x6e);
    let options = ServerOptions {
        psk_id: psk_id_for(&psk),
        psk_category: "lt".to_owned(),
        psk,
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let stored = StoredPsk {
        category: PskCategory::LongTerm,
        psk,
        server_id: "a different server".to_owned(),
    };
    let (mut events, handle) = connect_with_stored_psks(
        &server,
        syncspin_client::AudioMode::Passthrough,
        sink,
        vec![stored],
    )
    .await;

    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => {
            assert!(
                reason.contains("another server"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
    let outcome = tokio::time::timeout(Duration::from_secs(2), handle.finished())
        .await
        .expect("the session must not hang");
    assert!(outcome.is_err());
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

    // The state report follows the first completed burst. The filter needs three measurements,
    // so the client runs three bursts before the clock is ready; the server counts the replies,
    // and the 24th is ordered before the audio below.
    wait_for_client_state(&mut server).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_time_replies(24))
            .await
            .expect("the fake server must answer the initial bursts"),
        "the connection must stay open while the clock estimate forms"
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
        answer_time_limit: Some(0),
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
async fn the_initial_state_is_sent_after_a_single_time_reply() {
    let options = ServerOptions {
        answer_time_limit: Some(1),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // The burst has a single deadline, so the unanswered requests cost one short wait, not seven.
    let state = wait_for_client_state(&mut server).await;
    assert!(state.available);
}

#[tokio::test]
async fn the_initial_state_is_sent_after_two_time_replies() {
    let options = ServerOptions {
        answer_time_limit: Some(2),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let state = wait_for_client_state(&mut server).await;
    assert!(state.available);
}

#[tokio::test]
async fn readding_the_player_role_reports_state_again() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    wait_for_client_state(&mut server).await;

    server.activate(&["metadata@v1"]);
    server.activate(&["player@v1", "metadata@v1"]);
    let state = wait_for_client_state(&mut server).await;
    assert!(
        state.available,
        "a re-added player role must report itself again"
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
            level: Some(25),
            muted: None
        }
    );
}

#[tokio::test]
async fn a_mute_command_does_not_report_a_volume() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let command = serde_json::to_string(&Incoming::ServerCommand(ServerCommand {
        player: Some(PlayerCommand {
            command: "mute".to_owned(),
            volume: None,
            mute: Some(true),
            output_delay_ms: None,
        }),
    }))
    .unwrap();
    server.json(command);

    assert_eq!(
        next_event(&mut events).await,
        Event::Volume {
            level: None,
            muted: Some(true)
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
    let options = ServerOptions {
        active_roles: vec![
            "player@v1".to_owned(),
            "metadata@v1".to_owned(),
            "controller@v1".to_owned(),
        ],
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
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

    match next_event(&mut events).await {
        Event::State(state) => {
            assert_eq!(state.supported_commands, vec!["play".to_owned()]);
            assert_eq!(state.volume, Some(40));
            assert_eq!(state.muted, Some(false));
        }
        other => panic!("expected State, got {other:?}"),
    }
}

#[tokio::test]
async fn metadata_fields_are_reported() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let state = serde_json::to_string(&Incoming::ServerState(ServerState {
        metadata: Some(syncspin_core::messages::Metadata {
            title: Some("A title".to_owned()),
            artist: Some("An artist".to_owned()),
            album: Some("An album".to_owned()),
            album_artist: Some("An album artist".to_owned()),
            artwork_url: Some("https://example.test/art.png".to_owned()),
            progress: Some(Progress {
                track_progress: Some(1_500),
                track_duration: Some(240_000),
                playback_speed: Some(1_000),
            }),
            ..Default::default()
        }),
        controller: None,
    }))
    .unwrap();
    server.json(state);

    match next_event(&mut events).await {
        Event::Track {
            title,
            artist,
            album,
            album_artist,
            artwork_url,
            progress_ms,
            duration_ms,
        } => {
            assert_eq!(title, "A title");
            assert_eq!(artist, "An artist");
            assert_eq!(album, "An album");
            assert_eq!(album_artist, "An album artist");
            assert_eq!(artwork_url, "https://example.test/art.png");
            assert_eq!(progress_ms, Some(1_500));
            assert_eq!(duration_ms, Some(240_000));
        }
        other => panic!("expected Track, got {other:?}"),
    }
}

#[tokio::test]
async fn a_short_playout_delay_is_reported() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = sink_with_latency(Duration::from_secs(60));
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let state = wait_for_client_state(&mut server).await;
    let player = state.player.expect("the player state follows the role");
    assert_eq!(
        player.output_delay_ms, 5_000,
        "an absurd sink latency is clamped before it reaches the server"
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
#[tokio::test]
async fn a_second_time_request_waits_for_the_first_reply() {
    let options = ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let first = tokio::time::timeout(Duration::from_secs(2), server.next_time_request())
        .await
        .expect("the client must send its first clock request")
        .expect("the connection must stay open");

    // The spec sends one request at a time: no second request may arrive before the reply.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server.next_time_request())
            .await
            .is_err(),
        "a second client/time arrived before the first reply"
    );

    server.answer_time(first);
    tokio::time::timeout(Duration::from_secs(2), server.next_time_request())
        .await
        .expect("the client must send the next request after the reply")
        .expect("the connection must stay open");
}

#[tokio::test]
async fn a_stream_end_for_another_role_leaves_the_player_alone() {
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
    server.stream_end_for(&["visualizer"]);
    server.audio(now_us(), 0, vec![0x88; 64]);

    // The player stream is untouched: the chunk still plays and the sink was not flushed again.
    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(written[0].frame, Written::Pcm(vec![0x88; 64]));
    assert_eq!(
        recordings.flushes(),
        1,
        "a stream end for another role must not flush the player stream"
    );
}
