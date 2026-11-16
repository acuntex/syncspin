//! End-to-end tests of the session against the hermetic fake server.
//!
//! Every test binds one loopback port, runs the Noise initiator with `snow` on the server side and
//! records the frames a [`Sink`] receives. No test touches an audio device or another host.

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use syncspin_client::{
    connect, connect_with_psks, AudioFormat, AudioFrame, ClientConfig, ClientHandle, Codec, Event,
    EventStream, PskCategory, Sink, StoredPsk, StreamEndReason, VolumePolicy,
    DEFAULT_PAIRING_TIMEOUT, NORMAL_PLAYBACK_SPEED,
};
use syncspin_core::messages::{
    ClientState, ControllerState, GroupUpdate, Incoming, PlayerCommand, Progress, ServerCommand,
    ServerState,
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

/// A gate that holds one sink flush until the test releases it.
///
/// It lets a test prove ordering: the session cannot release the held flush before it emitted the
/// event, so a test that only releases the gate after it saw the event fails when the order is
/// reversed (the flush spins and no event arrives).
#[derive(Clone, Default)]
struct FlushGate {
    release: Arc<AtomicBool>,
}

impl FlushGate {
    /// Lets the held flush return.
    fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
    }

    /// Spins until the test released the gate, or the bound expires.
    ///
    /// The bound keeps a failing test from wedging its worker thread forever; the test itself
    /// fails earlier, because it is waiting for the event with a shorter timeout.
    fn wait(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.release.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::yield_now();
        }
    }
}

/// A sink that records instead of playing, and can fail on a chosen write.
struct RecordingSink {
    recordings: Recordings,
    fail_on_write: Option<usize>,
    fail_on_flush: Option<usize>,
    fail_on_open: bool,
    latency: Option<Duration>,
    writes: usize,
    /// Flush call that holds the session until the gate is released.
    hold_flush: Option<usize>,
    gate: Option<FlushGate>,
}

impl RecordingSink {
    fn new(recordings: Recordings) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_open: false,
            latency: None,
            writes: 0,
            hold_flush: None,
            gate: None,
        }
    }

    fn failing_on(recordings: Recordings, write: usize) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: Some(write),
            fail_on_flush: None,
            fail_on_open: false,
            latency: None,
            writes: 0,
            hold_flush: None,
            gate: None,
        }
    }

    /// Creates a sink that fails the `flush`th flush, counting from one.
    fn failing_flush_on(recordings: Recordings, flush: usize) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: Some(flush),
            fail_on_open: false,
            latency: None,
            writes: 0,
            hold_flush: None,
            gate: None,
        }
    }

    /// Creates a sink that rejects every stream format.
    fn failing_open(recordings: Recordings) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_open: true,
            latency: None,
            writes: 0,
            hold_flush: None,
            gate: None,
        }
    }

    fn with_latency(recordings: Recordings, latency: Duration) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_open: false,
            latency: Some(latency),
            writes: 0,
            hold_flush: None,
            gate: None,
        }
    }

    fn gated(recordings: Recordings, gate: FlushGate, hold_flush: usize) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_open: false,
            latency: None,
            writes: 0,
            hold_flush: Some(hold_flush),
            gate: Some(gate),
        }
    }
}

impl Sink for RecordingSink {
    fn open(&mut self, format: AudioFormat) -> Result<()> {
        if self.fail_on_open {
            bail!("the recording sink was told to reject the format");
        }
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
        let count = {
            let mut flushes = self
                .recordings
                .flushes
                .lock()
                .expect("the recordings lock is not poisoned");
            *flushes += 1;
            *flushes
        };
        if self.fail_on_flush == Some(count) {
            bail!("the recording sink was told to fail flush {count}");
        }
        if self.hold_flush == Some(count) {
            if let Some(gate) = &self.gate {
                gate.wait();
            }
        }
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

/// Creates a recording sink that holds the `hold_flush`th flush until the gate is released.
fn gated_sink(hold_flush: usize) -> (Recordings, FlushGate, Box<dyn Sink>) {
    let recordings = Recordings::default();
    let gate = FlushGate::default();
    let sink = Box::new(RecordingSink::gated(
        recordings.clone(),
        gate.clone(),
        hold_flush,
    ));
    (recordings, gate, sink)
}

/// Builds a configuration for `server`.
fn config_for(server: &FakeServer, mode: syncspin_client::AudioMode) -> ClientConfig {
    ClientConfig {
        server: server.endpoint(),
        player_name: "Test player".to_owned(),
        device_info: None,
        identity: Identity::generate(),
        storage: None,
        audio_mode: mode,
        volume: 100,
        muted: false,
        volume_policy: VolumePolicy::default(),
        max_backoff: Duration::from_secs(1),
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

/// Asserts that a transient failure left the connection reconnecting instead of ending it.
async fn assert_still_reconnecting(handle: ClientHandle) {
    assert!(
        tokio::time::timeout(Duration::from_millis(200), handle.finished())
            .await
            .is_err(),
        "a transient failure must not end the connection"
    );
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
            playback_speed,
        } => {
            assert_eq!(title, "A title");
            assert_eq!(artist, "An artist");
            assert_eq!(album, "");
            assert_eq!(album_artist, "");
            assert_eq!(artwork_url, "");
            assert_eq!(progress_ms, None);
            assert_eq!(duration_ms, None);
            assert_eq!(playback_speed, NORMAL_PLAYBACK_SPEED);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_end_emits_an_event_before_the_flush() {
    // The second flush - the one `stream/end` causes - holds the session until this test releases
    // it. The event therefore has to arrive while the sink is still inside that flush; an
    // implementation that flushed first would never get to the event and this test would time out.
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, gate, sink) = gated_sink(2);
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
    match next_event_within(&mut events, Duration::from_secs(2)).await {
        Event::StreamEnd { reason } => assert_eq!(reason, StreamEndReason::End),
        other => panic!("expected StreamEnd, got {other:?}"),
    }
    gate.release();
    wait_for_flushes(&recordings, 2).await;
}

/// `messaging.md` names the roles in `stream/end` as bare `player`, while `server/activate` uses
/// `player@v1`. Matching only the versioned form silently ignored every pause from the server.
#[tokio::test]
async fn a_bare_player_role_still_ends_the_stream() {
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

    server.stream_end_for(&["player"]);
    match next_event_within(&mut events, Duration::from_secs(2)).await {
        Event::StreamEnd { .. } => {}
        other => panic!("expected StreamEnd for a bare player role, got {other:?}"),
    }
    let _ = recordings;
}

#[tokio::test]
async fn a_stream_clear_carries_the_timestamp() {
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

    let seek_position = now_us() - 1_000_000;
    server.stream_clear(Some(seek_position));
    match next_event(&mut events).await {
        Event::StreamClear { from_timestamp } => assert_eq!(
            from_timestamp,
            Some(seek_position),
            "the seek position must reach the host unchanged"
        ),
        other => panic!("expected StreamClear, got {other:?}"),
    }
    wait_for_flushes(&recordings, 2).await;

    server.stream_clear(None);
    match next_event(&mut events).await {
        Event::StreamClear { from_timestamp } => assert_eq!(
            from_timestamp, None,
            "a clear without a position must not invent one"
        ),
        other => panic!("expected StreamClear, got {other:?}"),
    }
    wait_for_flushes(&recordings, 3).await;
}

#[tokio::test]
async fn removing_the_player_role_reports_role_removed() {
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
    match next_event(&mut events).await {
        Event::StreamEnd { reason } => assert_eq!(reason, StreamEndReason::RoleRemoved),
        other => panic!("expected StreamEnd, got {other:?}"),
    }
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
        Event::Disconnected { reason, retry_in } => {
            assert!(reason.contains("sink"), "unexpected reason: {reason}");
            assert_eq!(
                retry_in,
                Duration::ZERO,
                "a broken sink is not retried, so no delay is recommended"
            );
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
async fn a_malformed_control_message_is_ignored() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // A known type whose payload does not deserialize: `volume` is an integer on the wire, so 300
    // does not fit. A value in 101-255 decodes and stays capped by the volume policy
    // (`docs/spec-deviations.md`, entry 14), which is not a decode failure.
    server.json(
        r#"{"type":"server/command","payload":{"player":{"command":"volume","volume":300}}}"#,
    );
    // A truncated body: the JSON object never closes.
    server.json(r#"{"type":"server/state","payload":{"metadata":{"title":"#);

    // Both are dropped. The first message that decodes still arrives, so the session survived
    // them and the stream stayed usable.
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, artist, .. } => {
            assert_eq!(title, "Still here");
            assert_eq!(artist, "An artist");
        }
        other => panic!("a malformed control message must not close the connection, got {other:?}"),
    }

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
}

#[tokio::test]
async fn a_malformed_audio_header_is_a_protocol_error() {
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
    assert_still_reconnecting(handle).await;
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
    assert_still_reconnecting(handle).await;
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
    assert_still_reconnecting(handle).await;
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
    assert_still_reconnecting(handle).await;
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

    // The burst carries one answered request and times the rest out, so the filter's first sample
    // lands when the burst ends. The state is reported then, never on an individual reply.
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

    // Two answered requests still leave the burst short of its full eight, so the report follows
    // the burst's last timeout.
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
            requested: 25,
            applied: 25,
            muted: None,
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
            requested: 100,
            applied: 100,
            muted: Some(true),
        }
    );
}

#[tokio::test]
async fn an_invalid_configuration_is_rejected_before_connecting() {
    let base = |name: &str| ClientConfig {
        server: "127.0.0.1:1".to_owned(),
        player_name: name.to_owned(),
        device_info: None,
        identity: Identity::generate(),
        storage: None,
        audio_mode: syncspin_client::AudioMode::Passthrough,
        volume: 100,
        muted: false,
        volume_policy: VolumePolicy::default(),
        max_backoff: Duration::from_secs(1),
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

    for (label, config, field) in [
        ("an empty name", base(""), "player_name"),
        (
            "a level above the range",
            ClientConfig {
                volume: 101,
                ..base("Test player")
            },
            "volume",
        ),
        (
            "a threshold above the range",
            ClientConfig {
                volume_policy: VolumePolicy {
                    threshold: 101,
                    ..VolumePolicy::default()
                },
                ..base("Test player")
            },
            "volume_policy",
        ),
        (
            "a step above the range",
            ClientConfig {
                volume_policy: VolumePolicy {
                    max_step: 101,
                    ..VolumePolicy::default()
                },
                ..base("Test player")
            },
            "volume_policy",
        ),
        (
            "a zero backoff",
            ClientConfig {
                max_backoff: Duration::ZERO,
                ..base("Test player")
            },
            "max_backoff",
        ),
    ] {
        let (_recordings, sink) = recording_sink();
        match connect(config, sink).await {
            Ok(_) => panic!("{label} must be rejected"),
            Err(error) => assert!(
                format!("{error:#}").contains(field),
                "{label}: the error should name {field}, got: {error:#}"
            ),
        }
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
    assert_eq!(
        hello.device_info, None,
        "a host that describes no device announces none"
    );
}

#[tokio::test]
async fn device_info_is_announced_in_the_hello() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.device_info = Some(syncspin_client::DeviceInfo {
        product_name: "A110".to_owned(),
        manufacturer: "Acme Audio".to_owned(),
        software_version: Some("1.4.2".to_owned()),
        mac_address: Some("02:00:5e:10:00:01".to_owned()),
    });
    let (_handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    let hello = tokio::time::timeout(Duration::from_secs(2), server.wait_for_client_hello())
        .await
        .expect("the fake server must see client/hello")
        .expect("the connection must not close before client/hello");
    assert_eq!(
        hello.device_info,
        Some(syncspin_core::messages::DeviceInfo {
            product_name: Some("A110".to_owned()),
            manufacturer: Some("Acme Audio".to_owned()),
            software_version: Some("1.4.2".to_owned()),
            mac_address: Some("02:00:5e:10:00:01".to_owned()),
        }),
        "the configured device must reach the server unchanged"
    );
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
async fn group_update_is_the_authoritative_playback_state() {
    let options = ServerOptions {
        active_roles: vec!["player@v1".to_owned(), "controller@v1".to_owned()],
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // The controller state carries the volume, mute and command set but no group fields.
    let state = serde_json::to_string(&Incoming::ServerState(ServerState {
        metadata: None,
        controller: Some(ControllerState {
            supported_commands: vec!["play".to_owned()],
            volume: Some(35),
            muted: Some(false),
            repeat: None,
            shuffle: None,
        }),
    }))
    .unwrap();
    server.json(state);

    match next_event(&mut events).await {
        Event::State(state) => {
            assert_eq!(state.volume, Some(35));
            assert_eq!(
                state.group_id, None,
                "no group/update has arrived, so the client knows no group yet"
            );
        }
        other => panic!("expected State, got {other:?}"),
    }

    // `group/update` is where the group's playback state comes from, and the picture it completes
    // keeps the role fields that `server/state` supplied.
    let group_id = "A".repeat(43);
    let update = serde_json::to_string(&Incoming::GroupUpdate(GroupUpdate {
        playback_state: "playing".to_owned(),
        group_id: group_id.clone(),
        group_name: "Living room".to_owned(),
    }))
    .unwrap();
    server.json(update);

    match next_event(&mut events).await {
        Event::State(state) => {
            assert_eq!(state.playback_state.as_deref(), Some("playing"));
            assert_eq!(state.group_id.as_deref(), Some(group_id.as_str()));
            assert_eq!(state.group_name.as_deref(), Some("Living room"));
            assert_eq!(state.volume, Some(35), "the controller picture is kept");
            assert_eq!(state.supported_commands, vec!["play".to_owned()]);
        }
        other => panic!("expected State, got {other:?}"),
    }
}

#[tokio::test]
async fn a_group_update_needs_no_role() {
    // `group/update` is a core message: the client reports it even when the server activated no
    // role at all, so a host without the controller role still learns what the group is doing.
    let options = ServerOptions {
        active_roles: Vec::new(),
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let update = serde_json::to_string(&Incoming::GroupUpdate(GroupUpdate {
        playback_state: "stopped".to_owned(),
        group_id: "A".repeat(43),
        group_name: "Living room".to_owned(),
    }))
    .unwrap();
    server.json(update);

    match next_event(&mut events).await {
        Event::State(state) => {
            assert_eq!(state.playback_state.as_deref(), Some("stopped"));
            assert_eq!(state.group_name.as_deref(), Some("Living room"));
            assert!(state.supported_commands.is_empty());
        }
        other => panic!("expected State, got {other:?}"),
    }
}

#[tokio::test]
async fn a_group_update_with_a_malformed_group_id_is_a_protocol_error() {
    // The identifier is 32 bytes as 43 unpadded base64url characters; both a wrong length and a
    // character outside the alphabet are protocol errors that close the connection.
    for group_id in ["B".repeat(42), format!("{}=", "B".repeat(42))] {
        let server = FakeServer::start(ServerOptions::default()).await.unwrap();
        let (_recordings, sink) = recording_sink();
        let (mut events, _handle) =
            connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
        expect_connected(&mut events, &server).await;

        let update = serde_json::to_string(&Incoming::GroupUpdate(GroupUpdate {
            playback_state: "stopped".to_owned(),
            group_id: group_id.clone(),
            group_name: "Living room".to_owned(),
        }))
        .unwrap();
        server.json(update);

        match next_event(&mut events).await {
            Event::Disconnected { reason, .. } => assert!(
                reason.contains("group_id"),
                "the reason should name the group_id rule, got: {reason}"
            ),
            other => panic!("expected Disconnected, got {other:?}"),
        }
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
            playback_speed,
        } => {
            assert_eq!(title, "A title");
            assert_eq!(artist, "An artist");
            assert_eq!(album, "An album");
            assert_eq!(album_artist, "An album artist");
            assert_eq!(artwork_url, "https://example.test/art.png");
            assert_eq!(progress_ms, Some(1_500));
            assert_eq!(duration_ms, Some(240_000));
            assert_eq!(playback_speed, NORMAL_PLAYBACK_SPEED);
        }
        other => panic!("expected Track, got {other:?}"),
    }
}

#[tokio::test]
async fn the_track_event_carries_the_playback_speed() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // The metadata role's progress carries the speed in per-mille; 1500 is one and a half times
    // normal speed.
    let state = serde_json::to_string(&Incoming::ServerState(ServerState {
        metadata: Some(syncspin_core::messages::Metadata {
            title: Some("A title".to_owned()),
            progress: Some(Progress {
                track_progress: Some(1_500),
                track_duration: Some(240_000),
                playback_speed: Some(1_500),
            }),
            ..Default::default()
        }),
        controller: None,
    }))
    .unwrap();
    server.json(state);

    match next_event(&mut events).await {
        Event::Track {
            playback_speed,
            progress_ms,
            ..
        } => {
            assert_eq!(
                playback_speed, 1_500,
                "the reported speed must reach the host unchanged"
            );
            assert_eq!(progress_ms, Some(1_500));
        }
        other => panic!("expected Track, got {other:?}"),
    }

    // A metadata message without a progress object plays at normal speed, and the host still sees
    // a speed rather than a missing value.
    server.metadata("No progress", "An artist");
    match next_event(&mut events).await {
        Event::Track {
            playback_speed,
            progress_ms,
            ..
        } => {
            assert_eq!(playback_speed, NORMAL_PLAYBACK_SPEED);
            assert_eq!(progress_ms, None);
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

#[tokio::test]
async fn an_unknown_binary_message_id_is_ignored() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // Message id 77 belongs to a role this revision does not implement. The body is arbitrary
    // bytes; only the id decides that it is not for this client.
    server.binary(vec![77, 0xff, 0x00, 0x42]);
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("an unknown binary id must not close the connection, got {other:?}"),
    }
}

#[tokio::test]
async fn cleartext_text_after_the_handshake_is_a_protocol_error() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.text(r#"{"type":"server/state","payload":{}}"#);
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("cleartext text"),
            "the reason must name the unencrypted frame, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }
    assert_still_reconnecting(handle).await;
}

#[tokio::test]
async fn the_burst_deadline_starts_the_next_burst_after_eight_unanswered_requests() {
    // The server records every clock request and answers none. The client sends one at a time,
    // moving on after the per-reply timeout, until the overall burst deadline ends the burst and
    // the next one starts. Nine requests prove the deadline path ran.
    let options = ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let mut requests = Vec::new();
    for _ in 0..8 {
        let request = tokio::time::timeout(Duration::from_secs(3), server.next_time_request())
            .await
            .expect("the client must keep the burst going")
            .expect("the connection must stay open");
        requests.push(request);
    }
    let started = Instant::now();
    let ninth = tokio::time::timeout(Duration::from_secs(3), server.next_time_request())
        .await
        .expect("the burst deadline must start the next burst")
        .expect("the connection must stay open");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the next burst must follow the deadline, not another full delay"
    );
    assert!(
        !requests.contains(&ninth),
        "the request timestamp must change between bursts"
    );
}

#[tokio::test]
async fn a_message_for_another_direction_is_ignored() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // `server/hello` travels only during the handshake; after it the client has no action for it.
    server.json(r#"{"type":"server/hello","payload":{"name":"Again"}}"#);
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("a message for another direction must be ignored, got {other:?}"),
    }
}

#[tokio::test]
async fn readding_the_player_role_before_the_clock_is_ready_starts_a_burst() {
    let options = ServerOptions {
        active_roles: vec!["metadata@v1".to_owned()],
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // No player role was active, so no clock burst ran. Adding it has to start one, and the state
    // report follows the first sample.
    server.activate(&["player@v1", "metadata@v1"]);
    let state = wait_for_client_state(&mut server).await;
    assert_eq!(
        state
            .player
            .expect("the re-added role reports a player object")
            .volume,
        Some(100)
    );
}

#[tokio::test]
async fn a_stream_announcement_for_an_inactive_player_is_ignored() {
    let options = ServerOptions {
        active_roles: vec!["metadata@v1".to_owned()],
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("a stream for an inactive role must be ignored, got {other:?}"),
    }
    assert!(
        recordings.opened().is_empty(),
        "the sink must not open for an inactive player role"
    );
}

#[tokio::test]
async fn a_stream_announcement_without_a_player_object_is_ignored() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(r#"{"type":"stream/start","payload":{"server_transmitted":0}}"#);
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("a stream without a player object must be ignored, got {other:?}"),
    }
    assert!(
        recordings.opened().is_empty(),
        "no format was announced, so the sink must stay closed"
    );
}

#[tokio::test]
async fn a_past_timestamp_is_played_immediately_once_the_clock_is_ready() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // The initial bursts make the clock ready; the state report follows the first of them, so the
    // replies are counted to be sure the estimate exists before the chunk is judged.
    wait_for_client_state(&mut server).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_time_replies(24))
            .await
            .expect("the fake server must answer the initial bursts")
    );

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    server.audio(now_us() - 5_000_000, 0, vec![0x99; 32]);

    let written = wait_for_writes(&recordings, 1).await;
    assert!(
        written[0].due <= Instant::now(),
        "a deadline in the past must be reported as now, not scheduled later"
    );
}

#[tokio::test]
async fn metadata_is_ignored_when_its_role_is_inactive() {
    let options = ServerOptions {
        active_roles: vec!["player@v1".to_owned(), "controller@v1".to_owned()],
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(
        serde_json::to_string(&Incoming::ServerState(ServerState {
            metadata: Some(syncspin_core::messages::Metadata {
                title: Some("Not for this client".to_owned()),
                ..Default::default()
            }),
            controller: Some(ControllerState {
                supported_commands: vec!["play".to_owned()],
                volume: Some(20),
                muted: Some(false),
                repeat: None,
                shuffle: None,
            }),
        }))
        .unwrap(),
    );

    // The metadata object is dropped; the controller object in the same message still arrives.
    match next_event(&mut events).await {
        Event::State(state) => assert_eq!(state.volume, Some(20)),
        other => panic!("expected State without a Track, got {other:?}"),
    }
}

#[tokio::test]
async fn controller_state_is_ignored_when_its_role_is_inactive() {
    let options = ServerOptions {
        active_roles: vec!["player@v1".to_owned(), "metadata@v1".to_owned()],
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(
        serde_json::to_string(&Incoming::ServerState(ServerState {
            metadata: None,
            controller: Some(ControllerState {
                supported_commands: vec!["play".to_owned()],
                volume: Some(20),
                muted: Some(false),
                repeat: None,
                shuffle: None,
            }),
        }))
        .unwrap(),
    );
    server.metadata("After the controller state", "An artist");

    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "After the controller state"),
        other => panic!("expected Track without a State, got {other:?}"),
    }
}

#[tokio::test]
async fn a_player_command_is_ignored_when_the_player_role_is_inactive() {
    let options = ServerOptions {
        active_roles: vec!["metadata@v1".to_owned()],
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(
        serde_json::to_string(&Incoming::ServerCommand(ServerCommand {
            player: Some(PlayerCommand {
                command: "volume".to_owned(),
                volume: Some(10),
                mute: None,
                output_delay_ms: None,
            }),
        }))
        .unwrap(),
    );
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("a command for an inactive role must be ignored, got {other:?}"),
    }
}

#[tokio::test]
async fn malformed_player_commands_are_ignored() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // A command without a player object, a volume and a mute command without their value, and a
    // command this client does not advertise: each is dropped without a state report or an event.
    for body in [
        r#"{"type":"server/command","payload":{}}"#,
        r#"{"type":"server/command","payload":{"player":{"command":"volume"}}}"#,
        r#"{"type":"server/command","payload":{"player":{"command":"mute"}}}"#,
        r#"{"type":"server/command","payload":{"player":{"command":"set_output_delay","output_delay_ms":250}}}"#,
    ] {
        server.json(body);
        server.metadata("Still here", "An artist");
        match next_event(&mut events).await {
            Event::Track { title, .. } => assert_eq!(title, "Still here"),
            other => panic!("{body} must be ignored, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn reporting_a_level_without_the_player_role_is_refused() {
    let options = ServerOptions {
        active_roles: vec!["metadata@v1".to_owned()],
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    let error = control
        .report_volume(70)
        .await
        .expect_err("a report needs the player role");
    assert!(
        format!("{error:#}").contains("player@v1"),
        "the error must name the missing role, got: {error:#}"
    );
    assert_eq!(control.volume(), 100, "a refused report changes nothing");

    // The refusal belongs to the call: the connection is still usable.
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("expected Track, got {other:?}"),
    }
}

#[tokio::test]
async fn a_flush_failure_at_stream_end_ends_the_session() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let recordings = Recordings::default();
    let sink = Box::new(RecordingSink::failing_flush_on(recordings, 2));
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    server.stream_end();

    match next_event(&mut events).await {
        Event::StreamEnd { .. } => {}
        other => panic!("the end is reported before the flush, got {other:?}"),
    }
    match next_event(&mut events).await {
        Event::Disconnected { reason, retry_in } => {
            assert!(
                reason.contains("rejected a flush"),
                "the reason must name the failed flush, got: {reason}"
            );
            assert_eq!(
                retry_in,
                Duration::ZERO,
                "a broken sink is not retried, so no delay is recommended"
            );
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
}

#[tokio::test]
async fn a_sink_that_rejects_the_format_ends_the_session() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let recordings = Recordings::default();
    let sink = Box::new(RecordingSink::failing_open(recordings.clone()));
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("flac", 48_000, 2, 16);
    match next_event(&mut events).await {
        Event::Disconnected { reason, retry_in } => {
            assert!(
                reason.contains("rejected the stream format"),
                "the reason must name the rejected format, got: {reason}"
            );
            assert_eq!(retry_in, Duration::ZERO);
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
    assert!(
        recordings.opened().is_empty(),
        "a rejected format must not be recorded as opened"
    );
    let outcome = tokio::time::timeout(Duration::from_secs(5), handle.finished())
        .await
        .expect("the session must not hang after a sink error");
    assert!(outcome.is_err());
}

#[tokio::test]
async fn a_flush_failure_after_the_session_ends_the_connection() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let recordings = Recordings::default();
    let sink = Box::new(RecordingSink::failing_flush_on(recordings, 1));
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.close();
    loop {
        match next_event(&mut events).await {
            Event::Disconnected { reason, retry_in } => {
                assert_eq!(reason, "the server closed the connection");
                assert_eq!(
                    retry_in,
                    Duration::ZERO,
                    "a flush that failed after the session is fatal, so no retry follows"
                );
                break;
            }
            _ => continue,
        }
    }
    let outcome = tokio::time::timeout(Duration::from_secs(5), handle.finished())
        .await
        .expect("the session must not hang after a sink error");
    let error = outcome.expect_err("a failed post-session flush ends the connection");
    assert!(
        format!("{error:#}").contains("after the connection ended"),
        "the error must name the post-session flush, got: {error:#}"
    );
}

#[tokio::test]
async fn an_activation_that_changes_no_role_leaves_the_stream_alone() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;
    wait_for_client_state(&mut server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    let flushes = recordings.flushes();

    // The same role set again is neither a removal nor a re-add: no stream end, no second state.
    server.activate(&["player@v1", "controller@v1", "metadata@v1"]);
    server.audio(now_us(), 0, vec![0x7a; 32]);
    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(written[0].frame, Written::Pcm(vec![0x7a; 32]));
    assert_eq!(
        recordings.flushes(),
        flushes,
        "an activation that changes nothing must not flush the stream"
    );
}

#[tokio::test]
async fn websocket_control_frames_are_handled_without_reaching_the_session() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.ping(vec![1, 2, 3]);
    server.pong(vec![4, 5, 6]);
    server.metadata("After the control frames", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "After the control frames"),
        other => panic!("control frames must not become events, got {other:?}"),
    }
    assert_eq!(handle.control().volume(), 100);
}

#[tokio::test]
async fn a_control_handle_after_the_connection_ended_is_an_error() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let recordings = Recordings::default();
    let sink = Box::new(RecordingSink::failing_on(recordings, 1));
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    server.audio(now_us(), 0, vec![0x5b; 32]);

    loop {
        if let Event::Disconnected { .. } = next_event(&mut events).await {
            break;
        }
    }
    let outcome = handle.finished().await;
    assert!(outcome.is_err(), "the sink failure ends the task");

    // The task is gone, so the command channel has no receiver. This is a different failure from
    // a request made while the task is alive but between attempts.
    let error = control
        .set_volume(50)
        .await
        .expect_err("a connection that ended cannot carry a request");
    assert!(
        format!("{error:#}").contains("the connection has ended"),
        "the error must say the connection is gone, got: {error:#}"
    );
    assert_eq!(
        control.volume(),
        100,
        "the level in force is still readable"
    );
}

/// Dropping the event stream ends a live session cleanly, and promptly enough to be usable.
///
/// The session notices a dropped stream at the top of its loop, so the test sends one message to
/// wake it: a host that stops listening stops the connection rather than leaving it running with
/// nowhere to report to.
#[tokio::test]
async fn dropping_the_event_stream_ends_a_live_session() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    drop(events);
    server.metadata("Wake up", "An artist");

    let outcome = tokio::time::timeout(Duration::from_secs(5), handle.finished())
        .await
        .expect("a dropped event stream must end the connection");
    outcome.expect("a host that stopped listening is not an error");
}
