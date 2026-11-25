//! End-to-end tests of the session against the hermetic fake server.
//!
//! Every test binds one loopback port, runs the Noise initiator with `snow` on the server side and
//! records the frames a [`Sink`] receives. No test touches an audio device or another host.

#![cfg(all(feature = "player", feature = "controller", feature = "metadata"))]

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
    EventStream, PlaybackState, PskCategory, Sink, StoredPsk, StreamEndReason, VolumePolicy,
    DEFAULT_PAIRING_TIMEOUT, NORMAL_PLAYBACK_SPEED,
};
use syncspin_core::messages::{
    ClientState, ControllerCommand, ControllerState, GroupUpdate, Incoming, PairingActivation,
    PlayerCommand, Progress, ServerActivate, ServerCommand, ServerState,
};
use syncspin_core::noise::{psk_id_for, Identity, SENTINEL_PSK};

use fake_server::{FakeServer, Observation, ServerOptions};

/// One frame the recording sink received.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Written {
    Pcm(Vec<u8>),
    Encoded(Codec, Vec<u8>),
}

/// A received frame with its playout deadline and the instant the sink was called.
#[derive(Debug, Clone)]
struct WrittenFrame {
    frame: Written,
    due: Instant,
    written: Instant,
}

/// The timing a [`RecordingSink`] reports, shared so a test can change it while the session runs.
#[derive(Debug, Clone, Copy)]
struct ReportedTiming {
    output_delay: Option<Duration>,
    pre_port_delay: Duration,
}

impl Default for ReportedTiming {
    fn default() -> Self {
        Self {
            output_delay: None,
            pre_port_delay: Duration::ZERO,
        }
    }
}

/// Shared handle to a [`RecordingSink`]'s reported timing.
type TimingHandle = Arc<Mutex<ReportedTiming>>;

/// Creates a timing handle a test can keep to change the values later.
fn timing_handle(output_delay: Option<Duration>, pre_port_delay: Duration) -> TimingHandle {
    Arc::new(Mutex::new(ReportedTiming {
        output_delay,
        pre_port_delay,
    }))
}

/// What the sink recorded, shared with the test that owns the assertion.
#[derive(Clone, Default)]
struct Recordings {
    opened: Arc<Mutex<Vec<AudioFormat>>>,
    written: Arc<Mutex<Vec<WrittenFrame>>>,
    flushes: Arc<Mutex<usize>>,
    discards: Arc<Mutex<Vec<Instant>>>,
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

    /// The deadlines of every `discard_from`, in call order.
    fn discards(&self) -> Vec<Instant> {
        self.discards
            .lock()
            .expect("the recordings lock is not poisoned")
            .clone()
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

/// A gate that holds one sink write until the test releases it.
///
/// It has the same release/wait shape as [`FlushGate`]: the session is blocked inside `write`, so
/// a test on another worker proves that the drain only continues once it is released.
#[derive(Clone, Default)]
struct WriteGate {
    release: Arc<AtomicBool>,
}

impl WriteGate {
    /// Lets the held write return.
    fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
    }

    /// Spins until the test released the gate, or the bound expires.
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
    fail_on_discard: Option<usize>,
    fail_on_open: bool,
    timing: TimingHandle,
    writes: usize,
    discards: usize,
    /// Flush call that holds the session until the gate is released.
    hold_flush: Option<usize>,
    /// Write call that holds the session until the gate is released.
    hold_write: Option<usize>,
    gate: Option<FlushGate>,
    write_gate: Option<WriteGate>,
}

impl RecordingSink {
    fn new(recordings: Recordings) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_discard: None,
            fail_on_open: false,
            timing: timing_handle(None, Duration::ZERO),
            writes: 0,
            discards: 0,
            hold_flush: None,
            hold_write: None,
            gate: None,
            write_gate: None,
        }
    }

    fn failing_on(recordings: Recordings, write: usize) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: Some(write),
            fail_on_flush: None,
            fail_on_discard: None,
            fail_on_open: false,
            timing: timing_handle(None, Duration::ZERO),
            writes: 0,
            discards: 0,
            hold_flush: None,
            hold_write: None,
            gate: None,
            write_gate: None,
        }
    }

    /// Creates a sink that fails the `flush`th flush, counting from one.
    fn failing_flush_on(recordings: Recordings, flush: usize) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: Some(flush),
            fail_on_discard: None,
            fail_on_open: false,
            timing: timing_handle(None, Duration::ZERO),
            writes: 0,
            discards: 0,
            hold_flush: None,
            hold_write: None,
            gate: None,
            write_gate: None,
        }
    }

    /// Creates a sink that rejects every stream format.
    fn failing_open(recordings: Recordings) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_discard: None,
            fail_on_open: true,
            timing: timing_handle(None, Duration::ZERO),
            writes: 0,
            discards: 0,
            hold_flush: None,
            hold_write: None,
            gate: None,
            write_gate: None,
        }
    }

    fn with_output_delay(recordings: Recordings, output_delay: Duration) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_discard: None,
            fail_on_open: false,
            timing: timing_handle(Some(output_delay), Duration::ZERO),
            writes: 0,
            discards: 0,
            hold_flush: None,
            hold_write: None,
            gate: None,
            write_gate: None,
        }
    }

    fn with_timing(recordings: Recordings, timing: TimingHandle) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_discard: None,
            fail_on_open: false,
            timing,
            writes: 0,
            discards: 0,
            hold_flush: None,
            hold_write: None,
            gate: None,
            write_gate: None,
        }
    }

    fn gated(recordings: Recordings, gate: FlushGate, hold_flush: usize) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_discard: None,
            fail_on_open: false,
            timing: timing_handle(None, Duration::ZERO),
            writes: 0,
            discards: 0,
            hold_flush: Some(hold_flush),
            hold_write: None,
            gate: Some(gate),
            write_gate: None,
        }
    }

    /// Creates a sink that holds the `hold_write`th write until the gate is released.
    fn write_gated(recordings: Recordings, gate: WriteGate, hold_write: usize) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_discard: None,
            fail_on_open: false,
            timing: timing_handle(None, Duration::ZERO),
            writes: 0,
            discards: 0,
            hold_flush: None,
            hold_write: Some(hold_write),
            gate: None,
            write_gate: Some(gate),
        }
    }

    /// Creates a sink that fails the `discard`th `discard_from`, counting from one.
    fn failing_discard_on(recordings: Recordings, discard: usize) -> RecordingSink {
        RecordingSink {
            recordings,
            fail_on_write: None,
            fail_on_flush: None,
            fail_on_discard: Some(discard),
            fail_on_open: false,
            timing: timing_handle(None, Duration::ZERO),
            writes: 0,
            discards: 0,
            hold_flush: None,
            hold_write: None,
            gate: None,
            write_gate: None,
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
        let written = Instant::now();
        let frame = match frame {
            AudioFrame::Pcm(data) => Written::Pcm(data.to_vec()),
            AudioFrame::Encoded { codec, data } => Written::Encoded(codec.clone(), data.to_vec()),
        };
        self.recordings
            .written
            .lock()
            .expect("the recordings lock is not poisoned")
            .push(WrittenFrame {
                frame,
                due,
                written,
            });
        // Recorded before the hold so the test can see the in-flight write on its own worker.
        if self.hold_write == Some(self.writes) {
            if let Some(gate) = &self.write_gate {
                gate.wait();
            }
        }
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

    fn discard_from(&mut self, due: Instant) -> Result<()> {
        self.discards += 1;
        if self.fail_on_discard == Some(self.discards) {
            bail!(
                "the recording sink was told to fail on discard {}",
                self.discards
            );
        }
        self.recordings
            .discards
            .lock()
            .expect("the recordings lock is not poisoned")
            .push(due);
        Ok(())
    }

    fn output_delay(&self) -> Option<Duration> {
        self.timing
            .lock()
            .expect("the timing lock is not poisoned")
            .output_delay
    }

    fn pre_port_delay(&self) -> Duration {
        self.timing
            .lock()
            .expect("the timing lock is not poisoned")
            .pre_port_delay
    }
}

/// Creates a recording sink and the shared record it writes to.
fn recording_sink() -> (Recordings, Box<dyn Sink>) {
    let recordings = Recordings::default();
    (recordings.clone(), Box::new(RecordingSink::new(recordings)))
}

/// Creates a recording sink that reports a fixed output delay.
fn sink_with_output_delay(output_delay: Duration) -> (Recordings, Box<dyn Sink>) {
    let recordings = Recordings::default();
    (
        recordings.clone(),
        Box::new(RecordingSink::with_output_delay(recordings, output_delay)),
    )
}

/// Creates a recording sink whose reported timing the test can change while the session runs.
fn sink_with_timing(
    output_delay: Option<Duration>,
    pre_port_delay: Duration,
) -> (Recordings, TimingHandle, Box<dyn Sink>) {
    let recordings = Recordings::default();
    let timing = timing_handle(output_delay, pre_port_delay);
    (
        recordings.clone(),
        timing.clone(),
        Box::new(RecordingSink::with_timing(recordings, timing)),
    )
}

/// Asserts that `actual` lies within `tolerance` of `expected`.
fn assert_near(actual: Instant, expected: Instant, tolerance: Duration, what: &str) {
    let earliest = expected
        .checked_sub(tolerance)
        .expect("the tolerance must stay inside the instant range");
    let latest = expected
        .checked_add(tolerance)
        .expect("the tolerance must stay inside the instant range");
    assert!(
        actual >= earliest && actual <= latest,
        "{what}: {actual:?} is not within {tolerance:?} of {expected:?}"
    );
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

/// Creates a recording sink that holds the `hold_write`th write until the gate is released.
fn write_gated_sink(hold_write: usize) -> (Recordings, WriteGate, Box<dyn Sink>) {
    let recordings = Recordings::default();
    let gate = WriteGate::default();
    let sink = Box::new(RecordingSink::write_gated(
        recordings.clone(),
        gate.clone(),
        hold_write,
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
        strict_group_id: false,
        output_delay_control: false,
        unpaired_access: true,
        required_lead_time_ms: 250,
        min_buffer_ms: None,
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

/// Waits until every message sent before it was handled, by round-tripping a track event.
///
/// A batch of audio may produce `LateAudio` reports; those are skipped. The marker travels on the
/// same socket after the batch, so its event proves the client finished with the audio.
async fn wait_for_processed(server: &FakeServer, events: &mut EventStream) {
    server.metadata("processed", "processed");
    loop {
        match next_event(events).await {
            Event::LateAudio { .. } => continue,
            Event::Track { title, .. } => {
                assert_eq!(title, "processed", "the marker must be the batch's barrier");
                return;
            }
            other => panic!("expected the processing marker, got {other:?}"),
        }
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

/// Waits until the sink recorded `count` discards and returns their deadlines.
async fn wait_for_discards(recordings: &Recordings, count: usize) -> Vec<Instant> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let discards = recordings.discards();
        if discards.len() >= count {
            return discards;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {count} sink discards, saw {}",
            discards.len()
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

/// Answers clock bursts until the client stops asking, so the estimate is ready before audio.
///
/// The filter keeps the best sample of a burst, so becoming ready takes three bursts. The fake
/// server otherwise answers within the same microsecond, and the filter rejects a sample that does
/// not advance its local receive time, so every reply is spaced. The client keeps bursting while
/// its estimate is not ready; the loop therefore ends when no new request arrives.
async fn establish_clock(server: &mut FakeServer) {
    for _ in 0..40 {
        let Ok(Some(request)) =
            tokio::time::timeout(Duration::from_millis(100), server.next_time_request()).await
        else {
            return;
        };
        tokio::time::sleep(Duration::from_millis(2)).await;
        server.answer_time(request);
    }
}

/// Answers clock requests only when the test asks for them.
///
/// A server started with `manual_time` records every `client/time` without answering it, so the
/// estimate stays unavailable until this runs. That is how a test lets the session start without a
/// clock and then form one mid-stream, with real round trips instead of a faked estimate. The loop
/// ends once no request arrives for longer than half a second: while the clock is not ready the
/// client starts the next burst immediately, so only a usable estimate leaves such a gap. Replies
/// are spaced like [`establish_clock`] because the filter rejects a sample that does not advance
/// its local receive time.
async fn answer_clock_requests(server: &mut FakeServer) {
    for _ in 0..60 {
        let Ok(Some(request)) =
            tokio::time::timeout(Duration::from_millis(500), server.next_time_request()).await
        else {
            return;
        };
        tokio::time::sleep(Duration::from_millis(2)).await;
        server.answer_time(request);
    }
}

/// The wire form of a `server/state` that changes nothing: no metadata, no controller state.
///
/// A flood of these keeps the socket delivering without touching the playout queue or the event
/// stream, which is what the starvation row needs: only the socket read is kept busy.
fn inert_state() -> String {
    serde_json::to_string(&Incoming::ServerState(ServerState {
        metadata: None,
        controller: None,
        ..Default::default()
    }))
    .expect("an empty server/state encodes")
}

/// Builds the `server/state` that advertises the controller commands and range the server offers.
fn controller_state(commands: &[&str], seek_max_ms: Option<u64>) -> String {
    serde_json::to_string(&Incoming::ServerState(ServerState {
        metadata: None,
        controller: Some(ControllerState {
            supported_commands: commands
                .iter()
                .map(|command| (*command).to_owned())
                .collect(),
            volume: Some(100),
            muted: Some(false),
            repeat: None,
            shuffle: None,
            seek_max_ms,
        }),
        ..Default::default()
    }))
    .expect("the state must encode")
}

/// Waits for the next client command and returns its controller object.
async fn next_controller_command(server: &mut FakeServer) -> ControllerCommand {
    let command = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_command())
        .await
        .expect("the client must send a command")
        .expect("the connection must not close before the command");
    command
        .controller
        .expect("a controller command carries a controller object")
}

/// Consumes the [`Event::State`] a `server/state` produces.
///
/// The control request reaches the session loop through a channel while the state travels through
/// the socket, so a test that calls `control()` before the event arrived can still see the range
/// the previous state left behind.
async fn expect_controller_state(stream: &mut EventStream) -> PlaybackState {
    match next_event(stream).await {
        Event::State(state) => state,
        other => panic!("expected State, got {other:?}"),
    }
}

/// Asserts that the client sends no client command within the bound.
async fn assert_no_client_command(server: &mut FakeServer) {
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server.wait_for_client_command())
            .await
            .is_err(),
        "a refused command must not be sent"
    );
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
async fn frames_are_written_near_their_deadline() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    let started = Instant::now();
    server.audio(now_us() + 100_000, 250_000, vec![0x11; 4]);

    let written = wait_for_writes(&recordings, 1).await;
    let frame = &written[0];
    assert_near(
        frame.written,
        frame.due,
        Duration::from_millis(150),
        "the write happens at the frame's deadline",
    );
    assert!(
        frame.written >= started + Duration::from_millis(50),
        "a frame 100 ms in the future must not be written on arrival"
    );
    assert!(
        frame.due >= started + Duration::from_millis(50),
        "the deadline must be in the future, not clamped to the arrival"
    );
}

#[tokio::test]
async fn a_zero_pre_port_delay_keeps_arrival_timing() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, _timing, sink) = sink_with_timing(None, Duration::ZERO);
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    let started = Instant::now();
    // A timestamp just inside the 10 ms lateness tolerance: its deadline has passed, so the frame
    // keeps the arrival timing and is written at once.
    server.audio(now_us() - 5_000, 250_000, vec![0x22; 4]);

    let written = wait_for_writes(&recordings, 1).await;
    let frame = &written[0];
    assert!(
        frame.written <= started + Duration::from_millis(150),
        "a frame whose deadline passed is written immediately, saw {:?}",
        frame.written - started
    );
    assert!(
        frame.due <= started,
        "the deadline is the already-passed one, not a future instant"
    );
}

#[tokio::test]
async fn a_two_hundred_ms_pre_port_delay_writes_early() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, _timing, sink) = sink_with_timing(None, Duration::from_millis(200));
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    let started = Instant::now();
    server.audio(now_us() + 800_000, 1_000_000, vec![0x33; 4]);

    let written = wait_for_writes(&recordings, 1).await;
    let frame = &written[0];
    let early = frame
        .due
        .checked_sub(Duration::from_millis(200))
        .expect("the deadline is later than the pre-port delay");
    assert_near(
        frame.written,
        early,
        Duration::from_millis(300),
        "the write happens one pre-port delay before the deadline",
    );
    assert!(
        frame.written >= started + Duration::from_millis(300),
        "a 200 ms pre-port on an 800 ms deadline must not write on arrival"
    );
    // The wide window above reaches `due + 100 ms`, which a scheduler ignoring the pre-port delay
    // would also satisfy. The write must land at least 100 ms before the port deadline.
    let latest_early = frame
        .due
        .checked_sub(Duration::from_millis(100))
        .expect("the deadline is later than 100 ms");
    assert!(
        frame.written <= latest_early,
        "a 200 ms pre-port delay must write at least 100 ms before the deadline, wrote {:?} before it",
        frame.due - frame.written
    );
}

#[tokio::test]
async fn a_late_frame_is_dropped_and_reported() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // A second in the past is well beyond the 10 ms tolerance: the frame is dropped, never written.
    server.audio(now_us() - 1_000_000, 250_000, vec![0x44; 4]);

    match next_event(&mut events).await {
        Event::LateAudio { late_by, dropped } => {
            assert_eq!(dropped, 1, "one late frame is dropped");
            assert!(
                late_by >= Duration::from_millis(900),
                "the report carries how late the frame was, saw {late_by:?}"
            );
        }
        other => panic!("expected LateAudio, got {other:?}"),
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        recordings.written().is_empty(),
        "a frame beyond the tolerance must not reach the sink"
    );
}

#[tokio::test]
async fn the_late_window_tail_is_reported_after_the_interval() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // Four frames a second in the past arrive back to back. The first drop reports at once; the
    // other three wait in the window because the interval has not elapsed.
    for _ in 0..4 {
        server.audio(now_us() - 1_000_000, 250_000, vec![0x33; 4]);
    }

    match next_event(&mut events).await {
        Event::LateAudio { late_by, dropped } => {
            assert_eq!(dropped, 1, "the first drop is reported immediately");
            assert!(
                late_by >= Duration::from_millis(900),
                "the report carries the worst lateness, saw {late_by:?}"
            );
        }
        other => panic!("expected LateAudio, got {other:?}"),
    }

    // No further audio: the interval still elapses and the tail follows as one report.
    match next_event_within(&mut events, Duration::from_secs(3)).await {
        Event::LateAudio { late_by, dropped } => {
            assert_eq!(dropped, 3, "the window tail is flushed as one report");
            assert!(
                late_by >= Duration::from_millis(900),
                "the flushed report keeps the worst lateness, saw {late_by:?}"
            );
        }
        other => panic!("expected the flushed LateAudio, got {other:?}"),
    }
    assert!(
        recordings.written().is_empty(),
        "late frames must not reach the sink"
    );
}

#[tokio::test]
async fn late_reports_are_spaced_by_the_interval() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // One late frame every 100 ms for 2.5 s. The first reports at once; later drops accumulate
    // until the interval has elapsed, so the reports that arrive are about a second apart.
    let mut observed = Vec::new();
    let mut next_send = Instant::now();
    for _ in 0..26 {
        tokio::time::sleep_until(next_send.into()).await;
        next_send += Duration::from_millis(100);
        server.audio(now_us() - 1_000_000, 250_000, vec![0x44; 4]);
        loop {
            let remaining = next_send.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, events.next()).await {
                Ok(Some(Event::LateAudio { dropped, .. })) => {
                    observed.push((Instant::now(), dropped));
                }
                Ok(Some(other)) => panic!("expected LateAudio, got {other:?}"),
                Ok(None) => panic!("the event stream ended"),
                Err(_) => break,
            }
        }
    }

    assert!(
        observed.len() >= 2,
        "2.5 s of drops must produce more than one report, saw {observed:?}"
    );
    for pair in observed.windows(2) {
        let gap = pair[1].0.duration_since(pair[0].0);
        assert!(
            gap >= Duration::from_millis(900),
            "reports must be at least 900 ms apart, saw {gap:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_that_became_late_during_a_blocking_write_is_dropped() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, gate, sink) = write_gated_sink(1);
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // Two frames from one server timestamp: the drain pops both. The local deadlines differ by
    // sub-microsecond mapping jitter, so the queue order is not the send order; whichever frame is
    // written first is held in the sink, and the other is the one that becomes late.
    let timestamp = now_us() + 500_000;
    server.audio(timestamp, 1_000_000, vec![0xa1; 4]);
    server.audio(timestamp, 1_000_000, vec![0xa2; 4]);

    // The held write occupies a worker, and the sink records the frame before it spins. Poll with
    // an OS sleep: a tokio timer could be owned by the blocked worker and stall past the gate's
    // bound, which would release the write before the test saw it.
    let deadline = Instant::now() + Duration::from_secs(5);
    while recordings.written().is_empty() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the held write"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let written = recordings.written();
    assert_eq!(
        written.len(),
        1,
        "only the first frame reached the sink so far"
    );
    let released_at = written[0].due + Duration::from_millis(50);
    std::thread::sleep(released_at.saturating_duration_since(Instant::now()));
    gate.release();

    match next_event(&mut events).await {
        Event::LateAudio { late_by, dropped } => {
            assert_eq!(dropped, 1, "only the frame that became late is dropped");
            assert!(
                late_by >= Duration::from_millis(10),
                "the drop happened during the blocking write, saw {late_by:?}"
            );
        }
        other => panic!("expected LateAudio, got {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    let written = recordings.written();
    assert_eq!(
        written.len(),
        1,
        "the frame that became late during the write must not reach the sink"
    );
    match &written[0].frame {
        Written::Pcm(data) => assert!(
            data == &vec![0xa1; 4] || data == &vec![0xa2; 4],
            "the one written frame is one of the two sent payloads, got {data:?}"
        ),
        other => panic!("expected PCM, got {other:?}"),
    }
}

#[tokio::test]
async fn output_delay_is_subtracted_from_the_deadline() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = sink_with_output_delay(Duration::from_millis(100));
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    let started = Instant::now();
    server.audio(now_us() + 400_000, 1_000_000, vec![0x55; 4]);

    let written = wait_for_writes(&recordings, 1).await;
    let frame = &written[0];
    assert_near(
        frame.due,
        started + Duration::from_millis(300),
        Duration::from_millis(100),
        "the 100 ms post-port delay moves the deadline 100 ms earlier",
    );
    // The ±100 ms window puts an unsubtracted deadline (started + 400 ms) on its inclusive upper
    // bound, so the shift needs a one-sided bound with margin of its own.
    assert!(
        frame.due < started + Duration::from_millis(350),
        "an unsubtracted deadline would sit at +400 ms; the post-port delay must move it earlier, \
         got {:?}",
        frame.due - started
    );
    assert_near(
        frame.written,
        frame.due,
        Duration::from_millis(150),
        "the frame is written at the shifted deadline",
    );
}

#[tokio::test]
async fn a_change_of_output_delay_remaps_and_reports_state() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, timing, sink) = sink_with_timing(None, Duration::ZERO);
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    let started = Instant::now();
    // The metadata message follows the chunk on the same socket, so the frame is queued by the
    // time its event arrives.
    server.audio(now_us() + 1_500_000, 2_000_000, vec![0x66; 4]);
    server.metadata("queued", "queued");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "queued"),
        other => panic!("expected Track, got {other:?}"),
    }
    assert!(
        recordings.written().is_empty(),
        "a frame 1.5 s out is queued, not written"
    );

    // The host raises the reported post-port delay; the volume command makes the session report
    // its state, which is one of the points where the timing is polled.
    timing
        .lock()
        .expect("the timing lock is not poisoned")
        .output_delay = Some(Duration::from_millis(500));
    handle
        .control()
        .set_volume(50)
        .await
        .expect("the client must report the new level");

    // States sent before the change may still be queued; the change is the one carrying 500.
    loop {
        let player = wait_for_client_state(&mut server)
            .await
            .player
            .expect("the player state follows the role");
        if player.output_delay_ms == 500 {
            break;
        }
    }

    let written = wait_for_writes(&recordings, 1).await;
    let frame = &written[0];
    assert_near(
        frame.due,
        started + Duration::from_millis(1_000),
        Duration::from_millis(100),
        "the queued deadline is remapped 500 ms earlier",
    );
    assert_near(
        frame.written,
        frame.due,
        Duration::from_millis(150),
        "the remapped frame is written at its new deadline",
    );
}

#[tokio::test]
async fn the_reported_lead_covers_the_pre_port_delay() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, _timing, sink) = sink_with_timing(None, Duration::from_millis(250));
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.required_lead_time_ms = 100;
    let (_handle, _events) = connect(config, sink)
        .await
        .expect("the client must connect to the fake server");

    let player = wait_for_client_state(&mut server)
        .await
        .player
        .expect("the first state carries the player object");
    assert_eq!(
        player.required_lead_time_ms, 250,
        "the pre-port delay is a floor for the reported lead"
    );
}

#[tokio::test]
async fn a_lowered_pre_port_delay_reports_the_lead_again() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, timing, sink) = sink_with_timing(None, Duration::from_millis(250));
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.required_lead_time_ms = 100;
    let (_handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    let player = wait_for_client_state(&mut server)
        .await
        .player
        .expect("the first state carries the player object");
    assert_eq!(
        player.required_lead_time_ms, 250,
        "the pre-port delay is a floor for the reported lead"
    );

    // A lower pre-port delay lowers the reported lead. The stream start's poll is one of the three
    // points that must notice it; the state that follows carries the configured floor again.
    timing
        .lock()
        .expect("the timing lock is not poisoned")
        .pre_port_delay = Duration::from_millis(50);
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    loop {
        let player = wait_for_client_state(&mut server)
            .await
            .player
            .expect("the state carries the player object");
        if player.required_lead_time_ms == 100 {
            break;
        }
    }
}

#[tokio::test]
async fn flush_and_a_timestamped_clear_keep_the_prefix() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // Three future frames; the cut is the second frame's own server timestamp.
    let base = now_us();
    let first = base + 400_000;
    let cut = base + 700_000;
    let last = base + 1_000_000;
    server.audio(first, 1_500_000, vec![0xa1; 4]);
    server.audio(cut, 1_500_000, vec![0xa2; 4]);
    server.audio(last, 1_500_000, vec![0xa3; 4]);

    let cut_deadline = Instant::now() + Duration::from_millis(700);
    server.stream_clear(Some(cut));

    let discards = wait_for_discards(&recordings, 1).await;
    assert_near(
        discards[0],
        cut_deadline,
        Duration::from_millis(150),
        "the discard carries the mapped cut",
    );

    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(
        written.len(),
        1,
        "only the prefix before the cut survives the clear"
    );
    assert_eq!(
        written[0].frame,
        Written::Pcm(vec![0xa1; 4]),
        "the surviving frame is the one before the cut"
    );

    // A clear without a timestamp flushes: a frame still queued must never reach the sink.
    server.audio(now_us() + 300_000, 1_000_000, vec![0xa4; 4]);
    server.stream_clear(None);
    wait_for_flushes(&recordings, 2).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        recordings.written().len(),
        1,
        "a flush must empty the queue, not only the sink"
    );
}

/// A socket that never goes idle must not keep the scheduler from writing a due frame.
///
/// The session has two doors for that: the playout branch before the socket read under `biased;`
/// and the drain after every socket wake. A frame due while the socket carries a deep backlog must
/// still be written near its deadline; an implementation that only looks at playout once the read
/// is idle would wait for the backlog to drain, which the wall-clock bound does not allow.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_on_the_socket_does_not_starve_playout() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // The one frame due while the socket is fed.
    let started = Instant::now();
    server.audio(now_us() + 400_000, 1_000_000, vec![0xf1; 4]);

    // Fill the channel with messages that change nothing and keep topping it up without sleeping,
    // so the server has a deep backlog and the client's read stays ready while the frame is due.
    // The flood is bounded by a message cap and by a wall clock.
    let flood = inert_state();
    let mut flooded = 0usize;
    let deadline = started + Duration::from_secs(2);
    let mut written = Vec::new();
    while Instant::now() < deadline && flooded < 300_000 {
        for _ in 0..100 {
            server.json(flood.clone());
            flooded += 1;
        }
        tokio::task::yield_now().await;
        written = recordings.written();
        if !written.is_empty() {
            break;
        }
    }
    // The flood may be fully queued long before the deadline; keep watching while it drains.
    while written.is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
        written = recordings.written();
    }

    assert!(flooded >= 10_000, "the socket must actually carry a flood");
    assert_eq!(
        written.len(),
        1,
        "the frame due during the flood must be written exactly once"
    );
    assert_eq!(written[0].frame, Written::Pcm(vec![0xf1; 4]));
    assert_near(
        written[0].written,
        written[0].due,
        Duration::from_millis(300),
        "the frame is written at its deadline while the socket stays busy",
    );
    assert!(
        written[0].written <= started + Duration::from_millis(800),
        "the write must not wait for the flood to drain, saw {:?}",
        written[0].written - started
    );
}

/// An in-place `stream/start` replaces the format of a running stream and must clear its queue.
#[tokio::test]
async fn an_in_place_stream_start_clears_the_queue() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // A frame due after the second announcement; nothing may be written before it arrives.
    server.audio(now_us() + 900_000, 1_500_000, vec![0xa1; 4]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        recordings.written().is_empty(),
        "a future frame must be queued before the in-place announcement"
    );

    server.stream_start("flac", 44_100, 1, 24);
    match next_event(&mut events).await {
        Event::StreamStart { format } => assert_eq!(format.codec, Codec::Flac),
        other => panic!("expected StreamStart, got {other:?}"),
    }
    assert_eq!(
        recordings.opened().len(),
        2,
        "an in-place stream/start opens the format it announces"
    );
    assert_eq!(
        recordings.flushes(),
        2,
        "an in-place stream/start flushes the previous stream"
    );

    // The queued frame's deadline passes while the new format is open.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(
        recordings.written().is_empty(),
        "an in-place stream/start must clear the queue, not only flush the sink"
    );

    // The stream is still live: audio under the new format plays.
    server.audio(now_us() - 1_000, 0, vec![0xa2; 4]);
    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(
        written[0].frame,
        Written::Encoded(Codec::Flac, vec![0xa2; 4]),
        "the in-place stream must keep playing"
    );
}

/// The queue's lifetime is the `Session`, so a key swap must not drop it.
///
/// The activation after the swap is held, so the row proves two things at once: a frame queued
/// before the swap plays while the re-handshake is still in flight, and a frame queued before it
/// with a later deadline still plays after the new keys took over.
#[tokio::test]
async fn a_rehandshake_keeps_the_queue() {
    let pairing_psk = [0x4d; 32];
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        hold_rehandshake_activate: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let stored = StoredPsk {
        category: PskCategory::Pairing,
        psk: pairing_psk,
        server_id: server.server_id().to_owned(),
    };
    let (mut events, handle) = connect_with_stored_psks(
        &server,
        syncspin_client::AudioMode::Passthrough,
        sink,
        vec![stored],
    )
    .await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // One frame due while the swap is held, one due long after it completed.
    server.audio(now_us() + 400_000, 1_000_000, vec![0xc1; 4]);
    server.audio(now_us() + 2_500_000, 3_000_000, vec![0xc2; 4]);

    server.rehandshake(pairing_psk, "pr");
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_rehandshake())
            .await
            .expect("the client must answer the re-handshake"),
        "the re-handshake must complete in the client"
    );

    // The activation is still held: the transport is swapped, but the session may not act on
    // application messages. The playout branch must not be suspended by that window.
    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(
        written[0].frame,
        Written::Pcm(vec![0xc1; 4]),
        "a frame queued before the swap must play during the re-handshake"
    );

    server.release_rehandshake_activate();

    // Audio under the new keys joins the same queue.
    server.audio(now_us() + 400_000, 1_000_000, vec![0xc3; 4]);
    let written = wait_for_writes(&recordings, 3).await;
    let payloads: Vec<Written> = written.iter().map(|frame| frame.frame.clone()).collect();
    assert_eq!(
        payloads,
        vec![
            Written::Pcm(vec![0xc1; 4]),
            Written::Pcm(vec![0xc3; 4]),
            Written::Pcm(vec![0xc2; 4]),
        ],
        "both the frame due during the swap and the one due after it survive"
    );
    assert_eq!(
        recordings.opened().len(),
        1,
        "a key swap must not reopen the stream"
    );
    assert_eq!(
        recordings.flushes(),
        1,
        "a key swap must not drop buffered audio"
    );
    assert_still_reconnecting(handle).await;
}

/// A reconnect starts a new `Session`, and the attempt that ended flushes the sink with it.
#[tokio::test]
async fn a_reconnect_drops_the_queue() {
    let mut server = FakeServer::start(ServerOptions {
        connections: 2,
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // Queue a frame well past the drop; the marker proves the client handled it before the close.
    server.audio(now_us() + 2_000_000, 3_000_000, vec![0xd1; 4]);
    wait_for_processed(&server, &mut events).await;
    assert!(
        recordings.written().is_empty(),
        "the frame must be queued before the drop"
    );

    server.close();
    match next_event(&mut events).await {
        Event::Disconnected { .. } => {}
        other => panic!("expected Disconnected, got {other:?}"),
    }
    // The attempt ends with a flush before the next connection is attempted.
    wait_for_flushes(&recordings, 2).await;

    expect_connected(&mut events, &server).await;

    // No stream was announced on the second connection: waiting past the old deadline proves the
    // queued frame did not outlive the session that queued it.
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    assert!(
        recordings.written().is_empty(),
        "no queued frame may reach the sink after the connection that queued it ended"
    );
    assert_eq!(
        recordings.flushes(),
        2,
        "the reconnect flushes once at the attempt's end, not again on its own"
    );
    assert_eq!(
        recordings.opened().len(),
        1,
        "the second session must not reopen the stream the first one announced"
    );
}

/// Without an estimate the client writes at once; an estimate formed mid-stream starts queueing.
///
/// The server answers no clock request until the test asks: the first frame's far-future stamp is
/// ignored because there is nothing to map it through, and the second one is queued once the
/// answer loop made the estimate usable.
#[tokio::test]
async fn no_clock_writes_immediately_and_ready_starts_queueing() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // No reply has been sent yet, so the estimate is unavailable and the stamp cannot be mapped.
    let sent = Instant::now();
    server.audio(now_us() + 5_000_000, 5_000_000, vec![0xe1; 4]);
    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(written[0].frame, Written::Pcm(vec![0xe1; 4]));
    assert!(
        written[0].due <= sent + Duration::from_secs(1),
        "without an estimate the deadline is the arrival, not the server stamp"
    );
    assert!(
        written[0].written <= sent + Duration::from_secs(1),
        "without an estimate the frame is written at once, saw {:?}",
        written[0].written - sent
    );

    // The session has been asking since it started; answering now forms the estimate mid-stream.
    answer_clock_requests(&mut server).await;

    let started = Instant::now();
    server.audio(now_us() + 2_000_000, 2_000_000, vec![0xe2; 4]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        recordings.written().len(),
        1,
        "once the estimate is ready a future frame is queued, not written on arrival"
    );

    let written = wait_for_writes(&recordings, 2).await;
    assert_eq!(written[1].frame, Written::Pcm(vec![0xe2; 4]));
    assert!(
        written[1].due >= started + Duration::from_millis(1_500),
        "the queued frame's deadline comes from its server stamp, saw {:?}",
        written[1].due - started
    );
    assert!(
        written[1].written >= started + Duration::from_millis(1_500),
        "the queued frame must wait for its deadline, wrote at {:?}",
        written[1].written - started
    );
}

/// A server that never answers a clock request leaves the immediate-write path in force.
#[tokio::test]
async fn a_server_that_never_answers_the_clock_writes_immediately() {
    let server = FakeServer::start(ServerOptions {
        answer_time_limit: Some(0),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    let sent = Instant::now();
    server.audio(now_us() + 5_000_000, 5_000_000, vec![0xe0; 4]);
    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(written[0].frame, Written::Pcm(vec![0xe0; 4]));
    assert!(
        written[0].due <= sent + Duration::from_secs(1),
        "without a single reply the stamp cannot become a deadline"
    );
    assert!(
        written[0].written <= sent + Duration::from_secs(1),
        "without a single reply the frame is written at once"
    );
}

/// Post-seek frames must reach the sink in deadline order, not in arrival order.
#[tokio::test]
async fn a_seek_after_a_timestamped_clear_keeps_order() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));

    // A frame past the cut is queued before the clear; the clear must drop it.
    let cut = now_us();
    server.audio(cut + 800_000, 1_500_000, vec![0xb0; 4]);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        recordings.written().is_empty(),
        "the frame after the cut must be queued before the clear"
    );

    server.stream_clear(Some(cut));
    match next_event(&mut events).await {
        Event::StreamClear { from_timestamp } => assert_eq!(from_timestamp, Some(cut)),
        other => panic!("expected StreamClear, got {other:?}"),
    }
    wait_for_discards(&recordings, 1).await;

    // The three post-cut frames arrive out of deadline order.
    let base = cut + 300_000;
    server.audio(base + 600_000, 1_500_000, vec![0xb3; 4]);
    server.audio(base + 200_000, 1_500_000, vec![0xb1; 4]);
    server.audio(base + 400_000, 1_500_000, vec![0xb2; 4]);

    let written = wait_for_writes(&recordings, 3).await;
    let payloads: Vec<Written> = written.iter().map(|frame| frame.frame.clone()).collect();
    assert_eq!(
        payloads,
        vec![
            Written::Pcm(vec![0xb1; 4]),
            Written::Pcm(vec![0xb2; 4]),
            Written::Pcm(vec![0xb3; 4]),
        ],
        "post-seek frames must be written in deadline order, not arrival order"
    );
    assert!(
        written[0].due < written[1].due && written[1].due < written[2].due,
        "the recorded deadlines must be ordered"
    );
    assert!(
        !payloads.contains(&Written::Pcm(vec![0xb0; 4])),
        "the clear must drop the frame at or after the cut"
    );
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
async fn a_clear_with_a_timestamp_discards_from_it_and_one_without_flushes() {
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
    // `stream/start` flushed the previous (absent) stream once.
    assert_eq!(recordings.flushes(), 1);

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
    wait_for_discards(&recordings, 1).await;
    assert_eq!(
        recordings.flushes(),
        1,
        "a clear with a timestamp must discard, not flush"
    );

    server.stream_clear(None);
    match next_event(&mut events).await {
        Event::StreamClear { from_timestamp } => assert_eq!(
            from_timestamp, None,
            "a clear without a position must not invent one"
        ),
        other => panic!("expected StreamClear, got {other:?}"),
    }
    wait_for_flushes(&recordings, 2).await;
    assert_eq!(
        recordings.discards().len(),
        1,
        "a clear without a timestamp must flush, not discard"
    );
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
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    // A frame queued before the end, still in the future, must not survive the flush either.
    server.audio(now_us() + 800_000, 1_000_000, vec![0x44; 64]);
    server.stream_end();
    // The flush proves the end was processed; the audio below is sent after it.
    wait_for_flushes(&recordings, 2).await;

    server.audio(now_us(), 0, vec![0x55; 64]);
    // Wait beyond the queued frame's deadline: without the flush it would be written here.
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert!(
        recordings.written().is_empty(),
        "a chunk queued before or sent after stream/end must not reach the sink"
    );
}

#[tokio::test]
async fn a_timestamped_clear_discards_and_keeps_the_stream_open() {
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
    let flushes_before = recordings.flushes();
    server.stream_clear(Some(now_us() - 1_000_000));
    wait_for_discards(&recordings, 1).await;
    assert_eq!(
        recordings.flushes(),
        flushes_before,
        "a timestamped clear must not also flush what plays earlier"
    );

    // A clear is a seek, not an end: the announced format stays open and later chunks still play.
    server.audio(now_us(), 0, vec![0x66; 64]);
    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(written[0].frame, Written::Pcm(vec![0x66; 64]));
}

#[tokio::test]
async fn a_clear_with_a_timestamp_maps_the_deadline_once_the_clock_is_ready() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // The state report follows the first completed burst. The filter needs three measurements,
    // so the client runs three bursts before the clock is ready; the server counts the replies,
    // and the 24th is ordered before the clear below.
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
    server.stream_clear(Some(now_us() + 250_000));

    let discards = wait_for_discards(&recordings, 1).await;
    let due = discards[0];
    let now = Instant::now();
    assert!(
        due > now + Duration::from_millis(100),
        "the discard deadline {due:?} must be ahead of now {now:?}"
    );
    assert!(
        due < now + Duration::from_millis(700),
        "the discard deadline {due:?} must be near the announced timestamp"
    );
}

#[tokio::test]
async fn a_clear_before_the_clock_is_ready_discards_from_now() {
    // With no `client/time` reply the filter has no estimate, so a future timestamp maps to now.
    let options = ServerOptions {
        answer_time_limit: Some(0),
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_clear(Some(now_us() + 5_000_000));

    let discards = wait_for_discards(&recordings, 1).await;
    assert!(
        discards[0] <= Instant::now(),
        "without a clock estimate the discard deadline must be now, not a future instant"
    );
}

#[tokio::test]
async fn a_failing_discard_ends_the_connection() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let recordings = Recordings::default();
    let sink = Box::new(RecordingSink::failing_discard_on(recordings, 1));
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    server.stream_clear(Some(now_us()));

    match next_event(&mut events).await {
        Event::StreamClear { .. } => {}
        other => panic!("the clear is reported before the discard, got {other:?}"),
    }
    match next_event(&mut events).await {
        Event::Disconnected { reason, retry_in } => {
            assert!(
                reason.contains("rejected a discard"),
                "the reason must name the failed discard, got: {reason}"
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
async fn removing_the_player_role_flushes_the_sink() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    establish_clock(&mut server).await;
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    // A frame queued before the removal, still in the future, must not survive the flush.
    server.audio(now_us() + 800_000, 1_000_000, vec![0x66; 64]);
    server.activate(&["metadata@v1"]);
    wait_for_flushes(&recordings, 2).await;

    server.audio(now_us(), 0, vec![0x77; 64]);
    // Wait beyond the queued frame's deadline: without the flush it would be written here.
    tokio::time::sleep(Duration::from_millis(1_000)).await;
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
    // (`docs/spec-deviations.md`, "A player volume above 100 is capped, not rejected"), which is
    // not a decode failure.
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
async fn the_audio_header_boundary_is_twelve_bytes_after_the_id() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // Id 4, a full 12-byte header and no audio, with no stream announced: well-formed, so it is
    // ignored and the connection stays up.
    let mut header_only = vec![4];
    header_only.extend_from_slice(&[0; 12]);
    server.binary(header_only);
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("a complete header must not close the connection, got {other:?}"),
    }

    // One byte short of the header closes it, and the message names the length it saw.
    let mut short = vec![4];
    short.extend_from_slice(&[0; 11]);
    server.binary(short);
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("truncated") && reason.contains("12 bytes"),
            "unexpected reason: {reason}"
        ),
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
    let started = Instant::now();
    let timestamp = now_us() + 250_000;
    server.audio(timestamp, 250_000, vec![0x33; 64]);

    let written = wait_for_writes(&recordings, 1).await;
    assert_near(
        written[0].due,
        started + Duration::from_millis(250),
        Duration::from_millis(150),
        "the deadline must be the announced timestamp mapped into the future",
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
async fn a_late_time_reply_still_forms_the_clock_estimate() {
    let options = ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // Answer every `client/time` request, but only after the per-message timeout, so each reply is
    // late. A reply that arrives after its request timed out is still a measurement of the burst,
    // so the clock estimate forms and a later playout deadline moves into the future. The client
    // stops asking only once the filter is ready, so keep answering until the next request fails
    // to arrive within the quiet window.
    let mut answered = 0usize;
    loop {
        if answered >= 40 {
            break;
        }
        let transmitted =
            match tokio::time::timeout(Duration::from_millis(1500), server.next_time_request())
                .await
            {
                Ok(Some(transmitted)) => transmitted,
                Ok(None) => panic!("the connection closed while the clock estimate was forming"),
                Err(_) => break,
            };
        tokio::time::sleep(Duration::from_millis(300)).await;
        server.answer_time(transmitted);
        answered += 1;
    }

    // The estimate is ready, so a server timestamp ahead of now becomes a future playout deadline.
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    let started = Instant::now();
    let timestamp = now_us() + 1_000_000;
    server.audio(timestamp, 250_000, vec![0x33; 64]);

    let written = wait_for_writes(&recordings, 1).await;
    assert!(
        written[0].due >= started + Duration::from_millis(100),
        "a late reply must still form an estimate and schedule into the future, saw {:?}",
        written[0].due - started
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
async fn the_initial_state_carries_the_configured_timing() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.required_lead_time_ms = 400;
    config.min_buffer_ms = Some(600);
    let (_handle, _events) = connect(config, sink)
        .await
        .expect("the client must connect to the fake server");

    let player = wait_for_client_state(&mut server)
        .await
        .player
        .expect("the first state carries the player object");
    assert_eq!(
        player.required_lead_time_ms, 400,
        "the lead the host configured must reach the server"
    );
    assert_eq!(
        player.min_buffer_ms, 600,
        "a pinned buffer must be reported exactly as configured"
    );
}

#[tokio::test]
async fn an_auto_min_buffer_starts_at_250() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (_handle, _events) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;

    let player = wait_for_client_state(&mut server)
        .await
        .player
        .expect("the first state carries the player object");
    assert_eq!(
        player.min_buffer_ms, 250,
        "an unpinned buffer starts at the value every release before this field reported"
    );
    assert_eq!(
        player.required_lead_time_ms, 250,
        "a host that configures nothing keeps the lead earlier releases reported"
    );
}

#[tokio::test]
async fn a_pin_above_five_seconds_is_refused() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.min_buffer_ms = Some(5_001);

    match connect(config, sink).await {
        Ok(_) => panic!("a pin above the protocol's 5000 ms range must be refused"),
        Err(error) => {
            let message = format!("{error:#}");
            assert!(
                message.contains("min_buffer_ms") && message.contains("5000"),
                "the error must name the field and the range, got: {message}"
            );
        }
    }
}

#[tokio::test]
async fn a_lead_above_five_seconds_is_accepted() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.required_lead_time_ms = 6_000;
    let (_handle, _events) = connect(config, sink)
        .await
        .expect("the lead has no upper bound, so 6000 ms is a valid configuration");

    let player = wait_for_client_state(&mut server)
        .await
        .player
        .expect("the first state carries the player object");
    assert_eq!(
        player.required_lead_time_ms, 6_000,
        "the lead reaches the wire unchanged"
    );
}

#[tokio::test]
async fn a_pinned_value_is_not_overwritten() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.min_buffer_ms = Some(400);
    let (_handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    let player = wait_for_client_state(&mut server)
        .await
        .player
        .expect("the first state carries the player object");
    assert_eq!(
        player.min_buffer_ms, 400,
        "the pin is what the host asked for"
    );

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    // A start-from-empty burst does not represent steady-state delay, so wait past the warmup the
    // estimator applies. Then send more chunks than its window needs and a change needs two
    // evaluations to apply (128 minimum samples plus two 32-sample steps), so 200 covers both: a
    // session that derived would have reported a new value by the end of this.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    // A send-ahead of 50 ms maps each chunk to a transmit time 50 ms before now, so the measured
    // arrival delay is about 50 ms: far from the pin, and far from the 250 ms an unpinned session
    // starts at. A pinned session that was accidentally treated as auto would derive ~50 ms and
    // report it, which the timeout below catches.
    for _ in 0..200 {
        server.audio(now_us(), 50_000, vec![0x5a; 64]);
    }
    wait_for_processed(&server, &mut events).await;

    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.wait_for_client_state())
            .await
            .is_err(),
        "a pinned session must not report another state once audio arrives"
    );
}

#[tokio::test]
async fn a_saturated_send_ahead_produces_no_update() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;
    wait_for_client_state(&mut server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    // Past the estimator's warmup: a start-from-empty burst is not steady-state delay.
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    // `0` and `u32::MAX` are the protocol's saturation values for `send_ahead`, meaning "no
    // measurement". The `0` half is the one that discriminates the saturation filter: with the
    // timestamp half a second in the past, an unfiltered sample would derive ~500 ms and raise the
    // buffer after 160 samples. The `u32::MAX` half cannot: it maps the transmit time ~4300 s into
    // the past, so the delay falls outside the ±60 s plausibility bound and is discarded with or
    // without the saturation check. It stays as the wire-shape regression.
    for send_ahead in [0, u32::MAX] {
        for _ in 0..200 {
            server.audio(now_us() - 500_000, send_ahead, vec![0x5a; 64]);
        }
        wait_for_processed(&server, &mut events).await;
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.wait_for_client_state())
            .await
            .is_err(),
        "a saturated send_ahead is no measurement and must not change the buffer"
    );
}

#[tokio::test]
async fn an_auto_value_updates_after_a_window() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let player = wait_for_client_state(&mut server)
        .await
        .player
        .expect("the first state carries the player object");
    assert_eq!(
        player.min_buffer_ms, 250,
        "an unpinned session starts at the value it reports before any derivation"
    );

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    // Samples inside the first second of a stream are discarded as start-burst noise.
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    // A stable synthetic arrival pattern: each chunk claims a transmit time 50 ms ahead of a
    // timestamp half a second in the past, so the measured arrival delay is around 550 ms - far
    // from the 250 ms start value. 160 samples are enough for two evaluations; 200 leaves margin.
    for _ in 0..200 {
        server.audio(now_us() - 500_000, 50_000, vec![0x5a; 64]);
    }
    wait_for_processed(&server, &mut events).await;

    let player = wait_for_client_state(&mut server)
        .await
        .player
        .expect("the derived report carries the player object");
    assert_ne!(
        player.min_buffer_ms, 250,
        "a sustained arrival delay must replace the start value"
    );
    assert!(
        player.min_buffer_ms <= 5_000,
        "the derived value stays inside the protocol's range, got {}",
        player.min_buffer_ms
    );
}

#[tokio::test]
async fn a_start_burst_inside_the_warmup_is_not_sampled() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;
    wait_for_client_state(&mut server).await;
    // The state report follows the first reply, but the clock estimate needs three accepted
    // samples. Wait for the initial bursts, so the chunks below are sampleable and the row
    // discriminates the warmup rather than the clock. This happens before `stream/start`, so it
    // does not eat into the window.
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
    // A start-from-empty burst is transmitted back-to-back, so its arrival delay says nothing about
    // the steady state. These chunks carry a plausible 50 ms delay - far from the 250 ms start value
    // and from any pin - and 200 of them would apply it at sample 160 (two same-direction
    // evaluations after the 128-sample minimum) if the warmup did not discard every one of them.
    // They go out immediately after `stream/start`, well inside the one-second window, and the quiet
    // period below catches the report a missing guard would produce.
    for _ in 0..200 {
        server.audio(now_us(), 50_000, vec![0x5a; 64]);
    }
    wait_for_processed(&server, &mut events).await;

    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.wait_for_client_state())
            .await
            .is_err(),
        "chunks inside the warmup must not move the buffer"
    );

    // An in-place `stream/start` only swaps the format of a running stream: the arrival distribution
    // is unchanged, so it must not re-arm the warmup. Once the first window has elapsed, the same
    // pattern with a ~550 ms delay has to produce a report; an implementation that restarted the
    // warmup on every `stream/start` would send nothing within the default timeout.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    server.stream_start("pcm", 48_000, 2, 16);
    // The chunks above are past their deadlines and their tail report is now flushed; the row is
    // about the warmup, so those diagnostic events are skipped while waiting for the start.
    loop {
        match next_event(&mut events).await {
            Event::LateAudio { .. } => continue,
            Event::StreamStart { .. } => break,
            other => panic!("expected StreamStart, got {other:?}"),
        }
    }
    for _ in 0..200 {
        server.audio(now_us() - 500_000, 50_000, vec![0x5a; 64]);
    }
    wait_for_processed(&server, &mut events).await;

    let player = wait_for_client_state(&mut server)
        .await
        .player
        .expect("the derived report carries the player object");
    assert_ne!(
        player.min_buffer_ms, 250,
        "an in-place stream start must not re-arm the warmup"
    );
}

#[tokio::test]
async fn a_burst_with_a_sample_does_not_wait_for_a_lost_last_reply() {
    let options = ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // Answer the first seven requests of the burst immediately, so the burst already holds a sample,
    // and withhold the eighth. A reply for the eighth can never beat what is buffered, so the state
    // report must follow the eighth request's timeout, not the two-second burst deadline.
    for _ in 0..7 {
        let transmitted = server
            .next_time_request()
            .await
            .expect("the client must keep asking for time");
        server.answer_time(transmitted);
    }
    assert!(
        server.next_time_request().await.is_some(),
        "the eighth request must arrive"
    );
    let withheld_at = Instant::now();

    let state = wait_for_client_state(&mut server).await;
    assert!(state.available);
    assert!(
        withheld_at.elapsed() < Duration::from_secs(1),
        "the state report must follow the last request's timeout, not the two-second burst deadline"
    );
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
        strict_group_id: false,
        output_delay_control: false,
        unpaired_access: true,
        required_lead_time_ms: 250,
        min_buffer_ms: None,
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
                strict_group_id: false,
                output_delay_control: false,
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
    assert_eq!(
        hello.device_info, None,
        "a host that describes no device announces none"
    );
}

#[tokio::test]
async fn a_default_client_admits_unpaired_access() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (_events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    let hello = server
        .wait_for_client_hello()
        .await
        .expect("client/hello arrives");
    assert!(hello.unpaired_access.enabled);
}

#[tokio::test]
async fn a_client_that_refuses_unpaired_access_says_so_in_client_hello() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    // Both are bound, not dropped: dropping the event stream ends the session.
    let (_handle, _events) = connect(config, sink)
        .await
        .expect("the client must connect");
    let hello = server
        .wait_for_client_hello()
        .await
        .expect("client/hello arrives");
    assert!(!hello.unpaired_access.enabled);
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
            seek_max_ms: Some(245_000),
        }),
        ..Default::default()
    }))
    .unwrap();
    server.json(state);

    match next_event(&mut events).await {
        Event::State(state) => {
            assert_eq!(state.supported_commands, vec!["play".to_owned()]);
            assert_eq!(state.volume, Some(40));
            assert_eq!(state.muted, Some(false));
            assert_eq!(
                state.seek_max_ms,
                Some(245_000),
                "the seekable range reaches the host"
            );
        }
        other => panic!("expected State, got {other:?}"),
    }
}

#[tokio::test]
async fn a_controller_seek_sends_the_position() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(controller_state(&["play", "seek"], Some(245_000)));
    let state = expect_controller_state(&mut events).await;
    assert_eq!(state.seek_max_ms, Some(245_000));

    handle
        .control()
        .seek(123_456)
        .await
        .expect("an advertised seek inside the range is sent");
    let command = next_controller_command(&mut server).await;
    assert_eq!(command.command, "seek");
    assert_eq!(command.position_ms, Some(123_456));
    assert_eq!(
        command.offset_ms, None,
        "an absolute seek carries no offset"
    );
}

#[tokio::test]
async fn a_relative_seek_sends_the_offset() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(controller_state(&["seek_relative"], None));
    let state = expect_controller_state(&mut events).await;
    assert_eq!(
        state.seek_max_ms, None,
        "a relative seek needs no range, so none is reported"
    );

    handle
        .control()
        .seek_relative(-15_000)
        .await
        .expect("an advertised relative seek is sent");
    let command = next_controller_command(&mut server).await;
    assert_eq!(command.command, "seek_relative");
    assert_eq!(command.offset_ms, Some(-15_000));
    assert_eq!(
        command.position_ms, None,
        "a relative seek carries no absolute position"
    );
}

#[tokio::test]
async fn a_seek_the_server_did_not_offer_is_refused() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(controller_state(&["play"], None));
    expect_controller_state(&mut events).await;

    let error = handle
        .control()
        .seek(1)
        .await
        .expect_err("a command the server does not advertise must not be sent");
    assert!(
        format!("{error:#}").contains("does not accept the command \"seek\""),
        "the error names the advertised gate and the refused command, got: {error:#}"
    );
    assert_no_client_command(&mut server).await;
}

#[tokio::test]
async fn a_seek_at_the_upper_bound_is_sent() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(controller_state(&["seek"], Some(12_000)));
    let state = expect_controller_state(&mut events).await;
    assert_eq!(state.seek_max_ms, Some(12_000));

    handle
        .control()
        .seek(12_000)
        .await
        .expect("the range is inclusive, so a target at it is sent");
    let command = next_controller_command(&mut server).await;
    assert_eq!(command.command, "seek");
    assert_eq!(
        command.position_ms,
        Some(12_000),
        "the bound itself is a valid target"
    );
}

#[tokio::test]
async fn a_seek_beyond_the_range_is_refused() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(controller_state(&["seek"], Some(12_000)));
    let state = expect_controller_state(&mut events).await;
    assert_eq!(state.seek_max_ms, Some(12_000));

    let error = handle
        .control()
        .seek(12_001)
        .await
        .expect_err("a target beyond the range must be refused");
    assert!(
        format!("{error:#}").contains("12000"),
        "the error names the range, got: {error:#}"
    );
    assert_no_client_command(&mut server).await;
}

#[tokio::test]
async fn a_seek_without_a_range_is_refused() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(controller_state(&["seek"], None));
    let state = expect_controller_state(&mut events).await;
    assert_eq!(
        state.seek_max_ms, None,
        "the server offered seek without naming a range"
    );

    let error = handle
        .control()
        .seek(1)
        .await
        .expect_err("a target without a range cannot be checked");
    assert!(
        format!("{error:#}").contains("range"),
        "the error names the missing range, got: {error:#}"
    );
    assert_no_client_command(&mut server).await;
}

#[tokio::test]
async fn a_seek_before_the_first_state_is_refused_while_a_relative_seek_is_sent() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    // No `server/state` has arrived, so the range is unknown and an absolute seek has no target
    // it could be checked against: the open window does not extend to it.
    let error = handle
        .control()
        .seek(1)
        .await
        .expect_err("an absolute seek needs the range the first controller state carries");
    assert!(
        format!("{error:#}").contains("range"),
        "the error names the missing range, got: {error:#}"
    );
    assert_no_client_command(&mut server).await;

    // A relative seek needs no range, so it keeps the open window of the transport commands.
    handle
        .control()
        .seek_relative(-1_000)
        .await
        .expect("a relative seek needs no known range");
    let command = next_controller_command(&mut server).await;
    assert_eq!(command.command, "seek_relative");
    assert_eq!(command.offset_ms, Some(-1_000));
}

#[tokio::test]
async fn a_group_update_does_not_clear_the_seekable_range() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.json(controller_state(&["play", "seek"], Some(245_000)));
    let state = expect_controller_state(&mut events).await;
    assert_eq!(state.seek_max_ms, Some(245_000));

    // `group/update` replaces only the group fields, so the controller picture stays.
    let update = serde_json::to_string(&Incoming::GroupUpdate(GroupUpdate {
        playback_state: "playing".to_owned(),
        group_id: "A".repeat(43),
        group_name: "Living room".to_owned(),
    }))
    .unwrap();
    server.json(update);
    let state = expect_controller_state(&mut events).await;
    assert_eq!(state.playback_state.as_deref(), Some("playing"));
    assert_eq!(
        state.seek_max_ms,
        Some(245_000),
        "a group update keeps the seekable range the controller state reported"
    );
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
            seek_max_ms: None,
        }),
        ..Default::default()
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
async fn a_foreign_group_id_is_accepted_and_reported_once() {
    // The spec requires 43 base64url characters, but a real server sends a UUID. The tolerance
    // accepts it as an opaque string and reports the departure exactly once per connection.
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let uuid = "123e4567-e89b-12d3-a456-426614174000";
    let update = serde_json::to_string(&Incoming::GroupUpdate(GroupUpdate {
        playback_state: "playing".to_owned(),
        group_id: uuid.to_owned(),
        group_name: "Living room".to_owned(),
    }))
    .unwrap();
    server.json(update);

    match next_event(&mut events).await {
        Event::GroupIdNotCanonical { len } => {
            assert_eq!(len, uuid.len(), "the event names the length, not the value");
        }
        other => panic!("expected GroupIdNotCanonical, got {other:?}"),
    }
    match next_event(&mut events).await {
        Event::State(state) => {
            assert_eq!(
                state.group_id.as_deref(),
                Some(uuid),
                "the foreign identifier is carried as an opaque string"
            );
        }
        other => panic!("expected State, got {other:?}"),
    }

    // A second non-canonical update must not report the departure again.
    let update = serde_json::to_string(&Incoming::GroupUpdate(GroupUpdate {
        playback_state: "stopped".to_owned(),
        group_id: "another-foreign-id".to_owned(),
        group_name: "Living room".to_owned(),
    }))
    .unwrap();
    server.json(update);
    match next_event(&mut events).await {
        Event::State(state) => assert_eq!(state.group_id.as_deref(), Some("another-foreign-id")),
        other => panic!("expected State without a second tolerance event, got {other:?}"),
    }

    // A canonical identifier reports nothing at all, which is the behaviour every server gets.
    let canonical = "A".repeat(43);
    let update = serde_json::to_string(&Incoming::GroupUpdate(GroupUpdate {
        playback_state: "playing".to_owned(),
        group_id: canonical.clone(),
        group_name: "Living room".to_owned(),
    }))
    .unwrap();
    server.json(update);
    match next_event(&mut events).await {
        Event::State(state) => assert_eq!(state.group_id.as_deref(), Some(canonical.as_str())),
        other => panic!("a canonical group id must not be reported as a deviation, got {other:?}"),
    }
}

#[tokio::test]
async fn an_absurd_group_id_is_a_protocol_error() {
    // The tolerance drops the base64url and length rules, not the shape: an empty, oversized or
    // control-character value stays a protocol error that closes the connection.
    for group_id in [
        String::new(),
        "A".repeat(129),
        "a\nb".to_owned(),
        "a\tb".to_owned(),
    ] {
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
async fn a_group_update_with_a_malformed_group_id_is_a_protocol_error_in_strict_mode() {
    // `ClientConfig::strict_group_id` restores the spec's rule: any non-canonical value closes the
    // connection. Both a wrong length and a character outside the alphabet count.
    for group_id in [
        "B".repeat(42),
        format!("{}=", "B".repeat(42)),
        "123e4567-e89b-12d3-a456-426614174000".to_owned(),
    ] {
        let server = FakeServer::start(ServerOptions::default()).await.unwrap();
        let (_recordings, sink) = recording_sink();
        let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
        config.strict_group_id = true;
        let (_handle, mut events) = connect(config, sink)
            .await
            .expect("the client must connect to the fake server");
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
        ..Default::default()
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
        ..Default::default()
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
    let (_recordings, sink) = sink_with_output_delay(Duration::from_secs(60));
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    let state = wait_for_client_state(&mut server).await;
    let player = state.player.expect("the player state follows the role");
    assert_eq!(
        player.output_delay_ms, 5_000,
        "an absurd sink output delay is clamped before it reaches the server"
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

    // No player role was active, so no clock burst ran, and the initial report - owed to any client
    // with a role - carries no player object. Adding the role has to start a burst, and the state
    // report that follows the first sample carries the player.
    let initial = wait_for_client_state(&mut server).await;
    assert!(initial.player.is_none(), "no player role, no player object");
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
async fn a_past_timestamp_is_dropped_once_the_clock_is_ready() {
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

    // Five seconds late is beyond the tolerance: the frame is dropped instead of being played
    // late, and the report says how much of it there was.
    match next_event(&mut events).await {
        Event::LateAudio { late_by, dropped } => {
            assert_eq!(dropped, 1, "the one late frame is counted");
            assert!(
                late_by >= Duration::from_secs(4),
                "the report carries the lateness, saw {late_by:?}"
            );
        }
        other => panic!("expected LateAudio, got {other:?}"),
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        recordings.written().is_empty(),
        "a deadline in the past must not be written late"
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
                seek_max_ms: None,
            }),
            ..Default::default()
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
                seek_max_ms: None,
            }),
            ..Default::default()
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

/// Connects with [`ClientConfig::output_delay_control`] set, so the command is advertised.
async fn connect_with_output_delay_control(
    server: &FakeServer,
    sink: Box<dyn Sink>,
) -> (EventStream, ClientHandle) {
    let mut config = config_for(server, syncspin_client::AudioMode::Passthrough);
    config.output_delay_control = true;
    let (handle, events) = connect(config, sink)
        .await
        .expect("the client must connect to the fake server");
    (events, handle)
}

/// Sends one `server/command` player object.
fn send_player_command(server: &FakeServer, command: &str, output_delay_ms: Option<u32>) {
    server.json(
        serde_json::to_string(&Incoming::ServerCommand(ServerCommand {
            player: Some(PlayerCommand {
                command: command.to_owned(),
                volume: None,
                mute: None,
                output_delay_ms,
            }),
        }))
        .unwrap(),
    );
}

#[tokio::test]
async fn output_delay_is_advertised_only_when_the_host_opts_in() {
    // Default: a host that cannot apply the delay must not advertise it.
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;
    let state = wait_for_client_state(&mut server).await;
    let player = state.player.expect("the player object is present");
    assert!(
        !player
            .supported_commands
            .iter()
            .any(|command| command == "set_output_delay"),
        "the default configuration must not advertise set_output_delay"
    );

    // Opt-in: the host can apply it, so the command is advertised.
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) = connect_with_output_delay_control(&server, sink).await;
    expect_connected(&mut events, &server).await;
    let state = wait_for_client_state(&mut server).await;
    let player = state.player.expect("the player object is present");
    assert!(
        player
            .supported_commands
            .iter()
            .any(|command| command == "set_output_delay"),
        "the opt-in configuration advertises set_output_delay, got {:?}",
        player.supported_commands
    );
    for command in ["volume", "mute"] {
        assert!(
            player.supported_commands.iter().any(|name| name == command),
            "the base commands stay advertised, got {:?}",
            player.supported_commands
        );
    }
}

#[tokio::test]
async fn the_output_delay_command_reports_the_clamped_value() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) = connect_with_output_delay_control(&server, sink).await;
    expect_connected(&mut events, &server).await;

    for (requested, expected) in [(0, 0), (200, 200), (5_000, 5_000), (5_001, 5_000)] {
        send_player_command(&server, "set_output_delay", Some(requested));
        match next_event(&mut events).await {
            Event::OutputDelay {
                requested: sent,
                applied,
            } => {
                assert_eq!(sent, requested);
                assert_eq!(applied, expected, "the applied delay for {requested} ms");
            }
            other => panic!("expected OutputDelay for {requested} ms, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn an_unadvertised_output_delay_command_is_ignored() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    send_player_command(&server, "set_output_delay", Some(200));
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("an unadvertised command must be ignored, got {other:?}"),
    }
}

#[tokio::test]
async fn an_incomplete_output_delay_command_is_ignored() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) = connect_with_output_delay_control(&server, sink).await;
    expect_connected(&mut events, &server).await;

    // The advertised command without its required field: no event, no state, no disconnect.
    server.json(r#"{"type":"server/command","payload":{"player":{"command":"set_output_delay"}}}"#);
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("an incomplete command must be ignored, got {other:?}"),
    }
}

#[tokio::test]
async fn a_badly_typed_output_delay_command_is_ignored() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) = connect_with_output_delay_control(&server, sink).await;
    expect_connected(&mut events, &server).await;

    // A string where the field is an integer: the whole control message is dropped, as any
    // malformed control message is, and the connection continues.
    server.json(
        r#"{"type":"server/command","payload":{"player":{"command":"set_output_delay","output_delay_ms":"fast"}}}"#,
    );
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("a malformed command must be ignored, got {other:?}"),
    }

    // A negative value does not decode into the `u32` field either: no event, no state change.
    server.json(
        r#"{"type":"server/command","payload":{"player":{"command":"set_output_delay","output_delay_ms":-5}}}"#,
    );
    server.metadata("Still here too", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here too"),
        other => panic!("a negative delay must be ignored, got {other:?}"),
    }
}

#[tokio::test]
async fn the_applied_output_delay_is_reported_at_once() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let recordings = Recordings::default();
    let timing = timing_handle(None, Duration::ZERO);
    let sink = Box::new(RecordingSink::with_timing(recordings, timing.clone()));
    let (mut events, handle) = connect_with_output_delay_control(&server, sink).await;
    expect_connected(&mut events, &server).await;
    let _first = wait_for_client_state(&mut server).await;

    send_player_command(&server, "set_output_delay", Some(200));
    match next_event(&mut events).await {
        Event::OutputDelay { applied, .. } => assert_eq!(applied, 200),
        other => panic!("expected OutputDelay, got {other:?}"),
    }

    // The host applies it to its output, then tells the session; nothing else triggers a report.
    timing
        .lock()
        .expect("the timing lock is not poisoned")
        .output_delay = Some(Duration::from_millis(200));
    handle
        .control()
        .output_delay_applied()
        .await
        .expect("the player role is active");

    let state = wait_for_client_state(&mut server).await;
    let player = state.player.expect("the player object is present");
    assert_eq!(
        player.output_delay_ms, 200,
        "the state carries the applied delay"
    );
}

#[tokio::test]
async fn an_applied_output_delay_is_reported_without_the_host_call() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let recordings = Recordings::default();
    let timing = timing_handle(None, Duration::ZERO);
    let sink = Box::new(RecordingSink::with_timing(recordings, timing.clone()));
    let (mut events, _handle) = connect_with_output_delay_control(&server, sink).await;
    expect_connected(&mut events, &server).await;
    let _first = wait_for_client_state(&mut server).await;

    send_player_command(&server, "set_output_delay", Some(200));
    assert!(matches!(
        next_event(&mut events).await,
        Event::OutputDelay { applied: 200, .. }
    ));
    // The host adopts the value but never calls `output_delay_applied`: the fallback read of the
    // sink still reports it.
    timing
        .lock()
        .expect("the timing lock is not poisoned")
        .output_delay = Some(Duration::from_millis(200));

    let player = wait_for_client_state(&mut server)
        .await
        .player
        .expect("the player object is present");
    assert_eq!(player.output_delay_ms, 200);
}

#[tokio::test]
async fn an_output_delay_change_with_queued_audio_keeps_the_session_operational() {
    let mut server = FakeServer::start(ServerOptions {
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let recordings = Recordings::default();
    let timing = timing_handle(Some(Duration::from_millis(500)), Duration::ZERO);
    let sink = Box::new(RecordingSink::with_timing(
        recordings.clone(),
        timing.clone(),
    ));
    let (mut events, handle) = connect_with_output_delay_control(&server, sink).await;
    expect_connected(&mut events, &server).await;
    establish_clock(&mut server).await;

    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    // Two frames far enough out to stay queued while the delay changes. The metadata message
    // follows them on the same socket, so both are queued by the time its event arrives.
    let started = Instant::now();
    server.audio(now_us() + 2_000_000, 2_000_000, vec![0x11; 4]);
    server.audio(now_us() + 2_100_000, 2_100_000, vec![0x22; 4]);
    server.metadata("queued", "queued");
    assert!(matches!(next_event(&mut events).await, Event::Track { .. }));
    assert!(recordings.written().is_empty(), "both frames are queued");

    // The server lowers the delay: the queued frames move later by 400 ms and nothing is lost.
    send_player_command(&server, "set_output_delay", Some(100));
    match next_event(&mut events).await {
        Event::OutputDelay { applied, .. } => assert_eq!(applied, 100),
        other => panic!("expected OutputDelay, got {other:?}"),
    }
    timing
        .lock()
        .expect("the timing lock is not poisoned")
        .output_delay = Some(Duration::from_millis(100));
    handle
        .control()
        .output_delay_applied()
        .await
        .expect("the player role is active");
    loop {
        let player = wait_for_client_state(&mut server)
            .await
            .player
            .expect("the player state follows the role");
        if player.output_delay_ms == 100 {
            break;
        }
    }

    // The server raises it again while the frames are still queued.
    send_player_command(&server, "set_output_delay", Some(300));
    assert!(matches!(
        next_event(&mut events).await,
        Event::OutputDelay { applied: 300, .. }
    ));
    timing
        .lock()
        .expect("the timing lock is not poisoned")
        .output_delay = Some(Duration::from_millis(300));
    handle
        .control()
        .output_delay_applied()
        .await
        .expect("the session is still operational");
    loop {
        let player = wait_for_client_state(&mut server)
            .await
            .player
            .expect("the player state follows the role");
        if player.output_delay_ms == 300 {
            break;
        }
    }

    // Both frames are still played, at the deadlines of the delay now in force (2.0 s - 300 ms).
    let written = wait_for_writes(&recordings, 2).await;
    assert_near(
        written[0].due,
        started + Duration::from_millis(1_700),
        Duration::from_millis(150),
        "the first frame follows the delay in force",
    );
    // The deadlines are computed, not measured: the second frame's follows the first by the
    // 100 ms spacing of the timestamps, and both sit at the remapped (300 ms) position.
    let spacing = written[1].due.duration_since(written[0].due);
    assert!(
        spacing >= Duration::from_millis(80) && spacing <= Duration::from_millis(120),
        "the frames keep their 100 ms spacing, got {spacing:?}"
    );
    assert_near(
        written[1].due,
        started + Duration::from_millis(1_800),
        Duration::from_millis(150),
        "the second frame's deadline is remapped too",
    );
}

#[tokio::test]
async fn a_persisted_output_delay_is_reported_in_the_first_state() {
    // The host restores the delay in its sink; the session reports what the sink returns, so a
    // reconnect or restart keeps the value without the session storing anything.
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let recordings = Recordings::default();
    let timing = timing_handle(None, Duration::ZERO);
    timing
        .lock()
        .expect("the timing lock is not poisoned")
        .output_delay = Some(Duration::from_millis(350));
    let sink = Box::new(RecordingSink::with_timing(recordings, timing));
    let (mut events, _handle) = connect_with_output_delay_control(&server, sink).await;
    expect_connected(&mut events, &server).await;
    let state = wait_for_client_state(&mut server).await;
    let player = state.player.expect("the player object is present");
    assert_eq!(player.output_delay_ms, 350);
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

// ---------------------------------------------------------------------------
// The unpaired-access switch
// ---------------------------------------------------------------------------

/// Waits for the client's goodbye, failing instead of hanging when none arrives.
///
/// A regression here means the client silently kept a connection open, which no assertion can
/// observe if the wait itself never returns.
async fn goodbye_from(server: &mut FakeServer) -> Option<String> {
    tokio::time::timeout(Duration::from_secs(5), server.wait_for_goodbye())
        .await
        .expect("the client must say goodbye before closing the connection")
}

/// Asserts that the client sent no goodbye and did not close the connection within one second.
///
/// The unpaired-access switch under test must leave the connection open, so a `client/goodbye`
/// fails the test, and a close without one is the same failure observed by the server. A window
/// exists at all because "no goodbye" is a negative: the test can only observe the absence of a
/// message for some time, never prove the connection stays open forever. One second is long enough
/// that a wrongly sent goodbye is still caught when it arrives late, instead of slipping past a
/// shorter bound.
async fn assert_no_goodbye(server: &mut FakeServer) {
    if let Ok(observed) =
        tokio::time::timeout(Duration::from_secs(1), server.wait_for_goodbye()).await
    {
        panic!("the client must keep the connection open, the server observed {observed:?}");
    }
}

#[tokio::test]
async fn a_guest_refuses_playback_when_unpaired_access_is_off() {
    // The server's first activation is the harness default: activities ['playback'] with roles.
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    let (handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect");

    expect_connected(&mut events, &server).await;
    match next_event(&mut events).await {
        Event::PairingRequired { server_id, reason } => {
            assert_eq!(server_id, server.server_id());
            assert_eq!(
                reason,
                syncspin_client::PairingRequiredReason::UnpairedAccessDisabled
            );
        }
        other => panic!("expected PairingRequired, got {other:?}"),
    }
    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("pairing_required"),
        "the switch closes the connection with the spec's reason"
    );
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => {
            assert!(reason.contains("does not admit"), "got: {reason}")
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
    drop(handle);
}

#[tokio::test]
async fn a_guest_that_refuses_unpaired_access_can_still_pair() {
    // `['pairing']` with no roles is admissible under the Sentinel key whatever the setting. The
    // pairing PSK method is not admissible on a Sentinel-keyed connection, and that refusal is an
    // abort - the connection stays open, which is what proves the switch did not close it.
    let options = ServerOptions {
        first_activate: Some(ServerActivate {
            activities: vec!["pairing".to_owned()],
            active_roles: Some(Vec::new()),
            pairing: Some(PairingActivation {
                method: "pairing_psk".to_owned(),
                format: None,
            }),
        }),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    let (handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect");

    expect_connected(&mut events, &server).await;
    assert_eq!(
        server.wait_for_pairing_abort().await.as_deref(),
        Some("method_not_supported"),
        "the activation reached the pairing layer instead of closing the connection"
    );
    assert_still_reconnecting(handle).await;
}

#[tokio::test]
async fn a_paired_session_keeps_playback_when_unpaired_access_is_off() {
    let psk: [u8; 32] = std::array::from_fn(|index| (index as u8) ^ 0x5a);
    let options = ServerOptions {
        psk_id: psk_id_for(&psk),
        psk_category: "lt".to_owned(),
        psk,
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (recordings, sink) = recording_sink();
    let stored = StoredPsk {
        category: PskCategory::LongTerm,
        psk,
        server_id: server.server_id().to_owned(),
    };
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    let (_handle, mut events) = syncspin_client::connect_with_psks(config, sink, vec![stored])
        .await
        .expect("the client must connect");

    expect_connected(&mut events, &server).await;
    // The sink opening is the proof that the session is a playback session, not just a handshake.
    server.stream_start("pcm", 48_000, 2, 16);
    wait_for_open(&recordings).await;
}

#[tokio::test]
async fn an_unoffered_role_closes_the_connection_as_unauthorized() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;
    server.json(
        r#"{"type":"server/activate","payload":{"activities":["playback"],"active_roles":["source@v1"]}}"#,
    );
    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("unauthorized")
    );
}

#[tokio::test]
async fn an_unknown_activity_closes_the_connection_as_unauthorized() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;
    server.json(r#"{"type":"server/activate","payload":{"activities":["playback","kiosk"]}}"#);
    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("unauthorized")
    );
}

#[tokio::test]
async fn a_repeated_activity_closes_the_connection_as_unauthorized() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, _handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;
    server.json(r#"{"type":"server/activate","payload":{"activities":["playback","playback"]}}"#);
    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("unauthorized")
    );
}

#[tokio::test]
async fn a_wrong_pairing_method_closes_as_unauthorized_not_pairing_required() {
    // `playback` needs unpaired access and the declared method is not admissible on a
    // Sentinel-keyed connection without a store, so enabling the setting would not admit the
    // activation: rule 1 must not fire, and no `Event::PairingRequired` may separate `Connected`
    // from `Disconnected`.
    let options = ServerOptions {
        first_activate: Some(ServerActivate {
            activities: vec!["playback".to_owned(), "pairing".to_owned()],
            active_roles: Some(vec!["player@v1".to_owned()]),
            pairing: Some(PairingActivation {
                method: "pairing_psk".to_owned(),
                format: None,
            }),
        }),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    let (_handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect");
    expect_connected(&mut events, &server).await;
    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("unauthorized"),
        "the wrong method keeps the activation refused whatever the setting"
    );
    match next_event(&mut events).await {
        Event::Disconnected { .. } => {}
        other => panic!("expected Disconnected directly after Connected, got {other:?}"),
    }
}

#[tokio::test]
async fn a_credential_mismatch_does_not_hide_the_refused_activation() {
    // The server announces a long-term key this client never held and seals with the Sentinel key,
    // so the handshake reports the mismatch; the harness's default playback activation is then
    // refused because the setting is off. Both reasons belong to the same connection.
    let foreign: [u8; 32] = std::array::from_fn(|index| index as u8 ^ 0xa5);
    let mut server = FakeServer::start(ServerOptions {
        psk_id: psk_id_for(&foreign),
        psk_category: "lt".to_owned(),
        psk: SENTINEL_PSK,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    let (handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect");

    expect_connected(&mut events, &server).await;
    assert_eq!(
        next_event(&mut events).await,
        Event::PairingRequired {
            server_id: server.server_id().to_owned(),
            reason: syncspin_client::PairingRequiredReason::CredentialMismatch,
        }
    );
    assert_eq!(
        next_event(&mut events).await,
        Event::PairingRequired {
            server_id: server.server_id().to_owned(),
            reason: syncspin_client::PairingRequiredReason::UnpairedAccessDisabled,
        },
        "the refusal is a second reason on the same connection, not a suppressed one"
    );
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => {
            assert!(reason.contains("does not admit"), "got: {reason}")
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("pairing_required"),
        "the refused activation still closes with the spec's reason"
    );
    drop(handle);
}

#[tokio::test]
async fn an_empty_activation_leaves_an_unpaired_session_open() {
    // `[]` with no roles is admissible for a guest whatever the setting, so it is the first
    // activation here: the switch closes only a session whose activation needs unpaired access.
    let options = ServerOptions {
        activate_override: Some(
            r#"{"type":"server/activate","payload":{"activities":[]}}"#.to_owned(),
        ),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    let (_handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect");

    expect_connected(&mut events, &server).await;
    assert_no_goodbye(&mut server).await;
    match tokio::time::timeout(Duration::from_millis(300), events.next()).await {
        Ok(Some(event)) => panic!("an empty activation must not end the session, got {event:?}"),
        Ok(None) => panic!("the event stream ended after an empty activation"),
        Err(_) => {}
    }
}

#[tokio::test]
async fn initial_hello_advertises_the_configured_unpaired_access() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    // Both are bound, not dropped: dropping the event stream ends the session.
    let (_handle, _events) = connect(config, sink)
        .await
        .expect("the client must connect");
    let hello = server
        .wait_for_client_hello()
        .await
        .expect("client/hello arrives");
    assert!(
        !hello.unpaired_access.enabled,
        "the hello must carry the configured value before any live change"
    );
}

#[tokio::test]
async fn turning_it_off_closes_a_relying_session() {
    // The harness's default activation declares `playback` and carries roles, so this unpaired
    // session relies on unpaired access through both limbs the spec names.
    let mut server = FakeServer::start(ServerOptions {
        connections: 2,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    handle
        .control()
        .set_unpaired_access(false)
        .await
        .expect("the live change must be accepted");

    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("pairing_required"),
        "the client says why it closes a relying connection"
    );
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("stopped admitting unpaired access"),
            "the reason must name the host's choice, got: {reason}"
        ),
        other => panic!(
            "the close must be the next event, so no PairingRequired can precede it, got {other:?}"
        ),
    }
    let hello = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_hello())
        .await
        .expect("the client reconnects after the close")
        .expect("the second connection announces itself");
    assert!(
        !hello.unpaired_access.enabled,
        "the next hello must advertise the value the host set"
    );
    drop(handle);
}

#[tokio::test]
async fn turning_it_off_closes_a_playback_only_session() {
    // Dropping the default player role leaves an activation that declares only `playback` and no
    // roles: the declared activity is the limb that makes this session rely on unpaired access.
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    server.cancel_pairing(&[]);
    match next_event(&mut events).await {
        Event::StreamEnd { reason } => assert_eq!(reason, StreamEndReason::RoleRemoved),
        other => panic!("expected StreamEnd for the dropped player role, got {other:?}"),
    }

    handle
        .control()
        .set_unpaired_access(false)
        .await
        .expect("the live change must be accepted");

    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("pairing_required"),
        "a declared playback activity is enough to rely on the setting"
    );
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("stopped admitting unpaired access"),
            "the reason must name the host's choice, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }
    drop(handle);
}

#[tokio::test]
async fn turning_it_off_leaves_an_idle_session() {
    // `[]` with no roles is admissible for a guest whatever the setting, so nothing in the session
    // relies on unpaired access and turning the setting off must leave it open.
    let mut server = FakeServer::start(ServerOptions {
        activate_override: Some(
            r#"{"type":"server/activate","payload":{"activities":[]}}"#.to_owned(),
        ),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;

    handle
        .control()
        .set_unpaired_access(false)
        .await
        .expect("the live change must be accepted");
    assert_no_goodbye(&mut server).await;

    // The value is in force, so the activation that needs it is refused by the existing guard.
    server.activate(&["player@v1"]);
    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("pairing_required"),
        "the guard refuses the later activation on the open connection"
    );
    drop(handle);
}

#[tokio::test]
async fn turning_it_off_leaves_a_paired_session() {
    let psk: [u8; 32] = std::array::from_fn(|index| (index as u8) ^ 0x5a);
    let options = ServerOptions {
        psk_id: psk_id_for(&psk),
        psk_category: "lt".to_owned(),
        psk,
        // The second connection is what the setting must reach after this one ends.
        connections: 2,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let stored = StoredPsk {
        category: PskCategory::LongTerm,
        psk,
        server_id: server.server_id().to_owned(),
    };
    let config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    let (handle, mut events) = connect_with_psks(config, sink, vec![stored])
        .await
        .expect("the client must connect");
    expect_connected(&mut events, &server).await;
    let first = server
        .wait_for_client_hello()
        .await
        .expect("the first connection announces itself");
    assert!(
        first.unpaired_access.enabled,
        "the first hello carries the configured default"
    );
    // Consume the initial report, so the one after the change is unambiguously the new level.
    wait_for_client_state(&mut server).await;

    handle
        .control()
        .set_unpaired_access(false)
        .await
        .expect("the live change must be accepted");
    assert_no_goodbye(&mut server).await;

    // A host-set level has no Event::Volume, so the answer and the next report are the proof the
    // paired session still runs.
    assert_eq!(
        handle
            .control()
            .set_volume(20)
            .await
            .expect("the paired session must stay live"),
        20
    );
    let state = wait_for_client_state(&mut server).await;
    assert_eq!(
        state.player.expect("the player role stays active").volume,
        Some(20)
    );

    // Leaving the session open is only half of it: the value must also reach the next connection,
    // because the hello of that connection is where it is advertised.
    server.close();
    match next_event(&mut events).await {
        Event::Disconnected { .. } => {}
        other => panic!("expected Disconnected, got {other:?}"),
    }
    let hello = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_hello())
        .await
        .expect("the client reconnects after the server closes the connection")
        .expect("the second connection announces itself");
    assert!(
        !hello.unpaired_access.enabled,
        "the next connection must advertise the value the host set"
    );
    drop(handle);
}

#[tokio::test]
async fn turning_it_on_restarts_an_unpaired_session() {
    // `[]` with no roles is admissible whatever the setting, so the session is still open when the
    // host turns unpaired access on: the restart is the only reason this connection ends.
    let mut server = FakeServer::start(ServerOptions {
        connections: 2,
        activate_override: Some(
            r#"{"type":"server/activate","payload":{"activities":[]}}"#.to_owned(),
        ),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    let (handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect");
    expect_connected(&mut events, &server).await;
    let first = server
        .wait_for_client_hello()
        .await
        .expect("the first connection announces itself");
    assert!(
        !first.unpaired_access.enabled,
        "the first hello carries the configured value"
    );

    handle
        .control()
        .set_unpaired_access(true)
        .await
        .expect("the live change must be accepted");

    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("restart"),
        "the hello is where the client advertises the setting, so it restarts to send one"
    );
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("restarted the connection"),
            "the reason must name the restart, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }
    let hello = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_hello())
        .await
        .expect("the client reconnects after the restart")
        .expect("the second connection announces itself");
    assert!(
        hello.unpaired_access.enabled,
        "the next hello must advertise the value the host set"
    );
    drop(handle);
}

#[tokio::test]
async fn turning_it_on_leaves_a_paired_session() {
    // The setting never applied to a paired session, so turning it on must not restart one either.
    let psk: [u8; 32] = std::array::from_fn(|index| (index as u8) ^ 0x5a);
    let options = ServerOptions {
        psk_id: psk_id_for(&psk),
        psk_category: "lt".to_owned(),
        psk,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let stored = StoredPsk {
        category: PskCategory::LongTerm,
        psk,
        server_id: server.server_id().to_owned(),
    };
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    let (handle, mut events) = connect_with_psks(config, sink, vec![stored])
        .await
        .expect("the client must connect");
    expect_connected(&mut events, &server).await;
    let first = server
        .wait_for_client_hello()
        .await
        .expect("the first connection announces itself");
    assert!(
        !first.unpaired_access.enabled,
        "the first hello carries the configured value"
    );

    handle
        .control()
        .set_unpaired_access(true)
        .await
        .expect("the live change must be accepted");
    assert_no_goodbye(&mut server).await;

    // The harness accepts one connection, so a restart would have nowhere to go; a second hello
    // within the window is what a restart would have produced.
    let hello =
        tokio::time::timeout(Duration::from_millis(300), server.wait_for_client_hello()).await;
    assert!(
        hello.is_err(),
        "a paired session must not restart to advertise the setting"
    );
    drop(handle);
}

#[tokio::test]
async fn setting_the_same_value_sends_nothing() {
    // An idle unpaired session whose setting is already off: the request repeats the value in
    // force, so it neither closes nor restarts anything.
    let mut server = FakeServer::start(ServerOptions {
        activate_override: Some(
            r#"{"type":"server/activate","payload":{"activities":[]}}"#.to_owned(),
        ),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    let (handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect");
    expect_connected(&mut events, &server).await;

    handle
        .control()
        .set_unpaired_access(false)
        .await
        .expect("a repeated value is accepted");
    assert_no_goodbye(&mut server).await;
    drop(handle);

    // The paired half repeats the value a paired session starts from, so a restart would be wrong
    // twice: the setting never applied to it, and the value did not change.
    let psk: [u8; 32] = std::array::from_fn(|index| (index as u8) ^ 0x5a);
    let options = ServerOptions {
        psk_id: psk_id_for(&psk),
        psk_category: "lt".to_owned(),
        psk,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (_recordings, sink) = recording_sink();
    let stored = StoredPsk {
        category: PskCategory::LongTerm,
        psk,
        server_id: server.server_id().to_owned(),
    };
    let config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    let (handle, mut events) = connect_with_psks(config, sink, vec![stored])
        .await
        .expect("the client must connect");
    expect_connected(&mut events, &server).await;

    handle
        .control()
        .set_unpaired_access(true)
        .await
        .expect("a repeated value is accepted");
    assert_no_goodbye(&mut server).await;
    drop(handle);
}

#[tokio::test]
async fn changing_while_disconnected_reaches_the_next_hello() {
    // The empty activation keeps the first session open under `false`, so the server's close is the
    // only reason it ends and the change lands while the client is between attempts.
    let mut server = FakeServer::start(ServerOptions {
        connections: 2,
        activate_override: Some(
            r#"{"type":"server/activate","payload":{"activities":[]}}"#.to_owned(),
        ),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (_recordings, sink) = recording_sink();
    let mut config = config_for(&server, syncspin_client::AudioMode::Passthrough);
    config.unpaired_access = false;
    let (handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect");
    expect_connected(&mut events, &server).await;
    let first = server
        .wait_for_client_hello()
        .await
        .expect("the first connection announces itself");
    assert!(
        !first.unpaired_access.enabled,
        "the first hello carries the configured value, so the second can prove the write"
    );

    server.close();
    match next_event(&mut events).await {
        Event::Disconnected { .. } => {}
        other => panic!("expected Disconnected, got {other:?}"),
    }
    handle
        .control()
        .set_unpaired_access(true)
        .await
        .expect("a change between connections is stored, not refused");

    let hello = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_hello())
        .await
        .expect("the client reconnects on its own")
        .expect("the second connection announces itself");
    assert!(
        hello.unpaired_access.enabled,
        "the reconnect wait must store the value the next hello advertises"
    );
    drop(handle);
}

#[tokio::test]
async fn off_then_on_ends_with_on() {
    // The default activation declares `playback` and carries roles, so turning the setting off
    // closes this session; the flip back on is queued and answered while the client waits.
    let mut server = FakeServer::start(ServerOptions {
        connections: 2,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (_recordings, sink) = recording_sink();
    let (mut events, handle) =
        connect_to(&server, syncspin_client::AudioMode::Passthrough, sink).await;
    expect_connected(&mut events, &server).await;
    let first = server
        .wait_for_client_hello()
        .await
        .expect("the first connection announces itself");
    assert!(
        first.unpaired_access.enabled,
        "the default configuration admits unpaired access, so the flip is what decides the second hello"
    );

    handle
        .control()
        .set_unpaired_access(false)
        .await
        .expect("the first change must be accepted");
    handle
        .control()
        .set_unpaired_access(true)
        .await
        .expect("the queued change must be answered between connections");

    assert_eq!(
        goodbye_from(&mut server).await.as_deref(),
        Some("pairing_required"),
        "the request in force when the relying session ended is the one that closed it"
    );
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("stopped admitting unpaired access"),
            "the close is the off change, not the queued on change, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }
    let hello = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_hello())
        .await
        .expect("the client reconnects after the close")
        .expect("the second connection announces itself");
    assert!(
        hello.unpaired_access.enabled,
        "the queued flip must win over the close it follows"
    );
    drop(handle);
}
