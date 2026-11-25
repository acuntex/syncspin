//! End-to-end tests of the Pairing PSK flow against the hermetic fake server.
//!
//! Every test binds one loopback port and runs the Noise initiator with `snow` on the server side,
//! exactly as `session_guest.rs` does. What is new here is the store: the client keeps its pairing
//! PSK and the record a pairing produces in an in-memory [`Storage`], which is the only thing that
//! makes the Pairing PSK method available at all.

#![cfg(all(feature = "player", feature = "controller", feature = "metadata"))]

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use syncspin_client::storage::Storage;
use syncspin_client::{
    connect, AudioMode, ClientConfig, ClientHandle, Event, EventStream, Identity, PairingFailure,
    PskCategory, Sink, StoredPsk, StreamEndReason, VolumePolicy, DEFAULT_PAIRING_TIMEOUT,
};
use syncspin_core::messages::{PairingActivation, ServerActivate};
use syncspin_core::noise::psk_id_for;

use fake_server::{FakeServer, Observation, ServerOptions};

/// An in-memory store, with switches that make its calls fail.
#[derive(Default)]
struct MemoryStorage {
    pairing: Mutex<Option<[u8; 32]>>,
    records: Mutex<Vec<StoredPsk>>,
    /// How often the client handed back a drawn pairing PSK.
    stored_pairing_psks: AtomicUsize,
    /// Whether reading the records fails.
    fail_load: bool,
    /// Whether writing a record fails.
    fail_store_record: bool,
}

impl MemoryStorage {
    /// A store that already holds `pairing`.
    fn holding(pairing: [u8; 32]) -> Arc<MemoryStorage> {
        Arc::new(MemoryStorage {
            pairing: Mutex::new(Some(pairing)),
            ..MemoryStorage::default()
        })
    }

    fn pairing_psk(&self) -> Option<[u8; 32]> {
        *self.pairing.lock().expect("the test lock is not poisoned")
    }

    fn records(&self) -> Vec<StoredPsk> {
        self.records
            .lock()
            .expect("the test lock is not poisoned")
            .clone()
    }

    fn stored_pairing_psks(&self) -> usize {
        self.stored_pairing_psks.load(Ordering::SeqCst)
    }
}

impl Storage for MemoryStorage {
    fn pairing_psk(&self) -> Result<Option<[u8; 32]>> {
        Ok(self.pairing_psk())
    }

    fn store_pairing_psk(&self, psk: &[u8; 32]) -> Result<()> {
        *self.pairing.lock().expect("the test lock is not poisoned") = Some(*psk);
        self.stored_pairing_psks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn load_pairings(&self) -> Result<Vec<StoredPsk>> {
        if self.fail_load {
            bail!("the store was told to fail");
        }
        Ok(self.records())
    }

    fn store_pairing(&self, record: StoredPsk) -> Result<()> {
        if self.fail_store_record {
            bail!("the store was told to fail");
        }
        let mut records = self.records.lock().expect("the test lock is not poisoned");
        records.retain(|held| held.server_id != record.server_id);
        records.push(record);
        Ok(())
    }

    fn remove_pairing(&self, server_id: &str) -> Result<()> {
        self.records
            .lock()
            .expect("the test lock is not poisoned")
            .retain(|record| record.server_id != server_id);
        Ok(())
    }
}

/// A sink that accepts every call and plays nothing.
struct NullSink;

impl Sink for NullSink {
    fn open(&mut self, _format: syncspin_client::AudioFormat) -> Result<()> {
        Ok(())
    }

    fn write(&mut self, _frame: syncspin_client::AudioFrame<'_>, _due: Instant) -> Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// One frame a recording sink received, with its playout deadline.
struct WrittenFrame {
    data: Vec<u8>,
    due: Instant,
}

/// What a recording sink saw, shared with the test that owns the assertion.
#[derive(Default)]
struct Recordings {
    opened: Mutex<Vec<syncspin_client::AudioFormat>>,
    written: Mutex<Vec<WrittenFrame>>,
    flushes: Mutex<usize>,
}

impl Recordings {
    fn opened(&self) -> usize {
        self.opened
            .lock()
            .expect("the recordings lock is poisoned")
            .len()
    }

    fn written(&self) -> Vec<(Vec<u8>, Instant)> {
        self.written
            .lock()
            .expect("the recordings lock is poisoned")
            .iter()
            .map(|frame| (frame.data.clone(), frame.due))
            .collect()
    }

    fn flushes(&self) -> usize {
        *self
            .flushes
            .lock()
            .expect("the recordings lock is poisoned")
    }
}

/// A sink that records frames instead of playing them.
struct RecordingSink {
    recordings: Arc<Recordings>,
}

impl Sink for RecordingSink {
    fn open(&mut self, format: syncspin_client::AudioFormat) -> Result<()> {
        self.recordings
            .opened
            .lock()
            .expect("the recordings lock is poisoned")
            .push(format);
        Ok(())
    }

    fn write(&mut self, frame: syncspin_client::AudioFrame<'_>, due: Instant) -> Result<()> {
        let data = match frame {
            syncspin_client::AudioFrame::Pcm(data) => data.to_vec(),
            syncspin_client::AudioFrame::Encoded { data, .. } => data.to_vec(),
        };
        self.recordings
            .written
            .lock()
            .expect("the recordings lock is poisoned")
            .push(WrittenFrame { data, due });
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        *self
            .recordings
            .flushes
            .lock()
            .expect("the recordings lock is poisoned") += 1;
        Ok(())
    }
}

/// Creates a recording sink and the record it writes to.
fn recording_sink() -> (Arc<Recordings>, Box<dyn Sink>) {
    let recordings = Arc::new(Recordings::default());
    (
        Arc::clone(&recordings),
        Box::new(RecordingSink { recordings }),
    )
}

/// Waits until the sink received at least `count` frames.
async fn wait_for_writes(recordings: &Recordings, count: usize) -> Vec<(Vec<u8>, Instant)> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let written = recordings.written();
        if written.len() >= count {
            return written;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {count} sink writes, saw {}",
            written.len()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Waits until the sink was opened at least once.
async fn wait_for_open(recordings: &Recordings) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while recordings.opened() == 0 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the sink to open"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Waits until the sink was flushed at least `count` times.
async fn wait_for_flushes(recordings: &Recordings, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while recordings.flushes() < count {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {count} sink flushes, saw {}",
            recordings.flushes()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Builds a configuration for `server` with the given store.
fn config_for(server: &FakeServer, storage: Option<Arc<dyn Storage>>) -> ClientConfig {
    ClientConfig {
        server: server.endpoint(),
        player_name: "Test player".to_owned(),
        device_info: None,
        identity: Identity::generate(),
        storage,
        audio_mode: AudioMode::Passthrough,
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

/// Connects to `server` with the given store and returns the events and the handle.
async fn connect_to(
    server: &FakeServer,
    storage: Option<Arc<dyn Storage>>,
) -> (EventStream, ClientHandle) {
    let (handle, events) = connect(config_for(server, storage), Box::new(NullSink))
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

/// Waits for the client's `client/hello`.
async fn wait_for_hello(server: &mut FakeServer) -> syncspin_core::messages::ClientHello {
    tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_hello())
        .await
        .expect("the fake server must see client/hello")
        .expect("the connection must not close before client/hello")
}

/// Server options that seal the handshake with `psk` as a pairing key.
fn pairing_options(psk: [u8; 32]) -> ServerOptions {
    ServerOptions {
        psk_id: psk_id_for(&psk),
        psk_category: "pr".to_owned(),
        psk,
        active_roles: Vec::new(),
        ..ServerOptions::default()
    }
}

/// The activation that admits a Pairing PSK attempt as the first activation of a connection.
fn pairing_activation() -> ServerActivate {
    ServerActivate {
        activities: vec!["pairing".to_owned()],
        active_roles: Some(Vec::new()),
        pairing: Some(PairingActivation {
            method: "pairing_psk".to_owned(),
            format: None,
        }),
    }
}

/// A JSON body for a message this harness only sends verbatim.
fn json(message: syncspin_core::messages::Incoming) -> String {
    serde_json::to_string(&message).expect("a control message encodes")
}

/// Asserts that the connection is still reconnecting instead of having ended.
async fn assert_still_reconnecting(handle: ClientHandle) {
    assert!(
        tokio::time::timeout(Duration::from_millis(200), handle.finished())
            .await
            .is_err(),
        "a transient failure must not end the connection"
    );
}

/// Drains observations up to and including the close of the current connection.
async fn wait_for_close(server: &mut FakeServer) {
    loop {
        match server.observation().await {
            Some(Observation::Closed) | None => return,
            Some(_) => continue,
        }
    }
}

#[tokio::test]
async fn a_client_without_a_store_does_not_offer_the_pairing_psk() {
    let mut server = FakeServer::start(ServerOptions {
        first_activate: Some(pairing_activation()),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server, None).await;
    expect_connected(&mut events, &server).await;

    let hello = wait_for_hello(&mut server).await;
    assert_eq!(
        hello.supported_pair_methods.pairing_psk, None,
        "a client that cannot pair must not advertise the method"
    );

    assert_eq!(
        next_event(&mut events).await,
        Event::PairingFailed {
            reason: PairingFailure::MethodNotSupported
        }
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pairing_abort())
            .await
            .expect("the client must send pair/abort")
            .as_deref(),
        Some("method_not_supported")
    );

    // An abort from the server after the client ended the attempt has no effect, and the
    // connection keeps serving.
    server.json(json(syncspin_core::messages::Incoming::PairAbort(
        syncspin_core::messages::PairAbort {
            reason: "user_cancelled".to_owned(),
        },
    )));
    server.activate(&["metadata@v1"]);
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("a pairing abort must not end the connection, got {other:?}"),
    }
}

#[tokio::test]
async fn a_client_with_a_store_offers_the_method_and_draws_one_key() {
    let storage = Arc::new(MemoryStorage::default());
    let mut server = FakeServer::start(ServerOptions {
        connections: 2,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage.clone())).await;
    expect_connected(&mut events, &server).await;

    let hello = wait_for_hello(&mut server).await;
    assert!(
        hello.supported_pair_methods.pairing_psk.is_some(),
        "a configured store makes the method available"
    );
    let drawn = storage
        .pairing_psk()
        .expect("the first run must draw and store a pairing PSK");
    assert_eq!(storage.stored_pairing_psks(), 1);
    assert_ne!(drawn, [0u8; 32]);

    // A reconnect restores the same key instead of drawing another one.
    server.close();
    expect_disconnected(&mut events).await;
    wait_for_close(&mut server).await;
    expect_connected(&mut events, &server).await;
    assert_eq!(
        storage.pairing_psk(),
        Some(drawn),
        "a pairing PSK is never rotated"
    );
    assert_eq!(
        storage.stored_pairing_psks(),
        1,
        "the second attempt must restore the key, not replace it"
    );
}

#[tokio::test]
async fn a_pairing_psk_names_the_first_activation_of_the_connection() {
    let pairing_psk = [0x3c; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions {
        first_activate: Some(pairing_activation()),
        ..pairing_options(pairing_psk)
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage)).await;
    expect_connected(&mut events, &server).await;

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pair_init())
            .await
            .expect("the client must send client/pair-init"),
        Some(1),
        "the first pairing activation of the connection is index 1"
    );
}

#[tokio::test]
async fn the_psk_flow_stores_one_record_and_pairs_the_next_connection() {
    let pairing_psk = [0x5a; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions {
        first_activate: Some(pairing_activation()),
        connections: 2,
        ..pairing_options(pairing_psk)
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage.clone())).await;
    expect_connected(&mut events, &server).await;

    // The client sends both messages back to back; the harness answers the finalize.
    let long_term_psk =
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pair_finalize())
            .await
            .expect("the client must send client/pair-finalize")
            .expect("the connection must not close before the finalize")
            .0;

    match next_event(&mut events).await {
        Event::Paired { server_id } => assert_eq!(server_id, server.server_id()),
        other => panic!("expected Paired, got {other:?}"),
    }
    let records = storage.records();
    assert_eq!(records.len(), 1, "one pairing produces exactly one record");
    assert_eq!(records[0].category, PskCategory::LongTerm);
    assert_eq!(
        records[0].psk, long_term_psk,
        "the record holds the key the client sent"
    );
    assert_eq!(records[0].server_id, server.server_id());
    assert_eq!(
        storage.pairing_psk(),
        Some(pairing_psk),
        "a successful pairing does not consume the pairing PSK"
    );

    // The pairing left the session alive: playback messages still arrive on it.
    server.activate(&["metadata@v1"]);
    server.metadata("After pairing", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "After pairing"),
        other => panic!("the session must stay usable after pairing, got {other:?}"),
    }

    // The server now announces the new key as a long-term key, which is what the next connection
    // has to authenticate with. A client that did not persist the record could not connect.
    server.close();
    expect_disconnected(&mut events).await;
    wait_for_close(&mut server).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_message_2())
            .await
            .expect("the second handshake must happen"),
        "the second connection must authenticate under the new long-term PSK"
    );
    expect_connected(&mut events, &server).await;
    let hello = wait_for_hello(&mut server).await;
    assert!(
        hello.supported_pair_methods.pairing_psk.is_some(),
        "the pairing method stays offered after a pairing"
    );
    server.activate(&["metadata@v1"]);
    server.metadata("Under the new keys", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Under the new keys"),
        other => panic!("the session must work under the new keys, got {other:?}"),
    }
}

/// The switch governs playback on a guest connection, not the pairing flow itself.
///
/// A device that has never paired is a guest, so refusing `['pairing']` here would leave it no way
/// to become paired: the setting would be a one-way door.
#[tokio::test]
async fn a_pairing_completes_with_unpaired_access_off() {
    let pairing_psk = [0x5b; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions {
        first_activate: Some(pairing_activation()),
        ..pairing_options(pairing_psk)
    })
    .await
    .unwrap();
    let mut config = config_for(&server, Some(storage.clone()));
    config.unpaired_access = false;
    let (_handle, mut events) = connect(config, Box::new(NullSink))
        .await
        .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    let long_term_psk =
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pair_finalize())
            .await
            .expect("the client must send client/pair-finalize")
            .expect("the connection must not close before the finalize")
            .0;

    let paired = match next_event(&mut events).await {
        Event::PairingRequired { .. } => {
            panic!("an activation that only declares pairing must not be refused by the setting")
        }
        Event::Paired { server_id } => server_id,
        other => panic!("expected Paired, got {other:?}"),
    };
    assert_eq!(paired, server.server_id());

    let records = storage.records();
    assert_eq!(records.len(), 1, "one pairing produces exactly one record");
    assert_eq!(records[0].category, PskCategory::LongTerm);
    assert_eq!(
        records[0].psk, long_term_psk,
        "the record holds the key the client sent"
    );
    assert_eq!(
        storage.pairing_psk(),
        Some(pairing_psk),
        "a successful pairing does not consume the pairing PSK"
    );
}

#[tokio::test]
async fn a_matched_sentinel_key_cannot_pair() {
    let pairing_psk = [0x11; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions {
        first_activate: Some(pairing_activation()),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage)).await;
    expect_connected(&mut events, &server).await;
    let hello = wait_for_hello(&mut server).await;
    assert!(
        hello.supported_pair_methods.pairing_psk.is_some(),
        "the method is offered, but this connection is not keyed by the pairing PSK"
    );

    // The guest connection is sealed with the published Sentinel key, so the pairing method is not
    // admissible even though this client offers it.
    assert_eq!(
        next_event(&mut events).await,
        Event::PairingFailed {
            reason: PairingFailure::MethodNotSupported
        }
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pairing_abort())
            .await
            .expect("the client must send pair/abort")
            .as_deref(),
        Some("method_not_supported")
    );
}

#[tokio::test]
async fn a_method_this_build_does_not_carry_is_aborted() {
    let pairing_psk = [0x22; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(pairing_options(pairing_psk))
        .await
        .unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage)).await;
    expect_connected(&mut events, &server).await;
    wait_for_hello(&mut server).await;

    server.activate_pairing("dynamic_pairing_code");
    assert_eq!(
        next_event(&mut events).await,
        Event::PairingFailed {
            reason: PairingFailure::MethodNotSupported
        }
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pairing_abort())
            .await
            .expect("the client must send pair/abort")
            .as_deref(),
        Some("method_not_supported")
    );
}

#[tokio::test]
async fn a_silent_server_times_the_attempt_out() {
    let pairing_psk = [0x77; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions {
        first_activate: Some(pairing_activation()),
        acknowledge_pairing: false,
        ..pairing_options(pairing_psk)
    })
    .await
    .unwrap();

    // The attempt timeout is two minutes by default; the test injects a short one instead of
    // waiting, and the deadline still runs from `client/pair-init`.
    let mut config = config_for(&server, Some(storage.clone()));
    config.pairing_timeout = Duration::from_millis(200);
    let (handle, mut events) = connect(config, Box::new(NullSink)).await.unwrap();
    expect_connected(&mut events, &server).await;
    tokio::time::timeout(Duration::from_secs(5), server.wait_for_pair_finalize())
        .await
        .expect("the client must send client/pair-finalize")
        .expect("the connection must not close before the finalize");

    assert_eq!(
        next_event(&mut events).await,
        Event::PairingFailed {
            reason: PairingFailure::AttemptTimeout
        }
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pairing_abort())
            .await
            .expect("the client must send pair/abort")
            .as_deref(),
        Some("attempt_timeout")
    );
    assert!(
        storage.records().is_empty(),
        "a timed-out attempt must persist nothing"
    );

    // The abort ends the attempt, not the connection.
    server.activate(&["metadata@v1"]);
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("a timeout must leave the session alive, got {other:?}"),
    }
    assert_still_reconnecting(handle).await;
}

#[tokio::test]
async fn a_cancelling_activation_persists_nothing() {
    let pairing_psk = [0x66; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions {
        first_activate: Some(pairing_activation()),
        acknowledge_pairing: false,
        ..pairing_options(pairing_psk)
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage.clone())).await;
    expect_connected(&mut events, &server).await;
    tokio::time::timeout(Duration::from_secs(5), server.wait_for_pair_finalize())
        .await
        .expect("the client must send client/pair-finalize")
        .expect("the connection must not close before the finalize");

    // The server ends the transition in place of `server/pair-finalize`.
    server.cancel_pairing(&["metadata@v1"]);
    // A finalize that arrives afterwards is a message from an attempt the client already discarded.
    server.json(json(syncspin_core::messages::Incoming::ServerPairFinalize(
        syncspin_core::messages::ServerPairFinalize {},
    )));
    server.metadata("Still here", "An artist");

    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(
            title, "Still here",
            "the cancellation must leave the connection serving"
        ),
        other => panic!("expected Track, got {other:?}"),
    }
    assert!(
        storage.records().is_empty(),
        "a cancelling server/activate must persist nothing"
    );
}

#[tokio::test]
async fn a_server_abort_ends_the_attempt_with_its_reason() {
    let pairing_psk = [0x44; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions {
        first_activate: Some(pairing_activation()),
        acknowledge_pairing: false,
        ..pairing_options(pairing_psk)
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage.clone())).await;
    expect_connected(&mut events, &server).await;
    tokio::time::timeout(Duration::from_secs(5), server.wait_for_pair_finalize())
        .await
        .expect("the client must send client/pair-finalize")
        .expect("the connection must not close before the finalize");

    server.json(json(syncspin_core::messages::Incoming::PairAbort(
        syncspin_core::messages::PairAbort {
            reason: "user_cancelled".to_owned(),
        },
    )));
    assert_eq!(
        next_event(&mut events).await,
        Event::PairingFailed {
            reason: PairingFailure::UserCancelled
        }
    );
    assert!(
        storage.records().is_empty(),
        "an aborted attempt must persist nothing"
    );
}

#[tokio::test]
async fn a_record_the_store_refuses_ends_the_session_with_an_error() {
    let pairing_psk = [0x88; 32];
    let storage = Arc::new(MemoryStorage {
        pairing: Mutex::new(Some(pairing_psk)),
        fail_store_record: true,
        ..MemoryStorage::default()
    });
    let server = FakeServer::start(ServerOptions {
        first_activate: Some(pairing_activation()),
        ..pairing_options(pairing_psk)
    })
    .await
    .unwrap();
    let (mut events, handle) = connect_to(&server, Some(storage)).await;
    expect_connected(&mut events, &server).await;

    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("pairing record"),
            "the refusal must name the record, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }
    assert_still_reconnecting(handle).await;
}

#[tokio::test]
async fn a_store_that_cannot_be_read_never_falls_back_to_the_sentinel_key() {
    let storage = Arc::new(MemoryStorage {
        pairing: Mutex::new(Some([0x99; 32])),
        fail_load: true,
        ..MemoryStorage::default()
    });
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (mut events, handle) = connect_to(&server, Some(storage)).await;

    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("records"),
            "the read failure must name the records, got: {reason}"
        ),
        other => panic!("expected Disconnected before any connection, got {other:?}"),
    }
    assert_still_reconnecting(handle).await;
}

#[tokio::test]
async fn a_pairing_activity_without_parameters_ends_the_attempt_with_an_error() {
    let pairing_psk = [0x12; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let server = FakeServer::start(ServerOptions {
        // A pairing activity without its object is malformed, not an attempt with defaults.
        first_activate: Some(ServerActivate {
            activities: vec!["pairing".to_owned()],
            active_roles: Some(Vec::new()),
            pairing: None,
        }),
        ..pairing_options(pairing_psk)
    })
    .await
    .unwrap();
    let (mut events, handle) = connect_to(&server, Some(storage)).await;
    expect_connected(&mut events, &server).await;

    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("pairing parameters"),
            "the malformed activation must be named, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }
    assert_still_reconnecting(handle).await;
}

#[tokio::test]
async fn a_malformed_pairing_message_is_a_protocol_error() {
    let pairing_psk = [0x34; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(pairing_options(pairing_psk))
        .await
        .unwrap();
    let (mut events, handle) = connect_to(&server, Some(storage.clone())).await;
    expect_connected(&mut events, &server).await;

    // `server/pair-confirm` without its tag cannot be acted on, and the spec makes a malformed
    // pairing field a protocol error: the client closes without an application-level message and
    // persists nothing.
    server.json(r#"{"type":"server/pair-confirm","payload":{}}"#.to_owned());
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => {
            assert!(
                reason.contains("malformed"),
                "the reason must name the malformed message, got: {reason}"
            );
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pairing_abort())
            .await
            .expect("the fake server must notice the close"),
        None,
        "a protocol error must not send pair/abort"
    );
    assert!(
        storage.records().is_empty(),
        "a malformed pairing message must persist nothing"
    );
    assert_still_reconnecting(handle).await;
}

/// Waits for the client's first `client/state`, which follows its first clock measurement.
async fn wait_for_client_state(server: &mut FakeServer) {
    tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_state())
        .await
        .expect("the client must report its state")
        .expect("the connection must not close before the state report");
}

/// The CPace session id of a pairing attempt: the label, the handshake hash and two indexes.
///
/// `pairing.md` defines `sid` as `"sendspin-pair-pake-v1" || h || pairing_index || round`, all raw.
/// A re-handshake mixes in a new `h` and resets the index, so the `sid` of the next attempt differs.
fn pake_sid(handshake_hash: &[u8; 32], pairing_index: u32, round: u32) -> Vec<u8> {
    let mut sid = Vec::from(b"sendspin-pair-pake-v1".as_slice());
    sid.extend_from_slice(handshake_hash);
    sid.extend_from_slice(&pairing_index.to_be_bytes());
    sid.extend_from_slice(&round.to_be_bytes());
    sid
}

/// Current wall clock in microseconds since the Unix epoch, the domain of server timestamps.
fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros() as i64)
        .unwrap_or(0)
}

#[tokio::test]
async fn audio_survives_a_rehandshake_mid_stream() {
    let pairing_psk = [0x2b; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (recordings, sink) = recording_sink();
    let (handle, mut events) = connect(config_for(&server, Some(storage)), sink)
        .await
        .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    // A usable clock estimate needs three bursts; the 24 replies are ordered before the audio.
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
    server.audio(now_us() + 250_000, 250_000, vec![0x11; 64]);
    let written = wait_for_writes(&recordings, 1).await;
    assert_eq!(written[0].0, vec![0x11; 64]);
    assert!(
        written[0].1 >= started + Duration::from_millis(100),
        "the frame before the swap must be scheduled from the clock estimate, got {:?}",
        written[0].1 - started
    );

    // The server rotates the live connection to the pairing PSK, mid-stream, and activates under
    // the new keys. Nothing about the stream or the clock may change with the keys.
    let flushes_before = recordings.flushes();
    server.rehandshake(pairing_psk, "pr");
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_rehandshake())
            .await
            .expect("the client must answer the re-handshake"),
        "the re-handshake must complete instead of closing"
    );

    let started = Instant::now();
    server.audio(now_us() + 250_000, 250_000, vec![0x22; 64]);
    let written = wait_for_writes(&recordings, 2).await;
    assert_eq!(
        written[1].0,
        vec![0x22; 64],
        "audio must arrive again under the new keys"
    );
    assert!(
        written[1].1 >= started + Duration::from_millis(100),
        "the clock estimate must survive the key swap, got {:?}",
        written[1].1 - started
    );
    assert_eq!(
        recordings.opened(),
        1,
        "a key swap must not reopen the stream"
    );
    assert_eq!(
        recordings.flushes(),
        flushes_before,
        "a key swap must not drop buffered audio"
    );
    assert_still_reconnecting(handle).await;
}

#[tokio::test]
async fn a_pairing_after_a_rehandshake_uses_index_one() {
    let pairing_psk = [0x6c; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage)).await;
    expect_connected(&mut events, &server).await;
    wait_for_hello(&mut server).await;

    // The first pairing activation of this handshake is not admissible, because the connection is
    // Sentinel-keyed; it ends in an abort, but it still advances the pairing index to 1. The
    // activation clears the roles as well, so the (empty) player stream ends on the way.
    server.activate_pairing("pairing_psk");
    loop {
        match next_event(&mut events).await {
            Event::PairingFailed { reason } => {
                assert_eq!(reason, PairingFailure::MethodNotSupported);
                break;
            }
            Event::StreamEnd { .. } => continue,
            other => panic!("expected PairingFailed, got {other:?}"),
        }
    }
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pairing_abort())
            .await
            .expect("the client must answer the activation")
            .as_deref(),
        Some("method_not_supported")
    );

    let hashes_before = server.handshake_hashes();
    server.rehandshake(pairing_psk, "pr");
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_rehandshake())
            .await
            .expect("the client must answer the re-handshake"),
        "the re-handshake must complete instead of closing"
    );
    let hashes_after = server.handshake_hashes();
    assert_eq!(
        hashes_before.len(),
        1,
        "one handshake happened before the swap"
    );
    assert_eq!(hashes_after.len(), 2, "the swap is a second handshake");

    // The index counts pairing activations since the last handshake, so this is index 1 again
    // even though the connection already saw one before the swap (it would be 2 without the
    // reset).
    server.activate_pairing("pairing_psk");
    let pairing_index = tokio::time::timeout(Duration::from_secs(5), server.wait_for_pair_init())
        .await
        .expect("the client must start the pairing attempt")
        .expect("the connection must not close before client/pair-init");
    assert_eq!(pairing_index, 1, "a re-handshake resets the pairing index");

    // The CPace `sid` mixes in `h` and the pairing index; both differ from the first handshake.
    assert_ne!(
        hashes_before[0], hashes_after[1],
        "a new handshake must produce a new `h` for the `sid`"
    );
    assert_ne!(
        pake_sid(&hashes_before[0], 0, 1),
        pake_sid(&hashes_after[1], pairing_index, 1),
        "the `sid` of an attempt after a re-handshake must differ from index 0"
    );
}

#[tokio::test]
async fn a_rehandshake_to_an_unknown_key_closes_without_a_second_message() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    // No store and no host records: the announced key of the new handshake is a lookup miss.
    let (mut events, handle) = connect_to(&server, None).await;
    expect_connected(&mut events, &server).await;
    wait_for_hello(&mut server).await;

    // A miss during a re-handshake fails it: there is no Sentinel fallback once the connection is
    // authenticated, and the close carries no message of its own.
    server.rehandshake([0x4d; 32], "lt");
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("re-handshake"),
            "the reason must name the refused re-handshake, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }
    match tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match server.observation().await {
                Some(Observation::RehandshakeMessage2) => break false,
                Some(Observation::ClosedBeforeMessage2) | Some(Observation::Closed) | None => {
                    break true
                }
                Some(_) => continue,
            }
        }
    })
    .await
    .expect("the fake server must notice the close")
    {
        true => {}
        false => panic!("the client must not answer a re-handshake whose key it does not hold"),
    }
    assert_still_reconnecting(handle).await;
}

#[tokio::test]
async fn a_message_under_the_previous_keys_is_discarded() {
    let pairing_psk = [0x3d; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions {
        stale_message_on_rehandshake: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage)).await;
    expect_connected(&mut events, &server).await;
    wait_for_hello(&mut server).await;

    server.rehandshake(pairing_psk, "pr");
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_rehandshake())
            .await
            .expect("the client must answer the re-handshake"),
        "a frame under the previous keys must not end the connection"
    );

    // The frame the harness sent between message 1 and its message 2 carried the previous keys and
    // arrived before the activation; acting on it would report a track the new session never sent.
    server.metadata("Under the new keys", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(
            title, "Under the new keys",
            "a message under the previous keys must be discarded, not delivered"
        ),
        other => panic!("expected Track, got {other:?}"),
    }
}

#[tokio::test]
async fn a_rehandshake_to_the_pairing_psk_removes_the_player_role() {
    // A paired client with unpaired access off. The server re-handshakes to the pairing PSK to
    // upgrade the pairing, then activates `[]` with no `active_roles` - admissible, but not
    // playback-capable, so the roles of the previous keys are dropped instead of the connection
    // closed.
    let long_term: [u8; 32] = std::array::from_fn(|index| (index as u8) ^ 0x6b);
    let pairing_psk = [0x3d; 32];
    let options = ServerOptions {
        psk_id: psk_id_for(&long_term),
        psk_category: "lt".to_owned(),
        psk: long_term,
        rehandshake_activate: Some(ServerActivate {
            activities: Vec::new(),
            active_roles: None,
            pairing: None,
        }),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (recordings, sink) = recording_sink();
    let storage = Arc::new(MemoryStorage {
        pairing: Mutex::new(Some(pairing_psk)),
        records: Mutex::new(vec![StoredPsk {
            category: PskCategory::LongTerm,
            psk: long_term,
            server_id: server.server_id().to_owned(),
        }]),
        ..MemoryStorage::default()
    });
    let mut config = config_for(&server, Some(storage));
    config.unpaired_access = false;
    let (_handle, mut events) = connect(config, sink)
        .await
        .expect("the client must connect");

    expect_connected(&mut events, &server).await;
    // Roles are active: the sink opens for the paired session.
    server.stream_start("pcm", 48_000, 2, 16);
    assert!(matches!(
        next_event(&mut events).await,
        Event::StreamStart { .. }
    ));
    wait_for_open(&recordings).await;

    // Losing the player role must not leave the audio it buffered audible, and the flush is what
    // the clearing in `apply_activate` buys.
    let flushes_before = recordings.flushes();
    server.rehandshake(pairing_psk, "pr");
    assert!(
        server.wait_for_rehandshake().await,
        "the client must accept the new keys"
    );
    match next_event(&mut events).await {
        Event::StreamEnd { reason } => assert_eq!(reason, StreamEndReason::RoleRemoved),
        other => panic!("expected StreamEnd(RoleRemoved), got {other:?}"),
    }
    wait_for_flushes(&recordings, flushes_before + 1).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), server.wait_for_goodbye())
            .await
            .is_err(),
        "a re-pairing transition must not be closed by the switch"
    );
}

#[tokio::test]
async fn a_flip_during_a_rehandshake_is_refused() {
    // The server rotates the live connection to the pairing PSK - the flow a pairing finishes with -
    // and holds the activation that must follow, so the window in which the client may send nothing
    // stays open long enough for the host to try a change inside it.
    let pairing_psk = [0x4e; 32];
    let storage = MemoryStorage::holding(pairing_psk);
    let mut server = FakeServer::start(ServerOptions {
        hold_rehandshake_activate: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, handle) = connect_to(&server, Some(storage)).await;
    expect_connected(&mut events, &server).await;
    wait_for_hello(&mut server).await;

    server.rehandshake(pairing_psk, "pr");
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_rehandshake())
            .await
            .expect("the client must answer the re-handshake"),
        "the re-handshake must complete its Noise messages"
    );

    let error = handle
        .control()
        .set_unpaired_access(false)
        .await
        .expect_err("a change during a key switch must be refused");
    assert!(
        format!("{error:#}").contains("switching keys"),
        "the refusal must name the re-handshake, got: {error:#}"
    );

    // The refusal is answered before the value is touched, so the unpaired relying session is still
    // the one in force. Releasing the activation lets it carry on and the client's window is five
    // seconds, so the release comes here rather than after any further assertion.
    server.release_rehandshake_activate();
    server.metadata("After the refusal", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(
            title, "After the refusal",
            "the refused change must leave the session serving"
        ),
        other => panic!("expected Track after the key switch, got {other:?}"),
    }

    // Nothing was written by the refused call, so the retry applies the value and closes the relying
    // session instead of finding the change already in force and doing nothing.
    handle
        .control()
        .set_unpaired_access(false)
        .await
        .expect("the retry after the key switch must be accepted");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_goodbye())
            .await
            .expect("the client must say goodbye"),
        Some("pairing_required".to_owned()),
        "the retry turns off the setting the refusal left in force"
    );
    assert_still_reconnecting(handle).await;
}

/// Waits for the [`Event::Disconnected`] that ends an attempt.
async fn expect_disconnected(stream: &mut EventStream) {
    match next_event(stream).await {
        Event::Disconnected { .. } => {}
        other => panic!("expected Disconnected, got {other:?}"),
    }
}
