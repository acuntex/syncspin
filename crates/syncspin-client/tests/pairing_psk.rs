//! End-to-end tests of the Pairing PSK flow against the hermetic fake server.
//!
//! Every test binds one loopback port and runs the Noise initiator with `snow` on the server side,
//! exactly as `session_guest.rs` does. What is new here is the store: the client keeps its pairing
//! PSK and the record a pairing produces in an in-memory [`Storage`], which is the only thing that
//! makes the Pairing PSK method available at all.

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use syncspin_client::storage::Storage;
use syncspin_client::{
    connect, AudioMode, ClientConfig, ClientHandle, Event, EventStream, Identity, PairingFailure,
    PskCategory, Sink, StoredPsk, VolumePolicy, DEFAULT_PAIRING_TIMEOUT,
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
        pairing_timeout: DEFAULT_PAIRING_TIMEOUT,
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

/// Waits for the [`Event::Disconnected`] that ends an attempt.
async fn expect_disconnected(stream: &mut EventStream) {
    match next_event(stream).await {
        Event::Disconnected { .. } => {}
        other => panic!("expected Disconnected, got {other:?}"),
    }
}
