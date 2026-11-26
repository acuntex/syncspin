//! End-to-end tests of the Static Pairing Code flow against the hermetic fake server.
//!
//! The connection is Sentinel-keyed, as `pairing.md` describes for a code-based pairing: nothing is
//! authenticated until the CPace round completes. The fake server runs the CPace initiator (the
//! server) side, derives the same generator from the code, verifies the client's key-confirmation
//! tag and only then unwraps the long-term PSK it received sealed.
//!
//! What the tests decide: the window gates every attempt, the flow takes one round, a failed
//! `server_kc` aborts without a retry, the fifth failure closes the window, and the delivered key is
//! a record under the server's id.

#![cfg(all(
    feature = "pairing-code",
    feature = "player",
    feature = "controller",
    feature = "metadata"
))]

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use syncspin_client::storage::Storage;
use syncspin_client::{
    connect, AudioMode, ClientConfig, Event, EventStream, Identity, PairingFailure, PskCategory,
    Sink, StoredPsk, VolumePolicy, DEFAULT_PAIRING_TIMEOUT, DEFAULT_PAIRING_WINDOW,
};
use syncspin_core::messages::{PairingActivation, ServerActivate};

use fake_server::{FakeServer, ServerOptions};

/// The code the client is configured with.
const CODE: &str = "12345678";

/// The code an operator typed into the server, which therefore derives a different generator.
const WRONG_CODE: &str = "87654321";

/// An in-memory store, with switches that make its calls fail.
#[derive(Default)]
struct MemoryStorage {
    pairing: Mutex<Option<[u8; 32]>>,
    records: Mutex<Vec<StoredPsk>>,
}

impl MemoryStorage {
    fn records(&self) -> Vec<StoredPsk> {
        self.records
            .lock()
            .expect("the test lock is not poisoned")
            .clone()
    }
}

impl Storage for MemoryStorage {
    fn pairing_psk(&self) -> Result<Option<[u8; 32]>> {
        Ok(*self.pairing.lock().expect("the test lock is not poisoned"))
    }

    fn store_pairing_psk(&self, psk: &[u8; 32]) -> Result<()> {
        *self.pairing.lock().expect("the test lock is not poisoned") = Some(*psk);
        Ok(())
    }

    fn load_pairings(&self) -> Result<Vec<StoredPsk>> {
        Ok(self.records())
    }

    fn store_pairing(&self, record: StoredPsk) -> Result<()> {
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

/// The activation that admits a static pairing attempt as the first of a connection.
fn static_activation() -> ServerActivate {
    ServerActivate {
        activities: vec!["pairing".to_owned()],
        active_roles: Some(Vec::new()),
        pairing: Some(PairingActivation {
            method: "static_pairing_code".to_owned(),
            format: None,
        }),
    }
}

/// Builds a configuration for `endpoint` with the given store.
///
/// The pairing PSK is irrelevant to the code flow, but a store is what makes a record persist, so
/// most tests pass one to observe the delivered key.
fn config_for(endpoint: &str, storage: Option<Arc<dyn Storage>>) -> ClientConfig {
    ClientConfig {
        server: endpoint.to_owned(),
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
        static_pairing_code: Some(CODE.to_owned()),
        pairing_window: DEFAULT_PAIRING_WINDOW,
        pairing_pending_text: None,
        #[cfg(feature = "pairing-code")]
        code_formats: Vec::new(),
        #[cfg(feature = "pairing-code")]
        code_out_channels: Vec::new(),
        #[cfg(feature = "artwork")]
        artwork_channels: Vec::new(),
        #[cfg(feature = "artwork")]
        max_artwork_bytes: syncspin_client::DEFAULT_MAX_ARTWORK_BYTES,
    }
}

/// Server options whose connection admits a static-code attempt with `code` as the operator's.
fn static_options(code: &str) -> ServerOptions {
    ServerOptions {
        first_activate: Some(static_activation()),
        static_pairing_code: Some(code.to_owned()),
        ..ServerOptions::default()
    }
}

/// Connects to `server` with the given store and returns the events and the handle.
async fn connect_to(
    server: &FakeServer,
    storage: Option<Arc<dyn Storage>>,
) -> (EventStream, syncspin_client::ClientHandle) {
    let (handle, events) = connect(config_for(&server.endpoint(), storage), Box::new(NullSink))
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

/// Waits for one observation with the default timeout, or `None` when the connection ended.
async fn observed<F>(future: F) -> Option<F::Output>
where
    F: std::future::Future,
{
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .ok()
}

#[tokio::test]
async fn a_gesture_without_a_connection_is_an_error() {
    // Nothing listens on the loopback port, so the attempt fails at once and the client waits
    // between attempts: there is no session for a window to belong to.
    let (handle, _events) = connect(config_for("127.0.0.1:1", None), Box::new(NullSink))
        .await
        .expect("an unreachable server is reported through the event stream");

    let error = handle
        .control()
        .open_pairing_window()
        .await
        .expect_err("a gesture without a connection must be refused");
    assert!(
        format!("{error:#}").contains("no connection"),
        "the error must say no connection is established, got: {error:#}"
    );
}

#[tokio::test]
async fn a_window_runs_one_round_and_persists_the_wrapped_key() {
    let storage = Arc::new(MemoryStorage::default());
    let mut server = FakeServer::start(static_options(CODE)).await.unwrap();
    let (mut events, handle) = connect_to(&server, Some(storage.clone())).await;
    expect_connected(&mut events, &server).await;

    let hello = wait_for_hello(&mut server).await;
    assert!(
        hello.supported_pair_methods.static_pairing_code.is_some(),
        "a configured code makes the method available"
    );

    // No window yet: the client holds the attempt back instead of starting it.
    let (index, message) = observed(server.wait_for_pair_pending())
        .await
        .expect("the client must report the held-back attempt")
        .expect("the connection must not close before client/pair-pending");
    assert_eq!(index, 1, "the first pairing activation of the connection");
    assert_eq!(message, None, "without host text the message carries none");

    handle
        .control()
        .open_pairing_window()
        .await
        .expect("the live connection accepts the gesture");
    assert_eq!(
        observed(server.wait_for_pair_init())
            .await
            .expect("the client must start the attempt once the window is open"),
        Some(1),
        "the pending activation's index reaches client/pair-init"
    );

    let share = observed(server.wait_for_pair_auth())
        .await
        .expect("the client must answer server/pair-auth")
        .expect("the connection must not close before client/pair-auth");
    assert_eq!(share.len(), 43, "a CPace share is 32 bytes in base64url");

    let tag = observed(server.wait_for_pair_confirm())
        .await
        .expect("the client must send client/pair-confirm")
        .expect("the connection must not close before client/pair-confirm");
    assert_eq!(tag.len(), 86, "an MCF tag is 64 bytes in base64url");

    // The harness only records a key it unwrapped from `wrapped_psk` under `K_wrap`, so a value
    // here is proof that the seal opened with the server's own CPace output.
    let delivered = observed(server.wait_for_pair_finalize())
        .await
        .expect("the client must send client/pair-finalize")
        .expect("the connection must not close before client/pair-finalize");

    // The record is written only after `server/pair-finalize`, which the harness sends next; the
    // event is the client's confirmation that the write happened.
    match next_event(&mut events).await {
        Event::Paired { server_id } => assert_eq!(server_id, server.server_id()),
        other => panic!("expected Paired, got {other:?}"),
    }
    let records = storage.records();
    assert_eq!(records.len(), 1, "one pairing produces exactly one record");
    assert_eq!(records[0].category, PskCategory::LongTerm);
    assert_eq!(
        records[0].psk, delivered.0,
        "the record holds the key the server unwrapped"
    );
    assert_eq!(records[0].server_id, server.server_id());

    // One round, no retry: the client sends no second share for this attempt.
    assert!(
        tokio::time::timeout(Duration::from_millis(150), server.wait_for_pair_auth())
            .await
            .is_err(),
        "the static flow runs a single PAKE round"
    );

    // The session stays usable after the pairing.
    server.activate(&["metadata@v1"]);
    server.metadata("After pairing", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "After pairing"),
        other => panic!("the session must stay usable after pairing, got {other:?}"),
    }
}

#[tokio::test]
async fn a_pending_message_carries_the_hosts_text() {
    let mut server = FakeServer::start(static_options(CODE)).await.unwrap();
    let mut config = config_for(&server.endpoint(), Some(Arc::new(MemoryStorage::default())));
    config.pairing_pending_text = Some("Press the button".to_owned());
    let (_handle, mut events) = connect(config, Box::new(NullSink)).await.unwrap();
    expect_connected(&mut events, &server).await;

    let (_index, message) = observed(server.wait_for_pair_pending())
        .await
        .expect("the client must report the held-back attempt")
        .expect("the connection must not close before client/pair-pending");
    assert_eq!(
        message.as_deref(),
        Some("Press the button"),
        "the host's sentence is what the operator sees"
    );

    // The held-back attempt starts no timeout and reports nothing: it has not begun.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), events.next())
            .await
            .is_err(),
        "a held-back attempt must not time out or report a pairing event"
    );
}

#[tokio::test]
async fn a_flip_during_a_static_code_attempt_closes_a_relying_session() {
    // The activation declares `playback`, `pairing` and the player role, so the session carries
    // roles and has declared playback: it relies on unpaired access while the attempt is held back.
    let mut server = FakeServer::start(ServerOptions {
        first_activate: Some(ServerActivate {
            activities: vec!["playback".to_owned(), "pairing".to_owned()],
            active_roles: Some(vec!["player@v1".to_owned()]),
            pairing: Some(PairingActivation {
                method: "static_pairing_code".to_owned(),
                format: None,
            }),
        }),
        static_pairing_code: Some(CODE.to_owned()),
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, handle) = connect_to(&server, Some(Arc::new(MemoryStorage::default()))).await;
    expect_connected(&mut events, &server).await;

    let (index, _message) = observed(server.wait_for_pair_pending())
        .await
        .expect("the client must report the held-back attempt")
        .expect("the connection must not close before client/pair-pending");
    assert_eq!(index, 1, "the first pairing activation of the connection");

    handle
        .control()
        .set_unpaired_access(false)
        .await
        .expect("the live change must be accepted");

    assert_eq!(
        observed(server.wait_for_goodbye())
            .await
            .expect("the client must say goodbye")
            .as_deref(),
        Some("pairing_required"),
        "a held-back pairing does not stop a relying session from closing"
    );
    drop(handle);
}

#[tokio::test]
async fn a_wrong_server_code_aborts_with_a_mismatch() {
    let storage = Arc::new(MemoryStorage::default());
    let mut server = FakeServer::start(static_options(WRONG_CODE)).await.unwrap();
    let (mut events, handle) = connect_to(&server, Some(storage.clone())).await;
    expect_connected(&mut events, &server).await;

    let _ = observed(server.wait_for_pair_pending())
        .await
        .expect("the client must report the held-back attempt");
    handle
        .control()
        .open_pairing_window()
        .await
        .expect("the live connection accepts the gesture");
    assert_eq!(
        observed(server.wait_for_pair_init())
            .await
            .expect("the client must start the attempt"),
        Some(1)
    );

    // The server derives everything from the code the operator typed; the client's tag verifies and
    // the server's does not. A failed `server_kc` ends the attempt: no retry, no record.
    assert_eq!(
        observed(server.wait_for_pairing_abort())
            .await
            .expect("the client must abort the attempt")
            .as_deref(),
        Some("pairing_code_mismatch")
    );
    assert_eq!(
        next_event(&mut events).await,
        Event::PairingFailed {
            reason: PairingFailure::PairingCodeMismatch
        }
    );
    assert!(
        storage.records().is_empty(),
        "a failed key confirmation must persist nothing"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), server.wait_for_pair_confirm())
            .await
            .is_err(),
        "a failed server tag must not release the client's tag"
    );

    // The abort ends the attempt, not the connection.
    server.activate(&["metadata@v1"]);
    server.metadata("Still here", "An artist");
    match next_event(&mut events).await {
        Event::Track { title, .. } => assert_eq!(title, "Still here"),
        other => panic!("the session must stay alive after a mismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn five_failed_confirmations_close_the_window() {
    let storage = Arc::new(MemoryStorage::default());
    let mut server = FakeServer::start(static_options(WRONG_CODE)).await.unwrap();
    let (mut events, handle) = connect_to(&server, Some(storage.clone())).await;
    expect_connected(&mut events, &server).await;

    let _ = observed(server.wait_for_pair_pending())
        .await
        .expect("the client must report the held-back attempt");
    handle
        .control()
        .open_pairing_window()
        .await
        .expect("the live connection accepts the gesture");

    for failure in 1..=5u32 {
        assert_eq!(
            observed(server.wait_for_pair_init())
                .await
                .expect("the window admits each attempt"),
            Some(failure),
            "activation {failure} of this connection"
        );
        assert_eq!(
            observed(server.wait_for_pairing_abort())
                .await
                .expect("each failed confirmation ends its attempt")
                .as_deref(),
            Some("pairing_code_mismatch")
        );
        assert_eq!(
            next_event(&mut events).await,
            Event::PairingFailed {
                reason: PairingFailure::PairingCodeMismatch
            }
        );
        if failure < 5 {
            server.activate_pairing("static_pairing_code");
        }
    }

    // The fifth failure closed the window: a sixth activation is held back and starts nothing.
    server.activate_pairing("static_pairing_code");
    let (index, _message) = observed(server.wait_for_pair_pending())
        .await
        .expect("the client must report the held-back attempt")
        .expect("the connection must not close");
    assert_eq!(index, 6, "the activation after the fifth failure");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server.wait_for_pair_init())
            .await
            .is_err(),
        "a closed window withholds client/pair-init"
    );

    // A new deliberate gesture opens a new window and admits the held-back activation.
    handle
        .control()
        .open_pairing_window()
        .await
        .expect("a second gesture opens a second window");
    assert_eq!(
        observed(server.wait_for_pair_init())
            .await
            .expect("the new window admits the pending activation"),
        Some(6)
    );
}

#[tokio::test]
async fn a_pair_auth_without_an_attempt_is_a_sequence_violation() {
    let storage = Arc::new(MemoryStorage::default());
    let mut server = FakeServer::start(static_options(CODE)).await.unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage.clone())).await;
    expect_connected(&mut events, &server).await;

    // The window is closed, so the activation waits as `client/pair-pending`: no attempt exists,
    // and a `server/pair-auth` now is out of sequence rather than something to discard.
    let _ = observed(server.wait_for_pair_pending())
        .await
        .expect("the client must report the held-back attempt");

    server.json(
        serde_json::json!({
            "type": "server/pair-auth",
            "payload": {"pake_msg_1": "A".repeat(43)},
        })
        .to_string(),
    );
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("without an active pairing attempt"),
            "the reason must name the sequence violation, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pairing_abort())
            .await
            .expect("the fake server must notice the close"),
        None,
        "a sequence violation must not send pair/abort"
    );
    assert!(
        storage.records().is_empty(),
        "a rejected pairing message must persist nothing"
    );
}

#[tokio::test]
async fn a_static_activation_without_a_configured_code_is_aborted() {
    let mut server = FakeServer::start(static_options(CODE)).await.unwrap();
    let mut config = config_for(&server.endpoint(), None);
    config.static_pairing_code = None;
    let (_handle, mut events) = connect(config, Box::new(NullSink)).await.unwrap();
    expect_connected(&mut events, &server).await;

    assert_eq!(
        next_event(&mut events).await,
        Event::PairingFailed {
            reason: PairingFailure::MethodNotSupported
        }
    );
    assert_eq!(
        observed(server.wait_for_pairing_abort())
            .await
            .expect("the client must answer the activation")
            .as_deref(),
        Some("method_not_supported")
    );
}
