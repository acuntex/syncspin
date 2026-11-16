//! End-to-end tests of the record lifecycle: `server/unpair` and the credential-mismatch signal.
//!
//! Both concern a paired client whose server dropped its side of the pairing. `server/unpair` is
//! the server saying so, and the client removes the record and closes. A `psk_id` the client does
//! not hold is the same situation seen from the handshake: the server still has a record, the
//! client does not, and the client has to tell its operator instead of silently becoming a guest.
//!
//! Everything runs against the hermetic fake server in `fake_server.rs`: one loopback port, the
//! Noise initiator played with `snow`, no audio device.

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use syncspin_client::storage::Storage;
use syncspin_client::{
    connect, AudioMode, ClientConfig, Event, EventStream, Identity, PairingRequiredReason,
    PskCategory, Sink, StoredPsk, VolumePolicy, DEFAULT_PAIRING_TIMEOUT,
};
use syncspin_core::messages::{Incoming, PairingActivation, ServerActivate, ServerUnpair};
use syncspin_core::noise::{psk_id_for, SENTINEL_PSK};

use fake_server::{FakeServer, Observation, ServerOptions};

/// An in-memory store that records how often it was asked to drop a record.
#[derive(Default)]
struct MemoryStorage {
    pairing: Mutex<Option<[u8; 32]>>,
    records: Mutex<Vec<StoredPsk>>,
}

impl MemoryStorage {
    /// A store that already holds `pairing`.
    fn holding(pairing: [u8; 32]) -> Arc<MemoryStorage> {
        Arc::new(MemoryStorage {
            pairing: Mutex::new(Some(pairing)),
            ..MemoryStorage::default()
        })
    }

    /// A store that already holds `record`.
    fn with_record(record: StoredPsk) -> Arc<MemoryStorage> {
        let storage = MemoryStorage::default();
        storage
            .records
            .lock()
            .expect("the test lock is not poisoned")
            .push(record);
        Arc::new(storage)
    }

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

/// A store whose record removal fails, which no pairing record may survive silently.
struct FailingRemoval {
    records: Mutex<Vec<StoredPsk>>,
}

impl Storage for FailingRemoval {
    fn pairing_psk(&self) -> Result<Option<[u8; 32]>> {
        Ok(None)
    }

    fn store_pairing_psk(&self, _psk: &[u8; 32]) -> Result<()> {
        Ok(())
    }

    fn load_pairings(&self) -> Result<Vec<StoredPsk>> {
        Ok(self
            .records
            .lock()
            .expect("the test lock is not poisoned")
            .clone())
    }

    fn store_pairing(&self, record: StoredPsk) -> Result<()> {
        self.records
            .lock()
            .expect("the test lock is not poisoned")
            .push(record);
        Ok(())
    }

    fn remove_pairing(&self, _server_id: &str) -> Result<()> {
        bail!("the test store was told to fail the removal")
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
) -> (EventStream, syncspin_client::ClientHandle) {
    let (handle, events) = connect(config_for(server, storage), Box::new(NullSink))
        .await
        .expect("the client must connect to the fake server");
    (events, handle)
}

/// Waits for one event, failing instead of hanging.
async fn next_event(stream: &mut EventStream) -> Event {
    match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
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

/// Asserts that no event arrives within `window`.
async fn expect_silence(stream: &mut EventStream, window: Duration) {
    match tokio::time::timeout(window, stream.next()).await {
        Ok(Some(event)) => panic!("expected no further event, got {event:?}"),
        Ok(None) => panic!("the event stream ended"),
        Err(_) => {}
    }
}

/// Waits until the next `Event::Track` and returns its title.
///
/// The default activation carries `metadata@v1`, so a `server/state` is enough; narrowing the roles
/// first would end the player stream and report that instead.
async fn expect_track(server: &FakeServer, stream: &mut EventStream, title: &'static str) {
    server.metadata(title, "An artist");
    match next_event(stream).await {
        Event::Track { title: seen, .. } => assert_eq!(seen, title),
        other => panic!("expected Track, got {other:?}"),
    }
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

/// Pairs the client with `server` on its first connection and returns the stored record.
///
/// The harness promotes the key the client delivered to the announcement of the next connection,
/// so the reconnect that follows is a paired session - which is what both messages of this file
/// are about.
async fn pair_and_reconnect(
    server: &mut FakeServer,
    storage: &Arc<MemoryStorage>,
    events: &mut EventStream,
) -> StoredPsk {
    expect_connected(events, server).await;
    let long_term_psk =
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_pair_finalize())
            .await
            .expect("the client must send client/pair-finalize")
            .expect("the connection must not close before the finalize")
            .0;
    match next_event(events).await {
        Event::Paired { server_id } => assert_eq!(server_id, server.server_id()),
        other => panic!("expected Paired, got {other:?}"),
    }
    let record = storage
        .records()
        .into_iter()
        .next()
        .expect("a completed pairing writes one record");
    assert_eq!(record.category, PskCategory::LongTerm);
    assert_eq!(record.psk, long_term_psk);

    server.close();
    match next_event(events).await {
        Event::Disconnected { .. } => {}
        other => panic!("expected Disconnected, got {other:?}"),
    }
    wait_for_close(server).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.wait_for_message_2())
            .await
            .expect("the second handshake must happen"),
        "the second connection must authenticate under the long-term PSK"
    );
    expect_connected(events, server).await;
    record
}

#[tokio::test]
async fn server_unpair_drops_the_record_and_ends_the_connection() {
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
    let record = pair_and_reconnect(&mut server, &storage, &mut events).await;
    assert_eq!(record.server_id, server.server_id());

    // The paired session is now told the server dropped its side.
    server.json(
        serde_json::to_string(&Incoming::ServerUnpair(ServerUnpair {}))
            .expect("server/unpair encodes"),
    );

    match next_event(&mut events).await {
        Event::Unpaired { server_id } => assert_eq!(server_id, server.server_id()),
        other => panic!("expected Unpaired, got {other:?}"),
    }
    assert!(
        storage.records().is_empty(),
        "the record the server dropped must be gone from the store"
    );
    assert_eq!(
        storage
            .pairing
            .lock()
            .expect("the test lock is not poisoned")
            .as_ref(),
        Some(&pairing_psk),
        "the client's own pairing PSK is not the dropped record"
    );

    // The client closes: the server sees the end of the connection, and the host hears why.
    wait_for_close(&mut server).await;
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("pairing record"),
            "the disconnect must name the dropped record, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unpair_on_an_unpaired_session_is_ignored() {
    // A guest session has no record to drop, so the message must leave it untouched.
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (mut events, _handle) = connect_to(&server, None).await;
    expect_connected(&mut events, &server).await;

    server.json(
        serde_json::to_string(&Incoming::ServerUnpair(ServerUnpair {}))
            .expect("server/unpair encodes"),
    );
    // The session carries on: the next event is the track the server sends, not an Unpaired.
    expect_track(&server, &mut events, "Still playing").await;
}

#[tokio::test]
async fn an_unheld_psk_id_is_reported_once_as_a_credential_mismatch() {
    // The server announces a long-term key this client never held and seals with the Sentinel key,
    // which is what the Sentinel Fallback authenticates.
    let foreign: [u8; 32] = std::array::from_fn(|index| index as u8 ^ 0xa5);
    let server = FakeServer::start(ServerOptions {
        psk_id: psk_id_for(&foreign),
        psk_category: "lt".to_owned(),
        psk: SENTINEL_PSK,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server, None).await;
    expect_connected(&mut events, &server).await;

    assert_eq!(
        next_event(&mut events).await,
        Event::PairingRequired {
            server_id: server.server_id().to_owned(),
            reason: PairingRequiredReason::CredentialMismatch,
        }
    );

    // Once per connection, not per frame: the session keeps working and asks for nothing more.
    expect_track(&server, &mut events, "A guest after all").await;
    expect_silence(&mut events, Duration::from_millis(300)).await;
}

#[tokio::test]
async fn an_evicted_record_is_a_credential_mismatch_on_the_next_connection() {
    // The server keeps its record while the client's is gone, which is what an eviction or a
    // factory reset leaves behind. The client still holds a record, but for another server and a
    // different key, so nothing matches the announcement.
    let held: [u8; 32] = std::array::from_fn(|index| index as u8 ^ 0x3c);
    let announced: [u8; 32] = std::array::from_fn(|index| index as u8 ^ 0x91);
    let storage = MemoryStorage::with_record(StoredPsk {
        category: PskCategory::LongTerm,
        psk: held,
        server_id: "another-server".to_owned(),
    });
    let server = FakeServer::start(ServerOptions {
        psk_id: psk_id_for(&announced),
        psk_category: "lt".to_owned(),
        psk: SENTINEL_PSK,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server, Some(storage.clone())).await;
    expect_connected(&mut events, &server).await;

    assert_eq!(
        next_event(&mut events).await,
        Event::PairingRequired {
            server_id: server.server_id().to_owned(),
            reason: PairingRequiredReason::CredentialMismatch,
        }
    );

    // The mismatch must not touch the record the client does hold for another server.
    let records = storage.records();
    assert_eq!(records.len(), 1, "the signal may not remove a record");
    assert_eq!(records[0].psk, held);
    assert_eq!(records[0].server_id, "another-server");
}

#[tokio::test]
async fn a_plain_guest_handshake_does_not_ask_for_pairing() {
    // The Sentinel announcement is the ordinary unpaired handshake; nobody asked for a pairing.
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (mut events, _handle) = connect_to(&server, None).await;
    expect_connected(&mut events, &server).await;

    expect_track(&server, &mut events, "No pairing needed").await;
    expect_silence(&mut events, Duration::from_millis(300)).await;
}

#[tokio::test]
async fn an_unpair_whose_record_cannot_be_removed_is_not_reported_as_done() {
    // A store that refuses the removal leaves the record in place, so claiming Unpaired would be a
    // lie; the connection ends with the failure instead.
    let held: [u8; 32] = std::array::from_fn(|index| index as u8 ^ 0x77);
    let server = FakeServer::start(ServerOptions {
        psk_id: psk_id_for(&held),
        psk_category: "lt".to_owned(),
        psk: held,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let storage = Arc::new(FailingRemoval {
        records: Mutex::new(vec![StoredPsk {
            category: PskCategory::LongTerm,
            psk: held,
            server_id: server.server_id().to_owned(),
        }]),
    });
    let (mut events, _handle) = connect_to(&server, Some(storage)).await;
    expect_connected(&mut events, &server).await;

    server.json(
        serde_json::to_string(&Incoming::ServerUnpair(ServerUnpair {}))
            .expect("server/unpair encodes"),
    );

    // No `Unpaired` precedes this: the record is still there, so nothing was dropped.
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("pairing record"),
            "the failure must name the record, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }
}
