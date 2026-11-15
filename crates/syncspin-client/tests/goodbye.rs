//! `client/goodbye`: the reason a client gives before a graceful close.
//!
//! The message belongs to a deliberate close only: `server/unpair`, a `ClientHandle` that is closed
//! or dropped. An involuntary end - a protocol or transport failure - closes without one.
//!
//! Everything runs against the hermetic fake server in `fake_server.rs`.

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use syncspin_client::storage::Storage;
use syncspin_client::{
    connect, AudioMode, ClientConfig, Event, EventStream, GoodbyeReason, Identity, PskCategory,
    Sink, StoredPsk, VolumePolicy, DEFAULT_PAIRING_TIMEOUT,
};
use syncspin_core::messages::{Incoming, ServerUnpair};
use syncspin_core::noise::psk_id_for;

use fake_server::{FakeServer, Observation, ServerOptions};

/// An in-memory store that keeps records and the pairing PSK.
#[derive(Default)]
struct MemoryStorage {
    pairing: Mutex<Option<[u8; 32]>>,
    records: Mutex<Vec<StoredPsk>>,
}

impl MemoryStorage {
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
        Ok(self
            .records
            .lock()
            .expect("the test lock is not poisoned")
            .clone())
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

/// Waits until the client says goodbye and returns its reason.
async fn expect_goodbye(server: &mut FakeServer) -> String {
    tokio::time::timeout(Duration::from_secs(5), server.wait_for_goodbye())
        .await
        .expect("the client must say why it is leaving before the close")
        .expect("the connection must not close before client/goodbye")
}

/// Waits until the connection closed, failing on a goodbye on the way.
async fn expect_no_goodbye_before_close(server: &mut FakeServer) {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), server.observation()).await {
            Ok(Some(Observation::Goodbye(reason))) => {
                panic!("an involuntary end must not send client/goodbye, got {reason:?}")
            }
            Ok(Some(Observation::Closed)) | Ok(None) => return,
            Ok(Some(_)) => continue,
            Err(_) => panic!("timed out waiting for the connection to close"),
        }
    }
}

/// A server that keeps a long-term record for the client, so the session is a paired one.
async fn paired_server(psk: [u8; 32]) -> (FakeServer, Arc<MemoryStorage>) {
    let server = FakeServer::start(ServerOptions {
        psk_id: psk_id_for(&psk),
        psk_category: "lt".to_owned(),
        psk,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let storage = MemoryStorage::with_record(StoredPsk {
        category: PskCategory::LongTerm,
        psk,
        server_id: server.server_id().to_owned(),
    });
    (server, storage)
}

#[tokio::test]
async fn an_unpair_says_unpaired_before_the_close() {
    let (mut server, storage) = paired_server([0x24; 32]).await;
    let (mut events, _handle) = connect_to(&server, Some(storage)).await;
    expect_connected(&mut events, &server).await;

    server.json(
        serde_json::to_string(&Incoming::ServerUnpair(ServerUnpair {}))
            .expect("server/unpair encodes"),
    );
    match next_event(&mut events).await {
        Event::Unpaired { server_id } => assert_eq!(server_id, server.server_id()),
        other => panic!("expected Unpaired, got {other:?}"),
    }

    assert_eq!(
        expect_goodbye(&mut server).await,
        "unpaired",
        "the reason the spec names for a processed server/unpair"
    );
}

#[tokio::test]
async fn dropping_the_handle_says_shutdown() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (mut events, handle) = connect_to(&server, None).await;
    expect_connected(&mut events, &server).await;

    drop(handle);

    assert_eq!(
        expect_goodbye(&mut server).await,
        "shutdown",
        "a dropped handle is the device going away"
    );
}

#[tokio::test]
async fn close_with_a_reason_sends_that_reason() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (mut events, mut handle) = connect_to(&server, None).await;
    expect_connected(&mut events, &server).await;

    handle.close(GoodbyeReason::UserRequest);

    assert_eq!(
        expect_goodbye(&mut server).await,
        "user_request",
        "the reason the host chose reaches the server"
    );
}

#[tokio::test]
async fn a_protocol_error_ends_the_connection_without_a_goodbye() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (mut events, _handle) = connect_to(&server, None).await;
    expect_connected(&mut events, &server).await;

    // Cleartext after the Noise transport is a protocol error; the client ends the attempt.
    server.text("{}");
    match next_event(&mut events).await {
        Event::Disconnected { reason, .. } => assert!(
            reason.contains("cleartext"),
            "the reason must name the protocol error, got: {reason}"
        ),
        other => panic!("expected Disconnected, got {other:?}"),
    }

    expect_no_goodbye_before_close(&mut server).await;
}
