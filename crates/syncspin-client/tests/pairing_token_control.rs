//! `ControlHandle::pairing_token()`: the operator-facing version-0 token.
//!
//! The token is `SP:0` plus the base32 body of the client's static public key and the pairing PSK
//! drawn or restored at start. Everything runs against the hermetic fake server in `fake_server.rs`.
//!
//! A token is a credential: no assertion in this file prints one.

#[path = "fake_server.rs"]
mod fake_server;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use syncspin_client::storage::Storage;
use syncspin_client::{
    connect, AudioMode, ClientConfig, Event, EventStream, Identity, Sink, StoredPsk, VolumePolicy,
    DEFAULT_PAIRING_TIMEOUT,
};
use syncspin_core::pairing::token;

use fake_server::{FakeServer, ServerOptions};

/// An in-memory store that keeps the pairing PSK.
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

#[tokio::test]
async fn the_token_carries_the_identity_and_the_stored_pairing_psk() {
    let stored_psk = [0x37; 32];
    let storage = MemoryStorage::holding(stored_psk);
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let config = config_for(&server, Some(storage));
    let identity_key = config.identity.public;
    let (handle, mut events) = connect(config, Box::new(NullSink))
        .await
        .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    let token = handle
        .control()
        .pairing_token()
        .expect("a configured store supplies a token");
    assert!(
        token.starts_with("SP:0"),
        "a version-0 token starts with the prefix and the version"
    );

    let decoded = token::decode(&token).expect("the token the client handed out decodes");
    assert_eq!(decoded.version, 0);
    assert_eq!(
        &decoded.payload[..32],
        identity_key.as_slice(),
        "the first half is the client's static public key"
    );
    assert_eq!(
        &decoded.payload[32..],
        &stored_psk,
        "the second half is the pairing PSK the store holds"
    );
}

#[tokio::test]
async fn a_client_without_a_store_has_no_token() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect(config_for(&server, None), Box::new(NullSink))
        .await
        .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    assert_eq!(
        handle.control().pairing_token(),
        None,
        "a client without a store has no pairing PSK to put into a token"
    );
}

#[tokio::test]
async fn the_token_does_not_change_across_calls_or_a_reconnect() {
    let server = FakeServer::start(ServerOptions {
        connections: 2,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (handle, mut events) = connect(
        config_for(&server, Some(MemoryStorage::holding([0x0b; 32]))),
        Box::new(NullSink),
    )
    .await
    .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    let first = handle.control().pairing_token().expect("a token exists");
    let second = handle.control().pairing_token().expect("a token exists");
    assert_eq!(
        first, second,
        "the value is fixed for the client's lifetime"
    );

    server.close();
    match next_event(&mut events).await {
        Event::Disconnected { .. } => {}
        other => panic!("expected Disconnected, got {other:?}"),
    }
    expect_connected(&mut events, &server).await;

    let after_reconnect = handle.control().pairing_token().expect("a token exists");
    assert_eq!(
        first, after_reconnect,
        "a reconnect keeps the identity and the pairing PSK"
    );
}

#[tokio::test]
async fn the_token_never_reaches_a_debug_line() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect(
        config_for(&server, Some(MemoryStorage::holding([0x51; 32]))),
        Box::new(NullSink),
    )
    .await
    .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    let token = handle.control().pairing_token().expect("a token exists");
    let text = format!("{handle:?}");
    assert!(
        text.contains("<redacted>"),
        "the handle names the field but redacts it"
    );
    assert!(
        !text.contains(&token),
        "a token is a credential and must never reach a log line"
    );
}
