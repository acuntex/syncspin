//! Pairing as the server: the approval gate, the Pairing PSK flow, both code flows and `unpair`.
//!
//! The token flow runs against the real `syncspin-client`, which is the one test that proves the
//! two halves agree on the wire. The code flows run against the fake client, because the client's
//! own code flow needs an operator gesture and a displayed code; its CPace half is written here
//! from the spec, so a bug shared by the two implementations cannot hide.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use common::*;
use syncspin_client::storage::Storage;
use syncspin_client::{
    AudioFrame, Client, ClientConfig, ClientHandle, Event as ClientEvent, GoodbyeReason,
    PskCategory, Sink, StoredPsk,
};
use syncspin_core::messages::{
    ClientPairAuth, ClientPairConfirm, ClientPairFinalize, ClientPairInit, ClientPairPending,
    DynamicPairingCodeMethod, PairAbort, PairingActivation, StaticPairingCodeMethod,
};
use syncspin_core::noise::psk_id_for;
use syncspin_server::{
    CodeFormat, PairingMethod, PairingRecord, PairingStore, TrackInfo, WriteOutcome,
};

/// An in-memory server-side pairing store.
#[derive(Default)]
struct MemoryStore {
    records: Mutex<Vec<PairingRecord>>,
}

impl MemoryStore {
    fn records(&self) -> Vec<PairingRecord> {
        self.records
            .lock()
            .expect("the store lock is not poisoned")
            .clone()
    }

    fn record_for(&self, client_id: &str) -> Option<PairingRecord> {
        self.records()
            .into_iter()
            .find(|record| record.client_id == client_id)
    }
}

impl PairingStore for MemoryStore {
    fn load_pairings(&self) -> Result<Vec<PairingRecord>> {
        Ok(self.records())
    }

    fn store_pairing(&self, record: PairingRecord) -> Result<()> {
        let mut records = self.records.lock().expect("the store lock is not poisoned");
        records.retain(|held| held.client_id != record.client_id);
        records.push(record);
        Ok(())
    }

    fn remove_pairing(&self, client_id: &str) -> Result<()> {
        self.records
            .lock()
            .expect("the store lock is not poisoned")
            .retain(|record| record.client_id != client_id);
        Ok(())
    }
}

/// An in-memory store that can be told to fail one of its operations.
///
/// The two flags are independent on purpose: a `fail_load` row exercises the lookup a mismatch
/// refusal makes, a `fail_remove` row the removal the no-connection path performs. One flag for
/// both could pass without ever reaching the removal.
#[derive(Default)]
struct FlakyStore {
    inner: MemoryStore,
    fail_load: AtomicBool,
    fail_remove: AtomicBool,
}

impl FlakyStore {
    fn set_fail_load(&self, fail: bool) {
        self.fail_load.store(fail, Ordering::SeqCst);
    }

    fn set_fail_remove(&self, fail: bool) {
        self.fail_remove.store(fail, Ordering::SeqCst);
    }

    /// Reads the record straight from the inner store, bypassing the `fail_load` flag.
    fn record_for(&self, client_id: &str) -> Option<PairingRecord> {
        self.inner.record_for(client_id)
    }

    fn store_pairing(&self, record: PairingRecord) -> Result<()> {
        PairingStore::store_pairing(&self.inner, record)
    }
}

impl PairingStore for FlakyStore {
    fn load_pairings(&self) -> Result<Vec<PairingRecord>> {
        if self.fail_load.load(Ordering::SeqCst) {
            bail!("the store cannot be read");
        }
        self.inner.load_pairings()
    }

    fn store_pairing(&self, record: PairingRecord) -> Result<()> {
        self.inner.store_pairing(record)
    }

    fn remove_pairing(&self, client_id: &str) -> Result<()> {
        if self.fail_remove.load(Ordering::SeqCst) {
            bail!("the store cannot remove the record");
        }
        self.inner.remove_pairing(client_id)
    }
}

/// An in-memory client-side store, the one the real client pairs with.
#[derive(Default)]
struct ClientStore {
    pairing: Mutex<Option<[u8; 32]>>,
    records: Mutex<Vec<StoredPsk>>,
}

impl Storage for ClientStore {
    fn pairing_psk(&self) -> Result<Option<[u8; 32]>> {
        Ok(*self.pairing.lock().expect("the store lock is not poisoned"))
    }

    fn store_pairing_psk(&self, psk: &[u8; 32]) -> Result<()> {
        *self.pairing.lock().expect("the store lock is not poisoned") = Some(*psk);
        Ok(())
    }

    fn load_pairings(&self) -> Result<Vec<StoredPsk>> {
        Ok(self
            .records
            .lock()
            .expect("the store lock is not poisoned")
            .clone())
    }

    fn store_pairing(&self, record: StoredPsk) -> Result<()> {
        let mut records = self.records.lock().expect("the store lock is not poisoned");
        records.retain(|held| held.server_id != record.server_id);
        records.push(record);
        Ok(())
    }

    fn remove_pairing(&self, server_id: &str) -> Result<()> {
        self.records
            .lock()
            .expect("the store lock is not poisoned")
            .retain(|record| record.server_id != server_id);
        Ok(())
    }
}

/// A sink that plays nothing.
struct NullSink;

impl Sink for NullSink {
    fn open(&mut self, _format: syncspin_client::AudioFormat) -> Result<()> {
        Ok(())
    }

    fn write(&mut self, _frame: AudioFrame<'_>, _due: std::time::Instant) -> Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Builds one of the test servers, over any store.
fn config_with_store(store: std::sync::Arc<dyn PairingStore>) -> Result<ServerConfig> {
    Ok(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        storage: Some(store),
        pairing_timeout: Duration::from_secs(5),
        ..ServerConfig::new(SERVER_NAME, Identity::generate())
    })
}

/// Builds one of the test servers, with a store and the pairing timeout tests can live with.
fn config(store: std::sync::Arc<MemoryStore>) -> Result<ServerConfig> {
    config_with_store(store)
}

/// Waits for the server event `want` selects, skipping the others.
async fn wait_for_event(events: &mut EventStream, mut want: impl FnMut(&Event) -> bool) -> Event {
    loop {
        let event = next_event(events).await;
        if want(&event) {
            return event;
        }
    }
}

/// Asserts that no `CredentialMismatch` arrives within `within`.
///
/// The events a connection without a mismatch legitimately sends - its empty activation, a
/// pairing, the leave - are skipped, so [`expect_no_event`] cannot be used for this window: the
/// question is whether the fallback fired, not whether anything happened.
async fn expect_no_mismatch(events: &mut EventStream, within: Duration) {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, events.next()).await {
            Err(_) => return,
            Ok(None) => panic!("the event stream ended"),
            Ok(Some(Event::CredentialMismatch { .. })) => {
                panic!("a connection without a held record reported a credential mismatch")
            }
            Ok(Some(Event::ClientActivated { .. }))
            | Ok(Some(Event::Paired { .. }))
            | Ok(Some(Event::ClientLeft { .. })) => continue,
            Ok(Some(other)) => panic!("expected no other event, got {other:?}"),
        }
    }
}

/// Connects a client that seals message 2 with the Sentinel key against a server holding a record
/// for it, and asserts the admission that fallback produces.
///
/// The record is not announced, so the client still sees `lt` on message 1; only the key that
/// sealed the handshake differs. Roles and activities stay empty, `ClientConnected` reports the
/// connection unapproved, and the `CredentialMismatch` follows.
async fn connect_without_its_record(
    port: u16,
    identity: Identity,
    suite: Suite,
    events: &mut EventStream,
) -> Result<FakeClient> {
    let client_id = identity.public_base64();
    let mut client = FakeClient::connect(port).await?;
    client.identity = identity;
    let (mut responder, category) = client.begin_handshake_any(suite).await?;
    assert_eq!(category, "lt", "the server announces its record");
    responder.set_psk(&SENTINEL_PSK)?;
    client.finish_handshake(responder).await?;

    let activate = client.activate().await?;
    assert!(
        activate.active_roles.unwrap_or_default().is_empty(),
        "a client that could not use its record gets no roles"
    );
    assert!(
        activate.activities.is_empty(),
        "a client that could not use its record gets no activity"
    );
    assert!(
        matches!(
            next_event(events).await,
            Event::ClientConnected {
                approved: false,
                ..
            }
        ),
        "the mismatched connection is reported unapproved"
    );
    assert_eq!(
        next_event(events).await,
        Event::CredentialMismatch { client_id },
        "the mismatch is reported after the connection"
    );
    Ok(client)
}

/// Waits for the next client event, failing the test if none arrives.
async fn next_client_event(events: &mut syncspin_client::EventStream) -> ClientEvent {
    match tokio::time::timeout(TIMEOUT, events.next()).await {
        Ok(Some(event)) => event,
        Ok(None) => panic!("the client's event stream ended"),
        Err(_) => panic!("the client sent no event within {TIMEOUT:?}"),
    }
}

/// Connects a real client that keeps its records in `store` and returns its handle.
async fn real_client(
    port: u16,
    identity: Identity,
    store: std::sync::Arc<ClientStore>,
) -> Result<(ClientHandle, syncspin_client::EventStream)> {
    let mut config = ClientConfig::new(format!("127.0.0.1:{port}"), "A test player", identity);
    config.storage = Some(store);
    Client::connect(config, Box::new(NullSink)).await
}

#[tokio::test]
async fn a_token_pairs_a_real_client_and_its_next_connection_authenticates() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let client_store = std::sync::Arc::new(ClientStore::default());

    let (mut handle, mut client_events) = real_client(port, identity, client_store.clone()).await?;
    match next_client_event(&mut client_events).await {
        ClientEvent::Connected { encrypted, .. } => assert!(encrypted),
        other => bail!("expected Connected, got {other:?}"),
    }
    let token = handle
        .control()
        .pairing_token()
        .expect("a client with a store shows its token");
    assert_eq!(
        store.records().len(),
        0,
        "no record exists before the operator pairs"
    );

    tokio::time::timeout(TIMEOUT, server.pair(&token))
        .await
        .context("the token flow did not finish")??;

    let record = store
        .record_for(&client_id)
        .expect("the server stored a record for the token's client");
    assert_ne!(record.psk, [0u8; 32], "the record carries a drawn key");
    let client_records = client_store
        .records
        .lock()
        .expect("the store lock is not poisoned")
        .clone();
    assert_eq!(client_records.len(), 1, "the client stored its record");
    assert_eq!(
        client_records[0].category,
        PskCategory::LongTerm,
        "the client files the record as a long-term key"
    );
    assert_eq!(
        client_records[0].psk, record.psk,
        "both sides agree on the key"
    );

    // The client reports the pairing only after `server/pair-finalize`, and the server then sends
    // the activation under the new keys.
    loop {
        match next_client_event(&mut client_events).await {
            ClientEvent::Paired { .. } => break,
            ClientEvent::Disconnected { reason, .. } => bail!("the client disconnected: {reason}"),
            _ => continue,
        }
    }

    // The pairing discarded the approval, and the operator never approved anyone: the record is
    // what must authenticate the next connection.
    handle.close(GoodbyeReason::Shutdown);
    drop(client_events);
    drop(handle);
    let left = wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientLeft { .. })
    })
    .await;
    assert!(matches!(left, Event::ClientLeft { .. }));

    let (mut second, mut second_events) = real_client(port, identity, client_store).await?;
    match next_client_event(&mut second_events).await {
        ClientEvent::Connected { encrypted, .. } => assert!(encrypted),
        other => bail!("expected Connected, got {other:?}"),
    }
    let connected = wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientConnected { approved: true, .. })
    })
    .await;
    match connected {
        Event::ClientConnected {
            client_id: event_id,
            approved,
            ..
        } => {
            assert_eq!(event_id, client_id);
            assert!(
                approved,
                "the second connection is paired, so it needs no approval"
            );
        }
        other => bail!("expected ClientConnected, got {other:?}"),
    }
    let activated = wait_for_event(
        &mut events,
        |event| matches!(event, Event::ClientActivated { roles, .. } if !roles.is_empty()),
    )
    .await;
    match activated {
        Event::ClientActivated { roles, .. } => {
            assert!(roles.contains(&"player@v1".to_owned()));
        }
        other => bail!("expected an activation with roles, got {other:?}"),
    }

    second.close(GoodbyeReason::Shutdown);
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_real_client_that_lost_its_record_connects_and_can_pair() -> Result<()> {
    // The server still holds a record for the client; the client has none. The mismatch is what the
    // real client reports, and the token it can still show is the way back: pairing replaces the
    // record and promotes the live connection to it.
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let lost_psk = [0x71; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk: lost_psk,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let client_store = std::sync::Arc::new(ClientStore::default());
    let (mut handle, mut client_events) = real_client(port, identity, client_store.clone()).await?;

    // An empty client store cannot use the announced record, so it falls back to the Sentinel key
    // and the server admits it as a guest: unapproved, then the mismatch that is the operator's cue.
    assert!(
        matches!(
            next_event(&mut events).await,
            Event::ClientConnected {
                approved: false,
                ..
            }
        ),
        "the record did not seal the handshake, so the connection is unapproved"
    );
    assert_eq!(
        next_event(&mut events).await,
        Event::CredentialMismatch {
            client_id: client_id.clone()
        },
        "the server reports the record it holds but the client could not use"
    );

    // The event is actionable: the token flow reaches the registered session without a reconnect.
    let token = handle
        .control()
        .pairing_token()
        .expect("a client with a store shows its token");
    tokio::time::timeout(TIMEOUT, server.pair(&token))
        .await
        .context("the token flow did not finish")??;

    loop {
        match next_client_event(&mut client_events).await {
            ClientEvent::Paired { .. } => break,
            ClientEvent::Disconnected { reason, .. } => bail!("the client disconnected: {reason}"),
            _ => continue,
        }
    }
    let replaced = store
        .record_for(&client_id)
        .expect("the pairing stored a record for the client");
    assert_ne!(
        replaced.psk, lost_psk,
        "the pairing replaced the record the client had lost"
    );
    let client_records = client_store
        .records
        .lock()
        .expect("the store lock is not poisoned")
        .clone();
    assert_eq!(client_records.len(), 1, "the client stored its record");
    assert_eq!(
        client_records[0].psk, replaced.psk,
        "both sides agree on the key"
    );

    // The promotion activated the recovered session, and the mismatch is over for this connection.
    loop {
        match next_event(&mut events).await {
            Event::ClientActivated { roles, .. } if roles.contains(&"player@v1".to_owned()) => {
                break
            }
            Event::CredentialMismatch { .. } => {
                panic!("the re-paired connection reported a second credential mismatch")
            }
            Event::ClientLeft { reason } => {
                panic!("the recovered session left before its activation: {reason}")
            }
            Event::ClientConnected { .. } => {
                panic!("the activation arrived on a new connection, not the recovered one")
            }
            _ => continue,
        }
    }
    expect_no_mismatch(&mut events, Duration::from_millis(200)).await;

    handle.close(GoodbyeReason::Shutdown);
    drop(client_events);
    drop(handle);
    wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientLeft { .. })
    })
    .await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_token_for_another_client_is_refused() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, _events) = start_with_config(config(store.clone())?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    client.activate().await?;

    // A token that names a client the server has never seen: the live connection's `client_id`
    // does not match, and no record is written.
    let other = Identity::generate();
    let token = syncspin_core::pairing::token::encode_v0(&other.public, &[0x42; 32]);
    let error = server
        .pair(&token)
        .await
        .expect_err("a token for another client must be refused");
    assert!(
        format!("{error:#}").contains("no live connection"),
        "got: {error:#}"
    );
    assert!(store.records().is_empty(), "a refused token stores nothing");

    // A string that is not a token at all is refused just as clearly, and a version-1 token is a
    // dynamic code, not a pairing credential.
    assert!(server.pair("SP:9nonsense").await.is_err());
    let version_1 = syncspin_core::pairing::token::encode_v1(&[0x11; 24]);
    let error = server
        .pair(&version_1)
        .await
        .expect_err("a version-1 token is not a credential");
    assert!(format!("{error:#}").contains("version-1"), "got: {error:#}");
    assert!(store.records().is_empty());

    // A code method without its CPace feature or against the wrong format is refused by the API
    // as well, before any activation leaves.
    assert!(
        server
            .start_pairing(
                &client.identity.public_base64(),
                PairingMethod::PairingPsk,
                None
            )
            .await
            .is_err(),
        "the Pairing PSK flow starts from a token"
    );
    assert!(
        server
            .start_pairing(
                &client.identity.public_base64(),
                PairingMethod::DynamicCode,
                None
            )
            .await
            .is_err(),
        "a dynamic attempt needs an emission format"
    );

    let _ = client.goodbye("shutdown").await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn an_unapproved_client_gets_no_roles_and_no_audio() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, mut events) = start_with_config(config(store)?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    let activate = client.activate().await?;
    assert!(
        activate.active_roles.unwrap_or_default().is_empty(),
        "an unapproved client is activated at empty activities"
    );
    assert!(
        activate.activities.is_empty(),
        "an unapproved client declares no activity"
    );
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientConnected {
            client_id: client.identity.public_base64(),
            name: CLIENT_NAME.to_owned(),
            approved: false,
        },
        "the host is told that the client waits for approval"
    );

    let mut writer = server.open_stream(TrackInfo::default());
    assert_eq!(writer.write(&[3u8; 480 * 4]), WriteOutcome::Written);
    client.expect_no_audio(Duration::from_millis(300)).await?;

    // The approval activates the roles; the client is a member now and hears the group.
    server.approve(&client.identity.public_base64()).await?;
    let activate = client
        .read_activate(|activities| activities.is_empty())
        .await?;
    assert!(
        activate
            .active_roles
            .unwrap_or_default()
            .contains(&"player@v1".to_owned()),
        "the approval activates the player role"
    );
    client
        .send_json(&player_state_with_timing(true, 100, false, 0, 0))
        .await?;
    let start = client.read_stream_start().await?;
    assert_eq!(
        start.player.expect("the stream carries its format").codec,
        "pcm"
    );
    // The chunk written before the report was addressed to nobody. A zero report lead keeps this
    // row free of the lead, and the barrier proves the start was reported before the next write.
    client.barrier(1).await?;
    assert_eq!(writer.write(&[4u8; 480 * 4]), WriteOutcome::Written);
    let (_, audio) = client.read_audio().await?;
    assert_eq!(audio, [4u8; 480 * 4], "the approved client hears the group");

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn revoking_an_approval_takes_the_roles_and_the_audio_away() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, _events) = start_with_config(config(store)?).await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    client.activate().await?;
    server.approve(&client_id).await?;
    let activate = client
        .read_activate(|activities| activities.is_empty())
        .await?;
    assert!(activate
        .active_roles
        .unwrap_or_default()
        .contains(&"player@v1".to_owned()));

    let mut writer = server.open_stream(TrackInfo::default());
    client
        .send_json(&player_state_with_timing(true, 100, false, 0, 0))
        .await?;
    client.read_stream_start().await?;
    // A zero report lead and the start's send report leave the write ungated.
    client.barrier(1).await?;
    assert_eq!(writer.write(&[5u8; 480 * 4]), WriteOutcome::Written);
    let (_, audio) = client.read_audio().await?;
    assert_eq!(
        audio,
        [5u8; 480 * 4],
        "the approved client is a group member"
    );

    server.revoke_approval(&client_id).await?;
    let activate = client
        .read_activate(|activities| activities.is_empty())
        .await?;
    assert!(
        activate.active_roles.unwrap_or_default().is_empty(),
        "revoking the approval takes the roles away"
    );
    assert_eq!(writer.write(&[6u8; 480 * 4]), WriteOutcome::Written);
    client.expect_no_audio(Duration::from_millis(300)).await?;
    assert!(
        server.revoke_approval(&client_id).await.is_err(),
        "there is no approval left to revoke"
    );

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unpair_removes_the_record_and_disconnects() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x5a; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.identity = identity;
    let announcement = client.handshake_with_psk(Suite::ChaChaPoly, &psk).await?;
    assert_eq!(
        announcement, "lt",
        "the server announces the record's category"
    );
    let activate = client.activate().await?;
    assert!(
        activate
            .active_roles
            .unwrap_or_default()
            .contains(&"player@v1".to_owned()),
        "a paired client needs no approval"
    );
    assert!(
        matches!(
            next_event(&mut events).await,
            Event::ClientConnected { approved: true, .. }
        ),
        "the record sealed the handshake"
    );

    server.unpair(&client_id).await?;
    let message = client
        .read_until(|message| match message {
            Incoming::ServerUnpair(_) => Some(()),
            _ => None,
        })
        .await;
    assert!(message.is_ok(), "the client is told the record is gone");
    client.expect_closed().await?;
    assert!(
        store.record_for(&client_id).is_none(),
        "the unpair removed the record"
    );
    let left = wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientLeft { .. })
    })
    .await;
    assert_eq!(
        left,
        Event::ClientLeft {
            reason: "unpaired".to_owned(),
        }
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_client_that_cannot_use_its_record_is_admitted_unpaired() -> Result<()> {
    // A record the client cannot use no longer refuses it: the server retries message 2 under the
    // Sentinel key, admits the connection without roles, and reports the mismatch. The record is
    // untouched, so re-pairing remains the way back.
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x77; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client =
        connect_without_its_record(port, identity, Suite::ChaChaPoly, &mut events).await?;
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the admission must not touch the record"
    );

    // The session stays open: a client the server admitted unpaired may still leave cleanly.
    client.goodbye("done").await?;
    assert_eq!(
        wait_for_event(&mut events, |event| matches!(
            event,
            Event::ClientLeft { .. }
        ))
        .await,
        Event::ClientLeft {
            reason: "done".to_owned(),
        }
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_sentinel_valued_record_is_treated_as_absent() -> Result<()> {
    // The Sentinel key is published, so a record holding it is not a credential: the lookup skips
    // it and the row stays in the store, because removing a record is the host's business.
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk: SENTINEL_PSK,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.identity = identity;
    let (mut responder, category) = client.begin_handshake_any(Suite::ChaChaPoly).await?;
    assert_eq!(
        category, "sn",
        "a record holding the Sentinel key is not announced"
    );
    responder.set_psk(&SENTINEL_PSK)?;
    client.finish_handshake(responder).await?;

    let activate = client.activate().await?;
    assert!(activate.active_roles.unwrap_or_default().is_empty());
    assert!(activate.activities.is_empty());
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected {
            approved: false,
            ..
        }
    ));
    expect_no_mismatch(&mut events, Duration::from_millis(200)).await;
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(SENTINEL_PSK),
        "the row is treated as absent, not deleted"
    );

    client.goodbye("done").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_record_that_does_not_authenticate_under_either_key_closes() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x66; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.identity = identity;
    let (mut responder, category) = client.begin_handshake_any(Suite::ChaChaPoly).await?;
    assert_eq!(category, "lt", "the server announces its record");
    responder.set_psk(&[0x99; 32])?;
    let outcome = client.finish_handshake(responder).await;
    assert!(
        outcome.is_err(),
        "a message under neither the record's nor the Sentinel key must not be accepted"
    );
    client.expect_closed().await?;
    expect_no_event(&mut events, Duration::from_millis(200)).await;
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "a failed handshake must not touch the record"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_fallback_over_aes_gcm_behaves_identically() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x11; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client = connect_without_its_record(port, identity, Suite::AesGcm, &mut events).await?;
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the suite changes nothing about the record"
    );

    client.goodbye("done").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_lingering_approval_does_not_give_a_mismatched_session_roles() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk: [0x22; 32],
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    // No connection is live, so the approval is only remembered for the next one.
    server.approve(&client_id).await?;
    let mut client =
        connect_without_its_record(port, identity, Suite::ChaChaPoly, &mut events).await?;

    client.goodbye("done").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn the_next_connection_repeats_the_mismatch() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x44; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    for _ in 0..2 {
        let mut client =
            connect_without_its_record(port, identity, Suite::ChaChaPoly, &mut events).await?;
        client.goodbye("done").await?;
        wait_for_event(&mut events, |event| {
            matches!(event, Event::ClientLeft { .. })
        })
        .await;
    }

    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "neither connection touched the record"
    );
    assert!(
        server.revoke_approval(&client_id).await.is_err(),
        "the mismatch never stored an approval"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_record_for_another_client_does_not_trigger_the_fallback() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let other = Identity::generate();
    let other_id = other.public_base64();
    let other_psk = [0x33; 32];
    store.store_pairing(PairingRecord {
        client_id: other_id.clone(),
        psk: other_psk,
    })?;

    let identity = Identity::generate();
    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.identity = identity;
    let (mut responder, category) = client.begin_handshake_any(Suite::ChaChaPoly).await?;
    assert_eq!(
        category, "sn",
        "a record of another client does not leak into this handshake"
    );
    responder.set_psk(&SENTINEL_PSK)?;
    client.finish_handshake(responder).await?;

    let activate = client.activate().await?;
    assert!(activate.active_roles.unwrap_or_default().is_empty());
    assert!(activate.activities.is_empty());
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected {
            approved: false,
            ..
        }
    ));
    // The lookup missed, so no retry was attempted and there is nothing to report as a mismatch.
    expect_no_mismatch(&mut events, Duration::from_millis(200)).await;
    assert_eq!(
        store.record_for(&other_id).map(|record| record.psk),
        Some(other_psk),
        "the other client's record is untouched"
    );

    client.goodbye("done").await?;
    server.shutdown().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The host commands on a mismatched session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approving_a_mismatched_session_is_refused_and_stores_nothing() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x21; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client =
        connect_without_its_record(port, identity, Suite::ChaChaPoly, &mut events).await?;

    let error = server
        .approve(&client_id)
        .await
        .expect_err("an approval is refused while the record exists");
    assert!(
        format!("{error:#}").contains("mismatch"),
        "the error names the mismatch: {error:#}"
    );
    assert!(
        server.revoke_approval(&client_id).await.is_err(),
        "the refused approval must not be remembered"
    );
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the refusal leaves the record alone"
    );

    // The same client reconnects after the operator removed the record: the refused call left no
    // approval behind, so the next connection is reported unapproved.
    store.remove_pairing(&client_id)?;
    client.goodbye("done").await?;
    wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientLeft { .. })
    })
    .await;

    let mut second = FakeClient::connect(port).await?;
    second.identity = identity;
    second.handshake(Suite::ChaChaPoly).await?;
    second.activate().await?;
    assert_eq!(
        wait_for_event(&mut events, |event| matches!(
            event,
            Event::ClientConnected { .. }
        ))
        .await,
        Event::ClientConnected {
            client_id,
            name: CLIENT_NAME.to_owned(),
            approved: false,
        },
        "the refused approval stored nothing for the next connection"
    );

    second.goodbye("done").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_lingering_approval_still_refuses_approve() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x22; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    // No connection is live, so this approval is only remembered for the next one.
    server.approve(&client_id).await?;
    let mut client =
        connect_without_its_record(port, identity, Suite::ChaChaPoly, &mut events).await?;

    // The mismatch check precedes the already-approved short-circuit: the lingering approval
    // changes neither the answer nor the state.
    let error = server
        .approve(&client_id)
        .await
        .expect_err("a lingering approval does not let a mismatched session be approved");
    assert!(
        format!("{error:#}").contains("mismatch"),
        "the error names the mismatch: {error:#}"
    );

    server.revoke_approval(&client_id).await?;
    let activate = client
        .read_activate(|activities| activities.is_empty())
        .await?;
    assert!(
        activate.active_roles.unwrap_or_default().is_empty(),
        "the session still holds no roles after the refusal"
    );
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the refusal leaves the record alone"
    );

    client.goodbye("done").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn removing_the_record_then_approving_recovers_the_live_session() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk: [0x23; 32],
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client =
        connect_without_its_record(port, identity, Suite::ChaChaPoly, &mut events).await?;

    // The prohibition's precondition is gone once the store no longer holds the record.
    store.remove_pairing(&client_id)?;
    server.approve(&client_id).await?;
    let activate = client
        .read_activate(|activities| activities.is_empty())
        .await?;
    assert!(
        activate
            .active_roles
            .unwrap_or_default()
            .contains(&"player@v1".to_owned()),
        "the recovered session is activated with its roles"
    );

    // The recovery cleared the flag, so the connection does not report the mismatch again.
    expect_no_mismatch(&mut events, Duration::from_millis(200)).await;

    client.goodbye("done").await?;
    wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientLeft { .. })
    })
    .await;

    // The handle recorded the approval only after the session confirmed the activation.
    let mut second = FakeClient::connect(port).await?;
    second.identity = identity;
    second.handshake(Suite::ChaChaPoly).await?;
    second.activate().await?;
    let connected = wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientConnected { .. })
    })
    .await;
    assert!(
        matches!(connected, Event::ClientConnected { approved: true, .. }),
        "the next connection reports the recovered approval: {connected:?}"
    );

    second.goodbye("done").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unpairing_a_mismatched_session_keeps_the_record_and_the_approval() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x24; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    server.approve(&client_id).await?;
    let mut client =
        connect_without_its_record(port, identity, Suite::ChaChaPoly, &mut events).await?;

    let error = server
        .unpair(&client_id)
        .await
        .expect_err("an unpair is refused while the record exists");
    assert!(
        format!("{error:#}").contains("mismatch"),
        "the error names the mismatch: {error:#}"
    );
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the refused unpair leaves the record alone"
    );

    // The refusal touched neither the registry nor the connection: the approval is still there to
    // be revoked, and the revocation reaches the session.
    server.revoke_approval(&client_id).await?;
    let activate = client
        .read_activate(|activities| activities.is_empty())
        .await?;
    assert!(activate.active_roles.unwrap_or_default().is_empty());

    client.goodbye("done").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn removing_the_record_then_unpairing_disconnects() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk: [0x25; 32],
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client =
        connect_without_its_record(port, identity, Suite::ChaChaPoly, &mut events).await?;

    // The removal is already done by the store, so the unpair only has to end the connection.
    store.remove_pairing(&client_id)?;
    server.unpair(&client_id).await?;
    let message = client
        .read_until(|message| match message {
            Incoming::ServerUnpair(_) => Some(()),
            _ => None,
        })
        .await;
    assert!(message.is_ok(), "the client is told the record is gone");
    client.expect_closed().await?;
    assert_eq!(
        wait_for_event(&mut events, |event| matches!(
            event,
            Event::ClientLeft { .. }
        ))
        .await,
        Event::ClientLeft {
            reason: "unpaired".to_owned(),
        }
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn the_event_is_actionable_before_the_session_loop() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk: [0x26; 32],
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.identity = identity;
    let (mut responder, category) = client.begin_handshake_any(Suite::ChaChaPoly).await?;
    assert_eq!(category, "lt", "the server announces its record");
    responder.set_psk(&SENTINEL_PSK)?;
    client.finish_handshake(responder).await?;
    // The host reacts to the events, not to the activation: `client/hello` is sent, and the two
    // events are read before anything else.
    client.send_json(&client_hello()).await?;
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected {
            approved: false,
            ..
        }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::CredentialMismatch {
            client_id: client_id.clone()
        },
        "the mismatch follows the connection"
    );

    // The session registered before the event went out, so the handle reaches it and the refusal
    // is the mismatch one; "no live connection" would mean the event arrived too early to act on.
    let error = server
        .approve(&client_id)
        .await
        .expect_err("the mismatched session is refused");
    let message = format!("{error:#}");
    assert!(
        message.contains("mismatch"),
        "the error names the mismatch: {message}"
    );
    assert!(
        !message.contains("no live connection"),
        "the event is actionable: {message}"
    );

    client.goodbye("done").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_failing_store_leaves_approve_and_unpair_untouched() -> Result<()> {
    let store = std::sync::Arc::new(FlakyStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x27; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config_with_store(store.clone())?).await?;
    let mut client =
        connect_without_its_record(port, identity, Suite::ChaChaPoly, &mut events).await?;

    // A store that cannot be read is the error of the call, and nothing else changes.
    store.set_fail_load(true);
    let error = server
        .approve(&client_id)
        .await
        .expect_err("a store read failure refuses the approval");
    assert!(
        format!("{error:#}").contains("cannot be read"),
        "the store error is reported: {error:#}"
    );
    let error = server
        .unpair(&client_id)
        .await
        .expect_err("a store read failure refuses the unpair");
    assert!(
        format!("{error:#}").contains("cannot be read"),
        "the store error is reported: {error:#}"
    );
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the failed calls leave the record alone"
    );
    assert!(
        server.revoke_approval(&client_id).await.is_err(),
        "the failed approvals stored nothing"
    );

    // The second call fails the same way: the first did not activate the session, so there is no
    // already-approved short-circuit to answer `Ok`.
    let error = server
        .approve(&client_id)
        .await
        .expect_err("a store read failure still refuses the second approval");
    assert!(
        format!("{error:#}").contains("cannot be read"),
        "the store error is reported again: {error:#}"
    );
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the record is untouched by either call"
    );

    client.goodbye("done").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn an_unpair_without_a_live_connection_and_a_failing_store_keeps_the_record() -> Result<()> {
    let store = std::sync::Arc::new(FlakyStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x28; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config_with_store(store.clone())?).await?;
    let mut client =
        connect_without_its_record(port, identity, Suite::ChaChaPoly, &mut events).await?;
    client.goodbye("done").await?;
    wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientLeft { .. })
    })
    .await;

    // Only the removal fails, so the lookup a live session still makes is unaffected: until the
    // registration is gone the mismatch refusal fires, and once it is gone the direct path reaches
    // `remove_pairing` and fails there.
    store.set_fail_remove(true);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let error = loop {
        let error = server
            .unpair(&client_id)
            .await
            .expect_err("the record cannot be removed while the store fails");
        let message = format!("{error:#}");
        if message.contains("cannot remove") {
            break message;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the direct path was not reached within 1 s; last error: {message}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        error.contains("cannot remove"),
        "the error comes from the store: {error}"
    );
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the failed removal leaves the record alone"
    );

    store.set_fail_remove(false);
    server.unpair(&client_id).await?;
    assert!(
        store.record_for(&client_id).is_none(),
        "the retry removes the record"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn an_unpaired_access_disabled_client_stays_connected_and_idle() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, mut events) = start_with_config(config(store)?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;

    let Incoming::ClientHello(mut hello) = client_hello() else {
        panic!("the helper builds a client/hello");
    };
    hello.unpaired_access.enabled = false;
    let activate = client.activate_with(Incoming::ClientHello(hello)).await?;
    assert!(activate.active_roles.unwrap_or_default().is_empty());
    assert!(activate.activities.is_empty());
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected {
            approved: false,
            ..
        }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { roles, .. } if roles.is_empty()
    ));
    // The server sends no activation this client would have to reject.
    expect_no_event(&mut events, Duration::from_millis(200)).await;

    // The connection stays usable: a state report is accepted before a clean goodbye.
    client.send_json(&player_state(true, 100, false)).await?;
    client.goodbye("idle").await?;
    assert_eq!(
        wait_for_event(&mut events, |event| matches!(
            event,
            Event::ClientLeft { .. }
        ))
        .await,
        Event::ClientLeft {
            reason: "idle".to_owned(),
        }
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_malformed_pairing_message_is_a_protocol_error() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, mut events) = start_with_config(config(store)?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    client.activate().await?;

    // `pairing_index` is an integer on the wire; a string is not a message any conformant peer
    // sends, and a half-open attempt must not continue.
    client
        .send_raw_json(r#"{"type":"client/pair-init","payload":{"pairing_index":"one"}}"#)
        .await?;
    client.expect_closed().await?;
    let left = wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientLeft { .. })
    })
    .await;
    assert_eq!(
        left,
        Event::ClientLeft {
            reason: "protocol error".to_owned(),
        }
    );

    server.shutdown().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The code flows, against a client that runs CPace itself
// ---------------------------------------------------------------------------

/// The state the fake client keeps across one CPace round.
#[cfg(feature = "pairing-code")]
struct ClientRound {
    share: [u8; 32],
    expected_server_tag: [u8; 64],
    client_tag: [u8; 64],
    wrapped_psk: [u8; 48],
    wrapped_nonce_b: Option<[u8; 48]>,
}

/// Builds the CPace session id of one round: label, `h`, pairing index and round.
#[cfg(feature = "pairing-code")]
fn pake_sid(handshake_hash: &[u8; 32], pairing_index: u32, round: u32) -> Vec<u8> {
    let mut sid = Vec::from(b"sendspin-pair-pake-v1".as_slice());
    sid.extend_from_slice(handshake_hash);
    sid.extend_from_slice(&pairing_index.to_be_bytes());
    sid.extend_from_slice(&round.to_be_bytes());
    sid
}

/// Answers `server/pair-auth` the way the client crate does.
#[cfg(feature = "pairing-code")]
fn answer_auth(
    prs: &[u8],
    handshake_hash: &[u8; 32],
    pairing_index: u32,
    round: u32,
    ya: &[u8; 32],
    psk: [u8; 32],
    nonce_b: Option<[u8; 32]>,
) -> Result<ClientRound> {
    use syncspin_core::pairing::{pake, wrap};

    let sid = pake_sid(handshake_hash, pairing_index, round);
    let generator = pake::generator(prs, b"", &sid);
    let mut scalar = [0u8; 32];
    getrandom::fill(&mut scalar).map_err(|_| anyhow::anyhow!("no CSPRNG"))?;
    let share = pake::public_share(&scalar, &generator)?;
    let point = pake::scalar_mult_vfy(&scalar, ya)?;
    let transcript = pake::transcript_ir(ya, b"server", &share, b"client");
    let isk = pake::intermediate_session_key(&sid, &point, &transcript);
    let expected_server_tag = pake::key_confirmation_tag(&sid, &isk, ya, b"server");
    let client_tag = pake::key_confirmation_tag(&sid, &isk, &share, b"client");
    let wrapped_psk = wrap::wrap(
        Suite::ChaChaPoly,
        &wrap::k_wrap(wrap::PSK_LABEL, &sid, &isk),
        &psk,
    )?;
    let wrapped_nonce_b = match nonce_b {
        Some(nonce) => Some(wrap::wrap(
            Suite::ChaChaPoly,
            &wrap::k_wrap(wrap::NONCE_LABEL, &sid, &isk),
            &nonce,
        )?),
        None => None,
    };
    Ok(ClientRound {
        share,
        expected_server_tag,
        client_tag,
        wrapped_psk,
        wrapped_nonce_b,
    })
}

/// Reads the next `noise/handshake` and swaps the fake client's keys.
///
/// It also checks the announcement: a server that promotes the connection to a key it does not
/// hold, or under the wrong category, would leave the client unable to continue.
#[cfg(feature = "pairing-code")]
async fn accept_rehandshake(
    client: &mut FakeClient,
    server_public: [u8; 32],
    psk: [u8; 32],
    category: &str,
) -> Result<()> {
    let previous = *client
        .noise
        .as_ref()
        .expect("the handshake finished before a re-handshake")
        .handshake_hash();
    let suite = client
        .noise
        .as_ref()
        .expect("the handshake finished before a re-handshake")
        .suite();
    let handshake = client
        .read_until(|message| match message {
            Incoming::NoiseHandshake(handshake) => Some(handshake),
            _ => None,
        })
        .await?;
    let message_1 = URL_SAFE_NO_PAD.decode(&handshake.data)?;
    let mut responder =
        Responder::with_peer_suite(&client.identity, &server_public, suite, &previous)?;
    let metadata = responder.read_message(&message_1)?;
    let announcement: serde_json::Value = serde_json::from_slice(&metadata)?;
    assert_eq!(
        announcement["psk_id"].as_str(),
        Some(psk_id_for(&psk).as_str())
    );
    assert_eq!(announcement["psk_category"].as_str(), Some(category));
    responder.set_psk(&psk)?;
    let message_2 = Incoming::NoiseHandshake(NoiseHandshake {
        data: URL_SAFE_NO_PAD.encode(responder.write_message()?),
    });
    client.send_json(&message_2).await?;
    client.noise = Some(responder.into_transport()?);
    Ok(())
}

/// Reads the promotion's `noise/handshake` and answers message 2 under `sealed_with`.
///
/// The announcement is checked first: the server promotes the connection to `announced`, under the
/// long-term category. The caller then sees what the server does with a message 2 that does not
/// authenticate against that key: the re-handshake has no Sentinel fallback, so the connection ends.
#[cfg(feature = "pairing-code")]
async fn reject_rehandshake(
    client: &mut FakeClient,
    server_public: [u8; 32],
    announced: [u8; 32],
    sealed_with: &[u8; 32],
) -> Result<()> {
    let previous = *client
        .noise
        .as_ref()
        .expect("the handshake finished before a re-handshake")
        .handshake_hash();
    let suite = client
        .noise
        .as_ref()
        .expect("the handshake finished before a re-handshake")
        .suite();
    let handshake = client
        .read_until(|message| match message {
            Incoming::NoiseHandshake(handshake) => Some(handshake),
            _ => None,
        })
        .await?;
    let message_1 = URL_SAFE_NO_PAD.decode(&handshake.data)?;
    let mut responder =
        Responder::with_peer_suite(&client.identity, &server_public, suite, &previous)?;
    let metadata = responder.read_message(&message_1)?;
    let announcement: serde_json::Value = serde_json::from_slice(&metadata)?;
    assert_eq!(
        announcement["psk_id"].as_str(),
        Some(psk_id_for(&announced).as_str()),
        "the server promotes the connection to the record it stored"
    );
    assert_eq!(announcement["psk_category"].as_str(), Some("lt"));
    responder.set_psk(sealed_with)?;
    let message_2 = Incoming::NoiseHandshake(NoiseHandshake {
        data: URL_SAFE_NO_PAD.encode(responder.write_message()?),
    });
    client.send_json(&message_2).await?;
    Ok(())
}

/// Reads the `server/pair-auth` a `submit_code` triggers and returns its share.
#[cfg(feature = "pairing-code")]
async fn read_server_auth(client: &mut FakeClient) -> Result<[u8; 32]> {
    let auth = client
        .read_pairing(|message| match message {
            Incoming::ServerPairAuth(auth) => Some(auth),
            _ => None,
        })
        .await?;
    let bytes = URL_SAFE_NO_PAD.decode(&auth.pake_msg_1)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("pake_msg_1 is not 32 bytes"))
}

/// Reads `server/pair-confirm` and verifies the server's tag.
#[cfg(feature = "pairing-code")]
async fn read_server_confirm(client: &mut FakeClient, expected: &[u8; 64]) -> Result<()> {
    let confirm = client
        .read_pairing(|message| match message {
            Incoming::ServerPairConfirm(confirm) => Some(confirm),
            _ => None,
        })
        .await?;
    use syncspin_core::pairing::pake;
    let received: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&confirm.server_kc)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("server_kc is not 64 bytes"))?;
    if !pake::verify_key_confirmation_tag(expected, &received) {
        bail!("the server's key-confirmation tag does not verify");
    }
    Ok(())
}

/// Reads the activation that admits a pairing attempt.
#[cfg(feature = "pairing-code")]
async fn read_pairing_activation(client: &mut FakeClient) -> Result<PairingActivation> {
    client
        .read_activate(|activities| activities.iter().any(|activity| activity == "pairing"))
        .await?
        .pairing
        .ok_or_else(|| anyhow::anyhow!("the pairing activation carries no parameters"))
}

/// A `client/hello` that offers the pairing method under test.
#[cfg(feature = "pairing-code")]
fn hello_with_pairing(method: PairingMethod, format: Option<CodeFormat>) -> Incoming {
    let mut message = client_hello();
    let Incoming::ClientHello(hello) = &mut message else {
        unreachable!("client_hello builds a hello");
    };
    match method {
        PairingMethod::StaticCode => {
            hello.supported_pair_methods.static_pairing_code =
                Some(StaticPairingCodeMethod::default());
        }
        PairingMethod::DynamicCode => {
            hello.supported_pair_methods.dynamic_pairing_code = Some(DynamicPairingCodeMethod {
                out_channels: vec!["display".to_owned()],
                formats: vec![format
                    .expect("a dynamic attempt has a format")
                    .wire_name()
                    .to_owned()],
            });
        }
        PairingMethod::PairingPsk => {}
    }
    message
}

#[cfg(feature = "pairing-code")]
#[tokio::test]
async fn the_static_code_flow_stores_a_record_and_promotes_the_connection() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let server_identity = Identity::generate();
    let (server, port, mut events) = start_with_config(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        storage: Some(store.clone()),
        pairing_timeout: Duration::from_secs(5),
        ..ServerConfig::new(SERVER_NAME, server_identity)
    })
    .await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    client
        .activate_with(hello_with_pairing(PairingMethod::StaticCode, None))
        .await?;
    server.approve(&client_id).await?;
    client.read_activate(|_| true).await?;

    server
        .start_pairing(&client_id, PairingMethod::StaticCode, None)
        .await?;
    let activation = read_pairing_activation(&mut client).await?;
    assert_eq!(activation.method, "static_pairing_code");
    assert_eq!(activation.format, None);
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::PairingRequested {
            client_id: client_id.clone(),
            method: PairingMethod::StaticCode,
            code: None,
        },
        "the host is asked for the code the device carries"
    );

    let code = "12345678";
    let handshake_hash = *client
        .noise
        .as_ref()
        .expect("the handshake finished")
        .handshake_hash();
    client
        .send_json(&Incoming::ClientPairInit(ClientPairInit {
            pairing_index: 1,
            commit_b: None,
        }))
        .await?;
    let psk = [0x31; 32];
    server.submit_code(&client_id, "1234-5678").await?;
    let ya = read_server_auth(&mut client).await?;
    let round = answer_auth(code.as_bytes(), &handshake_hash, 1, 1, &ya, psk, None)?;
    client
        .send_json(&Incoming::ClientPairAuth(ClientPairAuth {
            pake_msg_2: URL_SAFE_NO_PAD.encode(round.share),
        }))
        .await?;
    read_server_confirm(&mut client, &round.expected_server_tag).await?;
    client
        .send_json(&Incoming::ClientPairConfirm(ClientPairConfirm {
            client_kc: URL_SAFE_NO_PAD.encode(round.client_tag),
            wrapped_nonce_b: None,
        }))
        .await?;
    client
        .send_json(&Incoming::ClientPairFinalize(ClientPairFinalize {
            long_term_psk: None,
            wrapped_psk: Some(URL_SAFE_NO_PAD.encode(round.wrapped_psk)),
        }))
        .await?;
    client
        .read_pairing(|message| match message {
            Incoming::ServerPairFinalize(_) => Some(()),
            _ => None,
        })
        .await?;

    // The server stores the record before it acknowledges, and then promotes the connection.
    let record = store
        .record_for(&client_id)
        .expect("the code flow stored a record");
    assert_eq!(record.psk, psk, "the server opened the sealed key");
    accept_rehandshake(&mut client, server_identity.public, psk, "lt").await?;
    let activate = client.read_activate(|_| true).await?;
    assert!(
        activate
            .active_roles
            .unwrap_or_default()
            .contains(&"player@v1".to_owned()),
        "the paired connection is activated"
    );

    let paired = wait_for_event(&mut events, |event| matches!(event, Event::Paired { .. })).await;
    assert_eq!(paired, Event::Paired { client_id });

    let _ = client.goodbye("shutdown").await;
    server.shutdown().await?;
    Ok(())
}

#[cfg(feature = "pairing-code")]
#[tokio::test]
async fn a_rehandshake_miss_does_not_fall_back_to_the_sentinel() -> Result<()> {
    // The promotion's re-handshake has no fallback: a client that answers message 2 under a key
    // other than the announced record ends the connection, even though the record was already
    // stored. The Sentinel key is the sharpest choice - it is the only wrong key a fallback-aware
    // read would accept, so a listener that used `read_message_with_sentinel` here would promote
    // the connection instead of closing it.
    let store = std::sync::Arc::new(MemoryStore::default());
    let server_identity = Identity::generate();
    let (server, port, mut events) = start_with_config(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        storage: Some(store.clone()),
        pairing_timeout: Duration::from_secs(5),
        ..ServerConfig::new(SERVER_NAME, server_identity)
    })
    .await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    client
        .activate_with(hello_with_pairing(PairingMethod::StaticCode, None))
        .await?;
    server.approve(&client_id).await?;
    client.read_activate(|_| true).await?;

    server
        .start_pairing(&client_id, PairingMethod::StaticCode, None)
        .await?;
    let activation = read_pairing_activation(&mut client).await?;
    assert_eq!(activation.method, "static_pairing_code");
    assert_eq!(activation.format, None);
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::PairingRequested {
            client_id: client_id.clone(),
            method: PairingMethod::StaticCode,
            code: None,
        },
        "the host is asked for the code the device carries"
    );

    let code = "12345678";
    let handshake_hash = *client
        .noise
        .as_ref()
        .expect("the handshake finished")
        .handshake_hash();
    client
        .send_json(&Incoming::ClientPairInit(ClientPairInit {
            pairing_index: 1,
            commit_b: None,
        }))
        .await?;
    let psk = [0x31; 32];
    server.submit_code(&client_id, "1234-5678").await?;
    let ya = read_server_auth(&mut client).await?;
    let round = answer_auth(code.as_bytes(), &handshake_hash, 1, 1, &ya, psk, None)?;
    client
        .send_json(&Incoming::ClientPairAuth(ClientPairAuth {
            pake_msg_2: URL_SAFE_NO_PAD.encode(round.share),
        }))
        .await?;
    read_server_confirm(&mut client, &round.expected_server_tag).await?;
    client
        .send_json(&Incoming::ClientPairConfirm(ClientPairConfirm {
            client_kc: URL_SAFE_NO_PAD.encode(round.client_tag),
            wrapped_nonce_b: None,
        }))
        .await?;
    client
        .send_json(&Incoming::ClientPairFinalize(ClientPairFinalize {
            long_term_psk: None,
            wrapped_psk: Some(URL_SAFE_NO_PAD.encode(round.wrapped_psk)),
        }))
        .await?;
    client
        .read_pairing(|message| match message {
            Incoming::ServerPairFinalize(_) => Some(()),
            _ => None,
        })
        .await?;

    // The record is stored before the re-handshake, so a miss must leave it in place.
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the server stored the record before it promoted the connection"
    );
    reject_rehandshake(&mut client, server_identity.public, psk, &SENTINEL_PSK).await?;
    client.expect_closed().await?;
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "a failed promotion must not remove the record it stored"
    );
    // No fallback: the miss produces neither a Sentinel session nor a second mismatch report.
    expect_no_mismatch(&mut events, Duration::from_millis(200)).await;

    server.shutdown().await?;
    Ok(())
}

#[cfg(feature = "pairing-code")]
#[tokio::test]
async fn the_dynamic_code_flow_checks_the_commitment_and_binds_the_code() -> Result<()> {
    use syncspin_core::pairing::code::{commitment, DynamicCode};

    let store = std::sync::Arc::new(MemoryStore::default());
    let server_identity = Identity::generate();
    let (server, port, mut events) = start_with_config(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        storage: Some(store.clone()),
        pairing_timeout: Duration::from_secs(5),
        ..ServerConfig::new(SERVER_NAME, server_identity)
    })
    .await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    client
        .activate_with(hello_with_pairing(
            PairingMethod::DynamicCode,
            Some(CodeFormat::Digits),
        ))
        .await?;
    server.approve(&client_id).await?;
    client.read_activate(|_| true).await?;

    server
        .start_pairing(
            &client_id,
            PairingMethod::DynamicCode,
            Some(CodeFormat::Digits),
        )
        .await?;
    let activation = read_pairing_activation(&mut client).await?;
    assert_eq!(activation.method, "dynamic_pairing_code");
    assert_eq!(activation.format.as_deref(), Some("digits"));

    let handshake_hash = *client
        .noise
        .as_ref()
        .expect("the handshake finished")
        .handshake_hash();
    let nonce_b = [0x66u8; 32];
    client
        .send_json(&Incoming::ClientPairInit(ClientPairInit {
            pairing_index: 1,
            commit_b: Some(URL_SAFE_NO_PAD.encode(commitment(&nonce_b))),
        }))
        .await?;
    let init = client
        .read_pairing(|message| match message {
            Incoming::ServerPairInit(init) => Some(init),
            _ => None,
        })
        .await?;
    let nonce_a: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            init.nonce_a
                .as_deref()
                .expect("the first round carries nonce_A"),
        )?
        .try_into()
        .unwrap();
    let code = DynamicCode::derive(&handshake_hash, &nonce_a, &nonce_b).digits_text();
    assert!(matches!(
        wait_for_event(&mut events, |event| {
            matches!(event, Event::PairingRequested { .. })
        })
        .await,
        Event::PairingRequested { .. }
    ));

    let psk = [0x32; 32];
    server.submit_code(&client_id, &code).await?;
    let ya = read_server_auth(&mut client).await?;
    let round = answer_auth(
        code.as_bytes(),
        &handshake_hash,
        1,
        1,
        &ya,
        psk,
        Some(nonce_b),
    )?;
    client
        .send_json(&Incoming::ClientPairAuth(ClientPairAuth {
            pake_msg_2: URL_SAFE_NO_PAD.encode(round.share),
        }))
        .await?;
    read_server_confirm(&mut client, &round.expected_server_tag).await?;
    client
        .send_json(&Incoming::ClientPairConfirm(ClientPairConfirm {
            client_kc: URL_SAFE_NO_PAD.encode(round.client_tag),
            wrapped_nonce_b: Some(
                URL_SAFE_NO_PAD.encode(
                    round
                        .wrapped_nonce_b
                        .expect("the dynamic flow seals nonce_B"),
                ),
            ),
        }))
        .await?;
    client
        .send_json(&Incoming::ClientPairFinalize(ClientPairFinalize {
            long_term_psk: None,
            wrapped_psk: Some(URL_SAFE_NO_PAD.encode(round.wrapped_psk)),
        }))
        .await?;
    client
        .read_pairing(|message| match message {
            Incoming::ServerPairFinalize(_) => Some(()),
            _ => None,
        })
        .await?;
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the binding checks passed and the record was stored"
    );
    accept_rehandshake(&mut client, server_identity.public, psk, "lt").await?;
    client.read_activate(|_| true).await?;
    let paired = wait_for_event(&mut events, |event| matches!(event, Event::Paired { .. })).await;
    assert_eq!(paired, Event::Paired { client_id });

    let _ = client.goodbye("shutdown").await;
    server.shutdown().await?;
    Ok(())
}

#[cfg(feature = "pairing-code")]
#[tokio::test]
async fn a_static_code_that_does_not_match_ends_the_attempt_without_a_record() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, mut events) = start_with_config(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        storage: Some(store.clone()),
        pairing_timeout: Duration::from_secs(5),
        ..ServerConfig::new(SERVER_NAME, Identity::generate())
    })
    .await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    client
        .activate_with(hello_with_pairing(PairingMethod::StaticCode, None))
        .await?;
    server.approve(&client_id).await?;
    client.read_activate(|_| true).await?;

    server
        .start_pairing(&client_id, PairingMethod::StaticCode, None)
        .await?;
    read_pairing_activation(&mut client).await?;
    let handshake_hash = *client
        .noise
        .as_ref()
        .expect("the handshake finished")
        .handshake_hash();
    client
        .send_json(&Incoming::ClientPairInit(ClientPairInit {
            pairing_index: 1,
            commit_b: None,
        }))
        .await?;
    // The operator types the wrong code: the server's round uses the wrong PRS, so the client's
    // verification of `server_kc` fails.
    server.submit_code(&client_id, "87654321").await?;
    let ya = read_server_auth(&mut client).await?;
    let round = answer_auth(b"12345678", &handshake_hash, 1, 1, &ya, [0x33; 32], None)?;
    client
        .send_json(&Incoming::ClientPairAuth(ClientPairAuth {
            pake_msg_2: URL_SAFE_NO_PAD.encode(round.share),
        }))
        .await?;
    let outcome = read_server_confirm(&mut client, &round.expected_server_tag).await;
    assert!(outcome.is_err(), "the server's tag must not verify");
    client
        .send_json(&Incoming::PairAbort(PairAbort {
            reason: "pairing_code_mismatch".to_owned(),
        }))
        .await?;

    let failed = wait_for_event(&mut events, |event| {
        matches!(event, Event::PairingFailed { .. })
    })
    .await;
    assert!(matches!(failed, Event::PairingFailed { .. }));
    assert!(
        store.records().is_empty(),
        "an attempt without key confirmation stores nothing"
    );

    // The connection stays open after a key-confirmation failure.
    client.send_json(&player_state(true, 100, false)).await?;
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_pairing_message_without_an_attempt_is_a_protocol_error() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, mut events) = start_with_config(config(store)?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    client.activate().await?;

    // A pairing message when the server admitted no attempt is not answered.
    client
        .send_json(&Incoming::ClientPairInit(ClientPairInit {
            pairing_index: 1,
            commit_b: None,
        }))
        .await?;
    client.expect_closed().await?;

    let left = wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientLeft { .. })
    })
    .await;
    assert_eq!(
        left,
        Event::ClientLeft {
            reason: "protocol error".to_owned(),
        },
        "a client that pairs without being admitted is cut off"
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_pair_token_for_a_client_that_did_not_offer_the_method_is_refused() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    // The default `client/hello` offers no pairing method at all.
    client.activate().await?;

    let token = syncspin_core::pairing::token::encode_v0(&client.identity.public, &[0x42; 32]);
    let error = server
        .pair(&token)
        .await
        .expect_err("a token for a client that cannot pair is refused");
    assert!(
        format!("{error:#}").contains("did not offer the Pairing PSK method"),
        "got: {error:#}"
    );
    assert!(store.records().is_empty(), "a refused token stores nothing");

    // The refusal is the operator's mistake, not the client's: the connection survives and the
    // operator can still approve the client.
    server.approve(&client_id).await?;
    let activate = client
        .read_activate(|activities| activities.is_empty())
        .await?;
    assert!(
        activate
            .active_roles
            .unwrap_or_default()
            .contains(&"player@v1".to_owned()),
        "the client is still on a healthy connection and receives its roles"
    );

    // The refusal must not have ended the connection: no leave is reported.
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[cfg(feature = "pairing-code")]
#[tokio::test]
async fn entering_a_code_without_a_pairing_attempt_is_refused() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    client.activate().await?;

    let error = server
        .submit_code(&client.identity.public_base64(), "12345678")
        .await
        .expect_err("no attempt is in progress");
    assert!(
        format!("{error:#}").contains("no pairing attempt"),
        "got: {error:#}"
    );

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[cfg(feature = "pairing-code")]
#[tokio::test]
async fn a_pairing_attempt_that_is_never_answered_times_out() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, mut events) = start_with_config(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        storage: Some(store.clone()),
        pairing_timeout: Duration::from_millis(200),
        ..ServerConfig::new(SERVER_NAME, Identity::generate())
    })
    .await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    client
        .activate_with(hello_with_pairing(PairingMethod::StaticCode, None))
        .await?;
    server.approve(&client_id).await?;
    client.read_activate(|_| true).await?;

    server
        .start_pairing(&client_id, PairingMethod::StaticCode, None)
        .await?;
    read_pairing_activation(&mut client).await?;

    // The operator never enters the code, so the attempt is cancelled at its deadline.
    let failed = wait_for_event(&mut events, |event| {
        matches!(event, Event::PairingFailed { .. })
    })
    .await;
    match failed {
        Event::PairingFailed { reason, .. } => {
            assert!(reason.contains("timed out"), "got: {reason}")
        }
        other => bail!("expected PairingFailed, got {other:?}"),
    }
    let activate = client
        .read_activate(|activities| activities.is_empty())
        .await?;
    assert!(
        activate.pairing.is_none(),
        "the cancellation drops the pairing activity"
    );

    // The connection and its roles survive a cancelled attempt.
    client.send_json(&player_state(true, 100, false)).await?;
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[cfg(feature = "pairing-code")]
#[tokio::test]
async fn a_pairing_index_that_was_never_activated_is_a_protocol_error() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, mut events) = start_with_config(config(store)?).await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    client
        .activate_with(hello_with_pairing(PairingMethod::StaticCode, None))
        .await?;
    server.approve(&client_id).await?;
    client.read_activate(|_| true).await?;

    server
        .start_pairing(&client_id, PairingMethod::StaticCode, None)
        .await?;
    read_pairing_activation(&mut client).await?;

    // The client reports an activation the server never sent.
    client
        .send_json(&Incoming::ClientPairPending(ClientPairPending {
            pairing_index: 999,
            message: None,
        }))
        .await?;
    client.expect_closed().await?;

    let left = wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientLeft { .. })
    })
    .await;
    assert_eq!(
        left,
        Event::ClientLeft {
            reason: "protocol error".to_owned(),
        },
        "an activation the server never admitted is a protocol error"
    );
    server.shutdown().await?;
    Ok(())
}

#[cfg(feature = "pairing-code")]
#[tokio::test]
async fn a_client_whose_gate_is_closed_reports_pair_pending_and_waits_for_the_code() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, _events) = start_with_config(config(store)?).await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    client
        .activate_with(hello_with_pairing(PairingMethod::StaticCode, None))
        .await?;
    server.approve(&client_id).await?;
    client.read_activate(|_| true).await?;

    server
        .start_pairing(&client_id, PairingMethod::StaticCode, None)
        .await?;
    read_pairing_activation(&mut client).await?;

    // A `pair-pending` with the admitted index holds the attempt back without an error, and the
    // client then starts it properly.
    client
        .send_json(&Incoming::ClientPairPending(ClientPairPending {
            pairing_index: 1,
            message: None,
        }))
        .await?;
    client
        .send_json(&Incoming::ClientPairInit(ClientPairInit {
            pairing_index: 1,
            commit_b: None,
        }))
        .await?;
    server.submit_code(&client_id, "12345678").await?;
    // A `server/pair-auth` is the proof the attempt started after the pending report.
    read_server_auth(&mut client).await?;

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[cfg(feature = "pairing-code")]
#[tokio::test]
async fn a_bad_client_key_confirmation_aborts_the_attempt() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let (server, port, mut events) = start_with_config(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        storage: Some(store.clone()),
        pairing_timeout: Duration::from_secs(5),
        ..ServerConfig::new(SERVER_NAME, Identity::generate())
    })
    .await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    client
        .activate_with(hello_with_pairing(PairingMethod::StaticCode, None))
        .await?;
    server.approve(&client_id).await?;
    client.read_activate(|_| true).await?;

    server
        .start_pairing(&client_id, PairingMethod::StaticCode, None)
        .await?;
    read_pairing_activation(&mut client).await?;
    let handshake_hash = *client
        .noise
        .as_ref()
        .expect("the handshake finished")
        .handshake_hash();
    client
        .send_json(&Incoming::ClientPairInit(ClientPairInit {
            pairing_index: 1,
            commit_b: None,
        }))
        .await?;
    server.submit_code(&client_id, "12345678").await?;
    let ya = read_server_auth(&mut client).await?;
    let round = answer_auth(b"12345678", &handshake_hash, 1, 1, &ya, [0x44; 32], None)?;
    client
        .send_json(&Incoming::ClientPairAuth(ClientPairAuth {
            pake_msg_2: URL_SAFE_NO_PAD.encode(round.share),
        }))
        .await?;
    read_server_confirm(&mut client, &round.expected_server_tag).await?;

    // The client's tag does not verify: the server answers with `pair/abort`, stores nothing and
    // keeps the connection open.
    client
        .send_json(&Incoming::ClientPairConfirm(ClientPairConfirm {
            client_kc: URL_SAFE_NO_PAD.encode([0u8; 64]),
            wrapped_nonce_b: None,
        }))
        .await?;
    let abort = client
        .read_until(|message| match message {
            Incoming::PairAbort(abort) => Some(abort),
            _ => None,
        })
        .await?;
    assert_eq!(abort.reason, "pairing_code_mismatch");

    let failed = wait_for_event(&mut events, |event| {
        matches!(event, Event::PairingFailed { .. })
    })
    .await;
    match failed {
        Event::PairingFailed { reason, .. } => {
            assert!(reason.contains("pairing_code_mismatch"), "got: {reason}")
        }
        other => bail!("expected PairingFailed, got {other:?}"),
    }
    assert!(
        store.records().is_empty(),
        "a failed key confirmation stores nothing"
    );

    client.send_json(&player_state(true, 100, false)).await?;
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[cfg(feature = "pairing-code")]
#[tokio::test]
async fn a_record_is_stored_even_when_the_live_promotion_fails() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let server_identity = Identity::generate();
    let (server, port, mut events) = start_with_config(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        storage: Some(store.clone()),
        pairing_timeout: Duration::from_secs(5),
        ..ServerConfig::new(SERVER_NAME, server_identity)
    })
    .await?;
    let mut client = FakeClient::connect(port).await?;
    let client_id = client.identity.public_base64();
    client.handshake(Suite::ChaChaPoly).await?;
    client
        .activate_with(hello_with_pairing(PairingMethod::StaticCode, None))
        .await?;
    server.approve(&client_id).await?;
    client.read_activate(|_| true).await?;

    server
        .start_pairing(&client_id, PairingMethod::StaticCode, None)
        .await?;
    read_pairing_activation(&mut client).await?;
    let handshake_hash = *client
        .noise
        .as_ref()
        .expect("the handshake finished")
        .handshake_hash();
    client
        .send_json(&Incoming::ClientPairInit(ClientPairInit {
            pairing_index: 1,
            commit_b: None,
        }))
        .await?;
    server.submit_code(&client_id, "12345678").await?;
    let ya = read_server_auth(&mut client).await?;
    let psk = [0x55; 32];
    let round = answer_auth(b"12345678", &handshake_hash, 1, 1, &ya, psk, None)?;
    client
        .send_json(&Incoming::ClientPairAuth(ClientPairAuth {
            pake_msg_2: URL_SAFE_NO_PAD.encode(round.share),
        }))
        .await?;
    read_server_confirm(&mut client, &round.expected_server_tag).await?;
    client
        .send_json(&Incoming::ClientPairConfirm(ClientPairConfirm {
            client_kc: URL_SAFE_NO_PAD.encode(round.client_tag),
            wrapped_nonce_b: None,
        }))
        .await?;
    client
        .send_json(&Incoming::ClientPairFinalize(ClientPairFinalize {
            long_term_psk: None,
            wrapped_psk: Some(URL_SAFE_NO_PAD.encode(round.wrapped_psk)),
        }))
        .await?;
    client
        .read_pairing(|message| match message {
            Incoming::ServerPairFinalize(_) => Some(()),
            _ => None,
        })
        .await?;

    // The record is stored before the re-handshake, so a client that abandons the promotion still
    // leaves the pairing in place.
    assert_eq!(
        store.record_for(&client_id).map(|record| record.psk),
        Some(psk),
        "the record outlives the promotion"
    );
    let paired = wait_for_event(&mut events, |event| matches!(event, Event::Paired { .. })).await;
    assert_eq!(
        paired,
        Event::Paired {
            client_id: client_id.clone()
        }
    );

    // The client drops instead of answering the re-handshake: the connection ends as lost.
    client.close().await?;
    let left = wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientLeft { .. })
    })
    .await;
    assert_eq!(
        left,
        Event::ClientLeft {
            reason: "connection lost".to_owned(),
        },
        "a promotion that cannot finish is reported as a lost connection"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unpair_removes_the_record_of_a_client_without_a_live_connection() -> Result<()> {
    let store = std::sync::Arc::new(MemoryStore::default());
    let client_id = Identity::generate().public_base64();
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk: [0x5a; 32],
    })?;

    let (server, _port, _events) = start_with_config(config(store.clone())?).await?;
    server.unpair(&client_id).await?;
    assert!(
        store.record_for(&client_id).is_none(),
        "unpairing a client that is offline still removes its record"
    );
    server.shutdown().await?;
    Ok(())
}
