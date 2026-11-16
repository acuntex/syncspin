//! Pairing as the server: the approval gate, the Pairing PSK flow, both code flows and `unpair`.
//!
//! The token flow runs against the real `syncspin-client`, which is the one test that proves the
//! two halves agree on the wire. The code flows run against the fake client, because the client's
//! own code flow needs an operator gesture and a displayed code; its CPace half is written here
//! from the spec, so a bug shared by the two implementations cannot hide.

mod common;

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
use syncspin_server::{CodeFormat, PairingMethod, PairingRecord, PairingStore};

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

/// Builds one of the test servers, with a store and the pairing timeout tests can live with.
fn config(store: std::sync::Arc<MemoryStore>) -> Result<ServerConfig> {
    Ok(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        storage: Some(store),
        pairing_timeout: Duration::from_secs(5),
        ..ServerConfig::new(SERVER_NAME, Identity::generate())
    })
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
    writer.write(&[3u8; 480 * 4]);
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
    client.send_json(&player_state(true, 100, false)).await?;
    let start = client.read_stream_start().await?;
    assert_eq!(
        start.player.expect("the stream carries its format").codec,
        "pcm"
    );
    // The chunk written before the report was addressed to nobody; the next one reaches the
    // approved member.
    writer.write(&[4u8; 480 * 4]);
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
    client.send_json(&player_state(true, 100, false)).await?;
    client.read_stream_start().await?;
    writer.write(&[5u8; 480 * 4]);
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
    writer.write(&[6u8; 480 * 4]);
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
async fn a_client_that_cannot_use_its_record_is_refused() -> Result<()> {
    // `docs/spec-deviations.md`, "The server does not try the Sentinel key after a record fails":
    // the server announces the record it holds and refuses a
    // message that does not authenticate under it. It cannot retry the same message with the
    // Sentinel key, so a client that lost its record does not get an unpaired session from this
    // server; the record stays, and re-pairing is the way back.
    let store = std::sync::Arc::new(MemoryStore::default());
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    let psk = [0x77; 32];
    store.store_pairing(PairingRecord {
        client_id: client_id.clone(),
        psk,
    })?;

    let (server, port, mut events) = start_with_config(config(store.clone())?).await?;
    let mut client = FakeClient::connect(port).await?;
    client.identity = identity;
    let (mut responder, category) = client.begin_handshake_any(Suite::ChaChaPoly).await?;
    assert_eq!(category, "lt", "the server announces its record");
    responder.set_psk(&SENTINEL_PSK)?;
    let outcome = client.finish_handshake(responder).await;
    assert!(
        outcome.is_err(),
        "a message sealed with the Sentinel key must not be accepted"
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
