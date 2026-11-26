//! End-to-end tests of the Dynamic Pairing Code flow against the hermetic fake server.
//!
//! The connection is Sentinel-keyed, as `pairing.md` describes for a code-based pairing: nothing is
//! authenticated until the CPace round completes. The client draws a nonce per attempt, commits to
//! it in `client/pair-init`, derives the code once the server's `nonce_A` arrives, and emits it for
//! an operator. The fake server plays the operator: a test takes the emitted code and hands it back
//! as the entered code, so the CPace round starts from exactly what the client displayed.
//!
//! What the tests decide: the derivation matches a pinned vector, the digits and the QR token reach
//! the host, the commitment is opened by the revealed nonce, a failed `server_kc` retries with the
//! same code and the same deadline, the twentieth round aborts, and the round limit holds the next
//! attempt back until it is released.

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
    connect, AudioMode, ClientConfig, CodeFormat, CodeOutChannel, Event, EventStream, Identity,
    PairingFailure, PskCategory, Sink, StoredPsk, VolumePolicy, DEFAULT_PAIRING_TIMEOUT,
    DEFAULT_PAIRING_WINDOW,
};
use syncspin_core::messages::{PairingActivation, ServerActivate};
use syncspin_core::pairing::code::DynamicCode;
use syncspin_core::pairing::token;

use fake_server::{FakeServer, ServerOptions};

/// An in-memory store, with its records readable for the assertions.
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

/// The activation that admits a dynamic attempt with `format` as the first of a connection.
fn dynamic_activation(format: &str) -> ServerActivate {
    ServerActivate {
        activities: vec!["pairing".to_owned()],
        active_roles: Some(Vec::new()),
        pairing: Some(PairingActivation {
            method: "dynamic_pairing_code".to_owned(),
            format: Some(format.to_owned()),
        }),
    }
}

/// Builds a configuration that offers `formats` for the dynamic flow.
fn config_for(
    endpoint: &str,
    storage: Option<Arc<dyn Storage>>,
    formats: Vec<CodeFormat>,
) -> ClientConfig {
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
        static_pairing_code: None,
        pairing_window: DEFAULT_PAIRING_WINDOW,
        pairing_pending_text: None,
        code_formats: formats,
        code_out_channels: vec![CodeOutChannel::Display],
        #[cfg(feature = "artwork")]
        artwork_channels: Vec::new(),
        #[cfg(feature = "artwork")]
        max_artwork_bytes: syncspin_client::DEFAULT_MAX_ARTWORK_BYTES,
    }
}

/// Server options that play the dynamic flow in `format`, failing `failed_rounds` of them.
fn dynamic_options(format: &str, failed_rounds: usize) -> ServerOptions {
    ServerOptions {
        first_activate: Some(dynamic_activation(format)),
        dynamic_format: Some(format.to_owned()),
        fail_server_kc_rounds: failed_rounds,
        ..ServerOptions::default()
    }
}

/// Connects with the given configuration and returns the events and the handle.
async fn connect_to(config: ClientConfig) -> (EventStream, syncspin_client::ClientHandle) {
    let (handle, events) = connect(config, Box::new(NullSink))
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

/// Waits for one observation with the default timeout, or `None` when it did not arrive.
async fn observed<F: std::future::Future>(future: F) -> Option<F::Output> {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .ok()
}

/// Waits for the code the client emitted in `round`.
async fn expect_code(stream: &mut EventStream, format: CodeFormat, round: u32) -> String {
    match next_event(stream).await {
        Event::PairingCode {
            code,
            format: emitted,
            round: emitted_round,
        } => {
            assert_eq!(
                emitted, format,
                "the activation's format is the emitted one"
            );
            assert_eq!(emitted_round, round, "the emission names its round");
            code
        }
        other => panic!("expected PairingCode, got {other:?}"),
    }
}

/// The fixed inputs of the derivation vector.
fn vector_inputs() -> ([u8; 32], [u8; 32], [u8; 32]) {
    (
        std::array::from_fn(|index| index as u8),
        std::array::from_fn(|index| 0x40 + index as u8),
        std::array::from_fn(|index| 0x80 + index as u8),
    )
}

#[test]
fn the_code_derivation_matches_the_pinned_vector() {
    // The same fixed triple the core vector uses: h = 0x00..=0x1f, nonce_A = 0x40..=0x5f,
    // nonce_B = 0x80..=0x9f. The values were computed from the spec's formula, not from this
    // crate.
    let (h, nonce_a, nonce_b) = vector_inputs();
    let code = DynamicCode::derive(&h, &nonce_a, &nonce_b);

    assert_eq!(
        code.digits_text(),
        "782070",
        "the digest modulo 10^6, zero-padded"
    );
    assert_eq!(
        code.qr_token(),
        "SP:1QJOHGMGBXP55Y6KMJD3KOYR9F6OWYD6QQPIKEFY",
        "the 24-byte code as a version-1 token"
    );
    let decoded = token::decode(&code.qr_token()).expect("the token decodes");
    assert_eq!(decoded.payload, code.qr_payload().to_vec());
}

#[tokio::test]
async fn a_dynamic_attempt_emits_digits_and_pairs() {
    let storage = Arc::new(MemoryStorage::default());
    let mut server = FakeServer::start(dynamic_options("digits", 0))
        .await
        .unwrap();
    let (mut events, _handle) = connect_to(config_for(
        &server.endpoint(),
        Some(storage.clone()),
        vec![CodeFormat::Digits, CodeFormat::QrCode],
    ))
    .await;
    expect_connected(&mut events, &server).await;

    // The client advertises the method with exactly the channels and formats it can drive.
    let hello = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_hello())
        .await
        .expect("the fake server must see client/hello")
        .expect("the connection must not close before client/hello");
    let descriptor = hello
        .supported_pair_methods
        .dynamic_pairing_code
        .expect("a configured out-channel offers the dynamic method");
    assert_eq!(descriptor.formats, vec!["digits", "qr_code"]);
    assert_eq!(descriptor.out_channels, vec!["display"]);

    // `client/pair-init` locks the client's nonce before it knows the server's.
    let (index, commitment) = observed(server.wait_for_pair_commitment())
        .await
        .expect("the client must start the attempt")
        .expect("the connection must not close before client/pair-init");
    assert_eq!(index, 1, "the first pairing activation of the connection");
    let commitment = commitment.expect("the dynamic flow carries commit_B");
    assert_eq!(commitment.len(), 43, "32 bytes in unpadded base64url");
    assert_eq!(
        base64_url(&commitment).len(),
        32,
        "the commitment decodes to 32 bytes"
    );

    // The first round emits six digits, which the operator types into the server.
    let code = expect_code(&mut events, CodeFormat::Digits, 1).await;
    assert_eq!(code.len(), 6, "the digits format is six characters");
    assert!(
        code.bytes().all(|byte| byte.is_ascii_digit()),
        "got: {code}"
    );
    server.enter_pairing_code(&code);

    // The CPace round completes, the server verifies the opening and the binding, and the record
    // is written only after `server/pair-finalize`.
    let (client_kc, wrapped_nonce_b) = observed(server.wait_for_pair_confirm_message())
        .await
        .expect("the client must send client/pair-confirm")
        .expect("the connection must not close before client/pair-confirm");
    assert_eq!(client_kc.len(), 86, "an MCF tag is 64 bytes in base64url");
    let sealed = wrapped_nonce_b.expect("the dynamic flow reveals its nonce sealed");
    assert_eq!(sealed.len(), 64, "48 sealed bytes in unpadded base64url");
    assert_eq!(base64_url(&sealed).len(), 48);

    let delivered = observed(server.wait_for_pair_finalize())
        .await
        .expect("the client must send client/pair-finalize")
        .expect("the binding checks must pass");
    match next_event(&mut events).await {
        Event::Paired { server_id } => assert_eq!(server_id, server.server_id()),
        other => panic!("expected Paired, got {other:?}"),
    }
    let records = storage.records();
    assert_eq!(records.len(), 1, "one pairing produces exactly one record");
    assert_eq!(records[0].category, PskCategory::LongTerm);
    assert_eq!(records[0].psk, delivered.0);
    assert_eq!(records[0].server_id, server.server_id());
}

#[tokio::test]
async fn a_qr_code_attempt_emits_a_version_1_token() {
    let storage = Arc::new(MemoryStorage::default());
    let mut server = FakeServer::start(dynamic_options("qr_code", 0))
        .await
        .unwrap();
    let (mut events, _handle) = connect_to(config_for(
        &server.endpoint(),
        Some(storage.clone()),
        vec![CodeFormat::QrCode],
    ))
    .await;
    expect_connected(&mut events, &server).await;

    let _ = observed(server.wait_for_pair_commitment())
        .await
        .expect("the client must start the attempt");
    let code = expect_code(&mut events, CodeFormat::QrCode, 1).await;
    assert!(code.starts_with("SP:1"), "version 1 of a pairing token");
    let token = token::decode(&code).expect("the emitted token decodes");
    assert_eq!(token.version, 1);
    assert_eq!(token.payload.len(), 24, "the qr code is 24 bytes");

    // The harness runs the CPace round on the token's payload, as a server that scanned it would.
    server.enter_pairing_code(&code);
    let _ = observed(server.wait_for_pair_finalize())
        .await
        .expect("the client must send client/pair-finalize")
        .expect("the binding checks must pass");
    match next_event(&mut events).await {
        Event::Paired { .. } => {}
        other => panic!("expected Paired, got {other:?}"),
    }
    assert_eq!(storage.records().len(), 1);
}

#[tokio::test]
async fn a_failed_server_tag_retries_with_the_same_code() {
    let storage = Arc::new(MemoryStorage::default());
    let mut server = FakeServer::start(dynamic_options("digits", 2))
        .await
        .unwrap();
    let (mut events, _handle) = connect_to(config_for(
        &server.endpoint(),
        Some(storage.clone()),
        vec![CodeFormat::Digits],
    ))
    .await;
    expect_connected(&mut events, &server).await;

    let _ = observed(server.wait_for_pair_commitment())
        .await
        .expect("the client must start the attempt");
    let first = expect_code(&mut events, CodeFormat::Digits, 1).await;
    server.enter_pairing_code(&first);

    // Round 1 fails: the client asks for another round instead of aborting.
    assert!(
        observed(server.wait_for_pair_retry())
            .await
            .expect("the client must retry a failed round"),
        "the connection must stay open across the retry"
    );
    assert_eq!(
        expect_code(&mut events, CodeFormat::Digits, 2).await,
        first,
        "a retry keeps the code the operator already typed"
    );

    assert!(observed(server.wait_for_pair_retry())
        .await
        .expect("the client must retry the second failed round"),);
    assert_eq!(
        expect_code(&mut events, CodeFormat::Digits, 3).await,
        first,
        "the third round shows the same code"
    );

    // Round 3 verifies, so the pairing completes without a failure event in between.
    let _ = observed(server.wait_for_pair_finalize())
        .await
        .expect("the client must send client/pair-finalize")
        .expect("the verified round must complete");
    match next_event(&mut events).await {
        Event::Paired { .. } => {}
        other => panic!("expected Paired, got {other:?}"),
    }
    assert_eq!(
        storage.records().len(),
        1,
        "a retried attempt still produces one record"
    );
}

#[tokio::test]
async fn the_twentieth_failed_round_aborts_with_a_mismatch() {
    let mut server = FakeServer::start(dynamic_options("digits", 20))
        .await
        .unwrap();
    let (mut events, _handle) = connect_to(config_for(
        &server.endpoint(),
        Some(Arc::new(MemoryStorage::default())),
        vec![CodeFormat::Digits],
    ))
    .await;
    expect_connected(&mut events, &server).await;

    let _ = observed(server.wait_for_pair_commitment())
        .await
        .expect("the client must start the attempt");
    let code = expect_code(&mut events, CodeFormat::Digits, 1).await;
    server.enter_pairing_code(&code);

    // Rounds one to nineteen answer `client/pair-retry`; the twentieth aborts.
    let mut retries = 0;
    let mut round = 1;
    loop {
        match observed(server.observation()).await.flatten() {
            Some(fake_server::Observation::PairRetry) => {
                retries += 1;
                round += 1;
                assert!(
                    round <= 20,
                    "the client must not start a twenty-first round"
                );
                assert_eq!(
                    expect_code(&mut events, CodeFormat::Digits, round).await,
                    code,
                    "the code stays the same across the retries"
                );
                continue;
            }
            Some(fake_server::Observation::PairingAborted(reason)) => {
                assert_eq!(reason, "pairing_code_mismatch");
                break;
            }
            Some(fake_server::Observation::Closed) => {
                panic!("the client closed the connection instead of aborting the attempt")
            }
            Some(_) => continue,
            None => panic!("the connection ended before the attempt did"),
        }
    }
    assert_eq!(retries, 19, "twenty failed rounds admit nineteen retries");
    assert_eq!(
        next_event(&mut events).await,
        Event::PairingFailed {
            reason: PairingFailure::PairingCodeMismatch
        },
        "the twentieth round ends the attempt"
    );
}

#[tokio::test]
async fn the_round_limit_holds_the_next_attempt_back_until_released() {
    let mut server = FakeServer::start(dynamic_options("digits", 20))
        .await
        .unwrap();
    let (mut events, handle) = connect_to(config_for(
        &server.endpoint(),
        Some(Arc::new(MemoryStorage::default())),
        vec![CodeFormat::Digits],
    ))
    .await;
    expect_connected(&mut events, &server).await;
    let _ = observed(server.wait_for_pair_commitment())
        .await
        .expect("the client must start the attempt");
    let code = expect_code(&mut events, CodeFormat::Digits, 1).await;
    server.enter_pairing_code(&code);

    // Run the attempt into the limit.
    assert_eq!(
        observed(server.wait_for_pairing_abort())
            .await
            .expect("the client must abort at the limit")
            .as_deref(),
        Some("pairing_code_mismatch")
    );
    // Each of the twenty rounds emitted the code, so those events are ahead of the failure.
    let failure = loop {
        match next_event(&mut events).await {
            Event::PairingCode { .. } => continue,
            event => break event,
        }
    };
    assert_eq!(
        failure,
        Event::PairingFailed {
            reason: PairingFailure::PairingCodeMismatch
        }
    );

    // A new activation is held back: `client/pair-pending`, no `client/pair-init`.
    server.activate_dynamic_pairing("digits");
    let (index, _) = observed(server.wait_for_pair_pending())
        .await
        .expect("the client must report the held-back attempt")
        .expect("the connection must not close");
    assert_eq!(index, 2, "the second pairing activation of the connection");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server.wait_for_pair_init())
            .await
            .is_err(),
        "the exhausted round count withholds client/pair-init"
    );

    // The operator action releases it, and the fresh attempt commits to a new nonce.
    handle
        .control()
        .release_holdback()
        .await
        .expect("the release belongs to the process, not the attempt");
    let (_, commitment) = observed(server.wait_for_pair_commitment())
        .await
        .expect("the release starts the held-back attempt")
        .expect("the connection must not close");
    assert!(
        commitment.is_some(),
        "a released dynamic attempt is a fresh one, with its own commitment"
    );
}

#[tokio::test]
async fn rounds_that_end_before_a_confirmation_still_count_toward_the_limit() {
    let mut server = FakeServer::start(dynamic_options("digits", 0))
        .await
        .unwrap();
    let (mut events, handle) = connect_to(config_for(
        &server.endpoint(),
        Some(Arc::new(MemoryStorage::default())),
        vec![CodeFormat::Digits],
    ))
    .await;
    expect_connected(&mut events, &server).await;

    // Twenty attempts, each ending right after its code was emitted. No `server_kc` ever arrives,
    // so nothing but the emission of a code can make a round count.
    for index in 1..=20u32 {
        if index > 1 {
            server.activate_dynamic_pairing("digits");
        }
        let (reported, commitment) = observed(server.wait_for_pair_commitment())
            .await
            .expect("the client must start each attempt")
            .expect("the connection must not close");
        assert_eq!(reported, index, "activation {index} of this connection");
        assert!(
            commitment.is_some(),
            "each attempt commits to its own nonce, even one that never completes"
        );
        // The attempt ends under the cancelling activation, after its round began.
        server.cancel_pairing(&["metadata@v1"]);
    }

    // The twenty-first activation is held back even though no key confirmation ever failed.
    server.activate_dynamic_pairing("digits");
    let (index, _) = observed(server.wait_for_pair_pending())
        .await
        .expect("the client must report the held-back attempt")
        .expect("the connection must not close");
    assert_eq!(index, 21, "the activation after twenty emitted rounds");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server.wait_for_pair_init())
            .await
            .is_err(),
        "twenty emitted rounds hold the next attempt back"
    );

    // The operator action the spec requires admits it again.
    handle
        .control()
        .release_holdback()
        .await
        .expect("the release belongs to the process");
    let (index, _) = observed(server.wait_for_pair_commitment())
        .await
        .expect("the release starts the held-back attempt")
        .expect("the connection must not close");
    assert_eq!(index, 21, "the held-back activation keeps its index");
}

#[tokio::test]
async fn attempts_that_end_before_their_first_round_do_not_count() {
    let mut server = FakeServer::start(ServerOptions {
        first_activate: Some(dynamic_activation("digits")),
        dynamic_format: Some("digits".to_owned()),
        // The harness records the commitment and never begins a round, so no code is emitted.
        dynamic_pair_init: false,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(config_for(
        &server.endpoint(),
        Some(Arc::new(MemoryStorage::default())),
        vec![CodeFormat::Digits],
    ))
    .await;
    expect_connected(&mut events, &server).await;

    for index in 1..=21u32 {
        if index > 1 {
            server.activate_dynamic_pairing("digits");
        }
        let (reported, _) = observed(server.wait_for_pair_commitment())
            .await
            .expect("each attempt is admitted")
            .expect("the connection must not close");
        assert_eq!(reported, index, "activation {index} of this connection");
        server.cancel_pairing(&["metadata@v1"]);
    }

    // Twenty-one attempts ended before their first round, so nothing was counted and the next
    // activation is admitted rather than held back.
    server.activate_dynamic_pairing("digits");
    let (index, commitment) = observed(server.wait_for_pair_commitment())
        .await
        .expect("an attempt that never emitted a code is not counted")
        .expect("the connection must not close");
    assert_eq!(index, 22);
    assert!(commitment.is_some());
}

/// Decodes an unpadded base64url string, failing the assertion when it is malformed.
fn base64_url(value: &str) -> Vec<u8> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD
        .decode(value)
        .expect("the value is unpadded base64url")
}
