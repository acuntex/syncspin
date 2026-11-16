//! Hermetic tests for the Noise layer.
//!
//! The peer side is built directly on `snow` rather than on another wrapper, so the tests pin
//! the wire behaviour - initiator vs. responder, PSK location, prologue and handshake payloads -
//! instead of trusting the code under test twice. No network and no fixture is involved.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, Keypair, TransportState as SnowTransportState};
use syncspin_core::noise::{
    psk_id_for, Identity, Responder, Suite, TransportState, MAX_MESSAGE_LEN, NOISE_PARAMS,
    SENTINEL_PSK, SENTINEL_PSK_ID,
};

/// A cleartext `client/init` announcing `suite`, as the first half of the prologue.
fn client_init(identity: &Identity, suite: Suite) -> String {
    format!(
        r#"{{"type":"client/init","payload":{{"client_id":"{}","version":1,"suite":"{}"}}}}"#,
        identity.public_base64(),
        suite.wire_name()
    )
}

/// A cleartext `server/init` with the given server id, as the second half of the prologue.
fn server_init(server_id: &str) -> String {
    format!(r#"{{"type":"server/init","payload":{{"server_id":"{server_id}","version":1}}}}"#)
}

/// The prologue both sides mix in: the exact init bytes, in wire order.
fn prologue(identity: &Identity, server_id: &str, suite: Suite) -> Vec<u8> {
    let mut bytes = client_init(identity, suite).into_bytes();
    bytes.extend_from_slice(server_init(server_id).as_bytes());
    bytes
}

/// The PSK metadata payload the server sends inside Noise message 1.
fn handshake_metadata() -> String {
    format!(r#"{{"psk_id":"{SENTINEL_PSK_ID}","psk_category":"sn"}}"#)
}

fn generate_keypair(suite: Suite) -> Keypair {
    Builder::new(suite.params().parse().expect("valid Noise parameters"))
        .generate_keypair()
        .expect("generate an X25519 keypair")
}

/// Builds the initiator exactly as a Sendspin server does, using the suite the client announced.
fn initiator(
    server: &Keypair,
    client_public: &[u8],
    prologue: &[u8],
    suite: Suite,
) -> HandshakeState {
    Builder::new(suite.params().parse().expect("valid Noise parameters"))
        .local_private_key(&server.private)
        .expect("set the local static key")
        .remote_public_key(client_public)
        .expect("set the peer static key")
        .psk(2, &SENTINEL_PSK)
        .expect("set the handshake PSK")
        .prologue(prologue)
        .expect("set the Noise prologue")
        .build_initiator()
        .expect("build the Noise initiator")
}

fn write(handshake: &mut HandshakeState, payload: &[u8]) -> Vec<u8> {
    let mut message = vec![0u8; MAX_MESSAGE_LEN];
    let len = handshake
        .write_message(payload, &mut message)
        .expect("write a Noise handshake message");
    message.truncate(len);
    message
}

fn read(handshake: &mut HandshakeState, message: &[u8]) -> Vec<u8> {
    let mut payload = vec![0u8; MAX_MESSAGE_LEN];
    let len = handshake
        .read_message(message, &mut payload)
        .expect("read a Noise handshake message");
    payload.truncate(len);
    payload
}

/// Runs the handshake under `suite` and returns our transport plus the initiator's, so both
/// directions of the cipher state are exercised independently.
fn completed_handshake(suite: Suite) -> (TransportState, SnowTransportState) {
    let server = generate_keypair(suite);
    let client = Identity::generate();
    let prologue = prologue(&client, &URL_SAFE_NO_PAD.encode(&server.public), suite);

    let mut initiator = initiator(&server, &client.public, &prologue, suite);
    let mut responder = Responder::new(&client, &prologue).expect("build the responder");
    assert_eq!(
        responder.suite(),
        suite,
        "the responder must run the suite its own client/init announced"
    );

    let metadata = handshake_metadata();
    let message_1 = write(&mut initiator, metadata.as_bytes());
    assert_eq!(
        responder.read_message(&message_1).expect("read message 1"),
        metadata.as_bytes()
    );
    assert!(
        !responder.handshake_finished(),
        "one of two handshake messages is not a finished handshake"
    );

    let message_2 = responder.write_message().expect("write message 2");
    assert_eq!(
        read(&mut initiator, &message_2),
        b"{}",
        "message 2 must carry the literal empty JSON object"
    );
    assert!(
        responder.handshake_finished(),
        "both handshake messages should finish the handshake"
    );

    (
        responder.into_transport().expect("responder transport"),
        initiator
            .into_transport_mode()
            .expect("initiator transport"),
    )
}

#[test]
fn sentinel_psk_id_matches_the_published_value() {
    assert_eq!(psk_id_for(&SENTINEL_PSK), SENTINEL_PSK_ID);
    assert_eq!(SENTINEL_PSK_ID.len(), 43);
}

#[test]
fn psk_id_is_derived_from_the_label_and_the_key() {
    let other: [u8; 32] = std::array::from_fn(|i| i as u8);
    let other_id = psk_id_for(&other);

    // psk_id = base64url(SHA-256("sendspin-psk-id-v1" || psk)), unpadded.
    let mut hasher = Sha256::new();
    hasher.update(b"sendspin-psk-id-v1");
    hasher.update(other);
    assert_eq!(other_id, URL_SAFE_NO_PAD.encode(hasher.finalize()));

    assert_ne!(
        other_id,
        psk_id_for(&SENTINEL_PSK),
        "a different PSK must map to a different id"
    );
    assert_eq!(
        other_id,
        psk_id_for(&other),
        "the derivation must be deterministic"
    );
    assert_eq!(other_id.len(), 43);
    assert!(
        other_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "ids are unpadded base64url: {other_id}"
    );
}

#[test]
fn responder_completes_a_kkpsk2_handshake_with_a_snow_initiator() {
    // Both suites must carry traffic in both directions; the peer is `snow` itself, so a suite
    // this crate got wrong would disagree with it here rather than only with itself.
    for suite in Suite::ALL {
        let (mut responder, mut initiator) = completed_handshake(suite);

        let ciphertext = responder
            .encrypt(b"hello from the responder")
            .expect("responder encrypt");
        let mut plaintext = vec![0u8; MAX_MESSAGE_LEN];
        let len = initiator
            .read_message(&ciphertext, &mut plaintext)
            .expect("initiator decrypt");
        assert_eq!(&plaintext[..len], b"hello from the responder");

        let mut ciphertext = vec![0u8; MAX_MESSAGE_LEN];
        let len = initiator
            .write_message(b"hello from the initiator", &mut ciphertext)
            .expect("initiator encrypt");
        assert_eq!(
            responder
                .decrypt(&ciphertext[..len])
                .expect("responder decrypt"),
            b"hello from the initiator"
        );

        // The transport nonce advances per message, so equal plaintexts differ on the wire.
        let first = responder.encrypt(b"same plaintext").expect("first encrypt");
        let second = responder
            .encrypt(b"same plaintext")
            .expect("second encrypt");
        assert_ne!(first, second, "transport nonces must never repeat");
    }
}

#[test]
fn an_aesgcm_handshake_completes_against_a_snow_peer() {
    // The second mandatory suite, named explicitly so a build that lost it fails here and not
    // only inside the loop above.
    let (mut responder, mut initiator) = completed_handshake(Suite::AesGcm);
    assert_eq!(responder.suite(), Suite::AesGcm);

    let ciphertext = responder.encrypt(b"aes-gcm").expect("encrypt");
    let mut plaintext = vec![0u8; MAX_MESSAGE_LEN];
    let len = initiator
        .read_message(&ciphertext, &mut plaintext)
        .expect("decrypt");
    assert_eq!(&plaintext[..len], b"aes-gcm");
}

#[test]
fn a_suite_that_disagrees_with_the_announcement_is_refused() {
    let server = generate_keypair(Suite::ChaChaPoly);
    let client = Identity::generate();
    // The client announces AES-GCM...
    let prologue = prologue(
        &client,
        &URL_SAFE_NO_PAD.encode(&server.public),
        Suite::AesGcm,
    );

    // ...so asking for ChaCha must be refused, not answered with a ChaCha handshake the peer
    // cannot follow.
    let Err(error) = Responder::with_suite(&client, Suite::ChaChaPoly, &prologue) else {
        panic!("an announced suite must not be overridden");
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("25519_AESGCM_SHA256") && message.contains("25519_ChaChaPoly_SHA256"),
        "the error must name both suites, got: {message}"
    );

    // The same announcement does build a responder for the suite it names.
    let responder =
        Responder::with_suite(&client, Suite::AesGcm, &prologue).expect("the announced suite");
    assert_eq!(responder.suite(), Suite::AesGcm);
}

#[test]
fn an_unknown_suite_is_refused_rather_than_downgraded() {
    // A name this build does not implement has no `Suite` value at all, so nothing can silently
    // fall back to ChaCha.
    for name in ["25519_Foo_SHA256", "", "Noise_KKpsk2_25519_AESGCM_SHA256"] {
        assert_eq!(Suite::from_wire_name(name), None, "{name:?} is not a suite");
    }
    for suite in Suite::ALL {
        assert_eq!(Suite::from_wire_name(suite.wire_name()), Some(suite));
    }

    // A prologue announcing such a name is rejected before any key is used.
    let server = generate_keypair(Suite::ChaChaPoly);
    let client = Identity::generate();
    let mut prologue = format!(
        r#"{{"type":"client/init","payload":{{"client_id":"{}","version":1,"suite":"25519_Foo_SHA256"}}}}"#,
        client.public_base64()
    )
    .into_bytes();
    prologue.extend_from_slice(server_init(&URL_SAFE_NO_PAD.encode(&server.public)).as_bytes());

    let Err(error) = Responder::new(&client, &prologue) else {
        panic!("an unknown suite must be refused");
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("25519_Foo_SHA256"),
        "the error must name the refused suite, got: {message}"
    );

    // A client/init that announces no suite at all is refused too: the field is required, and a
    // missing one is not an invitation to use ChaCha.
    let mut unnamed = format!(
        r#"{{"type":"client/init","payload":{{"client_id":"{}","version":1}}}}"#,
        client.public_base64()
    )
    .into_bytes();
    unnamed.extend_from_slice(server_init(&URL_SAFE_NO_PAD.encode(&server.public)).as_bytes());
    let Err(error) = Responder::new(&client, &unnamed) else {
        panic!("a missing suite must be refused");
    };
    assert!(
        format!("{error:#}").contains("suite"),
        "the error must name the missing field, got: {error:#}"
    );
}

#[test]
fn a_responder_whose_suite_the_peer_does_not_use_fails_message_1() {
    // No silent downgrade: a responder built for the other suite cannot read the initiator's
    // first message, and the handshake stops there.
    let server = generate_keypair(Suite::ChaChaPoly);
    let client = Identity::generate();
    let prologue = prologue(
        &client,
        &URL_SAFE_NO_PAD.encode(&server.public),
        Suite::ChaChaPoly,
    );
    let mut initiator = initiator(&server, &client.public, &prologue, Suite::ChaChaPoly);
    let message_1 = write(&mut initiator, handshake_metadata().as_bytes());

    let mut responder = Responder::with_peer_suite(
        &client,
        &server
            .public
            .as_slice()
            .try_into()
            .expect("an X25519 public key is 32 bytes"),
        Suite::AesGcm,
        &prologue,
    )
    .expect("the responder builds for its own suite");
    assert!(
        responder.read_message(&message_1).is_err(),
        "a ChaCha ciphertext must not authenticate under AES-GCM"
    );
}

#[test]
fn a_changed_psk_produces_a_message_2_that_the_original_initiator_rejects() {
    let server = generate_keypair(Suite::ChaChaPoly);
    let client = Identity::generate();
    let prologue = prologue(
        &client,
        &URL_SAFE_NO_PAD.encode(&server.public),
        Suite::ChaChaPoly,
    );

    // One initiator, two responders: the same message 1 reaches a responder that keeps the
    // Sentinel key and one that switches to another key, so message 2 differs only by the PSK.
    let mut first_initiator = initiator(&server, &client.public, &prologue, Suite::ChaChaPoly);
    let metadata = handshake_metadata();
    let message_1 = write(&mut first_initiator, metadata.as_bytes());

    let mut sentinel = Responder::new(&client, &prologue).expect("build the sentinel responder");
    sentinel
        .read_message(&message_1)
        .expect("read message 1 with the sentinel key");
    let sentinel_message_2 = sentinel.write_message().expect("write message 2");

    let other: [u8; 32] = std::array::from_fn(|index| index as u8 ^ 0x5a);
    let mut changed = Responder::new(&client, &prologue).expect("build the changed responder");
    changed
        .read_message(&message_1)
        .expect("read message 1 with the sentinel key");
    changed.set_psk(&other).expect("select another PSK");
    let changed_message_2 = changed.write_message().expect("write message 2");

    assert_ne!(
        sentinel_message_2, changed_message_2,
        "message 2 must authenticate the selected PSK"
    );

    // The initiator only holds the Sentinel key, so the changed message 2 must not authenticate.
    let mut payload = vec![0u8; MAX_MESSAGE_LEN];
    assert!(
        first_initiator
            .read_message(&changed_message_2, &mut payload)
            .is_err(),
        "an initiator with the Sentinel key must reject a message 2 sealed with another key"
    );

    // A fresh initiator with the Sentinel key still completes against the sentinel responder,
    // which pins that the rejection above came from the key and not from the sequence.
    let mut sentinel_initiator = initiator(&server, &client.public, &prologue, Suite::ChaChaPoly);
    let message_1 = write(&mut sentinel_initiator, metadata.as_bytes());
    let mut sentinel = Responder::new(&client, &prologue).expect("build the sentinel responder");
    assert_eq!(
        sentinel.read_message(&message_1).expect("read message 1"),
        metadata.as_bytes()
    );
    let message_2 = sentinel.write_message().expect("write message 2");
    assert_eq!(read(&mut sentinel_initiator, &message_2), b"{}");
}

#[test]
fn a_tampered_prologue_fails_the_handshake() {
    let server = generate_keypair(Suite::ChaChaPoly);
    let client = Identity::generate();
    let server_id = URL_SAFE_NO_PAD.encode(&server.public);
    let prologue = prologue(&client, &server_id, Suite::ChaChaPoly);

    // Same server_id, so the responder can still find the initiator's static key, but the bytes
    // mixed into the handshake differ from the initiator's copy.
    let mut tampered = prologue.clone();
    tampered.insert(0, b' ');

    let mut initiator = initiator(&server, &client.public, &prologue, Suite::ChaChaPoly);
    let mut responder = Responder::new(&client, &tampered).expect("server_id still parses");

    let message_1 = write(&mut initiator, handshake_metadata().as_bytes());
    assert!(
        responder.read_message(&message_1).is_err(),
        "a prologue that differs from the initiator's must fail message 1"
    );
}

#[test]
fn the_transport_carries_the_handshake_hash_both_sides_agree_on() {
    let server = generate_keypair(Suite::ChaChaPoly);
    let client = Identity::generate();
    let prologue = prologue(
        &client,
        &URL_SAFE_NO_PAD.encode(&server.public),
        Suite::ChaChaPoly,
    );

    let mut first_initiator = initiator(&server, &client.public, &prologue, Suite::ChaChaPoly);
    let mut responder = Responder::new(&client, &prologue).expect("build the responder");
    let message_1 = write(&mut first_initiator, handshake_metadata().as_bytes());
    responder.read_message(&message_1).expect("read message 1");
    let message_2 = responder.write_message().expect("write message 2");
    assert_eq!(read(&mut first_initiator, &message_2), b"{}");

    // `h` is final once message 2 is processed, and both sides must hold the same 32 bytes.
    let initiator_hash: [u8; 32] = first_initiator
        .get_handshake_hash()
        .try_into()
        .expect("SHA-256 produces 32 bytes");
    let mut transport = responder.into_transport().expect("the handshake finishes");
    assert_eq!(
        transport.handshake_hash(),
        &initiator_hash,
        "a re-handshake would mix in a hash the peer does not share"
    );
    assert_ne!(transport.handshake_hash(), &[0u8; 32]);

    // Transport traffic does not move the handshake hash.
    let mut first_transport = first_initiator
        .into_transport_mode()
        .expect("the initiator finishes");
    let ciphertext = transport.encrypt(b"a message").expect("encrypt");
    let mut plaintext = vec![0u8; MAX_MESSAGE_LEN];
    first_transport
        .read_message(&ciphertext, &mut plaintext)
        .expect("decrypt");
    assert_eq!(transport.handshake_hash(), &initiator_hash);

    // A second handshake that uses `h` as its prologue completes and produces a different hash,
    // which is the property a re-handshake relies on.
    let mut second_initiator =
        initiator(&server, &client.public, &initiator_hash, Suite::ChaChaPoly);
    let peer: [u8; 32] = server
        .public
        .clone()
        .try_into()
        .expect("an X25519 public key is 32 bytes");
    let mut second_responder = Responder::with_peer(&client, &peer, &initiator_hash)
        .expect("build the responder on the previous hash");
    let metadata = handshake_metadata();
    let message_1 = write(&mut second_initiator, metadata.as_bytes());
    assert_eq!(
        second_responder
            .read_message(&message_1)
            .expect("read message 1"),
        metadata.as_bytes()
    );
    let message_2 = second_responder.write_message().expect("write message 2");
    assert_eq!(read(&mut second_initiator, &message_2), b"{}");
    let second_hash = *second_responder
        .into_transport()
        .expect("the second handshake finishes")
        .handshake_hash();
    assert_ne!(
        second_hash, initiator_hash,
        "a re-handshake must derive a new handshake hash"
    );
    let second_peer_hash: [u8; 32] = second_initiator
        .get_handshake_hash()
        .try_into()
        .expect("SHA-256 produces 32 bytes");
    assert_eq!(second_hash, second_peer_hash);
}

#[test]
fn into_transport_before_the_handshake_fails() {
    let server = generate_keypair(Suite::ChaChaPoly);
    let client = Identity::generate();
    let prologue = prologue(
        &client,
        &URL_SAFE_NO_PAD.encode(&server.public),
        Suite::ChaChaPoly,
    );

    let responder = Responder::new(&client, &prologue).expect("build the responder");
    assert!(
        responder.into_transport().is_err(),
        "transport mode must not start before both handshake messages"
    );
}

#[test]
fn transport_rejects_oversized_plaintext() {
    let (mut responder, _initiator) = completed_handshake(Suite::ChaChaPoly);

    // A Noise message is at most 65535 bytes including the 16-byte authentication tag, so the
    // largest plaintext is MAX_MESSAGE_LEN - 16 and filling it produces one full-size message.
    let largest = vec![0u8; MAX_MESSAGE_LEN - 16];
    assert_eq!(
        responder
            .encrypt(&largest)
            .expect("the largest fitting plaintext")
            .len(),
        MAX_MESSAGE_LEN
    );

    // One byte more must be rejected rather than silently fragmented.
    let err = responder
        .encrypt(&vec![0u8; MAX_MESSAGE_LEN - 15])
        .expect_err("an oversized plaintext must not be fragmented silently");
    let message = format!("{err:#}").to_lowercase();
    assert!(
        message.contains("noise") && message.contains("maximum"),
        "error should explain the Noise maximum, got: {message}"
    );

    // Ciphertexts are bounded by the same message size ...
    let err = responder
        .decrypt(&vec![0u8; MAX_MESSAGE_LEN + 1])
        .expect_err("an oversized ciphertext must be rejected");
    let message = format!("{err:#}").to_lowercase();
    assert!(
        message.contains("noise") && message.contains("maximum"),
        "error should explain the Noise maximum, got: {message}"
    );

    // ... and must carry at least the authentication tag.
    let err = responder
        .decrypt(&[0u8; 15])
        .expect_err("a ciphertext without a full tag must be rejected");
    let message = format!("{err:#}").to_lowercase();
    assert!(
        message.contains("noise") && message.contains("16-byte") && message.contains("tag"),
        "error should name the tag length, got: {message}"
    );
}

#[test]
fn identity_secret_base64_roundtrip() {
    let identity = Identity::generate();
    let encoded = identity.secret_base64();
    assert_eq!(encoded.len(), 43);
    assert_eq!(identity.public_base64().len(), 43);

    let decoded = Identity::from_secret_base64(&encoded).expect("decode the secret key");
    assert_eq!(decoded.public, identity.public);
    assert_eq!(decoded.secret, identity.secret);
    assert_eq!(decoded.public_base64(), identity.public_base64());

    for invalid in [
        "",
        "short",
        &"A".repeat(42),
        &"B".repeat(44),
        &"!".repeat(43),
    ] {
        assert!(
            Identity::from_secret_base64(invalid).is_err(),
            "non-canonical key {invalid:?} must be rejected"
        );
    }
}

#[test]
fn noise_params_match_the_protocol_suite() {
    // A typo in the suite name would otherwise surface only as a failed handshake.
    assert_eq!(NOISE_PARAMS, "Noise_KKpsk2_25519_ChaChaPoly_SHA256");
    assert_eq!(NOISE_PARAMS, Suite::ChaChaPoly.params());

    // Every suite carries the same pattern and DH; only the AEAD differs.
    for suite in Suite::ALL {
        assert!(
            suite.params().starts_with("Noise_KKpsk2_25519_")
                && suite.params().ends_with("_SHA256"),
            "{suite:?} must keep the pattern, DH and hash: {}",
            suite.params()
        );
        assert!(suite.params().contains(suite.wire_name()));
    }
    assert_ne!(Suite::AesGcm.params(), Suite::ChaChaPoly.params());
    assert_ne!(Suite::AesGcm.wire_name(), Suite::ChaChaPoly.wire_name());
}

#[test]
fn responder_new_requires_the_initiator_key_in_the_prologue() {
    let identity = Identity::generate();
    // A prologue of just the client/init document parses but names no initiator key.
    let client_only = client_init(&identity, Suite::ChaChaPoly);
    let Err(err) = Responder::new(&identity, client_only.as_bytes()) else {
        panic!("a prologue without server/init must be rejected");
    };
    let message = format!("{err:#}");
    assert!(
        message.contains("server_id") && message.contains("with_peer"),
        "error should name the missing key and the way out, got: {message}"
    );
}
