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
    psk_id_for, Identity, Responder, TransportState, MAX_MESSAGE_LEN, NOISE_PARAMS, SENTINEL_PSK,
    SENTINEL_PSK_ID,
};

/// A cleartext `client/init` with the given client id, as the first half of the prologue.
fn client_init(identity: &Identity) -> String {
    format!(
        r#"{{"type":"client/init","payload":{{"client_id":"{}","version":1,"suite":"{}"}}}}"#,
        identity.public_base64(),
        "25519_ChaChaPoly_SHA256"
    )
}

/// A cleartext `server/init` with the given server id, as the second half of the prologue.
fn server_init(server_id: &str) -> String {
    format!(r#"{{"type":"server/init","payload":{{"server_id":"{server_id}","version":1}}}}"#)
}

/// The prologue both sides mix in: the exact init bytes, in wire order.
fn prologue(identity: &Identity, server_id: &str) -> Vec<u8> {
    let mut bytes = client_init(identity).into_bytes();
    bytes.extend_from_slice(server_init(server_id).as_bytes());
    bytes
}

/// The PSK metadata payload the server sends inside Noise message 1.
fn handshake_metadata() -> String {
    format!(r#"{{"psk_id":"{SENTINEL_PSK_ID}","psk_category":"sn"}}"#)
}

fn generate_keypair() -> Keypair {
    Builder::new(NOISE_PARAMS.parse().expect("valid Noise parameters"))
        .generate_keypair()
        .expect("generate an X25519 keypair")
}

/// Builds the initiator exactly as a Sendspin server does.
fn initiator(server: &Keypair, client_public: &[u8], prologue: &[u8]) -> HandshakeState {
    Builder::new(NOISE_PARAMS.parse().expect("valid Noise parameters"))
        .local_private_key(&server.private)
        .remote_public_key(client_public)
        .psk(2, &SENTINEL_PSK)
        .prologue(prologue)
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

/// Runs the handshake and returns our transport plus the initiator's, so both directions of the
/// cipher state are exercised independently.
fn completed_handshake() -> (TransportState, SnowTransportState) {
    let server = generate_keypair();
    let client = Identity::generate();
    let prologue = prologue(&client, &URL_SAFE_NO_PAD.encode(&server.public));

    let mut initiator = initiator(&server, &client.public, &prologue);
    let mut responder = Responder::new(&client, &prologue).expect("build the responder");

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
    let (mut responder, mut initiator) = completed_handshake();

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

#[test]
fn transport_rejects_oversized_plaintext() {
    let (mut responder, _initiator) = completed_handshake();

    // One Noise message is at most 65535 bytes including the 16-byte authentication tag.
    let err = responder
        .encrypt(&vec![0u8; MAX_MESSAGE_LEN])
        .expect_err("an oversized plaintext must not be fragmented silently");
    let message = format!("{err:#}").to_lowercase();
    assert!(
        message.contains("noise") && message.contains("maximum"),
        "error should explain the Noise maximum, got: {message}"
    );

    // The largest fitting plaintext still produces exactly one full-size message.
    let largest = vec![0u8; MAX_MESSAGE_LEN - 16];
    assert_eq!(
        responder
            .encrypt(&largest)
            .expect("the largest fitting plaintext")
            .len(),
        MAX_MESSAGE_LEN
    );
}

#[test]
fn identity_base64_roundtrip() {
    let identity = Identity::generate();
    let encoded = identity.secret_base64();
    assert_eq!(encoded.len(), 43);
    assert_eq!(identity.public_base64().len(), 43);

    let decoded = Identity::from_base64(&encoded).expect("decode the secret key");
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
            Identity::from_base64(invalid).is_err(),
            "non-canonical key {invalid:?} must be rejected"
        );
    }
}

#[test]
fn noise_params_match_the_protocol_suite() {
    // A typo in the suite name would otherwise surface only as a failed handshake.
    assert_eq!(NOISE_PARAMS, "Noise_KKpsk2_25519_ChaChaPoly_SHA256");
}

#[test]
fn responder_new_requires_the_initiator_key_in_the_prologue() {
    let identity = Identity::generate();
    let Err(err) = Responder::new(&identity, b"not the init exchange") else {
        panic!("a prologue without server/init must be rejected");
    };
    let message = format!("{err:#}");
    assert!(
        message.contains("server_id") && message.contains("with_peer"),
        "error should name the missing key and the way out, got: {message}"
    );
}
