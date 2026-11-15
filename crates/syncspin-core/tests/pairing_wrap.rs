//! Wrapping under the CPace output: `K_wrap` and the suite's AEAD.
//!
//! Round trips prove the module agrees with itself; they cannot catch a self-consistent change
//! to the wire format. The pinned vectors below therefore come from an independent
//! implementation: `K_wrap = SHA-256(label || sid || ISK)` and ChaCha20-Poly1305 with a 12-byte
//! all-zero nonce, empty associated data and a 16-byte tag. Nothing here may be adjusted to make
//! the module agree - the construction is the spec's.
//!
//! The sids are shaped like the real one (`"sendspin-pair-pake-v1" || h || pairing_index ||
//! round`, 61 bytes) as well as the short fixed-length case, so an accidental length prefix or
//! fixed-size assumption in the derivation shows up here.

#![cfg(feature = "pairing-code")]

use syncspin_core::pairing::wrap::{k_wrap, unwrap, wrap, NONCE_LABEL, PSK_LABEL};

/// A 32-byte `sid` for the first pinned vector.
const SID: [u8; 32] = [0x11; 32];

/// A 64-byte CPace intermediate session key for the first pinned vector.
const ISK: [u8; 64] = [0x22; 64];

/// Renders bytes as lower-case hex, the form the pinned vectors are written in.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").expect("writing into a String cannot fail");
        text
    })
}

/// The 32-byte value under test: `0x00..=0x1f`.
fn value() -> [u8; 32] {
    std::array::from_fn(|index| index as u8)
}

#[test]
fn the_labels_are_the_spec_literals() {
    // The label is the only domain separation between the two sealed fields; a typo would
    // produce a key the peer never derives, so the bytes are asserted here.
    assert_eq!(PSK_LABEL, b"sendspin-pair-psk-wrap-v1");
    assert_eq!(NONCE_LABEL, b"sendspin-pair-nonce-wrap-v1");
    assert_ne!(PSK_LABEL, NONCE_LABEL);
}

#[test]
fn the_psk_wrap_matches_the_pinned_vector() {
    let key = k_wrap(PSK_LABEL, &SID, &ISK);
    assert_eq!(
        hex(&key),
        "a517011815f0b5e438e436f526d030c6d0ef30e74839fd89d84796b5cf25045b",
        "K_wrap for the PSK label"
    );

    let sealed = wrap(&key, &value());
    assert_eq!(
        hex(&sealed),
        "2ef0c2fe8a956770f3fabae169ce7ad3ffc9cc6f747c2265d6e04319a8dd002d\
         297f5f1713849ae344265b9e875b3a99",
        "ciphertext plus tag for the PSK label"
    );
    assert_eq!(
        unwrap(&key, &sealed).expect("a value wrapped with this key unwraps"),
        value()
    );
}

#[test]
fn the_nonce_wrap_matches_the_pinned_vector() {
    let key = k_wrap(NONCE_LABEL, &SID, &ISK);
    assert_eq!(
        hex(&key),
        "d448a45bda6a92e641592f317ff27c78e8c2b1e589a4f3070f75c84e058a8a0c",
        "K_wrap for the nonce label"
    );

    // The dynamic flow reveals `nonce_B`, whose commitment preimage is a fresh 32 bytes.
    let nonce_b: [u8; 32] = [0xa5; 32];
    let sealed = wrap(&key, &nonce_b);
    assert_eq!(
        unwrap(&key, &sealed).expect("a value wrapped with this key unwraps"),
        nonce_b
    );
    assert_ne!(
        &sealed[..32],
        &nonce_b[..],
        "the sealed form is ciphertext and a tag, never the value"
    );
}

#[test]
fn the_sid_enters_the_derivation_raw_at_its_real_length() {
    // A real `sid` is `"sendspin-pair-pake-v1"` followed by the 32-byte `h`, a 4-byte pairing
    // index and a 4-byte round: 61 bytes, not a 32-byte array.
    let mut sid = Vec::from(b"sendspin-pair-pake-v1".as_slice());
    sid.extend_from_slice(&[0x5a; 32]);
    sid.extend_from_slice(&7u32.to_be_bytes());
    sid.extend_from_slice(&1u32.to_be_bytes());
    assert_eq!(sid.len(), 61, "the vector's sid is the spec's shape");

    let nonce_b = [0xa5; 32];
    let key = k_wrap(NONCE_LABEL, &sid, &ISK);
    assert_eq!(
        hex(&key),
        "663a9c96b9b217347117d2e632df62e9a66afe80ba7d0d81e106d9e065c21bd5",
        "K_wrap for a 61-byte sid"
    );
    assert_eq!(
        hex(&wrap(&key, &nonce_b)),
        "1026fe23327ad8af87c238a1fc79eec6a24b6324b24d4eca532b72b50fa8acff\
         f5e2ea330e3cdc006823b44af3497a40",
        "ciphertext plus tag for a 61-byte sid"
    );
}

#[test]
fn a_tampered_ciphertext_fails_to_unwrap() {
    let key = k_wrap(PSK_LABEL, &SID, &ISK);
    let sealed = wrap(&key, &value());

    // Every byte is covered by the tag, so a change anywhere must be rejected: leading and
    // trailing ciphertext bytes, and both ends of the tag.
    for index in [0, 31, 32, 47] {
        let mut tampered = sealed;
        tampered[index] ^= 0x01;
        let error =
            unwrap(&key, &tampered).expect_err("a changed byte must not decrypt to a value");
        let message = error.to_string();
        assert!(
            !message.contains(&hex(&key)),
            "the error must not carry the key: {message}"
        );
        assert!(
            !message.contains(&hex(&value())),
            "the error must not carry the plaintext: {message}"
        );
    }
}

#[test]
fn a_wrong_label_derives_a_different_key() {
    let psk_key = k_wrap(PSK_LABEL, &SID, &ISK);
    let nonce_key = k_wrap(NONCE_LABEL, &SID, &ISK);
    assert_ne!(
        psk_key, nonce_key,
        "the label must separate the two wrapped fields"
    );

    // A `wrapped_psk` therefore cannot be opened as a `wrapped_nonce_B`, nor the reverse.
    let sealed = wrap(&psk_key, &value());
    unwrap(&nonce_key, &sealed).expect_err("the other label's key must not open the seal");
}

#[test]
fn a_wrong_sid_derives_a_different_key() {
    let key = k_wrap(PSK_LABEL, &SID, &ISK);

    let mut wrong_sid = SID;
    wrong_sid[0] ^= 0x01;
    let wrong_key = k_wrap(PSK_LABEL, &wrong_sid, &ISK);
    assert_eq!(
        hex(&wrong_key),
        "66eabeaf4b51368612d1cd2d66804620feb46465e4743bd478603114aacb8b60",
        "a sid with one changed bit derives a different key"
    );
    assert_ne!(key, wrong_key);

    let sealed = wrap(&key, &value());
    unwrap(&wrong_key, &sealed).expect_err("a relay with a different sid cannot open the seal");
}

#[test]
fn a_wrong_isk_derives_a_different_key() {
    let key = k_wrap(PSK_LABEL, &SID, &ISK);
    let mut wrong_isk = ISK;
    wrong_isk[63] ^= 0x01;
    let wrong_key = k_wrap(PSK_LABEL, &SID, &wrong_isk);
    assert_ne!(key, wrong_key);

    let sealed = wrap(&key, &value());
    unwrap(&wrong_key, &sealed).expect_err("a party without the ISK cannot open the seal");
}
