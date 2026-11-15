//! The dynamic pairing code's derivation, pinned to one fixed triple.
//!
//! `pairing.md` derives the code from the Noise handshake hash and the two nonces:
//!
//! ```text
//! digest = SHA-256("sendspin-pairing-code-derive-v1" || h || nonce_A || nonce_B)
//! ```
//!
//! The inputs below are fixed by this file - `h = 0x00..=0x1f`, `nonce_A = 0x40..=0x5f` and
//! `nonce_B = 0x80..=0x9f` - so the digits, the 24-byte code and the token are a vector: they were
//! computed from the spec's formula independently of this crate and must not be adjusted to make an
//! implementation agree.
#![cfg(feature = "pairing-code")]

use syncspin_core::pairing::code::{commitment, DynamicCode};
use syncspin_core::pairing::token::decode;

/// The handshake hash of the vector: `0x00, 0x01, ... 0x1f`.
fn handshake_hash() -> [u8; 32] {
    std::array::from_fn(|index| index as u8)
}

/// The server nonce of the vector: `0x40, 0x41, ... 0x5f`.
fn nonce_a() -> [u8; 32] {
    std::array::from_fn(|index| 0x40 + index as u8)
}

/// The client nonce of the vector: `0x80, 0x81, ... 0x9f`.
fn nonce_b() -> [u8; 32] {
    std::array::from_fn(|index| 0x80 + index as u8)
}

/// The six digits the vector's digest reduces to.
const DIGITS: &str = "782070";

/// The 24-byte code of the vector, as hex.
const QR_PAYLOAD_HEX: &str = "825c7330c1bbfbdc794c48f6a7623a2f9d6c0fd083d0a217";

/// The version-1 token carrying that code.
const QR_TOKEN: &str = "SP:1QJOHGMGBXP55Y6KMJD3KOYR9F6OWYD6QQPIKEFY";

/// `SHA-256("sendspin-pair-commit-v1" || nonce_B)` for the vector's `nonce_B`, as hex.
const COMMITMENT_HEX: &str = "fc91579d2561d9caa0c0b933ca3f976d6a860c6ee561ff24a1a790a649df957c";

/// Returns the lower-case hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").expect("writing into a String cannot fail");
        text
    })
}

#[test]
fn the_digits_and_the_qr_code_match_the_vector() {
    let code = DynamicCode::derive(&handshake_hash(), &nonce_a(), &nonce_b());

    assert_eq!(
        code.digits_text(),
        DIGITS,
        "the digest modulo 10^6, zero-padded to six digits"
    );
    assert_eq!(
        code.digits(),
        *DIGITS.as_bytes(),
        "the digits a host displays are the same six ASCII digits CPace uses as PRS"
    );
    assert_eq!(
        code.digits().len(),
        6,
        "the digits format is six characters"
    );
    assert!(
        code.digits().iter().all(u8::is_ascii_digit),
        "every digit is an ASCII decimal digit"
    );

    assert_eq!(hex(&code.qr_payload()), QR_PAYLOAD_HEX);
    assert_eq!(
        code.qr_payload(),
        <[u8; 24]>::try_from(&code.qr_payload()[..]).expect("24 bytes"),
        "the qr payload is exactly 24 bytes"
    );
}

#[test]
fn the_qr_token_is_the_version_1_token_of_the_code() {
    let code = DynamicCode::derive(&handshake_hash(), &nonce_a(), &nonce_b());

    assert_eq!(code.qr_token(), QR_TOKEN);
    let token = decode(&code.qr_token()).expect("the derived token decodes");
    assert_eq!(token.version, 1, "the dynamic code rides in version 1");
    assert_eq!(
        token.payload,
        code.qr_payload().to_vec(),
        "the token carries exactly the 24-byte code"
    );
}

#[test]
fn the_commitment_matches_the_vector() {
    assert_eq!(hex(&commitment(&nonce_b())), COMMITMENT_HEX);
}

#[test]
fn the_derivation_depends_on_every_input() {
    let code = DynamicCode::derive(&handshake_hash(), &nonce_a(), &nonce_b());

    let mut other_hash = handshake_hash();
    other_hash[0] ^= 0x01;
    assert_ne!(
        DynamicCode::derive(&other_hash, &nonce_a(), &nonce_b()).qr_payload(),
        code.qr_payload(),
        "a different handshake hash gives a different code"
    );

    let mut other_nonce_a = nonce_a();
    other_nonce_a[31] ^= 0x80;
    assert_ne!(
        DynamicCode::derive(&handshake_hash(), &other_nonce_a, &nonce_b()).qr_payload(),
        code.qr_payload(),
        "a different server nonce gives a different code"
    );

    let mut other_nonce_b = nonce_b();
    other_nonce_b[31] ^= 0x80;
    assert_ne!(
        DynamicCode::derive(&handshake_hash(), &nonce_a(), &other_nonce_b).qr_payload(),
        code.qr_payload(),
        "a different client nonce gives a different code"
    );
}

#[test]
fn a_leading_zero_digit_is_padded_not_dropped() {
    // The digest is public, so a test can search for an input whose reduction is below 100000 and
    // would print as five digits without the padding. Searching is deterministic: the counter is
    // the thing that changes, and the first match is a fixed input.
    let mut nonce = [0u8; 32];
    let mut found = None;
    for counter in 0u32..1_000 {
        nonce[..4].copy_from_slice(&counter.to_be_bytes());
        let digits = DynamicCode::derive(&handshake_hash(), &nonce_a(), &nonce).digits_text();
        if digits.starts_with('0') {
            found = Some(digits);
            break;
        }
    }
    let digits = found.expect("a reduction below 100000 occurs within the first few hundred draws");
    assert_eq!(digits.len(), 6, "a leading zero is written, not dropped");
    assert!(digits.starts_with('0'), "got: {digits}");
}

#[test]
fn the_commitment_is_not_the_nonce() {
    let committed = commitment(&nonce_b());
    assert_ne!(
        committed,
        nonce_b(),
        "the commitment is a digest, not the value it locks"
    );
    let mut other = nonce_b();
    other[0] ^= 0x01;
    assert_ne!(
        committed,
        commitment(&other),
        "a one-bit change gives a different commitment"
    );
}
