//! The pairing token's reference vectors and decoding rules (Sendspin spec, "Pairing Token").
//!
//! Every token string and every payload in this file is transcribed from the spec: the version-0
//! vector carries `client_key = 0x00..=0x1f` and `pairing_psk = 0xe0..=0xff`, the version-1 vector
//! carries the 24-byte dynamic pairing code `0xe0..=0xf7`. No value here may be adjusted to make an
//! implementation agree.

use proptest::prelude::*;
use syncspin_core::pairing::token::{decode, encode_v0};

/// The spec's version-0 vector, base32 with `2` transliterated to `9` and padding stripped.
const VERSION_0: &str = "SP:0AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYP6BYPC4PSOLZXH5DU6V97M5XXO74HR6LZ7J5PW674PT6X37T6757Y";

/// The spec's version-1 vector for the 24-byte dynamic pairing code `0xe0..=0xf7`.
const VERSION_1: &str = "SP:14DQ6FY7E4XTOP9HJ5LV6Z3PO57YPD4XT6T97N5Y";

/// The spec's `client_key` for the version-0 vector: `0x00, 0x01, ... 0x1f`.
fn vector_client_key() -> [u8; 32] {
    std::array::from_fn(|index| index as u8)
}

/// The spec's `pairing_psk` for the version-0 vector: `0xe0, 0xe1, ... 0xff`.
fn vector_pairing_psk() -> [u8; 32] {
    std::array::from_fn(|index| 0xe0 + index as u8)
}

/// Returns the error text for input the decoder must reject.
fn rejection(token: &str) -> String {
    decode(token)
        .expect_err("the input is not a pairing token")
        .to_string()
}

#[test]
fn the_version_0_vector_decodes_to_the_client_key_and_pairing_psk() {
    let token = decode(VERSION_0).expect("the spec's version-0 vector decodes");
    assert_eq!(token.version, 0, "the prefix character selects version 0");
    assert_eq!(
        token.payload.len(),
        64,
        "version 0 carries client_key and pairing_psk, 32 bytes each"
    );
    assert_eq!(&token.payload[..32], &vector_client_key()[..]);
    assert_eq!(&token.payload[32..], &vector_pairing_psk()[..]);
}

#[test]
fn encode_v0_emits_the_version_0_vector() {
    assert_eq!(
        encode_v0(&vector_client_key(), &vector_pairing_psk()),
        VERSION_0
    );
}

#[test]
fn the_version_1_vector_decodes_to_the_dynamic_pairing_code() {
    let token = decode(VERSION_1).expect("the spec's version-1 vector decodes");
    assert_eq!(token.version, 1, "the prefix character selects version 1");
    assert_eq!(token.payload.len(), 24, "version 1 carries a 24-byte code");
    assert_eq!(
        token.payload,
        (0xe0..=0xf7).collect::<Vec<u8>>(),
        "the payload is the code the spec names for this vector"
    );
}

#[test]
fn decoding_is_lenient_about_case_whitespace_and_the_prefix() {
    let expected = decode(VERSION_0).expect("the canonical token decodes");

    // Operator input: lower case, surrounded by whitespace, copied without the `SP:` prefix.
    let pasted = format!("\t {} \r\n", VERSION_0[3..].to_lowercase());
    let token =
        decode(&pasted).expect("a lower-case, space-padded token without the prefix decodes");
    assert_eq!(token, expected, "lenient input decodes to the same token");

    // The prefix is case-insensitive too, because the whole string is upper-cased first.
    let pasted = format!(" sp:{} ", VERSION_0[3..].to_lowercase());
    let token = decode(&pasted).expect("a lower-case prefix is accepted");
    assert_eq!(token, expected, "the prefix's case does not matter");
}

proptest! {
    /// The body is base32 over the whole payload, so every 64-byte payload survives the
    /// transliteration, the padding strip and the re-padding on the way back.
    #[test]
    fn a_round_trip_preserves_both_halves(
        client_key in prop::collection::vec(any::<u8>(), 32),
        psk in prop::collection::vec(any::<u8>(), 32),
    ) {
        let client_key: [u8; 32] = client_key.try_into().expect("the strategy draws 32 bytes");
        let psk: [u8; 32] = psk.try_into().expect("the strategy draws 32 bytes");

        let token = decode(&encode_v0(&client_key, &psk)).expect("an encoded token decodes");
        prop_assert_eq!(token.version, 0);
        prop_assert_eq!(&token.payload[..32], &client_key[..]);
        prop_assert_eq!(&token.payload[32..], &psk[..]);
    }
}

#[test]
fn an_unknown_version_is_rejected() {
    // The version character is `0` or `1`; `2` selects no payload this crate defines. The rest of
    // the token is the spec's version-0 vector, so only the version is wrong.
    let message = rejection(&format!("SP:2{}", &VERSION_0[4..]));
    assert!(
        message.contains("version"),
        "the error names the version problem, not the payload: {message}"
    );
}

#[test]
fn a_payload_shorter_than_its_version_defines_is_rejected() {
    // The version-1 vector's body is 24 bytes, which version 0 cannot use.
    let message = rejection(&format!("SP:0{}", &VERSION_1[4..]));
    assert!(
        message.contains("64"),
        "the error names the 64 bytes version 0 needs: {message}"
    );

    // `MZXW6YTBOI` is RFC 4648 §10's base32 for `foobar`: valid base32, 6 bytes, too short for
    // version 1's 24-byte code.
    let message = rejection("SP:1MZXW6YTBOI");
    assert!(
        message.contains("24"),
        "the error names the 24 bytes version 1 needs: {message}"
    );
}

#[test]
fn input_without_a_version_is_rejected() {
    rejection("");
    rejection("   ");
    rejection("SP:");
    rejection("SP:   ");
}

#[test]
fn a_body_outside_the_base32_alphabet_is_rejected() {
    // `MZXW6YTBO` is the start of RFC 4648's `foobar` body; `0` and `1` are not in the alphabet
    // (only `A`-`Z` and `2`-`7`, with `9` standing in for `2`).
    rejection("SP:1MZXW6YTB0");
    rejection("SP:1MZXW6YTB1");
    rejection("SP:1MZXW6YTBOI!");
    rejection("SP:1MZXW6YTB OI");
}

#[test]
fn padding_in_the_body_is_rejected() {
    // The body is defined as base32 with the `=` padding stripped, so padding is not part of a
    // token even though the decoder re-pads internally.
    rejection("SP:1MZXW6YTBOI=====");
}

#[test]
fn non_zero_padding_bits_are_rejected() {
    // The spec's version-1 vector with its last character changed from `Y` (base32 value 24) to
    // `Z` (25): the three low bits of the final character are padding, so a decoder that ignores
    // them returns the same 24 bytes. The spec's decoding step accepts exactly the leniency it
    // lists, so these bits must be zero.
    let mut body = VERSION_1[4..].to_string();
    body.pop();
    body.push('Z');
    let message = rejection(&format!("SP:1{body}"));
    assert!(
        message.contains("padding"),
        "the error names the padding bits: {message}"
    );
}

#[test]
fn debug_does_not_print_the_payload() {
    let token = decode(VERSION_0).expect("the spec's version-0 vector decodes");
    let debug = format!("{token:?}");
    assert!(
        !debug.contains("224"),
        "the first pairing-psk byte's value must not appear: {debug}"
    );
    assert!(
        !debug.contains("000102"),
        "the client key's leading bytes must not appear: {debug}"
    );
    assert!(
        debug.contains("64"),
        "the payload's length is safe to print: {debug}"
    );
}
