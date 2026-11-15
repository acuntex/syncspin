//! The pairing token: the single string an operator carries from a client into a server.
//!
//! Sendspin's "Pairing Token" section defines a token as a fixed `SP:` prefix, one version
//! character and a body:
//!
//! ```text
//! token = "SP:" || version || body
//! body  = base32(payload), padding stripped, every `2` transliterated to `9`
//! ```
//!
//! The body is [RFC 4648 §6] base32 with the `=` padding stripped. Transliterating `2` to `9`
//! keeps the whole token inside the QR code alphanumeric set (`0`-`9`, `A`-`Z`, `:`), so a token
//! survives a QR scan and a manual copy identically. Decoding reverses the transform and is
//! lenient about how the operator supplied the string - surrounding whitespace, case and a
//! missing `SP:` prefix - and strict about everything else.
//!
//! Two versions exist:
//!
//! - version `0` carries `client_key || pairing_psk`, 64 payload bytes: a raw Curve25519 public
//!   key followed by the client's pairing PSK. [`encode_v0`] builds it.
//! - version `1` carries the 24-byte dynamic pairing code of the `qr_code` emission format.
//!
//! A token is a credential: anyone holding it can pair a server with the client. Nothing here is
//! behind a feature gate - a token is text, not a PAKE - and neither [`Debug`] output nor an
//! error message ever contains payload bytes; both report lengths instead.
//!
//! The spec's reference vectors are asserted in `tests/pairing_token.rs`.
//!
//! [RFC 4648 §6]: https://www.rfc-editor.org/rfc/rfc4648#section-6

use std::fmt;

use anyhow::{anyhow, bail, Result};

/// Version 0's payload length: a 32-byte public key and a 32-byte pairing PSK.
const VERSION_0_PAYLOAD_LEN: usize = 64;

/// Version 1's payload length: the dynamic pairing code of the `qr_code` emission format.
const VERSION_1_PAYLOAD_LEN: usize = 24;

/// The RFC 4648 base32 alphabet, upper case: `A`-`Z` then `2`-`7`.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A decoded pairing token.
///
/// The payload is a credential; [`Debug`] prints its length, never its bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    /// The version character the token carried, as a number.
    pub version: u8,
    /// The decoded payload, exactly as long as the version defines.
    ///
    /// Bytes beyond that length that the token carried are dropped here: the spec reserves them
    /// for future extension and requires a decoder to ignore them.
    pub payload: Vec<u8>,
}

impl fmt::Debug for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The payload is the pairing credential. A derived `Debug` would print it byte by byte
        // into any log line that formats the token, so report only what is not secret.
        formatter
            .debug_struct("Token")
            .field("version", &self.version)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Encodes a version-0 pairing token: `client_key || pairing_psk` as base32.
///
/// `client_key` is the raw 32-byte Curve25519 public key whose base64url form is the client's
/// `client_id`; `psk` is the client's pairing PSK. The two must be the pair the client actually
/// uses, because a server selects and verifies the client's Noise identity from them.
///
/// # Example
///
/// ```
/// use syncspin_core::pairing::token::encode_v0;
///
/// // The spec's reference vector: client_key 0x00..=0x1f, pairing_psk 0xe0..=0xff.
/// let client_key = std::array::from_fn(|index| index as u8);
/// let psk = std::array::from_fn(|index| 0xe0 + index as u8);
/// assert_eq!(
///     encode_v0(&client_key, &psk),
///     "SP:0AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYP6BYPC4PSOLZXH5DU6V97M5XXO74HR6LZ7J5PW674PT6X37T6757Y"
/// );
/// ```
pub fn encode_v0(client_key: &[u8; 32], psk: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(VERSION_0_PAYLOAD_LEN);
    payload.extend_from_slice(client_key);
    payload.extend_from_slice(psk);
    encode(0, &payload)
}

/// Decodes a pairing token, or reports why the input is not one.
///
/// Lenient about operator formatting: surrounding whitespace is trimmed, ASCII case is folded
/// and the leading `SP:` is optional. Everything else follows the spec: the first remaining
/// character is the version, it must be one this crate defines, and the payload must be at least
/// as long as that version defines. Bytes past that length are reserved for future extension and
/// are dropped, so [`Token::payload`] always has exactly the version's length. Errors name a rule
/// or a length and never echo the input.
///
/// # Example
///
/// ```
/// use syncspin_core::pairing::token::decode;
///
/// // The spec's version-1 vector for the code 0xe0..=0xf7.
/// let token = decode("SP:14DQ6FY7E4XTOP9HJ5LV6Z3PO57YPD4XT6T97N5Y").expect("version 1");
/// assert_eq!(token.version, 1);
/// assert_eq!(token.payload, (0xe0..=0xf7).collect::<Vec<u8>>());
/// ```
pub fn decode(token: &str) -> Result<Token> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        bail!("a pairing token is empty");
    }

    // Folding case first makes both the prefix and the body case-insensitive; the versions this
    // crate defines are digits, so folding cannot change which version a token selects.
    let mut input = trimmed.as_bytes().to_vec();
    input.make_ascii_uppercase();
    if input.starts_with(b"SP:") {
        input.drain(..3);
    }

    let (version, required) = match input.first() {
        Some(b'0') => (0, VERSION_0_PAYLOAD_LEN),
        Some(b'1') => (1, VERSION_1_PAYLOAD_LEN),
        // The character is free text from the operator and could be part of a pasted key, so the
        // error does not repeat it.
        Some(_) => bail!("unsupported pairing token version"),
        None => bail!("a pairing token needs a version character"),
    };

    let mut payload = decode_body(&input[1..])?;
    if payload.len() < required {
        bail!(
            "a version {version} pairing token needs {required} payload bytes, this one has {}",
            payload.len()
        );
    }
    // Bytes beyond the version's payload are reserved for future extension, and the spec says a
    // decoder MUST ignore them: ignoring them here means no caller ever has to remember to.
    payload.truncate(required);
    Ok(Token { version, payload })
}

/// Encodes `payload` as a token of `version`, the inverse of [`decode`].
fn encode(version: u8, payload: &[u8]) -> String {
    let body = encode_body(payload);
    let mut token = String::with_capacity(4 + body.len());
    token.push_str("SP:");
    token.push((b'0' + version) as char);
    token.push_str(&body);
    token
}

/// Encodes a payload as a token body: base32, padding stripped, every `2` transliterated to `9`.
fn encode_body(payload: &[u8]) -> String {
    let encoded = base32_encode(payload);
    let unpadded = encoded.trim_end_matches('=');
    // The transliteration keeps the body inside the QR code alphanumeric set; `2` and `9` are
    // then the only characters that differ between a body and plain base32.
    unpadded.replace('2', "9")
}

/// Decodes a token body: `9` back to `2`, re-padded to a multiple of eight, base32-decoded.
fn decode_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut text = Vec::with_capacity(body.len() + 7);
    for &byte in body {
        match byte {
            // The one transliteration of the format, applied before the alphabet check because
            // `9` is not itself a base32 character.
            b'9' => text.push(b'2'),
            b'A'..=b'Z' | b'2'..=b'7' => text.push(byte),
            // Padding, whitespace inside the body, and anything else are not part of a token.
            _ => bail!("a pairing token body has a character outside the base32 alphabet"),
        }
    }
    while text.len() % 8 != 0 {
        text.push(b'=');
    }
    base32_decode(&text)
}

/// Encodes bytes as RFC 4648 §6 base32, upper case, padded with `=` to eight characters.
fn base32_encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(base32_len(bytes.len()));
    let mut buffer = 0u16;
    let mut bits = 0u32;
    for &byte in bytes {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            text.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
            // Drop the bits just consumed; `buffer` then holds only pending bits.
            buffer &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        text.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    while text.len() % 8 != 0 {
        text.push('=');
    }
    text
}

/// Decodes RFC 4648 §6 base32, ignoring any trailing `=` padding.
///
/// Fails on a character outside the alphabet, on a length base32 cannot produce, and on non-zero
/// padding bits. None of the three is written by a conformant encoder, and accepting any of them
/// would turn a malformed string into a valid token.
fn base32_decode(text: &[u8]) -> Result<Vec<u8>> {
    let end = text
        .iter()
        .rposition(|&byte| byte != b'=')
        .map_or(0, |index| index + 1);
    let mut bytes = Vec::with_capacity(end * 5 / 8);
    let mut buffer = 0u16;
    let mut bits = 0u32;
    for &byte in &text[..end] {
        let value = base32_value(byte).ok_or_else(|| {
            anyhow!("a pairing token body has a character outside the base32 alphabet")
        })?;
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    // A final quantum of 1, 3 or 6 characters leaves a whole five-bit symbol that no byte uses;
    // base32 only produces final quanta of 2, 4, 5, 7 or 8 characters. When those bits are zero
    // the input would otherwise decode to a shorter payload and pass unnoticed.
    if bits >= 5 {
        bail!("a pairing token body has a length base32 cannot encode");
    }
    if buffer != 0 {
        bail!("a pairing token body has non-zero padding bits");
    }
    Ok(bytes)
}

/// Maps one base32 character to its five-bit value.
fn base32_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'2'..=b'7' => Some(byte - b'2' + 26),
        _ => None,
    }
}

/// Returns how many characters base32 uses for `len` bytes, padding included.
fn base32_len(len: usize) -> usize {
    (len * 8).div_ceil(5).div_ceil(8) * 8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10's base32 examples, transcribed from the RFC.
    const RFC_4648: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "MY======"),
        (b"fo", "MZXQ===="),
        (b"foo", "MZXW6==="),
        (b"foob", "MZXW6YQ="),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI======"),
    ];

    /// The spec's version-1 vector for the code `0xe0..=0xf7`.
    const VERSION_1: &str = "SP:14DQ6FY7E4XTOP9HJ5LV6Z3PO57YPD4XT6T97N5Y";

    #[test]
    fn base32_matches_the_rfc_vectors() {
        for (bytes, base32) in RFC_4648 {
            assert_eq!(&base32_encode(bytes), base32, "encoding {base32:?}");
            assert_eq!(
                base32_decode(base32.as_bytes()).expect("the RFC's own base32 decodes"),
                *bytes,
                "decoding {base32:?}"
            );
        }
    }

    #[test]
    fn the_body_transliterates_two_to_nine() {
        // 0xd0 is 11010 000 in five-bit groups: value 26 is the alphabet's character `2`, so the
        // body carries `9A` and a decoder has to map the `9` back.
        assert_eq!(encode_body(&[0xd0]), "9A");
        assert!(!encode_body(&[0xd0]).contains('2'));
        assert_eq!(
            decode_body(b"9A").expect("a transliterated body decodes"),
            [0xd0]
        );
    }

    #[test]
    fn bodies_round_trip_at_every_length() {
        let payload: Vec<u8> = (0..=64).collect();
        for len in 0..=payload.len() {
            let body = encode_body(&payload[..len]);
            assert!(
                !body.contains('=') && !body.contains('2'),
                "a body is unpadded base32 with `2` transliterated: {body}"
            );
            assert_eq!(
                decode_body(body.as_bytes()).expect("a body we just encoded decodes"),
                payload[..len],
                "a {len}-byte payload survives the body transform"
            );
        }
    }

    #[test]
    fn the_version_1_encoder_matches_the_spec() {
        assert_eq!(encode(1, &(0xe0..=0xf7).collect::<Vec<u8>>()), VERSION_1);
    }

    #[test]
    fn extension_bytes_beyond_the_version_are_dropped() {
        // The spec reserves trailing payload bytes for future extension and requires a decoder to
        // ignore them: the token still decodes, and its payload is exactly the version's length.
        for (version, len) in [(0, VERSION_0_PAYLOAD_LEN), (1, VERSION_1_PAYLOAD_LEN)] {
            let payload: Vec<u8> = (0..len as u8 + 3).collect();
            let token = decode(&encode(version, &payload)).unwrap_or_else(|error| {
                panic!("a longer version-{version} payload decodes: {error}")
            });
            assert_eq!(token.version, version);
            assert_eq!(
                token.payload,
                payload[..len],
                "version {version} drops the three extension bytes"
            );
        }
    }

    #[test]
    fn a_body_of_a_length_base32_cannot_encode_is_rejected() {
        // Appending one zero symbol to a 24-byte body gives 41 characters, whose five-bit groups
        // leave one whole symbol over: 40 characters (25 bytes) is the nearest length base32 can
        // write. All those bits are zero, so only the quantum check can catch it.
        let body = format!("{VERSION_1}AA");
        let message = decode(&body).expect_err("41 body characters are not a base32 length");
        assert!(
            message.to_string().contains("length"),
            "the error names the length: {message}"
        );
    }

    #[test]
    fn an_invalid_character_is_reported_without_echoing_it() {
        let message = decode_body(b"A!")
            .expect_err("`!` is not base32")
            .to_string();
        assert!(!message.contains('!'), "the error must not echo: {message}");
    }

    #[test]
    fn debug_reports_the_length_only() {
        let token = Token {
            version: 0,
            payload: vec![0xe0; VERSION_0_PAYLOAD_LEN],
        };
        assert_eq!(
            format!("{token:?}"),
            "Token { version: 0, payload_len: 64 }",
            "the payload bytes must not reach a log line"
        );
    }
}
