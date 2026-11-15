//! Wrapping a pairing payload under the CPace output.
//!
//! The code-based flows never send two values in clear: the new long-term PSK and, in the
//! Dynamic Pairing Code Flow, the commitment opening `nonce_B`. Each is sealed under the PAKE's
//! intermediate session key with a key derived per field:
//!
//! ```text
//! K_wrap = SHA-256(label || sid || ISK)
//! sealed = AEAD(K_wrap, nonce = 12 zero bytes, aad = empty, value)
//! ```
//!
//! The concatenation is raw - no separator, no length prefix, no NUL terminator - and `ISK` is
//! the 64-byte CPace intermediate session key. The label separates the two fields, so a
//! `wrapped_nonce_B` cannot be replayed as a `wrapped_psk`; the `sid` binds the seal to one CPace
//! session, so a man in the middle that relays between two handshakes, whose differing `h` gives
//! each leg a different `sid`, derives a key on neither leg.
//!
//! A value is 32 bytes and its sealed form 48: the ciphertext plus a 16-byte authentication tag.
//! A payload that fails to authenticate is an error, never a zero or partially decrypted value,
//! and neither [`Debug`] output nor an error string ever carries the key, the value or the seal.
//!
//! # The AEAD is the suite's
//!
//! The spec seals with the AEAD of the connection's negotiated cipher suite. Sendspin defines
//! two suites - `25519_ChaChaPoly_SHA256` and `25519_AESGCM_SHA256` - and this crate offers the
//! first only ([`NOISE_SUITE`](crate::messages::NOISE_SUITE)), so the AEAD here is
//! ChaCha20-Poly1305. Offering `25519_AESGCM_SHA256` would mean selecting the AEAD from the
//! suite rather than fixing it in this module.
//!
//! The module is behind the `pairing-code` feature with [`pake`](super::pake): wrapping exists
//! only for the code flows, and the default build keeps no AEAD of its own.

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use sha2::{Digest, Sha256};

/// The label that derives the key for `wrapped_psk`.
pub const PSK_LABEL: &[u8] = b"sendspin-pair-psk-wrap-v1";

/// The label that derives the key for `wrapped_nonce_B`.
pub const NONCE_LABEL: &[u8] = b"sendspin-pair-nonce-wrap-v1";

/// The length of a wrapped value: 32 bytes.
const VALUE_LEN: usize = 32;

/// The length of the AEAD's authentication tag: 16 bytes.
const TAG_LEN: usize = 16;

/// The length of a sealed value: ciphertext plus tag, the spec's 48-byte field.
const SEALED_LEN: usize = VALUE_LEN + TAG_LEN;

/// The nonce every wrapping uses. A key is derived per field per session, so it seals exactly
/// one value and the zero nonce never repeats under the same key.
const NONCE_BYTES: [u8; 12] = [0u8; 12];

/// Derives `K_wrap = SHA-256(label || sid || ISK)`.
///
/// `label` is [`PSK_LABEL`] or [`NONCE_LABEL`], `sid` the CPace session id exactly as the PAKE
/// used it, and `isk` the 64-byte CPace intermediate session key. The three are concatenated
/// raw; their lengths are fixed by the protocol, so no delimiter is needed.
pub fn k_wrap(label: &[u8], sid: &[u8], isk: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(sid);
    hasher.update(isk);
    hasher.finalize().into()
}

/// Seals a 32-byte value under `K_wrap`, returning the 48-byte ciphertext and tag.
///
/// The nonce is twelve zero bytes and the associated data is empty, as the spec requires. A
/// key is used for one value only, which is what makes the fixed nonce safe.
///
/// # Example
///
/// ```
/// use syncspin_core::pairing::wrap::{unwrap, wrap};
///
/// // The key comes from `k_wrap` in a real flow; any 32 bytes will do here.
/// let key = [0x42; 32];
/// let value = [0x24; 32];
/// assert_eq!(unwrap(&key, &wrap(&key, &value)).expect("round trip"), value);
/// ```
pub fn wrap(key: &[u8; 32], value: &[u8; 32]) -> [u8; SEALED_LEN] {
    let mut sealed = [0u8; SEALED_LEN];
    sealed[..VALUE_LEN].copy_from_slice(value);

    // In-place detached keeps the encryption allocation-free; the tag is appended by hand to
    // match the spec's ciphertext-plus-tag field. A 32-byte value is far below the AEAD's
    // maximum, so sealing cannot fail.
    let tag = cipher(key)
        .encrypt_in_place_detached(&nonce(), &[], &mut sealed[..VALUE_LEN])
        .expect("ChaCha20-Poly1305 always seals a 32-byte value");
    sealed[VALUE_LEN..].copy_from_slice(&tag);
    sealed
}

/// Opens a 48-byte sealed value under `K_wrap`, returning the 32-byte value.
///
/// # Errors
///
/// Fails when the tag does not authenticate: a wrong key - a different label, `sid` or `ISK` -
/// or any changed byte of the ciphertext or tag. The error names no key, value or seal bytes.
pub fn unwrap(key: &[u8; 32], sealed: &[u8; SEALED_LEN]) -> Result<[u8; 32]> {
    let mut value = [0u8; VALUE_LEN];
    value.copy_from_slice(&sealed[..VALUE_LEN]);
    let tag = Tag::from_slice(&sealed[VALUE_LEN..]);

    cipher(key)
        .decrypt_in_place_detached(&nonce(), &[], &mut value, tag)
        .map_err(|_| anyhow!("the wrapped pairing value does not authenticate"))?;
    Ok(value)
}

/// Builds the cipher for `key`.
///
/// `new_from_slice` only fails on a key of the wrong length, and `key` is exactly 32 bytes, so
/// the failure is unreachable. The panic message carries no key material.
fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new_from_slice(key).expect("a ChaCha20-Poly1305 key is 32 bytes")
}

/// Returns the fixed wrapping nonce.
fn nonce() -> Nonce {
    Nonce::from(NONCE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sealed_length_is_ciphertext_plus_tag() {
        assert_eq!(SEALED_LEN, 48, "the spec's wrapped field is 48 bytes");
        assert_eq!(
            SEALED_LEN,
            VALUE_LEN + TAG_LEN,
            "48 is 32 bytes of ciphertext and a 16-byte tag"
        );
    }

    #[test]
    fn a_wrap_is_deterministic_for_one_key_and_value() {
        // The nonce is fixed by the spec, so the same key and value must seal identically; if
        // this ever changes, the peer derives a different ciphertext for the same field.
        let key = [0x11; 32];
        let value = [0x22; 32];
        assert_eq!(wrap(&key, &value), wrap(&key, &value));
    }
}
