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
//! # The AEAD is the connection's suite
//!
//! The spec seals with the AEAD of the connection's negotiated cipher suite, so every function
//! here takes a [`Suite`]: `25519_ChaChaPoly_SHA256` seals with ChaCha20-Poly1305 and
//! `25519_AESGCM_SHA256` with AES-256-GCM. Both are 32-byte-key, 12-byte-nonce, 16-byte-tag
//! ciphers, so `K_wrap` and the sealed length are the same under either; only the ciphertext
//! differs, and a value sealed under one suite does not open under the other.
//!
//! The ciphers come from the same resolver `snow` uses for the handshake, which is where the
//! dependency already sits. A build whose resolver lacks the suite's cipher returns an error and
//! never falls back to the other suite.
//!
//! The module is behind the `pairing-code` feature with [`pake`](super::pake): wrapping exists
//! only for the code flows.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use snow::params::CipherChoice;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::Cipher;

use crate::noise::Suite;

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

/// The nonce number every wrapping uses. A key is derived per field per session, so it seals
/// exactly one value and the zero nonce never repeats under the same key. Zero is the spec's
/// twelve zero bytes under either cipher: both render a `u64` into the last eight bytes, and
/// this value is zero in either byte order.
const WRAP_NONCE: u64 = 0;

/// Derives `K_wrap = SHA-256(label || sid || ISK)`.
///
/// `label` is [`PSK_LABEL`] or [`NONCE_LABEL`], `sid` the CPace session id exactly as the PAKE
/// used it, and `isk` the 64-byte CPace intermediate session key. The three are concatenated
/// raw; their lengths are fixed by the protocol, so no delimiter is needed. The suite does not
/// enter the derivation: both of Sendspin's suites use the same key with a different AEAD.
pub fn k_wrap(label: &[u8], sid: &[u8], isk: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(sid);
    hasher.update(isk);
    hasher.finalize().into()
}

/// Seals a 32-byte value under `K_wrap` with the AEAD of `suite`, returning ciphertext and tag.
///
/// The nonce is twelve zero bytes and the associated data is empty, as the spec requires. A
/// key is used for one value only, which is what makes the fixed nonce safe.
///
/// # Errors
///
/// Fails when the build's cipher resolver has no AEAD for `suite`. That is the honest refusal:
/// sealing under the other suite's cipher would produce a field the peer cannot open.
///
/// # Example
///
/// ```
/// use syncspin_core::noise::Suite;
/// use syncspin_core::pairing::wrap::{unwrap, wrap};
///
/// // The key comes from `k_wrap` in a real flow; any 32 bytes will do here.
/// let key = [0x42; 32];
/// let value = [0x24; 32];
/// let sealed = wrap(Suite::ChaChaPoly, &key, &value).expect("the cipher is available");
/// assert_eq!(unwrap(Suite::ChaChaPoly, &key, &sealed).expect("round trip"), value);
/// ```
pub fn wrap(suite: Suite, key: &[u8; 32], value: &[u8; 32]) -> Result<[u8; SEALED_LEN]> {
    let cipher = cipher(suite, key)?;

    // The AEAD appends its tag, so one buffer holds the whole field. A 32-byte value is far
    // below the maximum, so sealing cannot fail.
    let mut sealed = [0u8; SEALED_LEN];
    let written = cipher.encrypt(WRAP_NONCE, &[], value, &mut sealed);
    debug_assert_eq!(written, SEALED_LEN, "the AEAD appends a {TAG_LEN}-byte tag");
    Ok(sealed)
}

/// Opens a 48-byte sealed value under `K_wrap` with the AEAD of `suite`, returning the value.
///
/// # Errors
///
/// Fails when the tag does not authenticate: a wrong key - a different label, `sid` or `ISK` - a
/// seal made under the other suite, or any changed byte of the ciphertext or tag. It also fails
/// when the build's cipher resolver has no AEAD for `suite`. The error names no key, value or
/// seal bytes.
pub fn unwrap(suite: Suite, key: &[u8; 32], sealed: &[u8; SEALED_LEN]) -> Result<[u8; 32]> {
    let cipher = cipher(suite, key)?;

    let mut value = [0u8; VALUE_LEN];
    cipher
        .decrypt(WRAP_NONCE, &[], sealed, &mut value)
        .map_err(|_| anyhow!("the wrapped pairing value does not authenticate"))?;
    Ok(value)
}

/// Builds the suite's AEAD for `key`.
///
/// The resolver is `snow`'s default one, the same one the handshake uses, so a build that has a
/// suite for Noise has it here as well. A missing cipher is an error and not a reason to seal
/// under the other suite. The panic messages and error strings carry no key material: `set`
/// cannot fail on a 32-byte key.
fn cipher(suite: Suite, key: &[u8; 32]) -> Result<Box<dyn Cipher>> {
    let choice = match suite {
        Suite::ChaChaPoly => CipherChoice::ChaChaPoly,
        Suite::AesGcm => CipherChoice::AESGCM,
    };
    let mut cipher = DefaultResolver.resolve_cipher(&choice).ok_or_else(|| {
        anyhow!("the cipher suite `{suite}` is not available in this build, so it cannot seal")
    })?;
    cipher.set(key);
    Ok(cipher)
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
        // The nonce is fixed by the spec, so the same key and value must seal identically under
        // either suite; if this ever changes, the peer derives a different ciphertext for the
        // same field.
        let key = [0x11; 32];
        let value = [0x22; 32];
        for suite in Suite::ALL {
            assert_eq!(
                wrap(suite, &key, &value).expect("the cipher is available"),
                wrap(suite, &key, &value).expect("the cipher is available")
            );
        }
    }

    #[test]
    fn the_fixed_nonce_is_zero() {
        // The wrapped field's nonce is the spec's twelve zero bytes, not the handshake's
        // counter; a change here would still round-trip against this crate and fail against a
        // real server.
        assert_eq!(WRAP_NONCE, 0);
    }
}
