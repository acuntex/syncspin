//! The dynamic pairing code: its commitment and the derivation both sides repeat.
//!
//! `pairing.md` binds a per-session code to the Noise handshake and to one nonce from each side:
//!
//! ```text
//! commit_B = SHA-256("sendspin-pair-commit-v1" || nonce_B)
//! digest   = SHA-256("sendspin-pairing-code-derive-v1" || h || nonce_A || nonce_B)
//! ```
//!
//! `commit_B` travels in `client/pair-init`, before any value from the server is known, so the
//! client is bound to the `nonce_B` it later reveals under the CPace output. The digest yields the
//! code in one of two emission formats: the six ASCII digits of `digits` (also CPace's `PRS`) or
//! the first 24 bytes of the digest, carried as a version-1 [token](super::token) in `qr_code`.
//!
//! # Secret handling
//!
//! `nonce_B` is a secret until it is revealed, sealed, in `client/pair-confirm`; [`commitment`]
//! takes it as bytes and neither function here formats any input. [`DynamicCode`] has no `Debug`
//! implementation, so the code - which the operator is meant to see - cannot reach a log line by
//! accident either: a caller emits it deliberately, through the client's event stream.
//!
//! The module is behind the `pairing-code` feature with [`pake`](super::pake) and
//! [`wrap`](super::wrap): only the code flows derive a code.

use sha2::{Digest, Sha256};

use super::token;

/// The label that prefixes the commitment of `nonce_B`.
pub const COMMIT_LABEL: &[u8] = b"sendspin-pair-commit-v1";

/// The label that prefixes the code derivation.
pub const DERIVE_LABEL: &[u8] = b"sendspin-pairing-code-derive-v1";

/// Number of digits the `digits` emission format carries.
pub const DIGITS_LEN: usize = 6;

/// Number of bytes the `qr_code` emission format carries.
pub const QR_CODE_LEN: usize = 24;

/// The divisor the digest is reduced by for the `digits` emission format.
const DIGITS_MODULUS: u64 = 1_000_000;

/// Computes `commit_B = SHA-256(label || nonce_B)`.
///
/// The label and the raw 32-byte nonce are concatenated without a separator, exactly as the spec
/// writes them. The value is public - it travels in `client/pair-init` - and reveals nothing about
/// `nonce_B` before the seal is opened.
pub fn commitment(nonce_b: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_LABEL);
    hasher.update(nonce_b);
    hasher.finalize().into()
}

/// The digest both sides derive the pairing code from.
///
/// One value serves both emission formats, so neither side has to know which format the client
/// chose before it derives. The digest does not include the emission format: the `digits` code and
/// the `qr_code` code of one digest are two views of the same binding.
pub struct DynamicCode {
    /// `SHA-256(label || h || nonce_A || nonce_B)`.
    digest: [u8; 32],
}

impl DynamicCode {
    /// Derives the digest from the handshake hash and the two nonces.
    ///
    /// All three are raw, concatenated after the label without a separator. `h` is the Noise
    /// handshake hash, `nonce_a` the server's nonce from the first round's `server/pair-init` and
    /// `nonce_b` this client's own nonce, which stays private until `client/pair-confirm`.
    pub fn derive(h: &[u8; 32], nonce_a: &[u8; 32], nonce_b: &[u8; 32]) -> DynamicCode {
        let mut hasher = Sha256::new();
        hasher.update(DERIVE_LABEL);
        hasher.update(h);
        hasher.update(nonce_a);
        hasher.update(nonce_b);
        DynamicCode {
            digest: hasher.finalize().into(),
        }
    }

    /// Returns the six ASCII digits of the `digits` emission format.
    ///
    /// The digest is read as an unsigned big-endian 256-bit integer and reduced modulo `10^6`,
    /// then written left-padded with zeroes to exactly six characters. Those six bytes are also
    /// the code's CPace `PRS`.
    ///
    /// ```
    /// use syncspin_core::pairing::code::DynamicCode;
    ///
    /// // Fixed inputs, so the digits are a vector: h = 0x00..=0x1f, nonce_A = 0x40..=0x5f,
    /// // nonce_B = 0x80..=0x9f.
    /// let code = DynamicCode::derive(
    ///     &std::array::from_fn(|index| index as u8),
    ///     &std::array::from_fn(|index| 0x40 + index as u8),
    ///     &std::array::from_fn(|index| 0x80 + index as u8),
    /// );
    /// assert_eq!(code.digits_text(), "782070");
    /// ```
    pub fn digits(&self) -> [u8; DIGITS_LEN] {
        let mut value = 0u64;
        for &byte in &self.digest {
            // `value < 10^6` before every step, so `value * 256 + 255` stays below 2.6·10^8.
            value = (value * 256 + u64::from(byte)) % DIGITS_MODULUS;
        }
        let mut digits = [0u8; DIGITS_LEN];
        for (index, digit) in digits.iter_mut().enumerate() {
            let divisor = 10u64.pow((DIGITS_LEN - 1 - index) as u32);
            *digit = b'0' + ((value / divisor) % 10) as u8;
        }
        digits
    }

    /// Returns the six digits as text, ready for a display or a speaker.
    #[must_use]
    pub fn digits_text(&self) -> String {
        let digits = self.digits();
        // Six ASCII digits from `digits`, which cannot fail.
        String::from_utf8(digits.to_vec()).expect("the digits format is six ASCII digits")
    }

    /// Returns the 24-byte code of the `qr_code` emission format.
    ///
    /// These are `digest[0..24]`, raw: they are the code's CPace `PRS` and the payload of the
    /// version-1 token a display renders.
    #[must_use]
    pub fn qr_payload(&self) -> [u8; QR_CODE_LEN] {
        self.digest[..QR_CODE_LEN]
            .try_into()
            .expect("the digest is 32 bytes, longer than the 24-byte code")
    }

    /// Returns the `qr_code` emission of the code: a version-1 pairing token string.
    #[must_use]
    pub fn qr_token(&self) -> String {
        token::encode_v1(&self.qr_payload())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digits_fold_keeps_the_whole_digest() {
        // The fold reads every byte: a version that dropped the last byte would differ here.
        let code = DynamicCode {
            digest: std::array::from_fn(|index| index as u8),
        };
        let mut value = 0u64;
        for &byte in &code.digest {
            value = (value * 256 + u64::from(byte)) % DIGITS_MODULUS;
        }
        assert_eq!(
            code.digits_text(),
            format!("{value:06}"),
            "the digits are the digest modulo 10^6, zero-padded"
        );
    }

    #[test]
    fn an_all_zero_digest_yields_six_zeroes() {
        let code = DynamicCode { digest: [0u8; 32] };
        assert_eq!(code.digits(), *b"000000");
        assert_eq!(code.digits_text(), "000000");
    }

    #[test]
    fn the_qr_payload_is_the_first_24_digest_bytes() {
        let digest: [u8; 32] = std::array::from_fn(|index| 0xf0 - index as u8);
        let code = DynamicCode { digest };
        assert_eq!(code.qr_payload(), digest[..24]);
        assert_eq!(
            code.qr_token(),
            token::encode_v1(&digest[..24].try_into().expect("24 bytes"))
        );
    }
}
