//! CPace over X25519 with SHA-512, as Sendspin's code-based pairing uses it.
//!
//! The suite is `CPACE-X25519-SHA512` from
//! [draft-irtf-cfrg-cpace-21](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/21/):
//! group `G_X25519`, hash SHA-512, mutual confirmation flow. This module implements the two
//! primitives the protocol is built on - the generator and the verified scalar multiplication -
//! and pins them to the draft's Appendix B.1 vectors in `tests/pake_vectors.rs`. It does not
//! implement the message flow, the confirmation tags or the transcript; those belong to the
//! session layer.
//!
//! # What the generator is
//!
//! `generator_string` is `lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)` with the zero padding
//! sized so that the first SHA-512 block holds exactly the encoded `DSI` and `PRS` (§8.1,
//! Appendix A.2). The first 32 bytes of its SHA-512 digest are decoded as a u-coordinate
//! (`decodeUCoordinate(_, 255)` from [RFC 7748]) and mapped with Elligator 2. The associated
//! data `ADa`/`ADb` is *not* an input: it enters the transcript that the confirmation flow
//! hashes, not the generator.
//!
//! # The representative convention
//!
//! CPace hands the map an arbitrary field element. `elligator2::from_representative` instead
//! expects a representative, a value below `(p-1)/2`, and masks bits 254 and 255 of its input.
//! The draft's field element can have bit 254 set, and then passing it straight in changes the
//! point: for the §B.1.1 vector the raw call returns `97ef2dc8...cd72fe23` instead of the
//! draft's `d04bf6d4...2f05a73f`. `representative` closes the gap exactly: Elligator 2 uses
//! only `r^2`, so `r` and `-r` map to the same point, and negating a value with bit 254 set
//! yields one the crate accepts. The §B.1.1 generator matches only with that normalisation.
//!
//! # Not reviewed
//!
//! Neither this module nor `elligator2` 0.1 has had an external cryptographic review. The
//! draft vectors pin the arithmetic, not the review.

use anyhow::{bail, Result};
use sha2::{Digest, Sha512};

/// `G_X25519.DSI`, the group's domain-separation identifier (§8.2).
const DSI: &[u8] = b"CPace255";

/// The input block size of SHA-512 in bytes (`H.s_in_bytes`), which `generator_string` pads to.
const SHA512_BLOCK_LEN: usize = 128;

/// The field modulus `p = 2^255 - 19`, little-endian.
const FIELD_MODULUS: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Derives the CPace generator for this `PRS`, `CI` and `sid`.
///
/// Returns the generator's u-coordinate as 32 little-endian bytes, the encoding every group
/// element in CPace uses. `PRS` is the pairing code's bytes, `CI` the channel identifier (empty
/// when the parties are identified by their associated data instead) and `sid` the session id.
///
/// The function is total: every input hashes to a field element, and Elligator 2 maps every
/// field element to a curve point.
///
/// # Example
///
/// ```
/// use syncspin_core::pairing::pake::generator;
///
/// // Draft §B.1.1, X25519 with SHA-512.
/// let sid = [
///     0x7e, 0x4b, 0x47, 0x91, 0xd6, 0xa8, 0xef, 0x01, 0x9b, 0x93, 0x6c, 0x79, 0xfb, 0x7f,
///     0x2c, 0x57,
/// ];
/// let g = generator(b"Password", b"\x0bA_initiator\x0bB_responder", &sid);
/// assert_eq!(
///     g,
///     [
///         0xd0, 0x4b, 0xf6, 0xd4, 0x1f, 0x6a, 0x28, 0x96, 0x32, 0xa2, 0xe9, 0x29, 0xfa, 0x29,
///         0xbe, 0xbd, 0x51, 0x09, 0x25, 0x12, 0xa7, 0x82, 0x9f, 0xdd, 0xe7, 0xd3, 0x14, 0xb6,
///         0x2f, 0x05, 0xa7, 0x3f,
///     ]
/// );
/// ```
pub fn generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> [u8; 32] {
    let digest = Sha512::digest(generator_string(prs, ci, sid));

    // `decodeUCoordinate(gen_str_hash, G.field_size_bits)`: the top 32 bytes of the digest
    // with bit 255 ignored.
    let mut field = [0u8; 32];
    field.copy_from_slice(&digest[..32]);
    field[31] &= 0x7f;

    elligator2::from_representative(&representative(field))
}

/// Computes `G_X25519.scalar_mult_vfy(scalar, u)`, the verified scalar multiplication.
///
/// X25519 clamps the scalar and ignores bit 255 of `u`, exactly as [RFC 7748] specifies, so the
/// non-canonical encodings of draft §B.1.10 are handled without a separate branch. A result that
/// is the neutral element means `u` was a low-order point; that is the abort case the draft
/// requires and the error this function returns.
///
/// # Errors
///
/// Fails when `u` encodes a low-order point, that is when the shared point is the neutral
/// element. CPace requires the caller to abort the round in that case.
pub fn scalar_mult_vfy(scalar: &[u8; 32], u: &[u8; 32]) -> Result<[u8; 32]> {
    let point = x25519_dalek::x25519(*scalar, *u);
    // Fold rather than compare: a slice comparison can stop at the first differing byte, which
    // would make the timing depend on how many leading bytes of a valid point are zero.
    if is_all_zero(&point) {
        bail!("the peer's CPace share encodes a low-order point");
    }
    Ok(point)
}

/// Returns whether every byte is zero, touching the whole slice.
fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &byte| acc | byte) == 0
}

/// Builds `generator_string(DSI, PRS, CI, sid, H.s_in_bytes)` (§8.1, Appendix A.2).
fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Vec<u8> {
    // The pad fills the first hash block after the encoded DSI and PRS, leaving room for the
    // length byte of the pad field itself.
    let pad = SHA512_BLOCK_LEN.saturating_sub(
        1 + prepend_len_len(DSI.len()) + DSI.len() + prepend_len_len(prs.len()) + prs.len(),
    );

    let mut string = Vec::new();
    push_lv(&mut string, DSI);
    push_lv(&mut string, prs);
    push_len(&mut string, pad);
    string.resize(string.len() + pad, 0);
    push_lv(&mut string, ci);
    push_lv(&mut string, sid);
    string
}

/// Appends `prepend_len(bytes)`: the LEB128 length followed by the bytes.
fn push_lv(out: &mut Vec<u8>, bytes: &[u8]) {
    push_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// Appends `len` as an unsigned LEB128 integer.
fn push_len(out: &mut Vec<u8>, mut len: usize) {
    loop {
        let byte = (len & 0x7f) as u8;
        len >>= 7;
        if len == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Returns how many bytes `prepend_len` uses for a value of `len` bytes.
fn prepend_len_len(len: usize) -> usize {
    let mut len = len;
    let mut width = 1;
    while len >= 0x80 {
        len >>= 7;
        width += 1;
    }
    width
}

/// Maps a field element into the representative domain `elligator2` accepts.
///
/// The crate's representatives are below `(p-1)/2` and it masks bits 254 and 255 of whatever it
/// is given. CPace's field element can have bit 254 set, so it is reduced modulo `p` and, when
/// bit 254 is still set, replaced by its negation. That is exact: Elligator 2 uses only `r^2`,
/// so `r` and `-r` map to the same point.
///
/// Both selections are branch-free. The inputs are derived from the pairing code, which is a
/// secret, and a data-dependent branch here would leak a bit of the hash output.
fn representative(field: [u8; 32]) -> [u8; 32] {
    // `field` is below 2^255 and therefore below 2p, so one subtraction reduces it.
    let (reduced, borrow) = subtract(&field, &FIELD_MODULUS);
    let reduced = select(&field, &reduced, borrow.wrapping_sub(1));

    let (negated, _) = subtract(&FIELD_MODULUS, &reduced);
    select(&reduced, &negated, 0u8.wrapping_sub(reduced[31] >> 6))
}

/// Subtracts two little-endian 256-bit integers, returning the difference and the borrow.
fn subtract(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], u8) {
    let mut difference = [0u8; 32];
    let mut borrow = 0u8;
    for (i, byte) in difference.iter_mut().enumerate() {
        let (value, borrowed_a) = a[i].overflowing_sub(b[i]);
        let (value, borrowed_b) = value.overflowing_sub(borrow);
        *byte = value;
        borrow = u8::from(borrowed_a) | u8::from(borrowed_b);
    }
    (difference, borrow)
}

/// Returns `b` when `mask` is all ones and `a` when it is zero, without branching.
fn select(a: &[u8; 32], b: &[u8; 32], mask: u8) -> [u8; 32] {
    let mut selected = [0u8; 32];
    for (i, byte) in selected.iter_mut().enumerate() {
        *byte = a[i] ^ ((a[i] ^ b[i]) & mask);
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The draft's §B.1.1 `generator_string`, 170 bytes.
    const DRAFT_GENERATOR_STRING: &str = concat!(
        "0843506163653235350850617373776f72646d00000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "180b415f696e69746961746f720b425f726573706f6e646572107e4b4791d6a8",
        "ef019b936c79fb7f2c57",
    );

    /// The draft's §B.1.1 SHA-512 digest of that string, first 32 bytes.
    const DRAFT_HASH: &str = "03998087bdb1a2617bbe25ef5a7c18cd4f84f902328701790958755ee4aed1d3";

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").expect("writing into a String cannot fail");
            text
        })
    }

    fn draft_sid() -> [u8; 16] {
        let mut sid = [0u8; 16];
        sid.copy_from_slice(
            &hex_decode("7e4b4791d6a8ef019b936c79fb7f2c57").expect("the vector is hex"),
        );
        sid
    }

    fn hex_decode(value: &str) -> Option<Vec<u8>> {
        if value.len() % 2 != 0 {
            return None;
        }
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
            .collect()
    }

    #[test]
    fn the_generator_string_matches_the_draft() {
        let string = generator_string(b"Password", b"\x0bA_initiator\x0bB_responder", &draft_sid());
        assert_eq!(
            string.len(),
            170,
            "the draft's generator string is 170 bytes"
        );
        assert_eq!(hex(&string), DRAFT_GENERATOR_STRING);
    }

    #[test]
    fn the_generator_string_hashes_to_the_draft_digest() {
        let digest = Sha512::digest(generator_string(
            b"Password",
            b"\x0bA_initiator\x0bB_responder",
            &draft_sid(),
        ));
        assert_eq!(hex(&digest[..32]), DRAFT_HASH);
    }

    #[test]
    fn is_all_zero_checks_every_byte() {
        assert!(is_all_zero(&[0u8; 32]), "32 zero bytes are all zero");
        assert!(is_all_zero(&[]), "an empty slice has no non-zero byte");

        let mut leading = [0u8; 32];
        leading[0] = 1;
        assert!(!is_all_zero(&leading), "a non-zero first byte counts");

        let mut trailing = [0u8; 32];
        trailing[31] = 1;
        assert!(!is_all_zero(&trailing), "a non-zero last byte counts");
    }

    #[test]
    fn a_field_element_above_the_representative_domain_is_negated() {
        // 2^254 + 1: bit 254 set, which `from_representative` would mask away. Negating it
        // gives a value the map reads unchanged, and the map is even, so both agree.
        let mut field = [0u8; 32];
        field[0] = 1;
        field[31] = 0x40;

        let canonical = representative(field);
        assert_eq!(
            canonical[31] >> 6,
            0,
            "the representative has bit 254 clear"
        );
        assert_eq!(
            representative(canonical),
            canonical,
            "an already canonical representative stays as it is"
        );
    }
}
