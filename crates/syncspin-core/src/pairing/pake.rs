//! CPace over X25519 with SHA-512, as Sendspin's code-based pairing uses it.
//!
//! The suite is `CPACE-X25519-SHA512` from
//! [draft-irtf-cfrg-cpace-21](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/21/):
//! group `G_X25519`, hash SHA-512, mutual confirmation flow. This module implements the
//! primitives that flow is built from - the generator, the verified scalar multiplication, the
//! transcript hashing, the intermediate session key and the key-confirmation tags - and pins them
//! to the draft's vectors in `tests/pake_vectors.rs`. The message flow itself belongs to the
//! session layer, which knows when a share or a tag crosses the wire.
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
//! # The transcript and the key confirmation
//!
//! Sendspin fixes CPace's initiator-responder mode, so the transcript is
//! [`transcript_ir`]: `lv_cat(Ya, ADa) || lv_cat(Yb, ADb)`. [`intermediate_session_key`] hashes
//! `lv_cat(G.DSI_ISK, sid, K)` followed by that transcript. The explicit key confirmation of
//! §10.4 derives `mac_key = H(b"CPaceMac" || sid || ISK)` and authenticates the sender's own
//! `lv_cat(share, associated data)` with HMAC-SHA-512, which is [`key_confirmation_tag`].
//! [`transcript_oc`] is the parallel-execution form: Sendspin does not use it, but the draft's
//! vectors cover it and keeping it proves the two forms differ only in the ordering step.
//!
//! # Representative convention
//!
//! CPace hands the map an arbitrary field element. `elligator2::from_representative` instead
//! expects a representative, a value below `(p-1)/2`, and masks bits 254 and 255 of its input.
//! The draft's field element can have bit 254 set, and then passing it straight in changes the
//! point: for the §B.1.1 vector the raw call returns `97ef2dc8...cd72fe23` instead of the
//! draft's `d04bf6d4...2f05a73f`. `representative` closes the gap exactly: Elligator 2 uses
//! only `r^2`, so `r` and `-r` map to the same point, and negating a value with bit 254 set
//! yields one the crate accepts. The §B.1.1 generator matches only with that normalisation.
//!
//! # Secret handling
//!
//! `PRS`, the scalar, the shared point, `ISK` and the tags derive from the pairing code or from a
//! scalar. This module returns them as bytes, exactly as [`mod@super::wrap`] does, and never
//! formats them: no `Debug`, no `Display`, no error string carries a value. [`key_confirmation_tag`]
//! and [`verify_key_confirmation_tag`] are branch-free over the secret-derived tag.
//!
//! The intermediate buffers this module builds are `Zeroizing`: the hashed ISK input, the
//! MAC-key input and the MAC key itself wipe when the call returns. The returned arrays belong to
//! the caller, and this crate does not scrub memory it no longer owns - a caller that keeps a
//! scalar or an ISK past the round should hold it in `Zeroizing` itself.
//!
//! # Not reviewed
//!
//! Neither this module nor `elligator2` 0.1 has had an external cryptographic review. The
//! draft vectors pin the arithmetic, not the review.

use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// `G_X25519.DSI`, the group's domain-separation identifier (§8.2).
const DSI: &[u8] = b"CPace255";

/// `G.DSI_ISK`, the domain-separation identifier of the ISK (§7.2).
const DSI_ISK: &[u8] = b"CPace255_ISK";

/// The label that prefixes the MCF MAC key (§10.4).
const MAC_LABEL: &[u8] = b"CPaceMac";

/// The input block size of SHA-512 in bytes (`H.s_in_bytes`), which `generator_string` pads to.
const SHA512_BLOCK_LEN: usize = 128;

/// Length of a CPace public share in bytes.
pub const SHARE_LEN: usize = 32;

/// Length of the intermediate session key in bytes: one SHA-512 output.
pub const ISK_LEN: usize = 64;

/// Length of a key-confirmation tag in bytes: one HMAC-SHA-512 output.
pub const TAG_LEN: usize = 64;

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

    map_to_curve(&field)
}

/// Maps a field element to `G_X25519` with Elligator 2, the draft's `map_to_curve_elligator2`.
///
/// `field` is a 32-byte little-endian field element, the encoding `decodeUCoordinate` produces.
/// Bit 255 is ignored here, as `decodeUCoordinate(_, 255)` ignores it, so the function is total
/// over 32-byte strings rather than relying on every caller to mask first. Values at or above
/// the modulus are reduced, so `map(u) == map(u mod p)`.
///
/// The image is a u-coordinate in the same little-endian encoding. The representative
/// normalisation that `elligator2` needs is inside and branch-free: the element is reduced and,
/// when it still has bit 254 set, replaced by its negation, which the map cannot distinguish.
pub fn map_to_curve(field: &[u8; 32]) -> [u8; 32] {
    let mut element = *field;
    element[31] &= 0x7f;
    elligator2::from_representative(&representative(element))
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

/// Computes a public share `Y = G.scalar_mult(scalar, generator)`.
///
/// X25519 clamps the scalar, exactly as `G_X25519.sample_scalar` does, so a scalar drawn from the
/// CSPRNG is used here unchanged. The generator is public, so the low-order check costs nothing
/// secret and rejects a degenerate generator instead of returning the neutral element.
///
/// # Errors
///
/// Fails when the group operation yields the neutral element, which only a low-order `generator`
/// can cause.
pub fn public_share(scalar: &[u8; 32], generator: &[u8; 32]) -> Result<[u8; 32]> {
    scalar_mult_vfy(scalar, generator)
}

/// Concatenates each part with its LEB128 length prepended (`lv_cat` from §6.3).
///
/// The length makes the encoding prefix-free, which is what lets the transcript be hashed without
/// an ambiguity between a share and the associated data that follows it.
///
/// # Example
///
/// ```
/// use syncspin_core::pairing::pake::lv_cat;
///
/// // Draft §A.1.4.
/// assert_eq!(
///     lv_cat(&[b"1234".as_slice(), b"5", b"", b"678"]),
///     [
///         0x04, b'1', b'2', b'3', b'4', 0x01, b'5', 0x00, 0x03, b'6', b'7', b'8',
///     ]
/// );
/// ```
pub fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut joined = Vec::new();
    for part in parts {
        push_lv(&mut joined, part);
    }
    joined
}

/// Builds the initiator-responder transcript `lv_cat(Ya, ADa) || lv_cat(Yb, ADb)` (§6.3).
///
/// Both sides hash the same ordering: the initiator's share and associated data first, then the
/// responder's, whichever party computes it. Sendspin's `ADa` is `b"server"` and its `ADb` is
/// `b"client"`.
pub fn transcript_ir(ya: &[u8], ad_a: &[u8], yb: &[u8], ad_b: &[u8]) -> Vec<u8> {
    let mut transcript = lv_cat(&[ya, ad_a]);
    transcript.extend_from_slice(&lv_cat(&[yb, ad_b]));
    transcript
}

/// Builds the parallel-execution transcript `o_cat(lv_cat(Ya, ADa), lv_cat(Yb, ADb))` (§6.3).
///
/// The two messages are ordered lexicographically and prefixed with `b"oc"`, so neither party has
/// to know who spoke first. Sendspin fixes an initiator and a responder, so it uses
/// [`transcript_ir`]; this form exists because the draft's vectors cover it.
pub fn transcript_oc(ya: &[u8], ad_a: &[u8], yb: &[u8], ad_b: &[u8]) -> Vec<u8> {
    let initiator = lv_cat(&[ya, ad_a]);
    let responder = lv_cat(&[yb, ad_b]);
    let mut transcript = Vec::from(b"oc".as_slice());
    if lexicographically_larger(&initiator, &responder) {
        transcript.extend_from_slice(&initiator);
        transcript.extend_from_slice(&responder);
    } else {
        transcript.extend_from_slice(&responder);
        transcript.extend_from_slice(&initiator);
    }
    transcript
}

/// Derives `ISK = H(lv_cat(G.DSI_ISK, sid, K) || transcript)` (§7.2).
///
/// `shared_point` is the secret point `K = scalar_mult_vfy(scalar, peer_share)`, and `transcript`
/// is [`transcript_ir`] or [`transcript_oc`]. The result is the 64-byte intermediate session key,
/// which the higher-level protocol processes before use: Sendspin derives `K_wrap` from it with
/// [`super::wrap::k_wrap`].
///
/// The value is secret. It is returned as bytes and never formatted.
pub fn intermediate_session_key(
    sid: &[u8],
    shared_point: &[u8],
    transcript: &[u8],
) -> [u8; ISK_LEN] {
    // The hashed input carries the shared point, which is the Diffie-Hellman secret of the
    // round, so the buffer scrubs itself when the digest returns.
    let mut input = Zeroizing::new(lv_cat(&[DSI_ISK, sid, shared_point]));
    input.extend_from_slice(transcript);
    Sha512::digest(&input[..]).into()
}

/// Computes the explicit key-confirmation tag of the sender's own message (§10.4).
///
/// `mac_key = H(b"CPaceMac" || sid || ISK)`, raw and without length prefixes, then
/// `T = HMAC-SHA-512(mac_key, lv_cat(share, associated data))`. Passing the initiator's `Ya` and
/// `ADa` yields `Ta` (`server_kc`); the responder's `Yb` and `ADb` yield `Tb` (`client_kc`).
///
/// The tag is secret-derived. It is returned as bytes and never formatted.
pub fn key_confirmation_tag(
    sid: &[u8],
    isk: &[u8; ISK_LEN],
    share: &[u8],
    ad: &[u8],
) -> [u8; TAG_LEN] {
    // Both buffers hold the ISK, so both scrub themselves when the tag is finalised.
    let mut key_input = Zeroizing::new(Vec::from(MAC_LABEL));
    key_input.extend_from_slice(sid);
    key_input.extend_from_slice(isk);
    let mac_key = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(&key_input[..])));

    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&mac_key[..])
        .expect("HMAC-SHA-512 accepts a key of any length");
    mac.update(&lv_cat(&[share, ad]));
    mac.finalize().into_bytes().into()
}

/// Returns whether a received tag equals the one this side derived.
///
/// The comparison is `subtle::ConstantTimeEq`, which folds every byte of both tags into one
/// choice instead of stopping at the first mismatch: the tags are derived from `ISK`, and an
/// early exit would leak how many leading bytes an attacker guessed. Only the single final
/// result depends on the data, and that result is public - it decides whether the round
/// continues. Going through the crate rather than an inline `==` is the point: a later edit
/// cannot turn this into a short-circuiting comparison without deleting an import.
#[must_use]
pub fn verify_key_confirmation_tag(expected: &[u8; TAG_LEN], received: &[u8; TAG_LEN]) -> bool {
    bool::from(expected[..].ct_eq(&received[..]))
}

/// Returns whether `left` is greater than `right` in the draft's lexicographical order (§A.3.1).
fn lexicographically_larger(left: &[u8], right: &[u8]) -> bool {
    for (a, b) in left.iter().zip(right) {
        if a > b {
            return true;
        }
        if a < b {
            return false;
        }
    }
    left.len() > right.len()
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

        // A peer that repeats one non-zero byte is not the zero element either. Accumulating with
        // XOR would cancel an even number of identical bytes and call this a low-order point.
        assert!(
            !is_all_zero(&[1u8; 32]),
            "32 identical non-zero bytes are not zero"
        );
    }

    #[test]
    fn the_lexicographical_order_is_bytes_then_a_prefix() {
        // §A.3.1 orders byte by byte, and only a proper prefix counts as smaller. Both sides of
        // the comparison come from peers, so an equal pair must not be "larger" and a prefix must
        // not win: that would break the symmetry the role assignment depends on.
        assert!(
            !lexicographically_larger(&[1, 2], &[1, 2]),
            "equal slices are not larger"
        );
        assert!(
            lexicographically_larger(&[1, 3], &[1, 2]),
            "byte order decides"
        );
        assert!(!lexicographically_larger(&[1, 2], &[1, 3]));
        assert!(
            !lexicographically_larger(&[1, 2], &[1, 2, 0]),
            "a proper prefix is smaller"
        );
        assert!(
            lexicographically_larger(&[1, 2, 0], &[1, 2]),
            "the longer slice is larger when the shorter one is its prefix"
        );
    }

    #[test]
    fn a_length_prefix_is_leb128_above_a_single_byte() {
        // `lv_cat` writes lengths as unsigned LEB128, so 127 fits in one byte and 128 needs two.
        // Every length this transcript passes today is below 128 - a 32-byte field, a short DSI, a
        // pad under the block size - so the multi-byte branch has no caller to reach it. The
        // encoding still has to be right for the lengths the format allows: a pad or an identifier
        // one byte longer would otherwise produce a transcript the peer cannot parse.
        for (len, expected) in [
            (0usize, vec![0x00]),
            (127, vec![0x7f]),
            (128, vec![0x80, 0x01]),
            (300, vec![0xac, 0x02]),
            (16_384, vec![0x80, 0x80, 0x01]),
        ] {
            let mut out = Vec::new();
            push_len(&mut out, len);
            assert_eq!(out, expected, "LEB128 encoding of {len}");
            assert_eq!(
                prepend_len_len(len),
                expected.len(),
                "prefix width for {len}"
            );
        }
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
