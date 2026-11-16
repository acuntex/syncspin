//! The CPace draft's X25519/SHA-512 vectors (draft-irtf-cfrg-cpace-21, Appendix B.1).
//!
//! These vectors decide whether the `elligator2` crate can carry Sendspin's
//! `CPACE-X25519-SHA512`. Nothing in `src/pairing` may be built on the map until they pass,
//! and no value here may be adjusted to make an implementation agree: the hex is transcribed
//! from the draft.

#![cfg(feature = "pairing-code")]

use proptest::prelude::*;
use sha2::{Digest, Sha512};
use syncspin_core::pairing::pake::{
    generator, intermediate_session_key, key_confirmation_tag, lv_cat, map_to_curve, public_share,
    scalar_mult_vfy, transcript_ir, transcript_oc, verify_key_confirmation_tag,
};

/// The draft's `PRS` (§B.1.1).
const PRS: &[u8] = b"Password";

/// The draft's `CI`: `lv_cat(b"A_initiator", b"B_responder")` (§B.1.1).
const CI: &[u8] = b"\x0bA_initiator\x0bB_responder";

/// Decodes a value written as `2 * N` hex characters into its `N` bytes.
fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(
        hex.len(),
        2 * N,
        "a {N}-byte vector is {} hex characters",
        2 * N
    );
    let mut bytes = [0u8; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("the vector is hex");
    }
    bytes
}

#[test]
fn the_generator_matches_the_draft() {
    // §B.1.1: `PRS = b'Password'`, `CI = b'\x0bA_initiator\x0bB_responder'` and this `sid`
    // give `generator g` = d04bf6d4...2f05a73f. The byte order is little-endian throughout,
    // as [RFC 7748] requires for a u-coordinate.
    let sid: [u8; 16] = bytes("7e4b4791d6a8ef019b936c79fb7f2c57");
    let expected: [u8; 32] =
        bytes("d04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f");
    assert_eq!(
        generator(PRS, CI, &sid),
        expected,
        "the generator for the draft's PRS, CI and sid"
    );
}

/// Decodes a 32-byte field element printed as hex and reverses it.
///
/// RFC 9380 prints the curve25519 vectors big-endian; [RFC 7748] and this crate encode field
/// elements little-endian. Reversing here keeps the transcribed hex identical to the RFC.
fn field_element(hex: &str) -> [u8; 32] {
    let mut field = bytes::<32>(hex);
    field.reverse();
    field
}

/// The field modulus `p = 2^255 - 19`, little-endian.
const P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Reduces a value below `2^255` modulo `p`, which takes one conditional subtraction.
fn reduce(field: [u8; 32]) -> [u8; 32] {
    let mut difference = [0u8; 32];
    let mut borrow = 0u8;
    for index in 0..32 {
        let (value, borrowed_a) = field[index].overflowing_sub(P[index]);
        let (value, borrowed_b) = value.overflowing_sub(borrow);
        difference[index] = value;
        borrow = u8::from(borrowed_a) | u8::from(borrowed_b);
    }
    if borrow == 0 {
        difference
    } else {
        field
    }
}

/// Returns `p - field` for `field <= p`, in the same little-endian encoding.
fn negate(field: [u8; 32]) -> [u8; 32] {
    let mut difference = [0u8; 32];
    let mut borrow = 0u8;
    for index in 0..32 {
        let (value, borrowed_a) = P[index].overflowing_sub(field[index]);
        let (value, borrowed_b) = value.overflowing_sub(borrow);
        difference[index] = value;
        borrow = u8::from(borrowed_a) | u8::from(borrowed_b);
    }
    difference
}

/// The map against RFC 9380 §J.4.2, which lists `u` and the resulting `Q.x`.
///
/// The draft pins the map with one vector only (§B.1.1), and that vector's `u` has bit 254 set,
/// which is the branch the code rewrites. RFC 9380 exercises both branches and values on either
/// side of the representative domain, so the adapter is pinned by an independent document rather
/// than by the one input it was derived from.
#[test]
fn the_map_matches_rfc_9380_j_4_2() {
    // RFC 9380's `curve25519_XMD:SHA-512_ELL2_NU_` suite, the five published `(u[0], Q.x)` pairs.
    const VECTORS: [(&str, &str); 5] = [
        (
            "608d892b641f0328523802a6603427c26e55e6f27e71a91a478148d45b5093cd",
            "51125222da5e763d97f3c10fcc92ea6860b9ccbbd2eb1285728f566721c1e65b",
        ),
        (
            "46f5b22494bfeaa7f232cc8d054be68561af50230234d7d1d63d1d9abeca8da5",
            "7d56d1e08cb0ccb92baf069c18c49bb5a0dcd927eff8dcf75ca921ef7f3e6eeb",
        ),
        (
            "235fe40c443766ce7e18111c33862d66c3b33267efa50d50f9e8e5d252a40aaa",
            "3fbe66b9c9883d79e8407150e7c2a1c8680bee496c62fabe4619a72b3cabe90f",
        ),
        (
            "001e92a544463bda9bd04ddbe3d6eed248f82de32f522669efc5ddce95f46f5b",
            "227e0bb89de700385d19ec40e857db6e6a3e634b1c32962f370d26f84ff19683",
        ),
        (
            "1a68a1af9f663592291af987203393f707305c7bac9c8d63d6a729bdc553dc19",
            "3bcd651ee54d5f7b6013898aab251ee8ecc0688166fce6e9548d38472f6bd196",
        ),
    ];

    let mut with_bit_254 = 0;
    let mut without_bit_254 = 0;
    for (u, q) in VECTORS {
        let field = field_element(u);
        assert_eq!(map_to_curve(&field), field_element(q), "map_to_curve({u})");
        if field[31] & 0x40 != 0 {
            with_bit_254 += 1;
        } else {
            without_bit_254 += 1;
        }
    }
    // Both branches must stay covered: without these counts a future edit could drop every
    // vector on one side and the test would still pass.
    assert!(with_bit_254 >= 1, "no vector exercises bit 254 set");
    assert!(without_bit_254 >= 1, "no vector exercises bit 254 clear");
}

/// The map depends on `u²`, so `u` and `p - u` must reach the same point.
///
/// That identity is what makes the bit-254 rewrite exact rather than a guess: negating an input
/// with bit 254 set is only legitimate because the map cannot tell the two apart.
#[test]
fn the_map_agrees_for_negated_field_elements() {
    proptest!(|(mut field in prop::array::uniform32(any::<u8>()))| {
        // Bit 255 is not part of the field element; masking it puts the input in `[0, 2^255)`.
        field[31] &= 0x7f;
        let canonical = reduce(field);
        let negated = negate(canonical);
        prop_assert_eq!(
            map_to_curve(&canonical),
            map_to_curve(&negated),
            "map({:?}) differs from map(p - u)", canonical
        );
    });
}

/// Encodings at or above `p` map like their reduction, including the encodings of `0` and `1`.
#[test]
fn an_element_at_or_above_the_modulus_maps_like_its_reduction() {
    // `p` through `p + 18 == 2^255 - 1` are the 19 encodings of `0` through `18`. The low byte
    // of `p` is `0xed`, so adding at most 18 cannot carry into the next byte.
    for offset in 0u8..19 {
        let mut non_canonical = P;
        non_canonical[0] = P[0].wrapping_add(offset);
        let mut reduced = [0u8; 32];
        reduced[0] = offset;
        assert_eq!(
            map_to_curve(&non_canonical),
            map_to_curve(&reduced),
            "the encoding of {offset} at p + {offset}"
        );
    }

    let mut one = [0u8; 32];
    one[0] = 1;
    let mut p_one = P;
    p_one[0] = P[0] + 1;
    assert_eq!(map_to_curve(&P), map_to_curve(&[0u8; 32]), "p is 0");
    assert_eq!(map_to_curve(&p_one), map_to_curve(&one), "p + 1 is 1");
}

#[test]
fn scalar_mult_vfy_matches_the_secret_point_vectors() {
    // §B.1.2 to §B.1.4: both sides compute the same secret point from their own scalar and
    // the peer's public share.
    let ya_scalar: [u8; 32] =
        bytes("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080");
    let yb_scalar: [u8; 32] =
        bytes("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a");
    let ya: [u8; 32] = bytes("1d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f32");
    let yb: [u8; 32] = bytes("248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea32185623");
    let expected: [u8; 32] =
        bytes("5b067effbdc0b2a0e1d907b21ebb25cfedb96a852179a847c37e43ee71322c6b");

    assert_eq!(
        scalar_mult_vfy(&ya_scalar, &yb).expect("Yb is not a low-order point"),
        expected,
        "scalar_mult_vfy(ya, Yb)"
    );
    assert_eq!(
        scalar_mult_vfy(&yb_scalar, &ya).expect("Ya is not a low-order point"),
        expected,
        "scalar_mult_vfy(yb, Ya)"
    );
}

#[test]
fn scalar_mult_vfy_matches_the_low_order_vectors() {
    // §B.1.10. `u6`, `u8`, `u9`, `ua` and `ub` are non-canonical: bit 255 is set, and
    // [RFC 7748] requires masking it before the ladder runs. `u0` to `u5` and `u7` encode a
    // low-order point, so the ladder yields the neutral element, which the draft also calls
    // the abort case. The other five must not abort.
    const S: &str = "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff";
    const U: [&str; 12] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
    ];
    const Q: [&str; 12] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38",
        "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456",
        "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a",
        "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175",
    ];
    /// §B.1.10: "u0,u1,u2,u3,u4,u5 and u7 MUST trigger the abort case".
    const MUST_ABORT: [usize; 7] = [0, 1, 2, 3, 4, 5, 7];

    let scalar: [u8; 32] = bytes(S);
    for (i, (u, q)) in U.iter().zip(Q).enumerate() {
        let result = scalar_mult_vfy(&scalar, &bytes::<32>(u));
        assert_eq!(
            result.is_err(),
            MUST_ABORT.contains(&i),
            "u{i} must {}",
            if MUST_ABORT.contains(&i) {
                "abort"
            } else {
                "yield a secret point"
            }
        );
        if MUST_ABORT.contains(&i) {
            assert_eq!(
                bytes::<32>(q),
                [0u8; 32],
                "q{i} is the neutral element, which is why u{i} aborts"
            );
        } else {
            assert_eq!(
                result.expect("the point was not rejected"),
                bytes::<32>(q),
                "q{i}"
            );
        }
    }
}

/// Decodes a value written as hex into its bytes, without a fixed length.
fn hex_vec(hex: &str) -> Vec<u8> {
    assert_eq!(
        hex.len() % 2,
        0,
        "a byte string has two hex digits per byte"
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("the vector is hex"))
        .collect()
}

/// The draft's §B.1.2 and §B.1.3 public shares, from the given scalar and generator.
#[test]
fn the_public_shares_match_the_draft() {
    let generator = generator(PRS, CI, &bytes::<16>("7e4b4791d6a8ef019b936c79fb7f2c57"));
    let ya_scalar: [u8; 32] =
        bytes("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080");
    let yb_scalar: [u8; 32] =
        bytes("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a");
    let ya: [u8; 32] = bytes("1d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f32");
    let yb: [u8; 32] = bytes("248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea32185623");

    assert_eq!(
        public_share(&ya_scalar, &generator).expect("the generator is not low-order"),
        ya,
        "§B.1.2: Ya = scalar_mult(ya, g)"
    );
    assert_eq!(
        public_share(&yb_scalar, &generator).expect("the generator is not low-order"),
        yb,
        "§B.1.3: Yb = scalar_mult(yb, g)"
    );
}

/// §A.1.4: `lv_cat(b"1234", b"5", b"", b"678")`.
#[test]
fn lv_cat_matches_the_draft() {
    let joined = lv_cat(&[b"1234".as_slice(), b"5", b"", b"678"]);
    assert_eq!(joined.len(), 12, "the draft's lv_cat is 12 bytes");
    assert_eq!(
        hex_vec("043132333401350003363738"),
        joined,
        "the length is LEB128 and precedes each value"
    );
}

/// §A.3.5: the initiator-responder transcript, over non-key-sized inputs.
#[test]
fn transcript_ir_matches_the_draft() {
    let transcript = transcript_ir(b"123", b"PartyA", b"234", b"PartyB");
    assert_eq!(transcript.len(), 22, "the draft's transcript is 22 bytes");
    assert_eq!(
        hex_vec("03313233065061727479410332333406506172747942"),
        transcript
    );

    let transcript = transcript_ir(b"3456", b"PartyA", b"2345", b"PartyB");
    assert_eq!(
        hex_vec("043334353606506172747941043233343506506172747942"),
        transcript
    );
}

/// §A.3.7: the parallel-execution transcript. Sendspin fixes initiator-responder mode, so this
/// form is not on the wire; the vector still pins the ordering and length encoding it shares with
/// `transcript_ir`.
#[test]
fn transcript_oc_matches_the_draft() {
    let transcript = transcript_oc(b"123", b"PartyA", b"234", b"PartyB");
    assert_eq!(
        hex_vec("6f6303323334065061727479420331323306506172747941"),
        transcript
    );
    let transcript = transcript_oc(b"3456", b"PartyA", b"2345", b"PartyB");
    assert_eq!(
        hex_vec("6f63043334353606506172747941043233343506506172747942"),
        transcript
    );
}

/// The draft's §B.1.5 values, shared by the ISK and confirmation tests.
fn draft_isk_inputs() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 16]) {
    let ya: [u8; 32] = bytes("1d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f32");
    let yb: [u8; 32] = bytes("248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea32185623");
    let point: [u8; 32] = bytes("5b067effbdc0b2a0e1d907b21ebb25cfedb96a852179a847c37e43ee71322c6b");
    let sid: [u8; 16] = bytes("7e4b4791d6a8ef019b936c79fb7f2c57");
    (ya, yb, point, sid)
}

/// §B.1.5: the initiator-responder transcript and the 64-byte ISK.
#[test]
fn the_initiator_responder_isk_matches_the_draft() {
    let (ya, yb, point, sid) = draft_isk_inputs();

    let transcript = transcript_ir(&ya, b"ADa", &yb, b"ADb");
    assert_eq!(transcript.len(), 74, "the draft's transcript is 74 bytes");
    let expected_transcript = hex_vec(
        "201d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f320341446120248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea3218562303414462",
    );
    assert_eq!(expected_transcript, transcript);

    let isk = intermediate_session_key(&sid, &point, &transcript);
    assert_eq!(
        isk.as_slice(),
        hex_vec(
            "6e19b875f7a561d6b3ca3dbb9ef42ac55de3e717881018204b8922b4d5e53bb2aa82c300bea7b65d2b671da71922ddf6472301b79bc270adfa8bf413285f2263"
        )
        .as_slice(),
        "§B.1.5: ISK = H(lv_cat(DSI_ISK, sid, K) || transcript_ir)"
    );
}

/// §B.1.6: the parallel-execution ISK. Sendspin does not use this transcript, but it pins the
/// hashing around `transcript_oc` as well.
#[test]
fn the_parallel_isk_matches_the_draft() {
    let (ya, yb, point, sid) = draft_isk_inputs();

    let transcript = transcript_oc(&ya, b"ADa", &yb, b"ADb");
    let expected_transcript = hex_vec(
        "6f6320248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea3218562303414462201d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f3203414461",
    );
    assert_eq!(expected_transcript, transcript);

    let isk = intermediate_session_key(&sid, &point, &transcript);
    assert_eq!(
        isk.as_slice(),
        hex_vec(
            "eef745e2f6e7ae2b1a1e53da340e777167a07fe150436648c51fb199c11f3cbabfc683a2b48e1af5881940dc398d375c95e6b4ae9948a45b8770de0656382be4"
        )
        .as_slice(),
        "§B.1.6: the same construction over transcript_oc"
    );
}

/// §B.1.7: the optional session-id output, which pins the transcript bytes under a second label.
#[test]
fn the_session_id_output_matches_the_draft() {
    let (ya, yb, _point, _sid) = draft_isk_inputs();

    let mut input = Vec::from(b"CPaceSidOutput".as_slice());
    input.extend_from_slice(&transcript_ir(&ya, b"ADa", &yb, b"ADb"));
    assert_eq!(
        Sha512::digest(&input).as_slice(),
        hex_vec(
            "cbc73f62589bbc96ab6a95ec2363df621e93bc3b0cea83ba6b9571d005fa8f5d2d08f7165622777fa484c02a9e6b20a84ee2dbebae8c53be757dcfc0eebdeb5f"
        )
        .as_slice()
    );

    let mut input = Vec::from(b"CPaceSidOutput".as_slice());
    input.extend_from_slice(&transcript_oc(&ya, b"ADa", &yb, b"ADb"));
    assert_eq!(
        Sha512::digest(&input).as_slice(),
        hex_vec(
            "3a504e9c7f1f7fa7314861e2c487d13f28566f3043f0ca760d22c4911aca0dd8b1f12a7ad0862eb92d08a76120140412ae6b8322e99d75cf1d20d8cfde2b40fe"
        )
        .as_slice()
    );
}

/// The draft recommends MCF in §10.4 but publishes no tag vector, so the construction is pinned
/// against the formula written out here: HMAC-SHA-512 under `H("CPaceMac" || sid || ISK)`, over
/// `lv_cat(own share, own associated data)`.
#[test]
fn the_key_confirmation_tag_follows_the_drafts_construction() {
    use hmac::{Hmac, Mac};

    let (ya, yb, point, sid) = draft_isk_inputs();
    let isk = intermediate_session_key(&sid, &point, &transcript_ir(&ya, b"ADa", &yb, b"ADb"));

    let mut mac_key = Vec::from(b"CPaceMac".as_slice());
    mac_key.extend_from_slice(&sid);
    mac_key.extend_from_slice(&isk);
    let mac_key = Sha512::digest(&mac_key);

    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&mac_key).expect("HMAC takes any key");
    mac.update(&lv_cat(&[ya.as_slice(), b"ADa"]));
    let expected: [u8; 64] = mac.finalize().into_bytes().into();

    let tag = key_confirmation_tag(&sid, &isk, &ya, b"ADa");
    assert_eq!(tag, expected, "Ta is the MAC over lv_cat(Ya, ADa)");
    assert_eq!(tag.len(), 64, "an MCF tag is a SHA-512 output");

    // A peer's tag authenticates only its own message: the other share, another sid or another
    // associated data derive a different value.
    assert_ne!(tag, key_confirmation_tag(&sid, &isk, &yb, b"ADb"));
    assert_ne!(
        tag,
        key_confirmation_tag(&sid, &isk, &ya, b"ADb"),
        "the associated data is part of the MAC input"
    );
    assert_ne!(
        tag,
        key_confirmation_tag(b"another sid", &isk, &ya, b"ADa"),
        "the sid is part of the MAC key"
    );
}

/// A received tag is compared without stopping at the first differing byte.
#[test]
fn a_received_tag_verifies_only_when_every_byte_matches() {
    let (ya, _yb, point, sid) = draft_isk_inputs();
    let isk = intermediate_session_key(&sid, &point, &transcript_ir(&ya, b"ADa", &_yb, b"ADb"));
    let tag = key_confirmation_tag(&sid, &isk, &ya, b"ADa");

    assert!(verify_key_confirmation_tag(&tag, &tag));
    // Every bit, not a sample: a comparison that stopped early would still pass a test that only
    // flipped bytes near the start and the end.
    for index in 0..64 {
        for bit in 0..8 {
            let mut tampered = tag;
            tampered[index] ^= 1 << bit;
            assert!(
                !verify_key_confirmation_tag(&tag, &tampered),
                "a flipped bit at byte {index}, bit {bit} must not verify"
            );
        }
    }
    assert!(
        !verify_key_confirmation_tag(&tag, &[0u8; 64]),
        "an all-zero tag must not verify"
    );
}
