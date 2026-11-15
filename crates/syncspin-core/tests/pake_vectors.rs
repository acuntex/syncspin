//! The CPace draft's X25519/SHA-512 vectors (draft-irtf-cfrg-cpace-21, Appendix B.1).
//!
//! These vectors decide whether the `elligator2` crate can carry Sendspin's
//! `CPACE-X25519-SHA512`. Nothing in `src/pairing` may be built on the map until they pass,
//! and no value here may be adjusted to make an implementation agree: the hex is transcribed
//! from the draft.

#![cfg(feature = "pairing-code")]

use syncspin_core::pairing::pake::{generator, scalar_mult_vfy};

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
