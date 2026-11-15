//! Property tests for the parts of the protocol with an input space rather than a handful of
//! cases: fragmentation, reassembly of arbitrary bytes, the PSK id derivation and envelope parsing.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use proptest::prelude::*;
use syncspin_core::framing::{
    reassemble_binary, split_binary, Reassembler, BINARY_MESSAGE_ID_FRAGMENT, MAX_PLAINTEXT_LEN,
};
use syncspin_core::messages::Incoming;
use syncspin_core::noise::psk_id_for;

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    /// Any payload the framing layer can carry splits into frames that fit one Noise plaintext and
    /// reassembles to the same bytes.
    #[test]
    fn a_payload_up_to_four_mibibytes_survives_fragmentation(
        payload in prop::collection::vec(any::<u8>(), 0..=4 * 1024 * 1024),
    ) {
        let frames = split_binary(4, &payload, MAX_PLAINTEXT_LEN);
        prop_assert!(!frames.is_empty());
        prop_assert!(
            frames.iter().all(|frame| frame.len() <= MAX_PLAINTEXT_LEN),
            "a fragment exceeded the {} byte plaintext limit",
            MAX_PLAINTEXT_LEN
        );
        prop_assert!(
            frames.iter().all(|frame| !frame.is_empty()),
            "a fragment without a message id or a flags byte was emitted"
        );
        if frames.len() > 1 {
            prop_assert_eq!(frames[0][0], BINARY_MESSAGE_ID_FRAGMENT);
        }
        let (id, reassembled) = reassemble_binary(&frames).expect("the frames form one message");
        prop_assert_eq!(id, 4);
        prop_assert_eq!(reassembled, payload);
    }
}

proptest! {
    /// A reassembler fed arbitrary bytes never panics, and an error leaves it ready for a new
    /// message instead of keeping the half-assembled one.
    #[test]
    fn arbitrary_byte_streams_do_not_panic_the_reassembler(
        frames in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..40), 0..24),
    ) {
        let mut reassembler = Reassembler::new(128);
        for frame in &frames {
            match reassembler.push(frame) {
                Ok(_) => {}
                Err(_) => {
                    // A rejected sequence is dropped, not left in flight: a plain frame is
                    // accepted immediately afterwards and yields its own body.
                    let completed = reassembler
                        .push(&[9, 1, 2, 3])
                        .expect("a plain frame is accepted after the reset");
                    prop_assert_eq!(completed, Some((9, vec![1, 2, 3])));
                }
            }
        }
    }
}

proptest! {
    /// The id derivation is a pure function of the key and always yields the canonical unpadded
    /// base64url encoding of a 32-byte digest, whatever the key length.
    #[test]
    fn the_psk_id_is_deterministic_canonical_base64url(
        psk in prop::collection::vec(any::<u8>(), 0..=256),
    ) {
        let id = psk_id_for(&psk);
        prop_assert_eq!(&id, &psk_id_for(&psk));
        prop_assert_eq!(id.len(), 43);
        prop_assert!(
            id.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "the id carries a character outside the unpadded base64url alphabet: {id}"
        );
        prop_assert!(!id.contains('='));
        let bytes = URL_SAFE_NO_PAD
            .decode(&id)
            .expect("a 43-character id is valid base64url");
        prop_assert_eq!(bytes.len(), 32);
        prop_assert_eq!(URL_SAFE_NO_PAD.encode(&bytes), id);
    }
}

proptest! {
    /// Arbitrary UTF-8 text never panics the envelope parser. A recognised message reserializes
    /// into a frame that parses back to the same value; a rejected one carries an error that names
    /// what was wrong.
    #[test]
    fn any_utf8_text_is_safe_to_parse(text in ".*") {
        match Incoming::parse(&text) {
            Ok(Some(message)) => {
                let json = serde_json::to_string(&message).expect("a decoded message encodes");
                let reparsed = Incoming::parse(&json).expect("an encoded message parses");
                prop_assert_eq!(reparsed, Some(message));
            }
            Ok(None) => {}
            Err(error) => {
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }
}
