//! Wire-format tests: exact JSON keys, envelope round trips, binary framing and fragmentation.

use syncspin_core::framing::{
    decode_frame, encode_binary, max_audio_payload, reassemble_binary, split_binary, Frame,
    Reassembler, BINARY_MESSAGE_ID_FRAGMENT, FRAGMENT_FLAGS_RESERVED, FRAGMENT_FLAG_FIRST,
    FRAGMENT_FLAG_LAST, MAX_PLAINTEXT_LEN, MAX_REASSEMBLED_LEN,
};
use syncspin_core::messages::{
    AudioChunkHeader, ClientCommand, ClientGoodbye, ClientHello, ClientInit, ClientPairAuth,
    ClientPairConfirm, ClientPairFinalize, ClientPairInit, ClientPairPending, ClientPairRetry,
    ClientState, ClientTime, ControllerCommand, DecodeError, DeviceInfo, DynamicPairingCodeMethod,
    GroupUpdate, Incoming, NoiseHandshake, PairAbort, PairingPskMethod, PlayerState, PlayerSupport,
    ServerActivate, ServerCommand, ServerError, ServerHello, ServerInit, ServerPairAuth,
    ServerPairConfirm, ServerPairFinalize, ServerPairInit, ServerState, ServerTime, ServerUnpair,
    StaticPairingCodeMethod, StreamClear, StreamEnd, StreamStart, StreamStartPlayer,
    SupportedFormat, SupportedPairMethods, UnpairedAccess, AUDIO_CHUNK_ID, NOISE_SUITE,
    PROTOCOL_VERSION,
};

/// A payload whose first bytes differ, so a reassembled message is easy to verify.
fn sample_payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

#[test]
fn cleartext_handshake_envelopes_roundtrip_on_the_wire() {
    let client_init = ClientInit {
        client_id: "H6Xk3zZBqL9Vv1f8k4c0n2y7m5w8r1t4p6s9d3g0j2a".to_owned(),
        version: PROTOCOL_VERSION,
        suite: NOISE_SUITE.to_owned(),
    };
    let json = serde_json::to_string(&Incoming::ClientInit(client_init.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/init",
            "payload": {
                "client_id": "H6Xk3zZBqL9Vv1f8k4c0n2y7m5w8r1t4p6s9d3g0j2a",
                "version": 1,
                "suite": "25519_ChaChaPoly_SHA256"
            }
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientInit(client_init)
    );

    let server_init = ServerInit {
        server_id: "B1y4w7z0c3f6i9l2o5r8u1x4a7d0g3j6m9p2s5v8y1b".to_owned(),
        version: PROTOCOL_VERSION,
    };
    let json = serde_json::to_string(&Incoming::ServerInit(server_init.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "server/init",
            "payload": {
                "server_id": "B1y4w7z0c3f6i9l2o5r8u1x4a7d0g3j6m9p2s5v8y1b",
                "version": 1
            }
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ServerInit(server_init)
    );

    let handshake = NoiseHandshake {
        data: "AAEC_w".to_owned(),
    };
    let json = serde_json::to_string(&Incoming::NoiseHandshake(handshake.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "noise/handshake",
            "payload": { "data": "AAEC_w" }
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::NoiseHandshake(handshake)
    );
}

#[test]
fn server_error_roundtrips_and_keeps_an_unknown_reason() {
    // Cleartext, in place of `server/init`: the payload carries the wire's `reason` alone.
    let error = ServerError {
        reason: "unsupported_version".to_owned(),
    };
    let json = serde_json::to_string(&Incoming::ServerError(error.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "server/error",
            "payload": {"reason": "unsupported_version"}
        })
    );
    assert_eq!(
        Incoming::parse(&json).unwrap(),
        Some(Incoming::ServerError(error))
    );

    // A reason this revision does not name is carried verbatim: a later revision's value must not
    // turn the server's rejection into a decoding failure.
    assert_eq!(
        Incoming::parse(r#"{"type":"server/error","payload":{"reason":"future_reason"}}"#).unwrap(),
        Some(Incoming::ServerError(ServerError {
            reason: "future_reason".to_owned()
        }))
    );

    // The reason is required: a rejection without one tells the caller nothing.
    assert!(matches!(
        Incoming::parse(r#"{"type":"server/error","payload":{}}"#),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn group_update_roundtrips_on_the_wire() {
    let update = GroupUpdate {
        playback_state: "playing".to_owned(),
        group_id: "A".repeat(43),
        group_name: "Living room".to_owned(),
    };
    let json = serde_json::to_string(&Incoming::GroupUpdate(update.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "group/update",
            "payload": {
                "playback_state": "playing",
                "group_id": "A".repeat(43),
                "group_name": "Living room"
            }
        }),
        "every message carries all three fields"
    );
    assert_eq!(
        Incoming::parse(&json).unwrap(),
        Some(Incoming::GroupUpdate(update))
    );

    // All three fields are required: a partial update cannot describe the group on its own.
    for payload in [
        r#"{"playback_state":"playing"}"#,
        r#"{"playback_state":"playing","group_id":"AAAA"}"#,
        r#"{"playback_state":"playing","group_name":"Living room"}"#,
        r#"{"group_id":"AAAA","group_name":"Living room"}"#,
    ] {
        let text = format!(r#"{{"type":"group/update","payload":{payload}}}"#);
        assert!(
            matches!(Incoming::parse(&text), Err(DecodeError::Malformed(_))),
            "a group/update without all three fields must be malformed: {text}"
        );
    }
}

#[test]
fn client_hello_and_server_hello_roundtrip_on_the_wire() {
    let hello = ClientHello {
        name: "Listening room".to_owned(),
        device_info: Some(DeviceInfo {
            product_name: Some("Reference speaker".to_owned()),
            manufacturer: Some("Acme".to_owned()),
            software_version: Some("0.1.0".to_owned()),
            mac_address: None,
        }),
        supported_roles: vec![
            "player@v1".to_owned(),
            "controller@v1".to_owned(),
            "metadata@v1".to_owned(),
        ],
        player_support: Some(PlayerSupport {
            supported_formats: vec![SupportedFormat {
                codec: "flac".to_owned(),
                channels: 2,
                sample_rate: 48_000,
                bit_depth: 16,
            }],
            buffer_capacity: 131_072,
        }),
        supported_pair_methods: SupportedPairMethods {
            pairing_psk: Some(PairingPskMethod {}),
            static_pairing_code: None,
            dynamic_pairing_code: None,
        },
        unpaired_access: UnpairedAccess { enabled: true },
    };

    let json = serde_json::to_string(&Incoming::ClientHello(hello.clone())).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    // The whole envelope is pinned, so a stray, missing or renamed key fails here.
    assert_eq!(
        value,
        serde_json::json!({
            "type": "client/hello",
            "payload": {
                "name": "Listening room",
                "device_info": {
                    "product_name": "Reference speaker",
                    "manufacturer": "Acme",
                    "software_version": "0.1.0"
                },
                "supported_roles": ["player@v1", "controller@v1", "metadata@v1"],
                "player@v1_support": {
                    "supported_formats": [
                        { "codec": "flac", "channels": 2, "sample_rate": 48000, "bit_depth": 16 }
                    ],
                    "buffer_capacity": 131_072
                },
                "supported_pair_methods": { "pairing_psk": {} },
                "unpaired_access": { "enabled": true }
            }
        })
    );

    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientHello(hello)
    );

    // A pairing method that was never offered stays absent instead of growing an empty descriptor.
    let bare: ClientHello = serde_json::from_value(serde_json::json!({
        "name": "Bare",
        "supported_roles": ["player@v1"],
        "supported_pair_methods": {},
        "unpaired_access": { "enabled": false }
    }))
    .unwrap();
    assert_eq!(bare.supported_pair_methods.pairing_psk, None);
    let json = serde_json::to_string(&Incoming::ClientHello(bare)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        value["payload"]["supported_pair_methods"]
            .get("pairing_psk")
            .is_none(),
        "an absent pairing method must not be sent as an empty object"
    );

    let hello = ServerHello {
        name: "Library".to_owned(),
        languages: Some(vec!["en".to_owned(), "de".to_owned()]),
    };
    let json = serde_json::to_string(&Incoming::ServerHello(hello.clone())).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "type": "server/hello",
            "payload": { "name": "Library", "languages": ["en", "de"] }
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ServerHello(hello)
    );
}

#[test]
fn server_activate_and_player_state_roundtrip() {
    let activate = ServerActivate {
        activities: vec!["playback".to_owned()],
        active_roles: Some(vec!["player@v1".to_owned(), "controller@v1".to_owned()]),
        pairing: None,
    };

    let json = serde_json::to_string(&Incoming::ServerActivate(activate.clone())).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "type": "server/activate",
            "payload": {
                "activities": ["playback"],
                "active_roles": ["player@v1", "controller@v1"]
            }
        }),
        "an absent pairing object must be absent, not null"
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ServerActivate(activate)
    );

    let state = ClientState {
        available: true,
        player: Some(PlayerState {
            volume: Some(37),
            muted: Some(false),
            output_delay_ms: 0,
            required_lead_time_ms: 250,
            min_buffer_ms: 250,
            supported_commands: vec!["volume".to_owned(), "mute".to_owned()],
            format: None,
        }),
    };

    let json = serde_json::to_string(&Incoming::ClientState(state.clone())).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "type": "client/state",
            "payload": {
                "available": true,
                "player": {
                    "volume": 37,
                    "muted": false,
                    "output_delay_ms": 0,
                    "required_lead_time_ms": 250,
                    "min_buffer_ms": 250,
                    "supported_commands": ["volume", "mute"]
                }
            }
        }),
        "no format preference means the key is absent"
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientState(state)
    );
}

#[test]
fn pairing_messages_roundtrip_on_the_wire() {
    // A Pairing PSK attempt: no commitment, the key itself in the finalize.
    let init = ClientPairInit {
        pairing_index: 0,
        commit_b: None,
    };
    let json = serde_json::to_string(&Incoming::ClientPairInit(init.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/pair-init",
            "payload": {"pairing_index": 0},
        }),
        "the commitment belongs to the code flows and must stay absent"
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientPairInit(init)
    );

    // A dynamic-code attempt spells `commit_B` with the capital the spec uses.
    let commitment = ClientPairInit {
        pairing_index: 3,
        commit_b: Some("AA".to_owned()),
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            &serde_json::to_string(&Incoming::ClientPairInit(commitment.clone())).unwrap()
        )
        .unwrap()["payload"]["commit_B"],
        serde_json::json!("AA")
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(
            &serde_json::to_string(&Incoming::ClientPairInit(commitment)).unwrap()
        )
        .unwrap(),
        Incoming::ClientPairInit(ClientPairInit {
            pairing_index: 3,
            commit_b: Some("AA".to_owned())
        })
    );

    let finalize = ClientPairFinalize {
        long_term_psk: Some("key".to_owned()),
        wrapped_psk: None,
    };
    let json = serde_json::to_string(&Incoming::ClientPairFinalize(finalize.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/pair-finalize",
            "payload": {"long_term_psk": "key"},
        }),
        "exactly one of the two key fields is present"
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientPairFinalize(finalize)
    );
    let json = serde_json::to_string(&Incoming::ServerPairFinalize(ServerPairFinalize {})).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({"type": "server/pair-finalize", "payload": {}})
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ServerPairFinalize(ServerPairFinalize {})
    );

    // `server/unpair` carries no fields: its payload is the empty object.
    let json = serde_json::to_string(&Incoming::ServerUnpair(ServerUnpair {})).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({"type": "server/unpair", "payload": {}})
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ServerUnpair(ServerUnpair {})
    );

    let abort = PairAbort {
        reason: "method_not_supported".to_owned(),
    };
    let json = serde_json::to_string(&Incoming::PairAbort(abort.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "pair/abort",
            "payload": {"reason": "method_not_supported"},
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::PairAbort(abort)
    );

    // `commit_B` and `reason` are required where the spec requires them.
    assert!(matches!(
        Incoming::parse(r#"{"type":"client/pair-init","payload":{}}"#),
        Err(DecodeError::Malformed(_))
    ));
    assert!(matches!(
        Incoming::parse(r#"{"type":"pair/abort","payload":{}}"#),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn client_goodbye_roundtrips_on_the_wire() {
    let goodbye = ClientGoodbye {
        reason: "unpaired".to_owned(),
    };
    let json = serde_json::to_string(&Incoming::ClientGoodbye(goodbye.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/goodbye",
            "payload": {"reason": "unpaired"},
        })
    );
    assert_eq!(
        Incoming::parse(&json).unwrap(),
        Some(Incoming::ClientGoodbye(goodbye))
    );

    // The reason is required: a goodbye without one cannot tell the server anything.
    assert!(matches!(
        Incoming::parse(r#"{"type":"client/goodbye","payload":{}}"#),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn a_pair_finalize_formats_without_its_key_material() {
    // A real 43-character key and a 64-character wrapping, so the assertions below would catch the
    // value in either field rather than a short placeholder.
    let long_term = "B1y4w7z0c3f6i9l2o5r8u1x4a7d0g3j6m9p2s5v8y1b";
    let wrapped = "k8Xm3f0Q2p9Lr4Tz7Vc1Nb6Yh5Jd8Gs2Wa0Ke3Ui7Oo4Pa6Sd9Fg1Hj5Kl8Zx2Cv4Bn7Mq0Rt3";
    let finalize = ClientPairFinalize {
        long_term_psk: Some(long_term.to_owned()),
        wrapped_psk: Some(wrapped.to_owned()),
    };

    for text in [
        format!("{finalize:?}"),
        format!("{:?}", Incoming::ClientPairFinalize(finalize.clone())),
    ] {
        assert!(
            text.contains("long_term_psk: Some(\"<redacted>\")"),
            "the field must be present but redacted: {text}"
        );
        assert!(
            text.contains("wrapped_psk: Some(\"<redacted>\")"),
            "the field must be present but redacted: {text}"
        );
        assert!(
            !text.contains(long_term),
            "the long-term key must never appear in a debug format: {text}"
        );
        assert!(
            !text.contains(wrapped),
            "the sealed key must never appear in a debug format: {text}"
        );
    }

    // An absent field reads as `None`, not as a redaction of something that is not there.
    let empty = ClientPairFinalize::default();
    assert_eq!(
        format!("{empty:?}"),
        "ClientPairFinalize { long_term_psk: None, wrapped_psk: None }"
    );
}

#[test]
fn code_pairing_messages_roundtrip_on_the_wire() {
    // `client/pair-pending` without text carries only the index.
    let pending = ClientPairPending {
        pairing_index: 2,
        message: None,
    };
    let json = serde_json::to_string(&Incoming::ClientPairPending(pending.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/pair-pending",
            "payload": {"pairing_index": 2},
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientPairPending(pending)
    );

    // The host's sentence is optional and travels verbatim.
    let explained = ClientPairPending {
        pairing_index: 2,
        message: Some("Press the button".to_owned()),
    };
    let json = serde_json::to_string(&Incoming::ClientPairPending(explained.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/pair-pending",
            "payload": {"pairing_index": 2, "message": "Press the button"},
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientPairPending(explained)
    );

    // The two PAKE shares use the field names the spec spells, with the capitalization it uses.
    let server_auth = ServerPairAuth {
        pake_msg_1: "A".repeat(43),
    };
    let json = serde_json::to_string(&Incoming::ServerPairAuth(server_auth.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "server/pair-auth",
            "payload": {"pake_msg_1": "A".repeat(43)},
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ServerPairAuth(server_auth)
    );

    let client_auth = ClientPairAuth {
        pake_msg_2: "B".repeat(43),
    };
    let json = serde_json::to_string(&Incoming::ClientPairAuth(client_auth.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/pair-auth",
            "payload": {"pake_msg_2": "B".repeat(43)},
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientPairAuth(client_auth)
    );

    // A static flow's confirm carries only the tag; the sealed nonce belongs to the dynamic flow
    // and must stay absent rather than serialize as null.
    let confirm = ClientPairConfirm {
        client_kc: "C".repeat(86),
        wrapped_nonce_b: None,
    };
    let json = serde_json::to_string(&Incoming::ClientPairConfirm(confirm.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/pair-confirm",
            "payload": {"client_kc": "C".repeat(86)},
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientPairConfirm(confirm)
    );

    let with_nonce = ClientPairConfirm {
        client_kc: "C".repeat(86),
        wrapped_nonce_b: Some("D".repeat(64)),
    };
    let json = serde_json::to_string(&Incoming::ClientPairConfirm(with_nonce.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap()["payload"]["wrapped_nonce_B"],
        serde_json::json!("D".repeat(64))
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientPairConfirm(with_nonce)
    );

    let server_confirm = ServerPairConfirm {
        server_kc: "E".repeat(86),
    };
    let json = serde_json::to_string(&Incoming::ServerPairConfirm(server_confirm.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "server/pair-confirm",
            "payload": {"server_kc": "E".repeat(86)},
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ServerPairConfirm(server_confirm)
    );

    // The index is required: a pending message without it cannot name its activation.
    assert!(matches!(
        Incoming::parse(r#"{"type":"client/pair-pending","payload":{}}"#),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn dynamic_pairing_messages_roundtrip_on_the_wire() {
    // The first round's `server/pair-init` carries the server's nonce; the later rounds carry none,
    // and the field must then be absent rather than serialize as null.
    let first_round = ServerPairInit {
        nonce_a: Some("A".repeat(43)),
    };
    let json = serde_json::to_string(&Incoming::ServerPairInit(first_round.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "server/pair-init",
            "payload": {"nonce_A": "A".repeat(43)},
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ServerPairInit(first_round)
    );

    let later_round = ServerPairInit { nonce_a: None };
    let json = serde_json::to_string(&Incoming::ServerPairInit(later_round.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({"type": "server/pair-init", "payload": {}})
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ServerPairInit(later_round)
    );

    // `client/pair-retry` is the empty object, like the other payload-less messages.
    assert_eq!(
        serde_json::to_value(Incoming::ClientPairRetry(ClientPairRetry {})).unwrap(),
        serde_json::json!({"type": "client/pair-retry", "payload": {}})
    );
    assert_eq!(
        Incoming::parse(r#"{"type":"client/pair-retry","payload":{}}"#).unwrap(),
        Some(Incoming::ClientPairRetry(ClientPairRetry {}))
    );

    // `client/pair-init` carries the commitment of the dynamic flow; the static flow omits it.
    let with_commitment = ClientPairInit {
        pairing_index: 4,
        commit_b: Some("B".repeat(43)),
    };
    let json = serde_json::to_string(&Incoming::ClientPairInit(with_commitment.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/pair-init",
            "payload": {"pairing_index": 4, "commit_B": "B".repeat(43)},
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientPairInit(with_commitment)
    );
}

#[test]
fn the_dynamic_code_descriptor_advertises_channels_and_formats() {
    let descriptor = DynamicPairingCodeMethod {
        out_channels: vec!["display".to_owned()],
        formats: vec!["digits".to_owned(), "qr_code".to_owned()],
    };
    assert_eq!(
        serde_json::to_value(descriptor).unwrap(),
        serde_json::json!({
            "out_channels": ["display"],
            "formats": ["digits", "qr_code"],
        }),
        "the descriptor is what `dynamic_pairing_code` advertises"
    );

    let methods = SupportedPairMethods {
        pairing_psk: Some(PairingPskMethod {}),
        static_pairing_code: None,
        dynamic_pairing_code: Some(DynamicPairingCodeMethod {
            out_channels: vec!["speaker".to_owned()],
            formats: vec!["digits".to_owned()],
        }),
    };
    let json = serde_json::to_value(methods).unwrap();
    assert_eq!(
        json["dynamic_pairing_code"]["formats"],
        serde_json::json!(["digits"]),
        "the method is keyed by its wire identifier"
    );
    assert!(
        json.get("static_pairing_code").is_none(),
        "a method that is not offered stays absent: {json}"
    );
}

#[test]
fn a_pair_confirm_formats_without_its_tags() {
    let client_tag = "C".repeat(86);
    let sealed_nonce = "D".repeat(64);
    let confirm = ClientPairConfirm {
        client_kc: client_tag.clone(),
        wrapped_nonce_b: Some(sealed_nonce.clone()),
    };
    for text in [
        format!("{confirm:?}"),
        format!("{:?}", Incoming::ClientPairConfirm(confirm.clone())),
    ] {
        assert!(text.contains("client_kc: \"<redacted>\""), "got: {text}");
        assert!(
            text.contains("wrapped_nonce_B: Some(\"<redacted>\")"),
            "got: {text}"
        );
        assert!(
            !text.contains(&client_tag),
            "the tag must not appear: {text}"
        );
        assert!(
            !text.contains(&sealed_nonce),
            "the sealed nonce must not appear: {text}"
        );
    }

    let server_tag = "E".repeat(86);
    let server = ServerPairConfirm {
        server_kc: server_tag.clone(),
    };
    for text in [
        format!("{server:?}"),
        format!("{:?}", Incoming::ServerPairConfirm(server.clone())),
    ] {
        assert!(text.contains("server_kc: \"<redacted>\""), "got: {text}");
        assert!(
            !text.contains(&server_tag),
            "the tag must not appear: {text}"
        );
    }
}

#[test]
fn no_pairing_message_formats_key_material_a_nonce_or_a_tag() {
    // Distinctive values, so a leak is unambiguous: a long-term key, a sealed key, both MCF tags,
    // the sealed opening of the client nonce, and the server's nonce.
    let long_term = "B1y4w7z0c3f6i9l2o5r8u1x4a7d0g3j6m9p2s5v8y1b".to_owned();
    let wrapped_psk =
        "k8Xm3f0Q2p9Lr4Tz7Vc1Nb6Yh5Jd8Gs2Wa0Ke3Ui7Oo4Pa6Sd9Fg1Hj5Kl8Zx2Cv4Bn7Mq0Rt3".to_owned();
    let server_tag = "E".repeat(86);
    let client_tag = "C".repeat(86);
    let sealed_nonce = "D".repeat(64);
    let server_nonce = "F".repeat(43);

    // Every value is a secret or a binding value: no `Debug` output of a pairing message may
    // print any of them, whichever message it came from.
    let secrets = [
        &long_term,
        &wrapped_psk,
        &server_tag,
        &client_tag,
        &sealed_nonce,
        &server_nonce,
    ];

    // Each entry is the message, plus the marker its format must carry when it holds a secret.
    // `client/pair-init`'s `commit_B` is a hash and the two `pake_msg` fields are public shares, so
    // those messages have nothing to redact; `nonce_A` is public on the wire as well, and is
    // redacted anyway so that no pairing message can print a nonce into a log.
    let messages: [(&str, Incoming, bool); 12] = [
        (
            "client/pair-init",
            Incoming::ClientPairInit(ClientPairInit {
                pairing_index: 3,
                commit_b: None,
            }),
            false,
        ),
        (
            "client/pair-finalize",
            Incoming::ClientPairFinalize(ClientPairFinalize {
                long_term_psk: Some(long_term.clone()),
                wrapped_psk: Some(wrapped_psk.clone()),
            }),
            true,
        ),
        (
            "server/pair-init",
            Incoming::ServerPairInit(ServerPairInit {
                nonce_a: Some(server_nonce.clone()),
            }),
            true,
        ),
        (
            "server/pair-auth",
            Incoming::ServerPairAuth(ServerPairAuth {
                pake_msg_1: "G".repeat(43),
            }),
            false,
        ),
        (
            "client/pair-auth",
            Incoming::ClientPairAuth(ClientPairAuth {
                pake_msg_2: "H".repeat(43),
            }),
            false,
        ),
        (
            "server/pair-confirm",
            Incoming::ServerPairConfirm(ServerPairConfirm {
                server_kc: server_tag.clone(),
            }),
            true,
        ),
        (
            "client/pair-confirm",
            Incoming::ClientPairConfirm(ClientPairConfirm {
                client_kc: client_tag.clone(),
                wrapped_nonce_b: Some(sealed_nonce.clone()),
            }),
            true,
        ),
        (
            "server/pair-finalize",
            Incoming::ServerPairFinalize(ServerPairFinalize {}),
            false,
        ),
        (
            "client/pair-retry",
            Incoming::ClientPairRetry(ClientPairRetry {}),
            false,
        ),
        (
            "client/pair-pending",
            Incoming::ClientPairPending(ClientPairPending {
                pairing_index: 3,
                message: Some("Place the device nearby".to_owned()),
            }),
            false,
        ),
        (
            "pair/abort",
            Incoming::PairAbort(PairAbort {
                reason: "attempt_timeout".to_owned(),
            }),
            false,
        ),
        (
            "server/unpair",
            Incoming::ServerUnpair(ServerUnpair {}),
            false,
        ),
    ];

    for (name, message, redacts) in messages {
        let text = format!("{message:?}");
        for secret in secrets {
            assert!(
                !text.contains(secret.as_str()),
                "{name} must not format a key, a nonce or a tag: {text}"
            );
        }
        if redacts {
            assert!(
                text.contains("<redacted>"),
                "{name} must name its redacted field: {text}"
            );
        }
    }
}

#[test]
fn a_static_pairing_code_descriptor_serializes_as_an_empty_object() {
    let methods = SupportedPairMethods {
        pairing_psk: Some(PairingPskMethod {}),
        static_pairing_code: Some(StaticPairingCodeMethod::default()),
        dynamic_pairing_code: None,
    };
    assert_eq!(
        serde_json::to_value(&methods).unwrap(),
        serde_json::json!({"pairing_psk": {}, "static_pairing_code": {}}),
        "a method with no parameters is the empty object"
    );

    let located = StaticPairingCodeMethod {
        locations: Some(vec!["device".to_owned()]),
    };
    assert_eq!(
        serde_json::to_value(&located).unwrap(),
        serde_json::json!({"locations": ["device"]})
    );

    assert_eq!(
        serde_json::to_value(SupportedPairMethods::default()).unwrap(),
        serde_json::json!({}),
        "an absent method is omitted instead of serializing as null"
    );
}

#[test]
fn client_command_roundtrips_on_the_wire() {
    let play = ClientCommand {
        controller: Some(ControllerCommand {
            command: "play".to_owned(),
            ..ControllerCommand::default()
        }),
    };
    let json = serde_json::to_string(&Incoming::ClientCommand(play.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/command",
            "payload": { "controller": { "command": "play" } }
        }),
        "a parameterless command carries only its name"
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientCommand(play)
    );

    // A parameter belongs to its command and the other fields stay absent rather than null.
    let seek = ClientCommand {
        controller: Some(ControllerCommand {
            command: "seek".to_owned(),
            position_ms: Some(1_500),
            ..ControllerCommand::default()
        }),
    };
    let json = serde_json::to_string(&Incoming::ClientCommand(seek.clone())).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        serde_json::json!({
            "type": "client/command",
            "payload": { "controller": { "command": "seek", "position_ms": 1_500 } }
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::ClientCommand(seek)
    );

    // A command aimed at another role parses, because a future revision may define one.
    let empty = Incoming::parse(r#"{"type":"client/command","payload":{}}"#).unwrap();
    assert_eq!(
        empty,
        Some(Incoming::ClientCommand(ClientCommand::default()))
    );
}

#[test]
fn stream_start_and_audio_chunk_header_roundtrip() {
    let start = StreamStart {
        server_transmitted: 1_760_000_000_000_000,
        player: Some(StreamStartPlayer {
            codec: "flac".to_owned(),
            sample_rate: 48_000,
            channels: 2,
            bit_depth: 16,
            codec_header: Some("ZkxhQwAAACAA".to_owned()),
        }),
    };

    let json = serde_json::to_string(&Incoming::StreamStart(start.clone())).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "type": "stream/start",
            "payload": {
                "server_transmitted": 1_760_000_000_000_000_i64,
                "player": {
                    "codec": "flac",
                    "sample_rate": 48_000,
                    "channels": 2,
                    "bit_depth": 16,
                    "codec_header": "ZkxhQwAAACAA"
                }
            }
        })
    );
    assert_eq!(
        serde_json::from_str::<Incoming>(&json).unwrap(),
        Incoming::StreamStart(start)
    );

    let audio = [0xf8, 0xff, 0x00, 0x11, 0x22];
    let header = AudioChunkHeader {
        timestamp_us: 1_760_000_123_456,
        send_ahead: 250_000,
    };
    let chunk = header.encode(&audio);
    assert_eq!(chunk[0], AUDIO_CHUNK_ID);
    assert_eq!(chunk.len(), AudioChunkHeader::LEN + audio.len());
    let (parsed, body) = AudioChunkHeader::parse(&chunk).unwrap();
    assert_eq!(parsed, header);
    assert_eq!(body, &audio);

    // The header is pinned byte for byte: id, eight big-endian timestamp bytes, four big-endian
    // send_ahead bytes. 42 is 0x2a in the last timestamp byte.
    let header = AudioChunkHeader {
        timestamp_us: 42,
        send_ahead: 7,
    };
    assert_eq!(
        header.encode(&[]),
        vec![4, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 7]
    );
    let (parsed, body) = AudioChunkHeader::parse(&[4, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 7])
        .expect("a hand-written chunk parses");
    assert_eq!(parsed, header);
    assert!(body.is_empty());

    // A negative timestamp is eight bytes of two's complement.
    let negative = AudioChunkHeader {
        timestamp_us: -1,
        send_ahead: 0,
    };
    let negative_chunk = negative.encode(&[]);
    assert_eq!(
        negative_chunk,
        vec![4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]
    );
    let (parsed, body) = AudioChunkHeader::parse(&negative_chunk).unwrap();
    assert_eq!(parsed, negative);
    assert!(body.is_empty());

    assert!(
        AudioChunkHeader::parse(&[]).is_err(),
        "an empty binary message is a protocol error"
    );
    assert!(
        AudioChunkHeader::parse(&[AUDIO_CHUNK_ID, 0, 0, 0]).is_err(),
        "a chunk shorter than its header is a protocol error"
    );
}

#[test]
fn incoming_classifies_known_and_rejects_unknown_types() {
    // Unknown payload fields are forward compatible and must not fail the parse.
    let message: Incoming = serde_json::from_str(
        r#"{"type":"server/hello","payload":{"name":"Library","languages":["en"],"future":true}}"#,
    )
    .unwrap();
    assert_eq!(
        message,
        Incoming::ServerHello(ServerHello {
            name: "Library".to_owned(),
            languages: Some(vec!["en".to_owned()]),
        })
    );

    let message: Incoming = serde_json::from_str(
        r#"{"type":"server/state","payload":{"metadata":{"timestamp":1700,"title":"Piece","artist":"Composer","progress":{"track_progress":1000,"track_duration":2000,"playback_speed":1000}}}}"#,
    )
    .unwrap();
    let state = match message {
        Incoming::ServerState(state) => state,
        other => panic!("classified as {other:?}"),
    };
    let metadata = state.metadata.expect("metadata object");
    assert_eq!(metadata.title.as_deref(), Some("Piece"));
    assert_eq!(metadata.artist.as_deref(), Some("Composer"));
    assert_eq!(metadata.progress.unwrap().track_progress, Some(1000));

    let error = serde_json::from_str::<Incoming>(r#"{"type":"server/hologram","payload":{}}"#)
        .expect_err("direct deserialization cannot classify an unknown type");
    assert!(
        error.to_string().contains("unknown variant"),
        "unexpected error: {error}"
    );
}

#[test]
fn unknown_type_is_ignorable() {
    // A type this revision does not implement is not an error: the protocol requires ignoring the
    // message and keeping the connection open.
    assert_eq!(
        Incoming::parse(r#"{"type":"future/telemetry","payload":{"value":1}}"#).unwrap(),
        None
    );
    assert_eq!(
        Incoming::parse(r#"{"type":"server/hologram","payload":{}}"#).unwrap(),
        None
    );
}

#[test]
fn malformed_known_type_is_an_error() {
    // A known type whose payload does not parse is a protocol error, not something to ignore.
    let error =
        Incoming::parse(r#"{"type":"server/state","payload":{"metadata":42}}"#).unwrap_err();
    assert!(
        matches!(&error, DecodeError::Malformed(_)),
        "unexpected error: {error}"
    );
    assert!(
        matches!(
            Incoming::parse(r#"{"type":"stream/end"}"#),
            Err(DecodeError::Malformed(_))
        ),
        "a known type without its payload object is malformed"
    );
    // A frame that is not an envelope at all cannot be ignored either.
    assert!(matches!(
        Incoming::parse("not json"),
        Err(DecodeError::Malformed(_))
    ));
    assert!(matches!(
        Incoming::parse(r#"{"payload":{}}"#),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn parse_accepts_every_message_this_revision_implements() {
    let messages = vec![
        Incoming::ClientInit(ClientInit {
            client_id: "id".to_owned(),
            version: PROTOCOL_VERSION,
            suite: NOISE_SUITE.to_owned(),
        }),
        Incoming::ServerInit(ServerInit {
            server_id: "id".to_owned(),
            version: PROTOCOL_VERSION,
        }),
        Incoming::NoiseHandshake(NoiseHandshake {
            data: "AA".to_owned(),
        }),
        Incoming::ServerHello(ServerHello {
            name: "Server".to_owned(),
            languages: None,
        }),
        Incoming::ClientHello(ClientHello {
            name: "Client".to_owned(),
            device_info: None,
            supported_roles: Vec::new(),
            player_support: None,
            supported_pair_methods: SupportedPairMethods::default(),
            unpaired_access: UnpairedAccess::default(),
        }),
        Incoming::ServerActivate(ServerActivate::default()),
        Incoming::GroupUpdate(GroupUpdate {
            playback_state: "stopped".to_owned(),
            group_id: "A".repeat(43),
            group_name: "Group".to_owned(),
        }),
        Incoming::ServerError(ServerError {
            reason: "malformed".to_owned(),
        }),
        Incoming::ClientPairInit(ClientPairInit::default()),
        Incoming::ClientPairFinalize(ClientPairFinalize::default()),
        Incoming::ServerPairFinalize(ServerPairFinalize {}),
        Incoming::ServerUnpair(ServerUnpair {}),
        Incoming::ClientGoodbye(ClientGoodbye {
            reason: "shutdown".to_owned(),
        }),
        Incoming::PairAbort(PairAbort {
            reason: "attempt_timeout".to_owned(),
        }),
        Incoming::ClientTime(ClientTime {
            client_transmitted: 1,
        }),
        Incoming::ServerTime(ServerTime {
            client_transmitted: 1,
            server_received: 2,
            server_transmitted: 3,
        }),
        Incoming::ClientState(ClientState {
            available: true,
            player: None,
        }),
        Incoming::ServerState(ServerState::default()),
        Incoming::ServerCommand(ServerCommand::default()),
        Incoming::ClientCommand(ClientCommand::default()),
        Incoming::StreamStart(StreamStart::default()),
        Incoming::StreamClear(StreamClear::default()),
        Incoming::StreamEnd(StreamEnd::default()),
    ];
    assert_eq!(messages.len(), 23, "one instance per message type");
    for message in messages {
        let text = serde_json::to_string(&message).unwrap();
        assert_eq!(
            Incoming::parse(&text).unwrap(),
            Some(message),
            "parse rejected {text}"
        );
    }
}

#[test]
fn a_payload_over_the_limit_is_fragmented_and_reassembles() {
    let payload = sample_payload(MAX_PLAINTEXT_LEN * 2 + 7);
    let frames = split_binary(4, &payload, MAX_PLAINTEXT_LEN);

    // A first fragment spends three bytes on its header, so every fragment carries at least
    // that many bytes less than the limit.
    let chunk = MAX_PLAINTEXT_LEN - 3;
    assert_eq!(frames.len(), payload.len().div_ceil(chunk));
    assert_eq!(
        frames.len(),
        3,
        "a payload of two limits plus seven bytes needs three fragments"
    );
    // Exact sizes: two full chunks and the seven bytes plus the three-byte-sized remainder.
    assert_eq!(
        frames.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![MAX_PLAINTEXT_LEN, MAX_PLAINTEXT_LEN - 1, 2 + 13],
        "65516 + 65516 + 13 payload bytes with three- and two-byte fragment headers"
    );
    for frame in &frames {
        assert!(
            frame.len() <= MAX_PLAINTEXT_LEN,
            "fragment of {} bytes exceeds the limit",
            frame.len()
        );
        assert_eq!(frame[0], BINARY_MESSAGE_ID_FRAGMENT);
    }
    assert_ne!(frames[0][1] & FRAGMENT_FLAG_FIRST, 0);
    assert_eq!(frames[0][1] & FRAGMENT_FLAG_LAST, 0);
    assert_eq!(
        frames[0][2], 4,
        "the first fragment carries the original message id"
    );
    assert_eq!(
        frames[2][1] & (FRAGMENT_FLAG_FIRST | FRAGMENT_FLAG_LAST),
        FRAGMENT_FLAG_LAST
    );
    assert_eq!(reassemble_binary(&frames).unwrap(), (4, payload.clone()));

    // A message that fits stays one frame and comes back unchanged.
    let small = split_binary(4, &payload[..16], MAX_PLAINTEXT_LEN);
    assert_eq!(small, vec![encode_binary(4, &payload[..16])]);
    assert_eq!(
        reassemble_binary(&small).unwrap(),
        (4, payload[..16].to_vec())
    );
}

#[test]
fn fragmentation_boundary_is_exact() {
    // One Noise transport message minus its authentication tag bounds the frame, message id
    // included.
    assert_eq!(
        MAX_PLAINTEXT_LEN,
        syncspin_core::noise::MAX_MESSAGE_LEN - syncspin_core::noise::TAG_LEN
    );

    // The largest application payload that fits one frame: one message id byte plus 65 518 bytes.
    let payload = vec![0xa5; MAX_PLAINTEXT_LEN - 1];
    let frames = split_binary(4, &payload, MAX_PLAINTEXT_LEN);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].len(), MAX_PLAINTEXT_LEN);
    assert_eq!(frames[0], encode_binary(4, &payload));
    assert_eq!(reassemble_binary(&frames).unwrap(), (4, payload));

    // One byte more does not fit: the first fragment takes the whole frame for 65 516 payload
    // bytes, and the three remaining bytes travel in a five-byte continuation fragment.
    let payload = vec![0xa5; MAX_PLAINTEXT_LEN];
    let frames = split_binary(4, &payload, MAX_PLAINTEXT_LEN);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].len(), MAX_PLAINTEXT_LEN);
    assert_eq!(frames[1].len(), 2 + 3);
    assert_eq!(frames[0][1], FRAGMENT_FLAG_FIRST);
    assert_eq!(frames[1][1], FRAGMENT_FLAG_LAST);
    assert_eq!(reassemble_binary(&frames).unwrap(), (4, payload));
}

#[test]
fn reassembly_rejects_a_missing_fragment() {
    let payload = sample_payload(MAX_PLAINTEXT_LEN * 2 + 7);
    let frames = split_binary(4, &payload, MAX_PLAINTEXT_LEN);
    assert_eq!(
        reassemble_binary(&frames).unwrap(),
        (4, payload),
        "the sequence starts out valid"
    );

    let without_last = &frames[..frames.len() - 1];
    assert!(
        reassemble_binary(without_last).is_err(),
        "a sequence without its last fragment is incomplete"
    );

    let without_first = &frames[1..];
    assert!(
        reassemble_binary(without_first).is_err(),
        "a sequence without its first fragment has no message id"
    );
}

#[test]
fn reassembly_rejects_a_misplaced_last_flag_and_reserved_bits() {
    // The flags byte is the only announcement of how much of a message is outstanding: the
    // first flag opens it and the last flag closes it. A last flag on the wrong fragment makes
    // the message claim to end where it does not.
    let payload = vec![0x5a; MAX_PLAINTEXT_LEN * 2 + 7];
    let frames = split_binary(4, &payload, MAX_PLAINTEXT_LEN);
    assert_eq!(frames.len(), 3);

    let mut early_end = frames.clone();
    let last = early_end.len() - 1;
    early_end[last][1] &= !FRAGMENT_FLAG_LAST;
    early_end[last - 1][1] |= FRAGMENT_FLAG_LAST;
    assert!(
        reassemble_binary(&early_end).is_err(),
        "data after the announced last fragment must be rejected"
    );

    let mut reserved_flags = frames;
    reserved_flags[1][1] |= FRAGMENT_FLAGS_RESERVED;
    assert!(
        reassemble_binary(&reserved_flags).is_err(),
        "reserved flag bits must be rejected"
    );
}

#[test]
fn reassembly_rejects_every_malformed_sequence() {
    let payload = vec![0x11; MAX_PLAINTEXT_LEN + 16];
    let frames = split_binary(4, &payload, MAX_PLAINTEXT_LEN);
    assert_eq!(frames.len(), 2);
    assert_eq!(reassemble_binary(&frames).unwrap(), (4, payload));

    // 1: an original message id of 1, which is reserved for fragmentation.
    let mut reserved_original = frames.clone();
    reserved_original[0][2] = BINARY_MESSAGE_ID_FRAGMENT;
    assert!(
        reassemble_binary(&reserved_original).is_err(),
        "an original message id of 1 must be rejected"
    );

    // 2: a second first fragment while one is still in flight.
    let mut second_first = frames.clone();
    second_first[1][1] = FRAGMENT_FLAG_FIRST;
    assert!(
        reassemble_binary(&second_first).is_err(),
        "a second first fragment must be rejected"
    );

    // 3: a plain message in the middle of a sequence.
    let mut plain_in_between = frames.clone();
    plain_in_between[1] = encode_binary(4, &[0, 1, 2]);
    assert!(
        reassemble_binary(&plain_in_between).is_err(),
        "a non-fragment frame while one is in flight must be rejected"
    );

    // 4: a fragment without its flags byte.
    let mut no_flags = frames.clone();
    no_flags[1] = vec![BINARY_MESSAGE_ID_FRAGMENT];
    assert!(
        reassemble_binary(&no_flags).is_err(),
        "a fragment without a flags byte must be rejected"
    );

    // 5: a first fragment without its original message id byte.
    let mut no_original = frames;
    no_original[0] = vec![BINARY_MESSAGE_ID_FRAGMENT, FRAGMENT_FLAG_FIRST];
    assert!(
        reassemble_binary(&no_original).is_err(),
        "a first fragment without an original message id must be rejected"
    );
}

#[test]
fn reassembler_yields_a_message_only_on_the_last_fragment() {
    let payload = sample_payload(MAX_PLAINTEXT_LEN * 2 + 7);
    let frames = split_binary(4, &payload, MAX_PLAINTEXT_LEN);
    let mut reassembler = Reassembler::new(MAX_REASSEMBLED_LEN);

    for frame in &frames[..frames.len() - 1] {
        assert_eq!(reassembler.push(frame).unwrap(), None);
    }
    assert_eq!(
        reassembler.push(&frames[frames.len() - 1]).unwrap(),
        Some((4, payload.clone()))
    );

    // A plain frame completes at once and leaves the reassembler ready for the next message.
    assert_eq!(
        reassembler.push(&encode_binary(0, b"{}")).unwrap(),
        Some((0, b"{}".to_vec()))
    );
    assert_eq!(
        reassembler.push(&frames[0]).unwrap(),
        None,
        "a fresh sequence starts cleanly"
    );
}

#[test]
fn reassembler_rejects_a_non_fragment_while_in_flight() {
    let payload = vec![0x22; 32];
    let frames = split_binary(4, &payload, 16);
    let mut reassembler = Reassembler::new(1024);

    assert_eq!(
        reassembler.push(&frames[0]).unwrap(),
        None,
        "the first fragment opens a message"
    );
    assert!(
        reassembler.push(&encode_binary(4, &[0, 1])).is_err(),
        "a plain frame cannot interrupt a sequence"
    );
    // The error drops the message in flight, so the next plain frame is a fresh message.
    assert_eq!(
        reassembler.push(&encode_binary(0, b"{}")).unwrap(),
        Some((0, b"{}".to_vec()))
    );
}

#[test]
fn reassembler_enforces_the_byte_cap() {
    let payload = vec![0x33; 32];
    let frames = split_binary(4, &payload, 16);
    let mut reassembler = Reassembler::new(16);

    // The first fragment carries 13 payload bytes and still fits; the second would exceed the cap.
    assert_eq!(reassembler.push(&frames[0]).unwrap(), None);
    assert!(
        reassembler.push(&frames[1]).is_err(),
        "a message longer than the cap must be rejected"
    );
}

#[test]
fn decode_frame_classifies_json_and_binary_plaintexts() {
    let body = r#"{"type":"server/hello","payload":{}}"#;
    let mut plaintext = vec![0];
    plaintext.extend_from_slice(body.as_bytes());
    assert_eq!(decode_frame(&plaintext).unwrap(), Frame::Json(body));

    let chunk = AudioChunkHeader {
        timestamp_us: 42,
        send_ahead: 7,
    }
    .encode(&[1, 2, 3]);
    assert_eq!(
        decode_frame(&chunk).unwrap(),
        Frame::Binary {
            id: AUDIO_CHUNK_ID,
            payload: &chunk[1..],
        }
    );

    assert!(
        decode_frame(&[]).is_err(),
        "an empty plaintext is a protocol error"
    );
    let mut malformed = vec![0];
    malformed.extend_from_slice(&[0xff, 0xfe]);
    assert!(
        decode_frame(&malformed).is_err(),
        "a JSON body must be valid UTF-8"
    );
}

#[test]
fn max_audio_payload_leaves_room_for_the_header() {
    let payload_len = max_audio_payload(MAX_PLAINTEXT_LEN);
    assert_eq!(payload_len, MAX_PLAINTEXT_LEN - AudioChunkHeader::LEN);

    let chunk = AudioChunkHeader {
        timestamp_us: 0,
        send_ahead: 0,
    }
    .encode(&vec![0u8; payload_len]);
    assert_eq!(
        chunk.len(),
        MAX_PLAINTEXT_LEN,
        "a maximal chunk must fill one frame exactly"
    );
    assert_eq!(
        split_binary(AUDIO_CHUNK_ID, &chunk[1..], MAX_PLAINTEXT_LEN).len(),
        1,
        "a maximal chunk must not be fragmented"
    );
    assert_eq!(
        max_audio_payload(AudioChunkHeader::LEN - 1),
        0,
        "a limit below the fixed header cannot carry audio"
    );
}

#[test]
fn an_audio_chunk_header_rejects_the_wrong_id_and_each_truncation() {
    use std::error::Error as _;

    let error = AudioChunkHeader::parse(&[]).expect_err("an empty message has no header");
    assert!(
        format!("{error:#}").contains("empty binary message"),
        "unexpected error: {error:#}"
    );

    let error = AudioChunkHeader::parse(&[7, 0, 0, 0])
        .expect_err("only an audio chunk id introduces a header");
    assert!(
        format!("{error:#}").contains("id 7 is not an audio chunk"),
        "unexpected error: {error:#}"
    );

    // Short enough that the timestamp is incomplete, then long enough for the timestamp but not
    // for `send_ahead`: both are truncations, and the message names the length it saw.
    for len in 1..AudioChunkHeader::LEN {
        let mut message = vec![AUDIO_CHUNK_ID; len];
        if len > 1 {
            message[1..].fill(0);
        }
        let error = AudioChunkHeader::parse(&message)
            .expect_err("a chunk shorter than the fixed header must be rejected");
        let message = format!("{error:#}");
        assert!(
            message.contains("truncated") && message.contains(&len.to_string()),
            "the error must name the truncation, got: {message}"
        );
    }

    // The two truncation points above are distinct branches: fewer than nine bytes fail at the
    // timestamp, nine to twelve fail after it.
    assert!(AudioChunkHeader::parse(&[AUDIO_CHUNK_ID; 8]).is_err());
    assert!(AudioChunkHeader::parse(&[AUDIO_CHUNK_ID; 9]).is_err());
    assert!(AudioChunkHeader::parse(&[AUDIO_CHUNK_ID; 12]).is_err());

    let header = AudioChunkHeader {
        timestamp_us: -1,
        send_ahead: 0,
    }
    .encode(&[1]);
    assert_eq!(header.len(), AudioChunkHeader::LEN + 1);
    assert_eq!(
        AudioChunkHeader::parse(&header).expect("a complete header parses"),
        (
            AudioChunkHeader {
                timestamp_us: -1,
                send_ahead: 0
            },
            &[1u8][..]
        )
    );

    let unknown = DecodeError::UnknownType("future/telemetry".to_owned());
    assert!(
        unknown.to_string().contains("future/telemetry"),
        "an unknown type names itself: {unknown}"
    );
    assert!(
        unknown.source().is_none(),
        "an unknown type wraps no underlying error"
    );

    let malformed = Incoming::parse("{\"type\":\"client/time\"}").unwrap_err();
    assert!(
        malformed.to_string().contains("malformed message"),
        "a malformed message names the decode failure: {malformed}"
    );
    assert!(
        malformed.source().is_some(),
        "a malformed message exposes the serde error as its source"
    );
}

#[test]
fn reassembly_rejects_an_empty_sequence_and_more_than_one_message() {
    let error = reassemble_binary(&[]).expect_err("an empty sequence has no message");
    assert!(
        format!("{error:#}").contains("no frame to reassemble"),
        "unexpected error: {error:#}"
    );

    let frames = vec![encode_binary(0, b"{}"), encode_binary(4, &[1, 2, 3])];
    let error = reassemble_binary(&frames).expect_err("two frames are two messages");
    assert!(
        format!("{error:#}").contains("more than one message"),
        "unexpected error: {error:#}"
    );
    assert!(
        format!("{error:#}").contains("frame 1"),
        "the error names the frame with the second message: {error:#}"
    );
}

#[test]
fn a_single_fragment_can_carry_both_flags() {
    // Nothing in the encoding forbids a message that fits one frame from being sent as a
    // first-and-last fragment; the reassembler has to hand it over as one message.
    let mut reassembler = Reassembler::new(1024);
    let frame = vec![
        BINARY_MESSAGE_ID_FRAGMENT,
        FRAGMENT_FLAG_FIRST | FRAGMENT_FLAG_LAST,
        9,
        1,
        2,
        3,
    ];
    assert_eq!(
        reassembler.push(&frame).unwrap(),
        Some((9, vec![1, 2, 3])),
        "a first-and-last fragment completes in one push"
    );
    assert_eq!(
        reassembler.push(&encode_binary(0, b"{}")).unwrap(),
        Some((0, b"{}".to_vec())),
        "the completed message leaves nothing in flight"
    );
}

#[test]
fn a_first_fragment_cannot_exceed_the_message_cap_on_its_own() {
    let mut reassembler = Reassembler::new(2);
    let frame = vec![BINARY_MESSAGE_ID_FRAGMENT, FRAGMENT_FLAG_FIRST, 4, 1, 2, 3];
    let error = reassembler
        .push(&frame)
        .expect_err("three payload bytes exceed the two-byte cap");
    assert!(
        format!("{error:#}").contains("exceeds 2 bytes"),
        "unexpected error: {error:#}"
    );

    // The rejected first fragment left nothing in flight, so a continuation is refused rather
    // than appended to a message that was never opened.
    assert!(
        reassembler
            .push(&[BINARY_MESSAGE_ID_FRAGMENT, 0, 1])
            .is_err(),
        "a continuation after the rejected first fragment has no message to continue"
    );
}

#[test]
fn an_empty_frame_is_rejected() {
    let mut reassembler = Reassembler::new(1024);
    let error = reassembler
        .push(&[])
        .expect_err("an empty frame has no message id");
    assert!(
        format!("{error:#}").contains("empty frame"),
        "unexpected error: {error:#}"
    );
    assert_eq!(
        reassembler.push(&encode_binary(0, b"{}")).unwrap(),
        Some((0, b"{}".to_vec())),
        "the error leaves the reassembler usable"
    );
}
