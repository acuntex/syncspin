//! The listener, the activation and the stream, driven by a client that speaks the specification.
//!
//! The fake client lives in `common`, shared with the pairing tests: it walks the messages
//! `connection.md` and `messaging.md` define and asserts what the server announces.

mod common;

use std::time::{Duration, Instant};

use common::*;
use syncspin_core::messages::{
    ClientCommand, ControllerCommand, Incoming, ServerError, ServerState, StreamEnd,
};
use syncspin_server::TrackInfo;
#[tokio::test]
async fn a_client_connects_and_is_activated() -> Result<()> {
    for suite in Suite::ALL {
        let (server, port, mut events) = start().await?;
        let mut client = FakeClient::connect(port).await?;
        let activate = client.connect_and_activate(&server, suite).await?;

        assert_eq!(
            client.server_name.as_deref(),
            Some(SERVER_NAME),
            "`server/hello` carries the configured name with suite {suite}"
        );
        let roles = activate.active_roles.unwrap_or_default();
        assert_eq!(
            roles,
            ["player@v1", "controller@v1", "metadata@v1"],
            "every role the client offered is active with suite {suite}"
        );
        assert!(
            activate.activities.is_empty(),
            "a server with no group declares no activity, with suite {suite}"
        );

        assert_eq!(
            next_event(&mut events).await,
            Event::ClientConnected {
                client_id: client.identity.public_base64(),
                name: CLIENT_NAME.to_owned(),
                approved: false,
            }
        );
        assert_eq!(
            next_event(&mut events).await,
            Event::ClientActivated {
                client_id: client.identity.public_base64(),
                roles: Vec::new(),
            },
            "an unapproved client is activated with no roles"
        );
        assert_eq!(
            next_event(&mut events).await,
            Event::ClientActivated {
                client_id: client.identity.public_base64(),
                roles: roles.clone(),
            },
            "the approval activates the roles the client offered"
        );

        client.goodbye("shutdown").await?;
        assert_eq!(
            next_event(&mut events).await,
            Event::ClientLeft {
                reason: "shutdown".to_owned(),
            },
            "the goodbye reason reaches the host verbatim"
        );
        server.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_handshake_that_does_not_authenticate_is_refused() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;

    // The same exchange, sealed with a key the server does not use: the initiator cannot
    // authenticate message 2, so the server closes without a further message.
    let mut responder = client.begin_handshake(Suite::ChaChaPoly).await?;
    responder.set_psk(&[7u8; 32])?;
    let outcome = client.finish_handshake(responder).await;
    assert!(
        outcome.is_err(),
        "the server must not answer a handshake it cannot authenticate"
    );

    client.expect_closed().await?;
    expect_no_event(&mut events, Duration::from_millis(200)).await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_client_that_never_completes_the_handshake_is_not_reported() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;

    // `client/init`, then the socket goes away without message 2.
    let init = init_text(
        &client.identity.public_base64(),
        PROTOCOL_VERSION,
        Suite::ChaChaPoly.wire_name(),
    );
    client.send_text(&init).await?;
    client.read_text().await?;
    drop(client);

    expect_no_event(&mut events, Duration::from_millis(200)).await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_refused_init_is_answered_with_server_error_and_the_matching_reason() -> Result<()> {
    let cases = [
        (
            "an unknown version",
            init_text("a-client", 2, Suite::ChaChaPoly.wire_name()),
            "unsupported_version",
        ),
        (
            "an unknown suite",
            init_text("a-client", PROTOCOL_VERSION, "25519_Unobtainium_SHA256"),
            "unsupported_suite",
        ),
        (
            "an envelope this revision does not have",
            r#"{"type":"server/init","payload":{}}"#.to_owned(),
            "malformed",
        ),
        ("not JSON at all", "not json at all".to_owned(), "malformed"),
    ];

    for (case, init, reason) in cases {
        let (server, port, _events) = start().await?;
        let mut client = FakeClient::connect(port).await?;
        client.send_text(&init).await?;

        match Incoming::parse(&client.read_text().await?)? {
            Some(Incoming::ServerError(ServerError { reason: announced })) => {
                assert_eq!(announced, reason, "{case}")
            }
            other => bail!("{case}: expected server/error, got {other:?}"),
        }
        client.expect_closed().await?;
        server.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_cleartext_message_after_the_handshake_closes_the_connection() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;

    // `client/hello` must travel under the transport keys.
    let hello = serde_json::to_string(&client_hello())?;
    client.send_text(&hello).await?;

    client.expect_closed().await?;
    expect_no_event(&mut events, Duration::from_millis(200)).await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_second_client_init_closes_the_connection() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    let init = init_text(
        &client.identity.public_base64(),
        PROTOCOL_VERSION,
        Suite::ChaChaPoly.wire_name(),
    );
    let init = Incoming::parse(&init)?.expect("client/init is a known message");
    client.send_json(&init).await?;

    client.expect_closed().await?;
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientConnected {
            client_id: client.identity.public_base64(),
            name: CLIENT_NAME.to_owned(),
            approved: false,
        }
    );
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "protocol error".to_owned(),
        }
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_closed_socket_is_reported_as_a_leave() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    client.close().await?;

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "connection closed".to_owned(),
        }
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn shutdown_closes_the_connection_and_ends_the_event_stream() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));

    server.shutdown().await?;

    client.expect_closed().await?;
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "server shutdown".to_owned(),
        }
    );
    assert!(
        tokio::time::timeout(TIMEOUT, events.next())
            .await?
            .is_none(),
        "the stream ends once the server is gone"
    );
    Ok(())
}

#[tokio::test]
async fn only_the_configured_path_is_served() -> Result<()> {
    let (server, port, _events) = start().await?;

    let result = tokio::time::timeout(
        TIMEOUT,
        connect_async(format!("ws://127.0.0.1:{port}/elsewhere")),
    )
    .await?;
    match result {
        Ok(_) => bail!("another path must not be served"),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 404);
        }
        Err(error) => bail!("expected an HTTP refusal, got {error:?}"),
    }

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_message_for_another_role_or_of_an_unknown_type_is_ignored() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    // A command for a role the server does not serve yet, and a type this revision does not have:
    // both leave the connection open, which the goodbye proves.
    client
        .send_json(&Incoming::ClientCommand(ClientCommand::default()))
        .await?;
    client
        .send_raw_json(r#"{"type":"colour/update","payload":{"hue":1}}"#)
        .await?;
    client.goodbye("shutdown").await?;

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "shutdown".to_owned(),
        }
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_player_receives_the_stream_with_playout_timestamps() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    let activate = client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    assert!(
        activate
            .active_roles
            .unwrap_or_default()
            .contains(&"player@v1".to_owned()),
        "a client that plays the configured format is a player"
    );

    let mut writer = server.open_stream(TrackInfo {
        title: Some("A title".to_owned()),
        duration: Some(Duration::from_secs(200)),
        ..TrackInfo::default()
    });
    let start = client.read_stream_start().await?;
    let player = start
        .player
        .expect("an active player stream carries its format");
    assert_eq!(player.codec, "pcm");
    assert_eq!(player.sample_rate, 48_000);
    assert_eq!(player.channels, 2);
    assert_eq!(player.bit_depth, 16);
    assert_eq!(player.codec_header, None);
    assert!(start.server_transmitted > 0);

    // 480 stereo frames of 16-bit PCM are 10 ms at 48 kHz.
    let chunk = [7u8; 480 * 4];
    writer.write(&chunk);
    writer.write(&chunk);

    let (first, payload) = client.read_audio().await?;
    assert_eq!(payload, chunk, "the server forwards the bytes unchanged");
    let (second, _) = client.read_audio().await?;
    assert_eq!(
        second.timestamp_us - first.timestamp_us,
        10_000,
        "the timeline advances by the playtime of the chunk"
    );
    assert!(
        first.send_ahead > 0,
        "the first chunk is transmitted before it is due"
    );

    writer.seek(Duration::from_secs(30));
    let clear = client
        .read_until(|message| match message {
            Incoming::StreamClear(clear) => Some(clear),
            _ => None,
        })
        .await?;
    assert_eq!(clear.roles, Some(vec!["player".to_owned()]));
    assert_eq!(clear.from_timestamp, None, "a seek drops every buffer");
    assert!(clear.server_transmitted >= start.server_transmitted);

    writer.end();
    let end: StreamEnd = client
        .read_until(|message| match message {
            Incoming::StreamEnd(end) => Some(end),
            _ => None,
        })
        .await?;
    assert_eq!(end.roles, Some(vec!["player".to_owned()]));

    assert_eq!(
        next_event(&mut events).await,
        Event::ClientConnected {
            client_id: client.identity.public_base64(),
            name: CLIENT_NAME.to_owned(),
            approved: false,
        }
    );
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(next_event(&mut events).await, Event::StreamStarted);
    assert_eq!(
        next_event(&mut events).await,
        Event::StreamEnded,
        "the host learns that the stream it opened has ended"
    );

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_client_without_the_stream_format_gets_no_player_role_and_no_stream() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    let hello = client_hello_with_formats(vec![SupportedFormat {
        codec: "opus".to_owned(),
        channels: 2,
        sample_rate: 48_000,
        bit_depth: 16,
    }]);
    let activate = client.activate_with(hello).await?;
    assert!(
        activate.active_roles.unwrap_or_default().is_empty(),
        "the first activation of an unapproved client carries no roles"
    );
    server.approve(&client.identity.public_base64()).await?;
    let activate = client
        .read_activate(|activities| activities.is_empty())
        .await?;
    assert_eq!(
        activate.active_roles.unwrap_or_default(),
        ["controller@v1", "metadata@v1"],
        "a client that cannot play the format keeps the roles that do not stream"
    );

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientActivated {
            client_id: client.identity.public_base64(),
            roles: Vec::new(),
        }
    );
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientActivated {
            client_id: client.identity.public_base64(),
            roles: vec!["controller@v1".to_owned(), "metadata@v1".to_owned()],
        }
    );
    match next_event(&mut events).await {
        Event::PlayerRoleWithheld { client_id, reason } => {
            assert_eq!(client_id, client.identity.public_base64());
            assert!(
                reason.contains("pcm, 48000 Hz, 2 channel(s), 16 bit"),
                "the reason names the format the server streams: {reason}"
            );
        }
        other => bail!("expected the player role to be reported as withheld, got {other:?}"),
    }

    let mut writer = server.open_stream(TrackInfo::default());
    writer.write(&[0u8; 480 * 4]);
    client.expect_no_stream(Duration::from_millis(300)).await?;
    writer.end();

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn server_state_carries_the_group_and_the_track() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    let state = client.read_state().await?;
    let controller = state
        .controller
        .expect("the controller role is active, so its state is present");
    assert_eq!(controller.volume, Some(100));
    assert_eq!(controller.muted, Some(false));
    assert_eq!(
        controller.supported_commands,
        ["play", "pause", "stop", "volume", "mute"]
    );
    let metadata = state
        .metadata
        .expect("the metadata role is active, so its state is present");
    assert!(
        metadata.timestamp.is_some(),
        "the first state of a role is dated, so a client is up to date"
    );
    assert_eq!(metadata.title, None, "no stream has started yet");

    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "stopped");
    assert_eq!(group.group_name, SERVER_NAME);
    assert_eq!(
        group.group_id.len(),
        43,
        "the group identifier is 32 bytes as unpadded base64url"
    );

    server.play();
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "playing");

    server.open_stream(TrackInfo {
        title: Some("A title".to_owned()),
        artist: Some("An artist".to_owned()),
        album: Some("An album".to_owned()),
        duration: Some(Duration::from_secs(200)),
        ..TrackInfo::default()
    });
    let state = client.read_state().await?;
    let metadata = state.metadata.expect("the metadata role is active");
    assert_eq!(metadata.title.as_deref(), Some("A title"));
    assert_eq!(metadata.artist.as_deref(), Some("An artist"));
    assert_eq!(metadata.album.as_deref(), Some("An album"));
    let progress = metadata
        .progress
        .expect("a running stream reports progress");
    assert_eq!(progress.track_duration, Some(200_000));
    assert_eq!(progress.playback_speed, Some(1000));
    assert_eq!(progress.track_progress, Some(0));

    server.pause();
    assert!(
        matches!(next_event(&mut events).await, Event::ClientConnected { .. }),
        "the connection events still lead the stream events"
    );
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(next_event(&mut events).await, Event::StreamStarted);
    assert_eq!(
        next_event(&mut events).await,
        Event::StreamEnded,
        "a paused group ends its player stream"
    );
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "stopped");

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn set_volume_reaches_the_client_and_a_controller_command_does_too() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    assert_eq!(
        client.read_state().await?.controller.unwrap().volume,
        Some(100)
    );

    assert_eq!(server.set_volume(40), 40);
    let controller = client.read_state().await?.controller.unwrap();
    assert_eq!(controller.volume, Some(40));
    assert_eq!(
        controller.muted,
        Some(false),
        "a volume change never touches the mute state"
    );

    assert_eq!(
        server.set_volume(200),
        100,
        "a level above the range is clamped, not rejected"
    );
    assert_eq!(
        client.read_state().await?.controller.unwrap().volume,
        Some(100)
    );

    client
        .send_json(&Incoming::ClientCommand(ClientCommand {
            controller: Some(ControllerCommand {
                command: "volume".to_owned(),
                volume: Some(25),
                ..ControllerCommand::default()
            }),
        }))
        .await?;
    assert_eq!(
        client.read_state().await?.controller.unwrap().volume,
        Some(25),
        "the group applies a controller command it advertised"
    );

    client.goodbye("shutdown").await?;
    Ok(())
}

#[tokio::test]
async fn a_client_that_never_answers_does_not_stall_the_writer() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    let mut writer = server.open_stream(TrackInfo::default());
    // Reading the announcement proves the server processed the state report, so the burst below
    // has somewhere to go; after it the client reads nothing until the end of the test.
    client.read_stream_start().await?;

    // The client's socket is not drained while the host pushes: a write only queues the chunk.
    let chunk = [0u8; 480 * 4];
    let started = Instant::now();
    for _ in 0..100 {
        writer.write(&chunk);
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "100 writes took {:?}, so a silent client held the host up",
        started.elapsed()
    );

    let mut last = i64::MIN;
    for _ in 0..100 {
        let (header, audio) = client.read_audio().await?;
        assert_eq!(audio.len(), chunk.len());
        assert!(
            header.timestamp_us > last,
            "every chunk is later than the one before it"
        );
        last = header.timestamp_us;
    }

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn pausing_ends_the_stream_and_playing_announces_it_again() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    let mut writer = server.open_stream(TrackInfo::default());
    client.read_stream_start().await?;

    server.pause();
    let end: StreamEnd = client
        .read_until(|message| match message {
            Incoming::StreamEnd(end) => Some(end),
            _ => None,
        })
        .await?;
    assert_eq!(
        end.roles,
        Some(vec!["player".to_owned()]),
        "a paused group ends its player stream"
    );
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "stopped");

    server.play();
    client.read_stream_start().await?;
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "playing");

    // Audio written after the resume goes out again.
    writer.write(&[0u8; 480 * 4]);
    client.read_audio().await?;

    server.stop();
    client
        .read_until(|message| match message {
            Incoming::StreamEnd(_) => Some(()),
            _ => None,
        })
        .await?;
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "stopped");

    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn two_players_receive_the_same_frames() -> Result<()> {
    let (server, port, _events) = start().await?;
    // One group, two members, each with its own suite and its own identity.
    let mut first = FakeClient::connect(port).await?;
    first
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    let mut second = FakeClient::connect(port).await?;
    second.connect_and_activate(&server, Suite::AesGcm).await?;

    let mut writer = server.open_stream(TrackInfo::default());
    first.read_stream_start().await?;
    second.read_stream_start().await?;

    let chunk = [5u8; 480 * 4];
    writer.write(&chunk);
    writer.write(&[6u8; 480 * 4]);

    let (first_header, first_payload) = first.read_audio().await?;
    let (second_header, second_payload) = second.read_audio().await?;
    assert_eq!(
        first_header, second_header,
        "one timeline serves the whole group, so the timestamps are identical"
    );
    assert_eq!(first_payload, chunk);
    assert_eq!(
        second_payload, chunk,
        "the bytes reach every member unchanged"
    );

    let (next_first, _) = first.read_audio().await?;
    let (next_second, _) = second.read_audio().await?;
    assert_eq!(next_first, next_second);
    assert_eq!(
        next_first.timestamp_us - first_header.timestamp_us,
        10_000,
        "both members advance by the playtime of the chunk"
    );

    writer.end();
    first.goodbye("shutdown").await?;
    second.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn the_start_lead_ignores_the_reported_timing() -> Result<()> {
    // Pins `docs/spec-deviations.md`, entry 17: the group schedules one fixed lead and does not
    // derive it from `min_buffer_ms` + `output_delay_ms`. When the group starts honouring them,
    // this test is the one to change.
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    client.activate().await?;
    server.approve(&client.identity.public_base64()).await?;
    client.read_activate(|_| true).await?;
    let Incoming::ClientState(mut state) = player_state(true, 100, false) else {
        unreachable!("player_state builds a client/state");
    };
    let player = state.player.as_mut().expect("the player object is present");
    player.min_buffer_ms = 3_000;
    player.output_delay_ms = 500;
    player.required_lead_time_ms = 3_000;
    client.send_json(&Incoming::ClientState(state)).await?;

    let mut writer = server.open_stream(TrackInfo::default());
    client.read_stream_start().await?;
    writer.write(&[0u8; 480 * 4]);
    let (header, _payload) = client.read_audio().await?;
    assert!(
        header.send_ahead <= 200_000,
        "the first chunk is sent at most the fixed 200 ms ahead, not the reported 3500 ms, got {} us",
        header.send_ahead
    );

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_stalled_member_does_not_hold_up_the_other() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut stalled = FakeClient::connect(port).await?;
    stalled
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    let mut moving = FakeClient::connect(port).await?;
    moving
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    let mut writer = server.open_stream(TrackInfo::default());
    stalled.read_stream_start().await?;
    moving.read_stream_start().await?;

    // `stalled` is not polled from here on. The group queues its frames and keeps serving `moving`,
    // because a write only queues the chunk per member and never waits for a reader.
    let chunk = [1u8; 480 * 4];
    let started = Instant::now();
    for _ in 0..50 {
        writer.write(&chunk);
    }
    let mut last = i64::MIN;
    for index in 0..50 {
        let (header, payload) = moving.read_audio().await?;
        assert_eq!(payload, chunk, "chunk {index} of the member that reads");
        assert!(
            header.timestamp_us > last,
            "chunk {index} is later than the one before it"
        );
        last = header.timestamp_us;
    }
    assert!(
        started.elapsed() < TIMEOUT,
        "the member that reads kept receiving while the other did not"
    );

    writer.end();
    moving.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn every_member_gets_its_own_clock_reply() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut first = FakeClient::connect(port).await?;
    first
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    let mut second = FakeClient::connect(port).await?;
    second
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    // Each client measures against the same server clock with its own readings.
    let mut previous = 0;
    for round in 0..3 {
        let sent = 1_000_000 + round * 10_000;
        let reply = first.round_trip_time(sent).await?;
        assert_eq!(
            reply.client_transmitted, sent,
            "the reply echoes the request it answers"
        );
        assert!(reply.server_received > 0, "the server clock has no zero");
        assert!(
            reply.server_transmitted >= reply.server_received,
            "the answer leaves after the request arrived"
        );
        assert!(
            reply.server_received > previous,
            "the second round trip is stamped later than the first"
        );
        previous = reply.server_received;

        let sent = 5_000_000 + round * 10_000;
        let reply = second.round_trip_time(sent).await?;
        assert_eq!(reply.client_transmitted, sent);
        assert!(reply.server_transmitted >= reply.server_received);
    }

    // The clock keeps working while the group streams: a queue of audio ahead of the request does
    // not lose the reply.
    let mut writer = server.open_stream(TrackInfo::default());
    first.read_stream_start().await?;
    second.read_stream_start().await?;
    for _ in 0..20 {
        writer.write(&[0u8; 480 * 4]);
    }
    let reply = first.round_trip_time(7_000_000).await?;
    assert_eq!(reply.client_transmitted, 7_000_000);
    assert!(reply.server_transmitted >= reply.server_received);

    writer.end();
    first.goodbye("shutdown").await?;
    second.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn group_state_applies_to_every_member_and_a_report_is_not_a_command() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut first = FakeClient::connect(port).await?;
    first
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    let mut second = FakeClient::connect(port).await?;
    second
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    assert_eq!(
        first.read_state().await?.controller.unwrap().volume,
        Some(100)
    );
    assert_eq!(
        second.read_state().await?.controller.unwrap().volume,
        Some(100),
        "every member starts from the group's level"
    );

    assert_eq!(server.set_volume(35), 35);
    assert_eq!(
        first.read_state().await?.controller.unwrap().volume,
        Some(35)
    );
    assert_eq!(
        second.read_state().await?.controller.unwrap().volume,
        Some(35),
        "a level set on the handle reaches every member"
    );

    // A controller command from one member is group state and reaches the other.
    first
        .send_json(&Incoming::ClientCommand(ClientCommand {
            controller: Some(ControllerCommand {
                command: "mute".to_owned(),
                mute: Some(true),
                ..ControllerCommand::default()
            }),
        }))
        .await?;
    let controller = second.read_state().await?.controller.unwrap();
    assert_eq!(controller.muted, Some(true));
    assert_eq!(
        controller.volume,
        Some(35),
        "a mute leaves the level of the group untouched"
    );
    assert_eq!(
        first.read_state().await?.controller.unwrap().muted,
        Some(true),
        "the member that sent the command is told what it did as well"
    );

    // A `client/state` is a report about one client's own output, never a command for the group.
    second.send_json(&player_state(true, 10, false)).await?;
    first.expect_no_state(Duration::from_millis(300)).await?;
    assert_eq!(server.set_volume(35), 35);
    assert_eq!(
        second.read_state().await?.controller.unwrap().volume,
        Some(35),
        "the reported level did not become the group's"
    );
    assert_eq!(
        first.read_state().await?.controller.unwrap().muted,
        Some(true),
        "the reported mute state did not unmute the group"
    );

    // Playback state is the group's as well and reaches both members.
    server.play();
    assert_eq!(first.read_group_update().await?.playback_state, "playing");
    assert_eq!(second.read_group_update().await?.playback_state, "playing");

    first.goodbye("shutdown").await?;
    second.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_player_hears_nothing_before_it_reports_its_state() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    // `activate` sends `client/hello` only: this client has not reported its state yet, and it is
    // not approved yet either.
    client.activate().await?;
    server.approve(&client.identity.public_base64()).await?;
    let activate = client
        .read_activate(|activities| activities.is_empty())
        .await?;
    assert!(
        activate
            .active_roles
            .unwrap_or_default()
            .contains(&"player@v1".to_owned()),
        "the role is active; the stream is what waits for the report"
    );

    let mut writer = server.open_stream(TrackInfo::default());
    writer.write(&[0u8; 480 * 4]);
    client.expect_no_stream(Duration::from_millis(300)).await?;

    // The report is what lets the server announce the stream; what was written before it is gone.
    client.send_json(&player_state(true, 100, false)).await?;
    let start = client.read_stream_start().await?;
    assert_eq!(
        start
            .player
            .expect("the announcement carries the format")
            .codec,
        "pcm"
    );
    writer.write(&[1u8; 480 * 4]);
    let (_, payload) = client.read_audio().await?;
    assert_eq!(payload, [1u8; 480 * 4]);

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_member_that_reports_itself_unavailable_receives_no_audio() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut away = FakeClient::connect(port).await?;
    away.connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    let mut here = FakeClient::connect(port).await?;
    here.connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    let mut writer = server.open_stream(TrackInfo::default());
    away.read_stream_start().await?;
    here.read_stream_start().await?;

    away.send_json(&player_state(false, 100, false)).await?;
    // A time request travels the same connection and is read after the report, so its reply proves
    // the group has seen the report before the chunk below is written.
    assert_eq!(away.round_trip_time(1_000).await?.client_transmitted, 1_000);
    writer.write(&[2u8; 480 * 4]);
    let (_, payload) = here.read_audio().await?;
    assert_eq!(payload, [2u8; 480 * 4]);
    away.expect_no_audio(Duration::from_millis(300)).await?;

    // A member that comes back hears the running stream again, without a new announcement.
    away.send_json(&player_state(true, 100, false)).await?;
    assert_eq!(away.round_trip_time(2_000).await?.client_transmitted, 2_000);
    writer.write(&[3u8; 480 * 4]);
    let (_, payload) = away.read_audio().await?;
    assert_eq!(payload, [3u8; 480 * 4]);

    writer.end();
    away.goodbye("shutdown").await?;
    here.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_playing_group_declares_the_playback_activity() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    let activate = client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    assert!(
        activate.activities.is_empty(),
        "a server that has not started playing declares no activity"
    );

    let mut writer = server.open_stream(TrackInfo::default());
    let playback = client
        .read_activate(|activities| activities.iter().any(|held| held == "playback"))
        .await?;
    assert_eq!(playback.activities, ["playback"]);
    assert_eq!(
        playback.active_roles, None,
        "the roles of the initial activation stay in force"
    );

    // Dropping the activity needs the stream to end first, and it does.
    server.pause();
    let mut ended = false;
    loop {
        match client.next_received().await? {
            Received::Json(message) => match *message {
                Incoming::StreamEnd(_) => ended = true,
                Incoming::ServerActivate(activate) if activate.activities.is_empty() => {
                    assert!(
                        ended,
                        "`stream/end` precedes the activation that drops `playback`"
                    );
                    break;
                }
                _ => continue,
            },
            Received::Audio(..) => continue,
        }
    }

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_cleartext_frame_after_the_transport_is_a_protocol_error() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    // Once the Noise transport is up, a cleartext text frame has no place on the wire.
    client.send_text("left the transport").await?;
    client.expect_closed().await?;

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "protocol error".to_owned(),
        },
        "a peer that drops to cleartext is cut off, not silently ignored"
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_frame_that_does_not_decrypt_is_a_protocol_error() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    // Bytes that do not authenticate under the transport keys are refused, not ignored.
    client.socket.send(Message::binary(vec![0xff; 16])).await?;
    client.expect_closed().await?;

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "protocol error".to_owned(),
        },
        "traffic that does not decrypt is a protocol error, not a message"
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_binary_message_of_an_unknown_id_is_ignored() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    // A binary message id this revision does not serve carries nothing to act on.
    let plaintext = encode_binary(0x77, b"a role this server does not serve");
    let ciphertext = client
        .noise
        .as_mut()
        .expect("the handshake finished")
        .encrypt(&plaintext)?;
    client.socket.send(Message::binary(ciphertext)).await?;

    client.goodbye("shutdown").await?;
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "shutdown".to_owned(),
        },
        "an unknown binary message must not end the connection"
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_message_of_the_wrong_direction_is_ignored() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    // A server-to-client message type sent by the client is not something the server answers.
    client
        .send_json(&Incoming::ServerState(ServerState::default()))
        .await?;
    client.goodbye("shutdown").await?;

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientActivated { .. }
    ));
    assert_eq!(
        next_event(&mut events).await,
        Event::ClientLeft {
            reason: "shutdown".to_owned(),
        },
        "a message in the wrong direction is ignored, not a protocol error"
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_controller_command_pauses_plays_and_stops_the_group() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    let mut writer = server.open_stream(TrackInfo::default());
    client.read_stream_start().await?;

    let command = |name: &str| {
        Incoming::ClientCommand(ClientCommand {
            controller: Some(ControllerCommand {
                command: name.to_owned(),
                ..ControllerCommand::default()
            }),
        })
    };

    client.send_json(&command("pause")).await?;
    client
        .read_until(|message| match message {
            Incoming::StreamEnd(_) => Some(()),
            _ => None,
        })
        .await?;
    assert_eq!(
        client.read_group_update().await?.playback_state,
        "stopped",
        "a controller's pause ends the stream and stops the group"
    );

    client.send_json(&command("play")).await?;
    client.read_stream_start().await?;
    assert_eq!(
        client.read_group_update().await?.playback_state,
        "playing",
        "a controller's play resumes the group"
    );

    client.send_json(&command("stop")).await?;
    client
        .read_until(|message| match message {
            Incoming::StreamEnd(_) => Some(()),
            _ => None,
        })
        .await?;
    assert_eq!(
        client.read_group_update().await?.playback_state,
        "stopped",
        "a controller's stop ends the stream"
    );

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn opening_a_second_track_is_a_jump_not_an_in_place_change() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    let mut writer = server.open_stream(TrackInfo::default());
    client.read_stream_start().await?;

    // A second stream while the first is active clears the players' buffers and re-announces the
    // format, instead of changing the running stream in place.
    let mut second = server.open_stream(TrackInfo {
        title: Some("A second track".to_owned()),
        ..TrackInfo::default()
    });
    let clear = client
        .read_until(|message| match message {
            Incoming::StreamClear(clear) => Some(clear),
            _ => None,
        })
        .await?;
    assert_eq!(
        clear.roles,
        Some(vec!["player".to_owned()]),
        "a track jump clears the player stream"
    );
    let start = client.read_stream_start().await?;
    assert_eq!(
        start
            .player
            .expect("the new stream carries its format")
            .codec,
        "pcm",
        "the new track announces its format again"
    );

    second.end();
    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}
