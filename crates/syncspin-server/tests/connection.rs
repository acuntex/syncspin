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
use syncspin_server::{TrackInfo, WriteError, WriteOutcome};
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

/// A client that vanishes right after the handshake may break the first activation. Whichever way
/// the connection ends, the host that saw `ClientConnected` gets exactly one `ClientLeft`.
#[tokio::test]
async fn a_client_that_vanishes_before_activation_still_leaves_once() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    // The hello makes the server announce the connection; the socket goes before the activation
    // is read, so the server's first write may already fail.
    client.send_json(&client_hello()).await?;
    client.close().await?;

    assert!(matches!(
        next_event(&mut events).await,
        Event::ClientConnected { .. }
    ));
    loop {
        match next_event(&mut events).await {
            Event::ClientLeft { .. } => break,
            Event::ClientActivated { .. } => {}
            other => panic!("expected ClientLeft, got {other:?}"),
        }
    }
    server.shutdown().await?;
    assert!(
        events.next().await.is_none(),
        "no second ClientLeft follows the first"
    );
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
    // The time reply travels after the state report on the same connection, so the member is
    // ready before the stream opens and anchors the timeline.
    client.barrier(1).await?;

    let mut writer = server.open_stream(TrackInfo {
        title: Some("A title".to_owned()),
        duration: Some(Duration::from_secs(200)),
        ..TrackInfo::default()
    });
    let start = client.read_stream_start().await?;
    // The reply proves the start's send report, which completes the anchor and clears the gate.
    client.barrier(2).await?;
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
    assert_eq!(writer.write(&chunk), WriteOutcome::Written);
    assert_eq!(writer.write(&chunk), WriteOutcome::Written);

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
    assert_eq!(writer.write(&[0u8; 480 * 4]), WriteOutcome::Written);
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
    // The time reply travels after the state report, so the member is ready before the stream
    // opens and anchors the timeline; the anchor is what gives the burst below a fresh timeline.
    client.barrier(1).await?;
    let mut writer = server.open_stream(TrackInfo::default());
    client.read_stream_start().await?;
    // The reply proves the start's send report, which completes the anchor before the first write.
    client.barrier(2).await?;

    // The client's socket is not drained while the host pushes: a write only queues the chunk.
    let chunk = [0u8; 480 * 4];
    let started = Instant::now();
    for _ in 0..100 {
        assert_eq!(writer.write(&chunk), WriteOutcome::Written);
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
    // The group update is queued after the start; read it before the barrier consumes the stream.
    let group = client
        .read_until(|message| match message {
            Incoming::GroupUpdate(group) => Some(group),
            _ => None,
        })
        .await?;
    assert_eq!(group.playback_state, "playing");
    // The reply proves the restart's send report, which completes its anchor before the write.
    client.barrier(1).await?;

    // Audio written after the resume goes out again.
    assert_eq!(writer.write(&[0u8; 480 * 4]), WriteOutcome::Written);
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
    // Each time reply proves its state report reached the group, so both members are ready before
    // the stream opens and anchor its timeline.
    first.barrier(1).await?;
    let mut second = FakeClient::connect(port).await?;
    second.connect_and_activate(&server, Suite::AesGcm).await?;
    second.barrier(1).await?;

    let mut writer = server.open_stream(TrackInfo::default());
    first.read_stream_start().await?;
    second.read_stream_start().await?;
    // Both sends are reported before the chunks below, so both members are released by the anchor.
    first.barrier(2).await?;
    second.barrier(2).await?;

    let chunk = [5u8; 480 * 4];
    assert_eq!(writer.write(&chunk), WriteOutcome::Written);
    assert_eq!(writer.write(&[6u8; 480 * 4]), WriteOutcome::Written);

    let (first_header, first_payload) = first.read_audio().await?;
    let (second_header, second_payload) = second.read_audio().await?;
    assert_eq!(
        first_header.timestamp_us, second_header.timestamp_us,
        "one timeline serves the whole group, so the timestamps are identical"
    );
    assert_eq!(first_payload, chunk);
    assert_eq!(
        second_payload, chunk,
        "the bytes reach every member unchanged"
    );

    let (next_first, _) = first.read_audio().await?;
    let (next_second, _) = second.read_audio().await?;
    assert_eq!(
        next_first.timestamp_us, next_second.timestamp_us,
        "the shared timeline advances the same way for both members"
    );
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
async fn the_start_lead_follows_the_reported_timing() -> Result<()> {
    // The group derives its lead from `min_buffer_ms` + `output_delay_ms` and anchors it on the
    // trigger's transmit time. A fixed lead could not pass a deliberately non-default report.
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    client.activate().await?;
    server.approve(&client.identity.public_base64()).await?;
    client.read_activate(|_| true).await?;
    client
        .send_json(&player_state_with_timing(true, 100, false, 3_000, 500))
        .await?;
    // The time reply travels after the report on the same connection, so the member is ready
    // before the stream opens and anchors the timeline rather than joining late.
    client.barrier(1).await?;

    let mut writer = server.open_stream(TrackInfo::default());
    let start = client.read_stream_start().await?;
    // The time reply is handled after the start's send report on the same task, so the member's
    // gate is clear before the first write without waiting out the 3.5 s lead.
    client.barrier(2).await?;
    assert_eq!(writer.write(&[0u8; 480 * 4]), WriteOutcome::Written);
    let (header, _payload) = client.read_audio().await?;
    assert!(
        header.timestamp_us >= start.server_transmitted + 3_500_000,
        "the first chunk is scheduled a full reported lead after the start was transmitted, \
         start at {} and chunk at {}",
        start.server_transmitted,
        header.timestamp_us
    );

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn send_ahead_measures_the_transmit_interval_of_a_delayed_chunk() -> Result<()> {
    // `send_ahead` is stamped when the chunk leaves, not when the host wrote it: after a delay
    // inside the lead it is smaller than the lead, and it matches the server clock that the
    // chunk's timestamp is measured against.
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client.handshake(Suite::ChaChaPoly).await?;
    client.activate().await?;
    server.approve(&client.identity.public_base64()).await?;
    client.read_activate(|_| true).await?;
    client
        .send_json(&player_state_with_timing(true, 100, false, 3_000, 500))
        .await?;
    // The time reply travels after the report, so the member is ready before the stream opens.
    client.barrier(1).await?;

    let lead_us = 3_500_000;
    let mut writer = server.open_stream(TrackInfo::default());
    client.read_stream_start().await?;
    // The time reply proves the start's send report has cleared the member's gate, without
    // waiting out the lead the test is about.
    client.barrier(2).await?;
    // Delay the write inside the lead, so the chunk's send time is not the segment's start.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(writer.write(&[0u8; 480 * 4]), WriteOutcome::Written);
    let (header, _payload) = client.read_audio().await?;

    let send_ahead = i64::from(header.send_ahead);
    assert!(
        send_ahead > 0,
        "the delayed chunk is still ahead of its due time"
    );
    assert!(
        send_ahead < lead_us,
        "a chunk sent after the start measures less than the lead, got {send_ahead} us"
    );
    let server_now = client.server_time().await?;
    let from_clock = header.timestamp_us - server_now;
    assert!(
        from_clock <= send_ahead,
        "the reply's clock is later than the chunk's send, so it measures {from_clock} us \
         against the stamped {send_ahead} us"
    );
    assert!(
        send_ahead - from_clock < 100_000,
        "the stamped send_ahead is {} us away from the transmit interval the clock implies",
        send_ahead - from_clock
    );

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_late_joiner_is_gated_on_its_own_start_and_keeps_the_timeline() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut early = FakeClient::connect(port).await?;
    early
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    // The time reply travels after the state report on the same connection, so the early member
    // is ready before the stream opens and anchors the timeline.
    early.barrier(1).await?;

    // The late client holds the player role but has not reported its state yet.
    let mut late = FakeClient::connect(port).await?;
    late.handshake(Suite::ChaChaPoly).await?;
    late.activate().await?;
    server.approve(&late.identity.public_base64()).await?;
    late.read_activate(|_| true).await?;

    let chunk = [4u8; 480 * 4];
    let mut writer = server.open_stream(TrackInfo::default());
    let early_start = early.read_stream_start().await?;
    // The reply proves the start's send report, which completes the anchor before the write.
    early.barrier(2).await?;
    assert_eq!(writer.write(&chunk), WriteOutcome::Written);
    let (opening, _) = early.read_audio().await?;
    assert!(opening.timestamp_us >= early_start.server_transmitted);

    // The late member reports a 300 ms startup lead, so its own floor is well beyond the group's
    // next chunk: the opening it missed is a hole, not a retroactive start.
    late.send_json(&player_state_with_timing(true, 100, false, 300, 0))
        .await?;
    let late_start = late.read_stream_start().await?;
    // The reply proves the late start's report, so its own floor is in force before the write.
    late.barrier(1).await?;

    // The chunk written now is before the late member's floor.
    assert_eq!(
        writer.write(&[5u8; 480 * 4]),
        WriteOutcome::Partial { skipped: 1 }
    );
    let (early_second_header, early_second) = early.read_audio().await?;
    assert_eq!(early_second, [5u8; 480 * 4]);
    late.expect_no_audio(Duration::from_millis(200)).await?;

    // Enough further chunks pass the floor; the member receives the group timeline, not a new one
    // of its own.
    let mut timestamps = vec![opening.timestamp_us, early_second_header.timestamp_us];
    for _ in 0..40 {
        assert_eq!(writer.write(&chunk), WriteOutcome::Written);
        let (header, _) = early.read_audio().await?;
        timestamps.push(header.timestamp_us);
    }
    let (late_first, late_payload) = late.read_audio().await?;
    assert_eq!(late_payload, chunk);
    assert!(
        late_first.timestamp_us >= late_start.server_transmitted + 300_000,
        "the late member's first chunk at {} is before its own start floor {}",
        late_first.timestamp_us,
        late_start.server_transmitted
    );
    assert!(
        timestamps.contains(&late_first.timestamp_us),
        "the late member joins the group timeline: {} is not one of its chunks",
        late_first.timestamp_us
    );
    let (late_second, _) = late.read_audio().await?;
    assert_eq!(
        late_second.timestamp_us - late_first.timestamp_us,
        10_000,
        "the late member keeps the group's spacing"
    );

    writer.end();
    early.goodbye("shutdown").await?;
    late.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_chunk_longer_than_150_ms_is_refused() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    // The time reply travels after the state report, so the member is ready before the stream
    // opens and anchors the timeline.
    client.barrier(1).await?;
    let mut writer = server.open_stream(TrackInfo::default());
    client.read_stream_start().await?;
    // The reply proves the start's send report, which completes the anchor before the writes.
    client.barrier(2).await?;

    // 160 ms of 16-bit stereo PCM at 48 kHz: 48 frames per millisecond.
    let too_long = [0u8; 48 * 160 * 4];
    assert_eq!(
        writer.write(&too_long),
        WriteOutcome::Dropped(WriteError::TooLong),
        "a chunk above the protocol's 150 ms bound must not be started"
    );
    let chunk = [7u8; 480 * 4];
    assert_eq!(writer.write(&chunk), WriteOutcome::Written);
    let (_, payload) = client.read_audio().await?;
    assert_eq!(payload, chunk, "the refused chunk leaves no hole");

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_member_with_no_room_is_skipped_until_its_buffer_drains() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    // One framed chunk is 13 + 480*4 = 1933 bytes, so a 2000-byte capacity holds one at a time.
    client
        .connect_and_activate_with(
            &server,
            Suite::ChaChaPoly,
            client_hello_with_capacity(2_000),
        )
        .await?;
    // The time reply travels after the state report, so the member is ready before the stream
    // opens and anchors the timeline.
    client.barrier(1).await?;
    let mut writer = server.open_stream(TrackInfo::default());
    client.read_stream_start().await?;
    // The reply proves the start's send report, which completes the anchor before the first write.
    client.barrier(2).await?;

    let first = [1u8; 480 * 4];
    assert_eq!(writer.write(&first), WriteOutcome::Written);
    let (_, payload) = client.read_audio().await?;
    assert_eq!(payload, first);

    // The second chunk would push the outstanding framed bytes past the capacity, so the member
    // is skipped instead of overrun.
    assert_eq!(
        writer.write(&[2u8; 480 * 4]),
        WriteOutcome::Partial { skipped: 1 }
    );
    client.expect_no_audio(Duration::from_millis(200)).await?;

    // The first chunk has played out; the next one fits again.
    let third = [3u8; 480 * 4];
    assert_eq!(writer.write(&third), WriteOutcome::Written);
    let (_, payload) = client.read_audio().await?;
    assert_eq!(
        payload, third,
        "the member receives audio once its buffer drains"
    );

    writer.end();
    client.goodbye("shutdown").await?;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn an_out_of_range_role_value_closes_the_connection() -> Result<()> {
    // The typed decode accepts a `u8` volume and a `u32` timing value, so the protocol's narrower
    // range is checked after it. A wrong-typed active object fails the decode itself.
    let timing = player_state_with_timing(true, 100, false, 5_001, 0);
    let delay = player_state_with_timing(true, 100, false, 100, 5_001);
    let loud = player_state_with_timing(true, 101, false, 100, 0);
    let controller = Incoming::ClientCommand(ClientCommand {
        controller: Some(ControllerCommand {
            command: "volume".to_owned(),
            volume: Some(101),
            ..ControllerCommand::default()
        }),
    });
    let wrong_type = r#"{"type":"client/state","payload":{"available":true,"player":
        {"volume":100,"muted":false,"output_delay_ms":0,"required_lead_time_ms":200,
         "min_buffer_ms":"soon"}}}"#;

    for (case, message) in [
        ("a player timing above the range", timing),
        ("a player output delay above the range", delay),
        ("a player volume above the range", loud),
        ("a controller volume above the range", controller),
    ] {
        let (server, port, mut events) = start().await?;
        let mut client = FakeClient::connect(port).await?;
        client
            .connect_and_activate(&server, Suite::ChaChaPoly)
            .await?;
        client.send_json(&message).await?;
        client.expect_closed().await?;
        assert_eq!(
            left_reason(&mut events).await,
            "protocol error",
            "{case} must close the connection as a protocol error"
        );
        server.shutdown().await?;
    }

    // An active object of the wrong type is a decode error, which is the same close.
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    client.send_raw_json(wrong_type).await?;
    client.expect_closed().await?;
    assert_eq!(
        left_reason(&mut events).await,
        "protocol error",
        "a wrong-typed value in an active player object must close the connection"
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn the_inclusive_role_range_edges_stay_open() -> Result<()> {
    // The ranges are bounds, not exclusive limits: 0 and 5000 ms of timing and a volume of 100
    // are valid, and only a value above one closes the connection.
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;

    for message in [
        player_state_with_timing(true, 100, false, 0, 5_000),
        player_state_with_timing(true, 100, false, 5_000, 0),
        Incoming::ClientCommand(ClientCommand {
            controller: Some(ControllerCommand {
                command: "volume".to_owned(),
                volume: Some(100),
                ..ControllerCommand::default()
            }),
        }),
    ] {
        client.send_json(&message).await?;
    }
    client.goodbye("shutdown").await?;
    assert_eq!(
        left_reason(&mut events).await,
        "shutdown",
        "the range bounds themselves stay inside the protocol"
    );
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn an_inactive_role_object_is_ignored_whatever_it_contains() -> Result<()> {
    let (server, port, mut events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    // The server streams PCM and this client plays Opus only, so its player role stays inactive.
    let hello = client_hello_with_formats(vec![SupportedFormat {
        codec: "opus".to_owned(),
        channels: 2,
        sample_rate: 48_000,
        bit_depth: 16,
    }]);
    client
        .connect_and_activate_with(&server, Suite::ChaChaPoly, hello)
        .await?;

    // The player object belongs to a role that is not active; `messaging.md` leaves it
    // unvalidated, so a wrong-typed value must not close the connection.
    client
        .send_raw_json(
            r#"{"type":"client/state","payload":{"available":true,"player":
                {"volume":"loud","min_buffer_ms":"soon"}}}"#,
        )
        .await?;
    client.goodbye("shutdown").await?;
    assert_eq!(
        left_reason(&mut events).await,
        "shutdown",
        "an inactive role object is dropped before the typed decode"
    );
    server.shutdown().await?;
    Ok(())
}

/// Reads events until the connection leaves and returns its reason.
async fn left_reason(events: &mut EventStream) -> String {
    loop {
        if let Event::ClientLeft { reason } = next_event(events).await {
            return reason;
        }
    }
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
    // Each time reply proves its state report reached the group, so both members are ready before
    // the stream opens and anchor its timeline.
    stalled.barrier(1).await?;
    moving.barrier(1).await?;

    let mut writer = server.open_stream(TrackInfo::default());
    stalled.read_stream_start().await?;
    moving.read_stream_start().await?;
    // Both sends are reported before the burst, so the anchor does not gate the member that reads.
    stalled.barrier(2).await?;
    moving.barrier(2).await?;

    // `stalled` is not polled from here on. The group queues its frames and keeps serving `moving`,
    // because a write only queues the chunk per member and never waits for a reader.
    let chunk = [1u8; 480 * 4];
    let started = Instant::now();
    for _ in 0..50 {
        assert_eq!(writer.write(&chunk), WriteOutcome::Written);
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
        assert_eq!(writer.write(&[0u8; 480 * 4]), WriteOutcome::Written);
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
    assert_eq!(writer.write(&[0u8; 480 * 4]), WriteOutcome::Written);
    client.expect_no_stream(Duration::from_millis(300)).await?;

    // The report is what lets the server announce the stream; what was written before it is gone.
    // A zero lead removes the late-joiner floor, so the barrier below is all the wait this row
    // needs before its write.
    client
        .send_json(&player_state_with_timing(true, 100, false, 0, 0))
        .await?;
    let start = client.read_stream_start().await?;
    // The reply proves the start's send report, so its floor and gate are in force before the write.
    client.barrier(1).await?;
    assert_eq!(
        start
            .player
            .expect("the announcement carries the format")
            .codec,
        "pcm"
    );
    assert_eq!(writer.write(&[1u8; 480 * 4]), WriteOutcome::Written);
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
    // Each time reply proves its state report reached the group, so both members anchor the stream.
    away.barrier(1).await?;
    here.barrier(1).await?;

    let mut writer = server.open_stream(TrackInfo::default());
    away.read_stream_start().await?;
    here.read_stream_start().await?;
    // Both sends are reported before the first write, so neither member starts gated.
    away.barrier(2).await?;
    here.barrier(2).await?;

    away.send_json(&player_state(false, 100, false)).await?;
    // A time request travels the same connection and is read after the report, so its reply proves
    // the group has seen the report before the chunk below is written.
    assert_eq!(away.round_trip_time(1_000).await?.client_transmitted, 1_000);
    assert_eq!(writer.write(&[2u8; 480 * 4]), WriteOutcome::Written);
    let (_, payload) = here.read_audio().await?;
    assert_eq!(payload, [2u8; 480 * 4]);
    away.expect_no_audio(Duration::from_millis(300)).await?;

    // A member that comes back hears the running stream again, without a new announcement.
    away.send_json(&player_state(true, 100, false)).await?;
    assert_eq!(away.round_trip_time(2_000).await?.client_transmitted, 2_000);
    assert_eq!(writer.write(&[3u8; 480 * 4]), WriteOutcome::Written);
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
async fn ending_a_track_sends_an_end_and_the_next_start_opens_a_new_stream() -> Result<()> {
    let (server, port, _events) = start().await?;
    let mut client = FakeClient::connect(port).await?;
    client
        .connect_and_activate(&server, Suite::ChaChaPoly)
        .await?;
    let mut first = server.open_stream(TrackInfo::default());
    client.read_stream_start().await?;

    // The host ends the track it played. The group has no queue, so it cannot tell this from a
    // real stop: the players are told the stream ended before the next one starts (deviation 22).
    first.end();
    let mut second = server.open_stream(TrackInfo {
        title: Some("The next track".to_owned()),
        ..TrackInfo::default()
    });

    // The order is the one the host API produces: `stream/end`, then the new `stream/start`. A
    // `stream/clear` between them would be the track-jump path and would fail this row.
    let mut stream_messages = Vec::new();
    while stream_messages.len() < 2 {
        if let Received::Json(message) = client.next_received().await? {
            if matches!(
                message.as_ref(),
                Incoming::StreamEnd(_) | Incoming::StreamStart(_) | Incoming::StreamClear(_)
            ) {
                stream_messages.push(*message);
            }
        }
    }
    match &stream_messages[0] {
        Incoming::StreamEnd(end) => assert_eq!(
            end.roles,
            Some(vec!["player".to_owned()]),
            "the first stream message is the end of the old track"
        ),
        other => panic!("expected stream/end first, got {other:?}"),
    }
    match &stream_messages[1] {
        Incoming::StreamStart(start) => assert_eq!(
            start
                .player
                .as_ref()
                .expect("the new stream carries its format")
                .codec,
            "pcm",
            "the second stream message is the new track's start"
        ),
        other => panic!("expected stream/start second, got {other:?}"),
    }

    second.end();
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
