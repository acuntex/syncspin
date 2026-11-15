//! Controls, the volume limit and the player state the client reports.
//!
//! Every test binds one loopback port and runs the hermetic fake server from `fake_server.rs`; no
//! audio device and no other host is involved.

#[path = "fake_server.rs"]
mod fake_server;

use std::time::{Duration, Instant};

use anyhow::Result;
use syncspin_client::{
    clamp_volume, clamp_volume_with, connect, AudioFormat, AudioFrame, AudioMode, ClientConfig,
    ClientHandle, ControlHandle, Event, EventStream, Identity, Sink, VolumePolicy,
    DEFAULT_PAIRING_TIMEOUT,
};
use syncspin_core::messages::{
    ClientState, ControllerCommand, ControllerState, Incoming, PlayerCommand, ServerCommand,
    ServerState,
};

use fake_server::{FakeServer, ServerOptions};

/// A sink that accepts every frame and records nothing; these tests never play audio.
struct NullSink;

impl Sink for NullSink {
    fn open(&mut self, _format: AudioFormat) -> Result<()> {
        Ok(())
    }

    fn write(&mut self, _frame: AudioFrame<'_>, _due: Instant) -> Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Builds a configuration for the fake server.
fn config_for(server: &FakeServer) -> ClientConfig {
    ClientConfig {
        server: server.endpoint(),
        player_name: "Test player".to_owned(),
        device_info: None,
        identity: Identity::generate(),
        storage: None,
        audio_mode: AudioMode::Passthrough,
        volume: 100,
        muted: false,
        volume_policy: VolumePolicy::default(),
        max_backoff: Duration::from_secs(30),
        pairing_timeout: DEFAULT_PAIRING_TIMEOUT,
        #[cfg(feature = "pairing-code")]
        static_pairing_code: None,
        #[cfg(feature = "pairing-code")]
        pairing_window: syncspin_client::DEFAULT_PAIRING_WINDOW,
        #[cfg(feature = "pairing-code")]
        pairing_pending_text: None,
        #[cfg(feature = "pairing-code")]
        code_formats: Vec::new(),
        #[cfg(feature = "pairing-code")]
        code_out_channels: Vec::new(),
    }
}

/// Connects to `server` with a fresh identity.
async fn connect_to(server: &FakeServer) -> (ClientHandle, EventStream) {
    connect(config_for(server), Box::new(NullSink))
        .await
        .expect("the client must connect to the fake server")
}

/// Waits for one event, failing instead of hanging.
async fn next_event(stream: &mut EventStream) -> Event {
    match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
        Ok(Some(event)) => event,
        Ok(None) => panic!("the event stream ended"),
        Err(_) => panic!("timed out waiting for an event"),
    }
}

/// Asserts that the next event is a successful encrypted connection.
async fn expect_connected(stream: &mut EventStream, server: &FakeServer) {
    match next_event(stream).await {
        Event::Connected {
            server_id,
            encrypted,
        } => {
            assert!(encrypted, "the connection must be reported as encrypted");
            assert_eq!(server_id, server.server_id());
        }
        other => panic!("expected Connected, got {other:?}"),
    }
}

/// Waits for the next `client/state` the fake server receives.
async fn next_client_state(server: &mut FakeServer) -> ClientState {
    tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_state())
        .await
        .expect("the client must report its state")
        .expect("the connection must not close before the state report")
}

/// Returns the player object of a state report.
fn player(state: ClientState) -> syncspin_core::messages::PlayerState {
    state
        .player
        .expect("an active player reports a player object")
}

/// Asserts that no further `client/state` arrives within a short window.
async fn assert_no_further_state(server: &mut FakeServer) {
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server.wait_for_client_state())
            .await
            .is_err(),
        "the request must produce exactly one state report"
    );
}

/// Builds the `server/command` that requests a player volume.
fn volume_command(level: u8) -> String {
    serde_json::to_string(&Incoming::ServerCommand(ServerCommand {
        player: Some(PlayerCommand {
            command: "volume".to_owned(),
            volume: Some(level),
            mute: None,
            output_delay_ms: None,
        }),
    }))
    .expect("the command must encode")
}

/// Builds the `server/command` that requests a player mute state.
fn mute_command(muted: bool) -> String {
    serde_json::to_string(&Incoming::ServerCommand(ServerCommand {
        player: Some(PlayerCommand {
            command: "mute".to_owned(),
            volume: None,
            mute: Some(muted),
            output_delay_ms: None,
        }),
    }))
    .expect("the command must encode")
}

/// Builds the `server/state` that advertises the controller commands the server accepts.
fn controller_state(commands: &[&str]) -> String {
    serde_json::to_string(&Incoming::ServerState(ServerState {
        metadata: None,
        controller: Some(ControllerState {
            supported_commands: commands
                .iter()
                .map(|command| (*command).to_owned())
                .collect(),
            volume: Some(100),
            muted: Some(false),
            repeat: None,
            shuffle: None,
        }),
    }))
    .expect("the state must encode")
}

/// Waits for the next client command and returns its controller object.
async fn next_controller_command(server: &mut FakeServer) -> ControllerCommand {
    let command = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_command())
        .await
        .expect("the client must send a command")
        .expect("the connection must not close before the command");
    command
        .controller
        .expect("a controller command carries a controller object")
}

#[test]
fn the_control_handle_is_clone_and_send() {
    fn assert_send_clone<T: Send + Clone>() {}
    assert_send_clone::<ControlHandle>();
}

#[test]
fn a_level_at_or_below_forty_is_applied_as_requested() {
    assert_eq!(
        clamp_volume(10, 40),
        40,
        "a raise to 40 is allowed from any level"
    );
    assert_eq!(clamp_volume(0, 31), 31);
    assert_eq!(
        clamp_volume(100, 20),
        20,
        "a lower request is applied as asked"
    );
    assert_eq!(clamp_volume(40, 10), 10);
}

#[test]
fn above_forty_a_single_request_raises_by_at_most_twenty() {
    assert_eq!(clamp_volume(40, 100), 60);
    assert_eq!(clamp_volume(50, 80), 70);
    assert_eq!(clamp_volume(100, 100), 100);
    assert_eq!(clamp_volume(0, 41), 20);
}

#[test]
fn a_level_outside_the_protocol_range_is_capped() {
    assert_eq!(clamp_volume(100, 101), 100);
    assert_eq!(clamp_volume(100, 150), 100);
    assert_eq!(clamp_volume(255, 255), 100);
    assert_eq!(
        clamp_volume(255, 10),
        10,
        "an impossible current level still allows a request within the range"
    );
}

#[test]
fn the_threshold_floor_policy_reaches_the_threshold() {
    let policy = VolumePolicy {
        threshold: 40,
        max_step: 20,
        threshold_floor: true,
    };

    assert_eq!(
        clamp_volume_with(policy, 0, 100),
        40,
        "a low level may jump to the threshold in one request"
    );
    assert_eq!(clamp_volume_with(policy, 1, 100), 40);
    assert_eq!(clamp_volume_with(policy, 10, 100), 40);
    assert_eq!(
        clamp_volume_with(policy, 40, 100),
        60,
        "above the threshold the step rule still applies"
    );
    assert_eq!(
        clamp_volume_with(policy, 100, 90),
        90,
        "a lower request is still applied as asked"
    );
    assert_eq!(clamp_volume_with(policy, 100, 41), 41);
}

#[test]
fn the_default_policy_still_steps_by_twenty() {
    let policy = VolumePolicy::default();
    assert_eq!(policy.threshold, 40);
    assert_eq!(policy.max_step, 20);
    assert!(!policy.threshold_floor);
    assert_eq!(
        clamp_volume_with(policy, 1, 100),
        21,
        "the default policy does not lift a low level to the threshold"
    );

    for (current, requested) in [
        (0, 41),
        (10, 100),
        (40, 100),
        (50, 80),
        (100, 90),
        (255, 255),
    ] {
        assert_eq!(
            clamp_volume_with(policy, current, requested),
            clamp_volume(current, requested),
            "the default policy must stay the compatibility rule for ({current}, {requested})"
        );
    }
}

#[tokio::test]
async fn the_client_announces_the_controller_role() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;

    let hello = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_hello())
        .await
        .expect("the client must announce itself")
        .expect("the connection must not close before client/hello");
    assert!(
        hello
            .supported_roles
            .iter()
            .any(|role| role == "controller@v1"),
        "transport commands need the controller role: {:?}",
        hello.supported_roles
    );
}

#[tokio::test]
async fn control_commands_reach_the_server() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    control
        .play()
        .await
        .expect("the command must reach the server");
    assert_eq!(
        next_controller_command(&mut server).await,
        ControllerCommand {
            command: "play".to_owned(),
            ..ControllerCommand::default()
        },
        "a transport command carries only its name"
    );

    control
        .pause()
        .await
        .expect("the command must reach the server");
    assert_eq!(next_controller_command(&mut server).await.command, "pause");

    control
        .next()
        .await
        .expect("the command must reach the server");
    assert_eq!(next_controller_command(&mut server).await.command, "next");

    control
        .previous()
        .await
        .expect("the command must reach the server");
    assert_eq!(
        next_controller_command(&mut server).await.command,
        "previous"
    );
}

#[tokio::test]
async fn a_volume_request_above_the_clamp_reports_the_applied_value() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    // The initial report settles the first observation, so the two requests below produce the
    // only further reports the assertions see.
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(100)
    );

    assert_eq!(
        control
            .set_volume(40)
            .await
            .expect("the level must be applied"),
        40,
        "the call returns the level that was applied"
    );
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(40)
    );

    assert_eq!(
        control
            .set_volume(100)
            .await
            .expect("the request must be applied"),
        60,
        "the call returns the limited level"
    );
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(60),
        "a request above 40 raises the level by at most 20"
    );
    assert_no_further_state(&mut server).await;
}

#[tokio::test]
async fn report_volume_bypasses_the_policy() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let mut config = config_for(&server);
    // The policy would limit a request for 70 from 20 to 40, so a report that reaches 70 proves
    // the policy was not consulted.
    config.volume = 20;
    config.volume_policy = VolumePolicy {
        threshold: 40,
        max_step: 20,
        threshold_floor: false,
    };
    let (handle, mut events) = connect(config, Box::new(NullSink))
        .await
        .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(20)
    );

    control
        .report_volume(70)
        .await
        .expect("the reported level must be accepted");
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(70),
        "the reported level goes out unchanged, above the policy threshold"
    );
    assert_eq!(
        control.volume(),
        70,
        "the handle follows the reported level"
    );
    assert_no_further_state(&mut server).await;
}

#[tokio::test]
async fn report_volume_rejects_over_one_hundred() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(100)
    );

    let error = control
        .report_volume(101)
        .await
        .expect_err("a level above the protocol range must be refused");
    assert!(
        format!("{error:#}").contains("101"),
        "the error names the refused value: {error:#}"
    );
    assert_eq!(control.volume(), 100, "a refused report changes nothing");
    assert_no_further_state(&mut server).await;

    // The refusal belongs to the call, not to the session: a level inside the range still works.
    control
        .report_volume(99)
        .await
        .expect("a level inside the range must be accepted");
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(99)
    );
}

#[tokio::test]
async fn a_volume_request_at_or_below_forty_is_applied_as_requested() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(100)
    );

    control
        .set_volume(40)
        .await
        .expect("the level must be applied");
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(40)
    );

    control
        .set_volume(10)
        .await
        .expect("the level must be applied");
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(10),
        "a request to 40 or below is never limited"
    );
    assert_no_further_state(&mut server).await;
}

#[tokio::test]
async fn a_lower_volume_request_is_never_clamped() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(100)
    );

    control
        .set_volume(100)
        .await
        .expect("the level must be applied");
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(100)
    );

    control
        .set_volume(90)
        .await
        .expect("the level must be applied");
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(90),
        "the limit bounds raises, not lowers"
    );
    assert_no_further_state(&mut server).await;
}

#[tokio::test]
async fn supported_commands_are_advertised_in_the_initial_state() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;

    let state = player(next_client_state(&mut server).await);
    assert_eq!(
        state.supported_commands,
        vec!["volume".to_owned(), "mute".to_owned()],
        "a server only sends the commands the player advertises"
    );
    assert_eq!(
        state.volume,
        Some(100),
        "advertising volume requires a level in the same report"
    );
    assert_eq!(
        state.muted,
        Some(false),
        "advertising mute requires a mute state in the same report"
    );
}

#[tokio::test]
async fn the_configured_level_and_mute_are_reported_in_the_initial_state() {
    // A host that restored a level passes it in the configuration; the first report must carry it
    // instead of an invented baseline.
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let mut config = config_for(&server);
    config.volume = 30;
    config.muted = true;
    let (handle, mut events) = connect(config, Box::new(NullSink))
        .await
        .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    assert_eq!(handle.control().volume(), 30);
    let state = player(next_client_state(&mut server).await);
    assert_eq!(state.volume, Some(30));
    assert_eq!(state.muted, Some(true));
}

#[tokio::test]
async fn mute_is_reported_without_changing_the_level() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(100)
    );

    control
        .set_volume(30)
        .await
        .expect("the level must be applied");
    let state = player(next_client_state(&mut server).await);
    assert_eq!(state.volume, Some(30));
    assert_eq!(state.muted, Some(false));

    control
        .set_muted(true)
        .await
        .expect("the mute must be applied");
    let state = player(next_client_state(&mut server).await);
    assert_eq!(
        state.volume,
        Some(30),
        "a mute must not report the level as zero"
    );
    assert_eq!(state.muted, Some(true));

    // The server path carries the same rule: the event names the mute and never a level, and the
    // following report keeps the level in force.
    server.json(mute_command(false));
    assert_eq!(
        next_event(&mut events).await,
        Event::Volume {
            requested: 30,
            applied: 30,
            muted: Some(false),
        }
    );
    let state = player(next_client_state(&mut server).await);
    assert_eq!(state.volume, Some(30));
    assert_eq!(state.muted, Some(false));
}

#[tokio::test]
async fn a_level_reported_before_the_first_state_reaches_the_server() {
    // One answered clock request is enough for the initial report; the level set before it must be
    // the level that report carries.
    let options = ServerOptions {
        answer_time_limit: Some(1),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    let control = handle.control();
    control
        .set_volume(40)
        .await
        .expect("the level must be applied");
    expect_connected(&mut events, &server).await;

    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(40),
        "a change made before the first report belongs to that report"
    );
}

#[tokio::test]
async fn a_host_mute_before_the_initial_report_is_carried_by_it() {
    let options = ServerOptions {
        answer_time_limit: Some(1),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    let control = handle.control();
    control
        .set_muted(true)
        .await
        .expect("the mute must be applied");
    expect_connected(&mut events, &server).await;

    let state = player(next_client_state(&mut server).await);
    assert_eq!(
        state.muted,
        Some(true),
        "a change made before the first report belongs to that report"
    );
    assert_eq!(
        state.volume,
        Some(100),
        "a mute must not change the level it reports"
    );
}

#[tokio::test]
async fn a_command_for_an_inactive_role_is_refused() {
    let options = ServerOptions {
        active_roles: vec!["metadata@v1".to_owned()],
        ..ServerOptions::default()
    };
    let server = FakeServer::start(options).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    assert!(
        control.play().await.is_err(),
        "a transport command needs the controller role"
    );
    assert!(
        control.set_volume(50).await.is_err(),
        "a volume needs the player role"
    );
    assert!(
        control.set_muted(true).await.is_err(),
        "a mute needs the player role"
    );
}

#[tokio::test]
async fn a_server_volume_command_reports_the_limited_value() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(100)
    );
    control
        .set_volume(40)
        .await
        .expect("the level must be applied");
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(40)
    );

    server.json(volume_command(100));
    assert_eq!(
        next_event(&mut events).await,
        Event::Volume {
            requested: 100,
            applied: 60,
            muted: None,
        },
        "the event carries the level that was applied, not the one requested"
    );
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(60),
        "the server sees the level that was applied"
    );
    assert_no_further_state(&mut server).await;
}

#[tokio::test]
async fn volume_events_carry_both_requested_and_applied() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(100)
    );
    control
        .set_volume(40)
        .await
        .expect("the level must be applied");
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(40)
    );

    server.json(volume_command(100));
    assert_eq!(
        next_event(&mut events).await,
        Event::Volume {
            requested: 100,
            applied: 60,
            muted: None,
        },
        "the event must name what the server asked for and what the policy allowed"
    );
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(60),
        "the state report keeps carrying the applied value only"
    );
}

#[tokio::test]
async fn the_configured_policy_applies_to_a_server_command() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let mut config = config_for(&server);
    config.volume = 1;
    config.volume_policy = VolumePolicy {
        threshold: 40,
        max_step: 20,
        threshold_floor: true,
    };
    let (_handle, mut events) = connect(config, Box::new(NullSink))
        .await
        .expect("the client must connect to the fake server");
    expect_connected(&mut events, &server).await;

    assert_eq!(player(next_client_state(&mut server).await).volume, Some(1));
    server.json(volume_command(100));
    assert_eq!(
        next_event(&mut events).await,
        Event::Volume {
            requested: 100,
            applied: 40,
            muted: None,
        },
        "the configured threshold floor must reach the session"
    );
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(40),
        "the server sees the value the configured policy applied"
    );
}

#[tokio::test]
async fn a_server_volume_above_the_protocol_range_is_capped() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;

    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(100)
    );

    // The wire field is a u8, so a level of 200 decodes; the protocol only allows 0-100, and the
    // client keeps its own report valid rather than closing the connection.
    server.json(volume_command(200));
    assert_eq!(
        next_event(&mut events).await,
        Event::Volume {
            requested: 200,
            applied: 100,
            muted: None,
        },
        "a level above the protocol range is capped at 100"
    );
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(100),
        "the report stays inside the range the server accepts"
    );
}

#[tokio::test]
async fn a_transport_command_must_be_advertised_by_the_server() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    // Before the server reports its controller state nothing is known, so the command is sent.
    control
        .play()
        .await
        .expect("the window before the first controller state is open");
    assert_eq!(next_controller_command(&mut server).await.command, "play");

    server.json(controller_state(&["play"]));
    assert!(
        matches!(next_event(&mut events).await, Event::State(_)),
        "the controller state must reach the host"
    );

    assert!(
        control.next().await.is_err(),
        "a command the server does not advertise must not be sent"
    );
    control
        .play()
        .await
        .expect("an advertised command still goes out");
    assert_eq!(next_controller_command(&mut server).await.command, "play");
}

#[tokio::test]
async fn set_volume_after_the_session_ended_is_an_error() {
    let server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (handle, mut events) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;
    let control = handle.control();

    server.close();
    loop {
        match next_event(&mut events).await {
            Event::Disconnected { .. } => break,
            _ => continue,
        }
    }

    let error = control
        .set_volume(50)
        .await
        .expect_err("no session can carry the request");
    assert!(
        format!("{error:#}").contains("no connection"),
        "the error should say that no session is established, got: {error:#}"
    );
    assert_eq!(
        control.volume(),
        100,
        "a refused request leaves the level in force alone"
    );
}
