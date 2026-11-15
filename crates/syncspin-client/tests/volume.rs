//! Controls, the volume limit and the player state the client reports.
//!
//! Every test binds one loopback port and runs the hermetic fake server from `fake_server.rs`; no
//! audio device and no other host is involved.

#[path = "fake_server.rs"]
mod fake_server;

use std::time::{Duration, Instant};

use anyhow::Result;
use syncspin_client::{
    clamp_volume, connect, AudioFormat, AudioFrame, AudioMode, ClientConfig, ClientHandle,
    ControlHandle, Event, EventStream, Identity, Sink,
};
use syncspin_core::messages::{ClientState, Incoming, PlayerCommand, ServerCommand};

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
        identity: Identity::generate(),
        audio_mode: AudioMode::Passthrough,
        max_backoff: Duration::from_secs(30),
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

/// Waits for the next `client/command` and returns its controller object.
async fn next_controller_command(server: &mut FakeServer) -> serde_json::Value {
    let body = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_command())
        .await
        .expect("the client must send a command")
        .expect("the connection must not close before the command");
    let value: serde_json::Value = serde_json::from_str(&body).expect("the command must be JSON");
    assert_eq!(
        value["type"], "client/command",
        "a controller command uses the client command envelope: {body}"
    );
    let controller = value["payload"]["controller"].clone();
    assert_eq!(
        controller.as_object().map(|object| object.len()),
        Some(1),
        "a transport command carries only its name: {body}"
    );
    controller
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
        next_controller_command(&mut server).await["command"],
        "play"
    );

    control
        .pause()
        .await
        .expect("the command must reach the server");
    assert_eq!(
        next_controller_command(&mut server).await["command"],
        "pause"
    );

    control
        .next()
        .await
        .expect("the command must reach the server");
    assert_eq!(
        next_controller_command(&mut server).await["command"],
        "next"
    );

    control
        .previous()
        .await
        .expect("the command must reach the server");
    assert_eq!(
        next_controller_command(&mut server).await["command"],
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

    control
        .set_volume(40)
        .await
        .expect("the level must be applied");
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(40)
    );

    control
        .set_volume(100)
        .await
        .expect("the request must be applied");
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(60),
        "a request above 40 raises the level by at most 20"
    );
    assert_no_further_state(&mut server).await;
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
            level: None,
            muted: Some(false)
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
            level: Some(60),
            muted: None
        },
        "the event carries the level that was applied, not the one requested"
    );
    assert_eq!(
        player(next_client_state(&mut server).await).volume,
        Some(60),
        "the server sees the level that was applied"
    );
}
