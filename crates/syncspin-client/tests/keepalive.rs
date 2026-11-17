//! The WebSocket keepalive: a silent link is pinged, an unanswered ping ends the session, and
//! traffic keeps the ping away.
//!
//! The protocol has no application-level liveness message, so an idle session is silent in both
//! directions. These tests play the half-open link that silence hides: the socket stays open while
//! the peer has already dropped the session.
//!
//! The shipped 15 s and 10 s windows are the ones under test, never a shortened copy. Time is
//! frozen only while the test waits for the client's timer and no frame is expected; every frame
//! exchange runs on the real clock, because a paused clock does not wake a socket read promptly
//! (the runtime advances to the next timer instead). Each silence assertion states the virtual
//! interval it measured, so a session that pinged early cannot pass by accident.

#[path = "fake_server.rs"]
mod fake_server;

use std::time::{Duration, Instant};

use anyhow::Result;
use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    connect, AudioFormat, AudioFrame, AudioMode, ClientConfig, ClientHandle, Event, EventStream,
    Identity, Sink, VolumePolicy, DEFAULT_PAIRING_TIMEOUT, INITIAL_BACKOFF,
};
use syncspin_core::messages::{GroupUpdate, Incoming};

/// Ceiling the tests use, so a dropped session reconnects within the test's patience.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Slack the window assertions allow for the frame that started the idle timer arriving a moment
/// before the test paused the clock.
const WINDOW_SLACK: Duration = Duration::from_secs(1);

/// A sink that discards what it is given.
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
        max_backoff: MAX_BACKOFF,
        strict_group_id: false,
        unpaired_access: true,
        required_lead_time_ms: 250,
        min_buffer_ms: None,
        pairing_timeout: DEFAULT_PAIRING_TIMEOUT,
        #[cfg(feature = "discovery")]
        inbound: None,
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

/// Connects to `server` with a fresh identity and a sink that discards audio.
async fn connect_to(server: &FakeServer) -> (EventStream, ClientHandle) {
    let (handle, events) = connect(config_for(server), Box::new(NullSink))
        .await
        .expect("the client must connect to the fake server");
    (events, handle)
}

/// Waits for one event, failing instead of hanging.
///
/// The bound is far beyond the 25 s the keepalive windows need, so the expected deadline is always
/// reached first, while a missing event still fails the test instead of blocking it forever.
async fn next_event(stream: &mut EventStream) -> Event {
    match tokio::time::timeout(Duration::from_secs(120), stream.next()).await {
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

/// Waits for the keepalive ping the client has to send and returns its payload.
async fn expect_ping(server: &mut FakeServer) -> Vec<u8> {
    match tokio::time::timeout(Duration::from_secs(60), server.wait_for_ping()).await {
        Ok(Some(payload)) => payload,
        Ok(None) => panic!("the connection ended before the keepalive ping"),
        Err(_) => panic!("the silent session never sent a keepalive ping"),
    }
}

/// Sends one `group/update`, a core message that needs no active role.
fn group_update(server: &FakeServer, name: &str) {
    let update = serde_json::to_string(&Incoming::GroupUpdate(GroupUpdate {
        playback_state: "playing".to_owned(),
        group_id: "A".repeat(43),
        group_name: name.to_owned(),
    }))
    .expect("a group/update encodes");
    server.json(update);
}

/// Waits for the `Event::State` of the next `group/update` and returns its group name.
async fn expect_group(stream: &mut EventStream) -> String {
    loop {
        match next_event(stream).await {
            Event::State(state) => {
                return state.group_name.expect("the group update named the group");
            }
            _ => continue,
        }
    }
}

/// Asserts that no ping arrives within `within` on the paused clock.
///
/// Observations queued before the call are inspected too, so a ping that arrived earlier in the
/// measured interval cannot hide behind them.
async fn expect_no_ping(server: &mut FakeServer, within: Duration) {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, server.observation()).await {
            Ok(Some(fake_server::Observation::Ping(payload))) => {
                panic!("a frame-carrying link must not be pinged, got payload {payload:?}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => return,
            Err(_) => return,
        }
    }
}

#[tokio::test]
async fn a_silent_session_pings_once_and_stays_connected() {
    // No role at all: the client has nothing to say after the handshake, which is the idle session
    // that stayed "connected" for hours in the field.
    let options = ServerOptions {
        active_roles: Vec::new(),
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;

    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let payload = expect_ping(&mut server).await;
    let waited = tokio::time::Instant::now() - started;
    assert!(
        waited + WINDOW_SLACK >= Duration::from_secs(15)
            && waited <= Duration::from_secs(15) + WINDOW_SLACK,
        "the ping belongs to the 15 s idle window, got {waited:?}"
    );
    assert_eq!(
        payload.len(),
        8,
        "the ping carries the 8-byte keepalive nonce"
    );

    // The harness answered, and the ping is on the wire. Five virtual seconds later - still inside
    // the 10 s pong window - the server sends a frame the client has to count: the idle timer
    // restarts from that frame, not from the ping. Exchange it on the real clock; the paused clock
    // is only for the idle waits.
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::time::resume();
    group_update(&server, "After the ping");
    assert_eq!(expect_group(&mut events).await, "After the ping");

    // Ten more virtual seconds put the clock at about 30 s, where a client that pinged on a fixed
    // 15 s schedule sends its second ping. A client that pings on silence waits until the frame
    // above plus 15 s (about 35 s), so only the fixed-schedule one has anything to send in the
    // second measured here.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(10)).await;
    expect_no_ping(&mut server, Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_frame_other_than_a_pong_answers_the_keepalive_ping() {
    // No role, so the link is silent in both directions and the keepalive is the only traffic.
    let options = ServerOptions {
        active_roles: Vec::new(),
        answer_pings: false,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;

    tokio::time::pause();
    let payload = expect_ping(&mut server).await;
    assert_eq!(
        payload.len(),
        8,
        "the ping carries the 8-byte keepalive nonce"
    );

    // The harness never answers that ping. Five virtual seconds later - still inside the 10 s pong
    // window - a normal group update arrives, and it is the answer: the client asks whether the link
    // delivers anything, not whether it delivers the pong. Only the wait is virtual; the exchange
    // itself runs on the real clock.
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::time::resume();
    group_update(&server, "Inside the pong window");
    assert_eq!(expect_group(&mut events).await, "Inside the pong window");

    // The answer counts only if the session is still there once the bail would have fired: about 28
    // s, with the ping 13 s old. A client that only accepted a pong ended the session at 25 s, so
    // this frame could not be delivered at all.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(8)).await;
    tokio::time::resume();
    group_update(&server, "After the pong window");
    assert_eq!(expect_group(&mut events).await, "After the pong window");
}

#[tokio::test]
async fn an_unanswered_ping_ends_the_session_and_the_client_reconnects() {
    // The harness records the ping and then lets the link go silent with the socket still open:
    // exactly what a server that dropped the session leaves behind.
    let options = ServerOptions {
        active_roles: vec!["controller@v1".to_owned()],
        answer_pings: false,
        connections: 2,
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;

    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let payload = expect_ping(&mut server).await;
    let ping_at = tokio::time::Instant::now();
    let waited = ping_at - started;
    assert!(
        waited + WINDOW_SLACK >= Duration::from_secs(15)
            && waited <= Duration::from_secs(15) + WINDOW_SLACK,
        "the ping belongs to the 15 s idle window, got {waited:?}"
    );
    assert_eq!(
        payload.len(),
        8,
        "the ping carries the 8-byte keepalive nonce"
    );

    // The ping is on the wire and nothing comes back. The session must end as a disconnect and
    // schedule the next attempt, not sit on a link the peer no longer serves.
    match next_event(&mut events).await {
        Event::Disconnected { reason, retry_in } => {
            let answered = tokio::time::Instant::now() - ping_at;
            assert!(
                answered + WINDOW_SLACK >= Duration::from_secs(10)
                    && answered <= Duration::from_secs(10) + WINDOW_SLACK,
                "the pong window is 10 s, got {answered:?}"
            );
            assert!(
                reason.contains("keepalive ping"),
                "the reason must name the unanswered ping, got: {reason}"
            );
            assert_eq!(
                retry_in, INITIAL_BACKOFF,
                "a session that connected recommends the initial delay"
            );
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }

    // The reconnect is a real handshake again: let the clock run for it, then check the second
    // connection is up and the client announced itself on it. The first hello and the ping were
    // consumed above, so the next one belongs to the new connection.
    tokio::time::resume();
    expect_connected(&mut events, &server).await;
    let hello = tokio::time::timeout(Duration::from_secs(5), server.wait_for_client_hello())
        .await
        .expect("the client must announce itself again");
    assert!(
        hello.is_some(),
        "the reconnected session must re-register with the server"
    );
}

#[tokio::test]
async fn frames_from_the_server_keep_the_link_alive_without_a_ping() {
    // The metadata role makes the server's frames reach the host, and it is not a role the client
    // reports for, so all traffic on this link comes from the server.
    let options = ServerOptions {
        active_roles: vec!["metadata@v1".to_owned()],
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;

    // Four frames, ten virtual seconds apart: more than the 15 s window in total, but never a gap
    // long enough for the client to be idle. Only the gaps are virtual; each frame is exchanged on
    // the real clock, because a paused clock does not wake a socket read. A client that pinged on
    // a timer instead of on silence would ping during this run and leave an observation behind.
    for index in 0..4 {
        let name = format!("Group {index}");
        group_update(&server, &name);
        assert_eq!(expect_group(&mut events).await, name);
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::time::resume();
    }

    // Freeze once more and drain what the run left behind: ten seconds after the last frame, still
    // inside the idle window. A ping from earlier in the run is queued here and fails the test.
    tokio::time::pause();
    expect_no_ping(&mut server, Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_server_ping_is_still_answered() {
    // The client's own keepalive must not replace the answer to the peer's: a server that pings
    // this client gets the RFC 6455 pong back, with the payload it sent.
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    expect_connected(&mut events, &server).await;

    server.ping(vec![9, 8, 7]);
    let pong = tokio::time::timeout(Duration::from_secs(5), server.wait_for_pong())
        .await
        .expect("the client must answer a server ping")
        .expect("the connection must not close before the pong");
    assert_eq!(pong, vec![9, 8, 7], "the pong echoes the ping payload");
}
