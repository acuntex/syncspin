//! Scheduled metadata on a headless client: a state is delivered at its server timestamp, a newer
//! one replaces a held one, a past or present one cancels it, and a client with no clock estimate
//! shows everything at once. The fake server answers `client/time` only when the test says so, so
//! the estimate is formed by real round trips at a moment the test chooses.

#![cfg(feature = "metadata")]

#[path = "fake_server.rs"]
mod fake_server;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    connect_headless, ClientConfig, ClientHandle, Event, EventStream, Identity, TrackProgress,
};

/// The roles every test here activates: metadata only.
fn metadata_only() -> ServerOptions {
    ServerOptions {
        active_roles: vec!["metadata@v1".to_owned()],
        manual_time: true,
        ..ServerOptions::default()
    }
}

/// The wall clock in microseconds, which is what the fake server stamps its replies with.
fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_micros() as i64
}

async fn connect_to(server: &FakeServer) -> (EventStream, ClientHandle) {
    let config = ClientConfig::new(server.endpoint(), "Test display", Identity::generate());
    let (handle, events) = connect_headless(config)
        .await
        .expect("a valid configuration");
    (events, handle)
}

/// Answers clock requests, spaced because the filter rejects a sample that does not advance its
/// local receive time, until the client stops asking.
async fn establish_clock(server: &mut FakeServer) {
    for _ in 0..60 {
        let Ok(Some(request)) =
            tokio::time::timeout(Duration::from_millis(500), server.next_time_request()).await
        else {
            return;
        };
        tokio::time::sleep(Duration::from_millis(2)).await;
        server.answer_time(request);
    }
}

/// The next `Event::Track` within `within`, skipping other events.
async fn next_track(events: &mut EventStream, within: Duration) -> Option<Event> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, events.next()).await {
            Ok(Some(event @ Event::Track { .. })) => return Some(event),
            Ok(Some(_)) => continue,
            Ok(None) => panic!("the event stream ended"),
            Err(_) => return None,
        }
    }
}

fn title_of(event: &Event) -> &str {
    match event {
        Event::Track { title, .. } => title,
        other => panic!("expected Track, got {other:?}"),
    }
}

/// A `server/state` carrying metadata stamped `timestamp_us`.
fn state(title: &str, timestamp_us: i64) -> String {
    serde_json::json!({
        "type": "server/state",
        "payload": {"metadata": {"timestamp": timestamp_us, "title": title}},
    })
    .to_string()
}

#[tokio::test]
async fn a_future_state_is_delivered_at_its_timestamp() {
    let mut server = FakeServer::start(metadata_only()).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    establish_clock(&mut server).await;

    let due = now_us() + 700_000;
    let sent = Instant::now();
    server.json(state("Next track", due));
    assert!(
        next_track(&mut events, Duration::from_millis(350))
            .await
            .is_none(),
        "a state whose moment has not come must not be delivered"
    );
    let event = next_track(&mut events, Duration::from_secs(3))
        .await
        .expect("the held state is delivered when its moment comes");
    assert!(
        sent.elapsed() >= Duration::from_millis(600),
        "delivered after {:?}, before its timestamp",
        sent.elapsed()
    );
    match event {
        Event::Track { timestamp_us, .. } => assert_eq!(timestamp_us, due),
        other => panic!("expected Track, got {other:?}"),
    }
}

#[tokio::test]
async fn a_past_state_is_delivered_at_once() {
    let mut server = FakeServer::start(metadata_only()).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    establish_clock(&mut server).await;

    server.json(state("Now playing", now_us() - 1_000_000));
    let event = next_track(&mut events, Duration::from_millis(300))
        .await
        .expect("a past state describes the audio playing now");
    assert_eq!(title_of(&event), "Now playing");
}

#[tokio::test]
async fn a_newer_future_state_replaces_the_held_one() {
    let mut server = FakeServer::start(metadata_only()).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    establish_clock(&mut server).await;

    server.json(state("First", now_us() + 1_500_000));
    server.json(state("Second", now_us() + 600_000));
    let event = next_track(&mut events, Duration::from_secs(3))
        .await
        .expect("the replacement is delivered");
    assert_eq!(title_of(&event), "Second");
    assert!(
        next_track(&mut events, Duration::from_millis(1_500))
            .await
            .is_none(),
        "the replaced state is never delivered"
    );
}

#[tokio::test]
async fn a_present_state_cancels_the_scheduled_one() {
    let mut server = FakeServer::start(metadata_only()).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;
    establish_clock(&mut server).await;

    server.json(state("Scheduled", now_us() + 800_000));
    server.json(state("Current", now_us()));
    let event = next_track(&mut events, Duration::from_millis(300))
        .await
        .expect("the resent current state is delivered at once");
    assert_eq!(title_of(&event), "Current");
    assert!(
        next_track(&mut events, Duration::from_millis(1_300))
            .await
            .is_none(),
        "resending the current state cancels the scheduled update"
    );
}

#[tokio::test]
async fn without_a_clock_estimate_a_future_state_is_delivered_at_once() {
    // The fake server never answers a clock request here, so no estimate forms.
    let server = FakeServer::start(metadata_only()).await.unwrap();
    let (mut events, handle) = connect_to(&server).await;

    server.json(state("Far ahead", now_us() + 60_000_000));
    let event = next_track(&mut events, Duration::from_secs(2))
        .await
        .expect("a client with no estimate does not wait for convergence");
    assert_eq!(title_of(&event), "Far ahead");
    assert_eq!(
        handle.control().server_time_us(),
        None,
        "there is no server time before the first estimate"
    );
}

#[tokio::test]
async fn the_server_time_follows_the_clock_estimate() {
    let mut server = FakeServer::start(metadata_only()).await.unwrap();
    let (_events, handle) = connect_to(&server).await;
    assert_eq!(handle.control().server_time_us(), None);

    establish_clock(&mut server).await;
    let reported = handle
        .control()
        .server_time_us()
        .expect("the estimate is published once it exists");
    assert!(
        (reported - now_us()).abs() < 50_000,
        "the fake server's clock is the local one, so the estimate is within {} us",
        (reported - now_us()).abs()
    );
}

#[tokio::test]
async fn the_event_carries_year_track_timestamp_and_progress() {
    let server = FakeServer::start(metadata_only()).await.unwrap();
    let (mut events, _handle) = connect_to(&server).await;

    server.json(
        serde_json::json!({
            "type": "server/state",
            "payload": {"metadata": {
                "timestamp": 42,
                "title": "T",
                "year": 1999,
                "track": 7,
                "progress": {"track_progress": 1000, "track_duration": 5000, "playback_speed": 500},
            }},
        })
        .to_string(),
    );
    match next_track(&mut events, Duration::from_secs(2))
        .await
        .expect("a Track")
    {
        Event::Track {
            year,
            track,
            timestamp_us,
            progress,
            ..
        } => {
            assert_eq!((year, track, timestamp_us), (Some(1999), Some(7), 42));
            assert_eq!(progress.position_ms, Some(1000));
            assert_eq!(progress.duration_ms, Some(5000));
            assert_eq!(progress.speed_permille, 500);
            // At half speed, two seconds of server time are one second of track.
            assert_eq!(
                progress.position_ms_at(42, Some(42 + 2_000_000)),
                Some(2000)
            );
        }
        other => panic!("expected Track, got {other:?}"),
    }
}

#[test]
fn the_default_progress_is_normal_speed_with_nothing_known() {
    let progress = TrackProgress::default();
    assert_eq!(progress.speed_permille, 1_000, "speed 0 would mean paused");
    assert_eq!(progress.position_ms, None);
    assert_eq!(progress.duration_ms, None);
}

#[tokio::test]
async fn adding_the_metadata_role_mid_session_starts_a_clock_burst() {
    let mut server = FakeServer::start(ServerOptions {
        active_roles: Vec::new(),
        manual_time: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (_events, _handle) = connect_to(&server).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), server.next_time_request())
            .await
            .is_err(),
        "no role needs the clock yet"
    );
    server.activate(&["metadata@v1"]);
    assert!(
        tokio::time::timeout(Duration::from_secs(3), server.next_time_request())
            .await
            .is_ok(),
        "the metadata role starts the clock"
    );
}
