//! Handshake refusals: every stage of the cleartext exchange and the Noise handshake has a rule,
//! and a server that breaks it must end the attempt with a named reason. No test here plays audio.

#[path = "fake_server.rs"]
mod fake_server;

use std::time::{Duration, Instant};

use anyhow::Result;
use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    connect, AudioFormat, AudioFrame, AudioMode, ClientConfig, ClientHandle, Event, EventStream,
    Identity, Sink, VolumePolicy, DEFAULT_PAIRING_TIMEOUT,
};

/// A sink that accepts every call; these tests never announce a stream.
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

/// Builds a configuration for `server`.
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
        max_backoff: Duration::from_secs(1),
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

/// Connects to `server`.
async fn connect_to(server: &FakeServer) -> (EventStream, ClientHandle) {
    let (handle, events) = connect(config_for(server), Box::new(NullSink))
        .await
        .expect("the configuration is valid, so the attempt starts");
    (events, handle)
}

/// Waits for one event, failing instead of hanging.
async fn next_event(stream: &mut EventStream) -> Event {
    match tokio::time::timeout(Duration::from_secs(8), stream.next()).await {
        Ok(Some(event)) => event,
        Ok(None) => panic!("the event stream ended"),
        Err(_) => panic!("timed out waiting for an event"),
    }
}

/// Asserts that the server was refused with a reason naming `needle`, and that a retry follows.
async fn expect_refusal(server: ServerOptions, needle: &str) {
    let server = FakeServer::start(server).await.unwrap();
    let (mut events, handle) = connect_to(&server).await;

    match next_event(&mut events).await {
        Event::Disconnected { reason, retry_in } => {
            assert!(
                reason.contains(needle),
                "the reason should name {needle:?}, got: {reason}"
            );
            assert!(
                retry_in > Duration::ZERO,
                "a handshake refusal is retried, so a delay must be recommended"
            );
        }
        other => panic!("expected Disconnected, got {other:?}"),
    }
    drop(handle);
}

#[tokio::test]
async fn a_cleartext_message_that_is_not_server_init_is_refused() {
    expect_refusal(
        ServerOptions {
            server_init_override: Some(
                r#"{"type":"server/hello","payload":{"name":"Not an init"}}"#.to_owned(),
            ),
            ..ServerOptions::default()
        },
        "expected a cleartext server/init",
    )
    .await;
}

#[tokio::test]
async fn an_unsupported_server_version_is_refused() {
    expect_refusal(
        ServerOptions {
            server_version: 2,
            ..ServerOptions::default()
        },
        "unsupported server version 2",
    )
    .await;
}

#[tokio::test]
async fn a_cleartext_message_that_is_not_noise_message_one_is_refused() {
    expect_refusal(
        ServerOptions {
            message_1_override: Some(
                r#"{"type":"server/hello","payload":{"name":"Not a handshake"}}"#.to_owned(),
            ),
            ..ServerOptions::default()
        },
        "expected noise/handshake message 1",
    )
    .await;
}

#[tokio::test]
async fn a_close_before_server_init_is_refused() {
    expect_refusal(
        ServerOptions {
            close_before_init: true,
            ..ServerOptions::default()
        },
        "the connection closed during the Noise handshake",
    )
    .await;
}

#[tokio::test]
async fn a_close_after_message_two_is_refused() {
    expect_refusal(
        ServerOptions {
            close_after_message_2: true,
            ..ServerOptions::default()
        },
        "the connection closed during the Noise handshake",
    )
    .await;
}

#[tokio::test]
async fn a_first_encrypted_message_that_is_not_server_hello_is_refused() {
    expect_refusal(
        ServerOptions {
            hello_override: Some(
                r#"{"type":"server/activate","payload":{"active_roles":[]}}"#.to_owned(),
            ),
            ..ServerOptions::default()
        },
        "expected an encrypted server/hello",
    )
    .await;
}

#[tokio::test]
async fn a_second_encrypted_message_that_is_not_activate_is_refused() {
    expect_refusal(
        ServerOptions {
            activate_override: Some(r#"{"type":"server/hello","payload":{}}"#.to_owned()),
            ..ServerOptions::default()
        },
        "expected an encrypted server/activate",
    )
    .await;
}

#[tokio::test]
async fn cleartext_text_after_message_two_is_refused() {
    expect_refusal(
        ServerOptions {
            cleartext_after_message_2: true,
            ..ServerOptions::default()
        },
        "cleartext text after the Noise transport",
    )
    .await;
}

#[tokio::test]
async fn an_empty_noise_plaintext_during_the_handshake_is_refused() {
    expect_refusal(
        ServerOptions {
            pre_hello_plaintexts: vec![Vec::new()],
            ..ServerOptions::default()
        },
        "empty Noise plaintext",
    )
    .await;
}

#[tokio::test]
async fn a_binary_frame_before_server_init_is_skipped() {
    let server = FakeServer::start(ServerOptions {
        binary_before_init: true,
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server).await;

    match next_event(&mut events).await {
        Event::Connected {
            server_id,
            encrypted,
        } => {
            assert!(encrypted);
            assert_eq!(server_id, server.server_id());
        }
        other => panic!("a binary frame before the init exchange carries nothing, got {other:?}"),
    }
}

#[tokio::test]
async fn a_binary_message_before_server_hello_is_skipped() {
    let server = FakeServer::start(ServerOptions {
        // A player audio chunk id: during the handshake the client has no stream and has to wait
        // for the next message instead of treating it as the hello.
        pre_hello_plaintexts: vec![vec![4, 0, 0, 0]],
        ..ServerOptions::default()
    })
    .await
    .unwrap();
    let (mut events, _handle) = connect_to(&server).await;

    match next_event(&mut events).await {
        Event::Connected { encrypted, .. } => assert!(encrypted),
        other => {
            panic!("the hello after the binary message must complete the handshake, got {other:?}")
        }
    }
}
