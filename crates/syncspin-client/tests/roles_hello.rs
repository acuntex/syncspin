//! The roles a client advertises in `client/hello`: which role identifiers, in which order, and
//! which capability objects ride along. The hello is read as text, because the typed form drops
//! keys it does not know and so cannot show that a key is absent.

#[path = "fake_server.rs"]
mod fake_server;

use std::time::{Duration, Instant};

use anyhow::Result;
use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    connect, AudioFormat, AudioFrame, AudioMode, ClientConfig, Identity, Sink, VolumePolicy,
    DEFAULT_PAIRING_TIMEOUT,
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
        strict_group_id: false,
        output_delay_control: false,
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

/// Connects a sink client and returns the `client/hello` text it sent.
async fn hello_text() -> String {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let (_handle, _events) = connect(config_for(&server), Box::new(NullSink))
        .await
        .expect("the configuration is valid");
    tokio::time::timeout(Duration::from_secs(8), server.wait_for_client_hello_text())
        .await
        .expect("the client must announce itself")
        .expect("the server saw a client/hello")
}

#[tokio::test]
async fn the_default_hello_lists_the_roles_in_order() {
    let text = hello_text().await;
    let hello: serde_json::Value = serde_json::from_str(&text).expect("the hello is JSON");
    assert_eq!(
        hello["payload"]["supported_roles"],
        serde_json::json!(["player@v1", "controller@v1", "metadata@v1"]),
        "the default build advertises exactly these roles, in this order"
    );
}

#[tokio::test]
async fn only_the_player_role_carries_a_support_object() {
    let text = hello_text().await;
    let hello: serde_json::Value = serde_json::from_str(&text).expect("the hello is JSON");
    let payload = hello["payload"]
        .as_object()
        .expect("the payload is an object");
    let support: Vec<&String> = payload
        .keys()
        .filter(|key| key.ends_with("_support"))
        .collect();
    assert_eq!(
        support,
        vec!["player@v1_support"],
        "no other role defines a support object, so none may be sent"
    );
}
