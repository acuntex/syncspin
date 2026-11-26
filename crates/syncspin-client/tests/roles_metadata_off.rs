//! A build without the `metadata` feature does not advertise `metadata@v1`, and refuses a server that
//! activates it: the activation is answered with `client/goodbye` reason `unauthorized`, the same
//! as for any role the client never offered. `--all-features` never compiles this file, so the
//! per-feature matrix in `scripts/check-roles.sh` is what runs it.

#![cfg(all(feature = "player", not(feature = "metadata")))]

#[path = "fake_server.rs"]
mod fake_server;

use std::time::{Duration, Instant};

use anyhow::Result;
use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{connect, AudioFormat, AudioFrame, ClientConfig, Identity, Sink};

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

#[tokio::test]
async fn the_hello_does_not_list_the_role() {
    let mut server = FakeServer::start(ServerOptions::default()).await.unwrap();
    let config = ClientConfig::new(server.endpoint(), "Test player", Identity::generate());
    let (_handle, _events) = connect(config, Box::new(NullSink)).await.unwrap();

    let hello = tokio::time::timeout(Duration::from_secs(8), server.wait_for_client_hello())
        .await
        .expect("the client announces itself")
        .expect("a client/hello arrived");
    assert!(
        !hello
            .supported_roles
            .iter()
            .any(|role| role == "metadata@v1"),
        "metadata@v1 must not be advertised: {:?}",
        hello.supported_roles
    );
}

#[tokio::test]
async fn an_activation_of_the_role_is_refused_as_unauthorized() {
    let options = ServerOptions {
        active_roles: vec!["player@v1".to_owned(), "metadata@v1".to_owned()],
        ..ServerOptions::default()
    };
    let mut server = FakeServer::start(options).await.unwrap();
    let config = ClientConfig::new(server.endpoint(), "Test player", Identity::generate());
    let (_handle, _events) = connect(config, Box::new(NullSink)).await.unwrap();

    let reason = tokio::time::timeout(Duration::from_secs(8), server.wait_for_goodbye())
        .await
        .expect("the client answers an activation it will not honour");
    assert_eq!(reason.as_deref(), Some("unauthorized"));
}
