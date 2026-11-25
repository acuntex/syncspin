//! A headless client that advertises and is dialled by a server (`connection.md`, server-initiated
//! mode): it listens, offers no player role and takes part in the others.

#![cfg(all(feature = "discovery", feature = "metadata"))]

#[path = "fake_server.rs"]
mod fake_server;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    advertise_headless, ClientConfig, DiscoveredServer, Discovery, Event, Identity, Inbound,
    ServiceAdvertisement, DEFAULT_SENDSPIN_PATH,
};

/// A [`Discovery`] that keeps the records it was asked to publish.
#[derive(Default)]
struct RecordingDiscovery {
    advertised: Mutex<Vec<ServiceAdvertisement>>,
}

impl Discovery for RecordingDiscovery {
    fn advertise(&self, service: ServiceAdvertisement) -> Result<()> {
        self.advertised.lock().unwrap().push(service);
        Ok(())
    }

    fn withdraw(&self, _service_type: &str) -> Result<()> {
        Ok(())
    }

    fn browse(&self, _service_type: &str) -> Result<Vec<DiscoveredServer>> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn a_headless_advertiser_serves_a_dialling_server_without_the_player_role() {
    let discovery = Arc::new(RecordingDiscovery::default());
    let mut config = ClientConfig::new("127.0.0.1:1", "Test display", Identity::generate());
    config.inbound = Some(Inbound {
        discovery: discovery.clone(),
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        path: DEFAULT_SENDSPIN_PATH.to_owned(),
    });
    let (_handle, mut events) = advertise_headless(config)
        .await
        .expect("the configuration advertises");
    let record = discovery.advertised.lock().unwrap()[0].clone();
    let url = format!("ws://127.0.0.1:{}{}", record.port, record.path);

    let options = ServerOptions {
        active_roles: vec!["metadata@v1".to_owned()],
        ..ServerOptions::default()
    };
    let mut server = FakeServer::dial(&url, options).await.unwrap();
    let hello = tokio::time::timeout(Duration::from_secs(8), server.wait_for_client_hello())
        .await
        .expect("the client announces itself")
        .expect("a client/hello arrived");
    // The roles this build offers without a sink: the player is never among them.
    #[cfg(feature = "controller")]
    let expected = ["controller@v1", "metadata@v1"];
    #[cfg(not(feature = "controller"))]
    let expected = ["metadata@v1"];
    assert_eq!(
        hello.supported_roles, expected,
        "a headless advertiser offers no player role"
    );
    assert!(hello.player_support.is_none());
    let event = tokio::time::timeout(Duration::from_secs(8), events.next())
        .await
        .expect("an event")
        .expect("the stream is open");
    assert!(matches!(event, Event::Connected { .. }), "got {event:?}");
}
