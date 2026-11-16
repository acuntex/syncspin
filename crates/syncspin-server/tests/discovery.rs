//! Server-initiated connections driven by a fake [`Discovery`] and a real advertising client.
//!
//! No multicast leaves the process: the server's backend is a recording fake that reports the
//! record the client published, and the client's backend is a fake the test reads. The WebSocket
//! still goes over loopback, so the upgrade, the Noise handshake and `client/hello` are real. The
//! client rejects an upgrade that carries an `Origin` header, which is what makes the completed
//! connection evidence that the server sent none.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use syncspin_client::{
    advertise, AudioFormat as ClientFormat, AudioFrame, ClientConfig,
    DiscoveredServer as ClientDiscoveredServer, Discovery as ClientDiscovery, Event as ClientEvent,
    EventStream as ClientEventStream, GoodbyeReason, Identity as ClientIdentity, Inbound,
    ServiceAdvertisement as ClientAdvertisement, Sink,
};
use syncspin_server::{
    DiscoveredClient, Discovery, Event, EventStream, Identity, Server, ServerConfig, ServerHandle,
    ServiceAdvertisement, CLIENT_SERVICE_TYPE, DEFAULT_PATH, DEFAULT_SENDSPIN_PATH,
    SERVER_SERVICE_TYPE,
};

/// A sink that accepts every call and keeps nothing; the test never announces a stream.
struct NullSink;

impl Sink for NullSink {
    fn open(&mut self, _format: ClientFormat) -> Result<()> {
        Ok(())
    }

    fn write(&mut self, _frame: AudioFrame<'_>, _due: std::time::Instant) -> Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The client's discovery backend: records what the client advertises, browses nothing.
#[derive(Default)]
struct ClientDiscoveryFake {
    advertised: Mutex<Vec<ClientAdvertisement>>,
}

impl ClientDiscoveryFake {
    /// Returns the one record this client published.
    fn only_record(&self) -> ClientAdvertisement {
        let mut records = self
            .advertised
            .lock()
            .expect("the record list is not poisoned");
        assert_eq!(records.len(), 1, "one listener publishes one record");
        records.remove(0)
    }
}

impl ClientDiscovery for ClientDiscoveryFake {
    fn advertise(&self, service: ClientAdvertisement) -> Result<()> {
        self.advertised
            .lock()
            .expect("the record list is not poisoned")
            .push(service);
        Ok(())
    }

    fn withdraw(&self, _service_type: &str) -> Result<()> {
        Ok(())
    }

    fn browse(&self, _service_type: &str) -> Result<Vec<ClientDiscoveredServer>> {
        Ok(Vec::new())
    }
}

/// The server's discovery backend: publishes what it is told and reports the clients it was given.
struct ServerDiscoveryFake {
    advertised: Mutex<Vec<ServiceAdvertisement>>,
    withdrawn: Mutex<Vec<String>>,
    browsed: Mutex<Vec<String>>,
    clients: Vec<DiscoveredClient>,
}

impl ServerDiscoveryFake {
    fn with_clients(clients: Vec<DiscoveredClient>) -> ServerDiscoveryFake {
        ServerDiscoveryFake {
            advertised: Mutex::new(Vec::new()),
            withdrawn: Mutex::new(Vec::new()),
            browsed: Mutex::new(Vec::new()),
            clients,
        }
    }

    fn only_advertised(&self) -> ServiceAdvertisement {
        let mut records = self
            .advertised
            .lock()
            .expect("the record list is not poisoned");
        assert_eq!(records.len(), 1, "one server publishes one record");
        records.remove(0)
    }

    fn withdrawn(&self) -> Vec<String> {
        self.withdrawn
            .lock()
            .expect("the withdrawal list is not poisoned")
            .clone()
    }

    fn browsed(&self) -> Vec<String> {
        self.browsed
            .lock()
            .expect("the query list is not poisoned")
            .clone()
    }
}

impl Discovery for ServerDiscoveryFake {
    fn advertise(&self, service: ServiceAdvertisement) -> Result<()> {
        self.advertised
            .lock()
            .expect("the record list is not poisoned")
            .push(service);
        Ok(())
    }

    fn withdraw(&self, service_type: &str) -> Result<()> {
        self.withdrawn
            .lock()
            .expect("the withdrawal list is not poisoned")
            .push(service_type.to_owned());
        Ok(())
    }

    fn browse(&self, service_type: &str) -> Result<Vec<DiscoveredClient>> {
        self.browsed
            .lock()
            .expect("the query list is not poisoned")
            .push(service_type.to_owned());
        Ok(self.clients.clone())
    }
}

/// Waits for the first server event `wanted` accepts.
async fn wait_for_event(events: &mut EventStream, mut wanted: impl FnMut(&Event) -> bool) -> Event {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let event = tokio::time::timeout_at(deadline, events.next())
            .await
            .expect("the expected server event arrives")
            .expect("the event stream stays open");
        if wanted(&event) {
            return event;
        }
    }
}

/// Waits for the first client event `wanted` accepts.
async fn wait_for_client_event(
    events: &mut ClientEventStream,
    mut wanted: impl FnMut(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let event = tokio::time::timeout_at(deadline, events.next())
            .await
            .expect("the expected client event arrives")
            .expect("the event stream stays open");
        if wanted(&event) {
            return event;
        }
    }
}

/// Starts a server whose discovery backend reports `client`, and returns it with the fake.
async fn start_with_client(
    client: DiscoveredClient,
) -> Result<(ServerHandle, Arc<ServerDiscoveryFake>)> {
    let discovery = Arc::new(ServerDiscoveryFake::with_clients(vec![client]));
    let config = ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        discovery: Some(discovery.clone()),
        ..ServerConfig::new("A test server", Identity::generate())
    };
    let server = Server::start(config).await?;
    Ok((server, discovery))
}

/// A discovered client is dialled without an `Origin` header and the protocol completes.
#[tokio::test]
async fn a_discovered_client_is_connected_without_an_origin_header() -> Result<()> {
    let client_discovery = Arc::new(ClientDiscoveryFake::default());
    let mut config = ClientConfig::new("127.0.0.1:1", "A fake client", ClientIdentity::generate());
    config.inbound = Some(Inbound {
        discovery: client_discovery.clone(),
        listen: "127.0.0.1:0".parse().expect("a literal address parses"),
        path: DEFAULT_SENDSPIN_PATH.to_owned(),
    });
    let (mut client, mut client_events) = advertise(config, Box::new(NullSink)).await?;
    let record = client_discovery.only_record();
    let endpoint = DiscoveredClient {
        addresses: vec![format!("127.0.0.1:{}", record.port)],
        path: record.path.clone(),
        name: record.name.clone(),
    };

    let (mut server, discovery) = start_with_client(endpoint).await?;
    let mut events = server.events();

    // The server publishes the client-initiated record before it starts browsing.
    let advertised = discovery.only_advertised();
    assert_eq!(advertised.service_type, SERVER_SERVICE_TYPE);
    assert_eq!(advertised.port, server.local_addr().port());
    assert_eq!(advertised.path, DEFAULT_PATH);
    assert_eq!(advertised.name.as_deref(), Some("A test server"));

    // The client completes the handshake; its rejection of an `Origin` header means the server
    // sent none.
    let connected = wait_for_event(&mut events, |event| {
        matches!(event, Event::ClientConnected { .. })
    })
    .await;
    assert_eq!(
        discovery.browsed().first().map(String::as_str),
        Some(CLIENT_SERVICE_TYPE),
        "the server browses the client service type"
    );
    match connected {
        Event::ClientConnected { name, approved, .. } => {
            assert_eq!(name, "A fake client");
            assert!(
                !approved,
                "an unpaired client is reported as unapproved before the operator acts"
            );
        }
        other => panic!("expected ClientConnected, got {other:?}"),
    }
    let report = wait_for_client_event(&mut client_events, |event| {
        matches!(event, ClientEvent::Connected { .. })
    })
    .await;
    match report {
        ClientEvent::Connected { encrypted, .. } => {
            assert!(
                encrypted,
                "a server-initiated connection is encrypted as well"
            );
        }
        other => panic!("expected Connected, got {other:?}"),
    }

    server.shutdown().await?;
    assert_eq!(
        discovery.withdrawn(),
        vec![SERVER_SERVICE_TYPE.to_owned()],
        "a server that stops listening must not stay advertised"
    );

    client.close(GoodbyeReason::Shutdown);
    client.finished().await?;
    Ok(())
}

/// A discovery record with an unusable endpoint is not dialled.
#[tokio::test]
async fn an_endpoint_that_is_not_ws_is_not_dialled() -> Result<()> {
    let client = DiscoveredClient {
        addresses: vec!["wss://192.0.2.7:8928".to_owned()],
        path: DEFAULT_SENDSPIN_PATH.to_owned(),
        name: None,
    };
    let (mut server, discovery) = start_with_client(client).await?;
    let mut events = server.events();

    assert!(
        tokio::time::timeout(Duration::from_millis(300), events.next())
            .await
            .is_err(),
        "a record that does not name a plain ws:// endpoint must not produce a connection"
    );
    server.shutdown().await?;
    assert_eq!(discovery.withdrawn(), vec![SERVER_SERVICE_TYPE.to_owned()]);
    Ok(())
}
