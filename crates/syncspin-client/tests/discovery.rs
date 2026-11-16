//! Server-initiated connections: the client advertises `_sendspin._tcp`, accepts a server on the
//! advertised endpoint, and refuses to dial one while it advertises.
//!
//! The discovery backend is a recording fake, so no multicast group is joined and nothing leaves
//! the loopback interface. The listener binds `127.0.0.1:0`, which makes the port ephemeral and the
//! advertisement carry whatever was bound.

#![cfg(feature = "discovery")]

#[path = "fake_server.rs"]
mod fake_server;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use fake_server::{FakeServer, ServerOptions};
use syncspin_client::{
    advertise, connect, AudioFormat, AudioFrame, ClientConfig, DiscoveredServer, Discovery, Event,
    EventStream, GoodbyeReason, Identity, Inbound, ServiceAdvertisement, Sink, CLIENT_SERVICE_TYPE,
    DEFAULT_INBOUND_PORT, DEFAULT_SENDSPIN_PATH, SERVER_SERVICE_TYPE,
};

/// A sink that accepts every call and keeps nothing; these tests never announce a stream.
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

/// A [`Discovery`] that keeps what it was told, so a test can assert on the record itself.
#[derive(Default)]
struct RecordingDiscovery {
    /// Records passed to `advertise`, in the order they arrived.
    advertised: Mutex<Vec<ServiceAdvertisement>>,
    /// Service types passed to `withdraw`.
    withdrawn: Mutex<Vec<String>>,
    /// Service types passed to `browse`.
    browsed: Mutex<Vec<String>>,
    /// What `browse` reports.
    servers: Mutex<Vec<DiscoveredServer>>,
}

impl RecordingDiscovery {
    /// Returns the records advertised so far.
    fn advertised(&self) -> Vec<ServiceAdvertisement> {
        self.advertised
            .lock()
            .expect("the record list is not poisoned")
            .clone()
    }

    /// Returns the service types withdrawn so far.
    fn withdrawn(&self) -> Vec<String> {
        self.withdrawn
            .lock()
            .expect("the withdrawal list is not poisoned")
            .clone()
    }

    /// Returns the service types browsed so far.
    fn browsed(&self) -> Vec<String> {
        self.browsed
            .lock()
            .expect("the query list is not poisoned")
            .clone()
    }

    /// Returns the one record this client published.
    fn only_record(&self) -> ServiceAdvertisement {
        let mut records = self.advertised();
        assert_eq!(records.len(), 1, "one listener publishes one record");
        records.remove(0)
    }
}

impl Discovery for RecordingDiscovery {
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

    fn browse(&self, service_type: &str) -> Result<Vec<DiscoveredServer>> {
        self.browsed
            .lock()
            .expect("the query list is not poisoned")
            .push(service_type.to_owned());
        Ok(self
            .servers
            .lock()
            .expect("the server list is not poisoned")
            .clone())
    }
}

/// Builds the configuration of a client that advertises on an ephemeral loopback port.
fn inbound_config(discovery: Arc<dyn Discovery>) -> ClientConfig {
    let mut config = ClientConfig::new("127.0.0.1:1", "Test player", Identity::generate());
    config.inbound = Some(Inbound {
        discovery,
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        path: DEFAULT_SENDSPIN_PATH.to_owned(),
    });
    config
}

/// Waits for the first event `wanted` accepts, ignoring the ones that arrive before it.
async fn wait_for(events: &mut EventStream, mut wanted: impl FnMut(&Event) -> bool) -> Event {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::time::timeout_at(deadline, events.next())
            .await
            .expect("the expected event arrives")
            .expect("the event stream stays open");
        if wanted(&event) {
            return event;
        }
    }
}

/// Waits until the client reports that it connected to `server_id`.
async fn wait_for_connected(events: &mut EventStream, server_id: &str) {
    let event = wait_for(events, |event| matches!(event, Event::Connected { .. })).await;
    match event {
        Event::Connected {
            server_id: reported,
            encrypted,
        } => {
            assert_eq!(reported, server_id, "the reported server key");
            assert!(encrypted, "an inbound connection is encrypted as well");
        }
        other => panic!("expected Connected, got {other:?}"),
    }
}

/// Waits until the client reports that the connection ended, and returns the delay it named.
async fn wait_for_disconnected(events: &mut EventStream) -> Duration {
    match wait_for(events, |event| matches!(event, Event::Disconnected { .. })).await {
        Event::Disconnected { retry_in, .. } => retry_in,
        other => panic!("expected Disconnected, got {other:?}"),
    }
}

/// The advertisement names the endpoint a server needs: the bound port, the path and the player.
#[tokio::test]
async fn a_client_advertises_its_endpoint_and_its_name() {
    let discovery = Arc::new(RecordingDiscovery::default());
    let (mut handle, _events) = advertise(inbound_config(discovery.clone()), Box::new(NullSink))
        .await
        .expect("the client must be able to advertise");

    let record = discovery.only_record();
    assert_eq!(record.service_type, CLIENT_SERVICE_TYPE);
    assert_eq!(
        record.path, "/sendspin",
        "the path TXT record names the endpoint"
    );
    assert_eq!(
        record.name.as_deref(),
        Some("Test player"),
        "the name TXT record repeats the name client/hello carries"
    );
    assert_ne!(
        record.port, 0,
        "the record carries the port the listener bound, not the configured zero"
    );

    handle.close(GoodbyeReason::Shutdown);
    handle
        .finished()
        .await
        .expect("a closed client ends without an error");
    assert_eq!(
        discovery.withdrawn(),
        vec![CLIENT_SERVICE_TYPE.to_owned()],
        "a client that no longer listens must not stay advertised"
    );
}

/// A server that dials the advertised endpoint runs the ordinary session.
#[tokio::test]
async fn an_inbound_server_runs_the_normal_session() {
    let discovery = Arc::new(RecordingDiscovery::default());
    let (mut handle, mut events) = advertise(inbound_config(discovery.clone()), Box::new(NullSink))
        .await
        .expect("the client must be able to advertise");
    let record = discovery.only_record();
    let url = format!("ws://127.0.0.1:{}{}", record.port, record.path);

    let mut server = FakeServer::dial(&url, ServerOptions::default())
        .await
        .expect("the server must reach the advertised endpoint");
    let hello = server
        .wait_for_client_hello()
        .await
        .expect("the client answers with client/hello");
    assert_eq!(hello.name, "Test player");
    wait_for_connected(&mut events, server.server_id()).await;

    // The server's close ends the session, and the client waits for the next server instead of
    // dialling one itself: no attempt is scheduled, so the delay it reports is zero.
    server.close();
    assert_eq!(
        wait_for_disconnected(&mut events).await,
        Duration::ZERO,
        "an advertising client does not schedule a connection"
    );

    // A second server finds the listener still there.
    let mut again = FakeServer::dial(&url, ServerOptions::default())
        .await
        .expect("the listener accepts a second server");
    assert!(
        again.wait_for_client_hello().await.is_some(),
        "the client serves every server that connects, one at a time"
    );
    wait_for_connected(&mut events, again.server_id()).await;

    handle.close(GoodbyeReason::Shutdown);
    handle.finished().await.expect("the client closes cleanly");
}

/// A second server that arrives while one is admitted is rejected, not left waiting in the backlog.
#[tokio::test]
async fn a_second_server_is_rejected_with_concurrent_attempt() {
    let discovery = Arc::new(RecordingDiscovery::default());
    let (mut handle, mut events) = advertise(inbound_config(discovery.clone()), Box::new(NullSink))
        .await
        .expect("the client must be able to advertise");
    let record = discovery.only_record();
    let url = format!("ws://127.0.0.1:{}{}", record.port, record.path);

    let mut first = FakeServer::dial(&url, ServerOptions::default())
        .await
        .expect("the first server reaches the advertised endpoint");
    assert!(first.wait_for_client_hello().await.is_some());
    wait_for_connected(&mut events, first.server_id()).await;

    // A second server completes its handshake in parallel and is told why it is not admitted.
    let mut second = FakeServer::dial(&url, ServerOptions::default())
        .await
        .expect("the listener accepts the second connection");
    assert_eq!(
        second.wait_for_goodbye().await.as_deref(),
        Some("concurrent_attempt"),
        "connection.md rejects a connection that conflicts with the admitted one"
    );

    // The admitted server keeps its connection: rejection is not a disconnect of the group.
    assert!(
        first.wait_for_time_replies(1).await,
        "the admitted server keeps being served"
    );

    first.close();
    assert_eq!(
        wait_for_disconnected(&mut events).await,
        Duration::ZERO,
        "an advertising client does not schedule a connection"
    );

    handle.close(GoodbyeReason::Shutdown);
    handle.finished().await.expect("the client closes cleanly");
}

/// A request that carries an `Origin` header is refused, and the client keeps serving.
#[tokio::test]
async fn an_upgrade_with_an_origin_header_is_rejected() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::header::ORIGIN;
    use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
    use tokio_tungstenite::tungstenite::Error as WsError;

    let discovery = Arc::new(RecordingDiscovery::default());
    let (mut handle, _events) = advertise(inbound_config(discovery.clone()), Box::new(NullSink))
        .await
        .expect("the client must be able to advertise");
    let record = discovery.only_record();
    let url = format!("ws://127.0.0.1:{}{}", record.port, record.path);

    let mut request = url
        .clone()
        .into_client_request()
        .expect("the URL builds a request");
    request
        .headers_mut()
        .insert(ORIGIN, HeaderValue::from_static("http://a-page.invalid"));
    match tokio_tungstenite::connect_async(request).await {
        Err(WsError::Http(response)) => assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "connection.md requires the client to reject an upgrade carrying Origin"
        ),
        Err(error) => panic!("expected the 403 of the Origin rule, got {error}"),
        Ok(_) => panic!("a request with an Origin header must not be served"),
    }

    // The refusal is about the header alone: the same endpoint still serves a plain upgrade.
    let mut server = FakeServer::dial(&url, ServerOptions::default())
        .await
        .expect("a plain upgrade is still served");
    assert!(server.wait_for_client_hello().await.is_some());

    handle.close(GoodbyeReason::Shutdown);
    handle.finished().await.expect("the client closes cleanly");
}

/// A request for another path is not this client's endpoint.
#[tokio::test]
async fn an_upgrade_for_another_path_is_refused() {
    use tokio_tungstenite::tungstenite::http::StatusCode;
    use tokio_tungstenite::tungstenite::Error as WsError;

    let discovery = Arc::new(RecordingDiscovery::default());
    let (mut handle, _events) = advertise(inbound_config(discovery.clone()), Box::new(NullSink))
        .await
        .expect("the client must be able to advertise");
    let record = discovery.only_record();
    let url = format!("ws://127.0.0.1:{}/not-sendspin", record.port);

    match tokio_tungstenite::connect_async(url).await {
        Err(WsError::Http(response)) => assert_eq!(response.status(), StatusCode::NOT_FOUND),
        Err(error) => panic!("expected the 404 of the path rule, got {error}"),
        Ok(_) => panic!("a request for another path must not be served"),
    }

    handle.close(GoodbyeReason::Shutdown);
    handle.finished().await.expect("the client closes cleanly");
}

/// A peer that does not speak WebSocket is not a reason to stop accepting servers.
#[tokio::test]
async fn a_broken_upgrade_does_not_stop_the_listener() {
    let discovery = Arc::new(RecordingDiscovery::default());
    let (mut handle, _events) = advertise(inbound_config(discovery.clone()), Box::new(NullSink))
        .await
        .expect("the client must be able to advertise");
    let record = discovery.only_record();
    let url = format!("ws://127.0.0.1:{}{}", record.port, record.path);

    let mut raw = tokio::net::TcpStream::connect(("127.0.0.1", record.port))
        .await
        .expect("the listener accepts a TCP connection");
    {
        use tokio::io::AsyncWriteExt;
        raw.write_all(b"not a WebSocket request\r\n\r\n")
            .await
            .expect("the request reaches the listener");
        raw.shutdown().await.expect("the peer can close its side");
    }
    drop(raw);

    let mut server = FakeServer::dial(&url, ServerOptions::default())
        .await
        .expect("the listener still serves the next server");
    assert!(server.wait_for_client_hello().await.is_some());

    handle.close(GoodbyeReason::Shutdown);
    handle.finished().await.expect("the client closes cleanly");
}

/// `connection.md` lets a client use one method at a time, so a dialling call is refused.
#[tokio::test]
async fn a_manual_connection_is_refused_while_advertising() {
    let discovery = Arc::new(RecordingDiscovery::default());
    let config = inbound_config(discovery);

    let error = connect(config, Box::new(NullSink))
        .await
        .expect_err("a client that advertises must not dial a server");
    let text = format!("{error:#}");
    assert!(
        text.contains("advertis") && text.contains("connection.md"),
        "the error has to name the rule, got: {text}"
    );
}

/// The listener is what makes the mode possible, so advertising without one is refused.
#[tokio::test]
async fn advertising_without_an_inbound_mode_is_refused() {
    let config = ClientConfig::new("127.0.0.1:1", "Test player", Identity::generate());

    let error = advertise(config, Box::new(NullSink))
        .await
        .expect_err("there is no endpoint to advertise without an Inbound");
    let text = format!("{error:#}");
    assert!(
        text.contains("ClientConfig::inbound"),
        "the error names the field, got: {text}"
    );
}

/// The defaults are the values the spec recommends.
#[test]
fn the_inbound_defaults_are_the_recommended_ones() {
    let inbound = Inbound::new(Arc::new(RecordingDiscovery::default()));
    assert_eq!(inbound.listen.port(), DEFAULT_INBOUND_PORT);
    assert_eq!(inbound.path, DEFAULT_SENDSPIN_PATH);
    assert_eq!(
        inbound.listen.ip().to_string(),
        "0.0.0.0",
        "a client listens on every interface unless the host narrows it"
    );
}

/// The path becomes TXT record content, so a relative one cannot be published.
#[tokio::test]
async fn a_relative_inbound_path_is_rejected() {
    for path in ["", "sendspin", "//sendspin"] {
        let discovery = Arc::new(RecordingDiscovery::default());
        let mut config = inbound_config(discovery);
        config
            .inbound
            .as_mut()
            .expect("the configuration carries an inbound mode")
            .path = path.to_owned();

        let error = advertise(config, Box::new(NullSink))
            .await
            .expect_err("a path that is not absolute has no endpoint");
        assert!(
            format!("{error:#}").contains("inbound.path"),
            "the error names the field, got: {error:#}"
        );
    }
}

/// A dropped event stream ends the listener, and the advertisement goes with it.
#[tokio::test]
async fn a_dropped_event_stream_ends_the_listener() {
    let discovery = Arc::new(RecordingDiscovery::default());
    let (handle, events) = advertise(inbound_config(discovery.clone()), Box::new(NullSink))
        .await
        .expect("the client must be able to advertise");
    drop(events);

    handle
        .finished()
        .await
        .expect("dropping the event stream is a deliberate end, not a failure");
    assert_eq!(
        discovery.withdrawn(),
        vec![CLIENT_SERVICE_TYPE.to_owned()],
        "the advertisement goes with the listener"
    );
}

/// Browsing is the other half of the trait, and the client only ever asks for servers.
#[test]
fn browsing_asks_for_servers_and_reads_a_plain_ws_endpoint() {
    let discovery = RecordingDiscovery {
        servers: Mutex::new(vec![DiscoveredServer {
            addresses: vec!["127.0.0.1:8927".to_owned()],
            path: "/sendspin".to_owned(),
            name: Some("A server".to_owned()),
        }]),
        ..RecordingDiscovery::default()
    };

    let servers = syncspin_client::discover_servers(&discovery).expect("the backend answers");
    assert_eq!(
        discovery.browsed(),
        vec![SERVER_SERVICE_TYPE.to_owned()],
        "the client-initiated half searches for the server service type"
    );
    assert_eq!(
        servers.first().and_then(DiscoveredServer::endpoint),
        Some("ws://127.0.0.1:8927/sendspin".to_owned()),
        "a discovered record names a plain ws:// endpoint"
    );
}
