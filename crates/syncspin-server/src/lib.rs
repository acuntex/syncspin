//! Server side of Sendspin.
//!
//! A server accepts client connections, runs the Noise handshake as its initiator and owns what
//! happens on the connection afterwards. This crate is the protocol and the transport; a host that
//! has audio to distribute drives the handle [`Server::start`] returns and follows the connections
//! through the [`Event`] stream.
//!
//! The listener is the part that exists: a client connects, `client/init` is answered with
//! `server/init` and Noise message 1, the handshake completes, and the server sends `server/hello`
//! and `server/activate`. Roles, streams, pairing and discovery follow in `0.2`.
//!
//! Every connection is encrypted. A client that does not complete the Noise handshake is refused
//! and there is no plaintext path, not behind a flag, not in a test. A `client/init` the server
//! cannot accept is answered with `server/error` and a close; every later handshake failure is
//! silent, as the specification requires.
//!
//! The crate is published as `publish = false` until the server half has stabilised.

mod listener;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

// The identity is part of [`ServerConfig`], so a host that builds a configuration needs it. A
// re-export keeps a consumer from having to depend on the protocol crate directly.
pub use syncspin_core::noise::Identity;

/// The address the listener binds when the configuration does not narrow it.
///
/// Encryption is the boundary, not the bind address: a server that listens on every interface is
/// still only reachable by a client that completes the handshake.
pub const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8927);

/// The WebSocket endpoint the listener serves when the configuration does not name one.
pub const DEFAULT_PATH: &str = "/sendspin";

/// Longest server name `server/hello` may carry, in bytes of UTF-8.
pub const MAX_SERVER_NAME_LEN: usize = 64;

/// Everything a server needs to listen and identify itself.
///
/// [`ServerConfig::new`] fills in the defaults for the address and the endpoint path; the identity
/// belongs to the host, which stores it and keeps it across restarts because the public half is
/// the `server_id` every client associates its pairing record with.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Friendly name the server announces in `server/hello`.
    pub name: String,
    /// Address the listener binds.
    pub bind: SocketAddr,
    /// WebSocket endpoint the listener serves; every other path is refused.
    pub path: String,
    /// Static keypair of the server. The public half is the `server_id`.
    pub identity: Identity,
}

impl ServerConfig {
    /// Builds a configuration with the default address and endpoint path.
    pub fn new(name: impl Into<String>, identity: Identity) -> ServerConfig {
        ServerConfig {
            name: name.into(),
            bind: DEFAULT_BIND,
            path: DEFAULT_PATH.to_owned(),
            identity,
        }
    }

    /// Rejects a name `server/hello` may not carry and a path that is not a `path-absolute`.
    fn validate(self) -> Result<ServerConfig> {
        if self.name.len() > MAX_SERVER_NAME_LEN {
            bail!(
                "the server name is {} bytes of UTF-8, longer than the {MAX_SERVER_NAME_LEN} bytes \
                 `server/hello` allows",
                self.name.len()
            );
        }
        if !self.path.starts_with('/') || self.path.starts_with("//") {
            bail!(
                "the endpoint path {:?} is not a `path-absolute` (RFC 3986, section 3.3): it must \
                 start with one `/` and not with `//`",
                self.path
            );
        }
        if self.path.contains('?') || self.path.contains('#') {
            bail!(
                "the endpoint path {:?} carries a query or a fragment, which is not part of a \
                 `path-absolute`",
                self.path
            );
        }
        Ok(self)
    }
}

/// One change the host has to know about.
///
/// The stream carries the lifecycle of a connection, not its content: a client is reported once it
/// has said who it is, again once the server has decided its roles, and once when it leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A client completed the handshake and sent `client/hello`.
    ///
    /// `client_id` is the client's static public key and stays the same across reconnections;
    /// `name` is the friendly name from `client/hello`.
    ClientConnected {
        /// Static public key of the client, as 43 unpadded base64url characters.
        client_id: String,
        /// Friendly name the client announced.
        name: String,
    },
    /// The client's first `server/activate` was sent.
    ClientActivated {
        /// Versioned roles the connection may use; empty when it may use none.
        roles: Vec<String>,
    },
    /// The connection ended.
    ClientLeft {
        /// Why it ended: the `reason` of a `client/goodbye`, or a short description of a close
        /// the server observed, such as `connection closed` or `server shutdown`.
        reason: String,
    },
}

/// The receiving end of a server's [`Event`] stream.
///
/// [`EventStream::next`] returns `None` once the server has shut down and no connection is left to
/// report. Dropping the stream does not end the server; only [`ServerHandle::shutdown`] does.
#[derive(Debug)]
pub struct EventStream {
    events: mpsc::UnboundedReceiver<Event>,
}

impl EventStream {
    /// Waits for the next event.
    pub async fn next(&mut self) -> Option<Event> {
        self.events.recv().await
    }
}

/// Namespaced entry point, for callers that prefer a type to the free function.
#[derive(Debug, Clone, Copy, Default)]
pub struct Server;

impl Server {
    /// Binds the configured address and starts accepting clients.
    ///
    /// The listener runs in a task of its own and every connection in one more, so this returns as
    /// soon as the address is bound. A failure to bind is reported here; a client that cannot
    /// complete the handshake is not an error of the server and only shows up as the absence of a
    /// [`Event::ClientConnected`].
    ///
    /// # Errors
    /// Returns an error for a configuration the protocol forbids - a name longer than
    /// [`MAX_SERVER_NAME_LEN`], a path that is not a `path-absolute` - and for an address this
    /// build cannot bind.
    ///
    /// # Panics
    /// Panics when called outside a Tokio runtime, because the listener is spawned.
    pub async fn start(config: ServerConfig) -> Result<ServerHandle> {
        let config = config.validate()?;
        let bound = TcpListener::bind(config.bind)
            .await
            .with_context(|| format!("failed to bind the listener to {}", config.bind))?;
        let local_addr = bound
            .local_addr()
            .context("failed to read the listener's address")?;
        let (events, event_stream) = mpsc::unbounded_channel();
        let (shutdown, shutdown_signal) = watch::channel(false);
        let task = tokio::spawn(listener::run(bound, config, events, shutdown_signal));
        Ok(ServerHandle {
            task: Some(task),
            event_stream: Some(event_stream),
            shutdown,
            local_addr,
        })
    }
}

/// A running server.
///
/// The handle owns the listener task and the event stream. [`ServerHandle::events`] hands the
/// stream out once; [`ServerHandle::shutdown`] ends the server, and dropping the handle does the
/// same without waiting for it.
#[derive(Debug)]
pub struct ServerHandle {
    task: Option<JoinHandle<Result<()>>>,
    event_stream: Option<mpsc::UnboundedReceiver<Event>>,
    shutdown: watch::Sender<bool>,
    local_addr: SocketAddr,
}

impl ServerHandle {
    /// Returns the address the listener is bound to.
    ///
    /// It differs from [`ServerConfig::bind`] when the configuration asked for port 0, which is
    /// what a test does to leave the choice of port to the operating system.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Hands out the event stream.
    ///
    /// There is one consumer of the lifecycle, so this can be called once; a second call returns a
    /// stream that has already ended.
    pub fn events(&mut self) -> EventStream {
        let events = self.event_stream.take().unwrap_or_else(|| {
            let (events, receiver) = mpsc::unbounded_channel();
            drop(events);
            receiver
        });
        EventStream { events }
    }

    /// Stops the listener and closes every live connection.
    ///
    /// A connection that is still open receives a WebSocket close before its task ends, and the
    /// listener waits for the tasks it spawned. The handle is consumed: after this, the event
    /// stream reports the connections that left and then ends.
    ///
    /// # Errors
    /// Returns an error when the listener task failed, for example because an accept call failed.
    pub async fn shutdown(mut self) -> Result<()> {
        let _ = self.shutdown.send(true);
        let task = self.task.take().expect("the handle owns its task");
        task.await.context("the listener task panicked")?
    }
}

impl Drop for ServerHandle {
    /// Signals the listener and drops its task, which closes the port.
    ///
    /// Dropping is the abrupt way out: a connection is closed without the graceful close frame
    /// [`ServerHandle::shutdown`] sends. It exists so that a handle that is dropped cannot leave a
    /// listener behind on the address.
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            let _ = self.shutdown.send(true);
            task.abort();
        }
    }
}

/// Returns the version of this crate as recorded in its manifest.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_the_workspace_version() {
        assert_eq!(version(), "0.1.2");
    }

    #[test]
    fn a_configuration_with_defaults_uses_the_server_defaults() {
        let config = ServerConfig::new("a server", Identity::generate());
        assert_eq!(config.bind, DEFAULT_BIND);
        assert_eq!(config.bind.port(), 8927);
        assert!(config.bind.ip().is_unspecified());
        assert_eq!(config.path, "/sendspin");
    }

    #[test]
    fn a_name_longer_than_server_hello_allows_is_rejected() {
        let mut config =
            ServerConfig::new("a".repeat(MAX_SERVER_NAME_LEN + 1), Identity::generate());
        assert!(config.clone().validate().is_err());
        config.name = "a".repeat(MAX_SERVER_NAME_LEN);
        assert!(
            config.validate().is_ok(),
            "a name of exactly the limit is accepted"
        );
    }

    #[test]
    fn a_path_that_is_not_absolute_is_rejected() {
        for path in ["", "sendspin", "//sendspin", "/sendspin?x=1", "/sendspin#f"] {
            let mut config = ServerConfig::new("a server", Identity::generate());
            config.path = path.to_owned();
            assert!(
                config.validate().is_err(),
                "{path:?} must not be accepted as an endpoint path"
            );
        }
        let mut config = ServerConfig::new("a server", Identity::generate());
        config.path = "/".to_owned();
        assert!(config.validate().is_ok(), "the root path is absolute");
    }
}
