//! Client side of Sendspin.
//!
//! This crate owns the session: it connects to a server, runs the Noise handshake, keeps a clock
//! estimate and feeds audio to a sink the host provides. It stays device agnostic - the
//! application that owns the speakers implements [`Sink`] and decides what playout means.
//!
//! A connection always ends in Noise: the client refuses a server that does not complete the
//! handshake and never falls back to cleartext. A successful connection reports
//! [`Event::Connected`] and then one event per change on the connection, ending with at most one
//! [`Event::Disconnected`].
//!
//! [`connect`] validates the configuration and opens the WebSocket; everything after that runs in
//! a spawned task and reaches the caller through the [`EventStream`]. The [`ClientHandle`] waits
//! for the task's outcome.

mod client;
mod config;
mod session;
mod sink;

pub use client::{
    connect, connect_with_psks, Client, ClientHandle, Event, EventStream, PlaybackState,
};
pub use config::{AudioMode, ClientConfig, PskCategory, StoredPsk, MAX_PLAYER_NAME_LEN};
pub use sink::{AudioFormat, AudioFrame, Codec, Sink};

// The identity is part of [`ClientConfig`], so a host that builds a configuration needs it. A
// re-export keeps a consumer from having to depend on the protocol crate directly.
pub use syncspin_core::noise::Identity;

/// Returns the version of this crate as recorded in its manifest.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_the_workspace_version() {
        assert_eq!(version(), "0.1.0");
    }
}
