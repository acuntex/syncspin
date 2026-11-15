//! Client side of Sendspin.
//!
//! This crate owns the session: it connects to a server, runs the Noise handshake, keeps a clock
//! estimate and feeds audio to a sink the host provides. It stays device agnostic - the
//! application that owns the speakers implements [`Sink`] and decides what playout means.
//!
//! A connection always ends in Noise: the client refuses a server that does not complete the
//! handshake and never falls back to cleartext. A successful attempt reports [`Event::Connected`]
//! and then one event per change; an attempt that ends reports [`Event::Disconnected`] with the
//! delay before the next one, and the crate reconnects on its own with the same sink and identity.
//!
//! [`connect`] validates the configuration and opens the first WebSocket; everything after that
//! runs in a spawned task and reaches the caller through the [`EventStream`]. The [`ClientHandle`]
//! waits for the connection to end and hands out a [`ControlHandle`] for transport commands, the
//! volume level and mute state. The level follows a fixed limit - see [`clamp_volume`] - and the
//! value the server receives is the applied one. [`ClientConfig::volume`] and
//! [`ClientConfig::muted`] are the level and mute state the first report carries, so a host passes
//! the values it restored instead of letting the server see a baseline the output is not at.
//!
//! The connection keeps running until the audio sink fails, which the host has to repair, or until
//! the handle or the event stream is dropped.

mod client;
mod config;
mod session;
mod sink;

pub use client::{
    clamp_volume, connect, connect_with_psks, next_backoff, Client, ClientHandle, ControlHandle,
    Event, EventStream, PlaybackState, INITIAL_BACKOFF,
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
