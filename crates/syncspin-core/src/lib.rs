//! Protocol core for Sendspin.
//!
//! This crate owns everything that is shared between client and server and that must exist
//! exactly once: the Noise handshake, message framing, the message types and the clock filter.
//! It knows no transport and no device integration, and it never depends on the
//! `syncspin-client` or `syncspin-server` crates.
//!
//! Both halves use it: the Noise layer carries [`noise::Responder`] for the client and
//! [`noise::Initiator`] for the server, over both cipher suites the specification names. Beyond
//! that this crate holds the message types, the framing layer with fragmentation, the clock filter,
//! and the pairing primitives — the token, the CPace code flow and the AEAD that seals its values
//! behind `pairing-code`. It is the protocol and the crypto; the connection state machines live in
//! the `syncspin-client` and `syncspin-server` crates.

pub mod clock;
pub mod framing;
pub mod messages;
pub mod noise;
pub mod pairing;

/// Returns the version of this crate as recorded in its manifest.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_the_workspace_version() {
        assert_eq!(version(), "0.3.0");
    }
}
