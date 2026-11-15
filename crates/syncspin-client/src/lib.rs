//! Client side of Sendspin.
//!
//! This crate owns the session loop: connecting to a server, running the Noise handshake,
//! decoding messages, driving the clock filter and feeding audio to a sink implementation that
//! the host provides. It stays device agnostic - the player that owns the speakers supplies the
//! sink.
//!
//! This is a `0.1` work in progress: only the crate skeleton exists so far.

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
