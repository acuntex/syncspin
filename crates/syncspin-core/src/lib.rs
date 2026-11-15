//! Protocol core for Sendspin.
//!
//! This crate owns everything that is shared between client and server and that must exist
//! exactly once: the Noise handshake, message framing, the message types and the clock filter.
//! It knows no transport and no device integration, and it never depends on the
//! `syncspin-client` or `syncspin-server` crates.
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
