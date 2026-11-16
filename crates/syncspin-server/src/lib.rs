//! Server side of Sendspin.
//!
//! Planned for `0.2`: listener, streams, role handling, pairing as a server and mDNS
//! discovery in both directions. The crate is published as `publish = false` until that work
//! has stabilised.
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
        assert_eq!(version(), "0.1.2");
    }
}
