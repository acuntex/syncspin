//! Advertise-only discovery: publish the server record, never dial a client.

// Task 5 hands the wrapper to `Server::start`; until then this module's only consumer is its test,
// so the allowance covers the gap between the two steps and goes away with it.
#![allow(dead_code)]

use std::sync::Arc;

use anyhow::Result;
use syncspin_server::{DiscoveredClient, Discovery, ServiceAdvertisement};

/// A [`Discovery`] that publishes a record and reports no clients at all.
///
/// [`Server::start`] with a discovery backend spawns a task that browses `_sendspin._tcp` every ten
/// seconds and dials every client advertising there. This example runs both roles in one process, so
/// that task would dial whatever unrelated client happens to be on the LAN, which is not the pairing
/// the run is meant to show. Advertising through the real backend keeps the record genuine, and an
/// empty browse is what keeps the server from dialling anyone: the wrapper never asks the backend.
///
/// [`Server::start`]: syncspin_server::Server::start
pub struct AdvertiseOnly {
    /// The backend that publishes and withdraws; its browser is never used.
    inner: Arc<dyn Discovery>,
}

impl AdvertiseOnly {
    /// Wraps `inner`, forwarding the advertisement calls and dropping the browsing half.
    pub fn new(inner: Arc<dyn Discovery>) -> Self {
        Self { inner }
    }
}

impl Discovery for AdvertiseOnly {
    fn advertise(&self, service: ServiceAdvertisement) -> Result<()> {
        self.inner.advertise(service)
    }

    fn withdraw(&self, service_type: &str) -> Result<()> {
        self.inner.withdraw(service_type)
    }

    fn browse(&self, _service_type: &str) -> Result<Vec<DiscoveredClient>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use syncspin_server::{DiscoveredClient, Discovery, ServiceAdvertisement};

    #[derive(Default)]
    struct Fake {
        advertised: AtomicUsize,
        withdrawn: AtomicUsize,
    }

    impl Discovery for Fake {
        fn advertise(&self, _service: ServiceAdvertisement) -> anyhow::Result<()> {
            self.advertised.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn withdraw(&self, _service_type: &str) -> anyhow::Result<()> {
            self.withdrawn.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn browse(&self, _service_type: &str) -> anyhow::Result<Vec<DiscoveredClient>> {
            panic!("the wrapper must never dial")
        }
    }

    #[test]
    fn advertise_and_withdraw_pass_through_and_browse_is_empty() {
        let fake = std::sync::Arc::new(Fake::default());
        let wrapper = AdvertiseOnly::new(fake.clone());
        let service = ServiceAdvertisement::server(8927, "/sendspin", "mdns-pair");

        wrapper
            .advertise(service)
            .expect("the advertisement is forwarded");
        wrapper
            .withdraw("_sendspin-server._tcp.local.")
            .expect("the withdrawal is forwarded");
        assert!(wrapper
            .browse("_sendspin._tcp.local.")
            .expect("a browse is answered")
            .is_empty());
        assert_eq!(fake.advertised.load(Ordering::SeqCst), 1);
        assert_eq!(fake.withdrawn.load(Ordering::SeqCst), 1);
    }
}
