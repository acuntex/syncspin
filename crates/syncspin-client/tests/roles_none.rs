//! A build with no role feature has nothing to offer, so the headless entry points refuse to start
//! instead of sending `supported_roles: []`. The refusal is a local policy, not a protocol rule.
//! `--all-features` never compiles this file, so the per-feature matrix in
//! `scripts/check-roles.sh` is what runs it.

#![cfg(not(any(
    feature = "player",
    feature = "controller",
    feature = "metadata",
    feature = "artwork"
)))]

use syncspin_client::{connect_headless, ClientConfig, Identity};

#[tokio::test]
async fn a_build_without_roles_refuses_to_connect() {
    let config = ClientConfig::new("127.0.0.1:1", "Test display", Identity::generate());
    let Err(error) = connect_headless(config).await else {
        panic!("a client with no role must not start");
    };
    assert!(
        format!("{error:#}").contains("offers no role"),
        "the error names the cause: {error:#}"
    );
}

#[cfg(feature = "discovery")]
#[tokio::test]
async fn a_build_without_roles_refuses_to_advertise() {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use syncspin_client::{
        advertise_headless, DiscoveredServer, Discovery, Inbound, ServiceAdvertisement,
        DEFAULT_SENDSPIN_PATH,
    };

    struct Silent;
    impl Discovery for Silent {
        fn advertise(&self, _service: ServiceAdvertisement) -> anyhow::Result<()> {
            panic!("nothing may be advertised without a role");
        }
        fn withdraw(&self, _service_type: &str) -> anyhow::Result<()> {
            Ok(())
        }
        fn browse(&self, _service_type: &str) -> anyhow::Result<Vec<DiscoveredServer>> {
            Ok(Vec::new())
        }
    }

    let mut config = ClientConfig::new("127.0.0.1:1", "Test display", Identity::generate());
    config.inbound = Some(Inbound {
        discovery: Arc::new(Silent),
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        path: DEFAULT_SENDSPIN_PATH.to_owned(),
    });
    let Err(error) = advertise_headless(config).await else {
        panic!("a client with no role must not advertise");
    };
    assert!(format!("{error:#}").contains("offers no role"));
}
