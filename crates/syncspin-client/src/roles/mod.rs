//! The roles this client takes part in.
//!
//! The list of roles is written once, in [`supported_roles`], so the roles announced in
//! `client/hello` and the roles the activation check admits cannot drift apart.

#[cfg(feature = "artwork")]
pub(crate) mod artwork;
#[cfg(any(feature = "metadata", feature = "artwork"))]
pub(crate) mod sched;

/// Versioned role identifier of the audio player.
#[cfg(feature = "player")]
pub(crate) const PLAYER_ROLE: &str = "player@v1";

/// Versioned role identifier of the now-playing metadata.
#[cfg(feature = "metadata")]
pub(crate) const METADATA_ROLE: &str = "metadata@v1";

/// Versioned role identifier of the artwork display.
#[cfg(feature = "artwork")]
pub(crate) const ARTWORK_ROLE: &str = "artwork@v1";

/// Bare role name artwork uses in `stream/end`, `stream/clear` and binary routing.
#[cfg(feature = "artwork")]
pub(crate) const ARTWORK_STREAM_ROLE: &str = "artwork";

/// Versioned role identifier of the group controller state.
#[cfg(feature = "controller")]
pub(crate) const CONTROLLER_ROLE: &str = "controller@v1";

/// What a connection can carry out, which decides the roles it offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Offer {
    /// Whether the connection has an audio sink, which is what the player role is offered for.
    pub(crate) sink: bool,
    /// Whether the configuration names at least one artwork channel.
    #[cfg(feature = "artwork")]
    pub(crate) artwork: bool,
}

impl Offer {
    /// The offer of a connection with `sink` (or without) and the channels `config` names.
    #[cfg_attr(not(feature = "artwork"), allow(unused_variables))]
    pub(crate) fn new(sink: bool, config: &crate::config::ClientConfig) -> Self {
        Self {
            sink,
            #[cfg(feature = "artwork")]
            artwork: config.artwork_channels.iter().any(Option::is_some),
        }
    }

    /// An offer with a sink and nothing optional, for tests.
    #[cfg(test)]
    pub(crate) const SINK: Offer = Offer {
        sink: true,
        #[cfg(feature = "artwork")]
        artwork: false,
    };
}

/// The roles this client advertises in `client/hello` and admits in `server/activate`.
///
/// The player role is offered exactly with a sink, and only in a build with the `player` feature, so
/// a headless client never advertises a role it cannot carry out. Controller and metadata are offered
/// in the builds that have them; artwork in a build with the feature and at least one configured
/// channel. The order is fixed: player, controller, metadata, artwork.
#[cfg_attr(not(feature = "player"), allow(unused_variables))]
pub(crate) fn supported_roles(offer: Offer) -> Vec<&'static str> {
    let roles: &[Option<&'static str>] = &[
        #[cfg(feature = "player")]
        offer.sink.then_some(PLAYER_ROLE),
        #[cfg(feature = "controller")]
        Some(CONTROLLER_ROLE),
        #[cfg(feature = "metadata")]
        Some(METADATA_ROLE),
        #[cfg(feature = "artwork")]
        offer.artwork.then_some(ARTWORK_ROLE),
    ];
    roles.iter().flatten().copied().collect()
}

/// The roles that are in `new` and not in `old` (added), and in `old` and not in `new` (removed).
///
/// Roles are compared as versioned identifiers, so replacing `controller@v1` by another version of
/// it is a removal and an addition. Order within each list follows the input.
pub(crate) fn role_changes(old: &[String], new: &[String]) -> (Vec<String>, Vec<String>) {
    let added = new
        .iter()
        .filter(|role| !old.contains(role))
        .cloned()
        .collect();
    let removed = old
        .iter()
        .filter(|role| !new.contains(role))
        .cloned()
        .collect();
    (added, removed)
}

/// Refuses to start a client that would have no role to offer.
///
/// A build with none of the role features, and a headless client in a build without `controller`
/// and `metadata`, would send `supported_roles: []`. That connection could never do anything, so
/// the entry points report it before connecting. This is a local policy, not a protocol rule.
pub(crate) fn ensure_roles(offer: Offer) -> anyhow::Result<()> {
    if supported_roles(offer).is_empty() {
        anyhow::bail!(
            "this build of syncspin-client offers no role: enable at least one of the `player`, \
             `controller` and `metadata` features"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_sink(sink: bool) -> Offer {
        let mut offer = Offer::SINK;
        offer.sink = sink;
        offer
    }

    #[cfg(all(feature = "player", feature = "controller", feature = "metadata"))]
    #[test]
    fn a_sink_adds_the_player_role_first() {
        assert_eq!(
            supported_roles(Offer::SINK),
            ["player@v1", "controller@v1", "metadata@v1"]
        );
        assert_eq!(
            supported_roles(Offer {
                sink: false,
                ..Offer::SINK
            }),
            ["controller@v1", "metadata@v1"]
        );
    }

    #[test]
    fn a_role_diff_names_additions_and_removals() {
        let set = |roles: &[&str]| roles.iter().map(|r| (*r).to_owned()).collect::<Vec<_>>();
        let (added, removed) = role_changes(
            &set(&["player@v1", "controller@v1"]),
            &set(&["controller@v1", "metadata@v1"]),
        );
        assert_eq!(
            (added, removed),
            (set(&["metadata@v1"]), set(&["player@v1"]))
        );
        let (added, removed) = role_changes(&set(&["controller@v1"]), &set(&["controller@v2"]));
        assert_eq!(
            (added, removed),
            (set(&["controller@v2"]), set(&["controller@v1"])),
            "a replaced version is removed and added"
        );
        let (added, removed) = role_changes(&set(&["metadata@v1"]), &set(&["metadata@v1"]));
        assert!(added.is_empty() && removed.is_empty());
    }

    #[test]
    fn the_role_check_agrees_with_the_role_list() {
        for sink in [true, false] {
            let offer = with_sink(sink);
            assert_eq!(
                ensure_roles(offer).is_ok(),
                !supported_roles(offer).is_empty()
            );
        }
    }
}
