//! The roles this client takes part in.
//!
//! The list of roles is written once, in [`supported_roles`], so the roles announced in
//! `client/hello` and the roles the activation check admits cannot drift apart.

/// Versioned role identifier of the audio player.
#[cfg(feature = "player")]
pub(crate) const PLAYER_ROLE: &str = "player@v1";

/// Versioned role identifier of the now-playing metadata.
#[cfg(feature = "metadata")]
pub(crate) const METADATA_ROLE: &str = "metadata@v1";

/// Versioned role identifier of the group controller state.
#[cfg(feature = "controller")]
pub(crate) const CONTROLLER_ROLE: &str = "controller@v1";

/// The roles this client advertises in `client/hello` and admits in `server/activate`.
///
/// `sink` says whether the session has an audio sink: the player role is offered exactly then, and
/// only in a build with the `player` feature, so a headless client never advertises a role it
/// cannot carry out. Controller and metadata are offered in the builds that have them. The order is
/// fixed: player, controller, metadata.
#[cfg_attr(not(feature = "player"), allow(unused_variables))]
pub(crate) fn supported_roles(sink: bool) -> Vec<&'static str> {
    let roles: &[Option<&'static str>] = &[
        #[cfg(feature = "player")]
        sink.then_some(PLAYER_ROLE),
        #[cfg(feature = "controller")]
        Some(CONTROLLER_ROLE),
        #[cfg(feature = "metadata")]
        Some(METADATA_ROLE),
    ];
    roles.iter().flatten().copied().collect()
}

/// Refuses to start a client that would have no role to offer.
///
/// A build with none of the role features, and a headless client in a build without `controller`
/// and `metadata`, would send `supported_roles: []`. That connection could never do anything, so
/// the entry points report it before connecting. This is a local policy, not a protocol rule.
pub(crate) fn ensure_roles(sink: bool) -> anyhow::Result<()> {
    if supported_roles(sink).is_empty() {
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

    #[cfg(all(feature = "player", feature = "controller", feature = "metadata"))]
    #[test]
    fn a_sink_adds_the_player_role_first() {
        assert_eq!(
            supported_roles(true),
            ["player@v1", "controller@v1", "metadata@v1"]
        );
        assert_eq!(supported_roles(false), ["controller@v1", "metadata@v1"]);
    }

    #[test]
    fn the_role_check_agrees_with_the_role_list() {
        assert_eq!(
            ensure_roles(true).is_ok(),
            !supported_roles(true).is_empty()
        );
        assert_eq!(
            ensure_roles(false).is_ok(),
            !supported_roles(false).is_empty()
        );
    }
}
