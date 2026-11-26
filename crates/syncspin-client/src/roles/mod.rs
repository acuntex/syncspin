//! The roles this client takes part in.
//!
//! The list of roles is written once, in [`supported_roles`], so the roles announced in
//! `client/hello` and the roles the activation check admits cannot drift apart.

/// Versioned role identifier of the audio player.
pub(crate) const PLAYER_ROLE: &str = "player@v1";

/// Versioned role identifier of the now-playing metadata.
pub(crate) const METADATA_ROLE: &str = "metadata@v1";

/// Versioned role identifier of the group controller state.
pub(crate) const CONTROLLER_ROLE: &str = "controller@v1";

/// The roles this client advertises in `client/hello` and admits in `server/activate`.
///
/// `sink` says whether the session has an audio sink: the player role is offered exactly then, so
/// a headless client never advertises a role it cannot carry out. The order is fixed: player,
/// controller, metadata.
pub(crate) fn supported_roles(sink: bool) -> Vec<&'static str> {
    let mut roles = Vec::new();
    if sink {
        roles.push(PLAYER_ROLE);
    }
    roles.push(CONTROLLER_ROLE);
    roles.push(METADATA_ROLE);
    roles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sink_adds_the_player_role_first() {
        assert_eq!(
            supported_roles(true),
            ["player@v1", "controller@v1", "metadata@v1"]
        );
        assert_eq!(supported_roles(false), ["controller@v1", "metadata@v1"]);
    }
}
