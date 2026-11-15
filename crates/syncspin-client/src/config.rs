//! Connection configuration.

use std::fmt;
use std::time::Duration;

use anyhow::{bail, Result};
use syncspin_core::noise::Identity;

/// Longest player name the protocol allows, in bytes of UTF-8.
pub const MAX_PLAYER_NAME_LEN: usize = 64;

/// How the client wants the stream delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioMode {
    /// Play raw samples.
    ///
    /// The session advertises PCM only, so the server delivers raw samples and the sink receives
    /// [`AudioFrame::Pcm`](crate::AudioFrame::Pcm). An encoded stream would need a decoder this
    /// build does not carry, so the session rejects one instead of handing encoded bytes to a
    /// sink that expects samples.
    Decode,
    /// Forward encoded frames.
    ///
    /// The session advertises the encoded formats it can forward and the sink receives
    /// [`AudioFrame::Encoded`](crate::AudioFrame::Encoded). A PCM stream still arrives as
    /// [`AudioFrame::Pcm`](crate::AudioFrame::Pcm), because there is nothing to decode.
    Passthrough,
}

/// Category of a pre-shared key, as the server announces it in Noise message 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskCategory {
    /// Long-term pairing key.
    LongTerm,
    /// Key for one pairing attempt.
    Pairing,
    /// The published key that authenticates nothing.
    Sentinel,
}

impl PskCategory {
    /// Decodes the two-letter category from the wire.
    pub(crate) fn from_wire(value: &str) -> Option<PskCategory> {
        match value {
            "lt" => Some(PskCategory::LongTerm),
            "pr" => Some(PskCategory::Pairing),
            "sn" => Some(PskCategory::Sentinel),
            _ => None,
        }
    }
}

/// A pre-shared key the host stores for a known server.
///
/// Selection after Noise message 1 compares the announced category and key id; a match is only
/// accepted when `server_id` equals the one in `server/init`. The key itself is never formatted or
/// logged: `Debug` prints it redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredPsk {
    /// Category the key belongs to.
    pub category: PskCategory,
    /// The 32-byte key.
    pub psk: [u8; 32],
    /// Static public key of the server this key belongs to, as announced in `server/init`.
    pub server_id: String,
}

impl fmt::Debug for StoredPsk {
    /// Formats the record with the key material redacted.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredPsk")
            .field("category", &self.category)
            .field("psk", &"<redacted>")
            .field("server_id", &self.server_id)
            .finish()
    }
}

/// Everything the client needs to open a session.
///
/// The identity is the client's long-lived X25519 keypair. It also becomes the `client_id` the
/// server sees, so reusing it keeps the player recognisable across reconnects; the crate never
/// generates or replaces one on its own.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Server address as `host:port`, or a full `ws://` URL.
    ///
    /// A bare address connects to `ws://<server>/sendspin`. TLS is not part of this build, so a
    /// `wss://` URL is rejected rather than silently downgraded.
    pub server: String,
    /// Friendly name announced to the server, non-empty and at most [`MAX_PLAYER_NAME_LEN`] bytes.
    pub player_name: String,
    /// Long-lived keypair that identifies this client.
    ///
    /// Restore a stored keypair with [`Identity::from_secret_base64`]; generating a fresh one
    /// makes the server treat the player as a new device.
    pub identity: Identity,
    /// Whether the sink receives samples or encoded frames.
    pub audio_mode: AudioMode,
    /// Upper bound for the delay between reconnects.
    ///
    /// The session reports a recommended delay in
    /// [`Event::Disconnected`](crate::Event::Disconnected) but schedules no retry itself; a host
    /// that reconnects applies its own backoff, using the value from
    /// [`next_backoff`](crate::next_backoff) and this as the cap.
    pub max_backoff: Duration,
}

impl ClientConfig {
    /// Rejects a configuration that would put invalid fields on the wire.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.server.trim().is_empty() {
            bail!("ClientConfig::server must not be empty");
        }
        if self.player_name.trim().is_empty() {
            bail!("ClientConfig::player_name must not be empty");
        }
        if self.player_name.len() > MAX_PLAYER_NAME_LEN {
            bail!(
                "ClientConfig::player_name is {} bytes, more than the {MAX_PLAYER_NAME_LEN} the \
                 protocol allows",
                self.player_name.len()
            );
        }
        Ok(())
    }
}
