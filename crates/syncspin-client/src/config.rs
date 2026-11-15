//! Connection configuration.

use std::fmt;
use std::time::Duration;

use anyhow::{bail, Result};
use syncspin_core::noise::Identity;

use crate::client::MAX_VOLUME;

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

/// Limits the session applies to a volume request.
///
/// A request at or below [`threshold`](VolumePolicy::threshold) is applied as asked, whether it
/// raises or lowers the level. Above the threshold, one request may raise the level by at most
/// [`max_step`](VolumePolicy::max_step); a lower request is still applied as asked, because the
/// limit bounds raises only. The configuration validation rejects a policy that cannot describe a
/// valid level before a connection is attempted.
///
/// [`VolumePolicy::default`] is the rule [`clamp_volume`](crate::clamp_volume) implements, so a
/// host that does not configure a policy keeps the behaviour of earlier releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumePolicy {
    /// At or below this level a request is applied as is, in the protocol's 0-100 range.
    pub threshold: u8,
    /// Above the threshold, at most this much may be added per command.
    pub max_step: u8,
    /// Whether a request above the threshold may always rise to the threshold itself.
    ///
    /// With `false` a low level creeps up by [`max_step`](VolumePolicy::max_step) per command, so
    /// 1 + a request for 100 yields 21. With `true` the same request yields the threshold, 40,
    /// because a level below the threshold may always reach it in one step.
    pub threshold_floor: bool,
}

impl Default for VolumePolicy {
    /// Returns the policy [`clamp_volume`](crate::clamp_volume) implements.
    fn default() -> Self {
        Self {
            threshold: 40,
            max_step: 20,
            threshold_floor: false,
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

/// What the client announces about the device it runs on.
///
/// The server shows these values to the operator, so they name the hardware rather than the
/// protocol: a product name and a manufacturer are always sent, and the software version and MAC
/// address are sent when the host knows them. The fields are plain text; the crate sends them as
/// the host provides them, so their content and length belong to the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Device model or product name.
    pub product_name: String,
    /// Device manufacturer.
    pub manufacturer: String,
    /// Software version of the host application, not the protocol version.
    pub software_version: Option<String>,
    /// Network interface MAC address as lowercase colon-separated bytes.
    pub mac_address: Option<String>,
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
    /// Description of the device the client runs on, announced in `client/hello`.
    ///
    /// The server displays it to the operator. A host that does not know the hardware passes
    /// `None` and no `device_info` object is sent, so the server shows only the player name.
    pub device_info: Option<DeviceInfo>,
    /// Long-lived keypair that identifies this client.
    ///
    /// Restore a stored keypair with [`Identity::from_secret_base64`]; generating a fresh one
    /// makes the server treat the player as a new device.
    pub identity: Identity,
    /// Whether the sink receives samples or encoded frames.
    pub audio_mode: AudioMode,
    /// Output level to start from, in the protocol's 0-100 range.
    ///
    /// The session reports this level in its first `client/state` and applies the volume limit
    /// against it, so a host passes the level it restored instead of an invented one. A host
    /// without a stored level passes 100, which neither attenuates nor limits an incoming request.
    pub volume: u8,
    /// Mute state to start from.
    ///
    /// Reported in the first `client/state`; a host without a stored state passes `false`.
    pub muted: bool,
    /// Limits applied to every volume request.
    ///
    /// The session applies the policy to a command from the server and to a level the host sets
    /// through [`ControlHandle::set_volume`](crate::ControlHandle::set_volume); the value it
    /// reports back is always the applied one. [`VolumePolicy::default`] keeps the fixed rule of
    /// earlier releases.
    pub volume_policy: VolumePolicy,
    /// Upper bound for the delay between reconnects.
    ///
    /// The connection reports a recommended delay in
    /// [`Event::Disconnected`](crate::Event::Disconnected) and waits it before the next attempt;
    /// [`next_backoff`](crate::next_backoff) never returns more than this.
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
        if self.volume > MAX_VOLUME {
            bail!(
                "ClientConfig::volume is {}, outside the 0-{MAX_VOLUME} the protocol defines",
                self.volume
            );
        }
        if self.volume_policy.threshold > MAX_VOLUME {
            bail!(
                "ClientConfig::volume_policy.threshold is {}, outside the 0-{MAX_VOLUME} level \
                 range",
                self.volume_policy.threshold
            );
        }
        if self.volume_policy.max_step > MAX_VOLUME {
            bail!(
                "ClientConfig::volume_policy.max_step is {}, outside the 0-{MAX_VOLUME} step \
                 range",
                self.volume_policy.max_step
            );
        }
        if self.max_backoff.is_zero() {
            bail!("ClientConfig::max_backoff must not be zero");
        }
        Ok(())
    }
}
