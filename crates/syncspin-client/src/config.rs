//! Connection configuration.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use syncspin_core::noise::Identity;

use crate::client::MAX_VOLUME;
use crate::storage::Storage;

/// Longest player name the protocol allows, in bytes of UTF-8.
pub const MAX_PLAYER_NAME_LEN: usize = 64;

/// Longest delay between reconnect attempts a configuration starts with.
///
/// [`ClientConfig::new`] uses it; a host that wants a longer or shorter ceiling sets
/// [`ClientConfig::max_backoff`] itself.
pub const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Number of digits in a static pairing code.
///
/// The protocol fixes the length at eight decimal digits, so a configured code is exactly this
/// many ASCII characters.
#[cfg(feature = "pairing-code")]
pub const STATIC_PAIRING_CODE_LEN: usize = 8;

/// Longest `client/pair-pending` message the protocol allows, in bytes of UTF-8.
#[cfg(feature = "pairing-code")]
pub const MAX_PAIRING_PENDING_TEXT_LEN: usize = 200;

/// How long an operator-opened pairing window admits attempts.
///
/// `pairing.md` recommends five minutes and starts the clock at the gesture, not at the first
/// attempt.
#[cfg(feature = "pairing-code")]
pub const DEFAULT_PAIRING_WINDOW: Duration = Duration::from_secs(300);

/// Emission format of a dynamic pairing code.
///
/// `pairing.md` defines two: `digits`, a six-digit decimal code the operator types into the
/// server, and `qr_code`, a 24-byte code presented as a version-1 pairing token in a QR code. The
/// format is chosen per connection by the server's `server/activate`, from the formats the client
/// advertises; it decides how a host presents the code and what CPace's `PRS` is.
#[cfg(feature = "pairing-code")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeFormat {
    /// Six decimal digits.
    Digits,
    /// A 24-byte code as a version-1 pairing token.
    QrCode,
}

#[cfg(feature = "pairing-code")]
impl CodeFormat {
    /// Returns the identifier the wire and `client/hello` use.
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            CodeFormat::Digits => "digits",
            CodeFormat::QrCode => "qr_code",
        }
    }

    /// Decodes an emission format from the wire, or `None` for a value this revision does not know.
    pub(crate) fn from_wire(value: &str) -> Option<CodeFormat> {
        match value {
            "digits" => Some(CodeFormat::Digits),
            "qr_code" => Some(CodeFormat::QrCode),
            _ => None,
        }
    }
}

/// Channel a dynamic pairing code reaches the operator through.
///
/// The client advertises the channels its host can actually drive. `display` covers a screen, an
/// e-ink panel or a seven-segment display; `speaker` covers a device that speaks the code from
/// audio it bundles itself. The crate derives the code and emits it; rendering and speaking belong
/// to the host.
#[cfg(feature = "pairing-code")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeOutChannel {
    /// A display the host renders the code on.
    Display,
    /// A speaker the host plays the code through.
    Speaker,
}

#[cfg(feature = "pairing-code")]
impl CodeOutChannel {
    /// Returns the identifier the wire and `client/hello` use.
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            CodeOutChannel::Display => "display",
            CodeOutChannel::Speaker => "speaker",
        }
    }
}

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

    /// Encodes the category the way the wire and a stored record spell it.
    ///
    /// The inverse of [`from_wire`](PskCategory::from_wire), so a backend this crate ships can
    /// write a record it reads back with the same meaning.
    #[cfg(feature = "storage-file")]
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            PskCategory::LongTerm => "lt",
            PskCategory::Pairing => "pr",
            PskCategory::Sentinel => "sn",
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
#[derive(Clone)]
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
    /// Where the pairing PSK and the pairing records live, or `None` for a guest-only client.
    ///
    /// The host owns the store; see [`Storage`]. With a store the client offers the Pairing PSK
    /// method, keeps one pairing PSK across restarts and writes a record for every completed
    /// pairing. Without one it offers no pairing method at all: it never draws a key it cannot
    /// hand back, and it answers a pairing activation with `pair/abort` reason
    /// `method_not_supported`. A plain guest session is unchanged either way.
    pub storage: Option<Arc<dyn Storage>>,
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
    /// Whether a `group_id` outside the spec's 43 base64url characters closes the connection.
    ///
    /// The spec makes such a value a protocol error, and with `true` the client behaves that way:
    /// the attempt ends and [`Event::Disconnected`](crate::Event::Disconnected) reports why.
    ///
    /// The default is `false`. A non-canonical but well-formed identifier - non-empty, at most 128
    /// bytes, valid UTF-8 without control characters - is then accepted as an opaque string and
    /// reported once per connection as [`Event::GroupIdNotCanonical`](crate::Event::GroupIdNotCanonical).
    /// That tolerance exists because a real server sends a UUID instead; see
    /// `docs/spec-deviations.md`. A host that talks to a conformant server, or that wants the
    /// spec's rule enforced, sets this to `true`.
    pub strict_group_id: bool,
    /// Whether this client admits a server with no pairing record.
    ///
    /// The value is advertised in `client/hello` as `unpaired_access.enabled` and both sides act on
    /// it. With `false` this client refuses to activate a session that is not keyed by a long-term
    /// PSK for playback: such a `server/activate` ends the connection with `client/goodbye` reason
    /// `pairing_required`. A server that honours the advertisement grants no roles to an unpaired
    /// client whose hello says `false`. Pairing is unaffected: both pairing flows run over a
    /// Sentinel-keyed session and stay admissible.
    ///
    /// The value can change while the client runs:
    /// [`ControlHandle::set_unpaired_access`](crate::ControlHandle::set_unpaired_access) stores a new
    /// value, which the next `client/hello` advertises and the activation guard enforces. Enabling it
    /// on an unpaired session forces that hello by reconnecting. This field is the value each
    /// `connect` call starts from.
    ///
    /// `pairing.md` leaves the default to the manufacturer and recommends `false` for a client whose
    /// input a stranger could reach, such as a microphone. The default here is `true`, which is what
    /// every release before this setting did.
    pub unpaired_access: bool,
    /// How long one pairing attempt may run, measured from `client/pair-init`.
    ///
    /// On expiry the client sends `pair/abort` with reason `attempt_timeout` and reports
    /// [`Event::PairingFailed`](crate::Event::PairingFailed). The protocol recommends two minutes,
    /// which is [`DEFAULT_PAIRING_TIMEOUT`](crate::DEFAULT_PAIRING_TIMEOUT); a host shortens it
    /// only for tests or for a deployment that wants a tighter bound.
    pub pairing_timeout: Duration,
    /// The operator-facing static pairing code, exactly eight decimal digits.
    ///
    /// The code is configuration, never generated: a manufacturer provisions one per device, and
    /// the operator reads it off the device or its leaflet. Offering the static code method in
    /// `client/hello` depends on this field being set, so a client without a code never advertises
    /// a method it cannot complete.
    ///
    /// The code is a credential: anyone who knows it and can reach the server may pair. It is
    /// never formatted - [`ClientConfig`]'s `Debug` prints it redacted - and never logged.
    #[cfg(feature = "pairing-code")]
    pub static_pairing_code: Option<String>,
    /// How long an operator-opened pairing window admits attempts, recommended five minutes.
    ///
    /// The window runs from [`ControlHandle::open_pairing_window`](crate::ControlHandle::open_pairing_window)
    /// and does not pause during an attempt. On expiry it closes silently; an attempt already in
    /// progress runs to its own end.
    #[cfg(feature = "pairing-code")]
    pub pairing_window: Duration,
    /// Sentence sent in `client/pair-pending`, in the host's language.
    ///
    /// A host that wants to tell the operator what to do sets it here; without one the message is
    /// sent with no text, because the crate does not invent operator-facing prose.
    #[cfg(feature = "pairing-code")]
    pub pairing_pending_text: Option<String>,
    /// Emission formats the client offers for a dynamic pairing code.
    ///
    /// An empty list offers no dynamic method at all; a non-empty one advertises
    /// `dynamic_pairing_code` in `client/hello`, together with [`ClientConfig::code_out_channels`].
    /// Both lists must be set for the method to be offered, because the protocol treats a
    /// descriptor left without a known format or channel as unrecognized. The code itself is
    /// derived per attempt, never configured.
    #[cfg(feature = "pairing-code")]
    pub code_formats: Vec<CodeFormat>,
    /// Channels the host can carry a dynamic pairing code through.
    ///
    /// The host sets what it can render or speak; the server picks the method's format, and the
    /// client emits the code through [`Event::PairingCode`](crate::Event::PairingCode).
    #[cfg(feature = "pairing-code")]
    pub code_out_channels: Vec<CodeOutChannel>,
    /// The server-initiated half of the connection mode, or `None` for client-initiated
    /// connections.
    ///
    /// Setting it makes [`advertise`](crate::advertise) publish `_sendspin._tcp` and accept the
    /// servers that connect, and makes a manual [`connect`](crate::connect) fail: `connection.md`
    /// lets a client use one of the two methods at a time, never both. [`Inbound::new`] fills the
    /// listen address and the path with the values the spec recommends.
    ///
    /// [`Inbound::new`]: crate::Inbound::new
    #[cfg(feature = "discovery")]
    pub inbound: Option<crate::Inbound>,
}

impl fmt::Debug for ClientConfig {
    /// Formats the configuration without the store and without key material.
    ///
    /// The store holds the pairing PSK and the records, and its own `Debug` is the host's; the
    /// identity redacts its secret. Neither is delegated to here, so a `Debug` log of a
    /// configuration cannot leak a key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ClientConfig");
        debug
            .field("server", &self.server)
            .field("player_name", &self.player_name)
            .field("device_info", &self.device_info)
            .field("identity", &self.identity)
            .field("storage", &self.storage.as_ref().map(|_| "<host storage>"))
            .field("audio_mode", &self.audio_mode)
            .field("volume", &self.volume)
            .field("muted", &self.muted)
            .field("volume_policy", &self.volume_policy)
            .field("max_backoff", &self.max_backoff)
            .field("strict_group_id", &self.strict_group_id)
            .field("unpaired_access", &self.unpaired_access)
            .field("pairing_timeout", &self.pairing_timeout);
        // The static code is a credential, so it is named but never printed.
        #[cfg(feature = "pairing-code")]
        debug
            .field(
                "static_pairing_code",
                &self.static_pairing_code.as_ref().map(|_| "<redacted>"),
            )
            .field("pairing_window", &self.pairing_window)
            .field("pairing_pending_text", &self.pairing_pending_text)
            .field("code_formats", &self.code_formats)
            .field("code_out_channels", &self.code_out_channels);
        // The backend's own `Debug` belongs to the host, so it is named rather than delegated to;
        // `Inbound`'s format does the same for the backend it holds.
        #[cfg(feature = "discovery")]
        debug.field("inbound", &self.inbound);
        debug.finish()
    }
}

impl ClientConfig {
    /// Builds a configuration for `server` with the crate's defaults.
    ///
    /// Everything a host rarely changes starts at a documented value: no device description, no
    /// pairing store, [`AudioMode::Decode`], volume 100 and unmuted, [`VolumePolicy::default`],
    /// [`DEFAULT_MAX_BACKOFF`], the tolerated foreign `group_id`, unpaired access admitted, and
    /// [`DEFAULT_PAIRING_TIMEOUT`](crate::DEFAULT_PAIRING_TIMEOUT). A
    /// host that restores a level or a mute state sets [`ClientConfig::volume`] and
    /// [`ClientConfig::muted`] on the value this returns.
    ///
    /// The fields stay public, so a host can also build the struct itself and name every field.
    pub fn new(
        server: impl Into<String>,
        player_name: impl Into<String>,
        identity: Identity,
    ) -> ClientConfig {
        ClientConfig {
            server: server.into(),
            player_name: player_name.into(),
            device_info: None,
            identity,
            storage: None,
            audio_mode: AudioMode::Decode,
            volume: 100,
            muted: false,
            volume_policy: VolumePolicy::default(),
            max_backoff: DEFAULT_MAX_BACKOFF,
            // The documented tolerance is the default: a foreign group id does not close the
            // connection unless the host asks for the spec's strictness.
            strict_group_id: false,
            // Earlier releases admitted every session, so the setting starts where they left off.
            unpaired_access: true,
            pairing_timeout: crate::DEFAULT_PAIRING_TIMEOUT,
            #[cfg(feature = "pairing-code")]
            static_pairing_code: None,
            #[cfg(feature = "pairing-code")]
            pairing_window: DEFAULT_PAIRING_WINDOW,
            #[cfg(feature = "pairing-code")]
            pairing_pending_text: None,
            #[cfg(feature = "pairing-code")]
            code_formats: Vec::new(),
            #[cfg(feature = "pairing-code")]
            code_out_channels: Vec::new(),
            // The client-initiated mode is the default: nothing is advertised and nothing listens.
            #[cfg(feature = "discovery")]
            inbound: None,
        }
    }

    /// Rejects a configuration that would put invalid fields on the wire.
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_common()?;
        if self.server.trim().is_empty() {
            bail!("ClientConfig::server must not be empty");
        }
        Ok(())
    }

    /// Rejects the fields both connection modes share.
    ///
    /// A server that advertises and accepts connections names no server address, so the address
    /// check belongs to [`validate`](ClientConfig::validate) alone and the inbound listener
    /// validates without it.
    pub(crate) fn validate_common(&self) -> Result<()> {
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
        if self.pairing_timeout.is_zero() {
            bail!("ClientConfig::pairing_timeout must not be zero");
        }
        #[cfg(feature = "pairing-code")]
        {
            if let Some(code) = &self.static_pairing_code {
                if code.len() != STATIC_PAIRING_CODE_LEN
                    || !code.bytes().all(|byte| byte.is_ascii_digit())
                {
                    // The code itself is a credential, so the error names the shape, never the
                    // value the host passed.
                    bail!(
                        "ClientConfig::static_pairing_code must be {STATIC_PAIRING_CODE_LEN} \
                         ASCII digits"
                    );
                }
            }
            if self.pairing_window.is_zero() {
                bail!("ClientConfig::pairing_window must not be zero");
            }
            if let Some(text) = &self.pairing_pending_text {
                if text.len() > MAX_PAIRING_PENDING_TEXT_LEN {
                    bail!(
                        "ClientConfig::pairing_pending_text is {} bytes, more than the \
                         {MAX_PAIRING_PENDING_TEXT_LEN} the protocol allows",
                        text.len()
                    );
                }
            }
            // A descriptor with formats but no channel - or the other way round - is one a server
            // treats as unrecognized, so the client would advertise a method it cannot complete.
            if self.code_formats.is_empty() != self.code_out_channels.is_empty() {
                bail!(
                    "ClientConfig::code_formats and ClientConfig::code_out_channels must both be \
                     set or both be empty"
                );
            }
        }
        // The path becomes TXT record content and the endpoint the listener serves, so it has to be
        // a `path-absolute` (RFC 3986) the other side can append to an authority: a leading slash,
        // and not the `//authority` form.
        #[cfg(feature = "discovery")]
        if let Some(inbound) = &self.inbound {
            if !inbound.path.starts_with('/') || inbound.path.starts_with("//") {
                bail!(
                    "ClientConfig::inbound.path must be an absolute path such as \
                     \"/sendspin\", not a relative one and not one starting with //"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configuration that passes validation, for tests that change one field.
    fn valid() -> ClientConfig {
        ClientConfig {
            server: "127.0.0.1:1".to_owned(),
            player_name: "Test player".to_owned(),
            device_info: None,
            identity: Identity::generate(),
            storage: None,
            audio_mode: AudioMode::Passthrough,
            volume: 100,
            muted: false,
            volume_policy: VolumePolicy::default(),
            max_backoff: Duration::from_secs(1),
            strict_group_id: false,
            unpaired_access: true,
            pairing_timeout: crate::DEFAULT_PAIRING_TIMEOUT,
            #[cfg(feature = "discovery")]
            inbound: None,
            #[cfg(feature = "pairing-code")]
            static_pairing_code: None,
            #[cfg(feature = "pairing-code")]
            pairing_window: DEFAULT_PAIRING_WINDOW,
            #[cfg(feature = "pairing-code")]
            pairing_pending_text: None,
            #[cfg(feature = "pairing-code")]
            code_formats: Vec::new(),
            #[cfg(feature = "pairing-code")]
            code_out_channels: Vec::new(),
        }
    }

    #[test]
    fn the_constructor_fills_a_configuration_that_validates() {
        let config = ClientConfig::new("127.0.0.1:8927", "Test player", Identity::generate());
        config.validate().expect("the defaults are valid");
        assert_eq!(config.server, "127.0.0.1:8927");
        assert_eq!(config.player_name, "Test player");
        assert_eq!(config.audio_mode, AudioMode::Decode);
        assert_eq!(config.volume, 100);
        assert!(!config.muted);
        assert_eq!(config.max_backoff, DEFAULT_MAX_BACKOFF);
        assert!(
            !config.strict_group_id,
            "the documented tolerance is the default; a host opts into the spec's strictness"
        );
        assert!(
            config.unpaired_access,
            "unpaired access is admitted by default, as every earlier release did"
        );
        assert_eq!(config.pairing_timeout, crate::DEFAULT_PAIRING_TIMEOUT);
        assert!(config.storage.is_none());
        assert!(config.device_info.is_none());
        // The client-initiated mode is what a host gets without asking: nothing advertises and no
        // socket listens until it sets an `Inbound`.
        #[cfg(feature = "discovery")]
        assert!(config.inbound.is_none());
    }

    #[test]
    fn the_pairing_timeout_must_be_positive() {
        let config = ClientConfig {
            pairing_timeout: Duration::ZERO,
            #[cfg(feature = "discovery")]
            inbound: None,
            ..valid()
        };
        let error = config
            .validate()
            .expect_err("a zero timeout would abort every attempt at once");
        assert!(
            format!("{error:#}").contains("pairing_timeout"),
            "the error must name the field, got: {error:#}"
        );
        config_with_default_timeout()
            .validate()
            .expect("120s is valid");
    }

    /// A configuration with the protocol's recommended attempt timeout.
    fn config_with_default_timeout() -> ClientConfig {
        let config = valid();
        assert_eq!(config.pairing_timeout, crate::DEFAULT_PAIRING_TIMEOUT);
        config
    }

    #[test]
    fn a_configuration_debug_names_no_key_material() {
        let store = std::sync::Arc::new(crate::test_support::MemoryStore::holding([7u8; 32]));
        let config = ClientConfig {
            storage: Some(store),
            ..valid()
        };
        let text = format!("{config:?}");
        assert!(text.contains("ClientConfig"), "unexpected format: {text}");
        assert!(
            text.contains("<host storage>"),
            "the store is named but never delegated to: {text}"
        );
        assert!(
            !text.contains(&config.identity.secret_base64()),
            "the identity secret must stay out of a debug format: {text}"
        );
    }

    #[test]
    fn a_stored_psk_formats_without_its_key_material() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let psk = [0xab; 32];
        let record = StoredPsk {
            category: PskCategory::Pairing,
            psk,
            server_id: "B1y4w7z0c3f6i9l2o5r8u1x4a7d0g3j6m9p2s5v8y1b".to_owned(),
        };
        let text = format!("{record:?}");
        assert!(text.contains("StoredPsk"), "unexpected format: {text}");
        assert!(text.contains("Pairing"), "the category is not key material");
        assert!(text.contains("B1y4w7z0c3f6i9l2o5r8u1x4a7d0g3j6m9p2s5v8y1b"));
        assert!(text.contains("<redacted>"));
        assert!(
            !text.contains(&URL_SAFE_NO_PAD.encode(psk)),
            "the key must never appear in a debug format: {text}"
        );
        assert!(
            !text.contains(&format!("{psk:?}")),
            "not even the raw bytes may appear: {text}"
        );
    }

    /// The dynamic method's descriptor needs a format and a channel; one without the other is
    /// treated as unrecognized by a server, so the configuration refuses it before a connection.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn the_code_descriptor_lists_are_set_together() {
        let formats_only = ClientConfig {
            code_formats: vec![CodeFormat::Digits],
            ..valid()
        };
        let error = formats_only
            .validate()
            .expect_err("a format without a channel is not a usable descriptor");
        assert!(
            format!("{error:#}").contains("code_out_channels"),
            "the error names the missing list, got: {error:#}"
        );

        let channels_only = ClientConfig {
            code_out_channels: vec![CodeOutChannel::Display],
            ..valid()
        };
        let error = channels_only
            .validate()
            .expect_err("a channel without a format is not a usable descriptor");
        assert!(
            format!("{error:#}").contains("code_formats"),
            "the error names the missing list, got: {error:#}"
        );

        ClientConfig {
            code_formats: vec![CodeFormat::Digits, CodeFormat::QrCode],
            code_out_channels: vec![CodeOutChannel::Display],
            ..valid()
        }
        .validate()
        .expect("both lists make the method offerable");
    }

    /// The identifiers are the ones `client/hello` and `server/activate` spell.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn the_code_types_round_trip_through_their_wire_names() {
        assert_eq!(CodeFormat::Digits.as_wire(), "digits");
        assert_eq!(CodeFormat::QrCode.as_wire(), "qr_code");
        assert_eq!(CodeFormat::from_wire("digits"), Some(CodeFormat::Digits));
        assert_eq!(CodeFormat::from_wire("qr_code"), Some(CodeFormat::QrCode));
        assert_eq!(
            CodeFormat::from_wire("nfc"),
            None,
            "a format this revision does not know selects nothing"
        );
        assert_eq!(CodeOutChannel::Display.as_wire(), "display");
        assert_eq!(CodeOutChannel::Speaker.as_wire(), "speaker");
    }

    #[test]
    fn an_empty_server_address_is_rejected() {
        for server in ["", "   "] {
            let config = ClientConfig {
                server: server.to_owned(),
                ..valid()
            };
            let error = config.validate().expect_err("an empty address has no host");
            assert!(
                format!("{error:#}").contains("server"),
                "the error must name the address, got: {error:#}"
            );
        }
    }

    #[test]
    fn a_player_name_is_bounded_by_the_protocol_length() {
        let longest = ClientConfig {
            player_name: "a".repeat(MAX_PLAYER_NAME_LEN),
            ..valid()
        };
        longest
            .validate()
            .expect("a name at the limit must be accepted");

        let config = ClientConfig {
            player_name: "a".repeat(MAX_PLAYER_NAME_LEN + 1),
            ..valid()
        };
        let error = config
            .validate()
            .expect_err("a name above the limit must be rejected");
        let message = format!("{error:#}");
        assert!(
            message.contains("player_name")
                && message.contains(&(MAX_PLAYER_NAME_LEN + 1).to_string()),
            "the error must name the field and the length, got: {message}"
        );

        let config = ClientConfig {
            player_name: " \t ".to_owned(),
            ..valid()
        };
        let error = config
            .validate()
            .expect_err("a blank name must be rejected");
        assert!(format!("{error:#}").contains("player_name"));
    }

    /// The protocol fixes the code at eight decimal digits; anything else cannot be entered.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_static_pairing_code_is_exactly_eight_digits() {
        for code in ["12345678", "00000000", "99999999"] {
            let config = ClientConfig {
                static_pairing_code: Some(code.to_owned()),
                ..valid()
            };
            config
                .validate()
                .unwrap_or_else(|error| panic!("{code:?} must be accepted: {error:#}"));
        }

        for code in [
            "",
            "1234567",
            "123456789",
            "1234 678",
            "1234567a",
            "--------",
            "１２３４５６７８",
        ] {
            let config = ClientConfig {
                static_pairing_code: Some(code.to_owned()),
                ..valid()
            };
            let error = config
                .validate()
                .expect_err("a code that is not eight digits must be rejected");
            let message = format!("{error:#}");
            assert!(
                message.contains("static_pairing_code"),
                "the error must name the field, got: {message}"
            );
            assert!(
                !message.contains(code) || code.is_empty(),
                "the code is a credential and must not appear in the error: {message}"
            );
        }
    }

    /// The window has no pause, so a zero lifetime would close it before any attempt could start.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn the_pairing_window_and_pending_text_are_bounded() {
        let config = ClientConfig {
            pairing_window: Duration::ZERO,
            ..valid()
        };
        let error = config
            .validate()
            .expect_err("a zero window cannot admit an attempt");
        assert!(
            format!("{error:#}").contains("pairing_window"),
            "the error must name the field, got: {error:#}"
        );

        let longest = ClientConfig {
            pairing_pending_text: Some("a".repeat(MAX_PAIRING_PENDING_TEXT_LEN)),
            ..valid()
        };
        longest
            .validate()
            .expect("a sentence at the limit must be accepted");

        let config = ClientConfig {
            pairing_pending_text: Some("a".repeat(MAX_PAIRING_PENDING_TEXT_LEN + 1)),
            ..valid()
        };
        let error = config
            .validate()
            .expect_err("a sentence above the limit must be rejected");
        assert!(
            format!("{error:#}").contains("pairing_pending_text"),
            "the error must name the field, got: {error:#}"
        );
    }

    /// The static code is a credential, so a `Debug` log of the configuration must not print it.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_static_pairing_code_is_redacted_in_debug() {
        let config = ClientConfig {
            static_pairing_code: Some("12345678".to_owned()),
            ..valid()
        };
        let text = format!("{config:?}");
        assert!(
            text.contains("static_pairing_code: Some(\"<redacted>\")"),
            "the field must be named but redacted: {text}"
        );
        assert!(
            !text.contains("12345678"),
            "the code must never appear in a debug format: {text}"
        );
    }
}
