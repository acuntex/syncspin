//! Sendspin wire messages.
//!
//! Every JSON message is an envelope of the form `{"type": "<group>/<name>", "payload": {..}}`.
//! [`Incoming`] classifies one such envelope: deserializing it reads `type` and parses `payload`
//! into the matching struct, and serializing a variant writes the envelope back, so a session
//! needs one type for both directions.
//!
//! The opening messages of a connection — `client/init`, `server/init` and `noise/handshake` —
//! travel as cleartext text before the Noise handshake; every later JSON message travels inside a
//! Noise transport message with binary message id `0`. The structs here do not know which phase
//! they belong to.
//!
//! Parsing is lenient in the direction a receiver needs it: unknown fields are ignored, and
//! fields the specification allows to be absent default. A `type` this revision does not define
//! is an error, never a silent default, so the caller decides whether to ignore the message.

use std::fmt;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Core message format version carried by `client/init` and `server/init`.
///
/// Both sides send `1`; a peer that sends another value is speaking a different core format.
pub const PROTOCOL_VERSION: u32 = 1;

/// Noise cipher suite name carried by `client/init`.
///
/// This is the suite the client of this library announces,
/// [`Suite::ChaChaPoly`](crate::noise::Suite::ChaChaPoly). A server MUST support both suites in
/// [`Suite::ALL`](crate::noise::Suite::ALL), so the choice lives with the client and the server
/// reads it from `client/init` rather than negotiating.
pub const NOISE_SUITE: &str = crate::noise::Suite::ChaChaPoly.wire_name();

/// Binary message id of a player audio chunk.
pub const AUDIO_CHUNK_ID: u8 = 4;

// ---------------------------------------------------------------------------
// Handshake: cleartext, before the Noise transport
// ---------------------------------------------------------------------------

/// `client/init`: the client's opening message on a connection.
///
/// `client_id` is the client's static X25519 public key, base64url-encoded without padding, and
/// stays the same across reconnections so a server can recognise the client. `suite` names the
/// Noise cipher suite the client picked for this connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientInit {
    /// Static public key as 43 base64url characters without padding.
    pub client_id: String,
    /// Core message format version, [`PROTOCOL_VERSION`].
    pub version: u32,
    /// Noise cipher suite, [`NOISE_SUITE`].
    pub suite: String,
}

/// `server/init`: the server's answer to [`ClientInit`].
///
/// The server sends it immediately, followed by the first `noise/handshake` message, without
/// waiting for anything in between.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerInit {
    /// Static public key as 43 base64url characters without padding.
    pub server_id: String,
    /// Core message format version, [`PROTOCOL_VERSION`].
    pub version: u32,
}

/// `server/error`: the server rejected the client's [`ClientInit`] and closes the connection.
///
/// Sent in place of [`ServerInit`] when the server cannot accept `client/init` (`connection.md`,
/// _Failure Handling_), before the Noise handshake starts. `reason` is one of
/// `unsupported_version`, `unsupported_suite` or `malformed`; an unknown value is carried verbatim
/// rather than rejected, so a later revision's reason reaches the caller instead of being read as a
/// decoding failure. The message is unauthenticated: its reason is a hint for logging and operator
/// display, not a verified fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerError {
    /// Why the server refused the init, for example `unsupported_version`.
    pub reason: String,
}

/// `noise/handshake`: one Noise handshake message.
///
/// The server sends the first message right after [`ServerInit`]; the client answers with the
/// second and last one. The bytes travel base64url-encoded without padding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NoiseHandshake {
    /// One Noise handshake message as base64url characters without padding.
    pub data: String,
}

// ---------------------------------------------------------------------------
// Client capabilities: client/hello
// ---------------------------------------------------------------------------

/// The `device_info` object of [`ClientHello`].
///
/// Every field is optional and plain text of at most 64 bytes in UTF-8.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceInfo {
    /// Device model or product name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    /// Device manufacturer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    /// Software version of the client, not the protocol version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
    /// Network interface MAC address as lowercase colon-separated bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
}

/// One audio format a player advertises in [`PlayerSupport::supported_formats`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SupportedFormat {
    /// Codec identifier: `opus`, `flac` or `pcm`.
    pub codec: String,
    /// Number of channels.
    pub channels: u8,
    /// Sample rate in hertz.
    pub sample_rate: u32,
    /// Bit depth; meaningful for `pcm` and `flac` only.
    pub bit_depth: u8,
}

/// The `player@v1_support` object of [`ClientHello`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PlayerSupport {
    /// Supported formats in priority order, most preferred first.
    pub supported_formats: Vec<SupportedFormat>,
    /// Largest total size in bytes of outstanding audio chunks.
    pub buffer_capacity: u64,
}

/// The `pairing_psk` descriptor of [`SupportedPairMethods`].
///
/// The method carries no parameters, so the descriptor is the empty object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PairingPskMethod {}

/// The `static_pairing_code` descriptor of [`SupportedPairMethods`].
///
/// The only field is an informational hint: where the operator finds the configured code. A client
/// that does not know leaves it absent, and the descriptor serializes as the empty object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StaticPairingCodeMethod {
    /// Where the code is available: `device`, `leaflet` or `operator`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,
}

/// The `dynamic_pairing_code` descriptor of [`SupportedPairMethods`].
///
/// The protocol requires both lists to be non-empty for a server to recognize the method: a
/// descriptor left empty is treated as unrecognized, so the client only advertises it when it can
/// actually emit a code.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DynamicPairingCodeMethod {
    /// Channels that carry the per-session code to the operator: `display` or `speaker`.
    pub out_channels: Vec<String>,
    /// Emission formats the client offers: `digits` or `qr_code`.
    pub formats: Vec<String>,
}

/// The `supported_pair_methods` object of [`ClientHello`], keyed by method identifier.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SupportedPairMethods {
    /// The pairing PSK method, offered by every conformant client; absent when a peer omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_psk: Option<PairingPskMethod>,
    /// The static pairing code method, offered when the client has a code configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_pairing_code: Option<StaticPairingCodeMethod>,
    /// The dynamic pairing code method, offered when the client can derive and emit a code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_pairing_code: Option<DynamicPairingCodeMethod>,
}

/// The `unpaired_access` object of [`ClientHello`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UnpairedAccess {
    /// Whether the client currently admits unpaired access.
    #[serde(default)]
    pub enabled: bool,
}

/// `client/hello`: the client's roles and capabilities.
///
/// Sent once per connection, after [`ServerHello`]. A role listed in `supported_roles` that
/// defines a support object must carry it; `player@v1` requires
/// [`player_support`](Self::player_support).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientHello {
    /// Friendly name of the client, plain text of at most 64 bytes in UTF-8.
    pub name: String,
    /// Optional description of the device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_info: Option<DeviceInfo>,
    /// Versioned role identifiers the client supports, for example `player@v1`.
    pub supported_roles: Vec<String>,
    /// Player capabilities; present exactly when `player@v1` is listed.
    #[serde(
        rename = "player@v1_support",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub player_support: Option<PlayerSupport>,
    /// Pairing methods the client currently offers.
    pub supported_pair_methods: SupportedPairMethods,
    /// Whether the client currently admits unpaired access.
    pub unpaired_access: UnpairedAccess,
}

// ---------------------------------------------------------------------------
// Server handshake: server/hello and server/activate
// ---------------------------------------------------------------------------

/// `server/hello`: the server's identity, the first message after the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerHello {
    /// Friendly name of the server, plain text of at most 64 bytes in UTF-8.
    #[serde(default)]
    pub name: String,
    /// BCP 47 language tags the operator understands, most preferred first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub languages: Option<Vec<String>>,
}

/// The `pairing` object of [`ServerActivate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PairingActivation {
    /// Pairing method the server picked from the client's offered set.
    pub method: String,
    /// Emission format of a dynamic pairing code; absent for other methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// `server/activate`: the server's purpose on this connection and the active roles.
///
/// The first activation of a connection declares the roles the client may use. Later ones may
/// omit `active_roles`, which leaves the previous set in force.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerActivate {
    /// Currently active purposes: `playback`, `pairing`, or none.
    #[serde(default)]
    pub activities: Vec<String>,
    /// Versioned roles active for this client; absent keeps the previous set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_roles: Option<Vec<String>>,
    /// Parameters of an admitted pairing attempt; present only with `pairing` activity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing: Option<PairingActivation>,
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

/// `client/pair-init`: starts a pairing attempt.
///
/// The Pairing PSK flow leaves `commit_B` absent. The Dynamic Pairing Code Flow requires it: the
/// commitment locks the client's nonce before any value from the server is known. The Static
/// Pairing Code Flow has no nonce of its own and leaves it absent as well.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientPairInit {
    /// Number of pairing `server/activate` messages received since the last Noise handshake.
    pub pairing_index: u32,
    /// `SHA-256(label || nonce_B)` of the dynamic flow's client nonce, when the method needs one.
    ///
    /// The wire spells the field `commit_B`, so the rename is explicit.
    #[serde(rename = "commit_B", default, skip_serializing_if = "Option::is_none")]
    pub commit_b: Option<String>,
}

/// `server/pair-init`: begins a round of the Dynamic Pairing Code Flow.
///
/// The server sends it in answer to `client/pair-init`, and again after every
/// [`ClientPairRetry`]. Only the first round carries the server's nonce: the binding values, and
/// with them the code, are unchanged across the rounds of one attempt.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerPairInit {
    /// 32-byte server nonce as 43 unpadded base64url characters; present in the first round only.
    ///
    /// The value is public - it is the server's half of the code binding - and is renamed to the
    /// `nonce_A` the wire spells. `Debug` redacts it anyway, so that no pairing message can carry
    /// a nonce into a log line.
    #[serde(rename = "nonce_A", default, skip_serializing_if = "Option::is_none")]
    pub nonce_a: Option<String>,
}

impl fmt::Debug for ServerPairInit {
    /// Formats the message with the server nonce redacted.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerPairInit")
            .field("nonce_A", &redacted(&self.nonce_a))
            .finish()
    }
}

/// `client/pair-retry`: asks for another round of the dynamic flow.
///
/// Sent in place of [`ClientPairConfirm`] when `server_kc` did not verify and the round limit still
/// admits another round. The payload is the empty object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientPairRetry {}

/// `client/pair-finalize`: the long-term PSK this pairing establishes.
///
/// Exactly one of the two fields is present: `long_term_psk` in the Pairing PSK flow, where the
/// key travels inside the authenticated channel, and `wrapped_psk` in the code flows, where it is
/// sealed under the CPace output. Both fields are key material, so `Debug` redacts them.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientPairFinalize {
    /// 32-byte long-term PSK as 43 base64url characters without padding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub long_term_psk: Option<String>,
    /// 48-byte sealed long-term PSK as 64 base64url characters without padding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_psk: Option<String>,
}

impl fmt::Debug for ClientPairFinalize {
    /// Formats the message with both key fields redacted.
    ///
    /// `long_term_psk` and `wrapped_psk` are key material: the first is the new long-term PSK
    /// itself and the second seals it. A `Debug` log of a decoded message, including one reached
    /// through [`Incoming`], therefore prints `<redacted>` and never the value.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientPairFinalize")
            .field("long_term_psk", &redacted(&self.long_term_psk))
            .field("wrapped_psk", &redacted(&self.wrapped_psk))
            .finish()
    }
}

/// Renders a key field as `Some("<redacted>")`, or `None` when the field is absent.
fn redacted(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<redacted>")
}

/// `server/pair-finalize`: the server persisted its pairing record.
///
/// The payload is the empty object; the message is the client's signal to persist its own record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerPairFinalize {}

/// `server/unpair`: the server dropped its pairing record for this client.
///
/// The payload is the empty object, the same shape as [`ServerPairFinalize`]. The message means the
/// server no longer holds the long-term PSK that authenticates this client, so the client removes
/// its own record and closes the connection. It is valid under any activity set, and a client on an
/// unpaired session - one keyed by the Sentinel key or by its pairing PSK - ignores it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerUnpair {}

/// `client/pair-pending`: the client is holding the admitted attempt back.
///
/// Sent instead of [`ClientPairInit`] while the static flow's pairing window is closed, or while
/// the dynamic flow's round limit holds attempts back. It neither starts the attempt nor its
/// timeout, so a `pairing_index` here may be followed by an init carrying the same value later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientPairPending {
    /// Number of pairing `server/activate` messages received since the last Noise handshake.
    pub pairing_index: u32,
    /// Short sentence for the operator, supplied by the host.
    ///
    /// The spec allows at most 200 bytes of UTF-8; the client sends what its configuration holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `server/pair-auth`: the server's CPace public share `Ya`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerPairAuth {
    /// 32-byte share as 43 base64url characters without padding.
    pub pake_msg_1: String,
}

/// `client/pair-auth`: the client's CPace public share `Yb`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientPairAuth {
    /// 32-byte share as 43 base64url characters without padding.
    pub pake_msg_2: String,
}

/// `server/pair-confirm`: the server's MCF tag `Ta`.
///
/// The tag is derived from the CPace session key, so `Debug` redacts it: no log line or failed
/// assertion prints it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerPairConfirm {
    /// 64-byte HMAC-SHA-512 tag as 86 base64url characters without padding.
    pub server_kc: String,
}

impl fmt::Debug for ServerPairConfirm {
    /// Formats the message with the key-confirmation tag redacted.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerPairConfirm")
            .field("server_kc", &"<redacted>")
            .finish()
    }
}

/// `client/pair-confirm`: the client's MCF tag `Tb`, plus the dynamic flow's sealed opening.
///
/// Both fields are derived from the CPace session key, so `Debug` redacts them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientPairConfirm {
    /// 64-byte HMAC-SHA-512 tag as 86 base64url characters without padding.
    pub client_kc: String,
    /// 48-byte sealing of `nonce_B`, present only in the Dynamic Pairing Code Flow.
    ///
    /// The wire spells the field `wrapped_nonce_B`, so the rename is explicit.
    #[serde(
        rename = "wrapped_nonce_B",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub wrapped_nonce_b: Option<String>,
}

impl fmt::Debug for ClientPairConfirm {
    /// Formats the message with the tag and the sealed nonce redacted.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientPairConfirm")
            .field("client_kc", &"<redacted>")
            .field("wrapped_nonce_B", &redacted(&self.wrapped_nonce_b))
            .finish()
    }
}

/// `pair/abort`: ends a pairing attempt, whether or not it started.
///
/// Both directions send it. The reason is one of the values `pairing.md` defines; an unknown
/// value is carried verbatim rather than treated as a decoding failure, so a later revision's
/// reason does not end the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PairAbort {
    /// Why the attempt ended, for example `attempt_timeout` or `method_not_supported`.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Clock synchronization
// ---------------------------------------------------------------------------

/// `client/time`: a clock-synchronization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientTime {
    /// Client clock timestamp in microseconds at which the request was sent.
    pub client_transmitted: i64,
}

/// `server/time`: the reply to [`ClientTime`], carrying the four timestamps of one measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerTime {
    /// Value of `client_transmitted` from the request.
    pub client_transmitted: i64,
    /// Server clock time in microseconds at which the request arrived.
    pub server_received: i64,
    /// Server clock time in microseconds at which this reply was sent.
    pub server_transmitted: i64,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The `player` object of [`ClientState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PlayerState {
    /// Volume in the range 0-100; required when `volume` is in `supported_commands`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<u8>,
    /// Mute state; required when `mute` is in `supported_commands`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub muted: Option<bool>,
    /// Output delay in milliseconds, compensating for delay beyond the audio port.
    pub output_delay_ms: u32,
    /// Minimum startup lead time in milliseconds.
    pub required_lead_time_ms: u32,
    /// Requested minimum ongoing buffer duration in milliseconds.
    pub min_buffer_ms: u32,
    /// Player commands the server may send: `volume`, `mute` and `set_output_delay`.
    #[serde(default)]
    pub supported_commands: Vec<String>,
    /// Preferred audio format, one of the entries of
    /// [`PlayerSupport::supported_formats`]; absent means no preference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<SupportedFormat>,
}

/// `client/state`: client availability plus the state of each active role.
///
/// A role object that is absent keeps its previous state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientState {
    /// Whether the client is available to take part in playback.
    pub available: bool,
    /// Player state; present exactly when the `player` role is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub player: Option<PlayerState>,
}

/// The `progress` object of [`Metadata`]. Times and durations are milliseconds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Progress {
    /// Position within the track.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_progress: Option<u64>,
    /// Length of the track; zero for a stream of unknown length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_duration: Option<u64>,
    /// Playback speed per mille, `1000` at normal speed and `0` while paused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub playback_speed: Option<u32>,
}

/// The `metadata` object of [`ServerState`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Metadata {
    /// Server clock time in microseconds at which this metadata becomes valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    /// Track title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Track artist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artist: Option<String>,
    /// Album artist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub album_artist: Option<String>,
    /// Album title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub album: Option<String>,
    /// URL of the artwork image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artwork_url: Option<String>,
    /// Release year.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub year: Option<i32>,
    /// Track number within its album.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track: Option<u32>,
    /// Playback progress; absent clears the known position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
}

/// The `controller` object of [`ServerState`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ControllerState {
    /// Media commands the group currently accepts.
    #[serde(default)]
    pub supported_commands: Vec<String>,
    /// Volume of the whole group in the range 0-100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<u8>,
    /// Mute state of the whole group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub muted: Option<bool>,
    /// Repeat mode: `off`, `one` or `all`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeat: Option<String>,
    /// Whether shuffle is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shuffle: Option<bool>,
    /// Maximum absolute position a `seek` may target, in milliseconds.
    ///
    /// A server that advertises `seek` includes it; absent means the server offers no absolute seek
    /// position, so only `seek_relative` is meaningful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seek_max_ms: Option<u64>,
}

/// `server/state`: the state of each active server role.
///
/// A role object that is absent keeps its previous state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerState {
    /// Metadata state; present exactly when the `metadata` role is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    /// Controller state; present exactly when the `controller` role is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<ControllerState>,
}

/// `group/update`: the state and identity of the group this client is part of.
///
/// The server sends it after the first `server/activate` and whenever one of the fields changes,
/// and every message carries all three. `server/state` carries only the role objects, so a client
/// that wants the group's playback state has no other source. `group_id` that is not 43 unpadded
/// base64url characters is a protocol error the receiver must close over; the check is the
/// session's, because it is about a field value rather than the message's shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GroupUpdate {
    /// `playing` or `stopped`; a paused group reports `stopped`. An unknown value is preserved.
    pub playback_state: String,
    /// 32-byte group identifier as 43 unpadded base64url characters.
    pub group_id: String,
    /// Friendly name of the group, plain text of at most 64 bytes in UTF-8.
    pub group_name: String,
}

// ---------------------------------------------------------------------------
// Stream lifecycle
// ---------------------------------------------------------------------------

/// The `player` object of [`StreamStart`]: the negotiated audio format of a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StreamStartPlayer {
    /// Codec of the stream: `opus`, `flac` or `pcm`.
    pub codec: String,
    /// Sample rate in hertz.
    pub sample_rate: u32,
    /// Number of channels.
    pub channels: u8,
    /// Bit depth; ignored for `opus`.
    pub bit_depth: u8,
    /// Codec header as standard base64 with padding, for example the `fLaC` marker followed by
    /// STREAMINFO for FLAC; absent for `pcm` and `opus`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec_header: Option<String>,
}

/// `stream/start`: announces a stream and its format.
///
/// Sent again with a new format to change the configuration of a running stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StreamStart {
    /// Server clock time in microseconds at which this message was sent.
    #[serde(default)]
    pub server_transmitted: i64,
    /// Player format of the stream; present exactly when the `player` role is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub player: Option<StreamStartPlayer>,
}

/// `stream/clear`: drops buffered data without ending the stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StreamClear {
    /// Server clock time in microseconds at which this message was sent.
    #[serde(default)]
    pub server_transmitted: i64,
    /// Server clock time from which buffered data is dropped; absent clears everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_timestamp: Option<i64>,
    /// Roles to clear; absent means every active stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

/// `stream/end`: ends one or more streams.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StreamEnd {
    /// Roles to end; absent means every active stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// The `player` object of [`ServerCommand`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PlayerCommand {
    /// Command to run: `volume`, `mute` or `set_output_delay`. A command outside the client's
    /// advertised set is ignored.
    pub command: String,
    /// Target volume in the range 0-100; required for `volume`, absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<u8>,
    /// Target mute state; required for `mute`, absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mute: Option<bool>,
    /// Target output delay in milliseconds; required for `set_output_delay`, absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_delay_ms: Option<u32>,
}

/// `server/command`: a command for one of the client's active roles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServerCommand {
    /// Player command; present exactly when the `player` role is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub player: Option<PlayerCommand>,
}

/// The `controller` object of [`ClientCommand`].
///
/// `command` names the operation and the other fields carry its parameter; a field that does not
/// belong to the command is absent rather than null.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ControllerCommand {
    /// Command to run: `play`, `pause`, `stop`, `next`, `previous`, `volume`, `mute`,
    /// `repeat_off`, `repeat_one`, `repeat_all`, `shuffle`, `unshuffle`, `switch`, `seek` or
    /// `seek_relative`. A command outside the server's advertised set is ignored by the server.
    pub command: String,
    /// Target group volume in the range 0-100; only for `volume`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<u8>,
    /// Target mute state; only for `mute`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mute: Option<bool>,
    /// Absolute position in milliseconds; only for `seek`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position_ms: Option<u64>,
    /// Offset from the current position in milliseconds; only for `seek_relative`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset_ms: Option<i64>,
}

/// `client/command`: a command the client sends to the server for one of its active roles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientCommand {
    /// Controller command; present exactly when the `controller` role is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<ControllerCommand>,
}

// ---------------------------------------------------------------------------
// Closing
// ---------------------------------------------------------------------------

/// `client/goodbye`: why the client is closing the connection.
///
/// Sent before a graceful close, so the server can tell a restart from a shutdown and whether to
/// reconnect. `reason` is one of the values `messaging.md` defines; an unknown value is carried
/// verbatim rather than rejected, so a reason this revision does not name still reaches the peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientGoodbye {
    /// Why the client is leaving, for example `shutdown`, `restart` or `unpaired`.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Binary audio
// ---------------------------------------------------------------------------

/// The fixed header of a player audio chunk, the binary message with id [`AUDIO_CHUNK_ID`].
///
/// Layout: one message-id byte, an 8-byte big-endian timestamp in microseconds and a 4-byte
/// big-endian `send_ahead` in microseconds; the encoded audio follows. The timestamp is two's
/// complement, so negative values round-trip exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioChunkHeader {
    /// Server clock time in microseconds at which the first sample of the chunk should be
    /// output.
    pub timestamp_us: i64,
    /// Microseconds between the server transmitting the chunk and [`Self::timestamp_us`].
    ///
    /// It measures arrival delay only and never changes when the chunk is played.
    pub send_ahead: u32,
}

impl AudioChunkHeader {
    /// Length of the header, including the message-id byte.
    pub const LEN: usize = 13;

    /// Parses one audio chunk, returning its header and the encoded audio that follows.
    ///
    /// After checking the id byte it delegates to [`Self::parse_body`].
    ///
    /// # Errors
    /// Returns an error for an empty message, for a message whose id is not [`AUDIO_CHUNK_ID`],
    /// and for a chunk shorter than [`Self::LEN`].
    pub fn parse(message: &[u8]) -> Result<(Self, &[u8])> {
        let Some((&id, body)) = message.split_first() else {
            bail!("empty binary message");
        };
        if id != AUDIO_CHUNK_ID {
            bail!("binary message id {id} is not an audio chunk");
        }
        Self::parse_body(body)
    }

    /// Parses an audio chunk whose message-id byte has already been removed.
    ///
    /// A reassembler hands the body over without the id, so a receiver that has classified the
    /// message by id can parse it in place instead of prefixing the id again. The result is the
    /// same as [`Self::parse`] on the id followed by `body`.
    ///
    /// # Errors
    /// Returns an error for a body shorter than [`Self::LEN`] minus the id byte.
    pub fn parse_body(body: &[u8]) -> Result<(Self, &[u8])> {
        let Some((timestamp, body)) = body.split_at_checked(8) else {
            bail!("audio chunk truncated: {} bytes", body.len() + 1);
        };
        let Some((send_ahead, audio)) = body.split_at_checked(4) else {
            bail!("audio chunk truncated: {} bytes", body.len() + 9);
        };
        let mut timestamp_us = [0u8; 8];
        timestamp_us.copy_from_slice(timestamp);
        let mut send_ahead_us = [0u8; 4];
        send_ahead_us.copy_from_slice(send_ahead);
        Ok((
            Self {
                timestamp_us: i64::from_be_bytes(timestamp_us),
                send_ahead: u32::from_be_bytes(send_ahead_us),
            },
            audio,
        ))
    }

    /// Builds one complete audio chunk from this header and the encoded audio.
    pub fn encode(&self, audio: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(Self::LEN + audio.len());
        message.push(AUDIO_CHUNK_ID);
        message.extend_from_slice(&self.timestamp_us.to_be_bytes());
        message.extend_from_slice(&self.send_ahead.to_be_bytes());
        message.extend_from_slice(audio);
        message
    }
}

// ---------------------------------------------------------------------------
// Envelope classification
// ---------------------------------------------------------------------------

/// One decoded JSON message, classified by its `type` field.
///
/// The same type writes the envelope: serializing a variant produces
/// `{"type": "<group>/<name>", "payload": {..}}`, which is what a session sends.
///
/// The enum is non-exhaustive: a newer revision of the protocol defines messages this one does
/// not, and a receiver must be able to ignore them without a breaking change.
///
/// Deserializing this type directly with `serde_json` reports an unknown `type` and a malformed
/// payload as the same kind of error, so it cannot drive the protocol's rule that the first is
/// ignored and the second closes the connection. Use [`Incoming::parse`] for received frames,
/// which tells the two apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[non_exhaustive]
pub enum Incoming {
    /// `client/init`, cleartext.
    #[serde(rename = "client/init")]
    ClientInit(ClientInit),
    /// `server/init`, cleartext.
    #[serde(rename = "server/init")]
    ServerInit(ServerInit),
    /// `server/error`, cleartext, in place of `server/init`.
    #[serde(rename = "server/error")]
    ServerError(ServerError),
    /// `noise/handshake`, cleartext.
    #[serde(rename = "noise/handshake")]
    NoiseHandshake(NoiseHandshake),
    /// `server/hello`.
    #[serde(rename = "server/hello")]
    ServerHello(ServerHello),
    /// `client/hello`.
    #[serde(rename = "client/hello")]
    ClientHello(ClientHello),
    /// `server/activate`.
    #[serde(rename = "server/activate")]
    ServerActivate(ServerActivate),
    /// `client/pair-init`.
    #[serde(rename = "client/pair-init")]
    ClientPairInit(ClientPairInit),
    /// `client/pair-pending`.
    #[serde(rename = "client/pair-pending")]
    ClientPairPending(ClientPairPending),
    /// `server/pair-init`.
    #[serde(rename = "server/pair-init")]
    ServerPairInit(ServerPairInit),
    /// `server/pair-auth`.
    #[serde(rename = "server/pair-auth")]
    ServerPairAuth(ServerPairAuth),
    /// `client/pair-auth`.
    #[serde(rename = "client/pair-auth")]
    ClientPairAuth(ClientPairAuth),
    /// `client/pair-retry`.
    #[serde(rename = "client/pair-retry")]
    ClientPairRetry(ClientPairRetry),
    /// `server/pair-confirm`.
    #[serde(rename = "server/pair-confirm")]
    ServerPairConfirm(ServerPairConfirm),
    /// `client/pair-confirm`.
    #[serde(rename = "client/pair-confirm")]
    ClientPairConfirm(ClientPairConfirm),
    /// `client/pair-finalize`.
    #[serde(rename = "client/pair-finalize")]
    ClientPairFinalize(ClientPairFinalize),
    /// `server/pair-finalize`.
    #[serde(rename = "server/pair-finalize")]
    ServerPairFinalize(ServerPairFinalize),
    /// `server/unpair`.
    #[serde(rename = "server/unpair")]
    ServerUnpair(ServerUnpair),
    /// `client/goodbye`.
    #[serde(rename = "client/goodbye")]
    ClientGoodbye(ClientGoodbye),
    /// `pair/abort`, in both directions.
    #[serde(rename = "pair/abort")]
    PairAbort(PairAbort),
    /// `client/time`.
    #[serde(rename = "client/time")]
    ClientTime(ClientTime),
    /// `server/time`.
    #[serde(rename = "server/time")]
    ServerTime(ServerTime),
    /// `client/state`.
    #[serde(rename = "client/state")]
    ClientState(ClientState),
    /// `server/state`.
    #[serde(rename = "server/state")]
    ServerState(ServerState),
    /// `group/update`.
    #[serde(rename = "group/update")]
    GroupUpdate(GroupUpdate),
    /// `server/command`.
    #[serde(rename = "server/command")]
    ServerCommand(ServerCommand),
    /// `client/command`.
    #[serde(rename = "client/command")]
    ClientCommand(ClientCommand),
    /// `stream/start`.
    #[serde(rename = "stream/start")]
    StreamStart(StreamStart),
    /// `stream/clear`.
    #[serde(rename = "stream/clear")]
    StreamClear(StreamClear),
    /// `stream/end`.
    #[serde(rename = "stream/end")]
    StreamEnd(StreamEnd),
}

impl Incoming {
    /// Parses one JSON text frame, telling an unknown message type from a malformed message.
    ///
    /// `Ok(None)` means the `type` names a message this revision does not implement. The protocol
    /// requires ignoring such a message, so it is not an error, and returning the identifier would
    /// only invite callers to treat the normal case as a failure.
    ///
    /// `Err(DecodeError::Malformed(..))` means the message cannot be used: either the frame is not
    /// a JSON object with a string `type`, or the `type` is known and its payload does not parse.
    /// The protocol treats that as an error, so the caller must act on it.
    ///
    /// Deserializing with `serde_json::from_str::<Incoming>` instead reports both cases through the
    /// same error type; use this method whenever the difference matters.
    pub fn parse(text: &str) -> Result<Option<Self>, DecodeError> {
        let envelope: EnvelopeType = serde_json::from_str(text).map_err(DecodeError::Malformed)?;
        if !is_known_type(&envelope.message_type) {
            return Ok(None);
        }
        serde_json::from_str(text)
            .map(Some)
            .map_err(DecodeError::Malformed)
    }
}

/// Why a text frame did not produce an [`Incoming`] message.
#[derive(Debug)]
pub enum DecodeError {
    /// The `type` is not one this revision implements.
    ///
    /// [`Incoming::parse`] reports this case as `Ok(None)` rather than as this variant, because the
    /// protocol requires ignoring an unrecognised type instead of closing the connection. The
    /// variant stays part of the public error type so a stricter dispatcher can still name the
    /// case.
    UnknownType(String),
    /// The `type` is known, but the message does not deserialize.
    Malformed(serde_json::Error),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownType(message_type) => {
                write!(formatter, "unrecognized message type {message_type:?}")
            }
            Self::Malformed(error) => write!(formatter, "malformed message: {error}"),
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed(error) => Some(error),
            Self::UnknownType(_) => None,
        }
    }
}

/// The `type` field of a message envelope, read before the payload is parsed.
#[derive(Deserialize)]
struct EnvelopeType {
    #[serde(rename = "type")]
    message_type: String,
}

/// Message types this revision implements, one per [`Incoming`] variant.
///
/// A variant added without its entry here would silently read as an unknown type, so the
/// integration tests parse one instance of every variant.
const KNOWN_TYPES: [&str; 30] = [
    "client/init",
    "server/init",
    "server/error",
    "noise/handshake",
    "server/hello",
    "client/hello",
    "server/activate",
    "client/pair-init",
    "client/pair-pending",
    "server/pair-init",
    "server/pair-auth",
    "client/pair-auth",
    "client/pair-retry",
    "server/pair-confirm",
    "client/pair-confirm",
    "client/pair-finalize",
    "server/pair-finalize",
    "server/unpair",
    "client/goodbye",
    "pair/abort",
    "client/time",
    "server/time",
    "client/state",
    "server/state",
    "group/update",
    "server/command",
    "client/command",
    "stream/start",
    "stream/clear",
    "stream/end",
];

/// Whether this revision implements a message type.
fn is_known_type(message_type: &str) -> bool {
    KNOWN_TYPES.contains(&message_type)
}
