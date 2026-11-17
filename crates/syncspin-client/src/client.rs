//! Public client surface: events, handles and the connection entry point.

use std::fmt;
#[cfg(feature = "pairing-code")]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use syncspin_core::pairing::token::encode_v0;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

#[cfg(feature = "pairing-code")]
use crate::config::CodeFormat;
use crate::config::{ClientConfig, StoredPsk, VolumePolicy};
use crate::pairing::{load_or_draw_pairing_psk, PairingPsk};
use crate::session::{self, Carried, Transport};
use crate::sink::{AudioFormat, Sink};

/// How long the TCP and WebSocket handshake may take before it is treated as unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Delay before the first reconnect attempt, and the value the backoff resets to.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// How long one pairing attempt may run, measured from `client/pair-init`.
///
/// `pairing.md` recommends two minutes. On expiry the client sends `pair/abort` with reason
/// `attempt_timeout` and reports [`Event::PairingFailed`]; a host that wants a tighter bound sets
/// [`ClientConfig::pairing_timeout`].
pub const DEFAULT_PAIRING_TIMEOUT: Duration = Duration::from_secs(120);

/// Highest level the protocol defines, in its 0-100 volume range.
pub(crate) const MAX_VOLUME: u8 = 100;

/// Playback speed the protocol defines as normal, in per-mille.
///
/// A metadata message that carries no speed plays at this rate, so the track event always names
/// one.
pub const NORMAL_PLAYBACK_SPEED: u32 = 1_000;

/// Returns the volume level to apply for `requested` while `current` is in force.
///
/// This is [`clamp_volume_with`] with [`VolumePolicy::default`]: a request to 40 or below is
/// applied as asked, and above 40 one request may raise the level by at most 20. Both values are
/// first limited to the protocol's 0-100 range, so the result is always a level the server
/// accepts.
///
/// ```
/// # use syncspin_client::clamp_volume;
/// assert_eq!(clamp_volume(40, 100), 60);
/// assert_eq!(clamp_volume(40, 10), 10);
/// assert_eq!(clamp_volume(100, 90), 90);
/// assert_eq!(clamp_volume(100, 150), 100);
/// ```
#[must_use]
pub fn clamp_volume(current: u8, requested: u8) -> u8 {
    clamp_volume_with(VolumePolicy::default(), current, requested)
}

/// Returns the volume level to apply for `requested` while `current` is in force, using `policy`.
///
/// Both values are first limited to the protocol's 0-100 range, so the result is always a level
/// the server accepts. A request at or below [`VolumePolicy::threshold`] is applied as asked,
/// whether it raises or lowers the level. Above the threshold, one request may raise the level by
/// at most [`VolumePolicy::max_step`]; a lower request is applied as asked, because the limit
/// bounds raises only. When [`VolumePolicy::threshold_floor`] is set, such a request may also rise
/// to the threshold itself, so a player at 1 reaches 40 in one command instead of 21.
///
/// A `policy` whose fields exceed 100 is not rejected here, because the configuration validation
/// rejects it before a connection exists; the values are limited to 100 so this function still
/// returns a level the server accepts.
///
/// ```
/// # use syncspin_client::{clamp_volume_with, VolumePolicy};
/// let policy = VolumePolicy {
///     threshold: 40,
///     max_step: 20,
///     threshold_floor: true,
/// };
/// assert_eq!(clamp_volume_with(policy, 1, 100), 40);
/// assert_eq!(clamp_volume_with(policy, 40, 100), 60);
/// assert_eq!(clamp_volume_with(policy, 100, 90), 90);
/// ```
#[must_use]
pub fn clamp_volume_with(policy: VolumePolicy, current: u8, requested: u8) -> u8 {
    let threshold = policy.threshold.min(MAX_VOLUME);
    let max_step = policy.max_step.min(MAX_VOLUME);
    let current = current.min(MAX_VOLUME);
    let requested = requested.min(MAX_VOLUME);
    if requested <= threshold {
        return requested;
    }
    let applied = requested.min(current.saturating_add(max_step));
    if policy.threshold_floor {
        applied.max(threshold)
    } else {
        applied
    }
}

/// Rejects a level outside the protocol's 0-100 range.
///
/// A reported level is not a request, so [`clamp_volume_with`] never sees it: a value the protocol
/// cannot carry is refused instead of being capped, and nothing is recorded or sent.
///
/// # Errors
/// Returns an error naming the value when it is above [`MAX_VOLUME`].
pub(crate) fn check_reported_level(level: u8) -> Result<()> {
    if level > MAX_VOLUME {
        bail!(
            "the reported level {level} is outside the 0-{MAX_VOLUME} range the protocol defines"
        );
    }
    Ok(())
}

/// Returns the delay to wait before the next connection attempt.
///
/// The delay starts at [`INITIAL_BACKOFF`] and doubles with every attempt that never reached
/// [`Event::Connected`], saturating at `max`. `previous` is the delay used before the failed
/// attempt, or [`Duration::ZERO`] for the first one. A `connected` session resets the delay: the
/// address and the handshake worked, so a later failure is retried without a growing penalty.
///
/// The crate keeps the sequence across the attempts it makes itself and reports each step in
/// [`Event::Disconnected`]. A host that drives its own loop, for example because it wants to stop
/// retrying, can use this function for the same policy.
///
/// ```
/// # use std::time::Duration;
/// # use syncspin_client::next_backoff;
/// let max = Duration::from_secs(30);
/// assert_eq!(next_backoff(Duration::ZERO, false, max), Duration::from_secs(1));
/// assert_eq!(next_backoff(Duration::from_secs(1), false, max), Duration::from_secs(2));
/// assert_eq!(next_backoff(Duration::from_secs(16), true, max), Duration::from_secs(1));
/// ```
#[must_use]
pub fn next_backoff(previous: Duration, connected: bool, max: Duration) -> Duration {
    let next = if connected || previous.is_zero() {
        INITIAL_BACKOFF
    } else {
        previous.saturating_mul(2)
    };
    next.min(max)
}

/// Why a player stream ended.
///
/// A seek is not an end: the stream stays open and later chunks still belong to it, so it is
/// reported as [`Event::StreamClear`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamEndReason {
    /// The server sent `stream/end`, which pauses playback.
    End,
    /// The server removed `player@v1` from the active roles.
    RoleRemoved,
}

/// Why a server needs a pairing this client cannot satisfy with what it holds.
///
/// The value is the reason field of [`Event::PairingRequired`]. The enum is non-exhaustive: a later
/// revision may classify another situation the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairingRequiredReason {
    /// The server announced a `psk_id` this client does not hold, so the handshake fell back to
    /// the Sentinel key.
    ///
    /// `connection.md` calls the resulting handshake the server's authenticated
    /// credential-mismatch signal: the server still holds a record for this client, and the client
    /// has none it can use for it. The signal alone never removes or replaces a record - not the
    /// server's and not the client's - so the host decides whether to offer pairing again. A code
    /// flow or the Pairing PSK flow then replaces the record on both sides.
    CredentialMismatch,
    /// The server asked for an unpaired session while this client refuses unpaired access;
    /// `Event::PairingRequired` reports it before the close.
    UnpairedAccessDisabled,
}

/// Why a pairing attempt ended without a record.
///
/// Each value is the `reason` field of a `pair/abort`: the client sends the ones it causes and
/// reports the ones it receives. The enum is non-exhaustive: a later revision defines reasons this
/// one does not name, which arrive as [`Unrecognised`](PairingFailure::Unrecognised).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairingFailure {
    /// The attempt did not complete within [`ClientConfig::pairing_timeout`].
    AttemptTimeout,
    /// The matched key and the requested method are not a permitted combination, or the client
    /// does not currently offer the method: it has no store, or the activation names a code method
    /// this build does not carry.
    MethodNotSupported,
    /// A key confirmation failed, so the code was wrong or a peer relayed between two handshakes.
    PairingCodeMismatch,
    /// The operator cancelled the pairing, on either side.
    UserCancelled,
    /// Another pairing attempt is already in progress with this client.
    ConcurrentAttempt,
    /// A reason this revision does not name, as it arrived on the wire.
    Unrecognised(String),
}

impl PairingFailure {
    /// Returns the reason as `pair/abort` spells it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::AttemptTimeout => "attempt_timeout",
            Self::MethodNotSupported => "method_not_supported",
            Self::PairingCodeMismatch => "pairing_code_mismatch",
            Self::UserCancelled => "user_cancelled",
            Self::ConcurrentAttempt => "concurrent_attempt",
            Self::Unrecognised(reason) => reason,
        }
    }

    /// Decodes the `reason` of a received `pair/abort`.
    ///
    /// An unknown value is carried verbatim rather than rejected: the message is a wellformed
    /// abort from a peer that may speak a later revision, and ending the connection over it would
    /// be worse than reporting the reason the host cannot classify.
    pub(crate) fn from_wire(reason: &str) -> Self {
        match reason {
            "attempt_timeout" => Self::AttemptTimeout,
            "method_not_supported" => Self::MethodNotSupported,
            "pairing_code_mismatch" => Self::PairingCodeMismatch,
            "user_cancelled" => Self::UserCancelled,
            "concurrent_attempt" => Self::ConcurrentAttempt,
            other => Self::Unrecognised(other.to_owned()),
        }
    }
}

/// Why a client says goodbye to a server.
///
/// The value is the `reason` field of `client/goodbye`, which the client sends before a graceful
/// close so the server knows whether to reconnect. The enum is non-exhaustive: a later revision may
/// add one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GoodbyeReason {
    /// The client is switching to another server.
    ///
    /// `messaging.md` requires this reason from a client that leaves one server for another; with
    /// one connection this revision only lets a host express it through
    /// [`ClientHandle::close`].
    AnotherServer,
    /// The client rejected a second server because another one is already admitted.
    ///
    /// A client that advertises `_sendspin._tcp` caps how many servers it serves at once; the
    /// admission rule of `connection.md`, _Multiple servers_, rejects the loser with this reason
    /// and closes the connection.
    ConcurrentAttempt,
    /// The client is restarting and will reconnect.
    Restart,
    /// The client is shutting down or otherwise going offline.
    Shutdown,
    /// The operator asked to disconnect from this server.
    UserRequest,
    /// The client processed `server/unpair`.
    Unpaired,
    /// The client does not admit the unpaired session the server activated, because unpaired access
    /// is disabled and enabling it would make the activation admissible.
    ///
    /// `pairing.md` § _Unpaired Access_ requires a client that stops admitting unpaired access to
    /// close any connection relying on it with this reason. `messaging.md` § `server/activate`
    /// names it as the first rejection rule.
    PairingRequired,
    /// The server's activation is not allowed for the matched PSK, or it names roles the connection
    /// may not use.
    ///
    /// `messaging.md` § `server/activate` names this as the second rejection rule: the activity set
    /// is not allowed for the matched PSK, or `active_roles` is non-empty on a connection that is not
    /// playback-capable.
    Unauthorized,
}

impl GoodbyeReason {
    /// Returns the reason as `client/goodbye` spells it.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AnotherServer => "another_server",
            Self::ConcurrentAttempt => "concurrent_attempt",
            Self::Restart => "restart",
            Self::Shutdown => "shutdown",
            Self::UserRequest => "user_request",
            Self::Unpaired => "unpaired",
            Self::PairingRequired => "pairing_required",
            Self::Unauthorized => "unauthorized",
        }
    }
}

/// Something that happened on the connection.
///
/// Events are ordered as the connection produced them. A connection attempt ends with at most one
/// [`Event::Disconnected`], and the crate then reconnects on its own, so a later event belongs to
/// the next attempt. The enum is non-exhaustive: a later revision adds events without breaking a
/// host's match.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The Noise handshake finished and the session is ready for playback.
    ///
    /// Reported once per successful attempt. `encrypted` is always `true`: this client has no path
    /// that speaks to a server without Noise, so the field documents the property rather than
    /// hedging it.
    Connected {
        /// The server's static public key as 43 base64url characters.
        server_id: String,
        /// Whether the connection is encrypted; always `true`.
        encrypted: bool,
    },
    /// The attempt ended.
    ///
    /// Another attempt follows unless the audio sink failed or the host dropped the connection.
    /// `reason` is human-readable and never contains key material. `retry_in` is the delay
    /// before the next attempt, one step of the reconnect policy: it is two seconds after an
    /// attempt that never reached [`Event::Connected`], doubles with every further failed attempt
    /// up to [`ClientConfig::max_backoff`], and drops to one second again after a session that
    /// connected. It is [`Duration::ZERO`] when no attempt follows, because the audio sink failed,
    /// and for every connection of an advertising client, which does not dial at all and waits for
    /// the next server instead.
    Disconnected {
        /// Why the attempt ended.
        reason: String,
        /// How long to wait before the next attempt; zero when none follows.
        retry_in: Duration,
    },
    /// The server rejected the connection's `client/init` with `server/error`.
    ///
    /// Reported during the cleartext exchange, before [`Event::Connected`], and followed by
    /// [`Event::Disconnected`] because the server closes after it. `reason` is the wire value
    /// carried verbatim: `unsupported_version`, `unsupported_suite` and `malformed` are the ones
    /// this revision defines, and an unknown value is what a newer server sends. The message is
    /// unauthenticated, so the reason is a hint for logging and operator display, not a verified
    /// fact.
    ServerError {
        /// Why the server refused the init.
        reason: String,
    },
    /// A stream was announced with the given format.
    ///
    /// The sink has been opened for this format before the event is emitted.
    StreamStart {
        /// Format of the new stream.
        format: AudioFormat,
    },
    /// A player stream ended.
    ///
    /// Reported before the sink is flushed, so a host can mute or stop its output first. The
    /// client flushes the sink itself as well, after this event. A seek does not end the stream;
    /// it is reported as [`Event::StreamClear`], and chunks after it still belong to the open
    /// stream.
    StreamEnd {
        /// Why the stream ended.
        reason: StreamEndReason,
    },
    /// The server asked to drop buffered audio without ending the stream.
    ///
    /// Reported before the buffered audio is discarded or flushed, so a host can restart its
    /// output or drop the matching part of its own queue first. The announced format stays open,
    /// and chunks that follow still belong to it.
    StreamClear {
        /// Server timestamp the audio should resume from, when the server named one.
        from_timestamp: Option<i64>,
    },
    /// Now-playing metadata changed.
    ///
    /// Absent text fields are reported as empty strings, so a host can clear its display; absent
    /// progress fields are `None`.
    Track {
        /// Track title.
        title: String,
        /// Track artist.
        artist: String,
        /// Album title.
        album: String,
        /// Album artist.
        album_artist: String,
        /// URL of the artwork image, empty when the server sent none.
        artwork_url: String,
        /// Position within the track in milliseconds, when the server reports one.
        progress_ms: Option<u64>,
        /// Track length in milliseconds, when the server reports one.
        duration_ms: Option<u64>,
        /// Playback speed per mille: `1000` is normal speed, `500` half speed and `0` paused.
        ///
        /// Reported as [`NORMAL_PLAYBACK_SPEED`] when the server sends no speed, because a track
        /// without the field plays at normal speed.
        playback_speed: u32,
    },
    /// The server's view of playback state changed.
    State(PlaybackState),
    /// The server sent a `group_id` the spec does not allow, and the client accepted it.
    ///
    /// `messaging.md` gives `group_id` as 32 server-chosen bytes in 43 base64url characters and
    /// calls any other value a protocol error. The default configuration tolerates a well-formed
    /// value instead - one that is non-empty, at most 128 bytes and free of control characters -
    /// because a real server sends a UUID. The event reports the departure so a host can log it or
    /// surface it to the operator; it never carries the identifier itself.
    ///
    /// Reported at most once per connection, however many non-canonical updates arrive. It is not
    /// reported for a canonical identifier, and it does not exist when
    /// [`ClientConfig::strict_group_id`] is set, because that configuration closes the connection
    /// instead. An empty, oversized or control-character value is a protocol error in both modes.
    GroupIdNotCanonical {
        /// Length of the value in bytes, which is all a log line needs.
        len: usize,
    },
    /// The server asked this player to change its volume or mute state.
    ///
    /// The session applies the [`VolumePolicy`] from its configuration and reports the applied
    /// level back to the server in `client/state`. The event carries both numbers, so a host can
    /// see what the server asked for and what the policy allowed without repeating the policy.
    /// `muted` is present for a mute command and absent for a volume command; a mute leaves the
    /// level unchanged, so both numbers then name the level already in force.
    Volume {
        /// Level the server asked for, as it arrived on the wire.
        ///
        /// A non-conformant server can send a value above 100; it is reported unchanged so a host
        /// can log it, while `applied` always stays inside the protocol's range.
        requested: u8,
        /// Level that was applied, always in the range 0-100.
        applied: u8,
        /// Mute state that was requested, absent for a volume command.
        muted: Option<bool>,
    },
    /// A pairing completed and the record is stored.
    ///
    /// Reported after `server/pair-finalize`, once [`Storage`](crate::storage::Storage) accepted
    /// the record. The record authenticates later connections to that server, and the server
    /// normally rotates the live connection to it with an in-band re-handshake: the session swaps
    /// its keys without reopening the stream, so playback continues and the next connection is
    /// keyed by the same long-term PSK.
    Paired {
        /// Static public key of the server the record belongs to, as 43 base64url characters.
        server_id: String,
    },
    /// The server dropped its pairing record for this client.
    ///
    /// Reported when a paired session receives `server/unpair`. The record is gone from
    /// [`Storage`](crate::storage::Storage) by the time the event arrives, and the client says
    /// goodbye with reason `unpaired` and closes the connection: the next connection to that
    /// server lands in the Sentinel fallback unless the host pairs again.
    ///
    /// A record the host passed through
    /// [`connect_with_psks`](crate::connect_with_psks) is not in a store the client may write, so
    /// the client reports it and ends the connection without removing it: the host owns that
    /// record and has to drop it.
    Unpaired {
        /// Static public key of the server that dropped the record, as 43 base64url characters.
        server_id: String,
    },
    /// A server needs a pairing this client cannot complete with what it holds.
    ///
    /// Two situations report it, each with its own [`PairingRequiredReason`].
    ///
    /// The handshake reports a credential mismatch once per connection, never once per message: the
    /// situation is decided by the Noise handshake, so the event fires after [`Event::Connected`]
    /// and before the session acts on its first message, and never again for that reason while the
    /// connection lasts. A plain guest handshake - an unpaired connection whose server announced the
    /// Sentinel key - is not a mismatch and reports nothing.
    ///
    /// The second situation is a refused activation: unpaired access is off and the server sent a
    /// `server/activate` that would be admissible if it were on. The value is
    /// [`ClientConfig::unpaired_access`] unless [`ControlHandle::set_unpaired_access`] changed it on
    /// this connection. That report fires at most once, immediately before the client closes the
    /// connection with `client/goodbye` reason `pairing_required`, and never for a session whose
    /// setting admits unpaired access. A connection the host closes because it turned the setting
    /// off reports no such event: that is a host choice, not a refused activation. One connection
    /// can therefore report this event twice, once per reason, when the handshake found a
    /// credential mismatch and the activation is then refused.
    ///
    /// In the credential-mismatch case nothing is removed or replaced on either side, and the
    /// session continues as an ordinary unpaired one. A server that holds a record for this client
    /// will keep the connection in pairing or idle until the host offers pairing again.
    PairingRequired {
        /// Static public key of the server this requirement concerns, as 43 base64url characters.
        server_id: String,
        /// Which situation produced the requirement: a credential mismatch, or a refused
        /// unpaired session.
        reason: PairingRequiredReason,
    },
    /// A pairing attempt ended without a record.
    ///
    /// Nothing was stored: the host has to offer pairing again, or act on the reason. The
    /// connection itself stays open - a pairing abort is not a connection failure - so the session
    /// keeps serving playback in the roles it had.
    PairingFailed {
        /// Why the attempt ended.
        reason: PairingFailure,
    },
    /// A dynamic pairing code is ready for the operator.
    ///
    /// The code belongs to one attempt and is bound to the Noise handshake and to the two nonces
    /// of that attempt. A client with a display or a speaker shows or speaks it; the operator then
    /// types or scans it into the server. The code does not change across the rounds of an attempt,
    /// so a host that already shows it can ignore a repeat with the same `code`, while `round`
    /// tells it that another round is running.
    ///
    /// The value is deliberate: it is the method's whole point, and the host is expected to render
    /// it. It is not key material, but it does authorise one pairing, so a host should not keep it
    /// longer than the attempt.
    #[cfg(feature = "pairing-code")]
    PairingCode {
        /// The code to show: six digits in the `digits` format, a version-1 token in `qr_code`.
        code: String,
        /// Emission format the server activated.
        format: CodeFormat,
        /// Round this emission belongs to, counting from one.
        round: u32,
    },
}

impl fmt::Debug for Event {
    /// Formats an event, redacting the dynamic pairing code it may carry.
    ///
    /// A host renders that code deliberately, through the event itself; a `Debug` format is what a
    /// panic, an assertion or a logging facade writes, and the code authorises one pairing, so it
    /// must not appear there. Every other field is what a log line needs.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected {
                server_id,
                encrypted,
            } => formatter
                .debug_struct("Connected")
                .field("server_id", server_id)
                .field("encrypted", encrypted)
                .finish(),
            Self::Disconnected { reason, retry_in } => formatter
                .debug_struct("Disconnected")
                .field("reason", reason)
                .field("retry_in", retry_in)
                .finish(),
            Self::ServerError { reason } => formatter
                .debug_struct("ServerError")
                .field("reason", reason)
                .finish(),
            Self::StreamStart { format } => formatter
                .debug_struct("StreamStart")
                .field("format", format)
                .finish(),
            Self::StreamEnd { reason } => formatter
                .debug_struct("StreamEnd")
                .field("reason", reason)
                .finish(),
            Self::StreamClear { from_timestamp } => formatter
                .debug_struct("StreamClear")
                .field("from_timestamp", from_timestamp)
                .finish(),
            Self::Track {
                title,
                artist,
                album,
                album_artist,
                artwork_url,
                progress_ms,
                duration_ms,
                playback_speed,
            } => formatter
                .debug_struct("Track")
                .field("title", title)
                .field("artist", artist)
                .field("album", album)
                .field("album_artist", album_artist)
                .field("artwork_url", artwork_url)
                .field("progress_ms", progress_ms)
                .field("duration_ms", duration_ms)
                .field("playback_speed", playback_speed)
                .finish(),
            Self::State(state) => formatter.debug_tuple("State").field(state).finish(),
            Self::GroupIdNotCanonical { len } => formatter
                .debug_struct("GroupIdNotCanonical")
                .field("len", len)
                .finish(),
            Self::Volume {
                requested,
                applied,
                muted,
            } => formatter
                .debug_struct("Volume")
                .field("requested", requested)
                .field("applied", applied)
                .field("muted", muted)
                .finish(),
            Self::Paired { server_id } => formatter
                .debug_struct("Paired")
                .field("server_id", server_id)
                .finish(),
            Self::Unpaired { server_id } => formatter
                .debug_struct("Unpaired")
                .field("server_id", server_id)
                .finish(),
            Self::PairingRequired { server_id, reason } => formatter
                .debug_struct("PairingRequired")
                .field("server_id", server_id)
                .field("reason", reason)
                .finish(),
            Self::PairingFailed { reason } => formatter
                .debug_struct("PairingFailed")
                .field("reason", reason)
                .finish(),
            #[cfg(feature = "pairing-code")]
            Self::PairingCode { format, round, .. } => formatter
                .debug_struct("PairingCode")
                .field("code", &"<redacted>")
                .field("format", format)
                .field("round", round)
                .finish(),
        }
    }
}

/// Playback state as the server describes it.
///
/// The group fields come from `group/update`, which is the authoritative source: every message
/// carries all three, so the latest one is the group's identity and playback state. The controller
/// fields come from `server/state` and stay part of the picture when a group update arrives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlaybackState {
    /// Commands the server accepts from clients in the same group.
    pub supported_commands: Vec<String>,
    /// Group volume in the range 0-100, when the server reports one.
    pub volume: Option<u8>,
    /// Group mute state, when the server reports one.
    pub muted: Option<bool>,
    /// Highest absolute position [`ControlHandle::seek`] may target, in milliseconds.
    ///
    /// [`supported_commands`](PlaybackState::supported_commands) says whether the server offers
    /// absolute or relative seek; this says how far an absolute target may go. It is `None`
    /// before the first controller state and when the server advertised `seek` without naming a
    /// range, and in both cases [`ControlHandle::seek`] refuses rather than sending a target it
    /// cannot check. A `group/update` leaves it alone, because it belongs to the controller state.
    pub seek_max_ms: Option<u64>,
    /// Playback state of the group, once a `group/update` arrived.
    ///
    /// `playing` and `stopped` are the values this revision defines; a paused group reports
    /// `stopped`. A value this revision does not name is carried verbatim.
    pub playback_state: Option<String>,
    /// Identifier of the group, once a `group/update` arrived.
    ///
    /// The spec gives it as 43 unpadded base64url characters; the default configuration also
    /// carries a well-formed foreign value such as a UUID, because a real server sends one. See
    /// [`ClientConfig::strict_group_id`] and [`Event::GroupIdNotCanonical`].
    pub group_id: Option<String>,
    /// Friendly name of the group, once a `group/update` arrived.
    pub group_name: Option<String>,
}

/// A live connection.
///
/// The connection reconnects on its own after a drop, so the handle and the event stream outlive
/// an individual session. Dropping the handle or the event stream ends it; [`ClientHandle::finished`]
/// waits without ending it.
#[derive(Debug)]
pub struct ClientHandle {
    pub(crate) task: Option<JoinHandle<Result<()>>>,
    pub(crate) control: ControlHandle,
    pub(crate) shutdown: Option<oneshot::Sender<GoodbyeReason>>,
}

impl ClientHandle {
    /// Returns a handle for the playback controls of this connection.
    ///
    /// The handle is a cheap clone; every copy controls the same connection.
    #[must_use]
    pub fn control(&self) -> ControlHandle {
        self.control.clone()
    }

    /// Stops the connection after telling the server why.
    ///
    /// The reason is sent as `client/goodbye` on the live connection before it closes; a client
    /// that is reconnecting has no connection to say it on. The goodbye is best effort: a write
    /// that fails neither turns the close into an error nor schedules another attempt. Dropping
    /// the handle does the same with [`GoodbyeReason::Shutdown`].
    pub fn close(&mut self, reason: GoodbyeReason) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(reason);
        }
    }

    /// Waits for the connection to end and returns its outcome.
    ///
    /// The connection ends when the handle or the event stream is dropped, when
    /// [`ClientHandle::close`] is called, or when the audio sink fails; a dropped session is
    /// reconnected, not returned. Awaiting this keeps the handle alive, so dropping the event
    /// stream is the usual way to stop.
    pub async fn finished(mut self) -> Result<()> {
        let task = self.task.take().expect("the handle owns its task");
        task.await.context("the connection task panicked")?
    }
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        // `finished` takes the task, so a handle that is only waiting on the connection does not
        // stop it; a handle that is dropped asks the connection to end and says why.
        if self.task.is_some() {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(GoodbyeReason::Shutdown);
            }
        }
    }
}

/// Playback controls for a live connection.
///
/// A call returns once the connection has handled it: a transport command or a seek has been
/// written to the server, and a level or mute change has been recorded and included in the next
/// state report. It is an error when the connection has ended, when no session is established at
/// that moment, and when the server did not activate the role the command belongs to: transport
/// commands and seeks need `controller@v1`, volume and mute state need `player@v1`. A transport
/// command or seek the server did not list in its controller state is refused as well, so a host
/// can offer exactly the buttons the server accepts. An absolute seek needs the reported range on
/// top of that, so it is refused before the first controller state.
#[derive(Debug, Clone)]
pub struct ControlHandle {
    pub(crate) commands: mpsc::UnboundedSender<ControlRequest>,
    pub(crate) volume: Arc<AtomicU8>,
    pub(crate) pairing_token: Option<PairingToken>,
}

/// The version-0 pairing token, held as the credential it is.
///
/// [`Debug`] prints `<redacted>`, so a log line that formats a [`ControlHandle`] never carries the
/// token, which would let anyone holding that line pair a server with this client.
#[derive(Clone)]
pub(crate) struct PairingToken(pub(crate) String);

impl fmt::Debug for PairingToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl ControlHandle {
    /// Resumes playback.
    pub async fn play(&self) -> Result<()> {
        self.transport("play").await
    }

    /// Pauses playback at the current position.
    pub async fn pause(&self) -> Result<()> {
        self.transport("pause").await
    }

    /// Skips to the next track.
    pub async fn next(&self) -> Result<()> {
        self.transport("next").await
    }

    /// Skips to the previous track.
    pub async fn previous(&self) -> Result<()> {
        self.transport("previous").await
    }

    /// Seeks to an absolute position in milliseconds.
    ///
    /// The server must offer `seek` and report a range: the target is checked against
    /// [`PlaybackState::seek_max_ms`], so a position beyond it is refused and nothing is sent.
    /// Before the first controller state neither the command nor the range is known, so an
    /// absolute seek is refused; [`ControlHandle::seek_relative`] follows the open-window rule of
    /// the other transport commands instead, because an offset needs no range.
    ///
    /// # Errors
    /// Returns an error when the connection has ended, when no session is established, when the
    /// server did not activate `controller@v1`, when it did not offer `seek`, when it reported no
    /// seekable range, and when `position_ms` is beyond that range. The last error names both the
    /// target and the range.
    pub async fn seek(&self, position_ms: u64) -> Result<()> {
        self.send(ControlAction::Seek(position_ms))
            .await
            .map(|_level| ())
    }

    /// Seeks by an offset in milliseconds from the current position; a negative offset rewinds.
    ///
    /// The server must offer `seek_relative`. The window before its first controller state is
    /// open, as it is for the other transport commands: an offset needs no known range, so there
    /// is nothing to check it against. An absolute [`ControlHandle::seek`] is different and is
    /// refused until the range is known.
    ///
    /// # Errors
    /// Returns an error when the connection has ended, when no session is established, when the
    /// server did not activate `controller@v1`, and when it did not offer `seek_relative`.
    pub async fn seek_relative(&self, offset_ms: i64) -> Result<()> {
        self.send(ControlAction::SeekRelative(offset_ms))
            .await
            .map(|_level| ())
    }

    /// Sets the output level, limited by [`ClientConfig::volume_policy`] against the level in
    /// force, and returns the level that was applied.
    ///
    /// The level belongs to the connection: the session reports the applied value to the server
    /// with its next state report, which is the initial report when the first clock measurement is
    /// still pending, and every reconnect keeps it. A new connection starts from
    /// [`ClientConfig::volume`], so a host passes the level it restored there and uses this call
    /// for changes after that. [`ControlHandle::volume`] answers what is in force without a call.
    pub async fn set_volume(&self, level: u8) -> Result<u8> {
        self.send(ControlAction::Volume(level)).await
    }

    /// Reports the level the device is actually at, without applying the volume policy.
    ///
    /// [`ControlHandle::set_volume`] treats its argument as a request, so the policy may lower it
    /// and above the threshold it limits one step. A host that knows the level its output is
    /// really at - because the device applied a level at its own control, or because another
    /// process raised it - reports that level with this call instead: it becomes the level in
    /// force, [`ControlHandle::volume`] returns it, and the next `client/state` carries it
    /// unchanged, so the server's view matches the output.
    ///
    /// The protocol's range still applies. A level above 100 is refused with an error before
    /// anything is recorded or sent; the policy is not consulted and does not clamp the value.
    ///
    /// # Errors
    /// Returns an error for a level above 100, for a connection that has ended, and when the
    /// server did not activate `player@v1`.
    pub async fn report_volume(&self, level: u8) -> Result<()> {
        check_reported_level(level)?;
        self.send(ControlAction::ReportVolume(level))
            .await
            .map(|_level| ())
    }

    /// Sets the mute state without changing the level.
    ///
    /// The reported level therefore stays what it was, and the server sees the mute in the
    /// `muted` field alone.
    pub async fn set_muted(&self, muted: bool) -> Result<()> {
        self.send(ControlAction::Mute(muted)).await.map(|_level| ())
    }

    /// Enables or disables unpaired access on the live connection.
    ///
    /// The value is what `client/hello` advertises and what the activation guard enforces.
    /// [`ClientConfig::unpaired_access`] is the value a `connect` call starts from. A live change is
    /// carried for the rest of that call - the next `client/hello` advertises it - and a new
    /// `connect` starts from the configuration again.
    ///
    /// Turning it off closes a connection that relies on it - an unpaired session with active roles
    /// or with the `playback` activity declared by an accepted activation - after saying goodbye
    /// with [`GoodbyeReason::PairingRequired`]. An unpaired session that relies on nothing yet stays
    /// open, and the existing activation guard refuses the next activation that would need unpaired
    /// access. A paired session is never closed by the setting, because the setting never applied to
    /// it. Turning it on stores the value and restarts an unpaired session with `client/goodbye`
    /// reason [`GoodbyeReason::Restart`]: `client/hello` is the only carrier of the advertisement,
    /// so a live connection cannot advertise the new value without a new one. A paired session is
    /// neither closed nor restarted, because the setting never applied to it. Pairing stays
    /// admissible in both directions, because the setting gates only roles and the `playback`
    /// activity, never pairing.
    ///
    /// # Errors
    /// Returns an error when the connection has ended, and when the connection is switching keys at
    /// that moment: the request is refused then, before anything is written, and the host can retry.
    /// A change made while the client is between connections is stored, not refused: it is what the
    /// next `client/hello` advertises.
    pub async fn set_unpaired_access(&self, enabled: bool) -> Result<()> {
        self.send(ControlAction::SetUnpairedAccess(enabled))
            .await
            .map(|_level| ())
    }

    /// Returns the volume level in force.
    ///
    /// The value follows every change the connection made or received, including a mute, which
    /// leaves it untouched. It is available without a call, so a host can render its slider while
    /// the connection is reconnecting.
    #[must_use]
    pub fn volume(&self) -> u8 {
        self.volume.load(Ordering::Relaxed)
    }

    /// The version-0 pairing token for this client, or `None` when no
    /// [`Storage`](crate::storage::Storage) is configured.
    ///
    /// The token is `SP:0` plus the base32 body of the identity's public key and the pairing PSK
    /// that was drawn or restored when the client started, so it is fixed for the client's
    /// lifetime and survives a reconnect. A token is a credential: anyone holding it can pair a
    /// server with this client, so a host renders it only while the operator needs it and never
    /// writes it into a log.
    #[must_use]
    pub fn pairing_token(&self) -> Option<String> {
        self.pairing_token.as_ref().map(|token| token.0.clone())
    }

    /// Opens a pairing window on the live connection and starts a waiting static-code attempt.
    ///
    /// The pairing window is the client's half of the static code flow's operator gesture: the host
    /// decides what the gesture is - a button press, a pinhole, a power-cycle pattern - and calls
    /// this when it happened. The window belongs to the connection that is live now, so it is
    /// opened there and closes when that connection ends, when the configured lifetime expires,
    /// when a pairing completes, or after five failed key confirmations.
    ///
    /// # Errors
    /// Returns an error when no connection is established at this moment. A call that arrives while
    /// the client is reconnecting is refused rather than remembered for the next connection, which
    /// the spec requires: a window admits attempts only on the connection that carries its gesture.
    #[cfg(feature = "pairing-code")]
    pub async fn open_pairing_window(&self) -> Result<()> {
        self.send(ControlAction::OpenPairingWindow)
            .await
            .map(|_level| ())
    }

    /// Releases the dynamic flow's round limit: the deliberate operator action the spec requires.
    ///
    /// After twenty rounds without a verified `server_kc`, the client aborts the attempt and holds
    /// further dynamic attempts back, answering their activations with `client/pair-pending`. The
    /// counter is not partitioned by server and only this call - or a verified `server_kc` - resets
    /// it. A host wires it to whatever gesture means "let this device try pairing again".
    ///
    /// Unlike a pairing window, the release needs no connection: the count belongs to the process,
    /// and the next connection starts from a clean one. The call still answers the current level,
    /// so it observes the same contract as the other control requests.
    #[cfg(feature = "pairing-code")]
    pub async fn release_holdback(&self) -> Result<()> {
        self.send(ControlAction::ReleaseHoldback)
            .await
            .map(|_level| ())
    }

    /// Sends one controller command.
    async fn transport(&self, command: &'static str) -> Result<()> {
        self.send(ControlAction::Transport(command))
            .await
            .map(|_level| ())
    }

    /// Queues one request and waits for the level in force after it.
    async fn send(&self, action: ControlAction) -> Result<u8> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(ControlRequest { action, reply })
            .map_err(|_| anyhow!("the connection has ended"))?;
        response
            .await
            .map_err(|_| anyhow!("the connection ended before it answered"))?
    }
}

/// What a [`ControlHandle`] asks the session to do.
#[derive(Debug)]
pub(crate) enum ControlAction {
    /// A controller command, by wire name.
    Transport(&'static str),
    /// Seek to an absolute position in milliseconds.
    Seek(u64),
    /// Seek by an offset in milliseconds; negative rewinds.
    SeekRelative(i64),
    /// Set the output level, subject to the volume limit.
    Volume(u8),
    /// Record the level the output is actually at, without the volume limit.
    ReportVolume(u8),
    /// Set the mute state, keeping the level.
    Mute(bool),
    /// Whether the connection admits an unpaired session, applied to the shared value.
    SetUnpairedAccess(bool),
    /// Open a pairing window for this connection and start a waiting static-code attempt.
    #[cfg(feature = "pairing-code")]
    OpenPairingWindow,
    /// Reset the dynamic flow's round counter and start the attempt it held back.
    #[cfg(feature = "pairing-code")]
    ReleaseHoldback,
}

/// One request from a [`ControlHandle`], with the channel its answer travels back on.
///
/// The answer is the volume level in force after the request; a transport command and a mute
/// leave it unchanged.
pub(crate) struct ControlRequest {
    /// Operation to perform.
    pub(crate) action: ControlAction,
    /// Answer for the waiting call.
    pub(crate) reply: oneshot::Sender<Result<u8>>,
}

/// The receiving end of a session's [`Event`] stream.
///
/// [`EventStream::next`] returns `None` once the connection has ended. An [`Event::Disconnected`]
/// is not necessarily the last event: the client reconnects and reports the next attempt's events
/// on the same stream, and only a fatal audio-sink failure or a dropped handle ends the sequence.
/// Dropping the stream ends the connection: the next time the client would emit an event, it stops
/// instead.
#[derive(Debug)]
pub struct EventStream {
    pub(crate) events: mpsc::UnboundedReceiver<Event>,
}

impl EventStream {
    /// Waits for the next event.
    pub async fn next(&mut self) -> Option<Event> {
        self.events.recv().await
    }
}

/// Namespaced entry point, for callers that prefer a type to the free function.
#[derive(Debug, Clone, Copy, Default)]
pub struct Client;

impl Client {
    /// Connects to `config.server` and returns the handle and event stream.
    ///
    /// See [`connect`] for the details.
    pub async fn connect(
        config: ClientConfig,
        sink: Box<dyn Sink>,
    ) -> Result<(ClientHandle, EventStream)> {
        connect(config, sink).await
    }

    /// Connects with pairing keys the host stores for known servers.
    ///
    /// See [`connect_with_psks`] for the details.
    pub async fn connect_with_psks(
        config: ClientConfig,
        sink: Box<dyn Sink>,
        psks: Vec<StoredPsk>,
    ) -> Result<(ClientHandle, EventStream)> {
        connect_with_psks(config, sink, psks).await
    }

    /// Advertises this client and serves the servers that connect to it.
    ///
    /// See [`advertise`](crate::advertise) for the details.
    #[cfg(feature = "discovery")]
    pub async fn advertise(
        config: ClientConfig,
        sink: Box<dyn Sink>,
    ) -> Result<(ClientHandle, EventStream)> {
        crate::advertise(config, sink).await
    }
}

/// Connects to a server and returns its handle and event stream.
///
/// The configuration is validated before this returns; the connection itself runs in a spawned
/// task and is reported through the event stream, with [`Event::Connected`] as the first event of a
/// successful attempt.
///
/// The task owns the sink and every attempt, so it reconnects after a drop with the same identity
/// and sink and with the level, mute state and roles the previous session had. Each drop is
/// reported as [`Event::Disconnected`] together with the delay before the next attempt. The
/// connection ends when the sink fails, which the host has to repair, or when the handle or the
/// event stream is dropped.
///
/// # Errors
/// Returns an error for an invalid [`ClientConfig`] and for a server address this build cannot use
/// (including a TLS URL). An unreachable server is not an error: the connection reports it as
/// [`Event::Disconnected`] and keeps retrying.
///
/// # Panics
/// Panics when called outside a Tokio runtime, because the connection is spawned.
pub async fn connect(
    config: ClientConfig,
    sink: Box<dyn Sink>,
) -> Result<(ClientHandle, EventStream)> {
    connect_with_psks(config, sink, Vec::new()).await
}

/// Connects with pairing keys the host stores for known servers.
///
/// The server announces a `psk_id` and `psk_category` in Noise message 1. A candidate matches when
/// its category and derived id both match the announcement; its `server_id` must then equal the one
/// in `server/init`. On a lookup miss the initial handshake continues with the published Sentinel
/// key, which is why [`connect`] is the same call with no candidates.
///
/// The keys are used for the handshake only; they are not stored or logged. A reconnect uses them
/// again, so a pairing that worked keeps working. A [`Storage`](crate::storage::Storage) configured
/// on `config` joins them: its records are read for every attempt, and on the same `server_id` the
/// stored record wins over `explicit`, because the store is the authority for the servers it knows.
/// The pairing PSK the store holds is always a candidate as well, whether or not a pairing is
/// running.
///
/// # Errors
/// Same as [`connect`]. A record that belongs to another server fails the handshake of that
/// attempt and is reported as [`Event::Disconnected`]. A store that cannot be read or cannot hold
/// the pairing PSK is reported from this call before the first attempt. A configuration with a
/// store makes the client draw and persist its pairing PSK on a device's first run.
pub async fn connect_with_psks(
    config: ClientConfig,
    sink: Box<dyn Sink>,
    psks: Vec<StoredPsk>,
) -> Result<(ClientHandle, EventStream)> {
    // connection.md, _Server Initiated Connections_: "Clients MUST NOT manually connect to servers
    // while advertising `_sendspin._tcp`." A client uses one of the two methods at a time, so a
    // configuration that advertises is refused here rather than connected on the side.
    #[cfg(feature = "discovery")]
    if config.inbound.is_some() {
        bail!(
            "this configuration advertises _sendspin._tcp, so it waits for a server to connect; \
             a manual connection is refused while advertising, as connection.md requires. Clear \
             ClientConfig::inbound to dial a server instead"
        );
    }
    config.validate()?;
    let endpoint = endpoint(&config.server)?;
    // The pairing PSK is settled before the first attempt, so a store that cannot hold it is
    // reported to the caller instead of a connection that silently cannot pair. A restored key is
    // used as it is; a missing one is drawn and stored once, here.
    let pairing = match config.storage.as_deref() {
        Some(storage) => Some(load_or_draw_pairing_psk(storage)?),
        None => None,
    };
    // The token is fixed once the key is settled: the identity and the pairing PSK do not change
    // while the client runs, so it is built here and carried by every control handle.
    let pairing_token = pairing
        .as_ref()
        .map(|psk| PairingToken(encode_v0(&config.identity.public, psk.as_bytes())));

    let (events, receiver) = mpsc::unbounded_channel();
    let (commands, control) = mpsc::unbounded_channel();
    let (shutdown, shutdown_rx) = oneshot::channel();
    let reported_volume = Arc::new(AtomicU8::new(config.volume));
    // The dynamic flow's round counter belongs to the process, not to a connection or a server:
    // only a verified `server_kc` or a deliberate operator action resets it.
    #[cfg(feature = "pairing-code")]
    let failed_rounds = Arc::new(AtomicU32::new(0));

    let carried = Carried {
        sink,
        control: Some(control),
        volume: config.volume,
        muted: config.muted,
        active_roles: Vec::new(),
        unpaired_access: Arc::new(AtomicBool::new(config.unpaired_access)),
        #[cfg(feature = "pairing-code")]
        failed_rounds,
    };
    let connection = Connection {
        endpoint,
        config,
        psks,
        pairing,
        events: events.clone(),
        reported_volume: Arc::clone(&reported_volume),
    };

    let task = tokio::spawn(serve_until_dropped(connection, carried, shutdown_rx));

    let handle = ClientHandle {
        task: Some(task),
        control: ControlHandle {
            commands,
            volume: reported_volume,
            pairing_token,
        },
        shutdown: Some(shutdown),
    };
    Ok((handle, EventStream { events: receiver }))
}

/// Opens one WebSocket, treating an address that does not answer as an error.
async fn open(endpoint: &str) -> Result<Transport> {
    tokio::time::timeout(CONNECT_TIMEOUT, Transport::connect(endpoint))
        .await
        .with_context(|| format!("timed out connecting to {endpoint}"))?
}

/// The parts of a connection that do not change across attempts.
struct Connection {
    endpoint: String,
    config: ClientConfig,
    psks: Vec<StoredPsk>,
    /// This client's pairing PSK, present exactly when a store is configured.
    pairing: Option<PairingPsk>,
    events: mpsc::UnboundedSender<Event>,
    /// Level shared with every [`ControlHandle`].
    reported_volume: Arc<AtomicU8>,
}

impl Connection {
    /// Delivers one event, ignoring a stream the host dropped.
    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }
}

/// One wake-up while no session is established.
enum Wakeup {
    /// A control handle sent a request.
    Control(Option<ControlRequest>),
    /// The delay elapsed.
    Deadline,
    /// The host dropped the event stream.
    Closed,
}

/// Answers a request that arrived while no session was established.
///
/// A pairing window belongs to a connection and is refused; releasing the round hold-back belongs
/// to the process and is honoured, and a change of the unpaired-access setting is stored for the
/// next `client/hello`, so an operator gesture made between connections is not lost.
pub(crate) fn answer_without_session(carried: &Carried, request: ControlRequest) {
    if let ControlAction::SetUnpairedAccess(enabled) = &request.action {
        carried.unpaired_access.store(*enabled, Ordering::Relaxed);
        let _ = request.reply.send(Ok(carried.volume));
        return;
    }
    #[cfg(feature = "pairing-code")]
    if matches!(request.action, ControlAction::ReleaseHoldback) {
        carried.failed_rounds.store(0, Ordering::SeqCst);
        let _ = request.reply.send(Ok(carried.volume));
        return;
    }
    let _ = request
        .reply
        .send(Err(anyhow!("no connection is established")));
}

/// Waits before the next attempt, answering control requests meanwhile.
///
/// Returns `false` when the host dropped the event stream and the connection should end.
async fn wait_before_retry(
    connection: &Connection,
    carried: &mut Carried,
    delay: Duration,
    shutdown: &mut oneshot::Receiver<GoodbyeReason>,
) -> bool {
    let deadline = tokio::time::Instant::now() + delay;
    loop {
        if connection.events.is_closed() {
            return false;
        }
        let control = &mut carried.control;
        let wakeup = tokio::select! {
            biased;
            request = async {
                match control {
                    Some(receiver) => receiver.recv().await,
                    None => std::future::pending().await,
                }
            } => Wakeup::Control(request),
            // No connection is open, so there is nothing to say goodbye on; the loop just ends.
            reason = &mut *shutdown => {
                let _ = reason;
                return false;
            }
            () = tokio::time::sleep_until(deadline) => Wakeup::Deadline,
            () = connection.events.closed() => Wakeup::Closed,
        };
        match wakeup {
            Wakeup::Control(Some(request)) => answer_without_session(carried, request),
            Wakeup::Control(None) => *control = None,
            Wakeup::Deadline => return true,
            Wakeup::Closed => return false,
        }
    }
}

/// Runs connection attempts until the host drops the connection or the sink fails.
///
/// Every attempt, including the first, is opened here. A failed one is followed by the next after
/// the delay [`next_backoff`] computes, with the sink, the level, the mute state and the roles
/// carried over. A [`ClientHandle::close`] or a dropped handle stops the loop after the live
/// session has had its chance to say goodbye.
async fn serve_until_dropped(
    connection: Connection,
    mut carried: Carried,
    mut shutdown: oneshot::Receiver<GoodbyeReason>,
) -> Result<()> {
    // The first attempt is not preceded by a wait, but the policy starts at the initial delay, so a
    // failure before any session connected reports two seconds: one growth step from that value.
    let mut delay = INITIAL_BACKOFF;

    loop {
        // A close that arrives while the attempt is still connecting has no session to say
        // goodbye on, so the loop ends as soon as it fires instead of waiting out the connect
        // timeout and reporting a failure the host did not cause.
        let transport = tokio::select! {
            result = open(&connection.endpoint) => result,
            reason = &mut shutdown => {
                let _ = reason;
                return Ok(());
            }
        };
        let transport = match transport {
            Ok(transport) => transport,
            Err(error) => {
                delay = next_backoff(delay, false, connection.config.max_backoff);
                connection.emit(Event::Disconnected {
                    reason: format!("cannot connect to {}: {error:#}", connection.endpoint),
                    retry_in: delay,
                });
                if !wait_before_retry(&connection, &mut carried, delay, &mut shutdown).await {
                    return Ok(());
                }
                continue;
            }
        };

        let attempt = session::attempt(
            transport,
            &connection.config,
            &connection.events,
            &connection.psks,
            connection.pairing,
            &connection.reported_volume,
            carried,
            &mut shutdown,
        )
        .await;
        carried = attempt.carried;

        // Nothing buffered for the session that ended may become audible later; the flush runs
        // before the host hears about the drop so the output stops even if the next attempt takes
        // a while.
        let flush_error = carried.sink.flush().err().map(|error| {
            error.context("the audio sink rejected a flush after the connection ended")
        });

        // A deliberate close is not a drop: nothing is reported and no attempt follows. The
        // goodbye was best effort, so neither its send nor the flush can turn it into an error.
        if matches!(&attempt.ending, session::Ending::Shutdown) {
            return Ok(());
        }

        // A broken output cannot be repaired by reconnecting, and neither can a flush that fails
        // after the session; both end the connection instead of scheduling another attempt.
        let fatal = attempt.sink_failed || flush_error.is_some();
        delay = if fatal {
            // No attempt follows, so there is no delay to recommend.
            Duration::ZERO
        } else {
            next_backoff(delay, attempt.connected, connection.config.max_backoff)
        };
        connection.emit(Event::Disconnected {
            reason: attempt.ending.reason(),
            retry_in: delay,
        });

        if attempt.sink_failed {
            // The host has to fix the sink; a retry would only fail the same way.
            return match attempt.ending {
                session::Ending::Failed(error) => Err(error),
                session::Ending::Closed
                | session::Ending::Unpaired
                | session::Ending::PairingRequired
                | session::Ending::UnpairedAccessOff
                | session::Ending::Restart
                | session::Ending::Unauthorized
                | session::Ending::Shutdown => Err(anyhow!("the audio sink failed")),
            };
        }
        if let Some(error) = flush_error {
            return Err(error);
        }

        if !wait_before_retry(&connection, &mut carried, delay, &mut shutdown).await {
            return Ok(());
        }
    }
}

/// Splits a URL tail into the part before a query or fragment and the marker onward.
fn split_marker(value: &str) -> (&str, &str) {
    match value.find(['?', '#']) {
        Some(index) => value.split_at(index),
        None => (value, ""),
    }
}

/// Builds the WebSocket URL for a configured server address.
///
/// A bare `host:port` uses the default `/sendspin` path, and so does a `ws://` URL without a path.
/// A URL with an explicit path is used unchanged. TLS is rejected: this build carries no TLS
/// stack, and pretending otherwise would end in a confusing connection error.
fn endpoint(server: &str) -> Result<String> {
    let server = server.trim();
    if server.is_empty() {
        bail!("the server address is empty");
    }
    if server.starts_with("wss://") {
        bail!("TLS is not supported by this build; use a ws:// address or host:port");
    }
    if let Some(rest) = server.strip_prefix("ws://") {
        if rest.is_empty() {
            bail!("the WebSocket address {server:?} names no host");
        }
        // A query or fragment belongs after the path, so the default path has to be inserted
        // before it rather than appended to the whole URL.
        let (before_marker, after_marker) = split_marker(rest);
        let Some((authority, path)) = before_marker.split_once('/') else {
            if before_marker.is_empty() {
                bail!("the WebSocket address {server:?} names no host");
            }
            return Ok(format!("ws://{before_marker}/sendspin{after_marker}"));
        };
        if authority.is_empty() {
            bail!("the WebSocket address {server:?} names no host");
        }
        if path.is_empty() {
            return Ok(format!("ws://{authority}/sendspin{after_marker}"));
        }
        return Ok(format!("ws://{before_marker}{after_marker}"));
    }
    if server.contains("://") {
        bail!("unsupported URL scheme in {server:?}; use ws:// or host:port");
    }
    let (before_marker, after_marker) = split_marker(server);
    if before_marker.is_empty() {
        bail!("the server address is empty");
    }
    Ok(format!("ws://{before_marker}/sendspin{after_marker}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_new_goodbye_reasons_use_the_wire_spelling() {
        assert_eq!(GoodbyeReason::PairingRequired.as_str(), "pairing_required");
        assert_eq!(GoodbyeReason::Unauthorized.as_str(), "unauthorized");
    }

    /// A pairing code is a credential for one attempt: `Debug` names it but never prints it.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn the_pairing_code_event_formats_without_its_code() {
        for (code, format) in [
            ("482913".to_owned(), CodeFormat::Digits),
            (
                "SP:1QJOHGMGBXP55Y6KMJD3KOYR9F6OWYD6QQPIKEFY".to_owned(),
                CodeFormat::QrCode,
            ),
        ] {
            let event = Event::PairingCode {
                code: code.clone(),
                format,
                round: 3,
            };
            let text = format!("{event:?}");
            assert!(text.contains("code: \"<redacted>\""), "got: {text}");
            assert!(
                !text.contains(&code),
                "the code must never reach a log line: {text}"
            );
            assert!(
                text.contains(&format!("format: {format:?}")),
                "the format is not secret: {text}"
            );
            assert!(text.contains("round: 3"), "the round is not secret: {text}");
        }
    }

    /// The record-lifecycle events name the server, which is not secret, and nothing else.
    #[test]
    fn the_record_lifecycle_events_format_their_server_id() {
        let server_id = "B1y4w7z0c3f6i9l2o5r8u1x4a7d0g3j6m9p2s5v8y1b".to_owned();

        let unpaired = format!(
            "{:?}",
            Event::Unpaired {
                server_id: server_id.clone(),
            }
        );
        assert!(
            unpaired.contains(&format!("Unpaired {{ server_id: \"{server_id}\" }}")),
            "got: {unpaired}"
        );

        let required = format!(
            "{:?}",
            Event::PairingRequired {
                server_id: server_id.clone(),
                reason: PairingRequiredReason::CredentialMismatch,
            }
        );
        assert!(required.contains(&server_id), "got: {required}");
        assert!(
            required.contains("CredentialMismatch"),
            "the reason is what the host acts on: {required}"
        );
        assert!(
            !required.contains("<redacted>"),
            "neither event carries a secret, so neither redacts a field: {required}"
        );
    }

    /// The tolerance event reports the length and never the identifier itself.
    #[test]
    fn the_group_id_tolerance_event_formats_its_length() {
        let text = format!("{:?}", Event::GroupIdNotCanonical { len: 36 });
        assert_eq!(text, "GroupIdNotCanonical { len: 36 }");
    }

    /// Every other event keeps the fields a log line needs.
    #[test]
    fn an_event_still_formats_its_readable_fields() {
        let text = format!(
            "{:?}",
            Event::Disconnected {
                reason: "the server closed the connection".to_owned(),
                retry_in: Duration::from_secs(2),
            }
        );
        assert!(
            text.contains("Disconnected { reason: \"the server closed the connection\""),
            "got: {text}"
        );
        assert!(text.contains("retry_in: 2s"), "got: {text}");
    }

    #[test]
    fn every_abort_reason_round_trips_through_the_wire_spelling() {
        for (wire, reason) in [
            ("attempt_timeout", PairingFailure::AttemptTimeout),
            ("method_not_supported", PairingFailure::MethodNotSupported),
            ("pairing_code_mismatch", PairingFailure::PairingCodeMismatch),
            ("user_cancelled", PairingFailure::UserCancelled),
            ("concurrent_attempt", PairingFailure::ConcurrentAttempt),
        ] {
            assert_eq!(reason.as_str(), wire);
            assert_eq!(PairingFailure::from_wire(wire), reason);
        }

        // A reason from a later revision is carried, not rejected.
        assert_eq!(
            PairingFailure::from_wire("future_reason"),
            PairingFailure::Unrecognised("future_reason".to_owned())
        );
        assert_eq!(
            PairingFailure::Unrecognised("future_reason".to_owned()).as_str(),
            "future_reason"
        );
    }

    #[test]
    fn a_bare_address_gets_the_default_websocket_endpoint() {
        assert_eq!(
            endpoint("192.0.2.10:8927").unwrap(),
            "ws://192.0.2.10:8927/sendspin"
        );
        assert_eq!(
            endpoint(" 192.0.2.10:8927 ").unwrap(),
            "ws://192.0.2.10:8927/sendspin"
        );
        assert_eq!(
            endpoint("ws://example.test:1").unwrap(),
            "ws://example.test:1/sendspin"
        );
        assert_eq!(
            endpoint("ws://example.test:1/").unwrap(),
            "ws://example.test:1/sendspin"
        );
        assert_eq!(
            endpoint("ws://example.test:1/player").unwrap(),
            "ws://example.test:1/player"
        );
    }

    #[test]
    fn a_query_or_fragment_stays_after_the_default_path() {
        assert_eq!(
            endpoint("ws://example.test:1?token=1").unwrap(),
            "ws://example.test:1/sendspin?token=1"
        );
        assert_eq!(
            endpoint("ws://example.test:1#frag").unwrap(),
            "ws://example.test:1/sendspin#frag"
        );
        assert_eq!(
            endpoint("ws://example.test:1/?token=1").unwrap(),
            "ws://example.test:1/sendspin?token=1"
        );
        assert_eq!(
            endpoint("ws://example.test:1/player?token=1").unwrap(),
            "ws://example.test:1/player?token=1"
        );
        assert_eq!(
            endpoint("example.test:1?token=1").unwrap(),
            "ws://example.test:1/sendspin?token=1"
        );
    }

    #[test]
    fn an_address_this_build_cannot_use_is_rejected() {
        for server in [
            "",
            "   ",
            "wss://example.test",
            "https://example.test",
            "ws://",
            "ws://?token=1",
            "ws://#fragment",
            "ws:///player",
            "?token=1",
            "#fragment",
        ] {
            assert!(
                endpoint(server).is_err(),
                "{server:?} must not be turned into a cleartext endpoint"
            );
        }
    }

    use crate::test_support::NullSink;

    /// Builds the parts of a connection that do not change across attempts.
    fn connection_at(endpoint: &str, events: mpsc::UnboundedSender<Event>) -> Connection {
        Connection {
            endpoint: endpoint.to_owned(),
            config: ClientConfig {
                server: endpoint.to_owned(),
                player_name: "Test player".to_owned(),
                device_info: None,
                identity: crate::Identity::generate(),
                storage: None,
                audio_mode: crate::AudioMode::Passthrough,
                volume: 42,
                muted: false,
                volume_policy: VolumePolicy::default(),
                max_backoff: Duration::from_secs(30),
                strict_group_id: false,
                unpaired_access: true,
                pairing_timeout: DEFAULT_PAIRING_TIMEOUT,
                #[cfg(feature = "discovery")]
                inbound: None,
                #[cfg(feature = "pairing-code")]
                static_pairing_code: None,
                #[cfg(feature = "pairing-code")]
                pairing_window: crate::DEFAULT_PAIRING_WINDOW,
                #[cfg(feature = "pairing-code")]
                pairing_pending_text: None,
                #[cfg(feature = "pairing-code")]
                code_formats: Vec::new(),
                #[cfg(feature = "pairing-code")]
                code_out_channels: Vec::new(),
            },
            psks: Vec::new(),
            pairing: None,
            events,
            reported_volume: Arc::new(AtomicU8::new(42)),
        }
    }

    fn empty_carried(control: Option<mpsc::UnboundedReceiver<ControlRequest>>) -> Carried {
        Carried {
            sink: Box::new(NullSink),
            control,
            volume: 42,
            muted: false,
            active_roles: Vec::new(),
            unpaired_access: Arc::new(AtomicBool::new(true)),
            #[cfg(feature = "pairing-code")]
            failed_rounds: Arc::new(AtomicU32::new(0)),
        }
    }

    /// A shutdown receiver the test never fires; its sender is leaked so the receiver stays open.
    fn idle_shutdown() -> oneshot::Receiver<GoodbyeReason> {
        let (sender, receiver) = oneshot::channel();
        Box::leak(Box::new(sender));
        receiver
    }

    #[tokio::test]
    async fn a_retry_wait_without_a_control_handle_still_honours_the_delay() {
        let (events, _receiver) = mpsc::unbounded_channel();
        let connection = connection_at("127.0.0.1:1", events);
        let (commands, control) = mpsc::unbounded_channel();
        drop(commands);
        let mut carried = empty_carried(Some(control));
        let mut shutdown = idle_shutdown();

        let started = std::time::Instant::now();
        let retry = wait_before_retry(
            &connection,
            &mut carried,
            Duration::from_millis(50),
            &mut shutdown,
        )
        .await;

        assert!(retry, "the delay elapsed, so the next attempt must follow");
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "the delay must be waited out, not skipped"
        );
        assert!(
            carried.control.is_none(),
            "a control channel whose senders are gone is dropped"
        );
    }

    #[tokio::test]
    async fn dropping_the_event_stream_during_a_retry_ends_the_connection() {
        let (events, receiver) = mpsc::unbounded_channel();
        let connection = connection_at("127.0.0.1:1", events);
        let mut carried = empty_carried(None);
        let mut shutdown = idle_shutdown();

        let retry = wait_before_retry(
            &connection,
            &mut carried,
            Duration::from_secs(60),
            &mut shutdown,
        );
        tokio::pin!(retry);
        let mut finished = false;
        tokio::select! {
            _ = &mut retry => finished = true,
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
        assert!(!finished, "the wait must not end while the stream is open");

        drop(receiver);
        assert!(
            !retry.await,
            "a dropped event stream must stop the retry loop"
        );
    }

    #[tokio::test]
    async fn a_failed_attempt_with_no_event_stream_ends_the_connection() {
        // Bind and release a loopback port, so the open fails immediately rather than timing out.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a loopback port");
        let address = listener.local_addr().expect("the bound address");
        drop(listener);

        let (events, receiver) = mpsc::unbounded_channel();
        drop(receiver);
        let connection = connection_at(&address.to_string(), events);

        let outcome = serve_until_dropped(connection, empty_carried(None), idle_shutdown()).await;
        assert!(
            outcome.is_ok(),
            "a host that dropped the stream ends the connection cleanly"
        );
    }

    /// A close that arrives while the socket is still opening ends the loop at once, without an
    /// `Event::Disconnected` for a failure the host did not cause.
    #[tokio::test]
    async fn a_close_during_the_connect_ends_without_a_disconnected_event() {
        // A loopback listener that never accepts: the TCP connection is queued by the kernel and
        // the WebSocket handshake answers nothing, so the open stays in flight.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a loopback port");
        let address = listener.local_addr().expect("the bound address");
        let url = format!("ws://{address}/sendspin");

        let (events, mut receiver) = mpsc::unbounded_channel();
        let connection = connection_at(&url, events);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(serve_until_dropped(
            connection,
            empty_carried(None),
            shutdown_rx,
        ));

        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown
            .send(GoodbyeReason::UserRequest)
            .expect("the connection loop is still waiting");

        let outcome = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the close must not wait out the connect timeout")
            .expect("the connection task panicked");
        assert!(
            outcome.is_ok(),
            "a close during the connect is clean: {outcome:?}"
        );
        if let Ok(event) = receiver.try_recv() {
            panic!(
                "no failure event may be reported for a close the host asked for, got {event:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_namespace_entry_points_wrap_the_free_functions() {
        // A bad configuration is rejected by both before any socket is opened, which pins the
        // forwarding: a wrapper that inverted the result would not return this error.
        let mut config = connection_at("127.0.0.1:1", mpsc::unbounded_channel().0).config;
        config.player_name.clear();
        let error = Client::connect(config, Box::new(NullSink))
            .await
            .expect_err("an invalid configuration must be rejected");
        assert!(format!("{error:#}").contains("player_name"));

        let mut config = connection_at("127.0.0.1:1", mpsc::unbounded_channel().0).config;
        config.server = "wss://example.test".to_owned();
        let error = Client::connect_with_psks(config, Box::new(NullSink), Vec::new())
            .await
            .expect_err("a TLS address must be rejected before connecting");
        assert!(format!("{error:#}").contains("TLS"));
    }
}
