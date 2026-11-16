//! The pairing method this client offers, and the state of one pairing attempt.
//!
//! Two methods are implemented. The Pairing PSK flow, which the protocol makes mandatory for every
//! client, is offered exactly when a [`Storage`] is configured, because the method needs a pairing
//! PSK that survives restarts and a place to write the record the pairing produces. A client
//! without a store advertises no pairing method at all and answers a pairing activation with
//! `pair/abort` reason `method_not_supported`.
//!
//! The static pairing code flow is offered when the `pairing-code` feature is on,
//! [`ClientConfig::static_pairing_code`](crate::ClientConfig::static_pairing_code) holds a code and
//! a store can persist the record it produces. It runs one CPace round per attempt, gated by a
//! pairing window the host opens; this module holds the CPace values between the messages, the
//! session owns the window and the messages.
//!
//! The dynamic pairing code flow is offered when the same feature is on,
//! [`ClientConfig::code_formats`](crate::ClientConfig::code_formats) and
//! [`ClientConfig::code_out_channels`](crate::ClientConfig::code_out_channels) are set and a store
//! exists. It draws a nonce per attempt, commits to it in `client/pair-init`, derives the code once
//! the server's nonce arrives, and runs CPace rounds until the server's key confirmation verifies.
//! This module holds the binding values and the round state; the session emits the code, sends the
//! messages and counts the rounds against the limit.
//!
//! # Key material
//!
//! The pairing PSK and the long-term PSK of an attempt are key material. Both are wrapped in types
//! whose `Debug` prints `<redacted>`, and neither is ever formatted into an event or an error. The
//! static code, the CPace intermediate session key and the key-confirmation tags are secrets of
//! the same kind: they live in types without a formatting implementation, and the tags leave this
//! module only as base64 on the wire. The dynamic flow's `nonce_B` is secret until it is revealed,
//! sealed, in `client/pair-confirm`; it is never formatted, and the code it contributes to is only
//! handed to the session for deliberate emission.

use std::fmt;
use std::time::{Duration, Instant};

#[cfg(feature = "pairing-code")]
use anyhow::bail;
use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

#[cfg(feature = "pairing-code")]
use syncspin_core::pairing::code::commitment;
#[cfg(feature = "pairing-code")]
use syncspin_core::pairing::code::DynamicCode;
#[cfg(feature = "pairing-code")]
use syncspin_core::pairing::pake::{self, SHARE_LEN, TAG_LEN};
#[cfg(feature = "pairing-code")]
use syncspin_core::pairing::wrap::{self, NONCE_LABEL, PSK_LABEL};
#[cfg(feature = "pairing-code")]
use zeroize::Zeroizing;

#[cfg(feature = "pairing-code")]
use crate::config::CodeFormat;
use crate::config::{PskCategory, StoredPsk};
use crate::storage::Storage;
#[cfg(feature = "pairing-code")]
use syncspin_core::noise::Suite;
use syncspin_core::noise::SENTINEL_PSK;

/// Method identifier of the Pairing PSK flow, as it is spelled on the wire.
pub(crate) const METHOD_PAIRING_PSK: &str = "pairing_psk";

/// Method identifier of the Static Pairing Code flow, as it is spelled on the wire.
#[cfg(feature = "pairing-code")]
pub(crate) const METHOD_STATIC_PAIRING_CODE: &str = "static_pairing_code";

/// Method identifier of the Dynamic Pairing Code flow, as it is spelled on the wire.
#[cfg(feature = "pairing-code")]
pub(crate) const METHOD_DYNAMIC_PAIRING_CODE: &str = "dynamic_pairing_code";

/// The label that starts every CPace `sid`, as `pairing.md` fixes it.
#[cfg(feature = "pairing-code")]
const PAKE_SID_LABEL: &[u8] = b"sendspin-pair-pake-v1";

/// CPace associated data of the initiator, which is the server.
#[cfg(feature = "pairing-code")]
const AD_SERVER: &[u8] = b"server";

/// CPace associated data of the responder, which is the client.
#[cfg(feature = "pairing-code")]
const AD_CLIENT: &[u8] = b"client";

/// The round number of the static flow's only round.
#[cfg(feature = "pairing-code")]
pub(crate) const STATIC_CODE_ROUND: u32 = 1;

/// Length of a wrapped payload: 32 bytes of ciphertext and a 16-byte tag.
#[cfg(feature = "pairing-code")]
const SEALED_LEN: usize = 48;

/// Builds the CPace session id of one attempt: `label || h || pairing_index || round`.
///
/// All four parts are raw; `h` is the Noise handshake hash and both indexes are big-endian `u32`,
/// exactly as `pairing.md` defines `sid`. The value is public but bound to one handshake, and it
/// separates every attempt of every connection.
#[cfg(feature = "pairing-code")]
pub(crate) fn pake_sid(handshake_hash: &[u8; 32], pairing_index: u32, round: u32) -> Vec<u8> {
    let mut sid = Vec::with_capacity(PAKE_SID_LABEL.len() + 32 + 8);
    sid.extend_from_slice(PAKE_SID_LABEL);
    sid.extend_from_slice(handshake_hash);
    sid.extend_from_slice(&pairing_index.to_be_bytes());
    sid.extend_from_slice(&round.to_be_bytes());
    sid
}

/// This client's pairing PSK.
///
/// The value is a credential: anyone holding it can pair a server with this client. It is drawn
/// once and restored from [`Storage`] afterwards, so it survives restarts and stays among the
/// handshake candidates of every connection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PairingPsk(pub(crate) [u8; 32]);

impl PairingPsk {
    /// Returns the key for the handshake.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PairingPsk {
    /// Formats the key redacted, so `Debug` output is safe to log.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PairingPsk")
            .field(&"<redacted>")
            .finish()
    }
}

/// Returns the pairing PSK the host restored, drawing and storing one on a device's first run.
///
/// A key the host holds is used as it is, so pairing survives a restart and a second process; a
/// missing key is drawn from the operating system's CSPRNG and handed back through
/// [`Storage::store_pairing_psk`] before it is used. The crate never rotates a key on its own.
pub(crate) fn load_or_draw_pairing_psk(storage: &dyn Storage) -> Result<PairingPsk> {
    if let Some(psk) = storage
        .pairing_psk()
        .context("the pairing store did not return the pairing PSK")?
    {
        return Ok(PairingPsk(psk));
    }
    let psk = draw_key();
    storage
        .store_pairing_psk(&psk)
        .context("the pairing store did not accept the new pairing PSK")?;
    Ok(PairingPsk(psk))
}

/// Draws 32 bytes from the operating system's CSPRNG.
///
/// # Panics
/// Panics if the CSPRNG is unavailable, as [`syncspin_core::noise::Identity::generate`] does: a
/// silent substitute would be a weak key.
fn draw_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("the operating system CSPRNG is available");
    key
}

/// Draws the long-term PSK one attempt delivers, never one the protocol forbids.
///
/// `pairing.md` calls a delivered long-term PSK equal to the published Sentinel PSK, or to the
/// pairing PSK the connection is keyed by, a protocol error. The chance of drawing either is
/// negligible, but the check is cheap and a conformant client resamples rather than relying on it.
/// `pairing_psk` is this client's pairing PSK when the connection could be keyed by it.
fn draw_long_term_psk(pairing_psk: Option<[u8; 32]>) -> [u8; 32] {
    draw_long_term_psk_with(pairing_psk, draw_key)
}

/// [`draw_long_term_psk`] with an injectable generator, so a test can force a forbidden draw.
fn draw_long_term_psk_with(
    pairing_psk: Option<[u8; 32]>,
    mut draw: impl FnMut() -> [u8; 32],
) -> [u8; 32] {
    loop {
        let key = draw();
        if key != SENTINEL_PSK && pairing_psk != Some(key) {
            return key;
        }
    }
}

/// The keys one connection attempt may seal the Noise handshake with.
///
/// The pairing PSK is always present when a store is configured, whether or not a pairing activity
/// is running, because the server may re-handshake to it at any time. The records are re-read for
/// every attempt, so a record a completed pairing stored is a candidate for the next connection.
#[derive(Debug, Clone)]
pub(crate) struct Candidates {
    /// This client's pairing PSK, when a store is configured.
    pairing: Option<PairingPsk>,
    /// Records of known servers, the store's first and any host-supplied ones after it.
    records: Vec<StoredPsk>,
}

impl Candidates {
    /// Builds the candidate set for one attempt.
    ///
    /// The store is read on every attempt. `explicit` records - the ones
    /// [`connect_with_psks`](crate::connect_with_psks) receives - join the set beside the stored
    /// records; a record for a server the store already holds is dropped, because the store is the
    /// authority for the servers it knows. A store that cannot be read is an error, never a
    /// fallback: silently continuing with fewer keys would downgrade a paired connection to the
    /// Sentinel key.
    pub(crate) fn load(
        storage: Option<&dyn Storage>,
        explicit: &[StoredPsk],
        pairing: Option<PairingPsk>,
    ) -> Result<Candidates> {
        let mut records = match storage {
            Some(storage) => storage
                .load_pairings()
                .context("the pairing store did not return its records")?,
            None => Vec::new(),
        };
        for record in explicit {
            if !records
                .iter()
                .any(|held| held.server_id == record.server_id)
            {
                records.push(record.clone());
            }
        }
        Ok(Candidates { pairing, records })
    }

    /// Returns this client's pairing PSK, or `None` without a store.
    pub(crate) fn pairing(&self) -> Option<[u8; 32]> {
        self.pairing.map(|psk| *psk.as_bytes())
    }

    /// Adds a record this client just persisted, so a re-handshake to it can select the key.
    ///
    /// The store was read once, at the start of the attempt; a pairing that completes while the
    /// connection is live writes a record the set did not hold yet, and the server rotates the
    /// connection to exactly that key. One record per server, as [`Candidates::load`] keeps it.
    pub(crate) fn remember(&mut self, record: StoredPsk) {
        self.records
            .retain(|held| held.server_id != record.server_id);
        self.records.push(record);
    }

    /// Returns the records that may seal this connection.
    pub(crate) fn records(&self) -> &[StoredPsk] {
        &self.records
    }
}

/// Which key sealed the Noise handshake of a connection.
///
/// It decides what the server may ask of this connection: the pairing method is admissible only
/// on a connection keyed by this client's own pairing PSK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchedPsk {
    /// The published Sentinel key, which authenticates nothing.
    Sentinel,
    /// This client's pairing PSK.
    PairingPsk,
    /// A stored record, filed under its category.
    Stored(PskCategory),
}

/// Which method one attempt runs, and how far its code flow has gone.
///
/// The Pairing PSK flow sends both of its messages back to back, so it has one state. The code
/// flows alternate with the server: init, the two CPace shares, the two tags, then the finalize.
#[cfg(feature = "pairing-code")]
enum Flow {
    /// The Pairing PSK flow, which sends `client/pair-init` and `client/pair-finalize` at once.
    PairingPsk,
    /// The Static Pairing Code flow, in the phase its one CPace round is in.
    Static(CodePhase),
    /// The Dynamic Pairing Code flow, holding the binding values and the current round.
    Dynamic(DynamicFlow),
}

/// The values the Dynamic Pairing Code Flow holds between `client/pair-init` and the finalize.
///
/// The binding values are fixed per attempt and unchanged across rounds: `nonce_B` is drawn once,
/// its commitment is what `client/pair-init` locked, and `nonce_A` arrives in the first round's
/// `server/pair-init`. The derived code lives here as a type without a formatting implementation,
/// so a host sees it only through the event the session emits.
#[cfg(feature = "pairing-code")]
struct DynamicFlow {
    /// This client's nonce, kept private until it is sealed into `client/pair-confirm`.
    nonce_b: [u8; 32],
    /// The server's nonce from the first round, or `None` before that message arrived.
    nonce_a: Option<[u8; 32]>,
    /// The derived code, once both nonces are known.
    code: Option<DynamicCode>,
    /// The emission format the activation selected.
    format: CodeFormat,
    /// The round this attempt is in; `0` before the first `server/pair-init`.
    round: u32,
    /// The phase of the round in progress.
    phase: CodePhase,
}

/// How far one CPace round of a code flow has gone.
#[cfg(feature = "pairing-code")]
enum CodePhase {
    /// A dynamic round has not begun: the server's `server/pair-init` is awaited.
    RoundStart,
    /// `client/pair-init` is on the wire; the server's share is awaited.
    Auth,
    /// Both shares crossed; the server's tag is awaited and ours is ready to send.
    Confirm(Box<RoundProof>),
    /// Both tags crossed and the sealed key is on the wire; `server/pair-finalize` is awaited.
    Finalization,
}

#[cfg(feature = "pairing-code")]
impl CodePhase {
    /// Whether the round has not begun yet.
    fn is_round_start(&self) -> bool {
        matches!(self, CodePhase::RoundStart)
    }

    /// Whether the server's CPace share is awaited.
    fn is_auth(&self) -> bool {
        matches!(self, CodePhase::Auth)
    }

    /// Whether the server's key-confirmation tag is awaited.
    fn is_confirm(&self) -> bool {
        matches!(self, CodePhase::Confirm(_))
    }

    /// Whether `server/pair-finalize` is awaited.
    fn is_finalization(&self) -> bool {
        matches!(self, CodePhase::Finalization)
    }
}

/// The values one CPace round holds between `server/pair-auth` and `server/pair-confirm`.
///
/// The CPace intermediate session key is not kept: the two tags and the seals are everything the
/// following messages need, and they are dropped once the finalize is sent. The static flow seals
/// only the long-term PSK; the dynamic flow additionally seals `nonce_B`, the opening of the
/// commitment `client/pair-init` sent.
#[cfg(feature = "pairing-code")]
struct RoundProof {
    /// `Ta`, the server's tag this client expects in `server/pair-confirm`.
    expected_server_tag: [u8; TAG_LEN],
    /// `Tb`, this client's tag for `client/pair-confirm`.
    client_tag: [u8; TAG_LEN],
    /// The long-term PSK sealed under `K_wrap`, for `client/pair-finalize`.
    wrapped_psk: [u8; SEALED_LEN],
    /// `nonce_B` sealed under the nonce label, for the dynamic flow's `client/pair-confirm`.
    wrapped_nonce_b: Option<[u8; SEALED_LEN]>,
}

/// What a verified `server_kc` releases: the fields of the messages that follow.
///
/// All of them are derived from key material, so the type has no formatting implementation.
#[cfg(feature = "pairing-code")]
pub(crate) struct Confirmation {
    /// `Tb` as 86 unpadded base64url characters, for `client/pair-confirm`.
    pub(crate) client_kc: String,
    /// The sealed long-term PSK as 64 unpadded base64url characters, for `client/pair-finalize`.
    pub(crate) wrapped_psk: String,
    /// The sealed `nonce_B` as 64 unpadded base64url characters, in the dynamic flow only.
    pub(crate) wrapped_nonce_b: Option<String>,
}

/// The code one round shows the operator.
///
/// `code` is the text a host displays or speaks: six digits in the `digits` format, a version-1
/// token in `qr_code`. It is the protocol's deliberate out-channel emission, not an accidental
/// format of a secret, and the session carries it into [`Event::PairingCode`](crate::Event).
#[cfg(feature = "pairing-code")]
pub(crate) struct CodeEmission {
    /// The operator-facing code: six digits, or the version-1 token string.
    pub(crate) code: String,
    /// The emission format the client was activated with.
    pub(crate) format: CodeFormat,
    /// The round this emission belongs to, counting from `1`.
    pub(crate) round: u32,
}

/// What verifying `server_kc` decided.
#[cfg(feature = "pairing-code")]
pub(crate) enum TagOutcome {
    /// The tag verified; the two messages that follow may carry these fields.
    Confirmed(Confirmation),
    /// The tag did not verify. The dynamic flow rewound to its next round; the static flow leaves
    /// the decision to its caller.
    Mismatch,
}

/// One pairing attempt in progress.
///
/// The attempt begins with `client/pair-init` and ends with `server/pair-finalize`, a `pair/abort`
/// in either direction, a cancelling `server/activate`, or the attempt timeout. The long-term PSK
/// travels to the server in `client/pair-finalize` and is kept here until the server confirms that
/// it persisted its side, because only then may the client store its record.
pub(crate) struct PairingAttempt {
    /// Number of the pairing `server/activate` that admitted this attempt.
    pub(crate) pairing_index: u32,
    /// When the attempt is aborted as timed out.
    pub(crate) deadline: Instant,
    /// The long-term PSK sent to the server, kept until `server/pair-finalize`.
    psk: [u8; 32],
    /// The method this attempt runs.
    #[cfg(feature = "pairing-code")]
    flow: Flow,
}

impl PairingAttempt {
    /// Starts an attempt, drawing the long-term PSK this pairing will deliver.
    ///
    /// `pairing_psk` is this client's pairing PSK when the connection may be keyed by it; the drawn
    /// key never equals it or the Sentinel PSK.
    pub(crate) fn new(
        pairing_index: u32,
        timeout: Duration,
        pairing_psk: Option<[u8; 32]>,
    ) -> PairingAttempt {
        PairingAttempt {
            pairing_index,
            deadline: Instant::now() + timeout,
            psk: draw_long_term_psk(pairing_psk),
            #[cfg(feature = "pairing-code")]
            flow: Flow::PairingPsk,
        }
    }

    /// Starts a static-code attempt, which waits for the server's CPace share.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn static_code(
        pairing_index: u32,
        timeout: Duration,
        pairing_psk: Option<[u8; 32]>,
    ) -> PairingAttempt {
        PairingAttempt {
            pairing_index,
            deadline: Instant::now() + timeout,
            psk: draw_long_term_psk(pairing_psk),
            flow: Flow::Static(CodePhase::Auth),
        }
    }

    /// Starts a dynamic-code attempt, which waits for the server's `server/pair-init`.
    ///
    /// `nonce_B` is drawn here, once, so the commitment `client/pair-init` carries is fixed for the
    /// whole attempt - across every round and every retry. `format` is the emission format the
    /// activation selected and decides how the derived code is presented and what its CPace `PRS`
    /// are.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn dynamic_code(
        pairing_index: u32,
        timeout: Duration,
        pairing_psk: Option<[u8; 32]>,
        format: CodeFormat,
    ) -> PairingAttempt {
        PairingAttempt {
            pairing_index,
            deadline: Instant::now() + timeout,
            psk: draw_long_term_psk(pairing_psk),
            flow: Flow::Dynamic(DynamicFlow {
                nonce_b: draw_key(),
                nonce_a: None,
                code: None,
                format,
                round: 0,
                phase: CodePhase::RoundStart,
            }),
        }
    }

    /// Whether this attempt runs the Static Pairing Code flow.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn is_static_code(&self) -> bool {
        matches!(self.flow, Flow::Static(_))
    }

    /// Whether this attempt runs the Dynamic Pairing Code flow.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn is_dynamic_code(&self) -> bool {
        matches!(self.flow, Flow::Dynamic(_))
    }

    /// Returns `commit_B` for `client/pair-init`, or `None` outside the dynamic flow.
    ///
    /// The commitment is public: it locks `nonce_B` without revealing it, and the server verifies
    /// the opening it receives in `client/pair-confirm` against it.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn commit_b(&self) -> Option<String> {
        match &self.flow {
            Flow::Dynamic(state) => Some(URL_SAFE_NO_PAD.encode(commitment(&state.nonce_b))),
            _ => None,
        }
    }

    /// Whether the server's `server/pair-init` is the message this attempt is waiting for.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn awaiting_server_init(&self) -> bool {
        matches!(
            self.flow,
            Flow::Dynamic(DynamicFlow {
                phase: CodePhase::RoundStart,
                ..
            })
        )
    }

    /// Whether the server's CPace share is the message this attempt is waiting for.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn awaiting_server_auth(&self) -> bool {
        self.phase_is(CodePhase::is_auth)
    }

    /// Whether the server's key-confirmation tag is the message this attempt is waiting for.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn awaiting_server_confirm(&self) -> bool {
        self.phase_is(CodePhase::is_confirm)
    }

    /// Whether `server/pair-finalize` is the message this attempt is waiting for.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn awaiting_finalize(&self) -> bool {
        self.phase_is(CodePhase::is_finalization)
    }

    /// Returns whether the round's phase satisfies `check`.
    #[cfg(feature = "pairing-code")]
    fn phase_is(&self, check: fn(&CodePhase) -> bool) -> bool {
        match &self.flow {
            Flow::Static(phase) => check(phase),
            Flow::Dynamic(state) => check(&state.phase),
            Flow::PairingPsk => false,
        }
    }

    /// Returns the number of the round in progress: `1` for the static flow's only round.
    ///
    /// # Errors
    ///
    /// Fails for a dynamic attempt whose first `server/pair-init` has not been accepted yet. That
    /// attempt has no round number, and handing out `1` for it would derive the `sid` of a round
    /// that never ran instead of reporting the sequence violation.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn round(&self) -> Result<u32> {
        match &self.flow {
            Flow::Dynamic(state) => {
                if state.round == 0 {
                    bail!("the dynamic pairing attempt has no round number yet");
                }
                Ok(state.round)
            }
            _ => Ok(STATIC_CODE_ROUND),
        }
    }

    /// Returns the code one round shows the operator, or `None` outside the dynamic flow.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn code_emission(&self) -> Option<CodeEmission> {
        let Flow::Dynamic(state) = &self.flow else {
            return None;
        };
        let code = state.code.as_ref()?;
        Some(CodeEmission {
            code: match state.format {
                CodeFormat::Digits => code.digits_text(),
                CodeFormat::QrCode => code.qr_token(),
            },
            format: state.format,
            round: state.round,
        })
    }

    /// Returns the CPace `PRS` of the derived code, or `None` outside the dynamic flow.
    ///
    /// The static flow's `PRS` is its configured code, which the caller passes directly; the
    /// dynamic flow's is derived, so it lives with the attempt.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn prs(&self) -> Option<Vec<u8>> {
        let Flow::Dynamic(state) = &self.flow else {
            return None;
        };
        let code = state.code.as_ref()?;
        Some(match state.format {
            CodeFormat::Digits => code.digits().to_vec(),
            CodeFormat::QrCode => code.qr_payload().to_vec(),
        })
    }

    /// Begins a dynamic round from the server's `server/pair-init` and returns its emission.
    ///
    /// The first round must carry `nonce_A`, and the code is derived from it, the handshake hash
    /// and the attempt's own nonce. Later rounds carry no nonce: `pairing.md` puts it in the first
    /// round only, so a repeat is a message no conformant server sends and a protocol error either
    /// way. The round number increases per message, so every round has its own CPace `sid`.
    ///
    /// # Errors
    ///
    /// Fails when the attempt is not a dynamic one, when the message is out of sequence for its
    /// phase, when the first round's nonce is missing, or when a later round carries one.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn begin_round(
        &mut self,
        nonce_a: Option<[u8; 32]>,
        handshake_hash: &[u8; 32],
    ) -> Result<CodeEmission> {
        let Flow::Dynamic(state) = &mut self.flow else {
            bail!("the attempt does not run the dynamic pairing code flow");
        };
        if !state.phase.is_round_start() {
            bail!("the attempt is not waiting for server/pair-init");
        }
        match (state.nonce_a, nonce_a) {
            (None, None) => {
                bail!("the first round's server/pair-init carries no nonce_A")
            }
            (None, Some(nonce)) => state.nonce_a = Some(nonce),
            (Some(_), Some(_)) => {
                // Only the first round carries the server's half of the binding; a repeat, equal or
                // not, is a message no conformant server sends.
                bail!("the server repeated nonce_A after the first round")
            }
            (Some(_), None) => {}
        }
        state.round = state.round.saturating_add(1);
        if state.code.is_none() {
            let nonce_a = state
                .nonce_a
                .expect("the first round set the server nonce before the code is derived");
            state.code = Some(DynamicCode::derive(
                handshake_hash,
                &nonce_a,
                &state.nonce_b,
            ));
        }
        state.phase = CodePhase::Auth;
        self.code_emission()
            .ok_or_else(|| anyhow::anyhow!("the pairing code was not derived"))
    }

    /// Answers `server/pair-auth`: derives the shared point, both tags and the seals.
    ///
    /// `sid` is [`pake_sid`] of this attempt and round, and `prs` is the pairing code's CPace `PRS`:
    /// the configured code's digits for the static flow, or the code this attempt derived for the
    /// dynamic one. The function returns `Yb`, the share `client/pair-auth` carries. The CPace
    /// intermediate session key stays inside this call; only what the next two messages need is
    /// kept.
    ///
    /// `suite` is the cipher suite the connection negotiated, because the spec seals the two
    /// wrapped fields with that suite's AEAD. The session passes the suite of the transport the
    /// pairing exchange runs inside.
    ///
    /// # Errors
    ///
    /// Fails when the round is not waiting for the server's share, when the server's share
    /// encodes a low-order point, which the draft requires the round to abort, and when the
    /// build cannot seal under `suite`. The session treats that as a protocol error and closes
    /// the connection.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn accept_server_share(
        &mut self,
        prs: &[u8],
        sid: &[u8],
        peer_share: &[u8; SHARE_LEN],
        suite: Suite,
    ) -> Result<[u8; SHARE_LEN]> {
        if !self.awaiting_server_auth() {
            bail!("the attempt is not waiting for the server's CPace share");
        }

        let generator = pake::generator(prs, b"", sid);
        // A fresh scalar per round: reusing one would link rounds, and the draft samples a new one
        // for every run. It is scrubbed when the round's key material is derived.
        let scalar = Zeroizing::new(draw_key());
        let share = pake::public_share(&scalar, &generator)
            .context("the CPace generator did not yield a group element")?;

        // The peer's share is verified before a transcript is built from it.
        let point = Zeroizing::new(pake::scalar_mult_vfy(&scalar, peer_share)?);
        let transcript = pake::transcript_ir(peer_share, AD_SERVER, &share, AD_CLIENT);
        let isk = Zeroizing::new(pake::intermediate_session_key(sid, &point[..], &transcript));
        let expected_server_tag = pake::key_confirmation_tag(sid, &isk, peer_share, AD_SERVER);
        let client_tag = pake::key_confirmation_tag(sid, &isk, &share, AD_CLIENT);
        let psk_key = Zeroizing::new(wrap::k_wrap(PSK_LABEL, sid, &isk));
        let wrapped_psk = wrap::wrap(suite, &psk_key, &self.psk)?;
        let wrapped_nonce_b = match &self.flow {
            Flow::Dynamic(state) => {
                let nonce_key = Zeroizing::new(wrap::k_wrap(NONCE_LABEL, sid, &isk));
                Some(wrap::wrap(suite, &nonce_key, &state.nonce_b)?)
            }
            _ => None,
        };

        let proof = RoundProof {
            expected_server_tag,
            client_tag,
            wrapped_psk,
            wrapped_nonce_b,
        };
        match &mut self.flow {
            Flow::Static(phase) => *phase = CodePhase::Confirm(Box::new(proof)),
            Flow::Dynamic(state) => state.phase = CodePhase::Confirm(Box::new(proof)),
            Flow::PairingPsk => bail!("the attempt does not run a code flow"),
        }
        Ok(share)
    }

    /// Verifies `server_kc` and, when it matches, releases the fields to send next.
    ///
    /// A mismatch is [`TagOutcome::Mismatch`]. The dynamic flow rewinds to its next round there and
    /// leaves the retry decision to the caller, which owns the round limit; the static flow stays
    /// in its confirmation phase for the caller to abort. The comparison is constant-time and the
    /// release happens only after it succeeds, so a peer that cannot derive the key never sees the
    /// sealed nonce or the sealed long-term PSK.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn verify_server_tag(&mut self, received: &[u8; TAG_LEN]) -> TagOutcome {
        let proof = match &mut self.flow {
            Flow::Static(CodePhase::Confirm(proof)) => proof,
            Flow::Dynamic(state) => match &mut state.phase {
                CodePhase::Confirm(proof) => proof,
                _ => return TagOutcome::Mismatch,
            },
            _ => return TagOutcome::Mismatch,
        };
        if !pake::verify_key_confirmation_tag(&proof.expected_server_tag, received) {
            if let Flow::Dynamic(state) = &mut self.flow {
                // The round is over; the same code, the same binding values and the same deadline
                // carry into the next one, which begins with `server/pair-init`.
                state.phase = CodePhase::RoundStart;
            }
            return TagOutcome::Mismatch;
        }
        let confirmation = Confirmation {
            client_kc: URL_SAFE_NO_PAD.encode(proof.client_tag),
            wrapped_psk: URL_SAFE_NO_PAD.encode(proof.wrapped_psk),
            wrapped_nonce_b: proof
                .wrapped_nonce_b
                .map(|sealed| URL_SAFE_NO_PAD.encode(sealed)),
        };
        match &mut self.flow {
            Flow::Static(phase) => *phase = CodePhase::Finalization,
            Flow::Dynamic(state) => state.phase = CodePhase::Finalization,
            Flow::PairingPsk => unreachable!("only a code flow has a round to confirm"),
        }
        TagOutcome::Confirmed(confirmation)
    }

    /// Returns the long-term PSK as the 43-character unpadded base64url the wire carries.
    pub(crate) fn psk_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.psk)
    }

    /// Returns the long-term PSK the record has to hold.
    pub(crate) fn psk(&self) -> [u8; 32] {
        self.psk
    }
}

impl fmt::Debug for PairingAttempt {
    /// Formats the attempt without the key it carries, its nonce or a code it derived.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("PairingAttempt");
        debug
            .field("pairing_index", &self.pairing_index)
            .field("deadline", &self.deadline)
            .field("psk", &"<redacted>");
        #[cfg(feature = "pairing-code")]
        {
            let flow = match &self.flow {
                Flow::PairingPsk => "pairing_psk",
                Flow::Static(phase) => match phase {
                    CodePhase::RoundStart => "static_pairing_code/round_start",
                    CodePhase::Auth => "static_pairing_code/awaiting_auth",
                    CodePhase::Confirm(_) => "static_pairing_code/awaiting_confirm",
                    CodePhase::Finalization => "static_pairing_code/awaiting_finalize",
                },
                Flow::Dynamic(state) => match state.phase {
                    CodePhase::RoundStart => "dynamic_pairing_code/awaiting_server_init",
                    CodePhase::Auth => "dynamic_pairing_code/awaiting_auth",
                    CodePhase::Confirm(_) => "dynamic_pairing_code/awaiting_confirm",
                    CodePhase::Finalization => "dynamic_pairing_code/awaiting_finalize",
                },
            };
            debug.field("flow", &flow);
            if let Flow::Dynamic(state) = &self.flow {
                // The round number is not secret; the nonce and the code are.
                debug
                    .field("round", &state.round)
                    .field("nonce_b", &"<redacted>")
                    .field("code", &state.code.as_ref().map(|_| "<redacted>"));
            }
        }
        debug.finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::MemoryStore;

    /// A key that is recognisable in a formatted value.
    const KEY: [u8; 32] = [0x5a; 32];

    fn record(server_id: &str) -> StoredPsk {
        StoredPsk {
            category: PskCategory::LongTerm,
            psk: KEY,
            server_id: server_id.to_owned(),
        }
    }

    #[test]
    fn a_restored_pairing_psk_is_used_as_it_is() {
        let storage = MemoryStore::holding(KEY);
        let psk = load_or_draw_pairing_psk(&storage).expect("the stored key is accepted");
        assert_eq!(psk.as_bytes(), &KEY);
        assert_eq!(
            storage.stored_pairing_psks(),
            0,
            "a restored key must never be replaced"
        );
    }

    #[test]
    fn a_missing_pairing_psk_is_drawn_once_and_stored() {
        let storage = MemoryStore::default();
        let psk = load_or_draw_pairing_psk(&storage).expect("a key is drawn");
        assert_eq!(
            storage.pairing_psk_value().as_ref(),
            Some(psk.as_bytes()),
            "the drawn key must be the one the store keeps"
        );
        assert_eq!(storage.stored_pairing_psks(), 1);
        assert_ne!(psk.as_bytes(), &[0u8; 32], "a drawn key is not all zeroes");

        // A second call restores the stored key instead of drawing another one.
        let again = load_or_draw_pairing_psk(&storage).expect("the stored key is accepted");
        assert_eq!(again.as_bytes(), psk.as_bytes());
        assert_eq!(storage.stored_pairing_psks(), 1, "a key is never rotated");
    }

    #[test]
    fn a_store_that_fails_is_reported_and_never_silently_replaced() {
        let error = load_or_draw_pairing_psk(&MemoryStore::failing_reads())
            .expect_err("a read failure is an error");
        assert!(
            format!("{error:#}").contains("pairing PSK"),
            "got: {error:#}"
        );

        let error = load_or_draw_pairing_psk(&MemoryStore::failing_writes())
            .expect_err("a write failure is an error");
        assert!(
            format!("{error:#}").contains("did not accept"),
            "got: {error:#}"
        );
    }

    #[test]
    fn the_candidates_read_the_store_and_let_the_store_win() {
        let storage = MemoryStore::default();
        storage.preload(record("from-store"));
        let explicit = [record("from-host"), record("from-store")];
        let candidates = Candidates::load(Some(&storage), &explicit, None).unwrap();

        let ids: Vec<&str> = candidates
            .records()
            .iter()
            .map(|record| record.server_id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["from-store", "from-host"],
            "the store's records come first and its record for a server wins"
        );
        assert_eq!(candidates.pairing(), None);

        let pairing = PairingPsk(KEY);
        let candidates = Candidates::load(None, &[], Some(pairing)).unwrap();
        assert_eq!(candidates.pairing(), Some(KEY));
        assert!(candidates.records().is_empty());
    }

    #[test]
    fn a_record_stored_during_the_connection_becomes_a_candidate() {
        let mut candidates =
            Candidates::load(None, &[record("from-host")], None).expect("the set builds");
        assert_eq!(candidates.records().len(), 1);

        // A later store for the same server replaces the earlier record instead of duplicating it.
        candidates.remember(record("from-host"));
        assert_eq!(
            candidates.records().len(),
            1,
            "one record per server, as the store keeps it"
        );

        // A server this client had no record for is added, so its re-handshake can select it.
        candidates.remember(record("just-paired"));
        let ids: Vec<&str> = candidates
            .records()
            .iter()
            .map(|record| record.server_id.as_str())
            .collect();
        assert_eq!(ids, vec!["from-host", "just-paired"]);
    }

    #[test]
    fn a_store_that_cannot_be_read_is_an_error() {
        let error = Candidates::load(Some(&MemoryStore::failing_reads()), &[], None)
            .expect_err("a read failure must not fall back to fewer keys");
        assert!(format!("{error:#}").contains("records"), "got: {error:#}");
    }

    #[test]
    fn key_material_is_redacted_in_every_debug_format() {
        let encoded = URL_SAFE_NO_PAD.encode(KEY);
        let pairing = PairingPsk(KEY);
        let attempt = PairingAttempt::new(1, Duration::from_secs(120), None);
        let candidates = Candidates {
            pairing: Some(pairing),
            records: vec![record("a-server")],
        };

        for text in [
            format!("{pairing:?}"),
            format!("{attempt:?}"),
            format!("{candidates:?}"),
        ] {
            assert!(text.contains("<redacted>"), "unexpected format: {text}");
            assert!(
                !text.contains(&encoded),
                "the key must not appear encoded: {text}"
            );
            assert!(
                !text.contains(&format!("{KEY:?}")),
                "not even the raw bytes may appear: {text}"
            );
        }
    }

    #[test]
    fn an_attempt_expires_at_its_configured_timeout() {
        let started = Instant::now();
        let attempt = PairingAttempt::new(4, Duration::from_secs(120), None);
        assert_eq!(attempt.pairing_index, 4);
        assert!(attempt.deadline >= started + Duration::from_secs(120));
        assert_ne!(attempt.psk(), [0u8; 32], "the attempt draws its own key");
        assert_eq!(
            attempt.psk_base64().len(),
            43,
            "the wire carries the key unpadded base64url"
        );
    }

    #[test]
    fn a_drawn_long_term_psk_is_never_a_forbidden_key() {
        let pairing = [0x11; 32];
        let allowed = [0x22; 32];

        // The published Sentinel key and the connection's pairing PSK are both refused, in that
        // order, and the first allowed draw is the one returned.
        let mut draws = [SENTINEL_PSK, pairing, allowed].into_iter();
        let key = draw_long_term_psk_with(Some(pairing), || {
            draws.next().expect("the sequence holds enough draws")
        });
        assert_eq!(key, allowed);
        assert!(
            draws.next().is_none(),
            "the loop stops at the first allowed key"
        );

        // Without a connection pairing PSK the Sentinel key is still refused.
        let mut draws = [SENTINEL_PSK, allowed].into_iter();
        assert_eq!(
            draw_long_term_psk_with(None, || {
                draws.next().expect("the sequence holds enough draws")
            }),
            allowed
        );
    }

    /// The candidate set has to be usable through an `Arc`, like the one a configuration holds.
    #[test]
    fn a_store_behind_an_arc_is_still_a_candidate_source() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStore::holding(KEY));
        let candidates = Candidates::load(Some(storage.as_ref()), &[], None).unwrap();
        assert!(candidates.records().is_empty());
    }

    /// The configured static code these tests use; its digits are CPace's `PRS`.
    #[cfg(feature = "pairing-code")]
    const CODE: &str = "12345678";

    /// Runs the client half of one static-code round against a server half built here.
    ///
    /// Returns the attempt between the two tags, the client's share, and what the server derives:
    /// its tag and the intermediate session key.
    #[cfg(feature = "pairing-code")]
    fn static_round() -> (PairingAttempt, Vec<u8>, [u8; 32], [u8; 64], [u8; 64]) {
        let sid = pake_sid(&[0x33; 32], 7, STATIC_CODE_ROUND);
        let generator = pake::generator(CODE.as_bytes(), b"", &sid);
        let server_scalar = [0x44; 32];
        let peer_share = pake::public_share(&server_scalar, &generator).expect("a group element");

        let mut attempt = PairingAttempt::static_code(7, Duration::from_secs(120), None);
        let share = attempt
            .accept_server_share(CODE.as_bytes(), &sid, &peer_share, Suite::ChaChaPoly)
            .expect("the server's share is a group element");

        let point = pake::scalar_mult_vfy(&server_scalar, &share).expect("a group element");
        let transcript = pake::transcript_ir(&peer_share, b"server", &share, b"client");
        let isk = pake::intermediate_session_key(&sid, &point, &transcript);
        let server_tag = pake::key_confirmation_tag(&sid, &isk, &peer_share, b"server");
        (attempt, sid, share, server_tag, isk)
    }

    /// `sid` is the label, the handshake hash and two big-endian indexes, all raw.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn the_pake_sid_is_the_label_handshake_hash_and_indexes() {
        let handshake_hash = [0x11; 32];
        let sid = pake_sid(&handshake_hash, 0x0102_0304, 1);

        let mut expected = Vec::from(b"sendspin-pair-pake-v1".as_slice());
        expected.extend_from_slice(&handshake_hash);
        expected.extend_from_slice(&[1, 2, 3, 4]);
        expected.extend_from_slice(&[0, 0, 0, 1]);
        assert_eq!(sid, expected);
        assert_eq!(sid.len(), 21 + 32 + 8, "label, h and two u32");

        assert_ne!(
            pake_sid(&handshake_hash, 1, 1),
            pake_sid(&handshake_hash, 2, 1)
        );
        assert_ne!(
            pake_sid(&handshake_hash, 1, 1),
            pake_sid(&handshake_hash, 1, 2)
        );
        let mut other_hash = handshake_hash;
        other_hash[0] ^= 0x01;
        assert_ne!(pake_sid(&other_hash, 1, 1), sid);
    }

    /// The client's two values agree with the server's and the seal opens to the long-term PSK.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_static_attempt_seals_the_key_and_releases_it_only_after_the_server_tag() {
        let (mut attempt, sid, share, server_tag, isk) = static_round();
        assert!(attempt.awaiting_server_confirm());

        // Nothing is released before the verification succeeds: a single flipped bit is a mismatch,
        // and the caller aborts the attempt instead of sending anything.
        let mut tampered = server_tag;
        tampered[0] ^= 0x80;
        assert!(matches!(
            attempt.verify_server_tag(&tampered),
            TagOutcome::Mismatch
        ));
        assert!(
            attempt.awaiting_server_confirm(),
            "a mismatch leaves the attempt for the caller to abort"
        );

        let TagOutcome::Confirmed(confirmation) = attempt.verify_server_tag(&server_tag) else {
            panic!("the server's tag verifies");
        };
        assert!(attempt.awaiting_finalize());

        // `client_kc` is Tb over the client's own share and associated data.
        assert_eq!(
            confirmation.client_kc,
            URL_SAFE_NO_PAD.encode(pake::key_confirmation_tag(&sid, &isk, &share, b"client"))
        );

        // `wrapped_psk` is 48 bytes that open under K_wrap to the key the record will hold.
        let sealed: [u8; 48] = URL_SAFE_NO_PAD
            .decode(&confirmation.wrapped_psk)
            .expect("the sealed key is base64url")
            .try_into()
            .expect("a sealed value is 48 bytes");
        let key = wrap::k_wrap(PSK_LABEL, &sid, &isk);
        assert_eq!(
            wrap::unwrap(Suite::ChaChaPoly, &key, &sealed)
                .expect("the seal opens under the server's key"),
            attempt.psk(),
            "the server recovers exactly the long-term PSK the record keeps"
        );
        assert_ne!(
            attempt.psk(),
            [0u8; 32],
            "the attempt draws its own long-term key"
        );
    }

    /// A CPace value never reaches a `Debug` format, not even the tag the server sends.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_static_attempt_formats_without_its_cpace_values() {
        let (attempt, _sid, _share, server_tag, _isk) = static_round();
        let text = format!("{attempt:?}");
        assert!(
            text.contains("static_pairing_code/awaiting_confirm"),
            "the phase is not secret and names itself: {text}"
        );
        assert!(text.contains("psk: \"<redacted>\""), "got: {text}");
        assert!(
            !text.contains(&URL_SAFE_NO_PAD.encode(server_tag)),
            "the tag must never appear: {text}"
        );
        assert!(
            !text.contains(&format!("{server_tag:?}")),
            "not even the raw tag bytes may appear: {text}"
        );

        // The state a fresh attempt has is described, not dumped, as well.
        let fresh = PairingAttempt::static_code(1, Duration::from_secs(120), None);
        let text = format!("{fresh:?}");
        assert!(
            text.contains("static_pairing_code/awaiting_auth"),
            "got: {text}"
        );
        assert!(fresh.is_static_code());
        assert!(!fresh.awaiting_server_confirm());
        assert!(!fresh.awaiting_finalize());
    }

    /// The handshake hash the dynamic unit tests derive their codes from.
    #[cfg(feature = "pairing-code")]
    const HASH: [u8; 32] = [0x33; 32];

    /// The server nonce the dynamic unit tests use.
    #[cfg(feature = "pairing-code")]
    const NONCE_A: [u8; 32] = [0x51; 32];

    /// The client nonce the dynamic unit tests pin, so the derivation can be recomputed.
    #[cfg(feature = "pairing-code")]
    const NONCE_B: [u8; 32] = [0x77; 32];

    /// A dynamic attempt between `client/pair-init` and the first `server/pair-init`.
    ///
    /// The struct is built here so the client nonce is the pinned one: the production constructor
    /// draws it, and a test that has to recompute the derivation cannot see it otherwise.
    #[cfg(feature = "pairing-code")]
    fn dynamic_attempt(format: CodeFormat) -> PairingAttempt {
        PairingAttempt {
            pairing_index: 9,
            deadline: Instant::now() + Duration::from_secs(120),
            psk: [0x2a; 32],
            flow: Flow::Dynamic(DynamicFlow {
                nonce_b: NONCE_B,
                nonce_a: None,
                code: None,
                format,
                round: 0,
                phase: CodePhase::RoundStart,
            }),
        }
    }

    /// The commitment is the digest of the nonce the attempt keeps, and each attempt has its own.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_dynamic_attempt_commits_to_a_fresh_nonce() {
        let attempt = dynamic_attempt(CodeFormat::Digits);
        let commitment = attempt.commit_b().expect("the dynamic flow commits");
        assert_eq!(
            commitment,
            URL_SAFE_NO_PAD.encode(syncspin_core::pairing::code::commitment(&NONCE_B)),
            "the commitment is the digest of the pinned nonce"
        );
        assert!(attempt.awaiting_server_init());
        assert!(!attempt.awaiting_server_auth());
        assert!(attempt.is_dynamic_code());
        assert!(!attempt.is_static_code());

        let other =
            PairingAttempt::dynamic_code(9, Duration::from_secs(120), None, CodeFormat::Digits);
        assert_ne!(
            commitment,
            other.commit_b().expect("the other attempt commits too"),
            "a second attempt commits to a different nonce"
        );

        // The static flow has no nonce to commit to.
        let static_attempt = PairingAttempt::static_code(1, Duration::from_secs(120), None);
        assert_eq!(static_attempt.commit_b(), None);
    }

    /// The first round derives the pinned code from `h`, `nonce_A` and the attempt's nonce.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_dynamic_round_derives_the_code_both_sides_repeat() {
        let mut attempt = dynamic_attempt(CodeFormat::Digits);
        let first = attempt
            .begin_round(Some(NONCE_A), &HASH)
            .expect("the first round carries nonce_A");
        let expected = DynamicCode::derive(&HASH, &NONCE_A, &NONCE_B);

        assert_eq!(first.round, 1);
        assert_eq!(first.format, CodeFormat::Digits);
        assert_eq!(first.code, expected.digits_text());
        assert_eq!(
            attempt.prs().as_deref(),
            Some(expected.digits().as_slice()),
            "the digits are also CPace's PRS"
        );
        assert!(attempt.awaiting_server_auth());

        // The same instant, so the retry comparison below is about the deadline and nothing else.
        let deadline = attempt.deadline;
        fail_the_round(&mut attempt);
        let retried = attempt
            .begin_round(None, &HASH)
            .expect("a later round carries no nonce");
        assert_eq!(retried.round, 2);
        assert_eq!(retried.code, first.code, "the code does not change");
        assert_eq!(
            attempt.deadline, deadline,
            "a retry keeps the attempt's deadline"
        );

        assert!(
            attempt.begin_round(None, &HASH).is_err(),
            "a third round may not begin while the second is running"
        );
    }

    /// A QR attempt presents and feeds CPace with the same 24-byte code.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_qr_attempt_uses_the_24_byte_code() {
        let mut attempt = dynamic_attempt(CodeFormat::QrCode);
        let first = attempt
            .begin_round(Some(NONCE_A), &HASH)
            .expect("the first round carries nonce_A");
        let expected = DynamicCode::derive(&HASH, &NONCE_A, &NONCE_B);

        assert_eq!(first.code, expected.qr_token());
        assert!(first.code.starts_with("SP:1"));
        assert_eq!(
            attempt.prs().as_deref(),
            Some(expected.qr_payload().as_slice()),
            "the raw 24-byte code is CPace's PRS"
        );
    }

    /// A missing first-round nonce, a repeated one and a changed later one are protocol errors.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_round_rejects_a_missing_or_repeated_server_nonce() {
        let mut attempt = dynamic_attempt(CodeFormat::Digits);
        assert!(
            attempt.begin_round(None, &HASH).is_err(),
            "the first round has to carry nonce_A"
        );

        attempt
            .begin_round(Some(NONCE_A), &HASH)
            .expect("the first round is accepted");

        // A round has to end before the next one can begin; the retry is where the nonce must be
        // absent again.
        fail_the_round(&mut attempt);
        assert!(
            attempt.begin_round(Some(NONCE_A), &HASH).is_err(),
            "a repeated nonce_A in a later round is a message no conformant server sends"
        );
        let mut changed = NONCE_A;
        changed[0] ^= 0x01;
        assert!(
            attempt.begin_round(Some(changed), &HASH).is_err(),
            "a changed nonce_A would silently change the operator's code"
        );

        // The retry that carries no nonce is the one the spec describes.
        let retried = attempt
            .begin_round(None, &HASH)
            .expect("a later round carries no nonce_A");
        assert_eq!(
            retried.code,
            DynamicCode::derive(&HASH, &NONCE_A, &NONCE_B).digits_text(),
            "the binding values, and so the code, stay the same"
        );

        // A static attempt has no round to begin.
        let mut static_attempt = PairingAttempt::static_code(1, Duration::from_secs(120), None);
        assert!(static_attempt.begin_round(Some(NONCE_A), &HASH).is_err());
    }

    /// A dynamic attempt before its first `server/pair-init` has no round number.
    ///
    /// Reporting `1` there would derive the `sid` of a round that never began; the call reports
    /// the sequence violation instead.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_dynamic_attempt_without_a_round_reports_a_protocol_error() {
        let mut attempt = dynamic_attempt(CodeFormat::Digits);
        assert!(
            attempt.round().is_err(),
            "an attempt with round 0 has no round number"
        );

        attempt
            .begin_round(Some(NONCE_A), &HASH)
            .expect("the first round is accepted");
        assert_eq!(attempt.round().expect("the round has a number"), 1);

        let static_attempt = PairingAttempt::static_code(1, Duration::from_secs(120), None);
        assert_eq!(
            static_attempt
                .round()
                .expect("the static flow has one round"),
            STATIC_CODE_ROUND,
            "the static flow's only round is round 1"
        );
    }

    /// Completes the client half of the round in progress against a server half built here.
    ///
    /// Returns the round's `sid`, the server's tag and the intermediate session key, so a test can
    /// verify, unwrap or deliberately trip the server's side.
    #[cfg(feature = "pairing-code")]
    fn cross_the_round(attempt: &mut PairingAttempt) -> (Vec<u8>, [u8; 64], [u8; 64]) {
        let prs = attempt.prs().expect("the code was derived");
        let sid = pake_sid(
            &HASH,
            attempt.pairing_index,
            attempt.round().expect("the round has a number"),
        );
        let generator = pake::generator(&prs, b"", &sid);
        let server_scalar = [0x44; 32];
        let peer_share = pake::public_share(&server_scalar, &generator).expect("a group element");
        let share = attempt
            .accept_server_share(&prs, &sid, &peer_share, Suite::ChaChaPoly)
            .expect("the server's share is a group element");

        let point = pake::scalar_mult_vfy(&server_scalar, &share).expect("a group element");
        let transcript = pake::transcript_ir(&peer_share, b"server", &share, b"client");
        let isk = pake::intermediate_session_key(&sid, &point, &transcript);
        let server_tag = pake::key_confirmation_tag(&sid, &isk, &peer_share, b"server");
        (sid, server_tag, isk)
    }

    /// Runs the round in progress into a failed `server_kc`, which rewinds it to the next round.
    #[cfg(feature = "pairing-code")]
    fn fail_the_round(attempt: &mut PairingAttempt) {
        let (_sid, server_tag, _isk) = cross_the_round(attempt);
        let mut tampered = server_tag;
        tampered[0] ^= 0x80;
        assert!(matches!(
            attempt.verify_server_tag(&tampered),
            TagOutcome::Mismatch
        ));
        assert!(
            attempt.awaiting_server_init(),
            "a failed round waits for the next server/pair-init"
        );
    }

    /// Runs one dynamic round against a server half built here.
    ///
    /// Returns the attempt between the two tags, the round's `sid`, the server's tag and the
    /// intermediate session key.
    #[cfg(feature = "pairing-code")]
    fn dynamic_round(format: CodeFormat) -> (PairingAttempt, Vec<u8>, [u8; 64], [u8; 64]) {
        let mut attempt = dynamic_attempt(format);
        let emission = attempt
            .begin_round(Some(NONCE_A), &HASH)
            .expect("the first round carries nonce_A");
        let prs = attempt.prs().expect("the code was derived");
        assert_eq!(
            prs.len(),
            match format {
                CodeFormat::Digits => 6,
                CodeFormat::QrCode => 24,
            },
            "the PRS belongs to the emission format: {}",
            emission.code.len()
        );

        let (sid, server_tag, isk) = cross_the_round(&mut attempt);
        (attempt, sid, server_tag, isk)
    }

    /// The revealed nonce opens the commitment, and only after the server's tag verifies.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_dynamic_attempt_seals_the_nonce_and_releases_it_only_after_the_server_tag() {
        let (mut attempt, sid, server_tag, isk) = dynamic_round(CodeFormat::Digits);
        assert!(attempt.awaiting_server_confirm());

        // A mismatch rewinds the round instead of releasing anything.
        let mut tampered = server_tag;
        tampered[0] ^= 0x80;
        assert!(matches!(
            attempt.verify_server_tag(&tampered),
            TagOutcome::Mismatch
        ));
        assert!(
            attempt.awaiting_server_init(),
            "a failed round waits for the next server/pair-init"
        );
        assert!(
            attempt.code_emission().is_some(),
            "the code survives the failed round"
        );

        // The next round has its own sid, so the seal from the failed one is never reused.
        let emission = attempt
            .begin_round(None, &HASH)
            .expect("the retry's round begins without a nonce");
        assert_eq!(emission.round, 2);
        let (retry_sid, retry_tag, retry_isk) = cross_the_round(&mut attempt);

        let TagOutcome::Confirmed(confirmation) = attempt.verify_server_tag(&retry_tag) else {
            panic!("the server's tag verifies");
        };
        assert!(attempt.awaiting_finalize());

        // `wrapped_nonce_B` opens under the nonce label of this round to the pinned nonce.
        let sealed: [u8; 48] = URL_SAFE_NO_PAD
            .decode(
                confirmation
                    .wrapped_nonce_b
                    .as_deref()
                    .expect("the dynamic flow seals its nonce"),
            )
            .expect("the sealed nonce is base64url")
            .try_into()
            .expect("a sealed value is 48 bytes");
        let nonce_key = wrap::k_wrap(NONCE_LABEL, &retry_sid, &retry_isk);
        assert_eq!(
            wrap::unwrap(Suite::ChaChaPoly, &nonce_key, &sealed)
                .expect("the seal opens under the server's key"),
            NONCE_B,
            "the server recovers exactly the nonce it committed to"
        );

        // The long-term key is sealed under the PSK label of the same round.
        let sealed_psk: [u8; 48] = URL_SAFE_NO_PAD
            .decode(&confirmation.wrapped_psk)
            .expect("the sealed key is base64url")
            .try_into()
            .expect("a sealed value is 48 bytes");
        let psk_key = wrap::k_wrap(PSK_LABEL, &retry_sid, &retry_isk);
        assert_eq!(
            wrap::unwrap(Suite::ChaChaPoly, &psk_key, &sealed_psk).expect("the seal opens"),
            attempt.psk()
        );

        // The first round's key material is not the retry's: a tripped test above would hide that.
        assert_ne!(sid, retry_sid, "each round has its own sid");
        assert_ne!(isk, retry_isk, "each round derives its own session key");
    }

    /// The nonce and the code never reach a `Debug` format.
    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_dynamic_attempt_formats_without_its_nonce_or_code() {
        let mut attempt = dynamic_attempt(CodeFormat::Digits);
        let text = format!("{attempt:?}");
        assert!(
            text.contains("dynamic_pairing_code/awaiting_server_init"),
            "the phase names itself: {text}"
        );
        assert!(
            !text.contains(&format!("{:?}", NONCE_B)),
            "the nonce must never appear: {text}"
        );
        assert!(text.contains("nonce_b: \"<redacted>\""), "got: {text}");
        assert!(text.contains("code: None"), "got: {text}");

        let emission = attempt
            .begin_round(Some(NONCE_A), &HASH)
            .expect("the first round carries nonce_A");
        let text = format!("{attempt:?}");
        assert!(
            text.contains("dynamic_pairing_code/awaiting_auth"),
            "got: {text}"
        );
        assert!(text.contains("code: Some(\"<redacted>\")"), "got: {text}");
        assert!(
            !text.contains(&emission.code),
            "the code reaches the operator through the event, not a log line: {text}"
        );
        assert!(
            !text.contains(&format!("{:?}", NONCE_A)),
            "the server nonce stays out of a format as well: {text}"
        );
    }
}
