//! Pairing as the server: records, the approval gate's counterpart, and the three methods.
//!
//! The server holds one [`PairingRecord`] per paired client, keyed by the client's `client_id`, and
//! the host owns the store behind [`PairingStore`]: this crate reads it, writes only records it
//! produced through a completed flow, and never rotates a key on its own.
//!
//! Three methods exist, and the server is the one that picks them:
//!
//! - **Pairing PSK** ([`Attempt::token`]), the mandatory flow. The operator hands the server a
//!   version-0 token, the server re-handshakes the live connection to the pairing PSK the token
//!   carries, and the client then delivers the long-term PSK inside that authenticated channel.
//! - **Static and dynamic pairing code** ([`Attempt::code`]), behind the `pairing-code` feature
//!   because they need CPace. The server is role `A`: it draws the scalar and `nonce_A`, verifies
//!   the client's key-confirmation tag, and only then opens the sealed long-term PSK.
//!
//! # Key material
//!
//! The long-term PSK, the pairing PSK, the CPace scalar, the intermediate session key and the
//! key-confirmation tags are all secret. None of them has a formatting implementation: a failed
//! assertion, a `Debug` line or an error string names a field or a length, never a value.
//! [`PairingRecord`] redacts its key, and so does [`Attempt`].

use std::fmt;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

#[cfg(feature = "pairing-code")]
use syncspin_core::messages::PairAbort;
#[cfg(feature = "pairing-code")]
use syncspin_core::messages::{
    ClientPairAuth, ClientPairConfirm, ServerPairAuth, ServerPairConfirm, ServerPairInit,
};
use syncspin_core::messages::{ClientPairFinalize, ClientPairInit, Incoming, ServerPairFinalize};
use syncspin_core::noise::{Suite, SENTINEL_PSK};

/// How long one attempt may stay unfinished before the server cancels it.
///
/// `pairing.md` recommends two minutes for the client's attempt timeout; the server applies the
/// same bound as a backstop, and it also covers the wait before `client/pair-init`.
pub const DEFAULT_PAIRING_TIMEOUT: Duration = Duration::from_secs(120);

/// How many rounds one dynamic attempt may run before the server refuses another.
///
/// `pairing.md` fixes the limit at twenty rounds since the last verified `server_kc`, and requires
/// the server to answer a `client/pair-retry` past it with `pair/abort` rather than a new round.
#[cfg(feature = "pairing-code")]
pub const MAX_ROUNDS: u32 = 20;

/// The reason the spec gives for an attempt that ends on a failed key confirmation.
#[cfg(feature = "pairing-code")]
const CODE_MISMATCH: &str = "pairing_code_mismatch";

/// The label that starts every CPace `sid`, as `pairing.md` fixes it.
#[cfg(feature = "pairing-code")]
const PAKE_SID_LABEL: &[u8] = b"sendspin-pair-pake-v1";

/// CPace associated data of the initiator, which is the server.
#[cfg(feature = "pairing-code")]
const AD_SERVER: &[u8] = b"server";

/// CPace associated data of the responder, which is the client.
#[cfg(feature = "pairing-code")]
const AD_CLIENT: &[u8] = b"client";

/// The round number the static flow always reports: it has exactly one round.
#[cfg(feature = "pairing-code")]
const STATIC_ROUND: u32 = 1;

/// Length of a sealed value: 32 bytes of ciphertext and a 16-byte tag.
#[cfg(feature = "pairing-code")]
const SEALED_LEN: usize = 48;

/// Unpadded base64url length of a 32-byte key or nonce.
const KEY_CHARS: usize = 43;

/// Unpadded base64url length of a 48-byte sealed value.
#[cfg(feature = "pairing-code")]
const SEALED_CHARS: usize = 64;

/// Unpadded base64url length of a 64-byte tag.
#[cfg(feature = "pairing-code")]
const TAG_CHARS: usize = 86;

/// Unpadded base64url length of a 32-byte commitment or nonce.
#[cfg(feature = "pairing-code")]
const COMMIT_CHARS: usize = 43;

/// One pairing record: the long-term PSK that authenticates one client.
///
/// The server files a record under the client's `client_id`, the client files its side under the
/// `server_id`. The key is key material, so [`Debug`] prints it redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingRecord {
    /// Static public key of the client, as 43 unpadded base64url characters.
    pub client_id: String,
    /// The long-term PSK the pairing established.
    pub psk: [u8; 32],
}

impl fmt::Debug for PairingRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingRecord")
            .field("client_id", &self.client_id)
            .field("psk", &"<redacted>")
            .finish()
    }
}

/// Where a server keeps the records of the clients it paired with.
///
/// The host implements this trait - over a file, a database or the device's own configuration -
/// and hands it to [`ServerConfig`](crate::ServerConfig). The crate reads it to select the PSK of
/// an incoming connection, and writes to it only with a key a completed pairing delivered.
///
/// The trait is a store, not a policy: [`store_pairing`](PairingStore::store_pairing) replaces the
/// record for the same `client_id`, and a backend need not enforce a capacity. There is no
/// eviction rule to apply on the server side: a client may hold several servers, but one client
/// has exactly one record per server.
///
/// Every method may be called from a connection task, so an implementation must be `Send + Sync`.
/// `Debug` is not required because a store holds key material: a host that wants to format one
/// writes its own implementation and redacts the keys.
pub trait PairingStore: Send + Sync + 'static {
    /// The records of every paired client.
    fn load_pairings(&self) -> Result<Vec<PairingRecord>>;

    /// Stores `record`, replacing the record for its `client_id`.
    fn store_pairing(&self, record: PairingRecord) -> Result<()>;

    /// Removes the record of `client_id`.
    ///
    /// Removing a record the store does not hold is not an error: a server may unpair a client it
    /// never paired with, and the wire message is the same.
    fn remove_pairing(&self, client_id: &str) -> Result<()>;
}

/// Returns the long-term PSK the store holds for `client_id`, or `None`.
///
/// A store that cannot be read is an error and never a reason to continue with fewer keys:
/// falling back to the Sentinel key would silently downgrade a paired connection to an unpaired
/// one, and the client would see a credential mismatch the server never intended.
pub(crate) fn record_for(
    store: Option<&dyn PairingStore>,
    client_id: &str,
) -> Result<Option<[u8; 32]>> {
    let Some(store) = store else {
        return Ok(None);
    };
    let records = store
        .load_pairings()
        .context("the pairing store did not return its records")?;
    Ok(records
        .into_iter()
        .find(|record| record.client_id == client_id)
        .map(|record| record.psk))
}

/// Persists a record a completed flow produced.
pub(crate) fn store_record(
    store: Option<&dyn PairingStore>,
    client_id: &str,
    psk: [u8; 32],
) -> Result<()> {
    let store = store.ok_or_else(|| {
        anyhow::anyhow!("this server has no pairing store, so it cannot keep a pairing record")
    })?;
    store
        .store_pairing(PairingRecord {
            client_id: client_id.to_owned(),
            psk,
        })
        .context("the pairing store did not accept the new record")
}

/// Removes the record of `client_id`, if the store holds one.
pub(crate) fn remove_record(store: Option<&dyn PairingStore>, client_id: &str) -> Result<()> {
    let Some(store) = store else {
        return Ok(());
    };
    store
        .remove_pairing(client_id)
        .context("the pairing store did not remove the record")
}

/// A pairing method `pairing.md` defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingMethod {
    /// The Pairing PSK flow, the one every server must have.
    PairingPsk,
    /// The Static Pairing Code flow.
    StaticCode,
    /// The Dynamic Pairing Code flow.
    DynamicCode,
}

impl PairingMethod {
    /// Returns the identifier the wire and `client/hello` use.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::PairingPsk => "pairing_psk",
            Self::StaticCode => "static_pairing_code",
            Self::DynamicCode => "dynamic_pairing_code",
        }
    }

    /// Decodes a method identifier, or `None` for a value this revision does not know.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "pairing_psk" => Some(Self::PairingPsk),
            "static_pairing_code" => Some(Self::StaticCode),
            "dynamic_pairing_code" => Some(Self::DynamicCode),
            _ => None,
        }
    }

    /// Whether the method runs a CPace round.
    #[must_use]
    pub const fn needs_code(self) -> bool {
        !matches!(self, Self::PairingPsk)
    }
}
/// An emission format of the Dynamic Pairing Code Flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeFormat {
    /// Six decimal digits.
    Digits,
    /// A 24-byte code presented as a version-1 pairing token.
    QrCode,
}

impl CodeFormat {
    /// Returns the identifier the wire and `client/hello` use.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Digits => "digits",
            Self::QrCode => "qr_code",
        }
    }

    /// Decodes an emission format, or `None` for a value this revision does not know.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "digits" => Some(Self::Digits),
            "qr_code" => Some(Self::QrCode),
            _ => None,
        }
    }
}

/// The messages the caller has to send because of one incoming pairing message.
#[derive(Debug, Default)]
pub(crate) struct Step {
    /// Control messages to put on the wire, in order.
    pub(crate) messages: Vec<Incoming>,
    /// Whether the client has just been asked to emit a pairing code.
    pub(crate) announce_code: bool,
}

impl Step {
    /// A step with nothing to send.
    fn none() -> Step {
        Step::default()
    }

    /// A step carrying one message.
    #[cfg(feature = "pairing-code")]
    fn one(message: Incoming) -> Step {
        Step {
            messages: vec![message],
            announce_code: false,
        }
    }
}

/// What verifying `client_kc` decided.
#[cfg(feature = "pairing-code")]
pub(crate) enum ConfirmOutcome {
    /// The tag verified and the attempt may continue with `client/pair-finalize`.
    Confirmed,
    /// The tag did not verify: the caller answers with `pair/abort` reason `pairing_code_mismatch`.
    Mismatch,
}

/// What a `client/pair-retry` decided.
#[cfg(feature = "pairing-code")]
pub(crate) enum RetryOutcome {
    /// A new round began and `server/pair-init` is in the step.
    NextRound(Step),
    /// The attempt reached its round limit; the caller aborts it.
    Exhausted,
}

/// How far one attempt has gone.
///
/// The variants name what is awaited, so a `Debug` line says where an attempt stopped without
/// saying what it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
enum Phase {
    /// The activation was sent; the client's first pairing message is awaited.
    AwaitInit,
    /// The attempt started; the operator's code for this round is awaited.
    #[cfg(feature = "pairing-code")]
    AwaitCode,
    /// `server/pair-auth` was sent; the client's CPace share is awaited.
    #[cfg(feature = "pairing-code")]
    AwaitClientAuth,
    /// `server/pair-confirm` was sent; the client's tag is awaited.
    #[cfg(feature = "pairing-code")]
    AwaitClientConfirm,
    /// The key confirmation passed; `client/pair-finalize` is awaited.
    AwaitFinalize,
}

/// The values one CPace round holds between `server/pair-auth` and `client/pair-confirm`.
#[cfg(feature = "pairing-code")]
struct CodeRound {
    /// The `sid` both sides derive the generator and the tags from.
    sid: Vec<u8>,
    /// The server's scalar, which only it holds.
    scalar: [u8; 32],
    /// `Ya`, the server's public share.
    ya: [u8; 32],
    /// The intermediate session key, set once the client's share arrived.
    isk: Option<[u8; 64]>,
    /// `Tb`, the tag the client's `client_kc` must equal.
    expected_client_tag: Option<[u8; 64]>,
}

/// The values a verified code round releases, needed to open the sealed long-term PSK.
#[cfg(feature = "pairing-code")]
struct Verified {
    /// The round's `sid`, which the wrapping key depends on.
    sid: Vec<u8>,
    /// The round's intermediate session key.
    isk: [u8; 64],
}

/// One pairing attempt in progress.
///
/// The attempt begins with the pairing activation and ends with `server/pair-finalize`, a
/// `pair/abort` in either direction, a cancelling activation, the attempt timeout or the
/// connection. It holds every secret of the flow, and its [`Debug`] output names the phase, the
/// method and the indexes, never a value.
pub(crate) struct Attempt {
    method: PairingMethod,
    format: Option<CodeFormat>,
    pairing_index: u32,
    round: u32,
    phase: Phase,
    deadline: Instant,
    /// The server's nonce of a dynamic attempt, drawn for the first round.
    #[cfg(feature = "pairing-code")]
    nonce_a: Option<[u8; 32]>,
    /// `commit_B` from `client/pair-init`, which the revealed nonce must hash to.
    #[cfg(feature = "pairing-code")]
    commit_b: Option<[u8; 32]>,
    /// The PRS of the code the operator entered for the current round.
    #[cfg(feature = "pairing-code")]
    code: Option<Vec<u8>>,
    /// The CPace round in progress.
    #[cfg(feature = "pairing-code")]
    round_state: Option<CodeRound>,
    /// The key material a verified round released.
    #[cfg(feature = "pairing-code")]
    verified: Option<Verified>,
}

impl Attempt {
    /// Starts the Pairing PSK flow, which the token carries.
    pub(crate) fn token(pairing_index: u32, timeout: Duration) -> Attempt {
        Attempt {
            method: PairingMethod::PairingPsk,
            format: None,
            pairing_index,
            round: 0,
            phase: Phase::AwaitInit,
            deadline: Instant::now() + timeout,
            #[cfg(feature = "pairing-code")]
            nonce_a: None,
            #[cfg(feature = "pairing-code")]
            commit_b: None,
            #[cfg(feature = "pairing-code")]
            code: None,
            #[cfg(feature = "pairing-code")]
            round_state: None,
            #[cfg(feature = "pairing-code")]
            verified: None,
        }
    }

    /// Starts a code-flow attempt; the caller has already sent the activation.
    ///
    /// # Errors
    /// Fails when the method is the Pairing PSK flow, when the emission format is missing or
    /// present where it does not belong, and when this build has no `pairing-code` feature.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn code(
        method: PairingMethod,
        format: Option<CodeFormat>,
        pairing_index: u32,
        timeout: Duration,
    ) -> Result<Attempt> {
        match (method, format) {
            (PairingMethod::PairingPsk, _) => {
                bail!("the Pairing PSK flow is started by a token, not by a code activation")
            }
            (PairingMethod::StaticCode, Some(_)) => {
                bail!("the Static Pairing Code flow takes no emission format")
            }
            (PairingMethod::StaticCode, None) => {}
            (PairingMethod::DynamicCode, None) => {
                bail!("the Dynamic Pairing Code flow needs an emission format")
            }
            (PairingMethod::DynamicCode, Some(_)) => {}
        }
        Ok(Attempt {
            method,
            format,
            pairing_index,
            round: 0,
            phase: Phase::AwaitInit,
            deadline: Instant::now() + timeout,
            nonce_a: None,
            commit_b: None,
            code: None,
            round_state: None,
            verified: None,
        })
    }

    /// Returns when the attempt is cancelled as timed out.
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Returns the method this attempt runs.
    pub(crate) fn method(&self) -> PairingMethod {
        self.method
    }

    /// Returns the emission format a dynamic attempt was admitted with.
    pub(crate) fn format(&self) -> Option<CodeFormat> {
        self.format
    }

    /// Returns the pairing index its activation carried.
    pub(crate) fn index(&self) -> u32 {
        self.pairing_index
    }

    /// Whether the operator's code has to be entered before the round can continue.
    ///
    /// The static flow accepts it as soon as the attempt exists; the dynamic flow only once the
    /// client has started its side, because the code is derived from the server's nonce.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn accepts_code(&self) -> bool {
        match self.phase {
            Phase::AwaitInit => self.method == PairingMethod::StaticCode,
            #[cfg(feature = "pairing-code")]
            Phase::AwaitCode => true,
            _ => false,
        }
    }

    /// Handles `client/pair-init` and returns what has to be sent next.
    ///
    /// `handshake_hash` is the hash of the handshake whose activation admitted the attempt: every
    /// CPace `sid` of every round mixes it in.
    ///
    /// # Errors
    /// Fails on a sequence violation, on a `commit_B` that is missing, present where it does not
    /// belong or not a canonical commitment, and when the CPace generator cannot be built. Each is
    /// a protocol error, which the caller answers by closing the connection.
    pub(crate) fn on_pair_init(
        &mut self,
        init: &ClientPairInit,
        handshake_hash: &[u8; 32],
    ) -> Result<Step> {
        if self.phase != Phase::AwaitInit {
            bail!("the client sent client/pair-init twice");
        }
        let _ = handshake_hash;
        match self.method {
            PairingMethod::PairingPsk => {
                if init.commit_b.is_some() {
                    bail!("the Pairing PSK flow's client/pair-init carries a commit_B");
                }
                // The client sends client/pair-finalize next, without waiting for an answer.
                self.phase = Phase::AwaitFinalize;
                Ok(Step::none())
            }
            #[cfg(feature = "pairing-code")]
            PairingMethod::StaticCode => {
                if init.commit_b.is_some() {
                    bail!("the Static Pairing Code flow's client/pair-init carries a commit_B");
                }
                self.phase = Phase::AwaitCode;
                let mut step = Step::none();
                if self.code.is_some() {
                    self.start_round(handshake_hash, &mut step)?;
                }
                Ok(step)
            }
            #[cfg(feature = "pairing-code")]
            PairingMethod::DynamicCode => {
                let Some(commit) = init.commit_b.as_deref() else {
                    bail!("the Dynamic Pairing Code Flow's client/pair-init carries no commit_B");
                };
                self.commit_b = Some(decode_fixed::<32>(commit, COMMIT_CHARS, "commit_B")?);
                let mut nonce_a = [0u8; 32];
                getrandom::fill(&mut nonce_a)
                    .map_err(|_| anyhow::anyhow!("cannot draw the server nonce from the CSPRNG"))?;
                self.nonce_a = Some(nonce_a);
                self.round = STATIC_ROUND;
                self.phase = Phase::AwaitCode;
                let mut step = Step::one(Incoming::ServerPairInit(ServerPairInit {
                    nonce_a: Some(URL_SAFE_NO_PAD.encode(nonce_a)),
                }));
                step.announce_code = true;
                if self.code.is_some() {
                    self.start_round(handshake_hash, &mut step)?;
                }
                Ok(step)
            }
            #[cfg(not(feature = "pairing-code"))]
            PairingMethod::StaticCode | PairingMethod::DynamicCode => {
                bail!("this build has no `pairing-code` feature, so it cannot run a code flow")
            }
        }
    }

    /// Accepts the operator's code for the current round and starts the CPace round.
    ///
    /// The static flow stores the code even when the client has not started yet, so an operator
    /// who types it first is not made to wait. The code's separators are stripped, as the spec
    /// asks of server-side entry: `123-456` and `123456` are the same dynamic code.
    ///
    /// # Errors
    /// Fails when the attempt does not accept a code right now, when the entered text is not a
    /// code of this method and emission format, and when the code is the wrong length.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn on_entered_code(
        &mut self,
        code: &str,
        handshake_hash: &[u8; 32],
    ) -> Result<Step> {
        if !self.accepts_code() {
            bail!("this pairing attempt is not waiting for a code");
        }
        let prs = match (self.method, self.format) {
            (PairingMethod::StaticCode, _) => {
                let digits = strip_separators(code);
                if digits.len() != 8 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    bail!("a static pairing code is exactly eight digits");
                }
                digits.into_bytes()
            }
            (PairingMethod::DynamicCode, Some(CodeFormat::Digits)) => {
                let digits = strip_separators(code);
                if digits.len() != 6 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    bail!("a dynamic pairing code in the `digits` format is six digits");
                }
                digits.into_bytes()
            }
            (PairingMethod::DynamicCode, Some(CodeFormat::QrCode)) => {
                let token = syncspin_core::pairing::token::decode(code)
                    .context("the entered code is not a pairing token")?;
                if token.version != 1 {
                    bail!("a `qr_code` pairing code is a version-1 token");
                }
                if token.payload.len() != syncspin_core::pairing::code::QR_CODE_LEN {
                    bail!("a `qr_code` pairing code carries 24 payload bytes");
                }
                token.payload
            }
            (PairingMethod::DynamicCode, None) => {
                bail!("a dynamic pairing code needs an emission format")
            }
            (PairingMethod::PairingPsk, _) => {
                bail!("the Pairing PSK flow takes no code")
            }
        };
        self.code = Some(prs);
        if self.phase == Phase::AwaitCode {
            let mut step = Step::none();
            self.start_round(handshake_hash, &mut step)?;
            return Ok(step);
        }
        Ok(Step::none())
    }

    /// Starts the CPace round the entered code admits and appends `server/pair-auth`.
    #[cfg(feature = "pairing-code")]
    fn start_round(&mut self, handshake_hash: &[u8; 32], step: &mut Step) -> Result<()> {
        let Some(prs) = self.code.as_deref() else {
            bail!("no pairing code was entered");
        };
        let round = self.round.max(STATIC_ROUND);
        let sid = pake_sid(handshake_hash, self.pairing_index, round);
        let generator = syncspin_core::pairing::pake::generator(prs, b"", &sid);
        let mut scalar = [0u8; 32];
        getrandom::fill(&mut scalar)
            .map_err(|_| anyhow::anyhow!("cannot draw the CPace scalar from the CSPRNG"))?;
        let ya = syncspin_core::pairing::pake::public_share(&scalar, &generator)
            .context("the CPace generator did not yield a group element")?;
        self.round_state = Some(CodeRound {
            sid,
            scalar,
            ya,
            isk: None,
            expected_client_tag: None,
        });
        self.phase = Phase::AwaitClientAuth;
        step.messages.push(Incoming::ServerPairAuth(ServerPairAuth {
            pake_msg_1: URL_SAFE_NO_PAD.encode(ya),
        }));
        Ok(())
    }

    /// Handles `client/pair-auth`: derives the round's key material and answers with `server_kc`.
    ///
    /// # Errors
    /// Fails on a sequence violation, on a share that is not canonical base64url of 32 bytes, and
    /// on a share that encodes a low-order point, which the draft requires the round to abort.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn on_client_auth(&mut self, auth: &ClientPairAuth) -> Result<Step> {
        if self.phase != Phase::AwaitClientAuth {
            bail!("the client sent client/pair-auth out of sequence");
        }
        let Some(round) = self.round_state.as_mut() else {
            bail!("client/pair-auth arrived before the CPace round began");
        };
        let yb: [u8; 32] = decode_fixed::<32>(&auth.pake_msg_2, KEY_CHARS, "pake_msg_2")?;
        let point = syncspin_core::pairing::pake::scalar_mult_vfy(&round.scalar, &yb)
            .context("the client's CPace share encodes a low-order point")?;
        let transcript =
            syncspin_core::pairing::pake::transcript_ir(&round.ya, AD_SERVER, &yb, AD_CLIENT);
        let isk =
            syncspin_core::pairing::pake::intermediate_session_key(&round.sid, &point, &transcript);
        let server_tag = syncspin_core::pairing::pake::key_confirmation_tag(
            &round.sid, &isk, &round.ya, AD_SERVER,
        );
        let client_tag =
            syncspin_core::pairing::pake::key_confirmation_tag(&round.sid, &isk, &yb, AD_CLIENT);
        round.isk = Some(isk);
        round.expected_client_tag = Some(client_tag);
        self.phase = Phase::AwaitClientConfirm;
        Ok(Step::one(Incoming::ServerPairConfirm(ServerPairConfirm {
            server_kc: URL_SAFE_NO_PAD.encode(server_tag),
        })))
    }

    /// Verifies `client/pair-confirm`, including the dynamic flow's three binding checks.
    ///
    /// # Errors
    /// Fails on a sequence violation, on a missing or malformed field, on a `wrapped_nonce_B`
    /// that does not open, on a revealed nonce that does not match `commit_B`, and on an entered
    /// code that does not bind to `h`, `nonce_A` and the revealed nonce. Each of those is a
    /// protocol error: the caller closes the connection and persists nothing.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn on_client_confirm(
        &mut self,
        confirm: &ClientPairConfirm,
        handshake_hash: &[u8; 32],
        suite: Suite,
    ) -> Result<ConfirmOutcome> {
        if self.phase != Phase::AwaitClientConfirm {
            bail!("the client sent client/pair-confirm out of sequence");
        }
        let Some(round) = self.round_state.take() else {
            bail!("client/pair-confirm arrived before the CPace round began");
        };
        let received: [u8; 64] = decode_fixed::<64>(&confirm.client_kc, TAG_CHARS, "client_kc")?;
        let (Some(isk), Some(expected)) = (round.isk, round.expected_client_tag) else {
            bail!("client/pair-confirm arrived before the client's CPace share");
        };
        if !syncspin_core::pairing::pake::verify_key_confirmation_tag(&expected, &received) {
            return Ok(ConfirmOutcome::Mismatch);
        }

        if self.method == PairingMethod::DynamicCode {
            let Some(sealed) = confirm.wrapped_nonce_b.as_deref() else {
                bail!("the dynamic flow's client/pair-confirm carries no wrapped_nonce_B");
            };
            let sealed: [u8; SEALED_LEN] =
                decode_fixed::<SEALED_LEN>(sealed, SEALED_CHARS, "wrapped_nonce_B")?;
            let key = syncspin_core::pairing::wrap::k_wrap(
                syncspin_core::pairing::wrap::NONCE_LABEL,
                &round.sid,
                &isk,
            );
            let nonce_b = syncspin_core::pairing::wrap::unwrap(suite, &key, &sealed)
                .context("wrapped_nonce_B does not open under the round's key")?;
            let Some(commit_b) = self.commit_b else {
                bail!("the dynamic flow has no commit_B to check the revealed nonce against");
            };
            if syncspin_core::pairing::code::commitment(&nonce_b) != commit_b {
                bail!("the revealed nonce_B does not match the commitment of client/pair-init");
            }
            let Some(nonce_a) = self.nonce_a else {
                bail!("the dynamic flow has no nonce_A to derive the code from");
            };
            let derived = syncspin_core::pairing::code::DynamicCode::derive(
                handshake_hash,
                &nonce_a,
                &nonce_b,
            );
            let expected_prs = match self.format {
                Some(CodeFormat::Digits) => derived.digits().to_vec(),
                Some(CodeFormat::QrCode) => derived.qr_payload().to_vec(),
                None => bail!("the dynamic flow activated no emission format"),
            };
            if self.code.as_deref() != Some(expected_prs.as_slice()) {
                bail!("the entered pairing code does not bind to h, nonce_A and nonce_B");
            }
        } else if confirm.wrapped_nonce_b.is_some() {
            bail!("the static flow's client/pair-confirm carries a wrapped_nonce_B");
        }

        self.verified = Some(Verified {
            sid: round.sid,
            isk,
        });
        self.phase = Phase::AwaitFinalize;
        Ok(ConfirmOutcome::Confirmed)
    }

    /// Handles `client/pair-retry`: begins the next round, or reports the round limit.
    ///
    /// The binding values, the code and the deadline carry over unchanged, so a client that keeps
    /// showing the code keeps showing the same one.
    ///
    /// # Errors
    /// Fails when the attempt is not a dynamic one or is not waiting for the client's tag.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn on_client_retry(&mut self) -> Result<RetryOutcome> {
        if self.method != PairingMethod::DynamicCode || self.phase != Phase::AwaitClientConfirm {
            bail!("the client sent client/pair-retry out of sequence");
        }
        self.round_state = None;
        self.verified = None;
        self.round = self.round.saturating_add(1);
        if self.round > MAX_ROUNDS {
            return Ok(RetryOutcome::Exhausted);
        }
        // The operator enters the code again, and the server sends no share until they do.
        self.code = None;
        self.phase = Phase::AwaitCode;
        let mut step = Step::one(Incoming::ServerPairInit(ServerPairInit { nonce_a: None }));
        step.announce_code = true;
        Ok(RetryOutcome::NextRound(step))
    }

    /// Opens `client/pair-finalize` and returns the long-term PSK it delivered.
    ///
    /// `connection_psk` is the pairing PSK the connection is keyed by, when it is keyed by one;
    /// `pairing.md` forbids delivering it or the Sentinel key as the long-term PSK.
    ///
    /// # Errors
    /// Fails on a sequence violation, on a field that is missing, doubled or malformed, on a seal
    /// that does not open, and on a key the protocol forbids.
    pub(crate) fn on_finalize(
        &mut self,
        finalize: &ClientPairFinalize,
        suite: Suite,
        connection_psk: Option<[u8; 32]>,
    ) -> Result<[u8; 32]> {
        if self.phase != Phase::AwaitFinalize {
            bail!("the client sent client/pair-finalize before its key confirmation");
        }
        let _ = suite;
        let key = match self.method {
            PairingMethod::PairingPsk => {
                if finalize.wrapped_psk.is_some() {
                    bail!("the Pairing PSK flow's client/pair-finalize carries a wrapped_psk");
                }
                let Some(encoded) = finalize.long_term_psk.as_deref() else {
                    bail!("the Pairing PSK flow's client/pair-finalize carries no long_term_psk");
                };
                decode_fixed::<32>(encoded, KEY_CHARS, "long_term_psk")?
            }
            #[cfg(feature = "pairing-code")]
            PairingMethod::StaticCode | PairingMethod::DynamicCode => {
                if finalize.long_term_psk.is_some() {
                    bail!("a code flow's client/pair-finalize carries the long-term PSK in clear");
                }
                let Some(encoded) = finalize.wrapped_psk.as_deref() else {
                    bail!("a code flow's client/pair-finalize carries no wrapped_psk");
                };
                let sealed: [u8; SEALED_LEN] =
                    decode_fixed::<SEALED_LEN>(encoded, SEALED_CHARS, "wrapped_psk")?;
                let verified = self
                    .verified
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("the CPace round never verified a tag"))?;
                let wrap_key = syncspin_core::pairing::wrap::k_wrap(
                    syncspin_core::pairing::wrap::PSK_LABEL,
                    &verified.sid,
                    &verified.isk,
                );
                syncspin_core::pairing::wrap::unwrap(suite, &wrap_key, &sealed)
                    .context("wrapped_psk does not open under the round's key")?
            }
            #[cfg(not(feature = "pairing-code"))]
            PairingMethod::StaticCode | PairingMethod::DynamicCode => {
                bail!("this build has no `pairing-code` feature, so it cannot run a code flow")
            }
        };
        if key == SENTINEL_PSK {
            bail!("the client delivered the published Sentinel key as a long-term PSK");
        }
        if connection_psk == Some(key) {
            bail!("the client delivered the pairing PSK the connection is keyed by");
        }
        Ok(key)
    }

    /// Returns the `server/pair-finalize` acknowledgement.
    pub(crate) fn finalized() -> Incoming {
        Incoming::ServerPairFinalize(ServerPairFinalize {})
    }

    /// Returns the `pair/abort` that ends an attempt for `reason`.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn abort(reason: &str) -> Incoming {
        Incoming::PairAbort(PairAbort {
            reason: reason.to_owned(),
        })
    }

    /// Returns the reason the spec gives for a failed key confirmation.
    #[cfg(feature = "pairing-code")]
    pub(crate) const fn code_mismatch_reason() -> &'static str {
        CODE_MISMATCH
    }
}

impl fmt::Debug for Attempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Attempt")
            .field("method", &self.method.wire_name())
            .field("format", &self.format.map(CodeFormat::wire_name))
            .field("pairing_index", &self.pairing_index)
            .field("round", &self.round)
            .field("phase", &self.phase)
            .field("code", &"<redacted>")
            .finish()
    }
}

/// Builds the CPace session id of one round: `label || h || pairing_index || round`.
///
/// All four parts are raw, and both indexes are big-endian `u32`, exactly as `pairing.md` defines
/// `sid`. The value is public but bound to one handshake, and it separates every round.
#[cfg(feature = "pairing-code")]
fn pake_sid(handshake_hash: &[u8; 32], pairing_index: u32, round: u32) -> Vec<u8> {
    let mut sid = Vec::with_capacity(PAKE_SID_LABEL.len() + 32 + 8);
    sid.extend_from_slice(PAKE_SID_LABEL);
    sid.extend_from_slice(handshake_hash);
    sid.extend_from_slice(&pairing_index.to_be_bytes());
    sid.extend_from_slice(&round.to_be_bytes());
    sid
}

/// Strips the separators a person types into a code: whitespace and hyphens.
#[cfg(feature = "pairing-code")]
fn strip_separators(code: &str) -> String {
    code.chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
        .collect()
}

/// Decodes a fixed-length unpadded base64url field of a pairing message.
///
/// The canonical re-encoding has to match the received text: a value with spare bits set is not
/// what a conformant peer sends. The error names the field and the length, never the value, since
/// one of these fields is a key-confirmation tag.
fn decode_fixed<const N: usize>(value: &str, chars: usize, name: &str) -> Result<[u8; N]> {
    if value.len() != chars {
        bail!("{name} is not {chars} unpadded base64url characters");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("{name} is not unpadded base64url"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        bail!("{name} is not the canonical base64url encoding");
    }
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} does not decode to {N} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_attempt_starts_with_the_pairing_psk_flow() {
        let attempt = Attempt::token(2, DEFAULT_PAIRING_TIMEOUT);
        assert_eq!(attempt.method(), PairingMethod::PairingPsk);
        assert_eq!(attempt.index(), 2);
        #[cfg(feature = "pairing-code")]
        assert!(!attempt.accepts_code());
        assert!(attempt.deadline() > Instant::now());
    }

    #[test]
    fn the_pairing_psk_flow_takes_no_commitment_and_waits_for_the_key() {
        let mut attempt = Attempt::token(1, DEFAULT_PAIRING_TIMEOUT);
        let step = attempt
            .on_pair_init(&pair_init(None), &[0x11; 32])
            .expect("the PSK flow's init is accepted");
        assert!(step.messages.is_empty());
        assert!(!step.announce_code, "the token flow shows no code");

        let mut with_commit = Attempt::token(1, DEFAULT_PAIRING_TIMEOUT);
        assert!(
            with_commit
                .on_pair_init(&pair_init(Some(&commitment_text())), &[0x11; 32])
                .is_err(),
            "a commit_B in the PSK flow is a protocol error"
        );
    }

    #[test]
    fn a_token_attempt_refuses_a_long_term_psk_the_protocol_forbids() {
        for key in [SENTINEL_PSK, [0x5a; 32]] {
            let mut attempt = Attempt::token(1, DEFAULT_PAIRING_TIMEOUT);
            attempt
                .on_pair_init(&pair_init(None), &[0x11; 32])
                .expect("the init is accepted");
            let finalize = ClientPairFinalize {
                long_term_psk: Some(URL_SAFE_NO_PAD.encode(key)),
                wrapped_psk: None,
            };
            // The second value stands in for the pairing PSK the connection is keyed by.
            let connection_psk = (key != SENTINEL_PSK).then_some(key);
            assert!(
                attempt
                    .on_finalize(&finalize, Suite::ChaChaPoly, connection_psk)
                    .is_err(),
                "a forbidden long-term PSK must be refused"
            );
        }

        // The flow refuses a finalize that carries the PSK sealed, which only a code flow does.
        let mut attempt = Attempt::token(1, DEFAULT_PAIRING_TIMEOUT);
        attempt
            .on_pair_init(&pair_init(None), &[0x11; 32])
            .expect("the init is accepted");
        assert!(attempt
            .on_finalize(
                &ClientPairFinalize {
                    long_term_psk: None,
                    wrapped_psk: Some("a".repeat(64)),
                },
                Suite::ChaChaPoly,
                None,
            )
            .is_err());
    }

    #[test]
    fn the_record_redacts_its_key() {
        let record = PairingRecord {
            client_id: "a-client".to_owned(),
            psk: [0x5a; 32],
        };
        let text = format!("{record:?}");
        assert!(text.contains("<redacted>"), "got: {text}");
        assert!(!text.contains(&format!("{:?}", [0x5a; 32])), "got: {text}");
    }

    #[test]
    fn a_field_length_is_checked_before_the_value_is_used() {
        assert!(decode_fixed::<32>("short", KEY_CHARS, "nonce_A").is_err());
        assert!(decode_fixed::<32>(&"!".repeat(KEY_CHARS), KEY_CHARS, "nonce_A").is_err());
        let value = URL_SAFE_NO_PAD.encode([0x11u8; 32]);
        assert_eq!(
            decode_fixed::<32>(&value, KEY_CHARS, "nonce_A").expect("a canonical key decodes"),
            [0x11u8; 32]
        );
    }

    #[test]
    fn the_wire_names_are_the_ones_the_specification_defines() {
        for method in [
            PairingMethod::PairingPsk,
            PairingMethod::StaticCode,
            PairingMethod::DynamicCode,
        ] {
            assert_eq!(PairingMethod::from_wire(method.wire_name()), Some(method));
        }
        for format in [CodeFormat::Digits, CodeFormat::QrCode] {
            assert_eq!(CodeFormat::from_wire(format.wire_name()), Some(format));
        }
        assert_eq!(PairingMethod::from_wire("colour"), None);
        assert_eq!(CodeFormat::from_wire("qr"), None);
    }

    #[test]
    fn an_attempt_names_its_phase_in_debug_without_a_code() {
        let attempt = Attempt::token(1, DEFAULT_PAIRING_TIMEOUT);
        let text = format!("{attempt:?}");
        assert!(text.contains("pairing_psk"), "got: {text}");
        assert!(text.contains("<redacted>"), "got: {text}");
    }

    fn pair_init(commit_b: Option<&str>) -> ClientPairInit {
        ClientPairInit {
            pairing_index: 1,
            commit_b: commit_b.map(str::to_owned),
        }
    }

    fn commitment_text() -> String {
        URL_SAFE_NO_PAD.encode([0u8; 32])
    }

    #[cfg(feature = "pairing-code")]
    fn static_attempt() -> Attempt {
        Attempt::code(PairingMethod::StaticCode, None, 1, DEFAULT_PAIRING_TIMEOUT)
            .expect("a static attempt builds")
    }

    #[cfg(feature = "pairing-code")]
    fn dynamic_attempt() -> Attempt {
        Attempt::code(
            PairingMethod::DynamicCode,
            Some(CodeFormat::Digits),
            1,
            DEFAULT_PAIRING_TIMEOUT,
        )
        .expect("a dynamic attempt builds")
    }

    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_static_attempt_waits_for_the_code_and_the_client() {
        let mut attempt = static_attempt();
        assert!(attempt.accepts_code(), "the static code is on the device");
        let step = attempt
            .on_pair_init(&pair_init(None), &[0x11; 32])
            .expect("a static init is accepted");
        assert!(
            step.messages.is_empty(),
            "no share before the code is entered"
        );
        assert!(
            attempt.accepts_code(),
            "a started static attempt still takes its code"
        );
        assert!(
            attempt.on_pair_init(&pair_init(None), &[0x11; 32]).is_err(),
            "a second client/pair-init is out of sequence"
        );
    }

    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_code_of_the_wrong_shape_is_refused_without_echoing_it() {
        let mut attempt = static_attempt();
        for code in ["1234567", "123456789", "abcdefgh"] {
            let message = attempt
                .on_entered_code(code, &[0x11; 32])
                .expect_err("a malformed static code is refused")
                .to_string();
            assert!(
                !message.contains(code),
                "the error must not echo the code: {message}"
            );
        }

        let mut dynamic = dynamic_attempt();
        dynamic
            .on_pair_init(&pair_init(Some(&commitment_text())), &[0x11; 32])
            .expect("a dynamic init is accepted");
        assert!(
            dynamic.on_entered_code("12345", &[0x11; 32]).is_err(),
            "five digits are not a dynamic code"
        );
        assert!(
            dynamic.on_entered_code("1234567", &[0x11; 32]).is_err(),
            "seven digits are not a dynamic code"
        );
        assert!(
            dynamic.on_entered_code("SP:1AAAA", &[0x11; 32]).is_err(),
            "a `digits` attempt takes no token"
        );
    }

    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_qr_code_is_read_as_its_24_byte_payload() {
        let mut attempt = Attempt::code(
            PairingMethod::DynamicCode,
            Some(CodeFormat::QrCode),
            1,
            DEFAULT_PAIRING_TIMEOUT,
        )
        .expect("a dynamic attempt builds");
        attempt
            .on_pair_init(&pair_init(Some(&commitment_text())), &[0x11; 32])
            .expect("a dynamic init is accepted");

        let code: [u8; 24] = std::array::from_fn(|index| index as u8);
        let token = syncspin_core::pairing::token::encode_v1(&code);
        let step = attempt
            .on_entered_code(&token, &[0x11; 32])
            .expect("a version-1 token is a `qr_code` code");
        assert_eq!(
            step.messages.len(),
            1,
            "the entered code starts the CPace round"
        );
        // The PRS is the raw 24 bytes, not the token text: the same code as a scanned QR.
        let mut wrong = Attempt::code(
            PairingMethod::DynamicCode,
            Some(CodeFormat::QrCode),
            1,
            DEFAULT_PAIRING_TIMEOUT,
        )
        .expect("a dynamic attempt builds");
        wrong
            .on_pair_init(&pair_init(Some(&commitment_text())), &[0x11; 32])
            .expect("a dynamic init is accepted");
        assert!(
            wrong
                .on_entered_code(
                    &syncspin_core::pairing::token::encode_v0(&[0u8; 32], &[0u8; 32]),
                    &[0x11; 32]
                )
                .is_err(),
            "a version-0 token is not a pairing code"
        );
    }

    #[cfg(feature = "pairing-code")]
    #[test]
    fn typed_separators_are_stripped_from_a_code() {
        assert_eq!(strip_separators("123-456"), "123456");
        assert_eq!(strip_separators(" 1234 5678 "), "12345678");
        assert_eq!(strip_separators("123456"), "123456");
    }

    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_dynamic_attempt_requires_its_commitment() {
        let mut attempt = dynamic_attempt();
        assert!(
            attempt.on_pair_init(&pair_init(None), &[0x11; 32]).is_err(),
            "the dynamic flow needs commit_B"
        );
        let mut attempt = dynamic_attempt();
        assert!(
            attempt
                .on_pair_init(&pair_init(Some("short")), &[0x11; 32])
                .is_err(),
            "a commitment that is not 43 characters is malformed"
        );
    }

    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_dynamic_attempt_answers_pair_init_with_nonce_a() {
        let mut attempt = dynamic_attempt();
        let step = attempt
            .on_pair_init(&pair_init(Some(&commitment_text())), &[0x11; 32])
            .expect("a dynamic init is accepted");
        assert_eq!(step.messages.len(), 1);
        assert!(step.announce_code, "the client now emits a code");
        match &step.messages[0] {
            Incoming::ServerPairInit(init) => {
                let nonce = init
                    .nonce_a
                    .as_deref()
                    .expect("the first round carries nonce_A");
                assert_eq!(nonce.len(), COMMIT_CHARS);
            }
            other => panic!("expected server/pair-init, got {other:?}"),
        }
        assert!(
            attempt.on_pair_init(&pair_init(None), &[0x11; 32]).is_err(),
            "a second client/pair-init is out of sequence"
        );
    }

    #[cfg(feature = "pairing-code")]
    #[test]
    fn the_round_limit_refuses_another_round() {
        let mut attempt = dynamic_attempt();
        let step = attempt
            .on_pair_init(&pair_init(Some(&commitment_text())), &[0x11; 32])
            .expect("a dynamic init is accepted");
        assert!(!step.messages.is_empty());
        // Reach the last accepted round without a key confirmation, as a client whose operator
        // keeps typing the wrong code does.
        attempt.phase = Phase::AwaitClientConfirm;
        attempt.round = MAX_ROUNDS;
        match attempt
            .on_client_retry()
            .expect("a retry at the limit is answered")
        {
            RetryOutcome::Exhausted => {}
            RetryOutcome::NextRound(_) => panic!("the round limit must refuse another round"),
        }
    }

    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_round_below_the_limit_begins_the_next_one_without_a_nonce() {
        let mut attempt = dynamic_attempt();
        attempt
            .on_pair_init(&pair_init(Some(&commitment_text())), &[0x11; 32])
            .expect("a dynamic init is accepted");
        attempt
            .on_entered_code("123456", &[0x11; 32])
            .expect("the code is accepted");
        attempt.phase = Phase::AwaitClientConfirm;
        match attempt.on_client_retry().expect("a retry is answered") {
            RetryOutcome::NextRound(step) => {
                assert!(
                    step.announce_code,
                    "the operator is asked for the code again"
                );
                match &step.messages[0] {
                    Incoming::ServerPairInit(init) => {
                        assert_eq!(init.nonce_a, None, "only the first round carries nonce_A");
                    }
                    other => panic!("expected server/pair-init, got {other:?}"),
                }
            }
            RetryOutcome::Exhausted => panic!("the first retry is below the limit"),
        }
        assert!(
            attempt.accepts_code(),
            "the next round waits for the code again"
        );
    }

    #[cfg(feature = "pairing-code")]
    #[test]
    fn an_attempt_redacts_the_code() {
        let mut attempt = dynamic_attempt();
        attempt
            .on_pair_init(&pair_init(Some(&commitment_text())), &[0x11; 32])
            .expect("a dynamic init is accepted");
        attempt
            .on_entered_code("123456", &[0x11; 32])
            .expect("a well-formed code is accepted");
        let text = format!("{attempt:?}");
        assert!(text.contains("<redacted>"), "got: {text}");
        assert!(
            !text.contains("123456"),
            "the code must not reach a log: {text}"
        );
    }

    #[cfg(feature = "pairing-code")]
    #[test]
    fn a_token_attempt_does_not_take_a_dynamic_format() {
        assert!(
            Attempt::code(PairingMethod::PairingPsk, None, 1, DEFAULT_PAIRING_TIMEOUT).is_err()
        );
        assert!(Attempt::code(
            PairingMethod::StaticCode,
            Some(CodeFormat::Digits),
            1,
            DEFAULT_PAIRING_TIMEOUT
        )
        .is_err());
        assert!(
            Attempt::code(PairingMethod::DynamicCode, None, 1, DEFAULT_PAIRING_TIMEOUT).is_err()
        );
    }
}
