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
//! # Key material
//!
//! The pairing PSK and the long-term PSK of an attempt are key material. Both are wrapped in types
//! whose `Debug` prints `<redacted>`, and neither is ever formatted into an event or an error. The
//! static code, the CPace intermediate session key and the key-confirmation tags are secrets of
//! the same kind: they live in types without a formatting implementation, and the tags leave this
//! module only as base64 on the wire.

use std::fmt;
use std::time::{Duration, Instant};

#[cfg(feature = "pairing-code")]
use anyhow::bail;
use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

#[cfg(feature = "pairing-code")]
use syncspin_core::pairing::pake::{self, SHARE_LEN, TAG_LEN};
#[cfg(feature = "pairing-code")]
use syncspin_core::pairing::wrap::{self, PSK_LABEL};

use crate::config::{PskCategory, StoredPsk};
use crate::storage::Storage;

/// Method identifier of the Pairing PSK flow, as it is spelled on the wire.
pub(crate) const METHOD_PAIRING_PSK: &str = "pairing_psk";

/// Method identifier of the Static Pairing Code flow, as it is spelled on the wire.
#[cfg(feature = "pairing-code")]
pub(crate) const METHOD_STATIC_PAIRING_CODE: &str = "static_pairing_code";

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

/// Which method one attempt runs, and how far a static-code attempt has gone.
///
/// The Pairing PSK flow sends both of its messages back to back, so it has one state. The static
/// flow alternates with the server: init, the two CPace shares, the two tags, then the finalize.
#[cfg(feature = "pairing-code")]
enum Flow {
    /// The Pairing PSK flow, which sends `client/pair-init` and `client/pair-finalize` at once.
    PairingPsk,
    /// The Static Pairing Code flow, in the phase its one CPace round is in.
    Static(CodePhase),
}

/// How far the single CPace round of a static-code attempt has gone.
#[cfg(feature = "pairing-code")]
enum CodePhase {
    /// `client/pair-init` is on the wire; the server's share is awaited.
    Auth,
    /// Both shares crossed; the server's tag is awaited and ours is ready to send.
    Confirm(StaticCode),
    /// Both tags crossed and the sealed key is on the wire; `server/pair-finalize` is awaited.
    Finalization,
}

/// The values a static-code attempt holds between `server/pair-auth` and `server/pair-confirm`.
///
/// The CPace intermediate session key is not kept: the two tags and the sealed long-term PSK are
/// everything the following messages need, and they are dropped once the finalize is sent.
#[cfg(feature = "pairing-code")]
struct StaticCode {
    /// `Ta`, the server's tag this client expects in `server/pair-confirm`.
    expected_server_tag: [u8; TAG_LEN],
    /// `Tb`, this client's tag for `client/pair-confirm`.
    client_tag: [u8; TAG_LEN],
    /// The long-term PSK sealed under `K_wrap`, for `client/pair-finalize`.
    wrapped_psk: [u8; SEALED_LEN],
}

/// What a verified `server_kc` releases: the two fields of the messages that follow.
///
/// Both are key material in base64, so the type has no formatting implementation.
#[cfg(feature = "pairing-code")]
pub(crate) struct Confirmation {
    /// `Tb` as 86 unpadded base64url characters, for `client/pair-confirm`.
    pub(crate) client_kc: String,
    /// The sealed long-term PSK as 64 unpadded base64url characters, for `client/pair-finalize`.
    pub(crate) wrapped_psk: String,
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
    pub(crate) fn new(pairing_index: u32, timeout: Duration) -> PairingAttempt {
        PairingAttempt {
            pairing_index,
            deadline: Instant::now() + timeout,
            psk: draw_key(),
            #[cfg(feature = "pairing-code")]
            flow: Flow::PairingPsk,
        }
    }

    /// Starts a static-code attempt, which waits for the server's CPace share.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn static_code(pairing_index: u32, timeout: Duration) -> PairingAttempt {
        PairingAttempt {
            pairing_index,
            deadline: Instant::now() + timeout,
            psk: draw_key(),
            flow: Flow::Static(CodePhase::Auth),
        }
    }

    /// Whether this attempt runs the Static Pairing Code flow.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn is_static_code(&self) -> bool {
        matches!(self.flow, Flow::Static(_))
    }

    /// Whether the server's CPace share is the message this attempt is waiting for.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn awaiting_server_auth(&self) -> bool {
        matches!(self.flow, Flow::Static(CodePhase::Auth))
    }

    /// Whether the server's key-confirmation tag is the message this attempt is waiting for.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn awaiting_server_confirm(&self) -> bool {
        matches!(self.flow, Flow::Static(CodePhase::Confirm(_)))
    }

    /// Whether `server/pair-finalize` is the message this attempt is waiting for.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn awaiting_finalize(&self) -> bool {
        matches!(self.flow, Flow::Static(CodePhase::Finalization))
    }

    /// Answers `server/pair-auth`: derives the shared point, both tags and the sealed key.
    ///
    /// `sid` is [`pake_sid`] of this attempt and `code` the configured code, whose digits are
    /// CPace's `PRS`. The function returns `Yb`, the share `client/pair-auth` carries. The CPace
    /// intermediate session key stays inside this call; only what the next two messages need is
    /// kept.
    ///
    /// # Errors
    ///
    /// Fails when the server's share encodes a low-order point, which the draft requires the round
    /// to abort. The session treats that as a protocol error and closes the connection.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn accept_server_share(
        &mut self,
        code: &str,
        sid: &[u8],
        peer_share: &[u8; SHARE_LEN],
    ) -> Result<[u8; SHARE_LEN]> {
        if !self.awaiting_server_auth() {
            bail!("the attempt is not waiting for the server's CPace share");
        }

        let generator = pake::generator(code.as_bytes(), b"", sid);
        // A fresh scalar per attempt: reusing one would link attempts, and the draft samples a new
        // one for every run.
        let scalar = draw_key();
        let share = pake::public_share(&scalar, &generator)
            .context("the CPace generator did not yield a group element")?;

        // The peer's share is verified before a transcript is built from it.
        let point = pake::scalar_mult_vfy(&scalar, peer_share)?;
        let transcript = pake::transcript_ir(peer_share, AD_SERVER, &share, AD_CLIENT);
        let isk = pake::intermediate_session_key(sid, &point, &transcript);
        let expected_server_tag = pake::key_confirmation_tag(sid, &isk, peer_share, AD_SERVER);
        let client_tag = pake::key_confirmation_tag(sid, &isk, &share, AD_CLIENT);
        let wrapped_psk = wrap::wrap(&wrap::k_wrap(PSK_LABEL, sid, &isk), &self.psk);

        self.flow = Flow::Static(CodePhase::Confirm(StaticCode {
            expected_server_tag,
            client_tag,
            wrapped_psk,
        }));
        Ok(share)
    }

    /// Verifies `server_kc` and, when it matches, releases the two fields to send next.
    ///
    /// A mismatch is `None`: the static flow has no retry, so the caller aborts the attempt with
    /// `pairing_code_mismatch` and counts it against the pairing window. The comparison is
    /// constant-time and the release happens only after it succeeds, so a peer that cannot derive
    /// the key never sees the sealed long-term PSK.
    #[cfg(feature = "pairing-code")]
    pub(crate) fn verify_server_tag(&mut self, received: &[u8; TAG_LEN]) -> Option<Confirmation> {
        let Flow::Static(CodePhase::Confirm(state)) = &self.flow else {
            return None;
        };
        if !pake::verify_key_confirmation_tag(&state.expected_server_tag, received) {
            return None;
        }
        let confirmation = Confirmation {
            client_kc: URL_SAFE_NO_PAD.encode(state.client_tag),
            wrapped_psk: URL_SAFE_NO_PAD.encode(state.wrapped_psk),
        };
        self.flow = Flow::Static(CodePhase::Finalization);
        Some(confirmation)
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
    /// Formats the attempt without the key it carries or any CPace value.
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
                Flow::Static(CodePhase::Auth) => "static_pairing_code/awaiting_auth",
                Flow::Static(CodePhase::Confirm(_)) => "static_pairing_code/awaiting_confirm",
                Flow::Static(CodePhase::Finalization) => "static_pairing_code/awaiting_finalize",
            };
            debug.field("flow", &flow);
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
        let attempt = PairingAttempt::new(1, Duration::from_secs(120));
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
        let attempt = PairingAttempt::new(4, Duration::from_secs(120));
        assert_eq!(attempt.pairing_index, 4);
        assert!(attempt.deadline >= started + Duration::from_secs(120));
        assert_ne!(attempt.psk(), [0u8; 32], "the attempt draws its own key");
        assert_eq!(
            attempt.psk_base64().len(),
            43,
            "the wire carries the key unpadded base64url"
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

        let mut attempt = PairingAttempt::static_code(7, Duration::from_secs(120));
        let share = attempt
            .accept_server_share(CODE, &sid, &peer_share)
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
        assert!(attempt.verify_server_tag(&tampered).is_none());
        assert!(
            attempt.awaiting_server_confirm(),
            "a mismatch leaves the attempt for the caller to abort"
        );

        let confirmation = attempt
            .verify_server_tag(&server_tag)
            .expect("the server's tag verifies");
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
            wrap::unwrap(&key, &sealed).expect("the seal opens under the server's key"),
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
        let fresh = PairingAttempt::static_code(1, Duration::from_secs(120));
        let text = format!("{fresh:?}");
        assert!(
            text.contains("static_pairing_code/awaiting_auth"),
            "got: {text}"
        );
        assert!(fresh.is_static_code());
        assert!(!fresh.awaiting_server_confirm());
        assert!(!fresh.awaiting_finalize());
    }
}
