//! The pairing method this client offers, and the state of one pairing attempt.
//!
//! One method is implemented: the Pairing PSK flow, which the protocol makes mandatory for every
//! client. It is offered exactly when a [`Storage`] is configured, because the method needs a
//! pairing PSK that survives restarts and a place to write the record the pairing produces. A
//! client without a store advertises no pairing method at all and answers a pairing activation
//! with `pair/abort` reason `method_not_supported`.
//!
//! The code-based methods are not part of this build. Their advertisement, attempt states and
//! messages arrive behind the `pairing-code` feature; the seam is the `#[cfg]` branch in
//! [`crate::session`]'s `supported_pair_methods`, and nothing here assumes they do not exist.
//!
//! # Key material
//!
//! The pairing PSK and the long-term PSK of an attempt are key material. Both are wrapped in types
//! whose `Debug` prints `<redacted>`, and neither is ever formatted into an event or an error.

use std::fmt;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::config::{PskCategory, StoredPsk};
use crate::storage::Storage;

/// Method identifier of the Pairing PSK flow, as it is spelled on the wire.
pub(crate) const METHOD_PAIRING_PSK: &str = "pairing_psk";

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
}

impl PairingAttempt {
    /// Starts an attempt, drawing the long-term PSK this pairing will deliver.
    pub(crate) fn new(pairing_index: u32, timeout: Duration) -> PairingAttempt {
        PairingAttempt {
            pairing_index,
            deadline: Instant::now() + timeout,
            psk: draw_key(),
        }
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
    /// Formats the attempt without the key it carries.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingAttempt")
            .field("pairing_index", &self.pairing_index)
            .field("deadline", &self.deadline)
            .field("psk", &"<redacted>")
            .finish()
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
}
