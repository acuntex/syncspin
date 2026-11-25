//! Client side of Sendspin.
//!
//! This crate owns the session: it connects to a server, runs the Noise handshake, keeps a clock
//! estimate and feeds audio to a sink the host provides. It stays device agnostic - the
//! application that owns the speakers implements `Sink` and decides what playout means.
//!
//! A connection always ends in Noise: the client refuses a server that does not complete the
//! handshake and never falls back to cleartext. A successful attempt reports [`Event::Connected`]
//! and then one event per change; an attempt that ends reports [`Event::Disconnected`] with the
//! delay before the next one, and the crate reconnects on its own with the same sink and identity.
//!
//! `connect` validates the configuration and spawns the connection; the first attempt and every
//! retry run in that task and reach the caller through the [`EventStream`]. Only an invalid
//! configuration or an address this build cannot use returns an error - an unreachable server is
//! reported as [`Event::Disconnected`]. The [`ClientHandle`] waits for the connection to end and
//! hands out a [`ControlHandle`] for transport commands, seek, the volume level and mute state. The
//! level follows [`ClientConfig::volume_policy`] - see [`clamp_volume_with`], and [`clamp_volume`]
//! for the default - and the value the server receives is the applied one. [`ClientConfig::volume`]
//! and [`ClientConfig::muted`] are the level and mute state the first report carries, so a host
//! passes the values it restored instead of letting the server see a baseline the output is not at.
//! `ControlHandle::report_volume` is the other direction: a level the host reads from its own
//! output is recorded and sent unchanged, because the policy limits requests rather than the level
//! the device is at.
//!
//! [`ClientConfig::device_info`] describes the device the client runs on and is announced in
//! `client/hello`; a host without an answer passes `None` and the server sees only the player name.
//!
//! Pairing records and the long-lived pairing PSK belong to the host: it implements
//! [`storage::Storage`] and the client keeps what it restores, so a paired server is recognised
//! across restarts. The crate does no file I/O of its own; `storage::FileStorage` is an optional
//! JSON backend behind the `storage-file` feature for a host that wants one.
//!
//! With a store the client offers the Pairing PSK method, the one method the protocol makes
//! mandatory, and runs it when a server admits an attempt: it draws the long-term PSK, sends
//! `client/pair-init` and `client/pair-finalize`, and writes the record after `server/pair-finalize`.
//! [`Event::Paired`] reports the record and [`Event::PairingFailed`] an attempt that ended without
//! one, always with the reason `pair/abort` carries. Without a store it offers no pairing method at
//! all: a guest connection is unchanged, and a server that picks pairing anyway is answered with
//! `pair/abort` reason `method_not_supported`. A pairing attempt is bounded by
//! [`ClientConfig::pairing_timeout`], [`DEFAULT_PAIRING_TIMEOUT`] by default.
//!
//! With the `pairing-code` feature and a code in
//! `ClientConfig::static_pairing_code`, the client also offers the Static Pairing Code method. Every
//! attempt is gated by an operator gesture: `ControlHandle::open_pairing_window` opens a window on
//! the live connection, the client answers a pairing activation with `client/pair-pending` while
//! none is open, and the fifth failed key confirmation closes the window. The round runs CPace over
//! X25519 with SHA-512 and delivers the new long-term PSK sealed under its output; that layer has
//! not had an external review.
//!
//! With the same feature and at least one entry in each of `ClientConfig::code_formats` and
//! `ClientConfig::code_out_channels`, the client offers the Dynamic Pairing Code method instead of
//! relying on a fixed secret. It draws a nonce per attempt, locks it with `commit_B` in
//! `client/pair-init`, and derives the per-session code once the server's `nonce_A` arrives: six
//! digits, or a version-1 pairing token for a QR code. `Event::PairingCode` carries the code and
//! its round; the code stays the same across the rounds of one attempt. A failed key confirmation
//! asks the server for another round, and the twentieth failed round ends the attempt. After the
//! limit the client holds dynamic attempts back - answering them with `client/pair-pending` - until
//! `ControlHandle::release_holdback` is called, the deliberate operator action the spec requires.
//!
//! A pairing record can also be dropped from the server's side. `server/unpair` removes it, reports
//! [`Event::Unpaired`] and closes the connection after `client/goodbye` with reason `unpaired`; a
//! server that announces a `psk_id` the client does not hold is reported once per connection as
//! [`Event::PairingRequired`] with reason [`PairingRequiredReason::CredentialMismatch`], so a host
//! can offer pairing again instead of the lost record going unnoticed. A deliberate close -
//! [`ClientHandle::close`] or dropping the handle - sends `client/goodbye` with its reason, so the
//! server can tell a restart from a shutdown and does not treat the close as a dropped link.
//!
//! [`ControlHandle::pairing_token`] hands the operator the version-0 `SP:` token while a store is
//! configured; it is a credential, so a host renders it only when the operator needs it.
//!
//! With the `discovery` feature the client can also take the other half of `connection.md`: instead
//! of dialling a server it advertises `_sendspin._tcp` and accepts the server that connects.
//! `Inbound` names the host's [`Discovery`] backend, the address to listen on and the path to
//! serve; `advertise` publishes the record - the bound port and the `path` and `name` TXT
//! records - and then serves one server at a time through the same session as a dialled connection.
//! An upgrade that carries an `Origin` header is refused, as the spec requires, and the Noise
//! handshake is unchanged because the server initiates it in both directions. A client uses one of
//! the two methods at a time: while `ClientConfig::inbound` is set, `connect` refuses to dial.
//! A second server that arrives while one is admitted is rejected with `client/goodbye` reason
//! `concurrent_attempt` and closed, which is the spec's admission rule for a client that caps
//! itself at one connection. The `mdns` feature carries the `mdns-sd` implementation of
//! [`Discovery`]; without it the trait is the seam, so a host can supply its own backend and a
//! fake drives the tests.
//!
//! A host that renders the stream sees its lifecycle as events: `Event::StreamStart` for a new
//! format, `Event::StreamEnd` when the server pauses or removes the player role, and
//! `Event::StreamClear` for a seek, plus [`Event::Track`] for the now-playing metadata with its
//! position, duration and playback speed. The end and clear events arrive before the client
//! discards or flushes the buffered audio, so the host can mute, stop or restart its output first.
//!
//! A host with no audio output uses [`connect_headless`] instead: the client then has no sink, does
//! not offer the `player@v1` role and reports no player state, and it starts its first
//! `client/state` and its clock as soon as the server activates a role.
//!
//! The connection keeps running until the audio sink fails, which the host has to repair, or until
//! the handle or the event stream is dropped.

#[cfg(feature = "player")]
mod buffer;
mod client;
mod config;
mod discovery;
mod pairing;
#[cfg(feature = "player")]
mod playout;
mod roles;
mod session;
#[cfg(feature = "player")]
mod sink;

pub mod storage;

pub use client::{
    clamp_volume, clamp_volume_with, connect_headless, connect_headless_with_psks, next_backoff,
    Client, ClientHandle, ControlHandle, Event, EventStream, GoodbyeReason, PairingFailure,
    PairingRequiredReason, PlaybackState, StreamEndReason, DEFAULT_PAIRING_TIMEOUT,
    INITIAL_BACKOFF, NORMAL_PLAYBACK_SPEED,
};
#[cfg(feature = "player")]
pub use client::{connect, connect_with_psks};
pub use config::{
    AudioMode, ClientConfig, DeviceInfo, PskCategory, StoredPsk, VolumePolicy, DEFAULT_MAX_BACKOFF,
    MAX_PLAYER_NAME_LEN,
};
#[cfg(feature = "pairing-code")]
pub use config::{
    CodeFormat, CodeOutChannel, DEFAULT_PAIRING_WINDOW, MAX_PAIRING_PENDING_TEXT_LEN,
    STATIC_PAIRING_CODE_LEN,
};
#[cfg(all(feature = "discovery", feature = "player"))]
pub use discovery::advertise;
#[cfg(feature = "mdns")]
pub use discovery::MdnsDiscovery;
#[cfg(feature = "discovery")]
pub use discovery::{advertise_headless, Inbound, DEFAULT_INBOUND_ADDR, DEFAULT_INBOUND_PORT};
pub use discovery::{
    discover_reachable_endpoint, discover_servers, reachable_endpoint, DiscoveredServer, Discovery,
    ServiceAdvertisement, CLIENT_SERVICE_TYPE, DEFAULT_SENDSPIN_PATH, SERVER_SERVICE_TYPE,
};
#[cfg(feature = "player")]
pub use sink::{AudioFormat, AudioFrame, Codec, Sink};

// The identity is part of [`ClientConfig`], so a host that builds a configuration needs it. A
// re-export keeps a consumer from having to depend on the protocol crate directly.
pub use syncspin_core::noise::Identity;

/// Returns the version of this crate as recorded in its manifest.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared test doubles for the unit tests in this crate.

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};
    #[cfg(feature = "player")]
    use std::time::Instant;

    use anyhow::{bail, Result};

    use crate::config::StoredPsk;
    #[cfg(feature = "player")]
    use crate::sink::{AudioFormat, AudioFrame, Sink};
    use crate::storage::Storage;

    /// A sink that accepts every call and keeps the trait's default output delay and underrun count.
    #[cfg(feature = "player")]
    pub(crate) struct NullSink;

    #[cfg(feature = "player")]
    impl Sink for NullSink {
        fn open(&mut self, _format: AudioFormat) -> anyhow::Result<()> {
            Ok(())
        }

        fn write(&mut self, _frame: AudioFrame<'_>, _due: Instant) -> anyhow::Result<()> {
            Ok(())
        }

        fn flush(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[cfg(feature = "player")]
    #[test]
    fn the_test_sink_reports_the_trait_defaults() {
        let mut sink = NullSink;
        sink.open(AudioFormat {
            codec: crate::Codec::Pcm,
            sample_rate: 48_000,
            channels: 2,
            bit_depth: 16,
            codec_header: None,
        })
        .expect("the test sink accepts a format");
        sink.write(AudioFrame::Pcm(&[1, 2]), Instant::now())
            .expect("the test sink accepts a frame");
        sink.flush().expect("the test sink flushes");
        assert_eq!(
            sink.output_delay(),
            None,
            "a sink that does not report a delay adds none"
        );
        assert_eq!(
            sink.underruns(),
            0,
            "a sink that does not count underruns reports none"
        );
    }

    /// A [`Storage`] that keeps everything in memory, optionally failing its calls.
    ///
    /// The crate's own tests need a store that answers instantly and one that fails a read or a
    /// write, so a single double carries both. It applies no rule of its own: the record ordering,
    /// the capacity and the live-record pin belong to [`persist_pairing`](crate::storage::persist_pairing).
    #[derive(Debug, Default)]
    pub(crate) struct MemoryStore {
        pairing: Mutex<Option<[u8; 32]>>,
        records: Mutex<Vec<StoredPsk>>,
        read_fails: AtomicBool,
        write_fails: AtomicBool,
        stored_pairing_psks: AtomicUsize,
    }

    impl MemoryStore {
        /// A store that already holds `pairing`.
        pub(crate) fn holding(pairing: [u8; 32]) -> MemoryStore {
            MemoryStore {
                pairing: Mutex::new(Some(pairing)),
                ..MemoryStore::default()
            }
        }

        /// A store whose reads fail.
        pub(crate) fn failing_reads() -> MemoryStore {
            MemoryStore {
                read_fails: AtomicBool::new(true),
                ..MemoryStore::default()
            }
        }

        /// A store whose writes fail.
        pub(crate) fn failing_writes() -> MemoryStore {
            MemoryStore {
                write_fails: AtomicBool::new(true),
                ..MemoryStore::default()
            }
        }

        /// The pairing PSK the store holds.
        pub(crate) fn pairing_psk_value(&self) -> Option<[u8; 32]> {
            *self.pairing.lock().expect("the store lock is not poisoned")
        }

        /// The records the store holds, oldest first.
        pub(crate) fn records(&self) -> Vec<StoredPsk> {
            self.records
                .lock()
                .expect("the store lock is not poisoned")
                .clone()
        }

        /// How often the client handed back a drawn pairing PSK.
        pub(crate) fn stored_pairing_psks(&self) -> usize {
            self.stored_pairing_psks.load(Ordering::SeqCst)
        }

        /// Puts a record into the store without going through the trait.
        pub(crate) fn preload(&self, record: StoredPsk) {
            self.records
                .lock()
                .expect("the store lock is not poisoned")
                .push(record);
        }

        /// The record list, for a caller that has to hold the lock across a change.
        fn records_lock(&self) -> MutexGuard<'_, Vec<StoredPsk>> {
            self.records.lock().expect("the store lock is not poisoned")
        }
    }

    impl Storage for MemoryStore {
        fn pairing_psk(&self) -> Result<Option<[u8; 32]>> {
            if self.read_fails.load(Ordering::SeqCst) {
                bail!("the test store was told to fail its reads");
            }
            Ok(self.pairing_psk_value())
        }

        fn store_pairing_psk(&self, psk: &[u8; 32]) -> Result<()> {
            if self.write_fails.load(Ordering::SeqCst) {
                bail!("the test store was told to fail its writes");
            }
            *self.pairing.lock().expect("the store lock is not poisoned") = Some(*psk);
            self.stored_pairing_psks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn load_pairings(&self) -> Result<Vec<StoredPsk>> {
            if self.read_fails.load(Ordering::SeqCst) {
                bail!("the test store was told to fail its reads");
            }
            Ok(self.records())
        }

        fn store_pairing(&self, record: StoredPsk) -> Result<()> {
            if self.write_fails.load(Ordering::SeqCst) {
                bail!("the test store was told to fail its writes");
            }
            let mut records = self.records_lock();
            records.retain(|held| held.server_id != record.server_id);
            records.push(record);
            Ok(())
        }

        fn remove_pairing(&self, server_id: &str) -> Result<()> {
            if self.write_fails.load(Ordering::SeqCst) {
                bail!("the test store was told to fail its writes");
            }
            self.records_lock()
                .retain(|record| record.server_id != server_id);
            Ok(())
        }
    }

    #[test]
    fn the_test_store_implements_the_storage_surface() {
        let store = MemoryStore::holding([7u8; 32]);
        assert_eq!(store.pairing_psk().unwrap(), Some([7u8; 32]));
        assert_eq!(store.pairing_psk_value(), Some([7u8; 32]));
        store.store_pairing_psk(&[8u8; 32]).unwrap();
        assert_eq!(store.pairing_psk().unwrap(), Some([8u8; 32]));
        assert_eq!(store.stored_pairing_psks(), 1);

        let record = StoredPsk {
            category: crate::PskCategory::LongTerm,
            psk: [9u8; 32],
            server_id: "a-server".to_owned(),
        };
        store.store_pairing(record.clone()).unwrap();
        store.preload(StoredPsk {
            server_id: "an-older-server".to_owned(),
            ..record.clone()
        });
        assert_eq!(store.records().len(), 2, "the older record stays");
        store.store_pairing(record.clone()).unwrap();
        assert_eq!(
            store.records().len(),
            2,
            "a record stored again replaces the one it replaces"
        );
        assert_eq!(store.load_pairings().unwrap().len(), 2);
        store.remove_pairing("a-server").unwrap();
        assert_eq!(store.load_pairings().unwrap().len(), 1);

        let reads = MemoryStore::failing_reads();
        assert!(reads.pairing_psk().is_err());
        assert!(reads.load_pairings().is_err());
        let writes = MemoryStore::failing_writes();
        assert!(writes.store_pairing_psk(&[0u8; 32]).is_err());
        assert!(writes.store_pairing(record).is_err());
        assert!(writes.remove_pairing("a-server").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_the_workspace_version() {
        assert_eq!(version(), "0.5.0");
    }
}
