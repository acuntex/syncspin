//! Pairing records: the host trait, the record rule and the JSON file backend.
//!
//! The trait and the rule need no feature. The file backend is compiled only with
//! `--features storage-file`, so a default build never links file I/O and its tests are gated the
//! same way.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use syncspin_client::storage::{evict, persist_pairing, Storage, MAX_PAIRINGS};
use syncspin_client::{PskCategory, StoredPsk};

/// Builds a record whose key is derived from `server_id`, so a test can tell records apart.
fn record(server_id: &str) -> StoredPsk {
    let mut psk = [0u8; 32];
    for (slot, byte) in psk.iter_mut().zip(server_id.bytes().cycle()) {
        *slot = byte;
    }
    StoredPsk {
        category: PskCategory::LongTerm,
        psk,
        server_id: server_id.to_owned(),
    }
}

/// Builds records for `server_ids`, oldest first.
fn named(server_ids: &[&str]) -> Vec<StoredPsk> {
    server_ids.iter().map(|id| record(id)).collect()
}

/// The server ids of `records`, oldest first.
fn ids(records: &[StoredPsk]) -> Vec<&str> {
    records
        .iter()
        .map(|record| record.server_id.as_str())
        .collect()
}

/// A host store with no rule of its own: it replaces a record for the same server, appends the new
/// one, and removes on request. Capacity, ordering and the live-record pin are the crate's
/// [`persist_pairing`], which these tests exercise through the trait.
#[derive(Default)]
struct MemoryStorage {
    pairing_psk: Mutex<Option<[u8; 32]>>,
    pairings: Mutex<Vec<StoredPsk>>,
}

impl Storage for MemoryStorage {
    fn pairing_psk(&self) -> Result<Option<[u8; 32]>> {
        Ok(*self
            .pairing_psk
            .lock()
            .expect("the test store is never poisoned"))
    }

    fn store_pairing_psk(&self, psk: &[u8; 32]) -> Result<()> {
        *self
            .pairing_psk
            .lock()
            .expect("the test store is never poisoned") = Some(*psk);
        Ok(())
    }

    fn load_pairings(&self) -> Result<Vec<StoredPsk>> {
        Ok(self
            .pairings
            .lock()
            .expect("the test store is never poisoned")
            .clone())
    }

    fn store_pairing(&self, record: StoredPsk) -> Result<()> {
        let mut records = self
            .pairings
            .lock()
            .expect("the test store is never poisoned");
        records.retain(|held| held.server_id != record.server_id);
        records.push(record);
        Ok(())
    }

    fn remove_pairing(&self, server_id: &str) -> Result<()> {
        self.pairings
            .lock()
            .expect("the test store is never poisoned")
            .retain(|held| held.server_id != server_id);
        Ok(())
    }
}

#[test]
fn the_storage_trait_is_object_safe() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::default());
    assert_eq!(
        storage.pairing_psk().expect("an empty store has no PSK"),
        None
    );

    storage
        .store_pairing_psk(&[7; 32])
        .expect("the store keeps the PSK");
    assert_eq!(
        storage.pairing_psk().expect("the PSK was stored"),
        Some([7; 32])
    );

    storage
        .store_pairing(record("server"))
        .expect("the store keeps a record");
    assert_eq!(
        ids(&storage.load_pairings().expect("the store loads")),
        ["server"]
    );

    storage
        .remove_pairing("server")
        .expect("the store removes a record");
    assert!(storage.load_pairings().expect("the store loads").is_empty());
}

#[test]
fn a_store_keeps_five_records_and_the_sixth_evicts_the_oldest() {
    let mut records = named(&["a", "b", "c", "d", "e"]);
    assert_eq!(records.len(), MAX_PAIRINGS);
    assert_eq!(
        evict(&mut records, None),
        None,
        "a store that is exactly full has nothing to drop"
    );

    records.push(record("f"));
    assert_eq!(evict(&mut records, None), Some(0));
    assert_eq!(ids(&records), ["b", "c", "d", "e", "f"]);
}

#[test]
fn the_live_record_is_skipped_when_a_record_has_to_go() {
    let mut records = named(&["live", "b", "c", "d", "e", "f"]);
    assert_eq!(evict(&mut records, Some("live")), Some(1));
    assert_eq!(ids(&records), ["live", "c", "d", "e", "f"]);
}

#[test]
fn a_store_holding_only_the_live_record_keeps_it() {
    let mut records = named(&["live"; 6]);
    assert_eq!(
        evict(&mut records, Some("live")),
        None,
        "the live record is never evictable, even over the floor"
    );
    assert_eq!(records.len(), 6);
}

#[test]
fn a_pairing_never_fails_for_lack_of_space() {
    // A host store with no eviction logic of its own, behind the trait object the client holds.
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::default());
    for id in ["a", "b", "c", "d", "e"] {
        storage
            .store_pairing(record(id))
            .expect("the store is open");
    }
    assert_eq!(storage.load_pairings().expect("the store loads").len(), 5);

    persist_pairing(&*storage, record("f"), None).expect("a full store makes room for a pairing");

    let loaded = storage.load_pairings().expect("the store loads");
    assert_eq!(loaded.len(), MAX_PAIRINGS);
    assert_eq!(ids(&loaded), ["b", "c", "d", "e", "f"]);
}

#[test]
fn the_live_record_survives_when_it_is_the_oldest() {
    let storage = MemoryStorage::default();
    for id in ["live", "b", "c", "d", "e"] {
        storage
            .store_pairing(record(id))
            .expect("the store is open");
    }

    persist_pairing(&storage, record("f"), Some("live"))
        .expect("the store makes room for a pairing");

    let loaded = storage.load_pairings().expect("the store loads");
    assert_eq!(loaded.len(), MAX_PAIRINGS);
    assert_eq!(
        ids(&loaded),
        ["live", "c", "d", "e", "f"],
        "the live record stays; the second oldest goes"
    );
}

#[test]
fn a_record_stored_again_moves_to_the_end() {
    let storage = MemoryStorage::default();
    for id in ["a", "b", "c", "d", "e"] {
        storage
            .store_pairing(record(id))
            .expect("the store is open");
    }

    let renewed = StoredPsk {
        psk: [9; 32],
        ..record("a")
    };
    persist_pairing(&storage, renewed.clone(), Some("a")).expect("the store replaces a record");

    let loaded = storage.load_pairings().expect("the store loads");
    assert_eq!(ids(&loaded), ["b", "c", "d", "e", "a"]);
    assert_eq!(loaded.len(), MAX_PAIRINGS, "re-storing must not duplicate");
    assert_eq!(loaded[4], renewed, "the newer key replaces the older one");
}

#[test]
fn the_record_being_stored_is_never_the_victim() {
    // Every held record belongs to the live server, so the live pin leaves no victim. The crate
    // still stores the new record rather than let the pairing fail; the store ends above the floor.
    let storage = MemoryStorage::default();
    storage
        .pairings
        .lock()
        .expect("the test store is never poisoned")
        .extend(named(&["live"; MAX_PAIRINGS]));

    persist_pairing(&storage, record("new"), Some("live")).expect("the new record is stored");

    let loaded = storage.load_pairings().expect("the store loads");
    assert_eq!(loaded.len(), MAX_PAIRINGS + 1);
    assert_eq!(
        loaded
            .iter()
            .filter(|held| held.server_id == "live")
            .count(),
        MAX_PAIRINGS,
        "no live record may be evicted"
    );
    assert_eq!(loaded[loaded.len() - 1].server_id, "new");
}

#[test]
fn a_record_without_a_server_never_reaches_the_store() {
    let storage = MemoryStorage::default();
    storage
        .store_pairing(record("a"))
        .expect("the store is open");
    let orphan = StoredPsk {
        server_id: String::new(),
        ..record("b")
    };

    let error =
        persist_pairing(&storage, orphan, None).expect_err("a record without a server is useless");
    assert!(
        format!("{error:#}").contains("server"),
        "the error must name what is missing, got: {error:#}"
    );
    assert_eq!(
        ids(&storage.load_pairings().expect("the store loads")),
        ["a"],
        "a refused record must not touch the store"
    );
}

#[test]
fn removing_a_pairing_leaves_the_rest_in_order() {
    let storage = MemoryStorage::default();
    for id in ["a", "b", "c", "d"] {
        storage
            .store_pairing(record(id))
            .expect("the store is open");
    }

    storage
        .remove_pairing("c")
        .expect("the store removes a record");
    assert_eq!(
        ids(&storage.load_pairings().expect("the store loads")),
        ["a", "b", "d"]
    );

    storage
        .remove_pairing("absent")
        .expect("removing a record the store does not hold is not an error");
    assert_eq!(
        ids(&storage.load_pairings().expect("the store loads")),
        ["a", "b", "d"]
    );
}

#[cfg(feature = "storage-file")]
mod files {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use syncspin_client::storage::FileStorage;

    use super::*;

    /// A private directory that removes itself when the test ends.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("the clock is after the epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "syncspin-storage-{}-{nanos}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("the test directory is created");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Opens a backend in a fresh directory, at the file name every test uses.
    fn open(dir: &TempDir) -> (FileStorage, PathBuf) {
        let path = dir.join("pairings.json");
        let storage = FileStorage::new(&path).expect("the backend creates its own file");
        (storage, path)
    }

    /// The one file's contents, as text.
    fn contents(path: &Path) -> String {
        fs::read_to_string(path).expect("the store is readable")
    }

    /// A JSON store holding `server_ids`, as a host might have written it.
    fn store_with(server_ids: &[&str]) -> String {
        let records: Vec<String> = server_ids
            .iter()
            .map(|id| file_record(&record(id).psk, "lt", id, ""))
            .collect();
        file_store(&records)
    }

    /// One record as the file spells it, for a store a test writes by hand.
    fn file_record(key: &[u8; 32], category: &str, server_id: &str, extra: &str) -> String {
        let key = URL_SAFE_NO_PAD.encode(key);
        format!(r#"{{"category":"{category}","psk":"{key}","server_id":"{server_id}"{extra}}}"#)
    }

    /// A whole store holding `records`, which is the JSON of a list.
    fn file_store(records: &[String]) -> String {
        format!(
            r#"{{"version":1,"pairing_psk":null,"pairings":[{}]}}"#,
            records.join(",")
        )
    }

    #[test]
    fn five_records_round_trip_through_the_file_in_order() {
        let dir = TempDir::new();
        let (storage, path) = open(&dir);
        for id in ["a", "b", "c", "d", "e"] {
            storage
                .store_pairing(record(id))
                .expect("the file is writable");
        }
        assert_eq!(
            ids(&storage.load_pairings().expect("the file loads")),
            ["a", "b", "c", "d", "e"]
        );
        drop(storage);

        let reopened = FileStorage::new(&path).expect("the file this build wrote is recognised");
        assert_eq!(
            ids(&reopened.load_pairings().expect("the file loads")),
            ["a", "b", "c", "d", "e"]
        );
    }

    #[test]
    fn a_direct_store_on_a_full_file_drops_the_oldest() {
        let dir = TempDir::new();
        let (storage, path) = open(&dir);
        for id in ["a", "b", "c", "d", "e", "f"] {
            storage
                .store_pairing(record(id))
                .expect("the file is writable");
        }

        let loaded = storage.load_pairings().expect("the file loads");
        assert_eq!(loaded.len(), MAX_PAIRINGS);
        assert_eq!(ids(&loaded), ["b", "c", "d", "e", "f"]);

        drop(storage);
        let reopened = FileStorage::new(&path).expect("the file is recognised");
        assert_eq!(
            ids(&reopened.load_pairings().expect("the file loads")),
            ["b", "c", "d", "e", "f"]
        );
    }

    #[test]
    fn the_crate_rule_drives_the_file_backend_too() {
        let dir = TempDir::new();
        let (storage, path) = open(&dir);
        for id in ["live", "b", "c", "d", "e"] {
            storage
                .store_pairing(record(id))
                .expect("the file is writable");
        }

        persist_pairing(&storage, record("f"), Some("live")).expect("the file makes room");

        let loaded = storage.load_pairings().expect("the file loads");
        assert_eq!(loaded.len(), MAX_PAIRINGS);
        assert_eq!(
            ids(&loaded),
            ["live", "c", "d", "e", "f"],
            "the rule is the crate's, even over a file"
        );

        drop(storage);
        let reopened = FileStorage::new(&path).expect("the file is recognised");
        assert_eq!(
            ids(&reopened.load_pairings().expect("the file loads")),
            ["live", "c", "d", "e", "f"]
        );
    }

    #[test]
    fn re_storing_a_record_moves_it_to_the_end_of_the_file() {
        let dir = TempDir::new();
        let (storage, path) = open(&dir);
        for id in ["a", "b", "c", "d", "e"] {
            storage
                .store_pairing(record(id))
                .expect("the file is writable");
        }
        let renewed = StoredPsk {
            psk: [9; 32],
            ..record("a")
        };
        storage
            .store_pairing(renewed)
            .expect("the file replaces a record");

        let loaded = storage.load_pairings().expect("the file loads");
        assert_eq!(ids(&loaded), ["b", "c", "d", "e", "a"]);
        assert_eq!(loaded.len(), MAX_PAIRINGS);
        assert_eq!(loaded[4].psk, [9; 32], "the newer key is the one kept");

        drop(storage);
        let reopened = FileStorage::new(&path).expect("the file is recognised");
        assert_eq!(
            ids(&reopened.load_pairings().expect("the file loads")),
            ["b", "c", "d", "e", "a"]
        );
    }

    #[test]
    fn removing_a_pairing_leaves_a_file_that_still_loads() {
        let dir = TempDir::new();
        let (storage, path) = open(&dir);
        for id in ["a", "b", "c"] {
            storage
                .store_pairing(record(id))
                .expect("the file is writable");
        }

        storage
            .remove_pairing("b")
            .expect("the file removes a record");
        assert_eq!(
            ids(&storage.load_pairings().expect("the file loads")),
            ["a", "c"]
        );

        storage
            .remove_pairing("absent")
            .expect("removing a record the store does not hold is not an error");
        assert_eq!(
            ids(&storage.load_pairings().expect("the file loads")),
            ["a", "c"]
        );

        drop(storage);
        let reopened = FileStorage::new(&path).expect("the file is still recognised");
        assert_eq!(
            ids(&reopened.load_pairings().expect("the file loads")),
            ["a", "c"]
        );

        reopened
            .remove_pairing("a")
            .expect("the file removes a record");
        reopened
            .remove_pairing("c")
            .expect("the file removes a record");
        assert!(reopened
            .load_pairings()
            .expect("an empty file loads")
            .is_empty());
        drop(reopened);
        FileStorage::new(&path).expect("an empty store is still a store this build owns");
        assert!(
            contents(&path).contains("\"pairings\": []"),
            "the file must hold no record once they are all removed"
        );
    }

    #[test]
    fn the_pairing_psk_round_trips_beside_the_records() {
        let dir = TempDir::new();
        let (storage, path) = open(&dir);
        assert_eq!(
            storage.pairing_psk().expect("the file loads"),
            None,
            "a new store has no pairing PSK"
        );

        storage
            .store_pairing_psk(&[3; 32])
            .expect("the file is writable");
        storage
            .store_pairing(record("a"))
            .expect("the file is writable");
        assert_eq!(
            storage.pairing_psk().expect("the file loads"),
            Some([3; 32])
        );

        drop(storage);
        let reopened = FileStorage::new(&path).expect("the file is recognised");
        assert_eq!(
            reopened.pairing_psk().expect("the file loads"),
            Some([3; 32])
        );
        assert_eq!(
            ids(&reopened.load_pairings().expect("the file loads")),
            ["a"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new();
        let (storage, path) = open(&dir);
        let mode = fs::metadata(&path)
            .expect("the file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "a new store must not be readable by others");

        storage
            .store_pairing(record("a"))
            .expect("the file is writable");
        let mode = fs::metadata(&path)
            .expect("the file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "a rewrite must keep the file private");
    }

    #[test]
    fn a_file_this_build_does_not_recognise_is_refused_and_left_alone() {
        let dir = TempDir::new();
        let path = dir.join("pairings.json");

        let key = [0u8; 32];
        let mut contents_before = [
            "",
            "not json at all",
            r#"{"version":2,"pairing_psk":null,"pairings":[]}"#,
            r#"{"version":"1","pairing_psk":null,"pairings":[]}"#,
            r#"{"version":1,"pairing_psk":null,"pairings":[],"extra":1}"#,
        ]
        .map(str::to_owned)
        .to_vec();
        // A record with a field this build does not write.
        contents_before.push(file_store(&[file_record(&key, "lt", "a", r#","note":1"#)]));
        // A record whose category this build does not know.
        contents_before.push(file_store(&[file_record(&key, "xx", "a", "")]));
        // Two records for one server, which this build never writes.
        contents_before.push(file_store(&[
            file_record(&key, "lt", "a", ""),
            file_record(&key, "lt", "a", ""),
        ]));

        for contents_before in contents_before {
            fs::write(&path, &contents_before).expect("the test writes the file");
            let error = FileStorage::new(&path)
                .expect_err("a file this build does not own must be refused");
            let message = format!("{error:#}");
            assert!(
                message.contains("pairings.json"),
                "the error must name the file it refused, got: {message}"
            );
            assert_eq!(
                contents(&path),
                contents_before,
                "a refused file must not be rewritten"
            );
        }
    }

    #[test]
    fn a_broken_file_does_not_echo_its_key_in_the_error() {
        let dir = TempDir::new();
        let path = dir.join("pairings.json");
        let key = [0x5a; 32];
        let encoded = URL_SAFE_NO_PAD.encode(key);
        let contents_before = file_store(&[file_record(&key, "xx", "a", "")]);
        fs::write(&path, &contents_before).expect("the test writes the file");

        let error = FileStorage::new(&path).expect_err("the record is malformed");
        for message in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
        ] {
            assert!(
                !message.contains(&encoded),
                "the error must not repeat the encoded key, got: {message}"
            );
            assert!(
                !message.contains(&format!("{key:?}")),
                "the error must not repeat the raw key, got: {message}"
            );
        }
    }

    #[test]
    fn the_backend_formats_without_its_contents() {
        let dir = TempDir::new();
        let (storage, path) = open(&dir);
        storage
            .store_pairing_psk(&[0x5a; 32])
            .expect("the file is writable");

        let text = format!("{storage:?}");
        assert!(text.contains("FileStorage"), "unexpected format: {text}");
        assert!(
            text.contains(&path.display().to_string()),
            "the backend names the file it owns, got: {text}"
        );
        for secret in [
            URL_SAFE_NO_PAD.encode([0x5a; 32]),
            format!("{:?}", [0u8; 32]),
        ] {
            assert!(
                !text.contains(&secret),
                "the backend must not print its secrets, got: {text}"
            );
        }
    }

    #[test]
    fn a_store_a_host_wrote_with_more_records_is_read_but_not_trimmed() {
        let dir = TempDir::new();
        let path = dir.join("pairings.json");
        fs::write(&path, store_with(&["a", "b", "c", "d", "e", "f", "g"]))
            .expect("the test writes the file");

        let storage = FileStorage::new(&path).expect("another host's store has our shape");
        assert_eq!(
            ids(&storage.load_pairings().expect("the file loads")),
            ["a", "b", "c", "d", "e", "f", "g"],
            "reading must not trim a store this build did not limit"
        );

        persist_pairing(&storage, record("h"), None).expect("the file makes room");
        assert_eq!(
            ids(&storage.load_pairings().expect("the file loads")),
            ["d", "e", "f", "g", "h"],
            "the next pairing applies the five-record floor and keeps the new record"
        );
    }

    #[test]
    fn a_store_without_the_optional_psk_key_reads_as_having_none() {
        let dir = TempDir::new();
        let path = dir.join("pairings.json");
        let record = file_record(&[0; 32], "lt", "a", "");
        fs::write(&path, format!(r#"{{"version":1,"pairings":[{record}]}}"#))
            .expect("the test writes the file");

        let storage = FileStorage::new(&path)
            .expect("an absent optional field is still this backend's shape");
        assert_eq!(storage.pairing_psk().expect("the file loads"), None);
        assert_eq!(
            ids(&storage.load_pairings().expect("the file loads")),
            ["a"]
        );
    }

    #[test]
    fn a_record_without_a_server_is_refused() {
        let dir = TempDir::new();
        let (storage, _path) = open(&dir);
        let orphan = StoredPsk {
            server_id: String::new(),
            ..record("a")
        };

        let error = storage
            .store_pairing(orphan)
            .expect_err("a record without a server cannot be selected later");
        assert!(
            format!("{error:#}").contains("server"),
            "the error must name what is missing, got: {error:#}"
        );
        assert!(
            storage
                .load_pairings()
                .expect("the file still loads")
                .is_empty(),
            "a refused record must not reach the file"
        );
        FileStorage::new(storage.path()).expect("the file is still one this build owns");
    }

    #[test]
    fn a_write_leaves_no_temporary_file_behind() {
        let dir = TempDir::new();
        let (storage, _path) = open(&dir);
        storage
            .store_pairing(record("a"))
            .expect("the file is writable");
        storage
            .store_pairing(record("b"))
            .expect("the file is writable");

        let mut names: Vec<String> = fs::read_dir(&dir.path)
            .expect("the test directory is readable")
            .map(|entry| {
                entry
                    .expect("the directory entry is readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(names, ["pairings.json"]);
    }

    #[test]
    fn a_missing_parent_directory_is_an_error() {
        let dir = TempDir::new();
        let path = dir.join("absent").join("pairings.json");
        let error = FileStorage::new(&path).expect_err("the backend does not create directories");
        assert!(
            format!("{error:#}").contains("pairings.json"),
            "the error must name the file, got: {error:#}"
        );
    }
}
