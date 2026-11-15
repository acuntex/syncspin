//! Where pairing records live.
//!
//! A pairing record is the long-term key the client keeps for a server it has paired with, and the
//! pairing PSK is the key that admits the client to the pairing activity in the first place. Both
//! belong to the host: it owns the file, its permissions, its backups and its lifetime. [`Storage`]
//! is the whole surface the client needs, and a host that has no store configures none - the client
//! then does not pair at all, and a plain guest session is unchanged.
//!
//! # Recency is list order
//!
//! [`Storage::load_pairings`] returns records oldest first. Using a record stores it again so it
//! moves to the end, and [`persist_pairing`] drops the first record that does not back the live
//! connection. There is no timestamp in the rule and no extra method: a backend that keeps a list in
//! file order is a recency-ordered store.
//!
//! # Capacity
//!
//! A store the client writes keeps at most [`MAX_PAIRINGS`] records. The floor is five and it is a
//! floor, not a ceiling on what a host may hand back: a store the crate reads but did not write may
//! hold more, and the client uses it as it is. The client never evicts the record backing the live
//! connection, because losing it would drop the peer it is talking to.
//!
//! The rules are enforced by [`persist_pairing`], not by a backend: a host implements the four
//! primitive operations of [`Storage`] and the crate does the ordering, the capacity and the
//! live-record pin on top of them. A pairing therefore never fails for lack of space, whichever
//! store the host chose.
//!
//! # File backend
//!
//! `FileStorage` implements the trait over one JSON file and is available with the
//! `storage-file` feature. It writes a temporary file in the same directory and renames it over the
//! store, so a crash leaves either the old store or the new one; it creates its file with mode
//! `0600` on Unix; and it refuses a file whose shape it does not recognise instead of rewriting it.
//! No key, encoded or raw, appears in its `Debug` output or in an error.

use anyhow::{bail, Result};

use crate::config::StoredPsk;

/// Most pairing records the client keeps in a store.
///
/// The value is the protocol's floor, not a preference: a store that holds more is read as it is.
pub const MAX_PAIRINGS: usize = 5;

/// The place pairing records and the pairing PSK live.
///
/// The host implements this trait - over a file, a database, or the device's own configuration -
/// and hands it to the client. Every method may be called from the session task, so an
/// implementation must be `Send + Sync`.
///
/// The trait is a store, not a policy: [`store_pairing`](Storage::store_pairing) replaces a record
/// for the same server and appends the new one, and [`persist_pairing`] is what the client calls to
/// apply the ordering, the capacity of [`MAX_PAIRINGS`] and the live-record pin. A backend therefore
/// never has to know which connection is live.
pub trait Storage: Send + Sync + 'static {
    /// The long-lived pairing PSK the host restored, or `None` on a device's first run.
    ///
    /// The client draws a key when this is `None`, hands it back through
    /// [`store_pairing_psk`](Storage::store_pairing_psk), and exports it as a pairing token for the
    /// operator. A key the host restored is used as it is, so pairing survives a restart.
    fn pairing_psk(&self) -> Result<Option<[u8; 32]>>;

    /// Persists the pairing PSK the client drew on this run.
    ///
    /// The client calls this once, when [`pairing_psk`](Storage::pairing_psk) returned `None`; a
    /// key is never rotated on its own.
    fn store_pairing_psk(&self, psk: &[u8; 32]) -> Result<()>;

    /// The records of known servers, oldest first.
    ///
    /// A backend may return more than [`MAX_PAIRINGS`] records; the client reads them all and never
    /// trims a store it did not write.
    fn load_pairings(&self) -> Result<Vec<StoredPsk>>;

    /// Stores `record` as the newest record for its server.
    ///
    /// This is the primitive [`persist_pairing`] is built on: a record the store already holds for
    /// the same `server_id` is replaced and the new one is placed at the end, so storing it again
    /// moves it to the end of the list. A backend does not evict here - capacity and the live-record
    /// pin belong to [`persist_pairing`], which calls this only after it has made room. An empty
    /// `server_id` is rejected, so the store cannot be left holding a record that can never be
    /// selected.
    fn store_pairing(&self, record: StoredPsk) -> Result<()>;

    /// Removes the record for `server_id`.
    ///
    /// Removing a record the store does not hold is not an error: a server may unpair a client that
    /// already forgot it.
    fn remove_pairing(&self, server_id: &str) -> Result<()>;
}

/// Stores `record` under the record rules: newest at the end, at most [`MAX_PAIRINGS`], never the
/// record backing the live connection.
///
/// This is the operation the client uses after a completed pairing, and it works for any
/// [`Storage`]: the rule is the crate's, not a backend's. `record.server_id` is the server being
/// paired with, which may or may not be `live`; the live server is the one the connection is
/// currently talking to, and its record is never chosen as a victim.
///
/// The store is read first, so room is made before the new record is written: a pairing never fails
/// for lack of space. The victim is dropped through [`Storage::remove_pairing`], because eviction
/// writes only through the trait. If a backend call fails, the error is returned; records it
/// already removed stay removed and `record` is not stored.
pub fn persist_pairing(storage: &dyn Storage, record: StoredPsk, live: Option<&str>) -> Result<()> {
    if record.server_id.is_empty() {
        bail!("a pairing record must name a server");
    }

    let mut records = storage.load_pairings()?;
    records.retain(|held| held.server_id != record.server_id);
    // Make room for the record that is about to be the newest one, then write it. The record being
    // stored is not in `records`, so it can never be chosen as the victim.
    while records.len() >= MAX_PAIRINGS {
        let Some(index) = evictable(&records, live) else {
            // Every remaining record belongs to the live connection; the live pin wins over the
            // capacity floor, so the store keeps one more than five rather than drop it.
            break;
        };
        let victim = records.remove(index);
        storage.remove_pairing(&victim.server_id)?;
    }
    storage.store_pairing(record)
}

/// Drops the oldest record that is not `live` when `records` holds more than [`MAX_PAIRINGS`].
///
/// Returns the index that was removed, or `None` when the list has room or every record belongs to
/// the live server. The live record wins over the capacity floor: with only live records in the
/// list nothing is removed.
///
/// This is the list form of the rule [`persist_pairing`] applies, for a caller that already holds
/// the records. It operates on a list in recency order (oldest first), which is the order
/// [`Storage::load_pairings`] returns. The caller is responsible for a record it is about to store:
/// [`persist_pairing`] keeps that record out of the list until after eviction.
pub fn evict(records: &mut Vec<StoredPsk>, live: Option<&str>) -> Option<usize> {
    if records.len() <= MAX_PAIRINGS {
        return None;
    }
    let index = evictable(records, live)?;
    records.remove(index);
    Some(index)
}

/// The index of the first record that may be dropped: not the live one, in recency order.
fn evictable(records: &[StoredPsk], live: Option<&str>) -> Option<usize> {
    records
        .iter()
        .position(|record| Some(record.server_id.as_str()) != live)
}

#[cfg(feature = "storage-file")]
mod file {
    use std::collections::HashSet;
    use std::fmt;
    use std::fs::{self, File, OpenOptions};
    use std::io::{ErrorKind, Write};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    use anyhow::{anyhow, bail, Result};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use serde::{Deserialize, Serialize};

    use crate::config::{PskCategory, StoredPsk};

    use super::{evict, Storage};

    /// Version this build writes and the only one it reads.
    const FORMAT_VERSION: u32 = 1;

    /// Counts the temporary names a writer tries, so a leftover file from a crashed run is skipped.
    const TEMPORARY_ATTEMPTS: u32 = 64;

    /// A pairing store in one JSON file, behind the `storage-file` feature.
    ///
    /// Creating it creates the file if it is absent and checks one that exists: a file that is not
    /// this backend's format, including one with a version this build does not know, is refused
    /// with an error and never rewritten. Every write goes to a temporary file in the same
    /// directory and is renamed over the store, so an interrupted write leaves the previous store
    /// intact. On Unix the file is created with mode `0600`.
    ///
    /// The backend holds no records in memory: every call reads the file, and writes hold a lock so
    /// two callers in one process cannot lose each other's record. One process owns the file; a
    /// second process writing the same path at the same time is not coordinated, which matches the
    /// client's one-connection design.
    pub struct FileStorage {
        path: PathBuf,
        lock: Mutex<()>,
    }

    impl fmt::Debug for FileStorage {
        /// Names the file, never its contents.
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FileStorage")
                .field("path", &self.path)
                .finish_non_exhaustive()
        }
    }

    impl FileStorage {
        /// Opens the store at `path`, creating it when it does not exist.
        ///
        /// The parent directory must exist; this backend creates a file, never a directory. An
        /// existing file must be a store of the shape this build writes, or the call returns an
        /// error and the file is left untouched.
        pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
            let path = path.into();
            if path.file_name().is_none() {
                bail!(
                    "{} is not a file path a pairing store can use",
                    path.display()
                );
            }
            let storage = Self {
                path,
                lock: Mutex::new(()),
            };

            {
                let _guard = storage.guard()?;
                if storage.read()?.is_none() {
                    storage.write(&Shape::empty())?;
                }
            }
            Ok(storage)
        }

        /// The file this backend owns.
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Serializes this process's writers, so a read-modify-write cannot lose a record.
        fn guard(&self) -> Result<MutexGuard<'_, ()>> {
            self.lock.lock().map_err(|_| {
                anyhow!(
                    "the pairing store {} was left poisoned by a panicking writer",
                    self.path.display()
                )
            })
        }

        /// Reads and checks the store; `None` means the file does not exist yet.
        fn read(&self) -> Result<Option<Shape>> {
            let text = match fs::read_to_string(&self.path) {
                Ok(text) => text,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                Err(error) => bail!(
                    "cannot read the pairing store {}: {error}",
                    self.path.display()
                ),
            };
            let shape =
                Shape::parse(&text).map_err(|error| anyhow!("{}: {error}", self.path.display()))?;
            Ok(Some(shape))
        }

        /// Reads the store, treating an absent file as an empty one.
        fn read_or_empty(&self) -> Result<Shape> {
            Ok(self.read()?.unwrap_or_else(Shape::empty))
        }

        /// Replaces the store with `shape` atomically: a temporary file, then a rename.
        fn write(&self, shape: &Shape) -> Result<()> {
            let text = serde_json::to_vec_pretty(shape)
                .map_err(|error| anyhow!("cannot encode the pairing store: {error}"))?;

            let (temporary, mut file) = self.temporary_file()?;
            let written = file.write_all(&text).and_then(|()| file.sync_all());
            drop(file);
            if let Err(error) = written {
                let _ = fs::remove_file(&temporary);
                bail!(
                    "cannot write the pairing store {}: {error}",
                    self.path.display()
                );
            }
            if let Err(error) = fs::rename(&temporary, &self.path) {
                let _ = fs::remove_file(&temporary);
                bail!(
                    "cannot replace the pairing store {}: {error}",
                    self.path.display()
                );
            }
            Ok(())
        }

        /// Creates the temporary file beside the store, private to its owner on Unix.
        ///
        /// The file sits in the same directory because a rename is only atomic within one
        /// filesystem.
        fn temporary_file(&self) -> Result<(PathBuf, File)> {
            let directory = match self.path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            let name = self
                .path
                .file_name()
                .ok_or_else(|| anyhow!("{} has no file name", self.path.display()))?;
            let name = name.to_string_lossy();

            for attempt in 0..TEMPORARY_ATTEMPTS {
                let candidate =
                    directory.join(format!(".{name}.{}.{attempt}.tmp", std::process::id()));
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                match options.open(&candidate) {
                    Ok(file) => return Ok((candidate, file)),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                    Err(error) => bail!(
                        "cannot create a temporary file beside {}: {error}",
                        self.path.display()
                    ),
                }
            }
            bail!(
                "cannot create a temporary file beside {} after {TEMPORARY_ATTEMPTS} attempts",
                self.path.display()
            )
        }
    }

    impl Storage for FileStorage {
        fn pairing_psk(&self) -> Result<Option<[u8; 32]>> {
            let _guard = self.guard()?;
            let shape = self.read_or_empty()?;
            shape.pairing_psk.as_deref().map(decode_key).transpose()
        }

        fn store_pairing_psk(&self, psk: &[u8; 32]) -> Result<()> {
            let _guard = self.guard()?;
            let mut shape = self.read_or_empty()?;
            shape.pairing_psk = Some(encode_key(psk));
            self.write(&shape)
        }

        fn load_pairings(&self) -> Result<Vec<StoredPsk>> {
            let _guard = self.guard()?;
            let shape = self.read_or_empty()?;
            shape.pairings.iter().map(decode_record).collect()
        }

        fn store_pairing(&self, record: StoredPsk) -> Result<()> {
            if record.server_id.is_empty() {
                bail!("a pairing record must name a server");
            }
            let _guard = self.guard()?;
            let mut shape = self.read_or_empty()?;

            let mut records: Vec<StoredPsk> = shape
                .pairings
                .iter()
                .map(decode_record)
                .collect::<Result<_>>()?;
            let server_id = record.server_id.clone();
            records.retain(|held| held.server_id != server_id);
            records.push(record);
            // A safety net for a caller that uses the primitive directly: this backend cannot know
            // which connection is live, so it drops the oldest record rather than pretend to pin
            // one. `persist_pairing` makes the room before calling this and is what protects the
            // live record; here the drop only keeps a direct caller from growing the file without
            // bound.
            while evict(&mut records, None).is_some() {}

            shape.pairings = records.iter().map(encode_record).collect();
            self.write(&shape)
        }

        fn remove_pairing(&self, server_id: &str) -> Result<()> {
            let _guard = self.guard()?;
            let mut shape = self.read_or_empty()?;
            let held = shape.pairings.len();
            shape
                .pairings
                .retain(|record| record.server_id != server_id);
            if shape.pairings.len() == held {
                return Ok(());
            }
            self.write(&shape)
        }
    }

    /// The file's shape, exactly as this backend writes it.
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Shape {
        version: u32,
        pairing_psk: Option<String>,
        pairings: Vec<ShapeRecord>,
    }

    /// One record in the file. The key is base64url without padding.
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct ShapeRecord {
        category: String,
        psk: String,
        server_id: String,
    }

    impl Shape {
        /// An empty store in the shape this build writes.
        fn empty() -> Self {
            Self {
                version: FORMAT_VERSION,
                pairing_psk: None,
                pairings: Vec::new(),
            }
        }

        /// Checks that `text` is a store this build knows, without echoing its contents.
        ///
        /// The error names the reason and, for malformed JSON, the line and column: never a value,
        /// because a record's value is a key.
        fn parse(text: &str) -> Result<Self> {
            let shape: Shape = serde_json::from_str(text).map_err(|error| {
                anyhow!(
                    "it is not the JSON this backend writes (line {}, column {})",
                    error.line(),
                    error.column()
                )
            })?;
            if shape.version != FORMAT_VERSION {
                bail!(
                    "it announces format version {}, this build writes version {FORMAT_VERSION}",
                    shape.version
                );
            }
            if let Some(encoded) = shape.pairing_psk.as_deref() {
                decode_key(encoded)?;
            }
            let mut seen = HashSet::with_capacity(shape.pairings.len());
            for record in &shape.pairings {
                let decoded = decode_record(record)?;
                if !seen.insert(decoded.server_id) {
                    bail!("it holds more than one record for the same server");
                }
            }
            Ok(shape)
        }
    }

    /// Encodes a 32-byte key the way the file spells it.
    fn encode_key(key: &[u8; 32]) -> String {
        URL_SAFE_NO_PAD.encode(key)
    }

    /// Decodes a 32-byte key from the file. The error never repeats the encoded value.
    fn decode_key(encoded: &str) -> Result<[u8; 32]> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow!("a stored key is not base64url"))?;
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| anyhow!("a stored key is not 32 bytes"))
    }

    /// Turns a record in the file into the record the client uses.
    fn decode_record(record: &ShapeRecord) -> Result<StoredPsk> {
        if record.server_id.is_empty() {
            bail!("a record has an empty server id");
        }
        let category = PskCategory::from_wire(&record.category)
            .ok_or_else(|| anyhow!("a record names an unknown key category"))?;
        Ok(StoredPsk {
            category,
            psk: decode_key(&record.psk)?,
            server_id: record.server_id.clone(),
        })
    }

    /// Turns a record the client uses into the shape the file holds.
    fn encode_record(record: &StoredPsk) -> ShapeRecord {
        ShapeRecord {
            category: record.category.as_wire().to_owned(),
            psk: encode_key(&record.psk),
            server_id: record.server_id.clone(),
        }
    }
}

#[cfg(feature = "storage-file")]
pub use file::FileStorage;
