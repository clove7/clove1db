//! One redb file: how it is opened, how it is written, and how it is closed.
//!
//! Three problems meet here:
//!
//! - **Memory.** redb caches pages up to 1 GiB *per file* unless told otherwise,
//!   so a full scan of a large table leaves about as much of it resident as it
//!   read. A 64 MiB cap bounds that at the same scan speed.
//!   [`RedbOptions::cache_bytes`] is that cap.
//! - **Repair.** A process killed after writing leaves every file needing a full
//!   repair on the next open — a walk of the whole file, whose time and peak
//!   memory grow with the file. [`RedbOptions::quick_repair`] makes each commit
//!   save the allocator state, so that open loads it instead, in milliseconds.
//! - **Closing.** redb closes a file cleanly only when its `Database` is dropped,
//!   and an application that keeps its storage in a `static` never drops it — so
//!   *every* run ended in a repair, even a clean Ctrl+C. [`DbHandle::close`]
//!   closes the file while clones of the handle are still alive.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};

use redb::{Builder, Database, Durability, StorageError, WriteTransaction, ReadableDatabase};

use crate::encrypted_store::{EncryptionHandle, OpenOptionsExt, StoreError};
use crate::events::{EventSink, LibraryEvent};

use crate::durability::DurabilityMode;
use crate::units::{ClError, Result};

/// How one database's redb files are opened and written.
///
/// Both default to redb's own behaviour, so a database that sets neither works
/// exactly as it did before these options existed.
#[derive(Debug, Clone, Default)]
pub struct RedbOptions {
    /// redb's page cache for each file, in bytes. `None` keeps redb's default
    /// of 1 GiB.
    ///
    /// Applies to the `.cldb` and to its `.cldb.bak` separately: each file has
    /// its own cache.
    pub cache_bytes: Option<usize>,

    /// Save the allocator state on every commit, so that reopening after a
    /// crash or a kill loads it instead of rebuilding it by walking the file.
    ///
    /// Costs every commit a little (0.94 → 2.02 ms measured) and saves the
    /// whole repair after an unclean exit. Only helps if *every* commit sets
    /// it — redb decides from the last one — which is why all writes go
    /// through [`DbRef::begin_write`].
    pub quick_repair: bool,

    /// Encrypt every file of the database. When set, each file goes through the encrypted file
    /// layer, whose commits always save the allocator state (two-phase), whatever
    /// [`RedbOptions::quick_repair`] says.
    pub encryption: Option<EncryptionHandle>,

    /// With [`RedbOptions::encryption`]: read and check every block of each file right after it
    /// is opened, so a block put back from an older copy is found before any data is used. Costs
    /// a full read of the file at every open.
    pub verify_on_open: bool,
}

/// Fail at once, with [`ClError::DatabaseInUse`], when another program holds a
/// lock on `path`.
///
/// redb waits for some of its own locks, so a file locked from outside can make
/// its open wait for as long as the other program keeps the lock. This takes a
/// whole-file lock on a separate handle without waiting, and releases it
/// before redb opens the file. `exclusive` is for opens that write; a read-only
/// open only needs the file free of writers. A file that does not exist yet is
/// not in use.
pub(crate) fn guard_open(path: &Path, exclusive: bool) -> Result<()> {
    let in_use = || ClError::DatabaseInUse { path: path.display().to_string() };
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        // ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION: another program
        // opened the file without sharing it.
        Err(e) if matches!(e.raw_os_error(), Some(32 | 33)) => return Err(in_use()),
        // Missing or unreadable: redb reports it with its own error.
        Err(_) => return Ok(()),
    };
    let taken = if exclusive { file.try_lock() } else { file.try_lock_shared() };
    match taken {
        Ok(()) => {
            let _ = file.unlock();
            Ok(())
        }
        Err(std::fs::TryLockError::WouldBlock) => Err(in_use()),
        // Locks the filesystem cannot take: leave it to redb.
        Err(std::fs::TryLockError::Error(_)) => Ok(()),
    }
}

/// Read `path` once, front to back, and drop what was read, so the operating system has it cached
/// before redb starts asking for its pages one by one. A file that is missing, locked or unreadable
/// is left alone: this only ever helps, and the open that follows reports any real problem.
pub(crate) fn prefetch_file(path: &Path) {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else { return };
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    while let Ok(n) = file.read(&mut buffer) {
        if n == 0 {
            break;
        }
        total += n as u64;
    }
    #[cfg(feature = "crash-inject")]
    PREFETCHED.lock().unwrap_or_else(PoisonError::into_inner).push((path.to_path_buf(), total));
    #[cfg(not(feature = "crash-inject"))]
    let _ = total;
}

#[cfg(feature = "crash-inject")]
static PREFETCHED: std::sync::Mutex<Vec<(PathBuf, u64)>> = std::sync::Mutex::new(Vec::new());

/// Test hook: how many bytes the prefetch has read from `path` so far in this process (0 when it never ran for it).
#[cfg(feature = "crash-inject")]
pub fn test_prefetched_bytes(path: &Path) -> u64 {
    PREFETCHED.lock().unwrap_or_else(PoisonError::into_inner).iter().filter(|(p, _)| p == path).map(|(_, n)| *n).sum()
}

/// A redb open error, with the "already open" case as [`ClError::DatabaseInUse`].
pub(crate) fn open_error(e: redb::DatabaseError, path: &Path) -> ClError {
    match e {
        redb::DatabaseError::DatabaseAlreadyOpen => ClError::DatabaseInUse { path: path.display().to_string() },
        redb::DatabaseError::Storage(StorageError::Io(io)) if crate::encrypted_store::is_tamper(&io) => ClError::DataTampered,
        e => ClError::Database(redb::Error::from(e)),
    }
}

impl RedbOptions {
    fn builder(&self) -> Builder {
        let mut builder = Database::builder();
        if let Some(bytes) = self.cache_bytes {
            builder.set_cache_size(bytes);
        }
        builder
    }

    /// Open an existing file.
    pub fn open(&self, path: &Path) -> Result<Database> {
        self.open_timed(path, false, "main").map(|(db, _)| db)
    }

    /// Open a file, creating it if it does not exist.
    pub fn create(&self, path: &Path) -> Result<Database> {
        self.open_timed(path, true, "main").map(|(db, _)| db)
    }

    /// The index file (`.inx`): its own small page cache, and the role `"index"` when encrypted.
    pub(crate) fn open_index_file(&self, path: &Path, create: bool, events: &EventSink) -> Result<Database> {
        const INDEX_CACHE_BYTES: usize = 2 * 1024 * 1024;
        if let Some(enc) = &self.encryption {
            return self.open_encrypted(enc, path, "index", create, false, Some(INDEX_CACHE_BYTES), events).map(|(db, _)| db);
        }
        let mut builder = Database::builder();
        builder.set_cache_size(INDEX_CACHE_BYTES);
        if create {
            builder.create(path).map_err(|e| ClError::Database(redb::Error::from(e)))
        } else {
            builder.open(path).map_err(|e| open_error(e, path))
        }
    }

    /// Open (or create) one file of an encrypted database; `read_only` leaves the file untouched.
    /// Returns the database and whether redb had to repair the file.
    fn open_encrypted(
        &self,
        enc: &EncryptionHandle,
        path: &Path,
        label: &str,
        create: bool,
        read_only: bool,
        cache_bytes: Option<usize>,
        events: &EventSink,
    ) -> Result<(Database, Arc<AtomicBool>)> {
        let repaired = Arc::new(AtomicBool::new(false));
        let options = OpenOptionsExt {
            cache_bytes,
            verify_on_open: self.verify_on_open,
            read_only,
            repair_seen: Some(repaired.clone()),
            ..OpenOptionsExt::default()
        };
        // The cause of a failed open goes to the event sink as a fixed name; the programmer
        // sees one error.
        let mut cause = None;
        let file = match label {
            "bak" => "bak",
            "index" => "index",
            _ => "main",
        };
        let opened = enc.open_file(path, label, create, &options, &mut |why| cause = Some(why));
        if let (Err(_), Some(why)) = (&opened, cause) {
            events.emit(&LibraryEvent::Encryption { event: why.event_name(), file });
        }
        let db = opened
            .map_err(|e| match e {
                StoreError::InUse => ClError::DatabaseInUse { path: path.display().to_string() },
                StoreError::NeedsRepair => ClError::Database(redb::Error::RepairAborted),
                e => ClError::from(e),
            })?
            .into_database();
        Ok((db, repaired))
    }

    /// Inspect without writing redb's allocator state or shutdown header.
    pub(crate) fn open_read_only_timed(
        &self,
        path: &Path,
        label: &str,
    ) -> (Result<DbOrRo>, FileOpen) {
        #[cfg(test)]
        opens::record(path);
        let start = Instant::now();
        let db = guard_open(path, false).and_then(|()| match &self.encryption {
            Some(enc) => self.open_encrypted(enc, path, label, false, true, self.cache_bytes, &EventSink::default()).map(|(db, _)| DbOrRo::Enc(db)),
            None => self
                .builder()
                .open_read_only(path)
                .map(DbOrRo::Plain)
                .map_err(|e| open_error(e, path)),
        });
        let open_time = start.elapsed();
        let opened = FileOpen {
            path: path.to_path_buf(),
            bytes: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            open_time,
            repaired: false,
            format_check: true,
        };
        (db, opened)
    }

    /// Open (or create) a file and say how the open went: how long it took,
    /// whether redb had to repair the file, and how large the file is.
    pub(crate) fn open_timed(&self, path: &Path, create: bool, label: &str) -> Result<(Database, FileOpen)> {
        self.open_timed_with_events(path, create, label, &EventSink::default())
    }

    /// [`RedbOptions::open_timed`] that reports why an encrypted open failed to `events`.
    pub(crate) fn open_timed_with_events(
        &self,
        path: &Path,
        create: bool,
        label: &str,
        events: &EventSink,
    ) -> Result<(Database, FileOpen)> {
        #[cfg(test)]
        opens::record(path);
        // redb calls this when it rebuilds the allocator state by walking the
        // whole file — a full repair. Loading a saved state (quick repair) or
        // opening a cleanly closed file never calls it. Initialising a new,
        // empty file goes through the same path, so a file that did not exist
        // before this open is never reported as repaired.
        let existed = path.is_file();
        let repaired = Arc::new(AtomicBool::new(false));
        let seen = repaired.clone();
        let mut builder = self.builder();
        builder.set_repair_callback(move |_| seen.store(true, Ordering::Relaxed));

        guard_open(path, true)?;
        let start = Instant::now();
        if let Some(enc) = &self.encryption {
            let (db, repaired) = self.open_encrypted(enc, path, label, create, false, self.cache_bytes, events)?;
            let open_time = start.elapsed();
            let bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            return Ok((
                db,
                FileOpen {
                    path: path.to_path_buf(),
                    bytes,
                    open_time,
                    repaired: existed && repaired.load(Ordering::Relaxed),
                    format_check: false,
                },
            ));
        }
        let opened = if create {
            builder.create(path)
        } else {
            builder.open(path)
        };
        let open_time = start.elapsed();
        let db = opened.map_err(|e| open_error(e, path))?;

        let bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        Ok((
            db,
            FileOpen {
                path: path.to_path_buf(),
                bytes,
                open_time,
                repaired: existed && repaired.load(Ordering::Relaxed),
                format_check: false,
            },
        ))
    }
}

/// A database opened only to look at it: the plain kind is redb's read-only database; the
/// encrypted kind is an ordinary database over a file layer that refuses every write.
pub(crate) enum DbOrRo {
    Plain(redb::ReadOnlyDatabase),
    Enc(Database),
}

impl ReadableDatabase for DbOrRo {
    fn begin_read(&self) -> std::result::Result<redb::ReadTransaction, redb::TransactionError> {
        match self {
            DbOrRo::Plain(db) => db.begin_read(),
            DbOrRo::Enc(db) => db.begin_read(),
        }
    }

    fn cache_stats(&self) -> redb::CacheStats {
        match self {
            DbOrRo::Plain(db) => db.cache_stats(),
            DbOrRo::Enc(db) => db.cache_stats(),
        }
    }
}

/// How one file's open went. Kept by its [`DbHandle`] and read through
/// `Storage::open_report`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileOpen {
    pub(crate) path: PathBuf,
    /// The file's size right after the open.
    pub(crate) bytes: u64,
    pub(crate) open_time: Duration,
    /// redb walked the whole file to rebuild its allocator state.
    pub(crate) repaired: bool,
    pub(crate) format_check: bool,
}

/// Every path opened through [`RedbOptions`], so a test can count the opens
/// one `Storage::build` costs a file.
#[cfg(test)]
pub(crate) mod opens {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static LOG: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    pub(crate) fn record(path: &Path) {
        LOG.lock().unwrap().push(path.to_path_buf());
    }

    pub(crate) fn count(path: &Path) -> usize {
        LOG.lock().unwrap().iter().filter(|p| p.as_path() == path).count()
    }
}

/// A redb file shared by every clone of the manager that owns it, and closable
/// while those clones are still alive.
///
/// Every operation holds a read guard for as long as it uses the file;
/// [`Self::close`] takes the write side, so it waits for the operations already
/// running and turns every later one into [`ClError::Closed`].
#[derive(Debug)]
pub struct DbHandle {
    slot: RwLock<Option<Database>>,
    path: PathBuf,
    durability: DurabilityMode,
    quick_repair: bool,
    opened: FileOpen,
}

impl DbHandle {
    /// Open an existing file; why an encrypted open failed goes to `events`.
    pub(crate) fn open_with_events(
        path: &Path,
        durability: DurabilityMode,
        options: RedbOptions,
        label: &str,
        events: &EventSink,
    ) -> Result<Self> {
        let (db, opened) = options.open_timed_with_events(path, false, label, events)?;
        Ok(Self::serve(db, opened, durability, options))
    }

    /// Open a file, creating it if it does not exist.
    pub(crate) fn create(path: &Path, durability: DurabilityMode, options: RedbOptions, label: &str) -> Result<Self> {
        Self::create_with_events(path, durability, options, label, &EventSink::default())
    }

    pub(crate) fn create_with_events(
        path: &Path,
        durability: DurabilityMode,
        options: RedbOptions,
        label: &str,
        events: &EventSink,
    ) -> Result<Self> {
        let (db, opened) = options.open_timed_with_events(path, true, label, events)?;
        Ok(Self::serve(db, opened, durability, options))
    }

    fn serve(db: Database, opened: FileOpen, durability: DurabilityMode, options: RedbOptions) -> Self {
        Self {
            slot: RwLock::new(Some(db)),
            path: opened.path.clone(),
            durability,
            // an encrypted file always commits in two phases and saves the allocator state
            quick_repair: options.quick_repair || options.encryption.is_some(),
            opened,
        }
    }

    /// How this file's open went.
    pub(crate) fn opened(&self) -> &FileOpen {
        &self.opened
    }

    /// The open file, or [`ClError::Closed`].
    ///
    /// Hold the returned guard only for one operation, and do not take a
    /// second one on the same handle while holding it: a waiting
    /// [`Self::close`] blocks new readers, so a nested read would wait on a
    /// close that is waiting on it.
    pub fn get(&self) -> Result<DbRef<'_>> {
        let guard = self.slot.read().unwrap_or_else(PoisonError::into_inner);
        if guard.is_none() {
            return Err(ClError::Closed {
                path: self.path.display().to_string(),
            });
        }
        Ok(DbRef {
            guard,
            durability: self.durability,
            quick_repair: self.quick_repair,
        })
    }

    /// Close the file. Returns `false` if it was already closed.
    ///
    /// Waits for operations already holding the file, then drops the
    /// `Database`: redb flushes, records the allocator state and releases the
    /// file lock, so the next open needs no repair.
    pub fn close(&self) -> bool {
        let mut slot = self.slot.write().unwrap_or_else(PoisonError::into_inner);
        slot.take().is_some()
    }

    pub fn is_closed(&self) -> bool {
        self.slot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A read-only handle to an open file. User writes go through `DatabaseManager`.
///
/// ```compile_fail
/// fn unlogged_write(db: &clove1db::repository::DatabaseManager) {
///     let _ = db.db().unwrap().begin_write();
/// }
/// ```
/// ```compile_fail
/// fn writable_coercion(db: &clove1db::repository::DatabaseManager) {
///     let _: &redb::Database = &db.db().unwrap();
/// }
/// ```
pub struct DbRef<'a> {
    guard: RwLockReadGuard<'a, Option<Database>>,
    durability: DurabilityMode,
    quick_repair: bool,
}

impl DbRef<'_> {
    /// A write transaction with this database's policy applied: `Immediate`
    /// durability in Strict mode, and quick repair when enabled.
    ///
    /// Shadows `Database::begin_write`, so `db.begin_write()` on a `DbRef`
    /// cannot skip the policy. A helper that takes `&Database` and writes
    /// *does* skip it — pass it the transaction instead.
    pub(crate) fn begin_write(&self) -> Result<WriteTransaction> {
        let mut txn = self.raw().begin_write()?;
        if self.durability.is_strict() {
            txn.set_durability(Durability::Immediate)?;
        }
        if self.quick_repair {
            txn.set_quick_repair(true);
        }
        Ok(txn)
    }
}

impl DbRef<'_> {
    /// A snapshot read. There is no coercion to a writable redb database.
    pub fn begin_read(&self) -> Result<redb::ReadTransaction> { Ok(self.raw().begin_read()?) }
    pub fn cache_stats(&self)->redb::CacheStats { self.raw().cache_stats() }
    pub(crate) fn raw(&self)->&Database {self.guard.as_ref().expect("DbRef holds an open database")}
}
