//! One redb file: how it is opened, how it is written, and how it is closed.
//!
//! Three problems meet here, and all three were measured on a production
//! server before this module existed:
//!
//! - **Memory.** redb caches pages up to 1 GiB *per file* unless told otherwise.
//!   A full scan of a 545 MB table left 528 MiB resident; with a 64 MiB cap it
//!   left 65 MiB, at the same speed. [`RedbOptions::cache_bytes`] is that cap.
//! - **Repair.** A process killed after writing leaves every file needing a full
//!   repair on the next open — a walk of the whole file, 612 ms and a 422 MiB
//!   peak for that 545 MB table. [`RedbOptions::quick_repair`] makes each commit
//!   save the allocator state, so the same open took 7 ms.
//! - **Closing.** redb closes a file cleanly only when its `Database` is dropped,
//!   and an application that keeps its storage in a `static` never drops it — so
//!   *every* run ended in a repair, even a clean Ctrl+C. [`DbHandle::close`]
//!   closes the file while clones of the handle are still alive.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock, RwLockReadGuard};

use redb::{Builder, Database, Durability, WriteTransaction};

use crate::durability::DurabilityMode;
use crate::units::{ClError, Result};

/// How one database's redb files are opened and written.
///
/// Both default to redb's own behaviour, so a database that sets neither works
/// exactly as it did before these options existed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
        #[cfg(test)]
        opens::record(path);
        self.builder()
            .open(path)
            .map_err(|e| ClError::Database(redb::Error::from(e)))
    }

    /// Open a file, creating it if it does not exist.
    pub fn create(&self, path: &Path) -> Result<Database> {
        #[cfg(test)]
        opens::record(path);
        self.builder()
            .create(path)
            .map_err(|e| ClError::Database(redb::Error::from(e)))
    }
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
}

impl DbHandle {
    pub(crate) fn new(
        db: Database,
        path: PathBuf,
        durability: DurabilityMode,
        options: RedbOptions,
    ) -> Self {
        Self {
            slot: RwLock::new(Some(db)),
            path,
            durability,
            quick_repair: options.quick_repair,
        }
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

/// The open file, held for one operation. Reads go through `Deref` to
/// [`Database`]; writes through [`Self::begin_write`].
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
    pub fn begin_write(&self) -> Result<WriteTransaction> {
        let mut txn = Deref::deref(self).begin_write()?;
        if self.durability.is_strict() {
            txn.set_durability(Durability::Immediate)?;
        }
        if self.quick_repair {
            txn.set_quick_repair(true);
        }
        Ok(txn)
    }
}

impl Deref for DbRef<'_> {
    type Target = Database;

    fn deref(&self) -> &Database {
        // `DbHandle::get` returns a `DbRef` only for a `Some` slot, and the
        // guard keeps `close` from emptying it.
        self.guard.as_ref().expect("DbRef holds an open database")
    }
}
