//! Creating and opening an encrypted database file.
use super::backend::BlockBackend;
use super::error::{Result, StoreDiagnostic, StoreError};
use super::file_header;
use super::layout::{DATA_BASE, FILE_HEADER_LEN, Geometry};
use crate::crypto::{
    Access, Aead, CipherKind, DataKey, Key32, KeySuite, LockedDataKey, OpenDiagnostic, PasswordKdf,
    ProgrammerKey, Scope, SecretBytes,
};
use redb::backends::FileBackend;
use redb::{Builder, Database, DatabaseError, ReadableDatabase, StorageBackend, StorageError};
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// What the programmer holds. Creating needs both keys; opening needs the read key (the search
/// key is checked too when given).
pub struct Credentials<'a> {
    pub suite: KeySuite,
    pub read: Option<&'a ProgrammerKey<'a>>,
    pub search: Option<&'a ProgrammerKey<'a>>,
}

#[derive(Debug, Clone, Default)]
pub struct OpenOptionsExt {
    /// redb's page cache, in bytes. `None` keeps redb's default.
    pub cache_bytes: Option<usize>,
    /// Read and check every block right after opening, so a block put back from an older copy
    /// is found before any data is used.
    pub verify_on_open: bool,
    /// Inspect only: nothing is written to the file, not even the marks redb leaves at open.
    /// A file that needs repair cannot be opened this way.
    pub read_only: bool,
    /// Set to `true` when redb had to rebuild the file's allocator (a repair after an unclean
    /// close), so the caller can report it.
    pub repair_seen: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Speed settings of the file layer (parallel sealing).
    pub tuning: super::tuning::EncryptionTuning,
}

/// The ciphers a whole database accepts: both are safe with a random nonce on every write for any
/// number of writes. The 96-bit-nonce kinds are not allowed here.
pub fn cipher_allowed(kind: CipherKind) -> bool {
    matches!(kind, CipherKind::Aes256GcmSiv | CipherKind::XChaCha20Poly1305)
}

fn check_suite(suite: &KeySuite) -> Result<()> {
    if cipher_allowed(suite.cipher) {
        Ok(())
    } else {
        Err(StoreError::InvalidParams("this cipher is not allowed for a whole database"))
    }
}

struct Material {
    suite: KeySuite,
    locked: LockedDataKey,
    access: Access,
}

impl Material {
    fn file_aead(&self, label: &str) -> Result<Aead> {
        let read = self.access.read().ok_or(StoreError::OpenFailed)?;
        let scope = Scope { table: "file", field: label };
        let key: Key32 = read.encryption_key(self.suite.hkdf, &scope).map_err(|_| StoreError::OpenFailed)?;
        Aead::new(self.suite.cipher, &key).map_err(|_| StoreError::OpenFailed)
    }
}

/// The unlocked data key of one database and the settings it was unlocked with: enough to create
/// and open every file that belongs to it (the main file, its backup, its index) one at a time.
/// Cheap to clone; the keys are wiped when the last clone is dropped.
#[derive(Clone)]
pub struct EncryptionContext {
    material: Arc<Material>,
}

impl std::fmt::Debug for EncryptionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptionContext")
    }
}

impl EncryptionContext {
    pub fn suite(&self) -> KeySuite {
        self.material.suite
    }

    pub fn access(&self) -> &Access {
        &self.material.access
    }

    /// The data key as it is stored in the file header, still locked under the programmer's keys.
    /// Read-only: it opens nothing by itself.
    pub fn locked_data_key(&self) -> &LockedDataKey {
        &self.material.locked
    }

    /// A new encrypted file at `path` (which must not exist) under this data key.
    pub fn create_file(&self, path: &Path, label: &str, options: &OpenOptionsExt) -> Result<EncryptedDatabase> {
        if path.exists() {
            return Err(StoreError::InvalidParams("a file already exists at this path"));
        }
        create_file(path, &self.material, label, options.cache_bytes)?;
        open_with_material(path, self.material.clone(), label, options, &mut |_| {})
    }

    /// An existing file of this database. A file made under another data key is refused.
    pub fn open_file(
        &self,
        path: &Path,
        label: &str,
        options: &OpenOptionsExt,
        sink: &mut dyn FnMut(StoreDiagnostic),
    ) -> Result<EncryptedDatabase> {
        let bytes = match read_header_bytes(path) {
            Ok(b) => b,
            Err(StoreError::OpenFailed) => {
                sink(StoreDiagnostic::HeaderMalformed);
                return Err(StoreError::OpenFailed);
            }
            Err(e) => return Err(e),
        };
        match file_header::decode(&self.material.suite, &bytes) {
            Ok(locked) if locked == self.material.locked => {}
            Ok(_) => {
                sink(StoreDiagnostic::LockRejected);
                return Err(StoreError::OpenFailed);
            }
            Err(why) => {
                sink(why);
                return Err(StoreError::OpenFailed);
            }
        }
        open_with_material(path, self.material.clone(), label, options, sink)
    }
}

/// An open encrypted database file.
pub struct EncryptedDatabase {
    db: Database,
    material: Arc<Material>,
    label: String,
}

impl std::fmt::Debug for EncryptedDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedDatabase").field("label", &self.label).finish_non_exhaustive()
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".creating");
    path.with_file_name(name)
}

fn map_open_error(e: DatabaseError, sink: &mut dyn FnMut(StoreDiagnostic)) -> StoreError {
    match e {
        DatabaseError::DatabaseAlreadyOpen => StoreError::InUse,
        // the read-only layer refused redb's repair write
        DatabaseError::Storage(StorageError::Io(io))
            if io.kind() == std::io::ErrorKind::PermissionDenied && io.raw_os_error().is_none() =>
        {
            StoreError::NeedsRepair
        }
        // Only a real operating system failure is passed on; an I/O error made up inside redb about
        // the content ("not a database") is a failure to open like any other.
        DatabaseError::Storage(StorageError::Io(io)) if io.raw_os_error().is_some() => StoreError::Io(io),
        _ => {
            sink(StoreDiagnostic::DatabaseUnreadable);
            StoreError::OpenFailed
        }
    }
}

/// Start a database over `inner`, whose first 2048 bytes already hold a file header. For a file
/// that exists (`existing`), a file cut down to its headers is refused rather than started afresh.
pub fn open_database_over<B: StorageBackend>(
    inner: B,
    aead: Aead,
    cache_bytes: Option<usize>,
    existing: bool,
) -> std::result::Result<Database, DatabaseError> {
    open_database_over_mode(inner, aead, cache_bytes, existing, false, None)
}

/// [`open_database_over`] with the option of leaving the file untouched (`read_only`).
pub fn open_database_over_mode<B: StorageBackend>(
    inner: B,
    aead: Aead,
    cache_bytes: Option<usize>,
    existing: bool,
    read_only: bool,
    repair_seen: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> std::result::Result<Database, DatabaseError> {
    open_database_over_tuned(inner, aead, cache_bytes, existing, read_only, repair_seen, super::tuning::EncryptionTuning::DEFAULT)
}

/// [`open_database_over_mode`] with speed settings for the file layer.
pub fn open_database_over_tuned<B: StorageBackend>(
    inner: B,
    aead: Aead,
    cache_bytes: Option<usize>,
    existing: bool,
    read_only: bool,
    repair_seen: Option<Arc<std::sync::atomic::AtomicBool>>,
    tuning: super::tuning::EncryptionTuning,
) -> std::result::Result<Database, DatabaseError> {
    if existing {
        let geo = Geometry { overhead: aead.kind().overhead() };
        let physical = inner.len().map_err(StorageError::from)?;
        if physical < DATA_BASE + geo.stride() as u64 {
            return Err(StorageError::Corrupted("the file is cut short".to_string()).into());
        }
    }
    let backend = BlockBackend::with_tuning(inner, aead, read_only, tuning).map_err(StorageError::from)?;
    let mut builder = Builder::new();
    if let Some(bytes) = cache_bytes {
        builder.set_cache_size(bytes);
    }
    if let Some(flag) = repair_seen {
        builder.set_repair_callback(move |_| flag.store(true, std::sync::atomic::Ordering::Relaxed));
    }
    builder.create_with_backend(backend)
}

/// Write the file header (locked data key plus random filler) at the start of `inner`.
pub fn write_file_header<B: StorageBackend>(
    inner: &B,
    suite: &KeySuite,
    locked: &LockedDataKey,
) -> std::io::Result<()> {
    let bytes = file_header::encode(suite, locked)?;
    inner.set_len(FILE_HEADER_LEN)?;
    inner.write(0, &bytes)
}

fn create_file(path: &Path, material: &Material, label: &str, cache_bytes: Option<usize>) -> Result<()> {
    let tmp = temp_path(path);
    let _ = std::fs::remove_file(&tmp);
    let file = OpenOptions::new().read(true).write(true).create_new(true).open(&tmp).map_err(StoreError::Io)?;
    let result = (|| -> Result<()> {
        let inner = FileBackend::new(file).map_err(|_| StoreError::OpenFailed)?;
        write_file_header(&inner, &material.suite, &material.locked).map_err(StoreError::Io)?;
        let aead = material.file_aead(label)?;
        #[cfg(test)]
        super::backend::set_next_tag(label);
        let db = open_database_over(inner, aead, cache_bytes, false).map_err(|e| map_open_error(e, &mut |_| {}))?;
        let mut w = db.begin_write().map_err(|_| StoreError::OpenFailed)?;
        w.set_quick_repair(true);
        w.commit().map_err(|_| StoreError::OpenFailed)?;
        drop(db);
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    let synced = OpenOptions::new().write(true).open(&tmp).and_then(|f| f.sync_all());
    if let Err(e) = synced {
        let _ = std::fs::remove_file(&tmp);
        return Err(StoreError::Io(e));
    }
    place_new_file(&tmp, path)
}

/// Move the finished temporary file to its real name without ever replacing a file that is there:
/// a plain rename would overwrite one that appeared since the check at the start. A hard link
/// fails if the name is taken; where hard links are not available, the check is made again
/// right before the rename.
///
/// Known limit: on a file system without hard links (FAT, exFAT, some network shares) the check
/// and the rename are two steps, so a file created by another process between them is replaced.
fn place_new_file(tmp: &Path, path: &Path) -> Result<()> {
    place_new_file_with(tmp, path, |from, to| std::fs::hard_link(from, to))
}

fn place_new_file_with(
    tmp: &Path,
    path: &Path,
    link: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<()> {
    match link(tmp, path) {
        Ok(()) => {
            let _ = std::fs::remove_file(tmp);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(tmp);
            Err(StoreError::InvalidParams("a file already exists at this path"))
        }
        Err(_) => {
            if path.exists() {
                let _ = std::fs::remove_file(tmp);
                return Err(StoreError::InvalidParams("a file already exists at this path"));
            }
            std::fs::rename(tmp, path).map_err(|e| {
                let _ = std::fs::remove_file(tmp);
                StoreError::Io(e)
            })
        }
    }
}

#[cfg(test)]
mod place_tests {
    use super::*;

    #[test]
    fn a_finished_file_never_replaces_one_that_is_already_there() {
        let dir = std::env::temp_dir().join(format!("place-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (tmp, real) = (dir.join("a.creating"), dir.join("a"));
        std::fs::write(&tmp, b"new").unwrap();
        std::fs::write(&real, b"old").unwrap();
        assert!(matches!(place_new_file(&tmp, &real), Err(StoreError::InvalidParams(_))));
        assert_eq!(std::fs::read(&real).unwrap(), b"old", "the existing file was replaced");
        assert!(!tmp.exists(), "the temporary file was left");
        std::fs::write(&tmp, b"new").unwrap();
        std::fs::remove_file(&real).unwrap();
        place_new_file(&tmp, &real).unwrap();
        assert_eq!(std::fs::read(&real).unwrap(), b"new");
        assert!(!tmp.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn without_hard_links_the_file_is_still_placed_and_still_never_replaces() {
        let dir = std::env::temp_dir().join(format!("place-nolink-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (tmp, real) = (dir.join("b.creating"), dir.join("b"));
        let unsupported = |_: &Path, _: &Path| Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
        // free name: placed by rename
        std::fs::write(&tmp, b"new").unwrap();
        place_new_file_with(&tmp, &real, unsupported).unwrap();
        assert_eq!(std::fs::read(&real).unwrap(), b"new");
        assert!(!tmp.exists());
        // taken name: refused, the old file stays, the temporary file is removed
        std::fs::write(&tmp, b"newer").unwrap();
        assert!(matches!(place_new_file_with(&tmp, &real, unsupported), Err(StoreError::InvalidParams(_))));
        assert_eq!(std::fs::read(&real).unwrap(), b"new", "the existing file was replaced");
        assert!(!tmp.exists(), "the temporary file was left");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn read_header_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path).map_err(StoreError::Io)?;
    let mut bytes = vec![0u8; FILE_HEADER_LEN as usize];
    file.read_exact(&mut bytes).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => StoreError::OpenFailed,
        // Windows refuses a read of a region another handle has locked: the file is in use.
        _ if matches!(e.raw_os_error(), Some(32) | Some(33)) => StoreError::InUse,
        _ => StoreError::Io(e),
    })?;
    Ok(bytes)
}

fn open_with_material(
    path: &Path,
    material: Arc<Material>,
    label: &str,
    options: &OpenOptionsExt,
    sink: &mut dyn FnMut(StoreDiagnostic),
) -> Result<EncryptedDatabase> {
    let file = OpenOptions::new().read(true).write(true).open(path).map_err(StoreError::Io)?;
    let inner = FileBackend::new(file).map_err(|e| map_open_error(e, sink))?;
    let aead = material.file_aead(label)?;
    #[cfg(test)]
    super::backend::set_next_tag(label);
    let mut db = open_database_over_tuned(inner, aead, options.cache_bytes, true, options.read_only, options.repair_seen.clone(), options.tuning)
        .map_err(|e| map_open_error(e, sink))?;
    if options.verify_on_open && !matches!(db.check_integrity(), Ok(true)) {
        sink(StoreDiagnostic::DatabaseUnreadable);
        return Err(StoreError::OpenFailed);
    }
    Ok(EncryptedDatabase { db, material, label: label.to_string() })
}

impl EncryptedDatabase {
    /// Make a new encrypted database at `path`, which must not exist. The data key is generated
    /// here and stored in the header locked by the two programmer keys. The file is built under a
    /// temporary name and renamed once it holds a first commit, so a crash while creating leaves
    /// no half-made database at `path`.
    pub fn create(
        path: &Path,
        credentials: &Credentials,
        label: &str,
        options: &OpenOptionsExt,
    ) -> Result<Self> {
        check_suite(&credentials.suite)?;
        let (Some(read), Some(search)) = (credentials.read, credentials.search) else {
            return Err(StoreError::InvalidParams("creating needs both the read and the search key"));
        };
        if path.exists() {
            return Err(StoreError::InvalidParams("a file already exists at this path"));
        }
        let data_key = DataKey::generate().map_err(|_| StoreError::OpenFailed)?;
        let locked = data_key.lock(&credentials.suite, read, search).map_err(|e| match e {
            crate::crypto::CryptoError::InvalidParams(why) => StoreError::InvalidParams(why),
            _ => StoreError::OpenFailed,
        })?;
        let access = locked
            .unlock(&credentials.suite, Some(read), Some(search))
            .map_err(|_| StoreError::OpenFailed)?;
        let material = Arc::new(Material { suite: credentials.suite, locked, access });
        create_file(path, &material, label, options.cache_bytes)?;
        open_with_material(path, material, label, options, &mut |_| {})
    }

    /// Open an existing encrypted database. Every failure on the key side is
    /// [`StoreError::OpenFailed`]; `sink` gets the cause, which holds nothing secret.
    pub fn open(
        path: &Path,
        credentials: &Credentials,
        label: &str,
        options: &OpenOptionsExt,
        sink: &mut dyn FnMut(StoreDiagnostic),
    ) -> Result<Self> {
        check_suite(&credentials.suite)?;
        let fail = |sink: &mut dyn FnMut(StoreDiagnostic), why| {
            sink(why);
            StoreError::OpenFailed
        };
        let bytes = match read_header_bytes(path) {
            Ok(b) => b,
            Err(StoreError::OpenFailed) => return Err(fail(sink, StoreDiagnostic::HeaderMalformed)),
            Err(e) => return Err(e),
        };
        let locked = file_header::decode(&credentials.suite, &bytes).map_err(|why| fail(sink, why))?;
        let access = locked
            .unlock_reporting(&credentials.suite, credentials.read, credentials.search, &mut |why| {
                sink(match why {
                    OpenDiagnostic::KeyMissing => StoreDiagnostic::KeyMissing,
                    OpenDiagnostic::MalformedInput => StoreDiagnostic::HeaderMalformed,
                    _ => StoreDiagnostic::LockRejected,
                })
            })
            .map_err(|_| StoreError::OpenFailed)?;
        if access.read().is_none() {
            return Err(fail(sink, StoreDiagnostic::KeyMissing));
        }
        let material = Arc::new(Material { suite: credentials.suite, locked, access });
        open_with_material(path, material, label, options, sink)
    }

    /// A new encrypted file for the same data key (an index file, a backup), with its own file key.
    pub fn create_sibling(&self, path: &Path, label: &str, options: &OpenOptionsExt) -> Result<Self> {
        self.context().create_file(path, label, options)
    }

    /// Open a file made by [`EncryptedDatabase::create_sibling`] (or the same data key's database).
    pub fn open_sibling(
        &self,
        path: &Path,
        label: &str,
        options: &OpenOptionsExt,
        sink: &mut dyn FnMut(StoreDiagnostic),
    ) -> Result<Self> {
        self.context().open_file(path, label, options, sink)
    }

    /// What is needed to create and open the other files of this database, without keeping this
    /// one open.
    pub fn context(&self) -> EncryptionContext {
        EncryptionContext { material: self.material.clone() }
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    pub fn into_database(self) -> Database {
        self.db
    }

    /// A write transaction that commits in two phases (each commit's data is on disk before the
    /// commit becomes the live one) and saves the allocator, which is what keeps a torn write at
    /// power loss harmless for this file layer.
    pub fn begin_write(&self) -> std::result::Result<redb::WriteTransaction, redb::TransactionError> {
        let mut w = self.db.begin_write()?;
        w.set_quick_repair(true);
        Ok(w)
    }

    pub fn begin_read(&self) -> std::result::Result<redb::ReadTransaction, redb::TransactionError> {
        self.db.begin_read()
    }

    pub fn locked_data_key(&self) -> &LockedDataKey {
        &self.material.locked
    }

    pub fn access(&self) -> &Access {
        &self.material.access
    }

    pub fn suite(&self) -> KeySuite {
        self.material.suite
    }

    /// Read and check every live block. A block put back from an older copy of the same file has
    /// a valid seal, so only this walk (redb's checksums over the whole tree) finds it.
    pub fn verify_all(&mut self) -> Result<()> {
        match self.db.check_integrity() {
            Ok(true) => Ok(()),
            Ok(false) => Err(StoreError::Tampered),
            Err(DatabaseError::Storage(StorageError::Io(e))) if e.raw_os_error().is_some() => Err(StoreError::Io(e)),
            Err(_) => Err(StoreError::Tampered),
        }
    }
}

/// Test builds only (`--cfg clove_test_encrypt_all`): the fixed settings every `DatabaseConfig` starts with.
#[cfg(clove_test_encrypt_all)]
pub(crate) fn test_encrypt_all_config() -> EncryptionConfig {
    // the default suite, so the matrix runs on what people use; the tests about the other cipher pick it by hand
    let config = EncryptionConfig::new(KeySource::Raw(Key32::from_bytes(&[0xA5; 32])), KeySource::Raw(Key32::from_bytes(&[0x5A; 32])));
    // `CLOVE_TEST_CIPHER=xchacha` runs the whole suite on the other allowed cipher
    if std::env::var("CLOVE_TEST_CIPHER").ok().as_deref() == Some("xchacha") {
        return config.with_suite(KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: crate::crypto::HkdfHash::Sha256 });
    }
    config
}

/// Check a database's files while they are closed: the main file, then the `.cldb.bak` and the
/// `.inx` when they sit in the same folder (`dir_path/dir_name/{db_name}.cldb`, `.cldb.bak`,
/// `.inx`). For each file, every block it holds is opened and authenticated directly, whether or not
/// redb would ever read it (live pages, free space, the unused tail), and then the file is opened
/// read-only with `verify_on_open`, so a block put back from an older copy of its own file is found
/// too. Returns `Ok`, or `DataTampered` (as [`StoreError::Tampered`]) when any block fails. The four
/// small header pieces are the one exception to "any change": the file layer tolerates one torn
/// copy of them by design (it keeps the newest valid one), so a change to a single piece is not an
/// error. A file that needs repair first, or that another program has open, is an error of its
/// own, never `Ok`.
///
/// Closed files only: an open `Storage` holds its files and Windows refuses a second reader, so
/// an open database relies on `encryption_verify_on_open` at its next open. A backup kept in a
/// separate `backup_dir_path` is not covered. A missing main file is an I/O error.
///
/// The panic guard needs `panic = "unwind"`: under `panic = "abort"` a panic from redb on an
/// authentic-but-old block stops the process instead of returning `DataTampered`.
pub fn verify_encrypted_files(
    dir_path: &Path,
    dir_name: &str,
    db_name: &str,
    encryption: &EncryptionHandle,
) -> Result<()> {
    let dir = dir_path.join(dir_name);
    let options = OpenOptionsExt { verify_on_open: true, read_only: true, ..OpenOptionsExt::default() };
    for (file, label, required) in [
        (format!("{db_name}.cldb"), "main", true),
        (format!("{db_name}.cldb.bak"), "bak", false),
        (format!("{db_name}.inx"), "index", false),
    ] {
        let path = dir.join(file);
        if !required && !path.is_file() {
            continue;
        }
        let mut cause = None;
        // redb can panic on content that is authentic but out of date; that is a stop, never wrong data
        let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            encryption.open_file(&path, label, false, &options, &mut |why| cause = Some(why))
        }));
        match opened {
            Ok(Ok(db)) => {
                drop(db);
                let context = encryption.context().ok_or(StoreError::OpenFailed)?;
                read_every_block(&path, context, label)?;
            }
            Ok(Err(StoreError::OpenFailed))
                if matches!(cause, Some(StoreDiagnostic::DatabaseUnreadable | StoreDiagnostic::HeaderMalformed)) =>
            {
                return Err(StoreError::Tampered);
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(StoreError::Tampered),
        }
    }
    Ok(())
}

/// Open and authenticate every block of one closed file, reading it through the file layer in
/// large steps. The cost is a sequential read and the cipher, which runs at memory speed.
fn read_every_block(path: &Path, context: &EncryptionContext, label: &str) -> Result<()> {
    let damaged = |e: std::io::Error| {
        if super::error::is_tamper(&e) || e.kind() == std::io::ErrorKind::InvalidData {
            StoreError::Tampered
        } else {
            StoreError::Io(e)
        }
    };
    let file = OpenOptions::new().read(true).open(path).map_err(StoreError::Io)?;
    let inner = FileBackend::new(file).map_err(|_| StoreError::OpenFailed)?;
    let aead = context.material.file_aead(label)?;
    let backend = BlockBackend::with_mode(inner, aead, true).map_err(damaged)?;
    let len = backend.len().map_err(damaged)?;
    let mut buf = vec![0u8; 256 * super::layout::PAGE];
    let mut pos = super::layout::LOGICAL_HEADER;
    while pos < len {
        let n = ((len - pos) as usize).min(buf.len());
        backend.read(pos, &mut buf[..n]).map_err(damaged)?;
        pos += n as u64;
    }
    Ok(())
}

// ---- owned settings, for a library that keeps its options around -------------------------------

/// A programmer key the library may keep: the raw key, or a password with its hashing settings.
pub enum KeySource {
    Raw(Key32),
    Password { password: SecretBytes, kdf: PasswordKdf },
}

impl KeySource {
    fn as_programmer(&self) -> ProgrammerKey<'_> {
        match self {
            KeySource::Raw(k) => ProgrammerKey::Raw(k),
            KeySource::Password { password, kdf } => ProgrammerKey::Password { password, kdf },
        }
    }
}

impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeySource([redacted])")
    }
}

/// The encryption choices of a database, as the programmer gives them. Holds secrets, so it has
/// no `Clone`; share it through [`EncryptionHandle`].
#[derive(Debug)]
pub struct EncryptionConfig {
    pub suite: KeySuite,
    pub read: Option<KeySource>,
    pub search: Option<KeySource>,
}

impl EncryptionConfig {
    /// The usual way to ask for whole-database encryption: the default suite (AES-256-GCM-SIV, HKDF-SHA-256) and both keys.
    /// A database is created with both keys; an existing one opens with the read key alone.
    pub fn new(read: KeySource, search: KeySource) -> Self {
        EncryptionConfig { suite: KeySuite::default(), read: Some(read), search: Some(search) }
    }

    /// The same keys with another suite, for example XChaCha20-Poly1305.
    pub fn with_suite(mut self, suite: KeySuite) -> Self {
        self.suite = suite;
        self
    }
}

/// What a library keeps in its options to open every file of one encrypted database. The first
/// file opened is the main one, which unlocks the data key; the others (backup, index) reuse it.
/// Cloning shares the same unlocked key.
#[derive(Clone, Debug)]
pub struct EncryptionHandle {
    config: Arc<EncryptionConfig>,
    context: Arc<std::sync::OnceLock<EncryptionContext>>,
    tuning: Option<super::tuning::EncryptionTuning>,
}

impl EncryptionHandle {
    pub fn new(config: EncryptionConfig) -> Self {
        EncryptionHandle { config: Arc::new(config), context: Arc::new(std::sync::OnceLock::new()), tuning: None }
    }

    /// The same handle with other speed settings for every file it opens from now on.
    pub fn with_tuning(mut self, tuning: super::tuning::EncryptionTuning) -> Self {
        self.tuning = Some(tuning);
        self
    }

    /// The settings set with [`EncryptionHandle::with_tuning`], or the defaults.
    pub fn tuning(&self) -> super::tuning::EncryptionTuning {
        self.tuning.unwrap_or_default()
    }

    pub fn suite(&self) -> KeySuite {
        self.config.suite
    }

    /// Check the shape of the settings alone, before any file is touched: the cipher must be one a
    /// whole database accepts, the read key is always needed, and a database that does not exist
    /// yet needs the search key as well (its data key is locked under both). The text says what is
    /// missing and holds no secret; failures that depend on the key and the file (a wrong key, an
    /// unencrypted file) are not found here but are the single open error.
    pub fn check_settings(&self, new_database: bool) -> std::result::Result<(), &'static str> {
        if !cipher_allowed(self.config.suite.cipher) {
            return Err("this cipher is not allowed for a whole database");
        }
        if self.config.read.is_none() {
            return Err("whole-database encryption needs a read key");
        }
        if new_database && self.config.search.is_none() {
            return Err("a new encrypted database needs both a read key and a search key");
        }
        Ok(())
    }

    /// The unlocked key, once the main file has been opened.
    pub fn context(&self) -> Option<&EncryptionContext> {
        self.context.get()
    }

    /// Open the file at `path` (role `label`: `"main"` first, later `"bak"`, `"index"`), creating
    /// it when it does not exist and `create` is set. A file that exists but is empty counts as
    /// not existing, as it does for an unencrypted database.
    pub fn open_file(
        &self,
        path: &Path,
        label: &str,
        create: bool,
        options: &OpenOptionsExt,
        sink: &mut dyn FnMut(StoreDiagnostic),
    ) -> Result<EncryptedDatabase> {
        let tuned;
        let options = match self.tuning {
            Some(tuning) => {
                tuned = OpenOptionsExt { tuning, ..options.clone() };
                &tuned
            }
            None => options,
        };
        let mut exists = path.exists();
        if exists && !path.is_dir() && std::fs::metadata(path).map(|m| m.len() == 0).unwrap_or(false) && create {
            std::fs::remove_file(path).map_err(StoreError::Io)?;
            exists = false;
        }
        if !exists && !create {
            return Err(StoreError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "no such database file")));
        }
        if let Some(ctx) = self.context.get() {
            return if exists { ctx.open_file(path, label, options, sink) } else { ctx.create_file(path, label, options) };
        }
        let read = self.config.read.as_ref().map(KeySource::as_programmer);
        let search = self.config.search.as_ref().map(KeySource::as_programmer);
        let credentials = Credentials { suite: self.config.suite, read: read.as_ref(), search: search.as_ref() };
        let db = if exists {
            EncryptedDatabase::open(path, &credentials, label, options, sink)?
        } else {
            EncryptedDatabase::create(path, &credentials, label, options)?
        };
        let _ = self.context.set(db.context());
        Ok(db)
    }
}
