mod paths;

#[cfg(test)]
mod tests;

#[cfg(feature = "encryption")]
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
#[cfg(feature = "encryption")]
use std::io::BufReader;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
#[cfg(feature = "encryption")]
use std::sync::Arc;

pub use paths::{blob_path, blob_root, blob_table_dir};
#[cfg(feature = "encryption")]
pub(crate) use paths::protected_blob_root;

/// Alias used by runtime (`{db_name}.blobs` root directory).
pub fn blobs_root(db_dir: &Path, db_name: &str) -> PathBuf {
    blob_root(db_dir, db_name)
}

use crate::durability::DurabilityMode;
#[cfg(feature = "encryption")]
use crate::encrypted_store::{EncryptionContext, FileKeys, SealedBlobStore, SealedReader};
use crate::fsutil::write_atomic;
use crate::units::{ClError, Result};

/// An attachment opened for reading. It reads and seeks like a file, and says how long the
/// attachment is. In an encrypted database it decrypts as it reads, block by block, so a large
/// attachment is never loaded whole; a block that was changed is an error
/// ([`ClError::DataTampered`]) and never wrong bytes.
pub struct BlobReader {
    inner: ReaderKind,
}

enum ReaderKind {
    Plain(File),
    #[cfg(feature = "encryption")]
    Sealed(SealedReader<BufReader<File>>),
}

impl BlobReader {
    /// The length of the attachment's data in bytes.
    pub fn len(&self) -> io::Result<u64> {
        match &self.inner {
            ReaderKind::Plain(file) => Ok(file.metadata()?.len()),
            #[cfg(feature = "encryption")]
            ReaderKind::Sealed(reader) => Ok(reader.len()),
        }
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
}

impl std::fmt::Debug for BlobReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlobReader")
    }
}

impl Read for BlobReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            ReaderKind::Plain(file) => file.read(out),
            #[cfg(feature = "encryption")]
            ReaderKind::Sealed(reader) => reader.read(out),
        }
    }
}

impl Seek for BlobReader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        match &mut self.inner {
            ReaderKind::Plain(file) => file.seek(to),
            #[cfg(feature = "encryption")]
            ReaderKind::Sealed(reader) => reader.seek(to),
        }
    }
}

/// Read-only inspection of a database's blob sidecar directory.
/// Use DatabaseManager's journaled methods for mutation.
///
/// ```compile_fail
/// fn unlogged_put(store: &clove1db::blob::BlobStore) {
///     let _ = store.write_atomic("files", "a", b"bytes");
/// }
/// ```
/// ```compile_fail
/// fn unlogged_delete(store: &clove1db::blob::BlobStore) {
///     let _ = store.delete("files", "a");
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BlobStore {
    db_dir: PathBuf,
    db_name: String,
    /// In an encrypted database: the sealed store that holds the attachments under fingerprint
    /// names. `None` for a plain database, which works exactly as it always did.
    #[cfg(feature = "encryption")]
    sealed: Option<SealedBlobStore>,
    /// The attachments of tables with protected fields: always sealed with the keys of those
    /// fields, bound to the table, the place of the attachment and the row.
    #[cfg(feature = "encryption")]
    protected: Option<ProtectedBlobs>,
}

/// Field number of the attachment of a row, in the binding of its sealed file.
#[cfg(feature = "encryption")]
const ATTACHMENT_FIELD: u32 = 0;

/// The two names under which the sealed store keeps the attachment of one row of a table with
/// protected fields: its "table" (the identity and the place of the attachment) and its "id" (the
/// row and the file, joined so that two different pairs never give the same text). Everything that
/// writes these files (the store, and the migration that moves attachments in) uses this one
/// function, so a file is always written under the name it is later opened by.
#[cfg(feature = "encryption")]
pub(crate) fn protected_names(table_id: &str, row: &str, blob_id: &str) -> (String, String) {
    (format!("{table_id}/{ATTACHMENT_FIELD}"), format!("{}:{row}{blob_id}", row.len()))
}

#[cfg(feature = "encryption")]
#[derive(Debug, Clone)]
struct ProtectedBlobs {
    store: SealedBlobStore,
    /// Table name to table identity.
    ids: Arc<HashMap<String, String>>,
}

#[cfg(feature = "encryption")]
impl ProtectedBlobs {
    /// The sealed store's "table" for one table: its identity and the place of the attachment.
    fn place(&self, table: &str) -> Result<String> {
        self.ids
            .get(table)
            .map(|id| protected_names(id, "", "").0)
            .ok_or_else(|| ClError::Validation("the attachment table has no protected identity".into()))
    }

    /// The sealed store's "id" for one attachment: the row and the file, joined unambiguously.
    fn file(row: &str, blob: &str) -> String {
        protected_names("", row, blob).1
    }
}

#[cfg(feature = "encryption")]
fn io_error(e: io::Error) -> ClError {
    ClError::from(e)
}

#[cfg(feature = "encryption")]
fn row_bound() -> ClError {
    ClError::Validation(
        "the attachments of a table with protected fields are bound to their row; open them through the row".into(),
    )
}

impl BlobStore {
    pub fn new(db_dir: &Path, db_name: &str) -> Self {
        Self {
            db_dir: db_dir.to_path_buf(),
            db_name: db_name.to_string(),
            #[cfg(feature = "encryption")]
            sealed: None,
            #[cfg(feature = "encryption")]
            protected: None,
        }
    }

    /// The store of an encrypted database.
    #[cfg(feature = "encryption")]
    pub(crate) fn with_encryption(db_dir: &Path, db_name: &str, context: EncryptionContext) -> Self {
        Self {
            db_dir: db_dir.to_path_buf(),
            db_name: db_name.to_string(),
            sealed: Some(SealedBlobStore::new(&blob_root(db_dir, db_name), context)),
            protected: None,
        }
    }

    /// Seal the attachments of `tables` (name to identity) with the keys of their protected fields.
    #[cfg(feature = "encryption")]
    pub(crate) fn with_protected(mut self, keys: Arc<dyn FileKeys>, tables: Arc<HashMap<String, String>>) -> Self {
        let root = paths::protected_blob_root(&self.db_dir, &self.db_name);
        self.protected = Some(ProtectedBlobs { store: SealedBlobStore::with_keys(&root, keys), ids: tables });
        self
    }

    /// True when the attachments of `table` are bound to the rows of a table with protected fields.
    #[cfg(feature = "encryption")]
    pub(crate) fn is_protected(&self, table: &str) -> bool {
        self.protected.as_ref().is_some_and(|p| p.ids.contains_key(table))
    }

    /// Without the `encryption` feature no table has protected fields.
    #[cfg(not(feature = "encryption"))]
    pub(crate) fn is_protected(&self, _table: &str) -> bool {
        false
    }

    /// True when the attachments of `table` are sealed with keys this program cannot open them with
    /// (a program that holds only the search key): they are neither checked nor cleaned.
    #[cfg(feature = "encryption")]
    pub(crate) fn is_unreadable(&self, table: &str) -> bool {
        self.protected_of(table).is_some_and(|p| !p.store.can_open())
    }

    #[cfg(not(feature = "encryption"))]
    pub(crate) fn is_unreadable(&self, _table: &str) -> bool {
        false
    }

    /// True when there are attachments of protected tables and this program cannot open them.
    #[cfg(feature = "encryption")]
    pub(crate) fn protected_unreadable(&self) -> bool {
        self.protected.as_ref().is_some_and(|p| !p.store.can_open())
    }

    #[cfg(not(feature = "encryption"))]
    pub(crate) fn protected_unreadable(&self) -> bool {
        false
    }

    #[cfg(feature = "encryption")]
    fn protected_of(&self, table: &str) -> Option<&ProtectedBlobs> {
        self.protected.as_ref().filter(|p| p.ids.contains_key(table))
    }

    #[cfg(feature = "encryption")]
    pub(crate) fn is_sealed(&self) -> bool {
        self.sealed.is_some()
    }

    #[cfg(not(feature = "encryption"))]
    pub(crate) fn is_sealed(&self) -> bool {
        false
    }

    pub fn root(&self) -> PathBuf {
        blob_root(&self.db_dir, &self.db_name)
    }

    pub fn table_dir(&self, table: &str) -> PathBuf {
        #[cfg(feature = "encryption")]
        if let Some(s) = &self.sealed {
            return s.table_dir(table).unwrap_or_else(|_| self.root().join("unavailable"));
        }
        blob_table_dir(&self.db_dir, &self.db_name, table)
    }

    pub fn path(&self, table: &str, id: &str) -> PathBuf {
        #[cfg(feature = "encryption")]
        if let Some(s) = &self.sealed {
            return s.path(table, id).unwrap_or_else(|_| self.root().join("unavailable"));
        }
        blob_path(&self.db_dir, &self.db_name, table, id)
    }

    pub(crate) fn ensure_root(&self) -> Result<()> {
        fs::create_dir_all(self.root()).map_err(|e| ClError::IoError(e.to_string()))
    }

    pub(crate) fn ensure_table(&self, table: &str) -> Result<()> {
        #[cfg(feature = "encryption")]
        {
            if let Some(p) = self.protected_of(table) {
                fs::create_dir_all(p.store.root()).map_err(io_error)?;
                return p.store.ensure_table(&p.place(table)?).map_err(io_error);
            }
            if let Some(s) = &self.sealed {
                return s.ensure_table(table).map_err(io_error);
            }
        }
        fs::create_dir_all(self.table_dir(table)).map_err(|e| ClError::IoError(e.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn write_atomic(&self, table: &str, id: &str, data: &[u8]) -> Result<()> {
        self.write_atomic_with_mode(table, "", id, data, DurabilityMode::Strict)
    }

    /// `row` is the row the attachment belongs to (only tables with protected fields use it).
    pub(crate) fn write_atomic_with_mode(
        &self,
        table: &str,
        row: &str,
        id: &str,
        data: &[u8],
        mode: DurabilityMode,
    ) -> Result<()> {
        #[cfg(feature = "encryption")]
        {
            if let Some(p) = self.protected_of(table) {
                return p
                    .store
                    .write_atomic(&p.place(table)?, &ProtectedBlobs::file(row, id), data, mode.is_strict())
                    .map_err(io_error);
            }
            if let Some(s) = &self.sealed {
                return s.write_atomic(table, id, data, mode.is_strict()).map_err(io_error);
            }
        }
        #[cfg(not(feature = "encryption"))]
        let _ = row;
        let path = self.path(table, id);
        write_atomic(&path, data, mode)
    }

    /// Seal whatever `source` yields into the attachment (encrypted databases only; the plain
    /// store copies through its own file code). Returns the size.
    #[cfg(feature = "encryption")]
    pub(crate) fn write_stream(
        &self,
        table: &str,
        row: &str,
        id: &str,
        source: &mut dyn Read,
        mode: DurabilityMode,
    ) -> Result<u64> {
        if let Some(p) = self.protected_of(table) {
            return p
                .store
                .write_stream(&p.place(table)?, &ProtectedBlobs::file(row, id), source, mode.is_strict())
                .map_err(io_error);
        }
        match &self.sealed {
            Some(s) => s.write_stream(table, id, source, mode.is_strict()).map_err(io_error),
            None => Err(ClError::Validation("write_stream is for encrypted databases".into())),
        }
    }

    /// Without the `encryption` feature there is no sealed store to stream into.
    #[cfg(not(feature = "encryption"))]
    pub(crate) fn write_stream(
        &self,
        _table: &str,
        _row: &str,
        _id: &str,
        _source: &mut dyn Read,
        _mode: DurabilityMode,
    ) -> Result<u64> {
        Err(ClError::Validation("write_stream is for encrypted databases".into()))
    }

    /// The size of an attachment's data.
    pub(crate) fn size_of(&self, table: &str, id: &str) -> Result<u64> {
        #[cfg(feature = "encryption")]
        if let Some(s) = &self.sealed {
            return s.size(table, id).map_err(io_error);
        }
        Ok(fs::metadata(self.path(table, id))?.len())
    }

    /// Delete every sealed attachment not named in `keep`, and leftover temporary files. The
    /// names are fingerprints that cannot be turned back, so what is wanted is named instead.
    #[cfg(feature = "encryption")]
    pub(crate) fn retain_only(&self, keep: &HashSet<(String, String)>) -> Result<usize> {
        match &self.sealed {
            Some(s) => s.retain_only(keep).map_err(io_error),
            None => Ok(0),
        }
    }

    #[cfg(not(feature = "encryption"))]
    pub(crate) fn retain_only(&self, _keep: &HashSet<(String, String)>) -> Result<usize> {
        Ok(0)
    }

    /// The same for the attachments of tables with protected fields: `keep` names (table, row,
    /// file) of every attachment still wanted. Returns how many files went.
    #[cfg(feature = "encryption")]
    pub(crate) fn retain_only_protected(&self, keep: &HashSet<(String, String, String)>) -> Result<usize> {
        let Some(p) = &self.protected else { return Ok(0) };
        let mut wanted = HashSet::new();
        for (table, row, id) in keep {
            if p.ids.contains_key(table) {
                wanted.insert((p.place(table)?, ProtectedBlobs::file(row, id)));
            }
        }
        p.store.retain_only(&wanted).map_err(io_error)
    }

    #[cfg(not(feature = "encryption"))]
    pub(crate) fn retain_only_protected(&self, _keep: &HashSet<(String, String, String)>) -> Result<usize> {
        Ok(0)
    }

    /// An attachment of a table with protected fields, opened as the attachment of `row`: it opens
    /// only if it was sealed for exactly that table, place, row and file.
    pub(crate) fn open_read_row(&self, table: &str, row: &str, id: &str) -> Result<BlobReader> {
        #[cfg(feature = "encryption")]
        if let Some(p) = self.protected_of(table) {
            let reader = p.store.open_read(&p.place(table)?, &ProtectedBlobs::file(row, id)).map_err(io_error)?;
            return Ok(BlobReader { inner: ReaderKind::Sealed(reader) });
        }
        #[cfg(not(feature = "encryption"))]
        let _ = row;
        self.open_read(table, id)
    }

    pub fn open_read(&self, table: &str, id: &str) -> Result<BlobReader> {
        #[cfg(feature = "encryption")]
        {
            if self.is_protected(table) {
                return Err(row_bound());
            }
            if let Some(s) = &self.sealed {
                return Ok(BlobReader { inner: ReaderKind::Sealed(s.open_read(table, id).map_err(io_error)?) });
            }
        }
        let path = self.path(table, id);
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|e| ClError::IoError(e.to_string()))?;
        Ok(BlobReader { inner: ReaderKind::Plain(file) })
    }

    #[cfg(test)]
    pub(crate) fn delete(&self, table: &str, id: &str) -> Result<bool> {
        #[cfg(feature = "encryption")]
        if let Some(s) = &self.sealed {
            return s.delete(table, id).map_err(io_error);
        }
        let path = self.path(table, id);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| ClError::IoError(e.to_string()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn count_files(&self, table: &str) -> Result<usize> {
        #[cfg(feature = "encryption")]
        {
            if let Some(p) = self.protected_of(table) {
                return p.store.count_files(&p.place(table)?).map_err(io_error);
            }
            if let Some(s) = &self.sealed {
                return s.count_files(table).map_err(io_error);
            }
        }
        let dir = self.table_dir(table);
        if !dir.exists() {
            return Ok(0);
        }
        let mut count = 0usize;
        for entry in fs::read_dir(&dir).map_err(|e| ClError::IoError(e.to_string()))? {
            let entry = entry.map_err(|e| ClError::IoError(e.to_string()))?;
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn count_all_files(&self) -> Result<usize> {
        #[cfg(feature = "encryption")]
        {
            let protected = match &self.protected {
                Some(p) => p.store.count_all_files().map_err(io_error)?,
                None => 0,
            };
            if let Some(s) = &self.sealed {
                return Ok(protected + s.count_all_files().map_err(io_error)?);
            }
            Ok(protected + self.count_plain_files()?)
        }
        #[cfg(not(feature = "encryption"))]
        self.count_plain_files()
    }

    fn count_plain_files(&self) -> Result<usize> {
        let root = self.root();
        if !root.exists() {
            return Ok(0);
        }
        let mut count = 0usize;
        for table_entry in fs::read_dir(&root).map_err(|e| ClError::IoError(e.to_string()))? {
            let table_entry = table_entry.map_err(|e| ClError::IoError(e.to_string()))?;
            if !table_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            for file_entry in
                fs::read_dir(table_entry.path()).map_err(|e| ClError::IoError(e.to_string()))?
            {
                let file_entry = file_entry.map_err(|e| ClError::IoError(e.to_string()))?;
                if file_entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}
