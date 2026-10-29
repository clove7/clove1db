//! Moving the attachments of a table from one place to another, piece by piece: from plain files
//! to files sealed with the keys of the protected fields (`{db}.pblobs`), back, from the sealed
//! files of a whole encrypted database, or from one set of keys to another.
//!
//! This is a part of a bigger change, never a change of its own: the attachments of a table with
//! protected fields are bound to the table, to the row and to the file, and the library removes
//! the ones it does not find under those names when it opens the database. So the caller moves the
//! main file (and rebuilds the change log, which names no attachment but the current ones) in the
//! same decision, through the marker files.
//!
//! One attachment is held at a time, as a few pieces of 64 KiB, whatever its size and however many
//! there are. A sealed file is sealed from its first byte (the temporary file included), so nothing
//! readable is written in the new place. Each attachment is compared with its source as it is
//! made (a hash of the bytes read, against a hash of the bytes read back), and all of the new
//! files are on disk before the caller makes its decision.
#![allow(dead_code)] // the changes that use these (keys, fields) are written by others
use super::rows::io;
use crate::{
    blob::protected_names,
    encrypted_store::{EncryptionContext, FileKeys, SealedBlobStore},
    journal_blob::{BlobRef, REFS},
    units::{ClError, Result},
};
use redb::{ReadableDatabase, ReadableTable};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Bytes read or written at a time.
const PIECE: usize = 64 * 1024;
/// How many new files are written before they are flushed to disk.
const SYNC_EVERY: usize = 256;
/// Bytes a sealed file has beyond its data: the salt, and for each piece its nonce and tag (the
/// larger of the two ciphers is taken).
const SEALED_FILE: u64 = 32;
const SEALED_PIECE: u64 = 40;

/// Where a set of attachments is kept, and how.
#[derive(Clone)]
pub(crate) enum Place {
    /// `{root}/{table}/{id}`, plain files.
    Plain { root: PathBuf },
    /// The sealed files of a database encrypted as a whole: `{root}/{fingerprint}/{fingerprint}`.
    WholeDb { root: PathBuf, context: EncryptionContext },
    /// The sealed files of tables with protected fields, bound to table identity, row and file.
    /// `ids` maps the name of a table to its identity.
    Protected { root: PathBuf, keys: Arc<dyn FileKeys>, ids: Arc<HashMap<String, String>> },
}

/// One attachment: the row of `table` that owns it, its file name (`blob_id`) and its size, as
/// `__blob_refs` records them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Item {
    pub table: String,
    pub row: String,
    pub blob_id: String,
    pub size: u64,
}

/// What a copy did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Copied {
    pub files: u64,
    pub bytes: u64,
}

/// Exit the process at the named point, after `CLOVE_CRASH_SKIP` earlier hits of that name (feature `crash-inject`).
#[cfg(feature = "crash-inject")]
fn crash_point(name: &str) {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    static HITS: AtomicU64 = AtomicU64::new(0);
    if std::env::var("CLOVE_CRASH_POINT").ok().as_deref() == Some(name) {
        let skip = std::env::var("CLOVE_CRASH_SKIP").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        if HITS.fetch_add(1, Relaxed) >= skip {
            std::process::exit(99);
        }
    }
}

#[cfg(not(feature = "crash-inject"))]
#[inline(always)]
fn crash_point(_name: &str) {}

// The files flushed to disk, by this thread (tests).
#[cfg(test)]
thread_local! {
    pub(crate) static SYNCED: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn bad(why: impl Into<String>) -> ClError {
    ClError::MigrationError(why.into())
}

fn safe_part(part: &str) -> bool {
    !part.is_empty() && part != "." && part != ".." && !part.contains(['/', '\\', ':'])
}

impl Place {
    pub(crate) fn root(&self) -> &Path {
        match self {
            Place::Plain { root } | Place::WholeDb { root, .. } | Place::Protected { root, .. } => root,
        }
    }

    /// The sealed store of this place (`None` for plain files).
    fn store(&self) -> Option<SealedBlobStore> {
        match self {
            Place::Plain { .. } => None,
            Place::WholeDb { root, context } => Some(SealedBlobStore::new(root, context.clone())),
            Place::Protected { root, keys, .. } => Some(SealedBlobStore::with_keys(root, keys.clone())),
        }
    }

    /// The two names the attachment has in the store (for plain files: its table and its file).
    fn names(&self, item: &Item) -> Result<(String, String)> {
        match self {
            Place::Plain { .. } | Place::WholeDb { .. } => Ok((item.table.clone(), item.blob_id.clone())),
            Place::Protected { ids, .. } => {
                let id = ids
                    .get(&item.table)
                    .ok_or_else(|| bad("an attachment table has no protected identity; nothing was changed"))?;
                Ok(protected_names(id, &item.row, &item.blob_id))
            }
        }
    }

    fn path(&self, item: &Item) -> Result<PathBuf> {
        let (table, file) = self.names(item)?;
        match self.store() {
            None => Ok(self.root().join(table).join(file)),
            Some(store) => store.path(&table, &file).map_err(io),
        }
    }

    /// Fails now, before anything is written, when these keys cannot seal or open a file (a program
    /// that holds only the search key).
    pub(crate) fn ensure_usable(&self) -> Result<()> {
        let Some(store) = self.store() else { return Ok(()) };
        if !store.can_open() {
            return Err(bad("the keys cannot open attachments (no read key); nothing was changed"));
        }
        let probe = match self {
            Place::WholeDb { context, .. } => context.name_fingerprint("probe", "probe"),
            Place::Protected { keys, .. } => keys.name_fingerprint("probe", "probe"),
            Place::Plain { .. } => return Ok(()),
        };
        probe.map(|_| ()).map_err(|_| bad("the keys cannot open attachments (no read key); nothing was changed"))
    }

    pub(crate) fn open(&self, item: &Item) -> Result<Box<dyn Read>> {
        let (table, file) = self.names(item)?;
        match self.store() {
            None => Ok(Box::new(fs::File::open(self.root().join(table).join(file)).map_err(io)?)),
            Some(store) => Ok(Box::new(store.open_read(&table, &file).map_err(io)?)),
        }
    }

    /// Write the attachment from `source`, sealed from the first byte when the place is sealed. The
    /// new file is not flushed; the path is returned for the caller to do it.
    fn write(&self, item: &Item, source: &mut dyn Read) -> Result<(u64, PathBuf)> {
        let (table, file) = self.names(item)?;
        match self.store() {
            None => {
                let path = self.root().join(&table).join(&file);
                fs::create_dir_all(path.parent().expect("a file has a folder")).map_err(io)?;
                let mut out = fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(io)?;
                let mut buf = vec![0u8; PIECE];
                let mut total = 0u64;
                loop {
                    let n = source.read(&mut buf).map_err(io)?;
                    if n == 0 {
                        break;
                    }
                    out.write_all(&buf[..n]).map_err(io)?;
                    total += n as u64;
                }
                Ok((total, path))
            }
            Some(store) => {
                let size = store.write_stream(&table, &file, source, false).map_err(io)?;
                Ok((size, store.path(&table, &file).map_err(io)?))
            }
        }
    }

    /// The name of the folder that holds the attachments of `table` in this place.
    fn folder_of(&self, table: &str) -> Result<std::ffi::OsString> {
        match self {
            Place::Plain { .. } => Ok(table.into()),
            Place::WholeDb { .. } => Ok(self.store().expect("sealed").table_dir(table).map_err(io)?.file_name().unwrap_or_default().to_os_string()),
            Place::Protected { ids, .. } => {
                let id = ids.get(table).ok_or_else(|| bad("an attachment table has no protected identity; nothing was changed"))?;
                let (place, _) = protected_names(id, "", "");
                Ok(self.store().expect("sealed").table_dir(&place).map_err(io)?.file_name().unwrap_or_default().to_os_string())
            }
        }
    }
}

/// Hashes what is read through it.
struct Hashing {
    inner: Box<dyn Read>,
    hasher: blake3::Hasher,
}

impl Read for Hashing {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(out)?;
        self.hasher.update(&out[..n]);
        Ok(n)
    }
}

fn hash_all(mut reader: Box<dyn Read>) -> Result<(blake3::Hash, u64)> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; PIECE];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(io)?;
        if n == 0 {
            return Ok((hasher.finalize(), total));
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
}

/// New files waiting to be flushed to disk, flushed in groups. `finish` has flushed every one.
#[derive(Default)]
struct Syncer {
    pending: Vec<PathBuf>,
}

impl Syncer {
    fn add(&mut self, path: PathBuf) -> Result<()> {
        self.pending.push(path);
        if self.pending.len() >= SYNC_EVERY {
            self.finish()?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        for path in self.pending.drain(..) {
            fs::OpenOptions::new().write(true).open(&path).and_then(|f| f.sync_all()).map_err(io)?;
            #[cfg(test)]
            SYNCED.with(|s| s.borrow_mut().push(path));
        }
        Ok(())
    }
}

/// Visit the attachments the main file refers to, in the order of its table, one at a time (nothing
/// is collected). `tables` limits them to those tables. Returns how many were visited. Reads only.
pub(crate) fn plan(
    main: &impl ReadableDatabase,
    tables: Option<&[String]>,
    visit: &mut dyn FnMut(Item) -> Result<()>,
) -> Result<u64> {
    let read = main.begin_read().map_err(io)?;
    let refs = read.open_table(REFS).map_err(io)?;
    let mut visited = 0;
    for row in refs.iter().map_err(io)? {
        let (k, v) = row.map_err(io)?;
        let (table, row_key): (String, String) = serde_json::from_str(k.value())?;
        if tables.is_some_and(|t| !t.contains(&table)) {
            continue;
        }
        let reference: BlobRef = serde_json::from_slice(v.value())?;
        if !safe_part(&table) || !safe_part(&reference.id) || row_key.is_empty() {
            return Err(bad("an attachment has a name that cannot be a file name; nothing was changed"));
        }
        visit(Item { table, row: row_key, blob_id: reference.id, size: reference.size })?;
        visited += 1;
    }
    Ok(visited)
}

/// Move every attachment of `tables` (all when `None`) from `from` into `to`, whose folder must not
/// exist yet, and check each one as it is made: the bytes read back from the new file are the bytes
/// read from the old, and the size is the one the main file records. When this returns, every new
/// file is flushed to disk. `progress` is told the bytes done after each attachment.
pub(crate) fn copy_all(
    main: &impl ReadableDatabase,
    tables: Option<&[String]>,
    from: &Place,
    to: &Place,
    progress: &mut dyn FnMut(u64),
) -> Result<Copied> {
    from.ensure_usable()?;
    to.ensure_usable()?;
    fs::create_dir_all(to.root()).map_err(io)?;
    let mut syncer = Syncer::default();
    let mut done = Copied::default();
    crash_point("attach_before_first_file");
    plan(main, tables, &mut |item| {
        let mut source = Hashing { inner: from.open(&item)?, hasher: blake3::Hasher::new() };
        let (size, path) = to.write(&item, &mut source)?;
        if size != item.size {
            return Err(bad(format!("an attachment of a table is {size} bytes, the main file says {}; nothing was changed", item.size)));
        }
        crash_point("attach_after_file");
        crash_point("attach_before_verify");
        let (back, back_size) = hash_all(to.open(&item)?)?;
        if back_size != size || back != source.hasher.finalize() {
            return Err(bad("an attachment of the new folder holds other bytes; nothing was changed"));
        }
        crash_point("attach_after_verify");
        syncer.add(path)?;
        done.files += 1;
        done.bytes += size;
        progress(done.bytes);
        Ok(())
    })?;
    syncer.finish()?;
    crash_point("attach_after_sync");
    Ok(done)
}

/// Copy, as bytes and without opening them, the attachments of `from` that do not belong to
/// `skip_tables` into `to_root` (a folder that does not exist yet): the attachments of the tables
/// the change does not touch. They stay valid because their keys and names do not change. Leftover
/// temporary files are not copied. Every copy is flushed to disk before this returns. Returns the bytes copied.
pub(crate) fn carry_over(from: &Place, to_root: &Path, skip_tables: &[String]) -> Result<u64> {
    fs::create_dir_all(to_root).map_err(io)?;
    if !from.root().is_dir() {
        return Ok(0);
    }
    let mut skip = Vec::new();
    for table in skip_tables {
        skip.push(from.folder_of(table)?);
    }
    let (mut syncer, mut bytes) = (Syncer::default(), 0u64);
    for folder in fs::read_dir(from.root()).map_err(io)? {
        let folder = folder.map_err(io)?;
        if !folder.path().is_dir() || skip.contains(&folder.file_name()) {
            continue;
        }
        let target = to_root.join(folder.file_name());
        fs::create_dir_all(&target).map_err(io)?;
        for file in fs::read_dir(folder.path()).map_err(io)? {
            let file = file.map_err(io)?;
            let name = file.file_name();
            if !file.path().is_file() || name.to_string_lossy().contains(".tmp") {
                continue;
            }
            let path = target.join(&name);
            bytes += fs::copy(file.path(), &path).map_err(io)?;
            syncer.add(path)?;
        }
    }
    syncer.finish()?;
    Ok(bytes)
}

/// Disk the new attachments need at most: the data of every attachment of `tables`, plus the
/// salt of each file and the nonce and tag of each piece of a sealed one, plus the size of the
/// folders in `carried` (counted whole). The old files stay until the end, so this is extra space.
pub(crate) fn required_bytes(main: &impl ReadableDatabase, tables: Option<&[String]>, carried: &[&Path]) -> Result<u64> {
    let mut total = 0u64;
    plan(main, tables, &mut |item| {
        let pieces = item.size.div_ceil(PIECE as u64).max(1);
        total = total.saturating_add(item.size).saturating_add(SEALED_FILE).saturating_add(pieces * SEALED_PIECE);
        Ok(())
    })?;
    for path in carried {
        total = total.saturating_add(super::space::size_of(path));
    }
    Ok(total)
}

/// After the swap: every attachment of `tables` opens in `place` under the name it is read by (a
/// sealed one only if it was sealed for exactly that table, row and file) and has the size the main
/// file records. Returns how many there are.
pub(crate) fn check_after_swap(main: &impl ReadableDatabase, place: &Place, tables: Option<&[String]>) -> Result<u64> {
    place.ensure_usable()?;
    plan(main, tables, &mut |item| {
        let len = match place.store() {
            Some(store) => {
                let (table, file) = place.names(&item)?;
                store.open_read(&table, &file).map_err(io)?.len()
            }
            None => fs::metadata(place.path(&item)?).map_err(io)?.len(),
        };
        if len != item.size {
            return Err(bad("an attachment in place has another size than the main file records"));
        }
        Ok(())
    })
}
