//! The side files of a database: the attachments (`{db}.blobs/`) and the migration records
//! (`{db}.migration/`), read from one form and written in the other (plain files, or sealed files
//! under fingerprint names).
//!
//! What to move is never found by listing a sealed folder (its names cannot be turned back): the
//! attachments are the ones the main file refers to, the migration records are the ones the
//! records themselves name. A plain folder is listed too, to say what is left unused.
use super::rows::io;
use crate::encrypted_store::{EncryptionContext, SealedBlobStore, SidecarFiles};
use crate::migration::types::{MigrationManifest, TableChainIndex};
use crate::units::{ClError, Result};
use redb::{ReadableDatabase, ReadableTable};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// How a folder of side files is kept.
#[derive(Clone)]
pub(crate) enum Form {
    Plain,
    Sealed(EncryptionContext),
}

/// One attachment the main file refers to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Blob {
    pub table: String,
    pub id: String,
    pub size: u64,
}

fn bad(why: &str) -> ClError {
    ClError::MigrationError(why.to_string())
}

fn ioerr(e: std::io::Error) -> ClError {
    ClError::MigrationError(e.to_string())
}

fn safe(part: &str) -> bool {
    !part.is_empty() && part != "." && part != ".." && !part.contains(['/', '\\', ':'])
}

/// The attachments the old main file refers to. Reads only.
pub(crate) fn plan_blobs(main: &impl ReadableDatabase) -> Result<Vec<Blob>> {
    #[derive(serde::Deserialize)]
    struct Reference {
        id: String,
        size: u64,
    }
    let read = main.begin_read().map_err(io)?;
    let refs = read.open_table(crate::journal_blob::REFS).map_err(io)?;
    let mut out = Vec::new();
    for row in refs.iter().map_err(io)? {
        let (k, v) = row.map_err(io)?;
        let (table, _): (String, String) = serde_json::from_str(k.value())?;
        let reference: Reference = serde_json::from_slice(v.value())?;
        if !safe(&table) || !safe(&reference.id) {
            return Err(bad("an attachment has a name that cannot be a file name; nothing was changed"));
        }
        out.push(Blob { table, id: reference.id, size: reference.size });
    }
    Ok(out)
}

fn plain_path(root: &Path, blob: &Blob) -> PathBuf {
    root.join(&blob.table).join(&blob.id)
}

fn open(form: &Form, root: &Path, blob: &Blob) -> Result<Box<dyn Read>> {
    match form {
        Form::Plain => Ok(Box::new(fs::File::open(plain_path(root, blob)).map_err(ioerr)?)),
        Form::Sealed(context) => {
            let store = SealedBlobStore::new(root, context.clone());
            Ok(Box::new(store.open_read(&blob.table, &blob.id).map_err(ioerr)?))
        }
    }
}

/// Copy each attachment from `from` (in `from_root`) to `to` (in `to_root`, a folder that does not
/// exist yet), piece by piece: nothing is held whole in memory, and in the sealed form nothing
/// readable is written. Returns the bytes copied.
pub(crate) fn copy_blobs(blobs: &[Blob], from: &Form, from_root: &Path, to: &Form, to_root: &Path, sync: bool) -> Result<u64> {
    fs::create_dir_all(to_root).map_err(ioerr)?;
    let mut total = 0u64;
    for blob in blobs {
        let mut source = open(from, from_root, blob)?;
        let size = match to {
            Form::Plain => {
                let path = plain_path(to_root, blob);
                fs::create_dir_all(path.parent().expect("a file has a folder")).map_err(ioerr)?;
                let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(ioerr)?;
                let n = std::io::copy(&mut source, &mut file).map_err(ioerr)?;
                if sync {
                    file.sync_all().map_err(ioerr)?;
                }
                n
            }
            Form::Sealed(context) => {
                SealedBlobStore::new(to_root, context.clone()).write_stream(&blob.table, &blob.id, &mut source, sync).map_err(ioerr)?
            }
        };
        if size != blob.size {
            return Err(ClError::MigrationError(format!(
                "an attachment of a table is {size} bytes, the main file says {}; nothing was changed",
                blob.size
            )));
        }
        total += size;
    }
    Ok(total)
}

/// Every attachment of the new folder holds the same bytes as the old one, compared piece by piece.
pub(crate) fn verify_blobs(blobs: &[Blob], from: &Form, from_root: &Path, to: &Form, to_root: &Path) -> Result<()> {
    for blob in blobs {
        let (mut a, mut b) = (open(from, from_root, blob)?, open(to, to_root, blob)?);
        let (mut x, mut y) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
        loop {
            let n = read_full(&mut a, &mut x)?;
            let m = read_full(&mut b, &mut y)?;
            if n != m || x[..n] != y[..m] {
                return Err(bad("an attachment of the new folder holds other bytes"));
            }
            if n == 0 {
                break;
            }
        }
    }
    Ok(())
}

fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..]).map_err(ioerr)?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Files of a plain attachment folder that no row refers to (a sealed one cannot be listed).
pub(crate) fn unused_plain_blobs(root: &Path, blobs: &[Blob]) -> Result<usize> {
    let mut unused = 0;
    let Ok(tables) = fs::read_dir(root) else { return Ok(0) };
    for table in tables.filter_map(|e| e.ok()) {
        if !table.path().is_dir() {
            continue;
        }
        for file in fs::read_dir(table.path()).map_err(ioerr)?.filter_map(|e| e.ok()) {
            let (t, f) = (table.file_name().to_string_lossy().into_owned(), file.file_name().to_string_lossy().into_owned());
            if !blobs.iter().any(|b| b.table == t && b.id == f) {
                unused += 1;
            }
        }
    }
    Ok(unused)
}

// ---- the migration records -----------------------------------------------------------------------

/// A record is named by its parts, from the folder down: `["tables", table, "index.json"]`.
pub(crate) type Parts = Vec<String>;

fn plain_file(root: &Path, parts: &[String]) -> PathBuf {
    parts.iter().fold(root.to_path_buf(), |p, part| p.join(part))
}

fn read_record(form: &Form, root: &Path, parts: &[String]) -> Result<Option<Vec<u8>>> {
    match form {
        Form::Plain => match fs::read(plain_file(root, parts)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ioerr(e)),
        },
        Form::Sealed(context) => {
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            SidecarFiles::new(root, context.clone()).read(&refs).map_err(ioerr)
        }
    }
}

fn write_record(form: &Form, root: &Path, parts: &[String], bytes: &[u8], sync: bool) -> Result<()> {
    match form {
        Form::Plain => {
            let path = plain_file(root, parts);
            fs::create_dir_all(path.parent().expect("a file has a folder")).map_err(ioerr)?;
            let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(ioerr)?;
            file.write_all(bytes).map_err(ioerr)?;
            if sync {
                file.sync_all().map_err(ioerr)?;
            }
            Ok(())
        }
        Form::Sealed(context) => {
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            SidecarFiles::new(root, context.clone()).write(&refs, bytes, sync).map_err(ioerr)
        }
    }
}

fn walk(base: &Path, dir: &Path, out: &mut Vec<Parts>) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(ioerr)?.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            walk(base, &path, out)?;
        } else {
            let rel = path.strip_prefix(base).expect("below the base");
            out.push(rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect());
        }
    }
    Ok(())
}

/// Which records the folder holds. A plain folder is listed; a sealed one is followed from the
/// records that name the others (the root, the index and the manifests of each table).
pub(crate) fn plan_records(form: &Form, root: &Path, tables: &[String]) -> Result<Vec<Parts>> {
    let mut out: Vec<Parts> = Vec::new();
    match form {
        Form::Plain => {
            if root.is_dir() {
                walk(root, root, &mut out)?;
            }
        }
        Form::Sealed(_) => {
            let parts = |p: &[&str]| -> Parts { p.iter().map(|s| s.to_string()).collect() };
            if read_record(form, root, &parts(&["index.json"]))?.is_some() {
                out.push(parts(&["index.json"]));
            }
            for table in tables {
                let index_parts = parts(&["tables", table, "index.json"]);
                let Some(bytes) = read_record(form, root, &index_parts)? else { continue };
                let index: TableChainIndex = serde_json::from_slice(&bytes).map_err(|_| ClError::DataTampered)?;
                out.push(index_parts);
                let mut newest = index.current_version.max(index.initial_version);
                for entry in &index.chain {
                    let id = entry.migration_id.as_str();
                    let manifest_parts = parts(&["tables", table, id, "manifest.json"]);
                    let bytes = read_record(form, root, &manifest_parts)?.ok_or(ClError::DataTampered)?;
                    let manifest: MigrationManifest = serde_json::from_slice(&bytes).map_err(|_| ClError::DataTampered)?;
                    newest = newest.max(manifest.from.schema_version).max(manifest.to.schema_version);
                    out.push(manifest_parts);
                    let snapshot = manifest.version_scope.primary_snapshot_ref.clone().unwrap_or_else(|| format!("primary_before_{id}"));
                    let refs_parts = parts(&["tables", table, id, "refs", &format!("{snapshot}.json")]);
                    if read_record(form, root, &refs_parts)?.is_some() {
                        out.push(refs_parts);
                    }
                }
                for version in 1..=newest {
                    let layout = parts(&["tables", table, "layouts", &format!("v{version}.json")]);
                    if read_record(form, root, &layout)?.is_some() {
                        out.push(layout);
                    }
                }
            }
        }
    }
    out.sort();
    for p in &out {
        if !p.iter().all(|part| safe(part)) {
            return Err(bad("a migration record has a name that cannot be a file name; nothing was changed"));
        }
    }
    Ok(out)
}

/// Copy the records from one form to the other. `to_root` must not exist yet.
pub(crate) fn copy_records(records: &[Parts], from: &Form, from_root: &Path, to: &Form, to_root: &Path, sync: bool) -> Result<()> {
    fs::create_dir_all(to_root).map_err(ioerr)?;
    for parts in records {
        let bytes = read_record(from, from_root, parts)?.ok_or_else(|| bad("a migration record disappeared while it was being copied"))?;
        write_record(to, to_root, parts, &bytes, sync)?;
    }
    Ok(())
}

/// Every record of the new folder holds the same bytes, and the new folder holds no other (for a
/// plain one, which can be listed).
pub(crate) fn verify_records(records: &[Parts], from: &Form, from_root: &Path, to: &Form, to_root: &Path) -> Result<()> {
    for parts in records {
        let (a, b) = (read_record(from, from_root, parts)?, read_record(to, to_root, parts)?);
        if a.is_none() || a != b {
            return Err(bad("a migration record of the new folder holds other bytes"));
        }
    }
    if matches!(to, Form::Plain) && to_root.is_dir() {
        let mut found = Vec::new();
        walk(to_root, to_root, &mut found)?;
        found.sort();
        let mut expected = records.to_vec();
        expected.sort();
        if found != expected {
            return Err(bad("the new migration folder holds a file nothing accounts for"));
        }
    }
    Ok(())
}
