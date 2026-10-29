//! Attachments of an encrypted database: one sealed file per attachment, in folders and under
//! file names that are fingerprints, so neither the content nor the table or the id is visible.
//!
//! Layout: `{root}/{fingerprint(table)}/{fingerprint(table, id)}`. The name of a file cannot be
//! turned back into a table or an id; to find what is no longer used, the caller names everything
//! that is used and the rest goes ([`SealedBlobStore::retain_only`]).
use super::sealed::{SealedReader, SealedWriter, read_sealed_file, write_sealed_file};
use super::sealed::FileKeys;
use super::store::EncryptionContext;
use std::sync::Arc;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read};
use std::path::{Path, PathBuf};

const LABEL: &str = "blob";

#[derive(Clone)]
pub struct SealedBlobStore {
    root: PathBuf,
    keys: Arc<dyn FileKeys>,
}

impl std::fmt::Debug for SealedBlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealedBlobStore")
    }
}

impl SealedBlobStore {
    /// `root` is the folder that holds the attachments (its own name is the caller's choice).
    pub fn new(root: &Path, context: EncryptionContext) -> Self {
        SealedBlobStore { root: root.to_path_buf(), keys: Arc::new(context) }
    }

    /// A store whose keys come from another source (the protected fields of an ordinary database).
    #[doc(hidden)]
    pub fn with_keys(root: &Path, keys: Arc<dyn FileKeys>) -> Self {
        SealedBlobStore { root: root.to_path_buf(), keys }
    }

    /// False when the keys of this store cannot open files.
    #[doc(hidden)]
    pub fn can_open(&self) -> bool {
        self.keys.can_open()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn table_name(&self, table: &str) -> io::Result<String> {
        self.keys.name_fingerprint("blob-table", table)
    }

    fn file_name(&self, table: &str, id: &str) -> io::Result<String> {
        // the table and the id are both part of what is fingerprinted, with an unambiguous join
        let joined = format!("{}:{table}{id}", table.len());
        self.keys.name_fingerprint("blob-file", &joined)
    }

    /// The logical name the file is bound to: the table and the id, joined so that two different
    /// pairs never give the same text. Not stored anywhere; reading rebuilds it from the caller.
    fn binding(table: &str, id: &str) -> String {
        format!("{}:{table}{id}", table.len())
    }

    pub fn table_dir(&self, table: &str) -> io::Result<PathBuf> {
        Ok(self.root.join(self.table_name(table)?))
    }

    pub fn path(&self, table: &str, id: &str) -> io::Result<PathBuf> {
        Ok(self.table_dir(table)?.join(self.file_name(table, id)?))
    }

    pub fn ensure_root(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.root)
    }

    pub fn ensure_table(&self, table: &str) -> io::Result<()> {
        std::fs::create_dir_all(self.table_dir(table)?)
    }

    /// Seal `data` as the attachment (through a temporary file and a rename).
    pub fn write_atomic(&self, table: &str, id: &str, data: &[u8], sync: bool) -> io::Result<()> {
        self.ensure_table(table)?;
        write_sealed_file(&self.path(table, id)?, &*self.keys, LABEL, &Self::binding(table, id), data, sync)
    }

    /// Seal whatever `source` yields, without holding it all in memory. Returns the size.
    pub fn write_stream(&self, table: &str, id: &str, source: &mut dyn Read, sync: bool) -> io::Result<u64> {
        self.ensure_table(table)?;
        let target = self.path(table, id)?;
        let mut tmp_name = target.file_name().unwrap_or_default().to_os_string();
        tmp_name.push(format!(".tmp.{}", std::process::id()));
        let tmp = target.with_file_name(tmp_name);
        let result = (|| -> io::Result<u64> {
            let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            let mut w = SealedWriter::new(BufWriter::new(file), &*self.keys, LABEL, &Self::binding(table, id))?;
            let size = io::copy(source, &mut w)?;
            let file = w.finish()?.into_inner().map_err(|e| e.into_error())?;
            if sync {
                file.sync_all()?;
            }
            drop(file);
            std::fs::rename(&tmp, &target)?;
            Ok(size)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// A reader that opens the attachment as it is read. A changed file is an error that
    /// [`super::is_tamper`] recognises.
    pub fn open_read(&self, table: &str, id: &str) -> io::Result<SealedReader<BufReader<File>>> {
        let file = File::open(self.path(table, id)?)?;
        SealedReader::new(BufReader::new(file), &*self.keys, LABEL, &Self::binding(table, id))
    }

    pub fn read_all(&self, table: &str, id: &str) -> io::Result<Vec<u8>> {
        read_sealed_file(&self.path(table, id)?, &*self.keys, LABEL, &Self::binding(table, id))
    }

    /// The size of the attachment's data, checked against the file.
    pub fn size(&self, table: &str, id: &str) -> io::Result<u64> {
        Ok(self.open_read(table, id)?.len())
    }

    /// Copy an attachment of another store (of the same or another database) into this one, piece
    /// by piece, so nothing readable is written in between.
    pub fn copy_from(&self, source: &SealedBlobStore, table: &str, id: &str, to_table: &str, to_id: &str, sync: bool) -> io::Result<u64> {
        let mut reader = source.open_read(table, id)?;
        self.write_stream(to_table, to_id, &mut reader, sync)
    }

    pub fn delete(&self, table: &str, id: &str) -> io::Result<bool> {
        match std::fs::remove_file(self.path(table, id)?) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn count_files(&self, table: &str) -> io::Result<usize> {
        let dir = self.table_dir(table)?;
        if !dir.is_dir() {
            return Ok(0);
        }
        count_in(&dir)
    }

    pub fn count_all_files(&self) -> io::Result<usize> {
        if !self.root.is_dir() {
            return Ok(0);
        }
        let mut total = 0;
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                total += count_in(&entry.path())?;
            }
        }
        Ok(total)
    }

    /// Delete every attachment file that is not in `keep` (table, id), and every temporary file
    /// left by an interrupted write. Returns how many files went.
    pub fn retain_only(&self, keep: &HashSet<(String, String)>) -> io::Result<usize> {
        if !self.root.is_dir() {
            return Ok(0);
        }
        let mut wanted: HashSet<(String, String)> = HashSet::new();
        for (table, id) in keep {
            wanted.insert((self.table_name(table)?, self.file_name(table, id)?));
        }
        let mut removed = 0;
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let table_fp = entry.file_name().to_string_lossy().into_owned();
            for file in std::fs::read_dir(entry.path())? {
                let file = file?;
                if !file.file_type()?.is_file() {
                    continue;
                }
                let name = file.file_name().to_string_lossy().into_owned();
                if !wanted.contains(&(table_fp.clone(), name)) {
                    std::fs::remove_file(file.path())?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

fn count_in(dir: &Path) -> io::Result<usize> {
    let mut n = 0;
    for entry in std::fs::read_dir(dir)? {
        if entry?.file_type()?.is_file() {
            n += 1;
        }
    }
    Ok(n)
}
