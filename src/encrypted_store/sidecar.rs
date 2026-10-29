//! Small side files next to the database (configuration, indexes of other things): each one is a
//! sealed file whose folders and name are fingerprints of its logical parts, and whose content is
//! bound to those parts, so a file moved to another place does not open.
use super::sealed::{read_sealed_file, write_sealed_file};
use super::store::EncryptionContext;
use std::io;
use std::path::{Path, PathBuf};

const LABEL: &str = "side";

#[derive(Clone)]
pub struct SidecarFiles {
    root: PathBuf,
    context: EncryptionContext,
}

impl std::fmt::Debug for SidecarFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SidecarFiles")
    }
}

impl SidecarFiles {
    /// `root` is the folder the side files live under (its own name is the caller's choice).
    pub fn new(root: &Path, context: EncryptionContext) -> Self {
        SidecarFiles { root: root.to_path_buf(), context }
    }

    fn binding(parts: &[&str]) -> String {
        // each part with its length, so ["a/b"] and ["a", "b"] never give the same text
        parts.iter().map(|p| format!("{}:{p}", p.len())).collect::<Vec<_>>().join("/")
    }

    pub fn path(&self, parts: &[&str]) -> io::Result<PathBuf> {
        self.context.masked_path(&self.root, parts)
    }

    pub fn exists(&self, parts: &[&str]) -> io::Result<bool> {
        Ok(self.path(parts)?.is_file())
    }

    /// Seal `bytes` as the file `parts` (folders are made as needed), atomically.
    pub fn write(&self, parts: &[&str], bytes: &[u8], sync: bool) -> io::Result<()> {
        let path = self.path(parts)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_sealed_file(&path, &self.context, LABEL, &Self::binding(parts), bytes, sync)
    }

    /// The content of the file, `None` when there is no such file. A file that was changed, moved
    /// from another place or damaged is an error that [`super::is_tamper`] recognises; it is never
    /// treated as missing.
    pub fn read(&self, parts: &[&str]) -> io::Result<Option<Vec<u8>>> {
        let path = self.path(parts)?;
        if !path.is_file() {
            return Ok(None);
        }
        read_sealed_file(&path, &self.context, LABEL, &Self::binding(parts)).map(Some)
    }

    pub fn remove(&self, parts: &[&str]) -> io::Result<bool> {
        match std::fs::remove_file(self.path(parts)?) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Move a file that failed to open out of the way (to a name made from its own, so it is not
    /// read again) and keep it for inspection. Only for files whose loss the caller can repair.
    pub fn set_aside(&self, parts: &[&str], stamp: u64) -> io::Result<()> {
        let path = self.path(parts)?;
        if !path.exists() {
            return Ok(());
        }
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".aside.{stamp}"));
        std::fs::rename(&path, path.with_file_name(name))
    }
}
