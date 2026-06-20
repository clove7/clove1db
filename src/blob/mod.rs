mod paths;

#[cfg(test)]
mod tests;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub use paths::{blob_path, blob_root, blob_table_dir};

/// Alias used by runtime (`{db_name}.blobs` root directory).
pub fn blobs_root(db_dir: &Path, db_name: &str) -> PathBuf {
    blob_root(db_dir, db_name)
}

use crate::units::{ClError, Result};

/// Per-database blob sidecar store rooted at `{db_dir}/{db_name}.blobs/`.
#[derive(Debug, Clone)]
pub struct BlobStore {
    db_dir: PathBuf,
    db_name: String,
}

impl BlobStore {
    pub fn new(db_dir: &Path, db_name: &str) -> Self {
        Self {
            db_dir: db_dir.to_path_buf(),
            db_name: db_name.to_string(),
        }
    }

    pub fn root(&self) -> PathBuf {
        blob_root(&self.db_dir, &self.db_name)
    }

    pub fn table_dir(&self, table: &str) -> PathBuf {
        blob_table_dir(&self.db_dir, &self.db_name, table)
    }

    pub fn path(&self, table: &str, id: &str) -> PathBuf {
        blob_path(&self.db_dir, &self.db_name, table, id)
    }

    pub fn ensure_root(&self) -> Result<()> {
        fs::create_dir_all(self.root()).map_err(|e| ClError::IoError(e.to_string()))
    }

    pub fn ensure_table(&self, table: &str) -> Result<()> {
        fs::create_dir_all(self.table_dir(table)).map_err(|e| ClError::IoError(e.to_string()))
    }

    pub fn write_atomic(&self, table: &str, id: &str, data: &[u8]) -> Result<()> {
        let path = self.path(table, id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| ClError::IoError(e.to_string()))?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut file = File::create(&tmp).map_err(|e| ClError::IoError(e.to_string()))?;
            file.write_all(data)
                .map_err(|e| ClError::IoError(e.to_string()))?;
            file.sync_all()
                .map_err(|e| ClError::IoError(e.to_string()))?;
        }
        fs::rename(&tmp, &path).map_err(|e| ClError::IoError(e.to_string()))?;
        Ok(())
    }

    pub fn open_read(&self, table: &str, id: &str) -> Result<File> {
        let path = self.path(table, id);
        OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|e| ClError::IoError(e.to_string()))
    }

    pub fn delete(&self, table: &str, id: &str) -> Result<bool> {
        let path = self.path(table, id);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| ClError::IoError(e.to_string()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn copy(
        &self,
        table: &str,
        id: &str,
        dest: &BlobStore,
        dest_table: &str,
        dest_id: &str,
    ) -> Result<()> {
        let from = self.path(table, id);
        let to = dest.path(dest_table, dest_id);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent).map_err(|e| ClError::IoError(e.to_string()))?;
        }
        fs::copy(&from, &to).map_err(|e| ClError::IoError(e.to_string()))?;
        Ok(())
    }

    pub fn count_files(&self, table: &str) -> Result<usize> {
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
            for file_entry in fs::read_dir(table_entry.path())
                .map_err(|e| ClError::IoError(e.to_string()))?
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
