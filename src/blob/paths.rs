use std::path::{Path, PathBuf};

/// Sidecar path: `{db_dir}/{db_name}.blobs/{table}/{entity_id}`
pub fn blob_path(db_dir: &Path, db_name: &str, table: &str, id: &str) -> PathBuf {
    db_dir
        .join(format!("{db_name}.blobs"))
        .join(table)
        .join(id)
}

pub fn blob_root(db_dir: &Path, db_name: &str) -> PathBuf {
    db_dir.join(format!("{db_name}.blobs"))
}

pub fn blob_table_dir(db_dir: &Path, db_name: &str, table: &str) -> PathBuf {
    blob_root(db_dir, db_name).join(table)
}
