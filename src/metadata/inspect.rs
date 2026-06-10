use std::path::{Path, PathBuf};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableHandle};

use crate::backup::BackupRecord;
use crate::metadata::store::read_meta;
use crate::metadata::types::{
    FileEra, META_TABLE, BACKUP_PRE_UPGRADE_SUFFIX, FRAMEWORK_ID,
};
use crate::migration::types::migration_dir_name;
use crate::units::{ClError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    New,
    Legacy042,
    Clove049,
    Authenticated,
    ExternalRedb,
    Invalid,
}

#[derive(Debug, Clone)]
pub struct DatabaseInspection {
    pub kind: FileKind,
    pub primary_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub migration_dir: PathBuf,
    pub primary_exists: bool,
    pub backup_exists: bool,
    pub migration_exists: bool,
    pub tables: Vec<String>,
    pub file_era: Option<FileEra>,
    pub backup_upgraded: bool,
}

#[derive(Debug, Clone)]
pub struct InspectReport {
    pub primary_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub kind: FileKind,
    pub tables: Vec<String>,
    pub file_era: Option<FileEra>,
    pub backup_exists: bool,
    pub backup_upgraded: bool,
    pub migration_exists: bool,
    pub framework_version: Option<String>,
    pub table_schemas: Vec<(String, u32)>,
}

pub fn inspect_cldb(primary_path: &Path) -> Result<InspectReport> {
    let parent = primary_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let db_name = primary_path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.strip_suffix(".cldb").unwrap_or(s))
        .unwrap_or("unknown")
        .to_string();

    let backup_path = parent.join(format!("{}.cldb.bak", db_name));
    let backup_path = if backup_path.exists() {
        Some(backup_path)
    } else {
        None
    };

    let migration_dir = parent.join(migration_dir_name(&db_name));
    let inspection = inspect_database(primary_path, backup_path.as_deref(), &migration_dir)?;

    let (framework_version, table_schemas) = if inspection.kind == FileKind::Authenticated {
        let db = Database::open(primary_path).map_err(|e| ClError::Database(redb::Error::from(e)))?;
        if let Some(meta) = read_meta(&db)? {
            let schemas = meta
                .tables
                .iter()
                .map(|t| (t.name.clone(), t.schema_version))
                .collect();
            (Some(meta.framework_version), schemas)
        } else {
            (None, Vec::new())
        }
    } else {
        (None, Vec::new())
    };

    Ok(InspectReport {
        primary_path: primary_path.to_path_buf(),
        backup_path: inspection.backup_path,
        kind: inspection.kind,
        tables: inspection.tables,
        file_era: inspection.file_era,
        backup_exists: inspection.backup_exists,
        backup_upgraded: inspection.backup_upgraded,
        migration_exists: inspection.migration_exists,
        framework_version,
        table_schemas,
    })
}

pub fn inspect_database(
    primary_path: &Path,
    backup_path: Option<&Path>,
    migration_dir: &Path,
) -> Result<DatabaseInspection> {
    let primary_exists = primary_path.exists();
    let backup_exists = backup_path.map(|p| p.exists()).unwrap_or(false);
    let migration_exists = migration_dir.join("index.json").exists();

    if !primary_exists {
        return Ok(DatabaseInspection {
            kind: FileKind::New,
            primary_path: primary_path.to_path_buf(),
            backup_path: backup_path.map(|p| p.to_path_buf()),
            migration_dir: migration_dir.to_path_buf(),
            primary_exists: false,
            backup_exists,
            migration_exists,
            tables: Vec::new(),
            file_era: None,
            backup_upgraded: !backup_exists,
        });
    }

    if primary_path.is_dir() {
        return Ok(DatabaseInspection {
            kind: FileKind::Invalid,
            primary_path: primary_path.to_path_buf(),
            backup_path: backup_path.map(|p| p.to_path_buf()),
            migration_dir: migration_dir.to_path_buf(),
            primary_exists: true,
            backup_exists,
            migration_exists,
            tables: Vec::new(),
            file_era: None,
            backup_upgraded: !backup_exists,
        });
    }

    let db = Database::open(primary_path).map_err(|e| ClError::Database(redb::Error::from(e)))?;
    let read_txn = db.begin_read()?;

    if !primary_has_clove_entity_json(&read_txn)? {
        return Ok(DatabaseInspection {
            kind: FileKind::ExternalRedb,
            primary_path: primary_path.to_path_buf(),
            backup_path: backup_path.map(|p| p.to_path_buf()),
            migration_dir: migration_dir.to_path_buf(),
            primary_exists: true,
            backup_exists,
            migration_exists,
            tables: list_user_tables(&read_txn)?,
            file_era: None,
            backup_upgraded: !backup_exists,
        });
    }

    let tables = list_user_tables(&read_txn)?;
    let meta = read_meta(&db)?;
    let file_era = meta.as_ref().map(|m| m.file_era);

    let kind = if meta.is_some() {
        FileKind::Authenticated
    } else if migration_exists {
        FileKind::Clove049
    } else {
        FileKind::Legacy042
    };

    let backup_upgraded = if backup_exists {
        meta.as_ref().map(|m| m.backup_upgraded).unwrap_or(false)
    } else {
        true
    };

    Ok(DatabaseInspection {
        kind,
        primary_path: primary_path.to_path_buf(),
        backup_path: backup_path.map(|p| p.to_path_buf()),
        migration_dir: migration_dir.to_path_buf(),
        primary_exists: true,
        backup_exists,
        migration_exists,
        tables,
        file_era,
        backup_upgraded,
    })
}

fn list_user_tables(read_txn: &redb::ReadTransaction) -> Result<Vec<String>> {
    Ok(read_txn
        .list_tables()?
        .map(|h| h.name().to_string())
        .filter(|n| n != META_TABLE && !n.ends_with("_version") && !n.ends_with("_bulk"))
        .collect())
}

fn primary_has_clove_entity_json(read_txn: &redb::ReadTransaction) -> Result<bool> {
    for name in read_txn.list_tables()? {
        let n = name.name();
        if n == META_TABLE || n.ends_with("_version") || n.ends_with("_bulk") {
            continue;
        }
        let table: TableDefinition<&str, &[u8]> = TableDefinition::new(n);
        if let Ok(t) = read_txn.open_table(table) {
            if let Some(entry) = t.iter()?.next() {
                let (_, v) = entry?;
                if value_looks_like_clove_entity(v.value()) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Clove entities always serialize an `id` string field (`Entity::entity_id`).
fn value_looks_like_clove_entity(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .and_then(|obj| obj.get("id").and_then(|id| id.as_str()).map(|_| true))
        .unwrap_or(false)
}

pub fn pre_upgrade_path(backup_path: &Path) -> PathBuf {
    let s = backup_path.to_string_lossy();
    PathBuf::from(format!("{s}{BACKUP_PRE_UPGRADE_SUFFIX}"))
}

pub fn upgrading_path(backup_path: &Path) -> PathBuf {
    use crate::metadata::types::BACKUP_UPGRADING_SUFFIX;
    let s = backup_path.to_string_lossy();
    PathBuf::from(format!("{s}{BACKUP_UPGRADING_SUFFIX}"))
}

pub fn is_clove_framework_meta(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| {
            v.get("framework")
                .and_then(|f| f.as_str())
                .map(|f| f == FRAMEWORK_ID)
        })
        .unwrap_or(false)
}

pub fn backup_record_from_bytes(bytes: &[u8]) -> Option<BackupRecord> {
    serde_json::from_slice(bytes).ok()
}
