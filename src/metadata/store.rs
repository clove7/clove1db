use redb::{Database, ReadableDatabase, TableDefinition, TableHandle, WriteTransaction};

use crate::metadata::types::{CloveMeta, FRAMEWORK_ID, META_KEY, META_TABLE};
use crate::units::{ClError, Result};

pub fn read_meta(db: &Database) -> Result<Option<CloveMeta>> {
    let read_txn = db.begin_read()?;
    let names: Vec<String> = read_txn
        .list_tables()?
        .map(|n| n.name().to_string())
        .collect();
    if !names.iter().any(|n| n == META_TABLE) {
        return Ok(None);
    }
    let table: TableDefinition<&str, &[u8]> = TableDefinition::new(META_TABLE);
    let table_ref = read_txn.open_table(table).map_err(|_| {
        ClError::MigrationError(format!("table '{}' not readable", META_TABLE))
    })?;
    let Some(value) = table_ref.get(META_KEY)?.map(|v| v.value().to_vec()) else {
        return Ok(None);
    };
    let meta: CloveMeta = serde_json::from_slice(&value)?;
    if meta.framework != FRAMEWORK_ID {
        return Err(ClError::NotCloveDatabase {
            path: "primary".into(),
        });
    }
    Ok(Some(meta))
}

/// Write `_clove_meta` in its own transaction.
///
/// For a raw `Database`. A database managed by `Storage` writes it with
/// `DatabaseManager::write_meta`, which keeps that database's commit policy —
/// a commit made here does not set quick repair, and redb decides whether the
/// next open needs a full repair from the *last* commit.
pub fn write_meta(db: &Database, meta: &CloveMeta) -> Result<()> {
    let write_txn = db.begin_write()?;
    put_meta(&write_txn, meta)?;
    write_txn.commit()?;
    Ok(())
}

pub fn ensure_meta_table(db: &Database) -> Result<()> {
    let write_txn = db.begin_write()?;
    create_meta_table(&write_txn)?;
    write_txn.commit()?;
    Ok(())
}

/// Write `_clove_meta` inside a transaction the caller opened.
pub(crate) fn put_meta(write_txn: &WriteTransaction, meta: &CloveMeta) -> Result<()> {
    let data = serde_json::to_vec(meta)?;
    let table: TableDefinition<&str, &[u8]> = TableDefinition::new(META_TABLE);
    let mut table_ref = write_txn.open_table(table)?;
    table_ref.insert(META_KEY, data.as_slice())?;
    Ok(())
}

pub(crate) fn create_meta_table(write_txn: &WriteTransaction) -> Result<()> {
    let table: TableDefinition<&str, &[u8]> = TableDefinition::new(META_TABLE);
    write_txn.open_table(table)?;
    Ok(())
}
