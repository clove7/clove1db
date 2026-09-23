use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableHandle};

use crate::units::{ClError, Result};

pub fn read_clove_table(path: &Path, table_name: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let db = Database::open(path).map_err(|e| ClError::Database(redb::Error::from(e)))?;
    let read_txn = db.begin_read()?;
    let table: TableDefinition<&str, &[u8]> = TableDefinition::new(table_name);
    let table_ref = read_txn.open_table(table).map_err(|_| {
        ClError::MigrationError(format!("table '{}' not found in {:?}", table_name, path))
    })?;

    // Every row, or an error. This feeds a migration, and a migration that
    // silently drops the rows it could not read writes a truncated copy and
    // reports success — the one outcome worse than failing.
    table_ref
        .iter()?
        .map(|entry| {
            let (k, v) = entry?;
            Ok((k.value().to_string(), v.value().to_vec()))
        })
        .collect()
}

pub fn list_clove_tables(path: &Path) -> Result<Vec<String>> {
    let db = Database::open(path).map_err(|e| ClError::Database(redb::Error::from(e)))?;
    let read_txn = db.begin_read()?;
    Ok(read_txn
        .list_tables()?
        .map(|name| name.name().to_string())
        .collect())
}
