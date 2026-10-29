use std::path::Path;

use redb::{ReadableDatabase, ReadableTable, TableDefinition, TableHandle};

use crate::units::{ClError, Result};

/// Open the source of a migration (or any file only read from) **read only**: nothing is written to it, not even the recovery mark redb leaves on a
/// writable open. A file that needs repair is an error that says to open it normally first; it is never repaired here.
pub(crate) fn open_source_read_only(path: &Path) -> Result<redb::ReadOnlyDatabase> {
    crate::handle::guard_open(path, false)?;
    redb::Database::builder().open_read_only(path).map_err(|e| match e {
        redb::DatabaseError::RepairAborted => ClError::Validation(format!(
            "{}: the file needs repair, and reading it for a migration never changes it; open the database normally first",
            path.display()
        )),
        e => crate::handle::open_error(e, path),
    })
}

pub fn read_clove_table(path: &Path, table_name: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let db = open_source_read_only(path)?;
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
    let db = open_source_read_only(path)?;
    let read_txn = db.begin_read()?;
    Ok(read_txn
        .list_tables()?
        .map(|name| name.name().to_string())
        .collect())
}
