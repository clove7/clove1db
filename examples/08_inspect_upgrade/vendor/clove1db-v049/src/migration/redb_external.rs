use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableHandle};

use crate::migration::types::{KeyDecoder, RedbTableSpec, ValueDecoder};
use crate::units::{ClError, Result};

pub fn read_external_table(path: &Path, spec: &RedbTableSpec) -> Result<Vec<(String, Vec<u8>)>> {
    let db = Database::open(path).map_err(|e| ClError::Database(redb::Error::from(e)))?;
    let read_txn = db.begin_read()?;

    match spec.key_decoder {
        KeyDecoder::Utf8String => read_utf8_table(&read_txn, spec),
        KeyDecoder::U64AsString => read_u64_table(&read_txn, spec),
    }
}

fn read_utf8_table(
    read_txn: &redb::ReadTransaction,
    spec: &RedbTableSpec,
) -> Result<Vec<(String, Vec<u8>)>> {
    let table: TableDefinition<&str, &[u8]> = TableDefinition::new(&spec.source_table);
    let table_ref = read_txn.open_table(table).map_err(|_| {
        ClError::MigrationError(format!("external table '{}' not found", spec.source_table))
    })?;

    let mut out = Vec::new();
    for entry in table_ref.iter()? {
        let (k, v) = entry?;
        let value = decode_value(v.value(), spec.value_decoder)?;
        out.push((k.value().to_string(), value));
    }
    Ok(out)
}

fn read_u64_table(
    read_txn: &redb::ReadTransaction,
    spec: &RedbTableSpec,
) -> Result<Vec<(String, Vec<u8>)>> {
    let table: TableDefinition<u64, &[u8]> = TableDefinition::new(&spec.source_table);
    let table_ref = read_txn.open_table(table).map_err(|_| {
        ClError::MigrationError(format!("external table '{}' not found", spec.source_table))
    })?;

    let mut out = Vec::new();
    for entry in table_ref.iter()? {
        let (k, v) = entry?;
        let value = decode_value(v.value(), spec.value_decoder)?;
        out.push((k.value().to_string(), value));
    }
    Ok(out)
}

fn decode_value(bytes: &[u8], decoder: ValueDecoder) -> Result<Vec<u8>> {
    match decoder {
        ValueDecoder::RawPassthrough => Ok(bytes.to_vec()),
        ValueDecoder::JsonValidate => {
            serde_json::from_slice::<serde_json::Value>(bytes)?;
            Ok(bytes.to_vec())
        }
    }
}

pub fn list_external_tables(path: &Path) -> Result<Vec<String>> {
    let db = Database::open(path).map_err(|e| ClError::Database(redb::Error::from(e)))?;
    let read_txn = db.begin_read()?;
    Ok(read_txn
        .list_tables()?
        .map(|name| name.name().to_string())
        .collect())
}
