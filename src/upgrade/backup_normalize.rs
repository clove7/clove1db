//! Convert on one sibling copy, verify against the untouched source, then replace.
use crate::{
    backup::codec,
    durability::DurabilityMode,
    handle::{FileOpen, RedbOptions},
    metadata::inspect::upgrading_path,
    units::{ClError, Result},
};
use chrono::Local;
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use std::{fs, io::Read, path::Path};
const BATCH_SIZE: usize = 1000;
pub struct BackupNormalizeResult {
    pub upgraded: bool,
    pub entries_converted: usize,
    pub entries_skipped: usize,
    pub pre_upgrade_removed: bool,
    pub(crate) opens: Vec<FileOpen>,
    pub failure: Option<String>,
}
pub fn eager_normalize(
    path: &Path,
    registered_tables: &[String],
    has_cache: bool,
    durability: DurabilityMode,
    redb: RedbOptions,
) -> Result<BackupNormalizeResult> {
    let mut result = BackupNormalizeResult {
        upgraded: false,
        entries_converted: 0,
        entries_skipped: 0,
        pre_upgrade_removed: false,
        opens: Vec::new(),
        failure: None,
    };
    if !path.exists() {
        return Ok(result);
    }
    let copy = upgrading_path(path);
    // Only this converter's reserved sibling is disposable. A previous interrupted
    // attempt is restarted from the original, never treated as authoritative.
    if copy.exists() {
        fs::remove_file(&copy)?;
    }
    let attempt = (|| -> Result<()> {
        let source = match format_open_read_only(redb, path, &mut result.opens) {
            Ok(source) => Some(source),
            // A read-only open cannot repair. Repair only the byte-identical copy.
            Err(ClError::Database(redb::Error::RepairAborted)) => None,
            Err(error) => return Err(error),
        };
        if let Some(source) = &source {
            let names = table_names(source)?;
            let data = history_tables(&names, registered_tables);
            let read = source.begin_read()?;
            let mut all_v2 = true;
            for name in &data {
                for entry in read
                    .open_table(TableDefinition::<&str, &[u8]>::new(name))?
                    .iter()?
                {
                    let (_, value) = entry?;
                    if !codec::is_v2(value.value())? {
                        all_v2 = false;
                    }
                }
            }
            if all_v2 {
                result.upgraded = true;
                return Ok(());
            }
        }
        fs::copy(path, &copy)?;
        verify_copy_bytes(path, &copy)?;
        let mut converted = format_open(redb, &copy, &mut result.opens)?;
        let tables = table_names(&converted)?;
        let data_tables = history_tables(&tables, registered_tables);
        // This MVCC snapshot represents the exact copy before conversion, after any
        // redb recovery. It remains readable through the writes, with bounded RAM.
        let read = converted.begin_read()?;
        let now = Local::now();
        let timestamp = now.timestamp_millis();
        let date = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        for name in data_tables.iter() {
            let table = read.open_table(TableDefinition::<&str, &[u8]>::new(name))?;
            let mut batch = Vec::with_capacity(BATCH_SIZE);
            for entry in table.iter()? {
                let (key, value) = entry?;
                let mut record = codec::decode_record(name, key.value(), value.value())?;
                if record.date_from_migration && record.date.is_empty() {
                    record.timestamp = timestamp;
                    record.date = date.clone();
                }
                batch.push((key.value().to_string(), codec::encode_record(&record)?));
                result.entries_converted += 1;
                if batch.len() == BATCH_SIZE {
                    write_batch(&converted, name, &batch, has_cache, durability, redb)?;
                    batch.clear();
                }
            }
            if !batch.is_empty() {
                write_batch(&converted, name, &batch, has_cache, durability, redb)?;
            }
        }
        #[cfg(test)]
        fault::corrupt_copy_if_requested(&converted, &data_tables)?;
        verify(&read, &converted, &tables, &data_tables, timestamp, &date)?;
        drop(read);
        // No read/write guards may survive into compact or file replacement.
        converted
            .compact()
            .map_err(|e| ClError::BackupNormalizeFailed {
                reason: format!("compact converted backup: {e}"),
            })?;
        drop(converted);
        drop(source);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&copy)?
            .sync_all()?;
        crate::fsutil::maybe_crash("backup_before_replace");
        // Same-directory rename replaces the destination on supported Windows/Unix.
        // Never remove or move the source aside first: there must be no missing-file gap.
        fs::rename(&copy, path)?;
        crate::fsutil::maybe_crash("backup_after_replace");
        result.upgraded = true;
        Ok(())
    })();
    if let Err(error) = attempt {
        if copy.exists() {
            fs::remove_file(&copy)?;
        }
        result.failure = Some(error.to_string());
    }
    Ok(result)
}
fn verify_copy_bytes(source: &Path, copy: &Path) -> Result<()> {
    let mut original = fs::File::open(source)?;
    let mut staged = fs::File::open(copy)?;
    let mut remaining = original.metadata()?.len();
    if remaining != staged.metadata()?.len() {
        return Err(mismatch("initial copy length"));
    }
    let mut left = [0u8; 8192];
    let mut right = [0u8; 8192];
    while remaining > 0 {
        let length = remaining.min(left.len() as u64) as usize;
        original.read_exact(&mut left[..length])?;
        staged.read_exact(&mut right[..length])?;
        if left[..length] != right[..length] {
            return Err(mismatch("initial copy bytes"));
        }
        remaining -= length as u64;
    }
    Ok(())
}
fn history_tables(tables: &[String], registered: &[String]) -> Vec<String> {
    tables
        .iter()
        .filter(|name| {
            if registered.contains(name) {
                return true;
            }
            let parent = name
                .strip_suffix("_version")
                .or_else(|| name.strip_suffix("_bulk"));
            !parent.is_some_and(|parent| tables.iter().any(|table| table == parent))
        })
        .cloned()
        .collect()
}
fn table_names(db: &impl ReadableDatabase) -> Result<Vec<String>> {
    Ok(db
        .begin_read()?
        .list_tables()?
        .map(|table| table.name().to_string())
        .collect())
}
fn format_open_read_only(
    redb: RedbOptions,
    path: &Path,
    opens: &mut Vec<FileOpen>,
) -> Result<redb::ReadOnlyDatabase> {
    let (db, opened) = redb.open_read_only_timed(path);
    opens.push(opened);
    db
}
fn format_open(redb: RedbOptions, path: &Path, opens: &mut Vec<FileOpen>) -> Result<Database> {
    let (db, mut opened) = redb.open_timed(path, false)?;
    opened.format_check = true;
    opens.push(opened);
    Ok(db)
}
fn write_batch(
    db: &Database,
    name: &str,
    batch: &[(String, Vec<u8>)],
    has_cache: bool,
    durability: DurabilityMode,
    redb: RedbOptions,
) -> Result<()> {
    let mut tx = db.begin_write()?;
    if durability.is_strict() {
        tx.set_durability(redb::Durability::Immediate)?;
    }
    if redb.quick_repair {
        tx.set_quick_repair(true);
    }
    {
        let mut table = tx.open_table(TableDefinition::<&str, &[u8]>::new(name))?;
        for (key, value) in batch {
            if has_cache {
                table.insert(key.as_str(), value.as_slice())?;
            } else {
                let mut slot = table.insert_reserve(key.as_str(), value.len())?;
                slot.as_mut().copy_from_slice(value);
            }
        }
    }
    tx.commit()?;
    Ok(())
}
fn verify(
    before: &redb::ReadTransaction,
    converted: &Database,
    names: &[String],
    data_tables: &[String],
    timestamp: i64,
    date: &str,
) -> Result<()> {
    if table_names(converted)? != names {
        return Err(mismatch("table inventory"));
    }
    let after = converted.begin_read()?;
    for name in names {
        if !data_tables.contains(name) && name.ends_with("_version") {
            let left = before.open_table(TableDefinition::<&str, u64>::new(name))?;
            let right = after.open_table(TableDefinition::<&str, u64>::new(name))?;
            if left.len()? != right.len()? {
                return Err(mismatch(name));
            }
            for entry in left.iter()? {
                let (key, value) = entry?;
                if right.get(key.value())?.map(|v| v.value()) != Some(value.value()) {
                    return Err(mismatch(name));
                }
            }
        } else {
            let left = before.open_table(TableDefinition::<&str, &[u8]>::new(name))?;
            let right = after.open_table(TableDefinition::<&str, &[u8]>::new(name))?;
            if left.len()? != right.len()? {
                return Err(mismatch(name));
            }
            for entry in left.iter()? {
                let (key, value) = entry?;
                let actual = right.get(key.value())?.ok_or_else(|| mismatch(name))?;
                if !data_tables.contains(name) && name.ends_with("_bulk") {
                    // Preserve every byte of bulk metadata, not just selected fields.
                    if value.value() != actual.value() {
                        return Err(mismatch(name));
                    }
                    let _: crate::backup::BulkRecord = serde_json::from_slice(actual.value())?;
                } else {
                    let mut expected = codec::decode_record(name, key.value(), value.value())?;
                    if expected.date_from_migration && expected.date.is_empty() {
                        expected.timestamp = timestamp;
                        expected.date = date.to_string();
                    }
                    if !codec::is_v2(actual.value())? {
                        return Err(mismatch(name));
                    }
                    let actual = codec::decode_record(name, key.value(), actual.value())?;
                    // Includes payload byte-for-byte and every metadata field.
                    if expected != actual {
                        return Err(mismatch(&format!("{name}/{}", key.value())));
                    }
                }
            }
        }
    }
    Ok(())
}
fn mismatch(context: &str) -> ClError {
    ClError::BackupNormalizeFailed {
        reason: format!("conversion verification mismatch: {context}"),
    }
}
#[cfg(test)]
pub(crate) mod fault {
    use super::*;
    thread_local! { static CORRUPT:std::cell::Cell<bool>=const { std::cell::Cell::new(false) }; }
    pub(crate) fn corrupt_next() {
        CORRUPT.with(|flag| flag.set(true));
    }
    pub(super) fn corrupt_copy_if_requested(db: &Database, names: &[String]) -> Result<()> {
        if !CORRUPT.with(|flag| flag.replace(false)) {
            return Ok(());
        }
        let name = names
            .first()
            .ok_or_else(|| mismatch("fault table missing"))?;
        let (key, mut record) = {
            let tx = db.begin_read()?;
            let table = tx.open_table(TableDefinition::<&str, &[u8]>::new(name))?;
            let (key, value) = table
                .iter()?
                .next()
                .ok_or_else(|| mismatch("fault record missing"))??;
            (
                key.value().to_string(),
                codec::decode_record(name, key.value(), value.value())?,
            )
        };
        record.data = Some(b"altered payload".to_vec());
        write_batch(
            db,
            name,
            &[(key, codec::encode_record(&record)?)],
            true,
            DurabilityMode::Strict,
            RedbOptions::default(),
        )
    }
}
