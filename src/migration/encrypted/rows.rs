//! Copying the rows of a table from one database file to another in batches, so that the memory
//! used does not depend on the size of the table. Each batch is read, changed, and committed in
//! the new file before the next one is read.
//!
//! The old file is read from one snapshot for the whole copy and is not written. The new file is
//! written only through these calls, one transaction per batch.
use crate::units::{ClError, Result};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

/// The page cache each file of a change is opened with. The default of the engine (one gibibyte for
/// each file) would make the memory of a change grow with the size of the database; a copy in batches
/// reads each page once, so a small cache costs nothing.
pub(crate) const PAGE_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// How much one batch may hold. A batch ends when either limit is reached (a row is never split,
/// so one very large row is a batch of its own).
#[derive(Clone, Copy, Debug)]
pub(crate) struct BatchLimits {
    pub max_rows: usize,
    pub max_bytes: usize,
}

impl BatchLimits {
    pub(crate) const DEFAULT: Self = Self { max_rows: 10_000, max_bytes: 8 * 1024 * 1024 };

    fn check(self) -> Result<()> {
        if self.max_rows == 0 || self.max_bytes == 0 {
            return Err(ClError::MigrationError("a batch needs a size above zero".into()));
        }
        Ok(())
    }
}

/// What a copy did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Copied {
    pub rows: u64,
    pub batches: u64,
    /// Bytes of keys and values of the largest batch that was held in memory.
    pub largest_batch_bytes: usize,
}

pub(crate) fn io(e: impl std::fmt::Display) -> ClError {
    ClError::MigrationError(e.to_string())
}

#[cfg(test)]
thread_local! {
    /// Test only: the number of batches that still succeed on this thread before a write fails
    /// the way a full disk does. Negative: never.
    pub(crate) static FAIL_AFTER_BATCHES: std::cell::Cell<i64> = const { std::cell::Cell::new(-1) };
}

/// Called after each batch is committed. In a test it can fail on purpose, as a full disk would.
#[cfg(test)]
pub(crate) fn injected_failure() -> Result<()> {
    FAIL_AFTER_BATCHES.with(|left| match left.get() {
        n if n < 0 => Ok(()),
        0 => {
            left.set(-1);
            Err(ClError::IoError("no space left on device (injected)".into()))
        }
        n => {
            left.set(n - 1);
            Ok(())
        }
    })
}

#[cfg(not(test))]
#[inline]
pub(crate) fn injected_failure() -> Result<()> {
    Ok(())
}

/// Copy `name` (text keys, byte values). `change` receives the key and the old value and returns
/// the new value. The table is made in the new file even when it is empty.
pub(crate) fn copy_bytes_table(
    from: &impl ReadableDatabase,
    to: &Database,
    name: &str,
    limits: BatchLimits,
    change: &mut dyn FnMut(&str, &[u8]) -> Result<Vec<u8>>,
) -> Result<Copied> {
    copy_bytes_table_as(from, to, name, name, limits, &mut |k, v| Ok(Some(change(k, v)?)))
}

/// [`copy_bytes_table`] into a table of another name, and `change` may return `None` to leave a
/// row out. `from` and `to` may be the same database (a copy of a table inside the new file).
pub(crate) fn copy_bytes_table_as(
    from: &impl ReadableDatabase,
    to: &Database,
    source: &str,
    target: &str,
    limits: BatchLimits,
    change: &mut dyn FnMut(&str, &[u8]) -> Result<Option<Vec<u8>>>,
) -> Result<Copied> {
    limits.check()?;
    let src = TableDefinition::<&str, &[u8]>::new(source);
    let dst = TableDefinition::<&str, &[u8]>::new(target);
    let read = from.begin_read().map_err(io)?;
    let table = read.open_table(src).map_err(io)?;
    let mut done = Copied::default();
    {
        let write = to.begin_write().map_err(io)?;
        write.open_table(dst).map_err(io)?;
        write.commit().map_err(io)?;
    }
    let mut rows = table.iter().map_err(io)?;
    loop {
        let mut batch: Vec<(String, Vec<u8>)> = Vec::new();
        let mut bytes = 0usize;
        for row in rows.by_ref() {
            let (key, value) = row.map_err(io)?;
            let Some(new) = change(key.value(), value.value())? else { continue };
            bytes += key.value().len() + new.len();
            batch.push((key.value().to_string(), new));
            if batch.len() >= limits.max_rows || bytes >= limits.max_bytes {
                break;
            }
        }
        if batch.is_empty() {
            break;
        }
        let write = to.begin_write().map_err(io)?;
        {
            let mut target = write.open_table(dst).map_err(io)?;
            for (key, value) in &batch {
                target.insert(key.as_str(), value.as_slice()).map_err(io)?;
            }
        }
        write.commit().map_err(io)?;
        injected_failure()?;
        done.rows += batch.len() as u64;
        done.batches += 1;
        done.largest_batch_bytes = done.largest_batch_bytes.max(bytes);
    }
    Ok(done)
}

/// Copy `name` (text keys, number values): the counters of the backup history.
pub(crate) fn copy_number_table(from: &impl ReadableDatabase, to: &Database, name: &str, limits: BatchLimits) -> Result<Copied> {
    limits.check()?;
    let def = TableDefinition::<&str, u64>::new(name);
    let read = from.begin_read().map_err(io)?;
    let table = read.open_table(def).map_err(io)?;
    let mut done = Copied::default();
    {
        let write = to.begin_write().map_err(io)?;
        write.open_table(def).map_err(io)?;
        write.commit().map_err(io)?;
    }
    let mut rows = table.iter().map_err(io)?;
    loop {
        let mut batch: Vec<(String, u64)> = Vec::new();
        let mut bytes = 0usize;
        for row in rows.by_ref() {
            let (key, value) = row.map_err(io)?;
            bytes += key.value().len() + 8;
            batch.push((key.value().to_string(), value.value()));
            if batch.len() >= limits.max_rows || bytes >= limits.max_bytes {
                break;
            }
        }
        if batch.is_empty() {
            break;
        }
        let write = to.begin_write().map_err(io)?;
        {
            let mut target = write.open_table(def).map_err(io)?;
            for (key, value) in &batch {
                target.insert(key.as_str(), *value).map_err(io)?;
            }
        }
        write.commit().map_err(io)?;
        injected_failure()?;
        done.rows += batch.len() as u64;
        done.batches += 1;
        done.largest_batch_bytes = done.largest_batch_bytes.max(bytes);
    }
    Ok(done)
}

/// Copy `name` (number keys, byte values): the catalog of the declared indexes.
pub(crate) fn copy_number_keyed_bytes(from: &impl ReadableDatabase, to: &Database, name: &str, limits: BatchLimits) -> Result<Copied> {
    limits.check()?;
    let def = TableDefinition::<u64, &[u8]>::new(name);
    let read = from.begin_read().map_err(io)?;
    let table = read.open_table(def).map_err(io)?;
    let mut done = Copied::default();
    {
        let write = to.begin_write().map_err(io)?;
        write.open_table(def).map_err(io)?;
        write.commit().map_err(io)?;
    }
    let mut rows = table.iter().map_err(io)?;
    loop {
        let mut batch: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut bytes = 0usize;
        for row in rows.by_ref() {
            let (key, value) = row.map_err(io)?;
            bytes += 8 + value.value().len();
            batch.push((key.value(), value.value().to_vec()));
            if batch.len() >= limits.max_rows || bytes >= limits.max_bytes {
                break;
            }
        }
        if batch.is_empty() {
            break;
        }
        let write = to.begin_write().map_err(io)?;
        {
            let mut target = write.open_table(def).map_err(io)?;
            for (key, value) in &batch {
                target.insert(*key, value.as_slice()).map_err(io)?;
            }
        }
        write.commit().map_err(io)?;
        injected_failure()?;
        done.rows += batch.len() as u64;
        done.batches += 1;
        done.largest_batch_bytes = done.largest_batch_bytes.max(bytes);
    }
    Ok(done)
}

/// A copy of a table whose key is bytes and whose value is `$value` (kept as its owned form).
macro_rules! copy_byte_keyed {
    ($(#[$doc:meta])* $name:ident, $value_def:ty, $value_owned:ty, |$v:ident| $own:expr, |$o:ident| $borrow:expr) => {
        $(#[$doc])*
        pub(crate) fn $name(from: &impl ReadableDatabase, to: &Database, name: &str, limits: BatchLimits) -> Result<Copied> {
            limits.check()?;
            let def = TableDefinition::<&[u8], $value_def>::new(name);
            let read = from.begin_read().map_err(io)?;
            let table = read.open_table(def).map_err(io)?;
            let mut done = Copied::default();
            {
                let write = to.begin_write().map_err(io)?;
                write.open_table(def).map_err(io)?;
                write.commit().map_err(io)?;
            }
            let mut rows = table.iter().map_err(io)?;
            loop {
                let mut batch: Vec<(Vec<u8>, $value_owned)> = Vec::new();
                let mut bytes = 0usize;
                for row in rows.by_ref() {
                    let (key, value) = row.map_err(io)?;
                    let $v = value.value();
                    let own: $value_owned = $own;
                    bytes += key.value().len() + $v.len();
                    batch.push((key.value().to_vec(), own));
                    if batch.len() >= limits.max_rows || bytes >= limits.max_bytes {
                        break;
                    }
                }
                if batch.is_empty() {
                    break;
                }
                let write = to.begin_write().map_err(io)?;
                {
                    let mut target = write.open_table(def).map_err(io)?;
                    for (key, $o) in &batch {
                        target.insert(key.as_slice(), $borrow).map_err(io)?;
                    }
                }
                write.commit().map_err(io)?;
                injected_failure()?;
        done.rows += batch.len() as u64;
                done.batches += 1;
                done.largest_batch_bytes = done.largest_batch_bytes.max(bytes);
            }
            Ok(done)
        }
    };
}

copy_byte_keyed!(
    /// Copy `name` (byte keys, byte values): the reverse index of the unique constraints.
    copy_bytes_to_bytes, &[u8], Vec<u8>, |v| v.to_vec(), |o| o.as_slice()
);
copy_byte_keyed!(
    /// Copy `name` (byte keys, text values): the keys of the unique constraints.
    copy_bytes_to_text, &str, String, |v| v.to_string(), |o| o.as_str()
);
