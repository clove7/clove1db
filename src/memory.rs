//! Large allocations the library makes itself.
//!
//! Rust's default answer to a failed allocation is to abort the process. That is safe for the data
//! (nothing half-written survives a restart) but it takes the programmer's whole program down. For
//! the allocations whose size follows the caller's data — a batch, a row, a table copy, a backup
//! record, an index row — the library reserves first and, when the system refuses, returns
//! [`ClError::OutOfMemory`] before anything was committed.
//!
//! What stays an abort: small allocations, and whatever happens inside redb, serde_json, fst and
//! Rust itself, which the library cannot reserve for.
//!
//! The sites below are the whole list. Each has a name that appears in the error.
use crate::units::{ClError, Result};

/// Every site that returns [`ClError::OutOfMemory`], by the name the error carries.
pub const ALLOC_SITES: &[&str] = &[
    "write.change_rows",
    "write.single_row",
    "journal.encode_row",
    "journal.read_rows",
    "journal.table_entries",
    "repository.list_rows",
    "backup.encode_record",
    "index.row_terms",
    "query.collect_rows",
    "index.trigram_build",
];

/// A reservation below this size is not probed: the allocation it guards is small enough to stay an abort.
const PROBE_MIN: usize = 1 << 20;

#[cfg(feature = "crash-inject")]
static FAIL_AT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Make every reservation at `site` fail, or stop doing so with `None`. Process-wide: tests that use it
/// run alone in their own test binary.
#[cfg(feature = "crash-inject")]
pub fn test_fail_allocation(site: Option<&str>) {
    *FAIL_AT.lock().unwrap_or_else(|e| e.into_inner()) = site.map(str::to_owned);
}

#[cfg(feature = "crash-inject")]
fn injected(site: &str) -> bool {
    FAIL_AT.lock().unwrap_or_else(|e| e.into_inner()).as_deref() == Some(site)
}
#[cfg(not(feature = "crash-inject"))]
#[inline(always)]
fn injected(_site: &str) -> bool {
    false
}

fn refused(site: &'static str, bytes: usize) -> ClError {
    ClError::OutOfMemory { site, bytes: bytes as u64 }
}

/// A vector with room for `n` items, or [`ClError::OutOfMemory`].
pub(crate) fn vec_with_capacity<T>(site: &'static str, n: usize) -> Result<Vec<T>> {
    let bytes = n.saturating_mul(std::mem::size_of::<T>());
    if injected(site) {
        return Err(refused(site, bytes));
    }
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| refused(site, bytes))?;
    Ok(v)
}

/// Room for `additional` more items in `v`, or [`ClError::OutOfMemory`].
pub(crate) fn reserve<T>(site: &'static str, v: &mut Vec<T>, additional: usize) -> Result<()> {
    if injected(site) {
        return Err(refused(site, additional.saturating_mul(std::mem::size_of::<T>())));
    }
    v.try_reserve(additional)
        .map_err(|_| refused(site, additional.saturating_mul(std::mem::size_of::<T>())))
}

/// `v.push(item)` that can fail with [`ClError::OutOfMemory`] instead of aborting.
pub(crate) fn push<T>(site: &'static str, v: &mut Vec<T>, item: T) -> Result<()> {
    reserve(site, v, 1)?;
    v.push(item);
    Ok(())
}

/// Room for `additional` more items in `heap`, or [`ClError::OutOfMemory`].
pub(crate) fn reserve_heap<T: Ord>(site: &'static str, heap: &mut std::collections::BinaryHeap<T>, additional: usize) -> Result<()> {
    let bytes = additional.saturating_mul(std::mem::size_of::<T>());
    if injected(site) {
        return Err(refused(site, bytes));
    }
    heap.try_reserve(additional).map_err(|_| refused(site, bytes))
}

/// A copy of `src`, or [`ClError::OutOfMemory`].
pub(crate) fn copy_bytes(site: &'static str, src: &[u8]) -> Result<Vec<u8>> {
    let mut v = vec_with_capacity(site, src.len())?;
    v.extend_from_slice(src);
    Ok(v)
}

/// Ask the system for `bytes` now and hand it straight back. For work whose buffers are built by
/// code the library does not own: it fails early, before the work starts, when the system is
/// already refusing memory of that size.
pub(crate) fn probe(site: &'static str, bytes: usize) -> Result<()> {
    if injected(site) {
        return Err(refused(site, bytes));
    }
    if bytes < PROBE_MIN {
        return Ok(());
    }
    let mut v: Vec<u8> = Vec::new();
    v.try_reserve_exact(bytes).map_err(|_| refused(site, bytes))
}

/// Room for `additional` more entries in `map`, or [`ClError::OutOfMemory`].
pub(crate) fn reserve_map<K: Eq + std::hash::Hash, V>(site: &'static str, map: &mut std::collections::HashMap<K, V>, additional: usize) -> Result<()> {
    let bytes = additional.saturating_mul(std::mem::size_of::<(K, V)>());
    if injected(site) {
        return Err(refused(site, bytes));
    }
    map.try_reserve(additional).map_err(|_| refused(site, bytes))
}

/// A copy of `src`, or [`ClError::OutOfMemory`].
pub(crate) fn copy_str(site: &'static str, src: &str) -> Result<String> {
    let bytes = copy_bytes(site, src.as_bytes())?;
    Ok(String::from_utf8(bytes).expect("a copy of a str is valid UTF-8"))
}
