//! How much disk a migration needs, and the check against what the program says is free.
//!
//! The library does not ask the system how much is free (that needs a dependency or unsafe code);
//! the program may say. A disk that fills up while the new files are written is an ordinary write
//! error: the migration is rolled back like any other failure.
use super::marker::{Places, Root};
use crate::units::{ClError, Result};
use std::path::Path;

/// Extra space the new files need, per folder: the files are written complete next to the old
/// ones, which stay until the end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Required {
    pub main: u64,
    /// `None` when the backup file lives in the database folder (it is counted in `main`).
    pub backup: Option<u64>,
}

/// What the program says is free, per folder. A value left out is not checked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Available {
    pub main: Option<u64>,
    pub backup: Option<u64>,
}

/// Bytes of a file, or of every file in a folder. A missing path is 0.
pub(crate) fn size_of(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return 0 };
    if meta.is_dir() {
        std::fs::read_dir(path).map(|rd| rd.filter_map(|e| e.ok()).map(|e| size_of(&e.path())).sum()).unwrap_or(0)
    } else {
        meta.len()
    }
}

/// The new version of a file is a little larger at most: every 4096-byte block grows by 40 bytes
/// (under 1%), and a file has a 4096-byte header. A margin of 2% and 8 KiB covers both.
fn grown(size: u64) -> u64 {
    size.saturating_add(size / 50).saturating_add(8192)
}

/// The most disk a database file (`.cldb`, `.cldb.bak`) that is written complete in batches takes
/// while it is written, measured (a table of rows of 20 MB and one of 500 MB, plain and encrypted).
/// Two things make it more than the old file:
/// * the new main file holds the rows, and the change log holds one more image of each table (the
///   file was 1.6 to 2.4 times the old one when it was done, in bytes: 24 to 55 MiB for 23 MiB, and
///   736 to 1376 MiB, 1160 MiB for the encrypted form);
/// * the file grows by doubling its length while it is written (160, 320, 640, 1280, 2560 MiB were
///   seen for one file) and is cut back to the room it uses when it is closed, so while it is written
///   it can be up to twice what it ends as (2560 MiB for 1376 MiB: 3.5 times the old file).
/// A main file is therefore counted as twice 2.5 times its old size. A history file has no image
/// of the tables: twice 1.25 times (not measured as the main file was).
fn rebuilt_peak(size: u64, ends_as: u64, per_ten: u64) -> u64 {
    let ends = size.saturating_mul(ends_as) / per_ten;
    ends.saturating_mul(2).saturating_add(8192)
}

fn is_history(name: &str) -> bool {
    name.ends_with(".cldb.bak")
}

fn is_main(name: &str) -> bool {
    name.ends_with(".cldb")
}

/// `files`: the files and folders that get a new version, with the folder each is in.
/// `keep_safe_copy`: a sealed copy of each old file is kept too (twice the space).
pub(crate) fn required(places: Places<'_>, files: &[(Root, &str)], keep_safe_copy: bool) -> Required {
    let copies = if keep_safe_copy { 2 } else { 1 };
    let (mut main, mut backup) = (0u64, 0u64);
    for (root, name) in files {
        let (base, total) = match root {
            Root::Main => (places.main, &mut main),
            Root::Backup => (places.backup, &mut backup),
        };
        let size = size_of(&base.join(name));
        let one = if is_main(name) {
            rebuilt_peak(size, 25, 10)
        } else if is_history(name) {
            rebuilt_peak(size, 125, 100)
        } else {
            grown(size)
        };
        *total = total.saturating_add(one.saturating_mul(copies));
    }
    if places.backup == places.main {
        Required { main: main.saturating_add(backup), backup: None }
    } else {
        Required { main, backup: Some(backup) }
    }
}

/// Refuse, before anything is touched, when the program says there is less room than needed.
pub(crate) fn check(need: Required, available: Available) -> Result<()> {
    let short = |what: &str, need: u64, have: u64| {
        ClError::MigrationError(format!("not enough room in the {what} folder: {need} bytes are needed, {have} are free; nothing was changed"))
    };
    if let Some(have) = available.main.filter(|have| *have < need.main) {
        return Err(short("database", need.main, have));
    }
    if let (Some(need), Some(have)) = (need.backup, available.backup)
        && have < need
    {
        return Err(short("backup", need, have));
    }
    Ok(())
}
