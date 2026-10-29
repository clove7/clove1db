//! Atomic file helpers used by migration metadata, blobs, and upgrades.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::durability::DurabilityMode;
use crate::units::{ClError, Result};

static TMP_NONCE: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "crash-inject")]
pub fn maybe_crash(point: &str) {
    if std::env::var("CLOVE_CRASH_POINT").ok().as_deref() == Some(point) {
        std::process::exit(99);
    }
}

#[cfg(not(feature = "crash-inject"))]
#[inline]
pub fn maybe_crash(_point: &str) {}

fn tmp_path_for(path: &Path) -> std::path::PathBuf {
    let nonce = TMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    path.with_file_name(format!("{file_name}.tmp.{pid}.{stamp}.{nonce}"))
}

fn sync_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    // Best-effort: directory fsync is not available the same way on all platforms.
    let _ = OpenOptions::new().read(true).open(parent);
    Ok(())
}

/// Atomically replace `path` with `bytes`.
///
/// Always writes to a unique tmp file then renames. In [`DurabilityMode::Strict`],
/// also `sync_all`s the tmp file before rename.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: DurabilityMode) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| ClError::IoError(e.to_string()))?;
    }

    let tmp = tmp_path_for(path);
    let write_result = (|| -> Result<()> {
        {
            let mut file = File::create(&tmp).map_err(|e| ClError::IoError(e.to_string()))?;
            file.write_all(bytes)
                .map_err(|e| ClError::IoError(e.to_string()))?;
            if mode.is_strict() {
                file.sync_all()
                    .map_err(|e| ClError::IoError(e.to_string()))?;
            }
        }
        maybe_crash("after_tmp_sync");
        maybe_crash("before_rename");
        replace_file(&tmp, path)?;
        if mode.is_strict() {
            sync_dir(path)?;
        }
        maybe_crash("after_rename");
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

/// Give `tmp` the name `path` in one step. Where `path` exists it is replaced: at every moment the
/// name holds the whole old file or the whole new one, never nothing. (On Windows the standard
/// `rename` replaces an existing file in one system call; moving the old file aside first and
/// the new one in afterwards leaves a gap in which `path` does not exist.)
///
/// On Windows a file that another program has just opened without allowing deletion (a virus
/// scanner, a search indexer) makes the call fail for a moment, so it is tried a few times.
fn replace_file(tmp: &Path, path: &Path) -> Result<()> {
    const TRIES: u32 = 8;
    let mut attempt = 0;
    loop {
        match fs::rename(tmp, path) {
            Ok(()) => return Ok(()),
            Err(e) if cfg!(windows) && e.kind() == std::io::ErrorKind::PermissionDenied && attempt + 1 < TRIES => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(10 * u64::from(attempt)));
            }
            Err(e) => return Err(ClError::IoError(e.to_string())),
        }
    }
}

/// Serialize `value` as pretty JSON and atomically write it.
pub fn write_atomic_json<T: Serialize>(path: &Path, value: &T, mode: DurabilityMode) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_atomic(path, &bytes, mode)
}

/// True when bytes are empty, all NUL, or not valid UTF-8 JSON object/array start material.
pub fn is_corrupt_index_bytes(data: &[u8]) -> bool {
    if data.is_empty() || data.iter().all(|b| *b == 0) {
        return true;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return true;
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return true;
    }
    serde_json::from_str::<serde_json::Value>(trimmed).is_err()
}

/// Quarantine a corrupt index path to `*.corrupt.<unix_ts>` and remove the original name.
pub fn quarantine_corrupt_file(path: &Path, detail: &str) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // the whole name is kept, so two files with the same stem (`a.json`, `a.bin`) never share a name
    let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let dest = path.with_file_name(format!("{file_name}.corrupt.{ts}"));
    match fs::rename(path, &dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Fall back to delete if rename fails (e.g. cross-device).
            fs::remove_file(path).map_err(|e| {
                ClError::CorruptMigrationIndex {
                    path: path.display().to_string(),
                    detail: format!("{detail}; also failed to remove: {e}"),
                }
            })?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn atomic_write_roundtrip_strict() {
        let dir = PathBuf::from("./target/test_fsutil_strict");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.json");
        write_atomic(&path, br#"{"ok":true}"#, DurabilityMode::Strict).unwrap();
        let got = fs::read_to_string(&path).unwrap();
        assert!(got.contains("ok"));
        assert!(!is_corrupt_index_bytes(got.as_bytes()));
    }

    fn temp() -> PathBuf {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    #[test]
    fn replacing_a_file_leaves_the_new_content_and_nothing_else() {
        let dir = temp();
        let path = dir.join("store.keys");
        fs::write(&path, b"old").unwrap();
        write_atomic(&path, b"new", DurabilityMode::Strict).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(names(&dir), vec!["store.keys".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_is_open_for_reading_can_be_replaced() {
        let dir = temp();
        let path = dir.join("store.keys");
        fs::write(&path, b"old").unwrap();
        let reader = fs::File::open(&path).unwrap();
        write_atomic(&path, b"new", DurabilityMode::Strict).unwrap();
        drop(reader);
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(names(&dir), vec!["store.keys".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_name_always_holds_a_whole_file_when_a_write_is_cut_short() {
        // a process that stops after the temporary file was written and before the rename leaves the
        // old file in place with a temporary file next to it; the next write is not bothered by it
        let dir = temp();
        let path = dir.join("store.keys");
        fs::write(&path, b"old").unwrap();
        fs::write(dir.join("store.keys.tmp.1.2.3"), b"half").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"old");
        write_atomic(&path, b"new", DurabilityMode::Strict).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_temporary_name_keeps_the_whole_name_so_two_files_never_share_one() {
        let (a, b) = (Path::new("d/store.keys"), Path::new("d/store.cldb"));
        let (ta, tb) = (tmp_path_for(a), tmp_path_for(b));
        assert_ne!(ta, tb);
        assert!(ta.file_name().unwrap().to_string_lossy().starts_with("store.keys.tmp."));
        assert!(tb.file_name().unwrap().to_string_lossy().starts_with("store.cldb.tmp."));
    }

    #[test]
    fn detects_nul_corruption() {
        assert!(is_corrupt_index_bytes(&[]));
        assert!(is_corrupt_index_bytes(&[0, 0, 0, 0]));
        assert!(is_corrupt_index_bytes(b"not-json"));
        assert!(!is_corrupt_index_bytes(br#"{"a":1}"#));
    }

    #[test]
    fn two_quarantined_files_with_the_same_stem_keep_apart() {
        let dir = temp();
        fs::write(dir.join("a.json"), [0u8; 4]).unwrap();
        fs::write(dir.join("a.bin"), [0u8; 4]).unwrap();
        quarantine_corrupt_file(&dir.join("a.json"), "nul").unwrap();
        quarantine_corrupt_file(&dir.join("a.bin"), "nul").unwrap();
        let found = names(&dir);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().any(|n| n.starts_with("a.json.corrupt.")), "{found:?}");
        assert!(found.iter().any(|n| n.starts_with("a.bin.corrupt.")), "{found:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn quarantine_moves_file() {
        let dir = PathBuf::from("./target/test_fsutil_quarantine");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.json");
        fs::write(&path, &[0u8; 32]).unwrap();
        quarantine_corrupt_file(&path, "nul").unwrap();
        assert!(!path.exists());
        let found = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains("corrupt."));
        assert!(found);
    }
}
