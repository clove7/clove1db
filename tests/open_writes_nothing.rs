//! A failed open leaves the migration files alone, and two good opens in a row do not rewrite the root index. Plain and encrypted.
//! (The main `.cldb` is left out of the byte comparison on purpose: any writable open of it is redb's own open, which sets its recovery flag, saves its free-space
//! state and may change the file's size and internal pages, even when the library then rejects the layout. What a rejected open must not change is the tables'
//! contents, which the test reads back below, and every other file.)
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const TABLE: &str = "notes_table";
const TABLE2: &str = "second_table"; // two tables, so the order of the root index entries would show if it changed

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    n: i64,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Aux {
    id: String,
}
impl Entity for Aux {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same table registered with a different layout.
#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Other {
    id: String,
    n: i64,
    extra: String,
}
impl Entity for Other {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn config() -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[7; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[8; 32]))),
    }
}

fn base(root: &Path, encrypted: bool) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).backup_enabled(true).has_cache(false);
    if encrypted {
        db.encryption(config())
    } else {
        #[cfg(clove_test_encrypt_all)]
        {
            db.plain()
        }
        #[cfg(not(clove_test_encrypt_all))]
        {
            db
        }
    }
}

fn open_note(root: &Path, encrypted: bool) -> Result<Storage, ClError> {
    Storage::builder(StorageConfig::default()).add_database(base(root, encrypted).register::<Note>(TABLE).register::<Aux>(TABLE2)).build()
}

fn open_other(root: &Path, encrypted: bool) -> Result<Storage, ClError> {
    Storage::builder(StorageConfig::default()).add_database(base(root, encrypted).register::<Other>(TABLE).register::<Aux>(TABLE2)).build()
}

fn fresh_root() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

/// Every file under `dir` except the main `.cldb`, by relative path.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else if path.extension().is_none_or(|e| e != "cldb") {
                let rel = path.strip_prefix(base).unwrap().display().to_string();
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn seed(root: &Path, encrypted: bool) {
    let s = open_note(root, encrypted).unwrap();
    let rows: Vec<(String, String, Vec<u8>)> = (0..20)
        .map(|i| (TABLE.to_string(), format!("{i:04}"), serde_json::to_vec(&Note { id: format!("{i:04}"), n: i }).unwrap()))
        .collect();
    s.db_manager("store").commit_batch_atomic(&rows, &[]).unwrap();
    s.close();
}

fn run(encrypted: bool) {
    let root = fresh_root();
    seed(&root, encrypted);
    let dir = root.join("records");
    let before = snapshot(&dir);

    // a mismatching layout fails, and nothing but the main file's header may have changed
    match open_other(&root, encrypted) {
        Err(ClError::LayoutMismatch { .. }) => {}
        Err(e) => panic!("expected LayoutMismatch, got {e}"),
        Ok(_) => panic!("a different layout must not open"),
    }
    let after = snapshot(&dir);
    assert_eq!(before.keys().collect::<Vec<_>>(), after.keys().collect::<Vec<_>>(), "no file appeared or vanished");
    for (name, bytes) in &before {
        assert!(after[name] == *bytes, "{name} changed by a failed open");
    }
    // the failed open closed the main file cleanly: redb's recovery flag (bit 1 of the byte after the 9-byte magic) is clear, so the next open needs no repair
    if !encrypted && cfg!(not(clove_test_encrypt_all)) {
        let header = std::fs::read(dir.join("store.cldb")).unwrap();
        assert_eq!(header[9] & 2, 0, "a failed open leaves the main file clean, not needing repair");
    }

    // the next open with the right layout is clean: rows are all there, and the recovery flag of a plain file was cleared again
    let s = open_note(&root, encrypted).unwrap();
    assert_eq!(s.domain::<Note>().query().count().unwrap(), 20);
    for i in 0..20i64 {
        assert_eq!(s.domain::<Note>().query().filter(Note::n.eq(i)).count().unwrap(), 1, "row {i} is unchanged after the failed open");
    }
    s.close();
    if !encrypted && cfg!(not(clove_test_encrypt_all)) {
        let header = std::fs::read(dir.join("store.cldb")).unwrap();
        assert_eq!(header[9] & 2, 0, "the main file was closed cleanly (redb recovery flag clear)");
    }

    // two good opens in a row: the root index is not rewritten (bytes and modification time)
    let index = dir.join("store.migration").join("index.json");
    let first = snapshot(&dir);
    let stamp = |p: &Path| std::fs::metadata(p).ok().and_then(|m| m.modified().ok());
    let t1 = stamp(&index);
    let plain_bytes = if encrypted { Vec::new() } else { std::fs::read(&index).unwrap() };
    for _ in 0..2 {
        let s = open_note(&root, encrypted).unwrap();
        s.close();
    }
    let second = snapshot(&dir);
    let sidecars = |m: &BTreeMap<String, Vec<u8>>| m.keys().filter(|k| k.contains("migration")).cloned().collect::<Vec<_>>();
    assert_eq!(sidecars(&first), sidecars(&second), "the same migration files");
    if !encrypted {
        assert!(plain_bytes == std::fs::read(&index).unwrap(), "index.json bytes are the same");
        assert_eq!(t1, stamp(&index), "index.json was not written again");
    } else {
        // sealed files carry a new nonce on every write, so a rewrite shows as changed bytes
        for name in sidecars(&first) {
            assert!(first[&name] == second[&name], "{name} was rewritten by a good open");
        }
    }
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_failed_open_changes_no_migration_file_plain() {
    run(false);
}

#[test]
fn a_failed_open_changes_no_migration_file_encrypted() {
    run(true);
}

// ── looking at a file never changes it ──────────────────────────────────────────────────────────────────────────────

fn all_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                out.insert(path.strip_prefix(base).unwrap().display().to_string(), std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn assert_untouched(before: &BTreeMap<String, Vec<u8>>, after: &BTreeMap<String, Vec<u8>>, what: &str) {
    assert_eq!(before.keys().collect::<Vec<_>>(), after.keys().collect::<Vec<_>>(), "{what}: no file appeared or vanished");
    for (name, bytes) in before {
        assert!(after[name] == *bytes, "{what}: {name} changed");
    }
}

#[test]
fn inspecting_and_reading_a_migration_source_leave_a_plain_file_byte_for_byte_unchanged() {
    let root = fresh_root();
    seed(&root, false);
    let dir = root.join("records");
    let primary = dir.join("store.cldb");
    let before = all_files(&dir);
    let report = clove1db::inspect_cldb(&primary).unwrap();
    assert!(!report.tables.is_empty());
    assert_untouched(&before, &all_files(&dir), "inspect_cldb");
    let rows = clove1db::migration::clove::read_clove_table(&primary, TABLE).unwrap();
    assert_eq!(rows.len(), 20);
    assert_eq!(clove1db::migration::clove::list_clove_tables(&primary).unwrap().contains(&TABLE.to_string()), true);
    assert_untouched(&before, &all_files(&dir), "the migration readers");
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn inspecting_an_encrypted_file_leaves_it_byte_for_byte_unchanged() {
    let root = fresh_root();
    seed(&root, true);
    let dir = root.join("records");
    let primary = dir.join("store.cldb");
    let before = all_files(&dir);
    let handle = clove1db::encrypted_store::EncryptionHandle::new(config());
    let report = clove1db::metadata::inspect::inspect_cldb_with(&primary, Some(&handle)).unwrap();
    assert!(!report.tables.is_empty());
    assert_untouched(&before, &all_files(&dir), "inspect_cldb_with");
    std::fs::remove_dir_all(&root).ok();
}

#[test]
#[cfg(not(clove_test_encrypt_all))]
fn a_file_that_needs_repair_is_not_repaired_by_inspecting_it() {
    let root = fresh_root();
    seed(&root, false);
    let dir = root.join("records");
    let primary = dir.join("store.cldb");
    // what a crash leaves: the recovery flag set in the header
    let mut bytes = std::fs::read(&primary).unwrap();
    bytes[9] |= 2;
    std::fs::write(&primary, &bytes).unwrap();
    let before = all_files(&dir);
    for result in [clove1db::inspect_cldb(&primary).map(|_| ()), clove1db::migration::clove::read_clove_table(&primary, TABLE).map(|_| ())] {
        match result {
            Err(ClError::Validation(message)) => assert!(message.contains("open the database normally first"), "{message}"),
            other => panic!("expected the needs-repair error, got {:?}", other.map_err(|e| e.to_string())),
        }
    }
    assert_untouched(&before, &all_files(&dir), "inspecting a file that needs repair");
    // and a normal open still repairs it and finds every row
    let s = open_note(&root, false).unwrap();
    assert_eq!(s.domain::<Note>().query().count().unwrap(), 20);
    s.close();
    std::fs::remove_dir_all(&root).ok();
}
