//! The whole directory of an encrypted database: side files and attachments sealed, names that
//! show nothing, a derived file rebuilt, history that is never replaced by something invented,
//! and events with fixed names.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const TABLE: &str = "secret_notes_table";
const BLOBS: &str = "secret_scan_files";
const MARKER: &str = "MARKER-77aa21d0-91ce";
const ID: &str = "ID-MARKER-3b9f";

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
struct Scan {
    id: String,
    title: String,
}
impl Entity for Scan {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

type Events = Arc<Mutex<Vec<String>>>;

fn config(read: u8) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha512 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[read; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[201; 32]))),
    }
}

fn build(root: &Path, key: u8, events: &Events) -> Result<Storage, ClError> {
    let sink = events.clone();
    let storage = StorageConfig::default().event_sink(move |e| {
        if let LibraryEvent::Encryption { event, file } = e {
            sink.lock().unwrap().push(format!("{event}@{file}"));
        }
    });
    Storage::builder(storage)
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root.to_path_buf())
                .backup_enabled(true)
                .blob_enabled(true)
                .has_cache(false)
                .encryption(config(key))
                .register::<Note>(TABLE)
                .register_blob::<Scan>(BLOBS),
        )
        .build()
}

fn fresh_root() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

fn rows(count: usize) -> Vec<(String, String, Vec<u8>)> {
    (0..count)
        .map(|i| {
            let id = format!("{MARKER}-{i:03}");
            (TABLE.to_string(), id.clone(), serde_json::to_vec(&Note { id, n: i as i64 }).unwrap())
        })
        .collect()
}

fn blob_bytes(len: usize) -> Vec<u8> {
    let mut v = format!("{MARKER}-blob-").into_bytes();
    while v.len() < len {
        v.push(b'a' + (v.len() % 23) as u8);
    }
    v
}

fn all_paths(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        out.push(p.clone());
        if p.is_dir() {
            out.extend(all_paths(&p));
        }
    }
    out
}

/// Nothing readable in any name or byte under `root`, apart from the names the programmer chose.
fn scan(root: &Path, step: &str) {
    let needles: [&[u8]; 8] = [
        MARKER.as_bytes(),
        TABLE.as_bytes(),
        BLOBS.as_bytes(),
        ID.as_bytes(),
        b"redb",
        b"clove",
        b"index_version",
        b"schema_id",
    ];
    for path in all_paths(root) {
        let rel = path.strip_prefix(root).unwrap().to_string_lossy().to_lowercase();
        // the folder, the database name and its file extensions are the programmer's own
        let below_chosen = rel.replace("records", "").replace("store", "");
        for bad in ["marker", "secret", "scan", "id-marker", "index.json", "manifest", "layouts", "refs", "tables", ".json"] {
            assert!(!below_chosen.contains(bad), "{step}: the path {rel} shows {bad}");
        }
        if path.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            for n in needles {
                assert!(!bytes.windows(n.len()).any(|w| w == n), "{step}: {rel} contains {:?}", String::from_utf8_lossy(n));
            }
            let (mut run, mut longest) = (0usize, 0usize);
            for b in &bytes {
                run = if *b == 0 { run + 1 } else { 0 };
                longest = longest.max(run);
            }
            assert!(longest < 16, "{step}: {rel} has {longest} zero bytes in a row");
        }
    }
}

fn migration_dir(root: &Path) -> PathBuf {
    std::fs::read_dir(root.join("records"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir() && !p.to_string_lossy().ends_with(".blobs"))
        .expect("the migration folder")
}

fn files_in(dir: &Path) -> Vec<PathBuf> {
    all_paths(dir).into_iter().filter(|p| p.is_file()).collect()
}

fn make(root: &Path, events: &Events) {
    let s = build(root, 1, events).unwrap();
    let db = s.db_manager("store");
    db.commit_batch_atomic(&rows(80), &[]).unwrap();
    db.write_blob(BLOBS, ID, &blob_bytes(200_000)).unwrap();
    s.close();
}

#[test]
fn nothing_is_readable_anywhere_in_the_directory_at_every_step() {
    let root = fresh_root();
    let events: Events = Default::default();
    let s = build(&root, 1, &events).unwrap();
    s.close();
    scan(&root, "after creating");
    let s = build(&root, 1, &events).unwrap();
    let db = s.db_manager("store");
    db.commit_batch_atomic(&rows(100), &[]).unwrap();
    db.write_blob(BLOBS, ID, &blob_bytes(300_000)).unwrap();
    db.write_blob(BLOBS, &format!("{ID}-2"), &blob_bytes(5)).unwrap();
    s.close();
    scan(&root, "after writing rows and attachments");
    let s = build(&root, 1, &events).unwrap();
    let mut back = Vec::new();
    s.db_manager("store").open_blob(BLOBS, ID).unwrap().read_to_end(&mut back).unwrap();
    assert_eq!(back, blob_bytes(300_000));
    assert_eq!(s.db_manager("store").open_blob(BLOBS, &format!("{ID}-2")).unwrap().len().unwrap(), blob_bytes(5).len() as u64);
    assert!(s.db_manager("store").delete_blob(BLOBS, &format!("{ID}-2")).unwrap());
    s.close();
    scan(&root, "after reading and deleting");
    // reopening cleans what no row refers to
    let s = build(&root, 1, &events).unwrap();
    s.close();
    scan(&root, "after reopening");
    assert!(events.lock().unwrap().is_empty(), "events without a cause: {:?}", events.lock().unwrap());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_changed_attachment_block_is_data_tampered_and_never_other_bytes() {
    let root = fresh_root();
    let events: Events = Default::default();
    make(&root, &events);
    let blobs = root.join("records").join("store.blobs");
    let file = files_in(&blobs).into_iter().next().expect("an attachment file");
    let original = std::fs::read(&file).unwrap();
    let mut changed = original.clone();
    let mid = changed.len() / 2;
    changed[mid] ^= 0x08;
    std::fs::write(&file, &changed).unwrap();
    // the open checks the attachments' last blocks; a change elsewhere shows when it is read
    match build(&root, 1, &events) {
        Err(ClError::DataTampered) => {}
        Ok(s) => {
            let mut out = Vec::new();
            let e = s.db_manager("store").open_blob(BLOBS, ID).and_then(|mut r| r.read_to_end(&mut out).map_err(ClError::from));
            assert!(matches!(e, Err(ClError::DataTampered)), "read {} bytes: {e:?}", out.len());
            s.close();
        }
        Err(other) => panic!("{other:?}"),
    }
    std::fs::write(&file, &original).unwrap();
    build(&root, 1, &events).unwrap().close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unreferenced_attachments_under_masked_names_are_removed_on_reopen_and_the_used_one_stays() {
    let root = fresh_root();
    let events: Events = Default::default();
    make(&root, &events);
    let blobs = root.join("records").join("store.blobs");
    let used = files_in(&blobs);
    assert_eq!(used.len(), 1, "one attachment was written: {used:?}");
    let used = used.into_iter().next().unwrap();
    let table_dir = used.parent().unwrap().to_path_buf();
    // a file nobody refers to, with a name that means nothing, and an authentic copy of the real one
    // under another name (a stray that would open fine if anything pointed at it)
    let stray_junk = table_dir.join("0123456789abcdef");
    let stray_copy = table_dir.join("fedcba9876543210");
    std::fs::write(&stray_junk, b"unpublished").unwrap();
    std::fs::copy(&used, &stray_copy).unwrap();
    assert_eq!(files_in(&blobs).len(), 3);
    let s = build(&root, 1, &events).unwrap();
    assert!(!stray_junk.exists(), "the junk file was not removed");
    assert!(!stray_copy.exists(), "the unreferenced copy was not removed");
    assert!(used.exists(), "the attachment that is in use was removed");
    let mut back = Vec::new();
    s.db_manager("store").open_blob(BLOBS, ID).unwrap().read_to_end(&mut back).unwrap();
    assert_eq!(back, blob_bytes(200_000));
    s.close();
    scan(&root, "after removing strays");
    assert!(events.lock().unwrap().is_empty(), "events without a cause: {:?}", events.lock().unwrap());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_root_index_that_fails_is_set_aside_and_built_again_with_everything_else_the_same() {
    let root = fresh_root();
    let events: Events = Default::default();
    make(&root, &events);
    let dir = migration_dir(&root);
    let top: Vec<PathBuf> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_file()).collect();
    assert_eq!(top.len(), 1, "exactly one file at the top of the migration folder: {top:?}");
    let nested_before: Vec<(PathBuf, Vec<u8>)> = files_in(&dir)
        .into_iter()
        .filter(|p| *p != top[0])
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect();
    assert!(!nested_before.is_empty());
    for damage in ["flip", "garbage", "empty"] {
        let mut bytes = std::fs::read(&top[0]).unwrap();
        match damage {
            "flip" => {
                let i = bytes.len() - 5;
                bytes[i] ^= 1;
            }
            "garbage" => bytes = (0..bytes.len()).map(|i| (i * 7) as u8).collect(),
            _ => bytes.clear(),
        }
        std::fs::write(&top[0], &bytes).unwrap();
        events.lock().unwrap().clear();
        let s = build(&root, 1, &events).unwrap_or_else(|e| panic!("{damage}: {e:?}"));
        assert_eq!(s.db_manager("store").read_view_at_head().unwrap().table_entries(TABLE).unwrap().len(), 80, "{damage}");
        let mut back = Vec::new();
        s.db_manager("store").open_blob(BLOBS, ID).unwrap().read_to_end(&mut back).unwrap();
        assert_eq!(back, blob_bytes(200_000), "{damage}");
        s.close();
        assert!(events.lock().unwrap().iter().any(|e| e == "encryption/sidecar_set_aside@sidecar"), "{damage}: {:?}", events.lock().unwrap());
        // the table chains, layouts and records are the very same bytes as before
        for (path, before) in &nested_before {
            assert_eq!(&std::fs::read(path).unwrap(), before, "{damage}: {} changed", path.display());
        }
        // and a new root index stands where the old one was
        let now: Vec<PathBuf> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_file()).collect();
        assert!(now.iter().any(|p| *p == top[0]), "{damage}: no new root index");
        assert!(now.iter().any(|p| p.to_string_lossy().contains(".aside.")), "{damage}: the old one was not kept");
        for aside in now.iter().filter(|p| p.to_string_lossy().contains(".aside.")) {
            std::fs::remove_file(aside).unwrap();
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_changed_table_chain_file_is_never_replaced_by_an_empty_one() {
    let root = fresh_root();
    let events: Events = Default::default();
    make(&root, &events);
    let dir = migration_dir(&root);
    let top: Vec<PathBuf> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_file()).collect();
    let nested: Vec<PathBuf> = files_in(&dir).into_iter().filter(|p| !top.contains(p)).collect();
    assert!(nested.len() >= 2, "a table index and a layout at least: {nested:?}");
    for file in nested {
        let original = std::fs::read(&file).unwrap();
        let mut changed = original.clone();
        let mid = changed.len() / 2;
        changed[mid] ^= 0x20;
        std::fs::write(&file, &changed).unwrap();
        let opened = build(&root, 1, &events);
        assert!(matches!(opened, Err(ClError::DataTampered)), "{}: {:?}", file.display(), opened.map(|s| s.close()));
        // moved to the place of another side file, the same
        std::fs::write(&file, &original).unwrap();
        build(&root, 1, &events).unwrap().close();
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_causes_of_failures_are_events_with_fixed_names() {
    let root = fresh_root();
    let events: Events = Default::default();
    make(&root, &events);
    let wrong = build(&root, 2, &events);
    assert!(matches!(wrong, Err(ClError::EncryptedOpenFailed)));
    assert_eq!(events.lock().unwrap().as_slice(), ["encryption/open_failed/lock_rejected@main"]);
    events.lock().unwrap().clear();
    // a damaged index file: set aside, rebuilt, reported
    let inx = root.join("records").join("store.inx");
    let mut bytes = std::fs::read(&inx).unwrap();
    for pos in (8192..bytes.len()).step_by(4096) {
        bytes[pos] ^= 0x40;
    }
    std::fs::write(&inx, &bytes).unwrap();
    build(&root, 1, &events).unwrap().close();
    assert!(events.lock().unwrap().iter().any(|e| e == "encryption/index_rebuilt@index"), "{:?}", events.lock().unwrap());
    // no event ever carries anything but its fixed text
    for e in events.lock().unwrap().iter() {
        assert!(e.starts_with("encryption/") && !e.contains(MARKER) && !e.contains(TABLE), "{e}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

// ---- a real migration on encrypted databases ------------------------------------------------------

#[derive(Clone, Default, Serialize, Deserialize)]
struct OldItem {
    price: f64,
}
impl Entity for OldItem {
    fn entity_id(&self) -> &str {
        "old"
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct NewItem {
    id: String,
    old_id: String,
    price: f64,
}
impl Entity for NewItem {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

impl clove1db::migration::MigrateTo<NewItem> for OldItem {
    fn migrate_json(value: serde_json::Value) -> Result<clove1db::migration::MigrateOutcome<serde_json::Value>, ClError> {
        let row: OldItem = serde_json::from_value(value)?;
        clove1db::migration::migrate_value(NewItem { id: "item-1".into(), old_id: "old-1".into(), price: row.price })
    }
}

fn migration_storage(root: &Path, events: &Events) -> Result<Storage, ClError> {
    let sink = events.clone();
    let storage = StorageConfig::default().event_sink(move |e| {
        if let LibraryEvent::Encryption { event, file } = e {
            sink.lock().unwrap().push(format!("{event}@{file}"));
        }
    });
    Storage::builder(storage)
        .migration_step::<OldItem, NewItem>()
        .add_database(
            DatabaseConfig::new("old", "old")
                .dir_path(root.join("old"))
                .has_cache(false)
                .encryption(config(1))
                .register::<OldItem>("old_items"),
        )
        .add_database(
            DatabaseConfig::new("items", "items")
                .dir_path(root.join("items"))
                .has_cache(false)
                .encryption(config(1))
                .register::<NewItem>("items"),
        )
        .build()
}

#[test]
fn a_real_migration_works_on_encrypted_databases_and_its_manifest_cannot_be_changed() {
    let root = fresh_root();
    let events: Events = Default::default();
    let storage = migration_storage(&root, &events).unwrap();
    storage
        .db_manager("old")
        .commit_batch(
            &[("old_items".to_string(), "old-1".to_string(), serde_json::to_vec(&OldItem { price: 12.5 }).unwrap())],
            &[],
        )
        .unwrap();
    let mut run = storage
        .migrate::<OldItem, NewItem>()
        .from_db("old", "old_items")
        .to(clove1db::migration::MigrationTo::new("items").table("items"))
        .on_target_conflict(clove1db::migration::TargetConflictPolicy::Skip);
    run.dry_run().unwrap();
    let done = run.execute().unwrap();
    assert_eq!(done.records_migrated, 1);
    let check = |s: &Storage| {
        let db = s.db_manager("items");
        let raw = db.get_raw("items", "item-1").unwrap().expect("the migrated row");
        let item: NewItem = serde_json::from_slice(&raw).unwrap();
        assert_eq!((item.old_id.as_str(), item.price), ("old-1", 12.5));
        assert_eq!(db.migration_index().unwrap().table_chain("items").unwrap().manifests.len(), 1);
        // the stored layout of the new version is readable through the database
        assert!(!db.table_layout("items").unwrap().layout_hash.is_empty());
    };
    check(&storage);
    storage.close();
    // after a reopen the history is still there and the data is right
    let again = migration_storage(&root, &events).unwrap();
    check(&again);
    again.close();
    // the migration made the index out of date: set aside and built again, with a fixed event
    assert!(events.lock().unwrap().iter().all(|e| e == "encryption/index_rebuilt@index"), "{:?}", events.lock().unwrap());
    scan(&root, "after the migration");

    // every file of the new database's history, the manifest among them: a changed byte is an error
    let dir = migration_dir_of(&root.join("items").join("items"));
    let top: Vec<PathBuf> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_file()).collect();
    // tables/<table>/<id>/<file> and tables/<table>/index.json, layouts/<file>: read when the
    // database opens. The snapshot copies below `refs` are read only when a restore needs them
    // (their tamper check is in encrypted_sidecar.rs), so they are not part of this loop.
    let depth = |p: &PathBuf| p.strip_prefix(&dir).unwrap().components().count();
    let nested: Vec<PathBuf> = files_in(&dir).into_iter().filter(|p| !top.contains(p) && depth(p) <= 4).collect();
    assert!(nested.len() >= 3, "index, layout and manifest at least: {nested:?}");
    assert!(files_in(&dir).iter().any(|p| depth(p) == 5), "the snapshot copy of the migration");
    // the manifest is the file that sits next to the `refs` folder of the migration
    let manifest = files_in(&dir)
        .into_iter()
        .find(|p| depth(p) == 5)
        .map(|r| r.parent().unwrap().parent().unwrap().to_path_buf())
        .and_then(|mid| nested.iter().find(|p| p.parent() == Some(mid.as_path())).cloned())
        .expect("the manifest of the migration");
    let mut accepted = Vec::new();
    for file in &nested {
        let original = std::fs::read(file).unwrap();
        let mut changed = original.clone();
        let mid = changed.len() / 2;
        changed[mid] ^= 0x20;
        std::fs::write(file, &changed).unwrap();
        let opened = migration_storage(&root, &events);
        match opened {
            Err(ClError::DataTampered) => {}
            Ok(s) => {
                s.close();
                assert_ne!(*file, manifest, "a changed manifest was accepted");
                accepted.push(file.clone());
            }
            Err(e) => panic!("{}: {e:?}", file.display()),
        }
        std::fs::write(file, &original).unwrap();
        check(&migration_storage(&root, &events).unwrap());
    }
    // only a layout of an older version is not read when the database opens
    assert!(accepted.len() <= 1, "files that were accepted although changed: {accepted:?}");
    // a manifest that is gone is history that was removed, never an empty history
    let original = std::fs::read(&manifest).unwrap();
    std::fs::remove_file(&manifest).unwrap();
    let opened = migration_storage(&root, &events);
    assert!(matches!(opened, Err(ClError::DataTampered)), "{:?}", opened.map(|s| s.close()));
    std::fs::write(&manifest, &original).unwrap();
    check(&migration_storage(&root, &events).unwrap());
    let _ = std::fs::remove_dir_all(&root);
}

fn migration_dir_of(db_dir: &Path) -> PathBuf {
    std::fs::read_dir(db_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir() && !p.to_string_lossy().ends_with(".blobs"))
        .expect("the migration folder")
}
