//! Changing how a whole database is protected, end to end: plain to encrypted and back, other keys
//! and another cipher, a key that does not open it, a database that is open, a full disk, and the
//! rule that no clear value stays in any file of the folder.
use super::rows::{BatchLimits, FAIL_AFTER_BATCHES};
use super::space::Available;
use super::run::ChangeProtection;
use crate::{
    CloveFields, LibraryEvent, Unique,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::{EncryptionConfig, KeySource},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    name: String,
    n: i64,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct Doc {
    id: String,
}
impl Entity for Doc {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// A distinctive text that no ciphertext, name or number contains by chance.
const SECRET: &str = "swordfish-marker-7731";

fn keys(read: u8, cipher: CipherKind) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[read; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[read.wrapping_add(1); 32]))),
    }
}

fn aes(read: u8) -> EncryptionConfig {
    keys(read, CipherKind::Aes256GcmSiv)
}

fn config(root: &Path, protection: Option<EncryptionConfig>) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store")
        .dir_path(root.to_path_buf())
        .has_cache(false)
        .blob_enabled(true)
        .register::<Note>("notes")
        .register_blob::<Doc>("files")
        .unique::<Note>(Unique::on(Note::name));
    match protection {
        Some(config) => db.encryption(config),
        None => {
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
}

fn dir(root: &Path) -> PathBuf {
    root.join("records")
}

fn attachment(i: usize) -> Vec<u8> {
    let mut v = SECRET.as_bytes().to_vec();
    v.extend((0..(30_000 * i)).map(|k| (k % 251) as u8));
    v
}

/// A database with rows that carry the secret, three attachments, and two readers of the log.
fn make(protection: Option<EncryptionConfig>) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default()).add_database(config(&root, protection)).build().unwrap();
    let db = s.db_manager("store");
    for i in 0..40 {
        let note = Note { id: format!("n{i:02}"), name: format!("{SECRET}-{i}"), n: i };
        db.set(TableDefinition::new("notes"), "notes", &note.id, serde_json::to_vec(&note).unwrap()).unwrap();
    }
    for i in 0..3 {
        db.write_blob("files", &format!("f{i}"), &attachment(i + 1)).unwrap();
    }
    drop(db);
    s.close();
    root
}

/// What the database holds, read through a normal open: the rows and the attachments.
fn contents(root: &Path, protection: Option<EncryptionConfig>) -> (Vec<(String, Vec<u8>)>, Vec<Vec<u8>>) {
    let s = Storage::builder(StorageConfig::default()).add_database(config(root, protection)).build().unwrap();
    let db = s.db_manager("store");
    let rows = db.list_entries("notes").unwrap();
    let mut blobs = Vec::new();
    for i in 0..3 {
        let mut reader = db.open_blob("files", &format!("f{i}")).unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut bytes).unwrap();
        blobs.push(bytes);
    }
    drop(db);
    s.close();
    (rows, blobs)
}

fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
        if e.path().is_dir() {
            all_files(&e.path(), out);
        } else {
            out.push(e.path());
        }
    }
}

fn files_holding_the_secret(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    all_files(root, &mut files);
    files
        .into_iter()
        .filter(|p| std::fs::read(p).unwrap().windows(SECRET.len()).any(|w| w == SECRET.as_bytes()))
        .collect()
}

fn listing(root: &Path) -> Vec<(String, u64)> {
    let mut files = Vec::new();
    all_files(root, &mut files);
    let mut v: Vec<(String, u64)> =
        files.iter().map(|p| (p.strip_prefix(root).unwrap().display().to_string(), std::fs::metadata(p).unwrap().len())).collect();
    v.sort();
    v
}

fn nothing_of_a_migration_is_left(root: &Path) {
    for (name, _) in listing(root) {
        assert!(
            !name.contains(".mig-") && !name.contains(".migrating") && !name.contains(".creating"),
            "left behind: {name}"
        );
    }
}

fn change(root: &Path) -> ChangeProtection {
    ChangeProtection::new(root, "records", "store")
}

#[test]
fn plain_to_encrypted_keeps_every_row_and_attachment_and_leaves_no_clear_value_anywhere() {
    let root = make(None);
    let (rows, blobs) = contents(&root, None);
    assert!(!files_holding_the_secret(&root).is_empty(), "the test needs the secret to be readable at the start");
    let done = change(&root).to_whole_database(aes(5)).execute().unwrap();
    assert_eq!(done.attachments, 3);
    assert!(done.files_replaced >= 3);
    // every file of the folder, the history and the log and the indexes included
    assert_eq!(files_holding_the_secret(&root), Vec::<PathBuf>::new());
    nothing_of_a_migration_is_left(&root);
    // the same database, opened with the keys, with the same rows and attachments
    let (rows_after, blobs_after) = contents(&root, Some(aes(5)));
    assert_eq!(rows_after, rows);
    assert_eq!(blobs_after, blobs);
    // without the keys it does not open
    let err = Storage::builder(StorageConfig::default()).add_database(config(&root, None)).build();
    assert!(err.is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn encrypted_to_plain_and_back_to_other_keys_and_another_cipher() {
    let root = make(Some(aes(5)));
    let (rows, blobs) = contents(&root, Some(aes(5)));
    // other keys, another cipher: a new data key
    change(&root).from_whole_database(aes(5)).to_whole_database(keys(9, CipherKind::XChaCha20Poly1305)).execute().unwrap();
    assert_eq!(contents(&root, Some(keys(9, CipherKind::XChaCha20Poly1305))), (rows.clone(), blobs.clone()));
    assert!(Storage::builder(StorageConfig::default()).add_database(config(&root, Some(aes(5)))).build().is_err(), "the old keys no longer open it");
    assert_eq!(files_holding_the_secret(&root), Vec::<PathBuf>::new());
    // back to plain
    change(&root).from_whole_database(keys(9, CipherKind::XChaCha20Poly1305)).to_plain().execute().unwrap();
    assert_eq!(contents(&root, None), (rows, blobs));
    nothing_of_a_migration_is_left(&root);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_wrong_key_or_a_wrong_starting_point_touches_nothing() {
    let root = make(Some(aes(5)));
    let before = listing(&root);
    let wrong = change(&root).from_whole_database(aes(6)).to_plain().execute();
    assert!(matches!(wrong, Err(ClError::EncryptedOpenFailed)), "{wrong:?}");
    let not_encrypted = change(&root).from_plain().to_whole_database(aes(7)).execute();
    assert!(matches!(not_encrypted, Err(ClError::EncryptedOpenFailed)), "{not_encrypted:?}");
    assert!(change(&root).from_whole_database(aes(5)).to_whole_database(aes(5)).dry_run().is_ok());
    assert_eq!(listing(&root), before);
    let _ = std::fs::remove_dir_all(&root);
    let plain = make(None);
    let before = listing(&plain);
    let claimed = change(&plain).from_whole_database(aes(5)).to_plain().execute();
    assert!(matches!(claimed, Err(ClError::Validation(_))), "{claimed:?}");
    assert!(matches!(change(&plain).execute(), Err(ClError::Validation(_))), "plain to plain is nothing to do");
    assert_eq!(listing(&plain), before);
    let _ = std::fs::remove_dir_all(&plain);
}

#[test]
fn a_database_that_is_open_is_refused_before_anything_is_written() {
    let root = make(None);
    let s = Storage::builder(StorageConfig::default()).add_database(config(&root, None)).build().unwrap();
    let before = listing(&root);
    let result = change(&root).to_whole_database(aes(5)).execute();
    assert!(matches!(result, Err(ClError::DatabaseInUse { .. })), "{result:?}");
    assert_eq!(listing(&root).iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(), before.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>());
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_dry_run_names_every_table_and_writes_nothing() {
    let root = make(None);
    let before = listing(&root);
    let report = change(&root).to_whole_database(aes(5)).dry_run().unwrap();
    assert_eq!(listing(&root), before);
    let named = |n: &str| report.tables.iter().find(|t| t.name == n).unwrap_or_else(|| panic!("{n} is not in the report"));
    assert_eq!((named("notes").how, named("notes").entries), ("copied", 40));
    assert_eq!(named("__lastwrite").how, "rebuilt");
    assert_eq!(named("__changes").how, "written again");
    assert_eq!(report.attachments, 3);
    assert_eq!(report.attachment_bytes, attachment(1).len() as u64 + attachment(2).len() as u64 + attachment(3).len() as u64);
    assert!(report.required_bytes > 0);
    assert!(report.replaces.iter().any(|n| n == "store.cldb"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn less_room_than_needed_is_refused_before_anything_is_written() {
    let root = make(None);
    let before = listing(&root);
    let need = change(&root).to_whole_database(aes(5)).dry_run().unwrap().required_bytes;
    let result = change(&root).to_whole_database(aes(5)).available_bytes(Available { main: Some(need - 1), backup: None }).execute();
    assert!(matches!(&result, Err(ClError::MigrationError(m)) if m.contains("not enough room")), "{result:?}");
    assert_eq!(listing(&root), before);
    // exactly enough is enough
    change(&root).to_whole_database(aes(5)).available_bytes(Available { main: Some(need), backup: None }).execute().unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_full_disk_at_any_batch_puts_the_database_back_exactly() {
    let root = make(None);
    let before = listing(&root);
    let bytes: Vec<(PathBuf, Vec<u8>)> = {
        let mut files = Vec::new();
        all_files(&root, &mut files);
        files.into_iter().map(|p| { let b = std::fs::read(&p).unwrap(); (p, b) }).collect()
    };
    let small = BatchLimits { max_rows: 5, max_bytes: 2048 };
    let mut failures = 0;
    for after in (0..60).step_by(3) {
        FAIL_AFTER_BATCHES.with(|n| n.set(after));
        let result = change(&root).to_whole_database(aes(5)).batch_limits(small).execute();
        FAIL_AFTER_BATCHES.with(|n| n.set(-1));
        if result.is_ok() {
            // the failure came later than the work: the migration ran to the end; put it back
            let back = change(&root).from_whole_database(aes(5)).to_plain().execute();
            assert!(back.is_ok(), "{back:?}");
            break;
        }
        failures += 1;
        assert!(matches!(&result, Err(ClError::IoError(m)) if m.contains("no space")), "{result:?}");
        assert_eq!(listing(&root), before, "after {after} batches the folder is not as it was");
        for (path, original) in &bytes {
            assert_eq!(&std::fs::read(path).unwrap(), original, "{} changed", path.display());
        }
        nothing_of_a_migration_is_left(&root);
    }
    assert!(failures >= 5, "the failure was injected {failures} times");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_stages_are_reported_without_any_value() {
    let root = make(None);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    change(&root)
        .to_whole_database(aes(5))
        .on_event(move |e| {
            if let LibraryEvent::Migration { event, files, rows } = e {
                sink.lock().unwrap().push((*event, *files, *rows));
            }
        })
        .execute()
        .unwrap();
    let events = seen.lock().unwrap().clone();
    let names: Vec<&str> = events.iter().map(|(e, _, _)| *e).collect();
    assert_eq!(names, vec!["migration/started", "migration/committed", "migration/finished"]);
    assert!(events[1].2 > 0, "the rows copied are counted");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_old_files_are_overwritten_before_they_go_when_asked() {
    let root = make(None);
    // a second name for the old main file keeps its bytes reachable after the name is removed
    let watch = dir(&root).join("watch");
    // the hard link is made once the old name has been moved aside, so it is made by hand here:
    // run the migration to the point after the swap by using the marker steps directly
    std::fs::hard_link(dir(&root).join("store.cldb"), &watch).unwrap();
    let before = std::fs::read(&watch).unwrap();
    change(&root).to_whole_database(aes(5)).wipe_originals(true).execute().unwrap();
    let after = std::fs::read(&watch).unwrap();
    assert_eq!(after.len(), before.len());
    assert_ne!(after, before, "the old file was only removed");
    assert!(after.windows(SECRET.len()).all(|w| w != SECRET.as_bytes()));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_build_that_fails_never_removes_files_that_a_cut_short_change_put_in_place() {
    use super::marker::{Migration, Places, Root, Target};
    // the change was cut short after its decision and in the middle of the swap: the main file is
    // moved aside and its new version is waiting under its temporary name
    let root = make(None);
    let (folder, db) = (dir(&root), "store");
    let (main, new) = (folder.join("store.cldb"), folder.join("store.cldb.mig-new"));
    {
        let places = Places { main: &folder, backup: &folder };
        let m = Migration::begin(places, db, vec![Target::new(Root::Main, "store.cldb", true)]).unwrap();
        std::fs::copy(&main, &new).unwrap();
        m.commit().unwrap();
        m.aside(0).unwrap();
        assert!(!main.exists());
    }
    // opened with keys that do not fit: the open fails, and the database is still there
    let result = Storage::builder(StorageConfig::default()).add_database(config(&root, Some(aes(5)))).build();
    assert!(result.is_err());
    assert!(main.is_file(), "the build that failed removed the main file the settling had put in place");
    nothing_of_a_migration_is_left(&root);
    // and it opens the way it is
    assert_eq!(contents(&root, None).0.len(), 40);
    let _ = std::fs::remove_dir_all(&root);
}

fn read_key_only(read: u8) -> EncryptionConfig {
    EncryptionConfig { search: None, ..aes(read) }
}

#[test]
fn a_program_with_only_the_read_key_opens_a_database_whose_change_was_cut_short_in_the_swap() {
    use super::marker::{Migration, Places, Root, Target};
    // the main file is moved aside and its new, encrypted version waits under its temporary name:
    // to the settings check that looks like a new database, which would ask for the search key
    let root = make(Some(aes(5)));
    let folder = dir(&root);
    let (main, new) = (folder.join("store.cldb"), folder.join("store.cldb.mig-new"));
    {
        let places = Places { main: &folder, backup: &folder };
        let m = Migration::begin(places, "store", vec![Target::new(Root::Main, "store.cldb", true)]).unwrap();
        std::fs::copy(&main, &new).unwrap();
        m.commit().unwrap();
        m.aside(0).unwrap();
        assert!(!main.exists());
    }
    let s = Storage::builder(StorageConfig::default()).add_database(config(&root, Some(read_key_only(5)))).build().unwrap();
    assert_eq!(s.db_manager("store").list_entries("notes").unwrap().len(), 40);
    s.close();
    nothing_of_a_migration_is_left(&root);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_migration_that_is_running_makes_the_build_fail_before_any_database_is_touched() {
    use super::marker::{Migration, Places, Root, Target};
    // two databases: the first has a change cut short (its marker is free), the second is being
    // changed right now (its marker is locked): the build fails, and the first is not settled
    let (a, b) = (make(None), make(None));
    let (da, db_) = (dir(&a), dir(&b));
    let places_a = Places { main: &da, backup: &da };
    let places_b = Places { main: &db_, backup: &db_ };
    {
        // cut short: the marker is dropped (the lock is free) with a new file waiting
        let m = Migration::begin(places_a, "store", vec![Target::new(Root::Main, "store.inx", false)]).unwrap();
        drop(m);
    }
    let live = Migration::begin(places_b, "other", vec![Target::new(Root::Main, "other.inx", false)]).unwrap();
    let both = || {
        Storage::builder(StorageConfig::default())
            .add_database(config(&a, None))
            .add_database(DatabaseConfig::new("records", "other").dir_path(b.clone()).has_cache(false).register::<Doc>("things"))
            .build()
    };
    let result = both();
    assert!(matches!(result, Err(ClError::DatabaseInUse { .. })), "{:?}", result.err());
    assert!(da.join("store.migrating").exists(), "the first database was settled although the build was refused");
    drop(live);
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
}

#[test]
fn a_database_with_protected_fields_is_refused_for_now_and_nothing_is_touched() {
    use crate::field_crypto::Sealed;
    #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
    struct Person {
        id: String,
        #[clove(encrypt, id = 1)]
        phone: Sealed<String>,
    }
    impl Entity for Person {
        fn entity_id(&self) -> &str {
            &self.id
        }
    }
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let db = DatabaseConfig::new("records", "store").dir_path(root.clone()).has_cache(false).encryption(aes(5)).register_sealed::<Person>("people");
    Storage::builder(StorageConfig::default()).add_database(db).build().unwrap().close();
    let before = listing(&root);
    let result = change(&root).from_whole_database(aes(5)).to_whole_database(aes(6)).execute();
    assert!(matches!(&result, Err(ClError::MigrationError(m)) if m.contains("protected fields")), "{result:?}");
    assert_eq!(listing(&root), before);
    let _ = std::fs::remove_dir_all(&root);
}
