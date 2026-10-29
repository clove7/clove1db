//! Attachments and migration records read in one form and written in the other.
use super::sidecars::{Blob, Form, copy_blobs, copy_records, plan_blobs, plan_records, unused_plain_blobs, verify_blobs, verify_records};
use crate::{
    encrypted_store::{EncryptionConfig, EncryptionContext, EncryptionHandle, KeySource, OpenOptionsExt},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use crate::crypto::{CipherKind, HkdfHash, Key32, KeySuite};
use redb::Database;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct File {
    id: String,
}
impl Entity for File {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn context(dir: &Path, key: u8) -> EncryptionContext {
    let config = EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[key; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[key.wrapping_add(1); 32]))),
    };
    let db = EncryptionHandle::new(config)
        .open_file(&dir.join(format!("k{key}.cldb")), "main", true, &OpenOptionsExt::default(), &mut |_| {})
        .unwrap();
    db.context()
}

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// A plain database with three attachments (one of them several sealed pieces long).
fn source() -> (PathBuf, Vec<(&'static str, Vec<u8>)>) {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let db = DatabaseConfig::new("records", "store")
        .dir_path(root.clone())
        .blob_enabled(true)
        .register_blob::<File>("files");
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    let s = Storage::builder(StorageConfig::default()).add_database(db).build().unwrap();
    let files = vec![("a", data(10, 1)), ("b", data(200_000, 2)), ("c", Vec::new())];
    for (id, bytes) in &files {
        s.db_manager("store").write_blob("files", id, bytes).unwrap();
    }
    s.close();
    (root, files)
}

fn main_file(root: &Path) -> PathBuf {
    root.join("records").join("store.cldb")
}

#[test]
fn the_attachments_are_the_ones_the_main_file_refers_to_and_go_both_ways() {
    let (root, files) = source();
    let main = Database::open(main_file(&root)).unwrap();
    let blobs = plan_blobs(&main).unwrap();
    assert_eq!(blobs.len(), 3);
    for (id, bytes) in &files {
        assert!(blobs.iter().any(|b| b.id.contains(id) || b.size == bytes.len() as u64), "{id}");
    }
    let sizes: Vec<u64> = { let mut s: Vec<u64> = blobs.iter().map(|b| b.size).collect(); s.sort(); s };
    assert_eq!(sizes, vec![0, 10, 200_000]);
    let old = root.join("records").join("store.blobs");
    assert_eq!(unused_plain_blobs(&old, &blobs).unwrap(), 0);
    let ctx = context(&root, 7);
    let (plain, sealed) = (Form::Plain, Form::Sealed(ctx));
    // plain to sealed: nothing readable is written
    let new = root.join("records").join("store.blobs.mig-new");
    let total = copy_blobs(&blobs, &plain, &old, &sealed, &new, true).unwrap();
    assert_eq!(total, 200_010);
    verify_blobs(&blobs, &plain, &old, &sealed, &new).unwrap();
    let mut names = Vec::new();
    let mut contents = Vec::new();
    fn walk(dir: &Path, names: &mut Vec<String>, contents: &mut Vec<Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
            names.push(e.file_name().to_string_lossy().into_owned());
            if e.path().is_dir() {
                walk(&e.path(), names, contents);
            } else {
                contents.push(std::fs::read(e.path()).unwrap());
            }
        }
    }
    walk(&new, &mut names, &mut contents);
    assert_eq!(contents.len(), 3);
    assert!(names.iter().all(|n| !n.contains("files") && !blobs.iter().any(|b| n.contains(&b.id))), "{names:?}");
    let marker = data(64, 2);
    let marker = &marker[..];
    assert!(
        contents.iter().all(|c| !c.windows(marker.len()).any(|w| w == &data(200_000, 2)[..marker.len()])),
        "a sealed file holds the bytes in the clear"
    );
    // and back
    let back = root.join("records").join("store.blobs.back");
    copy_blobs(&blobs, &sealed, &new, &plain, &back, true).unwrap();
    verify_blobs(&blobs, &plain, &old, &plain, &back).unwrap();
    drop(main);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_missing_or_changed_attachment_stops_the_copy() {
    let (root, _) = source();
    let main = Database::open(main_file(&root)).unwrap();
    let blobs = plan_blobs(&main).unwrap();
    let old = root.join("records").join("store.blobs");
    let big = blobs.iter().find(|b| b.size == 200_000).unwrap();
    // one byte short
    let path = old.join(&big.table).join(&big.id);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.pop();
    std::fs::write(&path, bytes).unwrap();
    let ctx = context(&root, 7);
    let err = copy_blobs(&blobs, &Form::Plain, &old, &Form::Sealed(ctx.clone()), &root.join("n1"), false).unwrap_err();
    assert!(matches!(&err, ClError::MigrationError(m) if m.contains("bytes")), "{err:?}");
    // gone
    std::fs::remove_file(&path).unwrap();
    assert!(copy_blobs(&blobs, &Form::Plain, &old, &Form::Sealed(ctx), &root.join("n2"), false).is_err());
    // a file that no row refers to is counted, not moved
    std::fs::write(old.join(&big.table).join("stray"), b"x").unwrap();
    assert_eq!(unused_plain_blobs(&old, &blobs).unwrap(), 1);
    drop(main);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_sealed_attachment_cannot_be_read_with_another_key_and_a_changed_byte_is_found() {
    let (root, _) = source();
    let main = Database::open(main_file(&root)).unwrap();
    let blobs = plan_blobs(&main).unwrap();
    let old = root.join("records").join("store.blobs");
    let (one, other) = (context(&root, 7), context(&root, 9));
    let new = root.join("sealed");
    copy_blobs(&blobs, &Form::Plain, &old, &Form::Sealed(one.clone()), &new, false).unwrap();
    assert!(verify_blobs(&blobs, &Form::Plain, &old, &Form::Sealed(other), &new).is_err());
    // change one byte of the biggest sealed file
    let big = blobs.iter().find(|b| b.size == 200_000).unwrap();
    let store = crate::encrypted_store::SealedBlobStore::new(&new, one.clone());
    let path = store.path(&big.table, &big.id).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(verify_blobs(&blobs, &Form::Plain, &old, &Form::Sealed(one), &new).is_err());
    drop(main);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_migration_records_follow_the_files_that_name_each_other() {
    let (root, _) = source();
    let old = root.join("records").join("store.migration");
    let tables = vec!["files".to_string()];
    let ctx = context(&root, 7);
    let (plain, sealed) = (Form::Plain, Form::Sealed(ctx));
    let records = plan_records(&plain, &old, &tables).unwrap();
    assert!(records.iter().any(|p| p == &vec!["index.json".to_string()]));
    assert!(records.iter().any(|p| p.last().is_some_and(|f| f.starts_with('v') && f.ends_with(".json"))), "{records:?}");
    let new = root.join("records").join("store.migration.mig-new");
    copy_records(&records, &plain, &old, &sealed, &new, true).unwrap();
    verify_records(&records, &plain, &old, &sealed, &new).unwrap();
    // following the sealed folder finds what was in the plain one
    assert_eq!(plan_records(&sealed, &new, &tables).unwrap(), records);
    // and back to plain: the same files, no more
    let back = root.join("back");
    copy_records(&records, &sealed, &new, &plain, &back, true).unwrap();
    verify_records(&records, &sealed, &new, &plain, &back).unwrap();
    std::fs::write(back.join("extra.json"), b"{}").unwrap();
    assert!(verify_records(&records, &sealed, &new, &plain, &back).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_blob_name_that_could_leave_the_folder_is_refused() {
    let blob = Blob { table: "..".into(), id: "x".into(), size: 1 };
    let _ = blob;
    let (root, _) = source();
    let path = main_file(&root);
    {
        let db = Database::open(&path).unwrap();
        let w = db.begin_write().unwrap();
        w.open_table(crate::journal_blob::REFS)
            .unwrap()
            .insert(r#"["..","k"]"#, br#"{"id":"x","size":1}"#.as_slice())
            .unwrap();
        w.commit().unwrap();
    }
    let main = Database::open(&path).unwrap();
    assert!(plan_blobs(&main).is_err());
    drop(main);
    let _ = std::fs::remove_dir_all(&root);
}
