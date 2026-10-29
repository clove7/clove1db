//! A build that fails after a new database was made removes what it made. The second database in
//! each build has no table, so the build stops after the first one is complete.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::Sealed,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Doc {
    id: String,
    title: String,
    #[clove(encrypt, id = 1)]
    secret: Sealed<String>,
}
impl Entity for Doc {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct Plain {
    id: String,
}
impl Entity for Plain {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn keys() -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

/// Every path below `dir`, relative to it, sorted.
fn tree(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.filter_map(|e| e.ok()) {
            let path = entry.path();
            out.push(path.strip_prefix(base).unwrap().display().to_string());
            if path.is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// A build whose first database is complete and whose second one is refused (it has no table).
fn failing_build(root: &Path, first: DatabaseConfig) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(first)
        .add_database(DatabaseConfig::new("second", "second").dir_path(root.to_path_buf()))
        .build()
}

/// Keys for the protected fields only, in an ordinary database: under the test cfg every database
/// is encrypted as a whole by default, which is switched off here.
trait FieldKeysOnly {
    fn and_field_keys(self) -> DatabaseConfig;
}

impl FieldKeysOnly for DatabaseConfig {
    fn and_field_keys(self) -> DatabaseConfig {
        #[cfg(clove_test_encrypt_all)]
        {
            self.plain().field_encryption(keys())
        }
        #[cfg(not(clove_test_encrypt_all))]
        {
            self.field_encryption(keys())
        }
    }
}

fn base(root: &Path) -> DatabaseConfig {
    DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false)
}

#[test]
fn control_whole_database_without_attachments_leaves_nothing() {
    let root = temp_dir();
    let first = base(&root).encryption(keys()).register::<Plain>("plain");
    assert!(failing_build(&root, first).is_err());
    let left = tree(&root);
    println!("left behind (control): {left:?}");
    assert!(left.is_empty(), "left behind: {left:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn whole_database_with_protected_attachments_leaves_nothing() {
    let root = temp_dir();
    let first = base(&root).blob_enabled(true).encryption(keys()).register_sealed_blob::<Doc>("docs");
    assert!(failing_build(&root, first).is_err());
    let left = tree(&root);
    println!("left behind (whole database, protected attachments): {left:?}");
    assert!(left.is_empty(), "left behind: {left:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// A database with field keys only is a new database too: a failed build leaves nothing of it.
#[test]
fn field_keys_only_with_protected_attachments_leaves_nothing() {
    let root = temp_dir();
    let first = base(&root).blob_enabled(true).and_field_keys().register_sealed_blob::<Doc>("docs");
    assert!(failing_build(&root, first).is_err());
    let left = tree(&root);
    println!("left behind (field keys only, protected attachments): {left:?}");
    assert!(left.is_empty(), "left behind: {left:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// A database that was there before is never touched by a build that fails.
fn existing_database_is_not_touched(make: impl Fn(&Path) -> DatabaseConfig) {
    let root = temp_dir();
    Storage::builder(StorageConfig::default()).add_database(make(&root)).build().unwrap().close();
    // Names only: opening a database writes to its files, so their sizes change on any open.
    let before = tree(&root);
    assert!(failing_build(&root, make(&root)).is_err());
    let after: Vec<String> = tree(&root).into_iter().filter(|p| !p.starts_with("second")).collect();
    let gone: Vec<&String> = before.iter().filter(|p| !after.contains(p)).collect();
    assert!(gone.is_empty(), "a failed build removed files that were already there: {gone:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Opening a database writes to it (a first open sets it up). Ten failed builds in a row must not
/// make the file grow each time: the size is recorded after the first and after each of the others.
fn sizes_over_failed_builds(make: impl Fn(&Path) -> DatabaseConfig) -> Vec<u64> {
    let root = temp_dir();
    Storage::builder(StorageConfig::default()).add_database(make(&root)).build().unwrap().close();
    let main = root.join("records").join("store.cldb");
    let mut sizes = vec![std::fs::metadata(&main).unwrap().len()];
    for _ in 0..10 {
        assert!(failing_build(&root, make(&root)).is_err());
        sizes.push(std::fs::metadata(&main).unwrap().len());
    }
    let _ = std::fs::remove_dir_all(&root);
    sizes
}

#[test]
fn the_main_file_does_not_grow_with_each_failed_build_whole_database() {
    let sizes = sizes_over_failed_builds(|root| base(root).blob_enabled(true).encryption(keys()).register_sealed_blob::<Doc>("docs"));
    println!("main file size after the create and after each failed build (whole database): {sizes:?}");
    // the file shrinks on the first opens (the space the creation reserved is given back) and then stays
    assert!(sizes.windows(2).all(|w| w[1] <= w[0]), "the file grows on an open: {sizes:?}");
    assert!(sizes[3..].iter().all(|s| *s == sizes[3]), "the file keeps changing: {sizes:?}");
}

#[test]
fn the_main_file_does_not_grow_with_each_failed_build_field_keys() {
    let sizes = sizes_over_failed_builds(|root| base(root).blob_enabled(true).and_field_keys().register_sealed_blob::<Doc>("docs"));
    println!("main file size after the create and after each failed build (field keys): {sizes:?}");
    assert!(sizes[2..].iter().all(|s| *s == sizes[1]), "the file grows on every open: {sizes:?}");
}

#[test]
fn an_existing_whole_database_with_protected_attachments_is_not_touched() {
    existing_database_is_not_touched(|root| {
        base(root).blob_enabled(true).encryption(keys()).register_sealed_blob::<Doc>("docs")
    });
}

#[test]
fn an_existing_database_with_field_keys_only_is_not_touched() {
    existing_database_is_not_touched(|root| {
        base(root).blob_enabled(true).and_field_keys().register_sealed_blob::<Doc>("docs")
    });
}
