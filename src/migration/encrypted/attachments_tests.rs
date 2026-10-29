//! Moving attachments between places: plain, sealed by the database, sealed by protected fields.
use super::attachments::{Copied, Item, Place, SYNCED, carry_over, check_after_swap, copy_all, plan, required_bytes};
use crate::blob::{BlobStore, protected_blob_root};
use crate::crypto::{CipherKind, DataKey, HkdfHash, Key32, KeySuite, ProgrammerKey};
use crate::encrypted_store::{EncryptionConfig, EncryptionContext, EncryptionHandle, FileKeys, KeySource, OpenOptionsExt};
use crate::entity::Entity;
use crate::field_crypto::FieldKeys;
use crate::storage::{DatabaseConfig, Storage, StorageConfig};
use redb::Database;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct File {
    id: String,
}
impl Entity for File {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// A plain database with attachments in the table `files` (one per size given, rows `r0`, `r1`, ...)
/// and in the table `more`. Returns the folder of the database and what was written.
fn source(files: &[usize], more: &[usize]) -> (PathBuf, Vec<(String, String, Vec<u8>)>) {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let db = DatabaseConfig::new("records", "store")
        .dir_path(root.clone())
        .blob_enabled(true)
        .register_blob::<File>("files")
        .register_blob::<File>("more");
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    let s = Storage::builder(StorageConfig::default()).add_database(db).build().unwrap();
    let mut written = Vec::new();
    for (table, sizes) in [("files", files), ("more", more)] {
        for (i, len) in sizes.iter().enumerate() {
            let (row, bytes) = (format!("r{i}"), data(*len, i as u8 + 1));
            s.db_manager("store").write_blob(table, &row, &bytes).unwrap();
            written.push((table.to_string(), row, bytes));
        }
    }
    s.close();
    (root.join("records"), written)
}

fn main_file(dir: &Path) -> PathBuf {
    dir.join("store.cldb")
}

fn plain(dir: &Path) -> Place {
    Place::Plain { root: crate::blob::blob_root(dir, "store") }
}

fn new_root(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("store.{name}.mig-new"))
}

fn keys(search_only: bool) -> Arc<FieldKeys> {
    let suite = KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 };
    let data = DataKey::generate().unwrap();
    let (read, search) = (Key32::from_bytes(&[1; 32]), Key32::from_bytes(&[2; 32]));
    let locked = data.lock(&suite, &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
    let access = locked
        .unlock(&suite, (!search_only).then_some(&ProgrammerKey::Raw(&read)), Some(&ProgrammerKey::Raw(&search)))
        .unwrap();
    Arc::new(FieldKeys::with_access(suite, access).unwrap())
}

fn protected(root: PathBuf, keys: &Arc<FieldKeys>) -> Place {
    let ids = HashMap::from([("files".to_string(), "table-one".to_string()), ("more".to_string(), "table-two".to_string())]);
    Place::Protected { root, keys: keys.clone() as Arc<dyn FileKeys>, ids: Arc::new(ids) }
}

fn context(dir: &Path) -> EncryptionContext {
    let config = EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[7; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[8; 32]))),
    };
    EncryptionHandle::new(config)
        .open_file(&dir.join("k.cldb"), "main", true, &OpenOptionsExt::default(), &mut |_| {})
        .unwrap()
        .context()
}

fn items(dir: &Path, tables: Option<&[String]>) -> Vec<Item> {
    let main = Database::open(main_file(dir)).unwrap();
    let mut out = Vec::new();
    plan(&main, tables, &mut |i| {
        out.push(i);
        Ok(())
    })
    .unwrap();
    out
}

fn read_all(mut r: impl Read) -> Vec<u8> {
    let mut v = Vec::new();
    r.read_to_end(&mut v).unwrap();
    v
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                out.extend(files_under(&e.path()));
            } else {
                out.push(e.path());
            }
        }
    }
    out
}

fn size_under(root: &Path) -> u64 {
    files_under(root).iter().map(|p| std::fs::metadata(p).unwrap().len()).sum()
}

fn copy(dir: &Path, tables: Option<&[String]>, from: &Place, to: &Place) -> crate::units::Result<Copied> {
    let main = Database::open(main_file(dir)).unwrap();
    copy_all(&main, tables, from, to, &mut |_| {})
}

/// Sizes around the edges of a sealed piece (64 KiB), an empty file, and a few pieces.
const SIZES: [usize; 6] = [0, 1, 65_535, 65_536, 65_537, 3 * 1024 * 1024 + 5];

#[test]
fn plain_to_protected_and_back_gives_the_same_bytes_at_every_size() {
    let (dir, written) = source(&SIZES, &[]);
    let k = keys(false);
    let sealed = protected(new_root(&dir, "pblobs"), &k);
    let done = copy(&dir, None, &plain(&dir), &sealed).unwrap();
    assert_eq!(done.files, SIZES.len() as u64);
    assert_eq!(done.bytes, SIZES.iter().sum::<usize>() as u64);
    let main = Database::open(main_file(&dir)).unwrap();
    assert_eq!(check_after_swap(&main, &sealed, None).unwrap(), SIZES.len() as u64);
    drop(main);
    // and back to plain files, from the sealed ones
    let back = Place::Plain { root: new_root(&dir, "blobs") };
    copy(&dir, None, &sealed, &back).unwrap();
    for item in items(&dir, None) {
        let original = &written.iter().find(|(t, r, _)| *t == item.table && *r == item.row).unwrap().2;
        let path = back.root().join(&item.table).join(&item.blob_id);
        assert_eq!(&std::fs::read(path).unwrap(), original);
    }
}

#[test]
fn the_names_are_the_ones_the_store_opens_by_and_a_file_belongs_to_its_row() {
    let (dir, written) = source(&[10, 200_000], &[]);
    let k = keys(false);
    // written straight into the folder the store reads, then opened through the store
    let place = protected(protected_blob_root(&dir, "store"), &k);
    copy(&dir, None, &plain(&dir), &place).unwrap();
    let ids = HashMap::from([("files".to_string(), "table-one".to_string())]);
    let store = BlobStore::new(&dir, "store").with_protected(k.clone() as Arc<dyn FileKeys>, Arc::new(ids));
    let all = items(&dir, None);
    for item in &all {
        let bytes = read_all(store.open_read_row(&item.table, &item.row, &item.blob_id).unwrap());
        assert_eq!(bytes, written.iter().find(|(_, r, _)| *r == item.row).unwrap().2);
    }
    // the file of one row does not open as the file of another
    assert!(store.open_read_row("files", &all[1].row, &all[0].blob_id).is_err());
}

#[test]
fn whole_database_places_move_both_ways() {
    let (dir, written) = source(&[300_000, 5], &[]);
    let ctx = context(&dir);
    let whole = Place::WholeDb { root: new_root(&dir, "blobs"), context: ctx };
    copy(&dir, None, &plain(&dir), &whole).unwrap();
    let k = keys(false);
    let sealed = protected(new_root(&dir, "pblobs"), &k);
    copy(&dir, None, &whole, &sealed).unwrap();
    let main = Database::open(main_file(&dir)).unwrap();
    assert_eq!(check_after_swap(&main, &whole, None).unwrap(), 2);
    assert_eq!(check_after_swap(&main, &sealed, None).unwrap(), 2);
    drop(main);
    let plain_again = Place::Plain { root: new_root(&dir, "again") };
    copy(&dir, None, &sealed, &plain_again).unwrap();
    for item in items(&dir, None) {
        let bytes = std::fs::read(plain_again.root().join(&item.table).join(&item.blob_id)).unwrap();
        assert_eq!(bytes, written.iter().find(|(_, r, _)| *r == item.row).unwrap().2);
    }
}

#[test]
fn nothing_readable_is_left_in_the_sealed_folder() {
    let marker = *b"CLOVE-ATTACHMENT-MARKER-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEF";
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let dir = root.join("records");
    let db = DatabaseConfig::new("records", "store").dir_path(root.clone()).blob_enabled(true).register_blob::<File>("files");
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    let s = Storage::builder(StorageConfig::default()).add_database(db).build().unwrap();
    let body: Vec<u8> = marker.iter().copied().cycle().take(200_000).collect();
    s.db_manager("store").write_blob("files", "r0", &body).unwrap();
    s.close();
    let found_in = |root: &Path| {
        files_under(root).iter().filter(|p| {
            let bytes = std::fs::read(p).unwrap();
            bytes.windows(16).any(|w| marker.windows(16).any(|m| m == w))
        }).count()
    };
    assert_eq!(found_in(&crate::blob::blob_root(&dir, "store")), 1, "the check can see the marker in the plain file");
    let sealed = protected(new_root(&dir, "pblobs"), &keys(false));
    copy(&dir, None, &plain(&dir), &sealed).unwrap();
    assert_eq!(found_in(sealed.root()), 0);
    for f in files_under(sealed.root()) {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.len() == 32 && name.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
    }
}

#[test]
fn every_new_file_is_flushed_before_the_copy_returns() {
    let (dir, _) = source(&[10, 70_000, 0, 1], &[]);
    SYNCED.with(|s| s.borrow_mut().clear());
    let sealed = protected(new_root(&dir, "pblobs"), &keys(false));
    copy(&dir, None, &plain(&dir), &sealed).unwrap();
    let mut made = files_under(sealed.root());
    let mut synced = SYNCED.with(|s| s.borrow().clone());
    made.sort();
    synced.sort();
    assert_eq!(made.len(), 4);
    assert_eq!(made, synced);
}

#[test]
fn progress_only_goes_up_and_ends_at_the_total() {
    let (dir, _) = source(&[10, 70_000, 5], &[]);
    let sealed = protected(new_root(&dir, "pblobs"), &keys(false));
    let main = Database::open(main_file(&dir)).unwrap();
    let mut seen = Vec::new();
    copy_all(&main, None, &plain(&dir), &sealed, &mut |b| seen.push(b)).unwrap();
    assert_eq!(seen.len(), 3);
    assert!(seen.windows(2).all(|w| w[0] <= w[1]));
    assert_eq!(*seen.last().unwrap(), 70_015);
}

#[test]
fn only_the_tables_asked_for_are_moved() {
    let (dir, _) = source(&[10, 20], &[30]);
    let only = vec!["more".to_string()];
    assert_eq!(items(&dir, Some(&only)).len(), 1);
    let sealed = protected(new_root(&dir, "pblobs"), &keys(false));
    let done = copy(&dir, Some(&only), &plain(&dir), &sealed).unwrap();
    assert_eq!((done.files, done.bytes), (1, 30));
}

#[test]
fn a_size_that_differs_from_the_main_file_stops_the_copy() {
    let (dir, _) = source(&[100], &[]);
    let item = items(&dir, None).remove(0);
    let path = plain(&dir).root().join(&item.table).join(&item.blob_id);
    // attachment files are read-only
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(&path, permissions).unwrap();
    std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(101).unwrap();
    let sealed = protected(new_root(&dir, "pblobs"), &keys(false));
    let err = copy(&dir, None, &plain(&dir), &sealed).unwrap_err().to_string();
    assert!(err.contains("main file says"), "{err}");
}

#[test]
fn a_missing_attachment_stops_the_copy() {
    let (dir, _) = source(&[100, 100], &[]);
    let item = items(&dir, None).remove(1);
    std::fs::remove_file(plain(&dir).root().join(&item.table).join(&item.blob_id)).unwrap();
    let sealed = protected(new_root(&dir, "pblobs"), &keys(false));
    assert!(copy(&dir, None, &plain(&dir), &sealed).is_err());
}

#[test]
fn keys_without_the_read_key_are_refused_before_anything_is_written() {
    let (dir, _) = source(&[100], &[]);
    let sealed = protected(new_root(&dir, "pblobs"), &keys(true));
    let err = copy(&dir, None, &plain(&dir), &sealed).unwrap_err().to_string();
    assert!(err.contains("no read key"), "{err}");
    assert!(!sealed.root().exists());
}

#[test]
fn a_table_without_an_identity_is_refused() {
    let (dir, _) = source(&[100], &[]);
    let k = keys(false);
    let sealed = Place::Protected { root: new_root(&dir, "pblobs"), keys: k as Arc<dyn FileKeys>, ids: Arc::new(HashMap::new()) };
    let err = copy(&dir, None, &plain(&dir), &sealed).unwrap_err().to_string();
    assert!(err.contains("no protected identity"), "{err}");
}

#[test]
fn the_other_tables_are_carried_over_as_they_are_and_leftovers_stay_behind() {
    let (dir, written) = source(&[10, 20], &[300, 70_000]);
    let from = plain(&dir);
    let leftover = from.root().join("more").join("x.tmp.1");
    std::fs::write(&leftover, b"half a write").unwrap();
    let to = new_root(&dir, "carried");
    let bytes = carry_over(&from, &to, &["files".to_string()]).unwrap();
    assert_eq!(bytes, 70_300);
    assert!(!to.join("files").exists());
    assert!(!to.join("more").join("x.tmp.1").exists());
    for item in items(&dir, Some(&["more".to_string()])) {
        let moved = std::fs::read(to.join("more").join(&item.blob_id)).unwrap();
        assert_eq!(moved, written.iter().find(|(t, r, _)| t == "more" && *r == item.row).unwrap().2);
    }
}

#[test]
fn sealed_files_of_tables_that_stay_are_carried_over_and_still_open() {
    let (dir, written) = source(&[10], &[300]);
    let k = keys(false);
    let old = protected(new_root(&dir, "old"), &k);
    copy(&dir, None, &plain(&dir), &old).unwrap();
    let new = protected(new_root(&dir, "new"), &k);
    let bytes = carry_over(&old, new.root(), &["files".to_string()]).unwrap();
    assert!(bytes > 300);
    let main = Database::open(main_file(&dir)).unwrap();
    assert_eq!(check_after_swap(&main, &new, Some(&["more".to_string()])).unwrap(), 1);
    drop(main);
    let one = items(&dir, Some(&["more".to_string()])).remove(0);
    let (t, f) = crate::blob::protected_names("table-two", &one.row, &one.blob_id);
    let store = crate::encrypted_store::SealedBlobStore::with_keys(new.root(), k as Arc<dyn FileKeys>);
    assert_eq!(store.read_all(&t, &f).unwrap(), written.iter().find(|(t, _, _)| t == "more").unwrap().2);
}

#[test]
fn the_space_asked_for_covers_what_is_written() {
    let (dir, _) = source(&SIZES, &[]);
    let sealed = protected(new_root(&dir, "pblobs"), &keys(false));
    copy(&dir, None, &plain(&dir), &sealed).unwrap();
    let main = Database::open(main_file(&dir)).unwrap();
    let asked = required_bytes(&main, None, &[]).unwrap();
    let written = size_under(sealed.root());
    assert!(asked >= written, "{asked} < {written}");
    let pieces: u64 = SIZES.iter().map(|s| (*s as u64).div_ceil(65_536).max(1)).sum();
    assert!(asked - written <= 12 * pieces, "asked {asked}, written {written}");
}

#[test]
fn a_sealed_file_that_was_changed_is_found_by_the_check_after_the_swap() {
    let (dir, _) = source(&[1000], &[]);
    let k = keys(false);
    let sealed = protected(new_root(&dir, "pblobs"), &k);
    copy(&dir, None, &plain(&dir), &sealed).unwrap();
    let file = files_under(sealed.root()).remove(0);
    let mut bytes = std::fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&file, bytes).unwrap();
    let main = Database::open(main_file(&dir)).unwrap();
    assert!(check_after_swap(&main, &sealed, None).is_err());
}
