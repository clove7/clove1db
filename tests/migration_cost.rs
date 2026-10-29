//! What changing how a database is protected costs: time, memory and disk, per megabyte. This is a
//! measuring program, not a test of behaviour: the `cost_entry` test does nothing unless the
//! variables `CLOVE_COST_ROOT` and `CLOVE_COST_ACTION` are set, and the script that measures starts it as
//! a process of its own (so the peak of memory is the peak of that change alone) and watches it.
//!
//! Actions: `make_rows` (a plain database of `CLOVE_COST_MB` megabytes of rows), `make_files` (the
//! same size in attachments of about a megabyte), `to_aes` / `aes_to_xchacha` / `xchacha_to_plain`
//! (a change of the protection of the whole database), `seal` (a plain field of every row becomes a
//! sealed one, in a plain database whose fields get keys of their own), `hash` (the same, as a hash).
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{Hashed, Sealed},
    migration::{ChangeFields, ChangeProtection},
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Row {
    id: String,
    name: String,
    phone: String,
    body: String,
}
impl Entity for Row {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct SealedRow {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    body: String,
}
impl Entity for SealedRow {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct HashedRow {
    id: String,
    name: String,
    #[clove(hash = "argon2id", id = 2)]
    phone: Hashed,
    body: String,
}
impl Entity for HashedRow {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn keys(n: u8) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite {
            cipher: if n % 2 == 0 { CipherKind::Aes256GcmSiv } else { CipherKind::XChaCha20Poly1305 },
            hkdf: HkdfHash::Sha256,
        },
        read: Some(KeySource::Raw(Key32::from_bytes(&[n; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[n.wrapping_add(100); 32]))),
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// A value that does not compress and is different for every row.
fn body(i: usize, len: usize) -> String {
    let mut state = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (b'a' + (state % 26) as u8) as char
        })
        .collect()
}

fn make_rows(root: &Path, mb: usize) {
    let config = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false).backup_enabled(false);
    #[cfg(clove_test_encrypt_all)]
    let config = config.plain();
    let s = Storage::builder(StorageConfig::default()).add_database(config.register::<Row>("people")).build().unwrap();
    let db = s.db_manager("store");
    let rows = mb * 1024; // about a kilobyte each
    let mut batch = Vec::new();
    for i in 0..rows {
        let row = Row { id: format!("p{i:08}"), name: format!("name-{i}"), phone: format!("+1555{i:08}"), body: body(i, 900) };
        batch.push(("people".to_string(), row.id.clone(), serde_json::to_vec(&row).unwrap()));
        if batch.len() == 500 {
            db.commit_batch(&batch, &[]).unwrap();
            batch.clear();
        }
    }
    if !batch.is_empty() {
        db.commit_batch(&batch, &[]).unwrap();
    }
    drop(db);
    s.close();
}

fn make_files(root: &Path, mb: usize) {
    let config = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false).blob_enabled(true);
    #[cfg(clove_test_encrypt_all)]
    let config = config.plain();
    let s = Storage::builder(StorageConfig::default()).add_database(config.register_blob::<Row>("people")).build().unwrap();
    let repo = s.domain::<Row>().repo();
    let bytes = body(7, 1024 * 1024).into_bytes();
    for i in 0..mb {
        let row = Row { id: format!("p{i:08}"), name: format!("name-{i}"), phone: format!("+1555{i:08}"), body: String::new() };
        repo.set_with_blob(&row.id, &row, &bytes).unwrap();
    }
    drop(repo);
    s.close();
}

fn whole(root: &Path, from: Option<u8>, to: Option<u8>) {
    let mut change = ChangeProtection::new(root, "records", "store");
    change = match from {
        Some(n) => change.from_whole_database(keys(n)),
        None => change.from_plain(),
    };
    change = match to {
        Some(n) => change.to_whole_database(keys(n)),
        None => change.to_plain(),
    };
    change.execute().unwrap();
}

fn required(bytes: u64) {
    println!("COST_REQUIRED {bytes}");
}

/// What each table of a plain main file holds, in bytes: the data, the tree around it, and the room
/// freed inside the file that has not been given back. Prints lines `STATS table rows stored metadata
/// fragmented`, and the size of the file.
fn stats(root: &Path) {
    use redb::{ReadableDatabase, ReadableTableMetadata, TableHandle};
    let path = root.join("records").join("store.cldb");
    let db = redb::Database::builder().open(&path).unwrap();
    let read = db.begin_read().unwrap();
    let mut names: Vec<String> = read.list_tables().unwrap().map(|h| h.name().to_string()).collect();
    names.sort();
    for name in names {
        let handle = read.list_tables().unwrap().find(|h| h.name() == name).unwrap();
        let table = read.open_untyped_table(handle).unwrap();
        let s = table.stats().unwrap();
        println!("STATS {name} {} {} {} {}", table.len().unwrap(), s.stored_bytes(), s.metadata_bytes(), s.fragmented_bytes());
    }
    println!("STATS_FILE {}", std::fs::metadata(&path).unwrap().len());
}

/// Run by the measuring script in a process of its own. Does nothing in a normal run.
#[test]
#[ignore = "a measuring program, run by tools\\measure-cost.ps1"]
fn cost_entry() {
    let (Some(root), Some(action)) = (var("CLOVE_COST_ROOT"), var("CLOVE_COST_ACTION")) else { return };
    let root = PathBuf::from(root);
    let mb: usize = var("CLOVE_COST_MB").and_then(|v| v.parse().ok()).unwrap_or(20);
    let started = Instant::now();
    match action.as_str() {
        "make_rows" => make_rows(&root, mb),
        "make_files" => make_files(&root, mb),
        "to_aes" => whole(&root, None, Some(4)),
        "aes_to_xchacha" => whole(&root, Some(4), Some(5)),
        "xchacha_to_plain" => whole(&root, Some(5), None),
        "seal" => {
            ChangeFields::new(&root, "records", "store").field_keys(keys(4)).table::<SealedRow>("people").execute().unwrap();
        }
        "hash" => {
            ChangeFields::new(&root, "records", "store").field_keys(keys(4)).table::<HashedRow>("people").confirm_one_way().execute().unwrap();
        }
        "stats" => stats(&root),
        // what the change says it needs, without making it
        "required_to_aes" => required(ChangeProtection::new(&root, "records", "store").from_plain().to_whole_database(keys(4)).dry_run().unwrap().required_bytes),
        "required_aes_to_xchacha" => {
            required(ChangeProtection::new(&root, "records", "store").from_whole_database(keys(4)).to_whole_database(keys(5)).dry_run().unwrap().required_bytes)
        }
        "required_xchacha_to_plain" => required(ChangeProtection::new(&root, "records", "store").from_whole_database(keys(5)).to_plain().dry_run().unwrap().required_bytes),
        "required_seal" => required(ChangeFields::new(&root, "records", "store").field_keys(keys(4)).table::<SealedRow>("people").dry_run().unwrap().required_bytes),
        other => panic!("unknown action {other}"),
    }
    println!("COST_ELAPSED_MS {}", started.elapsed().as_millis());
}
