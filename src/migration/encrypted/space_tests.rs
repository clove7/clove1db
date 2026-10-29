//! The room a change says it needs is at least the room it takes: the folder is watched while the
//! change runs, and the most it grew by is never more than what `dry_run` said.
use super::space::size_of;
use crate::{
    CloveFields,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::{EncryptionConfig, KeySource},
    entity::Entity,
    field_crypto::Sealed,
    migration::{ChangeFields, ChangeProtection},
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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

/// Text that does not compress and differs from row to row.
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

/// A plain database of about 20 megabytes of rows; with `history` each row is written twice and the
/// database keeps a history file.
fn make(history: bool) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let config = DatabaseConfig::new("records", "store").dir_path(root.clone()).has_cache(false).backup_enabled(history);
    #[cfg(clove_test_encrypt_all)]
    let config = config.plain();
    let s = Storage::builder(StorageConfig::default()).add_database(config.register::<Row>("people")).build().unwrap();
    let db = s.db_manager("store");
    for round in 0..if history { 2 } else { 1 } {
        let mut batch = Vec::new();
        for i in 0..20 * 1024 {
            let row = Row { id: format!("p{i:08}"), name: format!("name-{i}-{round}"), phone: format!("+1555{i:08}"), body: body(i, 900) };
            batch.push(("people".to_string(), row.id.clone(), serde_json::to_vec(&row).unwrap()));
            if batch.len() == 500 {
                db.commit_batch(&batch, &[]).unwrap();
                batch.clear();
            }
        }
        db.commit_batch(&batch, &[]).unwrap();
    }
    drop(db);
    s.close();
    if history {
        assert!(root.join("records").join("store.cldb.bak").is_file(), "the database has no history file");
    }
    root
}

/// Run `work`, and say by how much the folder at its largest was bigger than it was before.
fn growth_during<T>(folder: &Path, work: impl FnOnce() -> T) -> (T, u64) {
    let before = size_of(folder);
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = {
        let (stop, folder) = (stop.clone(), folder.to_path_buf());
        std::thread::spawn(move || {
            let mut most = 0u64;
            while !stop.load(Ordering::Relaxed) {
                most = most.max(size_of(&folder));
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            most.max(size_of(&folder))
        })
    };
    let done = work();
    stop.store(true, Ordering::Relaxed);
    (done, watcher.join().unwrap().saturating_sub(before))
}

#[test]
fn a_database_with_a_history_file_takes_no_more_room_than_it_said() {
    let root = make(true);
    let change = || ChangeProtection::new(&root, "records", "store").to_whole_database(keys(4));
    let said = change().dry_run().unwrap().required_bytes;
    let (done, grew) = growth_during(&root, || change().execute());
    done.unwrap();
    assert!(grew > 0, "the watcher saw nothing");
    assert!(said >= grew, "it said {said} bytes and took {grew}");
    // and the fields of its table
    let root = make(true);
    let change = || ChangeFields::new(&root, "records", "store").field_keys(keys(4)).table::<SealedRow>("people");
    let said = change().dry_run().unwrap().required_bytes;
    let (done, grew) = growth_during(&root, || change().execute());
    done.unwrap();
    assert!(grew > 0, "the watcher saw nothing");
    assert!(said >= grew, "it said {said} bytes and took {grew}");
}

#[test]
fn a_change_of_how_the_whole_database_is_protected_takes_no_more_room_than_it_said() {
    let root = make(false);
    let change = || ChangeProtection::new(&root, "records", "store").to_whole_database(keys(4));
    let said = change().dry_run().unwrap().required_bytes;
    let (done, grew) = growth_during(&root, || change().execute());
    done.unwrap();
    assert!(grew > 0, "the watcher saw nothing");
    assert!(said >= grew, "it said {said} bytes and took {grew}");
}

#[test]
fn a_change_of_the_protected_fields_takes_no_more_room_than_it_said() {
    let root = make(false);
    let change = || ChangeFields::new(&root, "records", "store").field_keys(keys(4)).table::<SealedRow>("people");
    let said = change().dry_run().unwrap().required_bytes;
    let (done, grew) = growth_during(&root, || change().execute());
    done.unwrap();
    assert!(grew > 0, "the watcher saw nothing");
    assert!(said >= grew, "it said {said} bytes and took {grew}");
}
