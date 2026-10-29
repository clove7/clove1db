//! The combined case: a database encrypted as a whole (`.encryption(keys)`) that also has protected
//! fields (encrypted, hashed, fingerprinted) and an attachment. Two layers must both be real:
//!
//! * the inner one: inside the open database, in the stored row, in the change log, in the history
//!   file and in an export, a protected field is sealed text and an ordinary field is readable;
//! * the outer one: on disk no value and no sign of the file format is visible.
//!
//! The same tests run in the ordinary build and under `--cfg clove_test_encrypt_all`.
//! The tamper case that needs a raw write inside the database is a unit test next to the envelope
//! code (`src/field_crypto/combined_tests.rs`), because the public API refuses raw writes.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{Hashed, Sealed, SearchPrint},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const PHONE: &str = "+155-COMBINED-PHONE-77";
const PASSWORD: &str = "COMBINED-SECRET-PASSWORD";
const EMAIL: &str = "combined.mail@example.test";
const ORDINARY: &str = "VISIBLE-ORDINARY";

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Account {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,
    #[clove(search_print, id = 3)]
    email: SearchPrint,
}
impl Entity for Account {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same fields, in a table whose rows carry an attachment.
#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Dossier {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(search_print, id = 3)]
    email: SearchPrint,
}
impl Entity for Dossier {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn account(id: &str, phone: &str) -> Account {
    Account {
        id: id.into(),
        name: format!("{ORDINARY}-{id}"),
        phone: Sealed::new(phone.into()),
        password: Hashed::new(PASSWORD),
        email: SearchPrint::new(EMAIL),
    }
}

fn keys(read: Option<u8>, search: Option<u8>) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 },
        read: read.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
        search: search.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

type Seen = Arc<Mutex<Vec<String>>>;

/// A database with a backup file, encrypted as a whole, with protected fields.
fn open_with(dir: &Path, config: EncryptionConfig, seen: &Seen) -> clove1db::units::Result<Storage> {
    let seen = seen.clone();
    let storage = StorageConfig::default().event_sink(move |e| match e {
        LibraryEvent::FieldRead { table, field, row, .. } => seen.lock().unwrap().push(format!("read {table}.{field} {row}")),
        LibraryEvent::HashVerify { field, row, matched, .. } => seen.lock().unwrap().push(format!("hash {field} {row} {matched}")),
        _ => {}
    });
    Storage::builder(storage)
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(dir.to_path_buf())
                .has_cache(false)
                .backup_enabled(true)
                .encryption(config)
                .register_sealed::<Account>("accounts"),
        )
        .build()
}

fn open(dir: &Path) -> Storage {
    open_with(dir, keys(Some(1), Some(2)), &Seen::default()).unwrap()
}

/// A database with attachments (it keeps no backup file), encrypted as a whole.
fn open_files(dir: &Path) -> Storage {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(dir.to_path_buf())
                .has_cache(false)
                .blob_enabled(true)
                .encryption(keys(Some(1), Some(2)))
                .register_sealed_blob::<Dossier>("dossiers"),
        )
        .build()
        .unwrap()
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

fn has(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn raw(s: &Storage, id: &str) -> Vec<u8> {
    s.db_manager("store")
        .get_uncached(TableDefinition::<&str, &[u8]>::new("accounts"), id)
        .unwrap()
        .expect("row exists")
}

/// Bytes that must show the ordinary field and none of the protected values.
fn assert_inner_layer(bytes: &[u8], where_: &str) {
    assert!(has(bytes, ORDINARY), "{where_}: the scan is blind, the ordinary field is not in these bytes");
    for secret in [PHONE, PASSWORD, EMAIL, "COMBINED-PHONE", "COMBINED-SECRET", "combined.mail"] {
        assert!(!has(bytes, secret), "{where_}: contains {secret}");
    }
}

#[test]
fn the_inner_layer_is_real_in_the_stored_row_the_change_log_the_history_and_an_export() {
    let dir = temp_dir();
    let s = open(&dir);
    let db = s.db_manager("store");
    let token = db.register_consumer("combined").unwrap();
    let repo = s.domain::<Account>().repo();
    repo.set("a1", &account("a1", PHONE)).unwrap();
    repo.set("a1", &account("a1", "+155-COMBINED-PHONE-78")).unwrap();
    repo.set("a2", &account("a2", PHONE)).unwrap();
    repo.delete("a2").unwrap();

    // The row as stored inside the open database: sealed text, a hash of the right size, a fingerprint.
    let bytes = raw(&s, "a1");
    assert_inner_layer(&bytes, "stored row");
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let text = |k: &str| json[k].as_str().unwrap_or_else(|| panic!("{k} is not text")).to_string();
    assert!(text("phone").len() >= 60, "the phone is not a sealed envelope: {}", text("phone"));
    assert_eq!(text("password").len(), 66, "the password is not a stored hash");
    assert_eq!(text("email").len(), 43, "the email is not a fingerprint");
    assert_eq!(text("name"), format!("{ORDINARY}-a1"));

    // The change log.
    let mut upserts = 0;
    for change in db.read_changes(&token, 0, 100).unwrap() {
        if let clove1db::ChangeKind::Upsert { table, value, .. } = change.kind {
            if table == "accounts" {
                assert_inner_layer(&value, "change log");
                upserts += 1;
            }
        }
    }
    assert_eq!(upserts, 3, "the change log should hold the three writes");

    // The history file: every version of the row, including the deleted one's earlier versions.
    let bm = db.backup_manager.as_ref().expect("the backup file");
    let mut versions = 0;
    for id in ["a1", "a2"] {
        for record in bm.history(TableDefinition::<&str, &[u8]>::new("accounts"), id).unwrap() {
            if let Some(data) = &record.data {
                assert_inner_layer(data, "history");
                versions += 1;
            }
        }
    }
    assert_eq!(versions, 3);

    // An export: the rows of a consistent view, and the rows serialized as a program would send them.
    let entries = db.read_view_at_head().unwrap().table_entries("accounts").unwrap();
    assert_eq!(entries.len(), 1);
    assert_inner_layer(&entries[0].1, "view export");
    let sent = serde_json::to_string(&repo.list().unwrap()).unwrap();
    assert_inner_layer(sent.as_bytes(), "serialized rows");
    let debug = format!("{:?}", repo.get("a1").unwrap());
    assert_inner_layer(debug.as_bytes(), "debug output");
}

#[test]
fn the_outer_layer_is_real_no_value_and_no_file_format_shows_on_disk() {
    let dir = temp_dir();
    {
        let s = open(&dir);
        s.domain::<Account>().repo().set("a1", &account("a1", PHONE)).unwrap();
        s.domain::<Account>().repo().set("a1", &account("a1", "+155-COMBINED-PHONE-78")).unwrap();
        s.close();
    }
    let files = walk(&dir);
    assert!(files.len() >= 2, "{files:?}");
    for path in &files {
        let bytes = std::fs::read(path).unwrap();
        assert!(!bytes.is_empty());
        for needle in [PHONE, PASSWORD, EMAIL, ORDINARY, "COMBINED", "accounts", "redb"] {
            assert!(!has(&bytes, needle), "{needle} found in {}", path.display());
        }
    }

    // The scan can see: the same rows in a database that is not encrypted as a whole show the
    // ordinary field, the table name and the file format (control).
    let control = temp_dir();
    {
        let db = DatabaseConfig::new("records", "store").dir_path(control.clone()).has_cache(false).backup_enabled(true);
        #[cfg(clove_test_encrypt_all)]
        let db = db.plain();
        let s = Storage::builder(StorageConfig::default())
            .add_database(db.field_encryption(keys(Some(1), Some(2))).register_sealed::<Account>("accounts"))
            .build()
            .unwrap();
        s.domain::<Account>().repo().set("a1", &account("a1", PHONE)).unwrap();
        s.close();
    }
    let mut seen = [false; 3];
    for path in walk(&control) {
        let bytes = std::fs::read(&path).unwrap();
        for secret in [PHONE, PASSWORD, EMAIL] {
            assert!(!has(&bytes, secret), "control: {secret} found in {}", path.display());
        }
        for (n, needle) in [ORDINARY, "accounts", "redb"].iter().enumerate() {
            seen[n] |= has(&bytes, needle);
        }
    }
    assert_eq!(seen, [true; 3], "the control scan is blind: it must see the ordinary field, the table and the format");
}

#[test]
fn a_value_opens_only_with_a_grant_and_every_opening_is_reported() {
    let dir = temp_dir();
    let seen = Seen::default();
    let s = open_with(&dir, keys(Some(1), Some(2)), &seen).unwrap();
    let domain = s.domain::<Account>();
    domain.repo().set("a1", &account("a1", PHONE)).unwrap();

    // Reading a row opens nothing: no value, no event.
    let row = domain.repo().get("a1").unwrap();
    assert!(seen.lock().unwrap().is_empty(), "reading a row is not opening a value");
    assert!(!format!("{row:?}").contains("COMBINED"));
    assert!(!serde_json::to_string(&row).unwrap().contains("COMBINED"));

    // A value that was never written has no place to open from, grant or not.
    let grant = domain.read_grant().unwrap();
    assert!(Sealed::new(PHONE.to_string()).open(&grant).is_err());

    // With a grant the value opens, and each opening is one event naming table, field and row.
    assert_eq!(row.phone.open(&grant).unwrap(), PHONE);
    assert_eq!(row.phone.open(&grant).unwrap(), PHONE);
    assert_eq!(*seen.lock().unwrap(), ["read accounts.phone a1", "read accounts.phone a1"]);
    assert!(!seen.lock().unwrap().iter().any(|e| e.contains("COMBINED")));
}

#[test]
fn a_sealed_value_written_to_another_row_is_refused_never_stored() {
    let dir = temp_dir();
    let s = open(&dir);
    let repo = s.domain::<Account>().repo();
    repo.set("a1", &account("a1", PHONE)).unwrap();
    repo.set("a2", &account("a2", "+155-COMBINED-PHONE-99")).unwrap();
    let before = raw(&s, "a2");
    // The sealed phone of a1 into the row of a2.
    let mut moved = repo.get("a2").unwrap();
    moved.phone = repo.get("a1").unwrap().phone;
    let err = repo.set("a2", &moved).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("can only be written back")), "{err:?}");
    // Text that came from outside the storage is never accepted as a protected value either.
    let outside: Account = serde_json::from_str(&serde_json::to_string(&repo.get("a2").unwrap()).unwrap()).unwrap();
    let err = repo.set("a2", &outside).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("can only be written back")), "{err:?}");
    assert_eq!(raw(&s, "a2"), before, "a refused write changed the row");
}

#[test]
fn update_delete_restore_close_reopen_and_the_wrong_keys() {
    let dir = temp_dir();
    {
        let s = open(&dir);
        let domain = s.domain::<Account>();
        domain.repo().set("a1", &account("a1", "+155-COMBINED-PHONE-01")).unwrap();
        domain.repo().set("a1", &account("a1", "+155-COMBINED-PHONE-02")).unwrap();
        domain.repo().set("gone", &account("gone", PHONE)).unwrap();
        domain.repo().delete("gone").unwrap();
        // Restore the first version of the row.
        domain.restore_by_version("a1", 1).unwrap();
        let grant = domain.read_grant().unwrap();
        assert_eq!(domain.repo().get("a1").unwrap().phone.open(&grant).unwrap(), "+155-COMBINED-PHONE-01");
        assert!(domain.repo().get("gone").is_err());
        s.close();
    }
    // Same keys: everything is as it was left.
    {
        let seen = Seen::default();
        let s = open_with(&dir, keys(Some(1), Some(2)), &seen).unwrap();
        let domain = s.domain::<Account>();
        let row = domain.repo().get("a1").unwrap();
        let grant = domain.read_grant().unwrap();
        assert_eq!(row.phone.open(&grant).unwrap(), "+155-COMBINED-PHONE-01");
        assert_eq!(row.name, format!("{ORDINARY}-a1"));
        assert!(domain.repo().get("gone").is_err());
        assert_eq!(domain.repo().list().unwrap().len(), 1);
        s.close();
    }
    // A wrong read key or a wrong search key gives the one open error.
    for wrong in [keys(Some(9), Some(2)), keys(Some(1), Some(9))] {
        let err = open_with(&dir, wrong, &Seen::default()).err().expect("must be refused");
        assert!(matches!(err, ClError::EncryptedOpenFailed), "{err:?}");
    }
    // The search key alone, and no keys at all, are refused for a database encrypted as a whole
    // (it needs a read key), as in the whole-database case.
    for incomplete in [keys(None, Some(2)), keys(None, None)] {
        let err = open_with(&dir, incomplete, &Seen::default()).err().expect("must be refused");
        assert!(matches!(&err, ClError::Validation(t) if t.contains("read key")), "{err:?}");
    }
    // And the right keys still open it.
    drop(open(&dir));
}

#[test]
fn the_hash_verifies_and_the_fingerprint_matches_in_the_combined_case() {
    let dir = temp_dir();
    let seen = Seen::default();
    let s = open_with(&dir, keys(Some(1), Some(2)), &seen).unwrap();
    let domain = s.domain::<Account>();
    domain.repo().set("a1", &account("a1", PHONE)).unwrap();
    let row = domain.repo().get("a1").unwrap();
    let verifier = domain.verifier().unwrap();
    assert!(row.password.verify(PASSWORD, &verifier).unwrap());
    assert!(!row.password.verify("not the password", &verifier).unwrap());
    assert!(row.email.matches(EMAIL, &verifier).unwrap());
    assert!(!row.email.matches("someone.else@example.test", &verifier).unwrap());
    assert_eq!(*seen.lock().unwrap(), ["hash password a1 true", "hash password a1 false"]);
    // After closing and opening again, the same.
    s.close();
    drop(s);
    let s = open(&dir);
    let domain = s.domain::<Account>();
    let row = domain.repo().get("a1").unwrap();
    let verifier = domain.verifier().unwrap();
    assert!(row.password.verify(PASSWORD, &verifier).unwrap());
    assert!(row.email.matches(EMAIL, &verifier).unwrap());
}

#[test]
fn an_attachment_in_the_combined_case_is_sealed_bound_to_its_row_and_hidden_on_disk() {
    let dir = temp_dir();
    let marker = "COMBINED-ATTACHMENT-MARKER-";
    let a = marker.repeat(6000).into_bytes();
    let b = format!("OTHER-{marker}").repeat(4000).into_bytes();
    let dossier = |id: &str| Dossier {
        id: id.into(),
        name: format!("{ORDINARY}-{id}"),
        phone: Sealed::new(PHONE.into()),
        email: SearchPrint::new(EMAIL),
    };
    let s = open_files(&dir);
    let repo = s.domain::<Dossier>().repo();
    repo.set_with_blob("d1", &dossier("d1"), &a).unwrap();
    repo.set_with_blob("d2", &dossier("d2"), &b).unwrap();

    // Inside the open database the row is sealed text and the attachment reads back exact.
    let stored = s
        .db_manager("store")
        .get_uncached(TableDefinition::<&str, &[u8]>::new("dossiers"), "d1")
        .unwrap()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    assert!(has(&stored, ORDINARY) && !has(&stored, PHONE) && !has(&stored, EMAIL));
    assert!(json["phone"].as_str().unwrap().len() >= 60);
    let read = |id: &str| {
        let mut out = Vec::new();
        repo.open_blob(id).and_then(|mut r| r.read_to_end(&mut out).map_err(Into::into)).map(|_| out)
    };
    assert_eq!(read("d1").unwrap(), a);
    assert_eq!(read("d2").unwrap(), b);

    // The attachment files: the bytes are not in them, and they are the field-bound ones
    // (the whole-database attachment folder holds none: this table's attachments have one sealing).
    s.close();
    drop(s);
    let files = walk(&dir);
    let attachments: Vec<&PathBuf> = files.iter().filter(|p| p.to_string_lossy().contains(".pblobs")).collect();
    assert_eq!(attachments.len(), 2, "{files:?}");
    for path in &files {
        let bytes = std::fs::read(path).unwrap();
        for needle in ["COMBINED", ORDINARY, "dossiers", "redb", PHONE, EMAIL] {
            assert!(!has(&bytes, needle), "{needle} found in {}", path.display());
        }
    }
    assert!(!files.iter().any(|p| p.to_string_lossy().contains(".blobs") && !p.to_string_lossy().contains(".pblobs")),
        "an attachment of a protected table was written to the whole-database attachment folder");

    // One attachment moved over the other is a tamper error, never the other's bytes.
    let (first, second) = {
        let mut sorted: Vec<PathBuf> = attachments.into_iter().cloned().collect();
        sorted.sort_by_key(|p| std::fs::metadata(p).unwrap().len());
        (sorted[0].clone(), sorted[1].clone())
    };
    assert_ne!(std::fs::metadata(&first).unwrap().len(), std::fs::metadata(&second).unwrap().len());
    std::fs::copy(&first, &second).unwrap();
    // The database notices when it opens (it checks every attachment it keeps), or the read does.
    let reopened = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(dir.clone())
                .has_cache(false)
                .blob_enabled(true)
                .encryption(keys(Some(1), Some(2)))
                .register_sealed_blob::<Dossier>("dossiers"),
        )
        .build();
    match reopened {
        Err(ClError::DataTampered) => {}
        Err(other) => panic!("wrong error {other:?}"),
        Ok(s) => {
            let victim = if a.len() < b.len() { "d2" } else { "d1" };
            match s.domain::<Dossier>().repo().open_blob(victim) {
                Err(ClError::DataTampered) => {}
                Err(other) => panic!("wrong error {other:?}"),
                Ok(mut reader) => {
                    let mut out = Vec::new();
                    match reader.read_to_end(&mut out) {
                        Err(e) if clove1db::encrypted_store::is_tamper(&e) => {}
                        other => panic!("other bytes or a wrong error: {other:?}"),
                    }
                }
            }
        }
    }
}
