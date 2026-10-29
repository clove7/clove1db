//! Search fingerprints: a keyed fingerprint of a normalised value, equal across rows, matched with
//! the search key, never readable as a value.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{Sealed, SearchPrint},
    fields::{Field, ValueKind},
    query::Asc,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Contact {
    id: String,
    name: String,
    #[clove(search_print, id = 1, normalize = "trim,lowercase")]
    email: SearchPrint,
    #[clove(encrypt, id = 2)]
    full_name: Sealed<String>,
}
impl Entity for Contact {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same table and fields, but the email is only trimmed.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct ContactTrimOnly {
    id: String,
    name: String,
    #[clove(search_print, id = 1, normalize = "trim")]
    email: SearchPrint,
    #[clove(encrypt, id = 2)]
    full_name: Sealed<String>,
}
impl Entity for ContactTrimOnly {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn contact(id: &str, email: &str) -> Contact {
    Contact { id: id.into(), name: "visible".into(), email: SearchPrint::new(email), full_name: Sealed::new("Alice Example".into()) }
}

fn keys(read: Option<u8>, search: Option<u8>) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: read.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
        search: search.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

/// Under `--cfg clove_test_encrypt_all` every database starts encrypted as a whole.
fn base(dir: &Path) -> DatabaseConfig {
    DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false).backup_enabled(true)
}

/// The keys for the protected fields: their own keys in an ordinary database, the keys of the
/// encryption of the whole database under the test cfg.
fn with_keys(db: DatabaseConfig, config: EncryptionConfig) -> DatabaseConfig {
    #[cfg(clove_test_encrypt_all)]
    {
        db.encryption(config)
    }
    #[cfg(not(clove_test_encrypt_all))]
    {
        db.field_encryption(config)
    }
}

/// An ordinary database with field keys, also under the test cfg: a program with only the search
/// key and a scan of readable files exist only there (listed in 7-5-plain-only.md).
fn open_field_mode(dir: &Path, config: EncryptionConfig) -> clove1db::units::Result<Storage> {
    let db = base(dir);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    Storage::builder(StorageConfig::default())
        .add_database(db.field_encryption(config).register_sealed::<Contact>("contacts"))
        .build()
}

fn open(dir: &Path, config: EncryptionConfig) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(dir), config).register_sealed::<Contact>("contacts"))
        .build()
}

fn open_trim_only(dir: &Path, config: EncryptionConfig) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(dir), config).register_sealed::<ContactTrimOnly>("contacts"))
        .build()
}

fn raw_json(s: &Storage, id: &str) -> serde_json::Value {
    let bytes = s
        .db_manager("store")
        .get_uncached(TableDefinition::<&str, &[u8]>::new("contacts"), id)
        .unwrap()
        .expect("row exists");
    serde_json::from_slice(&bytes).unwrap()
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

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn the_same_email_gives_the_same_stored_fingerprint_in_every_row_and_matches_after_normalising() {
    let dir = temp_dir();
    let s = open(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Contact>();
    domain.repo().set("c1", &contact("c1", "  Alice@Example.COM ")).unwrap();
    domain.repo().set("c2", &contact("c2", "alice@example.com")).unwrap();
    domain.repo().set("c3", &contact("c3", "bob@example.com")).unwrap();
    let (j1, j2, j3) = (raw_json(&s, "c1"), raw_json(&s, "c2"), raw_json(&s, "c3"));
    assert_eq!(j1["email"].as_str().unwrap().len(), 43);
    assert_eq!(j1["email"], j2["email"], "equal values, equal fingerprints, in any row");
    assert_ne!(j1["email"], j3["email"]);
    assert!(!j1.to_string().to_lowercase().contains("alice@"));
    let verifier = domain.verifier().unwrap();
    let c1 = domain.repo().get("c1").unwrap();
    assert!(c1.email.matches("ALICE@example.com  ", &verifier).unwrap());
    assert!(c1.email.matches("alice@example.com", &verifier).unwrap());
    assert!(!c1.email.matches("bob@example.com", &verifier).unwrap());
    assert!(!c1.email.matches("alice@example.org", &verifier).unwrap());
    let c3 = domain.repo().get("c3").unwrap();
    assert!(c3.email.matches("Bob@Example.com", &verifier).unwrap());
    assert!(!c3.email.matches("alice@example.com", &verifier).unwrap());
}

#[test]
fn a_fingerprint_is_kept_when_unchanged_and_replaced_when_the_value_is_replaced() {
    let dir = temp_dir();
    let s = open(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Contact>();
    domain.repo().set("c1", &contact("c1", "alice@example.com")).unwrap();
    let first = raw_json(&s, "c1");
    let read = domain.repo().get("c1").unwrap();
    domain.repo().set("c1", &read).unwrap();
    assert_eq!(raw_json(&s, "c1")["email"], first["email"]);
    let mut changed = domain.repo().get("c1").unwrap();
    changed.email = SearchPrint::new("carol@example.com");
    domain.repo().set("c1", &changed).unwrap();
    assert_ne!(raw_json(&s, "c1")["email"], first["email"]);
    let verifier = domain.verifier().unwrap();
    let now = domain.repo().get("c1").unwrap();
    assert!(now.email.matches("carol@example.com", &verifier).unwrap());
    assert!(!now.email.matches("alice@example.com", &verifier).unwrap());
}

#[test]
fn a_fingerprint_is_not_tied_to_a_row_by_design() {
    // Equal values must give equal fingerprints in every row, so a fingerprint copied to another
    // row is accepted and makes that row match the same value. Documented, and tested so it is a
    // decision and not an accident.
    let dir = temp_dir();
    let s = open(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Contact>();
    domain.repo().set("c1", &contact("c1", "alice@example.com")).unwrap();
    domain.repo().set("c2", &contact("c2", "bob@example.com")).unwrap();
    let mut moved = domain.repo().get("c2").unwrap();
    moved.email = domain.repo().get("c1").unwrap().email;
    domain.repo().set("c2", &moved).unwrap();
    assert_eq!(raw_json(&s, "c2")["email"], raw_json(&s, "c1")["email"]);
}

#[test]
fn no_email_text_appears_in_any_file_and_the_field_cannot_be_queried() {
    let dir = temp_dir();
    {
        let s = open_field_mode(&dir, keys(Some(1), Some(2))).unwrap();
        let domain = s.domain::<Contact>();
        for i in 0..20 {
            domain.repo().set(&format!("c{i}"), &contact(&format!("c{i}"), &format!("person{i}@example.com"))).unwrap();
        }
        // `Contact::email` is a handle and has no `exists`; the same conditions made by hand on the
        // stored path are refused when the query runs (what is checked since 9-1 is stronger: see
        // tests/sealed_search_full.rs).
        let by_hand = Field::<Contact, String>::new("email", ValueKind::Auto);
        let err = domain.query().filter(by_hand.clone().exists()).count().unwrap_err();
        assert!(matches!(&err, ClError::Validation(t) if t.contains("protected field")), "{err:?}");
        assert!(domain.query().order_by(by_hand, Asc).collect().is_err());
        s.close();
    }
    let mut ordinary = false;
    for path in walk(&dir) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(!contains(&bytes, b"person"), "an email was found in {}", path.display());
        assert!(!contains(&bytes, b"Alice Example"), "a name was found in {}", path.display());
        ordinary |= contains(&bytes, b"visible");
    }
    assert!(ordinary, "the scan itself is blind");
}

#[test]
fn the_search_key_alone_matches_but_cannot_write() {
    let dir = temp_dir();
    {
        let s = open_field_mode(&dir, keys(Some(1), Some(2))).unwrap();
        s.domain::<Contact>().repo().set("c1", &contact("c1", "alice@example.com")).unwrap();
        s.close();
    }
    let s = open_field_mode(&dir, keys(None, Some(2))).unwrap();
    let domain = s.domain::<Contact>();
    let read = domain.repo().get("c1").unwrap();
    let verifier = domain.verifier().unwrap();
    assert!(read.email.matches("ALICE@example.com", &verifier).unwrap());
    assert!(!read.email.matches("bob@example.com", &verifier).unwrap());
    let err = domain.repo().set("c2", &contact("c2", "x@example.com")).unwrap_err();
    assert!(matches!(err, ClError::Validation(_)), "{err:?}");
}

#[test]
fn the_read_key_alone_cannot_make_or_match_a_fingerprint() {
    let dir = temp_dir();
    {
        let s = open(&dir, keys(Some(1), Some(2))).unwrap();
        s.domain::<Contact>().repo().set("c1", &contact("c1", "alice@example.com")).unwrap();
        s.close();
    }
    let s = open(&dir, keys(Some(1), None)).unwrap();
    let domain = s.domain::<Contact>();
    let read = domain.repo().get("c1").unwrap();
    let verifier = domain.verifier().unwrap();
    let err = read.email.matches("alice@example.com", &verifier).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("no search key")), "{err:?}");
    let err = domain.repo().set("c2", &contact("c2", "x@example.com")).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("no search key")), "{err:?}");
    // A row read and written back keeps its fingerprint: nothing is made.
    domain.repo().set("c1", &read).unwrap();
}

#[test]
fn a_value_that_is_not_text_is_refused_and_a_new_or_outside_value_cannot_be_matched() {
    let dir = temp_dir();
    let s = open(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Contact>();
    let mut bad = contact("c1", "x");
    bad.email = SearchPrint::new([0xffu8, 0xfe]);
    let err = domain.repo().set("c1", &bad).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("must be text")), "{err:?}");
    let verifier = domain.verifier().unwrap();
    let err = SearchPrint::new("x").matches("x", &verifier).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("not been written")), "{err:?}");
    domain.repo().set("c1", &contact("c1", "alice@example.com")).unwrap();
    let read = domain.repo().get("c1").unwrap();
    let outside: Contact = serde_json::from_str(&serde_json::to_string(&read).unwrap()).unwrap();
    let err = outside.email.matches("alice@example.com", &verifier).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("not read from a storage")), "{err:?}");
}

#[test]
fn changing_the_normalisation_is_a_migration_and_writes_nothing() {
    let dir = temp_dir();
    {
        let s = open(&dir, keys(Some(1), Some(2))).unwrap();
        s.domain::<Contact>().repo().set("c1", &contact("c1", "alice@example.com")).unwrap();
        s.close();
    }
    let others = |dir: &Path| -> std::collections::BTreeMap<String, Vec<u8>> {
        walk(dir)
            .into_iter()
            .filter(|p| p.extension().is_none_or(|e| e != "cldb"))
            .map(|p| (p.strip_prefix(dir).unwrap().display().to_string(), std::fs::read(&p).unwrap()))
            .collect()
    };
    let before = others(&dir);
    let err = open_trim_only(&dir, keys(Some(1), Some(2))).err().expect("must be refused");
    match &err {
        ClError::Validation(t) => {
            assert!(t.contains("fingerprint settings") && t.contains("migration") && t.contains("nothing was written"), "{t}");
            assert!(!t.to_lowercase().contains("lowercase"), "{t}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    let after = others(&dir);
    assert_eq!(before.keys().collect::<Vec<_>>(), after.keys().collect::<Vec<_>>());
    for (name, bytes) in &before {
        assert!(after[name] == *bytes, "{name} was changed by a refused open");
    }
    // The description: the fingerprint field carries a check, the encrypted field does not.
    let s = open(&dir, keys(Some(1), Some(2))).unwrap();
    let meta = s.db_manager("store").read_meta().unwrap().unwrap();
    let table = meta.tables.into_iter().find(|t| t.name == "contacts").unwrap();
    let checks: Vec<(u32, Option<usize>)> = table.sealed.iter().map(|f| (f.id, f.check.as_ref().map(|c| c.len()))).collect();
    assert_eq!(checks, [(1, Some(43)), (2, None)]);
    // The search key alone cannot compare it with its own settings the other way round: it can,
    // since it holds the key; a read-key-only program cannot and opens.
    drop(s);
    drop(open_trim_only(&dir, keys(Some(1), None)).unwrap());
}
