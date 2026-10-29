//! A protected field never appears as text in a file, an index, a statistic or a history, and cannot
//! be used to filter, order, group or aggregate. The handle that a sealed field without a fingerprint
//! has (`ScanHandle`) has no such methods, so asking the compiler is the first line (the compile_fail
//! examples of `ScanHandle` and `HashHandle`); a field made by hand with the same name (`PHONE`, `TAGS`
//! below) gets past the compiler, and the query still refuses it, as before.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, Unique,
    fields::{Field, ValueKind},
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::Sealed,
    query::Asc,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Person {
    id: String,
    name: String,
    group: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(encrypt, id = 2)]
    tags: Sealed<Vec<String>>,
}
impl Entity for Person {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The stored names of the two protected fields as ordinary fields, which the derive no longer makes.
const PHONE: Field<Person, String> = Field::new("phone", ValueKind::Auto);
const TAGS: Field<Person, String> = Field::new("tags", ValueKind::Auto);

fn person_in(id: &str, group: &str, phone: &str, tag: &str) -> Person {
    Person {
        id: id.into(),
        name: "visible".into(),
        group: group.into(),
        phone: Sealed::new(phone.into()),
        tags: Sealed::new(vec![tag.into()]),
    }
}

fn person(id: &str, phone: &str, tag: &str) -> Person {
    person_in(id, "g0", phone, tag)
}

fn keys() -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
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
fn with_keys(db: DatabaseConfig) -> DatabaseConfig {
    #[cfg(clove_test_encrypt_all)]
    {
        db.encryption(keys())
    }
    #[cfg(not(clove_test_encrypt_all))]
    {
        db.field_encryption(keys())
    }
}

fn open(dir: &Path) -> Storage {
    Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(dir)).register_sealed::<Person>("people"))
        .build()
        .unwrap()
}

/// A database that is not encrypted as a whole, with field keys, also under the test cfg: the
/// decisive test needs files whose bytes can be searched (listed in 7-5-plain-only.md).
fn open_field_mode(dir: &Path) -> Storage {
    let db = base(dir);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    Storage::builder(StorageConfig::default())
        .add_database(db.field_encryption(keys()).register_sealed::<Person>("people"))
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

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn refused<T>(result: clove1db::units::Result<T>, what: &str) {
    match result {
        Err(ClError::Validation(text)) => {
            assert!(text.contains("protected field"), "{what}: {text}");
            assert!(text.contains("phone") || text.contains("tags"), "{what}: {text}");
        }
        Err(other) => panic!("{what}: wrong error {other:?}"),
        Ok(_) => panic!("{what}: was not refused"),
    }
}

#[test]
fn a_protected_field_cannot_filter_order_group_or_aggregate() {
    let s = open(&temp_dir());
    let domain = s.domain::<Person>();
    domain.repo().set("p1", &person("p1", "+155511111111", "vip")).unwrap();
    let q = || domain.query();
    refused(q().filter(PHONE.exists()).count(), "count");
    refused(q().filter(PHONE.exists()).collect(), "collect");
    refused(q().filter(PHONE.exists()).exists(), "exists");
    refused(q().filter(TAGS.exists()).page(), "page");
    refused(q().filter(PHONE.exists()).explain(), "explain");
    refused(q().order_by(PHONE, Asc).collect(), "order_by");
    refused(q().filter(Person::name.eq("visible".to_string())).then_by(TAGS, Asc).collect(), "then_by");
    refused(q().distinct(PHONE), "distinct");
    refused(q().min(PHONE), "min");
    refused(q().max(TAGS), "max");
    refused(q().sum(PHONE), "sum");
    refused(q().group_by(PHONE).count(), "group_by");
    refused(q().statistics(PHONE), "statistics");
    // The ordinary fields of the same entity still work.
    assert_eq!(q().filter(Person::name.eq("visible".to_string())).count().unwrap(), 1);
    assert_eq!(q().order_by(Person::name, Asc).collect().unwrap().len(), 1);
    assert_eq!(q().distinct(Person::name).unwrap().len(), 1);
}

#[test]
fn a_unique_constraint_on_a_protected_field_is_refused_before_any_file_is_made() {
    let dir = temp_dir();
    let err = Storage::builder(StorageConfig::default())
        .add_database(
            with_keys(base(&dir))
                .unique(Unique::on(PHONE))
                .register_sealed::<Person>("people"),
        )
        .build()
        .err()
        .expect("must be refused");
    assert!(matches!(&err, ClError::Validation(t) if t.contains("unique constraint cannot use it")), "{err:?}");
    assert!(walk(&dir).is_empty(), "files left behind");
    // A constraint on an ordinary field of the same entity is fine.
    let s = Storage::builder(StorageConfig::default())
        .add_database(
            with_keys(base(&dir))
                .unique(Unique::on(Person::name))
                .register_sealed::<Person>("people"),
        )
        .build()
        .unwrap();
    s.domain::<Person>().repo().set("p1", &person("p1", "+155511111111", "vip")).unwrap();
    assert!(s.domain::<Person>().repo().set("p2", &person("p2", "+155511111112", "vip")).is_err());
}

/// The decisive test: a plain database (not encrypted as a whole) goes through creating, updating,
/// deleting, restoring, querying until an index is built, and closing, with known values in every
/// protected field; then every file of the folder is searched, byte by byte, for those values.
/// The files searched are printed with their sizes, and an index file must be among them.
#[test]
fn no_protected_value_appears_in_any_file_after_a_full_life() {
    let dir = temp_dir();
    let markers = [
        "+155511111101", "+155511111102", "+155511111103", "+155511111104", "+155511111105",
        "tagmarker-alpha", "tagmarker-beta", "tagmarker-gamma",
    ];
    // 150 more rows, each with its own phone and tag, so that an index on an ordinary field pays off.
    let bulk: Vec<Person> = (0..150)
        .map(|i| person_in(&format!("b{i:03}"), &format!("g{}", i % 5), &format!("+1555200{i:05}"), &format!("bulktag-{i:03}")))
        .collect();
    let history_text;
    {
        let s = open_field_mode(&dir);
        let domain = s.domain::<Person>();
        let repo = domain.repo();
        for i in 1..=5 {
            repo.set(&format!("p{i}"), &person(&format!("p{i}"), markers[i - 1], markers[5 + (i % 3)])).unwrap();
        }
        let writes: Vec<(&str, &Person)> = bulk.iter().map(|p| (p.id.as_str(), p)).collect();
        repo.commit_entities(&writes, &[]).unwrap();
        // An update (a second version of the row), a delete, a restore of the first version.
        repo.set("p1", &person("p1", "+155511111101", "tagmarker-beta")).unwrap();
        domain.restore_by_version("p1", 1).unwrap();
        domain.delete("p5").unwrap();
        // Query an ordinary field until an index on it is built (the optimizer makes it from use).
        let started = Instant::now();
        loop {
            let found = domain.query().filter(Person::group.eq("g3".to_string())).count().unwrap();
            assert_eq!(found, 30);
            if s.index_report().iter().any(|r| r.ready) {
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(15), "no index became ready: {:?}", s.index_report());
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(domain.query().order_by(Person::name, Asc).collect().unwrap().len(), 154);
        // The history and the listing as they are exported to a caller.
        history_text = serde_json::to_string(&domain.history("p1").unwrap()).unwrap()
            + &serde_json::to_string(&repo.list().unwrap()).unwrap();
        s.close();
    }
    let mut ordinary_seen = false;
    let mut index_file_seen = false;
    let files = walk(&dir);
    println!("FILES SEARCHED: {}", files.len());
    for path in &files {
        let bytes = std::fs::read(path).unwrap();
        println!("  {:>10} bytes  {}", bytes.len(), path.strip_prefix(&dir).unwrap().display());
        for marker in markers {
            assert!(!contains(&bytes, marker.as_bytes()), "{marker} found in {}", path.display());
        }
        for i in (0..150).step_by(7) {
            assert!(!contains(&bytes, format!("+1555200{i:05}").as_bytes()), "bulk phone {i} in {}", path.display());
            assert!(!contains(&bytes, format!("bulktag-{i:03}").as_bytes()), "bulk tag {i} in {}", path.display());
        }
        ordinary_seen |= contains(&bytes, b"visible");
        index_file_seen |= path.extension().is_some_and(|e| e == "inx");
        assert!(!path.to_string_lossy().contains("marker"), "{}", path.display());
    }
    assert!(ordinary_seen, "the scan itself is blind: an ordinary field was not found in any file");
    assert!(index_file_seen, "no index file was among the files searched");
    for marker in markers {
        assert!(!history_text.contains(marker), "{marker} in the history or the listing");
    }
    assert!(!history_text.contains("+1555200"), "a bulk phone in the history or the listing");
    assert!(history_text.contains("visible"), "the history check is blind");
}
