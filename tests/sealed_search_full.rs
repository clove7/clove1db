//! Searching by the fingerprint of a whole value: equality and lists, unique constraints, the key
//! split between searching and reading, and nothing of a searched value in a query, an event or a file.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent, Unique,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{Sealed, SearchPrint},
    fields::{Field, TransformKind, ValueKind, transform},
    query::optimizer::Plan,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Account {
    id: String,
    group: String,
    #[clove(encrypt, id = 1, print = "full", normalize = "trim,arabic")]
    phone: Sealed<String>,
    #[clove(search_print, id = 2, normalize = "trim,lowercase")]
    token: SearchPrint,
    #[clove(encrypt, id = 3)]
    note: Sealed<String>,
}
impl Entity for Account {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same table, but the phone is normalised less.
#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct AccountTrimOnly {
    id: String,
    group: String,
    #[clove(encrypt, id = 1, print = "full", normalize = "trim")]
    phone: Sealed<String>,
    #[clove(search_print, id = 2, normalize = "trim,lowercase")]
    token: SearchPrint,
    #[clove(encrypt, id = 3)]
    note: Sealed<String>,
}
impl Entity for AccountTrimOnly {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn account(id: &str, group: &str, phone: &str, token: &str) -> Account {
    Account {
        id: id.into(),
        group: group.into(),
        phone: Sealed::new(phone.into()),
        token: SearchPrint::new(token),
        note: Sealed::new(format!("note of {id}")),
    }
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

/// An ordinary database with field keys, also under the test cfg (a scan of readable files and a
/// program with only the search key exist only there).
fn plain_with_keys(dir: &Path, config: EncryptionConfig) -> DatabaseConfig {
    let db = base(dir);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    db.field_encryption(config)
}

fn open(dir: &Path, config: EncryptionConfig) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(dir), config).register_sealed::<Account>("accounts"))
        .build()
}

fn open_plain(dir: &Path, config: EncryptionConfig) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(plain_with_keys(dir, config).register_sealed::<Account>("accounts"))
        .build()
}

fn raw_json(s: &Storage, id: &str) -> serde_json::Value {
    let bytes = s
        .db_manager("store")
        .get_uncached(TableDefinition::<&str, &[u8]>::new("accounts"), id)
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

fn arabic_digits(text: &str) -> String {
    text.chars().map(|c| if c.is_ascii_digit() { char::from_u32('٠' as u32 + (c as u32 - '0' as u32)).unwrap() } else { c }).collect()
}

fn ids_of(rows: Vec<Account>) -> BTreeSet<String> {
    rows.into_iter().map(|r| r.id).collect()
}

/// A pseudo-random phone number of ten digits; the same `i` gives the same number.
fn phone_of(i: u64) -> String {
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(12345);
    x ^= x >> 29;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 32;
    format!("05{:08}", x % 100_000_000)
}

/// How the row is written: plain digits, Arabic-Indic digits, or padded with spaces.
fn written_as(i: u64, phone: &str) -> String {
    match i % 3 {
        1 => arabic_digits(phone),
        2 => format!("  {phone} "),
        _ => phone.to_string(),
    }
}

fn normal(text: &str) -> String {
    transform(&transform(text, &TransformKind::Trim), &TransformKind::NormalizeArabic)
}

// ---------------------------------------------------------------------------------------------

/// The decisive correctness test: for many needles, in several spellings, the answer of the
/// search (before and after an index exists) is the answer of a scan that opens every row.
#[test]
fn equality_search_matches_a_scan_that_opens_every_row() {
    const ROWS: u64 = 30_000;
    let dir = temp_dir();
    let s = open(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Account>();
    let repo = domain.repo();
    // Numbers repeat: every phone appears about three times.
    let mut stored: Vec<(String, String)> = Vec::new();
    let mut batch: Vec<Account> = Vec::new();
    for i in 0..ROWS {
        let phone = phone_of(i % (ROWS / 3));
        let written = written_as(i, &phone);
        batch.push(account(&format!("a{i:06}"), &format!("g{}", i % 7), &written, &format!("tok-{i:06}")));
        stored.push((format!("a{i:06}"), phone));
        if batch.len() == 1000 {
            let writes: Vec<(&str, &Account)> = batch.iter().map(|a| (a.id.as_str(), a)).collect();
            repo.commit_entities(&writes, &[]).unwrap();
            batch.clear();
        }
    }
    // The oracle: open every row's phone with the read grant and normalise it.
    let read = domain.read_grant().unwrap();
    let mut opened: Vec<(String, String)> = Vec::new();
    for row in domain.query().collect().unwrap() {
        opened.push((row.id.clone(), normal(&row.phone.open(&read).unwrap())));
    }
    opened.sort();
    assert_eq!(opened.len() as u64, ROWS);
    for (id, phone) in &stored {
        assert_eq!(&opened.iter().find(|(i, _)| i == id).unwrap().1, phone);
    }
    let expected = |needle: &str| -> BTreeSet<String> {
        let want = normal(needle);
        opened.iter().filter(|(_, p)| *p == want).map(|(i, _)| i.clone()).collect()
    };
    let grant = domain.search_grant().unwrap();
    let search = |needle: &str| ids_of(domain.query().filter(Account::phone.print_eq(needle, &grant)).collect().unwrap());

    let mut needles: Vec<String> = (0..40).map(|k| phone_of((k * 997) % (ROWS / 3))).collect();
    needles.extend((0..6).map(|k| arabic_digits(&phone_of(k * 31))));
    needles.extend((0..4).map(|k| format!("   {}  ", phone_of(k * 17))));
    needles.extend(["5500000000", "5599999999", "", "x"].map(String::from));
    // Before the index: the answers come from a scan of the stored fingerprints.
    for needle in needles.iter().take(12) {
        assert_eq!(search(needle), expected(needle), "scan, needle {needle:?}");
    }
    // Ask until the optimizer has built an index on the fingerprint and uses it.
    let started = Instant::now();
    let probe = phone_of(7);
    loop {
        let q = domain.query().filter(Account::phone.print_eq(&probe, &grant));
        let _ = q.count().unwrap();
        if q.explain().unwrap().selected == Plan::IndexEquality {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(120), "no index on the fingerprint: {:?}", s.index_report());
        std::thread::sleep(Duration::from_millis(20));
    }
    for needle in &needles {
        assert_eq!(search(needle), expected(needle), "index, needle {needle:?}");
    }
    // A list of values is the union of the answers.
    let list = [phone_of(1), arabic_digits(&phone_of(2)), phone_of(3), "5500000000".into()];
    let want: BTreeSet<String> = list.iter().flat_map(|n| expected(n)).collect();
    let got = ids_of(domain.query().filter(Account::phone.print_in(&list, &grant)).collect().unwrap());
    assert_eq!(got, want);
    // And combined with an ordinary condition.
    let both = ids_of(
        domain.query().filter(Account::phone.print_eq(&phone_of(5), &grant).and(Account::group.eq("g5".to_string()))).collect().unwrap(),
    );
    let want_both: BTreeSet<String> = expected(&phone_of(5)).into_iter().filter(|id| id[1..].parse::<u64>().unwrap() % 7 == 5).collect();
    assert_eq!(both, want_both);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_search_fingerprint_field_is_searched_with_its_normalisation() {
    let dir = temp_dir();
    let s = open(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Account>();
    for i in 0..10 {
        domain.repo().set(&format!("t{i}"), &account(&format!("t{i}"), "g", "5501111111", &format!("  Token-{i}-ALPHA "))).unwrap();
    }
    let grant = domain.search_grant().unwrap();
    for i in 0..10 {
        let found = ids_of(domain.query().filter(Account::token.print_eq(format!("token-{i}-alpha"), &grant)).collect().unwrap());
        assert_eq!(found, BTreeSet::from([format!("t{i}")]));
        let padded = ids_of(domain.query().filter(Account::token.print_eq(format!(" TOKEN-{i}-Alpha  "), &grant)).collect().unwrap());
        assert_eq!(padded, found);
    }
    assert_eq!(domain.query().filter(Account::token.print_eq("token-99-alpha", &grant)).count().unwrap(), 0);
    // An empty list matches nothing.
    assert_eq!(domain.query().filter(Account::token.print_in(Vec::<String>::new(), &grant)).count().unwrap(), 0);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_row_is_stored_with_its_sealed_text_and_its_fingerprint_and_nothing_else() {
    let dir = temp_dir();
    let s = open_plain(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Account>();
    domain.repo().set("r1", &account("r1", "g", "5501234567", "Tok-1")).unwrap();
    let json = raw_json(&s, "r1");
    let phone = json["phone"].as_object().expect("a sealed field with a fingerprint is stored as an object");
    assert_eq!(phone.keys().collect::<Vec<_>>(), ["f", "s"]);
    assert_eq!(phone["f"].as_str().unwrap().len(), 43);
    assert!(!phone["s"].as_str().unwrap().contains("5501234567"));
    assert_eq!(json["token"].as_str().unwrap().len(), 43);
    assert!(json["note"].is_string(), "a sealed field without a fingerprint stays text");
    // The whole row says nothing of the values.
    let text = json.to_string();
    for secret in ["5501234567", "Tok-1", "tok-1", "note of r1"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
    // The value still opens, with the read grant.
    let read = domain.read_grant().unwrap();
    assert_eq!(domain.repo().get("r1").unwrap().phone.open(&read).unwrap(), "5501234567");
    s.close();
}

/// A value read and written back keeps its fingerprint (it cannot be made again without opening
/// the value); a new value gets a new one.
#[test]
fn a_value_written_back_keeps_its_fingerprint_and_a_new_value_gets_a_new_one() {
    let dir = temp_dir();
    let s = open_plain(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Account>();
    let repo = domain.repo();
    repo.set("a1", &account("a1", "g1", "5501111111", "t1")).unwrap();
    repo.set("a2", &account("a2", "g1", "5502222222", "t2")).unwrap();
    let before = raw_json(&s, "a1");

    let mut row = repo.get("a1").unwrap();
    row.group = "g9".into();
    repo.set("a1", &row).unwrap();
    let after = raw_json(&s, "a1");
    assert_eq!(after["phone"], before["phone"], "the closed value was written back as it was");
    assert_eq!(after["group"], "g9");

    let grant = domain.search_grant().unwrap();
    let find = |phone: &str| ids_of(domain.query().filter(Account::phone.print_eq(phone, &grant)).collect().unwrap());
    assert_eq!(find("5501111111"), BTreeSet::from(["a1".to_string()]));

    let mut row = repo.get("a1").unwrap();
    row.phone = Sealed::new("5503333333".into());
    repo.set("a1", &row).unwrap();
    let changed = raw_json(&s, "a1");
    assert_ne!(changed["phone"]["f"], before["phone"]["f"]);
    assert_eq!(find("5501111111"), BTreeSet::new());
    assert_eq!(find("5503333333"), BTreeSet::from(["a1".to_string()]));

    // A closed value moved to another row is refused, the fingerprint with it.
    let mut other = repo.get("a2").unwrap();
    other.phone = repo.get("a1").unwrap().phone;
    let err = repo.set("a2", &other).unwrap_err().to_string();
    assert!(err.contains("can only be written back"), "{err}");
    assert_eq!(find("5502222222"), BTreeSet::from(["a2".to_string()]));
    s.close();
}

// ---------------------------------------------------------------------------------------------

/// Anything but the handle's own conditions on a protected field is refused, even when it is built
/// by hand on the very path of the fingerprint. The value is not fingerprinted, and not seen
/// anywhere, because the refusal comes first.
#[test]
fn a_condition_built_by_hand_on_a_fingerprint_path_is_refused_and_its_value_is_seen_nowhere() {
    let dir = temp_dir();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let config = StorageConfig::default().event_sink(move |e: &LibraryEvent| sink.lock().unwrap().push(format!("{e:?}")));
    let s = Storage::builder(config)
        .add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Account>("accounts"))
        .build()
        .unwrap();
    let domain = s.domain::<Account>();
    domain.repo().set("a1", &account("a1", "g", "5509876543", "Secret-Token-Zeta")).unwrap();

    let phone_path = Field::<Account, String>::new("phone", ValueKind::Auto).then(Field::<String, String>::new("f", ValueKind::Auto));
    let phone_text = Field::<Account, String>::new("phone", ValueKind::Auto);
    let token_path = Field::<Account, String>::new("token", ValueKind::Auto);
    let raw = "5509876543";
    let token_raw = "Secret-Token-Zeta";
    let attempts = vec![
        ("fingerprint path, raw value", domain.query().filter(phone_path.clone().eq(raw.to_string()))),
        ("fingerprint path, raw list", domain.query().filter(phone_path.clone().in_([raw.to_string()]))),
        ("fingerprint path, range", domain.query().filter(phone_path.clone().gt(raw.to_string()))),
        ("fingerprint path, prefix", domain.query().filter(phone_path.clone().prefix(raw.to_string()))),
        ("sealed text path", domain.query().filter(phone_text.clone().eq(raw.to_string()))),
        ("search print, raw value", domain.query().filter(token_path.clone().eq(token_raw.to_string()))),
        ("search print, contains", domain.query().filter(token_path.clone().contains(token_raw.to_string()))),
    ];
    for (what, query) in attempts {
        let err = query.count().expect_err(what);
        assert!(matches!(&err, ClError::Validation(t) if t.contains("protected field") || t.contains("search grant")), "{what}: {err:?}");
        assert!(query.collect().is_err(), "{what}");
        assert!(query.explain().is_err(), "{what}");
    }
    // A fingerprint a handle made for one value cannot be reused for another path.
    let grant = domain.search_grant().unwrap();
    let ok = domain.query().filter(Account::phone.print_eq(raw, &grant));
    assert_eq!(ok.count().unwrap(), 1);

    // What the handle makes never carries the value: not its debug text, not the fingerprint of the query.
    let predicate = Account::phone.print_eq(raw, &grant);
    let token_predicate = Account::token.print_eq(token_raw, &grant);
    for p in [format!("{predicate:?}"), format!("{token_predicate:?}"), format!("{grant:?}"), format!("{:?}", Account::phone)] {
        assert!(!p.contains(raw) && !p.contains("Zeta") && !p.contains("zeta"), "{p}");
    }
    let bytes = predicate.fingerprint().unwrap();
    assert!(!contains(&bytes, raw.as_bytes()) && !contains(&bytes, b"5509876543"));
    let bytes = token_predicate.fingerprint().unwrap();
    assert!(!contains(&bytes, token_raw.as_bytes()) && !contains(&bytes, b"zeta"));
    // Nor an event.
    assert_eq!(domain.query().filter(token_predicate).count().unwrap(), 1);
    s.close();
    for event in seen.lock().unwrap().iter() {
        assert!(!event.contains(raw) && !event.to_lowercase().contains("zeta"), "{event}");
    }
    assert!(!seen.lock().unwrap().is_empty(), "the sink saw nothing: the check is blind");
    std::fs::remove_dir_all(&dir).ok();
}

/// A fingerprint made for the grant of one entity is not accepted by a handle that did not issue it.
#[test]
fn a_fingerprint_lifted_out_of_a_predicate_is_not_a_way_around_the_check() {
    let dir = temp_dir();
    let s = open(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Account>();
    domain.repo().set("a1", &account("a1", "g", "5501111111", "t")).unwrap();
    let grant = domain.search_grant().unwrap();
    // The fingerprint text is in the row; copying it into a hand-made condition is still refused,
    // since the query only accepts the ones its predicates carry.
    let stored = {
        let bytes = s.db_manager("store").get_uncached(TableDefinition::<&str, &[u8]>::new("accounts"), "a1").unwrap().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["phone"]["f"].as_str().map(String::from).unwrap_or_default()
    };
    assert_eq!(stored.len(), 43, "the stored fingerprint is not where the test looks");
    let phone_path = Field::<Account, String>::new("phone", ValueKind::Auto).then(Field::<String, String>::new("f", ValueKind::Auto));
    let by_hand = domain.query().filter(phone_path.eq(stored));
    assert!(by_hand.count().is_err());
    assert_eq!(domain.query().filter(Account::phone.print_eq("5501111111", &grant)).count().unwrap(), 1);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------------------------

fn open_unique(dir: &Path) -> Storage {
    Storage::builder(StorageConfig::default())
        .add_database(
            with_keys(base(dir), keys(Some(1), Some(2)))
                .unique::<Account>(Unique::on(Account::phone.print_field()))
                .unique::<Account>(Unique::on(Account::token.print_field()))
                .register_sealed::<Account>("accounts"),
        )
        .build()
        .unwrap()
}

#[test]
fn a_unique_constraint_on_a_fingerprint_stops_a_repeated_value_whatever_its_spelling() {
    let dir = temp_dir();
    let s = open_unique(&dir);
    let domain = s.domain::<Account>();
    let repo = domain.repo();
    repo.set("a1", &account("a1", "g", "5501111111", "token-one")).unwrap();
    // The same number written with other digits, with spaces: the same value after normalisation.
    for spelling in ["٥٥٠١١١١١١١", "  5501111111 "] {
        let err = repo.set("a2", &account("a2", "g", spelling, "token-two")).unwrap_err();
        assert!(matches!(err, ClError::UniqueViolation), "{spelling:?}: {err:?}");
    }
    let err = repo.set("a2", &account("a2", "g", "5502222222", " TOKEN-ONE ")).unwrap_err();
    assert!(matches!(err, ClError::UniqueViolation), "{err:?}");
    assert!(repo.get("a2").is_err(), "the refused row was not saved");
    // Different values are fine, and a row may be written again with its own value.
    repo.set("a2", &account("a2", "g", "5502222222", "token-two")).unwrap();
    let mut again = repo.get("a1").unwrap();
    again.group = "g2".into();
    repo.set("a1", &again).unwrap();
    // Two repeated values in one batch: the batch fails and none of it is saved.
    let (b1, b2) = (account("b1", "g", "5503333333", "token-b1"), account("b2", "g", "5503333333", "token-b2"));
    assert!(repo.commit_entities(&[("b1", &b1), ("b2", &b2)], &[]).is_err());
    assert!(repo.get("b1").is_err() && repo.get("b2").is_err());
    // Deleting frees the value.
    domain.delete("a1").unwrap();
    repo.set("a3", &account("a3", "g", "5501111111", "token-one")).unwrap();
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_unique_constraint_on_the_sealed_text_or_the_raw_field_is_still_refused() {
    let dir = temp_dir();
    let by_hand = Unique::on(Field::<Account, String>::new("phone", ValueKind::Auto));
    let err = Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).unique::<Account>(by_hand).register_sealed::<Account>("accounts"))
        .build()
        .err()
        .expect("must be refused");
    assert!(matches!(&err, ClError::Validation(t) if t.contains("unique constraint cannot use it")), "{err:?}");
    let note = Unique::on(Field::<Account, String>::new("note", ValueKind::Auto));
    assert!(
        Storage::builder(StorageConfig::default())
            .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).unique::<Account>(note).register_sealed::<Account>("accounts"))
            .build()
            .is_err()
    );
    assert!(!dir.exists() || walk(&dir).is_empty(), "files left behind");
}

// ---------------------------------------------------------------------------------------------

/// The key split: the search key finds rows and cannot open anything; the read key alone cannot search.
#[test]
fn a_program_with_the_search_key_alone_finds_rows_and_opens_nothing() {
    let dir = temp_dir();
    {
        let s = open_plain(&dir, keys(Some(1), Some(2))).unwrap();
        let domain = s.domain::<Account>();
        for i in 0..20 {
            domain.repo().set(&format!("a{i:02}"), &account(&format!("a{i:02}"), "g", &format!("55000000{i:02}"), &format!("tok{i}"))).unwrap();
        }
        s.close();
    }
    {
        let s = open_plain(&dir, keys(None, Some(2))).unwrap();
        let domain = s.domain::<Account>();
        let grant = domain.search_grant().expect("the search key is enough to search");
        let found = domain.query().filter(Account::phone.print_eq("5500000007", &grant)).collect().unwrap();
        assert_eq!(ids_of(found.clone()), BTreeSet::from(["a07".to_string()]));
        assert_eq!(domain.query().filter(Account::token.print_eq("tok13", &grant)).count().unwrap(), 1);
        // The row comes back closed, and this program cannot open it.
        let read = domain.read_grant();
        let opened = read.and_then(|g| found[0].phone.open(&g));
        assert!(opened.is_err(), "a program without the read key opened a value");
        // And it cannot write a row, which needs the read key to seal.
        assert!(domain.repo().set("z", &account("z", "g", "5500000099", "tz")).is_err());
        s.close();
    }
    {
        let s = open_plain(&dir, keys(Some(1), None)).unwrap();
        let domain = s.domain::<Account>();
        let err = domain.search_grant().unwrap_err().to_string();
        assert!(err.contains("search key"), "{err}");
        // It can still open values.
        let read = domain.read_grant().unwrap();
        assert_eq!(domain.repo().get("a03").unwrap().phone.open(&read).unwrap(), "5500000003");
        s.close();
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_table_with_a_sealed_fingerprint_cannot_be_created_without_the_search_key() {
    let dir = temp_dir();
    let err = open_plain(&dir, keys(Some(1), None)).err().expect("must be refused").to_string();
    assert!(err.contains("search key"), "{err}");
}

/// Changing how a fingerprint is made is a migration: the stored ones were made with the old way.
#[test]
fn a_changed_normalisation_is_a_migration_and_writes_nothing() {
    let dir = temp_dir();
    {
        let s = open(&dir, keys(Some(1), Some(2))).unwrap();
        s.domain::<Account>().repo().set("a1", &account("a1", "g", "5501111111", "t")).unwrap();
        s.close();
    }
    let before: Vec<(PathBuf, Vec<u8>)> = walk(&dir).into_iter().filter(|p| p.extension().is_none_or(|e| e != "cldb")).map(|p| (p.clone(), std::fs::read(p).unwrap())).collect();
    let err = Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<AccountTrimOnly>("accounts"))
        .build()
        .err()
        .expect("must be refused")
        .to_string();
    assert!(err.contains("migration") && err.contains("nothing was written"), "{err}");
    for (path, bytes) in before {
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{} changed by a refused open", path.display());
    }
    // The right declaration still opens, and finds the row.
    let s = open(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Account>();
    let grant = domain.search_grant().unwrap();
    assert_eq!(domain.query().filter(Account::phone.print_eq("5501111111", &grant)).count().unwrap(), 1);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

/// A table cannot have its settings filled in silently: a field with a fingerprint and no recorded
/// settings is a migration. (A plain database only: the description is edited in the file.)
#[cfg(not(clove_test_encrypt_all))]
#[test]
fn a_table_without_recorded_fingerprint_settings_is_a_migration() {
    use clove1db::metadata::store::{read_meta, write_meta};
    let dir = temp_dir();
    {
        let s = open(&dir, keys(Some(1), Some(2))).unwrap();
        s.domain::<Account>().repo().set("a1", &account("a1", "g", "5501111111", "t")).unwrap();
        s.close();
    }
    let primary = dir.join("records").join("store.cldb");
    let forget = |field_id: u32| {
        let db = redb::Database::open(&primary).unwrap();
        let mut meta = read_meta(&db).unwrap().unwrap();
        let mut seen = false;
        for table in &mut meta.tables {
            for field in &mut table.sealed {
                if field.id == field_id {
                    assert!(field.check.is_some(), "field {field_id} had no recorded settings to forget");
                    field.check = None;
                    seen = true;
                }
            }
        }
        assert!(seen);
        write_meta(&db, &meta).unwrap();
    };
    // A search fingerprint without settings: refused, nothing written. A program without the search
    // key cannot compare them and does not look.
    forget(2);
    let err = open(&dir, keys(Some(1), Some(2))).err().expect("must be refused").to_string();
    assert!(err.contains("migration") && err.contains("nothing was written") && err.contains("fingerprint settings"), "{err}");
    drop(open_plain(&dir, keys(Some(1), None)).expect("a program without the search key does not compare fingerprint settings"));
    // A sealed field with a fingerprint and without settings: the same.
    forget(1);
    let err = open(&dir, keys(Some(1), Some(2))).err().expect("must be refused").to_string();
    assert!(err.contains("migration") && err.contains("nothing was written"), "{err}");
    drop(open_plain(&dir, keys(Some(1), None)).expect("a program without the search key does not compare fingerprint settings"));
    std::fs::remove_dir_all(&dir).ok();
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Login {
    id: String,
    #[clove(hash = "argon2id", id = 1)]
    password: clove1db::field_crypto::Hashed,
}
impl Entity for Login {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same for a verification hash: the table records its settings when it is created, so a table
/// without them is a migration; a program without the read key does not look.
#[cfg(not(clove_test_encrypt_all))]
#[test]
fn a_table_without_recorded_hash_settings_is_a_migration() {
    use clove1db::metadata::store::{read_meta, write_meta};
    let dir = temp_dir();
    let open_login = |config: EncryptionConfig| {
        Storage::builder(StorageConfig::default())
            .add_database(plain_with_keys(&dir, config).register_sealed::<Login>("logins"))
            .build()
    };
    drop(open_login(keys(Some(1), Some(2))).unwrap());
    let primary = dir.join("records").join("store.cldb");
    {
        let db = redb::Database::open(&primary).unwrap();
        let mut meta = read_meta(&db).unwrap().unwrap();
        let field = &mut meta.tables.iter_mut().find(|t| t.name == "logins").unwrap().sealed[0];
        assert!(field.check.is_some(), "the creation recorded the hash settings");
        field.check = None;
        write_meta(&db, &meta).unwrap();
    }
    let err = open_login(keys(Some(1), Some(2))).err().expect("must be refused").to_string();
    assert!(err.contains("migration") && err.contains("hash settings") && err.contains("nothing was written"), "{err}");
    drop(open_login(keys(None, Some(2))).expect("a program without the read key does not compare hash settings"));
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------------------------

/// The decisive exclusion test, as for the sealed fields before it: a plain database goes through
/// writing, searching until an index on the fingerprint exists, updating, deleting, the history and
/// closing; then every file of the folder is searched for the values looked for, in every spelling.
#[test]
fn no_searched_value_appears_in_any_file_or_event() {
    let dir = temp_dir();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let phones = ["5599911101", "5599911102", "5599911103", "5599911104", "5599911105"];
    let tokens = ["Marker-Token-Alpha", "Marker-Token-Beta", "Marker-Token-Gamma"];
    let history_text;
    {
        let config = StorageConfig::default().event_sink(move |e: &LibraryEvent| sink.lock().unwrap().push(format!("{e:?}")));
        let s = Storage::builder(config)
            .add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Account>("accounts"))
            .build()
            .unwrap();
        let domain = s.domain::<Account>();
        let repo = domain.repo();
        for (i, phone) in phones.iter().enumerate() {
            repo.set(&format!("m{i}"), &account(&format!("m{i}"), "visible", phone, tokens[i % 3])).unwrap();
        }
        let bulk: Vec<Account> = (0..200).map(|i| account(&format!("b{i:03}"), "visible", &format!("0577{i:06}"), &format!("bulk-token-{i:03}"))).collect();
        let writes: Vec<(&str, &Account)> = bulk.iter().map(|a| (a.id.as_str(), a)).collect();
        repo.commit_entities(&writes, &[]).unwrap();
        let grant = domain.search_grant().unwrap();
        // Search until the optimizer has made an index of the fingerprints.
        let started = Instant::now();
        loop {
            let q = domain.query().filter(Account::phone.print_eq(phones[0], &grant));
            assert_eq!(q.count().unwrap(), 1);
            if q.explain().unwrap().selected == Plan::IndexEquality {
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(60), "no index: {:?}", s.index_report());
            std::thread::sleep(Duration::from_millis(10));
        }
        for phone in phones {
            assert_eq!(domain.query().filter(Account::phone.print_eq(arabic_digits(phone), &grant)).count().unwrap(), 1);
        }
        for token in tokens {
            assert!(domain.query().filter(Account::token.print_eq(token.to_uppercase(), &grant)).count().unwrap() >= 1);
        }
        // An update, a delete, the history.
        let mut row = repo.get("m1").unwrap();
        row.group = "changed".into();
        repo.set("m1", &row).unwrap();
        domain.delete("m4").unwrap();
        history_text = serde_json::to_string(&domain.history("m1").unwrap()).unwrap() + &serde_json::to_string(&repo.list().unwrap()).unwrap();
        s.close();
    }
    let mut needles: Vec<String> = Vec::new();
    for phone in phones {
        needles.push(phone.to_string());
        needles.push(arabic_digits(phone));
    }
    for token in tokens {
        needles.push(token.to_string());
        needles.push(token.to_lowercase());
        needles.push(token.to_uppercase());
    }
    needles.extend(["note of m0", "5577000012"].map(String::from));
    let mut ordinary_seen = false;
    let mut index_file_seen = false;
    for path in walk(&dir) {
        let bytes = std::fs::read(&path).unwrap();
        for needle in &needles {
            assert!(!contains(&bytes, needle.as_bytes()), "{needle:?} was found in {}", path.display());
        }
        ordinary_seen |= contains(&bytes, b"visible");
        index_file_seen |= path.extension().is_some_and(|e| e == "inx") && bytes.len() > 4096;
    }
    assert!(ordinary_seen, "the scan itself is blind");
    assert!(index_file_seen, "no index file was among the files searched");
    for needle in &needles {
        assert!(!history_text.contains(needle.as_str()), "{needle:?} in the history");
        for event in seen.lock().unwrap().iter() {
            assert!(!event.contains(needle.as_str()), "{needle:?} in {event}");
        }
    }
    assert!(!seen.lock().unwrap().is_empty(), "the sink saw nothing: the check is blind");
    std::fs::remove_dir_all(&dir).ok();
}
