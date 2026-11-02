//! Searching by a piece of a value, with the fingerprints of its parts (`print = "parts"`). The rows
//! returned are candidates: every row that has the text is among them, and some that do not are
//! too. These tests pin the first (no row is ever missed, in every grade, with and without an
//! index) and count the second.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{PrintHandle, Sealed, SealedFields},
    fields::{Field, TransformKind, ValueKind, transform},
    query::optimizer::Plan,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// One entity per grade: the same field, kept to 64, 12 and 8 bits of each part's fingerprint.
macro_rules! parts_entity {
    ($name:ident, $($attr:tt)*) => {
        #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
        struct $name {
            id: String,
            group: String,
            #[clove(encrypt, id = 1, print = "parts", $($attr)*)]
            value: Sealed<String>,
        }
        impl Entity for $name {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    };
}
parts_entity!(Fast, window = 3, grade = "fast", normalize = "trim,arabic");
parts_entity!(Balanced, window = 3, grade = "balanced", normalize = "trim,arabic");
parts_entity!(Protected, window = 3, grade = "protected", normalize = "trim,arabic");
/// The default settings: parts of 3 characters, 12 bits, no normalisation.
parts_entity!(Plain,);
/// The same field as `Balanced` with a longer part.
parts_entity!(Longer, window = 4, grade = "balanced", normalize = "trim,arabic");

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

/// An ordinary database with field keys, also under the test cfg (a scan of readable files).
fn plain_with_keys(dir: &Path, config: EncryptionConfig) -> DatabaseConfig {
    let db = base(dir);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    db.field_encryption(config)
}

fn arabic_digits(text: &str) -> String {
    text.chars().map(|c| if c.is_ascii_digit() { char::from_u32('٠' as u32 + (c as u32 - '0' as u32)).unwrap() } else { c }).collect()
}

fn phone_of(i: u64) -> String {
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(12345);
    x ^= x >> 29;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 32;
    format!("05{:08}", x % 100_000_000)
}

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

// ---------------------------------------------------------------------------------------------

/// The correctness test, for one grade: for many pieces taken out of the stored values, every row
/// that has the piece is among the candidates, with no index and with one; and the candidates that
/// are not matches are counted per length of the piece.
fn never_misses<E>(label: &str, bits: u32, table: &'static str, make: impl Fn(&str, &str, &str) -> E, handle: PrintHandle<E>, value_of: impl Fn(&E) -> &Sealed<String>, id_of: impl Fn(&E) -> String)
where
    E: Entity + Serialize + DeserializeOwned + Default + SealedFields + Clone + 'static,
{
    const ROWS: u64 = 30_000;
    let dir = temp_dir();
    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let config = StorageConfig::default().event_sink(move |e: &LibraryEvent| {
        if let LibraryEvent::Index { event, generation, rows, .. } = e {
            sink.lock().unwrap().push(format!("{event} gen={generation} rows={rows}"));
        }
    });
    let s = Storage::builder(config)
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<E>(table))
        .build()
        .unwrap();
    let domain = s.domain::<E>();
    let repo = domain.repo();
    let mut batch: Vec<E> = Vec::new();
    for i in 0..ROWS {
        let phone = phone_of(i % (ROWS / 3));
        batch.push(make(&format!("r{i:06}"), &format!("g{}", i % 7), &written_as(i, &phone)));
        if batch.len() == 1000 {
            let writes: Vec<(String, &E)> = batch.iter().map(|e| (id_of(e), e)).collect();
            let writes: Vec<(&str, &E)> = writes.iter().map(|(i, e)| (i.as_str(), *e)).collect();
            repo.commit_entities(&writes, &[]).unwrap();
            batch.clear();
        }
    }
    let read = domain.read_grant().unwrap();
    let mut opened: Vec<(String, String)> = Vec::new();
    for row in domain.query().collect().unwrap() {
        opened.push((id_of(&row), normal(&value_of(&row).open(&read).unwrap())));
    }
    assert_eq!(opened.len() as u64, ROWS);
    let grant = domain.search_grant().unwrap();
    let candidates = |needle: &str| -> BTreeSet<String> {
        match domain.query().filter(handle.part_candidates(needle, &grant)).collect() {
            Ok(rows) => rows.iter().map(&id_of).collect(),
            Err(e) => panic!("{label}: the search failed for {needle:?}: {e:?}; index events: {:?}; report: {:?}", events.lock().unwrap(), s.index_report()),
        }
    };
    let truth = |needle: &str| -> BTreeSet<String> {
        let want = normal(needle);
        opened.iter().filter(|(_, v)| v.contains(&want)).map(|(i, _)| i.clone()).collect()
    };
    // Pieces taken out of stored values, so that there is always at least one match.
    let mut needles: Vec<(usize, String)> = Vec::new();
    for len in [3usize, 4, 5, 6, 8, 10] {
        for k in 0..40usize {
            let row = (k * 7919 + len * 13) % opened.len();
            let value = &opened[row].1;
            let at = (k * 3 + len) % (value.chars().count() - len + 1);
            needles.push((len, value.chars().skip(at).take(len).collect()));
        }
    }
    // And a piece of a spelling with other digits.
    needles.push((6, arabic_digits(&opened[5].1[2..8])));
    // Without an index: the answers come from a scan of the stored fingerprints.
    for (len, needle) in needles.iter().step_by(11) {
        let want = truth(needle);
        let got = candidates(needle);
        assert!(want.is_subset(&got), "{label}: scan missed {:?} for {needle:?} (length {len})", want.difference(&got).take(3).collect::<Vec<_>>());
    }
    // Ask until the optimizer has built the index, then check everything.
    let started = Instant::now();
    let probe = needles[3].1.clone();
    loop {
        let q = domain.query().filter(handle.part_candidates(&probe, &grant));
        let _ = q.count().unwrap();
        if q.explain().unwrap().selected == Plan::IndexContains {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(120), "{label}: no index on the part fingerprints: {:?}", s.index_report());
        std::thread::sleep(Duration::from_millis(20));
    }
    // The index of the part fingerprints is a postings index of its own kind, not a text (Token) index.
    let kinds: Vec<String> = s.index_report().iter().filter(|r| r.ready).map(|r| r.definition.kind.clone()).collect();
    assert!(kinds.iter().any(|k| k == "Parts") && !kinds.iter().any(|k| k == "Token"), "{label}: index kinds {kinds:?}");
    let mut per_length: std::collections::BTreeMap<usize, (u64, u64, u64)> = Default::default();
    for (len, needle) in &needles {
        let want = truth(needle);
        let got = candidates(needle);
        assert!(want.is_subset(&got), "{label}: index missed {:?} for {needle:?} (length {len})", want.difference(&got).take(3).collect::<Vec<_>>());
        let entry = per_length.entry(*len).or_default();
        entry.0 += 1;
        entry.1 += got.len() as u64;
        entry.2 += want.len() as u64;
        // A piece as long as a part has one fingerprint: with every bit kept the candidates are the matches.
        if bits == 64 && *len == 3 {
            assert_eq!(got, want, "{label}: a piece of one part with 64 bits must be exact");
        }
    }
    for (len, (n, got, want)) in &per_length {
        println!(
            "PARTSTAT grade={label} bits={bits} window=3 rows={ROWS} piece_length={len} needles={n} candidates={got} matches={want} extra_per_needle={:.1} candidates_per_match={:.3}",
            (*got - *want) as f64 / *n as f64,
            *got as f64 / (*want).max(1) as f64
        );
    }
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn part_search_never_misses_a_row_with_the_text_fast() {
    never_misses("fast", 64, "fast", |id, g, v| Fast { id: id.into(), group: g.into(), value: Sealed::new(v.into()) }, Fast::value, |e| &e.value, |e| e.id.clone());
}

#[test]
fn part_search_never_misses_a_row_with_the_text_balanced() {
    never_misses("balanced", 12, "balanced", |id, g, v| Balanced { id: id.into(), group: g.into(), value: Sealed::new(v.into()) }, Balanced::value, |e| &e.value, |e| e.id.clone());
}

#[test]
fn part_search_never_misses_a_row_with_the_text_protected() {
    never_misses("protected", 8, "protected", |id, g, v| Protected { id: id.into(), group: g.into(), value: Sealed::new(v.into()) }, Protected::value, |e| &e.value, |e| e.id.clone());
}

// ---------------------------------------------------------------------------------------------

#[test]
fn a_row_is_stored_with_sorted_distinct_hex_fingerprints_of_its_parts() {
    let dir = temp_dir();
    let s = Storage::builder(StorageConfig::default())
        .add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Balanced>("b").register_sealed::<Fast>("f").register_sealed::<Protected>("p"))
        .build()
        .unwrap();
    let raw = |table: &'static str, id: &str| -> serde_json::Value {
        let bytes = s.db_manager("store").get_uncached(TableDefinition::<&str, &[u8]>::new(table), id).unwrap().expect("row");
        serde_json::from_slice(&bytes).unwrap()
    };
    s.domain::<Balanced>().repo().set("r", &Balanced { id: "r".into(), group: "g".into(), value: Sealed::new("5501234567".into()) }).unwrap();
    s.domain::<Fast>().repo().set("r", &Fast { id: "r".into(), group: "g".into(), value: Sealed::new("5501234567".into()) }).unwrap();
    s.domain::<Protected>().repo().set("r", &Protected { id: "r".into(), group: "g".into(), value: Sealed::new("5501234567".into()) }).unwrap();
    for (table, digits) in [("b", 3usize), ("f", 16), ("p", 2)] {
        let json = raw(table, "r");
        let value = json["value"].as_object().expect("an object");
        assert_eq!(value.keys().collect::<Vec<_>>(), ["f", "p", "s"]);
        let tags: Vec<&str> = value["p"].as_str().unwrap().split(' ').collect();
        assert!(tags.len() <= 8 && !tags.is_empty());
        assert!(tags.iter().all(|t| t.len() == digits && t.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))), "{table}: {tags:?}");
        let mut sorted = tags.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(tags, sorted, "{table}: sorted and distinct");
        assert!(!json.to_string().contains("5501234567"));
    }
    // Eight windows of a ten-digit value, all different, with 64 bits.
    assert_eq!(raw("f", "r")["value"]["p"].as_str().unwrap().split(' ').count(), 8);
    // A value shorter than a part has an empty list, and is stored all the same.
    s.domain::<Balanced>().repo().set("short", &Balanced { id: "short".into(), group: "g".into(), value: Sealed::new("ab".into()) }).unwrap();
    assert_eq!(raw("b", "short")["value"]["p"], "");
    s.close();
}

#[test]
fn a_text_shorter_than_a_part_is_refused_and_a_long_one_is_searched_with_the_first_64_parts() {
    let dir = temp_dir();
    let s = Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<Balanced>("b"))
        .build()
        .unwrap();
    let domain = s.domain::<Balanced>();
    let long: String = (0..140u32).map(|i| char::from_u32(0x61 + (i * 7 + i / 5) % 26).unwrap()).collect();
    domain.repo().set("long", &Balanced { id: "long".into(), group: "g".into(), value: Sealed::new(format!("x{long}y")) }).unwrap();
    domain.repo().set("other", &Balanced { id: "other".into(), group: "g".into(), value: Sealed::new("an unrelated value".into()) }).unwrap();
    let grant = domain.search_grant().unwrap();
    // Shorter than a part: a clear error that says what to do.
    for short in ["", "a", "ab"] {
        let err = domain.query().filter(Balanced::value.part_candidates(short, &grant)).count().unwrap_err().to_string();
        assert!(err.contains("slow scan") && err.contains("3 characters"), "{err}");
    }
    // Exactly one part is fine.
    assert!(domain.query().filter(Balanced::value.part_candidates("abc", &grant)).count().is_ok());
    // A piece of 100 characters has 98 parts at most; it is searched with 64 of them and the row that has it is found.
    let piece = &long[20..120];
    let found: Vec<String> = domain.query().filter(Balanced::value.part_candidates(piece, &grant)).collect().unwrap().into_iter().map(|r| r.id).collect();
    assert!(found.contains(&"long".to_string()), "{found:?}");
    assert!(!found.contains(&"other".to_string()));
    // The whole value, 142 characters.
    let whole = format!("x{long}y");
    let found: Vec<String> = domain.query().filter(Balanced::value.part_candidates(&whole, &grant)).collect().unwrap().into_iter().map(|r| r.id).collect();
    assert_eq!(found, ["long"]);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn another_digit_spelling_finds_the_same_candidates_and_a_closed_value_keeps_its_parts() {
    let dir = temp_dir();
    let s = Storage::builder(StorageConfig::default())
        .add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Balanced>("b"))
        .build()
        .unwrap();
    let domain = s.domain::<Balanced>();
    let repo = domain.repo();
    for (i, v) in ["5501234567", "٥٥٠١٢٣٤٥٦٧", "  5509999999 ", "5507654321"].iter().enumerate() {
        repo.set(&format!("r{i}"), &Balanced { id: format!("r{i}"), group: "g".into(), value: Sealed::new((*v).into()) }).unwrap();
    }
    let grant = domain.search_grant().unwrap();
    let ids = |needle: &str| -> BTreeSet<String> {
        domain.query().filter(Balanced::value.part_candidates(needle, &grant)).collect().unwrap().into_iter().map(|r| r.id).collect()
    };
    let expect: BTreeSet<String> = ["r0", "r1"].map(String::from).into();
    assert!(expect.is_subset(&ids("12345")));
    assert_eq!(ids("12345"), ids("١٢٣٤٥"));
    assert_eq!(ids(" 12345 "), ids("12345"));
    // Written back as it was read, the parts are the same bytes; a new value gets its own.
    let raw = |id: &str| -> serde_json::Value {
        serde_json::from_slice(&s.db_manager("store").get_uncached(TableDefinition::<&str, &[u8]>::new("b"), id).unwrap().unwrap()).unwrap()
    };
    let before = raw("r0");
    let mut row = repo.get("r0").unwrap();
    row.group = "g2".into();
    repo.set("r0", &row).unwrap();
    assert_eq!(raw("r0")["value"], before["value"]);
    let mut row = repo.get("r0").unwrap();
    row.value = Sealed::new("5551112223".into());
    repo.set("r0", &row).unwrap();
    assert_ne!(raw("r0")["value"]["p"], before["value"]["p"]);
    assert!(!ids("12345").contains("r0"), "the old value's parts are gone");
    assert!(ids("11122").contains("r0"));
    s.close();
}

/// Changing the length of a part or the bits kept is a migration, and a table without them recorded too.
#[test]
fn another_part_length_or_bits_is_a_migration_and_writes_nothing() {
    let dir = temp_dir();
    {
        let s = Storage::builder(StorageConfig::default())
            .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<Balanced>("t"))
            .build()
            .unwrap();
        s.domain::<Balanced>().repo().set("r", &Balanced { id: "r".into(), group: "g".into(), value: Sealed::new("5501234567".into()) }).unwrap();
        s.close();
    }
    let before: Vec<(PathBuf, Vec<u8>)> = walk(&dir).into_iter().filter(|p| p.extension().is_none_or(|e| e != "cldb")).map(|p| (p.clone(), std::fs::read(p).unwrap())).collect();
    // Same table, another length of part (Longer has the same field and a window of 4).
    let err = Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<Longer>("t"))
        .build()
        .err()
        .expect("must be refused")
        .to_string();
    assert!(err.contains("migration") && err.contains("length of a part") && err.contains("nothing was written"), "{err}");
    // Same length, another number of bits.
    let err = Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<Protected>("t"))
        .build()
        .err()
        .expect("must be refused")
        .to_string();
    assert!(err.contains("migration") && err.contains("length of a part"), "{err}");
    for (path, bytes) in before {
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{} changed by a refused open", path.display());
    }
    drop(Storage::builder(StorageConfig::default()).add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<Balanced>("t")).build().unwrap());
    std::fs::remove_dir_all(&dir).ok();
}

/// A table made by the build before the parts were fingerprinted recorded neither: refused, as a migration.
#[cfg(not(clove_test_encrypt_all))]
#[test]
fn a_parts_table_without_a_recorded_length_is_a_migration() {
    use clove1db::metadata::store::{read_meta, write_meta};
    let dir = temp_dir();
    let open = || Storage::builder(StorageConfig::default()).add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<Balanced>("t")).build();
    drop(open().unwrap());
    let primary = dir.join("records").join("store.cldb");
    {
        let db = redb::Database::open(&primary).unwrap();
        let mut meta = read_meta(&db).unwrap().unwrap();
        let field = &mut meta.tables.iter_mut().find(|t| t.name == "t").unwrap().sealed[0];
        assert_eq!((field.window, field.bits), (Some(3), Some(12)), "the creation recorded both");
        field.window = None;
        field.bits = None;
        write_meta(&db, &meta).unwrap();
    }
    let err = open().err().expect("must be refused").to_string();
    assert!(err.contains("migration") && err.contains("nothing was written"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_defaults_are_a_part_of_three_characters_and_twelve_bits() {
    let dir = temp_dir();
    let s = Storage::builder(StorageConfig::default())
        .add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Plain>("t"))
        .build()
        .unwrap();
    s.domain::<Plain>().repo().set("r", &Plain { id: "r".into(), group: "g".into(), value: Sealed::new("abcdef".into()) }).unwrap();
    let bytes = s.db_manager("store").get_uncached(TableDefinition::<&str, &[u8]>::new("t"), "r").unwrap().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let tags: Vec<&str> = json["value"]["p"].as_str().unwrap().split(' ').collect();
    // "abcdef" has 4 windows of 3 characters. The key is random in each run and a fingerprint of 12 bits has 4096
    // values, so two windows can share one (about 0.15 in a hundred runs): then there are 3 fingerprints, never fewer.
    assert!((3..=4).contains(&tags.len()), "{tags:?}");
    assert!(tags.iter().all(|t| t.len() == 3));
    s.close();
}

// ---------------------------------------------------------------------------------------------

/// A condition built by hand on the parts path is refused, whatever its operator and value.
#[test]
fn a_text_condition_built_by_hand_on_the_parts_path_is_refused() {
    let dir = temp_dir();
    let s = Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<Balanced>("b"))
        .build()
        .unwrap();
    let domain = s.domain::<Balanced>();
    domain.repo().set("r", &Balanced { id: "r".into(), group: "g".into(), value: Sealed::new("5501234567".into()) }).unwrap();
    let parts_path = Field::<Balanced, String>::new("value", ValueKind::Auto).then(Field::<String, String>::new("p", ValueKind::Auto));
    for query in [
        domain.query().filter(parts_path.clone().text("5501234567".to_string())),
        domain.query().filter(parts_path.clone().contains("501".to_string())),
        domain.query().filter(parts_path.clone().eq("abc".to_string())),
        domain.query().filter(parts_path.clone().prefix("abc".to_string())),
    ] {
        let err = query.count().unwrap_err();
        assert!(matches!(&err, ClError::Validation(t) if t.contains("search grant") || t.contains("protected field")), "{err:?}");
    }
    // The text condition of the handle goes through; a copy of its value on another path does not.
    let grant = domain.search_grant().unwrap();
    assert_eq!(domain.query().filter(Balanced::value.part_candidates("01234", &grant)).count().unwrap(), 1);
    // A handle of a field without parts refuses to search by parts.
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn no_part_search_text_appears_in_any_file_or_event() {
    let dir = temp_dir();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let needles = ["5599911", "9991123", "٥٥٩٩٩١١", "marker-piece-zz", "Marker-Piece-ZZ"];
    {
        let config = StorageConfig::default().event_sink(move |e: &LibraryEvent| sink.lock().unwrap().push(format!("{e:?}")));
        let s = Storage::builder(config)
            .add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Balanced>("b"))
            .build()
            .unwrap();
        let domain = s.domain::<Balanced>();
        domain.repo().set("m1", &Balanced { id: "m1".into(), group: "visible".into(), value: Sealed::new("5599911123".into()) }).unwrap();
        domain.repo().set("m2", &Balanced { id: "m2".into(), group: "visible".into(), value: Sealed::new("xx marker-piece-zz xx".into()) }).unwrap();
        let bulk: Vec<Balanced> = (0..300).map(|i| Balanced { id: format!("b{i:03}"), group: "visible".into(), value: Sealed::new(format!("0577{i:06}")) }).collect();
        let writes: Vec<(&str, &Balanced)> = bulk.iter().map(|a| (a.id.as_str(), a)).collect();
        domain.repo().commit_entities(&writes, &[]).unwrap();
        let grant = domain.search_grant().unwrap();
        let started = Instant::now();
        loop {
            let q = domain.query().filter(Balanced::value.part_candidates("5599911", &grant));
            assert!(q.collect().unwrap().iter().any(|r| r.id == "m1"));
            if q.explain().unwrap().selected == Plan::IndexContains {
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(60), "no index: {:?}", s.index_report());
            std::thread::sleep(Duration::from_millis(10));
        }
        for needle in needles {
            let predicate = Balanced::value.part_candidates(needle, &grant);
            let shown = format!("{predicate:?}");
            assert!(!shown.contains(needle) && !shown.to_lowercase().contains(&needle.to_lowercase()), "{shown}");
            if let Ok(fingerprint) = predicate.fingerprint() {
                assert!(!contains(&fingerprint, needle.as_bytes()) && !contains(&fingerprint, needle.to_lowercase().as_bytes()));
            }
            let _ = domain.query().filter(predicate).count();
        }
        s.close();
    }
    let mut ordinary = false;
    let mut index_file = false;
    for path in walk(&dir) {
        let bytes = std::fs::read(&path).unwrap();
        for needle in needles {
            assert!(!contains(&bytes, needle.as_bytes()), "{needle:?} was found in {}", path.display());
            assert!(!contains(&bytes, needle.to_lowercase().as_bytes()), "{needle:?} (lower case) was found in {}", path.display());
        }
        ordinary |= contains(&bytes, b"visible");
        index_file |= path.extension().is_some_and(|e| e == "inx") && bytes.len() > 4096;
    }
    assert!(ordinary, "the scan itself is blind");
    assert!(index_file, "no index file was among the files searched");
    let events = seen.lock().unwrap();
    assert!(!events.is_empty(), "the sink saw nothing: the check is blind");
    for event in events.iter() {
        for needle in needles {
            assert!(!event.contains(needle) && !event.to_lowercase().contains(&needle.to_lowercase()), "{needle:?} in {event}");
        }
    }
}
