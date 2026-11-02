//! The confirmed search by a piece of a value: candidates are opened inside the library and only the
//! rows that really contain the text come back; a program without the read key gets candidates and
//! opens nothing; one event is sent for each search.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{PartResults, PrintHandle, Sealed, SealedFields},
    fields::{TransformKind, transform},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::ReadableTable;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

macro_rules! parts_entity {
    ($name:ident, $($attr:tt)*) => {
        #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
        struct $name {
            id: String,
            group: String,
            #[clove(encrypt, id = 1, print = "parts", normalize = "trim,arabic", $($attr)*)]
            phone: Sealed<String>,
        }
        impl Entity for $name {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    };
}
parts_entity!(Fast, window = 3, grade = "fast");
parts_entity!(Balanced, window = 3, grade = "balanced");
parts_entity!(Protected, window = 3, grade = "protected");

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

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// What the sink saw: every event as text, and the confirm events as numbers.
#[derive(Default)]
struct Seen {
    all: Vec<String>,
    confirms: Vec<(u64, u64, u64, Option<Vec<String>>)>,
    reads: usize,
}

fn config_with_sink(seen: &Arc<Mutex<Seen>>) -> StorageConfig {
    let seen = seen.clone();
    StorageConfig::default().event_sink(move |e: &LibraryEvent| {
        let mut s = seen.lock().unwrap();
        s.all.push(format!("{e:?}"));
        match e {
            LibraryEvent::FieldConfirm { candidates, opened, matched, rows, .. } => s.confirms.push((*candidates, *opened, *matched, rows.clone())),
            LibraryEvent::FieldRead { .. } => s.reads += 1,
            _ => {}
        }
    })
}

// ---------------------------------------------------------------------------------------------

/// For one grade: the confirmed rows are exactly the rows that contain the text, for pieces of
/// 3, 4, 6 and 10 characters (and a spelling with other digits), and one event is sent for each search.
fn exact<E>(label: &str, table: &'static str, make: impl Fn(&str, &str, &str) -> E, handle: PrintHandle<E>, value_of: impl Fn(&E) -> &Sealed<String>, id_of: impl Fn(&E) -> String)
where
    E: Entity + Serialize + DeserializeOwned + Default + SealedFields + Clone + 'static,
{
    const ROWS: u64 = 30_000;
    let dir = temp_dir();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s = Storage::builder(config_with_sink(&seen))
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<E>(table))
        .build()
        .unwrap();
    let domain = s.domain::<E>();
    let mut batch: Vec<E> = Vec::new();
    for i in 0..ROWS {
        batch.push(make(&format!("r{i:06}"), &format!("g{}", i % 7), &written_as(i, &phone_of(i % (ROWS / 3)))));
        if batch.len() == 1000 {
            let ids: Vec<String> = batch.iter().map(&id_of).collect();
            let writes: Vec<(&str, &E)> = ids.iter().map(String::as_str).zip(batch.iter()).collect();
            domain.repo().commit_entities(&writes, &[]).unwrap();
            batch.clear();
        }
    }
    let read = domain.read_grant().unwrap();
    let mut opened: Vec<(String, String)> = Vec::new();
    for row in domain.query().collect().unwrap() {
        opened.push((id_of(&row), normal(&value_of(&row).open(&read).unwrap())));
    }
    seen.lock().unwrap().reads = 0;
    seen.lock().unwrap().confirms.clear();
    let grant = domain.search_grant().unwrap();
    let truth = |needle: &str| -> BTreeSet<String> {
        let want = normal(needle);
        opened.iter().filter(|(_, v)| v.contains(&want)).map(|(i, _)| i.clone()).collect()
    };
    let mut searches = 0usize;
    for len in [3usize, 4, 6, 10] {
        for k in 0..12usize {
            let value = &opened[(k * 7919 + len * 13) % opened.len()].1;
            let at = (k * 3 + len) % (value.chars().count() - len + 1).max(1);
            let needle: String = value.chars().skip(at).take(len).collect();
            let results = handle.part_search(&needle).run(domain, &grant).unwrap();
            assert!(results.is_confirmed());
            let got: BTreeSet<String> = results.rows().iter().map(&id_of).collect();
            assert_eq!(got, truth(&needle), "{label}: needle {needle:?} (length {len})");
            searches += 1;
        }
    }
    // Other digits and spaces in what is asked for: the same rows.
    let needle = normal(&opened[5].1[2..8]);
    let a = handle.part_search(arabic_digits(&needle)).run(domain, &grant).unwrap().into_rows();
    let b = handle.part_search(format!("  {needle} ")).run(domain, &grant).unwrap().into_rows();
    searches += 2;
    assert_eq!(a.iter().map(&id_of).collect::<BTreeSet<_>>(), truth(&needle));
    assert_eq!(b.iter().map(&id_of).collect::<BTreeSet<_>>(), truth(&needle));
    // One event for each search, with counts only; the opened values were not reported one by one.
    let seen = seen.lock().unwrap();
    assert_eq!(seen.confirms.len(), searches, "{label}: one event for each search");
    assert_eq!(seen.reads, 0, "{label}: the library's own opening is not a read grant's");
    for (candidates, opened_count, matched, rows) in &seen.confirms {
        assert_eq!(candidates, opened_count, "no limit: every candidate is opened");
        assert!(matched <= opened_count);
        assert!(rows.is_none(), "the row keys are off by default");
    }
    let events = seen.all.join("\n");
    for (_, value) in opened.iter().take(300) {
        assert!(!events.contains(value.as_str()), "{label}: a phone number is in the events");
    }
    assert!(!events.is_empty(), "{label}: the sink saw nothing");
    let total_extra: u64 = seen.confirms.iter().map(|(c, _, m, _)| c - m).sum();
    println!("CONFIRMSTAT grade={label} searches={searches} candidates_opened_total={} matched_total={} extra_total={total_extra}", seen.confirms.iter().map(|c| c.1).sum::<u64>(), seen.confirms.iter().map(|c| c.2).sum::<u64>());
    drop(seen);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_confirmed_rows_are_exactly_the_matches_fast() {
    exact("fast", "fast", |id, g, v| Fast { id: id.into(), group: g.into(), phone: Sealed::new(v.into()) }, Fast::phone, |e| &e.phone, |e| e.id.clone());
}

#[test]
fn the_confirmed_rows_are_exactly_the_matches_balanced() {
    exact("balanced", "balanced", |id, g, v| Balanced { id: id.into(), group: g.into(), phone: Sealed::new(v.into()) }, Balanced::phone, |e| &e.phone, |e| e.id.clone());
}

#[test]
fn the_confirmed_rows_are_exactly_the_matches_protected() {
    exact("protected", "protected", |id, g, v| Protected { id: id.into(), group: g.into(), phone: Sealed::new(v.into()) }, Protected::phone, |e| &e.phone, |e| e.id.clone());
}

// ---------------------------------------------------------------------------------------------

#[test]
fn a_program_with_the_search_key_alone_gets_candidates_and_opens_nothing() {
    let dir = temp_dir();
    {
        let s = Storage::builder(StorageConfig::default())
            .add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Protected>("t"))
            .build()
            .unwrap();
        let rows: Vec<Protected> = (0..2000).map(|i| Protected { id: format!("r{i:05}"), group: "g".into(), phone: Sealed::new(phone_of(i)) }).collect();
        let writes: Vec<(&str, &Protected)> = rows.iter().map(|r| (r.id.as_str(), r)).collect();
        s.domain::<Protected>().repo().commit_entities(&writes, &[]).unwrap();
        s.close();
    }
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s = Storage::builder(config_with_sink(&seen))
        .add_database(plain_with_keys(&dir, keys(None, Some(2))).register_sealed::<Protected>("t"))
        .build()
        .unwrap();
    let domain = s.domain::<Protected>();
    let grant = domain.search_grant().unwrap();
    let needle = &phone_of(17)[3..8];
    let results = Protected::phone.part_search(needle).run(domain, &grant).unwrap();
    assert!(!results.is_confirmed(), "without the read key the rows are candidates");
    assert!(matches!(&results, PartResults::Candidates(_)));
    let ids: BTreeSet<String> = results.rows().iter().map(|r| r.id.clone()).collect();
    let by_query: BTreeSet<String> = domain.query().filter(Protected::phone.part_candidates(needle, &grant)).collect().unwrap().into_iter().map(|r| r.id).collect();
    assert_eq!(ids, by_query);
    assert!(ids.contains("r00017"));
    let err = results.into_confirmed().unwrap_err().to_string();
    assert!(err.contains("candidates"), "{err}");
    // A limit applies to the candidates.
    let limited = Protected::phone.part_search(needle).limit(1).run(domain, &grant).unwrap();
    assert_eq!(limited.rows().len(), 1);
    let seen = seen.lock().unwrap();
    assert!(seen.confirms.is_empty() && seen.reads == 0, "nothing was opened: {} confirm events, {} reads", seen.confirms.len(), seen.reads);
    drop(seen);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_limit_stops_opening_candidates_once_it_has_enough_matches() {
    let dir = temp_dir();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s = Storage::builder(config_with_sink(&seen))
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<Balanced>("t"))
        .build()
        .unwrap();
    let domain = s.domain::<Balanced>();
    // 6000 rows that all contain "0123", and 4 groups.
    let rows: Vec<Balanced> = (0..6000).map(|i| Balanced { id: format!("r{i:05}"), group: format!("g{}", i % 4), phone: Sealed::new(format!("05{:04}0123", i % 10_000)) }).collect();
    for chunk in rows.chunks(1000) {
        let writes: Vec<(&str, &Balanced)> = chunk.iter().map(|r| (r.id.as_str(), r)).collect();
        domain.repo().commit_entities(&writes, &[]).unwrap();
    }
    let grant = domain.search_grant().unwrap();
    let all = Balanced::phone.part_search("0123").run(domain, &grant).unwrap().into_confirmed().unwrap();
    assert_eq!(all.len(), 6000);
    let five = Balanced::phone.part_search("0123").limit(5).run(domain, &grant).unwrap().into_confirmed().unwrap();
    assert_eq!(five.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["r00000", "r00001", "r00002", "r00003", "r00004"], "the first five in key order");
    // Another condition is met before the limit counts.
    let in_group = Balanced::phone.part_search("0123").filter(Balanced::group.eq("g2".to_string())).limit(3).run(domain, &grant).unwrap().into_confirmed().unwrap();
    assert_eq!(in_group.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["r00002", "r00006", "r00010"]);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.confirms.len(), 3);
    assert_eq!(seen.confirms[0], (6000, 6000, 6000, None), "no limit: all of them");
    let (candidates, opened, matched, _) = seen.confirms[1].clone();
    assert_eq!(matched, 5);
    assert!(opened <= 256 && candidates <= 256, "the limited search opened {opened} of 6000 candidates");
    assert_eq!(seen.confirms[2].2, 3);
    drop(seen);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_row_keys_are_in_the_event_only_when_asked_for_and_never_a_value() {
    let dir = temp_dir();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s = Storage::builder(config_with_sink(&seen))
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<Balanced>("t"))
        .build()
        .unwrap();
    let domain = s.domain::<Balanced>();
    for (i, v) in ["5599911123", "5511122233", "5577799911", "5500000000"].iter().enumerate() {
        domain.repo().set(&format!("k{i}"), &Balanced { id: format!("k{i}"), group: "g".into(), phone: Sealed::new((*v).into()) }).unwrap();
    }
    let grant = domain.search_grant().unwrap();
    let found = Balanced::phone.part_search("99911").report_rows(true).run(domain, &grant).unwrap().into_confirmed().unwrap();
    assert_eq!(found.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["k0", "k2"]);
    let _ = Balanced::phone.part_search("99911").run(domain, &grant).unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.confirms.len(), 2);
    let with_rows = seen.confirms[0].3.clone().expect("asked for the keys");
    assert!(with_rows.iter().all(|k| k.starts_with('k')) && with_rows.len() as u64 == seen.confirms[0].1);
    assert!(seen.confirms[1].3.is_none());
    for event in &seen.all {
        for secret in ["99911", "5599911123", "5511122233", "5577799911"] {
            assert!(!event.contains(secret), "{secret} in {event}");
        }
    }
    drop(seen);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_text_shorter_than_a_part_is_refused() {
    let dir = temp_dir();
    let s = Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(&dir), keys(Some(1), Some(2))).register_sealed::<Balanced>("t"))
        .build()
        .unwrap();
    let domain = s.domain::<Balanced>();
    domain.repo().set("a", &Balanced { id: "a".into(), group: "g".into(), phone: Sealed::new("5501234567".into()) }).unwrap();
    let grant = domain.search_grant().unwrap();
    let err = Balanced::phone.part_search("05").run(domain, &grant).unwrap_err().to_string();
    assert!(err.contains("slow scan"), "{err}");
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

/// A value changed in the file is not skipped: the search fails as a whole with `DataTampered`, and
/// the event says how far it got.
#[cfg(not(clove_test_encrypt_all))]
#[test]
fn a_changed_value_among_the_candidates_fails_the_whole_search() {
    let dir = temp_dir();
    {
        let s = Storage::builder(StorageConfig::default())
            .add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Balanced>("t"))
            .build()
            .unwrap();
        for i in 0..20u64 {
            s.domain::<Balanced>().repo().set(&format!("r{i:02}"), &Balanced { id: format!("r{i:02}"), group: "g".into(), phone: Sealed::new(format!("0599{i:06}")) }).unwrap();
        }
        s.close();
    }
    {
        let db = redb::Database::open(dir.join("records").join("store.cldb")).unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut table = tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("t")).unwrap();
            let bytes = table.get("r07").unwrap().unwrap().value().to_vec();
            let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let sealed = json["phone"]["s"].as_str().unwrap().to_string();
            let mut chars: Vec<char> = sealed.chars().collect();
            let last = chars.len() - 3;
            chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
            json["phone"]["s"] = serde_json::Value::String(chars.into_iter().collect());
            table.insert("r07", serde_json::to_vec(&json).unwrap().as_slice()).unwrap();
        }
        tx.commit().unwrap();
    }
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s = Storage::builder(config_with_sink(&seen))
        .add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Balanced>("t"))
        .build()
        .unwrap();
    let domain = s.domain::<Balanced>();
    let grant = domain.search_grant().unwrap();
    let err = Balanced::phone.part_search("0599").run(domain, &grant).unwrap_err();
    assert!(matches!(err, ClError::DataTampered), "{err:?}");
    // The rest of the table is fine: a search that does not reach that row works.
    let ok = Balanced::phone.part_search("0599").filter(Balanced::group.eq("none".to_string())).run(domain, &grant).unwrap();
    assert!(ok.rows().is_empty());
    let seen = seen.lock().unwrap();
    assert_eq!(seen.confirms.len(), 2, "the failed search sent its event too");
    assert_eq!(seen.confirms[0].2, 7, "seven rows matched before the changed one (r00 to r06)");
    drop(seen);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}
