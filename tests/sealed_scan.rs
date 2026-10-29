//! The slow scan of a protected field (9-4): approximate, range and ordered conditions on a field that
//! the fingerprints cannot answer, asked for with `scan_sealed(&grant)`. Each result is compared with the
//! plain values; one `FieldScan` event is sent for each scan, and no value is in any event.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    fields::Predicate,
    field_crypto::{PrintHandle, Sealed, SealedFields},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

macro_rules! scan_entity {
    ($name:ident, $($attr:tt)*) => {
        #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
        struct $name {
            id: String,
            group: String,
            #[clove(encrypt, id = 1, print = "parts", normalize = "trim", $($attr)*)]
            phone: Sealed<String>,
        }
        impl Entity for $name {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    };
}
scan_entity!(Fast, window = 3, grade = "fast");
scan_entity!(Balanced, window = 3, grade = "balanced");
scan_entity!(Protected, window = 3, grade = "protected");

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

fn with_keys(dir: &Path, config: EncryptionConfig) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false);
    #[cfg(clove_test_encrypt_all)]
    {
        db.encryption(config)
    }
    #[cfg(not(clove_test_encrypt_all))]
    {
        db.field_encryption(config)
    }
}

fn phone_of(i: u64) -> String {
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(12345);
    x ^= x >> 29;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 32;
    format!("05{:08}", x % 100_000_000)
}

/// What the sink saw: every event as text, and the scan events as numbers.
#[derive(Default)]
struct Seen {
    all: Vec<String>,
    scans: Vec<(u64, u64, u64, Option<Vec<String>>)>,
    reads: usize,
}

fn config_with_sink(seen: &Arc<Mutex<Seen>>) -> StorageConfig {
    let seen = seen.clone();
    StorageConfig::default().event_sink(move |e: &LibraryEvent| {
        let mut s = seen.lock().unwrap();
        s.all.push(format!("{e:?}"));
        match e {
            LibraryEvent::FieldScan { scanned, opened, matched, rows, .. } => s.scans.push((*scanned, *opened, *matched, rows.clone())),
            LibraryEvent::FieldRead { .. } => s.reads += 1,
            _ => {}
        }
    })
}

fn check<E>(label: &str, table: &'static str, make: impl Fn(&str, &str, &str) -> E, handle: PrintHandle<E>, phone_of_row: impl Fn(&E) -> &Sealed<String>, id_of: impl Fn(&E) -> String, group3: Predicate<E>)
where
    E: Entity + Serialize + DeserializeOwned + Default + SealedFields + Clone + std::fmt::Debug + 'static,
{
    const ROWS: u64 = 30_000;
    let dir = temp_dir();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s = Storage::builder(config_with_sink(&seen)).add_database(with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<E>(table)).build().unwrap();
    let domain = s.domain::<E>();
    let mut plain: Vec<(String, String)> = Vec::new();
    let mut batch: Vec<E> = Vec::new();
    for i in 0..ROWS {
        let (id, phone) = (format!("r{i:06}"), phone_of(i));
        plain.push((id.clone(), phone.clone()));
        batch.push(make(&id, &format!("g{}", i % 5), &phone));
        if batch.len() == 1000 {
            let ids: Vec<String> = batch.iter().map(&id_of).collect();
            let writes: Vec<(&str, &E)> = ids.iter().map(String::as_str).zip(batch.iter()).collect();
            domain.repo().commit_entities(&writes, &[]).unwrap();
            batch.clear();
        }
    }
    let read = domain.read_grant().unwrap();
    {
        // Read once the ordinary way so the reference is what the rows really hold.
        let first = domain.query().limit(1).collect().unwrap();
        assert_eq!(phone_of_row(&first[0]).open(&read).unwrap(), plain[0].1);
    }
    seen.lock().unwrap().reads = 0;
    seen.lock().unwrap().all.clear();

    // An approximate condition (a prefix and a digit sum, which no fingerprint answers).
    let ids = |rows: Vec<E>| -> Vec<String> { rows.iter().map(&id_of).collect() };
    let want: Vec<String> = plain.iter().filter(|(_, p)| p.starts_with("0512") && p.bytes().map(|b| u32::from(b - b'0')).sum::<u32>() % 2 == 0).map(|(i, _)| i.clone()).collect();
    assert!(want.len() > 20, "{label}: the condition must match something");
    let got = ids(handle.scan_sealed(&read).run(domain, |v: &String| v.starts_with("0512") && v.bytes().map(|b| u32::from(b - b'0')).sum::<u32>() % 2 == 0).unwrap());
    assert_eq!(got, want, "{label}: approximate scan, key order");

    // A range.
    let (lo, hi) = ("0530".to_string(), "0540".to_string());
    let want: Vec<String> = plain.iter().filter(|(_, p)| *p >= lo && *p < hi).map(|(i, _)| i.clone()).collect();
    let got = ids(handle.scan_sealed(&read).run(domain, |v: &String| *v >= lo && *v < hi).unwrap());
    assert_eq!(got, want, "{label}: range scan");

    // An order, with ties kept in key order, and a limit that applies after the order.
    let mut sorted: Vec<&(String, String)> = plain.iter().collect();
    sorted.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    let top: Vec<String> = sorted.iter().take(25).map(|(i, _)| i.clone()).collect();
    let got = ids(handle.scan_sealed(&read).limit(25).run_ordered(domain, |v: &String| Some(v.clone())).unwrap());
    assert_eq!(got, top, "{label}: ordered scan with a limit");

    // A limit without an order stops early: the first rows in key order, and not every row is opened.
    let before = seen.lock().unwrap().scans.len();
    let got = ids(handle.scan_sealed(&read).limit(7).run(domain, |_: &String| true).unwrap());
    assert_eq!(got, plain.iter().take(7).map(|(i, _)| i.clone()).collect::<Vec<_>>());
    let last = seen.lock().unwrap().scans[before].clone();
    assert!(last.1 < 1000, "{label}: a limit stops the scan early: {} rows opened", last.1);

    // An ordinary condition applied first opens only the rows it leaves.
    let narrowed = handle.scan_sealed(&read).filter(group3).run(domain, |_: &String| true).unwrap();
    assert_eq!(narrowed.len() as u64, ROWS / 5);
    let n = seen.lock().unwrap().scans.last().unwrap().clone();
    assert_eq!(n.1, ROWS / 5, "{label}: only the rows of the group were opened");

    // The row keys are in the event only when asked for.
    handle.scan_sealed(&read).report_rows(true).limit(3).run(domain, |_: &String| true).unwrap();
    let with_keys_ev = seen.lock().unwrap().scans.last().unwrap().clone();
    assert_eq!(with_keys_ev.3.as_ref().map(Vec::len), Some(3));

    // A value of another type than the field holds is an error, not a silent no-match.
    let err = handle.scan_sealed(&read).run(domain, |_: &i64| true).unwrap_err();
    assert!(matches!(err, ClError::Validation(_)), "{label}: {err:?}");

    // One event for each scan, no read events, no value anywhere.
    let seen = seen.lock().unwrap();
    assert_eq!(seen.reads, 0, "{label}: the scan's own opening is not a read grant's");
    assert!(seen.scans.len() >= 6, "{label}: {} scan events", seen.scans.len());
    for (scanned, opened, matched, rows) in seen.scans.iter().take(3) {
        assert_eq!(scanned, opened);
        assert!(matched <= opened);
        assert!(rows.is_none(), "the row keys are off by default");
    }
    let events = seen.all.join("\n");
    for (_, value) in plain.iter().take(300) {
        assert!(!events.contains(value.as_str()), "{label}: a phone number is in the events");
    }
    drop(seen);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn scans_match_the_plain_values_fast() {
    check("fast", "fast", |id, g, v| Fast { id: id.into(), group: g.into(), phone: Sealed::new(v.into()) }, Fast::phone, |e| &e.phone, |e| e.id.clone(), Fast::group.eq("g3".to_string()));
}

#[test]
fn scans_match_the_plain_values_balanced() {
    check("balanced", "balanced", |id, g, v| Balanced { id: id.into(), group: g.into(), phone: Sealed::new(v.into()) }, Balanced::phone, |e| &e.phone, |e| e.id.clone(), Balanced::group.eq("g3".to_string()));
}

#[test]
fn scans_match_the_plain_values_protected() {
    check("protected", "protected", |id, g, v| Protected { id: id.into(), group: g.into(), phone: Sealed::new(v.into()) }, Protected::phone, |e| &e.phone, |e| e.id.clone(), Protected::group.eq("g3".to_string()));
}

fn plain_with_keys(dir: &Path, config: EncryptionConfig) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    db.field_encryption(config)
}

/// A program that holds the search key alone cannot open anything, so its scan fails before the first value.
#[test]
fn a_program_without_the_read_key_cannot_scan() {
    let dir = temp_dir();
    {
        let s = Storage::builder(StorageConfig::default()).add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Balanced>("t")).build().unwrap();
        s.domain::<Balanced>().repo().set("a", &Balanced { id: "a".into(), group: "g".into(), phone: Sealed::new("0501234567".into()) }).unwrap();
        s.close();
    }
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s = Storage::builder(config_with_sink(&seen)).add_database(plain_with_keys(&dir, keys(None, Some(2))).register_sealed::<Balanced>("t")).build().unwrap();
    let domain = s.domain::<Balanced>();
    let read = domain.read_grant().unwrap();
    let err = Balanced::phone.scan_sealed(&read).run(domain, |_: &String| true).unwrap_err();
    assert!(!matches!(err, ClError::DataTampered), "no key is not tampering: {err:?}");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.scans.len(), 1);
    assert_eq!(seen.scans[0].1, 0, "nothing was opened");
    drop(seen);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

/// A value changed in the file is not skipped: the scan fails as a whole with `DataTampered`, and the
/// event says how far it got.
#[cfg(not(clove_test_encrypt_all))]
#[test]
fn a_changed_value_fails_the_whole_scan() {
    let dir = temp_dir();
    {
        let s = Storage::builder(StorageConfig::default()).add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Balanced>("t")).build().unwrap();
        for i in 0..20u64 {
            s.domain::<Balanced>().repo().set(&format!("r{i:02}"), &Balanced { id: format!("r{i:02}"), group: "g".into(), phone: Sealed::new(format!("0599{i:06}")) }).unwrap();
        }
        s.close();
    }
    {
        let db = redb::Database::open(dir.join("records").join("store.cldb")).unwrap();
        let tx = db.begin_write().unwrap();
        {
            use redb::ReadableTable;
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
    let s = Storage::builder(config_with_sink(&seen)).add_database(plain_with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Balanced>("t")).build().unwrap();
    let domain = s.domain::<Balanced>();
    let read = domain.read_grant().unwrap();
    let err = Balanced::phone.scan_sealed(&read).run(domain, |_: &String| true).unwrap_err();
    assert!(matches!(err, ClError::DataTampered), "{err:?}");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.scans.len(), 1, "the failed scan sent its event too");
    assert_eq!(seen.scans[0].1, 8, "r00 to r07 were opened, the changed one last");
    drop(seen);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------------------------

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Memo {
    id: String,
    #[clove(encrypt, id = 1)]
    note: Sealed<String>,
}
impl Entity for Memo {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// A sealed field with no fingerprint is searched by the slow scan alone: its handle has `scan_sealed`.
#[test]
fn a_sealed_field_without_a_fingerprint_is_scanned_through_its_own_handle() {
    let dir = temp_dir();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s = Storage::builder(config_with_sink(&seen)).add_database(with_keys(&dir, keys(Some(1), Some(2))).register_sealed::<Memo>("memos")).build().unwrap();
    let domain = s.domain::<Memo>();
    for i in 0..300u32 {
        domain.repo().set(&format!("m{i:03}"), &Memo { id: format!("m{i:03}"), note: Sealed::new(format!("note {}", i % 10)) }).unwrap();
    }
    let read = domain.read_grant().unwrap();
    let got: Vec<String> = Memo::note.scan_sealed(&read).run(domain, |v: &String| v == "note 7").unwrap().into_iter().map(|m| m.id).collect();
    assert_eq!(got.len(), 30);
    assert!(got.iter().all(|id| id[1..].parse::<u32>().unwrap() % 10 == 7));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.scans.len(), 1);
    assert_eq!(seen.scans[0].1, 300);
    assert_eq!(seen.scans[0].2, 30);
    assert_eq!(seen.reads, 0);
    drop(seen);
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}
