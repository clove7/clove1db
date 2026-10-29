//! The slow-query event of searches on protected fields never carries a value or the text searched for.
//! The threshold is set to zero so that every query is "slow"; the test then checks that the events
//! were sent (it is not blind) and that none of them, nor any other event, holds a known value or needle.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::Sealed,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Rec {
    id: String,
    group: String,
    #[clove(encrypt, id = 1, print = "full", normalize = "trim")]
    phone: Sealed<String>,
    #[clove(encrypt, id = 2, print = "parts", window = 3, grade = "balanced", normalize = "trim")]
    name: Sealed<String>,
}
impl Entity for Rec {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn keys() -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    }
}

#[test]
fn searches_on_protected_fields_leave_no_value_or_text_in_the_slow_query_event() {
    let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let seen: Arc<Mutex<Vec<(bool, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let config = StorageConfig::default().slow_query_threshold(Duration::ZERO).event_sink(move |e: &LibraryEvent| {
        sink.lock().unwrap().push((matches!(e, LibraryEvent::SlowQuery { .. }), format!("{e:?}")));
    });
    let db = DatabaseConfig::new("records", "store").dir_path(dir.clone()).has_cache(false);
    #[cfg(clove_test_encrypt_all)]
    let db = db.encryption(keys());
    #[cfg(not(clove_test_encrypt_all))]
    let db = db.field_encryption(keys());
    let s = Storage::builder(config).add_database(db.register_sealed::<Rec>("recs")).build().unwrap();
    let domain = s.domain::<Rec>();
    for i in 0..400u32 {
        let rec = Rec { id: format!("r{i:04}"), group: "g".into(), phone: Sealed::new(format!("0501SLOWMARK{i:04}")), name: Sealed::new(format!("SLOWNAME-{i:04}-LAST")) };
        domain.repo().set(&rec.id, &rec).unwrap();
    }
    let read = domain.read_grant().unwrap();
    let search = domain.search_grant().unwrap();
    seen.lock().unwrap().clear();
    let known_values = ["0501SLOWMARK0123", "SLOWNAME-0123-LAST"];
    let needles = ["SLOWMARK0123", "NAME-0123", "SLOWNAME-0123", "0501SLOWMARK"];
    // Twice each, so that the optimizer has seen them (the second may use an index).
    for _ in 0..2 {
        assert_eq!(domain.query().filter(Rec::phone.print_eq(known_values[0], &search)).collect().unwrap().len(), 1);
        for needle in needles {
            let _ = domain.query().filter(Rec::name.part_candidates(needle, &search)).collect().unwrap();
            let _ = Rec::name.part_search(needle).run(domain, &search).unwrap();
        }
        let scanned = Rec::phone.scan_sealed(&read).run(domain, |v: &String| v.ends_with("0123")).unwrap();
        assert_eq!(scanned.len(), 1);
        let _ = Rec::name.scan_sealed(&read).filter(Rec::group.eq("g".to_string())).limit(5).run(domain, |v: &String| v.contains("SLOWNAME-0001")).unwrap();
    }
    let events = seen.lock().unwrap();
    let slow = events.iter().filter(|(is_slow, _)| *is_slow).count();
    assert!(slow >= 10, "the slow-query event must have been sent for the searches: {slow} events");
    for (_, text) in events.iter() {
        for secret in known_values.iter().chain(needles.iter()) {
            assert!(!text.contains(secret), "{secret} is in the event {text}");
        }
        assert!(!text.contains("SLOWMARK"), "a value is in the event {text}");
        assert!(!text.contains("SLOWNAME"), "a value is in the event {text}");
    }
    drop(events);
    s.close();
    // The files do not hold them either (the ordinary part: only the fingerprint and the sealed text are stored).
    let mut files = vec![dir.clone()];
    while let Some(d) = files.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                files.push(p);
            } else {
                let bytes = std::fs::read(&p).unwrap();
                assert!(!bytes.windows(8).any(|w| w == b"SLOWMARK" || w == b"SLOWNAME"), "{} holds a value", p.display());
            }
        }
    }
    std::fs::remove_dir_all(&dir).ok();
}
