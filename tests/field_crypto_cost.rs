//! Cost of a protected field, in microseconds per field, against the same entity without protection.
//!
//! Write: `commit_entities` of many rows, so the commit itself is shared by both. Read: reading the
//! rows (which binds each protected value to its row) and then opening every value with a grant.
//! The difference between the protected and the plain entity, divided by the number of fields, is
//! the cost of one protected field. Median of several repeats, `DurabilityMode::Fast`, no cache,
//! no backup file, an ordinary database with field keys.
//!
//! Run on purpose, alone, in a quiet window (it is a measurement):
//! `cargo test --release --test field_crypto_cost -- --ignored --nocapture --test-threads=1`
//! It takes about two minutes.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    durability::DurabilityMode,
    entity::Entity,
    field_crypto::Sealed,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

macro_rules! entities {
    ($protected:ident, $plain:ident) => {
        #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
        struct $protected {
            id: String,
            #[clove(encrypt, id = 1)]
            f1: Sealed<String>,
            #[clove(encrypt, id = 2)]
            f2: Sealed<String>,
            #[clove(encrypt, id = 3)]
            f3: Sealed<String>,
            #[clove(encrypt, id = 4)]
            f4: Sealed<String>,
        }
        impl Entity for $protected {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
        #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
        struct $plain {
            id: String,
            f1: String,
            f2: String,
            f3: String,
            f4: String,
        }
        impl Entity for $plain {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    };
}
entities!(SmallProtected, SmallPlain);
entities!(BigProtected, BigPlain);

const FIELDS: usize = 4;
const REPEATS: usize = 7;

fn text(len: usize, seed: usize) -> String {
    (0..len).map(|i| (b'a' + ((i * 7 + seed) % 26) as u8) as char).collect()
}

fn cipher_of(name: &str) -> CipherKind {
    if name == "aes" { CipherKind::Aes256GcmSiv } else { CipherKind::XChaCha20Poly1305 }
}

fn keys(cipher: &str) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: cipher_of(cipher), hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    }
}

fn base(dir: &std::path::Path) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false).durability(DurabilityMode::Fast);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    db
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("clove-cost-{}", uuid::Uuid::new_v4()))
}

/// (median, worst) of one cost, in microseconds per field.
type Cost = (f64, f64);

struct Row {
    label: String,
    write_us: Cost,
    bind_us: Cost,
    open_us: Cost,
}

/// Median and worst of the per-repeat values.
fn summarize(mut values: Vec<f64>) -> Cost {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (values[values.len() / 2], *values.last().unwrap())
}

macro_rules! measure {
    ($protected:ident, $plain:ident, $rows:expr, $len:expr, $cipher:expr) => {{
        let n: usize = $rows;
        let len: usize = $len;
        let make_p = |i: usize| $protected {
            id: format!("r{i:06}"),
            f1: Sealed::new(text(len, i)),
            f2: Sealed::new(text(len, i + 1)),
            f3: Sealed::new(text(len, i + 2)),
            f4: Sealed::new(text(len, i + 3)),
        };
        let make_q = |i: usize| $plain {
            id: format!("r{i:06}"),
            f1: text(len, i),
            f2: text(len, i + 1),
            f3: text(len, i + 2),
            f4: text(len, i + 3),
        };
        let d1 = dir();
        let prot = Storage::builder(StorageConfig::default())
            .add_database(base(&d1).field_encryption(keys($cipher)).register_sealed::<$protected>("t"))
            .build()
            .unwrap();
        let d2 = dir();
        let plain = Storage::builder(StorageConfig::default())
            .add_database(base(&d2).register::<$plain>("t"))
            .build()
            .unwrap();
        let rows_p: Vec<$protected> = (0..n).map(&make_p).collect();
        let rows_q: Vec<$plain> = (0..n).map(&make_q).collect();
        let ids: Vec<String> = rows_p.iter().map(|r| r.id.clone()).collect();
        let (mut wp, mut wq, mut rp, mut rq, mut op) = (vec![], vec![], vec![], vec![], vec![]);
        let grant = prot.domain::<$protected>().read_grant().unwrap();
        for _ in 0..REPEATS {
            let writes: Vec<(&str, &$protected)> = ids.iter().map(|s| s.as_str()).zip(rows_p.iter()).collect();
            let t = Instant::now();
            prot.domain::<$protected>().repo().commit_entities(&writes, &[]).unwrap();
            wp.push(t.elapsed());
            let writes: Vec<(&str, &$plain)> = ids.iter().map(|s| s.as_str()).zip(rows_q.iter()).collect();
            let t = Instant::now();
            plain.domain::<$plain>().repo().commit_entities(&writes, &[]).unwrap();
            wq.push(t.elapsed());

            let t = Instant::now();
            let read_p = prot.domain::<$protected>().repo().list_map(|r| r).unwrap();
            rp.push(t.elapsed());
            let t = Instant::now();
            let read_q = plain.domain::<$plain>().repo().list_map(|r| r).unwrap();
            rq.push(t.elapsed());
            assert_eq!(read_p.len(), n);
            assert_eq!(read_q.len(), n);

            let t = Instant::now();
            let mut total = 0usize;
            for r in &read_p {
                total += r.f1.open(&grant).unwrap().len();
                total += r.f2.open(&grant).unwrap().len();
                total += r.f3.open(&grant).unwrap().len();
                total += r.f4.open(&grant).unwrap().len();
            }
            op.push(t.elapsed());
            assert_eq!(total, n * FIELDS * len);
        }
        prot.close();
        plain.close();
        let per_field = |d: Duration| d.as_secs_f64() * 1e6 / (n * FIELDS) as f64;
        // Each repeat pairs the protected run with the plain run made right before or after it.
        let paired = |p: &Vec<Duration>, q: &Vec<Duration>| -> Vec<f64> {
            p.iter().zip(q.iter()).map(|(a, b)| per_field(*a) - per_field(*b)).collect()
        };
        Row {
            label: format!("{:>6} B  {:7}", len, $cipher),
            write_us: summarize(paired(&wp, &wq)),
            bind_us: summarize(paired(&rp, &rq)),
            open_us: summarize(op.iter().map(|d| per_field(*d)).collect()),
        }
    }};
}

#[test]
#[ignore]
fn cost_of_one_protected_field_against_the_same_entity_without_protection() {
    let mut rows = Vec::new();
    for cipher in ["aes", "xchacha"] {
        rows.push(measure!(SmallProtected, SmallPlain, 4000, 16, cipher));
        rows.push(measure!(BigProtected, BigPlain, 600, 4096, cipher));
    }
    println!("\ncost of one protected field, microseconds (protected minus plain, per field; median / worst of {REPEATS} repeats)");
    println!("{:<18} {:>16} {:>16} {:>16} {:>16}", "field", "write", "read (bind)", "open", "read+open");
    for r in &rows {
        println!(
            "{:<18} {:>7.2} /{:>7.2} {:>7.2} /{:>7.2} {:>7.2} /{:>7.2} {:>7.2} /{:>7.2}",
            r.label,
            r.write_us.0, r.write_us.1,
            r.bind_us.0, r.bind_us.1,
            r.open_us.0, r.open_us.1,
            r.bind_us.0 + r.open_us.0, r.bind_us.1 + r.open_us.1,
        );
    }
}
