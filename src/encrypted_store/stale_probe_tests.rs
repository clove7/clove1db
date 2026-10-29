//! Measures what a block put back from an older copy of its file is, for the blocks the full check
//! passes: never read by redb, read and harmless, or read and giving wrong rows (which must be none).
use super::backend::READ_LOG;
use super::{Credentials, EncryptedDatabase, OpenOptionsExt};
use crate::crypto::{CipherKind, HkdfHash, Key32, KeySuite, ProgrammerKey};
use redb::{ReadableTable, TableDefinition};
use std::collections::BTreeSet;
use std::path::PathBuf;

const T: TableDefinition<u64, &[u8]> = TableDefinition::new("probe_rows");
const OPTS: OpenOptionsExt = OpenOptionsExt { cache_bytes: None, verify_on_open: false, read_only: false, repair_seen: None, tuning: super::tuning::EncryptionTuning::DEFAULT };

fn insert(db: &EncryptedDatabase, range: std::ops::Range<u64>, salt: u8) {
    let w = db.begin_write().unwrap();
    {
        let mut t = w.open_table(T).unwrap();
        for i in range {
            t.insert(i, vec![(i as u8).wrapping_add(salt); 300].as_slice()).unwrap();
        }
    }
    w.commit().unwrap();
}

fn read_all(db: &EncryptedDatabase) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let r = db.begin_read().map_err(|e| e.to_string())?;
    let t = r.open_table(T).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for entry in t.iter().map_err(|e| e.to_string())? {
        let (k, v) = entry.map_err(|e| e.to_string())?;
        out.push((k.value(), v.value().to_vec()));
    }
    Ok(out)
}

/// Open, check every block, read every row; returns the rows (or why not) and the blocks redb read.
fn look(path: &std::path::Path, c: &Credentials) -> (Result<Vec<(u64, Vec<u8>)>, String>, BTreeSet<u64>) {
    READ_LOG.with(|l| *l.borrow_mut() = Some(BTreeSet::new()));
    let seen = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Vec<(u64, Vec<u8>)>, String> {
        let mut db = EncryptedDatabase::open(path, c, "main", &OPTS, &mut |_| {}).map_err(|e| e.to_string())?;
        db.verify_all().map_err(|e| e.to_string())?;
        read_all(&db)
    }))
    .unwrap_or_else(|_| Err("panic".to_string()));
    let blocks = READ_LOG.with(|l| l.borrow_mut().take()).unwrap_or_default();
    (seen, blocks)
}

#[test]
fn old_blocks_the_full_check_passes_are_never_read_or_harmless() {
    let suite = KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 };
    let (rk, sk) = (Key32::from_bytes(&[7; 32]), Key32::from_bytes(&[8; 32]));
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let c = Credentials { suite, read: Some(&r), search: Some(&s) };
    let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let path: PathBuf = dir.join("p.db");
    let db = EncryptedDatabase::create(&path, &c, "main", &OPTS).unwrap();
    insert(&db, 0..200, 1);
    drop(db);
    let old = std::fs::read(&path).unwrap();
    let db = EncryptedDatabase::open(&path, &c, "main", &OPTS, &mut |_| {}).unwrap();
    insert(&db, 100..300, 2);
    drop(db);
    let now = std::fs::read(&path).unwrap();
    let (expected, _) = look(&path, &c);
    let expected = expected.unwrap();
    let stride = 4096 + suite.cipher.overhead();
    let blocks = (old.len().min(now.len()) - 4096) / stride;
    let work = dir.join("w.db");
    let (mut changed, mut found, mut never_read, mut read_same, mut read_wrong) = (0, 0, 0, 0, 0);
    for i in 0..blocks {
        let (a, b) = (4096 + i * stride, 4096 + (i + 1) * stride);
        if old[a..b] == now[a..b] {
            continue;
        }
        changed += 1;
        let mut m = now.clone();
        m[a..b].copy_from_slice(&old[a..b]);
        std::fs::write(&work, &m).unwrap();
        match look(&work, &c) {
            (Err(_), _) => found += 1,
            (Ok(rows), read) if !read.contains(&(i as u64)) => {
                never_read += 1;
                assert_eq!(rows, expected, "block {i} was never read but the rows differ");
            }
            (Ok(rows), _) if rows == expected => read_same += 1,
            (Ok(_), _) => read_wrong += 1,
        }
    }
    println!(
        "stale probe: changed={changed} found_by_full_check={found} passed_never_read={never_read} passed_read_rows_equal={read_same} passed_read_rows_wrong={read_wrong}"
    );
    assert!(changed > 3, "the probe changed nothing");
    assert_eq!(read_wrong, 0, "a block that redb reads gave wrong rows after the full check");
    let _ = std::fs::remove_dir_all(&dir);
}
