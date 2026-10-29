//! A power cut at every operation of a workload, replayed on an in-memory file: after each one the
//! database opens on the last commit that finished (or the one after it), never on damaged data.
mod encrypted_support;

use clove1db::crypto::{Aead, CipherKind, DataKey, Key32, KeySuite, HkdfHash, ProgrammerKey};
use clove1db::encrypted_store::{open_database_over, write_file_header};
use encrypted_support::*;
use std::collections::BTreeMap;

fn aead(kind: CipherKind) -> Aead {
    Aead::new(kind, &Key32::from_bytes(&[0x42; 32])).unwrap()
}

fn expected(model: &BTreeMap<u64, u64>) -> Vec<(u64, Vec<u8>)> {
    model.iter().map(|(k, v)| (*k, value(*k, *v))).collect()
}

fn run(kind: CipherKind, ntx: u64, per_tx: u64) -> (u64, u64, u64, u64) {
    let suite = KeySuite { cipher: kind, hkdf: HkdfHash::Sha256 };
    let (rk, sk) = (Key32::generate().unwrap(), Key32::generate().unwrap());
    let locked = DataKey::generate()
        .unwrap()
        .lock(&suite, &ProgrammerKey::Raw(&rk), &ProgrammerKey::Raw(&sk))
        .unwrap();
    let mem = MemFile::new(true);
    write_file_header(&mem, &suite, &locked).unwrap();
    let db = open_database_over(mem.clone(), aead(kind), Some(256 * 1024), false).unwrap();
    let begin = |db: &redb::Database| {
        let mut w = db.begin_write().unwrap();
        w.set_quick_repair(true);
        w
    };
    let mut states: Vec<Vec<(u64, Vec<u8>)>> = vec![Vec::new()];
    let mut commit_end = Vec::new();
    let mut model: BTreeMap<u64, u64> = BTreeMap::new();
    let mut rng = Rng(77);
    {
        let w = begin(&db);
        w.open_table(TABLE).unwrap();
        w.commit().unwrap();
        commit_end.push(mem.mark());
    }
    for j in 1..=ntx {
        let w = begin(&db);
        {
            let mut t = w.open_table(TABLE).unwrap();
            for i in 0..per_tx {
                let k = j * 10_000 + i;
                t.insert(k, value(k, j).as_slice()).unwrap();
                model.insert(k, j);
            }
            let keys: Vec<u64> = model.keys().copied().collect();
            for _ in 0..4 {
                let k = keys[rng.below(keys.len() as u64) as usize];
                t.insert(k, value(k, j + 1000).as_slice()).unwrap();
                model.insert(k, j + 1000);
            }
            for _ in 0..2 {
                let k = keys[rng.below(keys.len() as u64) as usize];
                t.remove(k).unwrap();
                model.remove(&k);
            }
        }
        w.commit().unwrap();
        commit_end.push(mem.mark());
        states.push(expected(&model));
    }
    drop(db);
    let log = mem.log();
    let (mut trials, mut ok, mut init_fail, mut bad) = (0u64, 0u64, 0u64, 0u64);
    for cut in 1..=log.len() {
        for (mi, model) in [Model::Prefix, Model::Subset, Model::Subset].into_iter().enumerate() {
            let mut r = Rng(cut as u64 * 31 + mi as u64 + 5);
            let img = crash_image(&log, cut, model, &mut r);
            trials += 1;
            let done = cut - 1;
            let last = commit_end.iter().rposition(|e| *e <= done);
            let opened = open_database_over(MemFile::from_image(img), aead(kind), Some(256 * 1024), true);
            let Some(last) = last else {
                // before the first commit finished there is nothing to recover
                if opened.is_err() {
                    init_fail += 1;
                } else {
                    ok += 1;
                }
                continue;
            };
            let accept: Vec<&Vec<(u64, Vec<u8>)>> =
                (last..=(last + 1).min(states.len() - 1)).map(|k| &states[k]).collect();
            match opened {
                Err(_) => bad += 1,
                Ok(db2) => match read_all(&db2) {
                    Ok(rows) if accept.iter().any(|s| **s == rows) => {
                        // the database must also take a new commit
                        let mut w = db2.begin_write().unwrap();
                        let _ = &w;
                        w.set_quick_repair(true);
                        let wrote = (move || -> Result<(), Box<dyn std::error::Error>> {
                            {
                                let mut t = w.open_table(TABLE)?;
                                t.insert(u64::MAX - 1, b"x".as_slice())?;
                            }
                            w.commit()?;
                            Ok(())
                        })()
                        .is_ok();
                        if wrote {
                            ok += 1;
                        } else {
                            bad += 1;
                        }
                    }
                    _ => bad += 1,
                },
            }
        }
    }
    (trials, ok, init_fail, bad)
}

#[test]
fn a_power_cut_at_any_operation_leaves_a_database_that_opens_on_a_finished_commit() {
    for kind in [CipherKind::XChaCha20Poly1305, CipherKind::Aes256GcmSiv] {
        let (trials, ok, init_fail, bad) = run(kind, 14, 30);
        println!("{kind:?}: {trials} cuts, {ok} recovered, {init_fail} before the first commit, {bad} bad");
        assert_eq!(bad, 0, "{kind:?}: {bad} of {trials} cuts did not recover cleanly");
        assert!(ok > trials / 2, "{kind:?}: too few recovered ({ok} of {trials})");
    }
}
