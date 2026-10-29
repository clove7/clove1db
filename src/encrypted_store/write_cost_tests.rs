//! Splits the whole time of a write into an encrypted database against a plain one, with the same counters on both
//! (the plain file goes through a counting wrapper). The same workload runs on one fresh file per kind, alternating over
//! several rounds: plain one-phase, plain two-phase (quick repair), XChaCha20-Poly1305, AES-256-GCM-SIV. Counters off and
//! on are both run, so what the counters cost can be read. Run alone, in release:
//!   cargo test --release --lib write_cost_split -- --ignored --nocapture
use super::backend::{CHECK_LEN, COST, Cost, Span};
use super::{Credentials, EncryptedDatabase, OpenOptionsExt};
use crate::crypto::{CipherKind, HkdfHash, Key32, KeySuite, ProgrammerKey};
use redb::backends::FileBackend;
use redb::{BackendError, Database, StorageBackend, TableDefinition, WriteTransaction};
use std::io;
use std::ops::Bound;
use std::path::Path;
use std::time::Instant;

const T: TableDefinition<u64, &[u8]> = TableDefinition::new("cost_rows");
const OPTS: OpenOptionsExt = OpenOptionsExt { cache_bytes: None, verify_on_open: false, read_only: false, repair_seen: None, tuning: super::tuning::EncryptionTuning::DEFAULT };
const ROWS: u64 = 10_000;
const BATCHES: u64 = 20;
const PER_BATCH: u64 = 500;
const ROUNDS: usize = 5;
const PAGE: u64 = 4096;

/// A plain file seen through the same counters as the sealed layer.
#[derive(Debug)]
struct Counting(FileBackend);

impl StorageBackend for Counting {
    fn len(&self) -> Result<u64, io::Error> {
        let _s = Span::new(|c: &mut Cost, ns: u128| {
            c.file_len_ns += ns;
            c.file_len_calls += 1;
        });
        self.0.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), io::Error> {
        let n = out.len() as u64;
        let _s = Span::new(move |c: &mut Cost, ns: u128| {
            c.layer_read_ns += ns;
            c.file_read_ns += ns;
            c.read_calls += 1;
            c.file_read_calls += 1;
            c.read_bytes += n;
            c.file_read_bytes += n;
            if offset % PAGE != 0 || n % PAGE != 0 {
                c.partial_reads += 1;
            }
        });
        self.0.read(offset, out)
    }

    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        let _s = Span::new(|c: &mut Cost, ns: u128| {
            c.layer_setlen_ns += ns;
            c.file_setlen_ns += ns;
            c.setlen_calls += 1;
            c.file_setlen_calls += 1;
        });
        self.0.set_len(len)
    }

    fn sync_data(&self) -> Result<(), io::Error> {
        let _s = Span::new(|c: &mut Cost, ns: u128| {
            c.layer_sync_ns += ns;
            c.file_sync_ns += ns;
            c.sync_calls += 1;
            c.file_sync_calls += 1;
        });
        self.0.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        let n = data.len() as u64;
        let _s = Span::new(move |c: &mut Cost, ns: u128| {
            c.layer_write_ns += ns;
            c.file_write_ns += ns;
            c.write_calls += 1;
            c.file_write_calls += 1;
            c.write_bytes += n;
            c.file_write_bytes += n;
            if offset % PAGE != 0 || n % PAGE != 0 {
                c.partial_writes += 1;
            }
            if n < PAGE {
                c.file_small_writes += 1;
            }
        });
        self.0.write(offset, data)
    }

    fn close(&self) -> Result<(), io::Error> {
        self.0.close()
    }

    fn try_lock_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<bool, BackendError> {
        self.0.try_lock_range(s, e)
    }
    fn try_lock_shared_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<bool, BackendError> {
        self.0.try_lock_shared_range(s, e)
    }
    fn lock_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<(), BackendError> {
        self.0.lock_range(s, e)
    }
    fn lock_shared_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<(), BackendError> {
        self.0.lock_shared_range(s, e)
    }
    fn unlock_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<(), BackendError> {
        self.0.unlock_range(s, e)
    }
    fn query_lock_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<bool, BackendError> {
        self.0.query_lock_range(s, e)
    }
}

fn commit_rows(begin: &dyn Fn() -> WriteTransaction, from: u64, count: u64, salt: u8) {
    let w = begin();
    {
        let mut t = w.open_table(T).unwrap();
        for i in from..from + count {
            let id = i % ROWS;
            t.insert(id, vec![(id as u8) ^ salt; 1000].as_slice()).unwrap();
        }
    }
    w.commit().unwrap();
}

fn start_counters(on: bool) {
    if on {
        COST.with(|c| *c.borrow_mut() = Some(Cost::default()));
    }
}

/// Preload (not counted), then the timed writes. Returns the milliseconds of the timed part and the counters.
fn workload(begin: &dyn Fn() -> WriteTransaction, counters: bool) -> (f64, Option<Cost>) {
    for b in 0..10 {
        commit_rows(begin, b * 1000, 1000, 0);
    }
    start_counters(counters);
    let t = Instant::now();
    for b in 0..BATCHES {
        commit_rows(begin, b * PER_BATCH, PER_BATCH, 7);
    }
    let ms = t.elapsed().as_secs_f64() * 1000.;
    (ms, COST.with(|c| c.borrow_mut().take()))
}

fn run_plain(dir: &Path, two_phase: bool) -> f64 {
    let db = Database::builder().create(dir.join("plain.db")).unwrap();
    let begin = || {
        let mut w = db.begin_write().unwrap();
        w.set_quick_repair(two_phase);
        w
    };
    workload(&begin, false).0
}

fn run_plain_counted(dir: &Path) -> (f64, Cost) {
    let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(dir.join("plain-counted.db")).unwrap();
    let db = Database::builder().create_with_backend(Counting(FileBackend::new(file).unwrap())).unwrap();
    let begin = || {
        let mut w = db.begin_write().unwrap();
        w.set_quick_repair(true);
        w
    };
    let (ms, cost) = workload(&begin, true);
    (ms, cost.unwrap())
}

fn run_encrypted(dir: &Path, cipher: CipherKind, counters: bool) -> (f64, Option<Cost>) {
    let suite = KeySuite { cipher, hkdf: HkdfHash::Sha256 };
    let (rk, sk) = (Key32::from_bytes(&[3; 32]), Key32::from_bytes(&[4; 32]));
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let c = Credentials { suite, read: Some(&r), search: Some(&s) };
    let db = EncryptedDatabase::create(&dir.join("enc.db"), &c, "main", &OPTS).unwrap();
    let begin = || db.begin_write().unwrap();
    workload(&begin, counters)
}

fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn med(costs: &[(f64, Cost)], f: &dyn Fn(f64, &Cost) -> f64) -> f64 {
    let mut v: Vec<f64> = costs.iter().map(|(t, c)| f(*t, c)).collect();
    median(&mut v)
}

fn ms(ns: u128) -> f64 {
    ns as f64 / 1e6
}

#[test]
#[ignore]
fn write_cost_split() {
    // the flag check asks the file for its length; it must not add to the time measured here
    CHECK_LEN.with(|c| c.set(false));
    let base = std::env::temp_dir().join(format!("clove-writecost-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let (mut p1, mut p2, mut xc_off, mut aes_off) = (vec![], vec![], vec![], vec![]);
    let (mut plain_on, mut xc_on, mut aes_on): (Vec<(f64, Cost)>, Vec<(f64, Cost)>, Vec<(f64, Cost)>) = (vec![], vec![], vec![]);
    for round in 0..ROUNDS {
        let d = |name: &str| {
            let d = base.join(format!("{name}-{round}"));
            std::fs::create_dir_all(&d).unwrap();
            d
        };
        p1.push(run_plain(&d("p1"), false));
        p2.push(run_plain(&d("p2"), true));
        plain_on.push(run_plain_counted(&d("pc")));
        xc_off.push(run_encrypted(&d("xo"), CipherKind::XChaCha20Poly1305, false).0);
        let (t, c) = run_encrypted(&d("xn"), CipherKind::XChaCha20Poly1305, true);
        xc_on.push((t, c.unwrap()));
        aes_off.push(run_encrypted(&d("ao"), CipherKind::Aes256GcmSiv, false).0);
        let (t, c) = run_encrypted(&d("an"), CipherKind::Aes256GcmSiv, true);
        aes_on.push((t, c.unwrap()));
    }
    println!("write {BATCHES}x{PER_BATCH} rows of 1000 bytes into a table of {ROWS} rows; {ROUNDS} rounds; medians in ms");
    println!("totals, counters off : plain one-phase {:.1} | plain two-phase {:.1} | XChaCha {:.1} | AES {:.1}", median(&mut p1.clone()), median(&mut p2.clone()), median(&mut xc_off.clone()), median(&mut aes_off.clone()));
    println!("two-phase commit alone (plain two-phase - one-phase): {:.1}", median(&mut p2.clone()) - median(&mut p1.clone()));
    let cols: [(&str, &Vec<(f64, Cost)>); 3] = [("plain 2-phase", &plain_on), ("XChaCha", &xc_on), ("AES-GCM-SIV", &aes_on)];
    let layer = |c: &Cost| ms(c.layer_read_ns + c.layer_write_ns + c.layer_setlen_ns + c.layer_sync_ns);
    let known = |c: &Cost| {
        ms(c.file_read_ns + c.open_ns + c.copy_ns + c.seal_ns + c.fill_seal_ns + c.header_seal_ns + c.file_write_ns + c.file_setlen_ns + c.file_sync_ns + c.file_len_ns + c.scratch_ns)
    };
    type Row<'a> = (&'a str, Box<dyn Fn(f64, &Cost) -> f64>);
    let rows: Vec<Row> = vec![
        ("TOTAL (counters on)", Box::new(|t, _| t)),
        ("redb's own work (total - everything in the file layer)", Box::new(move |t, c| t - layer(c))),
        ("file layer, all methods", Box::new(move |_, c| layer(c))),
        ("  read: from the file", Box::new(|_, c| ms(c.file_read_ns))),
        ("  read: decrypt (open blocks)", Box::new(|_, c| ms(c.open_ns))),
        ("  read: copy to redb's buffer", Box::new(|_, c| ms(c.copy_ns))),
        ("  write: seal data blocks", Box::new(|_, c| ms(c.seal_ns))),
        ("  write: seal zero-fill blocks", Box::new(|_, c| ms(c.fill_seal_ns))),
        ("  write: seal header pieces", Box::new(|_, c| ms(c.header_seal_ns))),
        ("  write: to the file", Box::new(|_, c| ms(c.file_write_ns))),
        ("  scratch buffer (grow/free)", Box::new(|_, c| ms(c.scratch_ns))),
        ("  set_len on the file", Box::new(|_, c| ms(c.file_setlen_ns))),
        ("  sync on the file", Box::new(|_, c| ms(c.file_sync_ns))),
        ("  len() on the file (file size query)", Box::new(|_, c| ms(c.file_len_ns))),
        ("  file layer, not covered by a line above", Box::new(move |_, c| layer(c) - known(c))),
    ];
    println!("\n{:<58} {:>14} {:>10} {:>10}  | gap XChaCha  gap AES", "ms", cols[0].0, cols[1].0, cols[2].0);
    for (name, f) in &rows {
        let v: Vec<f64> = cols.iter().map(|(_, costs)| med(costs, &**f)).collect();
        println!("{:<58} {:>14.2} {:>10.2} {:>10.2}  | {:>+10.2} {:>+9.2}", name, v[0], v[1], v[2], v[1] - v[0], v[2] - v[0]);
    }
    println!("\ncounts (medians; what redb asked of the layer, and what reached the file)");
    let counts: Vec<(&str, Box<dyn Fn(&Cost) -> f64>)> = vec![
        ("layer reads (calls)", Box::new(|c| c.read_calls as f64)),
        ("layer read bytes", Box::new(|c| c.read_bytes as f64)),
        ("layer partial reads (not whole pages)", Box::new(|c| c.partial_reads as f64)),
        ("layer writes (calls)", Box::new(|c| c.write_calls as f64)),
        ("layer write bytes", Box::new(|c| c.write_bytes as f64)),
        ("layer partial writes (not whole pages)", Box::new(|c| c.partial_writes as f64)),
        ("read-modify-write of a block", Box::new(|c| c.rmw as f64)),
        ("blocks sealed (data)", Box::new(|c| c.seal_blocks as f64)),
        ("blocks sealed (zero fill)", Box::new(|c| c.fill_blocks as f64)),
        ("blocks decrypted", Box::new(|c| c.open_blocks as f64)),
        ("header pieces sealed", Box::new(|c| c.header_writes as f64)),
        ("file writes (calls)", Box::new(|c| c.file_write_calls as f64)),
        ("file write bytes", Box::new(|c| c.file_write_bytes as f64)),
        ("file writes smaller than a page", Box::new(|c| c.file_small_writes as f64)),
        ("file reads (calls)", Box::new(|c| c.file_read_calls as f64)),
        ("file read bytes", Box::new(|c| c.file_read_bytes as f64)),
        ("file set_len (calls)", Box::new(|c| c.file_setlen_calls as f64)),
        ("syncs reaching the file", Box::new(|c| c.file_sync_calls as f64)),
        ("len() calls reaching the file", Box::new(|c| c.file_len_calls as f64)),
    ];
    for (name, f) in &counts {
        let v: Vec<f64> = cols.iter().map(|(_, costs)| med(costs, &|_, c| f(c))).collect();
        println!("{:<58} {:>14.0} {:>10.0} {:>10.0}", name, v[0], v[1], v[2]);
    }
    let _ = std::fs::remove_dir_all(&base);
}
