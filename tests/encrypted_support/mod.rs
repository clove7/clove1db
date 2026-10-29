//! Helpers shared by the encrypted store tests: a temporary directory, a deterministic table, and
//! an in-memory file that records every operation so a power cut can be replayed.
#![allow(dead_code)]
use clove1db::crypto::{CipherKind, HkdfHash, Key32, KeySuite};
use clove1db::encrypted_store::StoreError;
use redb::{ReadableDatabase, ReadableTable, StorageBackend, TableDefinition};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("people_notes");
pub const MARKER: &str = "MARKER-0f3a9c11-7be2-45d0";

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "encstore-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn suites() -> [KeySuite; 2] {
    [
        KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha512 },
    ]
}

pub fn key() -> Key32 {
    Key32::generate().unwrap()
}

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^ (x >> 31)
}

/// A value for `key` that carries the marker and is 100 to 800 bytes long.
pub fn value(key: u64, version: u64) -> Vec<u8> {
    let seed = splitmix(key ^ splitmix(version));
    let mut v = format!("{MARKER}-{key}-{version}-").into_bytes();
    let target = 100 + (seed % 700) as usize;
    let mut s = seed;
    while v.len() < target {
        s = splitmix(s);
        v.push(b'a' + (s % 26) as u8);
    }
    v
}

pub fn rows(from: u64, to: u64, version: u64) -> Vec<(u64, Vec<u8>)> {
    (from..to).map(|k| (k, value(k, version))).collect()
}

pub fn insert_rows(w: &redb::WriteTransaction, rows: &[(u64, Vec<u8>)]) {
    let mut t = w.open_table(TABLE).unwrap();
    for (k, v) in rows {
        t.insert(*k, v.as_slice()).unwrap();
    }
}

/// Every row, or the first error as text.
pub fn read_all(db: &redb::Database) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let r = db.begin_read().map_err(|e| e.to_string())?;
    let t = match r.open_table(TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut out = Vec::new();
    for item in t.iter().map_err(|e| e.to_string())? {
        let (k, v) = item.map_err(|e| e.to_string())?;
        out.push((k.value(), v.value().to_vec()));
    }
    Ok(out)
}

pub fn is_open_failed(e: &StoreError) -> bool {
    matches!(e, StoreError::OpenFailed)
}

// ---- an in-memory file that records its operations ----------------------------------------

#[derive(Clone, Debug)]
pub enum Op {
    Write { off: u64, data: Vec<u8> },
    SetLen(u64),
    Sync,
}

#[derive(Debug, Default)]
struct MemInner {
    cur: Vec<u8>,
    log: Vec<Op>,
    record: bool,
}

#[derive(Clone, Debug)]
pub struct MemFile(Arc<Mutex<MemInner>>);

impl MemFile {
    pub fn new(record: bool) -> Self {
        MemFile(Arc::new(Mutex::new(MemInner { cur: Vec::new(), log: Vec::new(), record })))
    }
    pub fn from_image(image: Vec<u8>) -> Self {
        MemFile(Arc::new(Mutex::new(MemInner { cur: image, log: Vec::new(), record: false })))
    }
    pub fn log(&self) -> Vec<Op> {
        self.0.lock().unwrap().log.clone()
    }
    pub fn mark(&self) -> usize {
        self.0.lock().unwrap().log.len()
    }
    pub fn image(&self) -> Vec<u8> {
        self.0.lock().unwrap().cur.clone()
    }
}

impl StorageBackend for MemFile {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.0.lock().unwrap().cur.len() as u64)
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        let g = self.0.lock().unwrap();
        let end = offset as usize + out.len();
        if end > g.cur.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read past the end"));
        }
        out.copy_from_slice(&g.cur[offset as usize..end]);
        Ok(())
    }
    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        let mut g = self.0.lock().unwrap();
        g.cur.resize(len as usize, 0);
        if g.record {
            g.log.push(Op::SetLen(len));
        }
        Ok(())
    }
    fn sync_data(&self) -> Result<(), std::io::Error> {
        let mut g = self.0.lock().unwrap();
        if g.record {
            g.log.push(Op::Sync);
        }
        Ok(())
    }
    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        let mut g = self.0.lock().unwrap();
        let end = offset as usize + data.len();
        if end > g.cur.len() {
            g.cur.resize(end, 0);
        }
        g.cur[offset as usize..end].copy_from_slice(data);
        if g.record {
            g.log.push(Op::Write { off: offset, data: data.to_vec() });
        }
        Ok(())
    }
}

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    pub fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Model {
    Prefix,
    Subset,
}

const SECTOR: usize = 512;

fn apply(img: &mut Vec<u8>, op: &Op) {
    match op {
        Op::Write { off, data } => {
            let end = *off as usize + data.len();
            if end > img.len() {
                img.resize(end, 0);
            }
            img[*off as usize..end].copy_from_slice(data);
        }
        Op::SetLen(len) => img.resize(*len as usize, 0),
        Op::Sync => {}
    }
}

/// The image after power is lost while `log[cut - 1]` is in flight: operations up to the last
/// completed sync are durable, later ones may or may not have reached the disk, and the write in
/// flight is torn on 512-byte sector boundaries.
pub fn crash_image(log: &[Op], cut: usize, model: Model, rng: &mut Rng) -> Vec<u8> {
    let completed = &log[..cut - 1];
    let inflight = &log[cut - 1];
    let synced = completed.iter().rposition(|op| matches!(op, Op::Sync));
    let split = synced.map_or(0, |s| s + 1);
    let mut img = Vec::new();
    for op in &completed[..split] {
        apply(&mut img, op);
    }
    for op in &completed[split..] {
        if model == Model::Prefix || rng.coin() {
            apply(&mut img, op);
        }
    }
    match inflight {
        Op::Write { off, data } if !data.is_empty() => {
            let start = *off as usize;
            let end = start + data.len();
            let first = start / SECTOR;
            let sectors = (end - 1) / SECTOR - first + 1;
            let mut kept = vec![false; sectors];
            match model {
                Model::Prefix => {
                    let n = rng.below(sectors as u64 + 1) as usize;
                    kept.iter_mut().take(n).for_each(|k| *k = true);
                }
                Model::Subset => kept.iter_mut().for_each(|k| *k = rng.coin()),
            }
            for (i, keep) in kept.iter().enumerate() {
                if *keep {
                    let s = ((first + i) * SECTOR).max(start);
                    let e = ((first + i + 1) * SECTOR).min(end);
                    apply(&mut img, &Op::Write { off: s as u64, data: data[s - start..e - start].to_vec() });
                }
            }
        }
        Op::SetLen(_) => {
            if rng.coin() {
                apply(&mut img, inflight);
            }
        }
        _ => {}
    }
    img
}

pub fn path_str(p: &Path) -> String {
    p.display().to_string()
}
