//! The file layer under redb: every 4096-byte page is one sealed block, and redb's header page
//! is kept in four small pieces so that one torn write cannot take both commit slots with it.
//!
//! Why it is shaped like this (measured on redb 4.4.0 by logging every file call): redb only reads and
//! writes whole 4096-byte pages at page-aligned places (apart from its 320-byte header), so one
//! block per page needs no read-modify-write and a torn block can only be a page of a commit that
//! never finished. The header pieces are one 512-byte sector each, the unit a disk writes at once.
//! Block numbers are part of what is authenticated, so a block moved elsewhere fails to open.
//! A block put back at its own place from an older copy is *not* detected here; that is a
//! documented limit, and [`super::EncryptedDatabase::verify_all`] catches it.
use super::error::tamper_io;
use super::layout::{
    DATA_BASE, FILE_HEADER_LEN, Geometry, LOGICAL_HEADER, PAGE, PIECE_LEN, REDB_HEADER_LEN,
};
use crate::crypto::{Aead, random_bytes};
use redb::{BackendError, StorageBackend};
use std::cell::RefCell;
use super::tuning::EncryptionTuning;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::ops::Bound;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

/// Blocks written per file call when filling new space.
const FILL_BATCH: usize = 128;

/// Parallel sealing (idea B). Pages staged for the next sync are held at most this many (4 MiB); when it is reached they are
/// sealed and written without waiting for the sync.
pub(crate) const PENDING_CAP_PAGES: usize = 1024;
/// The largest sealed block: a page plus the XChaCha nonce and tag (40 bytes). A test ties it to the ciphers.
pub(crate) const MAX_STRIDE: usize = PAGE + 40;
/// The thread's scratch buffer is kept between calls up to this size: the sealed copy of a full drain (`PENDING_CAP_PAGES` blocks of
/// the largest stride, about 4.04 MiB) rounded up to whole MiB, so a full drain never frees the buffer it will need again at the next commit.
pub(crate) const SCRATCH_KEEP: usize = (PENDING_CAP_PAGES * MAX_STRIDE).div_ceil(1 << 20) << 20;
/// Fewer staged pages than this are sealed on the calling thread: starting threads would cost more than it saves.
const SEAL_MIN_PAGES: usize = 64;
/// A helper thread is started only for at least this many pages.
const PAGES_PER_THREAD: usize = 16;
/// Pages per file write during a drain, so that a crash point can fall in the middle of the writes.
const WRITE_CHUNK: usize = 128;

/// Test hook for the crash tests (feature `crash-inject`): exit the process at the named point of a drain, after `CLOVE_CRASH_SKIP` earlier
/// hits of that name.
#[cfg(feature = "crash-inject")]
fn crash_point(name: &str) {
    static HITS: AtomicU64 = AtomicU64::new(0);
    if std::env::var("CLOVE_CRASH_POINT").ok().as_deref() == Some(name) {
        let skip = std::env::var("CLOVE_CRASH_SKIP").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        if HITS.fetch_add(1, Relaxed) >= skip {
            std::process::exit(99);
        }
    }
}

#[cfg(not(feature = "crash-inject"))]
#[inline(always)]
fn crash_point(_name: &str) {}

/// Seal `pages` into `out` (one block of `stride` bytes each).
fn seal_chunk(aead: &Aead, pages: &[(u64, Arc<[u8]>)], out: &mut [u8], stride: usize) -> io::Result<()> {
    for (i, (index, plain)) in pages.iter().enumerate() {
        aead.seal_into(&block_aad(*index), plain, &mut out[i * stride..(i + 1) * stride]).map_err(|_| bad("sealing a block failed"))?;
    }
    Ok(())
}

/// Test only: what the staging did, per backend.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Stats {
    pub drains: AtomicU64,
    pub drain_pages: AtomicU64,
    pub parallel_drains: AtomicU64,
    pub peak_pending: AtomicU64,
    pub served_pending: AtomicU64,
}

thread_local! {
    static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn with_scratch<R>(len: usize, f: impl FnOnce(&mut [u8]) -> R) -> R {
    SCRATCH.with(|cell| {
        let mut v = cell.borrow_mut();
        {
            #[cfg(test)]
            let _s = Span::new(|c: &mut Cost, ns: u128| c.scratch_ns += ns);
            if v.len() < len {
                v.resize(len, 0);
            }
        }
        let out = f(&mut v[..len]);
        {
            #[cfg(test)]
            let _s = Span::new(|c: &mut Cost, ns: u128| c.scratch_ns += ns);
            if v.capacity() > SCRATCH_KEEP {
                *v = Vec::new();
            }
        }
        out
    })
}

/// Test only: where the time and the bytes of reads and writes go. Off unless a probe switches it on for its thread.
/// A plain file is counted with the same fields by a wrapper in the probe, so the two can be set side by side.
#[cfg(test)]
#[derive(Default, Clone, Copy, Debug)]
pub(crate) struct Cost {
    // time inside each method of the backend, and what redb asked of it
    pub layer_read_ns: u128,
    pub layer_write_ns: u128,
    pub layer_setlen_ns: u128,
    pub layer_sync_ns: u128,
    pub read_calls: u64,
    pub read_bytes: u64,
    pub write_calls: u64,
    pub write_bytes: u64,
    /// reads / writes that are not whole aligned pages (the header page)
    pub partial_reads: u64,
    pub partial_writes: u64,
    pub setlen_calls: u64,
    pub sync_calls: u64,
    // inside the sealed layer
    pub seal_ns: u128,
    pub seal_blocks: u64,
    pub fill_seal_ns: u128,
    pub fill_blocks: u64,
    pub header_seal_ns: u128,
    pub header_writes: u64,
    pub open_ns: u128,
    pub open_blocks: u64,
    pub copy_ns: u128,
    pub scratch_ns: u128,
    /// read-modify-write of a block: the layer refuses unaligned writes, so this is 0 by construction
    pub rmw: u64,
    // the file below the layer (or the plain file itself)
    pub file_write_ns: u128,
    pub file_write_calls: u64,
    pub file_write_bytes: u64,
    pub file_small_writes: u64,
    pub file_read_ns: u128,
    pub file_read_calls: u64,
    pub file_read_bytes: u64,
    pub file_setlen_ns: u128,
    pub file_setlen_calls: u64,
    pub file_sync_ns: u128,
    pub file_sync_calls: u64,
    pub file_len_ns: u128,
    pub file_len_calls: u64,
}

/// Test only: while true, every `logical_len()` checks the stored "header area exists" flag against the file's real length.
/// The write-cost probe switches it off for its own thread so the check does not add to the time it measures.
#[cfg(test)]
thread_local! {
    pub(crate) static CHECK_LEN: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

#[cfg(test)]
thread_local! {
    pub(crate) static COST: RefCell<Option<Cost>> = const { RefCell::new(None) };
}


/// Test only: counters collected from every thread at once, per file ("main", "bak", "index", "other") and per
/// "this is the thread that called" (the commit's own thread) against all others (the index worker).
#[cfg(test)]
pub(crate) mod global {
    use super::Cost;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    pub(crate) static ON: AtomicBool = AtomicBool::new(false);
    pub(crate) static CALLER: Mutex<Option<std::thread::ThreadId>> = Mutex::new(None);
    pub(crate) static TOTALS: Mutex<Option<HashMap<(&'static str, bool), Cost>>> = Mutex::new(None);
}

#[cfg(test)]
thread_local! {
    /// The file the backend call running on this thread belongs to.
    pub(crate) static TAG: std::cell::Cell<&'static str> = const { std::cell::Cell::new("?") };
    /// Set just before a backend is built, read once by `with_mode`.
    pub(crate) static NEXT_TAG: std::cell::Cell<&'static str> = const { std::cell::Cell::new("?") };
}

#[cfg(test)]
pub(crate) fn set_next_tag(label: &str) {
    let tag = match label {
        "main" => "main",
        "bak" => "bak",
        "index" => "index",
        _ => "other",
    };
    NEXT_TAG.with(|t| t.set(tag));
}

/// Test only: marks the backend call running on this thread as belonging to one file, and puts the old mark back.
#[cfg(test)]
pub(crate) struct TagGuard(&'static str);

#[cfg(test)]
impl TagGuard {
    pub(crate) fn set(tag: &'static str) -> Self {
        TagGuard(TAG.with(|t| t.replace(tag)))
    }
}

#[cfg(test)]
impl Drop for TagGuard {
    fn drop(&mut self) {
        TAG.with(|t| t.set(self.0));
    }
}

#[cfg(test)]
pub(crate) fn cost_on() -> bool {
    global::ON.load(Relaxed) || COST.with(|c| c.borrow().is_some())
}

#[cfg(test)]
pub(crate) fn cost_add(f: impl FnOnce(&mut Cost)) {
    if global::ON.load(Relaxed) {
        let on_caller = *global::CALLER.lock().unwrap() == Some(std::thread::current().id());
        let tag = TAG.with(|t| t.get());
        let mut totals = global::TOTALS.lock().unwrap();
        f(totals.get_or_insert_with(Default::default).entry((tag, on_caller)).or_default());
        return;
    }
    COST.with(|c| {
        if let Some(c) = c.borrow_mut().as_mut() {
            f(c)
        }
    });
}

/// Test only: times the rest of the scope it lives in and adds the nanoseconds to the counters when dropped.
#[cfg(test)]
pub(crate) struct Span<F: FnOnce(&mut Cost, u128)>(Option<(std::time::Instant, F)>);

#[cfg(test)]
impl<F: FnOnce(&mut Cost, u128)> Span<F> {
    pub(crate) fn new(add: F) -> Self {
        Span(cost_on().then(|| (std::time::Instant::now(), add)))
    }
}

#[cfg(test)]
impl<F: FnOnce(&mut Cost, u128)> Drop for Span<F> {
    fn drop(&mut self) {
        if let Some((started, add)) = self.0.take() {
            let ns = started.elapsed().as_nanos();
            cost_add(|c| add(c, ns));
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Test only: the block numbers read on this thread while a probe has switched the log on.
    pub(crate) static READ_LOG: RefCell<Option<std::collections::BTreeSet<u64>>> = const { RefCell::new(None) };
}

fn block_aad(index: u64) -> [u8; 9] {
    let mut a = [0u8; 9];
    a[0] = b'b';
    a[1..].copy_from_slice(&index.to_le_bytes());
    a
}

fn piece_aad(piece: usize) -> [u8; 2] {
    [b'h', piece as u8]
}

struct Header {
    /// redb's 320 header bytes as the layer last saw them.
    bytes: [u8; REDB_HEADER_LEN],
    seq: u64,
    newest_copy: usize,
}

pub struct BlockBackend<B: StorageBackend> {
    inner: B,
    aead: Aead,
    geo: Geometry,
    /// redb's data length beyond its header page, in bytes.
    data_len: AtomicU64,
    /// The file is long enough to hold the header area (physical length >= `DATA_BASE`). Only this backend's constructor and
    /// `set_len` change the file's length (redb holds the file exclusively), so this stays true to the file and a read or a
    /// write need not ask the file for its size.
    header_area: AtomicBool,
    header: Mutex<Header>,
    /// Inspection only: redb's own header update at open stays in memory, every other write is
    /// refused, and the file is left byte for byte as it was.
    read_only: bool,
    tuning: EncryptionTuning,
    /// Processor threads available, read once.
    cores: usize,
    /// Pages written by redb and not yet sealed and written (idea B), by block number. They are newer than the file.
    pending: Mutex<BTreeMap<u64, Arc<[u8]>>>,
    #[cfg(test)]
    tag: &'static str,
    #[cfg(test)]
    pub(crate) stats: Stats,
}

impl<B: StorageBackend> fmt::Debug for BlockBackend<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlockBackend")
    }
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

impl<B: StorageBackend> BlockBackend<B> {
    /// Wrap `inner`, whose first 2048 bytes are the file header (not read here).
    pub fn new(inner: B, aead: Aead) -> io::Result<Self> {
        Self::with_mode(inner, aead, false)
    }

    pub fn with_mode(inner: B, aead: Aead, read_only: bool) -> io::Result<Self> {
        Self::with_tuning(inner, aead, read_only, EncryptionTuning::DEFAULT)
    }

    pub fn with_tuning(inner: B, aead: Aead, read_only: bool, tuning: EncryptionTuning) -> io::Result<Self> {
        let geo = Geometry { overhead: aead.kind().overhead() };
        let this = BlockBackend {
            inner,
            aead,
            geo,
            data_len: AtomicU64::new(0),
            header_area: AtomicBool::new(false),
            header: Mutex::new(Header { bytes: [0; REDB_HEADER_LEN], seq: 0, newest_copy: 0 }),
            read_only,
            tuning,
            cores: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            pending: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            tag: NEXT_TAG.with(|t| t.get()),
            #[cfg(test)]
            stats: Stats::default(),
        };
        let physical = this.inner.len()?;
        this.header_area.store(physical >= DATA_BASE, Relaxed);
        this.data_len
            .store(this.geo.logical_len(physical).saturating_sub(LOGICAL_HEADER), Relaxed);
        if physical >= DATA_BASE {
            this.load_header()?;
        }
        Ok(this)
    }

    // The four calls below go to the file below; in a test build they are counted, otherwise they are the plain call.
    #[inline]
    fn timed_write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        let _s = {
            let n = data.len() as u64;
            Span::new(move |c: &mut Cost, ns: u128| {
                c.file_write_ns += ns;
                c.file_write_calls += 1;
                c.file_write_bytes += n;
                if n < PAGE as u64 {
                    c.file_small_writes += 1;
                }
            })
        };
        self.inner.write(offset, data)
    }

    #[inline]
    fn timed_read(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        #[cfg(test)]
        let _s = {
            let n = buf.len() as u64;
            Span::new(move |c: &mut Cost, ns: u128| {
                c.file_read_ns += ns;
                c.file_read_calls += 1;
                c.file_read_bytes += n;
            })
        };
        self.inner.read(offset, buf)
    }

    #[inline]
    fn timed_set_len(&self, len: u64) -> io::Result<()> {
        #[cfg(test)]
        let _s = Span::new(|c: &mut Cost, ns: u128| {
            c.file_setlen_ns += ns;
            c.file_setlen_calls += 1;
        });
        self.inner.set_len(len)
    }

    #[inline]
    fn timed_len(&self) -> io::Result<u64> {
        #[cfg(test)]
        let _s = Span::new(|c: &mut Cost, ns: u128| {
            c.file_len_ns += ns;
            c.file_len_calls += 1;
        });
        self.inner.len()
    }

    #[inline]
    fn timed_sync(&self) -> io::Result<()> {
        #[cfg(test)]
        let _s = Span::new(|c: &mut Cost, ns: u128| {
            c.file_sync_ns += ns;
            c.file_sync_calls += 1;
        });
        self.inner.sync_data()
    }

    /// redb's length as the file stands now.
    pub fn logical_len(&self) -> io::Result<u64> {
        #[cfg(test)]
        if CHECK_LEN.with(|c| c.get()) && !global::ON.load(Relaxed) {
            let real = self.inner.len()? >= DATA_BASE;
            assert_eq!(self.header_area.load(Relaxed), real, "the stored header-area flag differs from the file's real length");
        }
        if !self.header_area.load(Relaxed) {
            return Ok(0);
        }
        Ok(LOGICAL_HEADER + self.data_len.load(Relaxed))
    }

    // ---- header pieces ------------------------------------------------------------------

    fn piece_offset(copy: usize) -> u64 {
        FILE_HEADER_LEN + (copy * PIECE_LEN) as u64
    }

    fn piece_plain(h: &Header, piece: usize, plain_len: usize) -> Vec<u8> {
        let mut v = match piece {
            0 => {
                let mut v = h.seq.to_le_bytes().to_vec();
                v.extend_from_slice(&h.bytes[0..64]);
                v
            }
            1 => h.bytes[64..192].to_vec(),
            _ => h.bytes[192..320].to_vec(),
        };
        v.resize(plain_len, 0);
        v
    }

    fn write_piece(&self, copy: usize, piece: usize, h: &Header) -> io::Result<()> {
        let plain = Self::piece_plain(h, piece, PIECE_LEN - self.geo.overhead);
        let mut sealed = vec![0u8; PIECE_LEN];
        {
            #[cfg(test)]
            let _s = Span::new(|c: &mut Cost, ns: u128| {
                c.header_seal_ns += ns;
                c.header_writes += 1;
            });
            self.aead
                .seal_into(&piece_aad(piece), &plain, &mut sealed)
                .map_err(|_| bad("sealing a header piece failed"))?;
        }
        self.timed_write(Self::piece_offset(copy), &sealed)
    }

    /// `None`: never written. An error: written but failed authentication.
    fn read_piece(&self, copy: usize, piece: usize) -> io::Result<Option<Vec<u8>>> {
        let mut raw = vec![0u8; PIECE_LEN];
        self.inner.read(Self::piece_offset(copy), &mut raw)?;
        if raw.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        match self.aead.open_in_place(&piece_aad(piece), &mut raw) {
            Ok(range) => Ok(Some(raw[range].to_vec())),
            Err(_) => Err(tamper_io(None)),
        }
    }

    /// A piece that fails authentication reads as zeros: redb then sees an invalid commit slot
    /// (or a missing header, which fails the open) and uses the other slot. That is what makes a
    /// torn header write harmless. Real damage to the live slot fails the open or the data read.
    fn load_header(&self) -> io::Result<()> {
        let mut h = self.header.lock().unwrap();
        let mut best: Option<(u64, usize, Vec<u8>)> = None;
        for copy in 0..2 {
            if let Ok(Some(p)) = self.read_piece(copy, 0) {
                let seq = u64::from_le_bytes(p[..8].try_into().unwrap());
                if best.as_ref().is_none_or(|b| seq > b.0) {
                    best = Some((seq, copy, p[8..72].to_vec()));
                }
            }
        }
        if let Some((seq, copy, p)) = best {
            h.seq = seq;
            h.newest_copy = copy;
            h.bytes[0..64].copy_from_slice(&p);
        }
        for (copy, piece, range) in [(2usize, 1usize, 64..192usize), (3, 2, 192..320)] {
            if let Ok(Some(p)) = self.read_piece(copy, piece) {
                h.bytes[range].copy_from_slice(&p[..128]);
            }
        }
        Ok(())
    }

    fn write_header_range(&self, offset: usize, data: &[u8]) -> io::Result<()> {
        let mut h = self.header.lock().unwrap();
        let n = data.len().min(REDB_HEADER_LEN.saturating_sub(offset));
        if data[n..].iter().any(|b| *b != 0) {
            return Err(bad("write into the unused part of redb's header page"));
        }
        let before = h.bytes;
        if n > 0 {
            h.bytes[offset..offset + n].copy_from_slice(&data[..n]);
        }
        if self.read_only {
            return Ok(());
        }
        // commit slots first, the piece holding redb's primary-slot byte last
        if before[64..192] != h.bytes[64..192] {
            self.write_piece(2, 1, &h)?;
        }
        if before[192..320] != h.bytes[192..320] {
            self.write_piece(3, 2, &h)?;
        }
        if before[0..64] != h.bytes[0..64] {
            h.seq += 1;
            let copy = h.newest_copy ^ 1;
            self.write_piece(copy, 0, &h)?;
            h.newest_copy = copy;
        }
        Ok(())
    }

    fn refuse_if_read_only(&self) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "opened for reading only"));
        }
        Ok(())
    }

    /// Four random-looking pieces to start with, so no part of the header area is blank.
    fn init_pieces(&self) -> io::Result<()> {
        let mut noise = vec![0u8; super::layout::PIECES_LEN as usize];
        random_bytes(&mut noise).map_err(|_| bad("no random source"))?;
        self.timed_write(FILE_HEADER_LEN, &noise)?;
        *self.header.lock().unwrap() = Header { bytes: [0; REDB_HEADER_LEN], seq: 0, newest_copy: 0 };
        Ok(())
    }

    // ---- blocks -------------------------------------------------------------------------

    /// Seal `count` blocks starting at `first` from `plain` (count * 4096 bytes) and write them
    /// with one file call.
    fn write_blocks(&self, first: u64, plain: &[u8], fill: bool) -> io::Result<()> {
        self.refuse_if_read_only()?;
        let stride = self.geo.stride();
        let count = plain.len() / PAGE;
        let _ = fill;
        if !fill {
            // control for the crash tests: the same kind of moment when the pages are written one at a time (parallel seal off)
            crash_point("enc_write_page");
        }
        with_scratch(count * stride, |buf| {
            {
                #[cfg(test)]
                let _s = Span::new(move |c: &mut Cost, ns: u128| {
                    if fill {
                        c.fill_seal_ns += ns;
                        c.fill_blocks += count as u64;
                    } else {
                        c.seal_ns += ns;
                        c.seal_blocks += count as u64;
                    }
                });
                for i in 0..count {
                    self.aead
                        .seal_into(
                            &block_aad(first + i as u64),
                            &plain[i * PAGE..(i + 1) * PAGE],
                            &mut buf[i * stride..(i + 1) * stride],
                        )
                        .map_err(|_| bad("sealing a block failed"))?;
                }
            }
            self.timed_write(self.geo.block_offset(first), buf)
        })
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    // ---- staged pages (idea B) ---------------------------------------------------------------------------

    /// Threads one step may use: the setting, never more than the processor offers.
    fn threads(&self) -> usize {
        self.tuning.threads.max(1).min(self.cores)
    }

    /// Threads worth starting for `pages` pages: one (the calling thread) below `SEAL_MIN_PAGES`, otherwise at most one per
    /// `PAGES_PER_THREAD` pages.
    fn workers_for(&self, pages: usize) -> usize {
        if pages < SEAL_MIN_PAGES { 1 } else { self.threads().min(pages / PAGES_PER_THREAD).max(1) }
    }

    /// Keep whole pages in memory until the next sync (or until `PENDING_CAP_PAGES` are held, when they are written at once).
    fn stage_pages(&self, first: u64, plain: &[u8]) -> io::Result<()> {
        self.refuse_if_read_only()?;
        let count = plain.len() / PAGE;
        let full = {
            let mut pending = self.pending.lock().unwrap();
            for i in 0..count {
                pending.insert(first + i as u64, Arc::from(&plain[i * PAGE..(i + 1) * PAGE]));
            }
            #[cfg(test)]
            self.stats.peak_pending.fetch_max(pending.len() as u64, Relaxed);
            pending.len() >= PENDING_CAP_PAGES
        };
        if full {
            self.drain()?;
        }
        Ok(())
    }

    /// Seal `batch` into `sealed` on `workers` threads (the calling thread is one of them).
    fn seal_all(&self, batch: &[(u64, Arc<[u8]>)], sealed: &mut [u8], stride: usize, workers: usize) -> io::Result<()> {
        if workers <= 1 {
            return seal_chunk(&self.aead, batch, sealed, stride);
        }
        let per = batch.len().div_ceil(workers);
        let aead = &self.aead;
        let mut jobs: Vec<(&[(u64, Arc<[u8]>)], &mut [u8])> = batch.chunks(per).zip(sealed.chunks_mut(per * stride)).collect();
        let mine = jobs.pop();
        std::thread::scope(|s| {
            let handles: Vec<_> = jobs.into_iter().map(|(p, o)| s.spawn(move || seal_chunk(aead, p, o, stride))).collect();
            let mut result = match mine {
                Some((p, o)) => seal_chunk(aead, p, o, stride),
                None => Ok(()),
            };
            for h in handles {
                let r = h.join().unwrap_or_else(|_| Err(bad("a sealing thread failed")));
                if result.is_ok() {
                    result = r;
                }
            }
            result
        })
    }

    /// Seal every staged page (in parallel when there are enough) and write them in order of block number. The pages stay readable
    /// from memory until they are in the file, and a page redb wrote again meanwhile is kept for the next drain.
    fn drain(&self) -> io::Result<()> {
        let batch: Vec<(u64, Arc<[u8]>)> = {
            let pending = self.pending.lock().unwrap();
            if pending.is_empty() {
                return Ok(());
            }
            pending.iter().map(|(k, v)| (*k, v.clone())).collect()
        };
        crash_point("enc_drain_before_seal");
        let stride = self.geo.stride();
        let workers = self.workers_for(batch.len());
        #[cfg(test)]
        {
            self.stats.drains.fetch_add(1, Relaxed);
            self.stats.drain_pages.fetch_add(batch.len() as u64, Relaxed);
            if workers > 1 {
                self.stats.parallel_drains.fetch_add(1, Relaxed);
            }
        }
        with_scratch(batch.len() * stride, |sealed| -> io::Result<()> {
            {
                #[cfg(test)]
                let _s = {
                    let n = batch.len() as u64;
                    Span::new(move |c: &mut Cost, ns: u128| {
                        c.seal_ns += ns;
                        c.seal_blocks += n;
                    })
                };
                self.seal_all(&batch, sealed, stride, workers)?;
            }
            crash_point("enc_drain_after_seal");
            let half = batch.len() / 2;
            let (mut written, mut crashed, mut i) = (0usize, false, 0usize);
            while i < batch.len() {
                let mut j = i + 1;
                while j < batch.len() && j - i < WRITE_CHUNK && batch[j].0 == batch[j - 1].0 + 1 {
                    j += 1;
                }
                self.timed_write(self.geo.block_offset(batch[i].0), &sealed[i * stride..j * stride])?;
                written += j - i;
                if !crashed && written >= half {
                    crashed = true;
                    crash_point("enc_drain_mid_write");
                }
                i = j;
            }
            Ok(())
        })?;
        let mut pending = self.pending.lock().unwrap();
        for (index, page) in &batch {
            if pending.get(index).is_some_and(|now| Arc::ptr_eq(now, page)) {
                pending.remove(index);
            }
        }
        Ok(())
    }

    /// redb's region shape from its header bytes: (header pages, data pages) of one region. `Ok(None)` only while redb has not
    /// written its header page at all; a header that is there but is not what `region_shape_of` knows is an error.
    fn region_shape(&self) -> io::Result<Option<(u64, u64)>> {
        let h = self.header.lock().unwrap();
        if h.bytes.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        region_shape_of(&h.bytes)
            .map(Some)
            .ok_or_else(|| bad("the header page of the database file is not in the form this version knows, so the file was not grown"))
    }

    /// Grow the file by writing sealed zero blocks, in batches. The file is extended by the writes themselves, so at every moment
    /// every block in it is sealed (at most a partial last block, which the length ignores) and a page redb never wrote still reads
    /// as authentic zeros. redb accepts only a file length that makes a whole region layout, so a batch never ends where the length
    /// would not (the few pages after a region boundary): the end moves on to the next valid length.
    fn fill(&self, first: u64, end: u64) -> io::Result<()> {
        static ZEROS: [u8; PAGE * FILL_BATCH] = [0; PAGE * FILL_BATCH];
        let shape = self.region_shape()?;
        if shape.is_none() && first > 0 {
            // An empty header is only the creation of a new file (its name is temporary, and a stop leaves it unused). A file that
            // already holds data is never grown without the layout rule: a length redb refuses would leave it unopenable.
            return Err(bad("the header page of the database file cannot be read, so the file was not grown"));
        }
        let valid = |pages: u64| length_makes_layout(pages, shape);

        let mut at = first;
        while at < end {
            let mut stop = (at + FILL_BATCH as u64).min(end);
            while stop < end && !valid(stop) {
                stop += 1;
            }
            let n = (stop - at) as usize;
            if n <= FILL_BATCH {
                self.write_blocks(at, &ZEROS[..n * PAGE], true)?;
            } else {
                self.write_blocks(at, &vec![0u8; n * PAGE], true)?;
            }
            at = stop;
            if at < end {
                // control for the crash tests: the new space is only partly filled
                crash_point("enc_fill_mid");
            }
        }
        Ok(())
    }
}

/// The region shape redb recorded in its header page: (region header pages, region data pages), read from redb's on-disk format
/// (redb 4.4, file format 3): the page size is the little-endian u32 at byte 12, the region header pages at 16 and the most data pages
/// of one region at 20. `None` for a header that does not fit (page size other than ours, or no data pages). redb 4.4 writes 0 region header pages, so every page-multiple length is valid for it. The test
/// `the_region_shape_and_the_accepted_lengths_are_what_redb_says` checks these offsets and `length_makes_layout` against a real redb
/// file, so a redb release that changes them fails that test.
fn region_shape_of(header: &[u8]) -> Option<(u64, u64)> {
    let word = |at: usize| header.get(at..at + 4).map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])));
    let (page, header_pages, data_pages) = (word(12)?, word(16)?, word(20)?);
    (page == PAGE as u64 && data_pages > 0).then_some((header_pages, data_pages))
}
/// Whether a file of `pages` data pages (after redb's header page) is a length redb opens: a whole number of regions, or whole
/// regions and a last one that holds its header pages and at least one data page. Unknown shape: any length.
fn length_makes_layout(pages: u64, shape: Option<(u64, u64)>) -> bool {
    match shape {
        Some((header_pages, data_pages)) => {
            let rest = pages % (header_pages + data_pages);
            rest == 0 || rest > header_pages
        }
        None => true,
    }
}

#[cfg(test)]
mod layout_length_tests {
    use super::{PAGE, length_makes_layout, region_shape_of};

    #[test]
    fn a_length_just_after_a_region_boundary_is_not_a_layout() {
        let shape = Some((130, 1_048_446));
        let region = 130 + 1_048_446;
        assert!(length_makes_layout(1000, shape));
        assert!(length_makes_layout(region, shape));
        assert!(length_makes_layout(region * 2, shape));
        for rest in 1..=130 {
            assert!(!length_makes_layout(region + rest, shape), "{rest}");
        }
        assert!(length_makes_layout(region + 131, shape));
        assert!(length_makes_layout(region + 1, None));
    }
    /// The offsets `region_shape_of` reads and the rule `length_makes_layout` applies, against a real redb file: the shape in the
    /// header is one whole region (redb's default 8 GiB class), and redb itself opens, after an unclean stop, exactly the lengths the
    /// rule calls valid around the first region boundary and refuses the others as corrupted. A redb release that moves the
    /// offsets or changes the rule fails here.
    #[test]
    fn the_region_shape_and_the_accepted_lengths_are_what_redb_says() {
        use std::io::{Read, Seek, SeekFrom, Write};
        let dir = std::env::temp_dir().join(format!("clove-redb-shape-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let original = dir.join("original.redb");
        {
            let db = redb::Database::create(&original).unwrap();
            let tx = db.begin_write().unwrap();
            {
                let mut table = tx.open_table(redb::TableDefinition::<u64, &[u8]>::new("t")).unwrap();
                for i in 0..200u64 {
                    table.insert(i, [7u8; 1000].as_slice()).unwrap();
                }
            }
            tx.commit().unwrap();
        }
        let bytes = std::fs::read(&original).unwrap();
        let (header_pages, data_pages) = region_shape_of(&bytes).unwrap_or_else(|| panic!("redb header no longer has the region shape where it was: {:?}", &bytes[..32]));
        let region = header_pages + data_pages;
        assert!(region.is_power_of_two() && region * PAGE as u64 >= 1 << 30, "a region is {region} pages: not the shape the rule was made for");
        assert!(header_pages < 4096, "{header_pages}");
        let original_pages = bytes.len() as u64 / PAGE as u64 - 1;
        assert!(original_pages > header_pages && original_pages < region);
        println!("region shape from redb: {header_pages} header pages, {data_pages} data pages");

        let probe = |pages: u64, extra: u64| -> Result<(), String> {
            let copy = dir.join(format!("probe-{pages}.redb"));
            std::fs::copy(&original, &copy).unwrap();
            let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&copy).unwrap();
            // sparse, so a file of several GiB takes no disk
            #[cfg(windows)]
            {
                let status = std::process::Command::new("fsutil").args(["sparse", "setflag"]).arg(&copy).status().unwrap();
                assert!(status.success(), "fsutil sparse setflag failed");
            }
            file.set_len((pages + 1) * PAGE as u64 + extra).unwrap();
            // as after an unclean stop: the "recovery required" bit of redb's flag byte
            let mut flag = [0u8];
            file.seek(SeekFrom::Start(9)).unwrap();
            file.read_exact(&mut flag).unwrap();
            file.seek(SeekFrom::Start(9)).unwrap();
            file.write_all(&[flag[0] | 2]).unwrap();
            file.sync_all().unwrap();
            drop(file);
            let result = redb::Database::open(&copy).map(drop).map_err(|e| format!("{e}"));
            let _ = std::fs::remove_file(&copy);
            result
        };

        let shape = Some((header_pages, data_pages));
        // lengths in the first region: valid from `header_pages + 1` pages on (the original is such a length)
        let mut lengths = vec![original_pages + 1, original_pages + 100, region - 1, region, region + 1, region + header_pages, region + header_pages + 1, region + header_pages + 2];
        lengths.sort_unstable();
        lengths.dedup();
        for pages in lengths {
            let said = length_makes_layout(pages, shape);
            let got = probe(pages, 0);
            assert_eq!(said, got.is_ok(), "{pages} pages ({} past a region): the rule says {said}, redb says {got:?}", pages as i64 - region as i64);
            if let Err(text) = &got {
                assert!(text.to_lowercase().contains("corrupt") || text.contains("region layout"), "refused for another reason: {text}");
            }
        }
        // the probe does reach redb's length check: a length that is not a whole number of pages is refused
        let refused = probe(region + 1, 100).expect_err("redb opened a file whose length is not a whole number of pages");
        assert!(refused.to_lowercase().contains("corrupt") || refused.contains("region layout"), "{refused}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
impl<B: StorageBackend> StorageBackend for BlockBackend<B> {
    fn len(&self) -> Result<u64, io::Error> {
        self.logical_len()
    }

    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        #[cfg(test)]
        let _tag = TagGuard::set(self.tag);
        #[cfg(test)]
        let _layer = Span::new(|c: &mut Cost, ns: u128| {
            c.layer_setlen_ns += ns;
            c.setlen_calls += 1;
        });
        if self.read_only && self.geo.physical_len(len) != Some(self.inner.len()?) {
            return self.refuse_if_read_only();
        }
        if self.read_only {
            return Ok(());
        }
        let physical = self.geo.physical_len(len).ok_or_else(|| bad("length is not a whole number of pages"))?;
        // staged pages are written before the file changes length
        self.drain()?;
        if len == 0 {
            self.data_len.store(0, Relaxed);
            let result = self.timed_set_len(physical);
            self.header_area.store(physical >= DATA_BASE, Relaxed);
            return result;
        }
        let new_data = len - LOGICAL_HEADER;
        let old_data = self.data_len.load(Relaxed);
        if self.timed_len()? < DATA_BASE {
            self.timed_set_len(DATA_BASE)?;
            self.header_area.store(true, Relaxed);
            self.init_pieces()?;
        }
        if new_data > old_data {
            self.fill(old_data / PAGE as u64, new_data / PAGE as u64)?;
            if self.timed_len()? > physical {
                self.timed_set_len(physical)?;
            }
        } else if new_data < old_data {
            self.timed_set_len(physical)?;
        }
        self.data_len.store(new_data, Relaxed);
        Ok(())
    }

    fn sync_data(&self) -> Result<(), io::Error> {
        #[cfg(test)]
        let _tag = TagGuard::set(self.tag);
        #[cfg(test)]
        let _layer = Span::new(|c: &mut Cost, ns: u128| {
            c.layer_sync_ns += ns;
            c.sync_calls += 1;
        });
        // The sync is reported as done only after every staged page is sealed and written, and the file itself is synced.
        self.drain()?;
        crash_point("enc_drain_before_sync");
        self.timed_sync()?;
        crash_point("enc_drain_after_sync");
        #[cfg(test)]
        assert!(self.pending.lock().unwrap().is_empty(), "a sync returned Ok with pages still staged");
        Ok(())
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), io::Error> {
        #[cfg(test)]
        let _tag = TagGuard::set(self.tag);
        #[cfg(test)]
        let _layer = {
            let n = out.len() as u64;
            Span::new(move |c: &mut Cost, ns: u128| {
                c.layer_read_ns += ns;
                c.read_calls += 1;
                c.read_bytes += n;
                if offset % PAGE as u64 != 0 || n % PAGE as u64 != 0 {
                    c.partial_reads += 1;
                }
            })
        };
        if out.is_empty() {
            return Ok(());
        }
        if offset + out.len() as u64 > self.logical_len()? {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end"));
        }
        let (mut pos, mut done) = (offset, 0usize);
        if pos < LOGICAL_HEADER {
            let h = self.header.lock().unwrap();
            let n = ((LOGICAL_HEADER - pos) as usize).min(out.len());
            for (i, byte) in out[..n].iter_mut().enumerate() {
                let p = pos as usize + i;
                *byte = if p < REDB_HEADER_LEN { h.bytes[p] } else { 0 };
            }
            pos += n as u64;
            done += n;
        }
        if done == out.len() {
            return Ok(());
        }
        let stride = self.geo.stride();
        let rel = pos - LOGICAL_HEADER;
        let first = rel / PAGE as u64;
        let last = (rel + (out.len() - done) as u64 - 1) / PAGE as u64;
        let count = (last - first + 1) as usize;
        let mut within = (rel % PAGE as u64) as usize;
        // a page redb wrote that is not in the file yet is newer than the file: answer from memory, no decrypting
        if self.tuning.parallel_seal {
            enum Staged {
                No,
                Page(Arc<[u8]>),
                Drain,
            }
            let staged = {
                let pending = self.pending.lock().unwrap();
                if pending.is_empty() {
                    Staged::No
                } else if count == 1 {
                    pending.get(&first).cloned().map_or(Staged::No, Staged::Page)
                } else if (first..first + count as u64).any(|b| pending.contains_key(&b)) {
                    Staged::Drain
                } else {
                    Staged::No
                }
            };
            match staged {
                Staged::Page(page) => {
                    let n = (PAGE - within).min(out.len() - done);
                    out[done..done + n].copy_from_slice(&page[within..within + n]);
                    #[cfg(test)]
                    self.stats.served_pending.fetch_add(1, Relaxed);
                    return Ok(());
                }
                Staged::Drain => self.drain()?,
                Staged::No => {}
            }
        }
        with_scratch(count * stride, |buf| {
            self.timed_read(self.geo.block_offset(first), buf)?;
            for i in 0..count {
                let index = first + i as u64;
                #[cfg(test)]
                READ_LOG.with(|log| {
                    if let Some(set) = log.borrow_mut().as_mut() {
                        set.insert(index);
                    }
                });
                let block = &mut buf[i * stride..(i + 1) * stride];
                let range = {
                    #[cfg(test)]
                    let _s = Span::new(|c: &mut Cost, ns: u128| {
                        c.open_ns += ns;
                        c.open_blocks += 1;
                    });
                    self.aead.open_in_place(&block_aad(index), block).map_err(|_| tamper_io(Some(index)))?
                };
                let plain = &block[range];
                let n = (PAGE - within).min(out.len() - done);
                {
                    #[cfg(test)]
                    let _s = Span::new(|c: &mut Cost, ns: u128| c.copy_ns += ns);
                    out[done..done + n].copy_from_slice(&plain[within..within + n]);
                }
                done += n;
                within = 0;
            }
            Ok(())
        })
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        #[cfg(test)]
        let _tag = TagGuard::set(self.tag);
        #[cfg(test)]
        let _layer = {
            let n = data.len() as u64;
            Span::new(move |c: &mut Cost, ns: u128| {
                c.layer_write_ns += ns;
                c.write_calls += 1;
                c.write_bytes += n;
                if offset % PAGE as u64 != 0 || n % PAGE as u64 != 0 {
                    c.partial_writes += 1;
                }
            })
        };
        if data.is_empty() {
            return Ok(());
        }
        if offset + data.len() as u64 > self.logical_len()? {
            return Err(bad("write past the end"));
        }
        let (mut pos, mut done) = (offset, 0usize);
        if pos < LOGICAL_HEADER {
            let n = ((LOGICAL_HEADER - pos) as usize).min(data.len());
            // the header must not reach the file before the pages it makes live
            self.drain()?;
            self.write_header_range(pos as usize, &data[..n])?;
            pos += n as u64;
            done += n;
        }
        if done == data.len() {
            return Ok(());
        }
        let rel = pos - LOGICAL_HEADER;
        if rel % PAGE as u64 != 0 || (data.len() - done) % PAGE != 0 {
            return Err(bad("write is not aligned to whole pages"));
        }
        let first = rel / PAGE as u64;
        if self.tuning.parallel_seal {
            self.stage_pages(first, &data[done..])
        } else {
            self.write_blocks(first, &data[done..], false)
        }
    }

    fn close(&self) -> Result<(), io::Error> {
        let drained = self.drain();
        let closed = self.inner.close();
        drained.and(closed)
    }

    fn try_lock_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<bool, BackendError> {
        self.inner.try_lock_range(s, e)
    }
    fn try_lock_shared_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<bool, BackendError> {
        self.inner.try_lock_shared_range(s, e)
    }
    fn lock_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<(), BackendError> {
        self.inner.lock_range(s, e)
    }
    fn lock_shared_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<(), BackendError> {
        self.inner.lock_shared_range(s, e)
    }
    fn unlock_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<(), BackendError> {
        self.inner.unlock_range(s, e)
    }
    fn query_lock_range(&self, s: Bound<u64>, e: Bound<u64>) -> Result<bool, BackendError> {
        self.inner.query_lock_range(s, e)
    }
}
