//! The file layer on its own, without redb: pages staged for a parallel seal (idea B).
use super::backend::BlockBackend;
use super::error::is_tamper;
use super::layout::{DATA_BASE, LOGICAL_HEADER, PAGE};
use super::tuning::EncryptionTuning;
use crate::crypto::{Aead, CipherKind, Key32};
use redb::StorageBackend;
use redb::backends::FileBackend;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;

type Layer = BlockBackend<FileBackend>;

fn folder() -> PathBuf {
    let d = std::env::temp_dir().join(format!("clove-layer-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn open(path: &Path, kind: CipherKind, tuning: EncryptionTuning) -> Layer {
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).unwrap();
    let aead = Aead::new(kind, &Key32::from_bytes(&[5; 32])).unwrap();
    BlockBackend::with_tuning(FileBackend::new(file).unwrap(), aead, false, tuning).unwrap()
}

fn page(i: u64, salt: u8) -> Vec<u8> {
    (0..PAGE).map(|k| ((k as u64).wrapping_mul(7).wrapping_add(i.wrapping_mul(13)) as u8) ^ salt).collect()
}

fn at(i: u64) -> u64 {
    LOGICAL_HEADER + i * PAGE as u64
}

fn grow(b: &Layer, pages: u64) {
    b.set_len(LOGICAL_HEADER + pages * PAGE as u64).unwrap();
}

fn read_page(b: &Layer, i: u64) -> Vec<u8> {
    let mut v = vec![0u8; PAGE];
    b.read(at(i), &mut v).unwrap();
    v
}

fn staged(b: &Layer) -> usize {
    b.pending_len()
}

const KINDS: [CipherKind; 2] = [CipherKind::Aes256GcmSiv, CipherKind::XChaCha20Poly1305];

#[test]
fn staged_pages_are_read_back_before_the_sync_and_written_by_it() {
    for kind in KINDS {
        let path = folder().join("a.db");
        let b = open(&path, kind, EncryptionTuning::DEFAULT);
        grow(&b, 300);
        for i in 0..100 {
            b.write(at(i), &page(i, 1)).unwrap();
        }
        assert_eq!(staged(&b), 100, "{kind:?}: the pages are held, not written");
        assert_eq!(read_page(&b, 7), page(7, 1), "{kind:?}: a staged page is read back");
        assert!(b.stats.served_pending.load(Relaxed) >= 1, "{kind:?}: and served from memory");
        b.write(at(7), &page(7, 2)).unwrap();
        assert_eq!(read_page(&b, 7), page(7, 2), "{kind:?}: a page written again before the sync is the new one");
        b.sync_data().unwrap();
        assert_eq!(staged(&b), 0, "{kind:?}: the sync leaves nothing staged");
        assert_eq!(read_page(&b, 7), page(7, 2));
        drop(b);
        let again = open(&path, kind, EncryptionTuning::OFF);
        for i in 0..100 {
            assert_eq!(read_page(&again, i), if i == 7 { page(7, 2) } else { page(i, 1) }, "{kind:?}: page {i} survives a reopen");
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

#[test]
fn a_small_commit_is_sealed_on_the_calling_thread_and_a_large_one_in_parallel() {
    let path = folder().join("a.db");
    let b = open(&path, CipherKind::Aes256GcmSiv, EncryptionTuning::DEFAULT);
    grow(&b, 400);
    for i in 0..10 {
        b.write(at(i), &page(i, 3)).unwrap();
    }
    b.sync_data().unwrap();
    assert_eq!(b.stats.drains.load(Relaxed), 1);
    assert_eq!(b.stats.parallel_drains.load(Relaxed), 0, "10 pages are below the threshold");
    for i in 0..300 {
        b.write(at(i), &page(i, 4)).unwrap();
    }
    b.sync_data().unwrap();
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if cores > 1 {
        assert_eq!(b.stats.parallel_drains.load(Relaxed), 1, "300 pages are sealed on several threads");
    }
    drop(b);
    let one = open(&path, CipherKind::Aes256GcmSiv, EncryptionTuning { threads: 1, ..EncryptionTuning::DEFAULT });
    for i in 0..300 {
        assert_eq!(read_page(&one, i), page(i, 4));
    }
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn reaching_the_cap_writes_the_pages_without_waiting_for_a_sync() {
    let path = folder().join("a.db");
    let b = open(&path, CipherKind::XChaCha20Poly1305, EncryptionTuning::DEFAULT);
    grow(&b, 2500);
    for i in 0..2300 {
        b.write(at(i), &page(i, 5)).unwrap();
    }
    assert!(b.stats.drains.load(Relaxed) >= 2, "the cap made it write twice before any sync");
    assert!(b.stats.peak_pending.load(Relaxed) <= 1024, "never more than 4 MiB staged: {}", b.stats.peak_pending.load(Relaxed));
    assert!(staged(&b) < 1024);
    for i in [0u64, 1023, 1024, 2299] {
        assert_eq!(read_page(&b, i), page(i, 5));
    }
    b.sync_data().unwrap();
    assert_eq!(staged(&b), 0);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn a_header_write_a_cut_and_a_close_write_the_staged_pages_first() {
    let path = folder().join("a.db");
    let b = open(&path, CipherKind::Aes256GcmSiv, EncryptionTuning::DEFAULT);
    grow(&b, 50);
    for i in 0..20 {
        b.write(at(i), &page(i, 6)).unwrap();
    }
    assert_eq!(staged(&b), 20);
    b.write(0, &[0u8; 64]).unwrap(); // redb's header comes after its data pages
    assert_eq!(staged(&b), 0, "a header write drains first");
    for i in 20..30 {
        b.write(at(i), &page(i, 6)).unwrap();
    }
    b.set_len(LOGICAL_HEADER + 40 * PAGE as u64).unwrap();
    assert_eq!(staged(&b), 0, "a change of length drains first");
    for i in 30..35 {
        b.write(at(i), &page(i, 6)).unwrap();
    }
    b.close().unwrap();
    assert_eq!(staged(&b), 0, "a close drains");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn a_file_written_with_any_setting_opens_with_any_other() {
    let settings = [EncryptionTuning::DEFAULT, EncryptionTuning::OFF];
    for (w, written_with) in settings.iter().enumerate() {
        for (r, read_with) in settings.iter().enumerate() {
            let path = folder().join("a.db");
            let b = open(&path, CipherKind::Aes256GcmSiv, *written_with);
            grow(&b, 200);
            for i in 0..200 {
                b.write(at(i), &page(i, 7)).unwrap();
            }
            b.sync_data().unwrap();
            drop(b);
            let c = open(&path, CipherKind::Aes256GcmSiv, *read_with);
            for i in 0..200 {
                assert_eq!(read_page(&c, i), page(i, 7), "written with setting {w}, read with setting {r}");
            }
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
        }
    }
}

fn written(kind: CipherKind, pages: u64) -> (PathBuf, ()) {
    let path = folder().join("a.db");
    let b = open(&path, kind, EncryptionTuning::OFF);
    grow(&b, pages);
    for i in 0..pages {
        b.write(at(i), &page(i, 8)).unwrap();
    }
    b.sync_data().unwrap();
    (path, ())
}

#[test]
fn a_changed_block_is_reported_as_changed_when_it_is_read() {
    for kind in KINDS {
        let (path, _) = written(kind, 200);
        let stride = PAGE as u64 + kind.overhead() as u64;
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[(DATA_BASE + 120 * stride + 100) as usize] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        let b = open(&path, kind, EncryptionTuning::DEFAULT);
        for i in 0..120 {
            assert_eq!(read_page(&b, i), page(i, 8), "{kind:?}: page {i} before the change is fine");
        }
        let mut v = vec![0u8; PAGE];
        let err = b.read(at(120), &mut v).unwrap_err();
        assert!(is_tamper(&err), "{kind:?}: the changed block is reported as changed: {err}");
        for i in 121..200 {
            assert_eq!(read_page(&b, i), page(i, 8), "{kind:?}: the blocks after it are fine");
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

#[test]
fn the_scratch_limit_covers_the_largest_possible_drain_for_both_ciphers() {
    use super::backend::{MAX_STRIDE, PENDING_CAP_PAGES, SCRATCH_KEEP};
    for kind in [CipherKind::Aes256GcmSiv, CipherKind::XChaCha20Poly1305] {
        let stride = PAGE + kind.overhead();
        assert!(stride <= MAX_STRIDE, "{kind:?}: a block of {stride} bytes is larger than MAX_STRIDE");
        assert!(PENDING_CAP_PAGES * stride <= SCRATCH_KEEP, "{kind:?}: a full drain ({} bytes) would not fit the kept buffer ({SCRATCH_KEEP})", PENDING_CAP_PAGES * stride);
    }
    assert_eq!(SCRATCH_KEEP % (1 << 20), 0, "whole MiB");
    assert!(SCRATCH_KEEP < 2 * PENDING_CAP_PAGES * MAX_STRIDE, "not wastefully large");
}

// ---- growing the file needs redb's header ------------------------------------------------------------------

/// redb's 320 header bytes with the region shape in them: page size, region header pages, data pages of one region.
fn header_bytes(page: u32, header_pages: u32, data_pages: u32) -> Vec<u8> {
    let mut h = vec![0u8; 320];
    h[..9].copy_from_slice(&[b'r', b'e', b'd', b'b', 0x1A, 0x0A, 0xA9, 0x0D, 0x0A]);
    h[12..16].copy_from_slice(&page.to_le_bytes());
    h[16..20].copy_from_slice(&header_pages.to_le_bytes());
    h[20..24].copy_from_slice(&data_pages.to_le_bytes());
    h
}

fn physical_len(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

/// A new file (redb has written no header yet) is grown without the layout rule; the first growth is the creation.
#[test]
fn a_new_file_is_grown_before_redb_has_written_its_header() {
    for kind in KINDS {
        let path = folder().join("new.db");
        let b = open(&path, kind, EncryptionTuning::DEFAULT);
        grow(&b, 300);
        assert_eq!(b.len().unwrap(), LOGICAL_HEADER + 300 * PAGE as u64, "{kind:?}");
        for i in [0, 150, 299] {
            assert_eq!(read_page(&b, i), vec![0u8; PAGE], "{kind:?}: page {i} of the new space is authentic zeros");
        }
    }
}

/// A file that holds data and whose header page cannot be read is not grown: a clear error, nothing changed, the data still read.
#[test]
fn a_file_with_data_and_no_readable_header_is_not_grown() {
    for kind in KINDS {
        let path = folder().join("noheader.db");
        let b = open(&path, kind, EncryptionTuning::DEFAULT);
        grow(&b, 50);
        b.write(at(3), &page(3, 9)).unwrap();
        b.sync_data().unwrap();
        let before = physical_len(&path);
        let error = b.set_len(LOGICAL_HEADER + 100 * PAGE as u64).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{kind:?}");
        assert!(error.to_string().contains("cannot be read"), "{kind:?}: {error}");
        assert_eq!(physical_len(&path), before, "{kind:?}: the file was not changed");
        assert_eq!(b.len().unwrap(), LOGICAL_HEADER + 50 * PAGE as u64, "{kind:?}: and the length is the old one");
        assert_eq!(read_page(&b, 3), page(3, 9), "{kind:?}: the data is still read");
        drop(b);
        let again = open(&path, kind, EncryptionTuning::OFF);
        assert_eq!(read_page(&again, 3), page(3, 9), "{kind:?}: also after a reopen");
    }
}

/// A header that is there but is not in the form this version knows (another page size, no data pages) is refused the same way.
#[test]
fn a_header_in_another_form_does_not_let_the_file_grow() {
    for kind in KINDS {
        for (name, header) in [("page size", header_bytes(8192, 0, 1 << 20)), ("no data pages", header_bytes(4096, 0, 0))] {
            let path = folder().join("odd.db");
            let b = open(&path, kind, EncryptionTuning::DEFAULT);
            grow(&b, 50);
            b.write(0, &header).unwrap();
            b.write(at(3), &page(3, 4)).unwrap();
            b.sync_data().unwrap();
            let before = physical_len(&path);
            let error = b.set_len(LOGICAL_HEADER + 100 * PAGE as u64).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{kind:?} {name}");
            assert!(error.to_string().contains("not in the form this version knows"), "{kind:?} {name}: {error}");
            assert_eq!(physical_len(&path), before, "{kind:?} {name}: the file was not changed");
            assert_eq!(read_page(&b, 3), page(3, 4), "{kind:?} {name}: the data is still read");
        }
    }
}

/// With the header redb writes, the file grows again and again, and every block of it is sealed at every length.
#[test]
fn a_file_with_redbs_header_grows() {
    for kind in KINDS {
        let path = folder().join("grown.db");
        let b = open(&path, kind, EncryptionTuning::DEFAULT);
        grow(&b, 50);
        b.write(0, &header_bytes(4096, 0, 1 << 20)).unwrap();
        b.write(at(3), &page(3, 6)).unwrap();
        for pages in [400u64, 1000, 5000] {
            grow(&b, pages);
            assert_eq!(b.len().unwrap(), LOGICAL_HEADER + pages * PAGE as u64, "{kind:?}");
            assert_eq!(read_page(&b, pages - 1), vec![0u8; PAGE], "{kind:?}: the last page of the new space is authentic zeros");
        }
        assert_eq!(read_page(&b, 3), page(3, 6), "{kind:?}");
    }
}
