//! Sealed files: round trips of every awkward size, streaming, random access, and every way of
//! changing a file (all must fail, none may return other data).
mod encrypted_support;

use clove1db::crypto::{ProgrammerKey, KeySuite};
use clove1db::encrypted_store::{
    Credentials, EncryptedDatabase, EncryptionContext, OpenOptionsExt, SEALED_BLOCK, SealedReader, SealedWriter,
    is_tamper, read_sealed_file, write_sealed_file,
};
use encrypted_support::*;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

const BIND: &str = "logical-name";

fn context(dir: &TempDir, name: &str, suite: KeySuite) -> EncryptionContext {
    let (rk, sk) = (key(), key());
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let creds = Credentials { suite, read: Some(&r), search: Some(&s) };
    let opts = OpenOptionsExt { cache_bytes: Some(1 << 20), ..Default::default() };
    let db = EncryptedDatabase::create(&dir.path(name), &creds, "main", &opts).unwrap();
    db.context()
}

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + seed as usize) % 251) as u8).collect()
}

fn seal(ctx: &EncryptionContext, label: &str, bytes: &[u8], piece: usize) -> Vec<u8> {
    let mut w = SealedWriter::new(Vec::new(), ctx, label, BIND).unwrap();
    for chunk in bytes.chunks(piece.max(1)) {
        w.write_all(chunk).unwrap();
    }
    w.finish().unwrap()
}

fn open_all(ctx: &EncryptionContext, label: &str, file: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut r = SealedReader::new(Cursor::new(file.to_vec()), ctx, label, BIND)?;
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
}

const SIZES: [usize; 11] = [
    0,
    1,
    100,
    SEALED_BLOCK - 1,
    SEALED_BLOCK,
    SEALED_BLOCK + 1,
    2 * SEALED_BLOCK,
    3 * SEALED_BLOCK - 1,
    3 * SEALED_BLOCK,
    3 * SEALED_BLOCK + 17,
    700_000,
];

#[test]
fn every_size_round_trips_whatever_the_write_pieces_are() {
    for suite in suites() {
        let dir = TempDir::new("sealed");
        let ctx = context(&dir, "a.db", suite);
        for len in SIZES {
            let plain = data(len, 3);
            for piece in [1usize << 20, 4096, 7, SEALED_BLOCK] {
                let sealed = seal(&ctx, "blob", &plain, piece);
                let stride = SEALED_BLOCK + suite.cipher.overhead();
                let blocks = len.div_ceil(SEALED_BLOCK).max(1);
                assert_eq!(sealed.len(), 32 + len + blocks * suite.cipher.overhead(), "{len} {piece}");
                assert!(sealed.len() <= 32 + blocks * stride);
                assert_eq!(open_all(&ctx, "blob", &sealed).unwrap(), plain, "{suite:?} {len} {piece}");
            }
        }
    }
}

#[test]
fn random_access_reads_the_right_bytes_and_knows_the_length() {
    let dir = TempDir::new("seek");
    let ctx = context(&dir, "a.db", suites()[0]);
    let plain = data(3 * SEALED_BLOCK + 500, 9);
    let sealed = seal(&ctx, "blob", &plain, 10_000);
    let mut r = SealedReader::new(Cursor::new(sealed), &ctx, "blob", BIND).unwrap();
    assert_eq!(r.len(), plain.len() as u64);
    for (from, n) in [(0usize, 10usize), (SEALED_BLOCK - 5, 20), (2 * SEALED_BLOCK, 3000), (plain.len() - 7, 7), (12345, 70_000)] {
        r.seek(SeekFrom::Start(from as u64)).unwrap();
        let mut got = vec![0u8; n.min(plain.len() - from)];
        r.read_exact(&mut got).unwrap();
        assert_eq!(got, plain[from..from + got.len()]);
    }
    r.seek(SeekFrom::End(-4)).unwrap();
    let mut tail = Vec::new();
    r.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, plain[plain.len() - 4..]);
}

#[test]
fn the_file_shows_no_content_and_no_pattern() {
    let dir = TempDir::new("looks");
    let ctx = context(&dir, "a.db", suites()[1]);
    let plain = format!("{MARKER}-{{\"id\":\"x\"}}").repeat(50_000).into_bytes();
    let sealed = seal(&ctx, "blob", &plain, 1 << 20);
    assert!(!sealed.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()));
    assert!(!sealed.windows(5).any(|w| w == b"\"id\":"));
    let (mut run, mut longest) = (0, 0);
    for b in &sealed {
        run = if *b == 0 { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    assert!(longest < 16);
    // two seals of the same data share nothing
    let again = seal(&ctx, "blob", &plain, 1 << 20);
    assert_ne!(sealed, again);
    assert_ne!(sealed[..32], again[..32], "the salts differ");
}

/// Every change below must end in an error, either when opening or when reading to the end, and
/// must never yield bytes other than the original.
fn must_fail(ctx: &EncryptionContext, label: &str, original: &[u8], changed: &[u8], what: &str) {
    match open_all(ctx, label, changed) {
        Ok(got) => panic!("{what}: read {} bytes without an error (original {} bytes, same: {})", got.len(), original.len(), got == original),
        Err(e) => assert!(is_tamper(&e) || e.kind() == std::io::ErrorKind::UnexpectedEof, "{what}: {e}"),
    }
}

#[test]
fn every_kind_of_change_is_found() {
    for suite in suites() {
        let dir = TempDir::new("tamper");
        let ctx = context(&dir, "a.db", suite);
        let stride = SEALED_BLOCK + suite.cipher.overhead();
        let plain = data(4 * SEALED_BLOCK + 1234, 5);
        let sealed = seal(&ctx, "blob", &plain, 50_000);
        let blocks = 5usize;
        assert_eq!(sealed.len(), 32 + 4 * stride + 1234 + suite.cipher.overhead());

        // one bit in the salt, in each block (first, middle and last byte), and in the tag
        for pos in [0usize, 31] {
            let mut m = sealed.clone();
            m[pos] ^= 1;
            must_fail(&ctx, "blob", &plain, &m, &format!("salt bit {pos}"));
        }
        for b in 0..blocks {
            let start = 32 + b * stride;
            let end = if b + 1 == blocks { sealed.len() } else { start + stride };
            for pos in [start, start + (end - start) / 2, end - 1] {
                let mut m = sealed.clone();
                m[pos] ^= 0x10;
                must_fail(&ctx, "blob", &plain, &m, &format!("bit in block {b} at {pos}"));
            }
        }
        // cut at every block boundary, and the last block removed
        for keep in 0..blocks {
            must_fail(&ctx, "blob", &plain, &sealed[..32 + keep * stride], &format!("cut after {keep} blocks"));
        }
        // cut in the middle of a block, a byte short, a byte extra, an extra block
        must_fail(&ctx, "blob", &plain, &sealed[..32 + 2 * stride + 100], "cut inside a block");
        must_fail(&ctx, "blob", &plain, &sealed[..sealed.len() - 1], "one byte short");
        let mut longer = sealed.clone();
        longer.push(0);
        must_fail(&ctx, "blob", &plain, &longer, "one byte extra");
        let mut more = sealed.clone();
        more.extend_from_slice(&sealed[32..32 + stride]);
        must_fail(&ctx, "blob", &plain, &more, "an extra block");
        // two blocks swapped inside the file, one block copied over another
        let mut swapped = sealed.clone();
        for k in 0..stride {
            swapped.swap(32 + k, 32 + stride + k);
        }
        must_fail(&ctx, "blob", &plain, &swapped, "blocks 0 and 1 swapped");
        let mut copied = sealed.clone();
        let first = sealed[32..32 + stride].to_vec();
        copied[32 + 2 * stride..32 + 3 * stride].copy_from_slice(&first);
        must_fail(&ctx, "blob", &plain, &copied, "block 0 copied over block 2");
        // wrong kind of file, wrong database
        assert!(open_all(&ctx, "other", &sealed).is_err());
        let ctx2 = context(&dir, "b.db", suite);
        assert!(open_all(&ctx2, "blob", &sealed).is_err());
        // a file shorter than its header, and an empty one
        assert!(open_all(&ctx, "blob", &sealed[..10]).is_err());
        assert!(open_all(&ctx, "blob", &[]).is_err());
    }
}

#[test]
fn a_block_taken_from_another_file_is_refused() {
    let dir = TempDir::new("two");
    let ctx = context(&dir, "a.db", suites()[0]);
    let stride = SEALED_BLOCK + suites()[0].cipher.overhead();
    let (pa, pb) = (data(3 * SEALED_BLOCK, 1), data(3 * SEALED_BLOCK, 2));
    let (fa, fb) = (seal(&ctx, "blob", &pa, 1 << 20), seal(&ctx, "blob", &pb, 1 << 20));
    for index in 0..3usize {
        let mut m = fa.clone();
        let s = 32 + index * stride;
        m[s..s + stride].copy_from_slice(&fb[s..s + stride]);
        must_fail(&ctx, "blob", &pa, &m, &format!("block {index} from another file"));
    }
    // the same block position, same data, different salt: still refused
    let same = seal(&ctx, "blob", &pa, 1 << 20);
    let mut m = fa.clone();
    m[32..32 + stride].copy_from_slice(&same[32..32 + stride]);
    must_fail(&ctx, "blob", &pa, &m, "the same data sealed again");
}

#[test]
fn files_are_written_atomically_and_read_back() {
    let dir = TempDir::new("files");
    let ctx = context(&dir, "a.db", suites()[0]);
    let path = dir.path("index.sealed");
    let first = data(1000, 1);
    write_sealed_file(&path, &ctx, "config", "cfg", &first, true).unwrap();
    assert_eq!(read_sealed_file(&path, &ctx, "config", "cfg").unwrap(), first);
    let second = data(200_000, 2);
    write_sealed_file(&path, &ctx, "config", "cfg", &second, false).unwrap();
    assert_eq!(read_sealed_file(&path, &ctx, "config", "cfg").unwrap(), second);
    let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left behind");
    // damage on disk is reported as a change
    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    assert!(is_tamper(&read_sealed_file(&path, &ctx, "config", "cfg").unwrap_err()));
}

#[test]
fn a_stream_of_unknown_length_can_be_copied_in_and_out() {
    let dir = TempDir::new("copy");
    let ctx = context(&dir, "a.db", suites()[1]);
    let plain = data(5 * SEALED_BLOCK + 3, 7);
    let mut w = SealedWriter::new(Vec::new(), &ctx, "blob", BIND).unwrap();
    let copied = std::io::copy(&mut Cursor::new(plain.clone()), &mut w).unwrap();
    assert_eq!(copied, plain.len() as u64);
    let sealed = w.finish().unwrap();
    let mut out = Vec::new();
    let n = std::io::copy(&mut SealedReader::new(Cursor::new(sealed), &ctx, "blob", BIND).unwrap(), &mut out).unwrap();
    assert_eq!(n, plain.len() as u64);
    assert_eq!(out, plain);
}

#[test]
fn names_are_stable_distinct_and_hide_what_they_stand_for() {
    let dir = TempDir::new("names");
    let ctx = context(&dir, "a.db", suites()[0]);
    let a = ctx.name_fingerprint("table", "customers").unwrap();
    assert_eq!(a.len(), 32);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(a, ctx.name_fingerprint("table", "customers").unwrap());
    assert_ne!(a, ctx.name_fingerprint("table", "orders").unwrap());
    assert_ne!(a, ctx.name_fingerprint("blob", "customers").unwrap(), "domains are separate");
    assert!(!a.contains("customers"));
    let other = context(&dir, "b.db", suites()[0]);
    assert_ne!(a, other.name_fingerprint("table", "customers").unwrap(), "another database, another name");
}

/// A file is bound to its logical name: the same bytes under another name do not open, whether
/// that is another attachment, another table or a side file standing in for a different one.
#[test]
fn a_file_does_not_open_under_another_logical_name() {
    let dir = TempDir::new("binding");
    let ctx = context(&dir, "a.db", suites()[0]);
    let plain = data(2 * SEALED_BLOCK + 9, 4);
    let sealed = seal(&ctx, "blob", &plain, 1 << 20);
    for other in ["logical-nam", "logical-name ", "Logical-name", "", "other/path.json"] {
        let e = SealedReader::new(Cursor::new(sealed.clone()), &ctx, "blob", other)
            .and_then(|mut r| {
                let mut v = Vec::new();
                r.read_to_end(&mut v).map(|_| v)
            })
            .unwrap_err();
        assert!(is_tamper(&e), "{other:?}: {e}");
    }
    assert_eq!(open_all(&ctx, "blob", &sealed).unwrap(), plain);
    let path = dir.path("side.sealed");
    write_sealed_file(&path, &ctx, "config", "migration/tables/a/index", b"one", false).unwrap();
    let elsewhere = dir.path("other.sealed");
    std::fs::copy(&path, &elsewhere).unwrap();
    assert!(is_tamper(&read_sealed_file(&elsewhere, &ctx, "config", "migration/tables/b/index").unwrap_err()));
    assert_eq!(read_sealed_file(&path, &ctx, "config", "migration/tables/a/index").unwrap(), b"one");
}

#[test]
fn masked_paths_are_stable_and_hide_every_component() {
    let dir = TempDir::new("masked");
    let ctx = context(&dir, "a.db", suites()[0]);
    let root = dir.path("migration");
    let p = ctx.masked_path(&root, &["tables", "customers", "index.json"]).unwrap();
    assert_eq!(p, ctx.masked_path(&root, &["tables", "customers", "index.json"]).unwrap());
    assert_ne!(p, ctx.masked_path(&root, &["tables", "orders", "index.json"]).unwrap());
    let text = p.strip_prefix(&root).unwrap().to_string_lossy().to_lowercase();
    for word in ["tables", "customers", "index", "json"] {
        assert!(!text.contains(word), "{text}");
    }
    assert_eq!(p.strip_prefix(&root).unwrap().components().count(), 3);
}
