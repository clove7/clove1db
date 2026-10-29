//! Attachments: sealed files under fingerprint names. After every step, with nothing open, every
//! file and folder name and every byte under the root is scanned for the content, the table
//! name and the ids.
mod encrypted_support;

use clove1db::crypto::ProgrammerKey;
use clove1db::encrypted_store::{
    Credentials, EncryptedDatabase, EncryptionContext, OpenOptionsExt, SealedBlobStore, SEALED_BLOCK, is_tamper,
};
use encrypted_support::*;
use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

const TABLE: &str = "customer_scans_secret";
const ID_PREFIX: &str = "ID-MARKER-7c1e";

fn context(dir: &TempDir, name: &str) -> EncryptionContext {
    let suite = suites()[0];
    let (rk, sk) = (key(), key());
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let creds = Credentials { suite, read: Some(&r), search: Some(&s) };
    let opts = OpenOptionsExt { cache_bytes: Some(1 << 20), ..Default::default() };
    EncryptedDatabase::create(&dir.path(name), &creds, "main", &opts).unwrap().context()
}

fn content(len: usize, seed: usize) -> Vec<u8> {
    let mut v = format!("{MARKER}-{seed}-").into_bytes();
    while v.len() < len {
        v.push(b'a' + ((v.len() * 7 + seed) % 26) as u8);
    }
    v.truncate(len);
    v
}

fn all_paths(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        out.push(p.clone());
        if p.is_dir() {
            out.extend(all_paths(&p));
        }
    }
    out
}

fn scan(root: &Path, step: &str) {
    let needles: [&[u8]; 4] = [MARKER.as_bytes(), TABLE.as_bytes(), ID_PREFIX.as_bytes(), b"secret"];
    for path in all_paths(root) {
        let rel = path.strip_prefix(root).unwrap().to_string_lossy().to_lowercase();
        for bad in ["marker", "secret", "customer", "scan", "id-"] {
            assert!(!rel.contains(bad), "{step}: the path {rel} shows {bad}");
        }
        if path.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            for n in needles {
                assert!(!bytes.windows(n.len()).any(|w| w == n), "{step}: {rel} contains {:?}", String::from_utf8_lossy(n));
            }
            let (mut run, mut longest) = (0usize, 0usize);
            for b in &bytes {
                run = if *b == 0 { run + 1 } else { 0 };
                longest = longest.max(run);
            }
            assert!(longest < 16, "{step}: {rel} has {longest} zero bytes in a row");
        }
    }
}

#[test]
fn attachments_hide_their_content_their_table_and_their_ids_at_every_step() {
    let dir = TempDir::new("blobs");
    let ctx = context(&dir, "a.db");
    let root = dir.path("a.blobs");
    let store = SealedBlobStore::new(&root, ctx.clone());
    store.ensure_root().unwrap();
    store.ensure_table(TABLE).unwrap();
    scan(&root, "after creating the folders");

    let sizes = [0usize, 1, 1000, SEALED_BLOCK - 1, SEALED_BLOCK, SEALED_BLOCK + 1, 300_000];
    for (i, len) in sizes.iter().enumerate() {
        store.write_atomic(TABLE, &format!("{ID_PREFIX}-{i}"), &content(*len, i), i % 2 == 0).unwrap();
    }
    scan(&root, "after writing");
    assert_eq!(store.count_files(TABLE).unwrap(), sizes.len());
    assert_eq!(store.count_all_files().unwrap(), sizes.len());
    for (i, len) in sizes.iter().enumerate() {
        let id = format!("{ID_PREFIX}-{i}");
        assert_eq!(store.read_all(TABLE, &id).unwrap(), content(*len, i), "size {len}");
        assert_eq!(store.size(TABLE, &id).unwrap(), *len as u64);
    }

    // a streamed write of unknown length, and a copy between two stores of two databases
    let big = content(5 * SEALED_BLOCK + 11, 99);
    let n = store.write_stream(TABLE, &format!("{ID_PREFIX}-stream"), &mut Cursor::new(big.clone()), true).unwrap();
    assert_eq!(n, big.len() as u64);
    let ctx2 = context(&dir, "b.db");
    let other = SealedBlobStore::new(&dir.path("b.blobs"), ctx2);
    let copied = other.copy_from(&store, TABLE, &format!("{ID_PREFIX}-stream"), "scans_copy_secret", &format!("{ID_PREFIX}-copy"), false).unwrap();
    assert_eq!(copied, big.len() as u64);
    assert_eq!(other.read_all("scans_copy_secret", &format!("{ID_PREFIX}-copy")).unwrap(), big);
    scan(&root, "after the stream and the copy (source)");
    scan(&dir.path("b.blobs"), "after the stream and the copy (target)");

    // reading piece by piece
    let mut r = store.open_read(TABLE, &format!("{ID_PREFIX}-stream")).unwrap();
    let mut head = vec![0u8; 100];
    r.read_exact(&mut head).unwrap();
    assert_eq!(head, big[..100]);

    // delete, and keep only what is wanted (unreferenced files and leftover temporary files go)
    assert!(store.delete(TABLE, &format!("{ID_PREFIX}-0")).unwrap());
    assert!(!store.delete(TABLE, &format!("{ID_PREFIX}-0")).unwrap());
    std::fs::write(store.table_dir(TABLE).unwrap().join("leftover.tmp.123"), b"x").unwrap();
    let keep: HashSet<(String, String)> = [1usize, 2, 3].iter().map(|i| (TABLE.to_string(), format!("{ID_PREFIX}-{i}"))).collect();
    let gone = store.retain_only(&keep).unwrap();
    // 7 written, 1 streamed, 1 deleted, 1 leftover temporary file; 3 kept
    assert_eq!(gone, 5, "files removed");
    assert_eq!(store.count_all_files().unwrap(), 3);
    for i in [1usize, 2, 3] {
        assert_eq!(store.read_all(TABLE, &format!("{ID_PREFIX}-{i}")).unwrap(), content(sizes[i], i));
    }
    scan(&root, "after clean-up");

    // no temporary file is left by the writes
    for path in all_paths(&root) {
        assert!(!path.to_string_lossy().contains(".tmp."), "{}", path.display());
    }
}

#[test]
fn a_changed_attachment_is_an_error_and_never_other_data() {
    let dir = TempDir::new("blobs-tamper");
    let ctx = context(&dir, "a.db");
    let store = SealedBlobStore::new(&dir.path("a.blobs"), ctx);
    let data = content(3 * SEALED_BLOCK + 5, 1);
    store.write_atomic("t", "x", &data, false).unwrap();
    let path = store.path("t", "x").unwrap();
    let original = std::fs::read(&path).unwrap();

    let try_read = |bytes: &[u8]| -> std::io::Result<Vec<u8>> {
        std::fs::write(&path, bytes).unwrap();
        store.read_all("t", "x")
    };
    for pos in [0usize, 31, 32, 5000, original.len() / 2, original.len() - 1] {
        let mut m = original.clone();
        m[pos] ^= 4;
        let e = try_read(&m).unwrap_err();
        assert!(is_tamper(&e), "bit {pos}: {e}");
    }
    let block = SEALED_BLOCK + suites()[0].cipher.overhead();
    for cut in [32 + block, 32 + 2 * block, 32 + 3 * block] {
        assert!(try_read(&original[..cut]).is_err(), "cut at {cut}");
    }
    assert!(try_read(&original[..original.len() - 1]).is_err());
    let mut longer = original.clone();
    longer.extend_from_slice(&original[32..32 + block]);
    assert!(try_read(&longer).is_err());
    // the same file under another id in the same table, or in another table, is not an attachment
    std::fs::write(&path, &original).unwrap();
    assert_eq!(store.read_all("t", "x").unwrap(), data);
    store.ensure_table("t").unwrap();
    std::fs::copy(&path, store.path("t", "y").unwrap()).unwrap();
    assert!(is_tamper(&store.read_all("t", "y").unwrap_err()), "copied to another id");
    assert!(is_tamper(&store.open_read("t", "y").err().expect("opening must fail")));
    store.ensure_table("u").unwrap();
    std::fs::copy(&path, store.path("u", "x").unwrap()).unwrap();
    assert!(is_tamper(&store.read_all("u", "x").unwrap_err()), "copied to another table");
    store.ensure_table("tx").unwrap();
    std::fs::copy(&path, store.path("tx", "").unwrap()).unwrap();
    assert!(is_tamper(&store.read_all("tx", "").unwrap_err()), "table and id cut differently");
    assert_eq!(store.read_all("t", "x").unwrap(), data);
}

#[test]
fn names_do_not_collide_across_tables_and_ids() {
    let dir = TempDir::new("blobs-names");
    let store = SealedBlobStore::new(&dir.path("a.blobs"), context(&dir, "a.db"));
    let pairs = [("ab", "c"), ("a", "bc"), ("abc", ""), ("", "abc"), ("t", "1"), ("t1", "")];
    let mut seen = HashSet::new();
    for (t, i) in pairs {
        assert!(seen.insert(store.path(t, i).unwrap()), "{t:?} {i:?} collides");
    }
}
