//! Side files: sealed under fingerprint names, bound to their logical place.
mod encrypted_support;

use clove1db::crypto::ProgrammerKey;
use clove1db::encrypted_store::{
    Credentials, EncryptedDatabase, EncryptionContext, OpenOptionsExt, SidecarFiles, is_tamper,
};
use encrypted_support::*;

fn context(dir: &TempDir) -> EncryptionContext {
    let (rk, sk) = (key(), key());
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let creds = Credentials { suite: suites()[1], read: Some(&r), search: Some(&s) };
    EncryptedDatabase::create(&dir.path("a.db"), &creds, "main", &OpenOptionsExt::default()).unwrap().context()
}

#[test]
fn files_round_trip_and_a_missing_one_is_none() {
    let dir = TempDir::new("side");
    let side = SidecarFiles::new(&dir.path("mig"), context(&dir));
    assert_eq!(side.read(&["index.json"]).unwrap(), None);
    assert!(!side.exists(&["index.json"]).unwrap());
    side.write(&["index.json"], b"{\"tables\":{}}", true).unwrap();
    side.write(&["tables", "customers_secret", "index.json"], b"{\"chain\":[]}", false).unwrap();
    assert_eq!(side.read(&["index.json"]).unwrap().unwrap(), b"{\"tables\":{}}");
    assert_eq!(side.read(&["tables", "customers_secret", "index.json"]).unwrap().unwrap(), b"{\"chain\":[]}");
    // nothing readable on disk, in names or bytes
    fn walk(p: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(p).unwrap() {
            let p = e.unwrap().path();
            out.push(p.clone());
            if p.is_dir() {
                walk(&p, out);
            }
        }
    }
    let mut all = Vec::new();
    walk(&dir.path("mig"), &mut all);
    assert_eq!(all.len(), 1 + 3, "one root file, then two folders and the file in them");
    for p in all {
        let rel = p.strip_prefix(dir.path("mig")).unwrap().to_string_lossy().to_lowercase();
        for bad in ["index", "json", "tables", "customers", "secret"] {
            assert!(!rel.contains(bad), "{rel}");
        }
        if p.is_file() {
            let b = std::fs::read(&p).unwrap();
            assert!(!b.windows(5).any(|w| w == b"chain") && !b.windows(6).any(|w| w == b"tables"));
        }
    }
    assert!(side.remove(&["index.json"]).unwrap());
    assert!(!side.remove(&["index.json"]).unwrap());
    assert_eq!(side.read(&["index.json"]).unwrap(), None);
}

#[test]
fn a_file_moved_to_another_place_or_changed_is_a_tamper_error_not_a_missing_file() {
    let dir = TempDir::new("side-move");
    let side = SidecarFiles::new(&dir.path("mig"), context(&dir));
    side.write(&["tables", "a", "index.json"], b"one", false).unwrap();
    side.write(&["tables", "b", "index.json"], b"two", false).unwrap();
    let a = side.path(&["tables", "a", "index.json"]).unwrap();
    let b = side.path(&["tables", "b", "index.json"]).unwrap();
    // a's bytes put where b's file is
    let original_b = std::fs::read(&b).unwrap();
    std::fs::copy(&a, &b).unwrap();
    assert!(is_tamper(&side.read(&["tables", "b", "index.json"]).unwrap_err()));
    std::fs::write(&b, &original_b).unwrap();
    assert_eq!(side.read(&["tables", "b", "index.json"]).unwrap().unwrap(), b"two");
    // a root-level file standing in for a nested one
    side.write(&["index.json"], b"root", false).unwrap();
    std::fs::copy(side.path(&["index.json"]).unwrap(), &a).unwrap();
    assert!(is_tamper(&side.read(&["tables", "a", "index.json"]).unwrap_err()));
    // one bit
    let mut bytes = std::fs::read(&b).unwrap();
    let mid = bytes.len() - 3;
    bytes[mid] ^= 1;
    std::fs::write(&b, &bytes).unwrap();
    assert!(is_tamper(&side.read(&["tables", "b", "index.json"]).unwrap_err()));
    // the parts are not confused by how they are cut
    side.write(&["a/b"], b"x", false).unwrap();
    side.write(&["a", "b"], b"y", false).unwrap();
    assert_eq!(side.read(&["a/b"]).unwrap().unwrap(), b"x");
    assert_eq!(side.read(&["a", "b"]).unwrap().unwrap(), b"y");
}

#[test]
fn a_file_set_aside_is_gone_from_its_name_and_kept() {
    let dir = TempDir::new("side-aside");
    let side = SidecarFiles::new(&dir.path("mig"), context(&dir));
    side.write(&["root.json"], b"derived", false).unwrap();
    side.set_aside(&["root.json"], 42).unwrap();
    assert_eq!(side.read(&["root.json"]).unwrap(), None);
    let kept = std::fs::read_dir(dir.path("mig")).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().contains(".aside.42")).count();
    assert_eq!(kept, 1);
    side.set_aside(&["root.json"], 43).unwrap();
}
