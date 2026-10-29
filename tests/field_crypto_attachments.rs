//! The attachment of a row in a table with protected fields is sealed in chunks with the keys of
//! those fields, bound to the table, the place and the row; its folder and file names show neither.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::is_tamper,
    entity::Entity,
    field_crypto::Sealed,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Doc {
    id: String,
    title: String,
    #[clove(encrypt, id = 1)]
    secret: Sealed<String>,
}
impl Entity for Doc {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same shape in another table.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Memo {
    id: String,
    title: String,
    #[clove(encrypt, id = 1)]
    secret: Sealed<String>,
}
impl Entity for Memo {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn doc(id: &str) -> Doc {
    Doc { id: id.into(), title: "visible title".into(), secret: Sealed::new("top secret".into()) }
}

fn memo(id: &str) -> Memo {
    Memo { id: id.into(), title: "visible title".into(), secret: Sealed::new("top secret".into()) }
}

fn keys() -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

fn base(dir: &Path) -> DatabaseConfig {
    DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false).backup_enabled(true).blob_enabled(true)
}

/// The keys for the protected fields: their own keys in an ordinary database, the keys of the
/// encryption of the whole database under the test cfg.
fn with_keys(db: DatabaseConfig) -> DatabaseConfig {
    #[cfg(clove_test_encrypt_all)]
    {
        db.encryption(keys())
    }
    #[cfg(not(clove_test_encrypt_all))]
    {
        db.field_encryption(keys())
    }
}

fn open(dir: &Path) -> Storage {
    Storage::builder(StorageConfig::default())
        .add_database(
            with_keys(base(dir)).register_sealed_blob::<Doc>("docs").register_sealed_blob::<Memo>("memos"),
        )
        .build()
        .unwrap()
}

/// An ordinary database (not encrypted as a whole) with field keys, also under the test cfg: the
/// scan of readable files needs it (listed in 7-5-plain-only.md).
fn open_field_mode(dir: &Path) -> Storage {
    let db = base(dir);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    Storage::builder(StorageConfig::default())
        .add_database(db.field_encryption(keys()).register_sealed_blob::<Doc>("docs").register_sealed_blob::<Memo>("memos"))
        .build()
        .unwrap()
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

/// The files of the protected attachments, by folder then size.
fn attachment_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = walk(dir).into_iter().filter(|p| p.to_string_lossy().contains(".pblobs")).collect();
    files.sort();
    files
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Distinct bytes of a given length that do not repeat in short runs.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + (i >> 8) * 7) as u8).wrapping_add(seed)).collect()
}

fn read_all(mut r: clove1db::blob::BlobReader) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
}

#[test]
fn the_bytes_of_an_attachment_appear_in_no_file_and_the_names_hide_table_and_row() {
    let dir = temp_dir();
    let marker = b"ATTACHMENT-MARKER-0123456789-ATTACHMENT-MARKER";
    let mut bytes = Vec::new();
    while bytes.len() < 200_000 {
        bytes.extend_from_slice(marker);
        bytes.extend_from_slice(b" ");
    }
    {
        let s = open_field_mode(&dir);
        s.domain::<Doc>().repo().set_with_blob("report-7", &doc("report-7"), &bytes).unwrap();
        let read = read_all(s.domain::<Doc>().repo().open_blob("report-7").unwrap()).unwrap();
        assert_eq!(read, bytes);
        s.close();
    }
    let files = walk(&dir);
    let mut ordinary = false;
    for path in &files {
        let content = std::fs::read(path).unwrap();
        assert!(!contains(&content, b"ATTACHMENT-MARKER"), "attachment bytes found in {}", path.display());
        assert!(!contains(&content, b"top secret"), "protected value found in {}", path.display());
        ordinary |= contains(&content, b"visible title");
    }
    assert!(ordinary, "the scan itself is blind: an ordinary field was not found");
    let attachments = attachment_files(&dir);
    assert_eq!(attachments.len(), 1, "{attachments:?}");
    // Neither the table nor the row appears in the folder or the file name.
    let relative = attachments[0].strip_prefix(&dir).unwrap().to_string_lossy().to_lowercase();
    assert!(relative.contains(".pblobs"));
    let below: String = relative.split(".pblobs").nth(1).unwrap().to_string();
    assert!(!below.contains("docs") && !below.contains("report"), "{below}");
    // The sealed file is larger than the data only by the salt and a tag per block.
    let size = std::fs::metadata(&attachments[0]).unwrap().len();
    assert!(size > bytes.len() as u64 && size < bytes.len() as u64 + 1024, "{size}");
}

#[test]
fn an_attachment_reads_back_in_pieces_and_by_position() {
    let dir = temp_dir();
    // More than four sealed blocks, and not a multiple of the block size.
    let bytes = pattern(300_123, 5);
    let s = open(&dir);
    let repo = s.domain::<Doc>().repo();
    repo.set_with_blob("d1", &doc("d1"), &bytes).unwrap();

    let mut reader = repo.open_blob("d1").unwrap();
    assert_eq!(reader.len().unwrap(), bytes.len() as u64);
    let mut got = Vec::new();
    let mut piece = [0u8; 4093];
    loop {
        let n = reader.read(&mut piece).unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&piece[..n]);
    }
    assert_eq!(got, bytes, "reading piece by piece differs from the original");

    // Random positions, across block boundaries.
    for (at, len) in [(0u64, 10usize), (65_530, 20), (131_070, 9000), (299_000, 1123)] {
        reader.seek(SeekFrom::Start(at)).unwrap();
        let mut out = vec![0u8; len];
        reader.read_exact(&mut out).unwrap();
        assert_eq!(out, bytes[at as usize..at as usize + len], "at {at}");
    }
    // The attachment survives closing and opening again.
    drop(reader);
    s.close();
    drop(s);
    let s = open(&dir);
    assert_eq!(read_all(s.domain::<Doc>().repo().open_blob("d1").unwrap()).unwrap(), bytes);
}

/// Reading gives an error that says the data was changed, never other bytes.
fn assert_tampered(result: clove1db::units::Result<clove1db::blob::BlobReader>, what: &str) {
    match result {
        Err(ClError::DataTampered) => {}
        Err(other) => panic!("{what}: wrong error {other:?}"),
        Ok(reader) => match read_all(reader) {
            Err(e) if is_tamper(&e) => {}
            Err(e) => panic!("{what}: wrong error {e:?}"),
            Ok(_) => panic!("{what}: other bytes were returned"),
        },
    }
}

#[test]
fn an_attachment_moved_to_another_row_or_table_is_a_tamper_error_never_other_bytes() {
    let dir = temp_dir();
    let (a, b, c) = (pattern(100_000, 1), pattern(70_000, 2), pattern(90_000, 3));
    let s = open(&dir);
    s.domain::<Doc>().repo().set_with_blob("d1", &doc("d1"), &a).unwrap();
    s.domain::<Doc>().repo().set_with_blob("d2", &doc("d2"), &b).unwrap();
    s.domain::<Memo>().repo().set_with_blob("m1", &memo("m1"), &c).unwrap();

    // Which file is which: by size (a sealed file is a little larger than its data).
    let files = attachment_files(&dir);
    assert_eq!(files.len(), 3, "{files:?}");
    let by_size = |n: usize| {
        files
            .iter()
            .find(|p| {
                let len = std::fs::metadata(p).unwrap().len() as usize;
                len > n && len < n + 1024
            })
            .unwrap_or_else(|| panic!("no file of about {n} bytes"))
            .clone()
    };
    let (file_a, file_b, file_c) = (by_size(a.len()), by_size(b.len()), by_size(c.len()));
    let original_b = std::fs::read(&file_b).unwrap();
    let original_c = std::fs::read(&file_c).unwrap();

    // Row d1's file in place of row d2's file (same table).
    std::fs::copy(&file_a, &file_b).unwrap();
    assert_tampered(s.domain::<Doc>().repo().open_blob("d2"), "another row, same table");
    // The row the file really belongs to still reads.
    assert_eq!(read_all(s.domain::<Doc>().repo().open_blob("d1").unwrap()).unwrap(), a);
    std::fs::write(&file_b, &original_b).unwrap();
    assert_eq!(read_all(s.domain::<Doc>().repo().open_blob("d2").unwrap()).unwrap(), b);

    // Row d1's file in place of the memo's file (another table).
    std::fs::copy(&file_a, &file_c).unwrap();
    assert_tampered(s.domain::<Memo>().repo().open_blob("m1"), "another table");
    std::fs::write(&file_c, &original_c).unwrap();
    assert_eq!(read_all(s.domain::<Memo>().repo().open_blob("m1").unwrap()).unwrap(), c);

    // One changed byte in the middle of a file.
    let mut changed = std::fs::read(&file_a).unwrap();
    let middle = changed.len() / 2;
    changed[middle] ^= 1;
    std::fs::write(&file_a, &changed).unwrap();
    assert_tampered(s.domain::<Doc>().repo().open_blob("d1"), "one changed byte");
}

#[test]
fn a_version_cannot_be_opened_without_its_row() {
    let dir = temp_dir();
    let s = open(&dir);
    s.domain::<Doc>().repo().set_with_blob("d1", &doc("d1"), &pattern(1000, 9)).unwrap();
    let err = s.db_manager("store").open_blob_version("docs", "__v_00000000-0000-0000-0000-000000000000").unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("bound to their row")), "{err:?}");
}

#[test]
fn cleaning_removes_what_nothing_uses_and_keeps_the_used_attachment() {
    let dir = temp_dir();
    let bytes = pattern(80_000, 4);
    {
        let s = open(&dir);
        s.domain::<Doc>().repo().set_with_blob("d1", &doc("d1"), &bytes).unwrap();
        s.close();
    }
    // A leftover attachment nothing refers to, and a temporary file of an interrupted write.
    let used = attachment_files(&dir);
    assert_eq!(used.len(), 1);
    let folder = used[0].parent().unwrap().to_path_buf();
    std::fs::copy(&used[0], folder.join("0123456789abcdef0123456789abcdef")).unwrap();
    std::fs::write(folder.join("interrupted.tmp.42"), b"half a write").unwrap();
    assert_eq!(attachment_files(&dir).len(), 3);

    let s = open(&dir);
    let left = attachment_files(&dir);
    assert_eq!(left, used, "the leftovers were not cleaned");
    assert_eq!(read_all(s.domain::<Doc>().repo().open_blob("d1").unwrap()).unwrap(), bytes);

    // Deleting the row removes its reference: the attachment is no longer there to open.
    s.domain::<Doc>().repo().delete("d1").unwrap();
    let err = s.domain::<Doc>().repo().open_blob("d1").unwrap_err();
    assert!(matches!(err, ClError::NotFound(_)), "{err:?}");
}

#[test]
fn a_program_with_only_the_search_key_cannot_open_an_attachment() {
    // Needs field keys opened with the search key alone: an ordinary database (listed in 7-5-plain-only.md).
    let dir = temp_dir();
    let bytes = pattern(5000, 8);
    {
        let s = open_field_mode(&dir);
        s.domain::<Doc>().repo().set_with_blob("d1", &doc("d1"), &bytes).unwrap();
        s.close();
    }
    let search_only = EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: None,
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    };
    let db = base(&dir);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    // Such a program opens (it checks and cleans nothing it cannot open) but cannot open the attachment.
    let before = attachment_files(&dir);
    let s = Storage::builder(StorageConfig::default())
        .add_database(db.field_encryption(search_only).register_sealed_blob::<Doc>("docs").register_sealed_blob::<Memo>("memos"))
        .build()
        .unwrap();
    assert!(s.domain::<Doc>().repo().open_blob("d1").is_err());
    assert!(s.db_manager("store").open_blob_version_row("docs", "d1", "__v_x").is_err());
    s.close();
    assert_eq!(attachment_files(&dir), before, "a read-only program changed the attachments");
}
