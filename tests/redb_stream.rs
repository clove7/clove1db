//! Streaming an external redb table into clove1db, on small tables made here.
use clove1db::migration::stream_external::{AttachmentMeta, FilePrefix, JsonRow, Kind, Options, StreamReport, Target, inventory, scan, stream, verify};
use clove1db::storage::{DatabaseConfig, Storage, StorageConfig};
use redb::TableDefinition;
use std::path::{Path, PathBuf};

const TABLE: &str = "attachments";

fn png(body: &[u8]) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend_from_slice(body);
    v
}

/// A made-up prefix for these tests: a marker byte, seven bytes, a group number at 8, 12 bytes in all.
const PREFIX: FilePrefix = FilePrefix { marker: 0xA5, len: 12, group_at: Some(8) };

/// The options of these tests: attachments that carry `PREFIX`.
fn opts() -> Options {
    Options::attachments(Some(PREFIX))
}

/// A value of the external table: the prefix, two bytes of padding, then the file.
fn with_prefix(group: u32, file: &[u8]) -> Vec<u8> {
    let mut v = vec![0xA5, 1, 2, 3, 4, 5, 6, 7];
    v.extend_from_slice(&group.to_le_bytes());
    v.extend_from_slice(&[7, 7]);
    v.extend_from_slice(file);
    v
}

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed)).collect()
}

/// Five rows: two pngs with the prefix, a jpeg without it, a prefix with no known file after it,
/// and an empty value.
fn rows() -> Vec<(u64, Vec<u8>)> {
    vec![
        (1, with_prefix(10, &png(&body(100_000, 1)))),
        (2, with_prefix(11, &png(&body(5, 2)))),
        (7, [b"\xff\xd8\xff".as_slice(), &body(70_000, 3)].concat()),
        (9, with_prefix(12, &body(300, 4))),
        (12, Vec::new()),
    ]
}

fn temp() -> PathBuf {
    let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_source(dir: &Path, rows: &[(u64, Vec<u8>)]) -> PathBuf {
    let path = dir.join("source.redb");
    let db = redb::Database::create(&path).unwrap();
    let write = db.begin_write().unwrap();
    {
        let mut t = write.open_table(TableDefinition::<u64, &[u8]>::new(TABLE)).unwrap();
        for (k, v) in rows {
            t.insert(*k, v.as_slice()).unwrap();
        }
    }
    write.commit().unwrap();
    path
}

fn storage(out: &Path) -> Storage {
    let db = DatabaseConfig::new("attachments", "attachments")
        .dir_path(out.to_path_buf())
        .backup_enabled(false)
        .has_cache(false)
        .blob_enabled(true)
        .register_blob::<AttachmentMeta>("files")
        .register::<JsonRow>("docs")
        .register::<JsonRow>("named");
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    Storage::builder(StorageConfig::default()).add_database(db).build().unwrap()
}

fn file_hash(path: &Path) -> blake3::Hash {
    blake3::hash(&std::fs::read(path).unwrap())
}

fn run(options: &Options) -> (PathBuf, PathBuf, Storage, StreamReport) {
    let dir = temp();
    let source = make_source(&dir, &rows());
    let s = storage(&dir.join("out"));
    let report = stream(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, options, None).unwrap();
    (dir, source, s, report)
}

/// Every table is read as the types it declares: the keys numbers, `&str` or `String`, the values
/// `&[u8]` or `Vec<u8>`. The same five rows are put in a table of each combination and the scan, the
/// stream and the check give the same answers, and the inventory names the declared types.
macro_rules! typed_table {
    ($name:ident, $K:ty, $V:ty, $kname:expr, $vname:expr, |$n:ident| $key:expr, |$v:ident| $val:expr) => {
        #[test]
        fn $name() {
            let dir = temp();
            let source = dir.join("source.redb");
            {
                let db = redb::Database::create(&source).unwrap();
                let write = db.begin_write().unwrap();
                {
                    let mut t = write.open_table(TableDefinition::<$K, $V>::new(TABLE)).unwrap();
                    for (n, value) in rows() {
                        let $n = n;
                        let $v = &value;
                        t.insert($key, $val).unwrap();
                    }
                }
                write.commit().unwrap();
            }
            let options = Options { max_rows: 2, ..opts() };
            let report = scan(&source, TABLE, &options).unwrap();
            assert_eq!((report.sizes.rows, report.without_prefix, report.without_signature), (5, 2, 2));
            assert_eq!(report.mimes.get("image/png"), Some(&2));
            let inventory = inventory(&source, &opts()).unwrap();
            let table = inventory.iter().find(|t| t.name == TABLE).expect("the table is listed");
            assert_eq!((table.key_type.as_str(), table.value_type.as_str(), table.rows), ($kname, $vname, 5));
            let s = storage(&dir.join("out"));
            let streamed = stream(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &options, None).unwrap();
            assert_eq!((streamed.sizes.rows, streamed.batches), (5, 3));
            let check = verify(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &options).unwrap();
            assert!(check.is_equal(), "{check:?}");
            assert_eq!((check.rows, check.target_rows, check.target_attachments, check.checked), (5, 5, 5, 5));
            s.close();
        }
    };
}

typed_table!(keys_of_numbers_and_values_of_slices, u64, &[u8], "u64", "&[u8]", |n| n, |v| &v[..]);
typed_table!(keys_of_numbers_and_values_of_vectors, u64, Vec<u8>, "u64", "Vec<u8>", |n| n, |v| v.clone());
typed_table!(keys_of_str_and_values_of_slices, &str, &[u8], "&str", "&[u8]", |n| format!("k{n:04}").as_str(), |v| &v[..]);
typed_table!(keys_of_str_and_values_of_vectors, &str, Vec<u8>, "&str", "Vec<u8>", |n| format!("k{n:04}").as_str(), |v| v.clone());
typed_table!(keys_of_text_and_values_of_slices, String, &[u8], "String", "&[u8]", |n| format!("k{n:04}"), |v| &v[..]);
typed_table!(keys_of_text_and_values_of_vectors, String, Vec<u8>, "String", "Vec<u8>", |n| format!("k{n:04}"), |v| v.clone());

#[test]
fn the_scan_counts_rows_sizes_and_what_it_cannot_tell() {
    let dir = temp();
    let source = make_source(&dir, &rows());
    let report = scan(&source, TABLE, &opts()).unwrap();
    assert_eq!(report.sizes.rows, 5);
    assert_eq!(report.without_prefix, 2, "the jpeg and the empty value have no prefix");
    assert_eq!(report.without_signature, 2, "the prefix with no known file, and the empty value");
    assert_eq!(report.sizes.smallest_value, 0);
    assert_eq!(report.sizes.largest_value, rows().iter().map(|(_, v)| v.len() as u64).max().unwrap());
    assert_eq!(report.mimes.get("image/png"), Some(&2));
    assert_eq!(report.mimes.get("image/jpeg"), Some(&1));
    assert_eq!(report.mimes.get("application/octet-stream"), Some(&2));
}

#[test]
fn every_row_arrives_with_the_same_bytes_and_batches_are_as_asked() {
    let options = Options { max_rows: 2, ..opts() };
    let (dir, source, s, report) = run(&options);
    assert_eq!((report.sizes.rows, report.batches), (5, 3));
    assert_eq!((report.without_prefix, report.without_signature), (2, 2));
    let check = verify(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &options).unwrap();
    assert!(check.is_equal(), "{check:?}");
    assert_eq!((check.rows, check.target_rows, check.target_attachments, check.checked), (5, 5, 5, 5));
    assert_ne!(check.source_fingerprint, 0);
    s.close();
    drop(dir);
}

#[test]
fn the_source_file_is_not_changed_by_any_stage() {
    let dir = temp();
    let source = make_source(&dir, &rows());
    let before = file_hash(&source);
    let stamp = std::fs::metadata(&source).unwrap().modified().unwrap();
    let s = storage(&dir.join("out"));
    let options = opts();
    scan(&source, TABLE, &options).unwrap();
    stream(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &options, None).unwrap();
    verify(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &options).unwrap();
    assert_eq!(file_hash(&source), before);
    assert_eq!(std::fs::metadata(&source).unwrap().modified().unwrap(), stamp);
}

#[test]
fn a_changed_attachment_is_found() {
    let options = opts();
    let (dir, source, s, _) = run(&options);
    let folder = dir.join("out").join("attachments").join("attachments.blobs").join("files");
    let file = std::fs::read_dir(&folder).unwrap().flatten().find(|e| e.metadata().unwrap().len() == 100_008).expect("the large png");
    let mut permissions = std::fs::metadata(file.path()).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(file.path(), permissions).unwrap();
    let mut bytes = std::fs::read(file.path()).unwrap();
    bytes[50_000] ^= 1;
    std::fs::write(file.path(), bytes).unwrap();
    let check = verify(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &options).unwrap();
    assert_eq!((check.different, check.missing), (1, 0));
    assert!(!check.is_equal());
}

#[test]
fn a_row_that_did_not_arrive_is_found() {
    let options = Options { limit: Some(3), ..opts() };
    let dir = temp();
    let source = make_source(&dir, &rows());
    let s = storage(&dir.join("out"));
    let report = stream(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &options, None).unwrap();
    assert_eq!(report.sizes.rows, 3);
    let check = verify(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &opts()).unwrap();
    assert_eq!((check.rows, check.target_rows, check.missing), (5, 3, 2));
    assert!(!check.is_equal());
}

#[test]
fn the_gate_refuses_a_run_that_does_not_fit_in_the_free_memory() {
    let dir = temp();
    let source = make_source(&dir, &rows());
    let s = storage(&dir.join("out"));
    // 64 MiB of cache, twice the largest value (100,022 bytes), 2 MiB: and 4 GiB to keep
    let tight = Options { free_memory: Some(4 << 30), ..opts() };
    let err = stream(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &tight, None).unwrap_err().to_string();
    assert!(err.contains("it was not started"), "{err}");
    assert_eq!(s.db_manager("attachments").count_keys("files").unwrap(), 0, "nothing was written");
    let roomy = Options { free_memory: Some(8 << 30), ..opts() };
    let report = stream(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &roomy, None).unwrap();
    assert_eq!(report.expected_peak_bytes, 64 * 1024 * 1024 + 2 * 100_022 + 2 * 1024 * 1024);
    assert_eq!(report.sizes.rows, 5);
}

/// A table of text values, and of bytes, with number and text keys, in the forms a redb file may hold.
fn make_json_source(dir: &Path) -> PathBuf {
    let path = dir.join("json.redb");
    let db = redb::Database::create(&path).unwrap();
    let write = db.begin_write().unwrap();
    {
        let mut docs = write.open_table(TableDefinition::<u64, String>::new("docs")).unwrap();
        for k in [3u64, 1, 2] {
            docs.insert(k, format!("{{\"n\":{k},\"t\":\"{}\"}}", "x".repeat(k as usize * 1000))).unwrap();
        }
        let mut named = write.open_table(TableDefinition::<&str, &[u8]>::new("named")).unwrap();
        named.insert("alpha", br#"{"a":1}"#.as_slice()).unwrap();
        named.insert("beta", br#"[1,2,3]"#.as_slice()).unwrap();
        let mut broken = write.open_table(TableDefinition::<u64, &str>::new("broken")).unwrap();
        broken.insert(1, "{not json").unwrap();
        let mut counts = write.open_table(TableDefinition::<&str, u64>::new("counts")).unwrap();
        counts.insert("next", 42).unwrap();
        write.open_table(TableDefinition::<u32, u32>::new("other")).unwrap();
    }
    write.commit().unwrap();
    path
}

#[test]
fn json_tables_move_as_they_are_with_number_and_text_keys() {
    let dir = temp();
    let source = make_json_source(&dir);
    let s = storage(&dir.join("out"));
    let json = Options { kind: Kind::Json, max_rows: 2, ..opts() };
    for (from, to, rows, batches) in [("docs", "docs", 3u64, 2u64), ("named", "named", 2, 1)] {
        let report = stream(&source, from, Target { storage: &s, db: "attachments", table: to }, &json, None).unwrap();
        assert_eq!((report.sizes.rows, report.batches), (rows, batches), "{from}");
        let check = verify(&source, from, Target { storage: &s, db: "attachments", table: to }, &json).unwrap();
        assert!(check.is_equal(), "{from}: {check:?}");
        assert_eq!(check.target_rows, rows);
        assert_eq!(check.checked, rows);
    }
    // a row that was not moved is found
    let partial = Options { kind: Kind::Json, limit: Some(1), ..opts() };
    let dir2 = temp();
    let s2 = storage(&dir2.join("out"));
    stream(&source, "docs", Target { storage: &s2, db: "attachments", table: "docs" }, &partial, None).unwrap();
    let check = verify(&source, "docs", Target { storage: &s2, db: "attachments", table: "docs" }, &json).unwrap();
    assert_eq!((check.missing, check.target_rows), (2, 1));
    assert!(!check.is_equal());
}

#[test]
fn a_row_that_is_not_json_stops_the_stream_of_json_rows() {
    let dir = temp();
    let source = make_json_source(&dir);
    let s = storage(&dir.join("out"));
    let json = Options { kind: Kind::Json, ..opts() };
    let err = stream(&source, "broken", Target { storage: &s, db: "attachments", table: "docs" }, &json, None).unwrap_err().to_string();
    assert!(err.contains("not valid JSON"), "{err}");
    let report = scan(&source, "broken", &json).unwrap();
    assert_eq!((report.sizes.rows, report.invalid_json), (1, 1));
}

#[test]
fn the_inventory_tells_the_types_and_sizes_of_every_table() {
    let dir = temp();
    let source = make_json_source(&dir);
    let report = inventory(&source, &opts()).unwrap();
    let by = |n: &str| report.iter().find(|t| t.name == n).unwrap().clone();
    let docs = by("docs");
    assert_eq!((docs.key_type.as_str(), docs.value_type.as_str(), docs.rows, docs.valid_json), ("u64", "String", 3, 3));
    assert_eq!(docs.largest_value, "{\"n\":3,\"t\":\"\"}".len() as u64 + 3000);
    let named = by("named");
    assert_eq!((named.key_type.as_str(), named.value_type.as_str(), named.rows, named.key_bytes), ("&str", "&[u8]", 2, 9));
    let broken = by("broken");
    assert_eq!((broken.rows, broken.valid_json, broken.valid_utf8), (1, 0, 1));
    let counts = by("counts");
    assert_eq!((counts.rows, counts.value_bytes), (1, 8));
    let other = by("other");
    assert_eq!(other.rows, 0);
    assert!(!other.note.is_empty());
}

#[test]
fn a_deep_scan_counts_the_signatures_that_show_late_or_never() {
    let dir = temp();
    let late = with_prefix(1, &[vec![9u8; 200], png(b"zz")].concat());
    let never = with_prefix(2, &body(300, 4));
    let source = make_source(&dir, &[(1, late), (2, never), (3, with_prefix(3, &png(b"ok")))]);
    let shallow = scan(&source, TABLE, &opts()).unwrap();
    assert_eq!((shallow.without_signature, shallow.late_signature), (2, 0));
    let deep = scan(&source, TABLE, &Options { deep_signature_check: true, ..opts() }).unwrap();
    assert_eq!((deep.late_signature, deep.no_signature_anywhere), (1, 1));
}

/// Timing of the stream on made-up tables (run on purpose: `--ignored --nocapture`). Prints the
/// time the files take (each is flushed to disk) and the time the rows take to commit.
#[test]
#[ignore]
fn timing_of_the_stream_on_made_up_tables() {
    for (count, size) in [(2000usize, 64 * 1024usize), (200, 1024 * 1024), (20, 8 * 1024 * 1024)] {
        let dir = temp();
        let rows: Vec<(u64, Vec<u8>)> = (0..count as u64).map(|k| (k, with_prefix(1, &png(&body(size, k as u8))))).collect();
        let source = make_source(&dir, &rows);
        let s = storage(&dir.join("out"));
        let start = std::time::Instant::now();
        let r = stream(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &opts(), None).unwrap();
        let total = start.elapsed().as_secs_f64();
        let check = verify(&source, TABLE, Target { storage: &s, db: "attachments", table: "files" }, &opts()).unwrap();
        assert!(check.is_equal());
        let mb = r.sizes.payload_bytes as f64 / 1048576.0;
        eprintln!(
            "TIMING rows={count} each={size}B payload={mb:.0}MiB total={total:.2}s files={:.2}s ({:.2} ms per file) commits={:.2}s other={:.2}s rate={:.1}MiB/s",
            r.files_time.as_secs_f64(),
            r.files_time.as_secs_f64() * 1000.0 / count as f64,
            r.commit_time.as_secs_f64(),
            total - (r.files_time + r.commit_time).as_secs_f64(),
            mb / total
        );
        s.close();
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn a_counter_becomes_a_row_with_its_value() {
    let dir = temp();
    let source = make_json_source(&dir);
    let s = storage(&dir.join("out"));
    let json = Options { kind: Kind::Json, ..opts() };
    let report = stream(&source, "counts", Target { storage: &s, db: "attachments", table: "docs" }, &json, None).unwrap();
    assert_eq!(report.sizes.rows, 1);
    assert!(verify(&source, "counts", Target { storage: &s, db: "attachments", table: "docs" }, &json).unwrap().is_equal());
    let db = s.db_manager("attachments").db().unwrap();
    let read = db.begin_read().unwrap();
    let table = read.open_table(TableDefinition::<&str, &[u8]>::new("docs")).unwrap();
    assert_eq!(table.get("next").unwrap().unwrap().value(), br#"{"value":42}"#.as_slice());
}

#[derive(Clone, Default, Debug, serde::Serialize, serde::Deserialize, clove1db::CloveFields)]
struct ProtectedRow {
    id: String,
    #[clove(encrypt, id = 1)]
    secret: clove1db::field_crypto::Sealed<String>,
}
impl clove1db::entity::Entity for ProtectedRow {
    fn entity_id(&self) -> &str { &self.id }
}
fn keys() -> clove1db::EncryptionConfig {
    use clove1db::{EncryptionConfig, KeySource, crypto::Key32};
    EncryptionConfig::new(KeySource::Raw(Key32::from_bytes(&[7;32])), KeySource::Raw(Key32::from_bytes(&[8;32])))
}
fn has_bytes(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).any(|p| {
        if p.is_dir() { has_bytes(&p, needle) }
        else { std::fs::read(p).unwrap().windows(needle.len()).any(|w| w == needle) }
    })
}
#[test]
fn protected_rows_and_blob_metadata_are_rejected_before_source_open() {
    use clove1db::units::ClError;
    for whole in [false, true] {
        let dir = temp();
        let config = DatabaseConfig::new("db", "db").dir_path(dir.join("out"))
            .backup_enabled(false).blob_enabled(true)
            .register_sealed::<ProtectedRow>("docs");
        let config = if whole { config.encryption(keys()) } else { config.field_encryption(keys()) };
        let s = Storage::builder(StorageConfig::default()).add_database(config).build().unwrap();
        let target = Target { storage: &s, db: "db", table: "docs" };
        assert!(matches!(stream(&dir.join("missing.redb"), "docs", target, &Options::json(), None), Err(ClError::Validation(_))));
        let source = make_json_source(&dir);
        assert!(matches!(stream(&source, "docs", target, &Options::json(), None), Err(ClError::Validation(_))));
        assert_eq!(s.db_manager("db").count_keys("docs").unwrap(), 0);
        s.close();
    }
    let dir = temp();
    let s = Storage::builder(StorageConfig::default()).add_database(
        DatabaseConfig::new("db", "db").dir_path(dir.join("out"))
            .backup_enabled(false).blob_enabled(true).field_encryption(keys())
            .register_sealed_blob::<ProtectedRow>("files")
    ).build().unwrap();
    let source = make_source(&dir, &rows());
    assert!(matches!(stream(&source, TABLE, Target { storage: &s, db: "db", table: "files" }, &opts(), None), Err(ClError::Validation(_))));
    assert_eq!(s.db_manager("db").count_keys("files").unwrap(), 0);
    s.close();
    assert!(!has_bytes(&dir.join("out"), b"\x89PNG\r\n\x1a\n"));
}
#[test]
fn overwritten_rows_refresh_a_populated_cache() {
    let dir = temp();
    let source = make_json_source(&dir);
    let s = Storage::builder(StorageConfig::default()).add_database(
        DatabaseConfig::new("db", "db").dir_path(dir.join("out"))
            .has_cache(true).backup_enabled(false).register::<JsonRow>("docs")
    ).build().unwrap();
    let manager = s.db_manager("db");
    let table = TableDefinition::<&str, &[u8]>::new("docs");
    manager.set(table, "docs", "1", br#"{"old":true}"#.to_vec()).unwrap();
    assert_eq!(manager.get(table, "docs", "1").unwrap().unwrap(), br#"{"old":true}"#);
    stream(&source, "docs", Target { storage: &s, db: "db", table: "docs" }, &Options::json(), None).unwrap();
    let got = manager.get(table, "docs", "1").unwrap().unwrap();
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&got).unwrap()["n"], 1);
    assert_eq!(got, manager.get_raw("docs", "1").unwrap().unwrap());
    s.close();
}
fn encrypted_storage(dir: &Path) -> Storage {
    Storage::builder(StorageConfig::default()).add_database(
        DatabaseConfig::new("db", "db").dir_path(dir.to_path_buf()).has_cache(true)
            .blob_enabled(true).encryption(keys())
            .register::<JsonRow>("docs").register_blob::<AttachmentMeta>("files")
    ).build().unwrap()
}
#[test]
fn encrypted_json_and_attachments_survive_reopen_without_plaintext() {
    use clove1db::encrypted_store::{EncryptionHandle, verify_encrypted_files};
    use std::io::Read;
    let dir = temp();
    let json = make_json_source(&dir);
    let source_rows = rows();
    let attachments = make_source(&dir, &source_rows);
    let out = dir.join("out");
    let s = encrypted_storage(&out);
    for (src, from, to, options) in [(&json, "docs", "docs", Options::json()), (&attachments, TABLE, "files", opts())] {
        let target = Target { storage: &s, db: "db", table: to };
        stream(src, from, target, &options, None).unwrap();
        assert!(verify(src, from, target, &options).unwrap().is_equal());
    }
    s.close(); drop(s);
    assert!(!has_bytes(&out, b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    assert!(!has_bytes(&out, b"\x89PNG\r\n\x1a\n"));
    verify_encrypted_files(&out, "db", "db", &EncryptionHandle::new(keys())).unwrap();
    let s = encrypted_storage(&out);
    assert!(verify(&json, "docs", Target { storage: &s, db: "db", table: "docs" }, &Options::json()).unwrap().is_equal());
    assert!(verify(&attachments, TABLE, Target { storage: &s, db: "db", table: "files" }, &opts()).unwrap().is_equal());
    let mut blob = s.domain::<AttachmentMeta>().open_blob("1").unwrap();
    let mut bytes = Vec::new(); blob.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, png(&body(100_000, 1)));
    s.close();
}
#[test]
fn structured_errors_and_zero_limit_preserve_the_target() {
    use clove1db::{units::ClError, migration::stream_external::StreamExternalError as E};
    let dir = temp(); let source = make_json_source(&dir); let s = storage(&dir.join("out"));
    let target = Target { storage: &s, db: "attachments", table: "docs" };
    assert!(matches!(stream(&source, "docs", target, &Options { max_rows: 0, ..Options::json() }, None), Err(ClError::StreamExternal(E::EmptyBatch))));
    assert!(matches!(stream(&source, "docs", target, &Options::attachments(None), None), Err(ClError::StreamExternal(E::NotAttachmentTable))));
    assert!(matches!(stream(&source, "broken", target, &Options::json(), None), Err(ClError::StreamExternal(E::NotJson { key })) if key == "1"));
    assert!(matches!(scan(&source, "other", &Options::json()), Err(ClError::StreamExternal(E::UnreadableTypes { key, value })) if key == "u32" && value == "u32"));
    assert!(matches!(stream(&source, "docs", target, &Options { free_memory: Some(0), ..Options::json() }, None), Err(ClError::StreamExternal(E::NotEnoughMemory { .. }))));
    let zero = Options { limit: Some(0), ..Options::json() };
    assert_eq!(stream(&source, "docs", target, &zero, None).unwrap().sizes.rows, 0);
    assert_eq!(scan(&source, "docs", &zero).unwrap().sizes.rows, 0);
    assert_eq!(verify(&source, "docs", target, &zero).unwrap().rows, 0);
    let one = Options { limit: Some(1), ..Options::json() };
    assert_eq!(verify(&source, "docs", target, &one).unwrap().missing, 1);
    assert_eq!(s.db_manager("attachments").count_keys("docs").unwrap(), 0);
    assert_eq!(Options::default().kind, Kind::Json);
    s.close();
}

#[test]
fn unclean_source_fixture() {
    if let Some(path) = std::env::var_os("STREAM_REPAIR_FIXTURE") {
        let db = redb::Database::create(PathBuf::from(path)).unwrap();
        let tx = db.begin_write().unwrap();
        { tx.open_table(TableDefinition::<u64, &str>::new("docs")).unwrap().insert(1, "{}").unwrap(); }
        tx.commit().unwrap();
        // Deliberately omit database close in this synthetic child only.
        std::process::exit(0);
    }
}
#[test]
fn repair_is_explicit_and_only_changes_the_supplied_copy() {
    use clove1db::{units::ClError, migration::stream_external::{StreamExternalError as E, repair_copy}};
    let dir = temp(); let source = dir.join("unclean.redb");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "unclean_source_fixture", "--nocapture"])
        .env("STREAM_REPAIR_FIXTURE", &source).status().unwrap();
    assert!(status.success());
    let before = file_hash(&source);
    assert!(matches!(scan(&source, "docs", &Options::json()), Err(ClError::StreamExternal(E::NeedsRepair { path })) if path == source));
    assert_eq!(file_hash(&source), before);
    let copy = dir.join("copy.redb"); std::fs::copy(&source, &copy).unwrap();
    repair_copy(&copy, &Options::json()).unwrap();
    assert_eq!(scan(&copy, "docs", &Options::json()).unwrap().sizes.rows, 1);
    assert_eq!(file_hash(&source), before);
}
#[test]
fn large_source_requires_explicit_memory_before_opening() {
    use clove1db::{units::ClError, migration::stream_external::StreamExternalError as E};
    let dir = temp(); let source = dir.join("large.redb");
    std::fs::File::create(&source).unwrap().set_len(1 << 30).unwrap();
    let s = storage(&dir.join("out"));
    assert!(matches!(stream(&source, "docs", Target { storage: &s, db: "attachments", table: "docs" }, &Options::json(), None), Err(ClError::StreamExternal(E::LargeSourceNeedsFreeMemory { bytes })) if bytes == 1 << 30));
    assert_eq!(s.db_manager("attachments").count_keys("docs").unwrap(), 0);
    s.close();
    std::fs::remove_file(source).unwrap();
}

#[test]
fn a_search_only_database_cannot_import_into_an_ordinary_table() {
    use clove1db::units::ClError;
    let dir = temp();
    let config = |keys| DatabaseConfig::new("db", "db").dir_path(dir.join("out"))
        .backup_enabled(false).field_encryption(keys)
        .register_sealed::<ProtectedRow>("protected").register::<JsonRow>("docs");
    let s = Storage::builder(StorageConfig::default()).add_database(config(keys())).build().unwrap();
    s.close(); drop(s);
    let mut search_only = keys(); search_only.read = None;
    let s = Storage::builder(StorageConfig::default()).add_database(config(search_only)).build().unwrap();
    assert!(matches!(stream(&dir.join("missing.redb"), "docs", Target { storage: &s, db: "db", table: "docs" }, &Options::json(), None), Err(ClError::Validation(_))));
    assert_eq!(s.db_manager("db").count_keys("docs").unwrap(), 0);
    s.close();
}
