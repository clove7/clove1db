//! Streaming an external redb table into clove1db, on small tables made here.
use clove1db::migration::stream_external::{AttachmentMeta, FilePrefix, JsonRow, Kind, Options, Report, scan, stream, verify};
use clove1db::storage::{DatabaseConfig, Storage, StorageConfig};
use redb::{ReadableDatabase, TableDefinition};
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
    Options { prefix: Some(PREFIX), ..Options::default() }
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

fn run(options: &Options) -> (PathBuf, PathBuf, Storage, Report) {
    let dir = temp();
    let source = make_source(&dir, &rows());
    let s = storage(&dir.join("out"));
    let report = stream(&source, TABLE, &s, "attachments", "files", options, &mut |_| {}).unwrap();
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
            assert_eq!((report.rows, report.without_prefix, report.without_signature), (5, 2, 2));
            assert_eq!(report.mimes.get("image/png"), Some(&2));
            let inventory = scan(&source, "", &Options { inventory: true, ..opts() }).unwrap();
            let table = inventory.tables.iter().find(|t| t.name == TABLE).expect("the table is listed");
            assert_eq!((table.key_type.as_str(), table.value_type.as_str(), table.rows), ($kname, $vname, 5));
            let s = storage(&dir.join("out"));
            let streamed = stream(&source, TABLE, &s, "attachments", "files", &options, &mut |_| {}).unwrap();
            assert_eq!((streamed.rows, streamed.batches), (5, 3));
            let check = verify(&source, TABLE, &s, "attachments", "files", &options).unwrap();
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
    assert_eq!(report.rows, 5);
    assert_eq!(report.without_prefix, 2, "the jpeg and the empty value have no prefix");
    assert_eq!(report.without_signature, 2, "the prefix with no known file, and the empty value");
    assert_eq!(report.smallest_value, 0);
    assert_eq!(report.largest_value, rows().iter().map(|(_, v)| v.len() as u64).max().unwrap());
    assert_eq!(report.mimes.get("image/png"), Some(&2));
    assert_eq!(report.mimes.get("image/jpeg"), Some(&1));
    assert_eq!(report.mimes.get("application/octet-stream"), Some(&2));
}

#[test]
fn every_row_arrives_with_the_same_bytes_and_batches_are_as_asked() {
    let options = Options { max_rows: 2, ..opts() };
    let (dir, source, s, report) = run(&options);
    assert_eq!((report.rows, report.batches), (5, 3));
    assert_eq!((report.without_prefix, report.without_signature), (2, 2));
    let check = verify(&source, TABLE, &s, "attachments", "files", &options).unwrap();
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
    stream(&source, TABLE, &s, "attachments", "files", &options, &mut |_| {}).unwrap();
    verify(&source, TABLE, &s, "attachments", "files", &options).unwrap();
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
    let check = verify(&source, TABLE, &s, "attachments", "files", &options).unwrap();
    assert_eq!((check.different, check.missing), (1, 0));
    assert!(!check.is_equal());
}

#[test]
fn a_row_that_did_not_arrive_is_found() {
    let options = Options { limit: Some(3), ..opts() };
    let dir = temp();
    let source = make_source(&dir, &rows());
    let s = storage(&dir.join("out"));
    let report = stream(&source, TABLE, &s, "attachments", "files", &options, &mut |_| {}).unwrap();
    assert_eq!(report.rows, 3);
    let check = verify(&source, TABLE, &s, "attachments", "files", &opts()).unwrap();
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
    let err = stream(&source, TABLE, &s, "attachments", "files", &tight, &mut |_| {}).unwrap_err().to_string();
    assert!(err.contains("it was not started"), "{err}");
    assert_eq!(s.db_manager("attachments").count_keys("files").unwrap(), 0, "nothing was written");
    let roomy = Options { free_memory: Some(8 << 30), ..opts() };
    let report = stream(&source, TABLE, &s, "attachments", "files", &roomy, &mut |_| {}).unwrap();
    assert_eq!(report.expected_peak_bytes, 64 * 1024 * 1024 + 2 * 100_022 + 2 * 1024 * 1024);
    assert_eq!(report.rows, 5);
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
        let report = stream(&source, from, &s, "attachments", to, &json, &mut |_| {}).unwrap();
        assert_eq!((report.rows, report.batches), (rows, batches), "{from}");
        let check = verify(&source, from, &s, "attachments", to, &json).unwrap();
        assert!(check.is_equal(), "{from}: {check:?}");
        assert_eq!(check.target_rows, rows);
        assert_eq!(check.checked, rows);
    }
    // a row that was not moved is found
    let partial = Options { kind: Kind::Json, limit: Some(1), ..opts() };
    let dir2 = temp();
    let s2 = storage(&dir2.join("out"));
    stream(&source, "docs", &s2, "attachments", "docs", &partial, &mut |_| {}).unwrap();
    let check = verify(&source, "docs", &s2, "attachments", "docs", &json).unwrap();
    assert_eq!((check.missing, check.target_rows), (2, 1));
    assert!(!check.is_equal());
}

#[test]
fn a_row_that_is_not_json_stops_the_stream_of_json_rows() {
    let dir = temp();
    let source = make_json_source(&dir);
    let s = storage(&dir.join("out"));
    let json = Options { kind: Kind::Json, ..opts() };
    let err = stream(&source, "broken", &s, "attachments", "docs", &json, &mut |_| {}).unwrap_err().to_string();
    assert!(err.contains("not valid JSON"), "{err}");
    let report = scan(&source, "broken", &json).unwrap();
    assert_eq!((report.rows, report.invalid_json), (1, 1));
}

#[test]
fn the_inventory_tells_the_types_and_sizes_of_every_table() {
    let dir = temp();
    let source = make_json_source(&dir);
    let report = scan(&source, "", &Options { inventory: true, ..opts() }).unwrap();
    let by = |n: &str| report.tables.iter().find(|t| t.name == n).unwrap().clone();
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
        let r = stream(&source, TABLE, &s, "attachments", "files", &opts(), &mut |_| {}).unwrap();
        let total = start.elapsed().as_secs_f64();
        let check = verify(&source, TABLE, &s, "attachments", "files", &opts()).unwrap();
        assert!(check.is_equal());
        let mb = r.payload_bytes as f64 / 1048576.0;
        eprintln!(
            "TIMING rows={count} each={size}B payload={mb:.0}MiB total={total:.2}s files={:.2}s ({:.2} ms per file) commits={:.2}s other={:.2}s rate={:.1}MiB/s",
            r.files_nanos as f64 / 1e9,
            r.files_nanos as f64 / 1e6 / count as f64,
            r.commit_nanos as f64 / 1e9,
            total - (r.files_nanos + r.commit_nanos) as f64 / 1e9,
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
    let report = stream(&source, "counts", &s, "attachments", "docs", &json, &mut |_| {}).unwrap();
    assert_eq!(report.rows, 1);
    assert!(verify(&source, "counts", &s, "attachments", "docs", &json).unwrap().is_equal());
    let db = s.db_manager("attachments").db().unwrap();
    let read = db.begin_read().unwrap();
    let table = read.open_table(TableDefinition::<&str, &[u8]>::new("docs")).unwrap();
    use redb::ReadableTable;
    assert_eq!(table.get("next").unwrap().unwrap().value(), br#"{"value":42}"#.as_slice());
}
