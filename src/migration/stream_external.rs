//! Moving a table of an external redb file into a clove1db database as a stream: either an
//! attachments table (keys are numbers, each value the bytes of one file, after an optional fixed
//! prefix that [`Options::prefix`] describes) or a table of JSON rows.
//!
//! This reads the source in one transaction, one row at a time, so it does not depend on the size
//! of the file; the bytes of an attachment go straight to the file of its attachment (no JSON in
//! between), and rows are committed in batches.
//!
//! The source is opened read only, so a scan, a stream and a check never write to it. A file that
//! needs repair has to be repaired first with [`Options::repair`], which opens the file it is given
//! for writing: give it a **copy**, never the only file you have.
//!
//! Three entry points do it all, with their choices in one [`Options`]: [`scan`] (the tables of
//! the file, and the sizes of one table), [`stream`] and [`verify`]. Nothing here prints a value:
//! the [`Report`] holds counts, sizes and fingerprints.
use crate::{
    entity::Entity,
    journal::ChangeKind,
    journal_blob::{self, REFS},
    storage::Storage,
    units::{ClError, Result},
};
use redb::{MultimapTableHandle, ReadableDatabase, ReadableTable, TableDefinition, TableHandle};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, path::Path};

/// Bytes of a value after which a file signature is no longer looked for.
const SIGNATURE_WINDOW: usize = 64;
const SIGNATURES: [(&[u8], &str); 6] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"RIFF", "image/webp"),
    (b"%PDF", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
];
/// Bytes of rows that may wait for their batch to be committed (a row is never split).
const BATCH_BYTES: usize = 8 * 1024 * 1024;
/// A source file this large must be run with the free memory told (see [`Options::free_memory`]).
const NEEDS_GATE: u64 = 1 << 30;
/// Inside the walk of a table: the limit of rows was reached, which is not a failure.
const STOPPED: &str = "stopped at the limit";

/// The small row kept in the database for each attachment.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentMeta {
    pub id: String,
    /// The number read from the value's prefix ([`FilePrefix::group_at`]); 0 without one.
    pub group: u64,
    pub size: u64,
    pub mime: String,
}

impl Entity for AttachmentMeta {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The carrier of a table of JSON rows whose shape the library does not know: the table exists and
/// its rows are the JSON of the source, as they are.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRow {
    pub id: String,
}

impl Entity for JsonRow {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// What the table to move holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    /// Number keys; each value is the bytes of one file, after the prefix [`Options::prefix`]
    /// describes when there is one. Moved to attachments.
    #[default]
    Attachments,
    /// Number or text keys; each value is JSON (as text or bytes). Moved inline, as it is.
    Json,
}

/// A fixed-size prefix that some tables of files put before each file. A value whose first byte
/// is `marker` and that is at least `len` bytes long has the prefix; the file starts after it, or
/// at the first known file signature in the next 64 bytes when one is there (padding is skipped).
/// Any other value is the file itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilePrefix {
    /// The first byte of a value that has the prefix.
    pub marker: u8,
    /// The length of the prefix in bytes, `marker` included. At least 1.
    pub len: usize,
    /// Where, inside the prefix, a little-endian 32-bit number sits that is kept as
    /// [`AttachmentMeta::group`]. `None`: the group is 0.
    pub group_at: Option<usize>,
}

/// How a scan, a stream or a check is done.
#[derive(Clone, Debug)]
pub struct Options {
    pub kind: Kind,
    /// Attachments: the prefix the values of the table carry before each file. `None` (the
    /// default): every value is the file itself.
    pub prefix: Option<FilePrefix>,
    /// Rows committed together.
    pub max_rows: usize,
    /// Cache of the source file's reader. The default of the reader is far larger than needed.
    pub source_cache_bytes: usize,
    /// Stop after this many rows (for a trial).
    pub limit: Option<u64>,
    /// In a scan: also look for a file signature in the whole of a value that shows none near its
    /// start (reads every byte of those values).
    pub deep_signature_check: bool,
    /// In a scan: list every table of the file with its types and sizes ([`Report::tables`]).
    pub inventory: bool,
    /// In a scan: open the copy normally once first, so that redb repairs it if it was not closed
    /// cleanly ([`Report::repair_seconds`]).
    pub repair: bool,
    /// In a stream: the free memory the run may count on. The run is refused when the memory it is
    /// expected to need, plus `reserve_memory`, is more. Required for a source of 1 GiB or more.
    pub free_memory: Option<u64>,
    pub reserve_memory: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            kind: Kind::Attachments,
            prefix: None,
            max_rows: 1000,
            source_cache_bytes: 64 * 1024 * 1024,
            limit: None,
            deep_signature_check: false,
            inventory: false,
            repair: false,
            free_memory: None,
            reserve_memory: 4 << 30,
        }
    }
}

/// One table of an external file: its types, and what its rows are made of. Counts only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TableInventory {
    pub name: String,
    /// The type names redb records for the key and the value (`u64`, `&str`, `String`, ...).
    pub key_type: String,
    pub value_type: String,
    pub rows: u64,
    pub key_bytes: u64,
    pub value_bytes: u64,
    pub smallest_value: u64,
    pub largest_value: u64,
    /// Values that start with the marker of [`Options::prefix`] (0 when no prefix is given).
    pub prefix_marker: u64,
    /// Values that are valid JSON, and values that are valid UTF-8 text.
    pub valid_json: u64,
    pub valid_utf8: u64,
    /// Why the rows were not read (a type this cannot read, or a multimap table).
    pub note: String,
}

/// What a scan, a stream or a check found. Counts, sizes and fingerprints only; the fields a step
/// does not fill stay zero.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    // the table
    pub rows: u64,
    pub value_bytes: u64,
    pub payload_bytes: u64,
    pub smallest_value: u64,
    pub largest_value: u64,
    /// Attachments: rows whose value has no prefix (kept whole, as a file), and rows whose payload
    /// starts with no known file signature.
    pub without_prefix: u64,
    pub without_signature: u64,
    /// With `deep_signature_check`: of the rows without a signature near the start, those that
    /// show one further in (found by looking through the whole value), and those that show none.
    pub late_signature: u64,
    pub no_signature_anywhere: u64,
    pub mimes: BTreeMap<String, u64>,
    /// Json: rows that are not valid JSON.
    pub invalid_json: u64,
    // scan options
    pub repair_seconds: Option<f64>,
    pub tables: Vec<TableInventory>,
    // stream
    pub batches: u64,
    /// Time spent writing the files of the attachments (each flushed to disk), and committing the rows.
    pub files_nanos: u128,
    pub commit_nanos: u128,
    /// The memory a stream was expected to need at most.
    pub expected_peak_bytes: u64,
    // check
    /// The check was of attachments (so the attachments of the target are counted too).
    pub attachments: bool,
    pub target_rows: u64,
    pub target_attachments: u64,
    pub checked: u64,
    pub missing: u64,
    pub different: u64,
    /// The sum of a fingerprint of every row (its key and the hash of its content), taken on the
    /// source side and on the target side. Equal when every row is there with the same bytes.
    pub source_fingerprint: u128,
    pub target_fingerprint: u128,
}

impl Report {
    /// For a check: every source row is in the target with the same bytes, and nothing else is.
    pub fn is_equal(&self) -> bool {
        self.missing == 0
            && self.different == 0
            && self.rows == self.target_rows
            && (!self.attachments || self.rows == self.target_attachments)
            && self.checked == self.rows
            && self.source_fingerprint == self.target_fingerprint
    }
}

fn bad(why: impl Into<String>) -> ClError {
    ClError::MigrationError(why.into())
}

fn io(e: impl std::fmt::Display) -> ClError {
    ClError::MigrationError(e.to_string())
}

fn open_source(path: &Path, cache: usize) -> Result<redb::ReadOnlyDatabase> {
    redb::Database::builder().set_cache_size(cache).open_read_only(path).map_err(|e| match e {
        redb::DatabaseError::RepairAborted => bad(format!(
            "{}: the file needs repair; repair the copy first (it is never repaired while it is read)",
            path.display()
        )),
        e => io(e),
    })
}

/// Open a copy normally once, so that redb repairs it if it was not closed cleanly. Returns the
/// seconds it took. It opens the file for writing: only for a copy.
fn repair(path: &Path, cache_bytes: usize) -> Result<f64> {
    let start = std::time::Instant::now();
    let db = redb::Database::builder().set_cache_size(cache_bytes).open(path).map_err(io)?;
    drop(db);
    Ok(start.elapsed().as_secs_f64())
}

/// A value of the attachments table split into its parts.
struct Split<'a> {
    group: u64,
    payload: &'a [u8],
    mime: &'static str,
    /// The length of the prefix the value had; 0 without one.
    prefix_len: usize,
    known: bool,
}

fn sniff(payload: &[u8]) -> Option<&'static str> {
    let head = &payload[..payload.len().min(SIGNATURE_WINDOW)];
    let found = SIGNATURES.iter().find(|(sig, _)| head.starts_with(sig)).map(|(_, mime)| *mime);
    // a container of the RIFF family is an image only when it says WEBP
    if found == Some("image/webp") && !(head.len() >= 12 && &head[8..12] == b"WEBP") {
        return Some("application/octet-stream");
    }
    found
}

/// The prefix of `raw`, if it has the one `prefix` describes, with the group number read from it.
fn prefix_of(raw: &[u8], prefix: Option<&FilePrefix>) -> Option<(usize, u64)> {
    let p = prefix?;
    if p.len == 0 || raw.len() < p.len || raw[0] != p.marker {
        return None;
    }
    let group = match p.group_at {
        Some(at) if at + 4 <= p.len => u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]) as u64,
        _ => 0,
    };
    Some((p.len, group))
}

fn split<'a>(raw: &'a [u8], prefix: Option<&FilePrefix>) -> Split<'a> {
    if let Some((len, group)) = prefix_of(raw, prefix) {
        let window = &raw[len..raw.len().min(len + SIGNATURE_WINDOW)];
        let offset = SIGNATURES
            .iter()
            .filter_map(|(sig, _)| window.windows(sig.len()).position(|w| w == *sig))
            .min()
            .map(|p| p + len);
        return match offset {
            Some(at) => {
                let payload = &raw[at..];
                Split { group, payload, mime: sniff(payload).unwrap_or("application/octet-stream"), prefix_len: len, known: true }
            }
            None => Split { group, payload: &raw[len..], mime: "application/octet-stream", prefix_len: len, known: false },
        };
    }
    match sniff(raw) {
        Some(mime) => Split { group: 0, payload: raw, mime, prefix_len: 0, known: true },
        None => Split { group: 0, payload: raw, mime: "application/octet-stream", prefix_len: 0, known: false },
    }
}

/// A number from a row's key and the hash of its content; rows add up, in any order.
fn fingerprint(key: &str, content_hash: &blake3::Hash) -> u128 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(key.len() as u64).to_le_bytes());
    hasher.update(key.as_bytes());
    hasher.update(content_hash.as_bytes());
    let out = hasher.finalize();
    u128::from_le_bytes(out.as_bytes()[..16].try_into().expect("16 bytes"))
}

/// Reads every row of a table of the given types, calling `tally(key_length, value_bytes)`.
macro_rules! walk {
    ($read:expr, $name:expr, $K:ty, $V:ty, $tally:ident, |$k:ident| $klen:expr, |$v:ident| $vbytes:expr) => {{
        for row in $read.open_table(TableDefinition::<$K, $V>::new($name)).map_err(io)?.iter().map_err(io)? {
            let (k, v) = row.map_err(io)?;
            let ($k, $v) = (k.value(), v.value());
            $tally($klen, $vbytes);
        }
    }};
}

/// Reads every row of a table of the given types, calling `f(key_as_text, value_bytes)`.
macro_rules! each {
    ($read:expr, $name:expr, $K:ty, $V:ty, $f:ident, |$v:ident| $vbytes:expr) => {{
        for row in $read.open_table(TableDefinition::<$K, $V>::new($name)).map_err(io)?.iter().map_err(io)? {
            let (k, v) = row.map_err(io)?;
            let $v = v.value();
            $f(k.value().to_string(), $vbytes)?;
        }
    }};
}

/// The type names redb records for a table.
fn table_types(read: &redb::ReadTransaction, name: &str) -> Result<(String, String)> {
    // opening with other types fails and tells which types the table has
    match read.open_table(TableDefinition::<u8, u8>::new(name)) {
        Err(redb::TableError::TableTypeMismatch { key, value, .. }) => Ok((key.name().to_string(), value.name().to_string())),
        Ok(_) => Ok(("u8".into(), "u8".into())),
        Err(e) => Err(io(e)),
    }
}

/// Call `f(key_as_text, value_bytes)` for every row, in the order of the table, one at a time.
/// Keys: numbers or text. Values: text or bytes. An error from `f` ends the walk.
fn for_each_row(read: &redb::ReadTransaction, name: &str, f: &mut dyn FnMut(String, &[u8]) -> Result<()>) -> Result<()> {
    let (kt, vt) = table_types(read, name)?;
    match (kt.as_str(), vt.as_str()) {
        ("u64", "&[u8]") => each!(read, name, u64, &[u8], f, |v| &v[..]),
        ("u64", "Vec<u8>") => each!(read, name, u64, Vec<u8>, f, |v| &v[..]),
        ("u64", "&str") => each!(read, name, u64, &str, f, |v| v.as_bytes()),
        ("u64", "String") => each!(read, name, u64, String, f, |v| v.as_bytes()),
        ("&str", "&[u8]") => each!(read, name, &str, &[u8], f, |v| &v[..]),
        ("&str", "Vec<u8>") => each!(read, name, &str, Vec<u8>, f, |v| &v[..]),
        ("&str", "&str") => each!(read, name, &str, &str, f, |v| v.as_bytes()),
        ("&str", "String") => each!(read, name, &str, String, f, |v| v.as_bytes()),
        ("String", "&[u8]") => each!(read, name, String, &[u8], f, |v| &v[..]),
        ("String", "Vec<u8>") => each!(read, name, String, Vec<u8>, f, |v| &v[..]),
        ("String", "&str") => each!(read, name, String, &str, f, |v| v.as_bytes()),
        ("String", "String") => each!(read, name, String, String, f, |v| v.as_bytes()),
        // a counter becomes a row `{"value":n}`
        ("&str", "u64") => each!(read, name, &str, u64, f, |v| format!("{{\"value\":{v}}}").as_bytes()),
        ("String", "u64") => each!(read, name, String, u64, f, |v| format!("{{\"value\":{v}}}").as_bytes()),
        ("u64", "u64") => each!(read, name, u64, u64, f, |v| format!("{{\"value\":{v}}}").as_bytes()),
        _ => return Err(bad(format!("the table has types this tool does not read ({kt} / {vt}); nothing was changed"))),
    }
    Ok(())
}

/// [`for_each_row`] that ends quietly when `f` fails with [`STOPPED`] (the limit was reached).
fn walk_until_stopped(read: &redb::ReadTransaction, name: &str, f: &mut dyn FnMut(String, &[u8]) -> Result<()>) -> Result<()> {
    match for_each_row(read, name, f) {
        Err(ClError::MigrationError(m)) if m == STOPPED => Ok(()),
        other => other,
    }
}

fn is_json(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok()
}

/// List every table of the file with its types and, for the types it can read, the sizes of its
/// rows, one row at a time.
fn inventory(read: &redb::ReadTransaction, marker: Option<u8>) -> Result<Vec<TableInventory>> {
    let mut names: Vec<String> = read.list_tables().map_err(io)?.map(|t| t.name().to_string()).collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let mut item = TableInventory { name: name.clone(), smallest_value: u64::MAX, ..Default::default() };
        match table_types(read, &name) {
            Ok((k, v)) => {
                item.key_type = k;
                item.value_type = v;
            }
            Err(e) => {
                item.note = format!("not opened: {e}");
                out.push(item);
                continue;
            }
        }
        let (kt, vt) = (item.key_type.clone(), item.value_type.clone());
        let mut tally = |key_len: u64, value: &[u8]| {
            item.rows += 1;
            item.key_bytes += key_len;
            item.value_bytes += value.len() as u64;
            item.smallest_value = item.smallest_value.min(value.len() as u64);
            item.largest_value = item.largest_value.max(value.len() as u64);
            item.prefix_marker += u64::from(marker.is_some() && value.first() == marker.as_ref());
            item.valid_utf8 += u64::from(std::str::from_utf8(value).is_ok());
            item.valid_json += u64::from(is_json(value));
        };
        match (kt.as_str(), vt.as_str()) {
            ("u64", "&[u8]") => walk!(read, &name, u64, &[u8], tally, |_k| 8u64, |v| &v[..]),
            ("u64", "Vec<u8>") => walk!(read, &name, u64, Vec<u8>, tally, |_k| 8u64, |v| &v[..]),
            ("u64", "&str") => walk!(read, &name, u64, &str, tally, |_k| 8u64, |v| v.as_bytes()),
            ("u64", "String") => walk!(read, &name, u64, String, tally, |_k| 8u64, |v| v.as_bytes()),
            ("&str", "&[u8]") => walk!(read, &name, &str, &[u8], tally, |k| k.len() as u64, |v| &v[..]),
            ("&str", "Vec<u8>") => walk!(read, &name, &str, Vec<u8>, tally, |k| k.len() as u64, |v| &v[..]),
            ("&str", "&str") => walk!(read, &name, &str, &str, tally, |k| k.len() as u64, |v| v.as_bytes()),
            ("&str", "String") => walk!(read, &name, &str, String, tally, |k| k.len() as u64, |v| v.as_bytes()),
            ("String", "&[u8]") => walk!(read, &name, String, &[u8], tally, |k| k.len() as u64, |v| &v[..]),
            ("String", "Vec<u8>") => walk!(read, &name, String, Vec<u8>, tally, |k| k.len() as u64, |v| &v[..]),
            ("String", "&str") => walk!(read, &name, String, &str, tally, |k| k.len() as u64, |v| v.as_bytes()),
            ("String", "String") => walk!(read, &name, String, String, tally, |k| k.len() as u64, |v| v.as_bytes()),
            ("&str", "u64") => walk!(read, &name, &str, u64, tally, |k| k.len() as u64, |v| &v.to_le_bytes()[..]),
            ("String", "u64") => walk!(read, &name, String, u64, tally, |k| k.len() as u64, |v| &v.to_le_bytes()[..]),
            ("u64", "u64") => walk!(read, &name, u64, u64, tally, |_k| 8u64, |v| &v.to_le_bytes()[..]),
            _ => item.note = "rows not read: a type this tool does not read".into(),
        }
        if item.rows == 0 {
            item.smallest_value = 0;
        }
        out.push(item);
    }
    for name in read.list_multimap_tables().map_err(io)?.map(|t| t.name().to_string()) {
        out.push(TableInventory { name, note: "multimap table: not read".into(), ..Default::default() });
    }
    Ok(out)
}

/// Count the rows and sizes of one table, one row at a time (nothing is loaded).
fn scan_table(read: &redb::ReadTransaction, table: &str, options: &Options, report: &mut Report) -> Result<()> {
    report.smallest_value = u64::MAX;
    match options.kind {
        Kind::Attachments => {
            // the table is opened with the types it declares (a key of numbers or of text, a value
            // of `&[u8]` or `Vec<u8>`), never read as another type
            let limit = options.limit;
            walk_until_stopped(read, table, &mut |_, raw| {
                let parts = split(raw, options.prefix.as_ref());
                report.rows += 1;
                report.value_bytes += raw.len() as u64;
                report.payload_bytes += parts.payload.len() as u64;
                report.smallest_value = report.smallest_value.min(raw.len() as u64);
                report.largest_value = report.largest_value.max(raw.len() as u64);
                report.without_prefix += u64::from(parts.prefix_len == 0);
                report.without_signature += u64::from(!parts.known);
                if options.deep_signature_check && !parts.known {
                    let from = parts.prefix_len;
                    let anywhere = raw.len() > from && SIGNATURES.iter().any(|(sig, _)| raw[from..].windows(sig.len()).any(|w| w == *sig));
                    report.late_signature += u64::from(anywhere);
                    report.no_signature_anywhere += u64::from(!anywhere);
                }
                *report.mimes.entry(parts.mime.to_string()).or_default() += 1;
                if limit.is_some_and(|n| report.rows >= n) {
                    return Err(bad(STOPPED));
                }
                Ok(())
            })?;
        }
        Kind::Json => {
            let limit = options.limit;
            walk_until_stopped(read, table, &mut |_, value| {
                report.rows += 1;
                report.value_bytes += value.len() as u64;
                report.payload_bytes += value.len() as u64;
                report.smallest_value = report.smallest_value.min(value.len() as u64);
                report.largest_value = report.largest_value.max(value.len() as u64);
                report.invalid_json += u64::from(!is_json(value));
                if limit.is_some_and(|n| report.rows >= n) {
                    return Err(bad(STOPPED));
                }
                Ok(())
            })?;
        }
    }
    if report.rows == 0 {
        report.smallest_value = 0;
    }
    Ok(())
}

/// The memory a stream is expected to need at most: the source cache, two copies of the largest
/// value (the reader's and the writer's piece), and a margin.
fn expected_peak(options: &Options, largest_value: u64) -> u64 {
    options.source_cache_bytes as u64 + 2 * largest_value + 2 * 1024 * 1024
}

/// The rule for starting a large run: the expected peak plus the memory to keep must be within the
/// free memory. The free memory is told by the caller (the library does not ask the system).
fn gate(expected_peak: u64, free_memory: u64, reserve_bytes: u64) -> Result<()> {
    if expected_peak.saturating_add(reserve_bytes) > free_memory {
        return Err(bad(format!(
            "the run needs about {expected_peak} bytes of memory and only {free_memory} are free with {reserve_bytes} to keep; it was not started"
        )));
    }
    Ok(())
}

/// Look at a source: repair the copy ([`Options::repair`]), list the tables of the file
/// ([`Options::inventory`]), and measure one `table` (leave it empty to look at the tables only).
pub fn scan(source: &Path, table: &str, options: &Options) -> Result<Report> {
    let mut report = Report::default();
    if options.repair {
        report.repair_seconds = Some(repair(source, options.source_cache_bytes)?);
    }
    let db = open_source(source, options.source_cache_bytes)?;
    let read = db.begin_read().map_err(io)?;
    if options.inventory {
        report.tables = inventory(&read, options.prefix.map(|p| p.marker))?;
    }
    if !table.is_empty() {
        scan_table(&read, table, options, &mut report)?;
    }
    Ok(report)
}

struct Pending {
    id: String,
    /// Attachments: the reference of the file. Json: none.
    reference: Option<journal_blob::BlobRef>,
    /// Attachments: the small row. Json: the row, as it is.
    row: Vec<u8>,
}

/// Move the table `source_table` of the copy into `table` of database `db` of `storage`, with the
/// rows committed in batches of `options.max_rows` rows (and no more than 8 MiB). Attachments go to
/// a table with attachments whose rows are [`AttachmentMeta`]; JSON rows go to any table, as they
/// are, keyed by the key of the source (a number as text). A source of 1 GiB or more is refused
/// unless `options.free_memory` is told and the run fits in it. `progress` is called after each
/// batch.
pub fn stream(
    source: &Path,
    source_table: &str,
    storage: &Storage,
    db: &str,
    table: &str,
    options: &Options,
    progress: &mut dyn FnMut(&Report),
) -> Result<Report> {
    if options.max_rows == 0 {
        return Err(bad("a batch needs at least one row"));
    }
    let manager = storage.db_manager(db);
    if options.kind == Kind::Attachments && !manager.is_blob_table(table) {
        return Err(bad("the target table is not a table with attachments"));
    }
    let mut report = Report::default();
    let file_size = std::fs::metadata(source).map_err(io)?.len();
    match options.free_memory {
        Some(free) => {
            let src = open_source(source, options.source_cache_bytes)?;
            let read = src.begin_read().map_err(io)?;
            let mut found = Report::default();
            scan_table(&read, source_table, &Options { deep_signature_check: false, ..options.clone() }, &mut found)?;
            report.expected_peak_bytes = expected_peak(options, found.largest_value);
            gate(report.expected_peak_bytes, free, options.reserve_memory)?;
        }
        None if file_size >= NEEDS_GATE => {
            return Err(bad("this source is 1 GiB or more: tell the free memory the run may count on; it was not started"));
        }
        None => {}
    }
    let src = open_source(source, options.source_cache_bytes)?;
    let read = src.begin_read().map_err(io)?;
    let mut batch: Vec<Pending> = Vec::new();
    let mut batch_bytes = 0usize;
    let flush = |batch: &mut Vec<Pending>, report: &mut Report| -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let clock = std::time::Instant::now();
        manager.journal_write(|tx, changes| {
            for p in batch.iter() {
                if let Some(reference) = &p.reference {
                    journal_blob::put(tx, table, &p.id, reference, changes)?;
                }
                tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?.insert(p.id.as_str(), p.row.as_slice())?;
                changes.push(ChangeKind::Upsert { table: table.into(), key: p.id.clone(), value: p.row.clone() });
            }
            Ok(())
        })?;
        report.commit_nanos += clock.elapsed().as_nanos();
        report.batches += 1;
        batch.clear();
        Ok(())
    };
    let (limit, max_rows, kind) = (options.limit, options.max_rows, options.kind);
    walk_until_stopped(&read, source_table, &mut |key: String, raw: &[u8]| -> Result<()> {
        match kind {
            Kind::Attachments => {
                let parts = split(raw, options.prefix.as_ref());
                // the bytes go to the file of the attachment as they are, never through JSON
                let clock = std::time::Instant::now();
                let reference = manager.prepare_blob(table, &key, parts.payload)?;
                report.files_nanos += clock.elapsed().as_nanos();
                let meta = serde_json::to_vec(&AttachmentMeta {
                    id: key.clone(),
                    group: parts.group,
                    size: parts.payload.len() as u64,
                    mime: parts.mime.to_string(),
                })?;
                report.payload_bytes += parts.payload.len() as u64;
                report.without_prefix += u64::from(parts.prefix_len == 0);
                report.without_signature += u64::from(!parts.known);
                batch_bytes += meta.len();
                batch.push(Pending { id: key, reference: Some(reference), row: meta });
            }
            Kind::Json => {
                if !is_json(raw) {
                    return Err(bad("a row of the source is not valid JSON; nothing was changed in it"));
                }
                report.payload_bytes += raw.len() as u64;
                batch_bytes += raw.len();
                batch.push(Pending { id: key, reference: None, row: raw.to_vec() });
            }
        }
        report.rows += 1;
        report.largest_value = report.largest_value.max(raw.len() as u64);
        if batch.len() >= max_rows || batch_bytes >= BATCH_BYTES {
            flush(&mut batch, &mut report)?;
            batch_bytes = 0;
            progress(&report);
        }
        if limit.is_some_and(|n| report.rows >= n) {
            return Err(bad(STOPPED));
        }
        Ok(())
    })?;
    flush(&mut batch, &mut report)?;
    progress(&report);
    Ok(report)
}

/// Check every row (not a sample): each source row against the row, or the attachment, now in the
/// database, byte for byte by hash, and the counts on both sides.
pub fn verify(source: &Path, source_table: &str, storage: &Storage, db: &str, table: &str, options: &Options) -> Result<Report> {
    let manager = storage.db_manager(db);
    let src = open_source(source, options.source_cache_bytes)?;
    let read = src.begin_read().map_err(io)?;
    let mut report = Report {
        target_rows: manager.count_keys(table)? as u64,
        attachments: options.kind == Kind::Attachments,
        ..Default::default()
    };
    let db_ref = manager.db()?;
    let target = db_ref.begin_read()?;
    if report.attachments {
        for entry in target.open_table(REFS)?.iter()? {
            let (k, _) = entry?;
            let (t, _): (String, String) = serde_json::from_str(k.value())?;
            report.target_attachments += u64::from(t == table);
        }
    }
    let rows = target.open_table(TableDefinition::<&str, &[u8]>::new(table))?;
    let mut buf = vec![0u8; 64 * 1024];
    let (kind, limit) = (options.kind, options.limit);
    walk_until_stopped(&read, source_table, &mut |key: String, raw: &[u8]| -> Result<()> {
        let content: &[u8] = if kind == Kind::Attachments { split(raw, options.prefix.as_ref()).payload } else { raw };
        let source_hash = blake3::hash(content);
        report.rows += 1;
        report.source_fingerprint = report.source_fingerprint.wrapping_add(fingerprint(&key, &source_hash));
        let (hash, total) = match kind {
            Kind::Attachments => {
                let Ok(mut blob) = manager.open_current_blob(table, &key) else {
                    report.missing += 1;
                    return Ok(());
                };
                let mut hasher = blake3::Hasher::new();
                let mut total = 0u64;
                loop {
                    let n = blob.read(&mut buf).map_err(io)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                    total += n as u64;
                }
                (hasher.finalize(), total)
            }
            Kind::Json => match rows.get(key.as_str())? {
                Some(found) => (blake3::hash(found.value()), found.value().len() as u64),
                None => {
                    report.missing += 1;
                    return Ok(());
                }
            },
        };
        report.checked += 1;
        if total != content.len() as u64 || hash != source_hash {
            report.different += 1;
        } else {
            report.target_fingerprint = report.target_fingerprint.wrapping_add(fingerprint(&key, &hash));
        }
        if limit.is_some_and(|n| report.rows >= n) {
            return Err(bad(STOPPED));
        }
        Ok(())
    })?;
    Ok(report)
}
