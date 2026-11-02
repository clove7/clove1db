//! Value-free library diagnostics. Applications choose where to send events.
use crate::query::optimizer::Plan;
use std::{sync::Arc, time::Duration};
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum LibraryEvent {
    Index {event:&'static str,generation:u64,fingerprint:u64,rows:u64,bytes:u64,elapsed:Duration},
    Query {
        plan: Plan,
        estimated_rows: f64,
        actual_rows: u64,
        bytes: u64,
        elapsed: Duration,
        fingerprint: u64,
    },
    SlowQuery {
        plan: Plan,
        estimated_rows: f64,
        actual_rows: u64,
        elapsed: Duration,
        fingerprint: u64,
    },
    NonUnique {
        count: u64,
        fingerprint: u64,
    },
    ConsumerExpired {
        name: String,
        last_acked_seq: u64,
    },
    IndexRebuildRequired {
        name: String,
        last_acked_seq: u64,
    },
    /// Tables the database file did not have were created empty at open, because
    /// `DatabaseConfig::create_missing_tables` was set. The names are here so that a misspelled table
    /// shows in the log. Never carries a value.
    TablesCreated { database: String, tables: Vec<String> },
    /// Something about an encrypted file happened. `event` is one of a fixed list
    /// (`encryption/open_failed/<reason>`, `encryption/index_rebuilt`,
    /// `encryption/sidecar_set_aside`, `encryption/cleanup_failed`); `file` is `main`, `bak`,
    /// `index` or `sidecar`. It never carries a key, anything derived from a key, data, a table
    /// name or a path.
    Encryption { event: &'static str, file: &'static str },
    /// A change of how the database is protected reached a stage. `event` is one of a fixed list
    /// (`migration/started`, `migration/committed`, `migration/finished`, `migration/rolled_back`,
    /// `migration/recovered`); `files` is how many files or folders it replaces and `rows` how many
    /// rows it has copied so far. It never carries a key, a value, a table name or a path.
    Migration { event: &'static str, files: u32, rows: u64 },
    /// A protected value was opened with a read grant (or opening it was tried). It says where the
    /// value is: the table, the field (name and number) and the key of the row, and when. It never
    /// carries the value or anything derived from it. The sink receives row keys, so an application
    /// that sends events to a shared log should treat them as it treats the rows themselves.
    FieldRead {
        table: String,
        field: String,
        field_id: u32,
        row: String,
        at: std::time::SystemTime,
    },
    /// A secret was checked against a stored verification hash. It says where the hash is, whether
    /// the secret matched, and when; never the secret. A run of `matched: false` for one row is
    /// what guessing looks like. Like [`LibraryEvent::FieldRead`] it carries names and the row key.
    HashVerify {
        table: String,
        field: String,
        field_id: u32,
        row: String,
        matched: bool,
        at: std::time::SystemTime,
    },
    /// A search for a piece of a protected value was confirmed inside the library: the candidates
    /// the part fingerprints gave were opened to see whether they really contain the text. One event
    /// for the whole search, not one per value. It says where the field is, how many candidates were
    /// looked at, how many were opened and how many matched, and when; never a value and never the
    /// text searched for. `rows` holds the keys of the rows that were opened only when the search
    /// asked for it (`PartSearch::report_rows`); it is `None` otherwise.
    FieldConfirm {
        table: String,
        field: String,
        field_id: u32,
        candidates: u64,
        opened: u64,
        matched: u64,
        rows: Option<Vec<String>>,
        at: std::time::SystemTime,
    },
    /// A slow scan of a protected field was made (`PrintHandle::scan_sealed`): the field of every row
    /// the ordinary conditions left was opened inside the library. One event for the whole scan, not
    /// one per value, also when the scan failed half-way. It says where the field is, how many rows
    /// were looked at, how many were opened, how many the scan kept, and when; never a value and never
    /// the condition. `rows` holds the keys of the rows that were opened only when the scan asked for
    /// it (`SealedScan::report_rows`); it is `None` otherwise. A scan of an empty table sends none.
    FieldScan {
        table: String,
        field: String,
        field_id: u32,
        scanned: u64,
        opened: u64,
        matched: u64,
        rows: Option<Vec<String>>,
        at: std::time::SystemTime,
    },
}
type Callback = dyn Fn(&LibraryEvent) + Send + Sync;
#[derive(Clone, Default)]
pub(crate) struct EventSink(pub Option<Arc<Callback>>);
impl std::fmt::Debug for EventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSink")
            .field("configured", &self.0.is_some())
            .finish()
    }
}
impl EventSink {
    pub fn emit(&self, event: &LibraryEvent) {
        if let Some(sink) = &self.0 {
            sink(event)
        }
    }
}
