//! Durable per-database change sequence. Journal rows are not backup history.
use crate::{
    fsutil::maybe_crash,
    handle::DbRef,
    units::{ClError, Result},
};
use redb::{ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};

pub(crate) const SEQ: TableDefinition<&str, &[u8]> = TableDefinition::new("__seq");
pub(crate) const CHANGES: TableDefinition<u64, &[u8]> = TableDefinition::new("__changes");
pub(crate) const CONSUMERS: TableDefinition<&str, &[u8]> = TableDefinition::new("__consumers");

/// One committed effect, ordered by its per-database sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub seq: u64,
    pub kind: ChangeKind,
}
/// After-images are exact stored bytes, not parsed and re-serialized JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeKind {
    Upsert {
        table: String,
        key: String,
        value: Vec<u8>,
    },
    Delete {
        table: String,
        key: String,
    },
    TableReset {
        table: String,
        snapshot: String,
    },
    BlobPut {
        table: String,
        key: String,
        blob_id: String,
        size: u64,
    },
    BlobDelete {
        table: String,
        key: String,
        blob_id: String,
        size: u64,
    },
}
impl ChangeKind {
    fn parts(&self) -> (u8, &str, &str, &[u8], u64) {
        match self {
            Self::Upsert { table, key, value } => (0, table, key, value, 0),
            Self::Delete { table, key } => (1, table, key, &[], 0),
            Self::TableReset { table, snapshot } => (2, table, "", snapshot.as_bytes(), 0),
            Self::BlobPut {
                table,
                key,
                blob_id,
                size,
            } => (3, table, key, blob_id.as_bytes(), *size),
            Self::BlobDelete {
                table,
                key,
                blob_id,
                size,
            } => (4, table, key, blob_id.as_bytes(), *size),
        }
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let (tag, table, key, payload, size) = self.parts();
        let mut bytes = crate::memory::vec_with_capacity(
            "journal.encode_row",
            2 + 3 * 8 + table.len() + key.len() + payload.len() + 8,
        )?;
        bytes.extend_from_slice(&[1, tag]);
        for part in [table.as_bytes(), key.as_bytes(), payload] {
            let len = u64::try_from(part.len())
                .map_err(|_| ClError::Validation("journal row too large".into()))?;
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(part);
        }
        bytes.extend_from_slice(&size.to_be_bytes());
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        fn bad() -> ClError {
            ClError::Validation("corrupt or unsupported journal row".into())
        }
        fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            if bytes.len() < n {
                return Err(bad());
            }
            let (a, b) = bytes.split_at(n);
            *bytes = b;
            Ok(a)
        }
        fn number(bytes: &mut &[u8]) -> Result<u64> {
            Ok(u64::from_be_bytes(
                take(bytes, 8)?.try_into().map_err(|_| bad())?,
            ))
        }
        fn part<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
            let len = usize::try_from(number(bytes)?).map_err(|_| bad())?;
            take(bytes, len)
        }
        let mut bytes = bytes;
        if take(&mut bytes, 1)? != [1] {
            return Err(bad());
        }
        let tag = take(&mut bytes, 1)?[0];
        let table = String::from_utf8(part(&mut bytes)?.to_vec()).map_err(|_| bad())?;
        let key = String::from_utf8(part(&mut bytes)?.to_vec()).map_err(|_| bad())?;
        let payload = crate::memory::copy_bytes("journal.read_rows", part(&mut bytes)?)?;
        let size = number(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(bad());
        }
        Ok(match tag {
            0 => Self::Upsert {
                table,
                key,
                value: payload,
            },
            1 => Self::Delete { table, key },
            2 => Self::TableReset {
                table,
                snapshot: String::from_utf8(payload).map_err(|_| bad())?,
            },
            3 => Self::BlobPut {
                table,
                key,
                blob_id: String::from_utf8(payload).map_err(|_| bad())?,
                size,
            },
            4 => Self::BlobDelete {
                table,
                key,
                blob_id: String::from_utf8(payload).map_err(|_| bad())?,
                size,
            },
            _ => return Err(bad()),
        })
    }
}
pub(crate) fn validate_table(name: &str) -> Result<()> {
    if name.starts_with("__") {
        return Err(ClError::Validation("table prefix __ is reserved".into()));
    }
    Ok(())
}
pub(crate) fn read_number(tx: &redb::ReadTransaction, key: &str) -> Result<u64> {
    let t = tx.open_table(SEQ)?;
    let v = t
        .get(key)?
        .ok_or_else(|| ClError::Validation("missing journal metadata".into()))?;
    Ok(u64::from_be_bytes(v.value().try_into().map_err(|_| {
        ClError::Validation("corrupt journal metadata".into())
    })?))
}
pub(crate) fn number(tx: &WriteTransaction, key: &str) -> Result<u64> {
    let t = tx.open_table(SEQ)?;
    let v = t
        .get(key)?
        .ok_or_else(|| ClError::Validation("missing journal metadata".into()))?;
    Ok(u64::from_be_bytes(v.value().try_into().map_err(|_| {
        ClError::Validation("corrupt journal metadata".into())
    })?))
}
pub(crate) fn put_number(tx: &WriteTransaction, key: &str, value: u64) -> Result<()> {
    tx.open_table(SEQ)?
        .insert(key, value.to_be_bytes().as_slice())?;
    Ok(())
}
/// Key of `__seq` that says attachment files written by a version without references may be in the
/// folders of this database. It is written with the log itself (see [`mark_adoption_due`]) and never removed.
pub(crate) const ADOPTION_DUE: &str = "blob_adopt_due";
/// Prefix of the keys of `__seq` that record, one per attachment table, that the old files of the table
/// were adopted: `blob_adopted:{table}`.
pub(crate) const ADOPTED_PREFIX: &str = "blob_adopted:";
/// Called just before [`initialize`] when a database is opened. A database that has no log yet was made by
/// a version that kept no references (or is new), so the files it left in attachment folders are
/// attachments, not leftovers. This is written in the transaction that creates the log, so no interruption
/// can separate the two; a database whose log already exists never gets it.
pub(crate) fn mark_adoption_due(tx: &WriteTransaction) -> Result<()> {
    let mut t = tx.open_table(SEQ)?;
    if t.get("head")?.is_none() {
        t.insert(ADOPTION_DUE, [1u8].as_slice())?;
    }
    Ok(())
}
pub(crate) fn initialize(tx: &WriteTransaction) -> Result<()> {
    let mut t = tx.open_table(SEQ)?;
    if t.get("head")?.is_none() {
        for (k, v) in [
            ("head", 0u64),
            ("journal_bytes", 0),
            ("floor", 1),
            ("reset_generation", 0),
            ("consumer_generation", 0),
        ] {
            t.insert(k, v.to_be_bytes().as_slice())?;
        }
        t.insert("db_uuid", uuid::Uuid::new_v4().as_bytes().as_slice())?;
    }
    drop(t);
    crate::lastwrite::init(tx)?;
    crate::unique::init(tx)?;
    crate::id_contract::init(tx)?;
    tx.open_table(CHANGES)?;
    tx.open_table(CONSUMERS)?;
    tx.open_table(crate::journal_blob::REFS)?;
    Ok(())
}
// Keep tiny appends on insert: constructing a cursor has a measurable fixed cost.
// Default-sized write batches amortize it and use redb's ordered run buffering.
fn append_effects(
    effects: Vec<ChangeKind>,
    head: &mut u64,
    bytes: &mut u64,
    mut put: impl FnMut(u64, &[u8]) -> Result<()>,
) -> Result<()> {
    for effect in effects {
        *head = head
            .checked_add(1)
            .ok_or_else(|| ClError::Validation("journal sequence exhausted".into()))?;
        let row = effect.encode()?;
        *bytes = bytes
            .checked_add(8 + row.len() as u64)
            .ok_or_else(|| ClError::Validation("journal size overflow".into()))?;
        put(*head, &row)?;
    }
    Ok(())
}
/// The sole owner of user-data write transactions. Failure drops all effects.
#[cfg(test)]
pub(crate) fn write<T>(
    db: &DbRef<'_>,
    retention: Retention,
    f: impl FnOnce(&WriteTransaction, &mut Vec<ChangeKind>) -> Result<T>,
) -> Result<T> {
    write_with_sink(db,retention,&Default::default(),f)
}
pub(crate) fn write_with_sink<T>(db:&DbRef<'_>,retention:Retention,sink:&crate::events::EventSink,f:impl FnOnce(&WriteTransaction,&mut Vec<ChangeKind>)->Result<T>)->Result<T> {
    let tx = db.begin_write()?;
    let mut effects = Vec::new();
    let output = f(&tx, &mut effects)?;
    crate::id_contract::validate(&tx,&effects)?;
    crate::unique::validate(&tx,&effects)?;
    let has_changes = !effects.is_empty();
    let mut head = number(&tx, "head")?;
    let mut bytes = number(&tx, "journal_bytes")?;
    for (i,effect) in effects.iter().enumerate() {
        let seq=head.checked_add(i as u64+1).ok_or_else(||ClError::Validation("sequence exhausted".into()))?;
        crate::lastwrite::apply(&tx,effect,seq)?;
    }
    {
        let mut rows = tx.open_table(CHANGES)?;
        if effects.len() >= crate::DEFAULT_MAX_COMMIT_BATCH_ENTRIES {
            let mut cursor = rows.upper_bound_mut(std::ops::Bound::<u64>::Unbounded)?;
            append_effects(effects, &mut head, &mut bytes, |seq, row| {
                cursor
                    .insert_before(seq, row)
                    .map_err(redb::Error::from)
                    .map_err(Into::into)
            })?;
            maybe_crash("journal_during_append");
            cursor.close()?;
        } else {
            append_effects(effects, &mut head, &mut bytes, |seq, row| {
                rows.insert(seq, row)?;
                Ok(())
            })?;
            if has_changes {
                maybe_crash("journal_during_append");
            }
        }
        let floor = rows
            .first()?
            .map(|(k, _)| k.value())
            .unwrap_or(head.saturating_add(1));
        put_number(&tx, "floor", floor)?;
    }
    put_number(&tx, "head", head)?;
    put_number(&tx, "journal_bytes", bytes)?;
    prune_acked(&tx)?;
    let events = enforce(&tx, retention)?;
    if has_changes {
        maybe_crash("journal_before_commit");
    }
    tx.commit()?;
    if has_changes {
        maybe_crash("journal_after_commit");
    }
    for event in events {sink.emit(&event);}
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codec_exact_and_rejects_damage() {
        for c in [
            ChangeKind::Upsert {
                table: "notes".into(),
                key: "a".into(),
                value: vec![0, 255, 3],
            },
            ChangeKind::Delete {
                table: "notes".into(),
                key: "a".into(),
            },
            ChangeKind::TableReset {
                table: "notes".into(),
                snapshot: "__reset_1".into(),
            },
            ChangeKind::BlobPut {
                table: "notes".into(),
                key: "a".into(),
                blob_id: "v".into(),
                size: 7,
            },
            ChangeKind::BlobDelete {
                table: "notes".into(),
                key: "a".into(),
                blob_id: "v".into(),
                size: 7,
            },
        ] {
            let b = c.encode().unwrap();
            assert_eq!(ChangeKind::decode(&b).unwrap(), c);
            for n in 0..b.len() {
                assert!(ChangeKind::decode(&b[..n]).is_err());
            }
        }
        assert!(validate_table("__hidden").is_err());
        assert!(validate_table("notes").is_ok());
    }
}

/// Default retention is a size budget; backup history is never pruned by it.
pub const DEFAULT_JOURNAL_MAX_BYTES: u64 = 256 * 1024 * 1024;
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Retention {
    Unlimited,
    #[default]
    Default,
    Limit {
        max_bytes: u64,
    },
}
impl Retention {
    fn max(self) -> Option<u64> {
        match self {
            Self::Unlimited => None,
            Self::Default => Some(DEFAULT_JOURNAL_MAX_BYTES),
            Self::Limit { max_bytes } => Some(max_bytes),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsumerToken {
    database_uuid: Vec<u8>,
    name: String,
    generation: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Consumer {
    generation: u64,
    acked_seq: u64,
    registered_at: i64,
    active: bool,
    internal: bool,
    needs_rebuild: bool,
}
/// Metadata from one coherent primary snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalStats {
    pub head: u64,
    pub floor: u64,
    pub journal_bytes: u64,
    pub database_uuid: Vec<u8>,
}
/// A primary read transaction with its sequence read in that same snapshot.
pub struct ReadView {
    pub head: u64,
    pub database_uuid: Vec<u8>,
    pub(crate) tx: redb::ReadTransaction,
}
impl ReadView {
    pub(crate) fn database_uuid(&self)->Result<Vec<u8>> {
        Ok(self.tx.open_table(SEQ)?.get("db_uuid")?.ok_or_else(||ClError::Validation("missing database uuid".into()))?.value().to_vec())
    }
    pub fn get_raw(&self, table: &str, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .tx
            .open_table(TableDefinition::<&str, &[u8]>::new(table))?
            .get(key)?
            .map(|v| v.value().to_vec()))
    }
    /// Immutable file identity in this primary snapshot, not the current one.
    pub fn blob_reference(&self, table: &str, key: &str) -> Result<Option<(String, u64)>> {
        let row = self
            .tx
            .open_table(crate::journal_blob::REFS)?
            .get(crate::journal_blob::key(table, key).as_str())?
            .map(|v| serde_json::from_slice::<crate::journal_blob::BlobRef>(v.value()))
            .transpose()?;
        Ok(row.map(|r| (r.id, r.size)))
    }
    pub fn table_entries(&self, table: &str) -> Result<Vec<(String, Vec<u8>)>> {
        use redb::ReadableTableMetadata;
        let rows = self
            .tx
            .open_table(TableDefinition::<&str, &[u8]>::new(table))?;
        let mut out = crate::memory::vec_with_capacity(
            "journal.table_entries",
            usize::try_from(rows.len()?).unwrap_or(0),
        )?;
        for row in rows.iter()? {
            let (k, v) = row?;
            let value = crate::memory::copy_bytes("journal.table_entries", v.value())?;
            crate::memory::push("journal.table_entries", &mut out, (k.value().into(), value))?;
        }
        Ok(out)
    }
}
fn expired() -> ClError {
    ClError::ConsumerExpired
}
fn check_token(token: &ConsumerToken, uuid: &[u8], consumer: Option<Consumer>) -> Result<Consumer> {
    let c = consumer.ok_or_else(expired)?;
    if token.database_uuid != uuid || token.generation != c.generation || !c.active {
        return Err(expired());
    }
    if c.needs_rebuild {
        return Err(ClError::ConsumerNeedsRebuild);
    }
    Ok(c)
}
fn prune(tx: &WriteTransaction, through: u64) -> Result<()> {
    let mut bytes = number(tx, "journal_bytes")?;
    let mut rows = tx.open_table(CHANGES)?;
    while rows.first()?.is_some_and(|(key, _)| key.value() <= through) {
        let (length, snapshot) = {
            let (_key, value) = rows
                .pop_first()?
                .ok_or_else(|| ClError::Validation("journal row disappeared".into()))?;
            let row = value.value();
            if row.first() != Some(&1) {
                return Err(ClError::Validation("unsupported journal row".into()));
            }
            let snapshot = if row.get(1) == Some(&2) {
                match ChangeKind::decode(row)? {
                    ChangeKind::TableReset { snapshot, .. } => Some(snapshot),
                    _ => None,
                }
            } else {
                None
            };
            (row.len() as u64, snapshot)
        };
        if let Some(snapshot) = snapshot {
            tx.delete_table(TableDefinition::<&str, &[u8]>::new(&snapshot))?;
            tx.delete_table(TableDefinition::<&str, &[u8]>::new(&format!(
                "{snapshot}_blobs"
            )))?;
        }
        bytes = bytes
            .checked_sub(8 + length)
            .ok_or_else(|| ClError::Validation("invalid journal byte accounting".into()))?;
        maybe_crash("journal_during_prune");
    }
    drop(rows);
    put_number(tx, "journal_bytes", bytes)?;
    let floor = tx
        .open_table(CHANGES)?
        .first()?
        .map(|(k, _)| k.value())
        .unwrap_or(number(tx, "head")?.saturating_add(1));
    put_number(tx, "floor", floor)?;
    Ok(())
}
fn consumers(tx: &WriteTransaction) -> Result<Vec<(String, Consumer)>> {
    tx.open_table(CONSUMERS)?
        .iter()?
        .map(|r| {
            let (k, v) = r?;
            Ok((k.value().into(), serde_json::from_slice(v.value())?))
        })
        .collect()
}
fn prune_acked(tx: &WriteTransaction) -> Result<()> {
    let limit = consumers(tx)?
        .iter()
        .filter(|(_, c)| c.active)
        .map(|(_, c)| c.acked_seq)
        .min()
        .unwrap_or(number(tx, "head")?);
    prune(tx, limit)
}
fn enforce(tx: &WriteTransaction, retention: Retention) -> Result<Vec<crate::LibraryEvent>> {
    let Some(max) = retention.max() else {
        return Ok(vec![]);
    };
    let mut events=vec![];
    while number(tx, "journal_bytes")? > max {
        prune_acked(tx)?;
        if number(tx, "journal_bytes")? <= max {
            break;
        }
        let all = consumers(tx)?;
        let min = all
            .iter()
            .filter(|(_, c)| c.active)
            .map(|(_, c)| c.acked_seq)
            .min()
            .unwrap_or(number(tx, "head")?);
        let Some((name, mut oldest)) = all
            .into_iter()
            .filter(|(_, c)| c.active && c.acked_seq == min)
            .min_by_key(|(_, c)| c.generation)
        else {
            return Err(ClError::Validation("journal cannot be pruned".into()));
        };
        if oldest.internal {
            events.push(crate::LibraryEvent::IndexRebuildRequired{name:name.clone(),last_acked_seq:oldest.acked_seq});
            oldest.needs_rebuild = true;
            oldest.acked_seq = number(tx, "head")?;

        } else {
            oldest.active = false;
            events.push(crate::LibraryEvent::ConsumerExpired{name:name.clone(),last_acked_seq:oldest.acked_seq});
        }
        tx.open_table(CONSUMERS)?
            .insert(name.as_str(), serde_json::to_vec(&oldest)?.as_slice())?;
    }
    Ok(events)
}
impl crate::repository::DatabaseManager {
    pub(crate) fn set_journal_retention(&mut self, retention: Retention) -> Result<()> {
        self.journal_retention = retention;
        self.journal_write(|_, _| Ok(()))
    }
    pub fn journal_stats(&self) -> Result<JournalStats> {
        let db = self.db()?;
        let tx = db.begin_read()?;
        let uuid = tx
            .open_table(SEQ)?
            .get("db_uuid")?
            .ok_or_else(|| ClError::Validation("missing database uuid".into()))?
            .value()
            .to_vec();
        Ok(JournalStats {
            head: read_number(&tx, "head")?,
            floor: read_number(&tx, "floor")?,
            journal_bytes: read_number(&tx, "journal_bytes")?,
            database_uuid: uuid,
        })
    }
    pub fn journal_head(&self) -> Result<u64> {
        Ok(self.journal_stats()?.head)
    }
    /// Register a new generation at the current head. Copy a ReadView before acking.
    pub fn register_consumer(&self, name: &str) -> Result<ConsumerToken> {
        self.register_journal_consumer(name, false)
    }
    /// Internal indexer hook. A size cap requests rebuild instead of expiration.
    pub(crate) fn register_journal_consumer(
        &self,
        name: &str,
        internal: bool,
    ) -> Result<ConsumerToken> {
        if name.is_empty() {
            return Err(ClError::Validation("empty consumer name".into()));
        }
        self.journal_write(|tx, _| {
            if !internal {
                let old = tx
                    .open_table(CONSUMERS)?
                    .get(name)?
                    .map(|v| serde_json::from_slice::<Consumer>(v.value()))
                    .transpose()?;
                if old.is_some_and(|c| c.internal) {
                    return Err(ClError::Validation(
                        "internal consumer is managed by the library".into(),
                    ));
                }
            }
            let generation = number(tx, "consumer_generation")?
                .checked_add(1)
                .ok_or_else(|| ClError::Validation("consumer generation exhausted".into()))?;
            put_number(tx, "consumer_generation", generation)?;
            let head = number(tx, "head")?;
            let uuid = tx
                .open_table(SEQ)?
                .get("db_uuid")?
                .ok_or_else(|| ClError::Validation("missing database uuid".into()))?
                .value()
                .to_vec();
            let c = Consumer {
                generation,
                acked_seq: head,
                registered_at: chrono::Utc::now().timestamp_millis(),
                active: true,
                internal,
                needs_rebuild: false,
            };
            tx.open_table(CONSUMERS)?
                .insert(name, serde_json::to_vec(&c)?.as_slice())?;
            Ok(ConsumerToken {
                database_uuid: uuid,
                name: name.into(),
                generation,
            })
        })
    }
    fn journal_read(&self, token: &ConsumerToken) -> Result<redb::ReadTransaction> {
        let db = self.db()?;
        let tx = db.begin_read()?;
        let uuid = tx
            .open_table(SEQ)?
            .get("db_uuid")?
            .ok_or_else(|| ClError::Validation("missing database uuid".into()))?
            .value()
            .to_vec();
        let c = tx
            .open_table(CONSUMERS)?
            .get(token.name.as_str())?
            .map(|v| serde_json::from_slice(v.value()))
            .transpose()?;
        check_token(token, &uuid, c)?;
        Ok(tx)
    }
    pub fn read_changes(
        &self,
        token: &ConsumerToken,
        after: u64,
        limit: usize,
    ) -> Result<Vec<Change>> {
        let tx = self.journal_read(token)?;
        if after < read_number(&tx, "floor")?.saturating_sub(1) {
            return Err(expired());
        }
        if after > read_number(&tx, "head")? {
            return Err(ClError::Validation("sequence is ahead of journal".into()));
        }
        let mut out = Vec::new();
        for r in tx
            .open_table(CHANGES)?
            .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))?
            .take(limit)
        {
            let (k, v) = r?;
            crate::memory::push(
                "journal.read_rows",
                &mut out,
                Change {
                    seq: k.value(),
                    kind: ChangeKind::decode(v.value())?,
                },
            )?;
        }
        Ok(out)
    }
    pub fn read_view_at_head(&self) -> Result<ReadView> {
        let db = self.db()?;
        let tx = db.begin_read()?;
        let head = read_number(&tx, "head")?;
        let uuid = tx
            .open_table(SEQ)?
            .get("db_uuid")?
            .ok_or_else(|| ClError::Validation("missing database uuid".into()))?
            .value()
            .to_vec();
        Ok(ReadView {
            head,
            database_uuid: uuid,
            tx,
        })
    }
    /// Read the immutable table image while its journal record is retained.
    pub fn read_reset(&self, token: &ConsumerToken, seq: u64) -> Result<Vec<(String, Vec<u8>)>> {
        let tx = self.journal_read(token)?;
        let c = tx
            .open_table(CHANGES)?
            .get(seq)?
            .map(|v| ChangeKind::decode(v.value()))
            .transpose()?
            .ok_or_else(expired)?;
        let ChangeKind::TableReset { snapshot, .. } = c else {
            return Err(ClError::Validation("not a table reset".into()));
        };
        tx.open_table(TableDefinition::<&str, &[u8]>::new(&snapshot))?
            .iter()?
            .map(|r| {
                let (k, v) = r?;
                Ok((k.value().into(), v.value().to_vec()))
            })
            .collect()
    }
    /// Blob identities captured in a retained TableReset: entity key, file id, size.
    pub fn read_reset_blobs(
        &self,
        token: &ConsumerToken,
        seq: u64,
    ) -> Result<Vec<(String, String, u64)>> {
        let tx = self.journal_read(token)?;
        let c = tx
            .open_table(CHANGES)?
            .get(seq)?
            .map(|v| ChangeKind::decode(v.value()))
            .transpose()?
            .ok_or_else(expired)?;
        let ChangeKind::TableReset { snapshot, .. } = c else {
            return Err(ClError::Validation("not a table reset".into()));
        };
        tx.open_table(TableDefinition::<&str, &[u8]>::new(&format!(
            "{snapshot}_blobs"
        )))?
        .iter()?
        .map(|r| {
            let (k, v) = r?;
            let (_, key): (String, String) = serde_json::from_str(k.value())?;
            let reference: crate::journal_blob::BlobRef = serde_json::from_slice(v.value())?;
            Ok((key, reference.id, reference.size))
        })
        .collect()
    }
    pub fn ack(&self, token: &ConsumerToken, seq: u64) -> Result<()> {
        self.journal_write(|tx, _| {
            let uuid = tx
                .open_table(SEQ)?
                .get("db_uuid")?
                .ok_or_else(|| ClError::Validation("missing database uuid".into()))?
                .value()
                .to_vec();
            let c = tx
                .open_table(CONSUMERS)?
                .get(token.name.as_str())?
                .map(|v| serde_json::from_slice(v.value()))
                .transpose()?;
            let mut c = check_token(token, &uuid, c)?;
            if seq < c.acked_seq || seq > number(tx, "head")? {
                return Err(ClError::Validation("invalid acknowledgement".into()));
            }
            c.acked_seq = seq;
            tx.open_table(CONSUMERS)?
                .insert(token.name.as_str(), serde_json::to_vec(&c)?.as_slice())?;
            prune_acked(tx)
        })?;
        maybe_crash("journal_prune_after_commit");
        Ok(())
    }
    pub fn unregister_consumer(&self, name: &str) -> Result<()> {
        self.journal_write(|tx, _| {
            let old = tx
                .open_table(CONSUMERS)?
                .get(name)?
                .map(|v| serde_json::from_slice::<Consumer>(v.value()))
                .transpose()?;
            if old.is_some_and(|c| c.internal) {
                return Err(ClError::Validation(
                    "internal consumer is managed by the library".into(),
                ));
            }
            tx.open_table(CONSUMERS)?.remove(name)?;
            prune_acked(tx)
        })
    }
}

impl crate::repository::DatabaseManager {
 pub(crate) fn resume_index_consumer(&self)->Result<(ConsumerToken,bool)> {
  let view=self.read_view_at_head()?;
  let existing=view.tx.open_table(CONSUMERS)?.get("__indexer")?.map(|v|serde_json::from_slice::<Consumer>(v.value())).transpose()?;
  if let Some(c)=existing {if c.internal&&c.active&&!c.needs_rebuild {return Ok((ConsumerToken{database_uuid:view.database_uuid,name:"__indexer".into(),generation:c.generation},false))}}
  Ok((self.register_journal_consumer("__indexer",true)?,true))
 }
}

impl crate::repository::DatabaseManager {
 pub(crate) fn disable_index_consumer(&self)->Result<()> {self.journal_write(|tx,_| {let old=tx.open_table(CONSUMERS)?.get("__indexer")?.map(|v|serde_json::from_slice::<Consumer>(v.value())).transpose()?;if let Some(mut c)=old {if c.internal {c.active=false;tx.open_table(CONSUMERS)?.insert("__indexer",serde_json::to_vec(&c)?.as_slice())?;}}Ok(())})}
}
