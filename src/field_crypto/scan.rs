//! The slow scan of a protected field (9-4): every row is read, the field is opened inside the library,
//! and a condition the fingerprints cannot answer (an approximate match, a range, an order) is applied.
use super::{
    envelope::{Place, open_envelope},
    grant::ReadGrant,
    search::PrintHandle,
};
use crate::{
    domain::Domain,
    entity::Entity,
    events::LibraryEvent,
    fields::Predicate,
    units::{ClError, Result},
};
use serde::de::DeserializeOwned;
use std::fmt;

/// How many rows are fetched and checked at a time.
const SCAN_CHUNK: usize = 256;

/// A scan of one protected field, asked for explicitly with [`PrintHandle::scan_sealed`]. There is no
/// index behind it: every row that the ordinary conditions leave is opened, so it is slow on a large
/// table. Without this request a condition the fingerprints cannot answer does not compile or run.
///
/// The condition is a function of the opened value, of the type the field holds. The values are not
/// returned: the rows come back with their protected fields closed, as always. One
/// [`LibraryEvent::FieldScan`] is sent for the whole scan, with how many rows were looked at and how
/// many were opened and kept; never a value. Whoever holds the read key and may scan can learn the
/// values by asking enough questions; each scan is reported.
pub struct SealedScan<E> {
    pub(super) handle: PrintHandle<E>,
    pub(super) grant: ReadGrant,
    pub(super) filter: Option<Predicate<E>>,
    pub(super) limit: Option<usize>,
    pub(super) report_rows: bool,
}

impl<E> fmt::Debug for SealedScan<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealedScan(..)")
    }
}

impl<E: Entity> SealedScan<E> {
    /// Another condition the rows must meet, on ordinary fields or through a search handle. It is
    /// applied before anything is opened, so a scan with a selective condition opens few rows.
    pub fn filter(mut self, condition: Predicate<E>) -> Self {
        self.filter = Some(match self.filter.take() {
            Some(old) => old.and(condition),
            None => condition,
        });
        self
    }

    /// At most `n` rows. For [`run`](Self::run) the first ones in key order, and the scan stops as soon as
    /// it has them; for [`run_ordered`](Self::run_ordered) the first ones in the order asked for.
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Puts the keys of the rows that were opened in the [`LibraryEvent::FieldScan`] event. Off by
    /// default: the event then carries only counts.
    pub fn report_rows(mut self, on: bool) -> Self {
        self.report_rows = on;
        self
    }

    /// The rows whose value `keep` accepts, in key order.
    pub fn run<T: DeserializeOwned>(&self, domain: &Domain<E>, mut keep: impl FnMut(&T) -> bool) -> Result<Vec<E>> {
        let limit = self.limit.unwrap_or(usize::MAX);
        let mut rows: Vec<E> = Vec::new();
        self.walk(domain, |row, value: &T| {
            let kept = keep(value);
            if kept {
                rows.push(row);
            }
            Ok((kept, rows.len() < limit))
        })?;
        Ok(rows)
    }

    /// The rows whose value `order` gives a key for (`None` leaves the row out), by that key; rows
    /// with the same key stay in key order.
    pub fn run_ordered<T: DeserializeOwned, K: Ord>(
        &self,
        domain: &Domain<E>,
        mut order: impl FnMut(&T) -> Option<K>,
    ) -> Result<Vec<E>> {
        let mut rows: Vec<(K, E)> = Vec::new();
        self.walk(domain, |row, value: &T| {
            let key = order(value);
            let kept = key.is_some();
            if let Some(key) = key {
                rows.push((key, row));
            }
            Ok((kept, true))
        })?;
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out: Vec<E> = rows.into_iter().map(|(_, row)| row).collect();
        out.truncate(self.limit.unwrap_or(usize::MAX));
        Ok(out)
    }

    /// Goes through the rows in pages, opens the field of each, and hands the row and its value to
    /// `visit` (which says whether it kept the row and whether to go on). Sends the one event, also when the scan fails half-way.
    fn walk<T: DeserializeOwned>(&self, domain: &Domain<E>, mut visit: impl FnMut(E, &T) -> Result<(bool, bool)>) -> Result<()> {
        let handle = &self.handle;
        let mut seen = 0u64;
        let mut opened = 0u64;
        let mut matched = 0u64;
        let mut where_from: Option<(String, u32)> = None;
        let mut opened_rows: Option<Vec<String>> = self.report_rows.then(Vec::new);
        let outcome = (|| -> Result<()> {
            let mut cursor = None;
            loop {
                let mut query = domain.query().limit(SCAN_CHUNK);
                if let Some(f) = &self.filter {
                    query = query.filter(f.clone());
                }
                if let Some(c) = cursor.take() {
                    query = query.after(c);
                }
                let page = query.page()?;
                for row in page.items {
                    seen += 1;
                    let value: T = {
                        let Some(view) = (handle.view)(&row) else {
                            return Err(ClError::Validation(
                                "a row was not read from a table registered with `register_sealed`".into(),
                            ));
                        };
                        if view.at.field_id != handle.field_id {
                            return Err(ClError::DataTampered);
                        }
                        where_from.get_or_insert_with(|| (view.at.table.to_string(), view.at.field_id));
                        let cipher = self.grant.cipher_quiet(&view.at.table_id, handle.field_id)?;
                        opened += 1;
                        if let Some(keys) = opened_rows.as_mut() {
                            keys.push(view.at.row_key.to_string());
                        }
                        let place = Place { table_id: &view.at.table_id, field_id: view.at.field_id, row_key: &view.at.row_key };
                        let plain = open_envelope(&cipher, &place, view.text).map_err(|_| ClError::DataTampered)?;
                        serde_json::from_slice::<T>(plain.as_bytes())
                            .map_err(|_| ClError::Validation("the field does not hold a value of the type the scan asks for".into()))?
                    };
                    let (kept, more) = visit(row, &value)?;
                    matched += u64::from(kept);
                    if !more {
                        return Ok(());
                    }
                }
                match page.next {
                    Some(next) => cursor = Some(next),
                    None => return Ok(()),
                }
            }
        })();
        if let Some((table, field_id)) = where_from {
            self.grant.emit_scan(LibraryEvent::FieldScan {
                table,
                field: handle.key.to_string(),
                field_id,
                scanned: seen,
                opened,
                matched,
                rows: opened_rows,
                at: std::time::SystemTime::now(),
            });
        }
        outcome
    }
}
