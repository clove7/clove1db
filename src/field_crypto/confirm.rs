//! The confirmed search by a piece of a value (9-3): the candidates that the fingerprints of the parts
//! give are opened inside the library, and the rows that really contain the text are kept.
use super::{
    envelope::{Place, open_envelope},
    prints,
    search::{PrintHandle, SearchGrant},
};
use crate::{
    domain::Domain,
    entity::Entity,
    events::LibraryEvent,
    fields::Predicate,
    units::{ClError, Result},
};
use std::fmt;

/// How many candidates are fetched and checked at a time.
const CONFIRM_CHUNK: usize = 256;

/// The rows a search by a piece of a value found.
#[derive(Debug)]
#[non_exhaustive]
pub enum PartResults<E> {
    /// Every row here contains the text: the candidates were opened inside the library and checked.
    /// This is what a program that holds the read key gets.
    Confirmed(Vec<E>),
    /// The rows that may contain the text, as the fingerprints of the parts say: all of the rows that
    /// do, and possibly others. This is what a program that holds the search key alone gets; it can
    /// open nothing, so it cannot check them.
    Candidates(Vec<E>),
}

impl<E> PartResults<E> {
    pub fn is_confirmed(&self) -> bool {
        matches!(self, PartResults::Confirmed(_))
    }

    pub fn rows(&self) -> &[E] {
        match self {
            PartResults::Confirmed(rows) | PartResults::Candidates(rows) => rows,
        }
    }

    /// The rows, whether or not they are confirmed.
    pub fn into_rows(self) -> Vec<E> {
        match self {
            PartResults::Confirmed(rows) | PartResults::Candidates(rows) => rows,
        }
    }

    /// The rows if they are confirmed, an error if they are only candidates.
    pub fn into_confirmed(self) -> Result<Vec<E>> {
        match self {
            PartResults::Confirmed(rows) => Ok(rows),
            PartResults::Candidates(_) => Err(ClError::Validation(
                "this program holds no read key: the rows are candidates, and cannot be confirmed".into(),
            )),
        }
    }
}

/// A search for a piece of a protected value (see [`PrintHandle::part_search`]).
///
/// It asks for the candidates the fingerprints of the parts give, and then, if the program holds the
/// read key, opens each one inside the library and keeps those whose value really contains the text
/// (after the normalisation the field declares). The values are not returned: the rows come back
/// with their protected fields closed, as always. One [`LibraryEvent::FieldConfirm`] is sent for the
/// whole search, with how many candidates were looked at and how many were opened.
///
/// A search that has a `limit` stops opening candidates as soon as it has that many matches; the
/// rows come in key order. The text must be at least as long as a part of the field.
///
/// Whoever may search and holds the read key can learn a value by asking again and again whether it
/// contains a text; that is what a search by a piece is. Each search is reported.
pub struct PartSearch<E> {
    pub(super) handle: PrintHandle<E>,
    pub(super) text: String,
    pub(super) filter: Option<Predicate<E>>,
    pub(super) limit: Option<usize>,
    pub(super) report_rows: bool,
}

impl<E> fmt::Debug for PartSearch<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PartSearch(..)")
    }
}

impl<E: Entity> PartSearch<E> {
    /// Another condition the rows must meet (on ordinary fields, or another handle's).
    pub fn filter(mut self, condition: Predicate<E>) -> Self {
        self.filter = Some(match self.filter.take() {
            Some(old) => old.and(condition),
            None => condition,
        });
        self
    }

    /// At most `n` rows, the first ones in key order.
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Puts the keys of the rows that were opened in the [`LibraryEvent::FieldConfirm`] event. Off by
    /// default: the event then carries only counts.
    pub fn report_rows(mut self, on: bool) -> Self {
        self.report_rows = on;
        self
    }

    pub fn run(&self, domain: &Domain<E>, grant: &SearchGrant<E>) -> Result<PartResults<E>> {
        let handle = &self.handle;
        let mut predicate = handle.part_candidates(&self.text, grant);
        if let Some(extra) = &self.filter {
            predicate = predicate.and(extra.clone());
        }
        let limit = self.limit.unwrap_or(usize::MAX);
        // Confirming needs the read key; without it the rows can only be handed over as candidates.
        let Ok(cipher) = grant.keys.cipher(&grant.table_id, handle.field_id) else {
            let mut rows: Vec<E> = Vec::new();
            let mut cursor = None;
            loop {
                let mut query = domain.query().filter(predicate.clone()).limit(CONFIRM_CHUNK);
                if let Some(c) = cursor.take() {
                    query = query.after(c);
                }
                let page = query.page()?;
                rows.extend(page.items);
                if rows.len() >= limit {
                    rows.truncate(limit);
                    break;
                }
                match page.next {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
            return Ok(PartResults::Candidates(rows));
        };
        let needle = zeroize::Zeroizing::new(prints::normalize(&self.text, handle.normalize));
        let mut seen = 0u64;
        let mut opened = 0u64;
        let mut opened_rows: Option<Vec<String>> = self.report_rows.then(Vec::new);
        let mut rows: Vec<E> = Vec::new();
        let outcome = (|| -> Result<()> {
            let mut cursor = None;
            loop {
                let mut query = domain.query().filter(predicate.clone()).limit(CONFIRM_CHUNK);
                if let Some(c) = cursor.take() {
                    query = query.after(c);
                }
                let page = query.page()?;
                for row in page.items {
                    seen += 1;
                    let hit = {
                        let Some(view) = (handle.view)(&row) else {
                            return Err(ClError::Validation(
                                "a candidate row was not read from a table registered with `register_sealed`".into(),
                            ));
                        };
                        if view.at.table_id != grant.table_id || view.at.field_id != handle.field_id {
                            return Err(ClError::DataTampered);
                        }
                        opened += 1;
                        if let Some(keys) = opened_rows.as_mut() {
                            keys.push(view.at.row_key.to_string());
                        }
                        let place = Place { table_id: &view.at.table_id, field_id: view.at.field_id, row_key: &view.at.row_key };
                        let plain = open_envelope(&cipher, &place, view.text).map_err(|_| ClError::DataTampered)?;
                        let value: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
                            serde_json::from_slice::<String>(plain.as_bytes())
                                .map_err(|_| ClError::Validation("a field searched by parts must hold text".into()))?,
                        );
                        let normalized = zeroize::Zeroizing::new(prints::normalize(&value, handle.normalize));
                        normalized.contains(needle.as_str())
                    };
                    if hit {
                        rows.push(row);
                        if rows.len() >= limit {
                            return Ok(());
                        }
                    }
                }
                match page.next {
                    Some(next) => cursor = Some(next),
                    None => return Ok(()),
                }
            }
        })();
        // One event for the search, also when it failed half-way (a changed value is DataTampered).
        grant.sink.emit(&LibraryEvent::FieldConfirm {
            table: grant.table.to_string(),
            field: handle.key.to_string(),
            field_id: handle.field_id,
            candidates: seen,
            opened,
            matched: rows.len() as u64,
            rows: opened_rows,
            at: std::time::SystemTime::now(),
        });
        outcome?;
        Ok(PartResults::Confirmed(rows))
    }
}
