//! Permission to open protected values.
//!
//! The application decides, for each request, whether the person asking may read protected fields,
//! and if so makes a [`ReadGrant`] and passes it to [`Sealed::open`](super::Sealed::open). Nothing
//! about a grant is stored, so taking a permission away needs no key to change: the next request
//! simply does not get a grant. Every use is reported to the event sink, without the value.
use super::{
    envelope::{Place, open_envelope},
    keys::FieldKeys,
    slots::Binding,
};
use crate::{
    crypto::SecretBytes,
    events::{EventSink, LibraryEvent},
    units::{ClError, Result},
};
use std::sync::Arc;

/// Lets the holder open protected values of one database. Cheap to clone; make one per request.
#[derive(Clone)]
pub struct ReadGrant {
    keys: Arc<FieldKeys>,
    sink: EventSink,
}

impl ReadGrant {
    pub(crate) fn new(keys: Arc<FieldKeys>, sink: EventSink) -> Self {
        Self { keys, sink }
    }

    /// Opens one stored value. The use is reported before the value is read; an attempt that
    /// fails (a value moved from its place, or damage) is reported too, and is `DataTampered`.
    pub(crate) fn open_value(&self, at: &Binding, text: &str) -> Result<SecretBytes> {
        let cipher = self.keys.cipher(&at.table_id, at.field_id)?;
        self.sink.emit(&LibraryEvent::FieldRead {
            table: at.table.to_string(),
            field: at.field.to_string(),
            field_id: at.field_id,
            row: at.row_key.to_string(),
            at: std::time::SystemTime::now(),
        });
        let place = Place { table_id: &at.table_id, field_id: at.field_id, row_key: &at.row_key };
        open_envelope(&cipher, &place, text).map_err(|_| ClError::DataTampered)
    }
}

impl ReadGrant {
    /// The cipher of one field, for the slow scan: it opens many values and reports once for the
    /// whole scan (`FieldScan`), not once for each (`FieldRead`).
    pub(super) fn cipher_quiet(&self, table_id: &str, field_id: u32) -> Result<std::sync::Arc<crate::crypto::Aead>> {
        self.keys.cipher(table_id, field_id)
    }

    pub(super) fn emit_scan(&self, event: LibraryEvent) {
        self.sink.emit(&event);
    }
}

/// Checks secrets (passwords, codes) against stored verification hashes of one database. It does
/// not open any value, so it is not a [`ReadGrant`]; the database still has to have been opened
/// with the read key, because the hash mixes in a key that is not in any file. Every check is
/// reported to the event sink, with whether it matched and without the secret.
#[derive(Clone)]
pub struct Verifier {
    keys: Arc<FieldKeys>,
    sink: EventSink,
}

impl Verifier {
    pub(crate) fn new(keys: Arc<FieldKeys>, sink: EventSink) -> Self {
        Self { keys, sink }
    }

    pub(crate) fn verify(&self, at: &Binding, stored: &str, secret: &[u8]) -> Result<bool> {
        let Some(algo) = at.hash else {
            return Err(ClError::Validation("this value is not a verification hash".into()));
        };
        let place = Place { table_id: &at.table_id, field_id: at.field_id, row_key: &at.row_key };
        let matched = super::hashing::verify_value(&self.keys, algo, &place, secret, stored)?;
        self.sink.emit(&LibraryEvent::HashVerify {
            table: at.table.to_string(),
            field: at.field.to_string(),
            field_id: at.field_id,
            row: at.row_key.to_string(),
            matched,
            at: std::time::SystemTime::now(),
        });
        Ok(matched)
    }
}

impl Verifier {
    /// Whether `candidate`, after the normalisation the field declares, has the stored fingerprint.
    /// Needs the search key. A search is not an opening of a value, so nothing is reported.
    pub(crate) fn matches_print(&self, at: &Binding, stored: &str, candidate: &str) -> Result<bool> {
        let print = super::prints::print_value(&self.keys, &at.table_id, at.field_id, at.normalize, candidate.as_bytes())?;
        Ok(super::hashing::same_settings(&print, stored))
    }
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Verifier")
    }
}

impl std::fmt::Debug for ReadGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadGrant")
    }
}
