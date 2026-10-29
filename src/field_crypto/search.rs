//! Searching a protected field by the fingerprint of a whole value.
//!
//! A field declared with a whole-value fingerprint (`encrypt` with `print`, or `search_print`) has a
//! handle instead of an ordinary field. The handle builds the only conditions a query accepts on
//! such a field, and each needs a [`SearchGrant`]: the value being looked for is turned into its
//! fingerprint while the condition is built, so the value itself never reaches the query, its
//! fingerprint (the hash of the query text), an event, or a file.
//!
//! The fingerprint of a field is stored in the row, beside the sealed text, so the indexes and the
//! unique constraints work on it like on any other text field, with no key.
//!
//! The handle has only the searches its method allows. This compiles:
//!
//! ```
//! use clove1db::{CloveFields, Unique, field_crypto::{Sealed, SearchGrant}};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct A { id: String, #[clove(encrypt, id = 1, print = "full")] phone: Sealed<String> }
//! fn search(grant: &SearchGrant<A>) {
//!     let _ = A::phone.print_eq("0501234567", grant);
//!     let _ = A::phone.print_in(["0501234567", "0507654321"], grant);
//!     let _: Unique<A> = Unique::on(A::phone.print_field());
//! }
//! ```
//!
//! and these do not, since the handle has no `eq`, no ordering, and is not a field to constrain:
//!
//! ```compile_fail
//! use clove1db::{CloveFields, field_crypto::Sealed};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct A { id: String, #[clove(encrypt, id = 1, print = "full")] phone: Sealed<String> }
//! let _ = A::phone.eq("0501234567");
//! ```
//!
//! ```compile_fail
//! use clove1db::{CloveFields, field_crypto::SearchPrint};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct A { id: String, #[clove(search_print, id = 1)] token: SearchPrint }
//! let _ = A::token.contains("abc");
//! ```
//!
//! ```compile_fail
//! use clove1db::{CloveFields, Unique, field_crypto::Sealed};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct A { id: String, #[clove(encrypt, id = 1, print = "full")] phone: Sealed<String> }
//! let _: Unique<A> = Unique::on(A::phone);
//! ```
//!
//! A fingerprint is not tied to the sealed text it was made with. Someone who can change the files can
//! change the result of an equality search by swapping fingerprints between rows; the sealed values
//! themselves stay protected.
use super::{
    grant::ReadGrant,
    envelope::{Place, open_envelope},
    keys::FieldKeys,
    method::Method,
    parts, prints,
    slots::ClosedView,
    spec::SealedSpec,
};
use crate::{
    domain::Domain,
    entity::Entity,
    events::{EventSink, LibraryEvent},
    fields::{Compare, Expr, Path, Predicate, Step, TransformKind, Value, ValueKind},
    units::{ClError, Result},
};
use std::{fmt, marker::PhantomData, sync::Arc};

/// The key, inside a field stored as an object, of the whole-value fingerprint.
const PRINT_KEY: &str = "f";

/// Where the whole-value fingerprint of a field is in the stored row, or `None` if the field has
/// none: the field itself for a search fingerprint, its `f` entry for a sealed field with one.
pub(crate) fn print_steps(spec: &SealedSpec) -> Option<Vec<Step>> {
    steps_for(spec.method, spec.key)
}

fn steps_for(method: Method, key: &str) -> Option<Vec<Step>> {
    match method {
        Method::SearchPrint => Some(vec![Step::Key(key.to_string())]),
        m if m.has_stored_print() => Some(vec![Step::Key(key.to_string()), Step::Key(PRINT_KEY.to_string())]),
        _ => None,
    }
}

/// The key, inside a field stored as an object, of the fingerprints of the parts of the value.
const PARTS_KEY: &str = "p";

/// The most fingerprints of parts one search asks for. The index asks for the rows that have all of
/// them, and a longer list than this is not worth the planner's time; a search whose text has more
/// parts asks with the first of its (sorted) fingerprints. That can only return more rows, never
/// fewer, so the rows it adds are for the confirmation to throw out.
pub(crate) const MAX_QUERY_PARTS: usize = 64;

/// Where the fingerprints of the parts of a field are in the stored row.
pub(crate) fn parts_steps(spec: &SealedSpec) -> Option<Vec<Step>> {
    spec.method.has_parts().then(|| vec![Step::Key(spec.key.to_string()), Step::Key(PARTS_KEY.to_string())])
}

/// The stored text of the fingerprints of the parts of the value `plain_json` of `spec`.
pub(crate) fn parts_of_json(
    keys: &FieldKeys,
    table_id: &str,
    spec: &SealedSpec,
    plain_json: &[u8],
) -> Result<String> {
    let text: zeroize::Zeroizing<String> = match serde_json::from_slice::<String>(plain_json) {
        Ok(text) => zeroize::Zeroizing::new(text),
        Err(_) => return Err(ClError::Validation("a field with a fingerprint must hold text".into())),
    };
    let tags = parts::part_tags(keys, table_id, spec.id, spec.normalize, spec.window, spec.bits, &text)?;
    Ok(parts::join(&tags))
}

/// The fingerprint to store beside the sealed text of `spec`, from the JSON of the value.
pub(crate) fn full_print_of_json(
    keys: &FieldKeys,
    table_id: &str,
    spec: &SealedSpec,
    plain_json: &[u8],
) -> Result<String> {
    let text: zeroize::Zeroizing<String> = match serde_json::from_slice::<String>(plain_json) {
        Ok(text) => zeroize::Zeroizing::new(text),
        Err(_) => return Err(ClError::Validation("a field with a fingerprint must hold text".into())),
    };
    prints::print_value(keys, table_id, spec.id, spec.normalize, text.as_bytes())
}

const DENIED: &str = "is a protected field: it cannot be used to filter, order, group or aggregate";

/// Refuses a condition on a protected field unless it is one the field's handle built with a search
/// grant: an equality (or a list of them) on the fingerprint of the field, whose every value is one
/// of the fingerprints in `printed`. Every other condition on a protected field, including one built
/// by hand on the same path, is refused here, before any fingerprint of the query is made.
pub(crate) fn check_filter(specs: &[SealedSpec], expr: &Expr, printed: &[String]) -> Result<()> {
    fn first<'a>(specs: &'a [SealedSpec], path: &Path) -> Option<&'a SealedSpec> {
        match path.steps.first() {
            Some(Step::Key(key)) => specs.iter().find(|s| s.key == key.as_str()),
            _ => None,
        }
    }
    fn refuse(spec: &SealedSpec) -> ClError {
        ClError::Validation(format!("`{}` {DENIED}", spec.key))
    }
    fn walk(specs: &[SealedSpec], e: &Expr, printed: &[String]) -> Result<()> {
        match e {
            Expr::Compare { path, op, values } => {
                let Some(spec) = first(specs, path) else { return Ok(()) };
                let on_print = print_steps(spec).is_some_and(|steps| steps == path.steps) && path.transforms.is_empty();
                let on_parts = parts_steps(spec).is_some_and(|steps| steps == path.steps) && path.transforms.is_empty();
                let issued = !values.is_empty()
                    && values.iter().all(|v| matches!(v, Value::String(s) if printed.iter().any(|p| p == s)));
                if on_print && matches!(op, Compare::Eq | Compare::In) && issued {
                    return Ok(());
                }
                if on_parts && matches!(op, Compare::Parts) && issued && values.len() == 1 {
                    return Ok(());
                }
                if on_print || on_parts {
                    return Err(ClError::Validation(format!(
                        "`{}`: a condition on this field must be built with its handle and a search grant",
                        spec.key
                    )));
                }
                Err(refuse(spec))
            }
            Expr::Presence { path, .. } | Expr::ElemMatch { path, .. } => match first(specs, path) {
                Some(spec) => Err(refuse(spec)),
                None => Ok(()),
            },
            Expr::And(a, b) | Expr::Or(a, b) => {
                walk(specs, a, printed)?;
                walk(specs, b, printed)
            }
            Expr::Not(a) => walk(specs, a, printed),
            _ => Ok(()),
        }
    }
    walk(specs, expr, printed)
}

// ---------------------------------------------------------------- the grant

/// Lets the holder search the fingerprinted fields of one entity. Made with
/// `Domain::search_grant`; the application decides, for each request, who may have one. Needs the
/// search key, not the read key: a program that holds only the search key can search and cannot
/// open any value. Nothing about a grant is stored.
pub struct SearchGrant<E> {
    pub(super) keys: Arc<FieldKeys>,
    pub(super) table: Arc<str>,
    pub(super) table_id: Arc<str>,
    pub(super) sink: EventSink,
    marker: PhantomData<fn(E)>,
}

impl<E> Clone for SearchGrant<E> {
    fn clone(&self) -> Self {
        Self { keys: self.keys.clone(), table: self.table.clone(), table_id: self.table_id.clone(), sink: self.sink.clone(), marker: PhantomData }
    }
}

impl<E> fmt::Debug for SearchGrant<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SearchGrant")
    }
}

impl<E> SearchGrant<E> {
    pub(crate) fn new(keys: Arc<FieldKeys>, table: Arc<str>, table_id: Arc<str>, sink: EventSink) -> Result<Self> {
        if !keys.has_search() {
            return Err(ClError::Validation(
                "this program holds no search key; fingerprints can be neither written nor matched".into(),
            ));
        }
        Ok(Self { keys, table, table_id, sink, marker: PhantomData })
    }

    fn print_of(&self, handle: &PrintHandle<E>, value: &str) -> Result<String> {
        prints::print_value(&self.keys, &self.table_id, handle.field_id, handle.normalize, value.as_bytes())
    }
}

// ---------------------------------------------------------------- the handle

/// A field with a whole-value fingerprint, as `#[derive(CloveFields)]` makes it. It has no `eq` of
/// its own: a condition on the field is made with a search grant, which turns the value into its
/// fingerprint at once.
pub struct PrintHandle<E> {
    pub(super) key: &'static str,
    pub(super) field_id: u32,
    method: Method,
    pub(super) normalize: &'static [TransformKind],
    window: u8,
    bits: u8,
    /// Looks at the sealed text of this field in an entity read from storage (to confirm a search).
    pub(super) view: for<'a> fn(&'a E) -> Option<ClosedView<'a>>,
    marker: PhantomData<fn(E)>,
}

impl<E> Clone for PrintHandle<E> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<E> Copy for PrintHandle<E> {}

impl<E> fmt::Debug for PrintHandle<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrintHandle(..)")
    }
}

impl<E> PrintHandle<E> {
    /// Used by the code the derive makes.
    #[doc(hidden)]
    pub const fn new(
        key: &'static str,
        field_id: u32,
        method: Method,
        normalize: &'static [TransformKind],
        window: u8,
        bits: u8,
        view: for<'a> fn(&'a E) -> Option<ClosedView<'a>>,
    ) -> Self {
        Self { key, field_id, method, normalize, window, bits, view, marker: PhantomData }
    }

    /// A search for a piece of the value, confirmed: the candidates that `part_candidates` gives are
    /// opened inside the library and only the rows that really contain the text are returned.
    /// See [`PartSearch`](super::confirm::PartSearch).
    pub fn part_search(&self, text: impl Into<String>) -> super::confirm::PartSearch<E> {
        super::confirm::PartSearch { handle: *self, text: text.into(), filter: None, limit: None, report_rows: false }
    }

    /// The slow scan, asked for explicitly: every row is opened inside the library and a condition the
    /// fingerprints cannot answer (approximate, range, order) is applied to the value. Needs a read
    /// grant, and only a field that is stored sealed (`#[clove(protected ..)]` with a sealed value) can
    /// be scanned. See [`SealedScan`](super::scan::SealedScan).
    pub fn scan_sealed(&self, grant: &ReadGrant) -> super::scan::SealedScan<E> {
        super::scan::SealedScan { handle: *self, grant: grant.clone(), filter: None, limit: None, report_rows: false }
    }

    /// Rows that may contain `text` (after the normalisation the field declares): those whose value
    /// has every part of it. **These are candidates, not matches.** The parts of `text` can be
    /// somewhere else in a value, and when fewer bits of a part's fingerprint are kept, other parts
    /// share it; both give rows that do not contain `text`. No row that does contain it is left out.
    /// Needs a field declared with `print = "parts"`. A text shorter than a part is refused: it needs
    /// the slow scan, with a read grant. A text of more than 64 parts is searched with 64 of them.
    pub fn part_candidates(&self, text: impl AsRef<str>, grant: &SearchGrant<E>) -> Predicate<E> {
        let invalid = |message: String| Predicate::with_printed(Expr::Invalid(message), Vec::new());
        if !self.method.has_parts() {
            return invalid(format!("`{}` has no fingerprints of parts: declare it with `print = \"parts\"`", self.key));
        }
        let text = text.as_ref();
        let length = parts::normalized_len(self.normalize, text);
        if length < usize::from(self.window) {
            return invalid(format!(
                "`{}` is searched by parts of {} characters, and the text searched for has {length}: a shorter text needs the slow scan, with a read grant",
                self.key, self.window
            ));
        }
        let mut tags = match parts::part_tags(&grant.keys, &grant.table_id, self.field_id, self.normalize, self.window, self.bits, text) {
            Ok(tags) => tags,
            Err(e) => return invalid(e.to_string()),
        };
        tags.truncate(MAX_QUERY_PARTS);
        let joined = parts::join(&tags);
        let path = Path {
            steps: vec![Step::Key(self.key.to_string()), Step::Key(PARTS_KEY.to_string())],
            kind: ValueKind::Auto,
            transforms: Vec::new(),
        };
        Predicate::with_printed(
            Expr::Compare { path, op: Compare::Parts, values: vec![Value::String(joined.clone())] },
            vec![joined],
        )
    }

    fn path(&self) -> Path {
        Path {
            steps: steps_for(self.method, self.key).unwrap_or_default(),
            kind: ValueKind::Auto,
            transforms: Vec::new(),
        }
    }

    fn condition(&self, op: Compare, tags: Vec<String>) -> Predicate<E> {
        if tags.is_empty() {
            return Predicate::with_printed(Expr::Never, Vec::new());
        }
        let values = tags.iter().cloned().map(Value::String).collect();
        Predicate::with_printed(Expr::Compare { path: self.path(), op, values }, tags)
    }

    /// Rows whose value is `value`, after the normalisation the field declares.
    pub fn print_eq(&self, value: impl AsRef<str>, grant: &SearchGrant<E>) -> Predicate<E> {
        match grant.print_of(self, value.as_ref()) {
            Ok(tag) => self.condition(Compare::Eq, vec![tag]),
            Err(e) => Predicate::with_printed(Expr::Invalid(e.to_string()), Vec::new()),
        }
    }

    /// Rows whose value is any of `values`.
    pub fn print_in<S: AsRef<str>>(
        &self,
        values: impl IntoIterator<Item = S>,
        grant: &SearchGrant<E>,
    ) -> Predicate<E> {
        let mut tags = Vec::new();
        for value in values {
            match grant.print_of(self, value.as_ref()) {
                Ok(tag) => tags.push(tag),
                Err(e) => return Predicate::with_printed(Expr::Invalid(e.to_string()), Vec::new()),
            }
        }
        self.condition(Compare::In, tags)
    }

    /// The stored fingerprint as a field for [`Unique::on`](crate::Unique::on): a unique constraint
    /// on it keeps two rows from holding the same value (after normalisation). It is not an ordinary
    /// field: nothing can be compared with it.
    pub fn print_field(&self) -> PrintField<E> {
        PrintField { path: self.path(), marker: PhantomData }
    }
}

/// The stored fingerprint of a field, for a unique constraint.
pub struct PrintField<E> {
    path: Path,
    marker: PhantomData<fn(E)>,
}

impl<E> PrintField<E> {
    pub(crate) fn into_path(self) -> Path {
        self.path
    }
}

impl<E> fmt::Debug for PrintField<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrintField(..)")
    }
}

// ---------------------------------------------------------------- fields that cannot be searched by fingerprint

/// A protected field that is sealed and has no fingerprint (`#[clove(encrypt)]`), as
/// `#[derive(CloveFields)]` makes it. Its only search is the slow scan, asked for explicitly with
/// [`scan_sealed`](Self::scan_sealed) and a read grant; it has no `eq`, `contains`, ordering or
/// fingerprint search, so any other search on it does not compile. This compiles:
///
/// ```
/// use clove1db::{CloveFields, field_crypto::{ReadGrant, Sealed}};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(encrypt, id = 1)] note: Sealed<String> }
/// fn scan(grant: &ReadGrant) {
///     let _ = A::note.scan_sealed(grant);
/// }
/// ```
///
/// and these do not (the field has no `eq`, no ordering, no fingerprint search, and is not a field to
/// constrain):
///
/// ```compile_fail,E0599
/// use clove1db::{CloveFields, field_crypto::Sealed};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(encrypt, id = 1)] note: Sealed<String> }
/// let _ = A::note.eq("x".to_string());
/// ```
///
/// ```compile_fail,E0599
/// use clove1db::{CloveFields, field_crypto::Sealed};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(encrypt, id = 1)] note: Sealed<String> }
/// let _ = A::note.exists();
/// ```
///
/// ```compile_fail,E0277
/// use clove1db::{CloveFields, Unique, field_crypto::Sealed};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(encrypt, id = 1)] note: Sealed<String> }
/// let _: Unique<A> = Unique::on(A::note);
/// ```
///
/// ```compile_fail,E0277
/// use clove1db::{CloveFields, query::Asc, field_crypto::Sealed};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(encrypt, id = 1)] note: Sealed<String> }
/// fn f(q: clove1db::query::Query<A>) {
///     let _ = q.order_by(A::note, Asc);
/// }
/// ```
///
/// ```compile_fail,E0308
/// use clove1db::{CloveFields, query::Asc, field_crypto::Sealed};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(encrypt, id = 1)] note: Sealed<String> }
/// fn f(q: clove1db::query::Query<A>) {
///     let _ = q.distinct(A::note);
/// }
/// ```
///
/// ```compile_fail,E0308
/// use clove1db::{CloveFields, query::Asc, field_crypto::Sealed};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(encrypt, id = 1)] note: Sealed<String> }
/// fn f(q: clove1db::query::Query<A>) {
///     let _ = q.min(A::note);
/// }
/// ```
///
/// ```compile_fail,E0308
/// use clove1db::{CloveFields, query::Asc, field_crypto::Sealed};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(encrypt, id = 1)] note: Sealed<String> }
/// fn f(q: clove1db::query::Query<A>) {
///     let _ = q.group_by(A::note);
/// }
/// ```
///
/// ```compile_fail,E0308
/// use clove1db::{CloveFields, query::Asc, field_crypto::Sealed};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(encrypt, id = 1)] note: Sealed<String> }
/// fn f(q: clove1db::query::Query<A>) {
///     let _ = q.statistics(A::note);
/// }
/// ```
pub struct ScanHandle<E> {
    inner: PrintHandle<E>,
}

impl<E> Clone for ScanHandle<E> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<E> Copy for ScanHandle<E> {}

impl<E> fmt::Debug for ScanHandle<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScanHandle(..)")
    }
}

impl<E> ScanHandle<E> {
    /// Used by the code the derive makes.
    #[doc(hidden)]
    pub const fn new(key: &'static str, field_id: u32, view: for<'a> fn(&'a E) -> Option<ClosedView<'a>>) -> Self {
        Self { inner: PrintHandle::new(key, field_id, Method::Encrypt, &[], 0, 0, view) }
    }

    /// The slow scan: every row is opened inside the library and a condition on the value is applied
    /// (approximate, range, order). See [`SealedScan`](super::scan::SealedScan).
    pub fn scan_sealed(&self, grant: &ReadGrant) -> super::scan::SealedScan<E> {
        self.inner.scan_sealed(grant)
    }
}

/// A verification hash (`#[clove(hash)]`), as `#[derive(CloveFields)]` makes it. A hash cannot be
/// reversed, so it can be neither searched nor scanned; it is only checked, with
/// [`Domain::verifier`](crate::domain::Domain::verifier). It has no methods, so a search on it does
/// not compile:
///
/// ```compile_fail,E0599
/// use clove1db::{CloveFields, field_crypto::Hashed};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(hash = "argon2id", id = 1)] password: Hashed }
/// let _ = A::password.eq("x".to_string());
/// ```
///
/// ```compile_fail,E0599
/// use clove1db::{CloveFields, field_crypto::{Hashed, ReadGrant}};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize, CloveFields)]
/// struct A { id: String, #[clove(hash = "argon2id", id = 1)] password: Hashed }
/// fn scan(grant: &ReadGrant) {
///     let _ = A::password.scan_sealed(grant);
/// }
/// ```
pub struct HashHandle<E> {
    marker: PhantomData<fn(E)>,
}

impl<E> Clone for HashHandle<E> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<E> Copy for HashHandle<E> {}

impl<E> fmt::Debug for HashHandle<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HashHandle(..)")
    }
}

impl<E> HashHandle<E> {
    /// Used by the code the derive makes.
    #[doc(hidden)]
    pub const fn new(_key: &'static str, _field_id: u32) -> Self {
        Self { marker: PhantomData }
    }
}
