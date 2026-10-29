//! The types an entity uses for protected fields: [`Sealed`], [`Hashed`] and [`SearchPrint`].
//!
//! A new value lives in memory in the clear until the storage layer seals it; it can never be
//! serialized outside that step. A value read from storage is closed: it holds only the stored
//! text, and a `Debug` of it prints a fixed marker.
use super::{
    grant::{ReadGrant, Verifier},
    method::HashAlgo,
    scope,
};
use crate::{
    crypto::{SecretBytes, ct_eq},
    units::{ClError, Result},
};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::Error as DeError,
    ser::Error as SerError,
};
use std::{fmt, sync::Arc};

/// Where a closed value was read from: its table, its field and its row. Two bindings are the same
/// place when the table identity, the field number and the row key are equal; the names are only
/// there to be reported.
#[derive(Clone)]
pub struct Binding {
    pub(crate) table: Arc<str>,
    pub(crate) table_id: Arc<str>,
    pub(crate) field: &'static str,
    pub(crate) field_id: u32,
    pub(crate) row_key: Arc<str>,
    /// For a verification hash: the algorithm the code declares for it.
    pub(crate) hash: Option<HashAlgo>,
    /// For a search fingerprint: how the code says a value is normalised before it is fingerprinted.
    pub(crate) normalize: &'static [crate::fields::TransformKind],
}

impl Binding {
    /// Sets the normalisation of a search fingerprint. Used by the code the derive makes.
    #[doc(hidden)]
    pub fn with_normalize(mut self, normalize: &'static [crate::fields::TransformKind]) -> Self {
        self.normalize = normalize;
        self
    }

    /// Sets the hash algorithm of a verification hash. Used by the code the derive makes.
    #[doc(hidden)]
    pub fn with_hash(mut self, hash: Option<HashAlgo>) -> Self {
        self.hash = hash;
        self
    }
}

impl PartialEq for Binding {
    fn eq(&self, other: &Self) -> bool {
        self.table_id == other.table_id && self.field_id == other.field_id && self.row_key == other.row_key
    }
}
impl Eq for Binding {}

impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Binding(..)")
    }
}

/// The row whose protected fields were just read.
#[derive(Clone)]
pub struct RowBinding {
    table: Arc<str>,
    table_id: Arc<str>,
    row_key: Arc<str>,
}

impl RowBinding {
    pub(crate) fn new(table_id: &str, row_key: &str) -> Self {
        Self::with_table("", table_id, row_key)
    }

    pub(crate) fn with_table(table: &str, table_id: &str, row_key: &str) -> Self {
        Self { table: table.into(), table_id: table_id.into(), row_key: row_key.into() }
    }

    /// The binding of the field with this number in this row.
    pub fn field(&self, field_id: u32) -> Binding {
        self.field_named(field_id, "")
    }

    /// Like [`RowBinding::field`], with the name of the field for the reports of its use.
    pub fn field_named(&self, field_id: u32, field: &'static str) -> Binding {
        Binding {
            table: self.table.clone(),
            table_id: self.table_id.clone(),
            field,
            field_id,
            row_key: self.row_key.clone(),
            hash: None,
            normalize: &[],
        }
    }
}

impl fmt::Debug for RowBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RowBinding(..)")
    }
}

/// What one protected field holds, as the storage layer needs it to write the row.
#[doc(hidden)]
pub enum Part<'a> {
    /// A new value: for [`Sealed`] its JSON encoding, for [`Hashed`] and [`SearchPrint`] the bytes.
    New(SecretBytes),
    /// A value read from storage, with the place it was read from (if it was bound).
    /// `full` is the whole-value fingerprint stored beside a sealed text (fields declared with one),
    /// and `parts` the fingerprints of its parts (fields declared with `print = "parts"`).
    Closed { text: &'a str, full: Option<&'a str>, parts: Option<&'a str>, bound: Option<&'a Binding> },
    /// A stored value that is not tied to a place.
    Stored(&'a str),
}

fn refuse<S: Serializer>(what: &str) -> std::result::Result<S::Ok, S::Error> {
    Err(S::Error::custom(format!(
        "a new {what} value can only be serialized by the storage that protects it"
    )))
}

macro_rules! slot_trait {
    ($name:ident, $msg:literal, $label:literal) => {
        #[diagnostic::on_unimplemented(message = $msg, label = $label)]
        #[doc(hidden)]
        pub trait $name {
            fn part(&self) -> Result<Part<'_>>;
            fn bind(&mut self, binding: Binding);
        }
    };
}
slot_trait!(
    EncryptSlot,
    "`{Self}` cannot hold a field declared with `#[clove(encrypt)]`",
    "declare this field as `Sealed<T>`"
);
slot_trait!(
    HashSlot,
    "`{Self}` cannot hold a field declared with `#[clove(hash = ..)]`",
    "declare this field as `Hashed`"
);
slot_trait!(
    PrintSlot,
    "`{Self}` cannot hold a field declared with `#[clove(search_print)]`",
    "declare this field as `SearchPrint`"
);

impl<T> crate::fields::CloveFields for Sealed<T> {}
impl crate::fields::CloveFields for Hashed {}
impl crate::fields::CloveFields for SearchPrint {}

// ---------------------------------------------------------------- Sealed

/// A value stored encrypted. Written with [`Sealed::new`]; read back closed.
#[derive(Clone)]
pub struct Sealed<T> {
    state: SealedState<T>,
}

#[derive(Clone)]
enum SealedState<T> {
    New(T),
    /// `full` is the whole-value fingerprint stored beside the sealed text, for a field declared with
    /// one: the value is then stored as `{"s": sealed text, "f": fingerprint}`, with `"p"` (the
    /// fingerprints of its parts) in a field declared with `print = "parts"`.
    Closed { text: Box<str>, full: Option<Box<str>>, parts: Option<Box<str>>, bound: Option<Binding> },
}

/// How a sealed field is stored: the sealed text alone, or an object that also carries the
/// fingerprint of the value.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredSealed {
    Text(String),
    Object {
        s: String,
        #[serde(default)]
        f: Option<String>,
        #[serde(default)]
        p: Option<String>,
    },
}

/// A value read from storage, as the library looks at it to confirm a search: its sealed text and
/// the place it was read from.
#[doc(hidden)]
pub struct ClosedView<'a> {
    pub(crate) text: &'a str,
    pub(crate) at: &'a Binding,
}

impl<T> Sealed<T> {
    pub fn new(value: T) -> Self {
        Self { state: SealedState::New(value) }
    }

    /// The sealed text and the place of a value read from storage; `None` for a new value or one
    /// that was not read from a table registered with `register_sealed`. Used by the code the derive
    /// makes.
    #[doc(hidden)]
    pub fn closed_view(&self) -> Option<ClosedView<'_>> {
        match &self.state {
            SealedState::Closed { text, bound: Some(at), .. } => Some(ClosedView { text, at }),
            _ => None,
        }
    }

    /// True for a value made with [`Sealed::new`] and not yet written.
    pub fn is_new(&self) -> bool {
        matches!(self.state, SealedState::New(_))
    }

    /// True for a value read from storage.
    pub fn is_bound(&self) -> bool {
        matches!(self.state, SealedState::Closed { bound: Some(_), .. })
    }
}

impl<T: serde::de::DeserializeOwned> Sealed<T> {
    /// Opens the value with a read grant. The use is reported to the event sink, without the value.
    ///
    /// Only a value read from the storage can be opened, and only where it was read from: a value
    /// that was never written, or that came from outside the storage, is an error; a value moved
    /// to another row or field is `DataTampered`.
    pub fn open(&self, grant: &ReadGrant) -> Result<T> {
        match &self.state {
            SealedState::New(_) => Err(ClError::Validation(
                "a value that has not been written yet cannot be opened".into(),
            )),
            SealedState::Closed { bound: None, .. } => Err(ClError::Validation(
                "this value was not read from a storage; read the row from a table registered with `register_sealed`".into(),
            )),
            SealedState::Closed { text, bound: Some(at), .. } => {
                let plain = grant.open_value(at, text)?;
                Ok(serde_json::from_slice(plain.as_bytes())?)
            }
        }
    }
}

impl<T: Default> Default for Sealed<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> fmt::Debug for Sealed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sealed([sealed])")
    }
}

impl<T: PartialEq> PartialEq for Sealed<T> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.state, &other.state) {
            (SealedState::New(a), SealedState::New(b)) => a == b,
            (SealedState::Closed { text: a, full: fa, parts: pa, .. }, SealedState::Closed { text: b, full: fb, parts: pb, .. }) => {
                a == b && fa == fb && pa == pb
            }
            _ => false,
        }
    }
}

impl<T> Serialize for Sealed<T> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match &self.state {
            SealedState::Closed { text, full: None, parts: None, .. } => s.serialize_str(text),
            SealedState::Closed { text, full, parts, .. } => {
                use serde::ser::SerializeMap;
                let mut map = s.serialize_map(Some(1 + usize::from(full.is_some()) + usize::from(parts.is_some())))?;
                map.serialize_entry("s", text)?;
                if let Some(full) = full {
                    map.serialize_entry("f", full)?;
                }
                if let Some(parts) = parts {
                    map.serialize_entry("p", parts)?;
                }
                map.end()
            }
            // A placeholder: the storage layer replaces it. No part of the value is in it.
            SealedState::New(_) if scope::active() => s.serialize_unit(),
            SealedState::New(_) => refuse::<S>("sealed"),
        }
    }
}

impl<'de, T> Deserialize<'de> for Sealed<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let stored = StoredSealed::deserialize(d).map_err(|_| D::Error::custom("a sealed field is stored as text"))?;
        let (text, full, parts) = match stored {
            StoredSealed::Text(text) => (text, None, None),
            StoredSealed::Object { s, f, p } => (s, f, p),
        };
        Ok(Self {
            state: SealedState::Closed { text: text.into(), full: full.map(Into::into), parts: parts.map(Into::into), bound: None },
        })
    }
}

impl<T: Serialize> EncryptSlot for Sealed<T> {
    fn part(&self) -> Result<Part<'_>> {
        Ok(match &self.state {
            SealedState::New(value) => Part::New(SecretBytes::new(serde_json::to_vec(value)?)),
            SealedState::Closed { text, full, parts, bound } => {
                Part::Closed { text, full: full.as_deref(), parts: parts.as_deref(), bound: bound.as_ref() }
            }
        })
    }

    fn bind(&mut self, binding: Binding) {
        if let SealedState::Closed { bound, .. } = &mut self.state {
            *bound = Some(binding);
        }
    }
}

// ---------------------------------------------------------------- Hashed

#[derive(Clone)]
enum SecretState {
    New(Vec<u8>),
    Closed { text: Box<str>, bound: Option<Binding> },
}

impl Drop for SecretState {
    fn drop(&mut self) {
        if let SecretState::New(bytes) = self {
            zeroize::Zeroize::zeroize(bytes);
        }
    }
}

/// A verification hash (for a password or a code). Written with [`Hashed::new`] from the secret;
/// read back closed, and never readable as a value.
#[derive(Clone)]
pub struct Hashed {
    state: SecretState,
}

impl Hashed {
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self { state: SecretState::New(secret.as_ref().to_vec()) }
    }

    pub fn is_new(&self) -> bool {
        matches!(self.state, SecretState::New(_))
    }

    pub fn is_bound(&self) -> bool {
        matches!(self.state, SecretState::Closed { bound: Some(_), .. })
    }
}

impl Hashed {
    /// Whether `secret` is the one this hash was made from. The check is slow on purpose and takes
    /// the same time whatever the secret is. It is reported to the event sink (with whether it
    /// matched, without the secret).
    ///
    /// Only a value read from the storage can be checked, and only where it was read from: a hash
    /// copied to another row does not match there.
    pub fn verify(&self, secret: impl AsRef<[u8]>, verifier: &Verifier) -> Result<bool> {
        match &self.state {
            SecretState::New(_) => Err(ClError::Validation(
                "a value that has not been written yet cannot be checked".into(),
            )),
            SecretState::Closed { bound: None, .. } => Err(ClError::Validation(
                "this value was not read from a storage; read the row from a table registered with `register_sealed`".into(),
            )),
            SecretState::Closed { text, bound: Some(at) } => verifier.verify(at, text, secret.as_ref()),
        }
    }
}

impl Default for Hashed {
    fn default() -> Self {
        Self::new(Vec::<u8>::new())
    }
}

impl fmt::Debug for Hashed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hashed([hash])")
    }
}

impl PartialEq for Hashed {
    fn eq(&self, other: &Self) -> bool {
        match (&self.state, &other.state) {
            (SecretState::New(a), SecretState::New(b)) => ct_eq(a, b),
            (SecretState::Closed { text: a, .. }, SecretState::Closed { text: b, .. }) => a == b,
            _ => false,
        }
    }
}

impl Serialize for Hashed {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match &self.state {
            SecretState::Closed { text, .. } => s.serialize_str(text),
            SecretState::New(_) if scope::active() => s.serialize_unit(),
            SecretState::New(_) => refuse::<S>("hashed"),
        }
    }
}

impl<'de> Deserialize<'de> for Hashed {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(d).map_err(|_| D::Error::custom("a hashed field is stored as text"))?;
        Ok(Self { state: SecretState::Closed { text: text.into(), bound: None } })
    }
}

impl HashSlot for Hashed {
    fn part(&self) -> Result<Part<'_>> {
        Ok(match &self.state {
            SecretState::New(bytes) => Part::New(SecretBytes::from_slice(bytes)),
            SecretState::Closed { text, bound } => Part::Closed { text, full: None, parts: None, bound: bound.as_ref() },
        })
    }

    fn bind(&mut self, binding: Binding) {
        if let SecretState::Closed { bound, .. } = &mut self.state {
            *bound = Some(binding);
        }
    }
}

// ---------------------------------------------------------------- SearchPrint

#[derive(Clone)]
enum PrintState {
    New(Vec<u8>),
    Stored { text: Box<str>, bound: Option<Binding> },
}

impl Drop for PrintState {
    fn drop(&mut self) {
        if let PrintState::New(bytes) = self {
            zeroize::Zeroize::zeroize(bytes);
        }
    }
}

/// A keyed fingerprint for equality search. Written with [`SearchPrint::new`] from the value;
/// read back as the fingerprint only. It is not tied to a row: equal values give equal prints.
#[derive(Clone)]
pub struct SearchPrint {
    state: PrintState,
}

impl SearchPrint {
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self { state: PrintState::New(value.as_ref().to_vec()) }
    }

    pub fn is_new(&self) -> bool {
        matches!(self.state, PrintState::New(_))
    }

    /// Whether `candidate` has this fingerprint, after the normalisation the field declares.
    /// Equal values give equal fingerprints, in any row. Needs the search key (the read key is not
    /// needed). Not reported to the event sink: it is a search, not an opening of a value.
    ///
    /// Only a value read from the storage can be matched: one never written, or one that came from
    /// outside the storage, does not know which field it is the fingerprint of.
    pub fn matches(&self, candidate: impl AsRef<str>, verifier: &Verifier) -> Result<bool> {
        match &self.state {
            PrintState::New(_) => Err(ClError::Validation(
                "a value that has not been written yet cannot be matched".into(),
            )),
            PrintState::Stored { bound: None, .. } => Err(ClError::Validation(
                "this value was not read from a storage; read the row from a table registered with `register_sealed`".into(),
            )),
            PrintState::Stored { text, bound: Some(at) } => verifier.matches_print(at, text, candidate.as_ref()),
        }
    }
}

impl Default for SearchPrint {
    fn default() -> Self {
        Self::new(Vec::<u8>::new())
    }
}

impl fmt::Debug for SearchPrint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SearchPrint([fingerprint])")
    }
}

impl PartialEq for SearchPrint {
    fn eq(&self, other: &Self) -> bool {
        match (&self.state, &other.state) {
            (PrintState::New(a), PrintState::New(b)) => ct_eq(a, b),
            (PrintState::Stored { text: a, .. }, PrintState::Stored { text: b, .. }) => a == b,
            _ => false,
        }
    }
}

impl Serialize for SearchPrint {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match &self.state {
            PrintState::Stored { text, .. } => s.serialize_str(text),
            PrintState::New(_) if scope::active() => s.serialize_unit(),
            PrintState::New(_) => refuse::<S>("fingerprint"),
        }
    }
}

impl<'de> Deserialize<'de> for SearchPrint {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(d).map_err(|_| D::Error::custom("a fingerprint field is stored as text"))?;
        Ok(Self { state: PrintState::Stored { text: text.into(), bound: None } })
    }
}

impl PrintSlot for SearchPrint {
    fn part(&self) -> Result<Part<'_>> {
        Ok(match &self.state {
            PrintState::New(bytes) => Part::New(SecretBytes::from_slice(bytes)),
            PrintState::Stored { text, .. } => Part::Stored(text),
        })
    }

    fn bind(&mut self, binding: Binding) {
        if let PrintState::Stored { bound, .. } = &mut self.state {
            *bound = Some(binding);
        }
    }
}
