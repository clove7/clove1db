//! Field-level protection: values sealed, hashed or fingerprinted before a row is written.
//!
//! A field is declared on the entity with `#[clove(...)]`. The stored value of a sealed field
//! is bound to its table, its field and its row: a value moved anywhere else does not open.
//! Nothing here writes a file; the storage layer calls into this module around row encoding.
//!
//! A field is declared with one protection method and a stable number, and its type says what
//! it holds:
//!
//! ```
//! use clove1db::{CloveFields, field_crypto::{Hashed, SealedFields, Sealed, SearchPrint}};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct Account {
//!     id: String,
//!     #[clove(encrypt, id = 1)]
//!     phone: Sealed<String>,
//!     #[clove(hash = "argon2id", id = 2)]
//!     password: Hashed,
//!     #[clove(search_print, id = 3)]
//!     token: SearchPrint,
//! }
//! assert_eq!(Account::SEALED.len(), 3);
//! ```
//!
//! A search fingerprint says which values count as the same, by normalising a value before it is
//! fingerprinted: `normalize` is a list of `"trim"`, `"lowercase"` and `"arabic"`. The fingerprint is
//! the only thing stored in that field; the original text is not, so keep it in a separate encrypted
//! field when it has to be shown. **`"arabic"` merges letters that are different letters** (ة with ه,
//! ى with ي, ؤ with و, ئ with ي, the forms of the alef), drops the vowel marks and the elongation
//! stroke, and turns the Arabic-Indic digits into digits; use it only where those spellings really
//! are the same thing to the person searching. The default is no normalisation at all.
//!
//! ```
//! use clove1db::{CloveFields, field_crypto::{SealedFields, SearchPrint}};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct Contact {
//!     id: String,
//!     #[clove(search_print, id = 1, normalize = "trim,lowercase")]
//!     email: SearchPrint,
//! }
//! assert_eq!(Contact::SEALED[0].normalize.len(), 2);
//! ```
//!
//! Combinations that cannot work are refused when the code is compiled. A protected field needs
//! a number:
//!
//! ```compile_fail
//! use clove1db::{CloveFields, field_crypto::Sealed};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct A { #[clove(encrypt)] phone: Sealed<String> }
//! ```
//!
//! One method per field:
//!
//! ```compile_fail
//! use clove1db::{CloveFields, field_crypto::Sealed};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct A { #[clove(encrypt, search_print, id = 1)] phone: Sealed<String> }
//! ```
//!
//! The same number twice:
//!
//! ```compile_fail
//! use clove1db::{CloveFields, field_crypto::Sealed};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct A {
//!     #[clove(encrypt, id = 1)] a: Sealed<String>,
//!     #[clove(encrypt, id = 1)] b: Sealed<String>,
//! }
//! ```
//!
//! A protected field cannot be skipped:
//!
//! ```compile_fail
//! use clove1db::{CloveFields, field_crypto::Sealed};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct A { #[serde(skip)] #[clove(encrypt, id = 1)] a: Sealed<String> }
//! ```
//!
//! The field type must match the method:
//!
//! ```compile_fail
//! use clove1db::{CloveFields, field_crypto::SealedFields};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct A { #[clove(encrypt, id = 1)] phone: String }
//! ```
//!
//! `print` only goes with `encrypt`:
//!
//! ```compile_fail
//! use clove1db::{CloveFields, field_crypto::Hashed};
//! use serde::{Deserialize, Serialize};
//! #[derive(Serialize, Deserialize, CloveFields)]
//! struct A { #[clove(hash = "argon2id", print = "full", id = 1)] p: Hashed }
//! ```
mod b64;
pub(crate) mod carried;
mod compat;
mod confirm;
mod scan;
mod envelope;
mod grant;
mod hashing;
mod hooks;
pub(crate) mod keyfile;
pub(crate) mod keystore;
mod keys;
mod method;
mod migrate;
mod parts;
mod prints;
mod rowcodec;
mod scope;
mod search;
mod slots;
mod spec;

#[cfg(test)]
mod combined_tests;
#[cfg(test)]
mod keyfile_tests;
#[cfg(test)]
mod entity_tests;

pub use crate::metadata::SealedField;
pub use compat::{Plan, check_layout};
pub use grant::{ReadGrant, Verifier};
pub use method::{HashAlgo, Method};
pub use confirm::{PartResults, PartSearch};
pub use scan::SealedScan;
pub use search::{HashHandle, PrintField, PrintHandle, ScanHandle, SearchGrant};
pub use slots::{
    Binding, ClosedView, EncryptSlot, Hashed, HashSlot, Part, PrintSlot, RowBinding, Sealed, SearchPrint,
};
pub use spec::{SealedFields, SealedSpec};

pub(crate) use hashing::{same_settings, settings_fingerprint};
pub(crate) use prints::settings_fingerprint as print_settings_fingerprint;
pub(crate) use hooks::{SealedHooks, SealedKit};
pub(crate) use search::{check_filter, print_steps};
pub(crate) use keys::FieldKeys;
#[allow(unused_imports)]
pub(crate) use migrate::{Row, Stored, hash_plain, hash_root_changed, open_stored, parts_are_set_up, print_plain, print_root_changed, protect_plain, read_stored, reseal_history_doc, reseal_row, seal_plain, settings_checks, apply_checks, with_prints, without_prints};
pub(crate) use scope::SealScope;
