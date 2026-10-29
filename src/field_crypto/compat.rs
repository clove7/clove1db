//! What a table remembers about its protected fields, and the check that the code still matches.
use super::{method::Method, spec::SealedSpec};
use crate::units::{ClError, Result};
use serde::{Deserialize, Serialize};

/// One protected field as written in the table description when the table was created.
///
/// The hash settings and the cipher are not here: they come from the code, so a reader of the
/// description learns which fields are protected and how, but not with what.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedField {
    pub id: u32,
    /// The key of the field in the stored row.
    pub name: String,
    /// [`Method::code`].
    pub method: u8,
    /// For a verification hash: a keyed fingerprint of its settings, so a later change of the
    /// settings in code is found at open. Absent for the other methods and for tables made before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    /// For fingerprints of parts: the length of a part, in characters. Absent for the other methods
    /// and for a table made before the parts were fingerprinted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<u8>,
    /// For fingerprints of parts: the bits kept of each part's fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<u8>,
}

impl SealedField {
    pub fn from_spec(spec: &SealedSpec) -> Self {
        let parts = spec.method.has_parts();
        Self {
            id: spec.id,
            name: spec.key.to_string(),
            method: spec.method.code(),
            check: None,
            window: parts.then_some(spec.window),
            bits: parts.then_some(spec.bits),
        }
    }
}

/// What opening a table decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Nothing to record: either no protected fields, or the same ones as before.
    Same,
    /// A new table with protected fields: record these.
    Create(Vec<SealedField>),
}

fn changed(table: &str, what: &str) -> ClError {
    ClError::Validation(format!(
        "table '{table}': {what}. Changing how a field is stored is a migration; nothing was written"
    ))
}

/// Compares the protected fields the code declares with those the table remembers. Any difference
/// in which fields are protected, in their key, or in their method is an error that writes nothing.
///
/// `table_is_new` is true when the table has no rows and no stored description yet.
pub fn check_layout(
    table: &str,
    code: &[SealedSpec],
    stored: &[SealedField],
    table_is_new: bool,
) -> Result<Plan> {
    for (i, a) in code.iter().enumerate() {
        if code[i + 1..].iter().any(|b| b.id == a.id) {
            return Err(ClError::Validation(format!(
                "table '{table}': field number {} is used by more than one protected field",
                a.id
            )));
        }
    }
    match (code.is_empty(), stored.is_empty()) {
        (true, true) => return Ok(Plan::Same),
        (false, true) => {
            return if table_is_new {
                Ok(Plan::Create(code.iter().map(SealedField::from_spec).collect()))
            } else {
                Err(changed(table, "protecting fields of a table that already exists"))
            };
        }
        (true, false) => return Err(changed(table, "the table has protected fields that the code no longer declares")),
        (false, false) => {}
    }
    if code.len() != stored.len() {
        return Err(changed(table, "the set of protected fields differs from the one the table was created with"));
    }
    for spec in code {
        let Some(old) = stored.iter().find(|s| s.id == spec.id) else {
            return Err(changed(table, "the set of protected fields differs from the one the table was created with"));
        };
        if old.name != spec.key {
            return Err(changed(table, "a protected field is stored under a different key"));
        }
        if old.method != spec.method.code() {
            let was = Method::from_code(old.method).map_or("an unknown method", Method::label);
            return Err(changed(
                table,
                &format!("a protected field was created as '{was}' and is now declared as '{}'", spec.method.label()),
            ));
        }
        // The length of a part and the bits kept of its fingerprint decide what every stored
        // fingerprint of the field is: another choice would not find the rows already written.
        let (window, bits) = if spec.method.has_parts() { (Some(spec.window), Some(spec.bits)) } else { (None, None) };
        if old.window != window || old.bits != bits {
            return Err(changed(
                table,
                "the part fingerprints of a field are made differently from how the table was created (the length of a part or the bits kept)",
            ));
        }
    }
    Ok(Plan::Same)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_crypto::HashAlgo;

    fn spec(id: u32, key: &'static str, method: Method) -> SealedSpec {
        let hash = (method == Method::Hash).then_some(HashAlgo::Argon2id);
        let (window, bits) = if method.has_parts() { (3, 12) } else { (0, 0) };
        SealedSpec { id, key, method, hash, normalize: &[], window, bits }
    }

    #[test]
    fn the_length_of_a_part_and_the_bits_are_recorded_and_checked() {
        let code = [spec(1, "phone", Method::EncryptPartPrints)];
        let Plan::Create(fields) = check_layout("t", &code, &[], true).unwrap() else { panic!("must create") };
        assert_eq!((fields[0].window, fields[0].bits), (Some(3), Some(12)));
        assert_eq!(check_layout("t", &code, &fields, false).unwrap(), Plan::Same);
        for other in [(4, 12), (3, 10)] {
            let changed = [SealedSpec { window: other.0, bits: other.1, ..code[0] }];
            let err = check_layout("t", &changed, &fields, false).unwrap_err().to_string();
            assert!(err.contains("migration") && err.contains("length of a part"), "{err}");
        }
        // A table made before the parts were fingerprinted recorded neither.
        let mut before = fields.clone();
        before[0].window = None;
        before[0].bits = None;
        let err = check_layout("t", &code, &before, false).unwrap_err().to_string();
        assert!(err.contains("migration"), "{err}");
        // The other methods record neither.
        let plain = Plan::Create(vec![SealedField::from_spec(&spec(2, "x", Method::EncryptFullPrint))]);
        assert_eq!(check_layout("t", &[spec(2, "x", Method::EncryptFullPrint)], &[], true).unwrap(), plain);
    }

    fn stored(specs: &[SealedSpec]) -> Vec<SealedField> {
        specs.iter().map(SealedField::from_spec).collect()
    }

    #[test]
    fn no_protected_fields_anywhere_is_unchanged_behaviour() {
        assert_eq!(check_layout("t", &[], &[], true).unwrap(), Plan::Same);
        assert_eq!(check_layout("t", &[], &[], false).unwrap(), Plan::Same);
    }

    #[test]
    fn a_new_table_records_its_fields() {
        let code = [spec(1, "phone", Method::Encrypt), spec(2, "pw", Method::Hash)];
        assert_eq!(check_layout("t", &code, &[], true).unwrap(), Plan::Create(stored(&code)));
    }

    #[test]
    fn protecting_an_existing_table_is_refused() {
        let code = [spec(1, "phone", Method::Encrypt)];
        let err = check_layout("t", &code, &[], false).unwrap_err().to_string();
        assert!(err.contains("migration") && err.contains("nothing was written"), "{err}");
    }

    #[test]
    fn the_same_declaration_matches_in_any_order() {
        let code = [spec(1, "phone", Method::Encrypt), spec(2, "pw", Method::Hash)];
        let mut old = stored(&code);
        old.reverse();
        assert_eq!(check_layout("t", &code, &old, false).unwrap(), Plan::Same);
    }

    #[test]
    fn a_different_method_key_or_set_is_refused() {
        let base = [spec(1, "phone", Method::Encrypt), spec(2, "pw", Method::Hash)];
        let old = stored(&base);
        let cases: Vec<Vec<SealedSpec>> = vec![
            vec![spec(1, "phone", Method::EncryptFullPrint), spec(2, "pw", Method::Hash)],
            vec![spec(1, "phone2", Method::Encrypt), spec(2, "pw", Method::Hash)],
            vec![spec(1, "phone", Method::Encrypt)],
            vec![spec(1, "phone", Method::Encrypt), spec(3, "pw", Method::Hash)],
            vec![],
        ];
        for code in cases {
            let err = check_layout("t", &code, &old, false).unwrap_err().to_string();
            assert!(err.contains("migration"), "{err}");
        }
    }

    #[test]
    fn two_fields_with_one_number_are_refused() {
        let code = [spec(1, "a", Method::Encrypt), spec(1, "b", Method::Encrypt)];
        assert!(check_layout("t", &code, &[], true).is_err());
    }

    #[test]
    fn the_description_does_not_name_a_cipher() {
        let text = serde_json::to_string(&stored(&[spec(1, "phone", Method::Encrypt)])).unwrap();
        for word in ["aes", "chacha", "gcm", "argon", "scrypt"] {
            assert!(!text.to_lowercase().contains(word), "{text}");
        }
    }

    #[test]
    fn method_codes_are_stable() {
        let codes: Vec<u8> = [
            Method::Encrypt,
            Method::EncryptFullPrint,
            Method::EncryptPartPrints,
            Method::Hash,
            Method::SearchPrint,
        ]
        .iter()
        .map(|m| m.code())
        .collect();
        assert_eq!(codes, [1, 2, 3, 4, 5]);
        for c in 1..=5u8 {
            assert_eq!(Method::from_code(c).unwrap().code(), c);
        }
        assert!(Method::from_code(0).is_none() && Method::from_code(6).is_none());
    }
}
