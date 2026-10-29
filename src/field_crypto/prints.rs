//! Search fingerprints: a keyed, fast fingerprint of a normalised value, for equality search.
//!
//! Stored form: URL-safe base64 of `HMAC-SHA-256(field search key, label || normalised value)`, 43
//! characters. The same value gives the same fingerprint in every row of the table (that is what
//! makes equality search possible), so a fingerprint is not tied to a row. It cannot be reversed,
//! and without the search key a file says nothing about the value; with the key, a guess can be
//! confirmed, which is the property that a search needs.
use super::{b64, keys::FieldKeys};
use crate::{
    crypto::MacKind,
    fields::{TransformKind, transform},
    units::{ClError, Result},
};

const LABEL: &[u8] = b"cf-print";

fn fail(what: &'static str) -> ClError {
    ClError::Validation(what.into())
}

/// The value after the declared normalisation, in order.
pub(crate) fn normalize(text: &str, kinds: &[TransformKind]) -> String {
    kinds.iter().fold(text.to_string(), |value, kind| transform(&value, kind))
}

/// The stored text for `value` (UTF-8 text) in this field.
pub(crate) fn print_value(
    keys: &FieldKeys,
    table_id: &str,
    field_id: u32,
    kinds: &[TransformKind],
    value: &[u8],
) -> Result<String> {
    let text = std::str::from_utf8(value).map_err(|_| fail("a fingerprint value must be text"))?;
    let key = keys.print_key(table_id, field_id)?;
    let mut data = LABEL.to_vec();
    data.extend_from_slice(normalize(text, kinds).as_bytes());
    let tag = MacKind::HmacSha256.mac(&key, &data).map_err(|_| fail("the fingerprint could not be made"));
    zeroize::Zeroize::zeroize(&mut data);
    Ok(b64::encode(tag?.as_bytes()))
}

/// A keyed fingerprint of the normalisation of one field, stored in the table description so that a
/// later change of the normalisation is found when the database is opened: every stored fingerprint
/// was made with the old one.
pub(crate) fn settings_fingerprint(
    keys: &FieldKeys,
    table_id: &str,
    field_id: u32,
    kinds: &[TransformKind],
) -> Result<String> {
    let key = keys.print_key(table_id, field_id)?;
    let mut data = b"cf-print-settings".to_vec();
    data.push(1);
    for kind in kinds {
        data.push(match kind {
            TransformKind::Trim => 1,
            TransformKind::Lowercase => 2,
            TransformKind::NormalizeArabic => 3,
        });
    }
    let tag = MacKind::HmacSha256.mac(&key, &data).map_err(|_| fail("the fingerprint settings could not be made"))?;
    Ok(b64::encode(tag.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherKind, DataKey, HkdfHash, Key32, KeySuite, ProgrammerKey};

    fn access_keys(seed: u8, read: bool, search: bool) -> FieldKeys {
        let suite = KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 };
        let data = DataKey::generate().unwrap();
        let r = Key32::from_bytes(&[seed; 32]);
        let s = Key32::from_bytes(&[2; 32]);
        let locked = data.lock(&suite, &ProgrammerKey::Raw(&r), &ProgrammerKey::Raw(&s)).unwrap();
        let access = locked
            .unlock(&suite, read.then_some(&ProgrammerKey::Raw(&r)), search.then_some(&ProgrammerKey::Raw(&s)))
            .unwrap();
        FieldKeys::with_access(suite, access).unwrap()
    }

    #[test]
    fn the_same_value_gives_the_same_print_and_another_does_not() {
        let k = access_keys(1, true, true);
        let a = print_value(&k, "t1", 5, &[], b"alice@example.com").unwrap();
        assert_eq!(a.len(), 43);
        assert_eq!(a, print_value(&k, "t1", 5, &[], b"alice@example.com").unwrap());
        assert_ne!(a, print_value(&k, "t1", 5, &[], b"bob@example.com").unwrap());
        assert!(!a.contains("alice"));
        // Another field or table or database: another key, so another print.
        assert_ne!(a, print_value(&k, "t1", 6, &[], b"alice@example.com").unwrap());
        assert_ne!(a, print_value(&k, "t2", 5, &[], b"alice@example.com").unwrap());
        let other_database = access_keys(1, true, true);
        assert_ne!(a, print_value(&other_database, "t1", 5, &[], b"alice@example.com").unwrap());
    }

    #[test]
    fn the_declared_normalisation_is_applied_before_the_print() {
        let k = access_keys(1, true, true);
        let kinds = [TransformKind::Trim, TransformKind::Lowercase];
        let a = print_value(&k, "t1", 5, &kinds, b"  Alice@Example.COM ").unwrap();
        assert_eq!(a, print_value(&k, "t1", 5, &kinds, b"alice@example.com").unwrap());
        // Without it they differ.
        assert_ne!(
            print_value(&k, "t1", 5, &[], b"  Alice@Example.COM ").unwrap(),
            print_value(&k, "t1", 5, &[], b"alice@example.com").unwrap()
        );
        // Arabic digits and letter forms reach one print.
        let arabic = [TransformKind::NormalizeArabic];
        assert_eq!(
            print_value(&k, "t1", 5, &arabic, "٠٥٠١٢٣".as_bytes()).unwrap(),
            print_value(&k, "t1", 5, &arabic, b"050123").unwrap()
        );
    }

    #[test]
    fn the_search_key_alone_makes_prints_and_the_read_key_alone_cannot() {
        let both = access_keys(1, true, true);
        let search_only = access_keys(1, false, true);
        // Both hold the same data key only if made from one; here they are separate databases, so
        // only the capability is compared.
        assert!(print_value(&search_only, "t1", 5, &[], b"x").is_ok());
        let read_only = access_keys(1, true, false);
        let err = print_value(&read_only, "t1", 5, &[], b"x").unwrap_err().to_string();
        assert!(err.contains("no search key"), "{err}");
        assert!(print_value(&both, "t1", 5, &[], b"x").is_ok());
    }

    #[test]
    fn a_value_that_is_not_text_is_refused() {
        let k = access_keys(1, true, true);
        let err = print_value(&k, "t1", 5, &[], &[0xff, 0xfe]).unwrap_err().to_string();
        assert!(err.contains("must be text"), "{err}");
    }

    #[test]
    fn the_settings_fingerprint_follows_the_normalisation_the_field_and_the_key() {
        let k = access_keys(1, true, true);
        let kinds = [TransformKind::Trim, TransformKind::Lowercase];
        let a = settings_fingerprint(&k, "t1", 5, &kinds).unwrap();
        assert_eq!(a, settings_fingerprint(&k, "t1", 5, &kinds).unwrap());
        assert_ne!(a, settings_fingerprint(&k, "t1", 5, &[TransformKind::Trim]).unwrap());
        assert_ne!(a, settings_fingerprint(&k, "t1", 5, &[TransformKind::Lowercase, TransformKind::Trim]).unwrap());
        assert_ne!(a, settings_fingerprint(&k, "t1", 6, &kinds).unwrap());
        assert_eq!(a.len(), 43);
    }
}
