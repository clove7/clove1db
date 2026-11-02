//! Turning an entity into the bytes of a stored row, and a stored row into an entity, when the
//! entity has protected fields.
//!
//! Writing: the entity is serialized to a JSON value (new protected values are placeholders), each
//! protected field is replaced by its stored text, and the row is checked once more before any
//! byte is returned. Reading needs no key: the protected fields stay closed and are tied to the
//! row they came from.
use super::{
    envelope::{Place, seal_envelope},
    hashing, prints,
    keys::FieldKeys,
    method::Method,
    scope::SealScope,
    search,
    slots::{Part, RowBinding},
    spec::{SealedFields, SealedSpec},
};
use crate::units::{ClError, Result};
use serde::Serialize;
use serde_json::Value;

/// Where an entity's rows live, as the storage layer knows it.
pub(crate) struct TableSeal<'a> {
    pub table_id: &'a str,
    pub specs: &'static [SealedSpec],
    pub keys: &'a FieldKeys,
}

const MOVED: &str = "a protected value can only be written back to the table, field and row it was read from";
const UNAVAILABLE: &str = "fingerprint fields cannot be written with this version";
const NO_PRINT: &str = "a field declared with a fingerprint holds sealed text without one; nothing was saved";

/// The stored value of a sealed field: the sealed text alone, or an object that also carries the
/// fingerprint of the value.
fn stored_form(sealed: String, full: Option<String>, parts: Option<String>) -> Value {
    match (full, parts) {
        (None, None) => Value::String(sealed),
        (full, parts) => {
            let mut object = serde_json::Map::new();
            object.insert("s".into(), Value::String(sealed));
            if let Some(full) = full {
                object.insert("f".into(), Value::String(full));
            }
            if let Some(parts) = parts {
                object.insert("p".into(), Value::String(parts));
            }
            Value::Object(object)
        }
    }
}

/// Every protected field must now be stored text. A placeholder left behind, or anything else, means
/// the row must not be saved.
fn check_sealed(object: &serde_json::Map<String, Value>, specs: &[SealedSpec]) -> Result<()> {
    let text = |v: Option<&Value>| matches!(v, Some(Value::String(t)) if !t.is_empty());
    for spec in specs {
        let stored = object.get(spec.key);
        let ok = if spec.method.has_stored_print() {
            // `"p"` may be empty: a value shorter than a part has no part fingerprints.
            matches!(stored, Some(Value::Object(o))
                if text(o.get("s")) && text(o.get("f")) && (!spec.method.has_parts() || matches!(o.get("p"), Some(Value::String(_)))))
        } else {
            text(stored)
        };
        match ok {
            true => {}
            false => {
                return Err(ClError::Validation(
                    "a protected field was not sealed; nothing was saved".into(),
                ));
            }
        }
    }
    Ok(())
}

/// The stored bytes of `entity` as row `key`.
pub(crate) fn seal_row<E: Serialize + SealedFields>(
    table: &TableSeal<'_>,
    key: &str,
    entity: &E,
) -> Result<Vec<u8>> {
    let parts = entity.sealed_parts()?;
    if parts.len() != table.specs.len() {
        return Err(ClError::Validation("the protected fields of the entity do not match its table".into()));
    }
    let mut value = {
        let _step = SealScope::enter();
        serde_json::to_value(entity)?
    };
    let Some(object) = value.as_object_mut() else {
        return Err(ClError::Validation("a row with protected fields must be a JSON object".into()));
    };
    let row = RowBinding::new(table.table_id, key);
    for (spec, part) in table.specs.iter().zip(parts) {
        let stored = match part {
            Part::New(plain) if spec.method.is_sealing() => {
                let place = Place { table_id: table.table_id, field_id: spec.id, row_key: key };
                // The fingerprint is made first: a value that cannot have one stops the write
                // before anything is sealed.
                let full = if spec.method.has_stored_print() {
                    Some(search::full_print_of_json(table.keys, table.table_id, spec, plain.as_bytes())?)
                } else {
                    None
                };
                let parts = if spec.method.has_parts() {
                    Some(search::parts_of_json(table.keys, table.table_id, spec, plain.as_bytes())?)
                } else {
                    None
                };
                let cipher = table.keys.cipher(table.table_id, spec.id)?;
                let sealed = seal_envelope(&cipher, &place, plain.as_bytes())
                    .map_err(|_| ClError::Validation("a protected value could not be sealed".into()))?;
                stored_form(sealed, full, parts)
            }
            Part::New(secret) if spec.method == Method::Hash => {
                let place = Place { table_id: table.table_id, field_id: spec.id, row_key: key };
                let Some(algo) = spec.hash else {
                    return Err(ClError::Validation("a hashed field has no hash setting".into()));
                };
                Value::String(hashing::hash_value(table.keys, algo, &place, secret.as_bytes())?)
            }
            Part::New(value) if spec.method == Method::SearchPrint => {
                Value::String(prints::print_value(table.keys, table.table_id, spec.id, spec.normalize, value.as_bytes())?)
            }
            Part::New(_) => return Err(ClError::Validation(UNAVAILABLE.into())),
            Part::Closed { text, full, parts, bound } => {
                if bound != Some(&row.field(spec.id)) {
                    return Err(ClError::Validation(MOVED.into()));
                }
                // A closed value is written back as it was read, fingerprints included: they
                // cannot be made again without opening the value.
                match (spec.method.has_stored_print(), spec.method.has_parts(), full, parts) {
                    (true, false, Some(full), None) => stored_form(text.to_string(), Some(full.to_string()), None),
                    (true, true, Some(full), Some(parts)) => {
                        stored_form(text.to_string(), Some(full.to_string()), Some(parts.to_string()))
                    }
                    (true, _, _, _) => return Err(ClError::Validation(NO_PRINT.into())),
                    (false, _, None, None) => Value::String(text.to_string()),
                    (false, _, _, _) => return Err(ClError::Validation(MOVED.into())),
                }
            }
            Part::Stored(text) => {
                if spec.method != Method::SearchPrint {
                    return Err(ClError::Validation(MOVED.into()));
                }
                Value::String(text.to_string())
            }
        };
        object.insert(spec.key.to_string(), stored);
    }
    check_sealed(object, table.specs)?;
    Ok(serde_json::to_vec(&value)?)
}

/// Ties the protected fields of an entity just read to the row they came from.
#[cfg(test)]
pub(crate) fn bind_row<E: SealedFields>(table_id: &str, key: &str, entity: &mut E) {
    entity.bind_sealed(&RowBinding::new(table_id, key));
}

/// Like [`bind_row`], with the table's name for the reports of the use of a protected value.
pub(crate) fn bind_row_named<E: SealedFields>(table: &str, table_id: &str, key: &str, entity: &mut E) {
    entity.bind_sealed(&RowBinding::with_table(table, table_id, key));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CloveFields,
        crypto::{CipherKind, DataKey, HkdfHash, Key32, KeySuite, ProgrammerKey},
        field_crypto::{Hashed, Sealed, envelope::open_envelope},
    };
    use serde::Deserialize;

    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, CloveFields)]
    struct Person {
        id: String,
        name: String,
        #[clove(encrypt, id = 1)]
        phone: Sealed<String>,
        #[clove(encrypt, id = 2)]
        tags: Sealed<Vec<String>>,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, CloveFields)]
    struct Printed {
        id: String,
        #[clove(encrypt, id = 1, print = "full", normalize = "trim")]
        phone: Sealed<String>,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, CloveFields)]
    struct PrintedNumber {
        id: String,
        #[clove(encrypt, id = 1, print = "parts")]
        code: Sealed<i64>,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, CloveFields)]
    struct WithHash {
        id: String,
        #[clove(hash = "argon2id", id = 1)]
        password: Hashed,
    }

    fn keys(cipher: CipherKind, with_read: bool) -> FieldKeys {
        let suite = KeySuite { cipher, hkdf: HkdfHash::Sha256 };
        let data = DataKey::generate().unwrap();
        let read = Key32::from_bytes(&[1; 32]);
        let search = Key32::from_bytes(&[2; 32]);
        let locked = data.lock(&suite, &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
        let access = locked
            .unlock(
                &suite,
                with_read.then_some(&ProgrammerKey::Raw(&read)),
                Some(&ProgrammerKey::Raw(&search)),
            )
            .unwrap();
        FieldKeys::with_access(suite, access).unwrap()
    }

    fn person() -> Person {
        Person {
            id: "p1".into(),
            name: "visible".into(),
            phone: Sealed::new("+155500000001".into()),
            tags: Sealed::new(vec!["vip".into(), "late".into()]),
        }
    }

    fn table<'a>(keys: &'a FieldKeys) -> TableSeal<'a> {
        TableSeal { table_id: "00112233445566778899aabbccddeeff", specs: Person::SEALED, keys }
    }

    const BOTH: [CipherKind; 2] = [CipherKind::Aes256GcmSiv, CipherKind::XChaCha20Poly1305];

    #[test]
    fn a_written_row_holds_no_plaintext_and_opens_in_its_place_only() {
        for cipher in BOTH {
            let k = keys(cipher, true);
            let t = table(&k);
            let bytes = seal_row(&t, "p1", &person()).unwrap();
            let text = String::from_utf8(bytes.clone()).unwrap();
            for secret in ["15550100001", "vip", "late"] {
                assert!(!text.contains(secret), "{text}");
            }
            let json: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["name"], "visible");
            for key in ["phone", "tags"] {
                assert!(json[key].as_str().is_some_and(|s| !s.is_empty()), "{key}");
            }
            let place = Place { table_id: t.table_id, field_id: 1, row_key: "p1" };
            let cipher_1 = k.cipher(t.table_id, 1).unwrap();
            let opened = open_envelope(&cipher_1, &place, json["phone"].as_str().unwrap()).unwrap();
            assert_eq!(opened.as_bytes(), b"\"+155500000001\"");
            let other_row = Place { row_key: "p2", ..place };
            assert!(open_envelope(&cipher_1, &other_row, json["phone"].as_str().unwrap()).is_err());
            let other_field = Place { field_id: 2, ..place };
            assert!(open_envelope(&cipher_1, &other_field, json["phone"].as_str().unwrap()).is_err());
        }
    }

    #[test]
    fn writing_the_same_value_twice_gives_different_text() {
        let k = keys(CipherKind::Aes256GcmSiv, true);
        let t = table(&k);
        let a: Value = serde_json::from_slice(&seal_row(&t, "p1", &person()).unwrap()).unwrap();
        let b: Value = serde_json::from_slice(&seal_row(&t, "p1", &person()).unwrap()).unwrap();
        assert_ne!(a["phone"], b["phone"]);
        assert_ne!(a["tags"], b["tags"]);
    }

    #[test]
    fn a_row_read_back_is_closed_and_tied_to_its_place() {
        let k = keys(CipherKind::XChaCha20Poly1305, true);
        let t = table(&k);
        let bytes = seal_row(&t, "p1", &person()).unwrap();
        let mut read: Person = serde_json::from_slice(&bytes).unwrap();
        assert!(!read.phone.is_bound());
        bind_row(t.table_id, "p1", &mut read);
        assert!(read.phone.is_bound() && read.tags.is_bound());
        // Written back to its own place: the stored text is unchanged.
        let again = seal_row(&t, "p1", &read).unwrap();
        assert_eq!(bytes, again);
    }

    #[test]
    fn a_closed_value_cannot_be_written_anywhere_else() {
        let k = keys(CipherKind::Aes256GcmSiv, true);
        let t = table(&k);
        let bytes = seal_row(&t, "p1", &person()).unwrap();
        let mut read: Person = serde_json::from_slice(&bytes).unwrap();
        bind_row(t.table_id, "p1", &mut read);
        let moved = seal_row(&t, "p2", &read).unwrap_err().to_string();
        assert!(moved.contains("can only be written back"), "{moved}");
        let mut elsewhere = read.clone();
        bind_row("ffffffffffffffffffffffffffffffff", "p1", &mut elsewhere);
        // Binding is by whoever reads the row; a value read from another table is refused.
        assert!(seal_row(&t, "p1", &elsewhere).is_err());
    }

    #[test]
    fn an_unbound_closed_value_is_refused() {
        let k = keys(CipherKind::Aes256GcmSiv, true);
        let t = table(&k);
        let bytes = seal_row(&t, "p1", &person()).unwrap();
        // Read from JSON outside the storage: never bound.
        let from_api: Person = serde_json::from_slice(&bytes).unwrap();
        let err = seal_row(&t, "p1", &from_api).unwrap_err().to_string();
        assert!(err.contains("can only be written back"), "{err}");
    }

    #[test]
    fn mixing_a_new_and_a_closed_value_is_allowed_in_place() {
        let k = keys(CipherKind::XChaCha20Poly1305, true);
        let t = table(&k);
        let bytes = seal_row(&t, "p1", &person()).unwrap();
        let mut read: Person = serde_json::from_slice(&bytes).unwrap();
        bind_row(t.table_id, "p1", &mut read);
        read.phone = Sealed::new("+155500000002".into());
        let next: Value = serde_json::from_slice(&seal_row(&t, "p1", &read).unwrap()).unwrap();
        let before: Value = serde_json::from_slice(&bytes).unwrap();
        assert_ne!(next["phone"], before["phone"]);
        assert_eq!(next["tags"], before["tags"]);
    }

    #[test]
    fn a_program_without_the_read_key_cannot_write_a_protected_value() {
        let k = keys(CipherKind::Aes256GcmSiv, false);
        let t = table(&k);
        let err = seal_row(&t, "p1", &person()).unwrap_err().to_string();
        assert!(err.contains("no read key"), "{err}");
    }

    #[test]
    fn a_hashed_field_is_stored_as_a_salted_hash_tied_to_its_row() {
        let k = keys(CipherKind::Aes256GcmSiv, true);
        let t = TableSeal { table_id: "00112233445566778899aabbccddeeff", specs: WithHash::SEALED, keys: &k };
        let entity = WithHash { id: "h".into(), password: Hashed::new("hunter2") };
        let bytes = seal_row(&t, "h", &entity).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(!text.contains("hunter2"), "{text}");
        let json: Value = serde_json::from_slice(&bytes).unwrap();
        let stored = json["password"].as_str().unwrap();
        assert_eq!(stored.len(), 66);
        let place = Place { table_id: t.table_id, field_id: 1, row_key: "h" };
        assert!(hashing::verify_value(&k, crate::field_crypto::HashAlgo::Argon2id, &place, b"hunter2", stored).unwrap());
        assert!(!hashing::verify_value(&k, crate::field_crypto::HashAlgo::Argon2id, &place, b"hunter3", stored).unwrap());
        // Read back and written to its own place: the same text. Anywhere else: refused.
        let mut read: WithHash = serde_json::from_slice(&bytes).unwrap();
        bind_row(t.table_id, "h", &mut read);
        assert_eq!(seal_row(&t, "h", &read).unwrap(), bytes);
        assert!(seal_row(&t, "other", &read).is_err());
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, CloveFields)]
    struct WithPrint {
        id: String,
        #[clove(search_print, id = 1)]
        token: crate::field_crypto::SearchPrint,
    }

    #[test]
    fn a_fingerprint_field_is_stored_as_a_keyed_fingerprint_equal_across_rows() {
        let k = keys(CipherKind::Aes256GcmSiv, true);
        let t = TableSeal { table_id: "00112233445566778899aabbccddeeff", specs: WithPrint::SEALED, keys: &k };
        let entity = WithPrint { id: "t".into(), token: crate::field_crypto::SearchPrint::new("abc") };
        let one = seal_row(&t, "row-1", &entity).unwrap();
        let two = seal_row(&t, "row-2", &entity).unwrap();
        let (a, b): (Value, Value) = (serde_json::from_slice(&one).unwrap(), serde_json::from_slice(&two).unwrap());
        assert_eq!(a["token"].as_str().unwrap().len(), 43);
        // The same value gives the same fingerprint in another row: that is what a search needs.
        assert_eq!(a["token"], b["token"]);
        assert!(!String::from_utf8(one.clone()).unwrap().contains("abc"));
        // Read back and written again, in the same row or in another: the stored text is kept.
        let mut read: WithPrint = serde_json::from_slice(&one).unwrap();
        bind_row(t.table_id, "row-1", &mut read);
        assert_eq!(seal_row(&t, "row-1", &read).unwrap(), one);
        let moved: Value = serde_json::from_slice(&seal_row(&t, "row-2", &read).unwrap()).unwrap();
        assert_eq!(moved["token"], a["token"]);
        // A value that is not text is refused.
        let bytes = WithPrint { id: "t".into(), token: crate::field_crypto::SearchPrint::new([0xffu8, 0xfe]) };
        assert!(seal_row(&t, "row-1", &bytes).is_err());
    }

    fn printed_table<'a>(keys: &'a FieldKeys) -> TableSeal<'a> {
        TableSeal { table_id: "00112233445566778899aabbccddeeff", specs: Printed::SEALED, keys }
    }

    #[test]
    fn a_value_with_a_fingerprint_is_stored_as_an_object_and_written_back_unchanged() {
        for cipher in BOTH {
            let k = keys(cipher, true);
            let t = printed_table(&k);
            let entity = Printed { id: "p1".into(), phone: Sealed::new(" 5550123456 ".into()) };
            let bytes = seal_row(&t, "p1", &entity).unwrap();
            let json: Value = serde_json::from_slice(&bytes).unwrap();
            let phone = json["phone"].as_object().unwrap();
            assert_eq!(phone.len(), 2);
            assert_eq!(phone["f"].as_str().unwrap().len(), 43);
            assert!(!String::from_utf8(bytes.clone()).unwrap().contains("5550123456"));
            // The fingerprint is that of the value after the declared normalisation.
            let same = seal_row(&t, "p2", &Printed { id: "p2".into(), phone: Sealed::new("5550123456".into()) }).unwrap();
            let same: Value = serde_json::from_slice(&same).unwrap();
            assert_eq!(same["phone"]["f"], phone["f"]);
            assert_ne!(same["phone"]["s"], phone["s"], "each write has its own nonce");
            // Read back and written back to its place: the same bytes.
            let mut read: Printed = serde_json::from_slice(&bytes).unwrap();
            bind_row(t.table_id, "p1", &mut read);
            assert_eq!(seal_row(&t, "p1", &read).unwrap(), bytes);
        }
    }

    #[test]
    fn sealed_text_without_a_fingerprint_in_a_field_that_has_one_is_refused() {
        let k = keys(CipherKind::Aes256GcmSiv, true);
        let t = printed_table(&k);
        let mut read: Printed = serde_json::from_str(r#"{"id":"p1","phone":"AAAA"}"#).unwrap();
        bind_row(t.table_id, "p1", &mut read);
        let err = seal_row(&t, "p1", &read).unwrap_err().to_string();
        assert!(err.contains("without one") && err.contains("nothing was saved"), "{err}");
        // And a fingerprint on a field that has none is not taken either.
        let mut people: Person = serde_json::from_str(r#"{"id":"p1","name":"n","phone":{"s":"AAAA","f":"BBBB"},"tags":"CCCC"}"#).unwrap();
        let people_table = table(&k);
        bind_row(people_table.table_id, "p1", &mut people);
        assert!(seal_row(&people_table, "p1", &people).is_err());
    }

    #[test]
    fn a_value_that_is_not_text_cannot_have_a_fingerprint() {
        let k = keys(CipherKind::Aes256GcmSiv, true);
        let t = TableSeal { table_id: "00112233445566778899aabbccddeeff", specs: PrintedNumber::SEALED, keys: &k };
        let err = seal_row(&t, "n1", &PrintedNumber { id: "n1".into(), code: Sealed::new(42) }).unwrap_err().to_string();
        assert!(err.contains("must hold text"), "{err}");
    }

    #[test]
    fn a_fingerprint_needs_the_search_key_to_be_written() {
        let suite = KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 };
        let data = DataKey::generate().unwrap();
        let read = Key32::from_bytes(&[1; 32]);
        let search = Key32::from_bytes(&[2; 32]);
        let locked = data.lock(&suite, &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
        let access = locked.unlock(&suite, Some(&ProgrammerKey::Raw(&read)), None).unwrap();
        let k = FieldKeys::with_access(suite, access).unwrap();
        let err = seal_row(&printed_table(&k), "p1", &Printed { id: "p1".into(), phone: Sealed::new("1".into()) }).unwrap_err().to_string();
        assert!(err.contains("no search key"), "{err}");
    }

    #[test]
    fn a_left_over_placeholder_stops_the_write() {
        let mut object = serde_json::Map::new();
        object.insert("phone".into(), Value::Null);
        object.insert("tags".into(), Value::String("x".into()));
        let err = check_sealed(&object, Person::SEALED).unwrap_err().to_string();
        assert!(err.contains("nothing was saved"), "{err}");
        object.insert("phone".into(), Value::String(String::new()));
        assert!(check_sealed(&object, Person::SEALED).is_err());
        object.insert("phone".into(), Value::String("y".into()));
        assert!(check_sealed(&object, Person::SEALED).is_ok());
        object.remove("tags");
        assert!(check_sealed(&object, Person::SEALED).is_err());
    }

    #[test]
    fn a_cipher_that_a_whole_database_refuses_is_refused_here_too() {
        let suite = KeySuite { cipher: CipherKind::Aes256Gcm, hkdf: HkdfHash::Sha256 };
        let data = DataKey::generate().unwrap();
        let read = Key32::from_bytes(&[1; 32]);
        let search = Key32::from_bytes(&[2; 32]);
        let locked = data.lock(&suite, &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
        let access = locked
            .unlock(&suite, Some(&ProgrammerKey::Raw(&read)), Some(&ProgrammerKey::Raw(&search)))
            .unwrap();
        assert!(FieldKeys::with_access(suite, access).is_err());
    }
}
