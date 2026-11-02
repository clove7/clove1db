//! The pieces that changing how a table's fields are protected, after the table was made, needs from
//! this module: the stored form of one field made from its plain value (or from its sealed one), and
//! a row read as raw values so that a field that does not change stays the very bytes it was.
//!
//! The stored forms are those of [`super::rowcodec`]. That file is not changed; a test here writes the
//! same rows both ways and compares them, so the two cannot drift apart.
//!
//! A row is not parsed into numbers and text: `serde_json` here has neither `arbitrary_precision` nor
//! `float_roundtrip`, so a number that went through a `Value` could lose digits. Every value of the
//! row is kept as the text it was written as, and only the fields that change are replaced.
#![allow(dead_code)] // used by `migration::encrypted::fields`, which is written next
use super::{
    envelope::{Place, open_envelope, seal_envelope},
    hashing, prints,
    keys::FieldKeys,
    search,
    spec::SealedSpec,
};
use crate::{
    crypto::SecretBytes,
    units::{ClError, Result},
};
use serde::{Deserialize, Deserializer, de::{MapAccess, Visitor}};
use serde_json::{Value, value::RawValue};
use zeroize::Zeroizing;

fn bad(why: &str) -> ClError {
    ClError::MigrationError(why.to_string())
}

fn json_string(text: &str) -> String {
    serde_json::to_string(text).expect("a string serializes")
}

/// A row as the object it is, with every value kept as the text it was written as and the fields in
/// their order.
pub(crate) struct Row {
    entries: Vec<(String, Box<RawValue>)>,
}

impl<'de> Deserialize<'de> for Row {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Entries;
        impl<'de> Visitor<'de> for Entries {
            type Value = Row;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> std::result::Result<Row, M::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry::<String, Box<RawValue>>()? {
                    entries.push(entry);
                }
                Ok(Row { entries })
            }
        }
        d.deserialize_map(Entries)
    }
}

impl Row {
    /// A stored row. Not an object, or a key twice: an error, and nothing is guessed.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let row: Row = serde_json::from_slice(bytes).map_err(|_| bad("a stored row is not a JSON object"))?;
        for (i, (key, _)) in row.entries.iter().enumerate() {
            if row.entries[..i].iter().any(|(k, _)| k == key) {
                return Err(bad("a stored row has a field twice"));
            }
        }
        Ok(row)
    }

    /// The text of the value of `key`, exactly as it was written.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v.get())
    }

    /// Replace the value of `key` (it must be there) with `json`, which must be one JSON value.
    pub(crate) fn set(&mut self, key: &str, json: String) -> Result<()> {
        let value = RawValue::from_string(json).map_err(|_| bad("a new field value is not JSON"))?;
        match self.entries.iter_mut().find(|(k, _)| k == key) {
            Some(entry) => {
                entry.1 = value;
                Ok(())
            }
            None => Err(bad("a stored row has no such field")),
        }
    }

    /// The row written again: the same fields in the same order, each value as its own text.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.entries.iter().map(|(k, v)| k.len() + v.get().len() + 4).sum::<usize>());
        out.push(b'{');
        for (i, (key, value)) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(json_string(key).as_bytes());
            out.push(b':');
            out.extend_from_slice(value.get().as_bytes());
        }
        out.push(b'}');
        out
    }

    /// Whether every field but `changed` is, in `other`, the very text it is here, and `other` holds
    /// no other field and no other order. This is the byte-for-byte check of a migrated row.
    pub(crate) fn same_but(&self, other: &Row, changed: &[&str]) -> bool {
        fn keep<'r>(row: &'r Row, changed: &[&str]) -> Vec<(&'r str, &'r str)> {
            row.entries.iter().filter(|(k, _)| !changed.contains(&k.as_str())).map(|(k, v)| (k.as_str(), v.get())).collect()
        }
        fn keys(row: &Row) -> Vec<&str> {
            row.entries.iter().map(|(k, _)| k.as_str()).collect()
        }
        keep(self, changed) == keep(other, changed) && keys(self) == keys(other)
    }
}

/// A protected field as it is stored: the sealed text, and the fingerprints beside it if it has any.
pub(crate) struct Stored {
    pub sealed: String,
    pub full: Option<String>,
    pub parts: Option<String>,
}

/// Read the stored value of a sealed field: a text, or the object `{"s", "f", "p"}`.
pub(crate) fn read_stored(raw: &str) -> Result<Stored> {
    let wrong = || bad("a protected field does not have the stored form of a sealed value");
    match serde_json::from_str::<Value>(raw).map_err(|_| wrong())? {
        Value::String(sealed) => Ok(Stored { sealed, full: None, parts: None }),
        Value::Object(object) => {
            let text = |key: &str| -> Result<Option<String>> {
                match object.get(key) {
                    None => Ok(None),
                    Some(Value::String(t)) => Ok(Some(t.clone())),
                    Some(_) => Err(wrong()),
                }
            };
            let sealed = text("s")?.ok_or_else(wrong)?;
            if object.keys().any(|k| !["s", "f", "p"].contains(&k.as_str())) {
                return Err(wrong());
            }
            Ok(Stored { sealed, full: text("f")?, parts: text("p")? })
        }
        _ => Err(wrong()),
    }
}

/// The stored value of a sealed field, as JSON text: the sealed text alone, or the object that also
/// carries the fingerprints (the same as the row codec writes it).
fn stored_form(sealed: String, full: Option<String>, parts: Option<String>) -> String {
    match (full, parts) {
        (None, None) => json_string(&sealed),
        (full, parts) => {
            let mut object = serde_json::Map::new();
            object.insert("s".into(), Value::String(sealed));
            if let Some(full) = full {
                object.insert("f".into(), Value::String(full));
            }
            if let Some(parts) = parts {
                object.insert("p".into(), Value::String(parts));
            }
            serde_json::to_string(&Value::Object(object)).expect("an object of texts serializes")
        }
    }
}

/// The fingerprints `spec` stores beside a sealed value, made from the JSON of the value.
fn prints_for(keys: &FieldKeys, table_id: &str, spec: &SealedSpec, plain_json: &[u8]) -> Result<(Option<String>, Option<String>)> {
    let full = if spec.method.has_stored_print() {
        Some(search::full_print_of_json(keys, table_id, spec, plain_json)?)
    } else {
        None
    };
    let parts = if spec.method.has_parts() { Some(search::parts_of_json(keys, table_id, spec, plain_json)?) } else { None };
    Ok((full, parts))
}

/// The stored value of a sealing field (`encrypt`, with or without fingerprints) for the value whose
/// JSON is `plain_json`, in row `row_key`. A fresh nonce each time.
pub(crate) fn seal_plain(keys: &FieldKeys, table_id: &str, spec: &SealedSpec, row_key: &str, plain_json: &[u8]) -> Result<String> {
    if !spec.method.is_sealing() {
        return Err(bad("this field is not one that seals its value"));
    }
    // fingerprints first: a value that cannot have one stops the change before anything is sealed
    let (full, parts) = prints_for(keys, table_id, spec, plain_json)?;
    let place = Place { table_id, field_id: spec.id, row_key };
    let cipher = keys.cipher(table_id, spec.id)?;
    let sealed = seal_envelope(&cipher, &place, plain_json).map_err(|_| bad("a value could not be sealed"))?;
    Ok(stored_form(sealed, full, parts))
}

/// The JSON of the value a sealed field holds, opened. Needs the read key.
pub(crate) fn open_stored(keys: &FieldKeys, table_id: &str, field_id: u32, row_key: &str, stored: &Stored) -> Result<SecretBytes> {
    let cipher = keys.cipher(table_id, field_id)?;
    let place = Place { table_id, field_id, row_key };
    open_envelope(&cipher, &place, &stored.sealed)
        .map_err(|_| bad("a protected value did not open with these keys and this place; nothing was changed"))
}

/// A sealed value kept as it is, with the fingerprints `spec` stores made again from `plain_json`
/// (the value, opened). The sealed text is not made again.
pub(crate) fn with_prints(keys: &FieldKeys, table_id: &str, spec: &SealedSpec, sealed: &str, plain_json: &[u8]) -> Result<String> {
    let (full, parts) = prints_for(keys, table_id, spec, plain_json)?;
    Ok(stored_form(sealed.to_string(), full, parts))
}

/// A sealed value kept as it is, without fingerprints. Needs no key.
pub(crate) fn without_prints(stored: &Stored) -> String {
    stored_form(stored.sealed.clone(), None, None)
}

fn text_of(plain_json: &[u8], what: &'static str) -> Result<Zeroizing<String>> {
    serde_json::from_slice::<String>(plain_json).map(Zeroizing::new).map_err(|_| bad(what))
}

/// The stored text of a verification hash of the value whose JSON is `plain_json` (it must be text).
/// The hash is slow on purpose and cannot be undone.
pub(crate) fn hash_plain(keys: &FieldKeys, table_id: &str, spec: &SealedSpec, row_key: &str, plain_json: &[u8]) -> Result<String> {
    let secret = text_of(plain_json, "only a text can become a verification hash")?;
    let Some(algo) = spec.hash else {
        return Err(bad("a hashed field has no hash setting"));
    };
    let place = Place { table_id, field_id: spec.id, row_key };
    Ok(json_string(&hashing::hash_value(keys, algo, &place, secret.as_bytes())?))
}

/// The stored text of the search fingerprint of the value whose JSON is `plain_json` (it must be
/// text). The value is not kept.
pub(crate) fn print_plain(keys: &FieldKeys, table_id: &str, spec: &SealedSpec, plain_json: &[u8]) -> Result<String> {
    let value = text_of(plain_json, "only a text can become a search fingerprint")?;
    Ok(json_string(&prints::print_value(keys, table_id, spec.id, spec.normalize, value.as_bytes())?))
}

/// The stored value of `spec` for the value whose JSON is `plain_json`, by the method the spec names.
pub(crate) fn protect_plain(keys: &FieldKeys, table_id: &str, spec: &SealedSpec, row_key: &str, plain_json: &[u8]) -> Result<String> {
    use super::method::Method;
    match spec.method {
        Method::Encrypt | Method::EncryptFullPrint | Method::EncryptPartPrints => seal_plain(keys, table_id, spec, row_key, plain_json),
        Method::Hash => hash_plain(keys, table_id, spec, row_key, plain_json),
        Method::SearchPrint => print_plain(keys, table_id, spec, plain_json),
    }
}

/// Check that the fingerprints of the parts of a value can be made with this spec (a part longer than
/// the value has none, which is fine). Used by the planner before it touches a row.
pub(crate) fn parts_are_set_up(spec: &SealedSpec) -> bool {
    !spec.method.has_parts() || (spec.window != 0 && (1..=64).contains(&spec.bits))
}

/// Where the keys behind a hash and the keys behind a fingerprint come from is a fixed probe place:
/// the same roots give the same key there, and other roots do not.
const PROBE: &str = "roots-probe";

/// Whether the read root differs (every verification hash was made with a key from it).
pub(crate) fn hash_root_changed(old: &FieldKeys, new: &FieldKeys) -> Result<bool> {
    Ok(old.hash_key(PROBE, 0)? != new.hash_key(PROBE, 0)?)
}

/// Whether the search root differs (every search fingerprint, and every fingerprint of a part, was
/// made with a key from it).
pub(crate) fn print_root_changed(old: &FieldKeys, new: &FieldKeys) -> Result<bool> {
    Ok(old.print_key(PROBE, 0)? != new.print_key(PROBE, 0)?)
}

/// A raw stored row of a table whose protected values are moved from the keys `old` to the keys
/// `new` (another cipher, other keys, or both): each sealed value is opened with `old`, sealed with
/// `new` in the same place, and checked to open to the same value; the fingerprints beside it are
/// made again from that value. A hash or a search fingerprint is kept as it is: if the roots changed
/// its key goes with it (`carried`), and without that key it would no longer be valid. Every other
/// field stays the very bytes it was.
pub(crate) fn reseal_row(
    old: &FieldKeys,
    new: &FieldKeys,
    table_id: &str,
    specs: &[SealedSpec],
    row_key: &str,
    row: &[u8],
) -> Result<Vec<u8>> {
    use super::method::Method;
    let mut parsed = Row::parse(row)?;
    for spec in specs {
        let raw = parsed
            .get(spec.key)
            .ok_or_else(|| bad("a stored row has no value for a protected field; nothing was changed"))?
            .to_string();
        match spec.method {
            // The value stays as it is. If the roots changed, its key is carried over to the new roots
            // (`carried::carry_plan`), so it is still the key the value was made with.
            Method::Hash | Method::SearchPrint => {}
            _ => {
                let stored = read_stored(&raw)?;
                let plain = open_stored(old, table_id, spec.id, row_key, &stored)?;
                let fresh = seal_plain(new, table_id, spec, row_key, plain.as_bytes())?;
                let made = read_stored(&fresh)?;
                let again = open_stored(new, table_id, spec.id, row_key, &made)?;
                if !crate::crypto::ct_eq(again.as_bytes(), plain.as_bytes()) {
                    return Err(bad("a value did not open to the same value after it was sealed again; nothing was changed"));
                }
                // The fingerprints do not change while the search root and the settings stay: a
                // difference means something else was different, and it is not guessed at.
                if spec.method.has_stored_print()
                    && !print_root_changed(old, new)?
                    && (stored.full != made.full || stored.parts != made.parts)
                {
                    return Err(bad("the fingerprints made again differ from the stored ones with the same keys; nothing was changed"));
                }
                parsed.set(spec.key, fresh)?;
            }
        }
    }
    Ok(parsed.encode())
}

/// [`reseal_row`] for a record of the backup history: the payload (`doc`) is the row, of the row
/// named in the record. A record of a deletion has none and is returned as it is. A record that is
/// not in the current form is refused (open the database once to bring the history to it).
pub(crate) fn reseal_history_doc(
    old: &FieldKeys,
    new: &FieldKeys,
    table_id: &str,
    specs: &[SealedSpec],
    record: &[u8],
) -> Result<Vec<u8>> {
    use crate::backup::codec::{decode_record, encode_record, is_v2};
    let unreadable = |_| bad("a record of the backup history cannot be read; nothing was changed");
    if !is_v2(record).map_err(unreadable)? {
        return Err(bad("a record of the backup history is not in the current form: open the database once to bring it to it; nothing was changed"));
    }
    let mut parsed = decode_record("", "", record).map_err(unreadable)?;
    let Some(data) = parsed.data.take() else {
        return Ok(record.to_vec());
    };
    let key = parsed.key.clone();
    parsed.data = Some(reseal_row(old, new, table_id, specs, &key, &data)?);
    encode_record(&parsed).map_err(unreadable)
}

/// The `check` each field of a table has in its description under the keys `keys`: the keyed
/// fingerprint of the settings of a hash, a whole-value or part fingerprint, or a fingerprint alone;
/// `None` for a field that only seals. `keys` must have the carried keys in place (see
/// [`super::carried::install_items`]), so a hash or a fingerprint that was carried keeps the `check` it
/// had, and the fingerprints made again with the new roots get theirs.
pub(crate) fn settings_checks(keys: &FieldKeys, table_id: &str, specs: &[SealedSpec]) -> Result<Vec<(u32, Option<String>)>> {
    use super::method::Method;
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let check = match spec.method {
            Method::Encrypt => None,
            Method::Hash => {
                let algo = spec.hash.ok_or_else(|| bad("a hashed field has no hash setting"))?;
                Some(hashing::settings_fingerprint(keys, table_id, spec.id, algo)?)
            }
            Method::EncryptFullPrint | Method::EncryptPartPrints | Method::SearchPrint => {
                Some(prints::settings_fingerprint(keys, table_id, spec.id, spec.normalize)?)
            }
        };
        out.push((spec.id, check));
    }
    Ok(out)
}

/// Put the checks of [`settings_checks`] into the description of a table's fields (by field number).
/// A field with no entry is left as it is.
pub(crate) fn apply_checks(fields: &mut [super::SealedField], checks: &[(u32, Option<String>)]) {
    for field in fields {
        if let Some((_, check)) = checks.iter().find(|(id, _)| *id == field.id) {
            field.check = check.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CloveFields,
        crypto::{CipherKind, DataKey, HkdfHash, Key32, KeySuite, ProgrammerKey},
        field_crypto::{
            Hashed, Sealed, SearchPrint,
            rowcodec::{TableSeal, bind_row, seal_row},
            spec::SealedFields,
        },
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Default, Serialize, Deserialize, CloveFields)]
    struct Mixed {
        id: String,
        #[clove(encrypt, id = 1)]
        a: Sealed<String>,
        #[clove(encrypt, id = 2, print = "full", normalize = "trim")]
        b: Sealed<String>,
        #[clove(encrypt, id = 3, print = "parts")]
        c: Sealed<String>,
        #[clove(hash = "argon2id", id = 4)]
        d: Hashed,
        #[clove(search_print, id = 5, normalize = "trim,lowercase")]
        e: SearchPrint,
    }

    const TABLE_ID: &str = "00112233445566778899aabbccddeeff";
    const BOTH: [CipherKind; 2] = [CipherKind::Aes256GcmSiv, CipherKind::XChaCha20Poly1305];

    fn keys(cipher: CipherKind) -> FieldKeys {
        let suite = KeySuite { cipher, hkdf: HkdfHash::Sha256 };
        let data = DataKey::generate().unwrap();
        let read = Key32::from_bytes(&[1; 32]);
        let search = Key32::from_bytes(&[2; 32]);
        let locked = data.lock(&suite, &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
        let access = locked.unlock(&suite, Some(&ProgrammerKey::Raw(&read)), Some(&ProgrammerKey::Raw(&search))).unwrap();
        FieldKeys::with_access(suite, access).unwrap()
    }

    const PLAIN_ROW: &str = r#"{"id":"x","a":"alpha","b":" bee ","c":"gamma ray","d":"hunter2","e":" ABC "}"#;

    #[test]
    fn a_field_that_does_not_change_stays_the_very_bytes_it_was() {
        // A number past u64, a float that rounds, an escape, a surrogate pair, an exponent: none may move.
        let original = r#"{"id":"r1","big":123456789012345678901234567890,"near":0.1000000000000000055511151231257827,"exp":1.5E+300,"text":"café 😀 \"q\" \\ /","list":[1,2.50,{"k":null}],"phone":"+155500000001"}"#;
        let mut row = Row::parse(original.as_bytes()).unwrap();
        row.set("phone", "\"sealed\"".into()).unwrap();
        let bytes = row.encode();
        let text = std::str::from_utf8(&bytes).unwrap();
        for kept in [
            "123456789012345678901234567890",
            "0.1000000000000000055511151231257827",
            "1.5E+300",
            r#""café 😀 \"q\" \\ /""#,
            r#"[1,2.50,{"k":null}]"#,
        ] {
            assert!(text.contains(kept), "{kept} in {text}");
        }
        assert!(!text.contains("+155500000001"));
        let after = Row::parse(&bytes).unwrap();
        assert!(Row::parse(original.as_bytes()).unwrap().same_but(&after, &["phone"]));
        // The fields keep their order, and a changed neighbour is noticed.
        assert!(text.starts_with(r#"{"id":"r1","big":"#));
        let mut other = Row::parse(&bytes).unwrap();
        other.set("exp", "1.5e300".into()).unwrap();
        assert!(!Row::parse(original.as_bytes()).unwrap().same_but(&other, &["phone"]));
    }

    #[test]
    fn a_row_that_is_not_an_object_or_repeats_a_field_is_refused() {
        for bad_row in ["[]", "\"x\"", "12", r#"{"a":1,"a":2}"#, "{"] {
            assert!(Row::parse(bad_row.as_bytes()).is_err(), "{bad_row}");
        }
        let mut row = Row::parse(br#"{"a":1}"#).unwrap();
        assert!(row.set("missing", "1".into()).is_err());
        assert!(row.set("a", "{not json".into()).is_err());
    }

    #[test]
    fn every_method_makes_what_the_row_codec_makes() {
        for cipher in BOTH {
            let k = keys(cipher);
            let table = TableSeal { table_id: TABLE_ID, specs: Mixed::SEALED, keys: &k };
            let entity = Mixed {
                id: "x".into(),
                a: Sealed::new("alpha".into()),
                b: Sealed::new(" bee ".into()),
                c: Sealed::new("gamma ray".into()),
                d: Hashed::new("hunter2"),
                e: SearchPrint::new(" ABC "),
            };
            let by_codec = seal_row(&table, "r1", &entity).unwrap();
            let mut row = Row::parse(PLAIN_ROW.as_bytes()).unwrap();
            for spec in Mixed::SEALED {
                let plain = row.get(spec.key).unwrap().as_bytes().to_vec();
                row.set(spec.key, protect_plain(&k, TABLE_ID, spec, "r1", &plain).unwrap()).unwrap();
            }
            let by_migration = row.encode();
            let (a, b) = (Row::parse(&by_codec).unwrap(), Row::parse(&by_migration).unwrap());
            assert_eq!(a.get("id"), b.get("id"));
            for spec in Mixed::SEALED {
                let (x, y) = (a.get(spec.key).unwrap(), b.get(spec.key).unwrap());
                match spec.key {
                    // deterministic: the very same text
                    "e" => assert_eq!(x, y),
                    // fresh nonce: the sealed text differs, the rest is the same, and both open to the same value
                    "a" | "b" | "c" => {
                        let (sx, sy) = (read_stored(x).unwrap(), read_stored(y).unwrap());
                        assert_ne!(sx.sealed, sy.sealed);
                        assert_eq!((&sx.full, &sx.parts), (&sy.full, &sy.parts), "{}", spec.key);
                        assert_eq!(sx.full.is_some(), spec.method.has_stored_print());
                        assert_eq!(sx.parts.is_some(), spec.method.has_parts());
                        let (ox, oy) = (
                            open_stored(&k, TABLE_ID, spec.id, "r1", &sx).unwrap(),
                            open_stored(&k, TABLE_ID, spec.id, "r1", &sy).unwrap(),
                        );
                        assert_eq!(ox.as_bytes(), oy.as_bytes());
                        // the object has the same keys, so the shape is the same
                        assert_eq!(x.starts_with('{'), y.starts_with('{'));
                    }
                    // salted: another text of the same length that verifies the same secret
                    "d" => {
                        assert_eq!(x.len(), y.len());
                        let stored: String = serde_json::from_str(y).unwrap();
                        let place = Place { table_id: TABLE_ID, field_id: spec.id, row_key: "r1" };
                        assert!(hashing::verify_value(&k, crate::field_crypto::HashAlgo::Argon2id, &place, b"hunter2", &stored).unwrap());
                        assert!(!hashing::verify_value(&k, crate::field_crypto::HashAlgo::Argon2id, &place, b"hunter3", &stored).unwrap());
                    }
                    other => panic!("{other}"),
                }
            }
            // The row the migration made is one the row codec accepts and writes back unchanged.
            let mut read: Mixed = serde_json::from_slice(&by_migration).unwrap();
            bind_row(TABLE_ID, "r1", &mut read);
            // (the codec writes the fields sorted by name and the migration keeps the row's own order,
            // so the two are compared as values; every value of this row is text)
            let back: Value = serde_json::from_slice(&seal_row(&table, "r1", &read).unwrap()).unwrap();
            assert_eq!(back, serde_json::from_slice::<Value>(&by_migration).unwrap());
        }
    }

    #[test]
    fn prints_are_added_remade_and_dropped_without_touching_the_sealed_text() {
        let k = keys(CipherKind::Aes256GcmSiv);
        let plain_spec = SealedSpec { id: 1, key: "v", method: crate::field_crypto::Method::Encrypt, hash: None, normalize: &[], window: 0, bits: 0 };
        let full_spec = SealedSpec { method: crate::field_crypto::Method::EncryptFullPrint, ..plain_spec };
        let parts_spec = SealedSpec { method: crate::field_crypto::Method::EncryptPartPrints, window: 3, bits: 12, ..plain_spec };
        let sealed = read_stored(&seal_plain(&k, TABLE_ID, &plain_spec, "r", b"\"hello world\"").unwrap()).unwrap();
        assert!(sealed.full.is_none() && sealed.parts.is_none());
        let opened = open_stored(&k, TABLE_ID, 1, "r", &sealed).unwrap();
        assert_eq!(opened.as_bytes(), b"\"hello world\"");
        let with_full = read_stored(&with_prints(&k, TABLE_ID, &full_spec, &sealed.sealed, opened.as_bytes()).unwrap()).unwrap();
        assert_eq!(with_full.sealed, sealed.sealed);
        assert!(with_full.full.is_some() && with_full.parts.is_none());
        let with_parts = read_stored(&with_prints(&k, TABLE_ID, &parts_spec, &sealed.sealed, opened.as_bytes()).unwrap()).unwrap();
        assert_eq!(with_parts.full, with_full.full);
        assert!(with_parts.parts.as_deref().is_some_and(|p| !p.is_empty()));
        // and they go again without a key
        let dropped = read_stored(&without_prints(&with_parts)).unwrap();
        assert_eq!(dropped.sealed, sealed.sealed);
        assert!(dropped.full.is_none() && dropped.parts.is_none());
        // another place does not open it
        assert!(open_stored(&k, TABLE_ID, 1, "other", &sealed).is_err());
        assert!(open_stored(&k, TABLE_ID, 2, "r", &sealed).is_err());
    }

    #[test]
    fn a_value_that_cannot_become_what_is_asked_is_refused() {
        let k = keys(CipherKind::Aes256GcmSiv);
        let by = |s: &SealedSpec, plain: &[u8]| protect_plain(&k, TABLE_ID, s, "r", plain);
        let hash = Mixed::SEALED[3];
        let print = Mixed::SEALED[4];
        let printed = Mixed::SEALED[1];
        for number in [&b"42"[..], b"null", b"[\"a\"]"] {
            assert!(by(&hash, number).is_err());
            assert!(by(&print, number).is_err());
            assert!(by(&printed, number).is_err());
        }
        assert!(hash_plain(&k, TABLE_ID, &SealedSpec { hash: None, ..hash }, "r", b"\"x\"").is_err());
        assert!(seal_plain(&k, TABLE_ID, &hash, "r", b"\"x\"").is_err());
        assert!(parts_are_set_up(&Mixed::SEALED[2]) && !parts_are_set_up(&SealedSpec { bits: 0, ..Mixed::SEALED[2] }));
        // a number is sealed fine where there is no fingerprint
        assert!(by(&Mixed::SEALED[0], b"42").is_ok());
    }

    #[test]
    fn another_cipher_under_the_same_roots_moves_every_value_and_keeps_the_rest() {
        let suite = |cipher| KeySuite { cipher, hkdf: HkdfHash::Sha256 };
        let data = DataKey::generate().unwrap();
        let (read, search) = (Key32::from_bytes(&[1; 32]), Key32::from_bytes(&[2; 32]));
        let under = |cipher| {
            let s = suite(cipher);
            let locked = data.lock(&s, &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
            let access = locked.unlock(&s, Some(&ProgrammerKey::Raw(&read)), Some(&ProgrammerKey::Raw(&search))).unwrap();
            FieldKeys::with_access(s, access).unwrap()
        };
        let (old, new) = (under(CipherKind::Aes256GcmSiv), under(CipherKind::XChaCha20Poly1305));
        assert!(!hash_root_changed(&old, &new).unwrap() && !print_root_changed(&old, &new).unwrap());
        // same roots: nothing to carry
        assert!(super::super::carried::carry_plan(&old, &new, TABLE_ID, Mixed::SEALED).unwrap().is_empty());
        let mut row = Row::parse(br#"{"n":123456789012345678901234567890,"id":"x","a":"alpha","b":" bee ","c":"gamma ray","d":"hunter2","e":" ABC "}"#).unwrap();
        for spec in Mixed::SEALED {
            let plain = row.get(spec.key).unwrap().as_bytes().to_vec();
            row.set(spec.key, protect_plain(&old, TABLE_ID, spec, "r1", &plain).unwrap()).unwrap();
        }
        let before = row.encode();
        let after = reseal_row(&old, &new, TABLE_ID, Mixed::SEALED, "r1", &before).unwrap();
        let (b, a) = (Row::parse(&before).unwrap(), Row::parse(&after).unwrap());
        // the hash, the fingerprint and everything else are the very bytes they were
        assert!(b.same_but(&a, &["a", "b", "c"]));
        for key in ["a", "b", "c"] {
            let (sb, sa) = (read_stored(b.get(key).unwrap()).unwrap(), read_stored(a.get(key).unwrap()).unwrap());
            assert_ne!(sb.sealed, sa.sealed, "{key}");
            assert_eq!((&sb.full, &sb.parts), (&sa.full, &sa.parts), "{key}");
            let id = Mixed::SEALED.iter().find(|s| s.key == key).unwrap().id;
            let (x, y) = (open_stored(&old, TABLE_ID, id, "r1", &sb).unwrap(), open_stored(&new, TABLE_ID, id, "r1", &sa).unwrap());
            assert_eq!(x.as_bytes(), y.as_bytes());
            // the old cipher no longer opens it, and neither does another place
            assert!(open_stored(&old, TABLE_ID, id, "r1", &sa).is_err());
            assert!(open_stored(&new, TABLE_ID, id, "r2", &sa).is_err());
        }
        // a row without one of the fields, or one that does not open, changes nothing
        assert!(reseal_row(&old, &new, TABLE_ID, Mixed::SEALED, "r1", br#"{"id":"x"}"#).is_err());
        assert!(reseal_row(&old, &new, TABLE_ID, Mixed::SEALED, "other", &before).is_err());
    }

    #[test]
    fn other_roots_move_sealed_values_and_leave_a_hash_and_a_fingerprint_as_they_are() {
        let (old, new) = (keys(CipherKind::Aes256GcmSiv), keys(CipherKind::Aes256GcmSiv));
        assert!(hash_root_changed(&old, &new).unwrap() && print_root_changed(&old, &new).unwrap());
        // the keys of the hash and of the fingerprint are the ones to carry
        let items = super::super::carried::carry_plan(&old, &new, TABLE_ID, Mixed::SEALED).unwrap();
        assert_eq!(items.len(), 2);
        assert!(items[0].key == old.hash_key(TABLE_ID, 4).unwrap() && items[1].key == old.print_key(TABLE_ID, 5).unwrap());
        let mut row = Row::parse(br#"{"id":"x","a":"alpha","b":" bee ","c":"gamma ray","d":"hunter2","e":" ABC "}"#).unwrap();
        for spec in Mixed::SEALED {
            let plain = row.get(spec.key).unwrap().as_bytes().to_vec();
            row.set(spec.key, protect_plain(&old, TABLE_ID, spec, "r1", &plain).unwrap()).unwrap();
        }
        let before = row.encode();
        let after = reseal_row(&old, &new, TABLE_ID, Mixed::SEALED, "r1", &before).unwrap();
        let (b, a) = (Row::parse(&before).unwrap(), Row::parse(&after).unwrap());
        // the hash and the fingerprint (and the rest) are the very bytes they were
        assert!(b.same_but(&a, &["a", "b", "c"]));
        // the sealed values moved and their fingerprints were made again with the new roots
        let (fb, fa) = (read_stored(b.get("b").unwrap()).unwrap(), read_stored(a.get("b").unwrap()).unwrap());
        assert_ne!(fb.full, fa.full);
        let opened = open_stored(&new, TABLE_ID, 2, "r1", &fa).unwrap();
        assert_eq!(opened.as_bytes(), b"\" bee \"");
        // a row that is not sealed with the old keys does not move
        assert!(reseal_row(&old, &new, TABLE_ID, Mixed::SEALED, "r1", PLAIN_ROW.as_bytes()).is_err());
    }

    #[test]
    fn a_history_record_is_moved_by_its_payload_and_its_own_row_key() {
        use crate::backup::{BackupOperation, BackupRecord, codec::{decode_record, encode_record}};
        let (old, new) = (keys(CipherKind::Aes256GcmSiv), keys(CipherKind::XChaCha20Poly1305));
        let spec = &Mixed::SEALED[1..3];
        let mut row = Row::parse(br#"{"id":"x","big":123456789012345678901234567890,"b":" bee ","c":"gamma ray"}"#).unwrap();
        for s in spec {
            let plain = row.get(s.key).unwrap().as_bytes().to_vec();
            row.set(s.key, protect_plain(&old, TABLE_ID, s, "r1", &plain).unwrap()).unwrap();
        }
        let record = |operation, data| BackupRecord {
            version: 3,
            timestamp: 1_700_000_000_000,
            date: "2026-10-28 10:00:00.000".into(),
            operation,
            table: "people".into(),
            key: "r1".into(),
            data,
            bulk_id: None,
            restored_version: None,
            date_from_migration: false,
        };
        let set = encode_record(&record(BackupOperation::Set, Some(row.encode()))).unwrap();
        let moved = reseal_history_doc(&old, &new, TABLE_ID, spec, &set).unwrap();
        let (a, b) = (decode_record("", "", &set).unwrap(), decode_record("", "", &moved).unwrap());
        assert_eq!((a.version, a.timestamp, &a.date, &a.key, &a.table), (b.version, b.timestamp, &b.date, &b.key, &b.table));
        let (ra, rb) = (Row::parse(a.data.as_ref().unwrap()).unwrap(), Row::parse(b.data.as_ref().unwrap()).unwrap());
        assert!(ra.same_but(&rb, &["b", "c"]));
        let stored = read_stored(rb.get("b").unwrap()).unwrap();
        assert_eq!(open_stored(&new, TABLE_ID, 2, "r1", &stored).unwrap().as_bytes(), b"\" bee \"");
        // the row key comes from the record: a record for another row does not open
        let other = encode_record(&BackupRecord { key: "r2".into(), ..record(BackupOperation::Set, Some(row.encode())) }).unwrap();
        assert!(reseal_history_doc(&old, &new, TABLE_ID, spec, &other).is_err());
        // a deletion has no payload and stays as it is
        let delete = encode_record(&record(BackupOperation::Delete, None)).unwrap();
        assert_eq!(reseal_history_doc(&old, &new, TABLE_ID, spec, &delete).unwrap(), delete);
        // text that is not a record of the current form is refused
        assert!(reseal_history_doc(&old, &new, TABLE_ID, spec, b"{\"id\":\"x\"}").is_err());
    }

    #[test]
    fn the_checks_follow_the_roots_for_fingerprints_and_stay_for_what_was_carried() {
        use super::super::carried::{carry_plan, install_items};
        let (old, new) = (keys(CipherKind::Aes256GcmSiv), keys(CipherKind::XChaCha20Poly1305));
        let before = settings_checks(&old, TABLE_ID, Mixed::SEALED).unwrap();
        // a field that only seals has none; the others have one
        let check = |v: &[(u32, Option<String>)], id: u32| v.iter().find(|(i, _)| *i == id).unwrap().1.clone();
        assert!(check(&before, 1).is_none());
        for id in 2..=5 {
            assert!(check(&before, id).is_some(), "{id}");
        }
        // other roots, the keys of the hash and of the fingerprint carried
        let items = carry_plan(&old, &new, TABLE_ID, Mixed::SEALED).unwrap();
        install_items(&new, &items);
        let after = settings_checks(&new, TABLE_ID, Mixed::SEALED).unwrap();
        assert_eq!(check(&after, 4), check(&before, 4), "a carried hash keeps its check");
        assert_eq!(check(&after, 5), check(&before, 5), "a carried fingerprint keeps its check");
        assert_ne!(check(&after, 2), check(&before, 2), "a fingerprint made again has the check of the new root");
        assert_ne!(check(&after, 3), check(&before, 3));
        // the same roots and another cipher change none
        let roots_data = DataKey::generate().unwrap();
        let (read, search) = (Key32::from_bytes(&[1; 32]), Key32::from_bytes(&[2; 32]));
        let under = |cipher| {
            let s = KeySuite { cipher, hkdf: HkdfHash::Sha256 };
            let locked = roots_data.lock(&s, &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
            let access = locked.unlock(&s, Some(&ProgrammerKey::Raw(&read)), Some(&ProgrammerKey::Raw(&search))).unwrap();
            FieldKeys::with_access(s, access).unwrap()
        };
        let (a, b) = (under(CipherKind::Aes256GcmSiv), under(CipherKind::XChaCha20Poly1305));
        assert_eq!(settings_checks(&a, TABLE_ID, Mixed::SEALED).unwrap(), settings_checks(&b, TABLE_ID, Mixed::SEALED).unwrap());
        // and they are written into the description by field number
        let mut fields: Vec<_> = Mixed::SEALED.iter().map(super::super::SealedField::from_spec).collect();
        apply_checks(&mut fields, &after);
        for f in &fields {
            assert_eq!(f.check, check(&after, f.id), "{}", f.id);
        }
        // a hash with no setting cannot have a check
        let no_hash = SealedSpec { hash: None, ..Mixed::SEALED[3] };
        assert!(settings_checks(&old, TABLE_ID, &[no_hash]).is_err());
    }

    #[test]
    fn a_stored_value_of_another_shape_is_refused() {
        for raw in ["12", "null", "[]", r#"{"f":"x"}"#, r#"{"s":1}"#, r#"{"s":"a","z":"b"}"#, "{"] {
            assert!(read_stored(raw).is_err(), "{raw}");
        }
        assert!(read_stored(r#""abc""#).is_ok() && read_stored(r#"{"s":"a","f":"b","p":""}"#).is_ok());
    }
}
