//! Keys carried over when the roots of a database change.
//!
//! A verification hash and a search fingerprint keep no value that could be made again, so a field
//! of either kind stays valid only with the very key it was made with. When the data key changes
//! (new roots), that key is not derived again: it is sealed under the new roots and stored in the
//! table `__carried_keys`, and [`super::keys::FieldKeys`] uses it for that field instead of deriving
//! one. The values themselves are copied as they are.
//!
//! One entry per field, text key `"{table_id}:{field_id}"`, value
//! `version (1) || kind (1: hash, 2: fingerprint) || sealed key`. A hash key is sealed under a key
//! of the read root, a fingerprint key under a key of the search root, so a program that holds only
//! the search key can use a carried fingerprint and cannot open a carried hash. The seal is bound to
//! the entry's place, so an entry moved to another field does not open. The table is written without
//! any journal effect, like `__field_keys`, and is in neither the change log nor the backup history.
//! A carried key is not in the keys file: that file exists to open sealed values if the main file is
//! lost, and a hash or a fingerprint is inside the main file with nothing to check it against.
#![allow(dead_code)] // used by the upgrade pipeline and the migration
use super::{keys::FieldKeys, method::Method, migrate, spec::SealedSpec};
use crate::{
    crypto::{Aead, Key32},
    units::{ClError, Result},
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

pub(crate) const TABLE: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("__carried_keys");

const VERSION: u8 = 1;
/// The table part of the scope the seal keys come from. The scopes of fields start with `t:`, so
/// this one is never the scope of any field.
pub(crate) const SCOPE: &str = "carried-keys";

/// What a carried key is a key of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CarriedKind {
    /// The key mixed into the verification hash of a field.
    Hash = 1,
    /// The key of the search fingerprint of a field.
    Print = 2,
}

impl CarriedKind {
    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(CarriedKind::Hash),
            2 => Some(CarriedKind::Print),
            _ => None,
        }
    }
}

/// A key to carry: the key the field has now, to be sealed under the new roots.
pub(crate) struct CarryItem {
    pub table_id: String,
    pub field_id: u32,
    pub kind: CarriedKind,
    pub key: Key32,
}

fn bad(why: &str) -> ClError {
    ClError::MigrationError(why.to_string())
}

/// The name of the entry of a field.
pub(crate) fn entry_name(table_id: &str, field_id: u32) -> String {
    format!("{table_id}:{field_id}")
}

fn parse_name(name: &str) -> Result<(&str, u32)> {
    let (table_id, field) = name.rsplit_once(':').ok_or_else(|| bad("an entry of the carried keys has a name that is not one"))?;
    let field_id = field.parse().map_err(|_| bad("an entry of the carried keys has a name that is not one"))?;
    Ok((table_id, field_id))
}

fn aad(kind: CarriedKind, table_id: &str, field_id: u32) -> Vec<u8> {
    let mut out = b"carried/v1".to_vec();
    out.push(kind as u8);
    out.extend_from_slice(&(table_id.len() as u64).to_le_bytes());
    out.extend_from_slice(table_id.as_bytes());
    out.extend_from_slice(&field_id.to_le_bytes());
    out
}

/// The stored value of a carried key. Needs the root the kind is sealed under.
pub(crate) fn seal_entry(keys: &FieldKeys, kind: CarriedKind, table_id: &str, field_id: u32, key: &Key32) -> Result<Vec<u8>> {
    let seal_key = keys.carried_seal_key(kind, table_id, field_id)?.ok_or_else(|| match kind {
        CarriedKind::Hash => bad("this program holds no read key; a carried key cannot be sealed"),
        CarriedKind::Print => bad("this program holds no search key; a carried key cannot be sealed"),
    })?;
    let aead = Aead::new(keys.suite().cipher, &seal_key).map_err(|_| bad("a carried key could not be sealed"))?;
    let sealed = aead.seal(&aad(kind, table_id, field_id), key.as_bytes()).map_err(|_| bad("a carried key could not be sealed"))?;
    let mut out = Vec::with_capacity(2 + sealed.len());
    out.push(VERSION);
    out.push(kind as u8);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a stored entry. `None` when the program does not hold the root it is sealed under (it has no
/// use for it); an error when the entry is not one this version knows or does not open.
pub(crate) fn open_entry(keys: &FieldKeys, table_id: &str, field_id: u32, stored: &[u8]) -> Result<Option<(CarriedKind, Key32)>> {
    let unknown = || bad("an entry of the carried keys is of a form this version does not know");
    let [version, kind, sealed @ ..] = stored else {
        return Err(unknown());
    };
    if *version != VERSION {
        return Err(unknown());
    }
    let kind = CarriedKind::from_code(*kind).ok_or_else(unknown)?;
    let Some(seal_key) = keys.carried_seal_key(kind, table_id, field_id)? else {
        return Ok(None);
    };
    let aead = Aead::new(keys.suite().cipher, &seal_key).map_err(|_| bad("a carried key could not be opened"))?;
    let opened = aead
        .open(&aad(kind, table_id, field_id), sealed)
        .map_err(|_| ClError::DataTampered)?;
    let key = Key32::from_slice(opened.as_bytes()).map_err(|_| ClError::DataTampered)?;
    Ok(Some((kind, key)))
}

/// What reading the table found.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Loaded {
    /// The database has the table at all.
    pub table_exists: bool,
    /// The fields (table identity, field number) that have an entry, opened here or not.
    pub fields: Vec<(String, u32)>,
    /// How many of the entries this program could open and now uses.
    pub opened: usize,
}

/// Read `__carried_keys` and hand the keys this program can open to `keys`. A database without the
/// table is the usual case and changes nothing.
pub(crate) fn load(db: &impl ReadableDatabase, keys: &FieldKeys) -> Result<Loaded> {
    let read = db.begin_read()?;
    let table = match read.open_table(TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Loaded::default()),
        Err(other) => return Err(other.into()),
    };
    let mut loaded = Loaded { table_exists: true, ..Loaded::default() };
    for row in table.iter()? {
        let (name, stored) = row?;
        let (table_id, field_id) = parse_name(name.value())?;
        loaded.fields.push((table_id.to_string(), field_id));
        if let Some((kind, key)) = open_entry(keys, table_id, field_id, stored.value())? {
            keys.install_carried(kind, table_id, field_id, key);
            loaded.opened += 1;
        }
    }
    Ok(loaded)
}

/// Write the whole table (every entry, by name), replacing what was there. No journal effect.
pub(crate) fn write_all(tx: &WriteTransaction, entries: &[(String, Vec<u8>)]) -> Result<()> {
    tx.delete_table(TABLE)?;
    let mut table = tx.open_table(TABLE)?;
    for (name, stored) in entries {
        table.insert(name.as_str(), stored.as_slice())?;
    }
    Ok(())
}

/// The keys that must be carried when the keys of a table go from `old` to `new`: every hash or
/// fingerprint-only field whose root differs, with the key it has now (a carried one if it was
/// carried before, so a second change carries it again). A field whose root is the same needs none.
pub(crate) fn carry_plan(old: &FieldKeys, new: &FieldKeys, table_id: &str, specs: &[SealedSpec]) -> Result<Vec<CarryItem>> {
    let mut items = Vec::new();
    for spec in specs {
        match spec.method {
            Method::Hash if migrate::hash_root_changed(old, new)? => {
                items.push(CarryItem { table_id: table_id.into(), field_id: spec.id, kind: CarriedKind::Hash, key: old.hash_key(table_id, spec.id)? });
            }
            Method::SearchPrint if migrate::print_root_changed(old, new)? => {
                items.push(CarryItem { table_id: table_id.into(), field_id: spec.id, kind: CarriedKind::Print, key: old.print_key(table_id, spec.id)? });
            }
            _ => {}
        }
    }
    Ok(items)
}

/// Put carried keys in place in `keys`, as the open does after reading the table, so that what is
/// computed with `keys` (the checks of the settings, the verification of a hash) uses them.
pub(crate) fn install_items(keys: &FieldKeys, items: &[CarryItem]) {
    for item in items {
        keys.install_carried(item.kind, &item.table_id, item.field_id, Key32::from_bytes(item.key.as_bytes()));
    }
}

/// The whole table of the new file: each old entry opened with `old` and sealed again with `new` (so a
/// change of cipher or of the other root is followed), except those `items` replace, then the new
/// entries sealed with `new`. Sorted by name.
pub(crate) fn next_table(
    old: &FieldKeys,
    new: &FieldKeys,
    old_entries: &[(String, Vec<u8>)],
    items: &[CarryItem],
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, stored) in old_entries {
        let (table_id, field_id) = parse_name(name)?;
        if items.iter().any(|i| i.table_id == table_id && i.field_id == field_id) {
            continue;
        }
        let Some((kind, key)) = open_entry(old, table_id, field_id, stored)? else {
            return Err(bad("an entry of the carried keys cannot be opened with these keys, so it cannot be carried on; nothing was changed"));
        };
        out.push((name.clone(), seal_entry(new, kind, table_id, field_id, &key)?));
    }
    for item in items {
        out.push((entry_name(&item.table_id, item.field_id), seal_entry(new, item.kind, &item.table_id, item.field_id, &item.key)?));
    }
    out.sort();
    Ok(out)
}

/// Whether the carried key of a field is missing: the database has the table, none of its entries is
/// for this field, and the settings stored for the field are not what its key makes.
fn is_missing(loaded: &Loaded, table_id: &str, spec: &SealedSpec, settings_match: bool) -> bool {
    loaded.table_exists
        && !settings_match
        && matches!(spec.method, Method::Hash | Method::SearchPrint)
        && !loaded.fields.iter().any(|(t, f)| t == table_id && *f == spec.id)
}

/// The table and the field (names, nothing secret) of the first hash or fingerprint-only field of
/// the tables in code whose carried key is missing from a database that has the table. The stored
/// settings of each field are compared with the ones its key makes; anything else is left to the
/// ordinary comparison of the settings. This is the detail for the developer; the open itself fails
/// with the one error every failed open has (see [`explain_all`]).
pub(crate) fn find_missing(
    meta: &crate::metadata::types::CloveMeta,
    tables: &[(&str, &'static [SealedSpec])],
    keys: &FieldKeys,
    loaded: &Loaded,
) -> Result<Option<(String, String)>> {
    if !loaded.table_exists {
        return Ok(None);
    }
    for (name, specs) in tables {
        let Some(table) = meta.tables.iter().find(|t| t.name == *name) else { continue };
        let Some(table_id) = table.table_id.as_deref() else { continue };
        for spec in specs.iter().filter(|s| matches!(s.method, Method::Hash | Method::SearchPrint)) {
            let Some(stored) = table.sealed.iter().find(|f| f.id == spec.id).and_then(|f| f.check.as_deref()) else { continue };
            let expected = match spec.method {
                Method::Hash => {
                    let Some(algo) = spec.hash else { continue };
                    if keys.is_search_only() {
                        continue;
                    }
                    super::hashing::settings_fingerprint(keys, table_id, spec.id, algo)?
                }
                _ => {
                    if !keys.has_search() {
                        continue;
                    }
                    super::prints::settings_fingerprint(keys, table_id, spec.id, spec.normalize)?
                }
            };
            if is_missing(loaded, table_id, spec, super::hashing::same_settings(stored, &expected)) {
                return Ok(Some(((*name).to_string(), spec.key.to_string())));
            }
        }
    }
    Ok(None)
}

/// For the open: a carried key that is missing or was changed fails like every failed open, with the
/// one error and no name (telling causes apart helps someone guessing), and the cause goes to the
/// event sink as a fixed name without a table, a field or a value.
pub(crate) fn explain_all(
    meta: &crate::metadata::types::CloveMeta,
    tables: &[(&str, &'static [SealedSpec])],
    keys: &FieldKeys,
    loaded: &Loaded,
    events: &crate::events::EventSink,
) -> Result<()> {
    if find_missing(meta, tables, keys, loaded)?.is_some() {
        events.emit(&crate::events::LibraryEvent::Encryption { event: "encryption/open_failed/carried_key_missing", file: "main" });
        return Err(ClError::EncryptedOpenFailed);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{CipherKind, DataKey, HkdfHash, Key32, KeySuite, ProgrammerKey},
        field_crypto::{HashAlgo, hashing, method::Method},
    };
    use redb::backends::InMemoryBackend;

    const TABLE_ID: &str = "00112233445566778899aabbccddeeff";

    struct Roots(DataKey);
    impl Roots {
        fn new() -> Self {
            Roots(DataKey::generate().unwrap())
        }
        fn keys(&self, cipher: CipherKind, read: bool, search: bool) -> FieldKeys {
            let suite = KeySuite { cipher, hkdf: HkdfHash::Sha256 };
            let (r, s) = (Key32::from_bytes(&[1; 32]), Key32::from_bytes(&[2; 32]));
            let locked = self.0.lock(&suite, &ProgrammerKey::Raw(&r), &ProgrammerKey::Raw(&s)).unwrap();
            let access = locked
                .unlock(&suite, read.then_some(&ProgrammerKey::Raw(&r)), search.then_some(&ProgrammerKey::Raw(&s)))
                .unwrap();
            FieldKeys::with_access(suite, access).unwrap()
        }
    }

    fn spec(id: u32, key: &'static str, method: Method) -> SealedSpec {
        let hash = (method == Method::Hash).then_some(HashAlgo::Argon2id);
        SealedSpec { id, key, method, hash, normalize: &[], window: 0, bits: 0 }
    }

    fn memory() -> redb::Database {
        redb::Database::builder().create_with_backend(InMemoryBackend::new()).unwrap()
    }

    fn store(db: &redb::Database, entries: &[(String, Vec<u8>)]) {
        let tx = db.begin_write().unwrap();
        write_all(&tx, entries).unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn the_scope_of_the_seal_is_the_scope_of_no_field() {
        assert!(!SCOPE.starts_with("t:"));
        let k = Roots::new().keys(CipherKind::Aes256GcmSiv, true, true);
        for id in [0u32, 1, 2, 77] {
            let hash_seal = k.carried_seal_key(CarriedKind::Hash, TABLE_ID, id).unwrap().unwrap();
            let print_seal = k.carried_seal_key(CarriedKind::Print, TABLE_ID, id).unwrap().unwrap();
            assert!(hash_seal != print_seal);
            // not the key of the hash, the fingerprint, the parts of that field, or its cipher
            assert!(hash_seal != k.hash_key(TABLE_ID, id).unwrap());
            assert!(print_seal != k.print_key(TABLE_ID, id).unwrap());
            assert!(print_seal != k.part_key(TABLE_ID, id).unwrap());
            // and the entry name is never the name of a field scope
            assert!(!entry_name(TABLE_ID, id).starts_with("f:"));
        }
        // other places give other seal keys
        let a = k.carried_seal_key(CarriedKind::Hash, TABLE_ID, 1).unwrap().unwrap();
        let b = k.carried_seal_key(CarriedKind::Hash, TABLE_ID, 2).unwrap().unwrap();
        assert!(a != b);
    }

    #[test]
    fn an_entry_opens_only_in_its_place_and_only_in_the_form_it_has() {
        for cipher in [CipherKind::Aes256GcmSiv, CipherKind::XChaCha20Poly1305] {
            let k = Roots::new().keys(cipher, true, true);
            let secret = Key32::from_bytes(&[9; 32]);
            for kind in [CarriedKind::Hash, CarriedKind::Print] {
                let stored = seal_entry(&k, kind, TABLE_ID, 4, &secret).unwrap();
                let (got_kind, got) = open_entry(&k, TABLE_ID, 4, &stored).unwrap().unwrap();
                assert!(got_kind == kind && got == secret);
                // not the 32 bytes themselves
                assert!(!stored.windows(32).any(|w| w == secret.as_bytes()));
                // another field or table, damage, another version, another kind, short
                assert!(open_entry(&k, TABLE_ID, 5, &stored).is_err());
                assert!(open_entry(&k, "ffffffffffffffffffffffffffffffff", 4, &stored).is_err());
                let mut damaged = stored.clone();
                *damaged.last_mut().unwrap() ^= 1;
                assert!(open_entry(&k, TABLE_ID, 4, &damaged).is_err());
                let mut version = stored.clone();
                version[0] = 2;
                assert!(open_entry(&k, TABLE_ID, 4, &version).is_err());
                let mut other_kind = stored.clone();
                other_kind[1] = if kind == CarriedKind::Hash { 2 } else { 1 };
                assert!(open_entry(&k, TABLE_ID, 4, &other_kind).is_err());
                assert!(open_entry(&k, TABLE_ID, 4, &stored[..1]).is_err());
                assert!(open_entry(&k, TABLE_ID, 4, &[]).is_err());
            }
        }
    }

    #[test]
    fn the_search_key_alone_uses_a_carried_fingerprint_and_leaves_a_carried_hash_closed() {
        let roots = Roots::new();
        let full = roots.keys(CipherKind::Aes256GcmSiv, true, true);
        let search_only = roots.keys(CipherKind::Aes256GcmSiv, false, true);
        let (hash, print) = (Key32::from_bytes(&[5; 32]), Key32::from_bytes(&[6; 32]));
        let entries = vec![
            (entry_name(TABLE_ID, 1), seal_entry(&full, CarriedKind::Hash, TABLE_ID, 1, &hash).unwrap()),
            (entry_name(TABLE_ID, 2), seal_entry(&full, CarriedKind::Print, TABLE_ID, 2, &print).unwrap()),
        ];
        let db = memory();
        store(&db, &entries);
        let loaded = load(&db, &search_only).unwrap();
        assert!(loaded.table_exists && loaded.opened == 1 && loaded.fields.len() == 2);
        assert!(search_only.print_key(TABLE_ID, 2).unwrap() == print);
        assert!(search_only.hash_key(TABLE_ID, 1).is_err(), "no read key, and nothing carried to use");
        let everything = roots.keys(CipherKind::Aes256GcmSiv, true, true);
        assert_eq!(load(&db, &everything).unwrap().opened, 2);
        assert!(everything.hash_key(TABLE_ID, 1).unwrap() == hash && everything.print_key(TABLE_ID, 2).unwrap() == print);
        // a field without an entry is derived as before
        assert!(everything.hash_key(TABLE_ID, 3).unwrap() != hash);
        // and clearing forgets them
        everything.clear();
        assert!(everything.hash_key(TABLE_ID, 1).is_err());
    }

    #[test]
    fn a_database_without_the_table_changes_nothing() {
        let k = Roots::new().keys(CipherKind::Aes256GcmSiv, true, true);
        let before = (k.hash_key(TABLE_ID, 1).unwrap(), k.print_key(TABLE_ID, 1).unwrap());
        let loaded = load(&memory(), &k).unwrap();
        assert_eq!(loaded, Loaded::default());
        assert!(k.hash_key(TABLE_ID, 1).unwrap() == before.0 && k.print_key(TABLE_ID, 1).unwrap() == before.1);
    }

    #[test]
    fn a_hash_and_a_fingerprint_survive_new_roots_twice_and_a_new_write_after() {
        let (specs, field_hash) = ([spec(1, "pw", Method::Hash), spec(2, "tok", Method::SearchPrint)], 1u32);
        let first = Roots::new().keys(CipherKind::Aes256GcmSiv, true, true);
        let place = |id| place_row(id, "r1");
        // values made with the first roots
        let hashed = migrate::hash_plain(&first, TABLE_ID, &specs[0], "r1", b"\"hunter2\"").unwrap();
        let stored_hash: String = serde_json::from_str(&hashed).unwrap();
        let printed = migrate::print_plain(&first, TABLE_ID, &specs[1], b"\"abc\"").unwrap();
        // 1) new roots, carried
        let second = Roots::new().keys(CipherKind::XChaCha20Poly1305, true, true);
        let items = carry_plan(&first, &second, TABLE_ID, &specs).unwrap();
        assert_eq!(items.len(), 2);
        let db = memory();
        store(&db, &next_table(&first, &second, &[], &items).unwrap());
        load(&db, &second).unwrap();
        assert!(hashing::verify_value(&second, HashAlgo::Argon2id, &place(field_hash), b"hunter2", &stored_hash).unwrap());
        assert!(!hashing::verify_value(&second, HashAlgo::Argon2id, &place(field_hash), b"hunter3", &stored_hash).unwrap());
        // the same value now gives the same fingerprint, and a value written after the change matches the old ones
        assert_eq!(migrate::print_plain(&second, TABLE_ID, &specs[1], b"\"abc\"").unwrap(), printed);
        assert_ne!(migrate::print_plain(&second, TABLE_ID, &specs[1], b"\"abd\"").unwrap(), printed);
        let new_hash: String = serde_json::from_str(&migrate::hash_plain(&second, TABLE_ID, &specs[0], "r2", b"\"s3cret\"").unwrap()).unwrap();
        assert!(hashing::verify_value(&second, HashAlgo::Argon2id, &place_row(field_hash, "r2"), b"s3cret", &new_hash).unwrap());
        // 2) new roots again: the carried keys are carried again, from the table the second roots read
        let third = Roots::new().keys(CipherKind::Aes256GcmSiv, true, true);
        let items = carry_plan(&second, &third, TABLE_ID, &specs).unwrap();
        assert_eq!(items.len(), 2);
        let old_rows = read_all(&db);
        let db2 = memory();
        store(&db2, &next_table(&second, &third, &old_rows, &items).unwrap());
        load(&db2, &third).unwrap();
        assert!(hashing::verify_value(&third, HashAlgo::Argon2id, &place(field_hash), b"hunter2", &stored_hash).unwrap());
        assert!(hashing::verify_value(&third, HashAlgo::Argon2id, &place_row(field_hash, "r2"), b"s3cret", &new_hash).unwrap());
        assert_eq!(migrate::print_plain(&third, TABLE_ID, &specs[1], b"\"abc\"").unwrap(), printed);
        // the table still has one entry per field
        assert_eq!(read_all(&db2).len(), 2);
    }

    fn place_row(id: u32, row: &str) -> super::super::envelope::Place<'static> {
        // the rows used above are static text, so the place can be static too
        let row: &'static str = Box::leak(row.to_string().into_boxed_str());
        super::super::envelope::Place { table_id: TABLE_ID, field_id: id, row_key: row }
    }

    fn read_all(db: &redb::Database) -> Vec<(String, Vec<u8>)> {
        let read = db.begin_read().unwrap();
        let table = read.open_table(TABLE).unwrap();
        table.iter().unwrap().map(|r| r.unwrap()).map(|(k, v)| (k.value().to_string(), v.value().to_vec())).collect()
    }

    #[test]
    fn the_same_roots_and_another_cipher_carry_nothing_and_reseal_what_is_there() {
        let roots = Roots::new();
        let (old, new) = (roots.keys(CipherKind::Aes256GcmSiv, true, true), roots.keys(CipherKind::XChaCha20Poly1305, true, true));
        let specs = [spec(1, "pw", Method::Hash)];
        assert!(carry_plan(&old, &new, TABLE_ID, &specs).unwrap().is_empty());
        let key = Key32::from_bytes(&[3; 32]);
        let entries = vec![(entry_name(TABLE_ID, 1), seal_entry(&old, CarriedKind::Hash, TABLE_ID, 1, &key).unwrap())];
        let moved = next_table(&old, &new, &entries, &[]).unwrap();
        assert_eq!(moved.len(), 1);
        assert_ne!(moved[0].1, entries[0].1);
        assert!(open_entry(&new, TABLE_ID, 1, &moved[0].1).unwrap().unwrap().1 == key);
        // an old entry the program cannot open (no read key) stops the change instead of being dropped
        let search_only = roots.keys(CipherKind::Aes256GcmSiv, false, true);
        assert!(next_table(&search_only, &new, &entries, &[]).is_err());
    }

    #[test]
    fn a_missing_entry_fails_the_open_like_any_other_and_names_nothing() {
        let s = spec(7, "password", Method::Hash);
        let loaded = Loaded { table_exists: true, fields: vec![(TABLE_ID.into(), 9)], opened: 1 };
        assert!(is_missing(&loaded, TABLE_ID, &s, false));
        // not when the settings match, when the field has its entry, when there is no table, or for another method
        assert!(!is_missing(&loaded, TABLE_ID, &s, true));
        let has = Loaded { table_exists: true, fields: vec![(TABLE_ID.into(), 7)], opened: 1 };
        assert!(!is_missing(&has, TABLE_ID, &s, false));
        assert!(!is_missing(&Loaded::default(), TABLE_ID, &s, false));
        assert!(!is_missing(&loaded, TABLE_ID, &spec(7, "x", Method::Encrypt), false));
    }

    #[test]
    fn the_missing_field_is_found_by_name_for_the_developer_and_the_open_error_is_the_one_error() {
        use crate::metadata::types::{CloveMeta, TableMeta};
        use std::sync::{Arc, Mutex};
        static SPECS: [SealedSpec; 1] =
            [SealedSpec { id: 7, key: "password", method: Method::Hash, hash: Some(HashAlgo::Argon2id), normalize: &[], window: 0, bits: 0 }];
        let k = Roots::new().keys(CipherKind::Aes256GcmSiv, true, true);
        // a table whose stored settings were made with some other key (as if its carried key were gone)
        let other = Roots::new().keys(CipherKind::Aes256GcmSiv, true, true);
        let mut field = crate::field_crypto::SealedField::from_spec(&SPECS[0]);
        field.check = Some(hashing::settings_fingerprint(&other, TABLE_ID, 7, HashAlgo::Argon2id).unwrap());
        let meta = CloveMeta::new(
            "db",
            crate::metadata::types::FileEra::Current,
            false,
            false,
            vec![TableMeta {
                name: "people".into(),
                schema_id: "people".into(),
                schema_version: 1,
                layout_hash: String::new(),
                storage: Default::default(),
                table_id: Some(TABLE_ID.into()),
                sealed: vec![field],
            }],
        );
        let tables = [("people", &SPECS[..])];
        let loaded = Loaded { table_exists: true, fields: vec![(TABLE_ID.into(), 9)], opened: 1 };
        // the developer's detail
        assert_eq!(find_missing(&meta, &tables, &k, &loaded).unwrap(), Some(("people".into(), "password".into())));
        // no table in the file: left to the ordinary comparison
        assert_eq!(find_missing(&meta, &tables, &k, &Loaded::default()).unwrap(), None);
        // the open: one error, no name, and an event without any name either
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let sink = {
            let seen = seen.clone();
            crate::events::EventSink(Some(Arc::new(move |e: &crate::events::LibraryEvent| seen.lock().unwrap().push(format!("{e:?}")))))
        };
        let err = explain_all(&meta, &tables, &k, &loaded, &sink).unwrap_err();
        assert!(matches!(err, ClError::EncryptedOpenFailed));
        for text in std::iter::once(err.to_string()).chain(seen.lock().unwrap().iter().cloned()) {
            assert!(!text.contains("people") && !text.contains("password") && !text.contains(TABLE_ID), "{text}");
        }
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(seen.lock().unwrap()[0].contains("carried_key_missing"));
    }
}