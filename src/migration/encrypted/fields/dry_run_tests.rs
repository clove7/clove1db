//! `dry_run` of a change of how the fields of a table are protected: what it reports, and every
//! reason it refuses, each with nothing in the folder touched.
use super::api::ChangeFields;
use crate::{
    CloveFields, Unique,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::{EncryptionConfig, KeySource},
    entity::Entity,
    field_crypto::{Hashed, Sealed, SearchPrint},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A person as the program had it before any field was protected.
#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Plain {
    id: String,
    name: String,
    phone: String,
    password: String,
}
impl Entity for Plain {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

macro_rules! entity {
    ($name:ident { $($body:tt)* }) => {
        #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
        struct $name {
            id: String,
            name: String,
            $($body)*
        }
        impl Entity for $name {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    };
}

entity!(Sealed1 {
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    password: String,
});
entity!(Printed1 {
    #[clove(encrypt, id = 1, print = "full")]
    phone: Sealed<String>,
    password: String,
});
entity!(Hashed2 {
    phone: String,
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,
});
entity!(Token3 {
    phone: String,
    password: String,
    #[clove(search_print, id = 3)]
    token: SearchPrint,
});
entity!(HashedAsPhone {
    #[clove(hash = "argon2id", id = 1)]
    phone: Hashed,
    password: String,
});
const SECRET: &str = "swordfish-marker-7731";

fn keys(read: u8) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[read; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[read.wrapping_add(1); 32]))),
    }
}

fn plain_db(root: &Path) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false).backup_enabled(true);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    db
}

/// A plain database of `rows` people; the row `skip` (if any) has no phone.
fn make(rows: usize, skip: Option<usize>, unique_phone: bool) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let mut db = plain_db(&root).register::<Plain>("people");
    if unique_phone {
        db = db.unique::<Plain>(Unique::on(Plain::phone));
    }
    let s = Storage::builder(StorageConfig::default()).add_database(db).build().unwrap();
    let m = s.db_manager("store");
    for i in 0..rows {
        let mut row = serde_json::json!({ "id": format!("p{i}"), "name": format!("{SECRET}-{i}"), "password": format!("pw-{i}") });
        if skip != Some(i) {
            row["phone"] = serde_json::Value::String(format!("+1555000000{i:02}"));
        }
        m.set(TableDefinition::new("people"), "people", &format!("p{i}"), serde_json::to_vec(&row).unwrap()).unwrap();
    }
    drop(m);
    s.close();
    root
}

fn listing(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
            if e.path().is_dir() {
                walk(&e.path(), out);
            } else {
                out.push(e.path());
            }
        }
    }
    let mut files = Vec::new();
    walk(root, &mut files);
    let mut v: Vec<_> = files.iter().map(|p| (p.strip_prefix(root).unwrap().display().to_string(), std::fs::read(p).unwrap())).collect();
    v.sort();
    v
}

fn change(root: &Path) -> ChangeFields {
    ChangeFields::new(root, "records", "store")
}

fn refused(result: crate::units::Result<impl std::fmt::Debug>, words: &[&str]) {
    let err = result.expect_err("must be refused").to_string();
    for w in words {
        assert!(err.contains(w), "{w} in {err}");
    }
}

#[test]
fn a_dry_run_says_what_a_plain_field_becomes_and_touches_nothing() {
    let root = make(5, None, false);
    let before = listing(&root);
    let report = change(&root).field_keys(keys(5)).table::<Sealed1>("people").dry_run().unwrap();
    assert_eq!(listing(&root), before, "a dry run writes nothing");
    let people = &report.tables[0];
    assert_eq!((people.table.as_str(), people.rows, people.rewrites_rows), ("people", 5, true));
    let phone = people.fields.iter().find(|f| f.field == "phone").unwrap();
    assert_eq!((phone.change, phone.one_way, phone.id), ("sealed", false, 1));
    assert!(report.makes_data_key, "the database had no keys for fields");
    assert!(report.required_bytes > 0 && report.estimated_hash_time.is_none() && report.hash_values == 0);
    assert!(report.replaces.iter().any(|n| n == "store.cldb") && report.replaces.iter().any(|n| n == "store.keys"));
    // fingerprints with the value
    let printed = change(&root).field_keys(keys(5)).table::<Printed1>("people").dry_run().unwrap();
    assert_eq!(printed.tables[0].fields[0].change, "sealed");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_hash_or_a_fingerprint_alone_loses_the_value_and_has_to_be_confirmed() {
    let root = make(5, None, false);
    let before = listing(&root);
    refused(change(&root).field_keys(keys(5)).table::<Hashed2>("people").dry_run(), &["people", "confirm_one_way", "Nothing was changed"]);
    refused(change(&root).field_keys(keys(5)).table::<Token3>("people").dry_run(), &["confirm_one_way"]);
    assert_eq!(listing(&root), before);
    let report = change(&root).field_keys(keys(5)).table::<Hashed2>("people").confirm_one_way().dry_run().unwrap();
    let password = report.tables[0].fields.iter().find(|f| f.field == "password").unwrap();
    assert_eq!((password.change, password.one_way), ("hashed", true));
    // the estimate comes from one hash timed here, once for each value
    // the five rows and the five saved versions of them (each version is hashed too)`r`n    assert_eq!(report.hash_values, 10);
    assert!(report.estimated_hash_time.is_some_and(|t| !t.is_zero()) && report.hash_memory_bytes > 0);
    assert_eq!(listing(&root), before);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_row_without_the_value_a_protected_field_must_hold_is_refused_with_the_count() {
    let root = make(5, Some(2), false);
    let before = listing(&root);
    refused(change(&root).field_keys(keys(5)).table::<Sealed1>("people").dry_run(), &["people", "1 rows hold no value", "phone"]);
    assert_eq!(listing(&root), before);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_unique_constraint_on_a_field_that_changes_is_refused_because_it_holds_the_value() {
    let root = make(5, None, true);
    let before = listing(&root);
    refused(change(&root).field_keys(keys(5)).table::<Sealed1>("people").dry_run(), &["unique constraint", "phone", "Nothing was changed"]);
    // a field the constraint is not on can change
    change(&root).field_keys(keys(5)).table::<Hashed2>("people").confirm_one_way().dry_run().unwrap();
    assert_eq!(listing(&root), before);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_wrong_keys_the_wrong_table_and_no_table_are_refused_before_anything_is_read_further() {
    let root = make(3, None, false);
    let before = listing(&root);
    // keys of a whole-database encryption for a plain database
    refused(change(&root).whole_database_keys(keys(5)).table::<Sealed1>("people").dry_run(), &["not encrypted as a whole"]);
    refused(change(&root).field_keys(keys(5)).table::<Sealed1>("nope").dry_run(), &["no table 'nope'"]);
    refused(change(&root).field_keys(keys(5)).dry_run(), &["at least one table"]);
    // a change that needs a key, with none given
    refused(change(&root).table::<Sealed1>("people").dry_run(), &["keys"]);
    // keys that cannot make the data key of a database that has none
    let read_only = EncryptionConfig { search: None, ..keys(5) };
    assert!(matches!(change(&root).field_keys(read_only).table::<Sealed1>("people").dry_run(), Err(ClError::Validation(_))));
    assert_eq!(listing(&root), before);
    assert!(change(&root.join("missing")).field_keys(keys(5)).table::<Sealed1>("people").dry_run().is_err());
    let _ = std::fs::remove_dir_all(&root);
}

/// A database whose `people` table was made with these protected fields (no rows).
#[test]
fn a_database_that_keeps_its_lock_in_a_keys_file_elsewhere_is_refused_before_anything_is_touched() {
    // made with `field_keys_file`: the main file holds no lock, and a new data key made now would not
    // open the fields it has
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let file = root.join("outside.keys");
    let db = plain_db(&root).field_encryption(keys(5)).field_keys_file(&file).register_sealed::<Sealed1>("people");
    let s = Storage::builder(StorageConfig::default()).add_database(db).build().unwrap();
    s.domain::<Sealed1>().repo().set("p0", &Sealed1::default()).unwrap();
    s.close();
    let before = listing(&root);
    refused(
        change(&root).field_keys(keys(5)).table::<Printed1>("people").dry_run(),
        &["outside the main file", "nothing was changed"],
    );
    refused(change(&root).field_keys(keys(5)).table::<Printed1>("people").execute(), &["outside the main file"]);
    assert!(before == listing(&root), "a refused change touched a file");
}

fn sealed_empty<E: Entity + Serialize + Default + crate::field_crypto::SealedFields>() -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let db = plain_db(&root).field_encryption(keys(5)).register_sealed::<E>("people");
    Storage::builder(StorageConfig::default()).add_database(db).build().unwrap().close();
    root
}

#[test]
fn a_sealed_field_can_be_opened_given_fingerprints_or_made_a_hash_and_the_keys_are_checked() {
    let root = sealed_empty::<Sealed1>();
    let before = listing(&root);
    let opened = change(&root).field_keys(keys(5)).table_without_protected_fields("people").dry_run().unwrap();
    assert_eq!(opened.tables[0].fields[0].change, "opened");
    assert!(!opened.makes_data_key, "the database already has them");
    let added = change(&root).field_keys(keys(5)).table::<Printed1>("people").dry_run().unwrap();
    assert_eq!(added.tables[0].fields[0].change, "fingerprints added");
    // a hash in place of the sealed value is one way
    refused(change(&root).field_keys(keys(5)).table::<HashedAsPhone>("people").dry_run(), &["confirm_one_way"]);
    let hashed = change(&root).field_keys(keys(5)).table::<HashedAsPhone>("people").confirm_one_way().dry_run().unwrap();
    assert_eq!(hashed.tables[0].fields[0].change, "opened and hashed");
    // the same fields: nothing to rewrite
    let same = change(&root).field_keys(keys(5)).table::<Sealed1>("people").dry_run().unwrap();
    assert!(!same.tables[0].rewrites_rows && same.tables[0].fields[0].change == "kept");
    // a wrong key does not open the database at all; the search key alone cannot open a value
    assert!(matches!(change(&root).field_keys(keys(6)).table_without_protected_fields("people").dry_run(), Err(ClError::EncryptedOpenFailed)));
    let search_only = EncryptionConfig { read: None, ..keys(5) };
    refused(change(&root).field_keys(search_only).table_without_protected_fields("people").dry_run(), &["read key"]);
    // taking the fingerprints off needs no key at all
    let printed = sealed_empty::<Printed1>();
    let drop = change(&printed).table::<Sealed1>("people").dry_run().unwrap();
    assert_eq!(drop.tables[0].fields[0].change, "fingerprints removed");
    assert_eq!(listing(&root), before);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&printed);
}

#[test]
fn a_hash_goes_nowhere_and_a_fingerprint_alone_changes_nothing_else() {
    let root = sealed_empty::<Hashed2>();
    let before = listing(&root);
    refused(change(&root).field_keys(keys(5)).table_without_protected_fields("people").dry_run(), &["password", "cannot be removed"]);
    refused(change(&root).field_keys(keys(5)).table::<Sealed1>("people").confirm_one_way().dry_run(), &["password"]);
    // kept as it is, with its settings compared once the keys are open
    let kept = change(&root).field_keys(keys(5)).table::<Hashed2>("people").dry_run().unwrap();
    assert!(!kept.tables[0].rewrites_rows);
    assert_eq!(listing(&root), before);
    let _ = std::fs::remove_dir_all(&root);
}

// ---- execute ----

const PHONE_MARK: &[u8] = b"+1555000000";

fn files_with(root: &Path, needle: &[u8]) -> Vec<String> {
    listing(root).into_iter().filter(|(_, bytes)| bytes.windows(needle.len()).any(|w| w == needle)).map(|(n, _)| n).collect()
}

fn nothing_left_over(root: &Path) {
    for (name, _) in listing(root) {
        assert!(!name.contains(".mig-") && !name.contains(".migrating") && !name.contains(".creating"), "left behind: {name}");
    }
}

fn open_sealed<E: Entity + Serialize + Default + crate::field_crypto::SealedFields>(root: &Path) -> Storage {
    let db = plain_db(root).field_encryption(keys(5)).register_sealed::<E>("people");
    Storage::builder(StorageConfig::default()).add_database(db).build().unwrap()
}

fn stored_row(s: &Storage, id: &str) -> serde_json::Value {
    let bytes = s.db_manager("store").get_uncached(TableDefinition::<&str, &[u8]>::new("people"), id).unwrap().expect("row exists");
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn a_plain_field_is_sealed_in_every_row_and_every_saved_version_and_no_clear_value_stays() {
    let root = make(5, None, false);
    // one more row with numbers and text the change must not touch
    {
        let s = Storage::builder(StorageConfig::default()).add_database(plain_db(&root).register::<Plain>("people")).build().unwrap();
        let text = r#"{"id":"px","name":"caf\u00e9","phone":"+155500000099","password":"pw-x","big":123456789012345678901234567890,"near":0.1000000000000000055511151231257827}"#;
        s.db_manager("store").set(TableDefinition::new("people"), "people", "px", text.as_bytes().to_vec()).unwrap();
        s.close();
    }
    assert!(!files_with(&root, PHONE_MARK).is_empty(), "the phones are in the files before");
    assert!(root.join("records").join("store.cldb.bak").is_file(), "there is a history file");
    let done = change(&root).field_keys(keys(5)).table::<Sealed1>("people").execute().unwrap();
    assert!(done.rows > 0 && done.versions >= 6 && done.files_replaced >= 3, "{done:?}");
    nothing_left_over(&root);
    assert!(files_with(&root, PHONE_MARK).is_empty(), "a phone is still in {:?}", files_with(&root, PHONE_MARK));
    assert!(root.join("records").join("store.keys").is_file(), "the keys file is there");
    // the database opens with the fields declared, and every value opens to what it was
    let s = open_sealed::<Sealed1>(&root);
    let grant = s.domain::<Sealed1>().read_grant().unwrap();
    for i in 0..5 {
        let person = s.domain::<Sealed1>().repo().get(&format!("p{i}")).unwrap();
        assert_eq!(person.phone.open(&grant).unwrap(), format!("+1555000000{i:02}"));
        assert_eq!(person.password, format!("pw-{i}"));
        assert!(person.name.contains(SECRET));
    }
    // a field that did not change is the very bytes it was
    let px = s.db_manager("store").get_uncached(TableDefinition::<&str, &[u8]>::new("people"), "px").unwrap().unwrap();
    let px = std::str::from_utf8(&px).unwrap();
    for kept in ["123456789012345678901234567890", "0.1000000000000000055511151231257827", r#""caf\u00e9""#] {
        assert!(px.contains(kept), "{kept} in {px}");
    }
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fingerprints_are_added_and_the_field_is_opened_again_without_loss() {
    let root = make(4, None, false);
    change(&root).field_keys(keys(5)).table::<Sealed1>("people").execute().unwrap();
    let done = change(&root).field_keys(keys(5)).table::<Printed1>("people").execute().unwrap();
    assert!(done.rows > 0);
    nothing_left_over(&root);
    let s = open_sealed::<Printed1>(&root);
    let grant = s.domain::<Printed1>().read_grant().unwrap();
    let stored = stored_row(&s, "p2");
    assert!(stored["phone"]["s"].is_string() && stored["phone"]["f"].is_string() && stored["phone"].as_object().unwrap().len() == 2);
    assert_eq!(s.domain::<Printed1>().repo().get("p2").unwrap().phone.open(&grant).unwrap(), "+155500000002");
    s.close();
    // and back to a plain field: the values are in the rows again, and nothing sealed stays
    change(&root).field_keys(keys(5)).table_without_protected_fields("people").execute().unwrap();
    nothing_left_over(&root);
    assert!(!files_with(&root, PHONE_MARK).is_empty());
    let s = Storage::builder(StorageConfig::default()).add_database(plain_db(&root).register::<Plain>("people")).build().unwrap();
    for i in 0..4 {
        assert_eq!(s.domain::<Plain>().repo().get(&format!("p{i}")).unwrap().phone, format!("+1555000000{i:02}"));
    }
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_plain_field_becomes_a_hash_that_does_not_keep_the_value() {
    let root = make(3, None, false);
    change(&root).field_keys(keys(5)).table::<Hashed2>("people").confirm_one_way().execute().unwrap();
    nothing_left_over(&root);
    assert!(files_with(&root, b"pw-1").is_empty(), "a password is still in {:?}", files_with(&root, b"pw-1"));
    let s = open_sealed::<Hashed2>(&root);
    let stored = stored_row(&s, "p1");
    assert!(stored["password"].as_str().is_some_and(|h| !h.is_empty() && h != "pw-1"));
    assert_eq!(stored["phone"], "+155500000001");
    // the library's own check, on the rows of the database as it opens now: the password the row had
    // is accepted, any other is not, and a hash copied from another row does not match here
    let verifier = s.domain::<Hashed2>().verifier().unwrap();
    for i in 0..3 {
        let person = s.domain::<Hashed2>().repo().get(&format!("p{i}")).unwrap();
        assert!(person.password.verify(format!("pw-{i}"), &verifier).unwrap(), "p{i}: its own password");
        assert!(!person.password.verify("pw-wrong", &verifier).unwrap(), "p{i}: a wrong password");
        assert!(!person.password.verify(format!("pw-{}", (i + 1) % 3), &verifier).unwrap(), "p{i}: another row's password");
    }
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_change_that_fails_part_way_puts_the_old_files_back_exactly() {
    use crate::migration::encrypted::rows::FAIL_AFTER_BATCHES;
    let root = make(5, None, false);
    let before = listing(&root);
    FAIL_AFTER_BATCHES.with(|left| left.set(1));
    let result = change(&root).field_keys(keys(5)).table::<Sealed1>("people").execute();
    FAIL_AFTER_BATCHES.with(|left| left.set(-1));
    assert!(result.is_err(), "{result:?}");
    assert_eq!(listing(&root), before, "the old files are byte for byte as they were");
    nothing_left_over(&root);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_change_with_nothing_to_change_writes_nothing() {
    let root = sealed_empty::<Sealed1>();
    let before = listing(&root);
    let done = change(&root).field_keys(keys(5)).table::<Sealed1>("people").execute().unwrap();
    assert_eq!(done, super::api::FieldChangeDone::default());
    assert_eq!(listing(&root), before);
    let _ = std::fs::remove_dir_all(&root);
}

// ---- fingerprints ----

use crate::field_crypto::{PrintHandle, SealedFields};
use std::collections::BTreeSet;

macro_rules! named {
    ($ty:ident, $($attr:tt)*) => {
        #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
        struct $ty {
            id: String,
            #[clove(encrypt, id = 1, $($attr)*)]
            name: Sealed<String>,
            phone: String,
            password: String,
        }
        impl Entity for $ty {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    };
}
named!(NameFull, print = "full");
named!(NameFullLower, print = "full", normalize = "lowercase");
named!(NameParts, print = "parts", window = 3, grade = "balanced", normalize = "trim,lowercase");
named!(NamePartsLonger, print = "parts", window = 4, grade = "balanced", normalize = "trim,lowercase");
named!(NamePartsProtected, print = "parts", window = 4, grade = "protected", normalize = "trim,lowercase");

/// People whose names are in two cases, so that a normalisation shows.
fn make_names(rows: usize) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default()).add_database(plain_db(&root).register::<Plain>("people")).build().unwrap();
    let m = s.db_manager("store");
    for i in 0..rows {
        let name = if i % 2 == 0 { format!("ALICE{i:03} Smith") } else { format!("bob{i:03} Jones") };
        let row = serde_json::json!({ "id": format!("p{i}"), "name": name, "phone": format!("+1555000000{i:02}"), "password": format!("pw-{i}") });
        m.set(TableDefinition::new("people"), "people", &format!("p{i}"), serde_json::to_vec(&row).unwrap()).unwrap();
    }
    drop(m);
    s.close();
    root
}

type Named<E> = (PrintHandle<E>, fn(&E) -> &Sealed<String>, fn(&E) -> String);

fn rows_with_print<E>(s: &Storage, (handle, _, id_of): Named<E>, text: &str) -> BTreeSet<String>
where
    E: Entity + Serialize + serde::de::DeserializeOwned + Default + SealedFields + Clone + 'static,
{
    let domain = s.domain::<E>();
    let grant = domain.search_grant().unwrap();
    domain.query().filter(handle.print_eq(text, &grant)).collect().unwrap().iter().map(id_of).collect()
}

fn rows_with_piece<E>(s: &Storage, (handle, _, id_of): Named<E>, text: &str) -> BTreeSet<String>
where
    E: Entity + Serialize + serde::de::DeserializeOwned + Default + SealedFields + Clone + 'static,
{
    let domain = s.domain::<E>();
    let grant = domain.search_grant().unwrap();
    let results = handle.part_search(text).run(&domain, &grant).unwrap();
    assert!(results.is_confirmed());
    results.rows().iter().map(id_of).collect()
}

/// What a scan of every opened value says, with `keep` deciding on the opened text.
fn scan<E>(s: &Storage, (_, value, id_of): Named<E>, keep: impl Fn(&str) -> bool) -> BTreeSet<String>
where
    E: Entity + Serialize + serde::de::DeserializeOwned + Default + SealedFields + Clone + 'static,
{
    let domain = s.domain::<E>();
    let grant = domain.read_grant().unwrap();
    domain.query().collect().unwrap().iter().filter(|row| keep(&value(row).open(&grant).unwrap())).map(id_of).collect()
}

fn change_of(root: &Path, to: &dyn Fn(ChangeFields) -> ChangeFields) -> &'static str {
    to(change(root).field_keys(keys(5))).dry_run().unwrap().tables[0].fields[0].change
}

#[test]
fn a_changed_normalisation_makes_every_fingerprint_again_and_search_finds_what_a_scan_finds() {
    let root = make_names(30);
    change(&root).field_keys(keys(5)).table::<NameFull>("people").execute().unwrap();
    let full: Named<NameFull> = (NameFull::name, |e| &e.name, |e| e.id.clone());
    let s = open_sealed::<NameFull>(&root);
    // no normalisation: the case matters
    assert_eq!(rows_with_print(&s, full, "ALICE004 Smith"), BTreeSet::from(["p4".to_string()]));
    assert!(rows_with_print(&s, full, "alice004 smith").is_empty());
    s.close();
    // lowercase: the check changes, so the fingerprints are made again
    assert_eq!(change_of(&root, &|c| c.table::<NameFullLower>("people")), "fingerprints made again");
    change(&root).field_keys(keys(5)).table::<NameFullLower>("people").execute().unwrap();
    nothing_left_over(&root);
    assert_eq!(change_of(&root, &|c| c.table::<NameFullLower>("people")), "kept", "the check was brought up to date");
    let lower: Named<NameFullLower> = (NameFullLower::name, |e| &e.name, |e| e.id.clone());
    let s = open_sealed::<NameFullLower>(&root);
    for text in ["alice004 smith", "ALICE004 SMITH", "Bob007 jones"] {
        let want = scan(&s, lower, |v| v.to_lowercase() == text.to_lowercase());
        assert!(!want.is_empty(), "{text}");
        assert_eq!(rows_with_print(&s, lower, text), want, "{text}");
    }
    // the values themselves did not change
    assert_eq!(scan(&s, lower, |v| v.starts_with("ALICE")).len(), 15);
    s.close();
    assert!(files_with(&root, b"ALICE").is_empty(), "a name is still in a file");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_longer_part_and_another_grade_make_the_part_fingerprints_again_and_search_still_agrees_with_a_scan() {
    let root = make_names(30);
    change(&root).field_keys(keys(5)).table::<NameParts>("people").execute().unwrap();
    let needles = ["alice0", "lice01", "ob007", "smith", "jones", "e004 ", "zzzz"];
    let check = |s: &Storage, a: Named<NameParts>| {
        for needle in needles {
            assert_eq!(rows_with_piece(s, a, needle), scan(s, a, |v| v.to_lowercase().contains(needle)), "{needle}");
        }
    };
    let s = open_sealed::<NameParts>(&root);
    check(&s, (NameParts::name, |e| &e.name, |e| e.id.clone()));
    s.close();
    // the window 3 to 4
    assert_eq!(change_of(&root, &|c| c.table::<NamePartsLonger>("people")), "fingerprints made again");
    change(&root).field_keys(keys(5)).table::<NamePartsLonger>("people").execute().unwrap();
    assert_eq!(change_of(&root, &|c| c.table::<NamePartsLonger>("people")), "kept");
    let longer: Named<NamePartsLonger> = (NamePartsLonger::name, |e| &e.name, |e| e.id.clone());
    let s = open_sealed::<NamePartsLonger>(&root);
    for needle in needles {
        assert_eq!(rows_with_piece(&s, longer, needle), scan(&s, longer, |v| v.to_lowercase().contains(needle)), "{needle} after a longer part");
    }
    s.close();
    // the bits kept: balanced to protected
    assert_eq!(change_of(&root, &|c| c.table::<NamePartsProtected>("people")), "fingerprints made again");
    change(&root).field_keys(keys(5)).table::<NamePartsProtected>("people").execute().unwrap();
    assert_eq!(change_of(&root, &|c| c.table::<NamePartsProtected>("people")), "kept");
    let protected: Named<NamePartsProtected> = (NamePartsProtected::name, |e| &e.name, |e| e.id.clone());
    let s = open_sealed::<NamePartsProtected>(&root);
    for needle in needles {
        assert_eq!(rows_with_piece(&s, protected, needle), scan(&s, protected, |v| v.to_lowercase().contains(needle)), "{needle} after other bits");
    }
    s.close();
    nothing_left_over(&root);
    assert!(files_with(&root, b"ALICE").is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

entity!(TokenA {
    phone: String,
    password: String,
    #[clove(search_print, id = 3)]
    token: SearchPrint,
});
entity!(TokenLower {
    phone: String,
    password: String,
    #[clove(search_print, id = 3, normalize = "lowercase")]
    token: SearchPrint,
});

#[test]
fn a_fingerprint_that_stands_alone_accepts_no_change_to_it() {
    let root = sealed_empty::<TokenA>();
    let before = listing(&root);
    // the same declaration: nothing to do
    assert_eq!(change_of(&root, &|c| c.table::<TokenA>("people")), "kept");
    // another normalisation: the value is not kept, so the fingerprints cannot be made again
    refused(change(&root).field_keys(keys(5)).table::<TokenLower>("people").dry_run(), &["token", "cannot be made again", "Nothing was changed"]);
    refused(change(&root).field_keys(keys(5)).table::<TokenLower>("people").execute(), &["token"]);
    // turned into anything else, or taken away
    refused(change(&root).field_keys(keys(5)).table::<Sealed1>("people").dry_run(), &["token"]);
    refused(change(&root).field_keys(keys(5)).table_without_protected_fields("people").dry_run(), &["token", "cannot be removed"]);
    assert_eq!(listing(&root), before);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_saved_versions_of_a_hashed_field_accept_the_password_each_one_had() {
    // three people written twice: each has two saved versions with a different password
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    {
        let s = Storage::builder(StorageConfig::default()).add_database(plain_db(&root).register::<Plain>("people")).build().unwrap();
        let m = s.db_manager("store");
        for round in 0..2 {
            for i in 0..3 {
                let row = serde_json::json!({ "id": format!("p{i}"), "name": format!("{SECRET}-{i}"), "phone": format!("+1555000000{i:02}"), "password": format!("pw-{i}-r{round}") });
                m.set(TableDefinition::new("people"), "people", &format!("p{i}"), serde_json::to_vec(&row).unwrap()).unwrap();
            }
        }
        drop(m);
        s.close();
    }
    // without the confirmation nothing is touched
    let before = listing(&root);
    refused(change(&root).field_keys(keys(5)).table::<Hashed2>("people").execute(), &["confirm_one_way", "Nothing was changed"]);
    assert_eq!(listing(&root), before);
    let done = change(&root).field_keys(keys(5)).table::<Hashed2>("people").confirm_one_way().execute().unwrap();
    assert_eq!(done.versions, 6, "the number of saved versions is the number it had");
    assert!(files_with(&root, b"pw-1-r0").is_empty() && files_with(&root, b"pw-1-r1").is_empty());
    // the library's own check, through its own history: bring each saved version back and ask
    let s = open_sealed::<Hashed2>(&root);
    let domain = s.domain::<Hashed2>();
    let verifier = domain.verifier().unwrap();
    for i in 0..3 {
        let key = format!("p{i}");
        let mut versions: Vec<u64> = domain.history(&key).unwrap().iter().filter(|r| r.data.as_json().is_some()).map(|r| r.version).collect();
        versions.sort();
        assert_eq!(versions.len(), 2, "{key}: both saved versions are there");
        for (round, version) in versions.iter().enumerate() {
            domain.restore_by_version(&key, *version).unwrap();
            let person = domain.repo().get(&key).unwrap();
            assert!(person.password.verify(format!("pw-{i}-r{round}"), &verifier).unwrap(), "{key} version {version}: its own password");
            assert!(!person.password.verify(format!("pw-{i}-r{}", 1 - round), &verifier).unwrap(), "{key} version {version}: the other version's password");
            assert!(!person.password.verify("pw-wrong", &verifier).unwrap(), "{key} version {version}: a wrong password");
        }
    }
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

// ---- the rest of the closing list ----

entity!(PhoneAsToken {
    #[clove(search_print, id = 1)]
    phone: SearchPrint,
    password: String,
});

/// People written `rounds` times, so that each has a saved version for each round; the phone says which.
fn make_rounds(rows: usize, rounds: usize) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default()).add_database(plain_db(&root).register::<Plain>("people")).build().unwrap();
    let m = s.db_manager("store");
    for round in 0..rounds {
        for i in 0..rows {
            let row = serde_json::json!({ "id": format!("p{i}"), "name": format!("{SECRET}-{i}"), "phone": format!("+1555000000{i:02}-{round}"), "password": format!("pw-{i}") });
            m.set(TableDefinition::new("people"), "people", &format!("p{i}"), serde_json::to_vec(&row).unwrap()).unwrap();
        }
    }
    drop(m);
    s.close();
    root
}

#[test]
fn the_log_after_a_change_makes_a_following_reader_take_the_table_again_and_a_late_one_expire() {
    let root = make(5, None, false);
    let (late, current, head_old) = {
        let s = Storage::builder(StorageConfig::default()).add_database(plain_db(&root).register::<Plain>("people")).build().unwrap();
        let db = s.db_manager("store");
        let late = db.register_consumer("late").unwrap();
        let row = serde_json::json!({ "id": "p5", "name": SECRET, "phone": "+155500000005", "password": "pw-5" });
        db.set(TableDefinition::new("people"), "people", "p5", serde_json::to_vec(&row).unwrap()).unwrap();
        let current = db.register_consumer("current").unwrap();
        let head = db.journal_head().unwrap();
        drop(db);
        s.close();
        (late, current, head)
    };
    change(&root).field_keys(keys(5)).table::<Sealed1>("people").execute().unwrap();
    let s = open_sealed::<Sealed1>(&root);
    let db = s.db_manager("store");
    // one reset for the one table
    assert_eq!(db.journal_head().unwrap(), head_old + 1);
    // a reader that was up to date takes the table again, and what it takes holds no clear value
    let changes = db.read_changes(&current, head_old, 10).unwrap();
    assert_eq!(changes.len(), 1);
    assert!(matches!(changes[0].kind, crate::journal::ChangeKind::TableReset { .. }));
    let image = db.read_reset(&current, changes[0].seq).unwrap();
    assert_eq!(image.len(), 6);
    assert!(image.iter().all(|(_, bytes)| !bytes.windows(PHONE_MARK.len()).any(|w| w == PHONE_MARK)));
    // a reader that was behind is told its place is gone
    assert!(matches!(db.read_changes(&late, 0, 10), Err(ClError::ConsumerExpired)));
    drop(db);
    s.close();
    // the old lines of the log are gone from the file with the rest
    assert!(files_with(&root, PHONE_MARK).is_empty(), "{:?}", files_with(&root, PHONE_MARK));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_index_on_the_changed_field_leaves_no_value_and_the_rebuilt_search_agrees_with_a_scan() {
    let root = make(160, None, false);
    let wait_for_index = |s: &Storage, ask: &dyn Fn() -> u64| {
        let started = std::time::Instant::now();
        loop {
            assert_eq!(ask(), 1);
            if s.index_report().iter().any(|r| r.ready) {
                break;
            }
            assert!(started.elapsed() < std::time::Duration::from_secs(20), "no index became ready: {:?}", s.index_report());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };
    {
        let s = Storage::builder(StorageConfig::default()).add_database(plain_db(&root).register::<Plain>("people")).build().unwrap();
        let d = s.domain::<Plain>();
        wait_for_index(&s, &|| d.query().filter(Plain::phone.eq("+155500000007".to_string())).count().unwrap() as u64);
        s.close();
    }
    assert!(files_with(&root, PHONE_MARK).iter().any(|n| n.ends_with(".inx")), "the index file holds the phones before");
    change(&root).field_keys(keys(5)).table::<Printed1>("people").execute().unwrap();
    nothing_left_over(&root);
    assert!(files_with(&root, PHONE_MARK).is_empty(), "{:?}", files_with(&root, PHONE_MARK));
    // the index is built again, now on the fingerprint
    let s = open_sealed::<Printed1>(&root);
    let domain = s.domain::<Printed1>();
    let grant = domain.search_grant().unwrap();
    wait_for_index(&s, &|| domain.query().filter(Printed1::phone.print_eq("+155500000007", &grant)).count().unwrap() as u64);
    let read = domain.read_grant().unwrap();
    let everyone = domain.query().collect().unwrap();
    for i in [0usize, 7, 50, 99, 159] {
        let text = format!("+1555000000{i:02}");
        let found: BTreeSet<String> =
            domain.query().filter(Printed1::phone.print_eq(&text, &grant)).collect().unwrap().iter().map(|p| p.id.clone()).collect();
        let scanned: BTreeSet<String> = everyone.iter().filter(|p| p.phone.open(&read).unwrap() == text).map(|p| p.id.clone()).collect();
        assert_eq!(found, scanned, "{text}");
        assert_eq!(found.len(), 1, "{text}");
    }
    s.close();
    assert!(files_with(&root, PHONE_MARK).is_empty(), "the rebuilt index holds a phone: {:?}", files_with(&root, PHONE_MARK));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_four_changes_not_yet_made_on_rows_are_made_on_rows() {
    // fingerprints taken off a sealed field
    let root = make(5, None, false);
    change(&root).field_keys(keys(5)).table::<Printed1>("people").execute().unwrap();
    change(&root).field_keys(keys(5)).table::<Sealed1>("people").execute().unwrap();
    nothing_left_over(&root);
    let s = open_sealed::<Sealed1>(&root);
    assert!(stored_row(&s, "p2")["phone"].is_string(), "no fingerprint is left beside the sealed text");
    let grant = s.domain::<Sealed1>().read_grant().unwrap();
    for i in 0..5 {
        assert_eq!(s.domain::<Sealed1>().repo().get(&format!("p{i}")).unwrap().phone.open(&grant).unwrap(), format!("+1555000000{i:02}"));
    }
    s.close();
    let _ = std::fs::remove_dir_all(&root);

    // a plain field becomes a fingerprint that does not keep the value
    let root = make(5, None, false);
    change(&root).field_keys(keys(5)).table::<PhoneAsToken>("people").confirm_one_way().execute().unwrap();
    assert!(files_with(&root, PHONE_MARK).is_empty());
    let s = open_sealed::<PhoneAsToken>(&root);
    assert_eq!(stored_row(&s, "p3")["phone"].as_str().map(str::len), Some(43));
    let domain = s.domain::<PhoneAsToken>();
    let grant = domain.search_grant().unwrap();
    let found: BTreeSet<String> = domain.query().filter(PhoneAsToken::phone.print_eq("+155500000003", &grant)).collect().unwrap().iter().map(|p| p.id.clone()).collect();
    assert_eq!(found, BTreeSet::from(["p3".to_string()]));
    s.close();
    let _ = std::fs::remove_dir_all(&root);

    // a sealed field becomes a hash
    let root = make(5, None, false);
    change(&root).field_keys(keys(5)).table::<Sealed1>("people").execute().unwrap();
    change(&root).field_keys(keys(5)).table::<HashedAsPhone>("people").confirm_one_way().execute().unwrap();
    assert!(files_with(&root, PHONE_MARK).is_empty());
    let s = open_sealed::<HashedAsPhone>(&root);
    let verifier = s.domain::<HashedAsPhone>().verifier().unwrap();
    for i in 0..5 {
        let person = s.domain::<HashedAsPhone>().repo().get(&format!("p{i}")).unwrap();
        assert!(person.phone.verify(format!("+1555000000{i:02}"), &verifier).unwrap(), "p{i}");
        assert!(!person.phone.verify("+155500000099", &verifier).unwrap(), "p{i}");
    }
    s.close();
    let _ = std::fs::remove_dir_all(&root);

    // a sealed field becomes a fingerprint that does not keep the value
    let root = make(5, None, false);
    change(&root).field_keys(keys(5)).table::<Sealed1>("people").execute().unwrap();
    change(&root).field_keys(keys(5)).table::<PhoneAsToken>("people").confirm_one_way().execute().unwrap();
    assert!(files_with(&root, PHONE_MARK).is_empty());
    let s = open_sealed::<PhoneAsToken>(&root);
    let domain = s.domain::<PhoneAsToken>();
    let grant = domain.search_grant().unwrap();
    let found: BTreeSet<String> = domain.query().filter(PhoneAsToken::phone.print_eq("+155500000004", &grant)).collect().unwrap().iter().map(|p| p.id.clone()).collect();
    assert_eq!(found, BTreeSet::from(["p4".to_string()]));
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn every_saved_version_of_a_sealed_field_opens_to_the_value_it_had() {
    let root = make_rounds(3, 3);
    let done = change(&root).field_keys(keys(5)).table::<Sealed1>("people").execute().unwrap();
    assert_eq!(done.versions, 9, "the number of saved versions is the number it had");
    assert!(files_with(&root, PHONE_MARK).is_empty());
    let s = open_sealed::<Sealed1>(&root);
    let domain = s.domain::<Sealed1>();
    let grant = domain.read_grant().unwrap();
    for i in 0..3 {
        let key = format!("p{i}");
        let mut versions: Vec<u64> = domain.history(&key).unwrap().iter().filter(|r| r.data.as_json().is_some()).map(|r| r.version).collect();
        versions.sort();
        assert_eq!(versions.len(), 3, "{key}");
        for (round, version) in versions.iter().enumerate() {
            domain.restore_by_version(&key, *version).unwrap();
            assert_eq!(domain.repo().get(&key).unwrap().phone.open(&grant).unwrap(), format!("+1555000000{i:02}-{round}"), "{key} version {version}");
        }
    }
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_wrong_key_stops_the_change_and_the_folder_stays_the_very_bytes_it_was() {
    let root = make(3, None, false);
    change(&root).field_keys(keys(5)).table::<Sealed1>("people").execute().unwrap();
    let before = listing(&root);
    // the wrong read and search keys, and the right read key with a wrong search key
    assert!(matches!(change(&root).field_keys(keys(6)).table::<Printed1>("people").execute(), Err(ClError::EncryptedOpenFailed)));
    let half = EncryptionConfig { search: keys(6).search, ..keys(5) };
    assert!(matches!(change(&root).field_keys(half).table::<Printed1>("people").execute(), Err(ClError::EncryptedOpenFailed)));
    assert!(matches!(change(&root).field_keys(keys(6)).table_without_protected_fields("people").execute(), Err(ClError::EncryptedOpenFailed)));
    assert_eq!(listing(&root), before);
    nothing_left_over(&root);
    let _ = std::fs::remove_dir_all(&root);
}