//! A sealed value moved inside a database that is encrypted as a whole: to another row, another
//! field, another table, or changed by a byte. The public API refuses to write such bytes, so these
//! tests write the stored row directly (a crate-private call) and then read it, as an attacker who
//! got past the outer layer would leave it. Every case must be a tamper error, never a wrong value.
use crate::{
    CloveFields,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::{EncryptionConfig, KeySource},
    entity::Entity,
    field_crypto::Sealed,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};

macro_rules! person {
    ($name:ident) => {
        #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
        struct $name {
            id: String,
            name: String,
            #[clove(encrypt, id = 1)]
            phone: Sealed<String>,
            #[clove(encrypt, id = 2)]
            tags: Sealed<Vec<String>>,
        }
        impl Entity for $name {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    };
}
person!(Person);
person!(Other);

fn keys() -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    }
}

fn open() -> Storage {
    let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(dir)
                .has_cache(false)
                .backup_enabled(true)
                .encryption(keys())
                .register_sealed::<Person>("people")
                .register_sealed::<Other>("others"),
        )
        .build()
        .unwrap()
}

fn raw(s: &Storage, table: &str, id: &str) -> serde_json::Value {
    let bytes = s
        .db_manager("store")
        .get_uncached(TableDefinition::<&str, &[u8]>::new(table), id)
        .unwrap()
        .expect("row exists");
    serde_json::from_slice(&bytes).unwrap()
}

/// Writes the stored row of `table`/`id` as `value`, bypassing the sealing.
fn put(s: &Storage, table: &'static str, id: &str, value: &serde_json::Value) {
    s.db_manager("store")
        .set_prepared(TableDefinition::<&str, &[u8]>::new(table), table, id, serde_json::to_vec(value).unwrap())
        .unwrap();
}

fn person(id: &str, phone: &str) -> Person {
    Person { id: id.into(), name: "n".into(), phone: Sealed::new(phone.into()), tags: Sealed::new(vec!["vip".into()]) }
}

#[test]
fn a_sealed_value_moved_or_changed_inside_a_whole_encrypted_database_is_a_tamper_error() {
    let s = open();
    let repo = s.domain::<Person>().repo();
    repo.set("p1", &person("p1", "+155500000001")).unwrap();
    repo.set("p2", &person("p2", "+155500000002")).unwrap();
    s.domain::<Other>()
        .repo()
        .set("o1", &Other { id: "o1".into(), name: "n".into(), phone: Sealed::new("+155500000003".into()), tags: Sealed::new(vec![]) })
        .unwrap();
    let grant = s.domain::<Person>().read_grant().unwrap();
    let original = raw(&s, "people", "p2");
    assert_eq!(repo.get("p2").unwrap().phone.open(&grant).unwrap(), "+155500000002");

    let phone_of_p1 = raw(&s, "people", "p1")["phone"].clone();
    let tags_of_p1 = raw(&s, "people", "p1")["tags"].clone();
    let phone_of_other_table = raw(&s, "others", "o1")["phone"].clone();
    let own_phone = original["phone"].as_str().unwrap().to_string();
    // One character changed near the end of the envelope (inside the ciphertext or tag).
    let mut changed = own_phone.clone().into_bytes();
    let last = changed.len() - 2;
    changed[last] = if changed[last] == b'A' { b'B' } else { b'A' };

    let cases: Vec<(&str, serde_json::Value)> = vec![
        ("another row", phone_of_p1),
        ("another field", tags_of_p1),
        ("another table", phone_of_other_table),
        ("one changed character", serde_json::Value::String(String::from_utf8(changed).unwrap())),
    ];
    for (what, value) in cases {
        let mut row = original.clone();
        row["phone"] = value;
        put(&s, "people", "p2", &row);
        let read = repo.get("p2").unwrap();
        match read.phone.open(&grant) {
            Err(ClError::DataTampered) => {}
            Err(other) => panic!("{what}: wrong error {other:?}"),
            Ok(value) => panic!("{what}: a value was returned: {value}"),
        }
        // The field next to it, untouched, still opens.
        assert_eq!(read.tags.open(&grant).unwrap(), vec!["vip".to_string()], "{what}");
    }
    // Put the original bytes back: it opens again.
    put(&s, "people", "p2", &original);
    assert_eq!(repo.get("p2").unwrap().phone.open(&grant).unwrap(), "+155500000002");
}
