//! The protected-field declaration as an outside program sees it.
use clove1db::{
    CloveFields,
    field_crypto::{
        HashAlgo, Hashed, Method, Plan, Sealed, SealedField, SealedFields, SearchPrint, check_layout,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, CloveFields)]
struct Customer {
    id: String,
    #[serde(rename = "mobile")]
    #[clove(encrypt, id = 10)]
    phone: Sealed<String>,
    #[clove(encrypt, id = 11, print = "parts")]
    national_id: Sealed<String>,
    #[clove(hash = "argon2id", id = 12)]
    password: Hashed,
    #[clove(search_print, id = 13)]
    api_token: SearchPrint,
}

#[derive(Serialize, Deserialize, CloveFields)]
#[serde(rename_all = "camelCase")]
struct Renamed {
    id: String,
    #[clove(encrypt, id = 1)]
    home_phone: Sealed<String>,
}

#[test]
fn the_json_key_follows_serde() {
    let keys: Vec<_> = Customer::SEALED.iter().map(|s| s.key).collect();
    assert_eq!(keys, ["mobile", "national_id", "password", "api_token"]);
    assert_eq!(Renamed::SEALED[0].key, "homePhone");
}

#[test]
fn methods_and_hash_settings_follow_the_attributes() {
    let got: Vec<_> = Customer::SEALED.iter().map(|s| (s.id, s.method, s.hash)).collect();
    assert_eq!(
        got,
        [
            (10, Method::Encrypt, None),
            (11, Method::EncryptPartPrints, None),
            (12, Method::Hash, Some(HashAlgo::Argon2id)),
            (13, Method::SearchPrint, None),
        ]
    );
}

#[test]
fn a_table_is_created_with_its_declaration_and_reopened_with_the_same_one() {
    let stored: Vec<SealedField> = Customer::SEALED.iter().map(SealedField::from_spec).collect();
    assert_eq!(
        check_layout("customers", Customer::SEALED, &[], true).unwrap(),
        Plan::Create(stored.clone())
    );
    assert_eq!(check_layout("customers", Customer::SEALED, &stored, false).unwrap(), Plan::Same);
}

#[test]
fn changing_the_declaration_of_an_existing_table_writes_nothing_and_says_migration() {
    let stored: Vec<SealedField> = Customer::SEALED.iter().map(SealedField::from_spec).collect();
    // A different entity (other numbers) opened over the same table.
    let err = check_layout("customers", Renamed::SEALED, &stored, false).unwrap_err().to_string();
    assert!(err.contains("migration") && err.contains("nothing was written"), "{err}");
    // The same fields declared on a table that has none stored.
    let err = check_layout("customers", Customer::SEALED, &[], false).unwrap_err().to_string();
    assert!(err.contains("migration"), "{err}");
}

#[test]
fn the_stored_description_names_no_cipher_and_no_hash() {
    let stored: Vec<SealedField> = Customer::SEALED.iter().map(SealedField::from_spec).collect();
    let text = serde_json::to_string(&stored).unwrap().to_lowercase();
    for word in ["aes", "chacha", "gcm", "siv", "argon", "scrypt", "hmac", "sha"] {
        assert!(!text.contains(word), "{text}");
    }
}
