use super::*;
use crate::CloveFields;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, CloveFields)]
struct Account {
    id: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(encrypt, id = 2, print = "full")]
    national: Sealed<Vec<u32>>,
    #[clove(encrypt, id = 3, print = "parts")]
    card: Sealed<Option<String>>,
    #[clove(hash = "argon2id", id = 4)]
    password: Hashed,
    #[clove(hash = "scrypt", id = 6)]
    code: Hashed,
    #[clove(search_print, id = 5)]
    token: SearchPrint,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, CloveFields)]
struct Plain {
    id: String,
    name: String,
}

fn fresh() -> Account {
    Account {
        id: "a1".into(),
        phone: Sealed::new("+155500000001".into()),
        national: Sealed::new(vec![1, 2, 3]),
        card: Sealed::new(None),
        password: Hashed::new("hunter2"),
        code: Hashed::new("000111"),
        token: SearchPrint::new("tok-abc"),
        name: "visible".into(),
    }
}

fn closed_json() -> serde_json::Value {
    serde_json::json!({
        "id": "a1",
        "phone": "AAAA",
        "national": "BBBB",
        "card": "CCCC",
        "password": "DDDD",
        "code": "EEEE",
        "token": "FFFF",
        "name": "visible"
    })
}

#[test]
fn the_declaration_lists_every_protected_field_in_order() {
    let want = [
        (1, "phone", Method::Encrypt, None),
        (2, "national", Method::EncryptFullPrint, None),
        (3, "card", Method::EncryptPartPrints, None),
        (4, "password", Method::Hash, Some(HashAlgo::Argon2id)),
        (6, "code", Method::Hash, Some(HashAlgo::Scrypt)),
        (5, "token", Method::SearchPrint, None),
    ];
    assert_eq!(Account::SEALED.len(), want.len());
    for (spec, (id, key, method, hash)) in Account::SEALED.iter().zip(want) {
        assert_eq!((spec.id, spec.key, spec.method, spec.hash), (id, key, method, hash));
    }
}

#[test]
fn an_entity_without_protected_fields_derives_as_before() {
    // The macro emits no protection items for `Plain`; it serializes exactly as it always did.
    fn needs<T: crate::fields::CloveFields>() {}
    needs::<Plain>();
    let plain = Plain { id: "p".into(), name: "n".into() };
    assert_eq!(serde_json::to_string(&plain).unwrap(), r#"{"id":"p","name":"n"}"#);
}

#[test]
fn a_new_value_cannot_be_serialized_outside_the_storage_step() {
    let entity = fresh();
    let err = serde_json::to_string(&entity).unwrap_err().to_string();
    assert!(err.contains("can only be serialized by the storage"), "{err}");
    assert!(!err.contains("15550100001") && !err.contains("hunter2"), "{err}");
}

#[test]
fn each_kind_refuses_on_its_own() {
    assert!(serde_json::to_string(&Sealed::new("x".to_string())).is_err());
    assert!(serde_json::to_string(&Hashed::new("x")).is_err());
    assert!(serde_json::to_string(&SearchPrint::new("x")).is_err());
}

#[test]
fn inside_the_storage_step_a_new_value_is_a_placeholder() {
    let entity = fresh();
    let _scope = SealScope::enter();
    let json = serde_json::to_value(&entity).unwrap();
    for key in ["phone", "national", "card", "password", "code", "token"] {
        assert!(json[key].is_null(), "{key}");
    }
    assert_eq!(json["name"], "visible");
    let text = json.to_string();
    for secret in ["15550100001", "hunter2", "000111", "tok-abc"] {
        assert!(!text.contains(secret));
    }
}

#[test]
fn a_value_read_from_storage_is_closed_and_serializes_as_its_text() {
    let entity: Account = serde_json::from_value(closed_json()).unwrap();
    assert!(!entity.phone.is_new() && !entity.phone.is_bound());
    assert!(!entity.password.is_new());
    assert_eq!(serde_json::to_value(&entity).unwrap(), closed_json());
}

#[test]
fn stored_text_is_required() {
    for key in ["phone", "password", "token"] {
        let mut json = closed_json();
        json[key] = serde_json::json!(12);
        assert!(serde_json::from_value::<Account>(json).is_err(), "{key}");
    }
}

#[test]
fn the_parts_of_a_new_entity_hold_the_new_values() {
    let entity = fresh();
    let parts = entity.sealed_parts().unwrap();
    assert_eq!(parts.len(), Account::SEALED.len());
    let new = |i: usize| match &parts[i] {
        Part::New(bytes) => bytes.as_bytes().to_vec(),
        _ => panic!("part {i} is not new"),
    };
    assert_eq!(new(0), b"\"+155500000001\"");
    assert_eq!(new(1), b"[1,2,3]");
    assert_eq!(new(2), b"null");
    assert_eq!(new(3), b"hunter2");
    assert_eq!(new(4), b"000111");
    assert_eq!(new(5), b"tok-abc");
}

#[test]
fn closed_parts_report_where_they_are_bound() {
    let mut entity: Account = serde_json::from_value(closed_json()).unwrap();
    let unbound = entity.sealed_parts().unwrap();
    assert!(matches!(unbound[0], Part::Closed { text: "AAAA", full: None, parts: None, bound: None }));
    assert!(matches!(unbound[5], Part::Stored("FFFF")));
    drop(unbound);

    let row = RowBinding::new("table-1", "a1");
    entity.bind_sealed(&row);
    assert!(entity.phone.is_bound() && entity.password.is_bound());
    let bound = entity.sealed_parts().unwrap();
    match &bound[0] {
        Part::Closed { bound: Some(b), .. } => assert_eq!(**b, row.field(1)),
        _ => panic!("phone is not bound"),
    }
    match &bound[3] {
        Part::Closed { bound: Some(b), .. } => assert_eq!(**b, row.field(4)),
        _ => panic!("password is not bound"),
    }
    assert!(matches!(bound[5], Part::Stored("FFFF")));
}

#[test]
fn a_binding_names_the_place_exactly() {
    let a = RowBinding::new("t", "r").field(1);
    assert_eq!(a, RowBinding::new("t", "r").field(1));
    assert_ne!(a, RowBinding::new("t", "r").field(2));
    assert_ne!(a, RowBinding::new("t", "s").field(1));
    assert_ne!(a, RowBinding::new("u", "r").field(1));
}

#[test]
fn debug_never_shows_a_value() {
    let entity = fresh();
    let text = format!("{entity:?}");
    for secret in ["15550100001", "hunter2", "000111", "tok-abc", "[1, 2, 3]"] {
        assert!(!text.contains(secret), "{text}");
    }
    assert!(text.contains("visible"));
    let closed: Account = serde_json::from_value(closed_json()).unwrap();
    let text = format!("{closed:?}");
    for text_part in ["AAAA", "DDDD", "FFFF"] {
        assert!(!text.contains(text_part), "{text}");
    }
}

#[test]
fn defaults_are_new_empty_values() {
    assert!(Sealed::<String>::default().is_new());
    assert!(Hashed::default().is_new());
    assert!(SearchPrint::default().is_new());
}
