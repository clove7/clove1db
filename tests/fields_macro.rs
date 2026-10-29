use clove1db::CloveFields;
use serde::{Deserialize, Serialize};
macro_rules! case {
    ($name:ident,$rule:literal) => {
        #[derive(Serialize, CloveFields)]
        #[serde(rename_all=$rule)]
        struct $name {
            first_name: String,
            letter_x: u64,
        }
        impl $name {
            fn verify() {
                let value = serde_json::to_value(Self {
                    first_name: "n".into(),
                    letter_x: 1,
                })
                .unwrap();
                for path in [Self::first_name.json_path(), Self::letter_x.json_path()] {
                    assert!(value.get(&path[0]).is_some());
                }
            }
        }
    };
}
case!(Lower, "lowercase");
case!(Upper, "UPPERCASE");
case!(Pascal, "PascalCase");
case!(Camel, "camelCase");
case!(Snake, "snake_case");
case!(Scream, "SCREAMING_SNAKE_CASE");
case!(Kebab, "kebab-case");
case!(LoudKebab, "SCREAMING-KEBAB-CASE");
#[test]
fn all_serde_rename_rules_match_serialized_keys() {
    Lower::verify();
    Upper::verify();
    Pascal::verify();
    Camel::verify();
    Snake::verify();
    Scream::verify();
    Kebab::verify();
    LoudKebab::verify();
}
#[derive(Serialize, Deserialize, CloveFields)]
struct Inner {
    #[serde(rename = "actual")]
    leaf: String,
}
#[derive(Serialize, CloveFields)]
struct Outer<T> {
    #[serde(rename(serialize = "stored", deserialize = "input"))]
    label: String,
    #[serde(flatten)]
    inner: Inner,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    optional: Option<String>,
    nested: T,
    #[serde(skip)]
    hidden: String,
    #[serde(skip_serializing)]
    transient: String,
}
#[test]
fn nested_flatten_optional_and_serialization_direction() {
    let n = Outer {
        label: "x".into(),
        inner: Inner { leaf: "y".into() },
        optional: None,
        nested: Inner { leaf: "z".into() },
        hidden: String::new(),
        transient: String::new(),
    };
    let value = serde_json::to_value(&n).unwrap();
    for path in [
        Outer::<Inner>::label.json_path(),
        Outer::<Inner>::inner.then(Inner::leaf).json_path(),
        Outer::<Inner>::nested.then(Inner::leaf).json_path(),
    ] {
        let pointer = path.iter().map(|p| format!("/{}", p)).collect::<String>();
        assert!(value.pointer(&pointer).is_some());
    }
    assert!(value.get("optional").is_none());
    assert_eq!(Outer::<Inner>::optional.json_path(), vec!["optional"]);
}

#[derive(Serialize, CloveFields)]
struct EmptyKey {
    #[serde(rename = "")]
    value: String,
}
#[test]
fn empty_json_key_is_not_flatten() {
    assert_eq!(EmptyKey::value.json_path(), vec![""]);
}
#[test]
fn transformed_nested_field_keeps_child_transform() {
    let bytes = br#"{"nested":{"actual":"  x  "}}"#;
    assert_eq!(
        Outer::<Inner>::nested
            .then(Inner::leaf.trim())
            .extract(bytes)
            .unwrap(),
        clove1db::fields::Value::String("x".into())
    );
}

fn number_text<S: serde::Serializer>(v: &i64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}
mod wrapped {
    pub fn serialize<S: serde::Serializer>(v: &i64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
}
#[derive(Serialize, CloveFields)]
struct Custom {
    #[serde(serialize_with = "number_text")]
    #[clove(as = String)]
    count: i64,
    #[serde(with = "wrapped")]
    #[clove(as = String)]
    other: i64,
    #[serde(serialize_with = "number_text")]
    #[clove(skip)]
    ignored: i64,
}
#[derive(Serialize, CloveFields)]
enum Color {
    #[serde(rename = "stored")]
    Blue,
}
#[derive(Serialize, CloveFields)]
#[serde(tag = "kind")]
enum Payload {
    Count { n: i64 },
}
#[derive(Serialize, CloveFields)]
struct Enums {
    color: Color,
    payload: Payload,
}
#[test]
fn explicit_custom_shape_and_enum_serialization() {
    let c = Custom {
        count: 3,
        other: 4,
        ignored: 5,
    };
    let bytes = serde_json::to_vec(&c).unwrap();
    assert_eq!(
        Custom::count.extract(&bytes).unwrap(),
        clove1db::fields::Value::String("3".into())
    );
    assert_eq!(
        Custom::other.extract(&bytes).unwrap(),
        clove1db::fields::Value::String("4".into())
    );
    let _ = Custom::count.trim().eq("3");
    let p = Enums::color.eq(Color::Blue);
    if let clove1db::fields::Expr::Compare { values, .. } = p.expression {
        assert_eq!(
            values,
            vec![clove1db::fields::Value::String("stored".into())]
        );
    } else {
        panic!();
    }
    let _ = Enums::payload
        .eq(Payload::Count { n: 1 })
        .fingerprint()
        .unwrap();
}

#[derive(Serialize)]
enum Opaque {
    Item { n: i64 },
}
#[derive(Serialize, CloveFields)]
struct Explicit {
    #[clove(as = serde_json::Value)]
    payload: Opaque,
}
#[derive(Serialize, CloveFields)]
struct Tree {
    name: String,
    children: Vec<Tree>,
}
#[test]
fn opaque_shapes_require_an_escape_and_recursive_shapes_compile() {
    let item = Explicit {
        payload: Opaque::Item { n: 1 },
    };
    let bytes = serde_json::to_vec(&item).unwrap();
    assert_eq!(
        Explicit::payload.extract(&bytes).unwrap(),
        clove1db::fields::Value::from_json(serde_json::json!({"Item":{"n":1}}))
    );
    let _ = Explicit::payload
        .eq(serde_json::json!({"Item":{"n":1}}))
        .fingerprint()
        .unwrap();
    let _ = Tree::children.any().then(Tree::name).eq("leaf");
}
