use clove1db::CloveFields;
use serde::Serialize;
use std::collections::HashMap;
#[derive(Serialize, CloveFields)]
struct Child {
    name: String,
}
#[derive(Serialize, CloveFields)]
struct Note {
    title: String,
    score: i64,
    child: Child,
    children: Vec<Child>,
    labels: Vec<String>,
    map: HashMap<String, Child>,
    dynamic: serde_json::Value,
}
#[test]
fn typed_navigation_and_canonical_ast() {
    let p = Note::title
        .trim()
        .lowercase()
        .eq("hello")
        .and(Note::score.between(1i64, 10i64))
        .or(Note::child.then(Child::name).exists().not());
    assert_eq!(p.fingerprint().unwrap(), p.clone().fingerprint().unwrap());
    let original = Note::title.trim().eq("x");
    let mut changed = original.clone();
    if let clove1db::fields::Expr::Compare { path, .. } = &mut changed.expression {
        path.transforms[0].version += 1;
    }
    assert_ne!(
        original.fingerprint().unwrap(),
        changed.fingerprint().unwrap()
    );
    assert_ne!(
        Note::title
            .trim()
            .lowercase()
            .eq("x")
            .fingerprint()
            .unwrap(),
        Note::title
            .lowercase()
            .trim()
            .eq("x")
            .fingerprint()
            .unwrap()
    );
    assert_eq!(
        Note::children.any().then(Child::name).json_path(),
        vec!["children", "name"]
    );
    let _ = Note::children.all().then(Child::name).eq("a");
    let _ = Note::children.at(1).then(Child::name).eq("a");
    let _ = Note::children.elem_match(Child::name.eq("a"));
    let _ = Note::labels.len().ge(2u64);
    assert_eq!(
        Note::map.key("a").then(Child::name).json_path(),
        vec!["map", "a", "name"]
    );
    let _ = Note::dynamic
        .key("array")
        .at(0)
        .key("name")
        .eq(serde_json::json!("a"));
    let _ = Note::title
        .prefix("p")
        .and(Note::title.contains("x"))
        .and(Note::title.text("word"));
}

#[test]
fn dynamic_literals_are_canonical_and_null_never_masks_valid_members() {
    use clove1db::fields::{Expr, Value};
    assert_eq!(
        Note::dynamic
            .eq(serde_json::json!(1))
            .fingerprint()
            .unwrap(),
        Note::dynamic
            .eq(serde_json::json!(1.0))
            .fingerprint()
            .unwrap()
    );
    assert!(matches!(
        Note::dynamic.eq(serde_json::Value::Null).expression,
        Expr::Never
    ));
    let predicate = Note::dynamic.in_([serde_json::Value::Null, serde_json::json!("valid")]);
    match predicate.expression {
        Expr::Compare { values, .. } => assert_eq!(values, vec![Value::String("valid".into())]),
        _ => panic!("a null member must not discard valid alternatives"),
    }
}
