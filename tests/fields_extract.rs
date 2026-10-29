use clove1db::{CloveFields, fields::Value};
#[derive(CloveFields)]
struct Note {
    missing: String,
    empty: Option<String>,
    num: i64,
}
#[test]
fn exact_number_and_missing_null() {
    let bytes = br#"{"empty":null,"num":9007199254740993.1234567890123456789}"#;
    assert_eq!(Note::missing.extract(bytes).unwrap(), Value::Missing);
    assert_eq!(Note::empty.extract(bytes).unwrap(), Value::Null);
    assert_eq!(
        Note::num.extract(bytes).unwrap(),
        Value::Number("9007199254740993.1234567890123456789".into())
    );
}

#[derive(CloveFields)]
struct Dynamic {
    document: serde_json::Value,
}
#[test]
fn selective_extraction_matches_pointer_for_random_documents() {
    let mut state = 7u64;
    for i in 0..100_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let item = match state % 5 {
            0 => serde_json::json!(null),
            1 => serde_json::json!({"x":state%1000}),
            2 => serde_json::json!({"x":[true,null,"text"]}),
            3 => serde_json::json!({"other":i}),
            _ => serde_json::json!({"x":{"a/b~c":"value"}}),
        };
        let doc = serde_json::json!({"document":{"a":[item,{"x":false}],"padding":"abc"}});
        let bytes = serde_json::to_vec(&doc).unwrap();
        let (field, pointer) = match i % 5 {
            0 => (Dynamic::document.key("a").at(0).key("x"), "/document/a/0/x"),
            1 => (Dynamic::document.key("a").at(2), "/document/a/2"),
            2 => (
                Dynamic::document.key("a").at(0).key("x").key("a/b~c"),
                "/document/a/0/x/a~1b~0c",
            ),
            3 => (Dynamic::document.key("a").at(0), "/document/a/0"),
            _ => (Dynamic::document.key("absent"), "/document/absent"),
        };
        let expected = doc
            .pointer(pointer)
            .cloned()
            .map(Value::from_json)
            .unwrap_or(Value::Missing);
        assert_eq!(field.extract(&bytes).unwrap(), expected);
    }
}
#[test]
fn invalid_json_is_not_silently_missing() {
    assert!(Note::missing.extract(br#"{"num":1,broken}"#).is_err());
}
