use clove1db::fields::{Value, codec};
#[test]
fn exact_decimal_domain_and_boundaries() {
    for token in ["1", "1.0", "1e0", "0.1e1", " 1 "] {
        assert_eq!(
            codec::encode(&Value::Number(token.into())).unwrap(),
            codec::encode(&Value::Number("1".into())).unwrap()
        );
    }
    for token in ["-0", "0.0", "-0e300"] {
        assert_eq!(
            codec::encode(&Value::Number(token.into())).unwrap(),
            codec::encode(&Value::Number("0".into())).unwrap()
        );
    }
    assert!(
        codec::encode(&Value::Number("9007199254740993".into())).unwrap()
            > codec::encode(&Value::Number("9007199254740992".into())).unwrap()
    );
    assert!(codec::number_from_f64(f64::NAN).is_err());
    assert!(codec::number_from_f64(f64::INFINITY).is_err());
}

use std::cmp::Ordering;
fn next(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}
fn number(s: &mut u64) -> (Value, i128, i128) {
    let n = next(s);
    match n % 4 {
        0 => (Value::Number((n as i64).to_string()), n as i64 as i128, 1),
        1 => (Value::Number(n.to_string()), n as i128, 1),
        2 => {
            let m = n as i64 as i128;
            let a = m.abs();
            (
                Value::Number(format!(
                    "{}{}.{:06}",
                    if m < 0 { "-" } else { "" },
                    a / 1_000_000,
                    a % 1_000_000
                )),
                m,
                1_000_000,
            )
        }
        _ => {
            let m = (n % 1_000_000) as i128;
            let v = m as f64 / 8.;
            (codec::number_from_f64(v).unwrap(), m, 8)
        }
    }
}
fn string(s: &mut u64) -> String {
    let choices = ['a', 'z', '\0', '\u{FFFF}', 'ع', 'ي', 'é', '🙂'];
    (0..(next(s) % 12))
        .map(|_| choices[(next(s) % choices.len() as u64) as usize])
        .collect()
}
fn rank(v: &Value) -> u8 {
    match v {
        Value::Missing => 1,
        Value::Null => 2,
        Value::Bool(false) => 3,
        Value::Bool(true) => 4,
        Value::Number(_) => 5,
        Value::Time(_) => 6,
        Value::String(_) => 7,
        Value::Array(_) => 8,
        _ => 9,
    }
}
fn natural(a: &Value, b: &Value) -> Ordering {
    let r = rank(a).cmp(&rank(b));
    if r != Ordering::Equal {
        return r;
    }
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => {
            a.parse::<i128>().unwrap().cmp(&b.parse::<i128>().unwrap())
        }
        (Value::Time(a), Value::Time(b)) => a.cmp(b),
        (Value::String(a), Value::String(b)) => a.cmp(b),
        (Value::Array(a), Value::Array(b)) => {
            for (a, b) in a.iter().zip(b) {
                let c = natural(a, b);
                if c != Ordering::Equal {
                    return c;
                }
            }
            a.len().cmp(&b.len())
        }
        _ => Ordering::Equal,
    }
}
fn mixed(s: &mut u64) -> Value {
    match next(s) % 8 {
        0 => Value::Missing,
        1 => Value::Null,
        2 => Value::Bool(next(s) % 2 == 0),
        3 => Value::Number((next(s) as i64).to_string()),
        4 => Value::Time(next(s) as i64 as i128 * 1_000_000_000),
        5 => Value::String(string(s)),
        _ => Value::Array(
            (0..next(s) % 4)
                .map(|_| Value::Number((next(s) as i64).to_string()))
                .collect(),
        ),
    }
}
#[test]
fn hundred_thousand_pairs_per_type_and_mixed() {
    let mut s = 19u64;
    for i in 0..100_000 {
        let (a, am, ad) = number(&mut s);
        let (b, bm, bd) = number(&mut s);
        assert_eq!(
            codec::encode(&a).unwrap().cmp(&codec::encode(&b).unwrap()),
            (am * bd).cmp(&(bm * ad)),
            "number pair {i}"
        );
        let pairs = [
            (Value::Missing, Value::Missing),
            (Value::Null, Value::Null),
            (
                Value::Bool(next(&mut s) % 2 == 0),
                Value::Bool(next(&mut s) % 2 == 0),
            ),
            (
                Value::Time(next(&mut s) as i64 as i128 * 1_000_000_000),
                Value::Time(next(&mut s) as i64 as i128 * 1_000_000_000),
            ),
            (Value::String(string(&mut s)), Value::String(string(&mut s))),
            (
                Value::Array(vec![Value::Number((next(&mut s) as i64).to_string())]),
                Value::Array(vec![
                    Value::Number((next(&mut s) as i64).to_string()),
                    Value::Null,
                ]),
            ),
            (mixed(&mut s), mixed(&mut s)),
        ];
        for (a, b) in pairs {
            assert_eq!(
                codec::encode(&a).unwrap().cmp(&codec::encode(&b).unwrap()),
                natural(&a, &b),
                "pair {i}"
            );
        }
    }
}
#[test]
fn fixed_edges_and_canonical_object_equality() {
    let sorted = [
        "-18446744073709551615",
        "-9223372036854775808",
        "-1.00000000000000000001",
        "-1",
        "-0.00000000000000000001",
        "0",
        "0.00000000000000000001",
        "1",
        "1.00000000000000000001",
        "9007199254740991",
        "9007199254740992",
        "9007199254740993",
        "9223372036854775807",
        "18446744073709551615",
    ];
    for pair in sorted.windows(2) {
        assert!(
            codec::encode(&Value::Number(pair[0].into())).unwrap()
                < codec::encode(&Value::Number(pair[1].into())).unwrap()
        );
    }
    let a = Value::from_json(serde_json::json!({"b":1,"a":2}));
    let b = Value::from_json(serde_json::json!({"a":2.0,"b":1.0}));
    assert_eq!(
        codec::encode_equality(&a).unwrap(),
        codec::encode_equality(&b).unwrap()
    );
    assert!(codec::encode(&a).is_err());
    for pair in [
        vec![Value::String("a".into())],
        vec![Value::String("a".into()), Value::Missing],
    ]
    .windows(2)
    {
        assert!(codec::encode_tuple(&pair[0]).unwrap() < codec::encode_tuple(&pair[1]).unwrap());
    }
    assert!(
        codec::encode(&Value::String("a".into())).unwrap()
            < codec::encode(&Value::String("a\0".into())).unwrap()
    );
}
#[derive(clove1db::CloveFields)]
struct Dates {
    utc: chrono::DateTime<chrono::Utc>,
    naive: chrono::NaiveDateTime,
    day: chrono::NaiveDate,
    #[clove(epoch = "s")]
    seconds: i64,
    #[clove(epoch = "ms")]
    millis: i64,
    ordinary: String,
}
#[test]
fn temporal_interpretation_matches_utc_and_epoch() {
    let bytes=br#"{"utc":"1969-12-31T19:00:00-05:00","naive":"1970-01-01T00:00:00","day":"1970-01-01","seconds":0,"millis":0,"ordinary":"1970-01-01"}"#;
    for value in [
        Dates::utc.extract(bytes).unwrap(),
        Dates::naive.extract(bytes).unwrap(),
        Dates::day.extract(bytes).unwrap(),
        Dates::seconds.extract(bytes).unwrap(),
        Dates::millis.extract(bytes).unwrap(),
    ] {
        assert_eq!(value, Value::Time(0));
    }
    assert!(matches!(
        Dates::ordinary.extract(bytes).unwrap(),
        Value::String(_)
    ));
    let utc = chrono::DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z").unwrap();
    let _ = Dates::utc.eq(utc).fingerprint().unwrap();
    for a in [
        "1900-01-01T00:00:00Z",
        "1969-12-31T23:59:59Z",
        "1970-01-01T00:00:00Z",
        "2038-01-19T03:14:08Z",
        "2100-01-01T00:00:00Z",
    ]
    .windows(2)
    {
        let parse = |v: &str| {
            let d = chrono::DateTime::parse_from_rfc3339(v).unwrap();
            Value::Time(d.timestamp() as i128 * 1_000_000_000)
        };
        assert!(codec::encode(&parse(a[0])).unwrap() < codec::encode(&parse(a[1])).unwrap());
    }
}

#[derive(clove1db::CloveFields)]
struct DateList {
    dates: Vec<chrono::NaiveDate>,
}
#[test]
fn date_list_navigation_retains_temporal_interpretation() {
    let bytes = br#"{"dates":["1970-01-01","1970-01-02"]}"#;
    assert_eq!(
        DateList::dates.at(0).extract(bytes).unwrap(),
        Value::Time(0)
    );
    assert_eq!(
        DateList::dates.any().extract(bytes).unwrap(),
        Value::Array(vec![Value::Time(0), Value::Time(86_400_000_000_000)])
    );
    assert_eq!(
        DateList::dates.len().extract(bytes).unwrap(),
        Value::Number("2".into())
    );
}

#[derive(clove1db::CloveFields)]
struct Floating {
    value: f64,
}
#[test]
fn nonfinite_comparison_is_an_explicit_error() {
    assert!(Floating::value.eq(f64::NAN).fingerprint().is_err());
    assert!(Floating::value.eq(f64::NEG_INFINITY).fingerprint().is_err());
}
