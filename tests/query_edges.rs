use clove1db::{
    CloveFields,
    entity::Entity,
    fields::{Expr, Value},
    query::{Desc, LastWrite},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Row {
    id: String,
    n: serde_json::Value,
    #[clove(epoch = "s")]
    stamp: i64,
}
impl Entity for Row {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
fn root() -> std::path::PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}
/// Under `--cfg clove_test_encrypt_all` every database starts encrypted; a test that needs a plain file says so
/// (each use is listed in 7-5-plain-only.md).
#[allow(dead_code)]
fn plain(db: DatabaseConfig) -> DatabaseConfig {
    #[cfg(clove_test_encrypt_all)]
    {
        db.plain()
    }
    #[cfg(not(clove_test_encrypt_all))]
    {
        db
    }
}

fn open_plain(root: &std::path::Path) -> Storage {
    Storage::builder(StorageConfig::default())
        .add_database(
            plain(DatabaseConfig::new("records", "store"))
                .dir_path(root.into())
                .has_cache(false)
                .register::<Row>("rows"),
        )
        .build()
        .unwrap()
}
fn open(root: &std::path::Path) -> Storage {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root.into())
                .has_cache(false)
                .register::<Row>("rows"),
        )
        .build()
        .unwrap()
}
#[test]
fn exact_sum_type_presence_time_and_invalid() {
    let r = root();
    let s = open(&r);
    let db = s.db_manager("store");
    let rows = [
        ("a", r#"{"id":"a","n":18446744073709551615,"stamp":1}"#),
        ("b", r#"{"id":"b","n":18446744073709551614,"stamp":2}"#),
    ]
    .into_iter()
    .map(|(k, v)| ("rows".into(), k.into(), v.as_bytes().to_vec()))
    .collect::<Vec<_>>();
    db.commit_batch_atomic(&rows, &[]).unwrap();
    let q = s.domain::<Row>().query();
    assert_eq!(
        q.sum(Row::n).unwrap(),
        clove1db::query::Sum::Integer(36893488147419103229)
    );
    assert_eq!(q.filter(Row::stamp.ge(2i64)).count().unwrap(), 1);
    db.set(
        redb::TableDefinition::new("rows"),
        "rows",
        "c",
        br#"{"id":"c","n":0.1,"stamp":3}"#.to_vec(),
    )
    .unwrap();
    assert_eq!(
        s.domain::<Row>().query().sum(Row::n).unwrap(),
        clove1db::query::Sum::Decimal("368934881474191032291e-1".into())
    );
    assert_eq!(
        s.domain::<Row>()
            .query()
            .filter(Row::n.key("absent").is_missing())
            .count()
            .unwrap(),
        3
    );
    let mut p = Row::id.eq("x");
    p.expression = Expr::Invalid("invalid".into());
    assert!(s.domain::<Row>().query().filter(p).count().is_err());
    let mut p = Row::id.eq("x");
    p.expression = Expr::Compare {
        path: Row::n.path(),
        op: clove1db::fields::Compare::Eq,
        values: vec![Value::String("18446744073709551615".into())],
    };
    assert_eq!(s.domain::<Row>().query().filter(p).count().unwrap(), 0);
    s.close();
}
#[test]
fn legacy_zero_lastwrite_reset_delete_and_atomic_failure() {
    let r = root();
    let s = open_plain(&r);
    let db = s.db_manager("store");
    let row = |id: &str| {
        serde_json::to_vec(&Row {
            id: id.into(),
            n: serde_json::json!(1),
            stamp: 0,
        })
        .unwrap()
    };
    db.commit_batch_atomic(
        &[
            ("rows".into(), "b".into(), row("b")),
            ("rows".into(), "a".into(), row("a")),
        ],
        &[],
    )
    .unwrap();
    s.close();
    drop(s);
    let db = redb::Database::open(r.join("records/store.cldb")).unwrap();
    let tx = db.begin_write().unwrap();
    tx.delete_table(redb::TableDefinition::<&[u8], u64>::new("__lastwrite"))
        .unwrap();
    tx.commit().unwrap();
    drop(db);
    let s = open_plain(&r);
    let db = s.db_manager("store");
    let q = s.domain::<Row>().query().order_by(LastWrite, Desc);
    assert_eq!(
        q.collect()
            .unwrap()
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    db.set(redb::TableDefinition::new("rows"), "rows", "b", row("b"))
        .unwrap();
    assert_eq!(q.collect().unwrap()[0].id, "b");
    db.replace_table("rows", &[("d".into(), row("d")), ("c".into(), row("c"))])
        .unwrap();
    assert_eq!(
        q.collect()
            .unwrap()
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        vec!["c", "d"]
    );
    s.domain::<Row>().delete("c").unwrap();
    assert_eq!(q.collect().unwrap()[0].id, "d");
    s.close();
}

#[test]
fn sum_extremes_and_overflow() {
    let r = root();
    let s = open(&r);
    let db = s.db_manager("store");
    let q = s.domain::<Row>().query();
    db.set(
        redb::TableDefinition::new("rows"),
        "rows",
        "a",
        br#"{"id":"a","n":-170141183460469231731687303715884105728,"stamp":0}"#.to_vec(),
    )
    .unwrap();
    assert_eq!(
        q.sum(Row::n).unwrap(),
        clove1db::query::Sum::Integer(i128::MIN)
    );
    db.set(
        redb::TableDefinition::new("rows"),
        "rows",
        "a",
        br#"{"id":"a","n":170141183460469231731687303715884105727,"stamp":0}"#.to_vec(),
    )
    .unwrap();
    db.set(
        redb::TableDefinition::new("rows"),
        "rows",
        "b",
        br#"{"id":"b","n":1,"stamp":0}"#.to_vec(),
    )
    .unwrap();
    assert!(matches!(q.sum(Row::n), Err(ClError::SumOverflow)));
    s.close();
}

#[test]
fn decimal_sum_uses_exact_tokens() {
    let r = root();
    let s = open(&r);
    let db = s.db_manager("store");
    db.commit_batch_atomic(
        &[
            (
                "rows".into(),
                "a".into(),
                br#"{"id":"a","n":0.1,"stamp":0}"#.to_vec(),
            ),
            (
                "rows".into(),
                "b".into(),
                br#"{"id":"b","n":0.2,"stamp":0}"#.to_vec(),
            ),
        ],
        &[],
    )
    .unwrap();
    assert_eq!(
        s.domain::<Row>().query().sum(Row::n).unwrap().to_string(),
        "3e-1"
    );
    s.close();
}
