use clove1db::{
    CloveFields,
    entity::Entity,
    query::{Asc, Desc, LastWrite},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    score: i64,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<String>,
    labels: Vec<String>,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
    fn id_field() -> Option<clove1db::fields::Field<Self, String>> {
        Some(Self::id)
    }
}
fn setup() -> Storage {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(std::env::temp_dir().join(uuid::Uuid::new_v4().to_string()))
                .has_cache(false)
                .register::<Note>("notes"),
        )
        .build()
        .unwrap()
}
fn insert(s: &Storage, n: usize) {
    let rows = (0..n)
        .map(|i| {
            (
                "notes".into(),
                format!("{i:06}"),
                serde_json::to_vec(&Note {
                    id: format!("{i:06}"),
                    score: (i % 7) as i64,
                    title: format!("  Alpha {i} عربي  "),
                    optional: if i % 2 == 0 { Some("x".into()) } else { None },
                    labels: vec!["a".into(), "b".into()],
                })
                .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    s.db_manager("store").commit_batch(&rows, &[]).unwrap();
}
#[test]
fn scan_order_cursor_aggregates() {
    let s = setup();
    insert(&s, 30);
    let d = s.domain::<Note>();
    let q = d
        .query()
        .filter(Note::score.ge(2))
        .order_by(Note::score, Desc)
        .then_by(Note::id, Asc)
        .limit(4);
    let p = q.page().unwrap();
    assert_eq!(p.items.len(), 4);
    assert!(p.items.iter().all(|n| n.score == 6));
    let second = q.clone().after(p.next.unwrap()).collect().unwrap();
    assert!(second.iter().all(|n| n.score < 6));
    assert_eq!(d.query().count().unwrap(), 30);
    assert_eq!(
        d.query().sum(Note::score).unwrap(),
        clove1db::query::Sum::Integer(85)
    );
    assert_eq!(d.query().distinct(Note::score).unwrap().len(), 7);
    assert_eq!(
        d.query()
            .group_by(Note::score)
            .count()
            .unwrap()
            .iter()
            .map(|g| g.count)
            .sum::<u64>(),
        30
    );
    assert!(d.query().exists().unwrap());
    assert!(matches!(
        d.query().one(),
        Err(ClError::NonUnique { count: 30 })
    ));
    assert!(
        d.query()
            .filter(Note::id.eq("missing"))
            .one()
            .unwrap()
            .is_none()
    );
    assert_eq!(
        d.query()
            .filter(Note::id.eq("000001"))
            .one()
            .unwrap()
            .unwrap()
            .score,
        1
    );
    assert!(
        d.query()
            .filter(Note::title.text("ALPHA عربي"))
            .count()
            .unwrap()
            == 30
    );
    assert_eq!(
        d.query()
            .filter(Note::optional.is_missing())
            .count()
            .unwrap(),
        15
    );
    assert_eq!(
        d.query()
            .filter(Note::labels.all().eq("a"))
            .count()
            .unwrap(),
        0
    );
    assert_eq!(
        d.query()
            .filter(Note::labels.any().eq("a"))
            .count()
            .unwrap(),
        30
    );
    s.close();
}
#[test]
fn snapshot_and_lastwrite() {
    let s = setup();
    insert(&s, 12);
    let db = s.db_manager("store");
    let view = db.read_view_at_head().unwrap();
    let mut n = s
        .domain::<Note>()
        .query()
        .filter(Note::id.eq("000001"))
        .one()
        .unwrap()
        .unwrap();
    n.score = 100;
    db.set(
        redb::TableDefinition::new("notes"),
        "notes",
        &n.id,
        serde_json::to_vec(&n).unwrap(),
    )
    .unwrap();
    let q = s
        .domain::<Note>()
        .query()
        .order_by(LastWrite, Desc)
        .limit(1);
    assert_eq!(q.collect().unwrap()[0].id, "000001");
    assert_eq!(q.collect_in(&view).unwrap()[0].id, "000011");
    drop(view);
    s.close();
}
#[test]
fn cursor_rejects_different_expression() {
    let s = setup();
    insert(&s, 5);
    let c = s
        .domain::<Note>()
        .query()
        .limit(1)
        .page()
        .unwrap()
        .next
        .unwrap();
    assert!(matches!(
        s.domain::<Note>()
            .query()
            .filter(Note::score.gt(0))
            .after(c)
            .collect(),
        Err(ClError::InvalidCursor)
    ));
    s.close();
}
