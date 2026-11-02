//! An entity whose field descriptors are written by hand, without `#[derive(CloveFields)]`:
//! it is filtered, ordered and counted like a derived one.
use clove1db::{
    entity::Entity,
    fields::{CloveFields, Field, Step, ValueKind},
    query::{Asc, Desc},
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct Note {
    id: String,
    score: i64,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<String>,
    labels: Vec<String>,
    #[serde(rename = "madeAt")]
    made_at: i64,
}

// The by-hand form of `#[derive(CloveFields)]`: the marker, and one constant per stored field.
// The name is the one the field has in the stored JSON (here `madeAt`, as serde renames it).
// A field of type `Option<T>` is a `Field<Self, T>`.
impl CloveFields for Note {}
#[allow(non_upper_case_globals)]
impl Note {
    pub const id: Field<Self, String> = Field::new("id", ValueKind::Auto);
    pub const score: Field<Self, i64> = Field::new("score", ValueKind::Auto);
    pub const title: Field<Self, String> = Field::new("title", ValueKind::Auto);
    pub const optional: Field<Self, String> = Field::new("optional", ValueKind::Auto);
    pub const labels: Field<Self, Vec<String>> = Field::new("labels", ValueKind::Auto);
    pub const made_at: Field<Self, i64> = Field::new("madeAt", ValueKind::EpochSeconds);
}

impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
    fn id_field() -> Option<Field<Self, String>> {
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

fn note(i: usize) -> Note {
    Note {
        id: format!("{i:04}"),
        score: (i % 7) as i64,
        title: format!("title {i}"),
        optional: if i % 2 == 0 { Some("x".into()) } else { None },
        labels: vec!["a".into(), if i % 3 == 0 { "b".into() } else { "c".into() }],
        made_at: 1_700_000_000 + i as i64,
    }
}

#[test]
fn a_hand_written_entity_is_found_ordered_and_counted() {
    let s = setup();
    let d = s.domain::<Note>();
    for i in 0..30 {
        d.repo().set(&format!("{i:04}"), &note(i)).unwrap();
    }
    let top = d.query().filter(Note::score.ge(5)).order_by(Note::score, Desc).then_by(Note::id, Asc).limit(4).collect().unwrap();
    assert_eq!(top.len(), 4);
    assert!(top.iter().all(|n| n.score >= 5));
    assert!(top.windows(2).all(|w| w[0].score >= w[1].score));
    // Equality on a text field, a field of an optional value, and a count.
    assert_eq!(d.query().filter(Note::title.eq("title 7".to_string())).collect().unwrap().len(), 1);
    assert_eq!(d.query().filter(Note::optional.eq("x".to_string())).count().unwrap(), 15);
    assert_eq!(d.query().filter(Note::score.eq(3)).count().unwrap(), 4);
    // The field named in serde's rename is found by its stored name.
    assert_eq!(d.query().filter(Note::made_at.ge(1_700_000_020)).count().unwrap(), 10);
}

#[test]
fn the_constants_walk_the_same_path_as_the_stored_json() {
    assert_eq!(Note::score.steps(), vec![Step::Key("score".into())]);
    assert_eq!(Note::made_at.json_path(), vec!["madeAt".to_string()]);
    let stored = serde_json::to_value(note(1)).unwrap();
    for path in [Note::id.json_path(), Note::score.json_path(), Note::made_at.json_path(), Note::labels.json_path()] {
        assert!(stored.get(&path[0]).is_some(), "{path:?} is not a key of the stored row");
    }
}
