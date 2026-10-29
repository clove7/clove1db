use clove1db::{
    CloveFields,
    entity::Entity,
    fields::Field,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    title: String,
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
fn bytes(id: &str) -> Vec<u8> {
    serde_json::to_vec(&Note {
        id: id.into(),
        title: "plain".into(),
    })
    .unwrap()
}
#[test]
fn mismatched_batch_is_atomic() {
    let s = setup();
    let db = s.db_manager("store");
    let head = db.read_view_at_head().unwrap().head;
    let r = db.commit_batch(
        &[
            ("notes".into(), "valid".into(), bytes("valid")),
            ("notes".into(), "wrong".into(), bytes("other")),
        ],
        &[],
    );
    assert!(r.is_err(), "mismatched serialized id must be rejected");
    let v = db.read_view_at_head().unwrap();
    assert_eq!(v.head, head);
    assert!(v.get_raw("notes", "valid").unwrap().is_none());
}
#[test]
fn reset_and_rewrite_reject_mismatches() {
    let s = setup();
    let db = s.db_manager("store");
    db.commit_batch(&[("notes".into(), "keep".into(), bytes("keep"))], &[])
        .unwrap();
    let head = db.read_view_at_head().unwrap().head;
    assert!(
        db.replace_table("notes", &[("wrong".into(), bytes("other"))])
            .is_err()
    );
    assert!(
        db.rewrite_tables(
            &[("notes".into(), "wrong".into(), bytes("other"))],
            &[("notes".into(), "keep".into())]
        )
        .is_err()
    );
    let v = db.read_view_at_head().unwrap();
    assert_eq!(v.head, head);
    assert!(v.get_raw("notes", "keep").unwrap().is_some());
}
#[test]
fn missing_null_and_nonstring_ids_are_rejected() {
    let s = setup();
    let db = s.db_manager("store");
    for value in [br#"{}"#.as_slice(), br#"{"id":null}"#, br#"{"id":1}"#] {
        assert!(
            db.commit_batch(&[("notes".into(), "key".into(), value.to_vec())], &[])
                .is_err()
        );
    }
    db.commit_batch(&[("notes".into(), "key".into(), bytes("key"))], &[])
        .unwrap();
    assert_eq!(
        s.domain::<Note>()
            .query()
            .filter(Note::id.eq("key"))
            .count()
            .unwrap(),
        1
    );
}

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Loose {
    id: String,
    title: String,
}
impl Entity for Loose {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
#[test]
fn undeclared_table_cannot_use_unenforced_point_lookup() {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root.clone())
                .has_cache(false)
                .register::<Loose>("notes"),
        )
        .build()
        .unwrap();
    let db = s.db_manager("store");
    db.commit_batch(
        &[("notes".into(), "physical".into(), bytes("logical"))],
        &[],
    )
    .unwrap();
    let q = db
        .query::<Note>("notes")
        .unwrap()
        .filter(Note::id.eq("logical"));
    assert_eq!(q.count().unwrap(), 1);
    s.close();
    drop(s);
    let reopened = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root)
                .has_cache(false)
                .register::<Note>("notes"),
        )
        .build();
    assert!(matches!(
        reopened,
        Err(clove1db::units::ClError::IdFieldMismatch)
    ));
}

#[test]
fn storage_creates_adjacent_index_file() {
 let s=setup();let db=s.db_manager("store");assert!(db.dir.dir.join("store.inx").is_file());s.close();
}
