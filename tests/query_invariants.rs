use clove1db::{
    CloveFields, LibraryEvent, Unique,
    entity::Entity,
    query::{Asc, Desc, LastWrite},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Barrier, Mutex};
#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    name: Option<String>,
    n: i64,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
fn config(root: &std::path::Path) -> DatabaseConfig {
    DatabaseConfig::new("records", "store")
        .dir_path(root.into())
        .has_cache(false)
        .redb_cache_bytes(2 * 1024 * 1024)
        .register::<Note>("notes")
}
fn put(s: &Storage, id: &str, name: Option<&str>) -> clove1db::units::Result<()> {
    s.db_manager("store").set(
        redb::TableDefinition::new("notes"),
        "notes",
        id,
        serde_json::to_vec(&Note {
            id: id.into(),
            name: name.map(str::to_owned),
            n: 1,
        })?,
    )
}
#[test]
fn concurrent_unique_update_delete_and_no_partial_batch() {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(config(&root).unique::<Note>(Unique::on(Note::name.trim().lowercase())))
        .build()
        .unwrap();
    let gate = Arc::new(Barrier::new(9));
    let mut threads = vec![];
    for i in 0..8 {
        let s = s.clone();
        let gate = gate.clone();
        threads.push(std::thread::spawn(move || {
            gate.wait();
            put(&s, &i.to_string(), Some(" VALUE "))
        }));
    }
    gate.wait();
    let results = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(ClError::UniqueViolation)))
            .count(),
        7
    );
    let n = s.domain::<Note>().query().one().unwrap().unwrap();
    put(&s, &n.id, Some("other")).unwrap();
    put(&s, "new", Some("value")).unwrap();
    s.domain::<Note>().delete("new").unwrap();
    put(&s, "again", Some("value")).unwrap();
    put(&s, "null-a", None).unwrap();
    put(&s, "null-b", None).unwrap();
    let head = s.db_manager("store").journal_head().unwrap();
    let rows = vec![
        (
            "notes".into(),
            "batch-a".into(),
            serde_json::to_vec(&Note {
                id: "batch-a".into(),
                name: Some("other".into()),
                n: 1,
            })
            .unwrap(),
        ),
        (
            "notes".into(),
            "batch-b".into(),
            serde_json::to_vec(&Note {
                id: "batch-b".into(),
                name: Some("unused".into()),
                n: 1,
            })
            .unwrap(),
        ),
    ];
    assert!(matches!(
        s.db_manager("store").commit_batch_atomic(&rows, &[]),
        Err(ClError::UniqueViolation)
    ));
    assert_eq!(s.db_manager("store").journal_head().unwrap(), head);
    assert!(
        !s.domain::<Note>()
            .query()
            .filter(Note::id.eq("batch-b"))
            .exists()
            .unwrap()
    );
    s.close();
}
#[test]
fn existing_duplicates_and_expression_rebuild() {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(config(&root))
        .build()
        .unwrap();
    put(&s, "a", Some("X")).unwrap();
    put(&s, "b", Some("x")).unwrap();
    s.close();
    let result = Storage::builder(StorageConfig::default())
        .add_database(config(&root).unique::<Note>(Unique::on(Note::name.lowercase())))
        .build();
    assert!(matches!(
        result,
        Err(ClError::DuplicateGroups { groups: 1 })
    ));
    let s = Storage::builder(StorageConfig::default())
        .add_database(config(&root).unique::<Note>(Unique::on(Note::name)))
        .build()
        .unwrap();
    s.domain::<Note>().delete("b").unwrap();
    s.close();
    let s = Storage::builder(StorageConfig::default())
        .add_database(config(&root).unique::<Note>(Unique::on(Note::name.lowercase())))
        .build()
        .unwrap();
    assert!(matches!(
        put(&s, "c", Some("x")),
        Err(ClError::UniqueViolation)
    ));
    s.close();
}
#[test]
fn events_cache_stats_and_privacy() {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let events = Arc::new(Mutex::new(vec![]));
    let capture = events.clone();
    let s = Storage::builder(
        StorageConfig::default()
            .slow_query_threshold(std::time::Duration::ZERO)
            .event_sink(move |e| capture.lock().unwrap().push(e.clone())),
    )
    .add_database(config(&root).journal_retention(clove1db::Retention::Limit { max_bytes: 1 }))
    .build()
    .unwrap();
    let db = s.db_manager("store");
    let token = db.register_consumer("replica").unwrap();
    put(&s, "a", Some("private-parameter")).unwrap();
    put(&s, "b", Some("private-parameter")).unwrap();
    assert!(matches!(
        s.domain::<Note>().query().one(),
        Err(ClError::NonUnique { count: 2 })
    ));
    let q = s
        .domain::<Note>()
        .query()
        .filter(Note::name.eq("private-parameter"));
    let a = q.explain().unwrap();
    let b = q.explain().unwrap();
    assert!(!a.cache_hit);
    assert!(b.cache_hit);
    assert!(!format!("{b:?}").contains("private-parameter"));
    for i in 0..10 {
        put(&s, &format!("n{i}"), Some("other")).unwrap();
    }
    let c = q.explain().unwrap();
    assert!(!c.cache_hit);
    assert!(c.statistics_generation > a.statistics_generation);
    let stats = q.statistics(Note::name).unwrap();
    assert_eq!(stats.rows, 12);
    assert!(stats.sample_bytes <= clove1db::query::stats::SAMPLE_BYTES);
    assert!(stats.mcv_frequencies.len() <= 32);
    assert!(stats.histogram_bounds <= 64);
    assert!(matches!(
        db.read_changes(&token, 0, 1),
        Err(ClError::ConsumerExpired)
    ));
    let events = events.lock().unwrap();
    assert!(events.iter().any(
        |e| matches!(e,LibraryEvent::ConsumerExpired{name,last_acked_seq:0}if name=="replica")
    ));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, LibraryEvent::NonUnique { count: 2, .. }))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, LibraryEvent::SlowQuery { .. }))
    );
    assert!(!format!("{events:?}").contains("private-parameter"));
    s.close();
}
#[test]
fn concurrent_results_belong_to_one_snapshot() {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(config(&root))
        .build()
        .unwrap();
    let write = s.clone();
    let thread = std::thread::spawn(move || {
        for epoch in 0..100 {
            let rows = (0..20)
                .map(|i| {
                    (
                        "notes".into(),
                        i.to_string(),
                        serde_json::to_vec(&Note {
                            id: i.to_string(),
                            name: None,
                            n: epoch,
                        })
                        .unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            write
                .db_manager("store")
                .commit_batch_atomic(&rows, &[])
                .unwrap();
        }
    });
    for _ in 0..100 {
        let view = s.db_manager("store").read_view_at_head().unwrap();
        let rows = s
            .domain::<Note>()
            .query()
            .order_by(LastWrite, Desc)
            .then_by(Note::id, Asc)
            .collect_in(&view)
            .unwrap();
        assert!(rows.iter().all(|r| r.n == rows[0].n));
        if !rows.is_empty() {
            assert_eq!(rows.len(), 20);
        }
    }
    thread.join().unwrap();
    s.close();
}

#[test]
fn composite_missing_and_reset_constraint() {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(config(&root).unique::<Note>(Unique::on(Note::name.lowercase()).and(Note::n)))
        .build()
        .unwrap();
    let db = s.db_manager("store");
    put(&s, "a", Some("one")).unwrap();
    db.set(
        redb::TableDefinition::new("notes"),
        "notes",
        "b",
        br#"{"id":"b","name":"ONE","n":2}"#.to_vec(),
    )
    .unwrap();
    for id in ["c", "d"] {
        db.set(
            redb::TableDefinition::new("notes"),
            "notes",
            id,
            format!(r#"{{"id":"{id}","n":1}}"#).into_bytes(),
        )
        .unwrap();
    }
    put(&s, "e", None).unwrap();
    put(&s, "f", None).unwrap();
    let head = db.journal_head().unwrap();
    let reset = vec![
        ("x".into(), br#"{"id":"x","name":"dup","n":1}"#.to_vec()),
        ("y".into(), br#"{"id":"y","name":"DUP","n":1}"#.to_vec()),
    ];
    assert!(matches!(
        db.replace_table("notes", &reset),
        Err(ClError::UniqueViolation)
    ));
    assert_eq!(db.journal_head().unwrap(), head);
    assert_eq!(s.domain::<Note>().query().count().unwrap(), 6);
    s.close();
}
