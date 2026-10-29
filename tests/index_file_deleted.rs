//! The index file is only a copy of what the records say. If it is deleted while the database is closed, a query
//! made right after the database is opened again must still return the rows the records hold, whether the index
//! was rebuilt already or the planner answers by scanning.
use clove1db::{
    CloveFields,
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    kind: String,
    text: String,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn open(dir: &Path) -> Storage {
    let db = DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    Storage::builder(StorageConfig::default()).add_database(db.register::<Note>("notes")).build().unwrap()
}

fn inx_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                todo.push(p);
            } else if p.extension().is_some_and(|x| x == "inx") {
                found.push(p);
            }
        }
    }
    found
}

#[test]
fn a_query_after_the_index_file_was_deleted_returns_what_the_records_hold() {
    let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let rows: Vec<Note> = (0..600).map(|i| Note { id: format!("n{i:04}"), kind: format!("k{}", i % 7), text: format!("alpha beta w{}", i % 13) }).collect();
    let by_kind = rows.iter().filter(|n| n.kind == "k3").count();
    let by_word = rows.iter().filter(|n| n.text.contains("w5")).count();
    assert!(by_kind > 0 && by_word > 0);
    {
        let s = open(&dir);
        let d = s.domain::<Note>();
        let writes: Vec<(&str, &Note)> = rows.iter().map(|n| (n.id.as_str(), n)).collect();
        d.repo().commit_entities(&writes, &[]).unwrap();
        // Repeated queries make the optimizer ask for the indexes; wait until the file exists and answers.
        let start = std::time::Instant::now();
        while inx_files(&dir).is_empty() || d.query().filter(Note::kind.eq("k3".to_string())).count().unwrap() as usize != by_kind {
            let _ = d.query().filter(Note::text.contains("w5".to_string())).count();
            assert!(start.elapsed().as_secs() < 60, "the index file never appeared");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        s.close();
    }
    let files = inx_files(&dir);
    assert!(!files.is_empty());
    for f in &files {
        std::fs::remove_file(f).unwrap();
    }
    let s = open(&dir);
    let d = s.domain::<Note>();
    // Straight after the open: no waiting for the index. Equality and contains must both give the right answers, repeatedly.
    for _ in 0..20 {
        assert_eq!(d.query().filter(Note::kind.eq("k3".to_string())).count().unwrap() as usize, by_kind);
        assert_eq!(d.query().filter(Note::text.contains("w5".to_string())).count().unwrap() as usize, by_word);
        assert_eq!(d.query().filter(Note::kind.eq("k3".to_string())).collect().unwrap().len(), by_kind);
    }
    s.close();
    std::fs::remove_dir_all(&dir).ok();
}
