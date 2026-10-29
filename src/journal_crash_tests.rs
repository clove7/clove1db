//! Process exits exercise real transaction recovery, not mocked failures.
use super::*;
use crate::{ChangeKind, ConsumerToken};
fn open(path: &std::path::Path) -> Storage {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(path.to_path_buf())
                .has_cache(false)
                .blob_enabled(true)
                .register::<Note>("notes")
                .register_blob::<BlobNote>("files"),
        )
        .build()
        .unwrap()
}
#[derive(Default, Clone, Serialize, Deserialize)]
struct BlobNote {
    id: String,
}
impl Entity for BlobNote {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
#[test]
#[ignore]
fn crash_child() {
    let path = std::path::PathBuf::from(std::env::var("JOURNAL_TEST_DIR").unwrap());
    let action = std::env::var("JOURNAL_TEST_ACTION").unwrap();
    let s = open(&path);
    let db = s.db_manager("store");
    match action.as_str() {
        "set" => db
            .commit_batch_atomic(&[("notes".into(), "a".into(), b"new".to_vec())], &[])
            .unwrap(),
        "delete" => db.delete_raw("notes", "a").unwrap(),
        "large_batch" => db
            .commit_batch_atomic(
                &(0..crate::DEFAULT_MAX_COMMIT_BATCH_ENTRIES)
                    .map(|i| ("notes".into(), format!("b{i}"), b"new".to_vec()))
                    .collect::<Vec<_>>(),
                &[],
            )
            .unwrap(),
        "batch" => db
            .commit_batch_atomic(
                &[
                    ("notes".into(), "b".into(), b"new".to_vec()),
                    ("notes".into(), "c".into(), b"new".to_vec()),
                ],
                &[],
            )
            .unwrap(),
        "blob" => s
            .domain::<BlobNote>()
            .set_with_blob("blob", &BlobNote { id: "blob".into() }, b"new")
            .unwrap(),
        "reset" => db
            .replace_table("notes", &[("b".into(), b"new".to_vec())])
            .unwrap(),
        "prune" => {
            let token: ConsumerToken =
                serde_json::from_slice(&std::fs::read(path.join("token.json")).unwrap()).unwrap();
            db.ack(&token, db.journal_head().unwrap()).unwrap();
        }
        _ => panic!("unknown test action"),
    }
}
#[test]
fn process_crashes_keep_data_and_journal_atomic() {
    use std::io::Read;
    for (action, point, committed) in [
        ("set", "journal_before_commit", false),
        ("set", "journal_after_commit", true),
        ("delete", "journal_before_commit", false),
        ("delete", "journal_after_commit", true),
        ("large_batch", "journal_during_append", false),
        ("large_batch", "journal_after_commit", true),
        ("batch", "journal_before_commit", false),
        ("batch", "journal_after_commit", true),
        ("blob", "journal_blob_before_descriptor", false),
        ("blob", "journal_after_commit", true),
        ("reset", "journal_during_reset", false),
        ("reset", "journal_after_commit", true),
        ("prune", "journal_during_prune", false),
        ("prune", "journal_prune_after_commit", true),
    ] {
        let path = std::env::temp_dir().join(format!("clove-crash-{}", uuid::Uuid::new_v4()));
        let s = open(&path);
        let db = s.db_manager("store");
        let token = db.register_consumer("reader").unwrap();
        db.commit_batch_atomic(&[("notes".into(), "a".into(), b"old".to_vec())], &[])
            .unwrap();
        if action == "blob" {
            s.domain::<BlobNote>()
                .set_with_blob("blob", &BlobNote { id: "blob".into() }, b"old")
                .unwrap();
        }
        let before = db.journal_head().unwrap();
        std::fs::write(path.join("token.json"), serde_json::to_vec(&token).unwrap()).unwrap();
        s.close();
        drop(s);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "journal_tests::crashes::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("JOURNAL_TEST_DIR", &path)
            .env("JOURNAL_TEST_ACTION", action)
            .env("CLOVE_CRASH_POINT", point)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(99),
            "{action} {point}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let s = open(&path);
        let db = s.db_manager("store");
        let expected = if committed {
            match action {
                "batch" | "blob" => 2,
                "large_batch" => crate::DEFAULT_MAX_COMMIT_BATCH_ENTRIES as u64,
                "prune" => 0,
                _ => 1,
            }
        } else {
            0
        };
        assert_eq!(db.journal_head().unwrap(), before + expected);
        if action == "prune" && committed {
            assert_eq!(db.journal_stats().unwrap().journal_bytes, 0);
        } else {
            let changes = db.read_changes(&token, 0, 1000).unwrap();
            assert_eq!(changes.len() as u64, db.journal_head().unwrap());
            for (i, c) in changes.iter().enumerate() {
                assert_eq!(c.seq, i as u64 + 1);
            }
            let calculated = changes
                .iter()
                .map(|c| 8 + c.kind.encode().unwrap().len() as u64)
                .sum::<u64>();
            assert_eq!(db.journal_stats().unwrap().journal_bytes, calculated);
        }
        match action {
            "set" => assert_eq!(
                db.get_raw("notes", "a").unwrap().unwrap(),
                if committed { b"new" } else { b"old" }
            ),
            "delete" => assert_eq!(db.get_raw("notes", "a").unwrap().is_none(), committed),
            "large_batch" => {
                assert_eq!(
                    db.count_keys("notes").unwrap(),
                    if committed {
                        crate::DEFAULT_MAX_COMMIT_BATCH_ENTRIES + 1
                    } else {
                        1
                    }
                );
            }
            "batch" => {
                assert_eq!(db.get_raw("notes", "b").unwrap().is_some(), committed);
                assert_eq!(db.get_raw("notes", "c").unwrap().is_some(), committed);
            }
            "blob" => {
                let mut bytes = Vec::new();
                db.open_blob("files", "blob")
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(bytes, if committed { b"new" } else { b"old" });
            }
            "reset" => {
                assert_eq!(db.get_raw("notes", "a").unwrap().is_none(), committed);
                if committed {
                    let changes = db.read_changes(&token, 0, 1000).unwrap();
                    let reset = changes
                        .iter()
                        .find(|c| matches!(c.kind, ChangeKind::TableReset { .. }))
                        .unwrap();
                    assert_eq!(
                        db.read_reset(&token, reset.seq).unwrap(),
                        vec![("b".into(), b"new".to_vec())]
                    );
                }
            }
            _ => (),
        }
        s.close();
    }
}
