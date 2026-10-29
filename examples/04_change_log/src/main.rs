//! # 04 — The change log
//!
//! Every committed write gets the next number in a durable sequence, and is kept in a change log
//! for the programs that follow the database: a replica, a search service, an export.
//!
//! A follower does four things:
//!
//! 1. `register_consumer(name)` — the log now keeps what this follower has not acknowledged;
//! 2. `read_view_at_head()` — a snapshot to copy everything that exists, with its sequence (`head`);
//! 3. `read_changes(&token, after, limit)` — what changed after a sequence, in order;
//! 4. `ack(&token, seq)` — "I have stored everything up to here"; the log may drop it.
//!
//! The follower's position is in the database, so it survives a restart. `replace_table` is one
//! change of its own (a reset) that the follower reads whole. A follower that falls too far behind
//! the retention budget is expired (`ConsumerExpired`) and must start again from a snapshot.
//!
//! Run it with `cargo run` from this folder.

use clove1db::{
    LibraryEvent, Retention,
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Note {
    id: String,
    text: String,
}

impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn check(ok: bool, what: &str) -> Result<()> {
    if ok {
        println!("  ok  {what}");
        Ok(())
    } else {
        Err(ClError::Validation(format!("check failed: {what}")))
    }
}

fn open(root: &Path, retention: Retention) -> Result<Storage> {
    let config = StorageConfig::default().event_sink(|event| {
        if let LibraryEvent::ConsumerExpired { last_acked_seq, .. } = event {
            println!("  event: a consumer expired, last acknowledged {last_acked_seq}");
        }
    });
    Storage::builder(config)
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root.to_path_buf())
                .journal_retention(retention)
                .register::<Note>("notes"),
        )
        .build()
}

fn note(id: &str, text: &str) -> Note {
    Note { id: id.into(), text: text.into() }
}

fn main() -> Result<()> {
    let root = std::env::temp_dir().join(format!("clove1db-example-04-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    println!("04 change log — data in {}", root.display());

    // The follower's copy. A real one would be another database or service.
    let mut replica: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    let storage = open(&root, Retention::Unlimited)?;
    let db = storage.db_manager("store");
    let notes = storage.domain::<Note>();
    notes.repo().set("a", &note("a", "written before the follower"))?;

    println!("\n1. register, then copy a snapshot");
    let token = db.register_consumer("replica")?;
    let view = db.read_view_at_head()?;
    for (key, bytes) in view.table_entries("notes")? {
        replica.insert(key, bytes);
    }
    let snapshot_head = view.head;
    drop(view); // a view holds a snapshot open: drop it when the copy is done
    db.ack(&token, snapshot_head)?;
    check(replica.len() == 1 && snapshot_head == 1, "the snapshot holds the one row, at sequence 1")?;

    println!("\n2. follow the changes");
    notes.repo().set("b", &note("b", "second"))?;
    notes.repo().set("a", &note("a", "first, changed"))?;
    notes.repo().delete("b")?;
    let changes = db.read_changes(&token, snapshot_head, 100)?;
    for change in &changes {
        println!("  seq {}", change.seq);
    }
    check(changes.len() == 3, "three changes after the snapshot")?;
    check(changes.windows(2).all(|w| w[1].seq == w[0].seq + 1), "in order, with no gap")?;
    // Copying a change is done by reading the row as it is now; a missing row was deleted.
    let now = db.read_view_at_head()?;
    replica = now.table_entries("notes")?.into_iter().collect();
    let last = now.head;
    drop(now);
    db.ack(&token, last)?;
    check(replica.len() == 1, "the replica has row a only, as the database does")?;

    println!("\n3. the position survives a restart");
    storage.close();
    drop(storage);
    let storage = open(&root, Retention::Unlimited)?;
    let db = storage.db_manager("store");
    storage.domain::<Note>().repo().set("c", &note("c", "written after the restart"))?;
    let resumed = db.read_changes(&token, last, 100)?;
    check(resumed.len() == 1 && resumed[0].seq == last + 1, "the old token resumes at the next sequence")?;
    db.ack(&token, resumed[0].seq)?;

    println!("\n4. replace a whole table: one reset change");
    db.replace_table(
        "notes",
        &[
            ("x".into(), br#"{"id":"x","text":"replacement one"}"#.to_vec()),
            ("y".into(), br#"{"id":"y","text":"replacement two"}"#.to_vec()),
        ],
    )?;
    let reset_seq = db.journal_head()?;
    let reset_rows = db.read_reset(&token, reset_seq)?;
    check(reset_rows.len() == 2, "the reset gives the follower the two new rows at once")?;
    db.ack(&token, reset_seq)?;
    check(db.journal_stats()?.journal_bytes == 0, "everything is acknowledged, so the log is empty")?;

    println!("\n5. registering again replaces the old follower");
    let fresh = db.register_consumer("replica")?;
    check(matches!(db.ack(&token, reset_seq), Err(ClError::ConsumerExpired)), "the old token is refused")?;
    db.ack(&fresh, reset_seq)?;
    storage.close();
    drop(storage);

    println!("\n6. a follower that falls behind a 64-byte budget is expired");
    let limited = open(&root.join("limited"), Retention::Limit { max_bytes: 64 })?;
    let db = limited.db_manager("store");
    let slow = db.register_consumer("slow")?;
    db.commit_batch_atomic(&[("notes".into(), "big".into(), vec![b'x'; 200])], &[])?;
    check(matches!(db.read_changes(&slow, 0, 10), Err(ClError::ConsumerExpired)), "read_changes says ConsumerExpired")?;
    limited.close();
    drop(limited);

    println!("\n7. with no follower, nothing is kept");
    let alone = open(&root.join("alone"), Retention::Default)?;
    let db = alone.db_manager("store");
    alone.domain::<Note>().repo().set("a", &note("a", "one"))?;
    alone.domain::<Note>().repo().set("b", &note("b", "two"))?;
    check(db.journal_head()? == 2, "the sequence still counts every commit")?;
    check(db.journal_stats()?.journal_bytes == 0, "but no change is stored for nobody")?;
    alone.close();
    drop(alone);

    std::fs::remove_dir_all(&root)?;
    println!("\n04 change log: all checks passed");
    Ok(())
}
