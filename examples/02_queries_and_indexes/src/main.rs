//! # 02 — Queries and indexes
//!
//! `#[derive(CloveFields)]` gives every field a typed handle (`Note::score`, `Note::title`, ...).
//! Queries are built from those handles and run against one snapshot of the database.
//!
//! - filters, ordering, pages with a cursor, `one()`, and aggregates (`count`, `sum`, `distinct`,
//!   `group_by`, `min`, `max`) that work on the whole filtered set;
//! - text, `contains`, `prefix` and `fuzzy` search, and order by similarity;
//! - a unique constraint, checked in the same transaction as the write;
//! - **automatic indexes** in the `.inx` file: there is no `create_index`. The optimizer builds an
//!   index when a query would pay for it, and `explain()` says which plan it chose and why;
//! - the `.inx` file is disposable: deleted, it is rebuilt before `build()` returns, with the same
//!   answers.
//!
//! Run it with `cargo run --release` from this folder (debug works, the index build is slower).

use clove1db::{
    CloveFields, Unique,
    entity::Entity,
    query::{Asc, Desc, LastWrite, Sum, optimizer::Plan},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    group: String,
    score: i64,
    title: String,
    labels: Vec<String>,
}

impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
    // The `id` field always equals the row key, so `Note::id.eq(..)` is a direct lookup.
    fn id_field() -> Option<clove1db::fields::Field<Self, String>> {
        Some(Self::id)
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Word {
    id: String,
    name: String,
}

impl Entity for Word {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn check(ok: bool, what: &str) -> Res<()> {
    if ok {
        println!("  ok  {what}");
        Ok(())
    } else {
        Err(format!("check failed: {what}").into())
    }
}

fn open(root: &Path) -> Res<Storage> {
    Ok(Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root.to_path_buf())
                .has_cache(false)
                .register::<Note>("notes")
                .register::<Word>("words")
                // Two titles that differ only in spaces or case are the same title.
                .unique::<Note>(Unique::on(Note::title.trim().lowercase())),
        )
        .build()?)
}

fn note(id: &str, group: &str, score: i64, title: &str, labels: &[&str]) -> Note {
    Note {
        id: id.into(),
        group: group.into(),
        score,
        title: title.into(),
        labels: labels.iter().map(|l| l.to_string()).collect(),
    }
}

fn small_queries(storage: &Storage) -> Res<()> {
    let notes = storage.domain::<Note>();
    for n in [
        note("a", "public", 25, " Introduction ", &["rust", "intro"]),
        note("b", "public", 40, "Advanced topics", &["rust"]),
        note("c", "draft", 5, "Work in progress", &[]),
        note("d", "public", 12, "Appendix", &["reference"]),
    ] {
        notes.repo().set(&n.id.clone(), &n)?;
    }

    println!("\nfilter, order and pages");
    let q = notes
        .query()
        .filter(Note::group.eq("public").and(Note::score.ge(20)))
        .order_by(Note::score, Desc)
        .then_by(Note::id, Asc)
        .limit(1);
    let first = q.page()?;
    check(first.items.len() == 1 && first.items[0].id == "b", "the first page holds the highest score")?;
    let cursor = first.next.ok_or("a second page was expected")?;
    let second = q.clone().after(cursor).collect()?;
    check(second.len() == 1 && second[0].id == "a", "the cursor gives the next row")?;

    println!("\none(): zero, one, or an error");
    check(notes.query().filter(Note::id.eq("a")).one()?.is_some(), "one row found")?;
    check(notes.query().filter(Note::id.eq("zz")).one()?.is_none(), "no row is None")?;
    check(
        matches!(notes.query().filter(Note::group.eq("public")).one(), Err(ClError::NonUnique { count: 3 })),
        "three rows are NonUnique { count: 3 }",
    )?;

    println!("\ntext search");
    check(notes.query().filter(Note::title.trim().lowercase().eq("introduction")).count()? == 1, "a transform before eq")?;
    check(notes.query().filter(Note::title.text("TOPICS")).count()? == 1, "text() matches whole words, any case")?;
    check(notes.query().filter(Note::title.contains("progress")).count()? == 1, "contains() matches inside a word")?;
    check(notes.query().filter(Note::title.prefix("App")).count()? == 1, "prefix()")?;
    check(notes.query().filter(Note::labels.any().eq("rust")).count()? == 2, "any() on a list")?;

    println!("\naggregates over the whole filtered set");
    check(notes.query().count()? == 4, "count")?;
    check(notes.query().sum(Note::score)? == Sum::Integer(82), "sum is exact: 25 + 40 + 5 + 12")?;
    check(notes.query().distinct(Note::group)?.len() == 2, "two distinct groups")?;
    check(notes.query().group_by(Note::group).count()?.len() == 2, "group_by().count()")?;
    check(notes.query().min(Note::score)?.is_some() && notes.query().max(Note::score)?.is_some(), "min and max")?;
    let latest = notes.query().order_by(LastWrite, Desc).limit(1).collect()?;
    check(latest[0].id == "d", "order by the last write")?;

    println!("\nthe unique constraint");
    let duplicate = note("e", "draft", 0, "  INTRODUCTION", &[]);
    check(matches!(notes.repo().set("e", &duplicate), Err(ClError::UniqueViolation)), "a duplicate title is refused")?;
    check(notes.query().count()? == 4, "and nothing was written")?;

    println!("\nseveral queries on one snapshot");
    let view = storage.db_manager("store").read_view_at_head()?;
    notes.repo().set("f", &note("f", "draft", 1, "Later", &[]))?;
    check(notes.query().collect_in(&view)?.len() == 4, "the snapshot does not see the later row")?;
    check(notes.query().count()? == 5, "a new query does")?;
    drop(view);

    Ok(())
}

fn wait_for_index(storage: &Storage, query: &clove1db::query::Query<Word>, kind: &str) -> Res<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        query.count()?; // a query is what asks for the index
        if storage.index_report().iter().any(|r| r.ready && r.definition.kind == kind) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("the {kind} index was not built within 60 s").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn indexes(storage: &Storage, root: &Path) -> Res<u64> {
    println!("\nautomatic indexes on 20,000 rows");
    let db = storage.db_manager("store");
    let names = ["alpha", "alphi", "beta", "gamma", "delta"];
    for start in (0..20_000usize).step_by(1_000) {
        let rows = (start..start + 1_000)
            .map(|i| {
                let w = Word { id: format!("w{i:06}"), name: names[i % 5].into() };
                Ok(("words".to_owned(), w.id.clone(), serde_json::to_vec(&w)?))
            })
            .collect::<Res<Vec<_>>>()?;
        db.commit_batch_atomic(&rows, &[])?;
    }

    let fuzzy = storage.domain::<Word>().query().filter(Word::name.fuzzy("alpha", 1));
    println!("  plan before any index: {:?}", fuzzy.explain()?.selected);
    wait_for_index(storage, &fuzzy, "Token")?;
    let plan = fuzzy.explain()?;
    println!("  plan once the index is ready: {:?} ({} alternatives costed)", plan.selected, plan.alternatives.len());
    check(plan.selected == Plan::IndexFuzzy, "the optimizer chose the fuzzy index")?;
    let matches = fuzzy.count()?;
    check(matches == 8_000, "fuzzy(\"alpha\", 1) matches alpha and alphi: 8,000 rows")?;

    let top = storage.domain::<Word>().query().order_by(Word::name.similarity("alpha"), Desc).limit(3).collect()?;
    check(top.iter().all(|w| w.name == "alpha"), "order by similarity puts exact matches first")?;

    println!("\na fresh write and allow_stale()");
    let late = Word { id: "late".into(), name: "alpha".into() };
    db.commit_batch_atomic(&[("words".into(), late.id.clone(), serde_json::to_vec(&late)?)], &[])?;
    let stale = fuzzy.clone().allow_stale().page()?;
    println!("  allow_stale: index sequence {:?}, stale {}", stale.index_sequence, stale.stale);
    check(fuzzy.count()? == matches + 1, "a normal query always sees the new row")?;
    println!("  index report: {} definitions", storage.index_report().len());

    let expected = fuzzy.count()?;
    storage.close();
    let inx = root.join("records").join("store.inx");
    std::fs::remove_file(&inx)?;
    println!("\ndeleted {}, opening again", inx.display());
    Ok(expected)
}

fn main() -> Res<()> {
    let root: PathBuf = std::env::temp_dir().join(format!("clove1db-example-02-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    println!("02 queries and indexes — data in {}", root.display());

    let storage = open(&root)?;
    small_queries(&storage)?;
    let expected = indexes(&storage, &root)?;
    drop(storage);

    let storage = open(&root)?;
    let again = storage.domain::<Word>().query().filter(Word::name.fuzzy("alpha", 1)).count()?;
    check(again == expected, "the rebuilt index gives the same answer")?;
    storage.close();
    drop(storage);

    std::fs::remove_dir_all(&root)?;
    println!("\n02 queries and indexes: all checks passed");
    Ok(())
}
