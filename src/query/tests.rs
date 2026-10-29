use super::*;
use crate::{
    CloveFields,
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    n: i64,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
    fn id_field() -> Option<Field<Self, String>> {
        Some(Self::id)
    }
}
#[test]
fn injected_plans_same_results_generation_and_trial() {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root)
                .has_cache(false)
                .register::<Note>("notes"),
        )
        .build()
        .unwrap();
    let db = s.db_manager("store");
    let rows = (0..2000)
        .map(|i| {
            (
                "notes".into(),
                i.to_string(),
                serde_json::to_vec(&Note {
                    id: i.to_string(),
                    n: i,
                })
                .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    db.commit_batch_atomic(&rows, &[]).unwrap();
    let q = s
        .domain::<Note>()
        .query()
        .filter(Note::id.eq("1700"))
        .order_by(Note::n, Desc)
        .limit(1);
    let view = db.read_view_at_head().unwrap();
    // Inject each execution candidate into an otherwise genuine cached plan.
    let mut canonical = q.fingerprint().unwrap();
    canonical.push(0);
    let ctx = q.context(&view, &canonical, false);
    for plan in [
        optimizer::Plan::FullScan,
        optimizer::Plan::SelectiveScan,
        optimizer::Plan::PointLookup,
        optimizer::Plan::TopK,
        optimizer::Plan::EarlyStop,
    ] {
        optimizer::prepare(&db.query_runtime, &ctx, false).unwrap();
        {
            let mut r = db.query_runtime.lock().unwrap();
            r.test_force(&ctx, plan).unwrap();
        }
        let result = q.collect_in(&view).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].n, 1700);
    }
    db.query_runtime.lock().unwrap().test_clear();
    let a = optimizer::prepare(&db.query_runtime, &ctx, false).unwrap();
    assert!(!a.cache_hit);
    assert!(
        optimizer::prepare(&db.query_runtime, &ctx, false)
            .unwrap()
            .cache_hit
    );
    let different = optimizer::Context {
        schema: ctx.schema + 1,
        ..ctx
    };
    assert!(
        !optimizer::prepare(&db.query_runtime, &different, false)
            .unwrap()
            .cache_hit
    );
    let scan = s.domain::<Note>().query().filter(Note::n.gt(900));
    let fingerprint = scan.fingerprint().unwrap();
    let ctx = scan.context(&view, &fingerprint, false);
    db.query_runtime.lock().unwrap().test_equal_costs();
    let trial = optimizer::prepare(&db.query_runtime, &ctx, true).unwrap();
    assert!(trial.trial_micros > 0);
    assert_eq!(optimizer::TRIAL_BUDGET, std::time::Duration::from_millis(5));
    // Time is checked before every row; an indivisible row may cross the deadline.
    assert!(trial.trial_micros < 100_000);
    println!("trial_micros={}", trial.trial_micros);
    db.query_runtime.lock().unwrap().test_clear();
    for i in 0..1000 {
        let large = vec![i as u8; 4096];
        let ctx = optimizer::Context {
            canonical: &large,
            ..ctx
        };
        optimizer::prepare(&db.query_runtime, &ctx, false).unwrap();
        assert!(db.query_runtime.lock().unwrap().test_cache_bytes() <= optimizer::CACHE_BYTES);
    }
    drop(view);
    s.close();
}
