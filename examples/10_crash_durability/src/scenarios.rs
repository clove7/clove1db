use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clove1db::fsutil::is_corrupt_index_bytes;
use clove1db::storage::{DatabaseConfig, Storage, StorageConfig};
use clove1db::units::Result;
use clove1db::DurabilityMode;

use crate::entities::{
    make_blob_bytes, make_device, make_feed, make_order_v1, Device, FeedEvent, InvoiceBlob, OrderV1,
    OrderV2, OrderV3,
};
use crate::log;

pub const BASE_DIR: &str = "./target/example_10_crash";

/// Tunables — heavy enough to take wall time and stress I/O.
pub const HEAVY_ORDERS: usize = 4_000;
pub const HEAVY_DEVICES: usize = 800;
pub const HEAVY_EVENTS: usize = 3_000;
pub const HEAVY_BLOBS: usize = 60;
pub const BLOB_BYTES: usize = 768 * 1024; // 768 KiB each ≈ 45 MB blobs
pub const DENSE_COMMIT_ROWS: usize = 5_000;
pub const PARALLEL_THREADS: usize = 8;
pub const PARALLEL_PER_THREAD: usize = 400;
pub const BACKUP_UPDATE_ROUNDS: usize = 8;
pub const PRESSURE_ROWS: usize = 2_500;
pub const PRESSURE_PAYLOAD: usize = 12_288;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn spawn_crash_child(scenario: &str, crash_point: &str, base: &Path) -> std::io::Result<i32> {
    log::action(format!(
        "Spawning crash-child scenario={scenario} point={crash_point}"
    ));
    let exe = env::current_exe()?;
    log::detail(format!("child exe: {}", exe.display()));
    let status = Command::new(exe)
        .env("CLOVE_CRASH_CHILD", scenario)
        .env("CLOVE_CRASH_POINT", crash_point)
        .env("CLOVE_BASE", base)
        .status()?;
    let code = status.code().unwrap_or(-1);
    log::detail(format!("child process exited with code {code} (crash inject uses 99)"));
    Ok(code)
}

fn assert_no_nul_finals(root: &Path) -> Result<()> {
    log::action(format!("Scanning for NUL/corrupt final JSON under {}", root.display()));
    let mut scanned = 0usize;
    let mut json_files = 0usize;
    fn walk(dir: &Path, scanned: &mut usize, json_files: &mut usize) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk(&path, scanned, json_files)?;
                continue;
            }
            *scanned += 1;
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.contains(".tmp.") || name.contains("corrupt.") || name.contains("replace-old")
            {
                continue;
            }
            if name.ends_with(".json") {
                *json_files += 1;
                let data = fs::read(&path)?;
                if !data.is_empty() && data.iter().all(|b| *b == 0) {
                    return Err(clove1db::units::ClError::Validation(format!(
                        "NUL final file: {}",
                        path.display()
                    )));
                }
                if name == "index.json" && is_corrupt_index_bytes(&data) {
                    return Err(clove1db::units::ClError::Validation(format!(
                        "corrupt index.json still present: {}",
                        path.display()
                    )));
                }
            }
        }
        Ok(())
    }
    walk(root, &mut scanned, &mut json_files)?;
    log::kv("files scanned", scanned);
    log::kv("json files checked", json_files);
    log::ok("no NUL / corrupt final index.json found");
    Ok(())
}

fn report_dir(label: &str, dir: &Path) {
    let size = log::dir_size(dir);
    log::kv(label, format!("{} ({})", dir.display(), log::bytes_human(size)));
}

fn orders_v1_storage(dir: PathBuf, backup: bool) -> Result<Storage> {
    let mut db = DatabaseConfig::new("orders_db", "orders")
        .dir_path(dir)
        .cache(5_000, 120, 60)
        .max_commit_batch_entries(128)
        .register::<OrderV1>("orders");
    if backup {
        db = db.backup_enabled(true);
    } else {
        db = db.backup_enabled(false);
    }
    Storage::builder(StorageConfig::default().durability(DurabilityMode::Strict))
        .migration_step::<OrderV1, OrderV2>()
        .migration_step::<OrderV2, OrderV3>()
        .add_database(db)
        .build()
}

fn seed_orders_batch(
    storage: &Storage,
    db_name: &str,
    count: usize,
    label: &str,
) -> Result<Vec<String>> {
    log::action(format!("Seeding {count} diverse OrderV1 rows ({label}) on db '{db_name}'"));
    let t = log::Timer::start(format!("seed {label}"));
    let mut writes = Vec::with_capacity(count);
    let mut ids = Vec::with_capacity(count);
    let base_ms = now_ms();
    for i in 0..count {
        let order = make_order_v1(i, base_ms);
        ids.push(order.id.clone());
        writes.push((
            "orders".to_string(),
            order.id.clone(),
            serde_json::to_vec(&order)?,
        ));
        log::progress(i + 1, count, "build batch");
    }
    log::detail(format!(
        "commit_batch size={} (will auto-chunk by max_commit_batch_entries)",
        writes.len()
    ));
    storage.db_manager(db_name).commit_batch(&writes, &[])?;
    t.finish();
    let sample: OrderV1 = storage.domain::<OrderV1>().get(&ids[0])?;
    let mid: OrderV1 = storage.domain::<OrderV1>().get(&ids[count / 2])?;
    let last: OrderV1 = storage.domain::<OrderV1>().get(&ids[count - 1])?;
    log::detail(format!(
        "sample[0] customer={} branch={} total={}",
        sample.customer_name, sample.branch_id, sample.total_halalas
    ));
    log::detail(format!(
        "sample[mid] customer={} items_len={}",
        mid.customer_name,
        mid.items_json.len()
    ));
    log::detail(format!(
        "sample[last] notes_len={} created_at={}",
        last.notes.len(),
        last.created_at_ms
    ));
    log::ok(format!("seeded {count} orders"));
    Ok(ids)
}

/// Child entry points used with CLOVE_CRASH_POINT injection.
pub fn run_child(scenario: &str, base: &Path) -> Result<()> {
    eprintln!("[crash-child] scenario={scenario} pid={}", std::process::id());
    match scenario {
        "index_write" => {
            let dir = base.join("s01");
            let mig = dir.join("orders_db").join("orders.migration");
            let _ = fs::remove_file(mig.join("index.json"));
            let _ = fs::remove_file(mig.join("tables").join("orders").join("index.json"));
            let _ = orders_v1_storage(dir, true)?;
        }
        "multi_layout" => {
            let dir = base.join("s03");
            let _ = Storage::builder(StorageConfig::default())
                .add_database(
                    DatabaseConfig::new("multi_db", "multi")
                        .dir_path(dir)
                        .backup_enabled(true)
                        .register::<OrderV1>("orders")
                        .register::<Device>("devices")
                        .register::<FeedEvent>("events"),
                )
                .build()?;
        }
        "dense_commit" => {
            let dir = base.join("s04");
            let storage = orders_v1_storage(dir, true)?;
            let mut writes = Vec::new();
            let base_ms = now_ms();
            for i in 0..DENSE_COMMIT_ROWS {
                let order = make_order_v1(10_000 + i, base_ms);
                writes.push((
                    "orders".to_string(),
                    order.id.clone(),
                    serde_json::to_vec(&order)?,
                ));
            }
            storage.db_manager("orders").commit_batch(&writes, &[])?;
        }
        "blob_write" => {
            let dir = base.join("s05");
            let storage = Storage::builder(StorageConfig::default())
                .add_database(
                    DatabaseConfig::new("docs_db", "docs")
                        .dir_path(dir)
                        .backup_enabled(false)
                        .blob_enabled(true)
                        .register_blob::<InvoiceBlob>("files"),
                )
                .build()?;
            let payload = make_blob_bytes(999, BLOB_BYTES * 2);
            storage
                .db_manager("docs")
                .write_blob("files", "crash-target", &payload)?;
        }
        "parallel" => {
            // Parent already seeded parallel rows. Child only forces an index rewrite crash.
            let dir = base.join("s07");
            eprintln!("[crash-child] forcing migration index rewrite crash after parallel seed");
            let mig = dir
                .join("orders_db")
                .join("orders.migration")
                .join("index.json");
            let _ = fs::remove_file(&mig);
            let storage = orders_v1_storage(dir, true)?;
            let _: OrderV1 = storage
                .domain::<OrderV1>()
                .create(make_order_v1(99_999, now_ms()))?;
        }
        "migrate" => {
            let dir = base.join("s08");
            let storage = Storage::builder(StorageConfig::default())
                .migration_step::<OrderV1, OrderV2>()
                .migration_step::<OrderV2, OrderV3>()
                .add_database(
                    DatabaseConfig::new("orders_db", "orders")
                        .dir_path(dir)
                        .backup_enabled(true)
                        .register::<OrderV1>("orders"),
                )
                .build()?;
            let mut run = storage.migrate::<OrderV1, OrderV2>().from_db("orders", "orders");
            run.dry_run()?;
            run.execute()?;
        }
        "multi_db" => {
            let dir = base.join("s09");
            let _ = Storage::builder(StorageConfig::default())
                .add_database(
                    DatabaseConfig::new("devices_db", "devices")
                        .dir_path(dir.clone())
                        .backup_enabled(true)
                        .register::<Device>("devices"),
                )
                .add_database(
                    DatabaseConfig::new("dashboard_db", "dashboard")
                        .dir_path(dir)
                        .backup_enabled(true)
                        .register::<FeedEvent>("events"),
                )
                .build()?;
        }
        "compound" => {
            let dir = base.join("s10");
            let storage = Storage::builder(StorageConfig::default())
                .add_database(
                    DatabaseConfig::new("compound_db", "compound")
                        .dir_path(dir)
                        .backup_enabled(true)
                        .cache(256, 30, 10)
                        .max_commit_batch_entries(64)
                        .blob_enabled(false)
                        .register::<OrderV1>("orders"),
                )
                .build()?;
            let mut writes = Vec::new();
            let base_ms = now_ms();
            for i in 0..800 {
                let order = make_order_v1(80_000 + i, base_ms);
                writes.push((
                    "orders".to_string(),
                    order.id.clone(),
                    serde_json::to_vec(&order)?,
                ));
            }
            storage.db_manager("compound").commit_batch(&writes, &[])?;
        }
        other => {
            return Err(clove1db::units::ClError::Validation(format!(
                "unknown child scenario: {other}"
            )));
        }
    }
    Ok(())
}

pub fn scenario_01_kill_during_index_write(base: &Path) -> Result<Duration> {
    log::scenario_header(
        1,
        "Kill during migration index rewrite",
        "Crash while rewriting index.json; reopen must keep seeded orders + backup history",
    );
    let wall = Instant::now();
    let dir = base.join("s01");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    log::phase("Prepare Strict storage with backup enabled");
    let storage = orders_v1_storage(dir.clone(), true)?;
    report_dir("data dir", &dir);

    log::phase("Seed heavy sensitive order set");
    let ids = seed_orders_batch(&storage, "orders", HEAVY_ORDERS / 2, "s01-initial")?;

    log::phase("Mutate subset to create backup history versions");
    let t = log::Timer::start("backup mutation rounds");
    let domain = storage.domain::<OrderV1>();
    for round in 0..BACKUP_UPDATE_ROUNDS {
        log::action(format!(
            "Round {}/{} — update first 200 orders (creates backup versions)",
            round + 1,
            BACKUP_UPDATE_ROUNDS
        ));
        for i in 0..200.min(ids.len()) {
            let mut o: OrderV1 = domain.get(&ids[i])?;
            o.notes = format!("{}|edit-round-{round}", o.notes);
            o.total_halalas += 1;
            let _: OrderV1 = domain.update(&ids[i], o)?;
        }
        log::detail(format!("round {round} complete"));
    }
    t.finish();

    let hist = domain.history(&ids[0])?;
    log::kv("backup history versions for first order", hist.len());
    log::ok("backup trail populated");

    drop(storage);

    log::phase("Inject hard crash during atomic index rewrite");
    let code = spawn_crash_child("index_write", "before_rename", base)
        .map_err(|e| clove1db::units::ClError::IoError(e.to_string()))?;
    log::kv("expected crash code", 99);
    log::kv("actual crash code", code);

    log::phase("Reopen after crash + verify integrity");
    let storage = orders_v1_storage(dir.clone(), true)?;
    let got: OrderV1 = storage.domain::<OrderV1>().get(&ids[0])?;
    log::detail(format!(
        "recovered order {} customer={} notes_contains_edit={}",
        got.id,
        got.customer_name,
        got.notes.contains("edit-round")
    ));
    let hist2 = storage.domain::<OrderV1>().history(&ids[0])?;
    log::kv("history versions after crash", hist2.len());
    assert!(!hist2.is_empty());
    assert_no_nul_finals(&dir)?;
    report_dir("data dir after", &dir);
    log::ok("SCENARIO 01 PASSED");
    Ok(wall.elapsed())
}

pub fn scenario_02_nul_index_recover(base: &Path) -> Result<Duration> {
    log::scenario_header(
        2,
        "Forced NUL index.json recovery",
        "Reproduce the cafe power-loss artifact; open must quarantine + rebuild indexes",
    );
    let wall = Instant::now();
    let dir = base.join("s02");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    log::phase("Seed Strict DB with backup");
    let storage = orders_v1_storage(dir.clone(), true)?;
    let ids = seed_orders_batch(&storage, "orders", HEAVY_ORDERS / 2, "s02-seed")?;
    drop(storage);

    log::phase("Manually corrupt migration indexes to all-NUL (power-loss shape)");
    let mig = dir.join("orders_db").join("orders.migration");
    let root_index = mig.join("index.json");
    let table_index = mig.join("tables").join("orders").join("index.json");
    let root_len = fs::metadata(&root_index)?.len() as usize;
    log::action(format!(
        "Overwriting {} with {} zero bytes",
        root_index.display(),
        root_len.max(256)
    ));
    fs::write(&root_index, vec![0u8; root_len.max(256)])?;
    if table_index.exists() {
        let len = fs::metadata(&table_index)?.len() as usize;
        log::action(format!(
            "Overwriting {} with {} zero bytes",
            table_index.display(),
            len.max(128)
        ));
        fs::write(&table_index, vec![0u8; len.max(128)])?;
    }
    log::warn("indexes are now intentionally corrupt (NUL)");

    log::phase("Reopen — library must recover without Serialization panic");
    let t = log::Timer::start("recover open");
    let storage = orders_v1_storage(dir.clone(), true)?;
    t.finish();

    let got: OrderV1 = storage.domain::<OrderV1>().get(&ids[0])?;
    let last: OrderV1 = storage.domain::<OrderV1>().get(ids.last().unwrap())?;
    log::detail(format!("first order ok: {}", got.customer_name));
    log::detail(format!("last order ok: {}", last.id));
    log::kv("orders verified", 2);
    assert_no_nul_finals(&dir)?;
    // Show quarantine artifacts if any
    if let Ok(rd) = fs::read_dir(&mig) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.contains("corrupt") {
                log::detail(format!("quarantine artifact: {name}"));
            }
        }
    }
    log::ok("SCENARIO 02 PASSED");
    Ok(wall.elapsed())
}

pub fn scenario_03_kill_multi_table_layout(base: &Path) -> Result<Duration> {
    log::scenario_header(
        3,
        "Kill during multi-table ensure_layout",
        "Several tables + backup; crash mid metadata write; reopen must succeed",
    );
    let wall = Instant::now();
    let dir = base.join("s03");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    log::phase("Crash child while creating multi-table schema");
    let code = spawn_crash_child("multi_layout", "before_rename", base)
        .map_err(|e| clove1db::units::ClError::IoError(e.to_string()))?;
    log::kv("crash code", code);

    log::phase("Reopen multi-table DB and load heavy diverse data");
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("multi_db", "multi")
                .dir_path(dir.clone())
                .backup_enabled(true)
                .cache(4_000, 90, 45)
                .max_commit_batch_entries(100)
                .register::<OrderV1>("orders")
                .register::<Device>("devices")
                .register::<FeedEvent>("events"),
        )
        .build()?;

    log::action(format!("Seeding {HEAVY_DEVICES} devices"));
    let t = log::Timer::start("seed devices+events");
    let mut device_writes = Vec::new();
    for i in 0..HEAVY_DEVICES {
        let d = make_device(i);
        device_writes.push(("devices".into(), d.id.clone(), serde_json::to_vec(&d)?));
        log::progress(i + 1, HEAVY_DEVICES, "devices");
    }
    storage.db_manager("multi").commit_batch(&device_writes, &[])?;

    log::action(format!("Seeding {HEAVY_EVENTS} feed events"));
    let mut event_writes = Vec::new();
    for i in 0..HEAVY_EVENTS {
        let e = make_feed(i);
        event_writes.push(("events".into(), e.id.clone(), serde_json::to_vec(&e)?));
        log::progress(i + 1, HEAVY_EVENTS, "events");
    }
    storage.db_manager("multi").commit_batch(&event_writes, &[])?;
    t.finish();

    let d0: Device = storage.domain::<Device>().get("dev-0000")?;
    let e0: FeedEvent = storage.domain::<FeedEvent>().get("evt-000000")?;
    log::detail(format!("device0={} firmware={}", d0.label, d0.firmware));
    log::detail(format!("event0 kind={} payload_len={}", e0.kind, e0.payload.len()));
    assert_no_nul_finals(&dir)?;
    report_dir("multi_db dir", &dir);
    log::ok("SCENARIO 03 PASSED");
    Ok(wall.elapsed())
}

pub fn scenario_04_kill_dense_commit(base: &Path) -> Result<Duration> {
    log::scenario_header(
        4,
        "Kill during dense commit_batch",
        "Thousands of rows + Immediate durability; crash before commit; anchor must survive",
    );
    let wall = Instant::now();
    let dir = base.join("s04");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    log::phase("Create anchor order under Strict+backup");
    let storage = orders_v1_storage(dir.clone(), true)?;
    let anchor = make_order_v1(0, now_ms());
    let anchor_id = anchor.id.clone();
    let _: OrderV1 = storage.domain::<OrderV1>().create(anchor)?;
    log::detail(format!("anchor id={anchor_id}"));
    drop(storage);

    log::phase(format!(
        "Crash child while committing {DENSE_COMMIT_ROWS} heavy rows"
    ));
    let code = spawn_crash_child("dense_commit", "before_commit", base)
        .map_err(|e| clove1db::units::ClError::IoError(e.to_string()))?;
    log::kv("crash code", code);

    log::phase("Reopen and verify only durable commits remain consistent");
    let storage = orders_v1_storage(dir.clone(), true)?;
    let got: OrderV1 = storage.domain::<OrderV1>().get(&anchor_id)?;
    log::detail(format!("anchor survived: {}", got.customer_name));
    assert_no_nul_finals(&dir)?;
    log::ok("SCENARIO 04 PASSED");
    Ok(wall.elapsed())
}

pub fn scenario_05_kill_blob_write(base: &Path) -> Result<Duration> {
    log::scenario_header(
        5,
        "Kill during large blob write",
        "Atomic blob path; prior invoice bytes must remain intact after crash",
    );
    let wall = Instant::now();
    let dir = base.join("s05");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    log::phase("Write keep-alive invoice blob + metadata");
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("docs_db", "docs")
                .dir_path(dir.clone())
                .backup_enabled(false)
                .blob_enabled(true)
                .register_blob::<InvoiceBlob>("files"),
        )
        .build()?;

    log::action(format!("Writing {HEAVY_BLOBS} invoice blobs × {}", log::bytes_human(BLOB_BYTES as u64)));
    let t = log::Timer::start("blob seed");
    for i in 0..HEAVY_BLOBS {
        let bytes = make_blob_bytes(i, BLOB_BYTES);
        let id = format!("inv-{i:04}");
        storage.db_manager("docs").write_blob("files", &id, &bytes)?;
        let meta = InvoiceBlob {
            id: id.clone(),
            order_id: format!("ord-{i:06}"),
            title: format!("Invoice #{i}"),
            size_bytes: bytes.len(),
            content_type: "application/octet-stream".into(),
        };
        let _: InvoiceBlob = storage.domain::<InvoiceBlob>().create(meta)?;
        log::progress(i + 1, HEAVY_BLOBS, "blobs");
    }
    // Dedicated keep blob
    storage
        .db_manager("docs")
        .write_blob("files", "keep", b"ALIVE-INVOICE-SEED")?;
    t.finish();
    report_dir("docs dir", &dir);
    drop(storage);

    log::phase("Crash while writing a 1MB+ replacement blob");
    let code = spawn_crash_child("blob_write", "before_rename", base)
        .map_err(|e| clove1db::units::ClError::IoError(e.to_string()))?;
    log::kv("crash code", code);

    log::phase("Verify keep blob + sample invoices");
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("docs_db", "docs")
                .dir_path(dir.clone())
                .backup_enabled(false)
                .blob_enabled(true)
                .register_blob::<InvoiceBlob>("files"),
        )
        .build()?;
    let mut f = storage.db_manager("docs").open_blob("files", "keep")?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    log::detail(format!("keep blob utf8={}", String::from_utf8_lossy(&buf)));
    assert_eq!(buf, b"ALIVE-INVOICE-SEED");
    let sample = make_blob_bytes(0, BLOB_BYTES);
    let mut f0 = storage.db_manager("docs").open_blob("files", "inv-0000")?;
    let mut got0 = Vec::new();
    f0.read_to_end(&mut got0)?;
    assert_eq!(got0, sample);
    log::ok("keep + sample invoice blobs intact");
    assert_no_nul_finals(&dir)?;
    log::ok("SCENARIO 05 PASSED");
    Ok(wall.elapsed())
}

pub fn scenario_06_memory_pressure(base: &Path) -> Result<Duration> {
    log::scenario_header(
        6,
        "RAM pressure + chunked commits",
        "Tiny cache, large payloads, auto-split batches; reopen must read all edges",
    );
    let wall = Instant::now();
    let dir = base.join("s06");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    log::phase("Open with tiny cache + small max_commit_batch_entries");
    log::kv("cache capacity", 48);
    log::kv("max_commit_batch_entries", 24);
    log::kv("rows", PRESSURE_ROWS);
    log::kv("payload bytes/row", PRESSURE_PAYLOAD);

    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("press_db", "press")
                .dir_path(dir.clone())
                .backup_enabled(true)
                .cache(48, 15, 8)
                .max_commit_batch_entries(24)
                .register::<OrderV1>("orders"),
        )
        .build()?;

    log::phase("Build oversized in-memory batch then commit (library chunks)");
    let t = log::Timer::start("pressure commit");
    let mut writes = Vec::new();
    let base_ms = now_ms();
    for i in 0..PRESSURE_ROWS {
        let mut order = make_order_v1(i, base_ms);
        order.notes = format!("{}|{}", order.notes, "Z".repeat(PRESSURE_PAYLOAD));
        writes.push((
            "orders".to_string(),
            order.id.clone(),
            serde_json::to_vec(&order)?,
        ));
        log::progress(i + 1, PRESSURE_ROWS, "build");
    }
    let batch_bytes: usize = writes.iter().map(|(_, _, v)| v.len()).sum();
    log::kv("approx batch RAM", log::bytes_human(batch_bytes as u64));
    storage.db_manager("press").commit_batch(&writes, &[])?;
    t.finish();
    drop(storage);

    log::phase("Reopen under same pressure settings and verify edges");
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("press_db", "press")
                .dir_path(dir.clone())
                .backup_enabled(true)
                .cache(48, 15, 8)
                .max_commit_batch_entries(24)
                .register::<OrderV1>("orders"),
        )
        .build()?;
    let first: OrderV1 = storage.domain::<OrderV1>().get("ord-000000")?;
    let last: OrderV1 = storage
        .domain::<OrderV1>()
        .get(&format!("ord-{:06}", PRESSURE_ROWS - 1))?;
    log::detail(format!(
        "first notes_len={} last notes_len={}",
        first.notes.len(),
        last.notes.len()
    ));
    assert!(first.notes.len() > PRESSURE_PAYLOAD);
    assert_no_nul_finals(&dir)?;
    report_dir("press dir", &dir);
    log::ok("SCENARIO 06 PASSED");
    Ok(wall.elapsed())
}

pub fn scenario_07_parallel_then_kill(base: &Path) -> Result<Duration> {
    log::scenario_header(
        7,
        "Parallel writers then kill",
        format!(
            "{PARALLEL_THREADS} threads × {PARALLEL_PER_THREAD} creates in parent, then crash on index rewrite"
        ),
    );
    let wall = Instant::now();
    let dir = base.join("s07");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    log::phase("Parent: parallel Strict+backup writers (visible load)");
    log::kv("threads", PARALLEL_THREADS);
    log::kv("creates/thread", PARALLEL_PER_THREAD);
    let total = PARALLEL_THREADS * PARALLEL_PER_THREAD;
    log::kv("total creates", total);

    let storage = Arc::new(orders_v1_storage(dir.clone(), true)?);
    let t = log::Timer::start("parallel create storm");
    let mut handles = Vec::new();
    for th in 0..PARALLEL_THREADS {
        let storage = Arc::clone(&storage);
        handles.push(thread::spawn(move || {
            let domain = storage.domain::<OrderV1>();
            let base_ms = now_ms();
            for i in 0..PARALLEL_PER_THREAD {
                let mut order = make_order_v1(50_000 + th * 1000 + i, base_ms);
                order.id = format!("par-t{th}-{i:04}");
                let _: OrderV1 = domain.create(order).unwrap();
            }
            th
        }));
    }
    for h in handles {
        let th = h.join().expect("thread panicked");
        log::detail(format!("thread {th} finished {PARALLEL_PER_THREAD} creates"));
    }
    t.finish();
    let before: Vec<OrderV1> = storage.domain::<OrderV1>().list()?;
    log::kv("rows before crash", before.len());
    drop(storage);
    thread::sleep(Duration::from_millis(100));

    log::phase("Crash child: delete index.json then reopen/write (before_rename)");
    let code = spawn_crash_child("parallel", "before_rename", base)
        .map_err(|e| clove1db::units::ClError::IoError(e.to_string()))?;
    log::kv("crash code", code);

    log::phase("Reopen and verify parallel rows survived");
    let storage = orders_v1_storage(dir.clone(), true)?;
    let list: Vec<OrderV1> = storage.domain::<OrderV1>().list()?;
    log::kv("rows after crash reopen", list.len());
    assert!(
        list.len() >= total,
        "expected parallel writes to remain durable"
    );
    if let Some(sample) = list.iter().find(|o| o.id.starts_with("par-t0-")) {
        log::detail(format!(
            "sample id={} customer={}",
            sample.id, sample.customer_name
        ));
    }
    assert_no_nul_finals(&dir)?;
    report_dir("parallel dir", &dir);
    log::ok("SCENARIO 07 PASSED");
    Ok(wall.elapsed())
}

pub fn scenario_08_kill_during_migrate(base: &Path) -> Result<Duration> {
    log::scenario_header(
        8,
        "Heavy migration V1→V2 with mid-flight crash",
        "Large order set + backup; crash during migrate; complete chain to V3 after recovery",
    );
    let wall = Instant::now();
    let dir = base.join("s08");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    log::phase("Seed full heavy OrderV1 catalog with backup");
    let storage = orders_v1_storage(dir.clone(), true)?;
    let ids = seed_orders_batch(&storage, "orders", HEAVY_ORDERS, "s08-pre-migrate")?;
    // Touch a few for backup versions before migrate
    log::action("Pre-migrate edits to thicken backup history");
    let domain = storage.domain::<OrderV1>();
    for i in 0..100 {
        let mut o: OrderV1 = domain.get(&ids[i])?;
        o.notes.push_str("|pre-mig");
        let _: OrderV1 = domain.update(&ids[i], o)?;
    }
    let hist = domain.history(&ids[0])?;
    log::kv("pre-migrate history len", hist.len());
    drop(storage);

    log::phase("Crash child during OrderV1 → OrderV2 migrate execute");
    let code = spawn_crash_child("migrate", "before_rename", base)
        .map_err(|e| clove1db::units::ClError::IoError(e.to_string()))?;
    log::kv("crash code", code);

    log::phase("Recover as OrderV1, finish V1→V2, then heavy V2→V3");
    let storage = orders_v1_storage(dir.clone(), true)?;
    let got: OrderV1 = storage.domain::<OrderV1>().get(&ids[0])?;
    log::detail(format!("still readable as V1: {}", got.customer_name));

    log::action("Completing migrate OrderV1 → OrderV2");
    let t = log::Timer::start("migrate V1→V2");
    {
        let mut run = storage.migrate::<OrderV1, OrderV2>().from_db("orders", "orders");
        let report = run.dry_run()?;
        log::detail(format!("dry_run report: {report:?}"));
        let result = run.execute()?;
        log::detail(format!("execute result: {result:?}"));
    }
    t.finish();
    drop(storage);

    // Brief pause so Windows releases redb file handles.
    thread::sleep(Duration::from_millis(150));

    log::action("Reopen as OrderV2 and migrate → OrderV3 (heavy audit fields)");
    let storage = Storage::builder(StorageConfig::default())
        .migration_step::<OrderV1, OrderV2>()
        .migration_step::<OrderV2, OrderV3>()
        .add_database(
            DatabaseConfig::new("orders_db", "orders")
                .dir_path(dir.clone())
                .backup_enabled(true)
                .cache(5_000, 120, 60)
                .max_commit_batch_entries(128)
                .register::<OrderV2>("orders"),
        )
        .build()?;
    let v2: OrderV2 = storage.domain::<OrderV2>().get(&ids[0])?;
    log::detail(format!(
        "V2 sample status={} cash={} card={}",
        v2.status, v2.cash_halalas, v2.card_halalas
    ));

    let t = log::Timer::start("migrate V2→V3");
    {
        let mut run = storage.migrate::<OrderV2, OrderV3>().from_db("orders", "orders");
        run.dry_run()?;
        run.execute()?;
    }
    t.finish();
    drop(storage);

    thread::sleep(Duration::from_millis(150));

    let storage = Storage::builder(StorageConfig::default())
        .migration_step::<OrderV1, OrderV2>()
        .migration_step::<OrderV2, OrderV3>()
        .add_database(
            DatabaseConfig::new("orders_db", "orders")
                .dir_path(dir.clone())
                .backup_enabled(true)
                .register::<OrderV3>("orders"),
        )
        .build()?;
    let v3: OrderV3 = storage.domain::<OrderV3>().get(&ids[0])?;
    let v3_last: OrderV3 = storage.domain::<OrderV3>().get(ids.last().unwrap())?;
    log::detail(format!(
        "V3 sample tax={} loyalty={} audit_len={}",
        v3.tax_halalas,
        v3.loyalty_points,
        v3.audit_trail.len()
    ));
    log::detail(format!("V3 last id={} status={}", v3_last.id, v3_last.status));
    assert!(!v3.audit_trail.is_empty());
    assert_no_nul_finals(&dir)?;
    report_dir("migrate dir", &dir);
    log::ok("SCENARIO 08 PASSED — full V1→V2→V3 chain after crash");
    Ok(wall.elapsed())
}

pub fn scenario_09_multi_db_kill(base: &Path) -> Result<Duration> {
    log::scenario_header(
        9,
        "Multi-DB devices+dashboard kill",
        "Cafe-like split DBs; crash on open metadata; then heavy seed + backup edits",
    );
    let wall = Instant::now();
    let dir = base.join("s09");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    log::phase("Crash during multi-db Storage::build");
    let code = spawn_crash_child("multi_db", "before_rename", base)
        .map_err(|e| clove1db::units::ClError::IoError(e.to_string()))?;
    log::kv("crash code", code);

    log::phase("Reopen both DBs with backup and load operational traffic");
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("devices_db", "devices")
                .dir_path(dir.clone())
                .backup_enabled(true)
                .cache(2_000, 60, 30)
                .register::<Device>("devices"),
        )
        .add_database(
            DatabaseConfig::new("dashboard_db", "dashboard")
                .dir_path(dir.clone())
                .backup_enabled(true)
                .cache(3_000, 60, 30)
                .max_commit_batch_entries(100)
                .register::<FeedEvent>("events"),
        )
        .build()?;

    log::action(format!("Seeding {HEAVY_DEVICES} devices with backup"));
    let t = log::Timer::start("devices seed");
    for i in 0..HEAVY_DEVICES {
        let _: Device = storage.domain::<Device>().create(make_device(i))?;
        log::progress(i + 1, HEAVY_DEVICES, "devices");
    }
    t.finish();

    log::action(format!("Seeding {HEAVY_EVENTS} dashboard events via batch"));
    let t = log::Timer::start("events batch");
    let mut writes = Vec::new();
    for i in 0..HEAVY_EVENTS {
        let e = make_feed(i);
        writes.push(("events".into(), e.id.clone(), serde_json::to_vec(&e)?));
    }
    storage
        .db_manager("dashboard")
        .commit_batch(&writes, &[])?;
    t.finish();

    log::action("Backup churn on first 50 devices (3 edit rounds)");
    let domain = storage.domain::<Device>();
    for round in 0..3 {
        for i in 0..50 {
            let id = format!("dev-{i:04}");
            let mut d: Device = domain.get(&id)?;
            d.firmware = format!("{}-r{round}", d.firmware);
            let _: Device = domain.update(&id, d)?;
        }
    }
    let hist = domain.history("dev-0000")?;
    log::kv("device backup versions", hist.len());

    assert_no_nul_finals(&dir)?;
    report_dir("multi-db root", &dir);
    log::ok("SCENARIO 09 PASSED");
    Ok(wall.elapsed())
}

pub fn scenario_10_compound_worst(base: &Path) -> Result<Duration> {
    log::scenario_header(
        10,
        "Compound worst case",
        "NUL indexes + crash mid bulk + pressure settings + backup + reopen verification",
    );
    let wall = Instant::now();
    let dir = base.join("s10");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    log::phase("Seed compound DB (Strict, backup, small cache)");
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("compound_db", "compound")
                .dir_path(dir.clone())
                .backup_enabled(true)
                .cache(96, 20, 10)
                .max_commit_batch_entries(48)
                .register::<OrderV1>("orders"),
        )
        .build()?;
    let ids = seed_orders_batch(&storage, "compound", 600, "s10-seed")?;
    let keep_id = ids[0].clone();
    let mut keep: OrderV1 = storage.domain::<OrderV1>().get(&keep_id)?;
    keep.notes.push_str("|COMPOUND-KEEP");
    let _: OrderV1 = storage.domain::<OrderV1>().update(&keep_id, keep)?;
    let hist = storage.domain::<OrderV1>().history(&keep_id)?;
    log::kv("keep order history", hist.len());
    drop(storage);

    log::phase("Force NUL on compound migration root index");
    let mig = dir
        .join("compound_db")
        .join("compound.migration")
        .join("index.json");
    if mig.exists() {
        let len = fs::metadata(&mig)?.len() as usize;
        log::action(format!("NUL-corrupting {}", mig.display()));
        fs::write(&mig, vec![0u8; len.max(128)])?;
    }

    log::phase("Crash child during dense compound commit");
    let code = spawn_crash_child("compound", "before_commit", base)
        .map_err(|e| clove1db::units::ClError::IoError(e.to_string()))?;
    log::kv("crash code", code);

    log::phase("Recover from NUL + crash; verify keep order + history");
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("compound_db", "compound")
                .dir_path(dir.clone())
                .backup_enabled(true)
                .cache(96, 20, 10)
                .max_commit_batch_entries(48)
                .register::<OrderV1>("orders"),
        )
        .build()?;
    let keep: OrderV1 = storage.domain::<OrderV1>().get(&keep_id)?;
    log::detail(format!(
        "keep notes contains marker: {}",
        keep.notes.contains("COMPOUND-KEEP")
    ));
    assert!(keep.notes.contains("COMPOUND-KEEP"));
    let hist2 = storage.domain::<OrderV1>().history(&keep_id)?;
    log::kv("history after compound crash", hist2.len());
    assert!(!hist2.is_empty());
    assert_no_nul_finals(&dir)?;
    report_dir("compound dir", &dir);
    log::ok("SCENARIO 10 PASSED — worst-case compound survived");
    Ok(wall.elapsed())
}

