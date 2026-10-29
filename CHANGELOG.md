# Changelog

All notable changes to clove1db. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before 1.0, a minor version (0.x.0) can break code or files; every such change is listed under **Breaking**.

## [0.1.0] — unreleased

The first minor release. It adds encryption of whole databases and of single fields, searching protected fields, changing the protection of an existing database, automatic indexes, typed queries, a durable change log and streaming imports from redb. Plain databases made by 0.0.126 open unchanged.

### Added

**Typed fields and queries**
- `#[derive(CloveFields)]` makes a typed handle for every field (`Note::score`), following serde renames, flattening, `Option`, lists, maps, nested structs and `chrono` types. `#[clove(as = Type)]` and `#[clove(skip)]` for fields serde cannot describe; `#[clove(epoch = "s" | "ms")]` for integer times.
- `domain.query()`: `filter`, `order_by` / `then_by`, `limit`, `page` with a cursor and `after`, `collect`, `one`, `exists`, `count`, `distinct`, `min`, `max`, `sum`, `group_by(..).count()`. Queries run on one snapshot and bypass the entity cache; `collect_in` / `page_in` share a `read_view_at_head()` snapshot.
- Conditions: `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `between`, `is_null`, `is_missing`, `exists`, `is_empty`, `text`, `contains`, `prefix`, `fuzzy`, list `any` / `all` / `at` / `len` / `elem_match`, `and` / `or`; transforms `trim`, `lowercase`, `normalize_arabic`; ordering by `LastWrite` and by `similarity`.
- Exact `sum`: `Sum::Integer(i128)` or `Sum::Decimal` in base ten, never a float; `SumOverflow`, `UnsupportedSum` and `DecimalSumLimit` errors.
- Unique constraints: `DatabaseConfig::unique::<E>(Unique::on(field).and(..))`, checked in the write's own transaction on every write path.
- `Entity::id_field()` to declare a field always equal to the row key, for direct lookups.
- `explain()`: the chosen plan, the alternatives and their estimated costs, without parameter values.

**Automatic indexes**
- One rebuildable `.inx` file per database. The cost-based optimizer builds equality, range, prefix, text, `contains`, fuzzy, order and fingerprint indexes when a query would pay for them; there is no manual index API.
- Results never depend on an index: missing, late or rebuilding indexes make queries slower, never different. `allow_stale()` opts into an index that is behind.
- `Storage::index_report()` describes every index without changing any. Unused indexes go idle; replaced ones stay readable until their successor is ready; fragmented files are compacted in the background.
- A long change backlog is rebuilt instead of replayed when that is cheaper (`index/rebuild/replay_budget` event), and an index under sustained overload is set aside until writes slow down.

**Durable change log**
- Every committed write gets the next number of a durable sequence (`journal_head`, `journal_stats`).
- Followers: `register_consumer`, `read_view_at_head`, `read_changes`, `ack`, `read_reset` / `read_reset_blobs` for `replace_table`. Positions survive restarts.
- `DatabaseConfig::journal_retention(Retention::Default | Unlimited | Limit { max_bytes })`; a follower too far behind is expired with `ClError::ConsumerExpired`.
- Attachment versions are immutable and referenced by the log: `ReadView::blob_reference`, `open_blob_version`.

**Whole-database encryption**
- `DatabaseConfig::encryption(EncryptionConfig)`: every file of the database (`.cldb`, `.cldb.bak`, `.inx`, attachments, side files) sealed in 4 KiB blocks with AES-256-GCM-SIV (default) or XChaCha20-Poly1305. No readable text, table name or redb signature remains.
- `EncryptionConfig::new(read, search)`, `.with_suite(..)`, `KeySource::Raw` and `KeySource::Password` (Argon2id 64 MiB / 3 passes by default, or scrypt; settings below a safe floor are refused).
- `encrypted_store::verify_encrypted_files` checks every block of closed files; `DatabaseConfig::encryption_verify_on_open(true)` does it at each open.
- `DatabaseConfig::encryption_tuning(EncryptionTuning { parallel_seal, threads })`: a commit's pages sealed on up to four threads (on by default).
- A new encrypted database is created under a temporary name and appears only when complete.
- `metadata::inspect::inspect_cldb_with` and `inspect_database_with` for encrypted files.

**Protected fields**
- `DatabaseConfig::field_encryption(keys)` and `register_sealed::<E>(table)`, with field attributes `#[clove(encrypt)]` (`Sealed<T>`), `#[clove(hash = "argon2id" | "scrypt")]` (`Hashed`), `#[clove(search_print)]` (`SearchPrint`), a stable `id = N` per field, and `normalize = "trim,lowercase,arabic"`.
- Values bound to their table, field and row: a moved value is `ClError::DataTampered`.
- `domain.read_grant()` to open values (`FieldRead` event per opening), `domain.verifier()` for `Hashed::verify` and `SearchPrint::matches` (`HashVerify` event), `domain.search_grant()` for fingerprint searches.
- Search by a whole value: `print = "full"`, `PrintHandle::print_eq` / `print_in`, and `Unique::on(handle.print_field())`.
- Search by a piece: `print = "parts"` with `window`, `grade` (`fast`, `balanced`, `protected`) or `bits`; `part_candidates` (candidates) and `part_search(..).run(..)` (`PartResults::Confirmed` with the read key, `Candidates` without; `FieldConfirm` event).
- `scan_sealed(&read_grant)` for conditions fingerprints cannot answer (`FieldScan` event).
- The keys file `{db}.keys` holding the sealed data key; `DatabaseConfig::field_keys_file(path)` to keep it only there.
- `register_sealed_blob::<E>(table)`: attachments of protected tables sealed in 64 KiB chunks, under `{db}.pblobs` with fingerprinted names.
- A program holding only the search key can read rows and match fingerprints, and is refused every write.

**Changing the protection**
- `migration::ChangeProtection`: plain ⇄ whole-database encryption, one key or cipher to another, and whole-database encryption ⇄ keys for protected fields only. `migration::ChangeFields`: seal, open, add or remove fingerprints, turn a field into a hash (`confirm_one_way()`).
- Both: `dry_run()` (what it would do, and a safe upper bound of the disk it needs), `execute()`, `available_bytes`, `protected_table::<E>(..)`, `wipe_originals(true)`, `on_event`.
- New files are written beside the old ones, compared row by row and file by file, and put in place by one crash-safe decision. Keys of hashes and fingerprint-only fields are carried over when the data key changes.

**Imports**
- `migration::stream_external`: `scan`, `stream` and `verify` copy a large redb table of JSON rows or of files into a database in batches, with memory checked before the run (`free_memory`, `reserve_memory`), fingerprint verification of every row, and `FilePrefix` for values that carry a fixed prefix before each file. The source is opened read only; repair (`Options::repair`) is for a copy.

**Memory, files and recovery**
- `DatabaseConfig::prefetch(..)`: read a file in order before redb opens it; automatic for files of 64 MiB or more.
- `DatabaseConfig::redb_cache_bytes(n)` caps redb's page cache per file; `quick_repair(true)` saves allocator state at each commit.
- `Storage::close()`, `Storage::open_report()` (size, open time, repair, format checks per file).
- `ClError::DatabaseInUse` for a file another program holds open; large allocations the library controls return an out-of-memory error instead of aborting.
- `Repository::list_map`, `Repository::get_uncached_as`, `Repository::commit_entities`.

**Events**
- `StorageConfig::event_sink` receives `LibraryEvent`s: slow queries (`slow_query_threshold`, 50 ms by default), non-unique `one()`, consumer expiry, index rebuilds and states, encryption and migration stages, and field openings, checks, confirmations and scans. Events carry names, counts and row keys, never values, keys or searched text.

**Examples**
- Seven examples replace the previous nineteen: getting started, queries and indexes, backup and batches, the change log, files and memory, encryption, migration and recovery. Each checks what it shows and fails if a check fails.

### Breaking

Compared with 0.0.126:

- **`ClError` has new variants:** `EncryptedOpenFailed`, `DataTampered`, `DatabaseInUse`, `BackupOpenFailed`, `OutOfMemory`, `ConsumerExpired`, `ConsumerNeedsRebuild`, `NonUnique`, `UniqueViolation`, `DuplicateGroups`, `IdFieldMismatch`, `InvalidCursor`, `SumOverflow`, `UnsupportedSum`, `DecimalSumLimit`. A `match` without a wildcard arm must handle them.
- **Attachments are read through `BlobReader`** (`Read + Seek`, `len()`) instead of `std::fs::File`.
- **`RedbOptions`** is no longer `Copy`, `PartialEq` or `Eq`, and has new fields (`encryption`, `verify_on_open`): build it with `..Default::default()`.
- **`BackupManager::new`** takes `&RedbOptions`; pass `&RedbOptions::default()` for a plain database.
- **`migration::DbMigrationRootIndex::tables`** is a `BTreeMap` (was `HashMap`), so `index.json` is written identically every time.
- **Inspection never repairs:** `inspect_cldb`, `inspect_cldb_with` and the migration readers open files read only; a file that needs repair returns `ClError::Validation` asking to open it normally first.
- **Quarantined side files keep their whole name:** `index.json.corrupt.{time}` (was `index.corrupt.{time}`).
- **A failed `Storage::build()` removes the database it was creating**, whatever its protection; nothing that existed before is touched.
- **A replaced side file is renamed in one step.** A `{name}.replace-old.{n}` file left by an older version that stopped mid-replacement is not looked for or restored.
- **The examples were rewritten**; the old example folders are gone.

Notes on the new APIs (not breaking for code written against 0.0.126): `LibraryEvent` and `PartResults` are `#[non_exhaustive]`; protected fields have `PrintHandle`, `ScanHandle` or `HashHandle` constants instead of `Field`, so queries on protected values do not compile; raw byte writes are refused on tables with protected fields; encrypted commits are always two-phase; rows of a table with protected fields are stored with their keys in alphabetical order.

### Changed

- Inspecting a database no longer writes to it.
- A failed open writes no migration file; the migration `index.json` is written only after the stored layouts are checked, and only when its content changed.
- Only the newest set-aside `.inx.invalid-<id>` file is kept.
- Strict durability flushes and renames every side file; corrupt or zeroed migration indexes are quarantined and rebuilt on open.

## [0.0.126] — 2026-10-06

### Changed

- **History records are stored as `json_wrapped_v2`.** The first `build()` converts existing `.cldb.bak` history on one checked copy (every record's metadata and bytes compared, counts and version/bulk metadata checked, the copy compacted), then replaces the original. A failed conversion removes its copy, records the reason in `_clove_meta.upgrade_log`, and retries next time. Releases before 0.0.126 cannot read the converted history; the `.cldb` data format is unchanged.
- Valid JSON is embedded byte for byte in `doc`; other bytes use `data_b64`; deletes have no payload. A history of 1,000 records went from 18.7 MB to 4.2 MB.
- Undated records get the conversion time once, flagged `date_from_migration: true`.
- Unreadable history records are reported as an error with their number and context. Table renames move history, counters and bulk metadata in one transaction.
- A version counter and its history record are written in one commit.

### Added

- `DatabaseManager::commit_batch_atomic`: every write and delete in one transaction, whatever the size.
- `OpenReport::format_check` for one-time format inspections and conversion copies.

### Breaking

- Public record and view structs include `date_from_migration`, and `OpenReport` includes `format_check`.

## Earlier versions

Versions 0.0.84 to 0.0.119 added in-place, cross-database and external migrations, migration outcomes (`MigrateOutcome`, `skip_record`), durability modes, cache budgets in bytes, and automatic upgrades of older files. See the repository history for details.
