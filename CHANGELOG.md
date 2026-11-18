# Changelog

All notable changes to clove1db. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before 1.0, a minor version (0.x.0) can break code or files; every such change is listed under **Breaking**.

## [0.1.7] — unreleased

An open database with no work is no longer written, the change of an empty table is recorded, and a table stays checked against its type after its first migration. The files and the API are unchanged: databases of 0.1.0 open as they are. One check at open is stricter, listed under **Breaking**.

### Fixed

- **An open database with no work is no longer written.** In 0.1.0 the indexer woke every 10 ms and, once a second, checkpointed the `.inx` file and rewrote the index catalog in the `.cldb` file of every open database, whether anything had changed or not. It now waits for work: a commit, an index request, a pause request and `close` wake it. A checkpoint is made only when changes were applied or an index was used since the last one, and the catalog is written only when it changed. A database with nothing to write still saves its uptime clock once a minute (the index deadlines count open time).
- A write after a quiet spell reaches the index as before (under a millisecond from the commit's return, measured), because the commit wakes the indexer. What has no wake (a clock deadline, an index's use count) is looked at every 200 ms at most.
- **The change of an empty table is recorded.** `migrate::<Old, New>()` in place on a table with no rows returned `Ok` and recorded nothing, so the table stayed refused under the new type. It now records the new shape (no rows moved) and the table opens.
- **The shape an in-place migration records is the new type's**, the one a later `build()` registers. It was the shape of the first moved row, which is another one when that row holds an optional field the type's default value leaves out.

### Breaking

- **A table changed in place is still checked at open.** In 0.1.0 a table was compared with its registered type only until its first migration: after it, any type opened the table with no error, and its rows failed to read later. Now `build()` returns `ClError::LayoutMismatch` for a type the table was not migrated to, as it does for a table that was never migrated. A program whose struct changed again with no migration must add that migration. Tables migrated by 0.1.0 open as before: the shape their last migration declared is accepted. Tables whose last migration brought rows in from another database or from a foreign file are left unchecked, as before.

### Changed

- Example `02_queries_and_indexes` prints how many files an idle database wrote in 3 s (none) and how long the index took to hold a write made after a quiet spell.
- Example `07_migration_and_recovery` prints the rows a migration moved, changes an empty table, and shows a third shape refused after the migration.

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
