use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::backup::view::HistoryDisplayMode;
use crate::durability::DurabilityMode;
use crate::fsutil::{
    is_corrupt_index_bytes, quarantine_corrupt_file, write_atomic, write_atomic_json,
};
use crate::encrypted_store::{EncryptionContext, SidecarFiles};
use crate::events::{EventSink, LibraryEvent};
use crate::migration::layout::FieldLayout;
use crate::migration::step_registry::MigrationStepRegistry;
use crate::migration::types::{
    layout_path, migration_dir_name, table_chain_dir, DbMigrationRootIndex, MigrationIndexEntry,
    MigrationManifest, TableChainIndex, TableChainSummary, MIGRATION_INDEX_VERSION,
};
use crate::units::{ClError, Result};
use crate::upgrade::legacy_migration::{is_legacy_root_index, upgrade_legacy_migration_index};

/// How the migration files are read and written: as plain files, or, in an encrypted database,
/// as sealed files under fingerprint names, bound to their logical place (`parts`).
#[derive(Debug, Clone)]
pub(crate) struct MigrationFiles {
    sealed: Option<SidecarFiles>,
}

impl MigrationFiles {
    pub(crate) fn plain() -> Self {
        Self { sealed: None }
    }

    pub(crate) fn new(dir: &Path, context: Option<EncryptionContext>) -> Self {
        Self { sealed: context.map(|c| SidecarFiles::new(dir, c)) }
    }

    pub(crate) fn is_sealed(&self) -> bool {
        self.sealed.is_some()
    }

    fn exists(&self, parts: &[&str], plain: &Path) -> bool {
        match &self.sealed {
            Some(s) => s.exists(parts).unwrap_or(false),
            None => plain.exists(),
        }
    }

    /// The content, `None` if there is no such file. A sealed file that was changed or moved is
    /// [`ClError::DataTampered`], never `None`.
    fn read(&self, parts: &[&str], plain: &Path) -> Result<Option<Vec<u8>>> {
        match &self.sealed {
            Some(s) => s.read(parts).map_err(ClError::from),
            None if plain.exists() => Ok(Some(fs::read(plain)?)),
            None => Ok(None),
        }
    }

    fn write(&self, parts: &[&str], plain: &Path, bytes: &[u8], durability: DurabilityMode) -> Result<()> {
        match &self.sealed {
            Some(s) => s.write(parts, bytes, durability.is_strict()).map_err(ClError::from),
            None => write_atomic(plain, bytes, durability),
        }
    }

    fn write_json<T: serde::Serialize>(&self, parts: &[&str], plain: &Path, value: &T, durability: DurabilityMode) -> Result<()> {
        match &self.sealed {
            Some(_) => self.write(parts, plain, &serde_json::to_vec_pretty(value)?, durability),
            None => write_atomic_json(plain, value, durability),
        }
    }

    /// Move a sealed file that failed to open out of the way (only for files the library can
    /// build again).
    fn set_aside(&self, parts: &[&str]) -> Result<()> {
        if let Some(s) = &self.sealed {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            s.set_aside(parts, stamp).map_err(ClError::from)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TableMigrationChain {
    pub table: String,
    pub dir: PathBuf,
    pub index: TableChainIndex,
    pub manifests: Vec<MigrationManifest>,
    pub durability: DurabilityMode,
    pub(crate) files: MigrationFiles,
}

#[derive(Debug, Clone)]
pub struct DbMigrationIndex {
    pub dir: PathBuf,
    pub db_name: String,
    pub root: DbMigrationRootIndex,
    pub tables: HashMap<String, TableMigrationChain>,
    pub durability: DurabilityMode,
    pub(crate) files: MigrationFiles,
}

impl DbMigrationIndex {
    pub fn migration_path(db_dir: &Path, db_name: &str) -> PathBuf {
        db_dir.join(migration_dir_name(db_name))
    }

    pub fn load(db_dir: &Path, db_name: &str, registered_tables: &[String]) -> Result<Self> {
        Self::load_with_durability(db_dir, db_name, registered_tables, DurabilityMode::Strict)
    }

    pub fn load_with_durability(
        db_dir: &Path,
        db_name: &str,
        registered_tables: &[String],
        durability: DurabilityMode,
    ) -> Result<Self> {
        Self::load_with_encryption(db_dir, db_name, registered_tables, durability, None, &EventSink::default())
    }

    /// [`DbMigrationIndex::load_with_durability`] for a database that may be encrypted: with a
    /// context the files are sealed. A sealed file that fails to open is an error
    /// ([`ClError::DataTampered`]) unless it can be built again from the others (the root index),
    /// in which case it is set aside, an event is sent, and it is rebuilt.
    pub(crate) fn load_with_encryption(
        db_dir: &Path,
        db_name: &str,
        registered_tables: &[String],
        durability: DurabilityMode,
        context: Option<EncryptionContext>,
        events: &EventSink,
    ) -> Result<Self> {
        let dir = Self::migration_path(db_dir, db_name);
        let files = MigrationFiles::new(&dir, context);
        if files.is_sealed() {
            return Self::load_sealed(dir, db_name, registered_tables, durability, files, events);
        }
        if !dir.exists() {
            return Ok(Self::empty(dir, db_name, registered_tables, durability));
        }

        let root_path = dir.join("index.json");
        if root_path.exists() {
            let data = fs::read(&root_path)?;
            if !is_corrupt_index_bytes(&data) {
                if let Ok(text) = std::str::from_utf8(&data) {
                    if is_legacy_root_index(text) {
                        upgrade_legacy_migration_index(
                            db_dir,
                            db_name,
                            registered_tables,
                            durability,
                        )?;
                    }
                }
            }
        } else if !dir.join("tables").exists() {
            return Err(ClError::LegacyMigrationFormat {
                path: root_path.display().to_string(),
            });
        }

        let root: DbMigrationRootIndex = match load_or_recover_root(&root_path, db_name)? {
            Some(root) => root,
            None => DbMigrationRootIndex {
                index_version: MIGRATION_INDEX_VERSION,
                db_name: db_name.to_string(),
                tables: BTreeMap::new(),
            },
        };

        let mut tables = HashMap::new();
        for table in registered_tables {
            let chain = Self::load_table_chain(&dir, table, durability)?;
            tables.insert(table.clone(), chain);
        }

        Ok(Self {
            dir,
            db_name: db_name.to_string(),
            root,
            tables,
            durability,
            files: MigrationFiles::plain(),
        })
    }

    /// The sealed form of loading. Nothing is read from plain names.
    fn load_sealed(
        dir: PathBuf,
        db_name: &str,
        registered_tables: &[String],
        durability: DurabilityMode,
        files: MigrationFiles,
        events: &EventSink,
    ) -> Result<Self> {
        let plain = dir.join("index.json");
        // The root index only summarises the table chains and is filled in again from them, so a
        // root that fails to open is set aside, reported, and built again.
        let root = match files.read(&["index.json"], &plain) {
            Ok(Some(bytes)) => match serde_json::from_slice::<DbMigrationRootIndex>(&bytes) {
                Ok(root) if root.index_version == MIGRATION_INDEX_VERSION => Some(root),
                _ => {
                    files.set_aside(&["index.json"])?;
                    events.emit(&LibraryEvent::Encryption { event: "encryption/sidecar_set_aside", file: "sidecar" });
                    None
                }
            },
            Ok(None) => None,
            Err(ClError::DataTampered) => {
                files.set_aside(&["index.json"])?;
                events.emit(&LibraryEvent::Encryption { event: "encryption/sidecar_set_aside", file: "sidecar" });
                None
            }
            Err(e) => return Err(e),
        };
        let root = root.unwrap_or_else(|| DbMigrationRootIndex {
            index_version: MIGRATION_INDEX_VERSION,
            db_name: db_name.to_string(),
            tables: BTreeMap::new(),
        });
        let mut tables = HashMap::new();
        for table in registered_tables {
            tables.insert(table.clone(), Self::load_table_chain_sealed(&dir, table, durability, &files)?);
        }
        Ok(Self { dir, db_name: db_name.to_string(), root, tables, durability, files })
    }

    /// A table's chain is real history (versions and migration records): if it does not open, the
    /// open fails; nothing is invented in its place.
    fn load_table_chain_sealed(
        migration_dir: &Path,
        table: &str,
        durability: DurabilityMode,
        files: &MigrationFiles,
    ) -> Result<TableMigrationChain> {
        let table_dir = table_chain_dir(migration_dir, table);
        let index_path = table_dir.join("index.json");
        let index: TableChainIndex = match files.read(&["tables", table, "index.json"], &index_path)? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| ClError::DataTampered)?,
            None => TableChainIndex {
                schema_id: table.to_string(),
                current_version: 1,
                initial_version: 1,
                chain: Vec::new(),
            },
        };
        let mut manifests = Vec::new();
        for entry in &index.chain {
            let parts = ["tables", table, entry.migration_id.as_str(), "manifest.json"];
            match files.read(&parts, &table_dir.join(&entry.migration_id).join("manifest.json"))? {
                Some(bytes) => manifests.push(serde_json::from_slice::<MigrationManifest>(&bytes).map_err(|_| ClError::DataTampered)?),
                // the index lists this migration, so its record must be there: a missing one is
                // removed history, not an empty one
                None => return Err(ClError::DataTampered),
            }
        }
        Ok(TableMigrationChain {
            table: table.to_string(),
            dir: table_dir,
            index,
            manifests,
            durability,
            files: files.clone(),
        })
    }

    fn load_table_chain(
        migration_dir: &Path,
        table: &str,
        durability: DurabilityMode,
    ) -> Result<TableMigrationChain> {
        let table_dir = table_chain_dir(migration_dir, table);
        let index_path = table_dir.join("index.json");

        let index: TableChainIndex = if index_path.exists() {
            match load_or_recover_table_index(&index_path, table)? {
                Some(index) => index,
                None => TableChainIndex {
                    schema_id: table.to_string(),
                    current_version: 1,
                    initial_version: 1,
                    chain: Vec::new(),
                },
            }
        } else {
            TableChainIndex {
                schema_id: table.to_string(),
                current_version: 1,
                initial_version: 1,
                chain: Vec::new(),
            }
        };

        let mut manifests = Vec::new();
        for entry in &index.chain {
            let manifest_path = table_dir
                .join(&entry.migration_id)
                .join("manifest.json");
            if manifest_path.exists() {
                let data = fs::read(&manifest_path)?;
                if is_corrupt_index_bytes(&data) {
                    quarantine_corrupt_file(
                        &manifest_path,
                        "zeroed or invalid migration manifest",
                    )?;
                    continue;
                }
                if let Ok(manifest) = serde_json::from_slice::<MigrationManifest>(&data) {
                    manifests.push(manifest);
                } else {
                    quarantine_corrupt_file(&manifest_path, "unparseable migration manifest")?;
                }
            }
        }

        Ok(TableMigrationChain {
            table: table.to_string(),
            dir: table_dir,
            index,
            manifests,
            durability,
            files: MigrationFiles::plain(),
        })
    }

    fn empty(
        dir: PathBuf,
        db_name: &str,
        tables: &[String],
        durability: DurabilityMode,
    ) -> Self {
        let mut table_map = HashMap::new();
        let mut summaries = BTreeMap::new();
        for t in tables {
            summaries.insert(
                t.clone(),
                TableChainSummary {
                    schema_id: t.clone(),
                    current_version: 1,
                    initial_version: 1,
                },
            );
            table_map.insert(
                t.clone(),
                TableMigrationChain {
                    table: t.clone(),
                    dir: table_chain_dir(&dir, t),
                    index: TableChainIndex {
                        schema_id: t.clone(),
                        current_version: 1,
                        initial_version: 1,
                        chain: Vec::new(),
                    },
                    manifests: Vec::new(),
                    durability,
                    files: MigrationFiles::plain(),
                },
            );
        }
        Self {
            dir,
            db_name: db_name.to_string(),
            root: DbMigrationRootIndex {
                index_version: MIGRATION_INDEX_VERSION,
                db_name: db_name.to_string(),
                tables: summaries,
            },
            tables: table_map,
            durability,
            files: MigrationFiles::plain(),
        }
    }

    pub fn ensure_table(&mut self, table: &str, layout: &FieldLayout) -> Result<()> {
        self.ensure_table_unpersisted(table, layout)?;
        self.persist_root()
    }

    /// [`ensure_table`](Self::ensure_table) without writing the root index. The open pipeline calls this and writes the root
    /// (`persist_root`) only after every stored layout has been checked, so an open that fails the check changes no migration file.
    pub(crate) fn ensure_table_unpersisted(&mut self, table: &str, layout: &FieldLayout) -> Result<()> {
        if !self.tables.contains_key(table) {
            let chain = TableMigrationChain {
                table: table.to_string(),
                dir: table_chain_dir(&self.dir, table),
                index: TableChainIndex {
                    schema_id: table.to_string(),
                    current_version: 1,
                    initial_version: 1,
                    chain: Vec::new(),
                },
                manifests: Vec::new(),
                durability: self.durability,
                files: self.files.clone(),
            };
            self.tables.insert(table.to_string(), chain);
            self.root.tables.insert(
                table.to_string(),
                TableChainSummary {
                    schema_id: table.to_string(),
                    current_version: 1,
                    initial_version: 1,
                },
            );
        }
        {
            let chain = self.tables.get_mut(table).unwrap();
            chain.ensure_layout(1, layout)?;
        }
        Ok(())
    }

    pub fn table_chain(&self, table: &str) -> Result<&TableMigrationChain> {
        self.tables
            .get(table)
            .ok_or_else(|| ClError::MigrationError(format!("table chain '{table}' not found")))
    }

    pub fn table_chain_mut(&mut self, table: &str) -> Result<&mut TableMigrationChain> {
        self.tables
            .get_mut(table)
            .ok_or_else(|| ClError::MigrationError(format!("table chain '{table}' not found")))
    }

    pub fn persist_root(&mut self) -> Result<()> {
        if !self.files.is_sealed() {
            fs::create_dir_all(&self.dir)?;
        }
        for (name, chain) in &self.tables {
            self.root.tables.insert(
                name.clone(),
                TableChainSummary {
                    schema_id: chain.index.schema_id.clone(),
                    current_version: chain.index.current_version,
                    initial_version: chain.index.initial_version,
                },
            );
        }
        let path = self.dir.join("index.json");
        let bytes = serde_json::to_vec_pretty(&self.root)?;
        if self.files.is_sealed() {
            if let Ok(Some(existing)) = self.files.read(&["index.json"], &path) {
                if existing == bytes {
                    return Ok(());
                }
            }
            return self.files.write(&["index.json"], &path, &bytes, self.durability);
        }
        if path.exists() {
            if let Ok(existing) = fs::read(&path) {
                if existing == bytes {
                    return Ok(());
                }
            }
        }
        write_atomic(&path, &bytes, self.durability)?;
        Ok(())
    }

    pub fn append_manifest(
        &mut self,
        table: &str,
        manifest: MigrationManifest,
        snapshot: Option<&[(String, Vec<u8>)]>,
        new_layout: Option<&FieldLayout>,
    ) -> Result<()> {
        let chain = self.table_chain_mut(table)?;
        chain.append(manifest, snapshot)?;
        if let Some(layout) = new_layout {
            chain.ensure_layout(chain.index.current_version, layout)?;
        }
        self.persist_root()?;
        Ok(())
    }
}

impl TableMigrationChain {
    pub fn current_version(&self) -> u32 {
        self.index.current_version
    }

    pub fn schema_id(&self) -> &str {
        &self.index.schema_id
    }

    pub fn ensure_layout(&self, version: u32, layout: &FieldLayout) -> Result<()> {
        if self.files.is_sealed() {
            let layout_name = format!("v{version}.json");
            let layout_parts = ["tables", self.table.as_str(), "layouts", layout_name.as_str()];
            let path = layout_path(&self.dir, version);
            if !self.files.exists(&layout_parts, &path) {
                self.files.write_json(&layout_parts, &path, layout, self.durability)?;
            }
            let index_parts = ["tables", self.table.as_str(), "index.json"];
            let index_path = self.dir.join("index.json");
            let bytes = serde_json::to_vec_pretty(&self.index)?;
            if let Ok(Some(existing)) = self.files.read(&index_parts, &index_path) {
                if existing == bytes {
                    return Ok(());
                }
            }
            return self.files.write(&index_parts, &index_path, &bytes, self.durability);
        }
        fs::create_dir_all(self.dir.join("layouts"))?;
        let path = layout_path(&self.dir, version);
        if !path.exists() {
            write_atomic_json(&path, layout, self.durability)?;
        }
        fs::create_dir_all(&self.dir)?;
        let index_path = self.dir.join("index.json");
        let bytes = serde_json::to_vec_pretty(&self.index)?;
        if index_path.exists() {
            if let Ok(existing) = fs::read(&index_path) {
                if existing == bytes {
                    return Ok(());
                }
            }
        }
        write_atomic(&index_path, &bytes, self.durability)?;
        Ok(())
    }

    /// A stored layout of this table (the file for `version`), or `None`. A sealed one that was
    /// changed is [`ClError::DataTampered`].
    pub(crate) fn read_layout(&self, version: u32) -> Result<Option<FieldLayout>> {
        let name = format!("v{version}.json");
        let parts = ["tables", self.table.as_str(), "layouts", name.as_str()];
        match self.files.read(&parts, &layout_path(&self.dir, version))? {
            Some(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(|e| {
                    if self.files.is_sealed() { ClError::DataTampered } else { ClError::from(e) }
                })?,
            )),
            None => Ok(None),
        }
    }

    pub fn schema_version_for_backup(&self, backup_version: u64) -> u32 {
        for manifest in &self.manifests {
            if backup_version <= manifest.version_scope.backup_versions_to {
                return manifest.from.schema_version;
            }
        }
        self.index.current_version
    }

    pub fn migration_id_for_version(&self, backup_version: u64) -> Option<&str> {
        for manifest in &self.manifests {
            if backup_version <= manifest.version_scope.backup_versions_to {
                return Some(&manifest.migration_id);
            }
        }
        None
    }

    pub fn is_restorable(&self, backup_version: u64) -> bool {
        self.schema_version_for_backup(backup_version) == self.index.current_version
    }

    pub fn decode_to_json(
        &self,
        bytes: &[u8],
        backup_version: u64,
        mode: HistoryDisplayMode,
        registry: &MigrationStepRegistry,
    ) -> Result<(Value, Vec<String>)> {
        let era_version = self.schema_version_for_backup(backup_version);
        let mut decode_path = vec![format!("{}@{}", self.index.schema_id, era_version)];

        match mode {
            HistoryDisplayMode::AsStored => {
                let json = serde_json::from_slice(bytes)?;
                Ok((json, decode_path))
            }
            HistoryDisplayMode::Normalized => {
                let mut current_bytes = bytes.to_vec();
                let mut current_ver = era_version;

                for manifest in &self.manifests {
                    if current_ver == manifest.from.schema_version {
                        let decoder = registry
                            .get_by_layout(&manifest.from_layout_hash, &manifest.to_layout_hash)
                            .map_err(|_| ClError::DecoderNotFound {
                                from_layout_hash: manifest.from_layout_hash.clone(),
                                to_layout_hash: manifest.to_layout_hash.clone(),
                                migration_id: manifest.migration_id.clone(),
                            })?;
                        current_bytes = decoder.migrate_bytes(&current_bytes)?;
                        current_ver = manifest.to.schema_version;
                        decode_path.push(format!("{}@{}", self.index.schema_id, current_ver));
                    }
                    if current_ver == self.index.current_version {
                        break;
                    }
                }

                let json = serde_json::from_slice(&current_bytes)?;
                Ok((json, decode_path))
            }
        }
    }

    pub fn append(
        &mut self,
        manifest: MigrationManifest,
        snapshot: Option<&[(String, Vec<u8>)]>,
    ) -> Result<()> {
        let mig_dir = self.dir.join(&manifest.migration_id);
        if !self.files.is_sealed() {
            fs::create_dir_all(mig_dir.join("refs"))?;
        }

        if let Some(entries) = snapshot {
            let ref_name = manifest
                .version_scope
                .primary_snapshot_ref
                .clone()
                .unwrap_or_else(|| format!("primary_before_{}", manifest.migration_id));
            let ref_path = mig_dir.join("refs").join(format!("{ref_name}.json"));
            let snapshot_data: Vec<(String, String)> = entries
                .iter()
                .map(|(k, v)| (k.clone(), hex_encode(v)))
                .collect();
            let ref_file = format!("{ref_name}.json");
            let ref_parts = ["tables", self.table.as_str(), manifest.migration_id.as_str(), "refs", ref_file.as_str()];
            self.files.write_json(&ref_parts, &ref_path, &snapshot_data, self.durability)?;
        }

        let manifest_parts = ["tables", self.table.as_str(), manifest.migration_id.as_str(), "manifest.json"];
        self.files.write_json(&manifest_parts, &mig_dir.join("manifest.json"), &manifest, self.durability)?;

        let order = (self.index.chain.len() + 1) as u32;
        self.index.chain.push(MigrationIndexEntry {
            migration_id: manifest.migration_id.clone(),
            order,
        });
        self.index.current_version = manifest.to.schema_version;
        self.manifests.push(manifest);

        if !self.files.is_sealed() {
            fs::create_dir_all(&self.dir)?;
        }
        self.files.write_json(
            &["tables", self.table.as_str(), "index.json"],
            &self.dir.join("index.json"),
            &self.index,
            self.durability,
        )?;
        Ok(())
    }
}

fn load_or_recover_root(path: &Path, db_name: &str) -> Result<Option<DbMigrationRootIndex>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(path)?;
    if is_corrupt_index_bytes(&data) {
        quarantine_corrupt_file(path, "zeroed or invalid root migration index")?;
        return Ok(None);
    }
    match serde_json::from_slice::<DbMigrationRootIndex>(&data) {
        Ok(parsed) => {
            if parsed.index_version != MIGRATION_INDEX_VERSION {
                return Err(ClError::LegacyMigrationFormat {
                    path: path.display().to_string(),
                });
            }
            let _ = db_name;
            Ok(Some(parsed))
        }
        Err(e) => {
            quarantine_corrupt_file(path, &format!("unparseable root index: {e}"))?;
            Ok(None)
        }
    }
}

fn load_or_recover_table_index(path: &Path, table: &str) -> Result<Option<TableChainIndex>> {
    let data = fs::read(path)?;
    if is_corrupt_index_bytes(&data) {
        quarantine_corrupt_file(
            path,
            &format!("zeroed or invalid table migration index for '{table}'"),
        )?;
        return Ok(None);
    }
    match serde_json::from_slice::<TableChainIndex>(&data) {
        Ok(index) => Ok(Some(index)),
        Err(e) => {
            quarantine_corrupt_file(path, &format!("unparseable table index '{table}': {e}"))?;
            Ok(None)
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{:02x}", b);
        s
    })
}

/// Legacy alias for compatibility during transition.
pub type MigrationChain = DbMigrationIndex;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::types::{MigrationKind, SchemaRef, TargetConflictPolicy, VersionScope};

    #[test]
    fn schema_version_for_backup_respects_chain() {
        let chain = TableMigrationChain {
            table: "products".into(),
            dir: PathBuf::from("/tmp"),
            index: TableChainIndex {
                schema_id: "products".into(),
                current_version: 3,
                initial_version: 1,
                chain: vec![],
            },
            manifests: vec![
                MigrationManifest {
                    migration_id: "mig-001".into(),
                    parent_migration_id: None,
                    timestamp: 1,
                    kind: MigrationKind::InPlaceEvolve,
                    from: SchemaRef {
                        db: "d".into(),
                        table: "products".into(),
                        schema_id: "products".into(),
                        schema_version: 1,
                    },
                    to: SchemaRef {
                        db: "d".into(),
                        table: "products".into(),
                        schema_id: "products".into(),
                        schema_version: 2,
                    },
                    version_scope: VersionScope {
                        backup_versions_from: 1,
                        backup_versions_to: 10,
                        scope_table: "products".into(),
                        primary_snapshot_ref: None,
                    },
                    from_layout_hash: "hash-v1".into(),
                    to_layout_hash: "hash-v2".into(),
                    target_conflict_policy: TargetConflictPolicy::Fail,
                    table_rename: None,
                    field_diff: None,
                },
                MigrationManifest {
                    migration_id: "mig-002".into(),
                    parent_migration_id: Some("mig-001".into()),
                    timestamp: 2,
                    kind: MigrationKind::InPlaceEvolve,
                    from: SchemaRef {
                        db: "d".into(),
                        table: "products".into(),
                        schema_id: "products".into(),
                        schema_version: 2,
                    },
                    to: SchemaRef {
                        db: "d".into(),
                        table: "products".into(),
                        schema_id: "products".into(),
                        schema_version: 3,
                    },
                    version_scope: VersionScope {
                        backup_versions_from: 11,
                        backup_versions_to: 20,
                        scope_table: "products".into(),
                        primary_snapshot_ref: None,
                    },
                    from_layout_hash: "hash-v2".into(),
                    to_layout_hash: "hash-v3".into(),
                    target_conflict_policy: TargetConflictPolicy::Fail,
                    table_rename: None,
                    field_diff: None,
                },
            ],
            durability: DurabilityMode::Strict,
            files: MigrationFiles::plain(),
        };

        assert_eq!(chain.schema_version_for_backup(5), 1);
        assert_eq!(chain.schema_version_for_backup(15), 2);
        assert_eq!(chain.schema_version_for_backup(25), 3);
        assert!(!chain.is_restorable(5));
        assert!(chain.is_restorable(25));
    }

    #[test]
    fn recovers_from_nul_root_index() {
        let dir = PathBuf::from("./target/test_mig_nul_recover");
        let _ = fs::remove_dir_all(&dir);
        let mig = dir.join("demo.migration");
        fs::create_dir_all(mig.join("tables/items")).unwrap();
        fs::write(mig.join("index.json"), &[0u8; 64]).unwrap();
        fs::write(mig.join("tables/items/index.json"), &[0u8; 32]).unwrap();

        let tables = vec!["items".to_string()];
        let loaded =
            DbMigrationIndex::load_with_durability(&dir, "demo", &tables, DurabilityMode::Fast)
                .unwrap();
        assert_eq!(loaded.tables["items"].index.schema_id, "items");
        assert!(!mig.join("index.json").exists() || {
            let data = fs::read(mig.join("index.json")).unwrap_or_default();
            !is_corrupt_index_bytes(&data) || data.is_empty()
        });
    }
}
