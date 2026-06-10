use serde::{Deserialize, Serialize};

pub const META_TABLE: &str = "_clove_meta";
pub const META_KEY: &str = "meta";
pub const FRAMEWORK_ID: &str = "clove1db";
pub const META_VERSION: u32 = 2;
pub const BACKUP_FORMAT_JSON: &str = "json_wrapped_v1";
pub const BACKUP_PRE_UPGRADE_SUFFIX: &str = ".pre-upgrade";
pub const BACKUP_UPGRADING_SUFFIX: &str = ".upgrading";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileEra {
    Legacy042,
    Clove049,
    Current,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupFormat {
    JsonWrappedV1,
    Unknown,
}

impl BackupFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JsonWrappedV1 => BACKUP_FORMAT_JSON,
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableMeta {
    pub name: String,
    pub schema_id: String,
    pub schema_version: u32,
    pub layout_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeLogEntry {
    pub step: String,
    pub at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloveMeta {
    pub framework: String,
    pub meta_version: u32,
    pub framework_version: String,
    pub file_era: FileEra,
    pub db_name: String,
    pub backup_enabled: bool,
    pub backup_format: String,
    pub backup_upgraded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_pre_upgrade_path: Option<String>,
    pub tables: Vec<TableMeta>,
    pub upgrade_complete: bool,
    #[serde(default)]
    pub upgrade_log: Vec<UpgradeLogEntry>,
}

impl CloveMeta {
    pub fn new(
        db_name: impl Into<String>,
        file_era: FileEra,
        backup_enabled: bool,
        tables: Vec<TableMeta>,
    ) -> Self {
        Self {
            framework: FRAMEWORK_ID.to_string(),
            meta_version: META_VERSION,
            framework_version: env!("CARGO_PKG_VERSION").to_string(),
            file_era,
            db_name: db_name.into(),
            backup_enabled,
            backup_format: if backup_enabled {
                BackupFormat::JsonWrappedV1.as_str().to_string()
            } else {
                BackupFormat::Unknown.as_str().to_string()
            },
            backup_upgraded: !backup_enabled,
            backup_pre_upgrade_path: None,
            tables,
            upgrade_complete: false,
            upgrade_log: Vec::new(),
        }
    }

    pub fn table_meta(&self, table: &str) -> Option<&TableMeta> {
        self.tables.iter().find(|t| t.name == table)
    }

    pub fn push_log(&mut self, step: impl Into<String>, detail: Option<String>) {
        self.upgrade_log.push(UpgradeLogEntry {
            step: step.into(),
            at: chrono::Utc::now().timestamp(),
            detail,
        });
    }
}
