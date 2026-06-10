use std::path::{Path, PathBuf};

pub const BASE_DIR: &str = "./examples_data/08_inspect_upgrade";

pub fn base() -> PathBuf {
    PathBuf::from(BASE_DIR)
}

pub fn fake_shop_dir() -> PathBuf {
    base().join("fake").join("fake_shop.cldb")
}

pub fn foreign_cldb() -> PathBuf {
    base().join("external").join("foreign.cldb")
}

pub fn era_042_retail_dir() -> PathBuf {
    base().join("era_042").join("retail")
}

pub fn era_042_retail_cldb() -> PathBuf {
    era_042_retail_dir().join("retail.cldb")
}

pub fn era_042_attachments_dir() -> PathBuf {
    base().join("era_042").join("attachments")
}

pub fn era_042_attachments_cldb() -> PathBuf {
    era_042_attachments_dir().join("attachments.cldb")
}

pub fn era_049_retail_dir() -> PathBuf {
    base().join("era_049").join("retail")
}

pub fn era_049_retail_cldb() -> PathBuf {
    era_049_retail_dir().join("retail.cldb")
}

pub fn era_056_retail_dir() -> PathBuf {
    base().join("era_056").join("retail")
}

pub fn era_056_retail_cldb() -> PathBuf {
    era_056_retail_dir().join("retail.cldb")
}

pub fn upgraded_042_dir() -> PathBuf {
    base().join("upgraded").join("retail_042")
}

pub fn upgraded_049_dir() -> PathBuf {
    base().join("upgraded").join("retail_049")
}

pub fn upgraded_attachments_dir() -> PathBuf {
    base().join("upgraded").join("attachments")
}

pub fn cache_off_dir() -> PathBuf {
    base().join("upgraded").join("cache_off")
}

pub fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}
