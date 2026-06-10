use crate::paths;

pub fn create() -> std::io::Result<()> {
    let dir = paths::fake_shop_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(())
}
