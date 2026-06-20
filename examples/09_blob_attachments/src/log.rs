pub fn banner(title: &str) {
    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("  {title}");
    println!("═══════════════════════════════════════════════════════════");
}

pub fn step(title: &str) {
    println!();
    println!("── {title} ──");
}

pub fn ok(msg: impl AsRef<str>) {
    println!("  ✓ {}", msg.as_ref());
}

pub fn line(msg: impl AsRef<str>) {
    println!("  {}", msg.as_ref());
}

pub fn kv(key: &str, value: impl std::fmt::Display) {
    println!("  {key}: {value}");
}
