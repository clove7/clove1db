use std::io::{self, Write};
use std::time::{Duration, Instant};

pub fn banner(title: &str) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║ {:<72} ║", title);
    println!("╚══════════════════════════════════════════════════════════════════════════╝");
    let _ = io::stdout().flush();
}

pub fn scenario_header(n: u32, title: &str, goal: impl AsRef<str>) {
    let goal = goal.as_ref();
    println!();
    println!("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("┃  SCENARIO {n:02} — {title:<60} ┃");
    println!("┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫");
    println!("┃  Goal: {goal:<66} ┃");
    println!("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    let _ = io::stdout().flush();
}

pub fn phase(name: impl AsRef<str>) {
    println!();
    println!("  ▸ PHASE: {}", name.as_ref());
    let _ = io::stdout().flush();
}

pub fn action(msg: impl AsRef<str>) {
    println!("    → {}", msg.as_ref());
    let _ = io::stdout().flush();
}

pub fn detail(msg: impl AsRef<str>) {
    println!("      · {}", msg.as_ref());
    let _ = io::stdout().flush();
}

pub fn kv(key: &str, value: impl std::fmt::Display) {
    println!("      · {key:<28} {value}");
    let _ = io::stdout().flush();
}

pub fn ok(msg: impl AsRef<str>) {
    println!("    ✓ {}", msg.as_ref());
    let _ = io::stdout().flush();
}

pub fn warn(msg: impl AsRef<str>) {
    println!("    ! {}", msg.as_ref());
    let _ = io::stdout().flush();
}

pub fn progress(done: usize, total: usize, label: &str) {
    if total == 0 {
        return;
    }
    let pct = (done * 100) / total;
    if done == total || done % ((total / 20).max(1)) == 0 || done == 1 {
        println!("      … {label}: {done}/{total} ({pct}%)");
        let _ = io::stdout().flush();
    }
}

pub struct Timer {
    label: String,
    start: Instant,
}

impl Timer {
    pub fn start(label: impl Into<String>) -> Self {
        let label = label.into();
        println!("    ⏱  start: {label}");
        let _ = io::stdout().flush();
        Self {
            label,
            start: Instant::now(),
        }
    }

    pub fn finish(self) -> Duration {
        let elapsed = self.start.elapsed();
        println!(
            "    ⏱  done: {} — took {}",
            self.label,
            format_dur(elapsed)
        );
        let _ = io::stdout().flush();
        elapsed
    }
}

pub fn format_dur(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{:.2} s", ms as f64 / 1000.0)
    } else {
        let s = ms / 1000;
        format!("{}m {:02}s", s / 60, s % 60)
    }
}

pub fn bytes_human(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    let f = n as f64;
    if f >= MB {
        format!("{:.2} MB", f / MB)
    } else if f >= KB {
        format!("{:.2} KB", f / KB)
    } else {
        format!("{n} B")
    }
}

pub fn dir_size(path: &std::path::Path) -> u64 {
    fn walk(p: &std::path::Path) -> u64 {
        let mut total = 0u64;
        let Ok(rd) = std::fs::read_dir(p) else {
            return 0;
        };
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                total += walk(&path);
            } else if let Ok(meta) = e.metadata() {
                total += meta.len();
            }
        }
        total
    }
    walk(path)
}

pub fn summary_box(title: &str, lines: &[String]) {
    println!();
    println!("  ┌─ {title} {}", "─".repeat(60usize.saturating_sub(title.len())));
    for line in lines {
        println!("  │  {line}");
    }
    println!("  └{}", "─".repeat(68));
    let _ = io::stdout().flush();
}

pub fn final_report(total: Duration, scenario_times: &[(String, Duration)]) {
    banner("FINAL REPORT — Crash Durability Stress Run");
    let mut lines = Vec::new();
    lines.push(format!("Total wall time: {}", format_dur(total)));
    lines.push(String::new());
    lines.push("Per-scenario timing:".into());
    for (name, d) in scenario_times {
        lines.push(format!("  {name:<40} {}", format_dur(*d)));
    }
    summary_box("Results", &lines);
    println!();
    println!("  ALL SCENARIOS PASSED — data integrity + crash recovery verified.");
    println!();
    let _ = io::stdout().flush();
}
