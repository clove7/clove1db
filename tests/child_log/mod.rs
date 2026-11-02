//! What a child program prints is kept in a file beside its folder (`<folder>.child.log`), not thrown away and not in a pipe nobody reads
//! (a full pipe would stop the child). A failure message shows the exit code and what the child printed.
#![allow(dead_code)]
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};

pub fn path(root: &Path) -> PathBuf {
    let mut name = root.file_name().unwrap_or_default().to_os_string();
    name.push(".child.log");
    root.with_file_name(name)
}

/// For `.stdout(..)` and `.stderr(..)` of the child that works in `root`: both streams go to the same file.
pub fn out(root: &Path) -> Stdio {
    match std::fs::OpenOptions::new().create(true).append(true).open(path(root)) {
        Ok(file) => Stdio::from(file),
        Err(_) => Stdio::null(),
    }
}

/// The last part of what the child printed.
pub fn said(root: &Path) -> String {
    let text = std::fs::read_to_string(path(root)).unwrap_or_default();
    let start = text.char_indices().rev().nth(3000).map_or(0, |(i, _)| i);
    text[start..].to_string()
}

/// For a failure message: the exit code, what it means if it is 1, and what the child printed.
pub fn why(root: &Path, status: ExitStatus) -> String {
    let hint = if status.code() == Some(1) { " (exit code 1 on Windows means the program was ended from outside)" } else { "" };
    format!("{status:?}{hint}; the child printed: {}", said(root))
}

/// Removes the folder and the log beside it.
pub fn clean(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_file(path(root));
}
