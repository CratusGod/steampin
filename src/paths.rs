//! Where RustyDPI keeps things, and its log. Tests point these at temp folders.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct Paths { pub install_dir: PathBuf, pub data_dir: PathBuf, pub hosts: PathBuf }

impl Paths {
    pub fn default_paths() -> Paths {
        let pf = std::env::var("ProgramW6432").or_else(|_| std::env::var("ProgramFiles")).unwrap_or_else(|_| "C:\\Program Files".into());
        let pd = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        Paths { install_dir: Path::new(&pf).join("RustyDPI"), data_dir: Path::new(&pd).join("RustyDPI"), hosts: crate::hosts::system_path() }
    }
    pub fn exe(&self) -> PathBuf { self.install_dir.join("RustyDPI.exe") }
    pub fn zapret_dir(&self) -> PathBuf { self.install_dir.join("zapret") }
    pub fn config(&self) -> PathBuf { self.data_dir.join("config.json") }
    pub fn state(&self) -> PathBuf { self.data_dir.join("state.json") }
    pub fn settings(&self) -> PathBuf { self.data_dir.join("settings.json") }
    pub fn status(&self) -> PathBuf { self.data_dir.join("status.json") }
    pub fn last_check(&self) -> PathBuf { self.data_dir.join("last-check.txt") }
    pub fn log(&self) -> PathBuf { self.data_dir.join("log.txt") }
    pub fn backups(&self) -> PathBuf { self.data_dir.join("backups") }
    pub fn lists(&self) -> PathBuf { self.data_dir.join("lists") }
    pub fn bypass(&self) -> crate::bypass::BypassFiles { crate::bypass::BypassFiles { zapret: self.zapret_dir(), lists: self.lists() } }
}

/// Appends timestamped lines to log.txt (kept under 512 KB) and optionally echoes them.
pub struct Log { path: Option<PathBuf>, echo: bool, lock: Mutex<()> }

impl Log {
    pub fn new(path: Option<PathBuf>, echo: bool) -> Log { Log { path, echo, lock: Mutex::new(()) } }
    pub fn info(&self, m: &str) { self.write("INFO", m) }
    pub fn warn(&self, m: &str) { self.write("WARN", m) }
    pub fn error(&self, m: &str) { self.write("ERROR", m) }

    fn write(&self, level: &str, m: &str) {
        let line = format!("{}  {level:<5} {m}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
        if self.echo { println!("{line}"); }
        let Some(p) = &self.path else { return };
        let _g = self.lock.lock();
        if let Some(d) = p.parent() { let _ = std::fs::create_dir_all(d); }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) { let _ = writeln!(f, "{line}"); }
        if std::fs::metadata(p).map(|m| m.len() > 512 * 1024).unwrap_or(false) {
            let all = std::fs::read_to_string(p).unwrap_or_default();
            let lines: Vec<&str> = all.lines().collect();
            let keep = lines[lines.len().saturating_sub(2000)..].join("\r\n") + "\r\n";
            let _ = std::fs::write(p, keep);
        }
    }
}

pub fn tail(path: &Path, n: usize) -> Vec<String> {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<String> = s.lines().map(String::from).collect();
    lines[lines.len().saturating_sub(n)..].to_vec()
}
