//! RustyDPI's managed block in the Windows hosts file. Never touches other lines.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

pub const BEGIN_PREFIX: &str = "# BEGIN RustyDPI";
pub const BEGIN_MARK: &str = "# BEGIN RustyDPI - managed automatically, edits inside this block are overwritten";
pub const END_MARK: &str = "# END RustyDPI";
/// The same block as written by SteamPin 3 (RustyDPI's earlier name): adopted and rewritten.
pub const OLD_BEGIN_PREFIX: &str = "# BEGIN SteamPin";
pub const OLD_END_MARK: &str = "# END SteamPin";
pub const LEGACY_TAG: &str = "# local VN Steam cache node - pinned; delete this line to undo"; // RustyDPI v1
pub const BACKUPS_KEPT: usize = 5;

#[derive(Default, Debug)]
pub struct Split {
    pub other: Vec<String>,
    pub pins: HashMap<String, String>,
    pub saw_block: bool,
    pub unterminated: bool,
    pub had_legacy: bool,
}

pub fn system_path() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    Path::new(&root).join("System32").join("drivers").join("etc").join("hosts")
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Enc { Utf8, Ansi }

/// UTF-8 (BOM stripped); falls back to the ANSI code page when the file isn't valid UTF-8.
pub fn read_text(path: &Path) -> (String, Enc) {
    let Ok(bytes) = std::fs::read(path) else { return (String::new(), Enc::Utf8) };
    let b = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    match std::str::from_utf8(b) {
        Ok(s) => (s.to_string(), Enc::Utf8),
        Err(_) => (crate::win::ansi_to_string(&bytes), Enc::Ansi),
    }
}

pub fn to_lines(text: &str) -> Vec<String> {
    if text.is_empty() { return vec![]; }
    let mut v: Vec<String> = text.split('\n').map(|l| l.trim_end_matches('\r').to_string()).collect();
    if v.last().map(|l| l.is_empty()).unwrap_or(false) { v.pop(); }
    v
}

pub fn split(lines: &[String], names: &[String]) -> Split {
    let mut s = Split::default();
    let mut in_block = false;
    // Lines inside an open block that aren't RustyDPI pins. If the END line is missing, the "block" runs to
    // the end of the file and these are most likely the user's own entries: keep them.
    let mut foreign_in_block: Vec<String> = Vec::new();
    for l in lines {
        if l.starts_with(BEGIN_PREFIX) || l.starts_with(OLD_BEGIN_PREFIX) { in_block = true; s.saw_block = true; foreign_in_block.clear(); continue; }
        if in_block && (l == END_MARK || l == OLD_END_MARK) { in_block = false; foreign_in_block.clear(); continue; }
        let legacy = l.contains(LEGACY_TAG);
        if in_block || legacy {
            if legacy { s.had_legacy = true; }
            let mut parts = l.split_whitespace();
            let mut ours = false;
            if let (Some(ip), Some(n)) = (parts.next(), parts.next()) {
                let n = n.to_ascii_lowercase();
                if !ip.starts_with('#') && (crate::iputil::is_public_ipv4(ip) || crate::relay::is_relay_ip(ip)) && names.contains(&n) {
                    ours = true;
                    s.pins.entry(n).or_insert_with(|| ip.to_string());
                }
            }
            if in_block && !ours && !legacy { foreign_in_block.push(l.clone()); }
            continue;
        }
        s.other.push(l.clone());
    }
    s.unterminated = in_block;
    if s.unterminated { s.other.extend(foreign_in_block.into_iter().filter(|l| !l.trim().is_empty())); }
    s
}

/// Names that also appear on an active line outside RustyDPI's block (the user's own entries).
pub fn foreign_entries(other: &[String], names: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for l in other {
        let body = l.split('#').next().unwrap_or("");
        for n in body.split_whitespace().skip(1) {
            let n = n.to_ascii_lowercase();
            if names.contains(&n) && !found.contains(&n) { found.push(n); }
        }
    }
    found
}

pub fn render(other: &[String], pins: &BTreeMap<String, Option<String>>, order: &[String]) -> String {
    let mut o: Vec<String> = other.to_vec();
    while o.last().map(|l| l.trim().is_empty()).unwrap_or(false) { o.pop(); }
    let names: Vec<&String> = order.iter().filter(|n| matches!(pins.get(*n), Some(Some(_)))).collect();
    if !names.is_empty() {
        o.push(String::new());
        o.push(BEGIN_MARK.into());
        for n in names { o.push(format!("{}\t{}", pins[n].as_ref().unwrap(), n)); }
        o.push(END_MARK.into());
    }
    if o.is_empty() { String::new() } else { o.join("\r\n") + "\r\n" }
}

fn encode(text: &str, enc: Enc) -> Vec<u8> {
    match enc { Enc::Utf8 => text.as_bytes().to_vec(), Enc::Ansi => crate::win::string_to_ansi(text) }
}

/// Writes the hosts file. A read-only hosts file (set by the user or antivirus to keep malware out) is
/// made writable just for this write and read-only again afterwards, so that protection stays.
pub fn write(path: &Path, backup_dir: &Path, text: &str, enc: Enc) -> Result<(), String> {
    let set_ro = |ro: bool| std::fs::metadata(path).map(|m| { let mut p = m.permissions(); p.set_readonly(ro); std::fs::set_permissions(path, p) });
    let was_ro = std::fs::metadata(path).map(|m| m.permissions().readonly()).unwrap_or(false);
    if was_ro { let _ = set_ro(false); }
    let r = write_inner(path, backup_dir, text, enc);
    if was_ro { let _ = set_ro(true); }
    r
}

/// Atomic replace (temp file next to hosts + rename), keeping 5 rotating backups.
fn write_inner(path: &Path, backup_dir: &Path, text: &str, enc: Enc) -> Result<(), String> {
    backup(path, backup_dir);
    let dir = path.parent().ok_or("bad hosts path")?;
    let tmp = dir.join("hosts.rustydpi.tmp");
    std::fs::write(&tmp, encode(text, enc)).map_err(|e| format!("Could not write the hosts file: {e}"))?;
    let mut done = false;
    let mut err = String::new();
    for _ in 0..10 {
        match crate::win::replace_file(&tmp, path) {
            Ok(()) => { done = true; break; }
            Err(e) => { err = e; std::thread::sleep(std::time::Duration::from_millis(500)); }
        }
    }
    if !done {
        // Some security tools block replacing hosts; fall back to an in-place write.
        for _ in 0..10 {
            match std::fs::write(path, encode(text, enc)) {
                Ok(()) => { done = true; break; }
                Err(e) => { err = e.to_string(); std::thread::sleep(std::time::Duration::from_millis(500)); }
            }
        }
        let _ = std::fs::remove_file(&tmp);
    }
    if !done { return Err(format!("Could not write the hosts file: {err}")); }
    if read_text(path).0 != text { return Err("The hosts file did not read back as written (another program changed it?).".into()); }
    Ok(())
}

fn backup(path: &Path, dir: &Path) {
    if !path.exists() { return; }
    let _ = std::fs::create_dir_all(dir);
    for i in (1..=BACKUPS_KEPT).rev() {
        let src = dir.join(format!("hosts.{i}.bak"));
        if !src.exists() { continue; }
        if i == BACKUPS_KEPT { let _ = std::fs::remove_file(&src); } else { let _ = std::fs::rename(&src, dir.join(format!("hosts.{}.bak", i + 1))); }
    }
    let _ = std::fs::copy(path, dir.join("hosts.1.bak"));
}

#[allow(dead_code)]
pub fn backups(dir: &Path) -> Vec<PathBuf> {
    (1..=BACKUPS_KEPT).map(|i| dir.join(format!("hosts.{i}.bak"))).filter(|p| p.exists()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> { ["store.steampowered.com", "api.steampowered.com", "login.steampowered.com"].map(String::from).to_vec() }

    #[test]
    fn adopts_steampin_block() {
        let lines: Vec<String> = ["127.0.0.1 localhost", "", "# BEGIN SteamPin - managed automatically, edits inside this block are overwritten",
            "42.119.186.138\tstore.steampowered.com", "# END SteamPin", "10.0.0.5 nas"].map(String::from).to_vec();
        let s = split(&lines, &names());
        assert_eq!(s.pins["store.steampowered.com"], "42.119.186.138");
        assert_eq!(s.other, vec!["127.0.0.1 localhost", "", "10.0.0.5 nas"]);
        let out = render(&s.other, &BTreeMap::from([("store.steampowered.com".to_string(), Some("42.119.186.138".to_string()))]), &names());
        assert!(!out.contains("SteamPin") && out.contains("# BEGIN RustyDPI") && out.contains("# END RustyDPI"));
    }

    fn sample() -> Vec<String> {
        vec![
            "# Copyright (c) Microsoft Corp.".into(), "# ghi chú tiếng Việt".into(), "".into(),
            format!("42.119.186.138\tstore.steampowered.com\t{LEGACY_TAG}"),
            BEGIN_MARK.into(), "118.69.17.16\tapi.steampowered.com".into(), "127.0.0.1\tlogin.steampowered.com".into(),
            "1.2.3.4\tevil.example.com".into(), END_MARK.into(),
            "0.0.0.0 ads.example.com".into(), "#1.1.1.1 store.steampowered.com".into(),
        ]
    }

    pub fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rustydpi-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn splits_block_and_legacy() {
        let s = split(&sample(), &names());
        assert_eq!(s.pins["store.steampowered.com"], "42.119.186.138");
        assert_eq!(s.pins["api.steampowered.com"], "118.69.17.16");
        assert!(!s.pins.contains_key("login.steampowered.com"));
        assert_eq!(s.other.len(), 5);
        assert!(s.other.contains(&"# ghi chú tiếng Việt".to_string()));
        assert!(s.other.contains(&"0.0.0.0 ads.example.com".to_string()));
        assert!(s.saw_block && s.had_legacy && !s.unterminated);
        assert!(split(&[BEGIN_MARK.into(), "1.2.3.4 a.com".into()], &names()).unterminated);
    }

    #[test]
    fn missing_end_line_keeps_the_users_own_entries() {
        let lines: Vec<String> = ["127.0.0.1 localhost", BEGIN_MARK, "42.119.186.138\tstore.steampowered.com", "", "10.0.0.5 nas", "0.0.0.0 ads.example.com"]
            .map(String::from).to_vec();
        let s = split(&lines, &names());
        assert!(s.unterminated);
        assert_eq!(s.pins["store.steampowered.com"], "42.119.186.138");
        assert_eq!(s.other, vec!["127.0.0.1 localhost", "10.0.0.5 nas", "0.0.0.0 ads.example.com"]);
        let out = render(&s.other, &BTreeMap::from([("store.steampowered.com".to_string(), Some("42.119.186.138".to_string()))]), &names());
        assert!(out.contains("10.0.0.5 nas") && out.contains(END_MARK));
        assert_eq!(out.matches("store.steampowered.com").count(), 1);
    }

    #[test]
    fn renders_block_at_end_crlf() {
        let s = split(&sample(), &names());
        let mut pins = BTreeMap::new();
        pins.insert("store.steampowered.com".to_string(), Some("42.119.186.138".to_string()));
        pins.insert("api.steampowered.com".to_string(), None);
        let text = render(&s.other, &pins, &names());
        assert!(text.ends_with(&format!("{END_MARK}\r\n")));
        assert!(!text.replace("\r\n", "").contains('\n'));
        assert!(text.contains("42.119.186.138\tstore.steampowered.com"));
        assert!(!text.contains("api.steampowered.com"));
        assert!(!text.contains(LEGACY_TAG));
        assert!(!render(&s.other, &BTreeMap::new(), &names()).contains("RustyDPI"));
    }

    #[test]
    fn finds_user_entries() {
        let mut l = sample();
        l.push("1.1.1.1 Store.SteamPowered.com # mine".into());
        let s = split(&l, &names());
        assert_eq!(foreign_entries(&s.other, &names()), vec!["store.steampowered.com"]);
    }

    #[test]
    fn writes_atomically_without_bom_and_rotates_backups() {
        let d = tmpdir("hosts");
        let path = d.join("hosts");
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend((sample().join("\r\n") + "\r\n").as_bytes());
        std::fs::write(&path, bytes).unwrap();
        let (text, enc) = read_text(&path);
        let s = split(&to_lines(&text), &names());
        assert_eq!(s.other[0], "# Copyright (c) Microsoft Corp.");
        for i in 0..7 {
            let mut pins = BTreeMap::new();
            pins.insert("store.steampowered.com".to_string(), Some(format!("42.119.186.{}", 100 + i)));
            write(&path, &d.join("backups"), &render(&s.other, &pins, &names()), enc).unwrap();
        }
        let back = std::fs::read(&path).unwrap();
        assert_ne!(back[0], 0xEF);
        assert!(String::from_utf8(back).unwrap().contains("ghi chú tiếng Việt"));
        let b = backups(&d.join("backups"));
        assert_eq!(b.len(), 5);
        assert!(std::fs::read_to_string(&b[0]).unwrap().contains("42.119.186.105"));
        assert!(!d.join("hosts.rustydpi.tmp").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn writes_read_only_file_and_keeps_it_read_only() {
        let d = tmpdir("readonly");
        let path = d.join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\r\n").unwrap();
        let mut p = std::fs::metadata(&path).unwrap().permissions(); p.set_readonly(true); std::fs::set_permissions(&path, p).unwrap();
        let (text, enc) = read_text(&path);
        let s = split(&to_lines(&text), &names());
        let mut pins = BTreeMap::new();
        pins.insert("store.steampowered.com".to_string(), Some("42.119.186.138".to_string()));
        write(&path, &d.join("backups"), &render(&s.other, &pins, &names()), enc).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("42.119.186.138"));
        assert!(std::fs::metadata(&path).unwrap().permissions().readonly(), "read-only must be restored");
        let mut p = std::fs::metadata(&path).unwrap().permissions(); p.set_readonly(false); std::fs::set_permissions(&path, p).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn keeps_ansi_encoding() {
        let d = tmpdir("ansi");
        let path = d.join("hosts");
        // "café" in Windows-1252; invalid as UTF-8.
        let raw = b"# caf\xe9\r\n".to_vec();
        std::fs::write(&path, &raw).unwrap();
        let (text, enc) = read_text(&path);
        assert_eq!(enc, Enc::Ansi);
        let mut pins = BTreeMap::new();
        pins.insert("api.steampowered.com".to_string(), Some("118.69.17.16".to_string()));
        write(&path, &d.join("b"), &render(&to_lines(&text), &pins, &names()), enc).unwrap();
        let back = std::fs::read(&path).unwrap();
        if crate::win::ansi_code_page() == 1252 { assert_eq!(&back[..7], &raw[..7]); }
        let _ = std::fs::remove_dir_all(&d);
    }
}
