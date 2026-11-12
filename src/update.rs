//! Updates from GitHub releases. The service (SYSTEM) does the work, so updating needs no admin prompt:
//! it asks GitHub for the latest release, downloads RustyDPI.exe and SHA256SUMS.txt over HTTPS
//! (certificates checked), checks the hash, saves the file in ProgramData\RustyDPI\update (only admins
//! can write there) and runs it with --install --after-update. The window only asks; it never hands
//! the service a file or a URL.

use crate::probe::{find, header_value, tls_config};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const REPO: &str = "CratusGod/rustydpi";
const EXE: &str = "RustyDPI.exe";
const MAX_EXE: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateInfo {
    /// Latest version on GitHub ("4.0.2"), when the last check worked.
    pub latest: Option<String>,
    /// That release's notes (markdown, shown as plain text).
    pub notes: String,
    pub newer: bool,
    pub checked: Option<crate::state::Time>,
    pub checking: bool,
    pub installing: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Release { pub version: String, pub notes: String, pub exe_url: String, pub sums_url: String }

pub fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let v = v.split(['-', '+']).next()?;
    let mut p = v.split('.').map(|x| x.parse::<u32>().ok());
    Some((p.next()??, p.next().flatten().unwrap_or(0), p.next().flatten().unwrap_or(0)))
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse_version(latest), parse_version(current)), (Some(a), Some(b)) if a > b)
}

/// Reads GitHub's "latest release" answer. Drafts and pre-releases never show up there.
pub fn parse_release(json: &str) -> Result<Release, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|_| "GitHub sent an unreadable answer".to_string())?;
    let tag = v["tag_name"].as_str().ok_or("no release found")?;
    let version = tag.trim_start_matches(['v', 'V']).to_string();
    parse_version(&version).ok_or("the latest release has no version number")?;
    let asset = |name: &str| v["assets"].as_array().into_iter().flatten()
        .find(|a| a["name"].as_str().map(|n| n.eq_ignore_ascii_case(name)).unwrap_or(false))
        .and_then(|a| a["browser_download_url"].as_str()).map(str::to_string);
    let exe_url = asset(EXE).ok_or("the latest release has no RustyDPI.exe")?;
    let sums_url = asset("SHA256SUMS.txt").ok_or("the latest release has no SHA256SUMS.txt")?;
    for u in [&exe_url, &sums_url] { if !u.starts_with("https://github.com/") { return Err("unexpected download address".into()); } }
    Ok(Release { version, notes: v["body"].as_str().unwrap_or("").trim().to_string(), exe_url, sums_url })
}

/// The expected hash of RustyDPI.exe from SHA256SUMS.txt ("<hex>  RustyDPI.exe").
pub fn expected_hash(sums: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let mut p = l.split_whitespace();
        let (h, name) = (p.next()?, p.next()?.trim_start_matches('*'));
        (name.eq_ignore_ascii_case(EXE) && h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit())).then(|| h.to_ascii_lowercase())
    })
}

pub fn verify(exe: &[u8], sums: &str) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let want = expected_hash(sums).ok_or("SHA256SUMS.txt has no line for RustyDPI.exe")?;
    if !exe.starts_with(b"MZ") { return Err("the download isn't a Windows program".into()); }
    if format!("{:x}", Sha256::digest(exe)) != want { return Err("the download doesn't match its checksum".into()); }
    Ok(())
}

/// HTTPS GET with redirects (GitHub sends downloads to its file servers). Returns the body.
pub fn get(url: &str, accept: &str, max: usize, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut url = url.to_string();
    for _ in 0..5 {
        let (code, location, body) = get_once(&url, accept, max, timeout)?;
        match (code, location) {
            (200, _) => return Ok(body),
            (301 | 302 | 303 | 307 | 308, Some(l)) if l.starts_with("https://") => url = l,
            (403 | 429, _) => return Err("GitHub is limiting requests right now; try again later".into()),
            (404, _) => return Err("no release found on GitHub".into()),
            (c, _) => return Err(format!("GitHub answered HTTP {c}")),
        }
    }
    Err("too many redirects".into())
}

fn get_once(url: &str, accept: &str, max: usize, timeout: Duration) -> Result<(u16, Option<String>, Vec<u8>), String> {
    let rest = url.strip_prefix("https://").ok_or("not an https address")?;
    let (host, path) = match rest.find('/') { Some(i) => (&rest[..i], &rest[i..]), None => (rest, "/") };
    let addr = (host, 443).to_socket_addrs().map_err(|_| format!("can't find {host}"))?.next().ok_or("no address")?;
    let sock = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("can't reach {host}: {e}"))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let conn = rustls::ClientConnection::new(tls_config(false), name).map_err(|e| e.to_string())?;
    let mut tls = rustls::StreamOwned::new(conn, sock);
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: RustyDPI/{}\r\nAccept: {accept}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", crate::engine::VERSION);
    tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let start = Instant::now();
    let mut raw = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if start.elapsed() > Duration::from_secs(300) { return Err("the download took too long".into()); }
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => { raw.extend_from_slice(&buf[..n]); if raw.len() > max + 64 * 1024 { return Err("the download is too big".into()); } }
            Err(e) if !raw.is_empty() && e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("download failed: {e}")),
        }
    }
    let h = find(&raw, b"\r\n\r\n").ok_or("no HTTP answer")?;
    let head = String::from_utf8_lossy(&raw[..h]).into_owned();
    let code: u16 = head.split(' ').nth(1).and_then(|c| c.parse().ok()).ok_or("no HTTP answer")?;
    let mut body = raw[h + 4..].to_vec();
    if header_value(&head, "transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false) { body = crate::probe::dechunk(&body); }
    if let Some(cl) = header_value(&head, "content-length").and_then(|v| v.parse::<usize>().ok()) {
        if code == 200 && body.len() != cl { return Err("the download was cut off".into()); }
    }
    Ok((code, header_value(&head, "location").map(str::to_string), body))
}

pub fn latest() -> Result<Release, String> {
    let body = get(&format!("https://api.github.com/repos/{REPO}/releases/latest"), "application/vnd.github+json", 1024 * 1024, Duration::from_secs(15))?;
    parse_release(&String::from_utf8_lossy(&body))
}

pub fn update_dir(data_dir: &Path) -> PathBuf { data_dir.join("update") }

/// Downloads and checks `r`, then starts its installer, which stops this service, replaces the
/// program and starts the new version.
pub fn download_and_install(r: &Release, data_dir: &Path) -> Result<(), String> {
    let sums = get(&r.sums_url, "*/*", 64 * 1024, Duration::from_secs(30))?;
    let exe = get(&r.exe_url, "*/*", MAX_EXE, Duration::from_secs(30))?;
    verify(&exe, &String::from_utf8_lossy(&sums))?;
    let dir = update_dir(data_dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(EXE);
    std::fs::write(&path, &exe).map_err(|e| format!("can't save the update: {e}"))?;
    // Read back what's on disk: antivirus may have changed or removed it.
    let on_disk = std::fs::read(&path).map_err(|e| format!("the saved update is gone (antivirus?): {e}"))?;
    verify(&on_disk, &String::from_utf8_lossy(&sums))?;
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x8; const CREATE_NO_WINDOW: u32 = 0x0800_0000; const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    std::process::Command::new(&path).args(["--install", "--after-update"])
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB)
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .spawn().map(|_| ()).map_err(|e| format!("can't start the update: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v4.0.1"), Some((4, 0, 1)));
        assert_eq!(parse_version("4.1"), Some((4, 1, 0)));
        assert_eq!(parse_version("4.0.2-beta"), Some((4, 0, 2)));
        assert_eq!(parse_version("latest"), None);
        assert!(is_newer("4.0.10", "4.0.9"));
        assert!(is_newer("v5.0.0", "4.9.9"));
        assert!(!is_newer("4.0.1", "4.0.1"));
        assert!(!is_newer("4.0.0", "4.0.1"), "never offers an older version");
        assert!(!is_newer("garbage", "4.0.1"));
    }

    #[test]
    fn reads_github_release() {
        let j = r#"{"tag_name":"v4.0.2","body":"Fixes things.\r\n","assets":[
            {"name":"RustyDPI.exe","browser_download_url":"https://github.com/CratusGod/rustydpi/releases/download/v4.0.2/RustyDPI.exe"},
            {"name":"SHA256SUMS.txt","browser_download_url":"https://github.com/CratusGod/rustydpi/releases/download/v4.0.2/SHA256SUMS.txt"}]}"#;
        let r = parse_release(j).unwrap();
        assert_eq!(r.version, "4.0.2");
        assert_eq!(r.notes, "Fixes things.");
        assert!(r.exe_url.ends_with("/RustyDPI.exe"));
        assert!(parse_release(r#"{"tag_name":"v4.0.2","assets":[]}"#).is_err(), "no exe, no update");
        let evil = j.replace("https://github.com/CratusGod", "https://evil.example");
        assert!(parse_release(&evil).is_err(), "downloads only from github.com");
        assert!(parse_release(r#"{"message":"Not Found"}"#).is_err());
    }

    #[test]
    fn checks_the_hash() {
        use sha2::{Digest, Sha256};
        let exe = b"MZ fake program".to_vec();
        let sums = format!("{:x}  RustyDPI.exe\n", Sha256::digest(&exe));
        assert!(verify(&exe, &sums).is_ok());
        assert!(verify(&exe, &sums.to_uppercase().replace("RUSTYDPI.EXE", "RustyDPI.exe")).is_ok(), "hex case doesn't matter");
        assert!(verify(b"MZ other program", &sums).is_err());
        assert!(verify(b"not a program", &format!("{:x}  RustyDPI.exe", Sha256::digest(b"not a program"))).is_err());
        assert!(verify(&exe, "").is_err());
        assert!(verify(&exe, &format!("{:x}  Other.exe", Sha256::digest(&exe))).is_err());
    }

    /// Asks the real GitHub for the latest release and checks its files. Run: cargo test -- --ignored update_live
    #[test]
    #[ignore]
    fn update_live() {
        let r = latest().unwrap();
        println!("latest {} ({} bytes of notes)", r.version, r.notes.len());
        let sums = get(&r.sums_url, "*/*", 64 * 1024, Duration::from_secs(30)).unwrap();
        let exe = get(&r.exe_url, "*/*", MAX_EXE, Duration::from_secs(30)).unwrap();
        verify(&exe, &String::from_utf8_lossy(&sums)).unwrap();
        println!("exe {} bytes, hash OK", exe.len());
    }
}
