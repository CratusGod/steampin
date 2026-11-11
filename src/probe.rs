//! HTTPS checks against a specific server IP with the real host name (SNI + Host), full
//! certificate validation and the target's own check (status, body or redirect).

use crate::config::Target;
use regex_lite::Regex;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum Fail { #[default] None, Timeout, Refused, Unreachable, TlsReset, WrongCertificate, HttpStatus, Body, Redirect, Other }

#[derive(Clone, Debug, PartialEq)]
pub struct ProbeResult { pub ok: bool, pub ms: Option<f64>, pub code: u16, pub fail: Fail, pub reason: String }

impl ProbeResult {
    pub fn failed(fail: Fail, reason: impl Into<String>) -> Self { ProbeResult { ok: false, ms: None, code: 0, fail, reason: reason.into() } }
    pub fn good(ms: f64, code: u16) -> Self { ProbeResult { ok: true, ms: Some(ms), code, fail: Fail::None, reason: String::new() } }
}

pub trait Prober: Sync {
    fn probe(&self, t: &Target, ip: &str) -> ProbeResult;
}

pub fn tls_config() -> Arc<rustls::ClientConfig> {
    static C: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    C.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let mut c = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(c)
    }).clone()
}

pub struct HttpsProber { pub connect_timeout: Duration, pub total_timeout: Duration }

const MAX_BODY: usize = 256 * 1024;

impl Prober for HttpsProber {
    /// The time reported is "TLS handshake complete" measured from the start of the TCP connect:
    /// it measures the path to the edge server (time-to-first-byte mostly measures Valve's origin).
    fn probe(&self, t: &Target, ip: &str) -> ProbeResult {
        let Ok(addr) = ip.parse::<IpAddr>() else { return ProbeResult::failed(Fail::Other, "bad IP") };
        let start = Instant::now();
        let sock = match TcpStream::connect_timeout(&SocketAddr::new(addr, 443), self.connect_timeout) {
            Ok(s) => s,
            Err(e) => return match e.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => ProbeResult::failed(Fail::Timeout, "connect timeout"),
                ErrorKind::ConnectionRefused => ProbeResult::failed(Fail::Refused, "refused"),
                _ => ProbeResult::failed(Fail::Unreachable, format!("connect failed ({})", e.kind())),
            },
        };
        let left = |d: Duration| d.saturating_sub(start.elapsed()).max(Duration::from_millis(50));
        let _ = sock.set_nodelay(true);
        let _ = sock.set_read_timeout(Some(left(self.total_timeout)));
        let _ = sock.set_write_timeout(Some(left(self.total_timeout)));
        let Ok(name) = ServerName::try_from(t.name.clone()) else { return ProbeResult::failed(Fail::Other, "bad host name") };
        let Ok(conn) = rustls::ClientConnection::new(tls_config(), name) else { return ProbeResult::failed(Fail::Other, "TLS setup failed") };
        let mut tls = rustls::StreamOwned::new(conn, sock);
        while tls.conn.is_handshaking() {
            if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
                return classify_tls_error(&e);
            }
        }
        let ms = (start.elapsed().as_secs_f64() * 1000.0).round();
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) SteamPin/3\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            t.path, t.name);
        if let Err(e) = tls.write_all(req.as_bytes()).and_then(|_| tls.flush()) {
            return if is_timeout(&e) { ProbeResult::failed(Fail::Timeout, "timeout") } else { ProbeResult::failed(Fail::TlsReset, "connection reset after TLS") };
        }
        let raw = match read_response(&mut tls, start, self.total_timeout) {
            Ok(r) => r,
            Err(e) if is_timeout(&e) => return ProbeResult::failed(Fail::Timeout, "response timeout"),
            Err(_) => return ProbeResult::failed(Fail::TlsReset, "connection reset after TLS"),
        };
        let Some((code, location, body)) = parse_http(&raw) else { return ProbeResult::failed(Fail::Other, "no HTTP response") };
        judge(t, code, location.as_deref(), &body, ms)
    }
}

fn is_timeout(e: &std::io::Error) -> bool { matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) }

fn classify_tls_error(e: &std::io::Error) -> ProbeResult {
    if is_timeout(e) { return ProbeResult::failed(Fail::Timeout, "TLS timeout"); }
    if let Some(inner) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        if let rustls::Error::InvalidCertificate(c) = inner {
            let s = format!("{c:?}");
            return if s.contains("NotValidForName") {
                ProbeResult::failed(Fail::WrongCertificate, "wrong certificate (another site)")
            } else {
                ProbeResult::failed(Fail::WrongCertificate, format!("bad certificate ({s})"))
            };
        }
        return ProbeResult::failed(Fail::TlsReset, format!("TLS failed ({inner})"));
    }
    ProbeResult::failed(Fail::TlsReset, "TLS reset (blocked)")
}

fn read_response(s: &mut impl Read, start: Instant, total: Duration) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    while out.len() < MAX_BODY {
        if start.elapsed() > total { return Err(ErrorKind::TimedOut.into()); }
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => { out.extend_from_slice(&buf[..n]); if complete(&out) { break; } }
            Err(e) if !out.is_empty() && !is_timeout(&e) => break, // closed abruptly after sending data
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> { h.windows(n.len()).position(|w| w == n) }

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn complete(data: &[u8]) -> bool {
    let Some(h) = find(data, b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&data[..h]);
    let body = &data[h + 4..];
    if let Some(cl) = header_value(&head, "content-length").and_then(|v| v.parse::<usize>().ok()) { return body.len() >= cl; }
    if header_value(&head, "transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false) {
        return body.starts_with(b"0\r\n\r\n") || find(body, b"\r\n0\r\n\r\n").is_some();
    }
    false
}

pub fn parse_http(raw: &[u8]) -> Option<(u16, Option<String>, String)> {
    let h = find(raw, b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..h]).into_owned();
    let first = head.split("\r\n").next()?;
    let mut parts = first.split(' ');
    if !parts.next()?.starts_with("HTTP/") { return None; }
    let code: u16 = parts.next()?.parse().ok().filter(|c| (100..600).contains(c))?;
    let location = header_value(&head, "location").map(str::to_string);
    let chunked = header_value(&head, "transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false);
    let mut body = raw[h + 4..].to_vec();
    if chunked { body = dechunk(&body); }
    Some((code, location, String::from_utf8_lossy(&body).into_owned()))
}

pub fn dechunk(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < b.len() {
        let Some(e) = find(&b[p..], b"\r\n") else { break };
        let size_str = String::from_utf8_lossy(&b[p..p + e]);
        let Ok(size) = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16) else { break };
        if size == 0 { break; }
        p += e + 2;
        let end = (p + size).min(b.len());
        out.extend_from_slice(&b[p..end]);
        p += size + 2;
    }
    out
}

pub fn judge(t: &Target, code: u16, location: Option<&str>, body: &str, ms: f64) -> ProbeResult {
    if !t.expect_status.contains(&code) {
        return ProbeResult { code, ..ProbeResult::failed(Fail::HttpStatus, format!("HTTP {code}")) };
    }
    if let Some(rx) = &t.expect_body {
        if !Regex::new(rx).map(|r| r.is_match(body)).unwrap_or(false) {
            return ProbeResult { code, ..ProbeResult::failed(Fail::Body, "unexpected content") };
        }
    }
    if let Some(rx) = &t.expect_redirect {
        let abs = location.map(|l| if l.starts_with('/') { format!("https://{}{}", t.name, l) } else { l.to_string() });
        if !abs.map(|a| Regex::new(rx).map(|r| r.is_match(&a)).unwrap_or(false)).unwrap_or(false) {
            return ProbeResult { code, ..ProbeResult::failed(Fail::Redirect, "unexpected redirect") };
        }
    }
    ProbeResult::good(ms, code)
}

/// A plain GET (http or https) to a URL, resolved through the system. Used for the online check and DoH.
pub fn http_get(url: &str, timeout: Duration, accept: &str) -> Result<(u16, String), String> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") { (true, r) } else if let Some(r) = url.strip_prefix("http://") { (false, r) } else { return Err("bad URL".into()) };
    let (host, path) = match rest.find('/') { Some(i) => (&rest[..i], &rest[i..]), None => (rest, "/") };
    let port = if https { 443 } else { 80 };
    let addr = (host, port).to_socket_addrs().map_err(|e| e.to_string())?.find(|a| a.is_ipv4()).ok_or("no address")?;
    let start = Instant::now();
    let sock = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SteamPin/3\r\nAccept: {accept}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
    let raw = if https {
        let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
        let conn = rustls::ClientConnection::new(tls_config(), name).map_err(|e| e.to_string())?;
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        read_response(&mut tls, start, timeout).map_err(|e| e.to_string())?
    } else {
        let mut s = sock;
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        read_response(&mut s, start, timeout).map_err(|e| e.to_string())?
    };
    let (code, _, body) = parse_http(&raw).ok_or("no HTTP response")?;
    Ok((code, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Target {
        Target { name: "login.steampowered.com".into(), expect_status: vec![302], expect_redirect: Some(r"^https://([a-z0-9-]+\.)*steampowered\.com/".into()), ..Default::default() }
    }

    #[test]
    fn parses_status_location_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nLocation: /x\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (code, loc, body) = parse_http(raw).unwrap();
        assert_eq!((code, loc.as_deref(), body.as_str()), (200, Some("/x"), "hello world"));
        assert!(parse_http(b"garbage").is_none());
        assert!(parse_http(b"HTTP/1.1 abc\r\n\r\n").is_none());
        assert!(complete(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
        assert!(!complete(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok"));
    }

    #[test]
    fn judges_redirects() {
        assert!(judge(&login(), 302, Some("https://store.steampowered.com/"), "", 20.0).ok);
        assert!(judge(&login(), 302, Some("/login/home"), "", 20.0).ok);
        assert_eq!(judge(&login(), 302, Some("https://evil.example/"), "", 20.0).fail, Fail::Redirect);
        assert_eq!(judge(&login(), 302, Some("https://steampowered.com.evil.example/"), "", 20.0).fail, Fail::Redirect);
        assert_eq!(judge(&login(), 302, None, "", 20.0).fail, Fail::Redirect);
        assert_eq!(judge(&login(), 403, None, "", 20.0).fail, Fail::HttpStatus);
    }

    #[test]
    fn judges_body() {
        let t = Target { name: "api.steampowered.com".into(), expect_body: Some("\"servertime\"".into()), ..Default::default() };
        assert!(judge(&t, 200, None, r#"{"servertime":1}"#, 20.0).ok);
        assert_eq!(judge(&t, 200, None, "<html>blocked</html>", 20.0).fail, Fail::Body);
    }
}
