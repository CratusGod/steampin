//! Minimal DNS client: asks one specific server over UDP (RFC 1035), never the hosts file.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;

#[derive(Clone, Debug, PartialEq)]
pub struct Answer { pub rtype: u16, pub data: String }

pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, QDCOUNT=1
    for label in name.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 { return Err("bad DNS name".into()); }
        q.push(b.len() as u8);
        q.extend_from_slice(b);
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    Ok(q)
}

fn u16_at(b: &[u8], p: usize) -> Option<u16> { b.get(p..p + 2).map(|s| u16::from_be_bytes([s[0], s[1]])) }

fn skip_name(b: &[u8], mut p: usize) -> usize {
    while p < b.len() {
        let l = b[p] as usize;
        if l == 0 { return p + 1; }
        if l & 0xC0 == 0xC0 { return p + 2; }
        p += l + 1;
    }
    p
}

fn read_name(b: &[u8], mut p: usize) -> String {
    let mut parts = Vec::new();
    for _ in 0..64 {
        let Some(&l) = b.get(p) else { break };
        if l == 0 { break; }
        if l & 0xC0 == 0xC0 {
            let Some(&lo) = b.get(p + 1) else { break };
            p = (((l & 0x3F) as usize) << 8) | lo as usize;
            continue;
        }
        let end = (p + 1 + l as usize).min(b.len());
        parts.push(String::from_utf8_lossy(&b[p + 1..end]).into_owned());
        p += l as usize + 1;
    }
    parts.join(".")
}

/// Parses a response; None when it isn't a valid answer to query `id`.
pub fn parse_response(b: &[u8], id: u16) -> Option<Vec<Answer>> {
    if b.len() < 12 || u16_at(b, 0)? != id || b[2] & 0x80 == 0 { return None; }
    let rcode = b[3] & 0x0F;
    let qd = u16_at(b, 4)? as usize;
    let an = u16_at(b, 6)? as usize;
    let mut out = Vec::new();
    if rcode != 0 { return Some(out); }
    let mut p = 12;
    for _ in 0..qd { p = skip_name(b, p) + 4; }
    for _ in 0..an {
        if p >= b.len() { break; }
        p = skip_name(b, p);
        if p + 10 > b.len() { break; }
        let rtype = u16_at(b, p)?;
        let rdlen = u16_at(b, p + 8)? as usize;
        p += 10;
        if p + rdlen > b.len() { break; }
        match rtype {
            TYPE_A if rdlen == 4 => out.push(Answer { rtype, data: format!("{}.{}.{}.{}", b[p], b[p + 1], b[p + 2], b[p + 3]) }),
            TYPE_AAAA if rdlen == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&b[p..p + 16]);
                out.push(Answer { rtype, data: std::net::Ipv6Addr::from(a).to_string() });
            }
            TYPE_CNAME => out.push(Answer { rtype, data: read_name(b, p) }),
            TYPE_TXT => {
                let mut s = String::new();
                let mut q = p;
                while q < p + rdlen {
                    let l = b[q] as usize;
                    q += 1;
                    let end = (q + l).min(p + rdlen);
                    s.push_str(&String::from_utf8_lossy(&b[q..end]));
                    q += l;
                }
                out.push(Answer { rtype, data: s });
            }
            _ => {}
        }
        p += rdlen;
    }
    Some(out)
}

/// Asks one server (an IP, or a host name resolved through the system). Two tries within `timeout`.
pub fn query(server: &str, name: &str, qtype: u16, timeout: Duration) -> Result<Vec<Answer>, String> {
    let addr: IpAddr = match server.parse() {
        Ok(a) => a,
        Err(_) => (server, 53).to_socket_addrs().map_err(|e| e.to_string())?
            .find(|a| a.is_ipv4()).map(|a| a.ip()).ok_or("no address for DNS server")?,
    };
    let id: u16 = (std::process::id() as u16) ^ (Instant::now().elapsed().subsec_nanos() as u16) ^ rand16();
    let q = build_query(id, name, qtype)?;
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let target = SocketAddr::new(addr, 53);
    let mut buf = [0u8; 4096];
    for _ in 0..2 {
        sock.send_to(&q, target).map_err(|e| e.to_string())?;
        let deadline = Instant::now() + timeout / 2;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() { break; }
            sock.set_read_timeout(Some(left)).ok();
            match sock.recv_from(&mut buf) {
                Ok((n, from)) if from.ip() == addr => {
                    if let Some(a) = parse_response(&buf[..n], id) { return Ok(a); }
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }
    Err(format!("DNS {server} timed out"))
}

fn rand16() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(Instant::now().elapsed().as_nanos() as u64);
    h.finish() as u16
}

/// Global unicast IPv6 addresses (2000::/3) for `name`.
pub fn query_aaaa(server: &str, name: &str, timeout: Duration) -> Vec<String> {
    query(server, name, TYPE_AAAA, timeout).map(|v| v.into_iter().filter(|a| a.rtype == TYPE_AAAA)
        .filter(|a| a.data.parse::<std::net::Ipv6Addr>().map(|ip| ip.segments()[0] & 0xe000 == 0x2000).unwrap_or(false)).map(|a| a.data).collect()).unwrap_or_default()
}

pub fn query_a(server: &str, name: &str, timeout: Duration) -> Vec<String> {
    query(server, name, TYPE_A, timeout).map(|v| v.into_iter().filter(|a| a.rtype == TYPE_A).map(|a| a.data).collect()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_name() {
        let q = build_query(0x1234, "api.steampowered.com", TYPE_A).unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(q[12], 3);
        assert_eq!(q[13], b'a');
        assert_eq!(q[q.len() - 3], TYPE_A as u8);
        assert!(build_query(1, "a..b", TYPE_A).is_err());
    }

    #[test]
    fn parses_cname_and_a_with_compression() {
        let q = build_query(7, "x.example.com", TYPE_A).unwrap();
        let mut r = q.clone();
        r[2] = 0x81; r[3] = 0x80; r[7] = 2;
        r.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 20, 0, 4, 1, b'y', 0xC0, 14]);
        r.extend_from_slice(&[0xC0, (q.len() + 12) as u8, 0, 1, 0, 1, 0, 0, 0, 20, 0, 4, 42, 119, 186, 138]);
        let a = parse_response(&r, 7).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].data, "y.example.com");
        assert_eq!(a[1].data, "42.119.186.138");
    }

    #[test]
    fn parses_txt() {
        let q = build_query(9, "a.b", TYPE_TXT).unwrap();
        let mut r = q.clone();
        r[2] = 0x81; r[3] = 0x80; r[7] = 1;
        let txt = b"18403 | 42.118.0.0/15 | VN";
        r.extend_from_slice(&[0xC0, 12, 0, 16, 0, 1, 0, 0, 0, 20, 0, (txt.len() + 1) as u8, txt.len() as u8]);
        r.extend_from_slice(txt);
        assert_eq!(parse_response(&r, 9).unwrap()[0].data, "18403 | 42.118.0.0/15 | VN");
    }

    #[test]
    fn parses_aaaa() {
        let q = build_query(11, "a.b", TYPE_AAAA).unwrap();
        let mut r = q.clone();
        r[2] = 0x81; r[3] = 0x80; r[7] = 1;
        r.extend_from_slice(&[0xC0, 12, 0, 28, 0, 1, 0, 0, 0, 20, 0, 16]);
        r.extend_from_slice(&[0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x1a, 0x04, 0xbc]);
        assert_eq!(parse_response(&r, 11).unwrap()[0].data, "2606:4700::681a:4bc");
    }

    /// Live: AAAA from a public resolver (needs internet).
    #[test]
    #[ignore]
    fn aaaa_live() {
        let a = query_aaaa("8.8.8.8", "www.cloudflare.com", Duration::from_secs(3));
        println!("{a:?}");
        assert!(!a.is_empty());
    }

    #[test]
    fn rejects_wrong_id_queries_and_garbage() {
        let q = build_query(5, "a.b", TYPE_A).unwrap();
        assert!(parse_response(&q, 6).is_none());
        assert!(parse_response(&q, 5).is_none());
        assert!(parse_response(&[1, 2, 3], 5).is_none());
        let mut nx = q.clone();
        nx[2] = 0x81; nx[3] = 0x83;
        assert!(parse_response(&nx, 5).unwrap().is_empty());
        // truncated answer section must not panic
        let mut t = q.clone();
        t[2] = 0x81; t[3] = 0x80; t[7] = 3;
        t.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert!(parse_response(&t, 5).unwrap().is_empty());
    }
}
