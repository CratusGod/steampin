//! The driverless bypass. When winws can't help (Windows blocks the WinDivert driver, antivirus removed it,
//! or no strategy works), a blocked site is pinned in the hosts file to its own loopback address
//! (127.77.x.y), where this relay listens. The relay reads the browser's TLS ClientHello and sends it on to
//! the server RustyDPI verified for that site, cut into small TLS records. DPI that reads the site name from
//! one record (FPT's does) doesn't see it; the server reassembles the records as TLS allows. After that it
//! only copies bytes: nothing is decrypted, and the browser still checks the site's real certificate.
//!
//! Each site has its own address, so the relay knows the site from the address the browser connected to.
//! That keeps working when the browser hides the name (Encrypted Client Hello), and it can't be used as an
//! open proxy: each address forwards to one verified server only. QUIC to a loopback address finds nothing
//! listening, so browsers fall back to TCP at once.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// TLS record size the ClientHello is cut into. 64 bytes splits any host name over several records.
pub const RECORD: usize = 64;
const MAX_HELLO: usize = 16 * 1024;
const STACK: usize = 64 * 1024;
/// Connections served at once; more wait in the listen queue. Browsers use 6-30 per site.
const MAX_CONNS: usize = 512;
static CONNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Relay addresses are in 127.77.0.0/16: loopback, and clear of 127.0.0.1 where local servers live.
pub fn is_relay_ip(ip: &str) -> bool { ip.parse::<Ipv4Addr>().map(|a| a.octets()[..2] == [127, 77]).unwrap_or(false) }

/// Each site's relay address: derived from its name (so it stays the same between checks and restarts),
/// unique within `hosts`.
pub fn assign<'a>(hosts: impl IntoIterator<Item = &'a String>) -> BTreeMap<String, Ipv4Addr> {
    const SLOTS: u32 = 254 * 254;
    let mut names: Vec<&String> = hosts.into_iter().collect();
    names.sort();
    let mut used = HashSet::new();
    let mut out = BTreeMap::new();
    for h in names {
        let mut i = h.bytes().fold(0x811c9dc5u32, |a, b| (a ^ b as u32).wrapping_mul(0x01000193)) % SLOTS;
        while !used.insert(i) { i = (i + 1) % SLOTS; }
        out.insert(h.clone(), Ipv4Addr::new(127, 77, (i / 254 + 1) as u8, (i % 254 + 1) as u8));
    }
    out
}

/// What the engine needs from the relay (tests use a stand-in).
pub trait Routes: Sync {
    /// Sets the relayed sites (host -> server IP) and returns each one's relay address. Listens as needed.
    fn set_routes(&self, routes: BTreeMap<String, String>) -> Result<BTreeMap<String, String>, String>;
}

/// Relay address -> (site, server it forwards to).
type Table = Arc<RwLock<HashMap<Ipv4Addr, (String, String)>>>;

pub struct Relay { table: Table, bound: Mutex<HashSet<Ipv4Addr>>, port: u16, up_port: u16 }

impl Relay {
    pub fn new() -> Relay { Relay::on_port(443) }
    pub fn on_port(port: u16) -> Relay { Relay { table: Table::default(), bound: Mutex::new(HashSet::new()), port, up_port: 443 } }

    fn listen(&self, ip: Ipv4Addr) -> Result<(), String> {
        let mut bound = self.bound.lock().unwrap();
        if bound.contains(&ip) { return Ok(()); }
        let l = TcpListener::bind(SocketAddr::new(IpAddr::V4(ip), self.port))
            .map_err(|e| format!("the driverless bypass can't listen on {ip}:{} ({e})", self.port))?;
        bound.insert(ip);
        let (table, up_port) = (self.table.clone(), self.up_port);
        std::thread::Builder::new().name("relay".into()).stack_size(STACK).spawn(move || {
            for c in l.incoming().flatten() {
                while CONNS.load(Ordering::SeqCst) >= MAX_CONNS { std::thread::sleep(Duration::from_millis(20)); }
                let table = table.clone();
                CONNS.fetch_add(1, Ordering::SeqCst);
                let spawned = std::thread::Builder::new().stack_size(STACK).spawn(move || {
                    let _ = serve(c, &table, up_port);
                    CONNS.fetch_sub(1, Ordering::SeqCst);
                });
                if spawned.is_err() { CONNS.fetch_sub(1, Ordering::SeqCst); }
            }
        }).map_err(|e| e.to_string())?;
        // Plain http:// to a relayed site: send the browser to https:// (best effort; port 80 may be taken).
        if self.port == 443 {
            if let Ok(l80) = TcpListener::bind(SocketAddr::new(IpAddr::V4(ip), 80)) {
                let table = self.table.clone();
                let _ = std::thread::Builder::new().name("relay-80".into()).stack_size(STACK).spawn(move || {
                    for c in l80.incoming().flatten() { let _ = redirect_to_https(c, &table); }
                });
            }
        }
        Ok(())
    }
}

impl Default for Relay { fn default() -> Self { Relay::new() } }

impl Routes for Relay {
    fn set_routes(&self, routes: BTreeMap<String, String>) -> Result<BTreeMap<String, String>, String> {
        let addrs = assign(routes.keys());
        *self.table.write().unwrap() = addrs.iter().map(|(h, ip)| (*ip, (h.clone(), routes[h].clone()))).collect();
        // Addresses no longer in the table stay bound but close every connection; that's cheap and rare.
        for ip in addrs.values() { self.listen(*ip)?; }
        Ok(addrs.into_iter().map(|(h, ip)| (h, ip.to_string())).collect())
    }
}

fn local_v4(c: &TcpStream) -> Option<Ipv4Addr> { match c.local_addr().ok()?.ip() { IpAddr::V4(a) => Some(a), IpAddr::V6(_) => None } }

fn serve(mut client: TcpStream, table: &RwLock<HashMap<Ipv4Addr, (String, String)>>, up_port: u16) -> std::io::Result<()> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    let (_, upstream) = local_v4(&client).and_then(|a| table.read().unwrap().get(&a).cloned()).ok_or_else(|| bad("not a relayed site"))?;
    let addr: IpAddr = upstream.parse().map_err(|_| bad("bad address"))?;
    client.set_nodelay(true)?;
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (version, hello) = read_client_hello(&mut client)?;
    let mut up = TcpStream::connect_timeout(&SocketAddr::new(addr, up_port), Duration::from_secs(5))?;
    up.set_nodelay(true)?;
    // Not for winws (if it runs at all): this connection is already handled.
    if addr.is_ipv4() { let _ = up.set_ttl(crate::bypass::PROBE_TTL); }
    up.write_all(&fragment(version, &hello, RECORD))?;
    client.set_read_timeout(None)?;
    let (mut c2, mut u2) = (client.try_clone()?, up.try_clone()?);
    let t = std::thread::Builder::new().stack_size(STACK).spawn(move || {
        let _ = std::io::copy(&mut c2, &mut u2);
        let _ = u2.shutdown(Shutdown::Write);
    })?;
    let _ = std::io::copy(&mut up, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = t.join();
    Ok(())
}

/// Answers a plain-HTTP request to a relayed site with a redirect to the same page over HTTPS.
fn redirect_to_https(mut c: TcpStream, table: &RwLock<HashMap<Ipv4Addr, (String, String)>>) -> std::io::Result<()> {
    c.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = vec![0u8; 8192];
    let mut n = 0;
    while n < buf.len() && !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
        let r = c.read(&mut buf[n..])?;
        if r == 0 { break; }
        n += r;
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    let path = head.lines().next().and_then(|l| l.split(' ').nth(1)).filter(|p| p.starts_with('/') && !p.contains(['\r', '\n'])).unwrap_or("/");
    let resp = match local_v4(&c).and_then(|a| table.read().unwrap().get(&a).map(|x| x.0.clone())) {
        Some(h) => format!("HTTP/1.1 301 Moved Permanently\r\nLocation: https://{h}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
    };
    c.write_all(resp.as_bytes())
}
/// Reads TLS handshake records until the whole ClientHello message is in. Returns the record version and
/// the handshake message (type, length, body).
pub fn read_client_hello(s: &mut impl Read) -> std::io::Result<([u8; 2], Vec<u8>)> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    let mut msg = Vec::new();
    let mut version;
    loop {
        let mut h = [0u8; 5];
        s.read_exact(&mut h)?;
        if h[0] != 0x16 { return Err(bad("not a TLS handshake")); }
        version = [h[1], h[2]];
        let len = u16::from_be_bytes([h[3], h[4]]) as usize;
        if len == 0 || msg.len() + len > MAX_HELLO { return Err(bad("bad record length")); }
        let start = msg.len();
        msg.resize(start + len, 0);
        s.read_exact(&mut msg[start..])?;
        if msg.len() >= 4 {
            if msg[0] != 1 { return Err(bad("not a ClientHello")); }
            let need = 4 + ((msg[1] as usize) << 16 | (msg[2] as usize) << 8 | msg[3] as usize);
            if need > MAX_HELLO { return Err(bad("ClientHello too big")); }
            if msg.len() >= need {
                // Anything after the ClientHello in the same record (rare) stays with it.
                return Ok((version, msg));
            }
        }
    }
}

/// The server name (SNI) in a ClientHello handshake message, lowercased. The relay routes by address, not by
/// this name (Encrypted Client Hello hides it); tests use it to see what the server received.
#[cfg(test)]
pub fn sni(msg: &[u8]) -> Option<String> {
    let b = msg.get(4..)?;
    let mut p = 2 + 32; // version, random
    let sid = *b.get(p)? as usize; p += 1 + sid;
    let cs = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize; p += 2 + cs;
    let comp = *b.get(p)? as usize; p += 1 + comp;
    let ext_end = p + 2 + u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize; p += 2;
    while p + 4 <= ext_end.min(b.len()) {
        let typ = u16::from_be_bytes([b[p], b[p + 1]]);
        let len = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        let body = b.get(p + 4..p + 4 + len)?;
        if typ == 0 {
            // server_name_list: length(2), then entries of type(1) length(2) name.
            let mut q = 2;
            while q + 3 <= body.len() {
                let (t, n) = (body[q], u16::from_be_bytes([body[q + 1], body[q + 2]]) as usize);
                let name = body.get(q + 3..q + 3 + n)?;
                if t == 0 { return std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase()); }
                q += 3 + n;
            }
            return None;
        }
        p += 4 + len;
    }
    None
}

/// The handshake message as TLS records of at most `size` bytes each.
pub fn fragment(version: [u8; 2], msg: &[u8], size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + msg.len() / size.max(1) * 5 + 5);
    for chunk in msg.chunks(size.max(1)) {
        out.extend_from_slice(&[0x16, version[0], version[1]]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;

    fn hello(host: &str, big: bool) -> Vec<u8> {
        let mut c = rustls::ClientConnection::new(crate::probe::tls_config(big), ServerName::try_from(host.to_string()).unwrap()).unwrap();
        let mut out = Vec::new();
        while c.wants_write() { c.write_tls(&mut out).unwrap(); }
        out
    }

    #[test]
    fn reads_name_and_refragments() {
        for big in [false, true] {
            let raw = hello("Store.SteamPowered.com", big);
            let (v, msg) = read_client_hello(&mut &raw[..]).unwrap();
            assert_eq!(sni(&msg).as_deref(), Some("store.steampowered.com"));
            let f = fragment(v, &msg, RECORD);
            assert!(f.len() > raw.len());
            // Reassembles to the same message, and no record carries the whole name.
            let (v2, back) = read_client_hello(&mut &f[..]).unwrap();
            assert_eq!((v2, &back), (v, &msg));
            for rec in f.chunks(5 + RECORD) { assert!(find(rec, b"store.steampowered.com").is_none()); }
        }
    }

    fn find(h: &[u8], n: &[u8]) -> Option<usize> { h.windows(n.len()).position(|w| w == n) }

    #[test]
    fn rejects_garbage() {
        assert!(read_client_hello(&mut &b"GET / HTTP/1.1\r\n\r\n"[..]).is_err());
        assert!(read_client_hello(&mut &[0x16, 3, 1, 0xff, 0xff][..]).is_err());
        assert!(sni(&[1, 0, 0, 1, 3]).is_none());
        // A ClientHello cut short isn't read past its end.
        let raw = hello("a.example", false);
        assert!(read_client_hello(&mut &raw[..raw.len() - 10]).is_err());
    }

    #[test]
    fn addresses_are_stable_unique_and_loopback() {
        let names: Vec<String> = (0..300).map(|i| format!("site{i}.example")).collect();
        let a = assign(&names);
        let set: HashSet<_> = a.values().collect();
        assert_eq!(set.len(), names.len(), "unique");
        for ip in a.values() { assert!(is_relay_ip(&ip.to_string()) && ip.is_loopback() && ip.octets()[2] != 0 && ip.octets()[3] != 0 && ip.octets()[3] != 255); }
        // A site keeps its address when others come and go (barring a rare collision).
        let one = assign(&names[..1]);
        assert_eq!(one["site0.example"], a["site0.example"]);
        assert!(!is_relay_ip("127.0.0.1") && !is_relay_ip("42.119.186.138") && is_relay_ip("127.77.3.4"));
    }

    /// End to end on this machine: the relay forwards whatever ClientHello arrives on a site's address, cut
    /// into records, to that site's server only (so it works with Encrypted Client Hello, whose visible name
    /// is a generic one), and then copies bytes both ways. A removed site's address closes connections.
    #[test]
    fn forwards_by_address_and_stops_when_removed() {
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut relay = Relay::on_port(free_port());
        relay.up_port = up.local_addr().unwrap().port();
        let addrs = relay.set_routes(BTreeMap::from([("ok.example".to_string(), "127.0.0.1".to_string())])).unwrap();
        let addr = addrs["ok.example"].clone();
        let server = std::thread::spawn(move || {
            let (mut s, _) = up.accept().unwrap();
            let mut first = [0u8; 5 + RECORD];
            s.read_exact(&mut first).unwrap();
            let (_, msg) = read_client_hello(&mut (&first[..]).chain(&mut s)).unwrap();
            s.write_all(b"pong").unwrap();
            (sni(&msg), first[3..5] == (RECORD as u16).to_be_bytes())
        });
        let connect = || { let c = TcpStream::connect((addr.as_str(), relay.port)).unwrap(); c.set_read_timeout(Some(Duration::from_secs(5))).unwrap(); c };
        // An ECH-style hello with a generic outer name is forwarded all the same.
        let mut c = connect();
        c.write_all(&hello("cloudflare-ech.com", true)).unwrap();
        let mut b = [0u8; 4];
        c.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"pong");
        assert_eq!(server.join().unwrap(), (Some("cloudflare-ech.com".to_string()), true));
        // Removed: the address stays bound but forwards nothing.
        relay.set_routes(BTreeMap::new()).unwrap();
        let mut c = connect();
        let _ = c.write_all(&hello("ok.example", false));
        assert!(matches!(c.read(&mut b), Ok(0) | Err(_)));
    }

    /// Live, not a regular test: runs the relay on port 443 for RDPI_RELAY_SECS seconds with routes
    /// RDPI_RELAY="host=ip,host=ip" and prints each site's relay address. Point curl
    /// (--resolve host:443:<address>) or a browser (--host-resolver-rules) at it meanwhile.
    #[test]
    #[ignore]
    fn relay_live() {
        let routes: BTreeMap<String, String> = std::env::var("RDPI_RELAY").expect("RDPI_RELAY").split(',')
            .filter_map(|r| r.split_once('=')).map(|(h, ip)| (h.to_string(), ip.to_string())).collect();
        let secs: u64 = std::env::var("RDPI_RELAY_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(60);
        for (h, a) in Relay::new().set_routes(routes).unwrap() { println!("{h} {a}"); }
        std::thread::sleep(Duration::from_secs(secs));
    }

    fn free_port() -> u16 { TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }
}