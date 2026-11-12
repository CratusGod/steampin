//! Network access the engine needs (behind a trait so tests can simulate any network),
//! the adapters Windows has, and which ISP we're on (found with DNS only).

use crate::config::Config;
use crate::dns;
use crate::state::NetworkId;
use std::time::Duration;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

pub trait Net: Sync {
    fn is_online(&self) -> bool;
    /// What Windows' own DNS servers answer (hosts file ignored). May include 127.0.0.1 etc. when poisoned.
    fn system_resolve(&self, name: &str) -> Vec<String>;
    /// Public IPs from the configured resolvers and DoH, filtered to allowedNetworks.
    fn public_resolve(&self, name: &str) -> Vec<String>;
    fn flush_dns(&self);
    fn detect_network(&self) -> NetworkId;
    /// Global IPv6 addresses Windows' DNS gives for `name` (browsers prefer these when the PC has IPv6).
    fn system_resolve_v6(&self, _name: &str) -> Vec<String> { vec![] }
}

pub struct RealNet<'a> { pub cfg: &'a Config, pub flush: bool }

impl Net for RealNet<'_> {
    fn is_online(&self) -> bool {
        let Some(url) = &self.cfg.connectivity_url else { return true };
        for i in 0..2 {
            if let Ok((_, body)) = crate::probe::http_get(url, Duration::from_secs(8), "*/*") {
                if self.cfg.connectivity_expect.as_ref().map(|e| body.contains(e.as_str())).unwrap_or(true) { return true; }
            }
            if i == 0 { std::thread::sleep(Duration::from_secs(2)); }
        }
        false
    }

    fn system_resolve(&self, name: &str) -> Vec<String> {
        for srv in system_dns_servers().iter().take(2) {
            let a = dns::query_a(srv, name, Duration::from_secs(2));
            if !a.is_empty() { return dedup(a); }
        }
        vec![]
    }

    fn public_resolve(&self, name: &str) -> Vec<String> {
        let mut all: Vec<String> = std::thread::scope(|s| {
            let mut hs: Vec<std::thread::ScopedJoinHandle<Vec<String>>> =
                self.cfg.resolvers.iter().map(|r| s.spawn(move || dns::query_a(r, name, Duration::from_secs(2)))).collect();
            hs.extend(self.cfg.doh_urls.iter().map(|u| s.spawn(move || doh_a(u, name))));
            hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
        });
        all.retain(|ip| crate::iputil::is_public_ipv4(ip) && crate::iputil::in_any(ip, &self.cfg.allowed_networks));
        dedup(all)
    }

    fn flush_dns(&self) {
        if self.flush { crate::win::run_hidden("ipconfig.exe", &["/flushdns"]); }
    }

    fn detect_network(&self) -> NetworkId { detect_network() }

    fn system_resolve_v6(&self, name: &str) -> Vec<String> {
        for srv in system_dns_servers().iter().take(2) {
            let a = dns::query_aaaa(srv, name, Duration::from_secs(2));
            if !a.is_empty() { return dedup(a); }
        }
        vec![]
    }
}

fn dedup(v: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(v.len());
    for x in v { if !out.contains(&x) { out.push(x); } }
    out
}

fn doh_a(url: &str, name: &str) -> Vec<String> {
    let Ok((200, body)) = crate::probe::http_get(&format!("{url}?name={name}&type=A"), Duration::from_secs(5), "application/dns-json") else { return vec![] };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else { return vec![] };
    v["Answer"].as_array().map(|a| a.iter().filter(|x| x["type"] == 1).filter_map(|x| x["data"].as_str().map(String::from)).collect()).unwrap_or_default()
}

#[derive(Clone, Debug, Default)]
pub struct Adapter { pub name: String, pub description: String, pub up: bool, pub dns: Vec<String>, pub gateways: Vec<String> }

/// IPv4 adapters with their DNS servers and gateways (GetAdaptersAddresses).
pub fn adapters() -> Vec<Adapter> {
    let mut out = Vec::new();
    let mut len: u32 = 32 * 1024;
    let mut buf: Vec<u64> = vec![0; (len as usize) / 8];
    unsafe {
        let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut rc = GetAdaptersAddresses(AF_INET as u32, flags, std::ptr::null(), buf.as_mut_ptr() as *mut _, &mut len);
        if rc == 111 { // ERROR_BUFFER_OVERFLOW
            buf = vec![0; (len as usize) / 8 + 1];
            rc = GetAdaptersAddresses(AF_INET as u32, flags, std::ptr::null(), buf.as_mut_ptr() as *mut _, &mut len);
        }
        if rc != 0 { return out; }
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !p.is_null() {
            let a = &*p;
            let mut ad = Adapter {
                name: pwstr(a.FriendlyName), description: pwstr(a.Description),
                up: a.OperStatus == windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp && a.IfType != 24,
                ..Default::default()
            };
            let mut d = a.FirstDnsServerAddress;
            while !d.is_null() { if let Some(ip) = sockaddr_v4((*d).Address.lpSockaddr) { ad.dns.push(ip); } d = (*d).Next; }
            let mut g = a.FirstGatewayAddress;
            while !g.is_null() { if let Some(ip) = sockaddr_v4((*g).Address.lpSockaddr) { ad.gateways.push(ip); } g = (*g).Next; }
            out.push(ad);
            p = a.Next;
        }
    }
    out
}

unsafe fn pwstr(p: *const u16) -> String {
    if p.is_null() { return String::new(); }
    let mut n = 0;
    while *p.add(n) != 0 { n += 1; }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

unsafe fn sockaddr_v4(sa: *const windows_sys::Win32::Networking::WinSock::SOCKADDR) -> Option<String> {
    if sa.is_null() || (*sa).sa_family != AF_INET { return None; }
    let sin = &*(sa as *const SOCKADDR_IN);
    let b = sin.sin_addr.S_un.S_addr.to_ne_bytes();
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}

/// DNS servers Windows is using right now (adapters that are up and have a gateway).
pub fn system_dns_servers() -> Vec<String> {
    let mut v = Vec::new();
    for a in adapters().into_iter().filter(|a| a.up && !a.gateways.is_empty()) {
        for d in a.dns { if !v.contains(&d) { v.push(d); } }
    }
    v
}

/// OpenDNS tells our public IP, Team Cymru its ASN and name. Used to tell networks apart.
pub fn detect_network() -> NetworkId {
    let gw = adapters().into_iter().filter(|a| a.up).flat_map(|a| a.gateways).next();
    let mut id = NetworkId::default();
    let t = Duration::from_millis(2500);
    if let Some(me) = dns::query_a("208.67.222.222", "myip.opendns.com", t).into_iter().next() {
        let rev: Vec<&str> = me.split('.').rev().collect();
        let txt = dns::query("8.8.8.8", &format!("{}.origin.asn.cymru.com", rev.join(".")), dns::TYPE_TXT, t).ok()
            .and_then(|v| v.into_iter().find(|a| a.rtype == dns::TYPE_TXT)).map(|a| a.data);
        // "18403 | 42.118.0.0/15 | VN | apnic | 2008-02-19"
        if let Some(txt) = txt {
            let parts: Vec<&str> = txt.split('|').map(str::trim).collect();
            if parts.len() >= 3 {
                let asn = parts[0].split(' ').next().unwrap_or("").to_string();
                id.country = Some(parts[2].to_string());
                let name = dns::query("8.8.8.8", &format!("AS{asn}.asn.cymru.com"), dns::TYPE_TXT, t).ok()
                    .and_then(|v| v.into_iter().find(|a| a.rtype == dns::TYPE_TXT)).map(|a| a.data);
                // "18403 | VN | apnic | 2002-03-19 | FPT-AS-AP The Corporation for Financing & Promoting Technology, VN"
                if let Some(n) = name { id.as_name = n.split('|').nth(4).map(|s| s.trim().to_string()); }
                id.asn = Some(asn);
            }
        }
    }
    id.key = Some(format!("{}|{}", id.asn.as_deref().unwrap_or("?"), gw.as_deref().unwrap_or("?")));
    id
}
