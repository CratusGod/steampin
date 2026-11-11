//! IPv4 validation. Everything that can reach the hosts file passes through `is_public_ipv4`.

use std::net::Ipv4Addr;

const NON_PUBLIC: &[&str] = &[
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
];

/// Parses a canonical dotted IPv4 (no leading zeros, no spaces).
fn parse_canonical(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    for p in &parts {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
    }
    s.parse::<Ipv4Addr>().ok()
}

/// True only for a canonical dotted IPv4 address that is publicly routable.
pub fn is_public_ipv4(s: &str) -> bool {
    match parse_canonical(s) {
        Some(_) => !NON_PUBLIC.iter().any(|c| in_cidr(s, c)),
        None => false,
    }
}

pub fn is_cidr(s: &str) -> bool {
    let Some((ip, len)) = s.split_once('/') else { return false };
    parse_canonical(ip).is_some() && len.parse::<u8>().map(|l| l <= 32).unwrap_or(false) && !len.starts_with('+')
}

pub fn in_cidr(ip: &str, cidr: &str) -> bool {
    let Some((net, len)) = cidr.split_once('/') else { return false };
    let (Some(ip), Some(net), Ok(len)) = (parse_canonical(ip), parse_canonical(net), len.parse::<u32>()) else { return false };
    if len > 32 { return false; }
    let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

pub fn in_any(ip: &str, networks: &[String]) -> bool {
    networks.is_empty() || networks.iter().any(|n| in_cidr(ip, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public() {
        for ok in ["42.119.186.138", "118.69.17.16", "8.8.8.8", "1.1.1.1"] { assert!(is_public_ipv4(ok), "{ok}"); }
        for bad in ["127.0.0.1", "0.0.0.0", "10.1.2.3", "192.168.1.1", "172.20.0.1", "100.64.0.1", "203.0.113.113",
                    "224.0.0.1", "255.255.255.255", "1.2.3", "01.2.3.4", "1.2.3.4 ", "::1", "", "256.1.1.1", "1.2.3.4.5", "a.b.c.d"] {
            assert!(!is_public_ipv4(bad), "{bad}");
        }
    }

    #[test]
    fn cidr() {
        assert!(in_cidr("42.119.186.138", "42.118.0.0/15"));
        assert!(in_cidr("42.118.0.1", "42.118.0.0/15"));
        assert!(!in_cidr("42.120.0.1", "42.118.0.0/15"));
        assert!(in_cidr("183.81.255.255", "183.80.0.0/15"));
        assert!(in_cidr("9.9.9.9", "0.0.0.0/0"));
        assert!(in_cidr("1.2.3.4", "1.2.3.4/32"));
        assert!(!in_cidr("1.2.3.5", "1.2.3.4/32"));
        assert!(!in_cidr("1.2.3.4", "1.2.3.0/33"));
        assert!(is_cidr("42.118.0.0/15"));
        assert!(!is_cidr("42.118.0.0"));
        assert!(!is_cidr("42.118.0.0/33"));
    }

    #[test]
    fn allow_list() {
        assert!(in_any("23.53.33.1", &[]));
        assert!(!in_any("23.53.33.1", &["42.118.0.0/15".into(), "118.68.0.0/15".into()]));
    }
}
