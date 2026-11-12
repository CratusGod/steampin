//! Configuration: built-in defaults (assets/default-config.json), optionally overridden by
//! C:\ProgramData\RustyDPI\config.json. Everything is validated before use.

use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Target {
    pub name: String,
    pub group: String,
    pub path: String,
    pub expect_status: Vec<u16>,
    pub expect_body: Option<String>,
    pub expect_redirect: Option<String>,
    pub seeds: Vec<String>,
    /// Probe with a browser-sized (post-quantum) ClientHello, as Chrome, Edge and Firefox send today.
    #[serde(skip)]
    pub big_hello: bool,
    /// Added by the user (Sites tab), not one of Steam's hosts.
    #[serde(skip)]
    pub user: bool,
}

impl Default for Target {
    fn default() -> Self {
        Target { name: String::new(), group: "Other".into(), path: "/".into(), expect_status: vec![200], expect_body: None, expect_redirect: None, seeds: vec![], big_hello: false, user: false }
    }
}

/// Group name for the sites the user added.
pub const USER_GROUP: &str = "Other sites";
pub const MAX_SITES: usize = 30;

/// How a user-added site appears in logs, reports and (until "Show names" is on) the window:
/// first letter and top-level domain only, with a fixed-length middle so the length doesn't leak.
/// "discord.com" -> "d****.com"
pub fn mask_site(name: &str) -> String {
    let first = name.chars().next().unwrap_or('?');
    let tld = name.rsplit('.').next().unwrap_or("");
    format!("{first}****.{tld}")
}

/// Turns what a user typed ("https://www.Example.com/page", "example.com:443") into a host name, or None.
pub fn clean_site(s: &str) -> Option<String> {
    let mut h = s.trim().to_ascii_lowercase();
    if let Some(i) = h.find("://") { h = h[i + 3..].to_string(); }
    if let Some(i) = h.find(|c| c == '/' || c == '?' || c == '#') { h.truncate(i); }
    if let Some(i) = h.rfind('@') { h = h[i + 1..].to_string(); }
    if let Some(i) = h.find(':') { h.truncate(i); }
    let h = h.trim_start_matches("*.").trim_end_matches('.').to_string();
    is_host_name(&h).then_some(h)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub targets: Vec<Target>,
    pub seeds: Vec<String>,
    pub resolvers: Vec<String>,
    pub doh_urls: Vec<String>,
    pub allowed_networks: Vec<String>,
    pub bypass_domains: Vec<String>,
    pub bypass_exclude: Vec<String>,
    pub samples: u32,
    pub probe_timeout_sec: u64,
    pub connect_timeout_sec: u64,
    pub max_candidates_per_name: usize,
    pub max_parallel_probes: usize,
    pub switch_min_gain_pct: f64,
    pub switch_min_gain_ms: f64,
    pub switch_confirm_runs: u32,
    pub remove_after_failed_runs: u32,
    pub forget_after_days: f64,
    pub run_budget_sec: u64,
    pub check_interval_min: u64,
    pub full_check_interval_hours: u64,
    pub connectivity_url: Option<String>,
    pub connectivity_expect: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            targets: vec![], seeds: vec![], resolvers: vec![], doh_urls: vec![], allowed_networks: vec![],
            bypass_domains: vec![], bypass_exclude: vec![],
            samples: 3, probe_timeout_sec: 6, connect_timeout_sec: 3, max_candidates_per_name: 16, max_parallel_probes: 24,
            switch_min_gain_pct: 20.0, switch_min_gain_ms: 15.0, switch_confirm_runs: 2, remove_after_failed_runs: 2,
            forget_after_days: 14.0, run_budget_sec: 300, check_interval_min: 30, full_check_interval_hours: 24,
            connectivity_url: Some("http://www.msftconnecttest.com/connecttest.txt".into()),
            connectivity_expect: Some("Microsoft Connect Test".into()),
        }
    }
}

pub const DEFAULT_JSON: &str = include_str!("../assets/default-config.json");

fn host_rx() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$").unwrap())
}

pub fn is_host_name(s: &str) -> bool { s.len() <= 253 && host_rx().is_match(s) }

impl Config {
    pub fn default_config() -> Config { Config::parse(DEFAULT_JSON).expect("built-in config is valid") }

    /// The override file when it exists, else the built-in defaults.
    pub fn load(path: &std::path::Path) -> Result<Config, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => Config::parse(&s),
            Err(_) => Ok(Config::default_config()),
        }
    }

    pub fn parse(json: &str) -> Result<Config, String> {
        let mut c: Config = serde_json::from_str(json).map_err(|e| format!("config.json: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    /// Adds the user's own sites as targets: any HTTP answer over HTTPS with a valid certificate counts
    /// as working (a blocked site gets a reset, a timeout or a block page with the wrong certificate).
    pub fn add_sites(&mut self, sites: &[String]) {
        for s in sites.iter().filter_map(|s| clean_site(s)).take(MAX_SITES) {
            if self.targets.iter().any(|t| t.name == s) { continue; }
            self.targets.push(Target { name: s, group: USER_GROUP.into(), expect_status: (100..=599).collect(), user: true, big_hello: true, ..Default::default() });
        }
    }

    /// A host name as it may be written to the log: user-added sites are masked.
    pub fn shown(&self, name: &str) -> String {
        if self.targets.iter().any(|t| t.user && t.name == name) { mask_site(name) } else { name.to_string() }
    }

    #[allow(dead_code)]
    pub fn target(&self, name: &str) -> Option<&Target> { self.targets.iter().find(|t| t.name == name) }

    pub fn validate(&mut self) -> Result<(), String> {
        if self.targets.is_empty() { return Err("Config has no targets.".into()); }
        let path_rx = Regex::new(r"^/[A-Za-z0-9/._~%?=&+-]*$").unwrap();
        let resolver_rx = Regex::new(r"^[A-Za-z0-9.-]+$").unwrap();
        let doh_rx = Regex::new(r"^https://[A-Za-z0-9.-]+(/[A-Za-z0-9/._-]*)?$").unwrap();
        let mut seen = std::collections::HashSet::new();
        for t in &mut self.targets {
            t.name = t.name.trim().to_ascii_lowercase();
            if t.name.is_empty() { return Err("Every target needs a name.".into()); }
            if !is_host_name(&t.name) { return Err(format!("Bad target name: {}", t.name)); }
            if !seen.insert(t.name.clone()) { return Err(format!("Duplicate target: {}", t.name)); }
            if t.path.is_empty() { t.path = "/".into(); }
            if !path_rx.is_match(&t.path) { return Err(format!("Bad path for {}: {}", t.name, t.path)); }
            if t.expect_status.is_empty() { t.expect_status = vec![200]; }
            if t.group.trim().is_empty() { t.group = "Other".into(); }
            for rx in [&t.expect_body, &t.expect_redirect].into_iter().flatten() {
                Regex::new(rx).map_err(|e| format!("Bad regex for {}: {e}", t.name))?;
            }
            for ip in &t.seeds { if !crate::iputil::is_public_ipv4(ip) { return Err(format!("Bad seed IP in config: {ip}")); } }
        }
        for ip in &self.seeds { if !crate::iputil::is_public_ipv4(ip) { return Err(format!("Bad seed IP in config: {ip}")); } }
        for n in &self.allowed_networks { if !crate::iputil::is_cidr(n) { return Err(format!("Bad network in allowedNetworks: {n}")); } }
        for r in &self.resolvers { if !resolver_rx.is_match(r) { return Err(format!("Bad resolver: {r}")); } }
        for u in &self.doh_urls { if !doh_rx.is_match(u) { return Err(format!("Bad DoH URL: {u}")); } }
        for d in self.bypass_domains.iter_mut().chain(self.bypass_exclude.iter_mut()) {
            *d = d.trim().to_ascii_lowercase();
            if !is_host_name(d) { return Err(format!("Bad bypass domain: {d}")); }
        }
        if !(1..=10).contains(&self.samples) { return Err("samples must be 1-10.".into()); }
        if !(1..=60).contains(&self.probe_timeout_sec) || !(1..=30).contains(&self.connect_timeout_sec) { return Err("Bad timeouts.".into()); }
        if !(1..=64).contains(&self.max_candidates_per_name) { return Err("maxCandidatesPerName must be 1-64.".into()); }
        if !(1..=128).contains(&self.max_parallel_probes) { return Err("maxParallelProbes must be 1-128.".into()); }
        if self.switch_confirm_runs < 1 || self.remove_after_failed_runs < 1 { return Err("Run counts must be at least 1.".into()); }
        if !(5..=1440).contains(&self.check_interval_min) { return Err("checkIntervalMin must be 5-1440.".into()); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_loads() {
        let c = Config::default_config();
        assert_eq!(c.targets.len(), 14);
        assert!(c.target("steamcommunity.com").is_some());
        assert_eq!(c.samples, 3);
        assert!(c.allowed_networks.is_empty());
    }

    #[test]
    fn missing_file_gives_defaults() {
        assert_eq!(Config::load(std::path::Path::new("Z:\\nope\\config.json")).unwrap().targets.len(), 14);
    }

    #[test]
    fn rejects_bad() {
        let cases = [
            r#"{ "targets": [] }"#,
            r#"{ "targets": [ { "name": "not a host" } ] }"#,
            r#"{ "targets": [ { "name": "a.com" }, { "name": "A.com" } ] }"#,
            r#"{ "targets": [ { "name": "a.com", "path": "no-slash" } ] }"#,
            r#"{ "targets": [ { "name": "a.com" } ], "seeds": ["127.0.0.1"] }"#,
            r#"{ "targets": [ { "name": "a.com", "seeds": ["10.0.0.1"] } ] }"#,
            r#"{ "targets": [ { "name": "a.com" } ], "allowedNetworks": ["42.118.0.0"] }"#,
            r#"{ "targets": [ { "name": "a.com" } ], "resolvers": ["8.8.8.8; rm"] }"#,
            r#"{ "targets": [ { "name": "a.com" } ], "dohUrls": ["http://dns.google/resolve"] }"#,
            r#"{ "targets": [ { "name": "a.com", "expectBody": "(" } ] }"#,
            r#"{ "targets": [ { "name": "a.com" } ], "samples": 0 }"#,
            r#"{ "targets": [ { "name": "a.com" } ], "bypassDomains": ["-x"] }"#,
            r#"{ "targets": "#,
        ];
        for c in cases { assert!(Config::parse(c).is_err(), "{c}"); }
    }

    #[test]
    fn cleans_user_sites() {
        assert_eq!(clean_site(" https://www.Example.com/a/b?c=1 ").as_deref(), Some("www.example.com"));
        assert_eq!(clean_site("discord.com:443").as_deref(), Some("discord.com"));
        assert_eq!(clean_site("*.medium.com").as_deref(), Some("medium.com"));
        for bad in ["", "localhost", "not a site", "a..com", "1.2.3", "exa mple.com", "-x.com", "x.com\n127.0.0.1 evil.com"] {
            assert_eq!(clean_site(bad), None, "{bad:?}");
        }
        let mut c = Config::default_config();
        c.add_sites(&["Example.com".into(), "example.com".into(), "store.steampowered.com".into(), "bad name".into()]);
        assert_eq!(c.targets.len(), 15);
        let t = c.target("example.com").unwrap();
        assert!(t.user && t.group == USER_GROUP && t.expect_status.contains(&403));
        assert!(!c.target("store.steampowered.com").unwrap().user);
        assert_eq!(mask_site("discord.com"), "d****.com");
        assert_eq!(mask_site("www.example.co.uk"), "w****.uk");
        assert_eq!(c.shown("example.com"), "e****.com");
        assert_eq!(c.shown("store.steampowered.com"), "store.steampowered.com");
    }

    #[test]
    fn normalises() {
        let c = Config::parse(r#"{ "targets": [ { "name": "Store.SteamPowered.com" } ] }"#).unwrap();
        assert_eq!(c.targets[0].name, "store.steampowered.com");
        assert_eq!(c.targets[0].path, "/");
        assert_eq!(c.targets[0].expect_status, vec![200]);
    }
}
