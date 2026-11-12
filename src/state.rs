//! What RustyDPI remembers between checks (state.json), and the user's settings (settings.json).

use crate::probe::Fail;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

pub type Time = NaiveDateTime;
pub fn now() -> Time { chrono::Local::now().naive_local() }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum Route { #[default] Unknown, Direct, Pinned, Bypass, PinnedBypass, Broken, Relay }

impl Route {
    pub fn text(self) -> &'static str {
        match self {
            Route::Direct => "direct", Route::Pinned => "pinned", Route::Bypass => "bypass",
            Route::PinnedBypass => "pinned+bypass", Route::Broken => "not working", Route::Unknown => "unknown",
            Route::Relay => "driverless",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IpEntry {
    pub first_seen: Option<Time>,
    pub last_seen_dns: Option<Time>,
    pub last_probe: Option<Time>,
    pub last_ok: Option<Time>,
    pub last_fail: Option<Time>,
    pub fail_streak: u32,
    pub last_ms: Option<f64>,
    pub last_reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TargetState {
    pub ips: HashMap<String, IpEntry>,
    pub challenger: Option<String>,
    pub challenger_runs: u32,
    pub failed_runs: u32,
    pub route: Route,
    pub last_ms: Option<f64>,
    pub last_note: Option<String>,
    pub last_direct_fail: Fail,
    pub last_ok: Option<Time>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BypassState {
    pub strategy: Option<String>,
    pub strategy_network: Option<String>,
    pub last_test: Option<Time>,
    pub scores: BTreeMap<String, String>,
    pub hosts: Vec<String>,
    pub last_error: Option<String>,
    pub unhealthy_runs: u32,
    /// Hosts the main strategy doesn't unblock but another one does: host -> strategy id.
    pub overrides: BTreeMap<String, String>,
    /// Checks in a row each bypassed host failed through the bypass.
    pub host_fails: BTreeMap<String, u32>,
    /// winws itself couldn't start (driver blocked, files missing), as opposed to no strategy working.
    pub start_failed: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct NetworkId {
    pub asn: Option<String>,
    pub as_name: Option<String>,
    pub country: Option<String>,
    pub key: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct State {
    pub version: Option<String>,
    pub last_run: Option<Time>,
    pub last_full_run: Option<Time>,
    pub blocked_network: bool,
    pub network: NetworkId,
    pub targets: HashMap<String, TargetState>,
    pub last_pins: BTreeMap<String, String>,
    pub bypass: BypassState,
    /// Sites served by the driverless relay: host -> the server it forwards to.
    pub relay_routes: BTreeMap<String, String>,
}

impl State {
    /// The state of one target; drops anything that isn't a valid public IP (state is data, never trusted).
    pub fn target(&mut self, name: &str) -> &mut TargetState {
        let ts = self.targets.entry(name.to_string()).or_default();
        ts.ips.retain(|ip, _| crate::iputil::is_public_ipv4(ip));
        ts
    }

    pub fn load(path: &Path, warn: &dyn Fn(String)) -> State {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                warn(format!("state.json unreadable, starting fresh ({e})"));
                State::default()
            }),
            Err(_) => State::default(),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> { save_json(path, self) }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub bypass_enabled: bool,
    /// Check and fix Steam (on by default). Off: only the sites the user added.
    pub steam_enabled: bool,
    pub auto_restart_steam: bool,
    /// Sites besides Steam the user wants unblocked (validated host names).
    pub extra_sites: Vec<String>,
    /// Hosts-file resets before this time are no longer reported (the user dismissed them).
    pub hosts_resets_seen: Option<Time>,
    /// Look for a new version on GitHub once a day (installing always waits for the user).
    pub check_updates: bool,
}

impl Default for Settings { fn default() -> Self { Settings { bypass_enabled: true, steam_enabled: true, auto_restart_steam: false, extra_sites: vec![], hosts_resets_seen: None, check_updates: true } } }

impl Settings {
    pub fn load(path: &Path) -> Settings {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }
    pub fn save(&self, path: &Path) -> std::io::Result<()> { save_json(path, self) }
}

pub fn save_json<T: Serialize>(path: &Path, v: &T) -> std::io::Result<()> {
    if let Some(d) = path.parent() { std::fs::create_dir_all(d)?; }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(v)?)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_invalid_ips() {
        let mut s = State::default();
        s.targets.entry("a.com".into()).or_default().ips.insert("127.0.0.1".into(), IpEntry::default());
        s.targets.get_mut("a.com").unwrap().ips.insert("8.8.8.8".into(), IpEntry::default());
        assert_eq!(s.target("a.com").ips.keys().collect::<Vec<_>>(), vec!["8.8.8.8"]);
    }

    #[test]
    fn reads_v2_state() {
        // v2 (PowerShell) wrote local times without an offset; they must still load.
        let v2 = r#"{"targets":{"store.steampowered.com":{"ips":{"42.119.186.138":{"firstSeen":"2026-11-10T20:01:02","lastOk":"2026-11-10T23:36:44","failStreak":0,"lastMs":20}},"challenger":null,"challengerRuns":0,"failedRuns":0}},"lastPins":{"store.steampowered.com":"42.119.186.138"},"lastRun":"2026-11-10T23:36:44","version":"2.0.0"}"#;
        let p = std::env::temp_dir().join(format!("rustydpi-v2state-{}.json", std::process::id()));
        std::fs::write(&p, v2).unwrap();
        let s = State::load(&p, &|w| panic!("{w}"));
        assert_eq!(s.last_pins["store.steampowered.com"], "42.119.186.138");
        assert!(s.targets["store.steampowered.com"].ips["42.119.186.138"].last_ok.is_some());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn corrupt_state_warns() {
        let p = std::env::temp_dir().join(format!("rustydpi-badstate-{}.json", std::process::id()));
        std::fs::write(&p, "{ not json").unwrap();
        let warned = std::cell::Cell::new(false);
        let s = State::load(&p, &|_| warned.set(true));
        assert!(warned.get() && s.targets.is_empty());
        let _ = std::fs::remove_file(&p);
    }
}
