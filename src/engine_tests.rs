//! Engine scenarios against a simulated network: which server works for which host, what DNS says,
//! and which bypass strategy unblocks what.

use crate::bypass::{self, BypassFiles, Runner};
use crate::config::{Config, Target};
use crate::engine::{Engine, RunKind, RunReport, TargetRow};
use crate::hosts;
use crate::net::Net;
use crate::paths::{Log, Paths};
use crate::probe::{Fail, ProbeResult, Prober};
use crate::state::{NetworkId, Route, Settings};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Default)]
struct W {
    online: bool,
    system_dns: HashMap<String, Vec<String>>,
    public_dns: HashMap<String, Vec<String>>,
    works: HashMap<(String, String), f64>,
    works_with_bypass: HashMap<(String, String), HashSet<&'static str>>,
    /// (host, server) pairs that answer when the ClientHello comes in small TLS records.
    works_fragmented: HashSet<(String, String)>,
    relay_routes: std::collections::BTreeMap<String, String>,
    system_dns_v6: HashMap<String, String>,
    running: Option<&'static str>,
    /// TCP profiles of the running winws in order: (inline host list, or None for the main list; strategy).
    profiles: Vec<(Option<Vec<String>>, &'static str)>,
    args: Vec<String>,
    start_error: Option<String>,
    starts: u32,
    stops: u32,
    direct_probes: u32,
    flushes: u32,
    network: NetworkId,
}

struct World { w: Mutex<W>, files: BypassFiles }

fn k(h: &str, ip: &str) -> (String, String) { (h.to_string(), ip.to_string()) }

impl World {
    /// The strategy winws applies to `host`: the first TCP profile whose host list matches.
    fn strategy_for(&self, host: &str) -> Option<&'static str> {
        let m = |h: &str, d: &str| h == d || h.ends_with(&format!(".{d}"));
        let profiles = self.w.lock().unwrap().profiles.clone();
        profiles.into_iter().find(|(list, _)| match list { Some(l) => l.iter().any(|d| m(host, d)), None => self.bypassed(host, true) }).map(|p| p.1)
    }

    fn bypassed(&self, host: &str, running: bool) -> bool {
        if !running { return false; }
        let m = |h: &str, d: &str| h == d || h.ends_with(&format!(".{d}"));
        let inc = std::fs::read_to_string(self.files.host_list()).unwrap_or_default();
        let exc = std::fs::read_to_string(self.files.exclude_list()).unwrap_or_default();
        inc.lines().any(|d| m(host, d)) && !exc.lines().any(|d| !d.is_empty() && m(host, d))
    }
}

impl Net for World {
    fn is_online(&self) -> bool { self.w.lock().unwrap().online }
    fn system_resolve(&self, n: &str) -> Vec<String> { self.w.lock().unwrap().system_dns.get(n).cloned().unwrap_or_default() }
    fn public_resolve(&self, n: &str) -> Vec<String> { self.w.lock().unwrap().public_dns.get(n).cloned().unwrap_or_default() }
    fn flush_dns(&self) { self.w.lock().unwrap().flushes += 1; }
    fn detect_network(&self) -> NetworkId { self.w.lock().unwrap().network.clone() }
    fn system_resolve_v6(&self, n: &str) -> Vec<String> { self.w.lock().unwrap().system_dns_v6.get(n).cloned().into_iter().collect() }
}

impl Prober for World {
    fn probe(&self, t: &Target, ip: &str) -> ProbeResult { self.check(t, ip, false) }
    fn probe_direct(&self, t: &Target, ip: &str) -> ProbeResult { self.w.lock().unwrap().direct_probes += 1; self.check(t, ip, true) }
    fn probe_fragmented(&self, t: &Target, ip: &str) -> ProbeResult {
        if self.w.lock().unwrap().works_fragmented.contains(&k(&t.name, ip)) { ProbeResult::good(40.0, 200) } else { self.check(t, ip, true) }
    }
}

impl crate::relay::Routes for World {
    fn set_routes(&self, r: std::collections::BTreeMap<String, String>) -> Result<std::collections::BTreeMap<String, String>, String> {
        let a = crate::relay::assign(r.keys()).into_iter().map(|(h, ip)| (h, ip.to_string())).collect();
        self.w.lock().unwrap().relay_routes = r;
        Ok(a)
    }
}

impl World {
    /// `direct`: the probe is marked so winws leaves it alone.
    fn check(&self, t: &Target, ip: &str, direct: bool) -> ProbeResult {
        if crate::relay::is_relay_ip(ip) {
            let w = self.w.lock().unwrap();
            let up = w.relay_routes.get(&t.name).cloned().unwrap_or_default();
            return if w.works_fragmented.contains(&k(&t.name, &up)) { ProbeResult::good(45.0, 200) } else { ProbeResult::failed(Fail::TlsReset, "TLS reset (blocked)") };
        }
        let (ms, wb, running) = {
            let w = self.w.lock().unwrap();
            (w.works.get(&k(&t.name, ip)).copied(), w.works_with_bypass.get(&k(&t.name, ip)).cloned(), w.running.filter(|_| !direct))
        };
        if let Some(ms) = ms { return ProbeResult::good(ms, 200); }
        if let Some(strategies) = wb {
            return match running.and_then(|_| self.strategy_for(&t.name)) {
                Some(s) if strategies.contains(s) => ProbeResult::good(30.0, 200),
                _ => ProbeResult::failed(Fail::TlsReset, "TLS reset (blocked)"),
            };
        }
        ProbeResult::failed(Fail::WrongCertificate, "wrong certificate (another site)")
    }
}

impl Runner for World {
    fn is_running(&self) -> bool { self.w.lock().unwrap().running.is_some() }
    fn recent_output(&self) -> String { String::new() }
    fn start(&self, args: &[String]) -> Result<(), String> {
        let mut w = self.w.lock().unwrap();
        w.starts += 1;
        if let Some(e) = w.start_error.clone() { w.running = None; return Err(e); }
        let tls = self.files.fake_tls().display().to_string();
        let profiles: Vec<(Option<Vec<String>>, &'static str)> = args.split(|a| a == "--new").filter(|p| p.iter().any(|a| a == "--filter-tcp=80,443")).map(|p| {
            let desync: Vec<String> = p.iter().filter(|a| a.starts_with("--dpi-desync")).cloned().collect();
            let id = bypass::STRATEGIES.iter().find(|s| s.tcp.iter().map(|a| a.replace("{tls}", &tls)).collect::<Vec<_>>() == desync).expect("known strategy").id;
            (p.iter().find_map(|a| a.strip_prefix("--hostlist-domains=")).map(|d| d.split(',').map(String::from).collect()), id)
        }).collect();
        w.running = profiles.iter().find(|p| p.0.is_none()).map(|p| p.1);
        w.profiles = profiles;
        w.args = args.to_vec();
        Ok(())
    }
    fn current_args(&self) -> Option<Vec<String>> { let w = self.w.lock().unwrap(); w.running.map(|_| w.args.clone()) }
    fn stop(&self) { let mut w = self.w.lock().unwrap(); if w.running.is_some() { w.stops += 1; } w.running = None; }
}

const STORE: &str = "store.steampowered.com";
const API: &str = "api.steampowered.com";
const LOGIN: &str = "login.steampowered.com";
const COMMUNITY: &str = "steamcommunity.com";

struct T { dir: PathBuf, paths: Paths, world: World, cfg: Config, log: Log }

impl Drop for T { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }

fn setup(tag: &str) -> T {
    let dir = std::env::temp_dir().join(format!("rustydpi-eng-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let paths = Paths { install_dir: dir.join("install"), data_dir: dir.join("data"), hosts: dir.join("hosts") };
    std::fs::write(&paths.hosts, "# Copyright (c) Microsoft Corp.\r\n127.0.0.1 localhost\r\n").unwrap();
    let cfg = Config::parse(r#"{
      "targets": [
        { "name": "store.steampowered.com", "group": "Store" },
        { "name": "api.steampowered.com", "group": "Sign-in" },
        { "name": "login.steampowered.com", "group": "Sign-in" },
        { "name": "steamcommunity.com", "group": "Community" }
      ],
      "seeds": ["42.119.186.138", "118.69.17.16"],
      "bypassDomains": ["steampowered.com", "steamcommunity.com"],
      "bypassExclude": ["steamcontent.com"]
    }"#).unwrap();
    let world = World { w: Mutex::new(W { online: true, network: NetworkId { asn: Some("18403".into()), as_name: Some("FPT".into()), country: None, key: Some("18403|gw".into()) }, ..Default::default() }), files: paths.bypass() };
    let log = Log::new(Some(paths.log()), false);
    T { dir, paths, world, cfg, log }
}

impl T {
    fn engine(&self) -> Engine<'_> {
        let mut e = Engine::new(&self.cfg, &self.paths, &self.world, &self.world, &self.world, &self.log);
        e.relay = Some(&self.world);
        e.probe_gap_ms = 0;
        e.settle_ms = 0;
        e
    }
    fn run(&self, k: RunKind) -> RunReport { self.engine().run(k) }
    fn hosts(&self) -> String { std::fs::read_to_string(&self.paths.hosts).unwrap() }
    fn w(&self) -> std::sync::MutexGuard<'_, W> { self.world.w.lock().unwrap() }

    /// FPT today: DNS gives foreign edges that are reset; local edges work when pinned; community only via bypass.
    fn fpt(&self) {
        let mut w = self.w();
        for n in [STORE, API, LOGIN, COMMUNITY] {
            w.system_dns.insert(n.into(), vec!["23.53.33.1".into()]);
            w.works_with_bypass.insert(k(n, "23.53.33.1"), HashSet::from(["split-disorder"]));
        }
        w.works.insert(k(STORE, "42.119.186.138"), 20.0);
        w.works.insert(k(API, "118.69.17.16"), 20.0);
        w.works.insert(k(LOGIN, "118.69.17.16"), 22.0);
    }
}

fn row<'a>(r: &'a RunReport, n: &str) -> &'a TargetRow { r.rows.iter().find(|x| x.name == n).unwrap() }

#[test]
fn blocked_network_pins_what_it_can_bypasses_the_rest() {
    let t = setup("blocked");
    t.fpt();
    let r = t.run(RunKind::Periodic);
    assert!(r.blocked);
    let s = row(&r, STORE);
    assert_eq!((s.route, s.ip.as_deref(), s.ok), (Route::Pinned, Some("42.119.186.138"), true));
    assert_eq!(row(&r, API).route, Route::Pinned);
    assert_eq!((row(&r, COMMUNITY).route, row(&r, COMMUNITY).ok), (Route::Bypass, true));
    assert_eq!(t.w().running, Some("split-disorder"));
    let h = t.hosts();
    assert!(h.contains("42.119.186.138\tstore.steampowered.com"));
    assert!(!h.contains(COMMUNITY));
    assert!(h.contains("127.0.0.1 localhost"));
    let ex = std::fs::read_to_string(t.paths.bypass().exclude_list()).unwrap();
    assert!(ex.lines().any(|l| l == STORE) && ex.lines().any(|l| l == API) && ex.lines().any(|l| l == "steamcontent.com"));
    assert_eq!(t.w().flushes, 1);
    assert!(t.paths.status().exists());
    assert!(std::fs::read_to_string(t.paths.last_check()).unwrap().starts_with("RustyDPI 4"));
}

#[test]
fn second_run_is_idempotent() {
    let t = setup("idem");
    t.fpt();
    t.run(RunKind::Periodic);
    let before = t.hosts();
    let starts = t.w().starts;
    let r = t.run(RunKind::Periodic);
    assert_eq!(before, t.hosts());
    assert!(!r.hosts_changed);
    assert_eq!(starts, t.w().starts);
    assert!(r.rows.iter().all(|x| x.ok));
    assert_eq!(row(&r, COMMUNITY).route, Route::Bypass);
}

#[test]
fn unblocked_network_no_pins_no_bypass() {
    let t = setup("free");
    {
        let mut w = t.w();
        for n in [STORE, API, LOGIN, COMMUNITY] { w.system_dns.insert(n.into(), vec!["2.2.2.2".into()]); w.works.insert(k(n, "2.2.2.2"), 30.0); }
        w.works.insert(k(STORE, "42.119.186.138"), 5.0);
    }
    let r = t.run(RunKind::Periodic);
    assert!(!r.blocked);
    assert!(r.rows.iter().all(|x| x.route == Route::Direct));
    assert!(!t.hosts().contains("RustyDPI"));
    assert!(t.w().running.is_none());
    assert_eq!(t.w().flushes, 0);
}

#[test]
fn poisoned_dns_pins_resettable_server_and_bypasses() {
    let t = setup("poison");
    t.fpt();
    {
        let mut w = t.w();
        w.system_dns.insert(COMMUNITY.into(), vec!["127.0.0.1".into()]);
        w.public_dns.insert(COMMUNITY.into(), vec!["42.119.184.231".into()]);
        w.works_with_bypass.insert(k(COMMUNITY, "42.119.184.231"), HashSet::from(["fake-split"]));
    }
    let r = t.run(RunKind::Periodic);
    let c = row(&r, COMMUNITY);
    assert_eq!((c.route, c.ip.as_deref(), c.ok), (Route::PinnedBypass, Some("42.119.184.231"), true));
    assert!(c.direct_problem.contains("poisoned"));
    assert_eq!(t.w().running, Some("fake-split"));
    assert!(t.hosts().contains("42.119.184.231\tsteamcommunity.com"));
}

#[test]
fn pinned_and_bypassed_host_survives_full_checks() {
    let t = setup("poisonfull");
    t.fpt();
    {
        let mut w = t.w();
        w.system_dns.insert(COMMUNITY.into(), vec!["127.0.0.1".into()]);
        w.public_dns.insert(COMMUNITY.into(), vec!["42.119.184.231".into()]);
        w.works_with_bypass.insert(k(COMMUNITY, "42.119.184.231"), HashSet::from(["split-disorder"]));
    }
    for (i, kind) in [RunKind::Periodic, RunKind::Full, RunKind::Periodic, RunKind::Full, RunKind::Full].into_iter().enumerate() {
        let r = t.run(kind);
        let c = row(&r, COMMUNITY);
        assert_eq!((c.route, c.ok, c.ip.as_deref()), (Route::PinnedBypass, true, Some("42.119.184.231")), "run {i} ({kind:?}): {c:?}");
        assert!(t.hosts().contains("42.119.184.231\tsteamcommunity.com"), "run {i}");
    }
}

#[test]
fn site_blocked_over_ipv6_is_pinned_to_ipv4() {
    let mut t = setup("ipv6");
    t.cfg.add_sites(&["v6.example.org".into(), "v6ok.example.org".into()]);
    t.fpt();
    {
        let mut w = t.w();
        for (h, v4, v6) in [("v6.example.org", "104.16.1.1", "2606:4700::1"), ("v6ok.example.org", "104.16.2.2", "2606:4700::2")] {
            w.system_dns.insert(h.into(), vec![v4.into()]);
            w.system_dns_v6.insert(h.into(), v6.into());
            w.works_with_bypass.insert(k(h, v4), HashSet::from(["split-disorder"]));
        }
        // Only the second site's IPv6 address works through the bypass.
        w.works_with_bypass.insert(k("v6ok.example.org", "2606:4700::2"), HashSet::from(["split-disorder"]));
        w.works_with_bypass.insert(k("v6.example.org", "2606:4700::1"), HashSet::new());
    }
    for kind in [RunKind::Periodic, RunKind::Full, RunKind::Periodic, RunKind::Full] {
        let r = t.run(kind);
        let s = row(&r, "v6.example.org");
        assert_eq!((s.route, s.ok), (Route::PinnedBypass, true), "{kind:?}: {s:?}");
        assert!(t.hosts().contains("104.16.1.1\tv6.example.org"), "{kind:?}");
        let o = row(&r, "v6ok.example.org");
        assert_eq!((o.route, o.ok), (Route::Bypass, true), "{kind:?}: {o:?}");
        assert!(!t.hosts().contains("v6ok.example.org"));
    }
}

#[test]
fn migrates_v1_legacy_lines() {
    let t = setup("legacy");
    t.fpt();
    let mut h = t.hosts();
    h += &format!("42.119.186.138\tstore.steampowered.com\t{}\r\n", hosts::LEGACY_TAG);
    std::fs::write(&t.paths.hosts, h).unwrap();
    t.run(RunKind::Periodic);
    let h = t.hosts();
    assert!(!h.contains(hosts::LEGACY_TAG));
    assert!(h.contains(hosts::BEGIN_MARK));
    assert_eq!(h.lines().filter(|l| l.contains(STORE)).count(), 1);
}

#[test]
fn dead_pin_replaced() {
    let t = setup("dead");
    t.fpt();
    t.run(RunKind::Periodic);
    {
        let mut w = t.w();
        w.works.remove(&k(STORE, "42.119.186.138"));
        w.public_dns.insert(STORE.into(), vec!["42.119.184.231".into()]);
        w.works.insert(k(STORE, "42.119.184.231"), 25.0);
    }
    let r = t.run(RunKind::Periodic);
    assert_eq!((row(&r, STORE).action.as_str(), row(&r, STORE).ip.as_deref()), ("replaced", Some("42.119.184.231")));
    assert!(t.hosts().contains("42.119.184.231\tstore.steampowered.com"));
}

#[test]
fn dead_pin_without_replacement_kept_once_then_bypass() {
    let t = setup("dead2");
    t.fpt();
    t.run(RunKind::Periodic);
    t.w().works.remove(&k(STORE, "42.119.186.138"));
    let r = t.run(RunKind::Periodic);
    assert_eq!((row(&r, STORE).action.as_str(), row(&r, STORE).route), ("failing", Route::Pinned));
    assert!(t.hosts().contains("42.119.186.138\tstore.steampowered.com"));
    let r = t.run(RunKind::Periodic);
    assert_eq!(row(&r, STORE).route, Route::Bypass);
    assert!(row(&r, STORE).ok);
    assert!(!t.hosts().contains(STORE));
}

#[test]
fn offline_changes_nothing() {
    let t = setup("offline");
    t.fpt();
    t.run(RunKind::Periodic);
    let before = t.hosts();
    let running = t.w().running;
    { let mut w = t.w(); w.online = false; w.works.clear(); }
    let r = t.run(RunKind::Full);
    assert!(!r.online);
    assert_eq!(before, t.hosts());
    assert_eq!(running, t.w().running);
}

#[test]
fn dry_run_touches_nothing() {
    let t = setup("dry");
    t.fpt();
    let before = t.hosts();
    let r = t.run(RunKind::DryRun);
    assert_eq!(before, t.hosts());
    assert!(r.hosts_changed);
    assert!(t.w().running.is_none());
    assert!(!t.paths.state().exists() && !t.paths.status().exists());
}

#[test]
fn winws_crash_restarted_next_run() {
    let t = setup("crash");
    t.fpt();
    t.run(RunKind::Periodic);
    t.w().running = None;
    let r = t.run(RunKind::Periodic);
    assert_eq!(t.w().running, Some("split-disorder"));
    assert!(row(&r, COMMUNITY).ok);
}

#[test]
fn strategy_stops_working_retested_after_two_bad_runs() {
    let t = setup("retest");
    t.fpt();
    t.run(RunKind::Periodic);
    t.w().works_with_bypass.insert(k(COMMUNITY, "23.53.33.1"), HashSet::from(["seqovl"]));
    let r = t.run(RunKind::Periodic);
    assert!(!row(&r, COMMUNITY).ok);
    t.run(RunKind::Periodic);
    assert_eq!(t.w().running, Some("seqovl"));
    let r = t.run(RunKind::Periodic);
    assert!(row(&r, COMMUNITY).ok);
}

#[test]
fn no_strategy_works_reports_broken() {
    let t = setup("nostrat");
    t.fpt();
    t.w().works_with_bypass.insert(k(COMMUNITY, "23.53.33.1"), HashSet::new());
    let r = t.run(RunKind::Periodic);
    assert_eq!(row(&r, COMMUNITY).route, Route::Broken);
    assert!(r.bypass.error.is_some());
    assert!(t.w().running.is_none());
    assert_eq!(r.bypass.scores.len(), bypass::STRATEGIES.len());
}

#[test]
fn windivert_fails_to_load_reports_error() {
    let t = setup("windivert");
    t.fpt();
    t.w().start_error = Some("winws.exe stopped at once (exit code: 1): error opening filter".into());
    let r = t.run(RunKind::Periodic);
    assert_eq!(row(&r, COMMUNITY).route, Route::Broken);
    assert!(r.bypass.error.as_deref().unwrap().contains("winws.exe stopped"));
    assert!(row(&r, STORE).ok);
}

#[test]
fn bypass_turned_off_explains() {
    let t = setup("off");
    t.fpt();
    Settings { bypass_enabled: false, ..Default::default() }.save(&t.paths.settings()).unwrap();
    let r = t.run(RunKind::Periodic);
    assert!(t.w().running.is_none());
    assert!(row(&r, COMMUNITY).note.contains("turned off"));
    assert!(!row(&r, COMMUNITY).ok);
}

#[test]
fn bypass_turned_off_while_running_reports_not_working() {
    let t = setup("offrunning");
    t.fpt();
    let r = t.run(RunKind::Periodic);
    assert!(row(&r, COMMUNITY).ok);
    Settings { bypass_enabled: false, ..Default::default() }.save(&t.paths.settings()).unwrap();
    let r = t.run(RunKind::Periodic);
    assert!(t.w().running.is_none());
    let c = row(&r, COMMUNITY);
    assert!(!c.ok, "a bypassed host can't be OK once the bypass is off");
    assert_eq!(c.route, Route::Broken);
    assert!(c.note.contains("turned off"));
    assert!(row(&r, STORE).ok);
    Settings { bypass_enabled: true, ..Default::default() }.save(&t.paths.settings()).unwrap();
    let r = t.run(RunKind::Periodic);
    assert!(row(&r, COMMUNITY).ok);
    assert!(t.w().running.is_some());
}

#[test]
fn network_change_forces_full_check() {
    let t = setup("netchg");
    t.fpt();
    t.run(RunKind::Periodic);
    t.w().network = NetworkId { asn: Some("7552".into()), as_name: Some("Viettel".into()), country: None, key: Some("7552|gw".into()) };
    let r = t.run(RunKind::Periodic);
    assert!(r.full);
    assert!(r.network.unwrap().contains("Viettel"));
}

#[test]
fn failed_isp_lookup_is_not_a_new_network() {
    let t = setup("asnfail");
    t.fpt();
    t.run(RunKind::Periodic);
    let starts = t.w().starts;
    t.w().network = NetworkId { asn: None, as_name: None, country: None, key: Some("?|gw".into()) };
    let r = t.run(RunKind::Periodic);
    assert!(!r.full, "same gateway: same network");
    assert!(r.network.unwrap().contains("FPT"));
    assert_eq!(t.w().starts, starts, "no strategy re-test");
}

#[test]
fn antivirus_wiped_block_warns_and_repins() {
    let t = setup("av");
    t.fpt();
    t.run(RunKind::Periodic);
    std::fs::write(&t.paths.hosts, "127.0.0.1 localhost\r\n").unwrap();
    let r = t.run(RunKind::Periodic);
    assert!(r.warnings.iter().any(|w| w.contains("disappeared")));
    assert!(t.hosts().contains("42.119.186.138\tstore.steampowered.com"));
}

#[test]
fn user_own_entry_warns() {
    let t = setup("own");
    t.fpt();
    let h = t.hosts() + "1.2.3.4 store.steampowered.com\r\n";
    std::fs::write(&t.paths.hosts, h).unwrap();
    let r = t.run(RunKind::Periodic);
    assert!(r.warnings.iter().any(|w| w.contains("your own entry")));
    assert!(t.hosts().contains("1.2.3.4 store.steampowered.com"));
}

#[test]
fn corrupt_state_starts_fresh() {
    let t = setup("corrupt");
    t.fpt();
    std::fs::create_dir_all(&t.paths.data_dir).unwrap();
    std::fs::write(t.paths.state(), "{ not json").unwrap();
    let r = t.run(RunKind::Periodic);
    assert!(row(&r, STORE).ok);
    assert!(std::fs::read_to_string(t.paths.log()).unwrap().contains("unreadable"));
}

#[test]
fn unpin_removes_block_only() {
    let t = setup("unpin");
    t.fpt();
    t.run(RunKind::Periodic);
    assert!(t.engine().unpin().unwrap());
    assert!(!t.hosts().contains("RustyDPI"));
    assert!(t.hosts().contains("127.0.0.1 localhost"));
    assert!(!t.engine().unpin().unwrap());
}

#[test]
fn full_check_reevaluates_bypassed_host() {
    let t = setup("full");
    t.fpt();
    t.run(RunKind::Periodic);
    { let mut w = t.w(); for n in [STORE, API, LOGIN, COMMUNITY] { w.works.insert(k(n, "23.53.33.1"), 25.0); } }
    let r = t.run(RunKind::Full);
    assert_eq!(row(&r, COMMUNITY).route, Route::Direct);
    assert!(t.w().running.is_none());
    assert_eq!(row(&r, STORE).route, Route::Pinned);
}

#[test]
fn full_check_keeps_the_bypass_running() {
    let t = setup("fullkeep");
    t.fpt();
    t.run(RunKind::Periodic);
    let counts = |t: &T| { let w = t.w(); (w.starts, w.stops) };
    let before = counts(&t);
    let r = t.run(RunKind::Full);
    assert!(r.full);
    assert_eq!(counts(&t), before, "no restart, no gap for the user's sites");
    assert_eq!(t.w().running, Some("split-disorder"));
    let c = row(&r, COMMUNITY);
    assert_eq!((c.route, c.ok), (Route::Bypass, true));
    assert!(c.direct_problem.contains("reset"), "the direct check saw the real block, not the bypass: {c:?}");
    assert!(t.w().direct_probes > 0);
}

#[test]
fn pins_are_judged_without_the_bypass() {
    // A pin that only works because winws happens to cover its domain must not be chosen as a pin.
    let t = setup("pinclean");
    t.fpt();
    t.run(RunKind::Periodic);
    { let mut w = t.w(); w.works_with_bypass.insert(k(COMMUNITY, "42.119.184.231"), HashSet::from(["split-disorder"])); w.public_dns.insert(COMMUNITY.into(), vec!["42.119.184.231".into()]); }
    let r = t.run(RunKind::Full);
    assert_ne!(row(&r, COMMUNITY).route, Route::Pinned);
    assert!(!t.hosts().contains(COMMUNITY));
}

#[test]
fn report_groups_and_text() {
    let t = setup("text");
    t.fpt();
    let r = t.run(RunKind::Periodic);
    assert_eq!(r.groups().iter().map(|g| g.0.as_str()).collect::<Vec<_>>(), vec!["Store", "Sign-in", "Community"]);
    let txt = r.to_text();
    assert!(txt.contains("network: AS18403 FPT (Steam is blocked here)"));
    assert!(txt.contains("bypass: on"));
}

#[test]
fn antivirus_wipe_on_unblocked_network_restores_existing_pins() {
    let t = setup("avfree");
    {
        let mut w = t.w();
        for n in [STORE, API, LOGIN, COMMUNITY] { w.system_dns.insert(n.into(), vec!["2.2.2.2".into()]); w.works.insert(k(n, "2.2.2.2"), 30.0); }
        w.works.insert(k(STORE, "42.119.186.138"), 20.0);
    }
    // The user (or v2) had pinned store; RustyDPI keeps healthy pins.
    let h = t.hosts() + &format!("{}\r\n42.119.186.138\tstore.steampowered.com\r\n{}\r\n", hosts::BEGIN_MARK, hosts::END_MARK);
    std::fs::write(&t.paths.hosts, h).unwrap();
    t.run(RunKind::Periodic);
    assert!(t.hosts().contains("42.119.186.138\tstore.steampowered.com"));
    std::fs::write(&t.paths.hosts, "127.0.0.1 localhost\r\n").unwrap();
    let r = t.run(RunKind::Periodic);
    assert!(r.warnings.iter().any(|w| w.contains("disappeared")));
    assert!(t.hosts().contains("42.119.186.138\tstore.steampowered.com"), "pin restored");
    assert_eq!(row(&r, STORE).route, Route::Pinned);
}

#[test]
fn user_site_that_is_down_does_not_mark_steam_blocked() {
    let mut t = setup("usersite-down");
    t.cfg.add_sites(&["example.com".into()]);
    {
        let mut w = t.w();
        for n in [STORE, API, LOGIN, COMMUNITY] {
            w.system_dns.insert(n.into(), vec!["23.1.1.1".into()]);
            w.works.insert(k(n, "23.1.1.1"), 15.0);
        }
        w.system_dns.insert("example.com".into(), vec!["93.184.215.14".into()]); // answers with the wrong certificate
    }
    let r = t.run(RunKind::Periodic);
    assert!(!r.blocked, "a user site that's down must not make RustyDPI pin Steam");
    for n in [STORE, API, LOGIN, COMMUNITY] { assert_eq!(row(&r, n).route, Route::Direct); }
    let ex = row(&r, "example.com");
    assert!(!ex.ok);
    assert_eq!(ex.group, crate::config::USER_GROUP);
}

#[test]
fn user_site_is_unblocked_by_the_bypass() {
    let mut t = setup("usersite-bypass");
    t.cfg.add_sites(&["blocked.example.org".into()]);
    t.fpt();
    {
        let mut w = t.w();
        w.system_dns.insert("blocked.example.org".into(), vec!["104.16.1.1".into()]);
        w.works_with_bypass.insert(k("blocked.example.org", "104.16.1.1"), HashSet::from(["split-disorder"]));
    }
    let r = t.run(RunKind::Periodic);
    let s = row(&r, "blocked.example.org");
    assert!(s.ok, "{s:?}");
    assert_eq!(s.route, Route::Bypass);
    assert!(std::fs::read_to_string(t.paths.bypass().host_list()).unwrap().lines().any(|l| l == "blocked.example.org"));
    assert!(row(&r, STORE).ok && row(&r, COMMUNITY).ok);
}

#[test]
fn www_site_also_lists_the_bare_name() {
    let mut t = setup("www");
    t.cfg.add_sites(&["www.blocked.example.org".into()]);
    t.fpt();
    {
        let mut w = t.w();
        w.system_dns.insert("www.blocked.example.org".into(), vec!["104.16.1.1".into()]);
        w.works_with_bypass.insert(k("www.blocked.example.org", "104.16.1.1"), HashSet::from(["split-disorder"]));
    }
    t.run(RunKind::Periodic);
    let list = std::fs::read_to_string(t.paths.bypass().host_list()).unwrap();
    assert!(list.lines().any(|l| l == "www.blocked.example.org") && list.lines().any(|l| l == "blocked.example.org"), "{list}");
}

#[test]
fn site_needing_another_strategy_gets_its_own_profile() {
    let mut t = setup("override");
    t.cfg.add_sites(&["cdn.example.org".into()]);
    t.fpt();
    {
        let mut w = t.w();
        w.system_dns.insert("cdn.example.org".into(), vec!["151.101.1.1".into()]);
        w.works_with_bypass.insert(k("cdn.example.org", "151.101.1.1"), HashSet::from(["fake-md5sig"]));
    }
    let r = t.run(RunKind::Periodic);
    assert!(row(&r, COMMUNITY).ok, "Steam keeps the strategy that works for it");
    assert!(row(&r, "cdn.example.org").ok, "{:?}", row(&r, "cdn.example.org"));
    assert_eq!(t.w().running, Some("split-disorder"));
    assert!(t.w().args.iter().any(|a| a == "--hostlist-domains=cdn.example.org"));
    // Stable: the next check neither re-tests nor restarts.
    let starts = t.w().starts;
    let r = t.run(RunKind::Periodic);
    assert!(r.rows.iter().all(|x| x.ok));
    assert_eq!(t.w().starts, starts);
}

#[test]
fn newly_added_site_that_fails_is_retested_at_once() {
    let mut t = setup("newsite");
    t.fpt();
    t.run(RunKind::Periodic);
    assert_eq!(t.w().running, Some("split-disorder"));
    // The user adds a site the current strategy can't open; a strategy test must run in this same check.
    t.cfg.add_sites(&["new.example.org".into()]);
    {
        let mut w = t.w();
        w.system_dns.insert("new.example.org".into(), vec!["151.101.2.2".into()]);
        w.works_with_bypass.insert(k("new.example.org", "151.101.2.2"), HashSet::from(["seqovl"]));
    }
    let r = t.run(RunKind::Periodic);
    assert!(row(&r, "new.example.org").ok, "{:?}", row(&r, "new.example.org"));
    assert!(row(&r, COMMUNITY).ok);
}

#[test]
fn driver_blocked_falls_back_to_the_relay_and_back() {
    let mut t = setup("relay");
    t.fpt();
    {
        let mut w = t.w();
        w.start_error = Some("winws.exe stopped at once (exit code: 1): error opening filter".into());
        w.works_fragmented.insert(k(COMMUNITY, "23.53.33.1"));
    }
    let r = t.run(RunKind::Periodic);
    let c = row(&r, COMMUNITY);
    assert_eq!((c.route, c.ok), (Route::Relay, true), "{c:?}");
    let addr = crate::relay::assign([COMMUNITY.to_string()].iter())[COMMUNITY].to_string();
    assert!(t.hosts().contains(&format!("{addr}\t{COMMUNITY}")), "{}", t.hosts());
    assert_eq!(t.w().relay_routes.get(COMMUNITY).map(String::as_str), Some("23.53.33.1"));
    assert_eq!(row(&r, STORE).route, Route::Pinned, "pins are unaffected");
    // Stable on the next check, without trying winws again (that waits for the next full check).
    let starts = t.w().starts;
    let r = t.run(RunKind::Periodic);
    assert_eq!((row(&r, COMMUNITY).route, row(&r, COMMUNITY).ok), (Route::Relay, true));
    assert!(!r.hosts_changed);
    assert_eq!(t.w().starts, starts);
    // A full check tries winws once (not every strategy) while the driver is still blocked.
    let r = t.run(RunKind::Full);
    assert_eq!((row(&r, COMMUNITY).route, row(&r, COMMUNITY).ok), (Route::Relay, true));
    assert_eq!(t.w().starts, starts + 1);
    // A user site getting pinned changes the hosts file; the relayed Steam host must not count as changed.
    t.cfg.add_sites(&["u.example.org".into()]);
    { let mut w = t.w(); w.system_dns.insert("u.example.org".into(), vec!["127.0.0.1".into()]); w.public_dns.insert("u.example.org".into(), vec!["93.184.1.1".into()]); w.works.insert(k("u.example.org", "93.184.1.1"), 20.0); }
    let r = t.run(RunKind::Periodic);
    assert!(r.hosts_changed && t.hosts().contains("93.184.1.1\tu.example.org"));
    assert_eq!(row(&r, COMMUNITY).route, Route::Relay);
    assert!(!r.steam_hosts_changed, "Steam's servers didn't change: no Steam restart");
    // The driver works again: the next full check goes back to winws and removes the relay pin.
    t.w().start_error = None;
    let r = t.run(RunKind::Full);
    assert_eq!((row(&r, COMMUNITY).route, row(&r, COMMUNITY).ok), (Route::Bypass, true));
    assert!(!t.hosts().contains("127.77."));
    assert!(t.w().relay_routes.is_empty());
}

#[test]
fn relay_that_stops_working_is_reported_then_rechecked() {
    let t = setup("relaystop");
    t.fpt();
    { let mut w = t.w(); w.start_error = Some("driver blocked".into()); w.works_fragmented.insert(k(COMMUNITY, "23.53.33.1")); }
    assert_eq!(row(&t.run(RunKind::Periodic), COMMUNITY).route, Route::Relay);
    t.w().works_fragmented.clear();
    let r = t.run(RunKind::Periodic);
    let c = row(&r, COMMUNITY);
    assert_eq!((c.route, c.ok), (Route::Broken, false));
    assert!(c.note.contains("driverless"), "{c:?}");
    assert!(!t.hosts().contains("127.77."), "relay pin removed");
    // The driver is back: the next check takes the normal route again.
    t.w().start_error = None;
    let r = t.run(RunKind::Periodic);
    assert_eq!((row(&r, COMMUNITY).route, row(&r, COMMUNITY).ok), (Route::Bypass, true));
}

#[test]
fn relay_respects_bypass_off_and_dead_sites() {
    let t = setup("relayoff");
    t.fpt();
    t.w().works_fragmented.insert(k(COMMUNITY, "23.53.33.1"));
    Settings { bypass_enabled: false, ..Default::default() }.save(&t.paths.settings()).unwrap();
    let r = t.run(RunKind::Periodic);
    assert_eq!(row(&r, COMMUNITY).route, Route::Broken, "bypass off means off");
    assert!(!t.hosts().contains("127.77."));
    // A site that is simply down isn't relayed either.
    Settings::default().save(&t.paths.settings()).unwrap();
    { let mut w = t.w(); w.works_fragmented.clear(); w.start_error = Some("blocked".into()); }
    let r = t.run(RunKind::Periodic);
    assert_eq!(row(&r, COMMUNITY).route, Route::Broken);
    assert!(t.w().relay_routes.is_empty());
}

/// Live, not a regular test: the real engine, prober and relay on this network, with DNS steered to
/// servers the ISP blocks and a winws that "can't load its driver". The engine must find the relay by
/// itself and verify the site through it. RDPI_BLOCKED="store.steampowered.com=23.200.182.104"
#[test]
#[ignore]
fn live_driver_blocked_uses_relay() {
    struct Steered<'a> { real: crate::net::RealNet<'a>, to: HashMap<String, String> }
    impl Net for Steered<'_> {
        fn is_online(&self) -> bool { self.real.is_online() }
        fn system_resolve(&self, n: &str) -> Vec<String> { self.to.get(n).cloned().into_iter().collect() }
        fn public_resolve(&self, n: &str) -> Vec<String> { self.to.get(n).cloned().into_iter().collect() }
        fn flush_dns(&self) {}
        fn detect_network(&self) -> NetworkId { self.real.detect_network() }
    }
    struct NoDriver;
    impl Runner for NoDriver {
        fn is_running(&self) -> bool { false }
        fn recent_output(&self) -> String { String::new() }
        fn start(&self, _: &[String]) -> Result<(), String> { Err("winws.exe stopped at once: error opening filter (driver blocked)".into()) }
        fn stop(&self) {}
    }
    let to: HashMap<String, String> = std::env::var("RDPI_BLOCKED").expect("RDPI_BLOCKED").split(',').filter_map(|x| x.split_once('=')).map(|(h, ip)| (h.into(), ip.into())).collect();
    let t = setup("live-relay");
    let mut cfg = Config::default_config();
    cfg.targets.retain(|x| to.contains_key(&x.name));
    cfg.seeds.clear();
    for x in cfg.targets.iter_mut() { x.seeds.clear(); }
    let net = Steered { real: crate::net::RealNet { cfg: &cfg, flush: false }, to };
    let prober = crate::probe::HttpsProber { connect_timeout: std::time::Duration::from_secs(3), total_timeout: std::time::Duration::from_secs(8) };
    let relay = crate::relay::Relay::new();
    let mut e = Engine::new(&cfg, &t.paths, &net, &prober, &NoDriver, &t.log);
    e.relay = Some(&relay);
    let r = e.run(RunKind::Full);
    print!("{}", r.to_text());
    for x in &r.rows { assert_eq!((x.route, x.ok), (Route::Relay, true), "{x:?}"); }
    assert!(t.hosts().contains("127.77."));
    println!("{}", std::fs::read_to_string(t.paths.log()).unwrap_or_default());
}

#[test]
fn removed_site_is_forgotten() {
    let mut t = setup("forget");
    t.cfg.add_sites(&["gone.example.org".into()]);
    t.fpt();
    { let mut w = t.w(); w.system_dns.insert("gone.example.org".into(), vec!["104.16.1.1".into()]); w.works.insert(k("gone.example.org", "104.16.1.1"), 20.0); }
    t.run(RunKind::Periodic);
    assert!(std::fs::read_to_string(t.paths.state()).unwrap().contains("gone.example.org"));
    t.cfg.targets.retain(|x| !x.user);
    t.run(RunKind::Periodic);
    assert!(!std::fs::read_to_string(t.paths.state()).unwrap().contains("gone.example.org"), "no trace of a removed site");
}

#[test]
fn steam_off_with_only_user_sites() {
    let mut t = setup("steamoff");
    t.fpt();
    t.run(RunKind::Periodic);
    assert!(t.hosts().contains(STORE), "Steam pinned while it's on");
    // What the service does when Steam is switched off.
    t.cfg.targets.clear(); t.cfg.seeds.clear(); t.cfg.bypass_domains.clear();
    t.cfg.add_sites(&["blocked.example.org".into()]);
    {
        let mut w = t.w();
        w.system_dns.insert("blocked.example.org".into(), vec!["104.16.1.1".into()]);
        w.works_with_bypass.insert(k("blocked.example.org", "104.16.1.1"), HashSet::from(["split-disorder"]));
    }
    let r = t.run(RunKind::Full);
    assert!(!t.hosts().contains(STORE), "Steam pins removed once Steam is off");
    assert_eq!(r.rows.len(), 1);
    assert!(r.rows[0].ok && r.rows[0].route == Route::Bypass);
    let list = std::fs::read_to_string(t.paths.bypass().host_list()).unwrap();
    assert!(!list.contains("steampowered.com"), "no Steam domains in the bypass list");
    assert!(!r.steam_hosts_changed || r.hosts_changed);
}
