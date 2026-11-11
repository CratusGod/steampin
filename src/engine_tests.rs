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
    running: Option<&'static str>,
    start_error: Option<String>,
    starts: u32,
    flushes: u32,
    network: NetworkId,
}

struct World { w: Mutex<W>, files: BypassFiles }

fn k(h: &str, ip: &str) -> (String, String) { (h.to_string(), ip.to_string()) }

impl World {
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
}

impl Prober for World {
    fn probe(&self, t: &Target, ip: &str) -> ProbeResult {
        let (ms, wb, running) = {
            let w = self.w.lock().unwrap();
            (w.works.get(&k(&t.name, ip)).copied(), w.works_with_bypass.get(&k(&t.name, ip)).cloned(), w.running)
        };
        if let Some(ms) = ms { return ProbeResult::good(ms, 200); }
        if let Some(strategies) = wb {
            return if self.bypassed(&t.name, running.is_some()) && strategies.contains(running.unwrap()) { ProbeResult::good(30.0, 200) }
                   else { ProbeResult::failed(Fail::TlsReset, "TLS reset (blocked)") };
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
        w.running = Some(bypass::STRATEGIES.iter().find(|s| s.tcp.iter().all(|a| args.contains(&a.replace("{tls}", &tls)))).unwrap().id);
        Ok(())
    }
    fn stop(&self) { self.w.lock().unwrap().running = None; }
}

const STORE: &str = "store.steampowered.com";
const API: &str = "api.steampowered.com";
const LOGIN: &str = "login.steampowered.com";
const COMMUNITY: &str = "steamcommunity.com";

struct T { dir: PathBuf, paths: Paths, world: World, cfg: Config, log: Log }

impl Drop for T { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }

fn setup(tag: &str) -> T {
    let dir = std::env::temp_dir().join(format!("steampin-eng-{tag}-{}", std::process::id()));
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
    assert!(std::fs::read_to_string(t.paths.last_check()).unwrap().starts_with("SteamPin 3"));
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
    assert!(!t.hosts().contains("SteamPin"));
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
    Settings { bypass_enabled: false, auto_restart_steam: false }.save(&t.paths.settings()).unwrap();
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
    Settings { bypass_enabled: false, auto_restart_steam: false }.save(&t.paths.settings()).unwrap();
    let r = t.run(RunKind::Periodic);
    assert!(t.w().running.is_none());
    let c = row(&r, COMMUNITY);
    assert!(!c.ok, "a bypassed host can't be OK once the bypass is off");
    assert_eq!(c.route, Route::Broken);
    assert!(c.note.contains("turned off"));
    assert!(row(&r, STORE).ok);
    Settings { bypass_enabled: true, auto_restart_steam: false }.save(&t.paths.settings()).unwrap();
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
    assert!(!t.hosts().contains("SteamPin"));
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
    // The user (or v2) had pinned store; SteamPin keeps healthy pins.
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
