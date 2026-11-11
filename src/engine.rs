//! One check of every Steam host. For each host it finds the first route that really works:
//! direct (normal DNS) -> pinned to a verified server in the hosts file -> DPI bypass (winws).

use crate::bypass::{self, Runner};
use crate::config::{Config, Target};
use crate::hosts;
use crate::net::Net;
use crate::paths::{Log, Paths};
use crate::pinlogic::{self, Measurement};
use crate::probe::{Fail, Prober};
use crate::state::{self, Route, Settings, State, TargetState, Time};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RunKind { Periodic, Full, DryRun }

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TargetRow {
    pub name: String,
    pub group: String,
    pub route: Route,
    pub ip: Option<String>,
    pub ms: Option<f64>,
    pub ok: bool,
    pub action: String,
    pub note: String,
    /// Why the normal (unpinned) connection fails, in plain words; empty when it works.
    pub direct_problem: String,
    pub working: usize,
    pub tried: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BypassStatus {
    pub enabled: bool,
    pub running: bool,
    pub strategy: Option<String>,
    pub strategy_name: Option<String>,
    pub hosts: Vec<String>,
    pub error: Option<String>,
    pub scores: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RunReport {
    pub version: String,
    pub time: Time,
    pub seconds: f64,
    pub online: bool,
    pub blocked: bool,
    pub full: bool,
    pub hosts_changed: bool,
    pub network: Option<String>,
    pub rows: Vec<TargetRow>,
    pub bypass: BypassStatus,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

impl Default for RunReport {
    fn default() -> Self {
        RunReport { version: VERSION.into(), time: state::now(), seconds: 0.0, online: true, blocked: false, full: false, hosts_changed: false,
                    network: None, rows: vec![], bypass: BypassStatus::default(), warnings: vec![], error: None }
    }
}

impl RunReport {
    /// Groups in first-seen order with whether every host in them works.
    pub fn groups(&self) -> Vec<(String, bool)> {
        let mut g: Vec<(String, bool)> = Vec::new();
        for r in &self.rows {
            match g.iter_mut().find(|(n, _)| n == &r.group) { Some(e) => e.1 &= r.ok, None => g.push((r.group.clone(), r.ok)) }
        }
        g
    }

    pub fn to_text(&self) -> String {
        let mut s = format!("SteamPin {} - last check {} (took {:.0} s){}\n", self.version, self.time.format("%Y-%m-%d %H:%M:%S"), self.seconds, if self.full { ", full check" } else { "" });
        if !self.online { s += "offline - nothing changed\n"; return s; }
        if let Some(n) = &self.network { s += &format!("network: {n}{}\n", if self.blocked { " (Steam is blocked here)" } else { "" }); }
        for r in &self.rows {
            s += &format!("{:<34} {:<14} {:<16} {:>7}  {}  {}\n", r.name, r.route.text(), r.ip.as_deref().unwrap_or(""),
                          r.ms.map(|m| format!("{m} ms")).unwrap_or_default(), if r.ok { "OK  " } else { "FAIL" }, r.note);
        }
        let b = &self.bypass;
        if !b.hosts.is_empty() || b.error.is_some() {
            s += &format!("bypass: {}, strategy {}{}\n", if b.running { "on" } else { "off" }, b.strategy_name.as_deref().unwrap_or("-"),
                          b.error.as_ref().map(|e| format!(", error: {e}")).unwrap_or_default());
        }
        for w in &self.warnings { s += &format!("warning: {w}\n"); }
        s
    }
}

/// Runs `f` over `items` on at most `n` threads, keeping order.
pub fn parallel_map<T: Sync, R: Send>(items: &[T], n: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let results: Vec<std::sync::Mutex<Option<R>>> = items.iter().map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..n.min(items.len()).max(1) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= items.len() { break; }
                let r = f(&items[i]);
                *results[i].lock().unwrap() = Some(r);
            });
        }
    });
    results.into_iter().map(|m| m.into_inner().unwrap().expect("every item processed")).collect()
}

struct Eval {
    t: Target,
    cur: Option<String>,
    sys_raw: Vec<String>,
    sys_public: Vec<String>,
    public: Vec<String>,
    results: HashMap<String, Measurement>,
    in_bypass: bool,
    row: TargetRow,
    new_pin: Option<String>,
}

impl Eval {
    fn direct_ok(&self) -> bool { self.sys_public.iter().any(|ip| self.results.get(ip).map(|m| m.all_passed()).unwrap_or(false)) }

    fn explain(&self) -> String {
        if self.sys_raw.is_empty() { return "DNS gives no address (blocked or failing)".into(); }
        if self.sys_public.is_empty() { return format!("DNS is poisoned (answers {})", self.sys_raw[0]); }
        let Some(m) = self.sys_public.iter().filter_map(|ip| self.results.get(ip)).find(|m| !m.all_passed()) else { return String::new() };
        match m.fail {
            Fail::TlsReset => "connection is reset (DPI blocks it)".into(),
            Fail::Timeout => "server doesn't answer (timeout)".into(),
            Fail::WrongCertificate => "DNS points to a server with the wrong certificate".into(),
            Fail::Refused | Fail::Unreachable => "server unreachable".into(),
            _ => m.reason.clone(),
        }
    }
}

pub struct Engine<'a> {
    pub cfg: &'a Config,
    pub paths: &'a Paths,
    pub net: &'a dyn Net,
    pub prober: &'a dyn Prober,
    pub runner: &'a dyn Runner,
    pub log: &'a Log,
    pub probe_gap_ms: u64,
    pub settle_ms: u64,
    pub force_strategy_test: bool,
}

impl<'a> Engine<'a> {
    pub fn new(cfg: &'a Config, paths: &'a Paths, net: &'a dyn Net, prober: &'a dyn Prober, runner: &'a dyn Runner, log: &'a Log) -> Self {
        Engine { cfg, paths, net, prober, runner, log, probe_gap_ms: 250, settle_ms: 700, force_strategy_test: false }
    }

    fn names(&self) -> Vec<String> { self.cfg.targets.iter().map(|t| t.name.clone()).collect() }

    fn measure(&self, t: &Target, ip: &str, samples: u32, fail_fast: bool) -> Measurement {
        let mut probes = Vec::new();
        for i in 0..samples {
            if i > 0 && self.probe_gap_ms > 0 { std::thread::sleep(std::time::Duration::from_millis(self.probe_gap_ms)); }
            let p = self.prober.probe(t, ip);
            let failed = !p.ok;
            probes.push(p);
            if failed && fail_fast { break; }
        }
        pinlogic::summarize(ip, &probes)
    }

    pub fn run(&self, kind: RunKind) -> RunReport {
        let start = std::time::Instant::now();
        let write = kind != RunKind::DryRun;
        let mut report = RunReport::default();
        let mut st = State::load(&self.paths.state(), &|w| self.log.warn(&w));
        let names = self.names();
        let (text, enc) = hosts::read_text(&self.paths.hosts);
        let split = hosts::split(&hosts::to_lines(&text), &names);

        let warn = |r: &mut RunReport, m: String| { self.log.warn(&m); r.warnings.push(m); };
        if split.unterminated { warn(&mut report, "The SteamPin block in the hosts file had no END line; it will be rewritten.".into()); }
        // When another program wiped the block, carry on from the pins SteamPin had: they are
        // re-checked like any current pin and written back if they still work.
        let mut current_pins = split.pins.clone();
        if !st.last_pins.is_empty() && !split.saw_block && split.pins.is_empty() {
            warn(&mut report, "The SteamPin block disappeared from the hosts file (reset by antivirus or another program?). Pinning again.".into());
            current_pins = st.last_pins.iter()
                .filter(|(n, ip)| names.contains(n) && crate::iputil::is_public_ipv4(ip))
                .map(|(n, ip)| (n.clone(), ip.clone())).collect();
        }
        for n in hosts::foreign_entries(&split.other, &names) {
            warn(&mut report, format!("The hosts file has your own entry for {n} outside SteamPin's block; it overrides SteamPin."));
        }

        if !self.net.is_online() {
            self.log.info("offline (connectivity check failed) - nothing changed");
            report.online = false;
            report.bypass = self.bypass_report(&st);
            self.finish(&mut report, start, write);
            return report;
        }

        let net_id = self.net.detect_network();
        report.network = net_id.asn.as_ref().map(|a| format!("AS{a} {}", net_id.as_name.as_deref().unwrap_or("")).trim().to_string());
        let net_changed = st.network.key.is_some() && net_id.key != st.network.key;
        if net_changed {
            self.log.info(&format!("network changed ({} -> {}); full check",
                st.network.as_name.as_deref().or(st.network.asn.as_deref()).unwrap_or("?"), net_id.as_name.as_deref().or(net_id.asn.as_deref()).unwrap_or("?")));
        }
        st.network = net_id;

        let now = state::now();
        let full = kind == RunKind::Full || net_changed
            || st.last_full_run.map(|t| (now - t).num_hours() >= self.cfg.full_check_interval_hours as i64).unwrap_or(true);
        report.full = full && write;
        if full && write && self.runner.is_running() { self.runner.stop(); }
        let bypass_active = self.runner.is_running();

        // Resolve every host, then measure every (host, candidate) pair on a bounded pool.
        let mut evals: Vec<Eval> = self.cfg.targets.iter().map(|t| Eval {
            t: t.clone(), cur: current_pins.get(&t.name).cloned(), sys_raw: vec![], sys_public: vec![], public: vec![],
            results: HashMap::new(), in_bypass: bypass_active && st.bypass.hosts.contains(&t.name), row: TargetRow::default(), new_pin: None,
        }).collect();
        let resolved = parallel_map(&evals, evals.len(), |e| (self.net.system_resolve(&e.t.name), self.net.public_resolve(&e.t.name)));
        let mut jobs: Vec<(usize, String, bool)> = Vec::new();
        for (i, (e, (sys, public))) in evals.iter_mut().zip(resolved).enumerate() {
            e.sys_public = sys.iter().filter(|ip| crate::iputil::is_public_ipv4(ip)).take(2).cloned().collect();
            e.sys_raw = sys;
            e.public = public;
            let ts = st.target(&e.t.name);
            for ip in e.public.iter().chain(e.sys_public.iter()) {
                let entry = ts.ips.entry(ip.clone()).or_insert_with(|| state::IpEntry { first_seen: Some(now), ..Default::default() });
                entry.last_seen_dns = Some(now);
            }
            let seeds: Vec<String> = e.t.seeds.iter().chain(self.cfg.seeds.iter()).cloned().collect();
            let dns: Vec<String> = e.sys_public.iter().chain(e.public.iter()).cloned().collect();
            let mut cands = pinlogic::candidates(e.cur.as_deref(), ts, &dns, &seeds, self.cfg.max_candidates_per_name);
            for ip in &e.sys_public { if !cands.contains(ip) { cands.push(ip.clone()); } }
            for ip in cands {
                let keep = Some(&ip) == e.cur.as_ref() || e.sys_public.contains(&ip);
                if keep || !pinlogic::is_backed_off(ts.ips.get(&ip), now) {
                    let fail_fast = Some(&ip) != e.cur.as_ref();
                    jobs.push((i, ip, fail_fast));
                }
            }
        }
        let measured = parallel_map(&jobs, self.cfg.max_parallel_probes, |(i, ip, ff)| self.measure(&evals[*i].t, ip, self.cfg.samples, *ff));
        for ((i, ip, _), m) in jobs.iter().zip(measured) {
            pinlogic::update(st.target(&evals[*i].t.name), &m, now);
            evals[*i].results.insert(ip.clone(), m);
        }

        let blocked = evals.iter().any(|e| e.in_bypass || !e.direct_ok());
        report.blocked = blocked;
        for e in evals.iter_mut() {
            let ts = st.target(&e.t.name);
            self.decide(e, ts, blocked);
        }

        self.apply_bypass(&mut evals, &mut st, &mut report, kind);

        // Hosts file.
        let new_pins: BTreeMap<String, Option<String>> = evals.iter().map(|e| (e.t.name.clone(), e.new_pin.clone())).collect();
        let current = hosts::read_text(&self.paths.hosts).0;
        let new_text = hosts::render(&split.other, &new_pins, &names);
        report.hosts_changed = new_text != current;
        if report.hosts_changed && write {
            match hosts::write(&self.paths.hosts, &self.paths.backups(), &new_text, enc) {
                Ok(()) => {
                    self.net.flush_dns();
                    let pinned: Vec<String> = names.iter().filter_map(|n| new_pins[n].as_ref().map(|ip| format!("{n}={ip}"))).collect();
                    self.log.info(&format!("hosts updated: {}", if pinned.is_empty() { "no pins".to_string() } else { pinned.join(" ") }));
                }
                Err(e) => { self.log.error(&e); report.error = Some(e); }
            }
        }

        for e in &evals {
            let ts = st.target(&e.t.name);
            let mut keep: Vec<String> = e.t.seeds.clone();
            keep.extend(e.new_pin.clone());
            keep.extend(e.cur.clone());
            pinlogic::remove_stale(ts, self.cfg.forget_after_days, now, &keep);
            ts.route = e.row.route;
            ts.last_ms = e.row.ms;
            ts.last_note = Some(e.row.note.clone());
            if e.row.ok { ts.last_ok = Some(now); }
        }
        report.rows = evals.into_iter().map(|e| e.row).collect();
        st.last_pins = new_pins.into_iter().filter_map(|(k, v)| v.map(|v| (k, v))).collect();
        st.last_run = Some(state::now());
        if full { st.last_full_run = st.last_run; }
        st.blocked_network = blocked;
        st.version = Some(VERSION.into());
        if write { if let Err(e) = st.save(&self.paths.state()) { self.log.warn(&format!("could not save state: {e}")); } }
        self.finish(&mut report, start, write);
        report
    }

    fn decide(&self, e: &mut Eval, ts: &mut TargetState, blocked: bool) {
        let direct_ok = e.direct_ok();
        let problem = if direct_ok { String::new() } else { e.explain() };
        let r = &mut e.row;
        r.name = e.t.name.clone();
        r.group = e.t.group.clone();
        r.working = e.results.values().filter(|m| m.pass > 0).count();
        r.tried = e.results.len();
        r.direct_problem = problem;

        if e.in_bypass {
            // While winws routes this host, a working probe may be thanks to the bypass,
            // so it stays in bypass until the next full check.
            let ip = e.cur.clone().or_else(|| e.sys_public.first().cloned());
            let m = ip.as_ref().and_then(|ip| e.results.get(ip));
            e.new_pin = e.cur.clone();
            r.route = if e.cur.is_some() { Route::PinnedBypass } else { Route::Bypass };
            r.ip = ip;
            r.ms = m.and_then(|m| m.ms);
            r.ok = m.map(|m| m.mostly_passed()).unwrap_or(false);
            r.action = "kept".into();
            r.note = if r.ok { String::new() } else { format!("bypass not working ({})", m.map(|m| m.reason.as_str()).unwrap_or("no address")) };
            return;
        }

        let d = pinlogic::select(self.cfg, ts, e.cur.as_deref(), &e.results);
        if let Some(pin) = d.pin.clone().filter(|_| !(e.cur.is_none() && direct_ok && !blocked)) {
            let m = e.results.get(&pin);
            e.new_pin = Some(pin.clone());
            r.route = Route::Pinned;
            r.ms = m.and_then(|m| m.ms);
            r.ok = m.map(|m| m.mostly_passed()).unwrap_or(false);
            r.ip = Some(pin);
            r.action = if d.action == "none" { "kept".into() } else { d.action.into() };
            r.note = d.note.clone();
            if !d.note.is_empty() {
                if matches!(d.action, "failing" | "removed") { self.log.warn(&format!("{}: {}", e.t.name, d.note)); } else { self.log.info(&format!("{}: {}", e.t.name, d.note)); }
            }
            return;
        }
        if d.action == "removed" { self.log.warn(&format!("{}: {}", e.t.name, d.note)); }
        if direct_ok {
            let ip = e.sys_public.iter().find(|ip| e.results.get(*ip).map(|m| m.all_passed()).unwrap_or(false)).cloned().unwrap();
            e.new_pin = None;
            r.ms = e.results[&ip].ms;
            r.ip = Some(ip);
            r.route = Route::Direct;
            r.ok = true;
            r.action = if d.action == "removed" { "removed".into() } else { "direct".into() };
            return;
        }

        // Neither direct nor a verified pin works: this host needs the DPI bypass. Prefer the
        // system DNS answer; when DNS is poisoned, pin a server that accepts the TCP connection
        // and is only reset at TLS (that's what the bypass fixes).
        let mut bip = e.sys_public.first().cloned();
        let mut pin = false;
        if bip.is_none() {
            bip = e.public.iter().chain(e.results.keys()).find(|ip| e.results.get(*ip).map(|m| m.fail == Fail::TlsReset).unwrap_or(false)).cloned()
                .or_else(|| e.public.first().cloned());
            pin = bip.is_some();
        }
        e.new_pin = if pin { bip.clone() } else { None };
        r.route = match (&bip, pin) { (None, _) => Route::Broken, (_, true) => Route::PinnedBypass, _ => Route::Bypass };
        r.ok = false; // set after the bypass is verified
        r.action = if bip.is_none() { "failing".into() } else { "bypass".into() };
        r.note = if bip.is_none() { "no usable server address found".into() } else { String::new() };
        r.ip = bip;
    }

    fn apply_bypass(&self, evals: &mut [Eval], st: &mut State, report: &mut RunReport, kind: RunKind) {
        let write = kind != RunKind::DryRun;
        let need: Vec<usize> = (0..evals.len()).filter(|&i| matches!(evals[i].row.route, Route::Bypass | Route::PinnedBypass) && evals[i].row.ip.is_some()).collect();
        let files = self.paths.bypass();
        let settings = Settings::load(&self.paths.settings());

        if need.is_empty() {
            if write && self.runner.is_running() { self.runner.stop(); self.log.info("bypass stopped (no Steam host needs it)"); }
            if write { st.bypass.hosts.clear(); st.bypass.unhealthy_runs = 0; st.bypass.last_error = None; }
            report.bypass = self.bypass_report(st);
            return;
        }
        if !settings.bypass_enabled {
            if write && self.runner.is_running() { self.runner.stop(); }
            // They were probed through the bypass before it was stopped: they don't work now.
            for &i in &need {
                let p = evals[i].row.direct_problem.clone();
                let r = &mut evals[i].row;
                r.route = Route::Broken;
                r.ok = false;
                r.ms = None;
                r.note = format!("needs the bypass, which is turned off ({p})");
            }
            report.bypass = self.bypass_report(st);
            return;
        }
        if !write {
            for &i in &need { if !evals[i].in_bypass { evals[i].row.note = "would use the bypass".into(); } }
            report.bypass = self.bypass_report(st);
            return;
        }

        let mut host_names: Vec<String> = need.iter().map(|&i| evals[i].t.name.clone()).collect();
        host_names.sort();
        let include: Vec<String> = self.cfg.bypass_domains.iter().cloned().chain(host_names.iter().cloned()).collect();
        let exclude: Vec<String> = self.cfg.bypass_exclude.iter().cloned()
            .chain(evals.iter().filter(|e| matches!(e.row.route, Route::Direct | Route::Pinned)).map(|e| e.t.name.clone())).collect();
        let lists_changed = bypass::write_lists(&files, &include, &exclude);
        st.bypass.hosts = host_names.clone();

        // Hosts already in the bypass were just checked through it: count runs where most of them failed.
        let active: Vec<usize> = need.iter().copied().filter(|&i| evals[i].in_bypass).collect();
        if !active.is_empty() {
            let bad = active.iter().filter(|&&i| !evals[i].row.ok).count();
            st.bypass.unhealthy_runs = if bad * 2 >= active.len() { st.bypass.unhealthy_runs + 1 } else { 0 };
        }

        let mut strategy = if st.bypass.strategy_network == st.network.key { bypass::find(st.bypass.strategy.as_deref()) } else { None };
        let need_test = strategy.is_none() || st.bypass.unhealthy_runs >= 2 || self.force_strategy_test;
        if need_test {
            let hosts: Vec<(Target, String)> = need.iter().map(|&i| (evals[i].t.clone(), evals[i].row.ip.clone().unwrap())).collect();
            self.log.info(&format!("testing bypass strategies for {}", host_names.join(", ")));
            // The strategy that worked before is tried first.
            let mut order: Vec<&'static bypass::Strategy> = bypass::STRATEGIES.iter().collect();
            order.sort_by_key(|s| if Some(s.id) == st.bypass.strategy.as_deref() { 0 } else { 1 });
            let ranked = bypass::test_strategies(self.runner, self.prober, &files, &hosts, &order, 4, self.settle_ms, &|m| self.log.info(m));
            st.bypass.scores = ranked.iter().map(|s| (s.id.to_string(), s.summary())).collect();
            st.bypass.last_test = Some(state::now());
            match ranked.iter().find(|s| s.error.is_none() && s.pass > 0) {
                None => {
                    let err = if !ranked.is_empty() && ranked.iter().all(|s| s.error.is_some()) { ranked[0].error.clone().unwrap() } else { "No bypass strategy unblocked these hosts on this network.".into() };
                    self.log.warn(&format!("bypass: {err}"));
                    for &i in &need { evals[i].row.route = Route::Broken; evals[i].row.note = err.clone(); }
                    st.bypass.last_error = Some(err);
                    st.bypass.strategy = None;
                    report.bypass = self.bypass_report(st);
                    return;
                }
                Some(best) => {
                    let s = bypass::find(Some(best.id)).unwrap();
                    if st.bypass.strategy.as_deref() != Some(best.id) { self.log.info(&format!("bypass strategy: {} ({})", s.name, best.summary())); }
                    strategy = Some(s);
                    st.bypass.strategy = Some(best.id.into());
                    st.bypass.strategy_network = st.network.key.clone();
                    st.bypass.unhealthy_runs = 0;
                }
            }
        }
        let strategy = strategy.unwrap();

        let mut started = false;
        if !self.runner.is_running() || lists_changed || need_test {
            if let Err(err) = self.runner.start(&bypass::build_args(strategy, &files)) {
                self.log.error(&format!("bypass: {err}"));
                for &i in &need { evals[i].row.route = Route::Broken; evals[i].row.note = err.clone(); }
                st.bypass.last_error = Some(err);
                report.bypass = self.bypass_report(st);
                return;
            }
            started = true;
            st.bypass.last_error = None;
            self.log.info(&format!("bypass running ({}) for {}", strategy.name, host_names.join(", ")));
        }

        // Verify every bypassed host through the running bypass.
        if started { std::thread::sleep(std::time::Duration::from_millis(self.settle_ms)); }
        let checks = parallel_map(&need, need.len(), |&i| self.measure(&evals[i].t, evals[i].row.ip.as_ref().unwrap(), self.cfg.samples, false));
        let mut bad = 0;
        for (&i, m) in need.iter().zip(checks) {
            let r = &mut evals[i].row;
            r.ok = m.mostly_passed();
            r.ms = m.ms;
            if r.ok { r.note.clear(); } else { bad += 1; r.note = format!("bypass not working ({})", m.reason); }
        }
        if bad == 0 { st.bypass.unhealthy_runs = 0; } else if active.is_empty() && bad * 2 >= need.len() { st.bypass.unhealthy_runs += 1; }
        if bad > 0 { self.log.warn(&format!("bypass: {bad} of {} hosts not working with {}", need.len(), strategy.name)); }
        report.bypass = self.bypass_report(st);
    }

    fn bypass_report(&self, st: &State) -> BypassStatus {
        BypassStatus {
            enabled: Settings::load(&self.paths.settings()).bypass_enabled,
            running: self.runner.is_running(),
            strategy: st.bypass.strategy.clone(),
            strategy_name: bypass::find(st.bypass.strategy.as_deref()).map(|s| s.name.to_string()),
            hosts: st.bypass.hosts.clone(),
            error: st.bypass.last_error.clone(),
            scores: st.bypass.scores.clone(),
        }
    }

    fn finish(&self, report: &mut RunReport, start: std::time::Instant, write: bool) {
        report.seconds = (start.elapsed().as_secs_f64() * 10.0).round() / 10.0;
        if !write { return; }
        let _ = std::fs::create_dir_all(&self.paths.data_dir);
        if let Err(e) = state::save_json(&self.paths.status(), report) { self.log.warn(&format!("could not save status: {e}")); }
        let _ = std::fs::write(self.paths.last_check(), report.to_text());
    }

    /// Removes SteamPin's block from the hosts file. Ok(true) when something was removed.
    pub fn unpin(&self) -> Result<bool, String> {
        let names = self.names();
        let (cur, enc) = hosts::read_text(&self.paths.hosts);
        let split = hosts::split(&hosts::to_lines(&cur), &names);
        let text = hosts::render(&split.other, &BTreeMap::new(), &names);
        if text == cur { return Ok(false); }
        hosts::write(&self.paths.hosts, &self.paths.backups(), &text, enc)?;
        self.net.flush_dns();
        self.log.info("all pins removed (unpin)");
        Ok(true)
    }

    /// Probes every candidate of every host (all samples) without changing anything.
    pub fn test_all(&self) -> Vec<(Target, Vec<String>, Vec<Measurement>)> {
        let mut st = State::load(&self.paths.state(), &|_| {});
        let names = self.names();
        let pins = hosts::split(&hosts::to_lines(&hosts::read_text(&self.paths.hosts).0), &names).pins;
        let mut jobs = Vec::new();
        let mut per: Vec<(Target, Vec<String>)> = Vec::new();
        for (ti, t) in self.cfg.targets.iter().enumerate() {
            let sys: Vec<String> = self.net.system_resolve(&t.name).into_iter().filter(|ip| crate::iputil::is_public_ipv4(ip)).collect();
            let dns: Vec<String> = sys.iter().chain(self.net.public_resolve(&t.name).iter()).cloned().collect::<Vec<_>>();
            let seeds: Vec<String> = t.seeds.iter().chain(self.cfg.seeds.iter()).cloned().collect();
            for ip in pinlogic::candidates(pins.get(&t.name).map(String::as_str), st.target(&t.name), &dns, &seeds, self.cfg.max_candidates_per_name) { jobs.push((ti, ip)); }
            let mut d = dns.clone(); d.dedup();
            per.push((t.clone(), d));
        }
        let ms = parallel_map(&jobs, self.cfg.max_parallel_probes, |(ti, ip)| self.measure(&self.cfg.targets[*ti], ip, self.cfg.samples, false));
        let mut out: Vec<(Target, Vec<String>, Vec<Measurement>)> = per.into_iter().map(|(t, d)| (t, d, vec![])).collect();
        for ((ti, _), m) in jobs.iter().zip(ms) { out[*ti].2.push(m); }
        for o in out.iter_mut() { o.2.sort_by(|a, b| a.ms.unwrap_or(f64::MAX).partial_cmp(&b.ms.unwrap_or(f64::MAX)).unwrap()); }
        out
    }
}
