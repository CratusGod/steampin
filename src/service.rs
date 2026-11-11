//! The Windows service (LocalSystem): runs checks on a schedule and on triggers (start, network
//! change, resume, requests from the window), keeps winws alive, and answers over the named pipe.

use crate::bypass::{Runner, WinwsRunner};
use crate::config::Config;
use crate::engine::{Engine, RunKind, RunReport};
use crate::ipc::{Request, Response, ServiceStatus};
use crate::net::RealNet;
use crate::paths::{Log, Paths};
use crate::probe::HttpsProber;
use crate::state::{self, Settings, State, Time};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub const SERVICE_NAME: &str = "SteamPin";

#[derive(Default)]
struct Shared {
    pending: Option<RunKind>,
    busy: bool,
    activity: Option<String>,
    next_run: Option<Time>,
    last_hosts_change: Option<Time>,
    last: Option<RunReport>,
    force_retest: bool,
    request_at: Option<std::time::Instant>,
}

pub struct Core {
    paths: Paths,
    log: Log,
    runner: WinwsRunner,
    shared: Mutex<Shared>,
    wake: Condvar,
    stop: AtomicBool,
    settings_lock: Mutex<()>,
}

impl Core {
    pub fn new(paths: Paths) -> Arc<Core> {
        let _ = std::fs::create_dir_all(&paths.data_dir);
        let last = std::fs::read_to_string(paths.status()).ok().and_then(|s| serde_json::from_str(&s).ok());
        Arc::new(Core {
            log: Log::new(Some(paths.log()), false), runner: WinwsRunner::new(paths.bypass()), paths,
            shared: Mutex::new(Shared { last, ..Default::default() }), wake: Condvar::new(), stop: AtomicBool::new(false), settings_lock: Mutex::new(()),
        })
    }

    /// Starts the worker threads; returns their handles.
    pub fn start(self: &Arc<Self>) -> Vec<std::thread::JoinHandle<()>> {
        self.log.info(&format!("service {} started", crate::engine::VERSION));
        self.request(RunKind::Full);
        let mut hs = Vec::new();
        let c = self.clone(); hs.push(std::thread::spawn(move || c.run_loop()));
        let c = self.clone(); hs.push(std::thread::spawn(move || c.watchdog()));
        let c = self.clone(); hs.push(std::thread::spawn(move || c.network_watch()));
        let c = self.clone(); hs.push(std::thread::spawn(move || crate::ipc::serve(&c.stop, &|r| c.handle(r))));
        hs
    }

    pub fn shutdown(&self, handles: Vec<std::thread::JoinHandle<()>>) {
        self.stop.store(true, Ordering::SeqCst);
        self.wake.notify_all();
        crate::ipc::poke();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        for h in handles { while !h.is_finished() && std::time::Instant::now() < deadline { std::thread::sleep(Duration::from_millis(50)); } }
        self.runner.stop();
        self.log.info("service stopped");
    }

    pub fn on_resume(&self) { self.log.info("resumed from sleep"); self.request_in(RunKind::Periodic, 20); }

    pub fn request(&self, kind: RunKind) {
        let mut s = self.shared.lock().unwrap();
        s.pending = Some(if s.pending == Some(RunKind::Full) || kind == RunKind::Full { RunKind::Full } else { RunKind::Periodic });
        s.request_at = None;
        self.wake.notify_all();
    }

    /// Network events come in bursts: one check `secs` after the last one.
    fn request_in(&self, kind: RunKind, secs: u64) {
        let mut s = self.shared.lock().unwrap();
        if s.pending.is_none() { s.pending = Some(kind); }
        s.request_at = Some(std::time::Instant::now() + Duration::from_secs(secs));
        self.wake.notify_all();
    }

    fn config(&self) -> Config {
        Config::load(&self.paths.config()).unwrap_or_else(|e| {
            self.log.error(&format!("config.json is invalid ({e}); using the built-in defaults"));
            Config::default_config()
        })
    }

    fn run_loop(&self) {
        while !self.stop.load(Ordering::SeqCst) {
            let interval = Duration::from_secs(self.config().check_interval_min * 60);
            let kind = {
                let mut s = self.shared.lock().unwrap();
                s.next_run = Some(state::now() + chrono::Duration::from_std(interval).unwrap());
                let deadline = std::time::Instant::now() + interval;
                loop {
                    if self.stop.load(Ordering::SeqCst) { return; }
                    let now = std::time::Instant::now();
                    if let Some(k) = s.pending { if s.request_at.map(|t| now >= t).unwrap_or(true) { s.pending = None; s.request_at = None; break k; } }
                    if now >= deadline { break RunKind::Periodic; }
                    let until = s.request_at.filter(|_| s.pending.is_some()).map(|t| t.min(deadline)).unwrap_or(deadline);
                    s = self.wake.wait_timeout(s, until.saturating_duration_since(now).max(Duration::from_millis(10))).unwrap().0;
                }
            };
            self.run_once(kind);
        }
    }

    fn run_once(&self, kind: RunKind) {
        let force = {
            let mut s = self.shared.lock().unwrap();
            s.busy = true;
            s.activity = Some(if kind == RunKind::Full { "Checking every Steam server".into() } else { "Checking Steam".into() });
            std::mem::take(&mut s.force_retest)
        };
        let cfg = self.config();
        let net = RealNet { cfg: &cfg, flush: true };
        let prober = HttpsProber { connect_timeout: Duration::from_secs(cfg.connect_timeout_sec), total_timeout: Duration::from_secs(cfg.probe_timeout_sec) };
        let mut engine = Engine::new(&cfg, &self.paths, &net, &prober, &self.runner, &self.log);
        engine.force_strategy_test = force;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| engine.run(kind)));
        let mut s = self.shared.lock().unwrap();
        match r {
            Ok(r) => { if r.hosts_changed { s.last_hosts_change = Some(state::now()); } s.last = Some(r); }
            Err(_) => self.log.error("check failed unexpectedly"),
        }
        s.busy = false;
        s.activity = None;
    }

    /// Every minute: if winws should be running but died, or the hosts block vanished, check again now.
    fn watchdog(&self) {
        loop {
            for _ in 0..60 { if self.stop.load(Ordering::SeqCst) { return; } std::thread::sleep(Duration::from_secs(1)); }
            if self.shared.lock().unwrap().busy { continue; }
            let st = State::load(&self.paths.state(), &|_| {});
            if Settings::load(&self.paths.settings()).bypass_enabled && !st.bypass.hosts.is_empty() && st.bypass.last_error.is_none() && !self.runner.is_running() {
                let out = self.runner.recent_output();
                let last = out.lines().map(str::trim).filter(|l| !l.is_empty()).last().unwrap_or("no output").to_string();
                self.log.warn(&format!("bypass (winws) stopped unexpectedly: {last}; restarting"));
                self.request(RunKind::Periodic);
                continue;
            }
            if !st.last_pins.is_empty() {
                let names: Vec<String> = st.last_pins.keys().cloned().collect();
                let split = crate::hosts::split(&crate::hosts::to_lines(&crate::hosts::read_text(&self.paths.hosts).0), &names);
                if split.pins.is_empty() { self.request(RunKind::Periodic); }
            }
        }
    }

    /// Polls the adapters every 5 s; a changed fingerprint (new network, reconnect) triggers a check.
    fn network_watch(&self) {
        let fp = || {
            let mut v: Vec<String> = crate::net::adapters().into_iter().filter(|a| a.up && !a.gateways.is_empty())
                .map(|a| format!("{}|{}|{}", a.name, a.gateways.join(","), a.dns.join(","))).collect();
            v.sort();
            v.join(";")
        };
        let mut last = fp();
        while !self.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(5));
            let now = fp();
            if now != last {
                last = now;
                if !last.is_empty() { self.log.info("network changed; checking in 20 s"); self.request_in(RunKind::Periodic, 20); }
            }
        }
    }

    fn change_settings(&self, f: impl FnOnce(&mut Settings)) {
        let _g = self.settings_lock.lock().unwrap();
        let mut s = Settings::load(&self.paths.settings());
        f(&mut s);
        let _ = s.save(&self.paths.settings());
    }

    fn status(&self) -> ServiceStatus {
        let s = self.shared.lock().unwrap();
        ServiceStatus {
            version: crate::engine::VERSION.into(),
            busy: s.busy || s.pending.is_some() && s.request_at.is_none(),
            activity: s.activity.clone().or_else(|| (s.pending.is_some() && s.request_at.is_none()).then(|| "Starting a check".into())),
            next_run: s.next_run, last_hosts_change: s.last_hosts_change, report: s.last.clone(),
            settings: Settings::load(&self.paths.settings()),
        }
    }

    pub fn handle(&self, req: Request) -> Response {
        let ok = |status: Option<ServiceStatus>| Response { ok: true, status, ..Default::default() };
        match (req.cmd.as_str(), req.flag) {
            ("status", _) => ok(Some(self.status())),
            ("fix", _) => { self.request(RunKind::Full); ok(Some(self.status())) }
            ("check", _) => { self.request(RunKind::Periodic); ok(Some(self.status())) }
            ("retest", _) => { self.shared.lock().unwrap().force_retest = true; self.request(RunKind::Full); ok(Some(self.status())) }
            ("bypass", Some(on)) => {
                self.change_settings(|s| s.bypass_enabled = on);
                self.log.info(&format!("bypass turned {} by the user", if on { "on" } else { "off" }));
                self.request(RunKind::Periodic);
                ok(Some(self.status()))
            }
            ("autorestart", Some(on)) => { self.change_settings(|s| s.auto_restart_steam = on); ok(Some(self.status())) }
            ("log", _) => Response { ok: true, lines: Some(crate::paths::tail(&self.paths.log(), 300)), ..Default::default() },
            ("diagnose", _) => {
                let last = self.shared.lock().unwrap().last.clone();
                Response { ok: true, checks: Some(crate::diag::system_checks(&self.paths, &self.config(), &self.runner, last.as_ref())), ..Default::default() }
            }
            _ => Response { ok: false, error: Some("unknown command".into()), ..Default::default() },
        }
    }
}

// ---- Windows service glue ----

windows_service::define_windows_service!(ffi_service_main, service_main);

pub fn run_dispatcher() -> Result<(), String> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| e.to_string())
}

fn service_main(_args: Vec<std::ffi::OsString>) {
    use windows_service::service::*;
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    let core = Core::new(Paths::default_paths());
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let c2 = core.clone();
    let handler = move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => { let _ = tx.send(()); ServiceControlHandlerResult::NoError }
        ServiceControl::PowerEvent(PowerEventParam::ResumeAutomatic) | ServiceControl::PowerEvent(PowerEventParam::ResumeSuspend) => { c2.on_resume(); ServiceControlHandlerResult::NoError }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(h) = service_control_handler::register(SERVICE_NAME, handler) else { return };
    let status = |state, accept| ServiceStatus_ {
        service_type: ServiceType::OWN_PROCESS, current_state: state, controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0), checkpoint: 0, wait_hint: Duration::from_secs(15), process_id: None,
    };
    let _ = h.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | ServiceControlAccept::POWER_EVENT));
    let threads = core.start();
    let _ = rx.recv();
    let _ = h.set_service_status(status(ServiceState::StopPending, ServiceControlAccept::empty()));
    core.shutdown(threads);
    let _ = h.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()));
}

type ServiceStatus_ = windows_service::service::ServiceStatus;
