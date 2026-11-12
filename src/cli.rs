//! Command line: RustyDPI.exe --status | --check [--full] | --retest | --dry-run | --test | --diagnose | --unpin | --install | --uninstall

use crate::bypass::Runner;
use crate::config::Config;
use crate::engine::{Engine, RunKind};
use crate::net::RealNet;
use crate::paths::{Log, Paths};
use crate::probe::HttpsProber;
use std::time::Duration;

const HELP: &str = "RustyDPI 4 - unblocks websites and Steam where they're blocked.

  RustyDPI.exe              open the window
  --status                  last check and current routes
  --check [--full]          ask the service to check now (--full re-checks everything)
  --retest                  ask the service to find the best bypass strategy again
  --dry-run                 check here and show what would change (changes nothing)
  --test                    probe every known server and print a speed table
  --diagnose                run the diagnosis and print it
  --restart-steam [--force] restart the Steam client (refuses while a game runs, unless --force)
  --unpin                   remove RustyDPI's entries from the hosts file (admin)
  --install / --uninstall   install or remove RustyDPI (admin)
";

/// The CLI never starts winws: only the service does.
struct NoRunner;
impl Runner for NoRunner {
    fn is_running(&self) -> bool { false }
    fn recent_output(&self) -> String { String::new() }
    fn start(&self, _: &[String]) -> Result<(), String> { Err("the bypass runs only in the service".into()) }
    fn stop(&self) {}
}

pub fn run(args: &[String]) -> i32 {
    let paths = Paths::default_paths();
    let say = |m: &str| println!("{m}");
    let has = |f: &str| args.iter().any(|a| a == f);
    match args[0].as_str() {
        "--install" => {
            let c = crate::installer::install(&say);
            // Started by the service's updater: the installer closed the window, so open it again
            // (on the Update tab) to show the new version.
            if c == 0 && has("--after-update") { crate::win::start_as_desktop_user(&paths.exe(), "--window --page 6"); }
            c
        }
        "--uninstall" => {
            if crate::win::is_admin() { crate::installer::uninstall(&say) }
            else if has("--quiet") { 5 }
            else { let c = crate::win::run_elevated("--uninstall"); say(if c == 0 { "RustyDPI was removed." } else { "Uninstall was cancelled." }); c }
        }
        "--repair" => crate::installer::repair(&say),
        "--hosts-writable" => crate::installer::hosts_writable(),
        "--stop-other-bypass" => crate::installer::stop_other_bypass(&say),
        "--status" => {
            match crate::ipc::send("status", None, Duration::from_secs(5)) {
                Some(r) => {
                    let s = r.status.unwrap_or_default();
                    match &s.report { Some(rep) => print!("{}", rep.to_text()), None => say("No check has run yet.") }
                    if s.busy { say(&format!("Busy: {}", s.activity.unwrap_or_default())); }
                }
                None => {
                    print!("{}", std::fs::read_to_string(paths.last_check()).unwrap_or_else(|_| "No check has run yet.\n".into()));
                    say("The RustyDPI service isn't running.");
                }
            }
            0
        }
        "--check" | "--retest" => {
            let cmd = if args[0] == "--retest" { "retest" } else if has("--full") { "fix" } else { "check" };
            match crate::ipc::send(cmd, None, Duration::from_secs(5)) {
                Some(_) => { say("Check started; see --status in a minute."); 0 }
                None => { say("The RustyDPI service isn't running."); 2 }
            }
        }
        "--diagnose" => {
            let mut checks = match crate::ipc::send("diagnose", None, Duration::from_secs(60)) {
                Some(r) => r.checks.unwrap_or_default(),
                None => vec![crate::diag::DiagCheck { id: "service".into(), title: "RustyDPI service".into(), level: crate::diag::Level::Fail, detail: "Not running. Reinstall RustyDPI.".into(), ..Default::default() }],
            };
            let lhc = crate::ipc::send("status", None, Duration::from_secs(5)).and_then(|r| r.status).and_then(|s| s.last_hosts_change);
            checks.extend(crate::diag::user_checks(lhc));
            for c in checks {
                say(&format!("[{:<4}] {}: {}", format!("{:?}", c.level).to_uppercase(), c.title, c.detail));
                if c.level >= crate::diag::Level::Warn { for l in c.help.lines() { say(&format!("         {l}")); } }
            }
            0
        }
        "--dry-run" | "--test" => {
            let cfg = crate::service::effective_config(&paths, &|e| say(e));
            let net = RealNet { cfg: &cfg, flush: false };
            let prober = HttpsProber { connect_timeout: Duration::from_secs(cfg.connect_timeout_sec), total_timeout: Duration::from_secs(cfg.probe_timeout_sec) };
            let log = Log::new(None, !has("--json"));
            let engine = Engine::new(&cfg, &paths, &net, &prober, &NoRunner, &log);
            if args[0] == "--dry-run" {
                let r = engine.run(RunKind::DryRun);
                if has("--json") {
                    let st = crate::ipc::ServiceStatus { version: crate::engine::VERSION.into(), report: Some(r), ..Default::default() };
                    println!("{}", serde_json::to_string_pretty(&st).unwrap_or_default());
                    return 0;
                }
                print!("{}", r.to_text());
                if r.hosts_changed { say("(the hosts file would change)"); }
            } else {
                for (t, dns, results) in engine.test_all() {
                    say(&format!("{}  (DNS: {})", cfg.shown(&t.name), if dns.is_empty() { "nothing usable".into() } else { dns.join(", ") }));
                    for m in results {
                        say(&format!("   {:<16} {}/{}  {:>8}  {}", m.ip, m.pass, m.total, m.ms.map(|x| format!("{x} ms")).unwrap_or_default(), if m.all_passed() { "" } else { &m.reason }));
                    }
                }
            }
            0
        }
        "--unpin" => {
            let cfg = Config::load(&paths.config()).unwrap_or_else(|_| Config::default_config());
            let net = RealNet { cfg: &cfg, flush: true };
            let prober = HttpsProber { connect_timeout: Duration::from_secs(3), total_timeout: Duration::from_secs(6) };
            let log = Log::new(Some(paths.log()), true);
            match Engine::new(&cfg, &paths, &net, &prober, &NoRunner, &log).unpin() {
                Ok(true) => { say("Removed."); 0 }
                Ok(false) => { say("Nothing to remove."); 0 }
                Err(e) => { say(&e); 1 }
            }
        }
        "--restart-steam" => {
            if crate::diag::steam::game_running() && !has("--force") { say("A game is running; not restarting Steam. Add --force to restart anyway."); return 3; }
            match crate::diag::steam::restart() { Ok(()) => { say("Steam restarted."); 0 } Err(e) => { say(&e); 1 } }
        }
        "--version" => { say(crate::engine::VERSION); 0 }
        "--service-test" => {
            // Runs the service logic in the foreground against a sandbox folder (its own hosts file,
            // state and lists), for testing without installing. Stops when <dir>\stop appears.
            let Some(dir) = args.get(1).map(std::path::PathBuf::from) else { say("usage: --service-test <dir>"); return 2 };
            let p = Paths { install_dir: dir.join("install"), data_dir: dir.join("data"), hosts: dir.join("hosts") };
            if !p.hosts.exists() { let _ = std::fs::copy(crate::hosts::system_path(), &p.hosts); }
            let core = crate::service::Core::new(p);
            let threads = core.start();
            while !dir.join("stop").exists() { std::thread::sleep(Duration::from_millis(500)); }
            core.shutdown(threads);
            0
        }
        a => { print!("{HELP}"); if matches!(a, "--help" | "-h" | "/?") { 0 } else { 2 } }
    }
}
