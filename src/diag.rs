//! Plain-language checks of everything that can stop Steam from working; each says what's wrong
//! and, where possible, offers a fix. Also finds and restarts the Steam client.

use crate::bypass::Runner;
use crate::config::Config;
use crate::engine::RunReport;
use crate::net::{Net, RealNet};
use crate::paths::Paths;
use crate::state::{Settings, Time};
use serde::{Deserialize, Serialize};
use winreg::enums::*;
use winreg::RegKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum Level { #[default] Ok, Info, Warn, Fail }

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DiagCheck { pub id: String, pub title: String, pub level: Level, pub detail: String, pub fix: Option<String>, pub fix_label: Option<String> }

fn check(id: &str, title: &str, level: Level, detail: impl Into<String>) -> DiagCheck {
    DiagCheck { id: id.into(), title: title.into(), level, detail: detail.into(), fix: None, fix_label: None }
}
fn with_fix(mut c: DiagCheck, fix: &str, label: &str) -> DiagCheck { c.fix = Some(fix.into()); c.fix_label = Some(label.into()); c }

pub mod fixes {
    pub const RUN_FULL: &str = "run-full";
    pub const RESTART_STEAM: &str = "restart-steam";
    pub const HOSTS_READONLY: &str = "hosts-readonly";
    pub const REPAIR: &str = "repair";
    pub const STOP_OTHER: &str = "stop-other-bypass";
    pub const RETEST: &str = "retest";
    pub const BYPASS_ON: &str = "bypass-on";
    pub const INSTALL: &str = "install";
}

const OTHER_BYPASS: &[&str] = &["winws.exe", "winws2.exe", "goodbyedpi.exe", "cdpiui.exe", "cdpiui_trayicon.exe", "byedpi.exe", "ciadpi.exe", "spoofdpi.exe"];

/// Other DPI-bypass tools running now (not SteamPin's own winws).
pub fn other_bypass_tools(our_zapret: &std::path::Path) -> Vec<crate::win::Proc> {
    let ours = our_zapret.display().to_string().to_ascii_lowercase();
    crate::win::processes().into_iter()
        .filter(|p| OTHER_BYPASS.contains(&p.name.to_ascii_lowercase().as_str()))
        .filter(|p| !p.path.as_ref().map(|x| x.to_ascii_lowercase().starts_with(&ours)).unwrap_or(false))
        .collect()
}

pub fn windivert_driver_path() -> Option<String> {
    RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Services\WinDivert").ok()?.get_value("ImagePath").ok()
}

pub fn memory_integrity_on() -> bool {
    RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")
        .and_then(|k| k.get_value::<u32, _>("Enabled")).map(|v| v == 1).unwrap_or(false)
}

pub fn active_vpns() -> Vec<String> {
    let rx = regex_lite::Regex::new(r"(?i)WARP|WireGuard|TAP-|Wintun|OpenVPN|NordLynx|ProtonVPN|Mullvad|Tailscale|ZeroTier|Hamachi").unwrap();
    let mut v: Vec<String> = crate::net::adapters().into_iter().filter(|a| a.up && (rx.is_match(&a.description) || rx.is_match(&a.name))).map(|a| a.description).collect();
    v.dedup();
    v
}

pub fn system_checks(paths: &Paths, cfg: &Config, runner: &dyn Runner, last: Option<&RunReport>) -> Vec<DiagCheck> {
    let mut list = vec![check("service", "SteamPin service", Level::Ok, format!("Running (version {}).", crate::engine::VERSION))];
    let net = RealNet { cfg, flush: false };
    let online = net.is_online();
    list.push(if online { check("internet", "Internet", Level::Ok, "Connected.") }
              else { check("internet", "Internet", Level::Fail, "No internet connection. SteamPin waits and changes nothing until you're back online.") });

    if online {
        let id = net.detect_network();
        let isp = match &id.asn { Some(a) => format!("{} (AS{a}, {})", id.as_name.as_deref().unwrap_or("?"), id.country.as_deref().unwrap_or("?")), None => "unknown network".into() };
        let blocked = last.map(|r| r.blocked).unwrap_or(false);
        list.push(check("network", "Your network", Level::Info, format!("{isp}. {}",
            if blocked { "Steam is blocked on this network; SteamPin works around it." } else { "Steam isn't blocked on this network." })));
        let servers = crate::net::system_dns_servers().join(", ");
        let answer = net.system_resolve("store.steampowered.com");
        list.push(if answer.is_empty() {
            check("dns", "DNS", Level::Warn, format!("Your DNS ({servers}) gives no address for Steam. SteamPin pins Steam's addresses, so this doesn't matter while it works."))
        } else if !answer.iter().any(|ip| crate::iputil::is_public_ipv4(ip)) {
            check("dns", "DNS", Level::Warn, format!("Your DNS ({servers}) gives a fake address for Steam ({}). SteamPin pins Steam's real addresses, so this is handled.", answer[0]))
        } else { check("dns", "DNS", Level::Ok, format!("Using {servers}.")) });
    }

    list.push(hosts_check(paths, last));

    let bad = crate::bypass::bad_files(&paths.zapret_dir());
    list.push(if bad.is_empty() { check("files", "Bypass files", Level::Ok, "All present and matching the official zapret release.") } else {
        with_fix(check("files", "Bypass files", Level::Fail, format!(
            "{} {} missing or changed. Antivirus often removes WinDivert (it calls it a \"RiskTool\"). Add an exception for {}, then repair.",
            bad.join(", "), if bad.len() == 1 { "is" } else { "are" }, paths.zapret_dir().display())), fixes::REPAIR, "Repair files")
    });

    if let Some(drv) = windivert_driver_path() {
        if !drv.to_ascii_lowercase().contains(&paths.zapret_dir().display().to_string().to_ascii_lowercase()) {
            list.push(check("windivert", "WinDivert driver", Level::Warn, format!("Another program's WinDivert driver is registered ({drv}). Only one DPI-bypass tool should run at a time.")));
        }
    }

    let others = other_bypass_tools(&paths.zapret_dir());
    if !others.is_empty() {
        let mut names: Vec<String> = others.iter().map(|p| p.name.clone()).collect();
        names.dedup();
        list.push(with_fix(check("other-bypass", "Other bypass tools", Level::Warn, format!(
            "{} {} running. Two DPI-bypass tools on the same traffic break each other. SteamPin replaces them for Steam.",
            names.join(", "), if names.len() == 1 { "is" } else { "are" })), fixes::STOP_OTHER, "Close them"));
    }

    let vpns = active_vpns();
    if !vpns.is_empty() {
        list.push(check("vpn", "VPN", Level::Info, format!("{} is connected. While it's on, Steam goes through the VPN and SteamPin's fixes don't apply. Turn it off when you don't need it.", vpns.join(", "))));
    }

    let settings = Settings::load(&paths.settings());
    let b = last.map(|r| &r.bypass);
    if !settings.bypass_enabled {
        list.push(with_fix(check("bypass", "DPI bypass", if b.map(|b| !b.hosts.is_empty()).unwrap_or(false) { Level::Warn } else { Level::Info },
            "Turned off. Hosts that can't be pinned stay blocked."), fixes::BYPASS_ON, "Turn on"));
    } else if let Some(err) = b.and_then(|b| b.error.clone()) {
        let hint = if err.contains("missing") { "" } else if memory_integrity_on() {
            " Memory integrity (Windows Security > Device security > Core isolation) can stop the WinDivert driver from loading."
        } else { " If this keeps happening, antivirus may be blocking the WinDivert driver." };
        list.push(with_fix(check("bypass", "DPI bypass", Level::Fail, format!("{err}{hint}")), fixes::RETEST, "Try again"));
    } else if let Some(b) = b.filter(|b| !b.hosts.is_empty()) {
        let running = runner.is_running();
        let c = check("bypass", "DPI bypass", if running { Level::Ok } else { Level::Warn }, if running {
            format!("On for {} Steam {}, using \"{}\".", b.hosts.len(), if b.hosts.len() == 1 { "host" } else { "hosts" }, b.strategy_name.as_deref().unwrap_or("?"))
        } else { "Should be on but isn't running.".into() });
        list.push(if running { with_fix(c, fixes::RETEST, "Find a better strategy") } else { with_fix(c, fixes::RUN_FULL, "Fix now") });
    } else {
        list.push(check("bypass", "DPI bypass", Level::Ok, "Not needed right now: every Steam host works directly or pinned."));
    }

    if let Some(r) = last {
        for (group, ok) in r.groups() {
            let rows: Vec<_> = r.rows.iter().filter(|x| x.group == group).collect();
            list.push(if ok {
                let mut routes: Vec<&str> = Vec::new();
                for x in &rows { if !routes.contains(&x.route.text()) { routes.push(x.route.text()); } }
                check(&format!("steam-{group}"), &format!("Steam {group}"), Level::Ok, routes.join(", "))
            } else {
                let why: Vec<String> = rows.iter().filter(|x| !x.ok).map(|x| format!("{}: {}.", x.name, if x.note.is_empty() { &x.direct_problem } else { &x.note })).collect();
                with_fix(check(&format!("steam-{group}"), &format!("Steam {group}"), Level::Fail, why.join(" ")), fixes::RUN_FULL, "Fix now")
            });
        }
    }
    list
}

fn hosts_check(paths: &Paths, last: Option<&RunReport>) -> DiagCheck {
    let title = "Hosts file";
    // Read-only is fine: SteamPin lifts it only while writing its pins and sets it back.
    let ro = std::fs::metadata(&paths.hosts).map(|m| m.permissions().readonly()).unwrap_or(false);
    if !ro { if let Err(e) = std::fs::OpenOptions::new().append(true).open(&paths.hosts) {
        return check("hosts", title, Level::Fail, if e.kind() == std::io::ErrorKind::PermissionDenied {
            "SteamPin isn't allowed to change the hosts file (blocked by antivirus or a security tool).".to_string()
        } else { format!("The hosts file is locked by another program ({e}).") });
    } }
    if let Some(w) = last.and_then(|r| r.warnings.iter().find(|w| w.contains("your own entry"))) {
        return check("hosts", title, Level::Warn, format!("{w} Delete that line if Steam misbehaves."));
    }
    let resets = crate::paths::tail(&paths.log(), 3000).iter().filter(|l| l.contains("disappeared from the hosts file")).count();
    if resets > 0 {
        return check("hosts", title, Level::Warn, format!("Another program removed SteamPin's entries {resets} time(s) recently (usually antivirus \"hosts file protection\"). SteamPin puts them back, but adding an exception for the hosts file stops the flip-flopping."));
    }
    check("hosts", title, Level::Ok, if ro { "Read-only (kept that way: SteamPin lifts it only while it writes its pins); SteamPin's block is in place." } else { "Writable; SteamPin's block is in place." })
}

// ---- checks that must run as the signed-in user (in the window) ----

pub fn user_checks(last_hosts_change: Option<Time>) -> Vec<DiagCheck> {
    let mut list = Vec::new();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(k) = hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") {
        if k.get_value::<u32, _>("ProxyEnable").map(|v| v == 1).unwrap_or(false) {
            let server: String = k.get_value("ProxyServer").unwrap_or_default();
            list.push(check("proxy", "Proxy", Level::Warn, format!("A system proxy is set ({server}). Steam's store and sign-in may go through it instead of SteamPin's fixes.")));
        }
    }
    for (b, mode) in browsers_with_secure_dns() {
        list.push(check(&format!("doh-{b}"), &format!("{b} Secure DNS"), Level::Warn, format!(
            "{b} uses its own Secure DNS ({mode}), which ignores the hosts file. If the Steam store doesn't open in {b}, turn off Secure DNS in its settings (Privacy and security > Security > Use secure DNS). The Steam app itself isn't affected.")));
    }
    match steam::find() {
        None => list.push(check("steam", "Steam", Level::Info, "Steam isn't installed for this Windows user.")),
        Some(_) => {
            let started = steam::start_time();
            list.push(match (started, last_hosts_change) {
                (Some(s), Some(c)) if s < c => with_fix(check("steam", "Steam", Level::Warn, "Steam was started before SteamPin's last change. Restart Steam so it uses the new servers."), fixes::RESTART_STEAM, "Restart Steam"),
                _ => check("steam", "Steam", Level::Ok, if started.is_none() { "Installed, not running." } else { "Running with the current settings." }),
            });
        }
    }
    list
}

/// Chromium browsers' Secure DNS setting (their Local State file), policies, and Firefox's DoH mode.
pub fn browsers_with_secure_dns() -> Vec<(String, String)> {
    let mut res: Vec<(String, String)> = Vec::new();
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
    for (name, dir) in [("Chrome", r"Google\Chrome\User Data"), ("Edge", r"Microsoft\Edge\User Data"), ("Brave", r"BraveSoftware\Brave-Browser\User Data"),
                        ("Helium", r"imput\Helium\User Data"), ("Vivaldi", r"Vivaldi\User Data"), ("Opera", r"Opera Software\Opera Stable")] {
        let p = std::path::Path::new(&local).join(dir).join("Local State");
        if let Ok(s) = std::fs::read_to_string(p) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                if v["dns_over_https"]["mode"] == "secure" { res.push((name.into(), "secure mode".into())); }
            }
        }
    }
    for (name, key) in [("Chrome", r"SOFTWARE\Policies\Google\Chrome"), ("Edge", r"SOFTWARE\Policies\Microsoft\Edge")] {
        for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
            let mode: Option<String> = RegKey::predef(hive).open_subkey(key).ok().and_then(|k| k.get_value("DnsOverHttpsMode").ok());
            if mode.as_deref() == Some("secure") && !res.iter().any(|r| r.0 == name) { res.push((name.into(), "secure mode, set by policy".into())); }
        }
    }
    let ff = std::path::Path::new(&std::env::var("APPDATA").unwrap_or_default()).join(r"Mozilla\Firefox\Profiles");
    if let Ok(dirs) = std::fs::read_dir(ff) {
        let rx = regex_lite::Regex::new(r#"user_pref\("network\.trr\.mode",\s*(\d)\)"#).unwrap();
        for d in dirs.flatten() {
            if let Ok(s) = std::fs::read_to_string(d.path().join("prefs.js")) {
                if let Some(c) = rx.captures(&s) {
                    match &c[1] { "2" => { res.push(("Firefox".into(), "DoH first".into())); break; } "3" => { res.push(("Firefox".into(), "DoH only".into())); break; } _ => {} }
                }
            }
        }
    }
    res
}

/// Finds, restarts and inspects the Steam client (runs as the user).
pub mod steam {
    use super::*;

    pub fn find() -> Option<std::path::PathBuf> {
        let exe: Option<String> = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Valve\Steam").ok().and_then(|k| k.get_value("SteamExe").ok());
        if let Some(e) = exe.map(|e| std::path::PathBuf::from(e.replace('/', "\\"))).filter(|p| p.exists()) { return Some(e); }
        let def = std::path::Path::new(&std::env::var("ProgramFiles(x86)").unwrap_or_default()).join(r"Steam\steam.exe");
        def.exists().then_some(def)
    }

    fn pids() -> Vec<u32> { crate::win::processes().into_iter().filter(|p| p.name.eq_ignore_ascii_case("steam.exe")).map(|p| p.pid).collect() }

    pub fn start_time() -> Option<Time> { pids().into_iter().filter_map(crate::win::process_start).min() }

    pub fn game_running() -> bool {
        RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Valve\Steam").ok()
            .and_then(|k| k.get_value::<u32, _>("RunningAppID").ok()).map(|id| id != 0).unwrap_or(false)
    }

    /// For a restart you asked for: a running game would close too, so ask first. True = go ahead.
    pub fn confirm_if_game() -> bool {
        use windows_sys::Win32::UI::WindowsAndMessaging::{IDYES, MB_ICONWARNING, MB_YESNO};
        !game_running() || crate::win::message_box("A game is running. Restarting Steam will close it.\n\nRestart Steam anyway?", "SteamPin", MB_YESNO | MB_ICONWARNING) == IDYES
    }

    /// Asks Steam to quit (steam.exe -shutdown), waits up to 40 s, then starts it again.
    pub fn restart() -> Result<(), String> {
        use std::process::Stdio;
        let exe = find().ok_or("Steam isn't installed.")?;
        // No inherited handles: Steam outlives us and would keep a caller's output pipe open.
        let cmd = || { let mut c = std::process::Command::new(&exe); c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()); c };
        if !pids().is_empty() {
            let _ = cmd().arg("-shutdown").spawn();
            for _ in 0..40 { if pids().is_empty() { break; } std::thread::sleep(std::time::Duration::from_secs(1)); }
            if !pids().is_empty() { return Err("Steam didn't close. Close it yourself, then open it again.".into()); }
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
        cmd().current_dir(exe.parent().unwrap()).spawn().map_err(|e| e.to_string())?;
        Ok(())
    }
}
