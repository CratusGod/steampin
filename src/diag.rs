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
pub struct DiagCheck { pub id: String, pub title: String, pub level: Level, pub detail: String, pub fix: Option<String>, pub fix_label: Option<String>, pub help: String }

fn check(id: &str, title: &str, level: Level, detail: impl Into<String>) -> DiagCheck {
    DiagCheck { id: id.into(), title: title.into(), level, detail: detail.into(), fix: None, fix_label: None, help: String::new() }
}
fn with_fix(mut c: DiagCheck, fix: &str, label: &str) -> DiagCheck { c.fix = Some(fix.into()); c.fix_label = Some(label.into()); c }
/// Step-by-step instructions shown under the check ("How to fix").
fn with_help(mut c: DiagCheck, help: &str) -> DiagCheck { c.help = help.into(); c }

pub mod fixes {
    pub const RUN_FULL: &str = "run-full";
    pub const RESTART_STEAM: &str = "restart-steam";
    pub const HOSTS_READONLY: &str = "hosts-readonly";
    pub const REPAIR: &str = "repair";
    pub const STOP_OTHER: &str = "stop-other-bypass";
    pub const RETEST: &str = "retest";
    pub const BYPASS_ON: &str = "bypass-on";
    pub const INSTALL: &str = "install";
    pub const HOSTS_SEEN: &str = "hosts-seen";
}

const OTHER_BYPASS: &[&str] = &["winws.exe", "winws2.exe", "goodbyedpi.exe", "cdpiui.exe", "cdpiui_trayicon.exe", "byedpi.exe", "ciadpi.exe", "spoofdpi.exe"];

/// Other DPI-bypass tools running now (not RustyDPI's own winws).
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

/// Windows' Code Integrity log: 3077 = a driver was blocked, 3076 = it would be blocked once the policy
/// is enforced (audit mode), 3033 = an image failed the signing level. Newer Windows 11 driver policies
/// can switch from audit to enforcement on their own, so the 3076 warning comes first.
pub fn windivert_code_integrity() -> Option<(bool, String)> {
    let out = crate::win::run_hidden_output("wevtutil.exe", &["qe", "Microsoft-Windows-CodeIntegrity/Operational",
        "/q:*[System[(EventID=3076 or EventID=3077 or EventID=3033)]]", "/c:200", "/rd:true", "/f:text"])?;
    parse_code_integrity(&out)
}

/// (blocked now, date of the newest event) for the newest event that names WinDivert.
pub fn parse_code_integrity(text: &str) -> Option<(bool, String)> {
    for ev in text.split("Event[").skip(1) {
        if !ev.to_ascii_lowercase().contains("windivert") { continue; }
        let id = ev.lines().find_map(|l| l.trim().strip_prefix("Event ID:").map(|v| v.trim().to_string())).unwrap_or_default();
        let date = ev.lines().find_map(|l| l.trim().strip_prefix("Date:").map(|v| v.trim().chars().take(10).collect::<String>())).unwrap_or_default();
        return Some((id != "3076", date));
    }
    None
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
    let mut list = vec![check("service", "RustyDPI service", Level::Ok, format!("Running (version {}).", crate::engine::VERSION))];
    let net = RealNet { cfg, flush: false };
    let online = net.is_online();
    list.push(if online { check("internet", "Internet", Level::Ok, "Connected.") }
              else { with_help(check("internet", "Internet", Level::Fail, "No internet connection. RustyDPI waits and changes nothing until you're back online."),
                  "1. Check the Wi-Fi or cable, and that other websites open.\n2. Restart your router if nothing loads.\n3. RustyDPI carries on by itself once you're back online.") });

    if online {
        let id = net.detect_network();
        let isp = match &id.asn { Some(a) => format!("{} (AS{a}, {})", id.as_name.as_deref().unwrap_or("?"), id.country.as_deref().unwrap_or("?")), None => "unknown network".into() };
        let blocked = last.map(|r| r.blocked).unwrap_or(false);
        list.push(check("network", "Your network", Level::Info, format!("{isp}. {}",
            if blocked { "Steam is blocked on this network; RustyDPI works around it." } else { "Steam isn't blocked on this network." })));
        let servers = crate::net::system_dns_servers().join(", ");
        let answer = net.system_resolve("store.steampowered.com");
        let dns_help = "Nothing to do: RustyDPI's pins take care of it for Steam.";
        list.push(if answer.is_empty() {
            with_help(check("dns", "DNS", Level::Warn, format!("Your DNS ({servers}) gives no address for Steam. RustyDPI pins Steam's addresses, so this doesn't matter while it works.")), dns_help)
        } else if !answer.iter().any(|ip| crate::iputil::is_public_ipv4(ip)) {
            with_help(check("dns", "DNS", Level::Warn, format!("Your DNS ({servers}) gives a fake address for Steam ({}). RustyDPI pins Steam's real addresses, so this is handled.", answer[0])), dns_help)
        } else { check("dns", "DNS", Level::Ok, format!("Using {servers}.")) });
    }

    list.push(hosts_check(paths, last));

    let bad = crate::bypass::bad_files(&paths.zapret_dir());
    list.push(if bad.is_empty() { check("files", "Bypass files", Level::Ok, "All present and matching the official zapret release.") } else {
        let zdir = paths.zapret_dir().display().to_string();
        with_help(with_fix(check("files", "Bypass files", Level::Fail, format!(
            "{} {} missing or changed. Antivirus often removes WinDivert (it calls it a \"RiskTool\").",
            bad.join(", "), if bad.len() == 1 { "is" } else { "are" })), fixes::REPAIR, "Repair files"),
            &format!("1. Open your antivirus. In Windows Security: Virus & threat protection > Manage settings > Exclusions > Add an exclusion > Folder.\n2. Add {zdir}\n3. If the antivirus quarantined the files, restore them (Windows Security > Protection history).\n4. Click Repair files and accept the Windows prompt."))
    });

    if let Some(drv) = windivert_driver_path() {
        if !drv.to_ascii_lowercase().contains(&paths.zapret_dir().display().to_string().to_ascii_lowercase()) {
            list.push(with_help(check("windivert", "WinDivert driver", Level::Warn, format!("Another program's WinDivert driver is registered ({drv}). Only one DPI-bypass tool should run at a time.")),
                "1. Uninstall the other tool (CDPI UI, GoodbyeDPI, zapret) in Windows Settings > Apps, if Steam was the only reason you had it.\n2. Restart the PC.\n3. Run diagnosis again."));
        }
    }

    let others = other_bypass_tools(&paths.zapret_dir());
    if !others.is_empty() {
        let mut names: Vec<String> = others.iter().map(|p| p.name.clone()).collect();
        names.dedup();
        list.push(with_help(with_fix(check("other-bypass", "Other bypass tools", Level::Warn, format!(
            "{} {} running. Two DPI-bypass tools on the same traffic break each other. RustyDPI replaces them for Steam.",
            names.join(", "), if names.len() == 1 { "is" } else { "are" })), fixes::STOP_OTHER, "Close them"),
            "1. Click Close them (this lasts until you restart).\n2. To stop them for good, uninstall them in Windows Settings > Apps, or turn off their \"start with Windows\" option.\n3. Need them for other sites? Add those sites in RustyDPI's Sites tab instead."));
    }

    let vpns = active_vpns();
    if !vpns.is_empty() {
        list.push(with_help(check("vpn", "VPN", Level::Info, format!("{} is connected. While it's on, Steam goes through the VPN and RustyDPI's fixes don't apply.", vpns.join(", "))),
            "Turn the VPN off when you don't need it (Cloudflare WARP: click its tray icon and switch it off)."));
    }

    if let Some((blocked, date)) = windivert_code_integrity() {
        let help = "1. Pinned sites keep working: RustyDPI pins what it can without the driver.\n2. Open Windows Security > Device security > Core isolation details, and turn off Memory integrity. Restart the PC.\n3. If you use Smart App Control (Windows Security > App & browser control), it can block the driver too; it can only be turned off, not back on.\n4. Click Try again in DPI bypass below. If Windows still blocks it, wait for a RustyDPI update.";
        list.push(with_help(if blocked {
            with_fix(check("driver-policy", "Windows driver policy", Level::Fail, format!("Windows blocked the WinDivert driver the DPI bypass needs (last on {date}). Sites that need the bypass won't work until it's allowed.")), fixes::RETEST, "Try again")
        } else {
            check("driver-policy", "Windows driver policy", Level::Warn, format!("Windows reported (on {date}) that it would block the WinDivert driver once its newer driver rules are enforced. It still loads for now."))
        }, help));
    }

    let settings = Settings::load(&paths.settings());
    let b = last.map(|r| &r.bypass);
    if !settings.bypass_enabled {
        list.push(with_help(with_fix(check("bypass", "DPI bypass", if b.map(|b| !b.hosts.is_empty()).unwrap_or(false) { Level::Warn } else { Level::Info },
            "Turned off. Hosts that can't be pinned stay blocked."), fixes::BYPASS_ON, "Turn on"), "Click Turn on (same as Settings > Use the DPI bypass when needed)."));
    } else if let Some(err) = b.and_then(|b| b.error.clone()) {
        let mi = memory_integrity_on();
        let help = format!("1. Click Try again.\n2. If it fails again, add an antivirus exclusion for {} and click Repair files.{}\n{}. Restart the PC and click Try again.",
            paths.zapret_dir().display(),
            if mi { "\n3. Turn off Memory integrity (Windows Security > Device security > Core isolation details) and restart: it can stop the WinDivert driver from loading." } else { "" },
            if mi { 4 } else { 3 });
        list.push(with_help(with_fix(check("bypass", "DPI bypass", Level::Fail, err), fixes::RETEST, "Try again"), &help));
    } else if let Some(b) = b.filter(|b| !b.hosts.is_empty()) {
        let running = runner.is_running();
        let c = check("bypass", "DPI bypass", if running { Level::Ok } else { Level::Warn }, if running {
            format!("On for {} {}, using \"{}\".", b.hosts.len(), if b.hosts.len() == 1 { "host" } else { "hosts" }, b.strategy_name.as_deref().unwrap_or("?"))
        } else { "Should be on but isn't running.".into() });
        list.push(if running { with_fix(c, fixes::RETEST, "Find a better strategy") } else { with_help(with_fix(c, fixes::RUN_FULL, "Fix now"), "Click Fix now. If it stops again, the Log page says why.") });
    } else {
        list.push(check("bypass", "DPI bypass", Level::Ok, "Not needed right now: every host works directly or pinned."));
    }

    if let Some(n) = last.map(|r| r.rows.iter().filter(|x| x.route == crate::state::Route::Relay).count()).filter(|&n| n > 0) {
        list.push(with_help(check("relay", "Driverless bypass", Level::Ok, format!(
            "On for {n} {}. The DPI bypass couldn't help {}, so RustyDPI relays {} itself; this needs no driver.",
            if n == 1 { "site" } else { "sites" }, if n == 1 { "it" } else { "them" }, if n == 1 { "it" } else { "them" })),
            "Nothing to do. These sites open over HTTPS; RustyDPI switches back to the normal bypass by itself once it works again."));
    }

    if let Some(r) = last {
        for (group, ok) in r.groups() {
            let rows: Vec<_> = r.rows.iter().filter(|x| x.group == group).collect();
            let user = group == crate::config::USER_GROUP;
            let title = if user { group.clone() } else { format!("Steam {group}") };
            list.push(if ok {
                let mut routes: Vec<&str> = Vec::new();
                for x in &rows { if !routes.contains(&x.route.text()) { routes.push(x.route.text()); } }
                check(&format!("steam-{group}"), &title, Level::Ok, routes.join(", "))
            } else {
                let why: Vec<String> = rows.iter().filter(|x| !x.ok).map(|x| format!("{}: {}.", if user { crate::config::mask_site(&x.name) } else { x.name.clone() }, if x.note.is_empty() { &x.direct_problem } else { &x.note })).collect();
                let help = if user {
                    "1. Check the name in the Sites tab (a site name like discord.com, not a page link).\n2. Click Fix now: RustyDPI tries a pinned server and the DPI bypass.\n3. Still failing? The site may be down, or blocked in a way only a VPN gets around."
                } else {
                    "1. Click Fix now and wait about a minute.\n2. If it stays red: turn off any VPN or proxy, and close other bypass tools.\n3. Still red? Click Copy report and open an issue on the project page (Settings > Project page)."
                };
                with_help(with_fix(check(&format!("steam-{group}"), &title, if user { Level::Warn } else { Level::Fail }, why.join(" ")), fixes::RUN_FULL, "Fix now"), help)
            });
        }
    }
    list
}

/// Hosts-file resets logged in the last 7 days and after the user dismissed them: (count, last time).
pub fn recent_hosts_resets(lines: &[String], seen: Option<Time>, now: Time) -> (usize, Option<Time>) {
    let week = now - chrono::Duration::days(7);
    let since = match seen { Some(s) if s > week => s, _ => week };
    let times: Vec<Time> = lines.iter().filter(|l| l.contains("disappeared from the hosts file"))
        .filter_map(|l| chrono::NaiveDateTime::parse_from_str(l.get(..19)?, "%Y-%m-%d %H:%M:%S").ok())
        .filter(|t| *t > since).collect();
    (times.len(), times.iter().max().copied())
}

fn hosts_check(paths: &Paths, last: Option<&RunReport>) -> DiagCheck {
    let title = "Hosts file";
    let hosts = paths.hosts.display().to_string();
    let av_help = format!("1. Open your antivirus settings and look for \"hosts file protection\" (Kaspersky, Avast, AVG, Bitdefender, Malwarebytes and others have it).\n2. Turn it off, or add an exception for {hosts} or for C:\\Program Files\\RustyDPI\\RustyDPI.exe.\n3. Windows Security alone doesn't do this; if it's your only antivirus, look for other security or \"PC optimizer\" tools.");
    // Read-only is fine: RustyDPI lifts it only while writing its pins and sets it back.
    let ro = std::fs::metadata(&paths.hosts).map(|m| m.permissions().readonly()).unwrap_or(false);
    if !ro { if let Err(e) = std::fs::OpenOptions::new().append(true).open(&paths.hosts) {
        return with_help(check("hosts", title, Level::Fail, if e.kind() == std::io::ErrorKind::PermissionDenied {
            "RustyDPI isn't allowed to change the hosts file (blocked by antivirus or a security tool).".to_string()
        } else { format!("The hosts file is locked by another program ({e}).") }), &av_help);
    } }
    if let Some(w) = last.and_then(|r| r.warnings.iter().find(|w| w.contains("your own entry"))) {
        return with_help(check("hosts", title, Level::Warn, w.clone()),
            &format!("1. Open Notepad as administrator (right-click Notepad > Run as administrator).\n2. File > Open: {hosts} (pick \"All files\").\n3. Delete the line with that name outside the \"# BEGIN RustyDPI\" block, and save.\n4. Click Run diagnosis again."));
    }
    let seen = Settings::load(&paths.settings()).hosts_resets_seen;
    let (resets, when) = recent_hosts_resets(&crate::paths::tail(&paths.log(), 3000), seen, crate::state::now());
    if resets > 0 {
        let when = when.map(|t| format!(", last on {}", t.format("%b %d at %H:%M"))).unwrap_or_default();
        return with_help(with_fix(check("hosts", title, Level::Warn, format!(
            "Another program removed RustyDPI's entries {resets} {} in the last 7 days{when}. RustyDPI put them back each time.", if resets == 1 { "time" } else { "times" })),
            fixes::HOSTS_SEEN, "Dismiss"),
            &format!("{av_help}\n4. Click Dismiss. The warning comes back only if it happens again, and clears by itself after 7 quiet days."));
    }
    check("hosts", title, Level::Ok, if ro { "Read-only (kept that way: RustyDPI lifts it only while it writes its pins); RustyDPI's block is in place." } else { "Writable; RustyDPI's block is in place." })
}

// ---- checks that must run as the signed-in user (in the window) ----

pub fn user_checks(last_hosts_change: Option<Time>) -> Vec<DiagCheck> {
    let mut list = Vec::new();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(k) = hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") {
        if k.get_value::<u32, _>("ProxyEnable").map(|v| v == 1).unwrap_or(false) {
            let server: String = k.get_value("ProxyServer").unwrap_or_default();
            list.push(with_help(check("proxy", "Proxy", Level::Warn, format!("A system proxy is set ({server}). Steam's store and sign-in may go through it instead of RustyDPI's fixes.")),
                "1. Open Windows Settings > Network & internet > Proxy.\n2. Under Manual proxy setup, click Edit and turn off \"Use a proxy server\" (unless you set it up on purpose).\n3. Restart Steam."));
        }
    }
    for (b, mode) in browsers_with_secure_dns() {
        list.push(with_help(check(&format!("doh-{b}"), &format!("{b} Secure DNS"), Level::Warn, format!(
            "{b} uses its own Secure DNS ({mode}), which ignores the hosts file, so the Steam website may not open in {b}. The Steam app itself isn't affected.")),
            &format!("1. In {b}, open Settings > Privacy and security > Security (Firefox: Settings > Privacy & Security > DNS over HTTPS).\n2. Turn off \"Use secure DNS\".\n3. Restart {b}.")));
    }
    match steam::find() {
        None => list.push(check("steam", "Steam", Level::Info, "Steam isn't installed for this Windows user.")),
        Some(_) => {
            let started = steam::start_time();
            list.push(match (started, last_hosts_change) {
                (Some(s), Some(c)) if s < c => with_help(with_fix(check("steam", "Steam", Level::Warn, "Steam was started before RustyDPI's last change. Restart Steam so it uses the new servers."), fixes::RESTART_STEAM, "Restart Steam"),
                    "Click Restart Steam, or turn on Restart Steam automatically in the Steam tab so you don't have to."),
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
        !game_running() || crate::win::message_box("A game is running. Restarting Steam will close it.\n\nRestart Steam anyway?", "RustyDPI", MB_YESNO | MB_ICONWARNING) == IDYES
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_code_integrity_events() {
        let blocked = "Event[0]:\r\n  Log Name: Microsoft-Windows-CodeIntegrity/Operational\r\n  Date: 2026-11-30T10:00:00.000\r\n  Event ID: 3077\r\n  Description: \r\nCode Integrity determined that a process attempted to load \\Device\\HarddiskVolume3\\Program Files\\RustyDPI\\zapret\\WinDivert64.sys that did not meet the requirements.\r\n";
        let audit = blocked.replace("3077", "3076");
        let other = "Event[0]:\r\n  Date: 2026-11-30T10:00:00.000\r\n  Event ID: 3077\r\n  Description: \r\nsomething else.sys\r\n";
        assert_eq!(parse_code_integrity(blocked), Some((true, "2026-11-30".into())));
        assert_eq!(parse_code_integrity(&audit), Some((false, "2026-11-30".into())));
        assert_eq!(parse_code_integrity(other), None);
        assert_eq!(parse_code_integrity(""), None);
    }

    #[test]
    fn hosts_resets_expire_and_can_be_dismissed() {
        let t = |s: &str| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap();
        let line = |s: &str| format!("{s}  WARN  The RustyDPI block disappeared from the hosts file (reset by antivirus or another program?). Pinning again.");
        let lines = vec![line("2026-11-01 10:00:00"), line("2026-11-10 09:00:00"), line("2026-11-11 18:05:28"), "2026-11-11 18:06:00  INFO  hosts updated".into()];
        let now = t("2026-11-12 12:00:00");
        assert_eq!(recent_hosts_resets(&lines, None, now), (2, Some(t("2026-11-11 18:05:28"))));
        assert_eq!(recent_hosts_resets(&lines, Some(t("2026-11-11 00:00:00")), now).0, 1);
        assert_eq!(recent_hosts_resets(&lines, Some(t("2026-11-12 00:00:00")), now).0, 0);
        assert_eq!(recent_hosts_resets(&lines, None, t("2026-11-20 00:00:00")).0, 0);
    }
}
