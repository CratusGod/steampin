//! Installs RustyDPI for all users: copies itself and the zapret files to Program Files, registers
//! the service (LocalSystem), the tray at logon, a Start menu shortcut and an Installed-apps entry.
//! Replaces RustyDPI v1/v2 (scheduled task + PowerShell script) in place.

use crate::paths::Paths;
use crate::service::SERVICE_NAME;
use crate::win::{self, run_hidden};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use winreg::enums::*;
use winreg::RegKey;

const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RustyDPI";

pub fn shortcut_path() -> PathBuf {
    Path::new(&std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())).join(r"Microsoft\Windows\Start Menu\Programs\RustyDPI.lnk")
}

/// Asks the Service Control Manager directly (the window calls this every 2 s; no sc.exe process).
pub fn service_exists() -> bool {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|m| m.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)).is_ok()
}

pub fn is_installed() -> bool { Paths::default_paths().exe().exists() && service_exists() }

pub fn running_from_install_dir() -> bool {
    std::env::current_exe().ok().map(|p| p.to_string_lossy().eq_ignore_ascii_case(&Paths::default_paths().exe().to_string_lossy())).unwrap_or(false)
}

fn stop_service() {
    run_hidden("sc.exe", &["stop", SERVICE_NAME]);
    for _ in 0..60 {
        let out = win::run_hidden_output("sc.exe", &["query", SERVICE_NAME]).unwrap_or_default();
        if out.is_empty() || out.contains("STOPPED") || !out.contains("STATE") { return; }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Closes other RustyDPI processes running from the install folder (tray, window).
fn kill_installed_instances(exe: &Path) {
    let me = std::process::id();
    for p in win::processes() {
        if p.pid != me && p.path.as_deref().map(|x| x.eq_ignore_ascii_case(&exe.to_string_lossy())).unwrap_or(false) { win::kill(p.pid); }
    }
}

fn copy_retry(from: &Path, to: &Path) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..10 {
        match std::fs::copy(from, to) { Ok(_) => return Ok(()), Err(e) => { last = e.to_string(); std::thread::sleep(std::time::Duration::from_secs(1)); } }
    }
    Err(format!("could not copy RustyDPI.exe: {last}"))
}

pub fn install(say: &dyn Fn(&str)) -> i32 {
    if !win::is_admin() { say("Installing needs administrator rights."); return 5; }
    let paths = Paths::default_paths();
    let exe = paths.exe();
    let me = std::env::current_exe().unwrap_or_default();

    say("Stopping the old version...");
    stop_service();
    run_hidden("sc.exe", &["stop", "WinDivert"]);
    kill_installed_instances(&exe);
    remove_legacy(&paths, say);

    say("Copying files...");
    let _ = std::fs::create_dir_all(&paths.install_dir);
    if !me.to_string_lossy().eq_ignore_ascii_case(&exe.to_string_lossy()) {
        if let Err(e) = copy_retry(&me, &exe) { say(&e); return 1; }
    }
    if let Err(e) = crate::bypass::extract(&paths.zapret_dir()) { say(&format!("warning: {e}")); }
    let bad = crate::bypass::bad_files(&paths.zapret_dir());
    if !bad.is_empty() {
        say(&format!("warning: {} could not be written or don't match the official zapret release (antivirus?). Pinning still works; the DPI bypass won't until this is fixed.", bad.join(", ")));
    }
    let _ = std::fs::create_dir_all(&paths.data_dir);
    let dd = paths.data_dir.display().to_string();
    run_hidden("icacls.exe", &[&dd, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX"]);

    say("Registering the service...");
    let bin = format!("\"{}\" --service", exe.display());
    if service_exists() {
        run_hidden("sc.exe", &["config", SERVICE_NAME, "binPath=", &bin, "start=", "auto", "obj=", "LocalSystem"]);
    } else {
        run_hidden("sc.exe", &["create", SERVICE_NAME, "binPath=", &bin, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", "RustyDPI"]);
    }
    run_hidden("sc.exe", &["description", SERVICE_NAME, "Unblocks Steam and the websites you add: pins them to working servers and runs a DPI bypass for just those sites when needed."]);
    run_hidden("sc.exe", &["failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000/restart/30000/restart/60000"]);
    // 4.0.0 registered a delayed start; "start= auto" alone may leave that flag set. Start with Windows.
    {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
        if let Ok(s) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).and_then(|m| m.open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG)) {
            let _ = s.set_delayed_auto_start(false);
        }
    }
    run_hidden("sc.exe", &["start", SERVICE_NAME]);

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok((k, _)) = hklm.create_subkey(RUN_KEY) { let _ = k.set_value("RustyDPI", &format!("\"{}\" --tray", exe.display())); }
    if let Ok((u, _)) = hklm.create_subkey(UNINSTALL_KEY) {
        let size = std::fs::metadata(&exe).map(|m| (m.len() / 1024) as u32).unwrap_or(0) + 4000;
        let _ = u.set_value("DisplayName", &"RustyDPI");
        let _ = u.set_value("DisplayVersion", &crate::engine::VERSION);
        let _ = u.set_value("Publisher", &"CratusGod");
        let _ = u.set_value("DisplayIcon", &exe.display().to_string());
        let _ = u.set_value("InstallLocation", &paths.install_dir.display().to_string());
        let _ = u.set_value("URLInfoAbout", &"https://github.com/CratusGod/rustydpi");
        let _ = u.set_value("UninstallString", &format!("\"{}\" --uninstall", exe.display()));
        let _ = u.set_value("NoModify", &1u32);
        let _ = u.set_value("NoRepair", &1u32);
        let _ = u.set_value("EstimatedSize", &size);
    }
    create_shortcut(&shortcut_path(), &exe);
    // The old tray was closed above; bring the icon back now instead of at the next sign-in.
    if !win::start_as_desktop_user(&exe, "--tray") { say("The tray icon will appear the next time you sign in."); }
    say("RustyDPI is installed. The first check takes about a minute.");
    0
}

pub fn uninstall(say: &dyn Fn(&str)) -> i32 {
    if !win::is_admin() { say("Uninstalling needs administrator rights."); return 5; }
    let paths = Paths::default_paths();
    say("Stopping RustyDPI...");
    stop_service();
    run_hidden("sc.exe", &["delete", SERVICE_NAME]);
    kill_installed_instances(&paths.exe());
    // Remove the WinDivert driver service only when it's ours.
    if crate::diag::windivert_driver_path().map(|d| d.to_ascii_lowercase().contains(&paths.zapret_dir().display().to_string().to_ascii_lowercase())).unwrap_or(false) {
        run_hidden("sc.exe", &["stop", "WinDivert"]);
        run_hidden("sc.exe", &["delete", "WinDivert"]);
    }
    say("Removing RustyDPI's entries from the hosts file...");
    let cfg = crate::config::Config::default_config();
    let net = crate::net::RealNet { cfg: &cfg, flush: true };
    let prober = crate::probe::HttpsProber { connect_timeout: std::time::Duration::from_secs(3), total_timeout: std::time::Duration::from_secs(6) };
    let runner = crate::bypass::WinwsRunner::new(paths.bypass());
    let log = crate::paths::Log::new(None, false);
    if let Err(e) = crate::engine::Engine::new(&cfg, &paths, &net, &prober, &runner, &log).unpin() { say(&format!("warning: {e}")); }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(k) = hklm.open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE) { let _ = k.delete_value("RustyDPI"); }
    let _ = hklm.delete_subkey_all(UNINSTALL_KEY);
    let _ = std::fs::remove_file(shortcut_path());
    let _ = std::fs::remove_dir_all(&paths.data_dir);
    let _ = std::fs::remove_dir_all(paths.zapret_dir());
    // The exe may be the one running: delete the folder after we exit.
    let dir = paths.install_dir.display().to_string();
    let _ = std::process::Command::new("cmd.exe").raw_arg(format!("/c timeout /t 3 /nobreak >nul & rmdir /s /q \"{dir}\""))
        .creation_flags(win::CREATE_NO_WINDOW).spawn();
    say("RustyDPI was removed.");
    0
}


/// RustyDPI's earlier name. SteamPin 3 was the same app; SteamPin 1/2 were a PowerShell script.
const OLD_NAME: &str = "SteamPin";

fn remove_legacy(paths: &Paths, say: &dyn Fn(&str)) {
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
    let (old_install, old_data) = (Path::new(&pf).join(OLD_NAME), Path::new(&pd).join(OLD_NAME));

    // SteamPin 1/2: a scheduled task running a PowerShell script.
    if run_hidden("schtasks.exe", &["/Query", "/TN", OLD_NAME]) == 0 {
        run_hidden("schtasks.exe", &["/Delete", "/TN", OLD_NAME, "/F"]);
        say("Removed SteamPin 2's scheduled task.");
    }
    let v2_config = old_install.join("config.json");
    if v2_config.exists() {
        let _ = std::fs::create_dir_all(&paths.data_dir);
        let _ = std::fs::copy(&v2_config, paths.data_dir.join("config.v2.json.bak"));
    }

    // SteamPin 3: same app under the old name. Stop it, carry its settings and state over, remove it.
    if run_hidden("sc.exe", &["query", OLD_NAME]) == 0 || old_install.exists() {
        say("Replacing SteamPin (RustyDPI's earlier name)...");
        run_hidden("sc.exe", &["stop", OLD_NAME]);
        for _ in 0..40 {
            let out = win::run_hidden_output("sc.exe", &["query", OLD_NAME]).unwrap_or_default();
            if !out.contains("STATE") || out.contains("STOPPED") { break; }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        run_hidden("sc.exe", &["delete", OLD_NAME]);
        let old_dir = old_install.display().to_string().to_ascii_lowercase();
        for p in win::processes() {
            if p.path.as_deref().map(|x| x.to_ascii_lowercase().starts_with(&old_dir)).unwrap_or(false) { win::kill(p.pid); }
        }
        if crate::diag::windivert_driver_path().map(|d| d.to_ascii_lowercase().contains(&old_dir)).unwrap_or(false) {
            run_hidden("sc.exe", &["stop", "WinDivert"]);
            run_hidden("sc.exe", &["delete", "WinDivert"]);
        }
        let _ = std::fs::create_dir_all(&paths.data_dir);
        for f in ["settings.json", "state.json", "config.json", "log.txt"] {
            let (from, to) = (old_data.join(f), paths.data_dir.join(f));
            if from.exists() && !to.exists() { let _ = std::fs::copy(&from, &to); }
        }
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(k) = hklm.open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE) { let _ = k.delete_value(OLD_NAME); }
        let _ = hklm.delete_subkey_all(format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{OLD_NAME}"));
        let _ = std::fs::remove_file(Path::new(&pd).join(format!(r"Microsoft\Windows\Start Menu\Programs\{OLD_NAME}.lnk")));
        let _ = std::fs::remove_dir_all(&old_data);
        let _ = std::fs::remove_dir_all(&old_install);
        // The hosts block SteamPin wrote is adopted by the first check and rewritten under the new name.
    }
}

/// Restores the zapret files after antivirus removed them.
pub fn repair(say: &dyn Fn(&str)) -> i32 {
    if !win::is_admin() { return win::run_elevated("--repair"); }
    let paths = Paths::default_paths();
    stop_service();
    let r = crate::bypass::extract(&paths.zapret_dir());
    run_hidden("sc.exe", &["start", SERVICE_NAME]);
    let bad = crate::bypass::bad_files(&paths.zapret_dir());
    if bad.is_empty() && r.is_ok() { say("Files repaired."); 0 } else { say(&format!("Still missing: {}. Add an antivirus exception for {}.", bad.join(", "), paths.zapret_dir().display())); 1 }
}

pub fn hosts_writable() -> i32 {
    if !win::is_admin() { return win::run_elevated("--hosts-writable"); }
    let p = crate::hosts::system_path();
    if let Ok(m) = std::fs::metadata(&p) {
        let mut perm = m.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        let _ = std::fs::set_permissions(&p, perm);
    }
    0
}

pub fn stop_other_bypass(say: &dyn Fn(&str)) -> i32 {
    if !win::is_admin() { return win::run_elevated("--stop-other-bypass"); }
    for p in crate::diag::other_bypass_tools(&Paths::default_paths().zapret_dir()) {
        if win::kill(p.pid) { say(&format!("closed {}", p.name)); }
    }
    std::thread::sleep(std::time::Duration::from_secs(1));
    crate::bypass::clear_stale_driver();
    0
}

fn create_shortcut(lnk: &Path, target: &Path) {
    let ps = format!(
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}');$s.TargetPath='{}';$s.WorkingDirectory='{}';$s.Description='RustyDPI - unblocks websites and Steam';$s.Save()",
        lnk.display(), target.display(), target.parent().map(|p| p.display().to_string()).unwrap_or_default());
    run_hidden("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", &ps]);
}
