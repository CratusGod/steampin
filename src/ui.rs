//! The window (Slint, drawn on the CPU so it stays a few MB). Runs only while it's open;
//! all the work happens in the service.

use crate::diag::{fixes, DiagCheck, Level};
use crate::engine::{RunReport, TargetRow};
use crate::ipc::ServiceStatus;
use crate::state::Route;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

slint::slint! {
    import { ScrollView } from "std-widgets.slint";

    export struct GroupRow { name: string, ok: bool, summary: string }
    export struct HostRow { name: string, note: string, note-warn: bool, route: string, ip: string, ms: string, ok: bool }
    export struct CheckRow { title: string, detail: string, level: int, fix: string, fix-label: string }

    global Theme {
        out property <color> bg: #171A21;
        out property <color> panel: #1F2630;
        out property <color> panel-hi: #28313D;
        out property <color> text: #E6EDF3;
        out property <color> muted: #8F9BA8;
        out property <color> accent: #1A9FFF;
        out property <color> info: #66C0F4;
        out property <color> good: #5BD17B;
        out property <color> warn: #F2B84B;
        out property <color> bad: #F2645A;
        public pure function level(l: int) -> color { return l == 0 ? good : l == 1 ? info : l == 2 ? warn : bad; }
    }

    component Btn inherits Rectangle {
        horizontal-stretch: 0;
        in property <string> text;
        in property <bool> primary;
        in property <bool> enabled: true;
        callback clicked;
        min-width: t.preferred-width + (primary ? 44px : 28px);
        height: primary ? 40px : 32px;
        border-radius: 6px;
        background: !enabled ? (primary ? #1A9FFF60 : #28313D80) : ta.pressed ? (primary ? #1580D0 : #3A4757) : ta.has-hover ? (primary ? #3AAEFF : #333E4C) : (primary ? Theme.accent : Theme.panel-hi);
        border-width: 1px;
        border-color: primary ? transparent : #2F3A47;
        t := Text { text: root.text; color: root.enabled ? (primary ? white : Theme.text) : Theme.muted; font-size: primary ? 15px : 13px; font-weight: primary ? 600 : 400; }
        accessible-role: button;
        accessible-label: root.text;
        accessible-enabled: root.enabled;
        accessible-action-default => { if (root.enabled) { root.clicked(); } }
        ta := TouchArea { enabled: root.enabled; mouse-cursor: pointer; clicked => { root.clicked(); } }
    }

    component Toggle inherits Rectangle {
        in property <string> text;
        in-out property <bool> checked;
        in property <bool> enabled: true;
        callback toggled(bool);
        height: max(24px, label.preferred-height);
        HorizontalLayout {
            spacing: 10px;
            Rectangle {
                width: 40px; height: 22px; y: 1px; border-radius: 11px;
                background: root.checked ? Theme.accent : #2F3A47;
                opacity: root.enabled ? 1 : 0.5;
                Rectangle { width: 16px; height: 16px; border-radius: 8px; background: white; x: root.checked ? 21px : 3px; animate x { duration: 120ms; } }
            }
            label := Text { text: root.text; color: Theme.text; wrap: word-wrap; vertical-alignment: center; }
        }
        accessible-role: checkbox;
        accessible-label: root.text;
        accessible-checkable: true;
        accessible-checked: root.checked;
        accessible-enabled: root.enabled;
        accessible-action-default => { if (root.enabled) { root.checked = !root.checked; root.toggled(root.checked); } }
        TouchArea { enabled: root.enabled; mouse-cursor: pointer; clicked => { root.checked = !root.checked; root.toggled(root.checked); } }
    }

    component Card inherits Rectangle {
        background: Theme.panel;
        border-radius: 10px;
        VerticalLayout { padding: 18px; spacing: 8px; @children }
    }

    component Dot inherits Rectangle {
        in property <color> c;
        in property <length> size: 10px;
        width: size; height: size; border-radius: size / 2; background: c;
    }

    component Muted inherits Text { color: Theme.muted; wrap: word-wrap; }
    component Heading inherits Text { font-size: 16px; font-weight: 600; color: Theme.text; }

    export component MainWindow inherits Window {
        title: "SteamPin";
        preferred-width: 820px; preferred-height: 660px;
        min-width: 640px; min-height: 520px;
        background: Theme.bg;
        default-font-size: 14px;

        in-out property <int> page: 0;
        in property <string> network;
        in property <string> head-title: "Loading...";
        in property <string> head-detail;
        in property <int> head-level: 1;
        in property <string> working;
        in property <string> main-button: "Fix Steam";
        in property <bool> main-enabled: true;
        in property <bool> restart-needed;
        in property <string> message;
        in property <[GroupRow]> groups;
        in property <string> groups-empty: "No check yet.";
        in property <string> footer;
        in property <[HostRow]> hosts;
        in property <string> bypass-detail;
        in property <[CheckRow]> checks;
        in property <bool> diag-running;
        in property <bool> diag-done;
        in property <string> copy-label: "Copy report";
        in property <string> log-text;
        in-out property <bool> bypass-on: true;
        in-out property <bool> autorestart;
        in property <bool> service-up;
        in property <bool> installed;
        in property <bool> busy;
        in property <string> strategy-text;
        in property <string> scores-text;
        in property <string> about-text;

        callback main-clicked;
        callback nav(int);
        callback run-diag;
        callback copy-report;
        callback check-fix(string);
        callback restart-steam;
        callback open-data;
        callback open-project;
        callback uninstall;
        callback set-bypass(bool);
        callback set-autorestart(bool);
        callback retest;
        callback dismiss-message;

        VerticalLayout {
            padding-left: 22px; padding-right: 22px; padding-top: 16px; padding-bottom: 12px;
            spacing: 10px;
            HorizontalLayout {
                Text { text: "SteamPin"; font-size: 24px; font-weight: 700; color: Theme.text; }
                Text { text: root.network; color: Theme.muted; horizontal-alignment: right; vertical-alignment: center; }
            }
            HorizontalLayout {
                spacing: 4px; alignment: start;
                for name[i] in ["Home", "Diagnose", "Details", "Log", "Settings"] : Rectangle {
                    width: nt.preferred-width + 24px; height: 32px; border-radius: 6px;
                    accessible-role: tab;
                    accessible-label: name;
                    accessible-item-selectable: true;
                    accessible-item-selected: root.page == i;
                    accessible-action-default => { root.page = i; root.nav(i); }
                    background: root.page == i ? Theme.panel-hi : transparent;
                    nt := Text { text: name; color: root.page == i || nta.has-hover ? Theme.text : Theme.muted; }
                    nta := TouchArea { mouse-cursor: pointer; clicked => { root.page = i; root.nav(i); } }
                }
            }
            if root.message != "" : Card {
                HorizontalLayout {
                    spacing: 12px;
                    Text { text: root.message; color: Theme.warn; wrap: word-wrap; vertical-alignment: center; horizontal-stretch: 1; }
                    Btn { text: "OK"; clicked => { root.dismiss-message(); } }
                }
            }
            ScrollView {
                VerticalLayout {
                    spacing: 10px; alignment: start;
                    // Home
                    if root.page == 0 : VerticalLayout {
                        spacing: 10px;
                        Card {
                            HorizontalLayout {
                                spacing: 16px;
                                VerticalLayout { padding-top: 8px; alignment: start; Dot { c: Theme.level(root.head-level); size: 18px; } }
                                VerticalLayout {
                                    spacing: 4px; horizontal-stretch: 1;
                                    Text { text: root.head-title; font-size: 22px; font-weight: 600; color: Theme.text; wrap: word-wrap; }
                                    Muted { text: root.head-detail; }
                                    if root.working != "" : Text { text: root.working; color: Theme.info; wrap: word-wrap; }
                                }
                                VerticalLayout { alignment: center; horizontal-stretch: 0; Btn { text: root.main-button; primary: true; enabled: root.main-enabled; clicked => { root.main-clicked(); } } }
                            }
                        }
                        if root.restart-needed : Card {
                            HorizontalLayout {
                                spacing: 12px;
                                Text { text: "SteamPin switched Steam to new servers. Restart Steam so it uses them."; color: Theme.warn; wrap: word-wrap; vertical-alignment: center; horizontal-stretch: 1; }
                                Btn { text: "Restart Steam"; clicked => { root.restart-steam(); } }
                            }
                        }
                        Card {
                            Heading { text: "Steam services"; }
                            if root.groups.length == 0 : Muted { text: root.groups-empty; }
                            for g in root.groups : HorizontalLayout {
                                spacing: 12px;
                                VerticalLayout { padding-top: 5px; alignment: start; Dot { c: g.ok ? Theme.good : Theme.bad; } }
                                Text { text: g.name; font-weight: 600; color: Theme.text; width: 140px; }
                                Muted { text: g.summary; }
                            }
                        }
                        Muted { text: root.footer; }
                    }
                    // Diagnose
                    if root.page == 1 : Card {
                        HorizontalLayout {
                            spacing: 8px;
                            VerticalLayout { spacing: 2px; horizontal-stretch: 1; Heading { text: "Diagnose"; } Muted { text: "Checks everything that can stop Steam from working, and offers a fix where there is one."; } }
                            VerticalLayout { alignment: center; horizontal-stretch: 0; Btn { text: root.copy-label; enabled: root.diag-done; clicked => { root.copy-report(); } } }
                            VerticalLayout { alignment: center; horizontal-stretch: 0; Btn { text: root.diag-running ? "Checking..." : "Run diagnosis"; primary: true; enabled: !root.diag-running; clicked => { root.run-diag(); } } }
                        }
                        if root.diag-running : Muted { text: "Running checks (up to 20 seconds)..."; }
                        for c in root.checks : HorizontalLayout {
                            spacing: 12px;
                            VerticalLayout { padding-top: 5px; alignment: start; Dot { c: Theme.level(c.level); } }
                            Text { text: c.title; font-weight: 600; color: Theme.text; width: 150px; wrap: word-wrap; }
                            Muted { text: c.detail; horizontal-stretch: 1; }
                            if c.fix != "" : VerticalLayout { alignment: start; horizontal-stretch: 0; Btn { text: c.fix-label; clicked => { root.check-fix(c.fix); } } }
                        }
                    }
                    // Details
                    if root.page == 2 : Card {
                        Heading { text: "Every Steam server SteamPin checks"; }
                        HorizontalLayout {
                            spacing: 12px;
                            Rectangle { width: 8px; }
                            Muted { text: "Host"; font-size: 12px; }
                            Muted { text: "Route"; font-size: 12px; width: 100px; }
                            Muted { text: "Server"; font-size: 12px; width: 120px; }
                            Muted { text: "Time"; font-size: 12px; width: 60px; }
                        }
                        for h in root.hosts : HorizontalLayout {
                            spacing: 12px;
                            VerticalLayout { padding-top: 6px; alignment: start; Dot { c: h.ok ? Theme.good : Theme.bad; size: 8px; } }
                            VerticalLayout {
                                Text { text: h.name; color: Theme.text; }
                                if h.note != "" : Text { text: h.note; font-size: 12px; color: h.note-warn ? Theme.warn : Theme.muted; wrap: word-wrap; }
                            }
                            Muted { text: h.route; width: 100px; }
                            Text { text: h.ip; font-family: "Consolas"; font-size: 12px; color: Theme.text; width: 120px; }
                            Muted { text: h.ms; width: 60px; }
                        }
                        Muted { text: root.bypass-detail; }
                    }
                    // Log
                    if root.page == 3 : Card {
                        HorizontalLayout { alignment: start; Btn { text: "Open data folder"; clicked => { root.open-data(); } } }
                        Text { text: root.log-text; font-family: "Consolas"; font-size: 12px; color: Theme.text; wrap: word-wrap; }
                    }
                    // Settings
                    if root.page == 4 : VerticalLayout {
                        spacing: 10px;
                        Card {
                            Heading { text: "DPI bypass"; }
                            Muted { text: "For Steam hosts that can't be pinned to a working server, SteamPin runs zapret's winws on Steam traffic only (ports 80 and 443, Steam host names). Games and other apps aren't touched."; }
                            Toggle { text: "Use the DPI bypass when needed"; checked <=> root.bypass-on; enabled: root.service-up; toggled(v) => { root.set-bypass(v); } }
                            Text { text: root.strategy-text; color: Theme.text; wrap: word-wrap; }
                            HorizontalLayout { alignment: start; Btn { text: "Find the best strategy again"; enabled: root.service-up && !root.busy; clicked => { root.retest(); } } }
                            if root.scores-text != "" : Text { text: root.scores-text; font-family: "Consolas"; font-size: 12px; color: Theme.muted; }
                        }
                        Card {
                            Heading { text: "Steam"; }
                            Toggle { text: "Restart Steam automatically after SteamPin switches servers (if a game is running, it waits until you close it)"; checked <=> root.autorestart; enabled: root.service-up; toggled(v) => { root.set-autorestart(v); } }
                        }
                        Card {
                            Heading { text: "About"; }
                            Muted { text: root.about-text; }
                            HorizontalLayout {
                                spacing: 8px; alignment: start;
                                Btn { text: "Project page"; clicked => { root.open-project(); } }
                                Btn { text: "Open data folder"; clicked => { root.open-data(); } }
                                Btn { text: "Uninstall SteamPin"; enabled: root.installed; clicked => { root.uninstall(); } }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Default)]
struct Shared {
    status: Option<ServiceStatus>,
    service_up: bool,
    installed: bool,
    polled: bool,
    checks: Option<Vec<DiagCheck>>,
    diag_running: bool,
    log: Vec<String>,
    working: Option<String>,
    message: Option<String>,
    copied: bool,
}

type S = Arc<Mutex<Shared>>;

pub fn run() -> i32 {
    unsafe {
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
        use windows_sys::Win32::UI::WindowsAndMessaging::*;
        let m = windows_sys::Win32::System::Threading::CreateMutexW(std::ptr::null(), 1, crate::win::wide("Local\\SteamPin.Window").as_ptr());
        if m.is_null() || GetLastError() == ERROR_ALREADY_EXISTS {
            let h = FindWindowW(std::ptr::null(), crate::win::wide("SteamPin").as_ptr());
            if !h.is_null() { ShowWindow(h, SW_RESTORE); SetForegroundWindow(h); }
            return 0;
        }
    }
    let Ok(w) = MainWindow::new() else {
        crate::win::message_box("SteamPin couldn't open its window. SteamPin itself keeps working in the background.", "SteamPin", 0x30);
        return 1;
    };
    let s: S = Arc::new(Mutex::new(Shared::default()));
    w.set_about_text(format!("SteamPin {} · MIT licence · DPI bypass by zapret (MIT) and WinDivert (LGPL) · UI by Slint.\nData folder: {}",
        crate::engine::VERSION, crate::paths::Paths::default_paths().data_dir.display()).into());
    wire(&w, &s);
    if let Some(p) = std::env::var("STEAMPIN_PAGE").ok().and_then(|p| p.parse::<i32>().ok()) { w.set_page(p); w.invoke_nav(p); }

    // Poll the service every 2 s on a background thread; the UI is refreshed on its own thread.
    let (weak, s2) = (w.as_weak(), s.clone());
    std::thread::spawn(move || loop {
        let demo = std::env::var("STEAMPIN_DEMO").ok();
        let installed = demo.is_some() || installed();
        let r = match &demo {
            // Screenshots and UI tests: show a saved status instead of asking the service.
            Some(p) => std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok()).map(|status| crate::ipc::Response { ok: true, status: Some(status), ..Default::default() }),
            None if installed => crate::ipc::send("status", None, Duration::from_secs(4)),
            None => None,
        };
        {
            let mut g = s2.lock().unwrap();
            g.installed = installed;
            g.service_up = r.is_some();
            g.status = r.and_then(|r| r.status);
            g.polled = true;
        }
        let s3 = s2.clone();
        if weak.upgrade_in_event_loop(move |w| render(&w, &s3)).is_err() { break; }
        std::thread::sleep(Duration::from_secs(2));
    });

    // Dark title bar once the window exists.
    let weak = w.as_weak();
    slint::Timer::single_shot(Duration::from_millis(200), move || {
        let _ = weak;
        unsafe {
            let h = windows_sys::Win32::UI::WindowsAndMessaging::FindWindowW(std::ptr::null(), crate::win::wide("SteamPin").as_ptr());
            if !h.is_null() {
                use windows_sys::Win32::UI::WindowsAndMessaging::*;
                let on: i32 = 1;
                windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute(h, 20, &on as *const _ as _, 4);
                let inst = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null());
                let big = LoadImageW(inst, 1 as _, IMAGE_ICON, 32, 32, 0);
                let small = LoadImageW(inst, 1 as _, IMAGE_ICON, 16, 16, 0);
                if !big.is_null() { SendMessageW(h, WM_SETICON, ICON_BIG as usize, big as isize); }
                if !small.is_null() { SendMessageW(h, WM_SETICON, ICON_SMALL as usize, small as isize); }
            }
        }
    });
    let _ = w.run();
    0
}

/// Runs `f` on a worker thread, showing `label` while it works, then re-renders.
fn spawn(w: &MainWindow, s: &S, label: &str, f: impl FnOnce(&S) + Send + 'static) {
    s.lock().unwrap().working = (!label.is_empty()).then(|| label.to_string());
    render(w, s);
    let (weak, s) = (w.as_weak(), s.clone());
    std::thread::spawn(move || {
        f(&s);
        s.lock().unwrap().working = None;
        let s2 = s.clone();
        let _ = weak.upgrade_in_event_loop(move |w| render(&w, &s2));
    });
}

fn send(w: &MainWindow, s: &S, cmd: &'static str, flag: Option<bool>) {
    spawn(w, s, "", move |_| { crate::ipc::send(cmd, flag, Duration::from_secs(5)); });
}

fn wire(w: &MainWindow, s: &S) {
    let ww = w.as_weak();
    macro_rules! on { ($cb:ident, |$w:ident, $s:ident $(, $a:ident : $t:ty)*| $body:expr) => {{
        let (weak, $s) = (ww.clone(), s.clone());
        w.$cb(move |$($a: $t),*| { if let Some($w) = weak.upgrade() { let $s = &$s; $body } });
    }}; }

    on!(on_main_clicked, |w, s| {
        let (installed, up) = { let g = s.lock().unwrap(); (g.installed, g.service_up) };
        if !installed { install(&w, s); }
        else if up { send(&w, s, "fix", None); }
        else { spawn(&w, s, "Repairing... accept the Windows prompt", |_| { crate::win::run_elevated("--install"); }); }
    });
    on!(on_nav, |w, s, p: i32| {
        if p == 1 && s.lock().unwrap().checks.is_none() { run_diagnosis(&w, s); }
        if p == 3 {
            spawn(&w, s, "", |s| {
                let lines = crate::ipc::send("log", None, Duration::from_secs(5)).and_then(|r| r.lines)
                    .unwrap_or_else(|| crate::paths::tail(&crate::paths::Paths::default_paths().log(), 300));
                s.lock().unwrap().log = lines;
            });
        }
        render(&w, s);
    });
    on!(on_run_diag, |w, s| { s.lock().unwrap().copied = false; run_diagnosis(&w, s); });
    on!(on_copy_report, |w, s| {
        let text = {
            let g = s.lock().unwrap();
            let mut t = format!("SteamPin {} diagnosis, {}\n", crate::engine::VERSION, chrono::Local::now().format("%Y-%m-%d %H:%M"));
            for c in g.checks.iter().flatten() { t += &format!("[{}] {}: {}\n", format!("{:?}", c.level).to_uppercase(), c.title, c.detail); }
            if let Some(r) = g.status.as_ref().and_then(|x| x.report.as_ref()) { t += "\n"; t += &r.to_text(); }
            t
        };
        set_clipboard(&text);
        s.lock().unwrap().copied = true;
        render(&w, s);
    });
    on!(on_check_fix, |w, s, fix: SharedString| do_fix(&w, s, fix.to_string()));
    on!(on_restart_steam, |w, s| do_fix(&w, s, fixes::RESTART_STEAM.into()));
    on!(on_open_data, |_w, _s| crate::win::open_url(&crate::paths::Paths::default_paths().data_dir.display().to_string()));
    on!(on_open_project, |_w, _s| crate::win::open_url("https://github.com/CratusGod/steampin"));
    on!(on_set_bypass, |w, s, v: bool| send(&w, s, "bypass", Some(v)));
    on!(on_set_autorestart, |w, s, v: bool| send(&w, s, "autorestart", Some(v)));
    on!(on_retest, |w, s| { send(&w, s, "retest", None); w.set_page(0); });
    on!(on_dismiss_message, |w, s| { s.lock().unwrap().message = None; render(&w, s); });
    on!(on_uninstall, |w, s| {
        if crate::win::message_box("Remove SteamPin? Steam goes back to how it was before (blocked, if your network blocks it).", "SteamPin", 0x31) == 1 {
            spawn(&w, s, "Uninstalling... accept the Windows prompt", |_| {
                if crate::win::run_elevated("--uninstall --quiet") == 0 { let _ = slint::invoke_from_event_loop(|| { let _ = slint::quit_event_loop(); }); }
            });
        }
    });
}

fn install(w: &MainWindow, s: &S) {
    spawn(w, s, "Installing... accept the Windows prompt", |s| {
        let code = crate::win::run_elevated("--install");
        if code != 0 {
            s.lock().unwrap().message = Some(if code == -1 { "Installation was cancelled.".into() } else { format!("Installation failed (code {code}).") });
            return;
        }
        let exe = crate::paths::Paths::default_paths().exe();
        let _ = std::process::Command::new(&exe).arg("--tray").spawn();
        if !crate::installer::running_from_install_dir() {
            // Continue in the installed copy and close this one (e.g. the copy in Downloads).
            let _ = slint::invoke_from_event_loop(move || {
                let _ = slint::quit_event_loop();
                let _ = std::process::Command::new(&exe).arg("--window").spawn();
            });
        }
    });
}

fn run_diagnosis(w: &MainWindow, s: &S) {
    { let mut g = s.lock().unwrap(); if g.diag_running { return; } g.diag_running = true; }
    spawn(w, s, "", |s| {
        let mut checks: Vec<DiagCheck> = Vec::new();
        let dc = |id: &str, title: &str, detail: &str, label: &str| DiagCheck { id: id.into(), title: title.into(), level: Level::Fail, detail: detail.into(), fix: Some(fixes::INSTALL.into()), fix_label: Some(label.into()) };
        if !installed() { checks.push(dc("install", "SteamPin", "Not installed.", "Install")); }
        else {
            match crate::ipc::send("diagnose", None, Duration::from_secs(60)) {
                Some(r) => checks.extend(r.checks.unwrap_or_default()),
                None => checks.push(dc("service", "SteamPin service", "Not running or not answering.", "Repair install")),
            }
        }
        let lhc = s.lock().unwrap().status.as_ref().and_then(|x| x.last_hosts_change);
        checks.extend(crate::diag::user_checks(lhc));
        checks.sort_by(|a, b| b.level.cmp(&a.level));
        let mut g = s.lock().unwrap();
        g.checks = Some(checks);
        g.diag_running = false;
    });
}

fn do_fix(w: &MainWindow, s: &S, fix: String) {
    spawn(w, s, "Working...", move |s| {
        let ipc = |c: &str, f: Option<bool>| { crate::ipc::send(c, f, Duration::from_secs(5)); };
        match fix.as_str() {
            fixes::RUN_FULL => ipc("fix", None),
            fixes::RETEST => ipc("retest", None),
            fixes::BYPASS_ON => ipc("bypass", Some(true)),
            fixes::RESTART_STEAM => { if crate::diag::steam::confirm_if_game() { if let Err(e) = crate::diag::steam::restart() { s.lock().unwrap().message = Some(e); } } }
            fixes::INSTALL => { crate::win::run_elevated("--install"); }
            fixes::REPAIR => { crate::win::run_elevated("--repair"); ipc("fix", None); }
            fixes::HOSTS_READONLY => { crate::win::run_elevated("--hosts-writable"); ipc("fix", None); }
            fixes::STOP_OTHER => {
                if crate::win::message_box("Close the other DPI-bypass tools now (for example CDPI UI)? They'll start again at your next sign-in unless you uninstall them.", "SteamPin", 0x21) == 1 {
                    crate::win::run_elevated("--stop-other-bypass");
                    ipc("fix", None);
                }
            }
            _ => {}
        }
        s.lock().unwrap().checks = None;
    });
}

fn set_clipboard(text: &str) {
    use windows_sys::Win32::System::DataExchange::*;
    use windows_sys::Win32::System::Memory::*;
    let w: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 { return; }
        EmptyClipboard();
        let h = GlobalAlloc(GMEM_MOVEABLE, w.len() * 2);
        if !h.is_null() {
            let p = GlobalLock(h) as *mut u16;
            std::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len());
            GlobalUnlock(h);
            SetClipboardData(13 /* CF_UNICODETEXT */, h as _);
        }
        CloseClipboard();
    }
}

// ---- turning status into words ----

struct Head { title: String, detail: String, level: Level }

fn headline(g: &Shared) -> Head {
    let h = |t: &str, d: &str, l| Head { title: t.into(), detail: d.into(), level: l };
    if !g.polled { return h("Loading...", "", Level::Info); }
    if !g.installed { return h("SteamPin isn't installed yet", "Install it to keep Steam working. It runs quietly in the background.", Level::Info); }
    if !g.service_up { return h("The SteamPin service isn't running", "Click Fix Steam to start it again.", Level::Fail); }
    let s = g.status.as_ref().unwrap();
    let r = s.report.as_ref();
    if s.busy { return h(s.activity.as_deref().unwrap_or("Checking Steam"), if r.is_none() { "The first check takes about a minute." } else { "This takes up to a minute." }, Level::Info); }
    let Some(r) = r else { return h("Waiting for the first check", "It starts in a moment.", Level::Info) };
    if !r.online { return h("You're offline", "SteamPin changes nothing until you're back online.", Level::Warn); }
    let bad: Vec<&TargetRow> = r.rows.iter().filter(|x| !x.ok).collect();
    if bad.is_empty() {
        let d = if r.blocked { format!("Steam is blocked on your network; SteamPin is working around it{}.", r.network.as_deref().map(|n| format!(" ({})", short_isp(n))).unwrap_or_default()) }
                else if r.rows.iter().any(|x| x.route == Route::Pinned) { "Nothing is blocked right now; SteamPin keeps its pinned servers ready in case that changes.".into() }
                else { "Nothing is blocked on this network.".into() };
        return Head { title: "Steam works".into(), detail: d, level: Level::Ok };
    }
    let mut groups: Vec<&str> = Vec::new();
    for b in &bad { if !groups.contains(&b.group.as_str()) { groups.push(&b.group); } }
    Head { title: format!("Steam {} not working", groups.join(", ")), detail: "Click Fix Steam to check everything again, or open Diagnose to see why.".into(), level: Level::Fail }
}

pub fn short_isp(n: &str) -> String {
    // "AS18403 FPT-VN - FPT Telecom Company, VN" -> "FPT Telecom Company"
    let s = n.split_once(" - ").map(|x| x.1).unwrap_or_else(|| n.split_once(' ').map(|x| x.1).unwrap_or(n));
    s.rsplit_once(',').map(|x| x.0).unwrap_or(s).to_string()
}

fn explain(r: &TargetRow) -> &'static str {
    match r.route {
        Route::Direct => "works normally", Route::Pinned => "pinned to a working server", Route::Bypass => "unblocked by the bypass",
        Route::PinnedBypass => "pinned + unblocked by the bypass", Route::Broken => "not working", Route::Unknown => "not checked yet",
    }
}

fn group_summary(rows: &[&TargetRow]) -> String {
    let bad: Vec<&&TargetRow> = rows.iter().filter(|r| !r.ok).collect();
    if !bad.is_empty() {
        let why = bad.iter().map(|r| if r.note.is_empty() { r.direct_problem.as_str() } else { r.note.as_str() }).find(|s| !s.is_empty());
        return format!("{} of {} not working{}", bad.len(), rows.len(), why.map(|w| format!(": {w}")).unwrap_or_default());
    }
    let mut routes: Vec<&str> = Vec::new();
    for r in rows { let e = explain(r); if !routes.contains(&e) { routes.push(e); } }
    let ms = rows.iter().filter_map(|r| r.ms).fold(0.0, f64::max);
    format!("{}{}", routes.join(", "), if ms > 0.0 { format!(" · {ms:.0} ms") } else { String::new() })
}

fn ago(t: crate::state::Time) -> String {
    let d = crate::state::now() - t;
    if d.num_seconds() < 60 { "just now".into() } else if d.num_minutes() < 60 { format!("{} min ago", d.num_minutes()) }
    else if d.num_hours() < 24 { format!("{} h ago", d.num_hours()) } else { t.format("%Y-%m-%d %H:%M").to_string() }
}

fn level_int(l: Level) -> i32 { match l { Level::Ok => 0, Level::Info => 1, Level::Warn => 2, Level::Fail => 3 } }

fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> { ModelRc::from(Rc::new(VecModel::from(v))) }

fn render(w: &MainWindow, s: &S) {
    let g = s.lock().unwrap();
    let head = headline(&g);
    let status = g.status.as_ref();
    let report: Option<&RunReport> = status.and_then(|s| s.report.as_ref());
    let busy = status.map(|s| s.busy).unwrap_or(false);
    w.set_head_title(head.title.into());
    w.set_head_detail(head.detail.into());
    w.set_head_level(level_int(head.level));
    w.set_working(g.working.clone().unwrap_or_default().into());
    w.set_main_button(if !g.installed { "Install" } else if busy { "Checking..." } else { "Fix Steam" }.into());
    w.set_main_enabled(g.polled && !busy && g.working.is_none());
    w.set_network(report.and_then(|r| r.network.as_deref()).map(short_isp).unwrap_or_default().into());
    w.set_message(g.message.clone().unwrap_or_default().into());
    w.set_installed(g.installed);
    w.set_service_up(g.service_up);
    w.set_busy(busy);
    w.set_restart_needed(status.and_then(|s| s.last_hosts_change).zip(crate::diag::steam::start_time()).map(|(c, st)| st < c).unwrap_or(false));

    let groups: Vec<GroupRow> = match report {
        Some(r) if r.online => r.groups().into_iter().map(|(name, ok)| {
            let rows: Vec<&TargetRow> = r.rows.iter().filter(|x| x.group == name).collect();
            GroupRow { summary: group_summary(&rows).into(), name: name.into(), ok }
        }).collect(),
        _ => vec![],
    };
    w.set_groups_empty(match report { Some(r) if !r.online => "Offline.", _ => "No check yet." }.into());
    w.set_groups(model(groups));

    let mut foot = Vec::new();
    if let Some(r) = report { foot.push(format!("Last check {} (took {:.0} s)", ago(r.time), r.seconds)); }
    if let Some(n) = status.filter(|s| !s.busy).and_then(|s| s.next_run) { foot.push(format!("next at {}", n.format("%H:%M"))); }
    if let Some(b) = report.map(|r| &r.bypass).filter(|b| b.running) { foot.push(format!("bypass on for {} {}", b.hosts.len(), if b.hosts.len() == 1 { "host" } else { "hosts" })); }
    w.set_footer(foot.join(" · ").into());

    let hosts: Vec<HostRow> = report.map(|r| r.rows.iter().map(|row| {
        let note = if row.ok { if row.note.starts_with("kept;") { row.note.clone() } else { String::new() } } else if row.note.is_empty() { row.direct_problem.clone() } else { row.note.clone() };
        HostRow { name: row.name.clone().into(), note_warn: !row.ok, note: note.into(), route: row.route.text().into(), ip: row.ip.clone().unwrap_or_default().into(),
                  ms: row.ms.map(|m| format!("{m:.0} ms")).unwrap_or_default().into(), ok: row.ok }
    }).collect()).unwrap_or_default();
    w.set_hosts(model(hosts));
    w.set_bypass_detail(report.map(|r| {
        let b = &r.bypass;
        if b.hosts.is_empty() && b.error.is_none() { "The DPI bypass isn't needed right now.".to_string() } else {
            format!("DPI bypass: {}{}{}", if b.running { "on" } else { "off" }, b.strategy_name.as_ref().map(|n| format!(", strategy \"{n}\"")).unwrap_or_default(),
                    b.error.as_ref().map(|e| format!(". Problem: {e}")).unwrap_or_default())
        }
    }).unwrap_or_default().into());

    w.set_diag_running(g.diag_running);
    w.set_diag_done(g.checks.is_some());
    w.set_copy_label(if g.copied { "Copied" } else { "Copy report" }.into());
    w.set_checks(model(g.checks.iter().flatten().map(|c| CheckRow {
        title: c.title.clone().into(), detail: c.detail.clone().into(), level: level_int(c.level),
        fix: c.fix.clone().unwrap_or_default().into(), fix_label: c.fix_label.clone().unwrap_or_default().into(),
    }).collect()));
    w.set_log_text(if g.log.is_empty() { "The log is empty.".into() } else { g.log.iter().rev().cloned().collect::<Vec<_>>().join("\n").into() });

    if let Some(st) = status {
        w.set_bypass_on(st.settings.bypass_enabled);
        w.set_autorestart(st.settings.auto_restart_steam);
    }
    let b = report.map(|r| r.bypass.clone()).unwrap_or_default();
    w.set_strategy_text(match &b.strategy_name { Some(n) => format!("Current strategy: {n}"), None => "No strategy chosen yet (chosen automatically when a Steam host needs the bypass).".into() }.into());
    w.set_scores_text(if b.scores.is_empty() { String::new() } else {
        "Last test (checks passed):\n".to_string() + &b.scores.iter().map(|(id, sc)| format!("  {:<42} {sc}", crate::bypass::find(Some(id)).map(|s| s.name).unwrap_or(id))).collect::<Vec<_>>().join("\n")
    }.into());
}

/// Installed for real, or told to act as if (UI tests against `--service-test`).
fn installed() -> bool { std::env::var("STEAMPIN_ASSUME_INSTALLED").is_ok() || crate::installer::is_installed() }
