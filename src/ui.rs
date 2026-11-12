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
    import { ScrollView, LineEdit } from "std-widgets.slint";

    export struct GroupRow { name: string, ok: bool, summary: string }
    export struct SiteRow { name: string, label: string, status: string, ok: bool, checked: bool }
    export struct HostRow { name: string, note: string, note-warn: bool, route: string, ip: string, ms: string, ok: bool }
    export struct CheckRow { title: string, detail: string, level: int, fix: string, fix-label: string, help: string }

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
        title: "RustyDPI";
        preferred-width: 820px; preferred-height: 660px;
        min-width: 640px; min-height: 520px;
        background: Theme.bg;
        default-font-size: 14px;

        in-out property <int> page: 0;
        in property <string> network;
        in property <string> head-title: "Loading...";
        in property <string> head-detail;
        in property <int> head-level: 1;
        in property <string> sites-title: "Loading...";
        in property <string> sites-detail;
        in property <int> sites-level: 1;
        in property <string> working;
        in property <string> main-button: "Fix Steam";
        in property <string> sites-button: "Check now";
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
        in-out property <bool> steam-on: true;
        in property <bool> service-up;
        in property <bool> installed;
        in property <bool> busy;
        in property <string> strategy-text;
        in property <string> scores-text;
        in property <string> about-text;
        in property <[SiteRow]> sites;
        in-out property <bool> show-sites;
        in property <string> site-error;

        callback main-clicked;
        callback sites-clicked;
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
        callback set-steam(bool);
        callback retest;
        callback dismiss-message;
        callback add-site(string) -> bool;
        callback remove-site(string);
        callback show-sites-changed(bool);

        VerticalLayout {
            padding-left: 22px; padding-right: 22px; padding-top: 16px; padding-bottom: 12px;
            spacing: 10px;
            HorizontalLayout {
                Text { text: "RustyDPI"; font-size: 24px; font-weight: 700; color: Theme.text; }
                Text { text: root.network; color: Theme.muted; horizontal-alignment: right; vertical-alignment: center; }
            }
            HorizontalLayout {
                spacing: 4px; alignment: start;
                for name[i] in ["Sites", "Steam", "Diagnose", "Details", "Log", "Settings"] : Rectangle {
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
                    // Sites (main tab)
                    if root.page == 0 : VerticalLayout {
                        spacing: 10px;
                        Card {
                            HorizontalLayout {
                                spacing: 16px;
                                VerticalLayout { padding-top: 8px; alignment: start; Dot { c: Theme.level(root.sites-level); size: 18px; } }
                                VerticalLayout {
                                    spacing: 4px; horizontal-stretch: 1;
                                    Text { text: root.sites-title; font-size: 22px; font-weight: 600; color: Theme.text; wrap: word-wrap; }
                                    Muted { text: root.sites-detail; }
                                    if root.working != "" : Text { text: root.working; color: Theme.info; wrap: word-wrap; }
                                }
                                VerticalLayout { alignment: center; horizontal-stretch: 0; Btn { text: root.sites-button; primary: true; enabled: root.main-enabled; clicked => { root.sites-clicked(); } } }
                            }
                        }
                        Card {
                            Heading { text: "Unblock a website"; }
                            Muted { text: "Type the site's name, like discord.com. RustyDPI tests it, then pins a working server or finds a DPI bypass that gets through, and keeps it working."; }
                            HorizontalLayout {
                                spacing: 8px;
                                site := LineEdit { placeholder-text: "Site name, like discord.com"; enabled: root.service-up; horizontal-stretch: 1; accessible-label: "Site to unblock";
                                    accepted(t) => { if (root.add-site(t)) { self.text = ""; } } }
                                Btn { text: "Add"; enabled: root.service-up && site.text != ""; clicked => { if (root.add-site(site.text)) { site.text = ""; } } }
                            }
                            if root.site-error != "" : Text { text: root.site-error; color: Theme.warn; wrap: word-wrap; }
                            if root.sites.length == 0 : Muted { text: "No sites yet."; }
                            if root.sites.length > 0 : Toggle {
                                text: "Show site names (hidden again each time RustyDPI opens; the log and Copy report always hide them)";
                                checked <=> root.show-sites; toggled(v) => { root.show-sites-changed(v); }
                            }
                            for s in root.sites : HorizontalLayout {
                                spacing: 12px;
                                VerticalLayout { padding-top: 6px; alignment: start; Dot { c: !s.checked ? Theme.muted : s.ok ? Theme.good : Theme.bad; } }
                                VerticalLayout {
                                    horizontal-stretch: 1;
                                    Text { text: s.label; color: Theme.text; }
                                    Text { text: s.status; font-size: 12px; color: !s.checked || s.ok ? Theme.muted : Theme.warn; wrap: word-wrap; }
                                }
                                VerticalLayout { alignment: center; Btn { text: "Remove"; enabled: root.service-up; clicked => { root.remove-site(s.name); } } }
                            }
                        }
                        Rectangle {
                            background: #1A9FFF18; border-radius: 10px; border-width: 1px; border-color: #1A9FFF50;
                            HorizontalLayout {
                                padding: 14px; spacing: 12px;
                                VerticalLayout { padding-top: 4px; alignment: start; Dot { c: Theme.info; } }
                                VerticalLayout {
                                    spacing: 4px; horizontal-stretch: 1;
                                    Text { text: "Site still won't open? Restart your browser."; font-weight: 600; color: Theme.text; wrap: word-wrap; }
                                    Muted { text: "Browsers keep old connections and remembered addresses for a while, so a site can stay blocked even after RustyDPI has fixed it. Close every browser window (check the tray, too) and open it again. Also do this after you add a site or RustyDPI switches servers. If it still fails, turn off the browser's Secure DNS: Diagnose shows how."; }
                                }
                            }
                        }
                        Muted { text: root.footer; }
                    }
                    // Steam
                    if root.page == 1 : VerticalLayout {
                        spacing: 10px;
                        if root.steam-on : Card {
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
                        if root.steam-on && root.restart-needed : Card {
                            HorizontalLayout {
                                spacing: 12px;
                                Text { text: "RustyDPI switched Steam to new servers. Restart Steam so it uses them."; color: Theme.warn; wrap: word-wrap; vertical-alignment: center; horizontal-stretch: 1; }
                                Btn { text: "Restart Steam"; clicked => { root.restart-steam(); } }
                            }
                        }
                        if root.steam-on : Card {
                            Heading { text: "Steam services"; }
                            if root.groups.length == 0 : Muted { text: root.groups-empty; }
                            for g in root.groups : HorizontalLayout {
                                spacing: 12px;
                                VerticalLayout { padding-top: 5px; alignment: start; Dot { c: g.ok ? Theme.good : Theme.bad; } }
                                Text { text: g.name; font-weight: 600; color: Theme.text; width: 140px; }
                                Muted { text: g.summary; }
                            }
                        }
                        Card {
                            Heading { text: "Steam settings"; }
                            Toggle { text: "Keep Steam working (store, sign-in, community, images)"; checked <=> root.steam-on; enabled: root.service-up; toggled(v) => { root.set-steam(v); } }
                            if root.steam-on : Toggle { text: "Restart Steam automatically after RustyDPI switches servers (if a game is running, it waits until you close it)"; checked <=> root.autorestart; enabled: root.service-up; toggled(v) => { root.set-autorestart(v); } }
                            if !root.steam-on : Muted { text: "Steam is left alone: RustyDPI removes its Steam pins and doesn't check Steam."; }
                        }
                    }
                    // Diagnose
                    if root.page == 2 : Card {
                        HorizontalLayout {
                            spacing: 8px;
                            VerticalLayout { spacing: 2px; horizontal-stretch: 1; Heading { text: "Diagnose"; } Muted { text: "Checks everything that can stop your sites or Steam from working, with steps to fix each problem."; } }
                            VerticalLayout { alignment: center; horizontal-stretch: 0; Btn { text: root.copy-label; enabled: root.diag-done; clicked => { root.copy-report(); } } }
                            VerticalLayout { alignment: center; horizontal-stretch: 0; Btn { text: root.diag-running ? "Checking..." : "Run diagnosis"; primary: true; enabled: !root.diag-running; clicked => { root.run-diag(); } } }
                        }
                        if root.diag-running : Muted { text: "Running checks (up to 20 seconds)..."; }
                        for c in root.checks : HorizontalLayout {
                            spacing: 12px;
                            VerticalLayout { padding-top: 5px; alignment: start; Dot { c: Theme.level(c.level); } }
                            Text { text: c.title; font-weight: 600; color: Theme.text; width: 150px; wrap: word-wrap; }
                            VerticalLayout {
                                spacing: 6px; horizontal-stretch: 1;
                                Muted { text: c.detail; }
                                if c.help != "" : Rectangle {
                                    background: Theme.panel-hi; border-radius: 6px;
                                    VerticalLayout {
                                        padding: 10px; spacing: 4px;
                                        Text { text: "How to fix"; font-size: 12px; font-weight: 600; color: Theme.info; }
                                        Text { text: c.help; font-size: 13px; color: Theme.text; wrap: word-wrap; }
                                    }
                                }
                            }
                            if c.fix != "" : VerticalLayout { alignment: start; horizontal-stretch: 0; Btn { text: c.fix-label; clicked => { root.check-fix(c.fix); } } }
                        }
                    }
                    // Details
                    if root.page == 3 : Card {
                        Heading { text: "Every server RustyDPI checks"; }
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
                    if root.page == 4 : Card {
                        HorizontalLayout { alignment: start; Btn { text: "Open data folder"; clicked => { root.open-data(); } } }
                        Text { text: root.log-text; font-family: "Consolas"; font-size: 12px; color: Theme.text; wrap: word-wrap; }
                    }
                    // Settings
                    if root.page == 5 : VerticalLayout {
                        spacing: 10px;
                        Card {
                            Heading { text: "DPI bypass"; }
                            Muted { text: "For sites that can't be pinned to a working server, RustyDPI runs zapret's winws on those site names only (ports 80 and 443). Games and other apps aren't touched."; }
                            Toggle { text: "Use the DPI bypass when needed"; checked <=> root.bypass-on; enabled: root.service-up; toggled(v) => { root.set-bypass(v); } }
                            Text { text: root.strategy-text; color: Theme.text; wrap: word-wrap; }
                            HorizontalLayout { alignment: start; Btn { text: "Find the best strategy again"; enabled: root.service-up && !root.busy; clicked => { root.retest(); } } }
                            if root.scores-text != "" : Text { text: root.scores-text; font-family: "Consolas"; font-size: 12px; color: Theme.muted; }
                        }
                        Card {
                            Heading { text: "About"; }
                            Muted { text: root.about-text; }
                            HorizontalLayout {
                                spacing: 8px; alignment: start;
                                Btn { text: "Project page"; clicked => { root.open-project(); } }
                                Btn { text: "Open data folder"; clicked => { root.open-data(); } }
                                Btn { text: "Uninstall RustyDPI"; enabled: root.installed; clicked => { root.uninstall(); } }
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
    site_error: Option<String>,
}

type S = Arc<Mutex<Shared>>;

pub fn run() -> i32 {
    unsafe {
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
        use windows_sys::Win32::UI::WindowsAndMessaging::*;
        let m = windows_sys::Win32::System::Threading::CreateMutexW(std::ptr::null(), 1, crate::win::wide("Local\\RustyDPI.Window").as_ptr());
        if m.is_null() || GetLastError() == ERROR_ALREADY_EXISTS {
            let h = FindWindowW(std::ptr::null(), crate::win::wide("RustyDPI").as_ptr());
            if !h.is_null() { ShowWindow(h, SW_RESTORE); SetForegroundWindow(h); }
            return 0;
        }
    }
    let Ok(w) = MainWindow::new() else {
        crate::win::message_box("RustyDPI couldn't open its window. RustyDPI itself keeps working in the background.", "RustyDPI", 0x30);
        return 1;
    };
    let s: S = Arc::new(Mutex::new(Shared::default()));
    w.set_about_text(format!("RustyDPI {} · MIT licence · DPI bypass by zapret (MIT) and WinDivert (LGPL) · UI by Slint.\nData folder: {}",
        crate::engine::VERSION, crate::paths::Paths::default_paths().data_dir.display()).into());
    wire(&w, &s);
    if let Some(p) = std::env::var("RUSTYDPI_PAGE").ok().and_then(|p| p.parse::<i32>().ok()) { w.set_page(p); w.invoke_nav(p); }

    // Poll the service every 2 s on a background thread; the UI is refreshed on its own thread.
    let (weak, s2) = (w.as_weak(), s.clone());
    std::thread::spawn(move || loop {
        let demo = std::env::var("RUSTYDPI_DEMO").ok();
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
            let h = windows_sys::Win32::UI::WindowsAndMessaging::FindWindowW(std::ptr::null(), crate::win::wide("RustyDPI").as_ptr());
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
        if p == 2 && s.lock().unwrap().checks.is_none() { run_diagnosis(&w, s); }
        if p == 4 {
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
            let mut t = format!("RustyDPI {} diagnosis, {}\n", crate::engine::VERSION, chrono::Local::now().format("%Y-%m-%d %H:%M"));
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
    on!(on_open_project, |_w, _s| crate::win::open_url("https://github.com/CratusGod/rustydpi"));
    on!(on_set_bypass, |w, s, v: bool| send(&w, s, "bypass", Some(v)));
    on!(on_set_autorestart, |w, s, v: bool| send(&w, s, "autorestart", Some(v)));
    on!(on_set_steam, |w, s, v: bool| send(&w, s, "steam", Some(v)));
    on!(on_sites_clicked, |w, _s| w.invoke_main_clicked());
    on!(on_retest, |w, s| { send(&w, s, "retest", None); w.set_page(0); });
    on!(on_dismiss_message, |w, s| { s.lock().unwrap().message = None; render(&w, s); });
    on!(on_show_sites_changed, |w, s, _v: bool| render(&w, s));
    {
        let (weak, s) = (ww.clone(), s.clone());
        w.on_add_site(move |text| {
            let Some(w) = weak.upgrade() else { return false };
            let current = s.lock().unwrap().status.as_ref().map(|x| x.settings.extra_sites.clone()).unwrap_or_default();
            let err = match crate::config::clean_site(&text) {
                None => Some(format!("\"{}\" isn't a site name. Type just the name, like discord.com.", text.trim())),
                Some(site) if current.contains(&site) => Some(format!("{site} is already in the list.")),
                Some(_) if current.len() >= crate::config::MAX_SITES => Some(format!("You can add up to {} sites.", crate::config::MAX_SITES)),
                Some(site) => { let mut l = current; l.push(site.clone()); set_sites(&w, &s, l, "add-site", site); None }
            };
            let ok = err.is_none();
            s.lock().unwrap().site_error = err;
            render(&w, &s);
            ok
        });
    }
    on!(on_remove_site, |w, s, site: SharedString| {
        let mut l = s.lock().unwrap().status.as_ref().map(|x| x.settings.extra_sites.clone()).unwrap_or_default();
        l.retain(|x| x.as_str() != site.as_str());
        s.lock().unwrap().site_error = None;
        set_sites(&w, s, l, "remove-site", site.to_string());
    });
    on!(on_uninstall, |w, s| {
        if crate::win::message_box("Remove RustyDPI? Steam goes back to how it was before (blocked, if your network blocks it).", "RustyDPI", 0x31) == 1 {
            spawn(&w, s, "Uninstalling... accept the Windows prompt", |_| {
                if crate::win::run_elevated("--uninstall --quiet") == 0 { let _ = slint::invoke_from_event_loop(|| { let _ = slint::quit_event_loop(); }); }
            });
        }
    });
}

/// Shows the new list at once and sends the one change to the service (the next poll confirms it).
fn set_sites(w: &MainWindow, s: &S, list: Vec<String>, cmd: &'static str, site: String) {
    if let Some(st) = s.lock().unwrap().status.as_mut() { st.settings.extra_sites = list; }
    spawn(w, s, "", move |s| {
        let r = crate::ipc::send_request(crate::ipc::Request { cmd: cmd.into(), flag: None, sites: Some(vec![site]) }, Duration::from_secs(5));
        if let Some(st) = r.and_then(|r| r.status) { s.lock().unwrap().status = Some(st); }
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
        let dc = |id: &str, title: &str, detail: &str, label: &str| DiagCheck { id: id.into(), title: title.into(), level: Level::Fail, detail: detail.into(), fix: Some(fixes::INSTALL.into()), fix_label: Some(label.into()),
            help: format!("Click {label} and accept the Windows prompt. If it keeps happening, restart the PC.") };
        if !installed() { checks.push(dc("install", "RustyDPI", "Not installed.", "Install")); }
        else {
            match crate::ipc::send("diagnose", None, Duration::from_secs(60)) {
                Some(r) => checks.extend(r.checks.unwrap_or_default()),
                None => checks.push(dc("service", "RustyDPI service", "Not running or not answering.", "Repair install")),
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
            fixes::HOSTS_SEEN => ipc("hosts-seen", None),
            fixes::BYPASS_ON => ipc("bypass", Some(true)),
            fixes::RESTART_STEAM => { if crate::diag::steam::confirm_if_game() { if let Err(e) = crate::diag::steam::restart() { s.lock().unwrap().message = Some(e); } } }
            fixes::INSTALL => { crate::win::run_elevated("--install"); }
            fixes::REPAIR => { crate::win::run_elevated("--repair"); ipc("fix", None); }
            fixes::HOSTS_READONLY => { crate::win::run_elevated("--hosts-writable"); ipc("fix", None); }
            fixes::STOP_OTHER => {
                if crate::win::message_box("Close the other DPI-bypass tools now (for example CDPI UI)? They'll start again at your next sign-in unless you uninstall them.", "RustyDPI", 0x21) == 1 {
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

/// The common states (loading, not installed, service down, checking, offline), or None when a report is ready.
fn base_head(g: &Shared, what: &str, button: &str) -> Option<Head> {
    let h = |t: &str, d: &str, l| Some(Head { title: t.into(), detail: d.into(), level: l });
    if !g.polled { return h("Loading...", "", Level::Info); }
    if !g.installed { return h("RustyDPI isn't installed yet", "Install it to unblock websites and keep Steam working. It runs quietly in the background.", Level::Info); }
    if !g.service_up { return h("The RustyDPI service isn't running", &format!("Click {button} to start it again."), Level::Fail); }
    let s = g.status.as_ref().unwrap();
    if s.busy { return h(s.activity.as_deref().unwrap_or(what), if s.report.is_none() { "The first check takes about a minute." } else { "This takes up to a minute." }, Level::Info); }
    let Some(r) = s.report.as_ref() else { return h("Waiting for the first check", "It starts in a moment.", Level::Info) };
    if !r.online { return h("You're offline", "RustyDPI changes nothing until you're back online.", Level::Warn); }
    None
}

/// Headline of the Steam tab: Steam's own hosts only.
fn headline(g: &Shared) -> Head {
    if let Some(h) = base_head(g, "Checking Steam", "Fix Steam") { return h; }
    let r = g.status.as_ref().unwrap().report.as_ref().unwrap();
    let steam: Vec<&TargetRow> = r.rows.iter().filter(|x| x.group != crate::config::USER_GROUP).collect();
    if steam.is_empty() { return Head { title: "Steam isn't being checked".into(), detail: "Turn on Keep Steam working below.".into(), level: Level::Info }; }
    let bad: Vec<&&TargetRow> = steam.iter().filter(|x| !x.ok).collect();
    if bad.is_empty() {
        let d = if r.blocked { format!("Steam is blocked on your network; RustyDPI is working around it{}.", r.network.as_deref().map(|n| format!(" ({})", short_isp(n))).unwrap_or_default()) }
                else if steam.iter().any(|x| x.route == Route::Pinned) { "Nothing is blocked right now; RustyDPI keeps its pinned servers ready in case that changes.".into() }
                else { "Nothing is blocked on this network.".into() };
        return Head { title: "Steam works".into(), detail: d, level: Level::Ok };
    }
    let mut groups: Vec<&str> = Vec::new();
    for b in &bad { if !groups.contains(&b.group.as_str()) { groups.push(&b.group); } }
    Head { title: format!("Steam {} not working", groups.join(", ")), detail: "Click Fix Steam to check everything again, or open Diagnose to see why.".into(), level: Level::Fail }
}

/// Headline of the Sites tab: the user's sites only.
fn sites_headline(g: &Shared, show: bool) -> Head {
    if let Some(h) = base_head(g, "Checking your sites", "Check now") { return h; }
    let st = g.status.as_ref().unwrap();
    let r = st.report.as_ref().unwrap();
    // By name, not group: a site that's also one of Steam's hosts is checked once, as Steam's.
    let rows: Vec<&TargetRow> = r.rows.iter().filter(|x| st.settings.extra_sites.contains(&x.name)).collect();
    if st.settings.extra_sites.is_empty() { return Head { title: "Add a website to unblock".into(), detail: "Type its name below. RustyDPI finds a way through and keeps it working.".into(), level: Level::Info }; }
    if rows.len() < st.settings.extra_sites.len() { return Head { title: "Checking your sites".into(), detail: "A new site is checked within a minute.".into(), level: Level::Info }; }
    let bad: Vec<String> = rows.iter().filter(|x| !x.ok).map(|x| site_label(&x.name, show)).collect();
    if bad.is_empty() {
        let n = rows.len();
        return Head { title: if n == 1 { "Your site works".into() } else { format!("All {n} sites work") }, level: Level::Ok,
            detail: format!("{} unblocked by RustyDPI, {} open normally.", rows.iter().filter(|x| x.route != Route::Direct).count(), rows.iter().filter(|x| x.route == Route::Direct).count()) };
    }
    Head { title: format!("{} of {} {} not working", bad.len(), rows.len(), if rows.len() == 1 { "site" } else { "sites" }), level: Level::Fail,
        detail: format!("{}. Click Check now to try again, or open Diagnose for steps.", bad.join(", ")) }
}

/// One line under each site: how it's reached, or why it isn't.
fn site_status(r: Option<&TargetRow>) -> (String, bool, bool) {
    match r {
        None => ("Not checked yet: it's checked within a minute.".into(), false, false),
        Some(x) if x.ok => (format!("{}{}", explain(x), x.ms.map(|m| format!(" · {m:.0} ms")).unwrap_or_default()), true, true),
        Some(x) => (format!("Not working: {}", if x.note.is_empty() { x.direct_problem.as_str() } else { x.note.as_str() }), false, true),
    }
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
        Route::Relay => "unblocked by the driverless bypass",
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

/// A user-added site as shown in the window: masked unless "Show site names" is on.
fn site_label(name: &str, show: bool) -> String { if show { name.to_string() } else { crate::config::mask_site(name) } }

fn render(w: &MainWindow, s: &S) {
    let g = s.lock().unwrap();
    let show = w.get_show_sites();
    let head = headline(&g);
    let sh = sites_headline(&g, show);
    w.set_sites_title(sh.title.into());
    w.set_sites_detail(sh.detail.into());
    w.set_sites_level(level_int(sh.level));
    let status = g.status.as_ref();
    let report: Option<&RunReport> = status.and_then(|s| s.report.as_ref());
    let busy = status.map(|s| s.busy).unwrap_or(false);
    w.set_head_title(head.title.into());
    w.set_head_detail(head.detail.into());
    w.set_head_level(level_int(head.level));
    w.set_working(g.working.clone().unwrap_or_default().into());
    w.set_main_button(if !g.installed { "Install" } else if busy { "Checking..." } else { "Fix Steam" }.into());
    w.set_sites_button(if !g.installed { "Install" } else if busy { "Checking..." } else { "Check now" }.into());
    w.set_main_enabled(g.polled && !busy && g.working.is_none());
    w.set_network(report.and_then(|r| r.network.as_deref()).map(short_isp).unwrap_or_default().into());
    w.set_message(g.message.clone().unwrap_or_default().into());
    w.set_site_error(g.site_error.clone().unwrap_or_default().into());
    w.set_installed(g.installed);
    w.set_service_up(g.service_up);
    w.set_busy(busy);
    w.set_restart_needed(status.and_then(|s| s.last_hosts_change).zip(crate::diag::steam::start_time()).map(|(c, st)| st < c).unwrap_or(false));

    let groups: Vec<GroupRow> = match report {
        Some(r) if r.online => r.groups().into_iter().filter(|(name, _)| name != crate::config::USER_GROUP).map(|(name, ok)| {
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
        let hide = row.group == crate::config::USER_GROUP && !show;
        HostRow { name: if hide { crate::config::mask_site(&row.name) } else { row.name.clone() }.into(), note_warn: !row.ok, note: note.into(), route: row.route.text().into(),
                  ip: if hide { String::new() } else { row.ip.clone().unwrap_or_default() }.into(),
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
        fix: c.fix.clone().unwrap_or_default().into(), fix_label: c.fix_label.clone().unwrap_or_default().into(), help: c.help.clone().into(),
    }).collect()));
    w.set_log_text(if g.log.is_empty() { "The log is empty.".into() } else { g.log.iter().rev().cloned().collect::<Vec<_>>().join("\n").into() });

    if let Some(st) = status {
        w.set_bypass_on(st.settings.bypass_enabled);
        w.set_autorestart(st.settings.auto_restart_steam);
        w.set_steam_on(st.settings.steam_enabled);
        w.set_sites(model(st.settings.extra_sites.iter().map(|x| {
            let (status, ok, checked) = site_status(report.and_then(|r| r.rows.iter().find(|row| &row.name == x)));
            SiteRow { name: x.as_str().into(), label: site_label(x, show).into(), status: status.into(), ok, checked }
        }).collect()));
    }
    let b = report.map(|r| r.bypass.clone()).unwrap_or_default();
    w.set_strategy_text(match &b.strategy_name { Some(n) => format!("Current strategy: {n}"), None => "No strategy chosen yet (chosen automatically when a site needs the bypass).".into() }.into());
    w.set_scores_text(if b.scores.is_empty() { String::new() } else {
        "Last test (checks passed):\n".to_string() + &b.scores.iter().map(|(id, sc)| format!("  {:<42} {sc}", crate::bypass::find(Some(id)).map(|s| s.name).unwrap_or(id))).collect::<Vec<_>>().join("\n")
    }.into());
}

/// Installed for real, or told to act as if (UI tests against `--service-test`).
fn installed() -> bool { std::env::var("RUSTYDPI_ASSUME_INSTALLED").is_ok() || crate::installer::is_installed() }
