//! The tray icon: plain Win32 (no UI framework) so it costs almost nothing while it sits there.
//! Opens the window, starts a fix, restarts Steam, and tells you when something needs you.

use crate::diag::steam;
use crate::win::wide;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WM_TRAY: u32 = WM_APP + 1;
const ID_OPEN: usize = 1;
const ID_FIX: usize = 2;
const ID_RESTART: usize = 3;
const ID_EXIT: usize = 4;

static HWND_: AtomicIsize = AtomicIsize::new(0);
static TASKBAR_CREATED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn hwnd() -> HWND { HWND_.load(Ordering::SeqCst) as HWND }

unsafe fn icon() -> HICON {
    let h = LoadImageW(GetModuleHandleW(std::ptr::null()), 1 as _, IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    if h.is_null() { LoadIconW(std::ptr::null_mut(), IDI_APPLICATION) } else { h as HICON }
}

fn copy_into(dst: &mut [u16], s: &str) {
    let w: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
    dst[..w.len()].copy_from_slice(&w);
    dst[w.len()] = 0;
}

unsafe fn nid() -> NOTIFYICONDATAW {
    let mut n: NOTIFYICONDATAW = std::mem::zeroed();
    n.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    n.hWnd = hwnd();
    n.uID = 1;
    n
}

unsafe fn add_icon() {
    let mut n = nid();
    n.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    n.uCallbackMessage = WM_TRAY;
    n.hIcon = icon();
    copy_into(&mut n.szTip, "RustyDPI");
    Shell_NotifyIconW(NIM_ADD, &n);
}

pub fn set_tip(text: &str) {
    unsafe {
        let mut n = nid();
        n.uFlags = NIF_TIP;
        copy_into(&mut n.szTip, text);
        Shell_NotifyIconW(NIM_MODIFY, &n);
    }
}

pub fn balloon(title: &str, text: &str, warn: bool) {
    unsafe {
        let mut n = nid();
        n.uFlags = NIF_INFO;
        copy_into(&mut n.szInfoTitle, title);
        copy_into(&mut n.szInfo, text);
        n.dwInfoFlags = if warn { NIIF_WARNING } else { NIIF_INFO };
        Shell_NotifyIconW(NIM_MODIFY, &n);
    }
}

pub fn open_window() {
    if let Ok(exe) = std::env::current_exe() { let _ = std::process::Command::new(exe).arg("--window").spawn(); }
}

fn restart_steam() {
    std::thread::spawn(|| { if let Err(e) = steam::restart() { balloon("Restart Steam", &e, true); } });
}

/// From the menu: you asked for it, but a game would be closed too, so ask first.
fn restart_steam_from_menu() {
    if steam::confirm_if_game() { restart_steam(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn t(m: u32) -> Option<crate::state::Time> { Some(chrono::NaiveDate::from_ymd_opt(2026, 11, 11).unwrap().and_hms_opt(12, m, 0).unwrap()) }

    #[test]
    fn steam_restart_decisions() {
        use SteamAction::*;
        // Steam started after the change, or not running, or no change: nothing.
        assert_eq!(steam_action(t(10), t(20), None, true, false, false), Nothing);
        assert_eq!(steam_action(t(10), None, None, true, false, false), Nothing);
        assert_eq!(steam_action(None, t(5), None, true, false, false), Nothing);
        // Auto-restart on, no game: restart.
        assert_eq!(steam_action(t(10), t(5), None, true, false, false), Restart);
        // Already handled this change: nothing.
        assert_eq!(steam_action(t(10), t(5), t(10), true, false, false), Nothing);
        // A newer change after the handled one: restart again.
        assert_eq!(steam_action(t(30), t(5), t(10), true, false, false), Restart);
        // Auto-restart off: tell the user.
        assert_eq!(steam_action(t(10), t(5), None, false, false, false), AskUser);
        assert_eq!(steam_action(t(10), t(5), None, false, true, false), AskUser);
        // In a game: wait (one notice), keep waiting quietly, restart when the game closes.
        assert_eq!(steam_action(t(10), t(5), None, true, true, false), WaitForGame);
        assert_eq!(steam_action(t(10), t(5), None, true, true, true), Nothing);
        assert_eq!(steam_action(t(10), t(5), None, true, false, true), Restart);
    }
}

unsafe extern "system" fn wndproc(h: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == TASKBAR_CREATED.load(Ordering::SeqCst) && msg != 0 { add_icon(); return 0; }
    match msg {
        WM_TRAY => {
            match lp as u32 {
                WM_LBUTTONDBLCLK | NIN_BALLOONUSERCLICK => open_window(),
                WM_RBUTTONUP | WM_CONTEXTMENU => {
                    let m = CreatePopupMenu();
                    for (id, text) in [(ID_OPEN, "Open RustyDPI"), (ID_FIX, "Fix Steam now"), (ID_RESTART, "Restart Steam")] {
                        AppendMenuW(m, MF_STRING, id, wide(text).as_ptr());
                    }
                    AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
                    AppendMenuW(m, MF_STRING, ID_EXIT, wide("Hide tray icon (RustyDPI keeps working)").as_ptr());
                    SetMenuDefaultItem(m, ID_OPEN as u32, 0);
                    let mut pt = POINT { x: 0, y: 0 };
                    GetCursorPos(&mut pt);
                    SetForegroundWindow(h);
                    let cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, std::ptr::null());
                    DestroyMenu(m);
                    match cmd as usize {
                        ID_OPEN => open_window(),
                        ID_FIX => { std::thread::spawn(|| { crate::ipc::send("fix", None, Duration::from_secs(5)); }); }
                        ID_RESTART => { std::thread::spawn(restart_steam_from_menu); }
                        ID_EXIT => { let n = nid(); Shell_NotifyIconW(NIM_DELETE, &n); PostQuitMessage(0); }
                        _ => {}
                    }
                }
                _ => {}
            }
            0
        }
        WM_DESTROY => { PostQuitMessage(0); 0 }
        _ => DefWindowProcW(h, msg, wp, lp),
    }
}

#[derive(Debug, PartialEq)]
pub enum SteamAction { Nothing, Restart, AskUser, WaitForGame }

/// What to do about Steam after RustyDPI changed the hosts file. `handled` is the change already dealt with;
/// `waiting` is true while a restart is held back for a game. Steam restarts only when no game is running:
/// with a game open it waits and restarts as soon as the game closes.
pub fn steam_action(changed: Option<crate::state::Time>, started: Option<crate::state::Time>, handled: Option<crate::state::Time>,
                    auto: bool, game: bool, waiting: bool) -> SteamAction {
    let (Some(c), Some(s)) = (changed, started) else { return SteamAction::Nothing };
    if s >= c || handled == Some(c) { return SteamAction::Nothing; }
    if !auto { return SteamAction::AskUser; }
    if game { return if waiting { SteamAction::Nothing } else { SteamAction::WaitForGame }; }
    SteamAction::Restart
}

/// Watches the service every 30 s and speaks up only when you need to act.
fn watch() {
    let mut was_ok: Option<bool> = None;
    let mut notified: Option<crate::state::Time> = None;
    let mut waiting = false;
    loop {
        if let Some(s) = crate::ipc::send("status", None, Duration::from_secs(4)).and_then(|r| r.status) {
            if let Some(r) = s.report.as_ref().filter(|r| r.online && !s.busy) {
                let ok = r.rows.iter().all(|x| x.ok);
                set_tip(if ok { "RustyDPI - everything works" } else { "RustyDPI - something isn't working" });
                if was_ok == Some(true) && !ok { balloon("Something isn't working", "RustyDPI couldn't fix everything. Open RustyDPI to see what's wrong.", true); }
                was_ok = Some(ok);
            }
            // After RustyDPI changed the hosts file, Steam must restart to use the new servers.
            if s.settings.steam_enabled { match steam_action(s.last_hosts_change, steam::start_time(), notified, s.settings.auto_restart_steam, steam::game_running(), waiting) {
                SteamAction::Nothing => {}
                SteamAction::Restart => { notified = s.last_hosts_change; waiting = false; restart_steam(); }
                SteamAction::AskUser => { notified = s.last_hosts_change; balloon("Restart Steam", "RustyDPI switched Steam to new servers. Restart Steam to use them.", false); }
                SteamAction::WaitForGame => { waiting = true; balloon("Restart Steam", "RustyDPI switched Steam to new servers. Steam will restart when you close your game.", false); }
            } }
            if steam::start_time().is_none() { waiting = false; }
        } else {
            set_tip("RustyDPI - service not running");
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

pub fn run() -> i32 {
    unsafe {
        let name = wide("Local\\RustyDPI.Tray");
        let m = CreateMutexW(std::ptr::null(), 1, name.as_ptr());
        if m.is_null() || GetLastError() == ERROR_ALREADY_EXISTS { return 0; }
        TASKBAR_CREATED.store(RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()), Ordering::SeqCst);
        let class = wide("RustyDPITray");
        let wc = WNDCLASSW { lpfnWndProc: Some(wndproc), hInstance: GetModuleHandleW(std::ptr::null()), lpszClassName: class.as_ptr(), ..std::mem::zeroed() };
        RegisterClassW(&wc);
        let h = CreateWindowExW(0, class.as_ptr(), wide("RustyDPI tray").as_ptr(), 0, 0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), wc.hInstance, std::ptr::null());
        if h.is_null() { return 1; }
        HWND_.store(h as isize, Ordering::SeqCst);
        add_icon();
        std::thread::spawn(watch);
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let n = nid();
        Shell_NotifyIconW(NIM_DELETE, &n);
        0
    }
}
