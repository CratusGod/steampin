//! Small Windows helpers (code pages, file replace, elevation, processes, message boxes).

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Globalization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> { s.as_ref().encode_wide().chain(Some(0)).collect() }

#[allow(dead_code)]
pub fn ansi_code_page() -> u32 { unsafe { GetACP() } }

pub fn ansi_to_string(b: &[u8]) -> String {
    if b.is_empty() { return String::new(); }
    unsafe {
        let n = MultiByteToWideChar(CP_ACP, 0, b.as_ptr(), b.len() as i32, std::ptr::null_mut(), 0);
        let mut w = vec![0u16; n.max(0) as usize];
        MultiByteToWideChar(CP_ACP, 0, b.as_ptr(), b.len() as i32, w.as_mut_ptr(), n);
        String::from_utf16_lossy(&w)
    }
}

pub fn string_to_ansi(s: &str) -> Vec<u8> {
    let w: Vec<u16> = s.encode_utf16().collect();
    if w.is_empty() { return vec![]; }
    unsafe {
        let n = WideCharToMultiByte(CP_ACP, 0, w.as_ptr(), w.len() as i32, std::ptr::null_mut(), 0, std::ptr::null(), std::ptr::null_mut());
        let mut b = vec![0u8; n.max(0) as usize];
        WideCharToMultiByte(CP_ACP, 0, w.as_ptr(), w.len() as i32, b.as_mut_ptr(), n, std::ptr::null(), std::ptr::null_mut());
        b
    }
}

/// Replaces `target` with `src` keeping the target's permissions (ReplaceFileW), or moves when there's no target yet.
pub fn replace_file(src: &Path, target: &Path) -> Result<(), String> {
    if !target.exists() { return std::fs::rename(src, target).map_err(|e| e.to_string()); }
    let (t, s) = (wide(target), wide(src));
    let ok = unsafe { ReplaceFileW(t.as_ptr(), s.as_ptr(), std::ptr::null(), REPLACEFILE_IGNORE_MERGE_ERRORS, std::ptr::null(), std::ptr::null()) };
    if ok != 0 { Ok(()) } else { Err(std::io::Error::last_os_error().to_string()) }
}

pub fn is_admin() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 { return false; }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(token, TokenElevation, &mut elev as *mut _ as *mut _, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len);
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

/// Runs this exe elevated (UAC prompt) with `args` and waits. Returns the exit code, or -1 if the prompt was declined.
pub fn run_elevated(args: &str) -> i32 {
    let exe = std::env::current_exe().unwrap_or_default();
    let (verb, file, params) = (wide("runas"), wide(&exe), wide(args));
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_HIDE;
        if ShellExecuteExW(&mut info) == 0 || info.hProcess.is_null() { return -1; }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1u32;
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        code as i32
    }
}

/// Starts `exe args` as the signed-in desktop user, not elevated: when this process is elevated it
/// borrows the token of the session's Explorer, so a tray started by the installer isn't an admin process.
pub fn start_as_desktop_user(exe: &Path, args: &str) -> bool {
    if !is_admin() {
        return Command::new(exe).args(args.split_whitespace()).spawn().is_ok();
    }
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    unsafe {
        let mut my_session = 0u32;
        ProcessIdToSessionId(GetCurrentProcessId(), &mut my_session);
        let Some(shell) = processes().into_iter().find(|p| {
            let mut s = u32::MAX;
            p.name.eq_ignore_ascii_case("explorer.exe") && ProcessIdToSessionId(p.pid, &mut s) != 0 && s == my_session
        }) else { return false };
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, shell.pid);
        if h.is_null() { return false; }
        let mut tok: HANDLE = std::ptr::null_mut();
        let ok = OpenProcessToken(h, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &mut tok);
        CloseHandle(h);
        if ok == 0 { return false; }
        let mut primary: HANDLE = std::ptr::null_mut();
        let ok = DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, std::ptr::null(), SecurityImpersonation, TokenPrimary, &mut primary);
        CloseHandle(tok);
        if ok == 0 { return false; }
        let mut cmd = wide(format!("\"{}\" {}", exe.display(), args));
        let dir = exe.parent().map(wide);
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let ok = CreateProcessWithTokenW(primary, 0, std::ptr::null(), cmd.as_mut_ptr(), CREATE_NO_WINDOW, std::ptr::null(),
            dir.as_ref().map(|d| d.as_ptr()).unwrap_or(std::ptr::null()), &si, &mut pi);
        CloseHandle(primary);
        if ok == 0 { return false; }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        true
    }
}

/// Runs a console program without a window; returns its exit code (or -1).
pub fn run_hidden(exe: &str, args: &[&str]) -> i32 {
    Command::new(exe).args(args).creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1)
}

pub fn run_hidden_output(exe: &str, args: &[&str]) -> Option<String> {
    Command::new(exe).args(args).creation_flags(CREATE_NO_WINDOW).output().ok().map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

#[derive(Clone, Debug)]
pub struct Proc { pub pid: u32, pub name: String, pub path: Option<String> }

/// All processes (name, pid and, where readable, the full exe path).
pub fn processes() -> Vec<Proc> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE { return out; }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            let name = String::from_utf16_lossy(&e.szExeFile[..len]);
            out.push(Proc { pid: e.th32ProcessID, path: process_path(e.th32ProcessID), name });
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
    }
    out
}

pub fn process_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() { return None; }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// When the process started, as local time.
pub fn process_start(pid: u32) -> Option<crate::state::Time> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() { return None; }
        let (mut c, mut x, mut k, mut u): (FILETIME, FILETIME, FILETIME, FILETIME) = std::mem::zeroed();
        let ok = GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u);
        CloseHandle(h);
        if ok == 0 { return None; }
        let ticks = ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64;
        let unix = (ticks / 10_000_000) as i64 - 11_644_473_600;
        chrono::DateTime::from_timestamp(unix, 0).map(|d| d.with_timezone(&chrono::Local).naive_local())
    }
}

pub fn kill(pid: u32) -> bool {
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid);
        if h.is_null() { return false; }
        let ok = TerminateProcess(h, 1) != 0;
        WaitForSingleObject(h, 5000);
        CloseHandle(h);
        ok
    }
}

pub fn message_box(text: &str, title: &str, flags: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    let (t, c) = (wide(text), wide(title));
    unsafe { MessageBoxW(std::ptr::null_mut(), t.as_ptr(), c.as_ptr(), flags) }
}

pub fn open_url(url: &str) {
    let (op, u) = (wide("open"), wide(url));
    unsafe { ShellExecuteW(std::ptr::null_mut(), op.as_ptr(), u.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) };
}

pub fn attach_console() {
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::System::Console::*;
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
        // Our output may be a caller's pipe. Child processes that outlive us (Steam) must not inherit it,
        // or the caller waits for them to exit.
        for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let h = GetStdHandle(id);
            if !h.is_null() && h != INVALID_HANDLE_VALUE_ { SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0); }
        }
    }
}
const INVALID_HANDLE_VALUE_: windows_sys::Win32::Foundation::HANDLE = -1isize as _;
