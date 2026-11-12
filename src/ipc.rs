//! Messages between the window/tray (run as the user) and the service (runs as SYSTEM),
//! over a local named pipe. Any signed-in user may ask for status or a check; the only text a command
//! takes is a list of site names, each validated as a host name before use.

use crate::diag::DiagCheck;
use crate::engine::RunReport;
use crate::state::{Settings, Time};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

pub const PIPE: &str = r"\\.\pipe\RustyDPI.v4";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Request { pub cmd: String, pub flag: Option<bool>, pub sites: Option<Vec<String>> }

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Response {
    pub ok: bool,
    pub error: Option<String>,
    pub status: Option<ServiceStatus>,
    pub lines: Option<Vec<String>>,
    pub checks: Option<Vec<DiagCheck>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServiceStatus {
    pub version: String,
    pub busy: bool,
    pub activity: Option<String>,
    pub next_run: Option<Time>,
    pub last_hosts_change: Option<Time>,
    pub report: Option<RunReport>,
    pub settings: Settings,
    pub update: crate::update::UpdateInfo,
}

/// Sends one request and waits up to `timeout` for the answer. None when the service isn't there.
pub fn send(cmd: &str, flag: Option<bool>, timeout: Duration) -> Option<Response> {
    send_request(Request { cmd: cmd.into(), flag, sites: None }, timeout)
}

pub fn send_request(req: Request, timeout: Duration) -> Option<Response> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = (|| -> Option<Response> {
            let mut f = None;
            for _ in 0..20 {
                match std::fs::OpenOptions::new().read(true).write(true).open(PIPE) {
                    Ok(p) => { f = Some(p); break; }
                    Err(e) if e.raw_os_error() == Some(231) => std::thread::sleep(Duration::from_millis(100)), // all pipe instances busy
                    Err(_) => return None,
                }
            }
            let mut f = f?;
            let mut line = serde_json::to_string(&req).ok()?;
            line.push('\n');
            f.write_all(line.as_bytes()).ok()?;
            let mut s = String::new();
            BufReader::new(f.take(8 * 1024 * 1024)).read_line(&mut s).ok()?;
            serde_json::from_str(&s).ok()
        })();
        let _ = tx.send(r);
    });
    rx.recv_timeout(timeout).ok().flatten()
}

/// The pipe server. `handle` answers each request; runs until `stop` is set.
pub fn serve(stop: &std::sync::atomic::AtomicBool, handle: &(dyn Fn(Request) -> Response + Sync)) {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::Pipes::*;

    // SYSTEM and admins: full; signed-in users: read/write; network logons: denied.
    let sddl = crate::win::wide("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)(D;;GA;;;NU)");
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) };
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
    let name = crate::win::wide(PIPE);
    std::thread::scope(|s| {
        while !stop.load(Ordering::SeqCst) {
            let h = unsafe {
                CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                 PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, &sa)
            };
            if h == INVALID_HANDLE_VALUE { std::thread::sleep(Duration::from_secs(1)); continue; }
            let connected = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if !connected || stop.load(Ordering::SeqCst) { unsafe { CloseHandle(h) }; continue; }
            let hv = h as isize;
            s.spawn(move || {
                use std::os::windows::io::FromRawHandle;
                let f = unsafe { std::fs::File::from_raw_handle(hv as _) };
                let mut reader = BufReader::new((&f).take(16 * 1024));
                let mut line = String::new();
                let resp = match reader.read_line(&mut line) {
                    Ok(_) => match serde_json::from_str::<Request>(&line) {
                        Ok(req) => handle(req),
                        Err(_) => Response { ok: false, error: Some("bad request".into()), ..Default::default() },
                    },
                    Err(_) => return,
                };
                if let Ok(mut out) = serde_json::to_string(&resp) {
                    out.push('\n');
                    let _ = (&f).write_all(out.as_bytes());
                    unsafe { FlushFileBuffers(hv as _); DisconnectNamedPipe(hv as _); }
                }
            });
        }
    });
    if !sd.is_null() { unsafe { LocalFree(sd as _) }; }
}

/// Unblocks a server waiting in ConnectNamedPipe (used when the service stops).
pub fn poke() { let _ = std::fs::OpenOptions::new().read(true).write(true).open(PIPE); }
