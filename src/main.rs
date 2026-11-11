#![cfg_attr(not(test), windows_subsystem = "windows")]
//! SteamPin 3 - keeps Steam working where it's blocked.
//!
//! One small exe with four roles:
//!   --service  the Windows service (LocalSystem) that does the work
//!   --tray     the tray icon (tiny, runs at logon)
//!   (no args)  the window, only while it's open
//!   --other    command line (see cli.rs)

mod bypass;
mod cli;
mod config;
mod diag;
mod dns;
mod engine;
mod hosts;
mod installer;
mod iputil;
mod ipc;
mod net;
mod paths;
mod pinlogic;
mod probe;
mod service;
mod state;
mod tray;
mod ui;
mod win;

#[cfg(test)]
mod engine_tests;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).map(|a| if a.starts_with("--") { a.to_ascii_lowercase() } else { a }).collect();
    let code = match args.first().map(String::as_str) {
        Some("--service") => { let _ = service::run_dispatcher(); 0 }
        Some("--tray") => tray::run(),
        None | Some("--window") => ui::run(),
        Some(_) => {
            win::attach_console();
            println!();
            cli::run(&args)
        }
    };
    std::process::exit(code);
}
