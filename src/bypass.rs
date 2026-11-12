//! The DPI bypass for the sites that need it: zapret's winws, strategies, host lists, and the strategy test.

use crate::config::Target;
use crate::probe::{ProbeResult, Prober};
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub struct Strategy { pub id: &'static str, pub name: &'static str, pub tcp: &'static [&'static str] }

/// Tried in this order by the strategy test. `{tls}` is replaced by the fake TLS ClientHello file.
pub const STRATEGIES: &[Strategy] = &[
    Strategy { id: "split-disorder", name: "Split + disorder (known to work on FPT)", tcp: &["--dpi-desync=multidisorder", "--dpi-desync-split-pos=1,midsld"] },
    Strategy { id: "fake-disorder", name: "Fake + split + disorder", tcp: &["--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-repeats=11", "--dpi-desync-fooling=badseq", "--dpi-desync-fake-tls=0x00000000", "--dpi-desync-fake-tls=!", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com"] },
    Strategy { id: "split", name: "Split", tcp: &["--dpi-desync=multisplit", "--dpi-desync-split-pos=1,midsld"] },
    Strategy { id: "fake-split", name: "Fake + split (badseq)", tcp: &["--dpi-desync=fake,multisplit", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=1000", "--dpi-desync-fake-tls={tls}"] },
    Strategy { id: "seqovl", name: "Split with sequence overlap", tcp: &["--dpi-desync=multisplit", "--dpi-desync-split-seqovl=681", "--dpi-desync-split-pos=1", "--dpi-desync-split-seqovl-pattern={tls}"] },
    Strategy { id: "disorder-sni", name: "Disorder at several SNI positions", tcp: &["--dpi-desync=multidisorder", "--dpi-desync-split-pos=1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1"] },
    Strategy { id: "fakedsplit", name: "Fake + faked split", tcp: &["--dpi-desync=fake,fakedsplit", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fooling=badseq", "--dpi-desync-repeats=6", "--dpi-desync-fake-tls={tls}"] },
    Strategy { id: "fake-hostsplit", name: "Fake + host fake split", tcp: &["--dpi-desync=fake,hostfakesplit", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com", "--dpi-desync-hostfakesplit-mod=host=www.google.com,altorder=1", "--dpi-desync-fooling=badseq", "--dpi-desync-repeats=6"] },
    Strategy { id: "fake-md5sig", name: "Fake (md5sig) + split", tcp: &["--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fooling=md5sig", "--dpi-desync-repeats=6", "--dpi-desync-fake-tls={tls}"] },
    Strategy { id: "fake-datanoack", name: "Fake (datanoack) + disorder", tcp: &["--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=midsld", "--dpi-desync-fooling=datanoack", "--dpi-desync-repeats=6", "--dpi-desync-fake-tls={tls}"] },
];

pub fn find(id: Option<&str>) -> Option<&'static Strategy> { id.and_then(|id| STRATEGIES.iter().find(|s| s.id == id)) }

/// The zapret files RustyDPI ships (official v72.13 release) with their SHA-256.
pub const ZAPRET_FILES: &[(&str, &str, &[u8])] = &[
    ("winws.exe", "a14bff1df6234ea555d2e0c61b589f0707c0b12d6c9b7eeccda76012154996e8", include_bytes!("../vendor/zapret/winws.exe")),
    ("cygwin1.dll", "103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b", include_bytes!("../vendor/zapret/cygwin1.dll")),
    ("WinDivert.dll", "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2", include_bytes!("../vendor/zapret/WinDivert.dll")),
    ("WinDivert64.sys", "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2", include_bytes!("../vendor/zapret/WinDivert64.sys")),
    ("tls_clienthello_www_google_com.bin", "936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c", include_bytes!("../vendor/zapret/tls_clienthello_www_google_com.bin")),
    ("quic_initial_www_google_com.bin", "f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a", include_bytes!("../vendor/zapret/quic_initial_www_google_com.bin")),
    ("ZAPRET-LICENSE.txt", "", include_bytes!("../vendor/zapret/ZAPRET-LICENSE.txt")),
    ("WINDIVERT-LICENSE.txt", "", include_bytes!("../vendor/zapret/WINDIVERT-LICENSE.txt")),
];

#[derive(Clone, Debug)]
pub struct BypassFiles { pub zapret: PathBuf, pub lists: PathBuf }

impl BypassFiles {
    pub fn winws(&self) -> PathBuf { self.zapret.join("winws.exe") }
    pub fn fake_tls(&self) -> PathBuf { self.zapret.join("tls_clienthello_www_google_com.bin") }
    pub fn fake_quic(&self) -> PathBuf { self.zapret.join("quic_initial_www_google_com.bin") }
    pub fn host_list(&self) -> PathBuf { self.lists.join("bypass.txt") }
    pub fn exclude_list(&self) -> PathBuf { self.lists.join("exclude.txt") }
}

/// Files missing or not matching the official release.
pub fn bad_files(dir: &std::path::Path) -> Vec<&'static str> {
    use sha2::{Digest, Sha256};
    ZAPRET_FILES.iter().filter(|(_, h, _)| !h.is_empty()).filter(|(n, h, _)| {
        match std::fs::read(dir.join(n)) {
            Ok(b) => format!("{:x}", Sha256::digest(&b)) != *h,
            Err(_) => true,
        }
    }).map(|(n, _, _)| *n).collect()
}

/// Writes the zapret files into `dir` (install and repair).
pub fn extract(dir: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    for (n, _, bytes) in ZAPRET_FILES {
        let mut last = String::new();
        let mut ok = false;
        for _ in 0..5 {
            match std::fs::write(dir.join(n), bytes) { Ok(()) => { ok = true; break; } Err(e) => { last = e.to_string(); std::thread::sleep(std::time::Duration::from_secs(1)); } }
        }
        if !ok { return Err(format!("{n}: {last}")); }
    }
    Ok(())
}

/// RustyDPI's own "does it work without the bypass?" probes send their packets with this IP TTL
/// (Windows uses 128), and the WinDivert filter below lets them through untouched. So checks never
/// have to stop the bypass, and the user's sites stay reachable while RustyDPI tests.
pub const PROBE_TTL: u32 = 117;

/// The WinDivert filter winws builds for `--wf-tcp=80,443 --wf-udp=443` (zapret v72 `wf_make_filter`),
/// plus one clause that skips IPv4 packets with [`PROBE_TTL`]. winws adds its own prolog and the
/// filter that skips LAN addresses around it.
pub fn filter_part() -> String {
    format!(
        "(outbound and (ipv6 or ip.TTL != {PROBE_TTL}) and (!tcp or tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength>0) \
         and (((tcp.DstPort == 80) or (tcp.DstPort == 443)) or ((udp.DstPort == 443)))) \
         or (inbound and tcp and (tcp.Ack and tcp.Syn or tcp.Rst or tcp.Fin) and ((tcp.SrcPort == 80) or (tcp.SrcPort == 443)))"
    )
}

/// Only ports 80/443 (TCP) and 443 (UDP, QUIC) are diverted, and only connections whose host
/// name is in the list are touched, so games and other apps are never affected.
/// `overrides`: hosts that need a different strategy than `s` (host -> strategy id). Each gets its own
/// profile ahead of the main one; winws uses the first profile whose host list matches.
pub fn build_args(s: &Strategy, f: &BypassFiles, overrides: &BTreeMap<String, String>) -> Vec<String> {
    let hl = format!("--hostlist={}", f.host_list().display());
    let ex = format!("--hostlist-exclude={}", f.exclude_list().display());
    let tls = f.fake_tls().display().to_string();
    let tcp = |s: &Strategy| s.tcp.iter().map(|x| x.replace("{tls}", &tls)).collect::<Vec<_>>();
    let mut a: Vec<String> = vec![
        format!("--wf-raw-part={}", filter_part()),
        "--filter-udp=443".into(), hl.clone(), ex.clone(),
        "--dpi-desync=fake".into(), "--dpi-desync-repeats=6".into(), format!("--dpi-desync-fake-quic={}", f.fake_quic().display()),
    ];
    let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (h, id) in overrides { if id != s.id { groups.entry(id.as_str()).or_default().push(h.as_str()); } }
    for (id, hosts) in groups {
        let Some(o) = find(Some(id)) else { continue };
        a.extend(["--new".into(), "--filter-tcp=80,443".into(), format!("--hostlist-domains={}", hosts.join(","))]);
        a.extend(tcp(o));
    }
    a.extend(["--new".into(), "--filter-tcp=80,443".into(), hl, ex]);
    a.extend(tcp(s));
    a
}

/// Hosts the winning strategy fails (passes under half its rounds) but another strategy unblocks:
/// host -> that strategy. Everything else stays on the winner.
pub fn overrides(ranked: &[Score], hosts: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(best) = ranked.iter().find(|s| s.error.is_none() && s.pass > 0) else { return out };
    let got = |s: &Score, i: usize| s.per_host.get(i).copied().unwrap_or(0);
    for (i, h) in hosts.iter().enumerate() {
        let rounds = best.rounds.max(1);
        if got(best, i) * 2 > rounds { continue; }
        // Ranked order breaks ties, so a better-ranked strategy wins between equals.
        let alt = ranked.iter().filter(|s| s.error.is_none() && got(s, i) > got(best, i))
            .fold(None::<&Score>, |acc, s| match acc { Some(a) if got(a, i) >= got(s, i) => Some(a), _ => Some(s) });
        if let Some(alt) = alt { if got(alt, i) * 2 > alt.rounds.max(1) { out.insert(h.clone(), alt.id.to_string()); } }
    }
    out
}

/// Writes the two host lists; returns true when either file changed.
pub fn write_lists(f: &BypassFiles, include: &[String], exclude: &[String]) -> bool {
    let _ = std::fs::create_dir_all(&f.lists);
    let w = |path: PathBuf, items: &[String]| {
        let mut v: Vec<&String> = items.iter().collect();
        v.sort();
        v.dedup();
        let text = v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n") + "\n";
        if std::fs::read_to_string(&path).ok().as_deref() == Some(text.as_str()) { return false; }
        let _ = std::fs::write(&path, text);
        true
    };
    let a = w(f.host_list(), include);
    let b = w(f.exclude_list(), exclude);
    a || b
}

pub trait Runner: Sync {
    fn is_running(&self) -> bool;
    fn recent_output(&self) -> String;
    /// Starts winws; Err(message) when it can't.
    fn start(&self, args: &[String]) -> Result<(), String>;
    fn stop(&self);
    /// The arguments the running winws was started with (None: unknown or not running).
    fn current_args(&self) -> Option<Vec<String>> { None }
}

/// Runs winws.exe as a child process inside a kill-on-close job object, so it never outlives us.
pub struct WinwsRunner { files: BypassFiles, child: Mutex<Option<Child>>, out: Arc<Mutex<String>>, job: Mutex<isize>, args: Mutex<Vec<String>> }

impl WinwsRunner {
    pub fn new(files: BypassFiles) -> Self { WinwsRunner { files, child: Mutex::new(None), out: Arc::new(Mutex::new(String::new())), job: Mutex::new(0), args: Mutex::new(vec![]) } }

    fn assign_job(&self, child: &Child) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::*;
        unsafe {
            let mut job = self.job.lock().unwrap();
            if *job == 0 {
                let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if h.is_null() { return; }
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(h, JobObjectExtendedLimitInformation, &info as *const _ as *const _, std::mem::size_of_val(&info) as u32);
                *job = h as isize;
            }
            AssignProcessToJobObject(*job as _, child.as_raw_handle() as _);
        }
    }
}

impl Drop for WinwsRunner {
    fn drop(&mut self) {
        self.stop();
        let j = *self.job.lock().unwrap();
        if j != 0 { unsafe { windows_sys::Win32::Foundation::CloseHandle(j as _) }; }
    }
}

/// A stopped WinDivert driver entry (left by CDPI UI or another tool, or disabled) makes winws fail with
/// "The service cannot be started". Nothing needs a stopped entry: delete it and winws registers its own.
pub fn clear_stale_driver() {
    if crate::diag::windivert_driver_path().is_none() { return; }
    let running = crate::win::run_hidden_output("sc.exe", &["query", "WinDivert"]).map(|o| o.contains("RUNNING")).unwrap_or(true);
    if !running { crate::win::run_hidden("sc.exe", &["delete", "WinDivert"]); }
}

impl Runner for WinwsRunner {
    fn is_running(&self) -> bool {
        let mut c = self.child.lock().unwrap();
        matches!(c.as_mut().map(|c| c.try_wait()), Some(Ok(None)))
    }

    fn recent_output(&self) -> String { self.out.lock().unwrap().clone() }

    fn start(&self, args: &[String]) -> Result<(), String> {
        self.stop();
        for (n, h, _) in ZAPRET_FILES {
            if !h.is_empty() && !self.files.zapret.join(n).exists() { return Err(format!("{n} is missing (antivirus may have removed it).")); }
        }
        self.out.lock().unwrap().clear();
        clear_stale_driver();
        let mut child = Command::new(self.files.winws()).args(args).current_dir(&self.files.zapret)
            .creation_flags(crate::win::CREATE_NO_WINDOW).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().map_err(|e| format!("winws.exe could not start: {e}"))?;
        self.assign_job(&child);
        for pipe in [child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>), child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>)].into_iter().flatten() {
            let out = self.out.clone();
            std::thread::spawn(move || {
                let mut pipe = pipe;
                let mut buf = [0u8; 4096];
                while let Ok(n) = pipe.read(&mut buf) {
                    if n == 0 { break; }
                    let mut o = out.lock().unwrap();
                    o.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if o.len() > 16000 { let cut = o.len() - 8000; *o = o[o.ceil_char_boundary(cut)..].to_string(); }
                }
            });
        }
        // winws exits within a moment if WinDivert can't load or an option is wrong.
        for _ in 0..15 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if let Ok(Some(status)) = child.try_wait() {
                std::thread::sleep(std::time::Duration::from_millis(100));
                let out = self.recent_output();
                let last: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
                return Err(format!("winws.exe stopped at once ({status}): {}", last[last.len().saturating_sub(4)..].join(" | ")));
            }
        }
        *self.child.lock().unwrap() = Some(child);
        *self.args.lock().unwrap() = args.to_vec();
        Ok(())
    }

    fn current_args(&self) -> Option<Vec<String>> { self.is_running().then(|| self.args.lock().unwrap().clone()) }

    fn stop(&self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

trait CeilBoundary { fn ceil_char_boundary(&self, i: usize) -> usize; }
impl CeilBoundary for String {
    fn ceil_char_boundary(&self, mut i: usize) -> usize { while i < self.len() && !self.is_char_boundary(i) { i += 1; } i }
}

/// One strategy's test result. `per_host[i]`: rounds host i passed, out of `rounds`.
#[derive(Clone, Debug, Default)]
pub struct Score { pub id: &'static str, pub pass: u32, pub total: u32, pub ms: Option<f64>, pub error: Option<String>, pub per_host: Vec<u32>, pub rounds: u32 }

impl Score {
    pub fn summary(&self) -> String {
        self.error.clone().unwrap_or_else(|| format!("{}/{}{}", self.pass, self.total, self.ms.map(|m| format!(", {m} ms")).unwrap_or_default()))
    }
}

/// Latency differences smaller than this are noise: between such strategies, keep the one tested first
/// (the current strategy is tested first, then the list order, which starts with the known-good FPT one).
pub const TIE_MS: f64 = 15.0;

pub fn rank(s: Vec<Score>) -> Vec<Score> {
    let ratio = |x: &Score| if x.total == 0 { -1.0 } else { x.pass as f64 / x.total as f64 };
    let mut idx: Vec<(usize, Score)> = s.into_iter().enumerate().collect();
    idx.sort_by(|(_, a), (_, b)| ratio(b).total_cmp(&ratio(a)).then(a.ms.unwrap_or(f64::MAX).total_cmp(&b.ms.unwrap_or(f64::MAX))));
    if let Some((_, best)) = idx.first() {
        let (r, ms) = (ratio(best), best.ms.unwrap_or(f64::MAX));
        if r > 0.0 {
            if let Some(pick) = idx.iter().enumerate()
                .filter(|(_, (_, x))| ratio(x) == r && x.ms.unwrap_or(f64::MAX) <= ms + TIE_MS)
                .min_by_key(|(_, (orig, _))| *orig).map(|(pos, _)| pos) {
                let e = idx.remove(pick);
                idx.insert(0, e);
            }
        }
    }
    idx.into_iter().map(|(_, x)| x).collect()
}

/// Works like zapret's blockcheck, but only for the blocked sites: runs each strategy and checks them for real.
pub fn test_strategies(runner: &dyn Runner, prober: &dyn Prober, files: &BypassFiles, hosts: &[(Target, String)],
                       order: &[&'static Strategy], rounds: u32, settle_ms: u64, log: &dyn Fn(&str)) -> Vec<Score> {
    let mut scores = Vec::new();
    for s in order {
        if let Err(e) = runner.start(&build_args(s, files, &BTreeMap::new())) {
            log(&format!("strategy {}: {e}", s.id));
            scores.push(Score { id: s.id, error: Some(e), ..Default::default() });
            continue;
        }
        std::thread::sleep(std::time::Duration::from_millis(settle_ms));
        let mut results: Vec<ProbeResult> = Vec::new();
        let mut per_host = vec![0u32; hosts.len()];
        // Alternate rounds use a browser-sized (post-quantum, two-packet) ClientHello: a strategy has to
        // get both through, or it may pass here and still fail in Chrome or Edge.
        for round_no in 0..rounds {
            let big = round_no % 2 == 1;
            let round: Vec<ProbeResult> = std::thread::scope(|sc| {
                let hs: Vec<_> = hosts.iter().map(|(t, ip)| sc.spawn(move || { let mut t = t.clone(); t.big_hello = big || t.big_hello; prober.probe(&t, ip) })).collect();
                hs.into_iter().map(|h| h.join().unwrap()).collect()
            });
            for (i, r) in round.iter().enumerate() { if r.ok { per_host[i] += 1; } }
            results.extend(round);
        }
        let mut ok: Vec<f64> = results.iter().filter(|r| r.ok).filter_map(|r| r.ms).collect();
        ok.sort_by(|a, b| a.total_cmp(b));
        let sc = Score { id: s.id, pass: results.iter().filter(|r| r.ok).count() as u32, total: results.len() as u32,
                         ms: ok.get(ok.len().saturating_sub(1) / 2).copied(), error: None, per_host, rounds };
        log(&format!("strategy {}: {}", s.id, sc.summary()));
        scores.push(sc);
    }
    runner.stop();
    rank(scores)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_stay_on_steam_ports_and_lists() {
        let f = BypassFiles { zapret: r"C:\Program Files\RustyDPI\zapret".into(), lists: r"C:\ProgramData\RustyDPI\lists".into() };
        let a = build_args(find(Some("fake-split")).unwrap(), &f, &BTreeMap::new());
        let wf = a.iter().find(|x| x.starts_with("--wf-raw-part=")).expect("own filter");
        assert!(wf.contains("tcp.DstPort == 443") && wf.contains("udp.DstPort == 443") && wf.contains("tcp.DstPort == 80"));
        assert!(wf.contains(&format!("ip.TTL != {PROBE_TTL}")));
        assert!(!a.iter().any(|x| x.starts_with("--wf-tcp") || x.starts_with("--wf-udp") || x.starts_with("--wf-raw=")));
        assert_eq!(a.iter().filter(|x| x.starts_with("--hostlist=")).count(), 2);
        assert_eq!(a.iter().filter(|x| x.starts_with("--hostlist-exclude=")).count(), 2);
        assert!(a.iter().any(|x| x == &format!("--dpi-desync-fake-tls={}", f.fake_tls().display())));
        assert!(!a.iter().any(|x| x.contains("{tls}") || x.contains("--ipset")));
    }

    #[test]
    fn ids_unique() {
        let mut ids: Vec<_> = STRATEGIES.iter().map(|s| s.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), STRATEGIES.len());
    }

    #[test]
    fn rank_prefers_passes_then_speed() {
        let s = |id, pass, total, ms: Option<f64>, err: Option<&str>| Score { id, pass, total, ms, error: err.map(String::from), ..Default::default() };
        let r = rank(vec![s("a", 5, 9, Some(30.0), None), s("b", 9, 9, Some(80.0), None), s("c", 9, 9, Some(40.0), None), s("d", 0, 0, None, Some("x"))]);
        assert_eq!(r.iter().map(|x| x.id).collect::<Vec<_>>(), vec!["c", "b", "a", "d"]);
    }

    #[test]
    fn overrides_only_for_hosts_the_winner_fails() {
        let s = |id, per_host: Vec<u32>| Score { id, pass: per_host.iter().sum(), total: 12, ms: Some(30.0), per_host, rounds: 4, ..Default::default() };
        let hosts: Vec<String> = ["steam", "cdn", "dead"].iter().map(|x| x.to_string()).collect();
        let ranked = rank(vec![s("split-disorder", vec![4, 0, 0]), s("fake-md5sig", vec![0, 4, 0]), s("seqovl", vec![4, 3, 0])]);
        assert_eq!(ranked[0].id, "seqovl", "most passes wins overall");
        // seqovl already passes "cdn" 3 of 4: no override. Nothing opens "dead": none either.
        assert!(overrides(&ranked, &hosts).is_empty());
        let ranked = rank(vec![s("split-disorder", vec![4, 0, 0]), s("fake-md5sig", vec![0, 4, 0])]);
        let o = overrides(&ranked, &hosts);
        assert_eq!(o.len(), 1);
        assert_eq!(o.get("cdn").map(String::as_str), Some(if ranked[0].id == "split-disorder" { "fake-md5sig" } else { "split-disorder" }));
        // A strategy that only sometimes works (2 of 4) isn't worth a profile.
        let ranked = rank(vec![s("split-disorder", vec![4, 0, 0]), s("fake-md5sig", vec![0, 2, 0])]);
        assert!(overrides(&ranked, &hosts).is_empty());
    }

    #[test]
    fn override_profiles_come_before_the_main_one() {
        let f = BypassFiles { zapret: r"C:\z".into(), lists: r"C:\l".into() };
        let o: BTreeMap<String, String> = [("a.example".to_string(), "seqovl".to_string()), ("b.example".to_string(), "seqovl".to_string())].into();
        let a = build_args(find(Some("split-disorder")).unwrap(), &f, &o);
        let pos = |p: &str| a.iter().position(|x| x.starts_with(p)).unwrap();
        assert!(a.iter().any(|x| x == "--hostlist-domains=a.example,b.example"));
        let main_tcp = a.iter().rposition(|x| x == "--filter-tcp=80,443").unwrap();
        assert!(pos("--hostlist-domains=") < main_tcp);
        assert_eq!(a.iter().filter(|x| *x == "--new").count(), 2);
        assert_eq!(a.last().map(String::as_str), Some("--dpi-desync-split-pos=1,midsld"));
    }

    #[test]
    fn rank_ignores_tiny_latency_differences() {
        let s = |id, pass, ms: f64| Score { id, pass, total: 6, ms: Some(ms), error: None, ..Default::default() };
        // Tested in this order; "cur" is the current strategy. 1-5 ms faster isn't worth switching.
        let r = rank(vec![s("cur", 6, 73.0), s("b", 6, 71.0), s("c", 6, 70.0), s("flaky", 5, 40.0)]);
        assert_eq!(r[0].id, "cur");
        // A clearly faster one still wins.
        let r = rank(vec![s("cur", 6, 90.0), s("fast", 6, 40.0)]);
        assert_eq!(r[0].id, "fast");
        // A full pass always beats a partial one.
        let r = rank(vec![s("cur", 5, 30.0), s("ok", 6, 80.0)]);
        assert_eq!(r[0].id, "ok");
    }

    #[test]
    fn lists_written_only_when_changed() {
        let d = std::env::temp_dir().join(format!("rustydpi-lists-{}", std::process::id()));
        let f = BypassFiles { zapret: d.clone(), lists: d.clone() };
        assert!(write_lists(&f, &["b.com".into(), "a.com".into(), "a.com".into()], &["x.com".into()]));
        assert!(!write_lists(&f, &["a.com".into(), "b.com".into()], &["x.com".into()]));
        assert_eq!(std::fs::read_to_string(f.host_list()).unwrap(), "a.com\nb.com\n");
        assert!(write_lists(&f, &["a.com".into()], &["x.com".into()]));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Compiles the full filter (as winws assembles it) with the real WinDivert.dll; no admin needed.
    #[test]
    fn filter_compiles_in_windivert() {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        type Compile = unsafe extern "C" fn(*const u8, u32, *mut u8, u32, *mut *const u8, *mut u32) -> i32;
        let dll: Vec<u16> = concat!(env!("CARGO_MANIFEST_DIR"), "\\vendor\\zapret\\WinDivert.dll").encode_utf16().chain([0]).collect();
        let lan = "(outbound and ((ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and (ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255)) or inbound and ((ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255)))";
        let compile = |f: &str| unsafe {
            let h = LoadLibraryW(dll.as_ptr());
            assert!(!h.is_null(), "WinDivert.dll not found");
            let p: Compile = std::mem::transmute(GetProcAddress(h, c"WinDivertHelperCompileFilter".as_ptr().cast()).expect("export"));
            let c = std::ffi::CString::new(f).unwrap();
            let (mut err, mut pos) = (std::ptr::null(), 0u32);
            let ok = p(c.as_ptr().cast(), 0, std::ptr::null_mut(), 0, &mut err, &mut pos) != 0;
            (ok, if err.is_null() { String::new() } else { std::ffi::CStr::from_ptr(err.cast()).to_string_lossy().into_owned() }, pos)
        };
        // Same shape as zapret's wf_make_filter with one raw part.
        let full = format!("!impostor and !loopback and\n(\n (\n{}\n )\n)\nand\n{lan}", filter_part());
        let (ok, err, pos) = compile(&full);
        assert!(ok, "filter error at {pos}: {err}");
        let (bad, _, _) = compile("outbound and !(ip.TTL == 117)");
        assert!(!bad, "the compile check must be able to fail");
    }

    #[test]
    fn embedded_files_match_hashes() {
        use sha2::{Digest, Sha256};
        for (n, h, b) in ZAPRET_FILES { if !h.is_empty() { assert_eq!(&format!("{:x}", Sha256::digest(b)), h, "{n}"); } }
    }
}
