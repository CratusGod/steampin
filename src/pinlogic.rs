//! The pin decision rules: pure functions over state and measurements.

use crate::config::Config;
use crate::probe::{Fail, ProbeResult};
use crate::state::{IpEntry, TargetState, Time};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
pub struct Measurement { pub ip: String, pub pass: u32, pub total: u32, pub ms: Option<f64>, pub fail: Fail, pub reason: String }

impl Measurement {
    pub fn all_passed(&self) -> bool { self.total > 0 && self.pass == self.total }
    pub fn mostly_passed(&self) -> bool { self.pass * 2 > self.total }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision { pub pin: Option<String>, pub action: &'static str, pub note: String }

pub fn summarize(ip: &str, probes: &[ProbeResult]) -> Measurement {
    let mut ok: Vec<f64> = probes.iter().filter(|p| p.ok).filter_map(|p| p.ms).collect();
    ok.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = if ok.is_empty() { None } else { Some(ok[(ok.len() - 1) / 2]) };
    let last_fail = probes.iter().rev().find(|p| !p.ok);
    Measurement {
        ip: ip.to_string(), pass: ok.len() as u32, total: probes.len() as u32, ms: median,
        fail: last_fail.map(|p| p.fail).unwrap_or_default(), reason: last_fail.map(|p| p.reason.clone()).unwrap_or_default(),
    }
}

/// Exponential backoff for IPs that keep failing: 30 min, 1 h, 2 h, ... capped at 6 h.
pub fn is_backed_off(e: Option<&IpEntry>, now: Time) -> bool {
    let Some(e) = e else { return false };
    let Some(last) = e.last_probe else { return false };
    if e.fail_streak < 3 { return false; }
    let mins = (30.0 * 2f64.powi(e.fail_streak as i32 - 3)).min(360.0);
    ((now - last).num_seconds() as f64 / 60.0) < mins
}

pub fn update(ts: &mut TargetState, m: &Measurement, now: Time) {
    let e = ts.ips.entry(m.ip.clone()).or_insert_with(|| IpEntry { first_seen: Some(now), ..Default::default() });
    e.last_probe = Some(now);
    if m.all_passed() { e.last_ok = Some(now); e.fail_streak = 0; e.last_ms = m.ms; }
    else if m.pass == 0 { e.fail_streak += 1; e.last_fail = Some(now); e.last_reason = Some(m.reason.clone()); }
}

pub fn remove_stale(ts: &mut TargetState, forget_after_days: f64, now: Time, keep: &[String]) {
    ts.ips.retain(|ip, e| {
        if keep.contains(ip) { return true; }
        match e.last_ok.or(e.last_seen_dns).or(e.first_seen) {
            Some(r) => ((now - r).num_seconds() as f64 / 86400.0) <= forget_after_days,
            None => false,
        }
    });
}

/// Candidate order: current pin, servers that worked before (newest first), DNS answers, seeds.
pub fn candidates<'a>(current: Option<&str>, ts: &TargetState, dns: impl IntoIterator<Item = &'a String>, seeds: impl IntoIterator<Item = &'a String>, max: usize) -> Vec<String> {
    let mut known: Vec<(&String, Time)> = ts.ips.iter().filter_map(|(ip, e)| e.last_ok.map(|t| (ip, t))).collect();
    known.sort_by(|a, b| b.1.cmp(&a.1));
    let mut all: Vec<String> = Vec::new();
    let iter = current.map(|c| c.to_string()).into_iter()
        .chain(known.into_iter().map(|(ip, _)| ip.clone()))
        .chain(dns.into_iter().cloned())
        .chain(seeds.into_iter().cloned());
    for ip in iter {
        if crate::iputil::is_public_ipv4(&ip) && !all.contains(&ip) { all.push(ip); }
    }
    all.truncate(max);
    all
}

/// Keep a healthy pin (2 of 3 checks); switch to a clearly faster server only after it wins
/// `switch_confirm_runs` runs in a row; replace a failing pin immediately with the fastest
/// server that passed every check; remove a failing pin only after `remove_after_failed_runs`.
pub fn select(cfg: &Config, ts: &mut TargetState, cur: Option<&str>, results: &HashMap<String, Measurement>) -> Decision {
    let cur_m = cur.and_then(|c| results.get(c));
    let cur_healthy = cur_m.map(|m| m.mostly_passed()).unwrap_or(false);
    let best = results.values()
        .filter(|m| Some(m.ip.as_str()) != cur && m.total == cfg.samples && m.all_passed())
        .min_by(|a, b| a.ms.partial_cmp(&b.ms).unwrap_or(std::cmp::Ordering::Equal));

    if cur_healthy {
        let cm = cur_m.unwrap();
        ts.failed_runs = 0;
        if let Some(b) = best {
            let (cms, bms) = (cm.ms.unwrap_or(0.0), b.ms.unwrap_or(0.0));
            let gain = cms - bms;
            if gain >= cfg.switch_min_gain_ms && gain >= cms * cfg.switch_min_gain_pct / 100.0 {
                if ts.challenger.as_deref() == Some(&b.ip) { ts.challenger_runs += 1; } else { ts.challenger = Some(b.ip.clone()); ts.challenger_runs = 1; }
                if ts.challenger_runs >= cfg.switch_confirm_runs {
                    let note = format!("{} is faster ({bms} ms vs {cms} ms on {} runs)", b.ip, ts.challenger_runs);
                    ts.challenger = None; ts.challenger_runs = 0;
                    return Decision { pin: Some(b.ip.clone()), action: "faster", note };
                }
                return Decision { pin: cur.map(String::from), action: "none", note: format!("kept; {} is faster ({bms} vs {cms} ms), switching if still faster next run", b.ip) };
            }
        }
        ts.challenger = None; ts.challenger_runs = 0;
        return Decision { pin: cur.map(String::from), action: "none", note: String::new() };
    }

    ts.challenger = None; ts.challenger_runs = 0;
    let why = match cur { Some(c) => format!("{c} failed ({})", cur_m.map(|m| m.reason.as_str()).unwrap_or("not checked")), None => "not pinned".into() };
    if let Some(b) = best {
        ts.failed_runs = 0;
        return Decision { pin: Some(b.ip.clone()), action: if cur.is_some() { "replaced" } else { "pinned" }, note: format!("{why} -> {} ({} ms)", b.ip, b.ms.unwrap_or(0.0)) };
    }
    if let Some(c) = cur {
        ts.failed_runs += 1;
        if ts.failed_runs >= cfg.remove_after_failed_runs {
            let note = format!("{why} on {} runs and no working server found -> pin removed", ts.failed_runs);
            ts.failed_runs = 0;
            return Decision { pin: None, action: "removed", note };
        }
        return Decision { pin: Some(c.to_string()), action: "failing", note: format!("{why}, no working replacement yet; keeping it until the next check") };
    }
    Decision { pin: None, action: "none", note: String::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(ip: &str, pass: u32, ms: Option<f64>) -> Measurement { mt(ip, pass, ms, 3) }
    fn mt(ip: &str, pass: u32, ms: Option<f64>, total: u32) -> Measurement {
        Measurement { ip: ip.into(), pass, total, ms, fail: if pass == total { Fail::None } else { Fail::TlsReset }, reason: if pass == total { String::new() } else { "TLS reset".into() } }
    }
    fn r(v: Vec<Measurement>) -> HashMap<String, Measurement> { v.into_iter().map(|x| (x.ip.clone(), x)).collect() }
    fn cfg() -> Config { Config::default_config() }

    #[test]
    fn backoff() {
        let now = crate::state::now();
        let e = |s: u32, mins: i64| IpEntry { fail_streak: s, last_probe: Some(now - chrono::Duration::minutes(mins)), ..Default::default() };
        assert!(!is_backed_off(Some(&e(2, 0)), now));
        assert!(is_backed_off(Some(&e(3, 10)), now));
        assert!(!is_backed_off(Some(&e(3, 31)), now));
        assert!(is_backed_off(Some(&e(5, 100)), now));
        assert!(!is_backed_off(Some(&e(20, 361)), now));
    }

    #[test]
    fn keeps_healthy_pin_when_others_slightly_faster() {
        let d = select(&cfg(), &mut TargetState::default(), Some("A"), &r(vec![m("A", 3, Some(20.0)), m("B", 3, Some(18.0))]));
        assert_eq!((d.pin.as_deref(), d.action), (Some("A"), "none"));
    }

    #[test]
    fn switches_to_clearly_faster_on_second_run() {
        let mut ts = TargetState::default();
        let res = r(vec![m("A", 3, Some(100.0)), m("B", 3, Some(40.0))]);
        assert_eq!(select(&cfg(), &mut ts, Some("A"), &res).pin.as_deref(), Some("A"));
        assert_eq!(ts.challenger_runs, 1);
        let d = select(&cfg(), &mut ts, Some("A"), &res);
        assert_eq!((d.pin.as_deref(), d.action), (Some("B"), "faster"));
    }

    #[test]
    fn challenger_resets() {
        let mut ts = TargetState::default();
        select(&cfg(), &mut ts, Some("A"), &r(vec![m("A", 3, Some(100.0)), m("B", 3, Some(40.0))]));
        let d = select(&cfg(), &mut ts, Some("A"), &r(vec![m("A", 3, Some(100.0)), m("B", 3, Some(95.0))]));
        assert_eq!(d.pin.as_deref(), Some("A"));
        assert_eq!(ts.challenger_runs, 0);
    }

    #[test]
    fn two_of_three_is_healthy() {
        assert_eq!(select(&cfg(), &mut TargetState::default(), Some("A"), &r(vec![m("A", 2, Some(30.0)), m("B", 3, Some(10.0))])).pin.as_deref(), Some("A"));
    }

    #[test]
    fn failing_pin_replaced_by_fastest_healthy() {
        let d = select(&cfg(), &mut TargetState::default(), Some("A"), &r(vec![m("A", 1, Some(30.0)), m("B", 3, Some(50.0)), m("C", 3, Some(25.0))]));
        assert_eq!((d.pin.as_deref(), d.action), (Some("C"), "replaced"));
    }

    #[test]
    fn fail_fast_not_eligible_dead_pin_kept_then_removed() {
        let mut ts = TargetState::default();
        let res = r(vec![m("A", 0, None), mt("B", 1, Some(10.0), 1)]);
        let d1 = select(&cfg(), &mut ts, Some("A"), &res);
        assert_eq!((d1.pin.as_deref(), d1.action), (Some("A"), "failing"));
        let d2 = select(&cfg(), &mut ts, Some("A"), &res);
        assert_eq!((d2.pin, d2.action), (None, "removed"));
    }

    #[test]
    fn new_pin_when_nothing_pinned() {
        let d = select(&cfg(), &mut TargetState::default(), None, &r(vec![m("B", 3, Some(50.0)), m("C", 3, Some(25.0))]));
        assert_eq!((d.pin.as_deref(), d.action), (Some("C"), "pinned"));
    }

    #[test]
    fn candidate_order() {
        let now = crate::state::now();
        let mut ts = TargetState::default();
        ts.ips.insert("5.5.5.5".into(), IpEntry { last_ok: Some(now - chrono::Duration::hours(2)), ..Default::default() });
        ts.ips.insert("6.6.6.6".into(), IpEntry { last_ok: Some(now - chrono::Duration::hours(1)), ..Default::default() });
        ts.ips.insert("7.7.7.7".into(), IpEntry::default());
        let dns = vec!["2.2.2.2".to_string(), "127.0.0.1".into(), "1.1.1.1".into()];
        let seeds = vec!["3.3.3.3".to_string()];
        assert_eq!(candidates(Some("1.1.1.1"), &ts, &dns, &seeds, 16), vec!["1.1.1.1", "6.6.6.6", "5.5.5.5", "2.2.2.2", "3.3.3.3"]);
        assert_eq!(candidates(Some("1.1.1.1"), &ts, &dns, &seeds, 2).len(), 2);
    }

    #[test]
    fn forgets_stale() {
        let now = crate::state::now();
        let mut ts = TargetState::default();
        for (ip, d) in [("5.5.5.5", 20), ("6.6.6.6", 2), ("7.7.7.7", 30)] {
            ts.ips.insert(ip.into(), IpEntry { last_ok: Some(now - chrono::Duration::days(d)), ..Default::default() });
        }
        remove_stale(&mut ts, 14.0, now, &["7.7.7.7".to_string()]);
        let mut k: Vec<_> = ts.ips.keys().cloned().collect();
        k.sort();
        assert_eq!(k, vec!["6.6.6.6", "7.7.7.7"]);
    }

    #[test]
    fn summarize_median() {
        let p = [ProbeResult::good(30.0, 200), ProbeResult::good(10.0, 200), ProbeResult::failed(Fail::Timeout, "t")];
        let s = summarize("x", &p);
        assert_eq!((s.pass, s.total, s.ms, s.fail), (2, 3, Some(10.0), Fail::Timeout));
    }
}
