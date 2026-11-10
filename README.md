# SteamPin

**Keeps Steam working on ISPs that block it, by pinning Steam's hostnames to the fastest server that actually works from your connection, and switching automatically when that server stops working.**

Built for Vietnam (FPT Telecom), where Steam's store, login and API are blocked by DNS poisoning and TLS resets, but Steam's own cache servers *inside* the ISP's network still work. Works with any ISP or hostname via `config.json`.

> Tiếng Việt: SteamPin tự động ghi IP máy chủ Steam nhanh nhất (đặt trong mạng FPT) vào file hosts, kiểm tra lại mỗi 30 phút và tự đổi sang máy chủ khác khi máy chủ cũ hỏng. Cài: chạy `install.cmd`.

## Why

When an ISP blocks Steam, the usual fixes each have a catch:

| Fix | Problem |
|---|---|
| Change DNS (8.8.8.8, 1.1.1.1) | 1.1.1.1 returns foreign servers that the ISP resets; Google DNS sometimes does too |
| Hosts entries shared online | They go stale: IPs shared on forums in 2024 now time out or serve the wrong certificate |
| zapret / GoodbyeDPI on Steam login/API | Slow or timing out through DPI bypass |
| VPN / WARP | Slower, and changes your Steam store region if left on |
| Tools like Watt Toolkit, UsbEAm, SmartDNS, AdGuard `fastest_addr` | Pick IPs by ping or TCP connect only; none verify the TLS certificate, so they happily pick an IP the ISP resets or that serves a different site |

SteamPin pins Steam to servers inside your ISP's network and **keeps checking them**.

## How it works

Every 30 minutes, at startup, when the network connects and after sleep, a scheduled task (running as SYSTEM) does this for each hostname:

1. **Find candidates.** The current pin, servers that worked before (remembered for 14 days), fresh DNS answers from Google, OpenDNS, Google DoH and Akamai's own name servers (filtered to your ISP's networks), and seed IPs from the config.
2. **Check them for real.** An HTTPS request to each IP with the real hostname: the certificate must be valid, and the answer must look right. For example, the API must return `servertime` JSON and login must redirect to steampowered.com. A server that answers ping, or serves an error page or the wrong site, does **not** count.
3. **Decide calmly.**
   - Keep the current pin while it works (2 of 3 checks pass).
   - Replace it **immediately** if it fails, using the fastest server that passed 3 of 3 checks.
   - Switch to a faster server only if it's clearly faster (20% and 15 ms) on **two runs in a row**, so pins don't flap.
   - Remove a pin (fall back to normal DNS) only after **two failed runs** with no working replacement.
   - Do **nothing** while the PC is offline.
   - Back off servers that keep failing (30 min, then 1 h, 2 h, up to 6 h).
4. **Edit safely.** Only its own block in the hosts file is touched:
   ```
   # BEGIN SteamPin - managed automatically, edits inside this block are overwritten
   42.119.186.138	store.steampowered.com
   118.69.17.16	api.steampowered.com
   118.69.17.204	login.steampowered.com
   # END SteamPin
   ```
   The file is replaced atomically, with a backup at `hosts.steampin.bak`, keeping its encoding, and only when something changed. Then the DNS cache is flushed.

Servers are ranked by TLS handshake time, which measures the network path to the server. Time-to-first-byte mostly measures Valve's origin servers behind the cache.

## Install

1. Download this repository (green **Code** button → **Download ZIP**) and unzip it.
2. Double-click **`install.cmd`** and accept the admin prompt.
3. It runs the first check and shows the result:
   ```
   SteamPin 2.0.0 - last check 2026-11-11 00:15:16 (took 28 s)
   store.steampowered.com     42.119.186.138     20 ms  kept      (3 of 10 servers working, 1 from DNS)
   api.steampowered.com       118.69.17.16       20 ms  kept      (11 of 14 servers working, 9 from DNS)
   login.steampowered.com     118.69.17.204      22 ms  kept      (7 of 10 servers working, 2 from DNS)
   ```

Installing again upgrades in place and keeps your `config.json`. Run `install.ps1 -ResetConfig` to get the new default config.

Requirements: Windows 10/11 (PowerShell 5.1 and `curl.exe` are built in).

## Use

| | |
|---|---|
| `status.cmd` | Last check, current pins, recent log |
| `test-servers.cmd` | Probe every known server and show a speed table (changes nothing) |
| Task Scheduler → **SteamPin** → Run | Check right now |
| `C:\ProgramData\SteamPin\log.txt` | Every change, with the reason |
| `uninstall.cmd` | Removes the pins, the task and all files |

Command line (`C:\Program Files\SteamPin\steampin.ps1`): `-Status`, `-Test`, `-DryRun`, `-Unpin`.

## Configure

`C:\Program Files\SteamPin\config.json` (admin-only, because the task runs as SYSTEM):

| Key | Meaning |
|---|---|
| `targets` | Hostnames to pin, each with a check: `path`, `expectStatus`, and optional `expectBody` / `expectRedirect` regex |
| `seeds` | Known-good IPs to always try (add per-target `seeds` too) |
| `resolvers`, `dohUrls` | Where to look for fresh candidates |
| `allowedNetworks` | Only use DNS answers inside these CIDRs (your ISP's ranges). Empty = any public IP |
| `samples` | Checks per server per run (default 3) |
| `switchMinGainPct`, `switchMinGainMs`, `switchConfirmRuns` | When a faster server is worth switching to |
| `removeAfterFailedRuns` | Failed runs before falling back to DNS |
| `forgetAfterDays` | How long to remember servers that worked |

For another ISP, replace `seeds` and `allowedNetworks`. To find your ISP's ranges, look up its ASN on [RIPEstat](https://stat.ripe.net/). Then run `test-servers.cmd` to see what works.

## Notes

- **Steam store, api and login only.** Community and image hosts are better handled by zapret / GoodbyeDPI. Content downloads already go to local caches.
- **Browsers with "Secure DNS" (DoH) on** may ignore the hosts file. If the store fails in the browser but works in the Steam client, turn Secure DNS off for that browser.
- **Antivirus** may reset the hosts file. SteamPin notices, logs it and pins again on the next run.
- **Security.**
  - The script and config live in Program Files (only admins can change them).
  - State lives in `C:\ProgramData\SteamPin`, which only SYSTEM and admins can write.
  - Every IP is validated before it reaches the hosts file (public IPv4 only).
  - curl is called with an argument list, never a built command string.
  - Nothing is downloaded or executed at run time.

## Tests

```powershell
.\tests\Run-Tests.ps1            # unit + end-to-end scenarios (needs a network where the seeds work)
.\tests\Run-Tests.ps1 -UnitOnly  # no network
```
They never touch the real hosts file and don't need admin rights.

## License

MIT
