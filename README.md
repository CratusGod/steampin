# RustyDPI

**Unblocks the websites you choose, and keeps Steam working, on networks that block them. One small Windows app (13 MB download, a few MB of RAM) that tests every site for real, picks the route that works, and fixes itself when something changes.**

Built for Vietnam (FPT, Viettel, VNPT), where sites are blocked by DNS poisoning and TLS resets. Works on any network: it measures what's actually blocked instead of assuming. Formerly called SteamPin.

> Tiếng Việt: RustyDPI kiểm tra từng trang web bạn thêm vào (và Steam) rồi chọn cách vào được: trực tiếp, ghi IP máy chủ tốt nhất vào file hosts, hoặc dùng bộ vượt chặn DPI (zapret) chỉ cho những trang đó. Tự sửa khi mạng thay đổi. Cài: tải `RustyDPI.exe`, mở, bấm **Install**, rồi thêm trang web ở thẻ **Sites**.

![RustyDPI](docs/home.png)

## Unblock a website

Open the **Sites** tab, type a site name (like `discord.com`) and click **Add**. RustyDPI tests it and keeps it working. Each site shows how it's reached, or why it isn't.

- **Restart your browser** after adding a site, or if a site still won't open. Browsers keep old connections and remembered addresses for a while, so a fixed site can look blocked until you close every browser window.
- If parts of a site still don't load (images, sign-in), add the other names it uses too. This matters most when a site shows "driverless bypass": that mode covers exactly the names in your list (add `www.` names too), while the normal bypass also covers every sub-name.
- Sites blocked in ways only a VPN gets around won't work.
- **Private by default:** the window shows your sites masked (`d****.com`) until you turn on **Show site names**, and the log and Copy report always mask them. To unblock a site, its name has to be in the bypass list or, if pinned, in the hosts file.

## Steam

The **Steam** tab keeps Steam's store, sign-in, community and images working (on by default; switch it off if you don't use Steam). It can restart Steam for you after a server switch, and never during a game: it waits until you close it.

## How it works

For each site, RustyDPI finds the first route that really works:

1. **Direct.** Normal DNS gives a working server: nothing to do.
2. **Pinned.** DNS is poisoned or points at a blocked server, but another server works: RustyDPI pins the fastest verified one in the hosts file.
3. **Bypass.** Nothing works without help: RustyDPI runs [zapret](https://github.com/bol-van/zapret)'s DPI bypass (`winws`) **for those site names only**, after testing about 10 bypass strategies on your network and keeping the best. A site the best strategy doesn't open gets its own strategy, if another one works for it.
4. **Driverless bypass.** If Windows blocks the WinDivert driver, antivirus removes it, or no strategy works, RustyDPI points the site at a small relay on your own PC (each site gets its own address in `127.77.x.x`, so it also works when the browser hides the site name with Encrypted Client Hello). The relay cuts the browser's first TLS message into small pieces before passing it on, which gets past DPI that reads the site name from one piece (FPT's does). It decrypts nothing: your browser still checks the real site's certificate. HTTPS only.

"Works" means an HTTPS request with the real host name and a valid certificate (for Steam, also a check of the answer). A server that answers ping, or serves a block page or another site, doesn't count.

It keeps checking every 30 minutes, when the network changes and after sleep. Checks never pause the bypass: RustyDPI marks its own test connections so the bypass lets them through untouched, and sites keep working while it tests.

- **Healthy pins stay.** It switches only to a clearly faster server, after two runs in a row.
- **Failing pins are replaced at once.** A failing bypass strategy is re-tested.
- **Repairs itself.** If antivirus wipes the hosts entries, they come back within a minute (a read-only hosts file stays read-only). If winws crashes, it's restarted.
- **Offline means hands off.** Nothing changes while there's no internet.
- **IPv6-aware.** Browsers prefer IPv6. If a site works over IPv4 but its IPv6 route is blocked, RustyDPI pins the working IPv4 server, which also hides the blocked IPv6 address from the browser.

## Diagnose

**Diagnose** checks everything that commonly breaks unblocking, in plain words, with step-by-step "How to fix" instructions and a fix button where there is one:

- DNS poisoning.
- A locked hosts file, or antivirus resetting it.
- Bypass files removed by antivirus.
- Windows blocking the WinDivert driver (newer Windows 11 driver rules, Memory integrity, Smart App Control).
- Another bypass tool running at the same time (CDPI UI, GoodbyeDPI, another zapret).
- A VPN or proxy that takes traffic elsewhere.
- Browsers whose Secure DNS ignores the hosts file.
- Steam started before the last change (it needs a restart).

**Copy report** gives a text summary to paste when asking for help. It contains no personal data, only server addresses, and your sites are masked.

## Install

1. Download `RustyDPI.exe` from [Releases](https://github.com/CratusGod/rustydpi/releases).
2. Open it and click **Install**, then accept the admin prompt.
3. Add your sites in the **Sites** tab. Steam is checked automatically.

It runs as a Windows service with a tray icon. Closing the window doesn't stop it.

- **Upgrading from SteamPin:** install over it. SteamPin is removed and your sites, settings and pins carry over.
- **Using CDPI UI, GoodbyeDPI or another zapret:** Diagnose offers to close them, because two bypass tools on the same traffic break each other.
- **Antivirus:** some antivirus flags WinDivert (the network driver zapret uses) as a "RiskTool". If the bypass files disappear, add an exception for `C:\Program Files\RustyDPI\zapret` and click **Repair** in Diagnose.

**Update:** the Update tab. RustyDPI looks for a new version once a day (you can turn that off) and installs it when you click Update now: no admin prompt, and your sites and settings are kept. Updates come only from this repository's releases and must match the published SHA256 checksum.

**Uninstall:** Settings → Uninstall, or Windows Settings → Apps. It removes the service, the driver, the hosts entries and all files.

## How light is it

| Part | Memory | When |
|---|---|---|
| Service | ~6 MB | always |
| Tray icon | ~2 MB | always |
| Window | ~5 MB | only while open |

A check takes 5–10 seconds, every 30 minutes. After a restart, the bypass that worked last time is back within a second of the service starting. The bypass touches only ports 80/443 to the site names that need it, so games and everything else are untouched.

## Command line

`RustyDPI.exe --status | --check [--full] | --retest | --diagnose | --dry-run | --test | --restart-steam | --unpin | --install | --uninstall`

## Configure

Optional: `C:\ProgramData\RustyDPI\config.json` (admins only) overrides the built-in [`assets/default-config.json`](assets/default-config.json): the Steam hosts to check, seed servers, DNS resolvers, bypass domain lists and timings.

## Build

```powershell
.\tools\fetch-zapret.ps1     # official zapret release, hash-checked
cargo test --release
cargo build --release        # target\release\rustydpi.exe
```

Releases are built by GitHub Actions from a `v*` tag.

## Credits and license

MIT. The DPI bypass is [zapret](https://github.com/bol-van/zapret) (MIT) with [WinDivert](https://github.com/basil00/WinDivert) (LGPL). The UI uses [Slint](https://slint.dev). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
