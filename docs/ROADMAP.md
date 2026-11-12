# RustyDPI roadmap: staying alive for years

Based on the research in `reports/RustyDPI future proofing.md` (November 2026). Items 1, 2, 3 and most of 5 are done in 4.0.0.

| # | What | Why | Effort | Priority |
|---|---|---|---|---|
| 1 | ~~Driver-block check~~ (done in 4.0.0) | Windows 11's 2026 driver rules can switch to blocking on their own; Diagnose now reads the Code Integrity log and says when WinDivert is blocked or about to be | S | P0 |
| 2 | ~~Browser restart reminder~~ (done in 4.0.0) | Browsers keep old connections and DNS, so a fixed site looks blocked | S | P1 |
| 3 | ~~Test with browser-sized ClientHellos~~ (done in 4.0.0) | Browsers now send post-quantum (ML-KEM) key shares, a ~1.7 KB ClientHello split over 2 packets. Our tester (rustls + ring) sends a small one, so a strategy can pass our test and still fail in Chrome. Switch the tester to rustls + aws-lc-rs with X25519MLKEM768, or pad the ClientHello, and test both sizes | S–M | P1 |
| 4 | **QUIC policy per site** | Bypassed sites over HTTP/3 (UDP 443) either need a tested QUIC desync or a clean drop so browsers fall back to TCP fast. Half-working QUIC means slow or broken loads | S | P1 |
| 5 | **Bypass backends** (driverless relay done in 4.0.0) | winws, plus a driverless relay (TLS record splitting, verified on FPT in November 2026) when Windows refuses WinDivert or no strategy works. Left: winws2 (zapret2). The relay can't do QUIC; browsers fall back to TCP | L | P0 |
| 6 | **Move to zapret2** | zapret 1 is end-of-life (bug fixes only; v72.13 is likely the last). zapret2 is active (v1.0.7, Nov 2026) but its strategies are Lua, so our ~10 strategies need rewriting | M | P1 |
| 7 | **Signed strategy updates** | New strategies, hostlists and pins without a new exe: an Ed25519-signed manifest (key built into the exe), increasing serial (no rollback), expiry, minimum app version; hosted on GitHub plus a mirror. Binary updates stay hash-pinned and need the user's OK | M | P0 |
| 8 | **Health journal** | Per network: which failure (reset, timeout, wrong certificate, block page, poisoned DNS) and when, to re-test before users notice; exportable as a redacted zip. Nothing leaves the PC | M | P1 |
| 9 | **Code signing and antivirus** | A signed exe helps with Smart App Control and antivirus; submit each release to vendors' false-positive forms (Kaspersky, Malwarebytes, ESET flag WinDivert) | M | P2 |
| 10 | **DoH and ECH** | Use DoH in the pin verifier to dodge poisoned DNS; try direct-over-ECH (RFC 9849) as one more route. Not a replacement: Russia already blocks Cloudflare's ECH | M | P2 |
| 11 | **Relay: more names, more shapes** | Driverless mode covers exact names only: offer the `www.` and other names a site uses (seen in its redirects and certificate). If a CDN ever rejects 64-byte records, try a 2-record split at the site name (zapret's tpws `--tlsrec`) before giving up | S | P2 |

What we know (November 2026 overnight test): FPT reassembles TCP (packet splits alone fail) but reads the site name from a single TLS record, so record splitting gets through with no driver. 18 of 18 major sites accept a ClientHello in 64-byte records.

What to watch: FPT/Viettel/VNPT moving to stream-reassembling DPI (as Russia's TSPU does, which defeats split-only strategies), and Vietnam's Cybersecurity Law (in force 1 July 2026).
