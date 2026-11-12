# Third-party software in RustyDPI

RustyDPI.exe embeds these files and installs them to `C:\Program Files\RustyDPI\zapret`.
They are copied unchanged from the official release and checked against SHA-256 hashes
at build time (`tools/fetch-zapret.ps1`) and at run time (`src/bypass.rs`).

| Component | Files | License | Source |
|---|---|---|---|
| zapret v72.13 by bol-van | `winws.exe`, `tls_clienthello_www_google_com.bin`, `quic_initial_www_google_com.bin` | MIT (`vendor/zapret/ZAPRET-LICENSE.txt`) | https://github.com/bol-van/zapret |
| WinDivert 2.2 by basil00 | `WinDivert.dll`, `WinDivert64.sys` | LGPL-3.0 or GPL-2.0 (`vendor/zapret/WINDIVERT-LICENSE.txt`) | https://github.com/basil00/WinDivert |
| Cygwin runtime | `cygwin1.dll` (used by winws) | LGPL-3.0 with linking exception | https://cygwin.com/git/?p=newlib-cygwin.git |

WinDivert.dll and cygwin1.dll are separate, replaceable files, as the LGPL requires.
Their source code is available at the links above.

Rust crates (statically linked) keep their own licenses (MIT / Apache-2.0 / ISC / BSD, and Slint
under its Royalty-free Desktop license, credited in the app's About section). Run
`cargo tree` for the full list.
