# Downloads the official zapret release and copies the Windows files SteamPin embeds into vendor\zapret,
# checking every file against the SHA-256 that SteamPin also checks at run time (src\bypass.rs).
$ErrorActionPreference = 'Stop'
$ver = 'v72.13'
$root = Split-Path -Parent $PSScriptRoot
$dl = Join-Path $root 'vendor\dl'
$out = Join-Path $root 'vendor\zapret'
New-Item -ItemType Directory -Force $dl, $out | Out-Null
$zip = Join-Path $dl "zapret-$ver.zip"
if (-not (Test-Path $zip)) { Invoke-WebRequest "https://github.com/bol-van/zapret/releases/download/$ver/zapret-$ver.zip" -OutFile $zip -UseBasicParsing }
$x = Join-Path $dl 'x'
if (Test-Path $x) { Remove-Item $x -Recurse -Force }
Expand-Archive $zip $x
$base = Join-Path $x "zapret-$ver"
$files = @{
    'binaries\windows-x86_64\winws.exe'       = 'a14bff1df6234ea555d2e0c61b589f0707c0b12d6c9b7eeccda76012154996e8'
    'binaries\windows-x86_64\cygwin1.dll'     = '103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b'
    'binaries\windows-x86_64\WinDivert.dll'   = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'binaries\windows-x86_64\WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
    'files\fake\tls_clienthello_www_google_com.bin' = '936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c'
    'files\fake\quic_initial_www_google_com.bin'    = 'f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a'
}
foreach ($f in $files.Keys) {
    $src = Join-Path $base $f
    $h = (Get-FileHash $src -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($h -ne $files[$f]) { throw "hash mismatch for $f ($h)" }
    Copy-Item $src $out -Force
}
Copy-Item (Join-Path $base 'docs\LICENSE.txt') (Join-Path $out 'ZAPRET-LICENSE.txt') -Force
Remove-Item $x -Recurse -Force
Write-Host "zapret $ver files ready in $out"
