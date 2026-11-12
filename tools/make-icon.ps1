# Draws RustyDPI's icon (a map pin on a dark-blue tile) and writes a multi-size .ico.
param([string]$Out = (Join-Path $PSScriptRoot '..\src\RustyDPI.App\rustydpi.ico'))
Add-Type -AssemblyName System.Drawing

function New-Frame([int]$s) {
    $bmp = New-Object Drawing.Bitmap $s, $s
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([Drawing.Color]::Transparent)
    $r = [math]::Max(2, $s * 0.22)
    $path = New-Object Drawing.Drawing2D.GraphicsPath
    $w = $s - 1
    $path.AddArc(0, 0, $r, $r, 180, 90); $path.AddArc($w - $r, 0, $r, $r, 270, 90)
    $path.AddArc($w - $r, $w - $r, $r, $r, 0, 90); $path.AddArc(0, $w - $r, $r, $r, 90, 90); $path.CloseFigure()
    $bg = New-Object Drawing.Drawing2D.LinearGradientBrush ([Drawing.Point]::new(0, 0)), ([Drawing.Point]::new($s, $s)),
        ([Drawing.Color]::FromArgb(255, 42, 71, 94)), ([Drawing.Color]::FromArgb(255, 23, 26, 33))
    $g.FillPath($bg, $path)
    # pin: circle head + triangle tail
    $cx = $s / 2; $head = $s * 0.46; $top = $s * 0.14
    $pin = New-Object Drawing.Drawing2D.GraphicsPath
    $pin.AddEllipse($cx - $head / 2, $top, $head, $head)
    $tip = [Drawing.PointF]::new($cx, $s * 0.88)
    $pin.AddPolygon([Drawing.PointF[]]@([Drawing.PointF]::new($cx - $head * 0.42, $top + $head * 0.72), [Drawing.PointF]::new($cx + $head * 0.42, $top + $head * 0.72), $tip))
    $blue = New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(255, 102, 192, 244))
    $g.FillPath($blue, $pin)
    $hole = $head * 0.42
    $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(255, 27, 40, 56))), $cx - $hole / 2, $top + ($head - $hole) / 2, $hole, $hole)
    $g.Dispose()
    $ms = New-Object IO.MemoryStream
    $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return , $ms.ToArray()
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 256
$frames = @(foreach ($s in $sizes) { , (New-Frame $s) })
$ico = New-Object IO.MemoryStream
$bw = New-Object IO.BinaryWriter $ico
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]; $b = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([byte]$b); $bw.Write([byte]$b); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]$frames[$i].Length); $bw.Write([uint32]$offset)
    $offset += $frames[$i].Length
}
foreach ($f in $frames) { $bw.Write($f) }
[IO.File]::WriteAllBytes($Out, $ico.ToArray())
Write-Host "wrote $Out"

