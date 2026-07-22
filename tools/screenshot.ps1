# Capture a window (by title substring) to a PNG. Used to generate README shots.
#   powershell -ExecutionPolicy Bypass -File tools\screenshot.ps1 "Aegis" docs\images\app.png
param(
  [string]$TitleMatch = "Aegis",
  [string]$OutPath = "docs\images\app.png"
)

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinApi {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT r);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# Find a visible top-level window whose title contains $TitleMatch.
$proc = Get-Process | Where-Object { $_.MainWindowTitle -like "*$TitleMatch*" -and $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (-not $proc) { Write-Error "No window matching '$TitleMatch' found"; exit 1 }
$h = $proc.MainWindowHandle

[WinApi]::ShowWindow($h, 3)      | Out-Null   # SW_MAXIMIZE (clean full-window shot)
[WinApi]::SetForegroundWindow($h)| Out-Null
Start-Sleep -Milliseconds 1200

$r = New-Object WinApi+RECT
[WinApi]::GetWindowRect($h, [ref]$r) | Out-Null
$w = $r.Right - $r.Left
$hgt = $r.Bottom - $r.Top
if ($w -le 0 -or $hgt -le 0) { Write-Error "Bad window rect"; exit 1 }

$bmp = New-Object System.Drawing.Bitmap $w, $hgt
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object System.Drawing.Size $w, $hgt))
$dir = Split-Path -Parent $OutPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
$bmp.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Output "Saved $OutPath ($w x $hgt)"
