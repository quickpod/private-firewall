<#
.SYNOPSIS
  Freeze the PrivateFirewall engine into a standalone PrivateFirewall.exe.

.DESCRIPTION
  Uses PyInstaller (installed under C:\Python313) to produce a single-file exe
  that bundles pfw\server.py + pfw\dashboard.html and needs no Python at runtime.
  The exe is emitted to .\dist\PrivateFirewall.exe. Setup-PrivateFirewall.ps1
  installs that exe; if it is absent, Setup falls back to running from source
  with C:\Python313\python.exe.

  Console subsystem on purpose: the launcher streams the engine's status line,
  and Ctrl+C stops it. The logon task hides the window with -WindowStyle Hidden.
#>
[CmdletBinding()]
param([switch]$Clean)

$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = 'C:\Python313\python.exe'
if (-not (Test-Path $python)) { throw "Python not found at $python" }

Push-Location $root
try {
  if ($Clean) { Remove-Item build, dist -Recurse -Force -ErrorAction SilentlyContinue }

  Write-Host 'Building PrivateFirewall.exe (PyInstaller --onefile --windowed)...' -ForegroundColor Cyan
  # NB: --specpath changes how a relative --add-data source resolves, so the
  # source path must be absolute here.
  $dash = Join-Path $root 'pfw\dashboard.html'
  # --windowed (no console): this is a background tray app, so it must NOT open
  # a console window that the user could close (which would kill the engine).
  # server.py redirects the now-None stdout/stderr so print() stays safe.
  # tray is imported lazily inside main(); name it explicitly so PyInstaller
  # bundles it (lazy imports can otherwise be missed).
  & $python -m PyInstaller --noconfirm --onefile --windowed `
      --name PrivateFirewall `
      --add-data "$dash;." `
      --hidden-import tray --hidden-import config `
      --paths "pfw" `
      --distpath dist --workpath build --specpath build `
      "pfw\server.py"
  if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit $LASTEXITCODE)" }

  $exe = Join-Path $root 'dist\PrivateFirewall.exe'
  if (-not (Test-Path $exe)) { throw 'Build reported success but dist\PrivateFirewall.exe is missing.' }
  $sz = [math]::Round((Get-Item $exe).Length / 1MB, 1)
  Write-Host "Built: $exe  (${sz} MB)" -ForegroundColor Green
}
finally { Pop-Location }
