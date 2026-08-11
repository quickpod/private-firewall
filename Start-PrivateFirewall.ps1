<#
.SYNOPSIS
  Launch the PrivateFirewall engine (elevated) and open the dashboard.

.DESCRIPTION
  PrivateFirewall is a user-mode control plane ON TOP OF Windows Firewall (WFP).
  It never re-routes packets: WFP stays the kernel entry point for all wired and
  wireless traffic, so if this process dies the configured firewall policy keeps
  enforcing (fail-open by design). The engine adds a live dashboard, a kill
  switch, dynamic block/allow rules (in the 'PrivateFirewall' rule group), and an
  intrusion/anomaly alert engine.

  This launcher:
    * enables firewall connection-drop logging so the blocked-connection feed and
      port-scan / brute-force alerts have data (saved-state captured for revert),
    * self-elevates (kill/block/lockdown need admin),
    * starts the Python engine bound to 127.0.0.1 with a random token,
    * opens the token URL in the default browser.

  Undo everything with:  .\Revert-PrivateFirewall.ps1 -Revert

.PARAMETER NoLog
  Skip enabling firewall drop-logging (leave Windows Firewall logging untouched).
.PARAMETER NoBrowser
  Start the engine but do not open the dashboard.
.PARAMETER Port
  TCP port for the localhost dashboard (default 58730).
#>
[CmdletBinding()]
param(
  [switch]$NoLog,
  [switch]$NoBrowser,
  [switch]$Tray,        # run with a system-tray icon instead of a console
  [int]$Port = 58730
)

$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = 'C:\Python313\python.exe'   # not on PATH; the store stub is not Python
$server = Join-Path $root 'pfw\server.py'
$backup = Join-Path $root 'Backups'

# Prefer the frozen exe (installed next to this script, or ./dist from a build);
# fall back to running the source with Python.
$exe = @(
  (Join-Path $root 'PrivateFirewall.exe'),
  (Join-Path $root 'dist\PrivateFirewall.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $exe) {
  if (-not (Test-Path $python)) {
    throw "No PrivateFirewall.exe found and Python is missing at $python. Build with Build-PrivateFirewall.ps1 or install Python."
  }
  if (-not (Test-Path $server)) { throw "Engine not found at $server" }
}

# ---- self-elevate ---------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if (-not $isAdmin) {
  Write-Host 'Elevation required for kill / block / lockdown controls. Relaunching...'
  $argline = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",
               '-Port',$Port)
  if ($NoLog)     { $argline += '-NoLog' }
  if ($NoBrowser) { $argline += '-NoBrowser' }
  if ($Tray)      { $argline += '-Tray' }
  Start-Process powershell -Verb RunAs -ArgumentList $argline
  return
}

# ---- enable firewall drop-logging (save prior state first) ----------------
if (-not $NoLog) {
  New-Item -ItemType Directory -Force -Path $backup | Out-Null
  $stateFile = Join-Path $backup 'firewall-logging.json'
  if (-not (Test-Path $stateFile)) {
    Get-NetFirewallProfile -All |
      Select-Object Name, LogBlocked, LogFileName, LogMaxSizeKilobytes |
      ConvertTo-Json | Set-Content -Encoding UTF8 $stateFile
    Write-Host "Saved prior firewall-logging state -> $stateFile"
  }
  Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 8192
  Write-Host 'Firewall drop-logging enabled (blocked-connection feed + scan alerts).'
}

# ---- launch engine --------------------------------------------------------
$token = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 28 | ForEach-Object {[char]$_})
$env:PFW_TOKEN = $token
$env:PFW_PORT  = "$Port"

Write-Host ''
Write-Host 'Starting PrivateFirewall engine (admin)...' -ForegroundColor Green
Write-Host "  Dashboard: http://127.0.0.1:$Port/#t=$token"
Write-Host '  Ctrl+C in this window stops the engine (firewall policy stays in force).'
Write-Host ''

$engineArgs = @()
if (-not $NoBrowser) { $engineArgs += '--open' }
if ($Tray)          { $engineArgs += '--tray' }
if ($exe) {
  Write-Host "  (engine: $exe $engineArgs)"
  & $exe @engineArgs
} else {
  Write-Host "  (engine: $python $server $engineArgs)"
  & $python $server @engineArgs
}
