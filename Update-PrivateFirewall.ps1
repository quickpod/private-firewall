<#
.SYNOPSIS
  Update PrivateFirewall to the latest version.

.DESCRIPTION
  Run from the source checkout. The updater:
    1. fetches the latest source (git pull if this is a git working tree and
       -NoPull was not given; otherwise uses the source as-is),
    2. rebuilds dist\PrivateFirewall.exe (unless -SkipBuild),
    3. re-runs Setup-PrivateFirewall.ps1 -Install, which is a repair+update:
       it overwrites the installed files, refreshes shortcuts / task / Defender
       exclusion, and PRESERVES existing settings (autostart stays on if the
       logon task exists; lockdown is never disarmed by an install).

  Because the install step preserves the logon task and never touches the boot
  lockdown, an update keeps your enforcement posture. The running tray is
  stopped and relaunched on the new build automatically.

  Version state lives in the "Add or remove programs" entry, so the updater can
  report the before/after version.

.PARAMETER NoPull     Do not run git pull; build+install the current source.
.PARAMETER SkipBuild  Do not rebuild the exe; install whatever is in dist\ (or
                      source mode if dist\ is empty).
.PARAMETER Force      Reinstall even if the installed version already matches.
#>
[CmdletBinding()]
param(
  [switch]$NoPull,
  [switch]$SkipBuild,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$setup     = Join-Path $root 'Setup-PrivateFirewall.ps1'
$build     = Join-Path $root 'Build-PrivateFirewall.ps1'
$UninstKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PrivateFirewall'

if (-not (Test-Path $setup)) { throw "Setup-PrivateFirewall.ps1 not found next to this updater." }

function Get-Meta($script) {
  # read the $ver literal from Setup so we know the version we're moving TO
  $m = Select-String -Path $script -Pattern "^\s*\`$ver\s*=\s*'([\d.]+)'" |
       Select-Object -First 1
  if ($m) { $m.Matches[0].Groups[1].Value } else { 'unknown' }
}

$installed = (Get-ItemProperty $UninstKey -ErrorAction SilentlyContinue).DisplayVersion
$target    = Get-Meta $setup
Write-Host "PrivateFirewall updater" -ForegroundColor Cyan
Write-Host "  installed: $(if($installed){$installed}else{'(not installed)'})"
Write-Host "  source:    $target"

# 1. pull latest source ------------------------------------------------------
if (-not $NoPull -and (Test-Path (Join-Path $root '.git'))) {
  $git = (Get-Command git -ErrorAction SilentlyContinue).Source
  if ($git) {
    Write-Host 'Pulling latest source (git pull)...' -ForegroundColor Cyan
    Push-Location $root
    try {
      $before = (& $git rev-parse HEAD).Trim()
      & $git pull --ff-only 2>&1 | Write-Host
      $after  = (& $git rev-parse HEAD).Trim()
      if ($before -eq $after) { Write-Host 'Already at the latest commit.' -ForegroundColor Gray }
      else { Write-Host "Updated source $($before.Substring(0,7)) -> $($after.Substring(0,7))." -ForegroundColor Green }
      $target = Get-Meta $setup   # re-read: pull may have bumped the version
    } finally { Pop-Location }
  } else { Write-Host 'git not on PATH; skipping pull.' -ForegroundColor Yellow }
} elseif (-not $NoPull) {
  Write-Host 'Not a git checkout; using local source as-is.' -ForegroundColor Gray
}

if ($installed -and $installed -eq $target -and -not $Force) {
  Write-Host "Already up to date at $installed. Use -Force to reinstall anyway." -ForegroundColor Green
  return
}

# 2. rebuild the exe ---------------------------------------------------------
if (-not $SkipBuild) {
  if (-not (Test-Path 'C:\Python313\python.exe')) {
    Write-Host 'Python missing at C:\Python313 - cannot rebuild; will install source mode.' -ForegroundColor Yellow
  } else {
    Write-Host 'Rebuilding PrivateFirewall.exe...' -ForegroundColor Cyan
    & $build -Clean
  }
}

# 3. repair+update install (preserves settings; self-elevates) ---------------
Write-Host 'Installing the update...' -ForegroundColor Cyan
& $setup -Install

Write-Host ''
Write-Host "Update complete -> $target." -ForegroundColor Green
