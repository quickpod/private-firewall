<#
.SYNOPSIS
  Installer / uninstaller for PrivateFirewall.

.DESCRIPTION
  Installs PrivateFirewall as a proper Windows application:
    * copies the app to  C:\Program Files\PrivateFirewall  (the frozen exe if
      present, otherwise the Python source + scripts),
    * creates Start Menu (and optionally desktop) shortcuts to the launcher,
    * registers an "Add or remove programs" entry that calls this script
      -Uninstall,
    * enables Windows Firewall drop-logging (so scan/brute-force alerts work),
      saving prior state for revert,
    * optionally registers a logon auto-start task (-Startup) and/or arms the
      boot-persistent default-deny-outbound policy (-BootLockdown).

  Runtime state (logs, saved firewall state) lives under
  C:\ProgramData\PrivateFirewall - never in Program Files.

  Self-elevates. Idempotent: re-running -Install refreshes files and shortcuts.

  Uninstall reverses everything:
    .\Setup-PrivateFirewall.ps1 -Uninstall
  which stops the engine, removes shortcuts + task + ARP entry, deletes the
  PrivateFirewall firewall rules, clears any lockdown, restores logging, and
  deletes the install directory. It does NOT delete C:\ProgramData logs unless
  -PurgeData is given.

.PARAMETER Install       Install (default action if no switch given).
.PARAMETER Uninstall     Remove the application and all its system changes.
.PARAMETER Startup       Also register the logon auto-start task.
.PARAMETER BootLockdown  Also arm persistent default-deny-outbound at boot.
.PARAMETER Desktop       Also create a desktop shortcut.
.PARAMETER PurgeData     (with -Uninstall) also delete C:\ProgramData\PrivateFirewall.
.PARAMETER InstallDir    Override install location (default: Program Files\PrivateFirewall).
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName='Install')]
param(
  [Parameter(ParameterSetName='Install')][switch]$Install,
  [Parameter(ParameterSetName='Uninstall')][switch]$Uninstall,
  [Parameter(ParameterSetName='Install')][switch]$Startup,
  [Parameter(ParameterSetName='Install')][switch]$NoStartup,   # opt out of autostart
  [Parameter(ParameterSetName='Install')][switch]$NoLaunch,    # don't start the tray now
  [Parameter(ParameterSetName='Install')][switch]$BootLockdown,
  [Parameter(ParameterSetName='Install')][switch]$Desktop,
  [Parameter(ParameterSetName='Uninstall')][switch]$PurgeData,
  [string]$InstallDir = (Join-Path $env:ProgramFiles 'PrivateFirewall')
)

$ErrorActionPreference = 'Stop'
$src        = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppName    = 'PrivateFirewall'
$DataDir    = Join-Path $env:ProgramData 'PrivateFirewall'
$TaskName   = 'PrivateFirewall Engine'
$UninstKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PrivateFirewall'
$StartMenu  = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
$DesktopDir = [Environment]::GetFolderPath('CommonDesktopDirectory')

# ---- self-elevate ---------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
  Write-Host 'Installer needs administrator rights. Relaunching elevated...'
  $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
  foreach ($kv in $PSBoundParameters.GetEnumerator()) {
    if ($kv.Value -is [switch]) { if ($kv.Value) { $a += "-$($kv.Key)" } }
    else { $a += "-$($kv.Key)"; $a += "`"$($kv.Value)`"" }
  }
  Start-Process powershell -Verb RunAs -ArgumentList $a
  return
}

function New-Shortcut($lnkPath, $target, $arguments, $iconPath, $desc) {
  $ws = New-Object -ComObject WScript.Shell
  $s  = $ws.CreateShortcut($lnkPath)
  $s.TargetPath       = $target
  $s.Arguments        = $arguments
  $s.WorkingDirectory = Split-Path $target
  if ($iconPath) { $s.IconLocation = $iconPath }
  $s.Description      = $desc
  $s.Save()
  # set the "run as administrator" bit (byte 21, 0x20) so the shortcut elevates
  $bytes = [IO.File]::ReadAllBytes($lnkPath)
  $bytes[0x15] = $bytes[0x15] -bor 0x20
  [IO.File]::WriteAllBytes($lnkPath, $bytes)
}

function Add-DefenderExclusions($dir, $exeName) {
  # A self-built PyInstaller network tool that authors firewall rules commonly
  # trips Defender heuristics. Scope the exclusion tightly: the install dir and
  # the engine process only - NOT ProgramData or any broad path. Uninstall
  # removes both so no exclusion is left behind.
  try {
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
      Write-Host 'Defender cmdlets unavailable; skipping exclusions.' -ForegroundColor Gray
      return
    }
    Add-MpPreference -ExclusionPath $dir -ErrorAction Stop
    if ($exeName) { Add-MpPreference -ExclusionProcess $exeName -ErrorAction SilentlyContinue }
    Write-Host "Defender exclusion added: $dir  (+ process $exeName)" -ForegroundColor Green
  } catch {
    Write-Host "Could not add Defender exclusion ($($_.Exception.Message)). If Defender is managed by policy, add it manually." -ForegroundColor Yellow
  }
}

function Remove-DefenderExclusions($dir, $exeName) {
  try {
    if (-not (Get-Command Remove-MpPreference -ErrorAction SilentlyContinue)) { return }
    Remove-MpPreference -ExclusionPath $dir -ErrorAction SilentlyContinue
    if ($exeName) { Remove-MpPreference -ExclusionProcess $exeName -ErrorAction SilentlyContinue }
    Write-Host 'Defender exclusions removed.' -ForegroundColor Green
  } catch { }
}

function Stop-Engine {
  Get-CimInstance Win32_Process -Filter "Name='PrivateFirewall.exe'" -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  # source-mode engine: python running server.py
  Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'server\.py' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

# ==========================================================================
# UNINSTALL
# ==========================================================================
if ($Uninstall) {
  Write-Host "Uninstalling $AppName (removing all traces)..." -ForegroundColor Cyan
  Stop-Engine
  Start-Sleep -Milliseconds 400   # release file handles before deleting files

  # 1. firewall rules + lockdown + logging + task, via the revert script
  $revert = Join-Path $InstallDir 'Revert-PrivateFirewall.ps1'
  if (-not (Test-Path $revert)) { $revert = Join-Path $src 'Revert-PrivateFirewall.ps1' }
  if (Test-Path $revert) {
    if ($PSCmdlet.ShouldProcess('firewall rules / lockdown / logging / task', 'Revert')) {
      & $revert -Revert -Uninstall
    }
  } else {
    Remove-NetFirewallRule -Group $AppName -ErrorAction SilentlyContinue
    Set-NetFirewallProfile -All -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
    Set-NetFirewallProfile -All -LogBlocked False -ErrorAction SilentlyContinue
  }
  # belt-and-braces: ensure the task is gone even if revert wasn't available
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

  # 2. Defender exclusions
  Remove-DefenderExclusions $InstallDir 'PrivateFirewall.exe'

  # 3. shortcuts
  Remove-Item (Join-Path $StartMenu "$AppName.lnk") -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $DesktopDir "$AppName.lnk") -ErrorAction SilentlyContinue

  # 4. machine env var + Add/Remove Programs entry
  [Environment]::SetEnvironmentVariable('PFW_LOG_DIR', $null, 'Machine')
  Remove-Item $UninstKey -Recurse -ErrorAction SilentlyContinue

  # 5. install directory
  if (Test-Path $InstallDir) {
    if ($PSCmdlet.ShouldProcess($InstallDir, 'Delete install directory')) {
      Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  # 6. runtime data (logs, saved state) - kept unless -PurgeData
  if ($PurgeData -and (Test-Path $DataDir)) {
    if ($PSCmdlet.ShouldProcess($DataDir, 'Delete runtime data (logs)')) {
      Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    }
  } elseif (Test-Path $DataDir) {
    Write-Host "Kept audit logs at $DataDir (use -PurgeData to remove them too)." -ForegroundColor Gray
  }

  # 7. report anything that survived
  $left = @()
  if (Test-Path $InstallDir) { $left += "dir: $InstallDir" }
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $left += "task: $TaskName" }
  if (@(Get-NetFirewallRule -Group $AppName -ErrorAction SilentlyContinue).Count) { $left += 'firewall rules' }
  if (Test-Path $UninstKey) { $left += 'ARP entry' }
  if ($left.Count) {
    Write-Host "Some items could not be removed (in use?): $($left -join '; ')" -ForegroundColor Yellow
    Write-Host 'Close the tray/dashboard and re-run -Uninstall.' -ForegroundColor Yellow
  } else {
    Write-Host "$AppName fully uninstalled - no traces remain." -ForegroundColor Green
  }
  return
}

# ==========================================================================
# INSTALL  (re-running is a repair + update: overwrites files, refreshes
#           shortcuts / task / Defender exclusion, preserves prior settings)
# ==========================================================================
$ver      = '1.1.0'
$existing = Get-ItemProperty $UninstKey -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "Updating/repairing $AppName ($($existing.DisplayVersion) -> $ver) in $InstallDir" -ForegroundColor Cyan
} else {
  Write-Host "Installing $AppName $ver to $InstallDir" -ForegroundColor Cyan
}

$builtExe = Join-Path $src 'dist\PrivateFirewall.exe'
$useExe   = Test-Path $builtExe
if (-not $useExe) {
  if (-not (Test-Path 'C:\Python313\python.exe')) {
    throw "No dist\PrivateFilewall.exe and Python missing. Run Build-PrivateFirewall.ps1 first, or install Python at C:\Python313."
  }
  Write-Host 'No frozen exe found - installing source mode (needs C:\Python313\python.exe at runtime).' -ForegroundColor Yellow
}

# autostart at logon is ON by default (this is a persistent tray app); -NoStartup
# opts out. A repair/update also keeps it if the task already exists.
if (-not $NoStartup) { $Startup = $true }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $Startup = $true }

Stop-Engine
Start-Sleep -Milliseconds 400   # let file handles release before overwrite
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir,
  (Join-Path $DataDir 'logs'), (Join-Path $InstallDir 'Backups') | Out-Null

# --- copy payload ----------------------------------------------------------
$scripts = 'Start-PrivateFirewall.ps1','Install-PrivateFirewall.ps1',
           'Revert-PrivateFirewall.ps1','README.md','FEATURES.md'
foreach ($f in $scripts) {
  Copy-Item (Join-Path $src $f) (Join-Path $InstallDir $f) -Force
}
if ($useExe) {
  Copy-Item $builtExe (Join-Path $InstallDir 'PrivateFirewall.exe') -Force
} else {
  New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'pfw') | Out-Null
  Copy-Item (Join-Path $src 'pfw\server.py')     (Join-Path $InstallDir 'pfw\server.py') -Force
  Copy-Item (Join-Path $src 'pfw\dashboard.html')(Join-Path $InstallDir 'pfw\dashboard.html') -Force
}
$iconSrc  = if ($useExe) { Join-Path $InstallDir 'PrivateFirewall.exe' } else { $null }

# engine should log to ProgramData regardless of install mode
[Environment]::SetEnvironmentVariable('PFW_LOG_DIR', (Join-Path $DataDir 'logs'), 'Machine')

# --- Windows Defender exclusions (scoped to the install dir + engine) -------
Add-DefenderExclusions $InstallDir 'PrivateFirewall.exe'

# --- shortcuts (launch the tray in the background, elevated via RunAs bit) ---
# Prefer the exe --tray; source mode uses pythonw.exe (no console).
if ($useExe) {
  $shortcutTarget = Join-Path $InstallDir 'PrivateFirewall.exe'
  $shortcutArgs   = '--tray'
} else {
  $pyw = 'C:\Python313\pythonw.exe'
  $shortcutTarget = if (Test-Path $pyw) { $pyw } else { 'C:\Python313\python.exe' }
  $shortcutArgs   = "`"$InstallDir\pfw\server.py`" --tray"
}
New-Shortcut (Join-Path $StartMenu "$AppName.lnk") $shortcutTarget $shortcutArgs $iconSrc `
  'Live firewall dashboard on top of Windows Firewall (tray)'
if ($Desktop) {
  New-Shortcut (Join-Path $DesktopDir "$AppName.lnk") $shortcutTarget $shortcutArgs $iconSrc `
    'Live firewall dashboard on top of Windows Firewall (tray)'
}

# --- Add or remove programs entry ------------------------------------------
New-Item -Path $UninstKey -Force | Out-Null
$uninstCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\Setup-PrivateFirewall.ps1`" -Uninstall"
Copy-Item $PSCommandPath (Join-Path $InstallDir 'Setup-PrivateFirewall.ps1') -Force
$size = [math]::Round(((Get-ChildItem $InstallDir -Recurse | Measure-Object Length -Sum).Sum)/1KB)
Set-ItemProperty $UninstKey DisplayName     "$AppName"
Set-ItemProperty $UninstKey DisplayVersion  $ver
Set-ItemProperty $UninstKey Publisher       'PrivateFirewall (self-built)'
Set-ItemProperty $UninstKey InstallLocation $InstallDir
Set-ItemProperty $UninstKey UninstallString $uninstCmd
Set-ItemProperty $UninstKey NoModify 1 -Type DWord
Set-ItemProperty $UninstKey NoRepair 1 -Type DWord
Set-ItemProperty $UninstKey EstimatedSize ([int]$size) -Type DWord
if ($iconSrc) { Set-ItemProperty $UninstKey DisplayIcon $iconSrc }

# --- firewall drop-logging (save prior state) ------------------------------
$stateFile = Join-Path $InstallDir 'Backups\firewall-logging.json'
if (-not (Test-Path $stateFile)) {
  Get-NetFirewallProfile -All |
    Select-Object Name, LogBlocked, LogFileName, LogMaxSizeKilobytes |
    ConvertTo-Json | Set-Content -Encoding UTF8 $stateFile
}
Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 8192
Write-Host 'Firewall drop-logging enabled.' -ForegroundColor Green

# --- logon auto-start watchdog task (registered inline for reliability) -----
if ($Startup) {
  # launch the engine in tray mode; prefer the installed exe, else pythonw.
  if ($useExe) {
    $taskAction = New-ScheduledTaskAction -Execute (Join-Path $InstallDir 'PrivateFirewall.exe') -Argument '--tray'
  } else {
    $pyw = if (Test-Path 'C:\Python313\pythonw.exe') { 'C:\Python313\pythonw.exe' } else { 'C:\Python313\python.exe' }
    $taskAction = New-ScheduledTaskAction -Execute $pyw -Argument "`"$InstallDir\pfw\server.py`" --tray"
  }
  # Trigger at logon + a 5-min repetition watchdog (omit RepetitionDuration =>
  # indefinite; [TimeSpan]::MaxValue serializes to an out-of-range P99999999D).
  # While the engine lives the task is "running" so repeats are ignored; if it
  # ever exits/crashes the next repeat relaunches it (mutex guards duplicates).
  $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
  $taskTrigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
      -RepetitionInterval (New-TimeSpan -Minutes 5)).Repetition
  $taskPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
      -LogonType Interactive -RunLevel Highest
  $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
      -DontStopIfGoingOnBatteries -StartWhenAvailable `
      -ExecutionTimeLimit ([TimeSpan]::Zero) `
      -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
      -MultipleInstances IgnoreNew
  try {
    Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $taskTrigger `
        -Principal $taskPrincipal -Settings $taskSettings -Force -ErrorAction Stop | Out-Null
    Write-Host "Registered logon watchdog task '$TaskName' (resident, restarts if it exits)." -ForegroundColor Green
  } catch {
    Write-Host "Could not register the logon task: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}
# boot lockdown still delegates to the boot installer
if ($BootLockdown) {
  & (Join-Path $InstallDir 'Install-PrivateFirewall.ps1') -BootLockdown
}

# --- start the tray now so the icon appears immediately ---------------------
# (always on a fresh install; on an update, restart if it had been running)
if (-not $NoLaunch) {
  if ($useExe) {
    Start-Process (Join-Path $InstallDir 'PrivateFirewall.exe') -ArgumentList '--tray'
  } else {
    $pyw = if (Test-Path 'C:\Python313\pythonw.exe') { 'C:\Python313\pythonw.exe' } else { 'C:\Python313\python.exe' }
    Start-Process $pyw -ArgumentList "`"$InstallDir\pfw\server.py`"", '--tray'
  }
  Start-Sleep -Milliseconds 800
  $now = @(Get-CimInstance Win32_Process -Filter "Name='PrivateFirewall.exe'" -ErrorAction SilentlyContinue) +
         @(Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue |
             Where-Object { $_.CommandLine -match 'server\.py' })
  if ($now.Count) { Write-Host 'Tray engine started.' -ForegroundColor Green }
  else { Write-Host 'Tray engine did not stay running - launch it from the Start Menu shortcut.' -ForegroundColor Yellow }
}

Write-Host ''
Write-Host "$AppName $ver $(if($existing){'updated'}else{'installed'})." -ForegroundColor Green
Write-Host "  App:  $InstallDir"
Write-Host "  Data: $DataDir"
Write-Host "  Autostart at logon: $(if($Startup){'ON'}else{'off'})   Boot lockdown: $(if($BootLockdown){'armed'}else{'not armed'})"
Write-Host ''
Write-Host '  A SHIELD ICON is now in the system tray. On Windows 11 new tray icons are' -ForegroundColor Cyan
Write-Host '  hidden by default: click the ^ chevron on the taskbar to see it, and drag it' -ForegroundColor Cyan
Write-Host '  onto the taskbar to keep it visible.' -ForegroundColor Cyan
Write-Host '  Double-click the icon for the dashboard; right-click for controls.'
