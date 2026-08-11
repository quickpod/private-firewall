<#
.SYNOPSIS
  Install boot-time enforcement + auto-start for PrivateFirewall.

.DESCRIPTION
  IMPORTANT - how "enforce before any outbound connection" actually works.

  A user-mode program (the Python engine, the dashboard) can NEVER be the packet
  entry point, and can never guarantee it runs before every app's first outbound
  connection. That guarantee belongs to the Windows Filtering Platform (WFP) in
  the kernel, driven by the Base Filtering Engine (BFE) service, which loads the
  PERSISTENT firewall policy from the registry very early in boot - before the
  user logs on and before any user application runs.

  So the way to make PrivateFirewall's policy take effect before any outbound
  connection is to write it into that persistent store. That is what
  -BootLockdown does:

    * DefaultOutboundAction = Block on all profiles, in the PERSISTENT store,
    * a starter allowlist (in the 'PrivateFirewall' rule group) for the services
      that must work for the network itself to come up: DNS cache (incl. the DoH
      chain), DHCP, NLA/NCSI connectivity checks, NTP, and core Windows Update.

  After a reboot the machine comes up default-deny-outbound with only those
  allowed - enforced by the kernel, with the dashboard not yet running. The
  engine is then just the monitor + control plane you use to allow more apps.

  -Startup registers a scheduled task that launches the engine + dashboard at
  logon (elevated, so kill/block/lockdown work). It does NOT gate traffic; the
  persistent WFP policy already does.

  Undo both with:  .\Revert-PrivateFirewall.ps1 -Revert -Uninstall

.PARAMETER Startup
  Register a logon scheduled task 'PrivateFirewall Engine' that auto-starts the
  engine elevated and opens the dashboard.
.PARAMETER BootLockdown
  Write a persistent default-deny-outbound baseline + starter allowlist, enforced
  by WFP at boot before any app connects.
.PARAMETER AllowService
  Extra Windows service short-names to allow outbound in the boot baseline
  (e.g. -AllowService wuauserv,BITS). Optional.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
  [switch]$Startup,
  [switch]$BootLockdown,
  [string[]]$AllowService = @()
)

$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $MyInvocation.MyCommand.Path
$group = 'PrivateFirewall'
$task  = 'PrivateFirewall Engine'

function Test-Admin {
  ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-not (Test-Admin)) { throw 'Run this installer elevated (right-click > Run as administrator).' }
if (-not ($Startup -or $BootLockdown)) {
  Write-Host 'Nothing to do. Pass -Startup and/or -BootLockdown.' -ForegroundColor Yellow
  return
}

# --- persistent default-deny-outbound baseline (enforced by WFP at boot) -----
if ($BootLockdown) {
  if ($PSCmdlet.ShouldProcess('Windows Firewall (persistent store)',
        'Write default-deny-outbound baseline + starter allowlist')) {

    # starter allowlist FIRST, so denying the default never strands the box
    $core = @(
      @{ n='PFW Core DNS';         svc='Dnscache' },
      @{ n='PFW Core DHCP';        svc='Dhcp'     },
      @{ n='PFW Core DHCPv6';      svc='Dhcp'     },
      @{ n='PFW Core NLA';         svc='NlaSvc'   },   # network location / NCSI
      @{ n='PFW Core Connectivity';svc='NcaSvc'   },
      @{ n='PFW Core Time';        svc='W32Time'  }
    )
    foreach ($c in $core) {
      if (-not (Get-NetFirewallRule -DisplayName $c.n -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $c.n -Group $group -Direction Outbound `
          -Action Allow -Service $c.svc -Profile Any | Out-Null
      }
    }
    foreach ($svc in $AllowService) {
      $n = "PFW Allow svc $svc"
      if (-not (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $n -Group $group -Direction Outbound `
          -Action Allow -Service $svc -Profile Any | Out-Null
      }
    }
    # core networking (DHCP/DNS/ICMPv6 ND) that Windows ships pre-authored
    Enable-NetFirewallRule -Group '@FirewallAPI.dll,-25000' -ErrorAction SilentlyContinue

    # now flip the default. The setting lives in the persistent store and is
    # applied by BFE at boot -> enforced before any user app connects outbound.
    Set-NetFirewallProfile -All -DefaultOutboundAction Block
    Write-Host 'Boot lockdown armed: persistent default-deny outbound + starter allowlist.' -ForegroundColor Green
    Write-Host 'Allow more apps from the dashboard, or: New-NetFirewallRule ... -Group PrivateFirewall -Action Allow' -ForegroundColor Gray
  }
}

# --- logon auto-start task for the engine/dashboard (tray mode) --------------
if ($Startup) {
  if ($PSCmdlet.ShouldProcess("Scheduled task '$task'", 'Register at logon')) {
    # launch the engine directly in tray mode; prefer the installed/built exe,
    # fall back to pythonw (no console). RunLevel Highest = no UAC at logon.
    $exe = @((Join-Path $root 'PrivateFirewall.exe'),
             (Join-Path $root 'dist\PrivateFirewall.exe')) |
           Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($exe) {
      $action = New-ScheduledTaskAction -Execute $exe -Argument '--tray'
    } else {
      $pyw = if (Test-Path 'C:\Python313\pythonw.exe') { 'C:\Python313\pythonw.exe' } else { 'C:\Python313\python.exe' }
      $action = New-ScheduledTaskAction -Execute $pyw `
        -Argument "`"$root\pfw\server.py`" --tray"
    }
    # Trigger at logon, then a watchdog: repeat every 5 min forever. The engine
    # runs as the task, so while it lives the task is "running" and repetitions
    # are ignored; if it ever exits/crashes, the next repetition relaunches it
    # (the single-instance mutex makes a redundant launch harmless). This is
    # what makes it "permanently resident unless uninstalled."
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    # Omit RepetitionDuration => repeat indefinitely. ([TimeSpan]::MaxValue
    # serializes to P99999999D which Task Scheduler rejects as out of range.)
    $rep = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
              -RepetitionInterval (New-TimeSpan -Minutes 5)).Repetition
    $trigger.Repetition = $rep
    $principal= New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
      -LogonType Interactive -RunLevel Highest
    # no time limit (don't let Task Scheduler kill a long-running engine),
    # restart on failure, and never spawn a duplicate instance.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
      -DontStopIfGoingOnBatteries -StartWhenAvailable `
      -ExecutionTimeLimit ([TimeSpan]::Zero) `
      -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
      -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger `
      -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "Registered logon task '$task' (auto-start + 5-min watchdog, elevated)." -ForegroundColor Green
  }
}

Write-Host ''
Write-Host 'Install complete.' -ForegroundColor Cyan
Write-Host 'Reboot to confirm the boot policy is enforced before logon (Revert-PrivateFirewall.ps1 shows status).'
