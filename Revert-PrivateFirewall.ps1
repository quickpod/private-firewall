<#
.SYNOPSIS
  Read-only status (no switch) / -Apply (arm logging) / -Revert (undo everything).

.DESCRIPTION
  Single-script convention: -Apply / -Revert / no-switch = status.
  no-switch status, SupportsShouldProcess for -WhatIf. -Revert needs no network,
  no downloads, and falls back to known-good defaults if the saved-state file is
  missing.

  What PrivateFirewall changes on the system, and what -Revert restores:
    1. All dynamic block/allow rules live in the Windows Firewall rule group
       'PrivateFirewall'. -Revert deletes the entire group in one call.
    2. Outbound lockdown sets DefaultOutboundAction=Block on all profiles.
       -Revert restores DefaultOutboundAction=Allow (the Windows default), so
       even a missing state file cannot leave outbound traffic cut off.
    3. Drop-logging (LogBlocked) is restored from Backups\firewall-logging.json
       when present, otherwise to the Windows default (LogBlocked=False).

  The engine itself is just a localhost Python process - closing its console
  window stops it and changes no system state, so it is not part of revert.

.PARAMETER Apply
  (Re)enable firewall drop-logging without launching the engine.
.PARAMETER Revert
  Remove all PrivateFirewall firewall rules, clear outbound lockdown, and restore
  drop-logging to its saved (or default) state.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
  [switch]$Apply,
  [switch]$Revert,
  [switch]$Uninstall   # with -Revert: also remove the logon auto-start task
)

$ErrorActionPreference = 'Stop'
$root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$group     = 'PrivateFirewall'
$task      = 'PrivateFirewall Engine'
$stateFile = Join-Path $root 'Backups\firewall-logging.json'

function Get-PfwRules {
  Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue
}

function Show-Status {
  Write-Host "== PrivateFirewall status ==" -ForegroundColor Cyan
  $rules = @(Get-PfwRules)
  Write-Host ("Dynamic rules in group '{0}': {1}" -f $group, $rules.Count)
  foreach ($r in $rules) {
    $af = $r | Get-NetFirewallAddressFilter
    $ap = $r | Get-NetFirewallApplicationFilter
    $target = if ($af.RemoteAddress -and $af.RemoteAddress -ne 'Any') { $af.RemoteAddress -join ',' }
              elseif ($ap.Program) { $ap.Program } else { 'any' }
    Write-Host ("  [{0}] {1} {2} -> {3}" -f $r.Action, $r.Direction, $r.DisplayName, $target)
  }
  Write-Host ''
  Get-NetFirewallProfile -All |
    Select-Object Name,
      @{n='OutboundDefault';e={$_.DefaultOutboundAction}},
      @{n='LogBlocked';e={$_.LogBlocked}},
      @{n='LogFile';e={[Environment]::ExpandEnvironmentVariables($_.LogFileName)}} |
    Format-Table -AutoSize
  $anyLock = (Get-NetFirewallProfile -All |
              Where-Object { $_.DefaultOutboundAction -eq 'Block' }).Count
  if ($anyLock) { Write-Host "LOCKDOWN ACTIVE on $anyLock profile(s)." -ForegroundColor Yellow }
  if (Test-Path $stateFile) { Write-Host "Saved logging state: $stateFile" }
}

function Test-Admin {
  ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ($Apply) {
  if (-not (Test-Admin)) { throw 'Run elevated to change firewall logging.' }
  if ($PSCmdlet.ShouldProcess('Windows Firewall', 'Enable drop-logging')) {
    New-Item -ItemType Directory -Force -Path (Split-Path $stateFile) | Out-Null
    if (-not (Test-Path $stateFile)) {
      Get-NetFirewallProfile -All |
        Select-Object Name, LogBlocked, LogFileName, LogMaxSizeKilobytes |
        ConvertTo-Json | Set-Content -Encoding UTF8 $stateFile
    }
    Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 8192
    Write-Host 'Drop-logging enabled.' -ForegroundColor Green
  }
  return
}

if ($Revert) {
  if (-not (Test-Admin)) { throw 'Run elevated to revert firewall changes.' }

  # 1. delete the whole rule group
  $rules = @(Get-PfwRules)
  if ($rules.Count -and $PSCmdlet.ShouldProcess("$($rules.Count) rule(s) in '$group'", 'Remove')) {
    Remove-NetFirewallRule -Group $group
    Write-Host "Removed $($rules.Count) PrivateFirewall rule(s)." -ForegroundColor Green
  } else { Write-Host 'No PrivateFirewall rules to remove.' }

  # 2. clear outbound lockdown -> Windows default (Allow). Unconditional:
  #    never leave the machine with outbound blocked, state file or not.
  if ($PSCmdlet.ShouldProcess('All firewall profiles', 'DefaultOutboundAction = Allow')) {
    Set-NetFirewallProfile -All -DefaultOutboundAction Allow
    Write-Host 'Outbound policy restored to Allow (lockdown cleared).' -ForegroundColor Green
  }

  # 3. restore drop-logging from saved state, else Windows default (off)
  if ($PSCmdlet.ShouldProcess('All firewall profiles', 'Restore drop-logging')) {
    if (Test-Path $stateFile) {
      $saved = Get-Content $stateFile -Raw | ConvertFrom-Json
      foreach ($p in $saved) {
        Set-NetFirewallProfile -Name $p.Name -LogBlocked ([bool]$p.LogBlocked)
      }
      Write-Host 'Drop-logging restored from saved state.' -ForegroundColor Green
    } else {
      Set-NetFirewallProfile -All -LogBlocked False
      Write-Host 'No saved state; drop-logging set to Windows default (off).' -ForegroundColor Yellow
    }
  }
  # 4. re-enable IPv6 in case the "block all IPv6" toggle unbound it
  if ($PSCmdlet.ShouldProcess('All adapters', 'Re-enable IPv6 binding')) {
    Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    Write-Host 'IPv6 binding restored on all adapters.' -ForegroundColor Green
  }

  # 5. optional: remove the logon auto-start task
  if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
      if ($PSCmdlet.ShouldProcess("Scheduled task '$task'", 'Unregister')) {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
        Write-Host "Removed logon task '$task'." -ForegroundColor Green
      }
    } else { Write-Host "No '$task' logon task present." }
  }

  Write-Host ''
  Write-Host 'Revert complete. WFP remains the traffic entry point with stock policy.'
  return
}

# status view also reports the logon task
if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
  Write-Host "Logon auto-start task '$task': REGISTERED" -ForegroundColor Yellow
}
Show-Status
