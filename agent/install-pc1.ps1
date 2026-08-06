<#
  PC1 bootstrap. Run once from an elevated PowerShell prompt:

    .\install-pc1.ps1 -VdsPublicKey "ssh-ed25519 AAAA... safe-connect" -VdsTailnetIp 100.64.0.5

  Leaves RDP disabled. The bot enables it per session.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VdsPublicKey,
    [Parameter(Mandatory = $true)][string]$VdsTailnetIp,
    [string]$InstallDir = 'C:\ProgramData\SafeConnect'
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell prompt.'
}

Write-Output '==> OpenSSH Server'
$capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $capability.Name | Out-Null
}
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

Write-Output '==> agent'
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot 'agent.ps1') -Destination $InstallDir -Force
@{ vds_tailnet_ip = $VdsTailnetIp } | ConvertTo-Json |
    Set-Content -Path (Join-Path $InstallDir 'agent.config.json') -Encoding ASCII

Write-Output '==> locking down the agent so a low-privilege foothold cannot rewrite it'
icacls $InstallDir /inheritance:r /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' | Out-Null

Write-Output '==> forced-command key'
# NOTE: `(& ssh -V) 2>&1` would merge sshd's version banner (written to stderr) into the
# output pipeline. On Windows PowerShell 5.1 that merge turns each stderr line into a
# non-terminating ErrorRecord, which -- under $ErrorActionPreference = 'Stop' above --
# is promoted to a *terminating* exception and aborts the script right here, every time.
# Route through cmd.exe instead: it collapses stdout+stderr into plain text before
# PowerShell ever sees it, so no ErrorRecord is created and Stop can't fire on it.
$sshdVersion = cmd /c 'ssh -V 2>&1'
$restrict = if ($sshdVersion -match 'OpenSSH_(\d+)\.(\d+)' -and
                ([int]$Matches[1] -gt 7 -or ([int]$Matches[1] -eq 7 -and [int]$Matches[2] -ge 2))) {
    'restrict'
} else {
    'no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc'
}

$agentPath = Join-Path $InstallDir 'agent.ps1'
$forced = "$restrict,command=`"powershell.exe -NoProfile -ExecutionPolicy Bypass -File $agentPath`" $VdsPublicKey"

$keyFile = 'C:\ProgramData\ssh\administrators_authorized_keys'
# @() around both Get-Content and the Where-Object result is load-bearing: PowerShell
# unwraps a one-element pipeline result to a bare scalar string. Without the @() coercion,
# a file with exactly one surviving line turns "$kept + $forced" into *string*
# concatenation instead of array-append, silently splicing two authorized_keys entries
# onto a single garbled line (and losing whichever key didn't win the splice) on re-run.
$existing = if (Test-Path $keyFile) { @(Get-Content $keyFile) } else { @() }
$keyBody = ($VdsPublicKey -split '\s+')[1]
$kept = @($existing | Where-Object { $_ -notmatch [regex]::Escape($keyBody) })
Set-Content -Path $keyFile -Value ($kept + $forced) -Encoding ASCII

icacls $keyFile /inheritance:r /grant 'SYSTEM:F' /grant 'Administrators:F' | Out-Null

Write-Output '==> making sure RDP starts disabled'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name 'fDenyTSConnections' -Value 1 -Type DWord
$rule = Get-NetFirewallRule -DisplayName 'SafeConnect-RDP-In' -ErrorAction SilentlyContinue
if ($rule) { Set-NetFirewallRule -DisplayName 'SafeConnect-RDP-In' -Enabled False | Out-Null }

Write-Output '==> requiring NLA'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name 'UserAuthentication' -Value 1 -Type DWord

Write-Output '==> account lockout policy (5 attempts, 15 minutes)'
& net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null

Write-Output '==> enabling logon auditing so /rdp_off can report sessions'
& auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null

Restart-Service sshd
Write-Output ''
Write-Output 'Done. RDP is disabled; the bot will enable it per session.'
Write-Output 'Verify from the VDS with:'
Write-Output "  sudo -u safeconnect ssh -i /var/lib/safe-connect/id_ed25519 <user>@<pc1-tailnet-ip> status"
