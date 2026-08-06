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

Write-Output '==> validating VdsPublicKey'
# Checked on the RAW value, before any Trim(): a newline anywhere -- leading, trailing, or
# embedded -- means Set-Content below would write more than one line to
# administrators_authorized_keys. A leading/trailing newline is an easy copy-paste slip
# (install-vds.sh prints the key for the operator to paste here), and the result is an
# UNRESTRICTED key line with no forced-command prefix: full admin SSH to this PC. Reject
# outright rather than trying to silently "fix" it by trimming newlines away.
if ($VdsPublicKey -match '[\r\n]') {
    throw ('VdsPublicKey contains a newline or carriage return, so it cannot be written as a ' +
        'single authorized_keys line. Paste exactly the one key line printed by ' +
        'install-vds.sh (starting with the key type, e.g. "ssh-ed25519 AAAA... safe-connect"), ' +
        'with no blank line before or after it.')
}
$VdsPublicKey = $VdsPublicKey.Trim()
if ($VdsPublicKey -notmatch '^\S+\s+[A-Za-z0-9+/]+=*(\s+\S.*)?$') {
    throw ("VdsPublicKey does not look like a single OpenSSH public key line " +
        "(expected '<type> <base64-body> [comment]', e.g. 'ssh-ed25519 AAAA... safe-connect'). " +
        "Got: '$VdsPublicKey'")
}

function Invoke-IcaclsOrThrow([string]$Description, [string[]]$IcaclsArgs) {
    # icacls is an external exe: a non-zero exit code is NOT promoted to a terminating
    # error by $ErrorActionPreference = 'Stop' on Windows PowerShell 5.1
    # ($PSNativeCommandUseErrorActionPreference doesn't exist there), so a failed icacls
    # would otherwise be silently swallowed by "| Out-Null" and the script would print
    # "Done" as though the lockdown succeeded. For $InstallDir specifically that fails
    # OPEN: agent.ps1 could stay writable by non-administrators.
    & icacls @IcaclsArgs | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed while $Description (exit code $LASTEXITCODE). Refusing to continue: this permission lockdown is a required security property."
    }
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

# *S-1-5-18 = SYSTEM, *S-1-5-32-544 = Administrators. These well-known SIDs are
# locale-independent; the readable names "SYSTEM" / "Administrators" are NOT -- on a
# Russian-locale Windows the built-in group is actually named "Администраторы", and icacls
# fails to resolve the English literal (exit 1332, "account could not be mapped"), which
# used to be swallowed silently and now (correctly) aborts the install. PC1 is a home PC
# and may well be installed in any language, so do NOT "clean this up" back to plain names
# -- that reintroduces the failure on every non-English Windows.
$SystemSid = '*S-1-5-18'
$AdministratorsSid = '*S-1-5-32-544'

Write-Output '==> locking down the agent so a low-privilege foothold cannot rewrite it'
Invoke-IcaclsOrThrow -Description 'locking down the agent install directory' -IcaclsArgs @(
    $InstallDir, '/inheritance:r', '/grant', "${SystemSid}:(OI)(CI)F", '/grant', "${AdministratorsSid}:(OI)(CI)F"
)

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
# Blank/whitespace-only lines are also dropped on every rebuild -- not just filtered by key
# body -- so any blank line (however it got there) is cleaned up rather than accumulating
# one more copy each time the script re-runs.
$existing = if (Test-Path $keyFile) { @(Get-Content $keyFile) } else { @() }
$keyBody = ($VdsPublicKey -split '\s+')[1]
$kept = @($existing | Where-Object { $_.Trim() -ne '' -and $_ -notmatch [regex]::Escape($keyBody) })
Set-Content -Path $keyFile -Value ($kept + $forced) -Encoding ASCII

Invoke-IcaclsOrThrow -Description 'locking down administrators_authorized_keys' -IcaclsArgs @(
    $keyFile, '/inheritance:r', '/grant', "${SystemSid}:F", '/grant', "${AdministratorsSid}:F"
)

Write-Output '==> making sure RDP starts disabled'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name 'fDenyTSConnections' -Value 1 -Type DWord
$rule = Get-NetFirewallRule -DisplayName 'SafeConnect-RDP-In' -ErrorAction SilentlyContinue
if ($rule) { Set-NetFirewallRule -DisplayName 'SafeConnect-RDP-In' -Enabled False | Out-Null }

Write-Output '==> requiring NLA'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name 'UserAuthentication' -Value 1 -Type DWord

Write-Output '==> account lockout policy (5 attempts, 15 minutes)'
# net accounts takes only fixed English switch names (no account/group names), so unlike
# icacls and auditpol it is locale-safe -- confirmed empirically (unelevated, this box):
# the switches parse fine and the only failure is "Access is denied", not a syntax error.
# Still check the exit code: a silently-failed lockout policy would leave the RDP account
# without brute-force protection, which the design relies on.
& net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "net accounts failed to set the lockout policy (exit code $LASTEXITCODE). Refusing to continue: brute-force protection on the RDP account is a required security property."
}

Write-Output '==> enabling logon auditing so /rdp_off can report sessions'
# {0CCE9215-69AE-11D9-BED3-505054503030} is the well-known, locale-independent GUID for the
# "Logon" audit subcategory (confirmed via `auditpol /list /subcategory:* /v` on this box:
# it's the first entry under the "Logon/Logoff" category). The readable name "Logon" is
# localized -- on this Russian-locale Windows the subcategory is actually named
# "Вход в систему", and auditpol rejects the English literal outright (exit 87, invalid
# parameter) before it ever gets to the privileged operation. Same rule as the icacls SIDs
# above: don't swap this back for a readable name, it will break on non-English Windows.
$LogonAuditGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}'
& auditpol /set /subcategory:"$LogonAuditGuid" /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "auditpol failed to enable logon auditing (exit code $LASTEXITCODE). Refusing to continue: without this, the audit verb silently reports no logons instead of reporting that auditing is off."
}

Restart-Service sshd
Write-Output ''
Write-Output 'Done. RDP is disabled; the bot will enable it per session.'
Write-Output 'Verify from the VDS with:'
Write-Output "  sudo -u safeconnect ssh -i /var/lib/safe-connect/id_ed25519 <user>@<pc1-tailnet-ip> status"
