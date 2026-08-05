<#
  The only program the safe-connect SSH key may execute.

  authorized_keys pins it:
    restrict,command="powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\SafeConnect\agent.ps1" ssh-ed25519 AAAA...

  Whoever holds that key can run these four verbs and nothing else. Keep it that
  way: never add a verb that takes a path, a command, or an address.

  Writes exactly one line of JSON to stdout. Nothing else may touch the host output stream.
#>

$ErrorActionPreference = 'Stop'

$ConfigPath = Join-Path $PSScriptRoot 'agent.config.json'
$RuleName   = 'SafeConnect-RDP-In'
$RegPath    = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'

function Write-Reply([hashtable]$Payload) {
    $Payload | ConvertTo-Json -Compress -Depth 5
}

function Get-VdsAddress {
    if (-not (Test-Path $ConfigPath)) { throw "missing $ConfigPath" }
    $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    if (-not $cfg.vds_tailnet_ip) { throw 'vds_tailnet_ip not set in agent.config.json' }
    return $cfg.vds_tailnet_ip
}

function Enable-Rdp {
    Set-ItemProperty -Path $RegPath -Name 'fDenyTSConnections' -Value 0 -Type DWord
    $vds = Get-VdsAddress
    $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 3389 -RemoteAddress $vds -Profile Any -Enabled True | Out-Null
    } else {
        Set-NetFirewallRule -DisplayName $RuleName -RemoteAddress $vds -Enabled True | Out-Null
    }
}

function Disable-Rdp {
    Set-ItemProperty -Path $RegPath -Name 'fDenyTSConnections' -Value 1 -Type DWord
    $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Set-NetFirewallRule -DisplayName $RuleName -Enabled False | Out-Null
    }
}

function Get-RdpEnabled {
    $deny = (Get-ItemProperty -Path $RegPath -Name 'fDenyTSConnections').fDenyTSConnections
    $rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    return ($deny -eq 0) -and ($null -ne $rule) -and ($rule.Enabled -eq 'True')
}

function Get-LogonEvents([datetime]$Since) {
    # 4624 = successful logon, 4625 = failed. LogonType 10 is RemoteInteractive (RDP);
    # 3 appears for the network leg of some NLA flows, so both are collected.
    $successes = @()
    $failures  = @()
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4624, 4625; StartTime = $Since
    } -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        $xml  = [xml]$event.ToXml()
        $data = @{}
        foreach ($node in $xml.Event.EventData.Data) { $data[$node.Name] = $node.'#text' }
        if ($data['LogonType'] -notin @('3', '10')) { continue }
        $record = @{
            time      = $event.TimeCreated.ToString('s')
            user      = [string]$data['TargetUserName']
            source_ip = [string]$data['IpAddress']
        }
        if ($event.Id -eq 4624) { $successes += $record } else { $failures += $record }
    }
    return @{ successes = $successes; failures = $failures }
}

try {
    $raw = $env:SSH_ORIGINAL_COMMAND
    if ([string]::IsNullOrWhiteSpace($raw)) { throw 'no command supplied' }

    $parts = $raw.Trim() -split '\s+'
    $verb  = $parts[0]

    switch ($verb) {
        'enable' {
            Enable-Rdp
            Write-Reply @{ ok = $true }
        }
        'disable' {
            Disable-Rdp
            Write-Reply @{ ok = $true }
        }
        'status' {
            Write-Reply @{ ok = $true; rdp_enabled = (Get-RdpEnabled) }
        }
        'audit' {
            if ($parts.Count -ne 2 -or $parts[1] -notmatch '^[0-9]{1,12}$') {
                throw 'audit requires a single epoch-seconds argument'
            }
            $since  = [datetimeoffset]::FromUnixTimeSeconds([int64]$parts[1]).LocalDateTime
            $events = Get-LogonEvents -Since $since
            Write-Reply @{ ok = $true; successes = $events.successes; failures = $events.failures }
        }
        default {
            throw "unknown verb: $verb"
        }
    }
} catch {
    Write-Reply @{ ok = $false; error = "$($_.Exception.Message)" }
    exit 0   # the transport succeeded; the payload carries the failure
}
