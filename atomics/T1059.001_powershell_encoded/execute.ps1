<#
.SYNOPSIS
    Atomic simulation for MITRE ATT&CK T1059.001 — PowerShell Encoded Command.

.DESCRIPTION
    Fires a PowerShell process with -EncodedCommand, where the payload is a
    benign Write-Host. The invocation pattern is identical to real adversary
    usage; the payload is not.

    Detection target: detections/sigma/T1059.001_powershell_encoded.yml

.NOTES
    Author:  cyberknight91
    License: MIT
    WARNING: Run only in an isolated lab VM. Ensure Sysmon + PowerShell
             ScriptBlock logging are active before firing.
#>

[CmdletBinding()]
param(
    [string]$Tag = "atomic-test"
)

$ErrorActionPreference = "Stop"

Write-Host "[+] T1059.001 — PowerShell Encoded Command" -ForegroundColor Magenta
Write-Host "    Tag      : $Tag"
Write-Host "    Timestamp: $(Get-Date -Format o)"
Write-Host ""

# ---- Build the payload (benign) -----------------------------------------
$payload  = 'Write-Host "' + $Tag + ': T1059.001 fired at $(Get-Date -Format o)"'
$bytes    = [System.Text.Encoding]::Unicode.GetBytes($payload)
$encoded  = [Convert]::ToBase64String($bytes)

Write-Host "[*] Encoded payload length: $($encoded.Length) chars"
Write-Host "[*] Launching powershell.exe -EncodedCommand ..."
Write-Host ""

# ---- Fire ---------------------------------------------------------------
$proc = Start-Process `
    -FilePath       "powershell.exe" `
    -ArgumentList   @("-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded) `
    -NoNewWindow `
    -PassThru `
    -Wait

Write-Host ""
Write-Host "[+] Child process exited with code $($proc.ExitCode)" -ForegroundColor Green
Write-Host "[+] Check your SIEM for Sysmon EventID 1 and PowerShell 4104 matching"
Write-Host "    rule_id: T1059.001_powershell_encoded"
