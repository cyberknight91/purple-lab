<#
.SYNOPSIS
    Atomic simulation for MITRE ATT&CK T1053.005 — Scheduled Task persistence.

.DESCRIPTION
    Creates a Windows scheduled task named "PurpleLab-AtomicTest" that runs
    notepad.exe at user logon. Generates Security 4698 and Sysmon 1 events
    identical in shape to hostile persistence tasks.

.PARAMETER CleanupAfter
    Delete the task immediately after creation (pure telemetry run).

.PARAMETER Cleanup
    Only delete the task, do not create it.

.NOTES
    Author:  cyberknight91
    License: MIT
    WARNING: Lab VM only. Will persist across reboots unless -CleanupAfter or
             -Cleanup is passed.
#>

[CmdletBinding()]
param(
    [switch]$CleanupAfter,
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$TaskName = "PurpleLab-AtomicTest"

function Remove-AtomicTask {
    param([string]$Name)
    Write-Host "[*] Removing scheduled task '$Name' ..."
    $null = schtasks /delete /tn $Name /f 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Task removed." -ForegroundColor Green
    } else {
        Write-Host "[!] Task was not present." -ForegroundColor Yellow
    }
}

Write-Host "[+] T1053.005 — Scheduled Task / Job" -ForegroundColor Magenta
Write-Host "    Timestamp: $(Get-Date -Format o)"
Write-Host ""

if ($Cleanup) {
    Remove-AtomicTask -Name $TaskName
    return
}

# ---- Create the task ----------------------------------------------------
Write-Host "[*] Creating task '$TaskName' ..."

# schtasks pattern — widely used by malware so the command line signature
# matches hostile usage.
$schTasksArgs = @(
    "/create",
    "/tn", $TaskName,
    "/tr", "notepad.exe",
    "/sc", "ONLOGON",
    "/rl", "LIMITED",
    "/f"
)

$proc = Start-Process -FilePath "schtasks.exe" `
                      -ArgumentList $schTasksArgs `
                      -NoNewWindow `
                      -PassThru `
                      -Wait

if ($proc.ExitCode -ne 0) {
    throw "schtasks /create failed (exit $($proc.ExitCode))"
}

Write-Host "[+] Task created." -ForegroundColor Green
Write-Host "[+] Check your SIEM for:"
Write-Host "    - Security EventID 4698 with TaskName='$TaskName'"
Write-Host "    - Sysmon EventID 1 for schtasks.exe"
Write-Host "    - Sigma rule: T1053.005_scheduled_task"
Write-Host ""

# ---- Optional clean-up --------------------------------------------------
if ($CleanupAfter) {
    Start-Sleep -Seconds 2
    Remove-AtomicTask -Name $TaskName
} else {
    Write-Host "[!] Task will persist across reboot. Run with -Cleanup to remove it." -ForegroundColor Yellow
}
