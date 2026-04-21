<#
.SYNOPSIS
  T1566.001 / T1204.002 — simulate an Office macro spawning a
  PowerShell child process via Shell() / WScript.Shell.Run.

.DESCRIPTION
  Lights up the canonical "Office product → shell/scripting host"
  parent→child lineage that initial-access loaders produce, without
  dropping a real payload.

  The child payload is benign: prints a timestamped atomic marker to
  stdout and exits.

.PARAMETER ParentBinary
  Path to the Windows binary that will act as the parent. Defaults to
  notepad.exe (present on every Windows install, disposable). If you
  pass a real Office binary (e.g. WINWORD.EXE), the ParentImage field
  in Sysmon EventID 1 will match production detection rules exactly.

.PARAMETER ChildMode
  One of:
    powershell  — spawns a base64-encoded PowerShell (default).
    mshta       — spawns mshta.exe with office.com URL (negative /
                  filter-case event for office_macro_suspicious_child).
    cmd         — spawns cmd.exe /c echo (for backend validation).

.EXAMPLE
  pwsh ./execute.ps1

.EXAMPLE
  pwsh ./execute.ps1 -ParentBinary "$env:ProgramFiles\Microsoft Office\root\Office16\WINWORD.EXE"

.EXAMPLE
  pwsh ./execute.ps1 -ChildMode mshta
#>

[CmdletBinding()]
param(
    [string]$ParentBinary = "$env:SystemRoot\System32\notepad.exe",
    [ValidateSet('powershell','mshta','cmd')]
    [string]$ChildMode = 'powershell'
)

$ErrorActionPreference = 'Stop'
$marker = "atomic-test: T1566.001 ($([DateTime]::UtcNow.ToString('o')))"

# --- Build the child command ---
$childLine = switch ($ChildMode) {
    'powershell' {
        $inner   = "Write-Host '$marker'"
        $b64     = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $b64"
    }
    'mshta' {
        # Filter-case: mshta with office.com URL is excluded by the companion rule.
        "$env:SystemRoot\System32\mshta.exe https://support.office.com/en-us/article/atomic-test-filter"
    }
    'cmd' {
        "$env:SystemRoot\System32\cmd.exe /c echo $marker"
    }
}

Write-Host "[atomic] parent  : $ParentBinary"
Write-Host "[atomic] child   : $childLine"

if (-not (Test-Path -LiteralPath $ParentBinary)) {
    Write-Error "Parent binary not found: $ParentBinary"
    exit 1
}

# --- Start the parent (hidden, short-lived) so we get a real PID
# to spawn the child from. On exit the parent closes itself.
$parent = Start-Process -FilePath $ParentBinary -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 400

try {
    # Use WMI Create to spawn a child with an arbitrary parent PID.
    # This is exactly what a VBA macro's Shell() does under the hood.
    $child = Invoke-WmiMethod -Class Win32_Process -Name Create `
        -ArgumentList $childLine, $null, $null, $parent.Id `
        -ErrorAction Stop

    if ($child.ReturnValue -ne 0) {
        Write-Error "Win32_Process.Create failed (rc=$($child.ReturnValue))"
        exit 1
    }

    Write-Host "[atomic] spawned child PID=$($child.ProcessId) under parent PID=$($parent.Id)"
    # Give Sysmon / Security a moment to flush
    Start-Sleep -Seconds 2
}
finally {
    # Close the parent process cleanly
    if (-not $parent.HasExited) {
        Stop-Process -Id $parent.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[atomic] done — $marker"
