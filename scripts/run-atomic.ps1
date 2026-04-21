<#
.SYNOPSIS
    Dispatcher for purple-lab atomics.

.DESCRIPTION
    Resolves an ATT&CK technique ID to its atomic folder and executes
    the execute.ps1 script found there. Passes remaining parameters
    through.

.EXAMPLE
    pwsh ./scripts/run-atomic.ps1 -Id T1059.001
    pwsh ./scripts/run-atomic.ps1 -Id T1053.005 -CleanupAfter
    pwsh ./scripts/run-atomic.ps1 -List

.NOTES
    Author: cyberknight91
#>

[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run', Position = 0, Mandatory)]
    [string]$Id,

    [Parameter(ParameterSetName = 'List')]
    [switch]$List,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PassThrough
)

$ErrorActionPreference = "Stop"

$repoRoot   = Split-Path -Parent $PSScriptRoot
$atomicsDir = Join-Path $repoRoot "atomics"

function Get-AtomicFolders {
    Get-ChildItem -Path $atomicsDir -Directory | Sort-Object Name
}

if ($List) {
    Write-Host ""
    Write-Host "Available atomics" -ForegroundColor Magenta
    Write-Host "-----------------"
    Get-AtomicFolders | ForEach-Object {
        $parts = $_.Name -split '_', 2
        $techId = $parts[0]
        $desc   = if ($parts.Count -gt 1) { $parts[1].Replace('_', ' ') } else { '' }
        "{0,-12} {1}" -f $techId, $desc | Write-Host
    }
    Write-Host ""
    return
}

# Resolve folder
$folder = Get-AtomicFolders | Where-Object { $_.Name -like "$Id*" } | Select-Object -First 1
if (-not $folder) {
    Write-Error "No atomic found for ID '$Id'. Run with -List to see available atomics."
    exit 1
}

$executeScript = Join-Path $folder.FullName "execute.ps1"
if (-not (Test-Path $executeScript)) {
    Write-Error "execute.ps1 missing in $($folder.FullName)"
    exit 1
}

Write-Host ""
Write-Host "==> Running atomic: $($folder.Name)" -ForegroundColor Cyan
Write-Host "==> Script:         $executeScript"
Write-Host ""

& $executeScript @PassThrough
