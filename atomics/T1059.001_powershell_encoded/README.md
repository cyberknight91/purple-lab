# T1059.001 — PowerShell: Encoded Command

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **Technique** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| **Platform** | Windows |
| **Permissions** | User |
| **Data sources** | `Process: Process Creation`, `Script: Script Execution`, `Command: Command Execution` |
| **Detection** | [`sigma/T1059.001_powershell_encoded.yml`](../../detections/sigma/T1059.001_powershell_encoded.yml) |

## Why adversaries use it

`powershell.exe -EncodedCommand <b64>` (short form `-enc`) is the most common living-off-the-land execution primitive on Windows. It bypasses command-line AV substring signatures, avoids disk artefacts, and survives script-blocking GPOs when ScriptBlock logging is not forced.

Real-world examples:
- **Emotet** loader — base64 PowerShell stage-1 dropped by malicious Office macros.
- **TrickBot** persistence — encoded PowerShell scheduled task payload.
- **LAPSUS$** — encoded payloads for credential dumping on hijacked sessions.

## Simulation

The payload this atomic executes is **benign** — it writes a single string to stdout. But the invocation pattern (PowerShell with `-EncodedCommand`, specific flags, base64 body) is identical to the malicious case, which is the only thing the detection cares about.

```powershell
pwsh ./execute.ps1
```

Behind the scenes:
```powershell
$cmd = 'Write-Host "atomic-test: T1059.001 ($(Get-Date -Format o))"'
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $b64 -NoNewWindow -Wait
```

## Expected telemetry

| Source | Event | Key fields |
|--------|-------|-----------|
| Sysmon | `EventID 1` · Process Creation | `Image` ends with `powershell.exe`, `CommandLine` contains `-EncodedCommand` (or `-enc`, `-ec`) |
| Security | `EventID 4688` | Same; requires "Audit Process Creation" + command-line logging GPO |
| PowerShell | `EventID 4104` · ScriptBlock | `ScriptBlockText` after decode is the string above |
| PowerShell | `EventID 4103` · ModuleLogging | Invocation record if Module Logging is enabled |

## Kill-chain mapping

```
Initial Access        ──►  (out of scope — assume phish / macro)
Execution  (T1059.001) ──►  THIS ATOMIC
Defense Evasion       ──►  (obfuscation of the decoded payload in real intrusions)
```

## Clean-up

None required — the atomic is ephemeral. No files written, no registry keys, no scheduled tasks.

## References

- [ATT&CK · T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Red Canary · 2024 Threat Detection Report — Encoded PowerShell](https://redcanary.com/threat-detection-report/)
- [Microsoft · about_PowerShell_exe](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe)
