# T1053.005 — Scheduled Task / Job

| Field | Value |
|-------|-------|
| **Tactic** | Persistence · Privilege Escalation · Execution |
| **Technique** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| **Platform** | Windows |
| **Permissions** | User (for user scope) / Admin (for `SYSTEM` scope) |
| **Data sources** | `Scheduled Job: Scheduled Job Creation`, `Process Creation`, `File: File Creation` |
| **Detection** | [`sigma/T1053.005_scheduled_task.yml`](../../detections/sigma/T1053.005_scheduled_task.yml) |

## Why adversaries use it

The Windows Task Scheduler is the most common persistence mechanism after run keys. It gives an attacker:

- **Time-based re-entry** (`/SC ONLOGON`, `/SC HOURLY`, boot triggers)
- **Privilege** — when created with `/RU SYSTEM` and the right token, payloads run as SYSTEM without touching services.
- **Longevity** — tasks persist across reboots, user logoffs, and even some AV quarantines.
- **Plausible deniability** — named like a legitimate Microsoft task, they hide in `\Microsoft\Windows\*`.

Real-world examples:
- **TrickBot** — `schtasks /create /ru SYSTEM /sc ONLOGON /tn ...` for boot persistence.
- **Cobalt Strike** Beacon — `schtasks` module for lateral persistence.
- **APT29 (Cozy Bear)** — scheduled tasks disguised under the `Microsoft\Windows\` tree.

## Simulation

Creates a scheduled task named `PurpleLab-AtomicTest` that runs `notepad.exe` every time any user logs on. The payload is benign; the creation pattern is identical to hostile usage.

```powershell
pwsh ./execute.ps1
```

To also remove the task immediately after creating it (pure telemetry run, no residual persistence):

```powershell
pwsh ./execute.ps1 -CleanupAfter
```

## Expected telemetry

| Source | Event | Key fields |
|--------|-------|-----------|
| Sysmon | `EventID 1` · Process Creation | `Image` = `schtasks.exe` or `svchost.exe` hosting the Scheduler; `CommandLine` with `/create` |
| Security | `EventID 4698` · Scheduled task created | `TaskName`, `TaskContent` (XML), `SubjectUserName` |
| Security | `EventID 4700` / `4702` | Task enabled / updated |
| TaskScheduler | `EventID 106` (Microsoft-Windows-TaskScheduler/Operational) | `TaskName`, `UserContext` |
| File | `FileCreate` under `C:\Windows\System32\Tasks\` | New XML file with the task definition |

Event 4698 is the most valuable — it carries the full task XML, including the triggers and the action. With that, you can fingerprint suspicious tasks (non-admin user creating boot triggers, tasks running binaries outside `%SystemRoot%`, etc.).

## Kill-chain mapping

```
Execution  (T1059.*)    ──►  initial foothold
Persistence (T1053.005) ──►  THIS ATOMIC
Privilege Escalation    ──►  if combined with /RU SYSTEM + UAC bypass
```

## Clean-up

`execute.ps1 -Cleanup` removes the task. Or manually:

```powershell
schtasks /delete /tn "PurpleLab-AtomicTest" /f
```

The file at `C:\Windows\System32\Tasks\PurpleLab-AtomicTest` is removed together with the registration.

## References

- [ATT&CK · T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [Microsoft · schtasks.exe reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
- [The DFIR Report · 2023 Year in Review — Persistence](https://thedfirreport.com/)
