# T1003.001 — OS Credential Dumping: LSASS Memory

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access |
| **Technique** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| **Platform** | Windows |
| **Permissions** | Admin (SeDebugPrivilege) |
| **Data sources** | `Process: Process Access`, `Process Creation`, `File Creation` |
| **Detection** | [`sigma/T1003.001_lsass_dump.yml`](../../detections/sigma/T1003.001_lsass_dump.yml) |

> **Safety note.** This atomic does **NOT** dump `lsass.exe`. It reproduces the
> exact `rundll32 + comsvcs.dll MiniDump` invocation pattern against a **disposable
> `notepad.exe`** process spawned by the script. That pattern is the signal the
> Sigma rule catches. A real adversary would substitute `notepad`'s PID with
> `lsass`'s PID — everything else is identical. See § "Going the real way" below.

## Why adversaries use it

`lsass.exe` holds cleartext (NTLM hashes, Kerberos tickets, cached credentials) for every interactive session on the box. Dumping its memory and exfiltrating the resulting `.dmp` lets an attacker run Mimikatz offline on attacker-controlled infrastructure and extract credentials without tripping on-host AV memory scans.

The `comsvcs.dll, MiniDump` export is attractive because:

- **No third-party tool** on disk — `comsvcs.dll` ships with Windows.
- **LOLBAS-compatible** — `rundll32.exe` is already allow-listed virtually everywhere.
- **One-liner** — fits in a Cobalt Strike `shell` command.

```text
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> <out.dmp> full
```

Real-world usage:
- **LAPSUS$** (2022) — post-compromise credential harvesting on hijacked VDI sessions.
- **Conti / BlackCat** — playbook step after initial domain admin.
- **APT29** — documented in multiple intrusion reports.

## Simulation

```powershell
pwsh ./execute.ps1
```

What happens:
1. Spawn `notepad.exe` as a disposable target (captures its PID).
2. Call `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID> <tmp>\atomic.dmp full`.
3. Wait for the dump, then delete it and close notepad.

The telemetry generated is functionally identical to the hostile variant **except** for the `TargetImage` (notepad, not lsass).

## Expected telemetry

| Source | Event | Key fields |
|--------|-------|-----------|
| Sysmon | `EventID 1` · rundll32 creation | `CommandLine` contains `comsvcs` + `MiniDump` |
| Sysmon | `EventID 10` · ProcessAccess | `SourceImage` rundll32, `TargetImage` the victim. `GrantedAccess` 0x1FFFFF or 0x1410 (PROCESS_VM_READ + PROCESS_QUERY_INFORMATION). In the real case `TargetImage` ends with `\lsass.exe`. |
| Sysmon | `EventID 11` · FileCreate | `.dmp` file written. |

## Going the real way (lab only)

On a **fully isolated admin-session** lab VM with an anti-tamper-free EDR, to dump `lsass` for real:

```powershell
# Elevated PowerShell
$pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $pid C:\lab\lsass.dmp full
```

Modern Microsoft Defender will flag this with `HackTool:Win32/LsassDumper.A!MTB` within seconds — which is exactly what we want to observe from the blue side.

## Kill-chain mapping

```
Execution              ──►  code exec as admin
Privilege Escalation   ──►  SeDebugPrivilege (admin default)
Credential Access (T1003.001) ──►  THIS ATOMIC
Lateral Movement       ──►  Pass-the-Hash / Pass-the-Ticket with the creds
```

## Clean-up

The script deletes the `.dmp` file and kills the disposable notepad. If the dump file remains (script interrupted), remove it manually — it contains the memory of a benign notepad, but hygiene matters.

## References

- [ATT&CK · T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [LOLBAS · comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/Comsvcs/)
- [Red Canary · Mimikatz Threat Detection](https://redcanary.com/threat-detection-report/techniques/credential-dumping/)
- [MDSec · Detecting & Preventing LSASS Credential Dumping](https://www.mdsec.co.uk/)
