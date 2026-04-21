# T1566.001 — Office Macro Spawning Child Process

| Field | Value |
|-------|-------|
| **Tactic** | Initial Access → Execution |
| **Technique** | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) (Spearphishing Attachment) |
| **Sub-technique** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (User Execution: Malicious File) |
| **Platform** | Windows |
| **Permissions** | User |
| **Data sources** | `Process: Process Creation`, `Process: Parent → Child lineage` |
| **Detection (same repo)** | [`sigma/T1059.001_powershell_encoded.yml`](../../detections/sigma/T1059.001_powershell_encoded.yml) (catches the payload) |
| **Detection (cross-repo)** | [`cyberknight91/detection-engineering · office_macro_suspicious_child.yml`](https://github.com/cyberknight91/detection-engineering/blob/main/rules/sigma/windows/initial_access/office_macro_suspicious_child.yml) (catches the lineage) |

## Why adversaries use it

The Office macro is the single most durable phishing initial-access
vector in Windows security history. Emotet, Qakbot, IcedID, TrickBot,
Dridex, Hancitor — the loader names change every 18 months but the
primitive is the same:

1. Phishing email with a `.docm` / `.xlsm` / `.docx` attachment
2. User opens, clicks "Enable Content"
3. VBA macro in `Document_Open()` calls `Shell()` or uses `WScript.Shell.Run`
4. Child process (cmd, powershell, mshta, rundll32, wscript…) downloads stage 2

Microsoft disabled internet-macro execution by default in 2022, which
dropped the success rate materially. But many SMEs run old Office
installs or signed-macro whitelisted setups — and the class is not
extinct, just less common.

## Simulation

The atomic simulates **the parent→child lineage only** — the thing every
detection in this class watches. It does **not** drop a real payload. The
spawned process prints a timestamp to stdout and exits.

Exactly which Office product is "simulated" is controllable. By default
we use `notepad.exe` as the parent stand-in (because it's disposable and
present on every Windows install) but `execute.ps1` accepts a path to a
real Office binary if you want the full ParentImage field to match in
your SIEM.

```powershell
# Default — uses notepad.exe as parent (safe, universal)
pwsh ./execute.ps1

# Optional — real Office binary (needs Office installed and path override)
pwsh ./execute.ps1 -ParentBinary "$env:ProgramFiles\Microsoft Office\root\Office16\WINWORD.EXE"
```

## Expected telemetry

| Source | Event | Key fields |
|--------|-------|-----------|
| Sysmon | `EventID 1` | `ParentImage|endswith: '\winword.exe'` (or `\notepad.exe` in default mode), `Image|endswith: '\powershell.exe'`, `CommandLine contains '-EncodedCommand'` |
| Security | `EventID 4688` | Same; requires Audit Process Creation + command-line logging |
| PowerShell | `EventID 4104` | ScriptBlock content of the decoded payload |

## Kill-chain mapping

```
Initial Access (T1566.001) ──► User opens malicious .docm
User Execution (T1204.002) ──► Clicks "Enable Content"
Execution     (T1059.001)  ──► Macro spawns powershell.exe
                                │
                                └─► THIS ATOMIC reproduces the lineage
Defense Evasion (T1140)    ──►  Base64 / encoded argument
Command & Control (T1105)  ──►  (out of scope) stage-2 download
```

## Clean-up

None required — no persistence, no files, no registry.

## Why pair this with `office_macro_suspicious_child.yml`

The detection rule is intentionally parent-driven: it watches for Office
executables becoming the parent of a shell/scripting host regardless of
what the child's command line looks like. Most other public rules pin on
PowerShell command-line heuristics — which attackers bypass by using
`mshta` or `rundll32` instead. By baseline-ing against the lineage, the
rule survives primitive churn.

This atomic exists to **prove the rule fires against the canonical
lineage** without needing an actual phishing lab, and to exercise the
`filter_office_help` negative case if you swap the child from
`powershell.exe` to `mshta.exe` with an office.com URL.

## References

- [ATT&CK · T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [ATT&CK · T1204.002 — User Execution Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [Microsoft — Macro execution blocked by default (2022)](https://learn.microsoft.com/en-us/DeployOffice/security/internet-macros-blocked)
- [Red Canary — 2024 Threat Detection Report · T1566.001](https://redcanary.com/threat-detection-report/techniques/spearphishing-attachment/)
