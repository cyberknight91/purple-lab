<div align="center">

# purple-lab

### Adversary simulation paired with detection engineering.

<p>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-covered-BA0C2F?style=flat-square">
  <img src="https://img.shields.io/badge/Sigma-validated-8B0000?style=flat-square">
  <img src="https://img.shields.io/badge/platform-Win%20%7C%20Linux-2496ED?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square">
  <a href="./.github/workflows/validate-sigma.yml"><img src="https://img.shields.io/badge/CI-sigma--validate-success?style=flat-square"></a>
</p>

<p><i>Every offensive test in this repo ships with the detection that catches it.</i></p>

</div>

---

## Why this exists

Most red-team repos give you the payload. Most blue-team repos give you the rule. Very few give you **both, paired, and tested against each other**.

`purple-lab` is the workbench I use to practice purple-team engagements:

1. **Simulate** a well-known ATT&CK technique in a controlled lab.
2. **Collect** the telemetry the attack leaves behind.
3. **Write** a Sigma rule that detects it — then an Elastic EQL query, and a hunt query.
4. **Measure** false-positive rate against a benign baseline.
5. **Document** the lot: the kill-chain, the rule, the FP notes, the runbook.

If any of those five steps is missing, the technique doesn't land in `main`.

---

## ATT&CK coverage

| ID | Technique | Tactic | Atomic | Sigma | Status |
|----|-----------|--------|--------|:-----:|:------:|
| `T1059.001` | PowerShell · Encoded Command | Execution | [link](atomics/T1059.001_powershell_encoded) | [rule](detections/sigma/T1059.001_powershell_encoded.yml) | ready |
| `T1053.005` | Scheduled Task / Job | Persistence | [link](atomics/T1053.005_scheduled_task) | [rule](detections/sigma/T1053.005_scheduled_task.yml) | ready |
| `T1003.001` | OS Credential Dumping · LSASS | Credential Access | [link](atomics/T1003.001_lsass_dump) | [rule](detections/sigma/T1003.001_lsass_dump.yml) | ready |
| `T1566.001` | Spearphishing Attachment · Macro → child | Initial Access | [link](atomics/T1566.001_office_macro_spawn) | [rule](https://github.com/cyberknight91/detection-engineering/blob/main/rules/sigma/windows/initial_access/office_macro_suspicious_child.yml) | ready |
| `T1018` | Remote System Discovery | Discovery | — | — | planned |
| `T1021.001` | Remote Services · RDP | Lateral Movement | — | — | planned |
| `T1047` | Windows Management Instrumentation | Execution | — | — | planned |
| `T1087.002` | Account Discovery · Domain | Discovery | — | — | planned |
| `T1136.001` | Create Account · Local | Persistence | — | — | planned |
| `T1218.011` | Signed Binary Proxy · Rundll32 | Defense Evasion | — | — | planned |

---

## Repo layout

```
purple-lab/
├── atomics/                             offensive side
│   └── T<id>_<slug>/
│       ├── README.md                    kill-chain, refs, impact
│       ├── execute.ps1 / .sh            the simulation itself
│       └── expected_events.md           what lands in the SIEM
├── detections/                          blue side
│   ├── sigma/                           canonical Sigma rules
│   ├── elastic/                         compiled EQL / KQL
│   └── <id>_analysis.md                 why-it-works + FP notes
├── docs/
│   ├── lab-setup.md                     how to build the lab VMs
│   ├── methodology.md                   my purple-team workflow
│   └── attack-navigator.json            ATT&CK Navigator export
├── scripts/
│   └── run-atomic.ps1                   dispatcher for all atomics
└── .github/workflows/
    └── validate-sigma.yml               CI: sigma-cli validates every rule
```

---

## Lab prerequisites

- Windows 10/11 VM **fully isolated** (no bridge to prod).
- Sysmon with [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) installed.
- PowerShell ScriptBlock + Module logging enabled (see [`docs/lab-setup.md`](docs/lab-setup.md)).
- Log forwarder shipping `Microsoft-Windows-Sysmon/Operational` and `Security` to a SIEM.
- Reference SIEM for this repo: the companion [`siem-homelab`](https://github.com/cyberknight91/siem-homelab) (Wazuh + Elastic, one compose file).

> **Warning.** These atomics touch LSASS, create scheduled tasks, and run encoded payloads. Don't run them on any host you care about. Snapshot the VM first, restore after.

---

## Usage

```powershell
# 1. Fire the atomic
pwsh ./scripts/run-atomic.ps1 -Id T1059.001

# 2. Ship the logs to your SIEM (any forwarder works)
# 3. Confirm the Sigma rule triggers. In Wazuh/Elastic:
#    rule_id:"T1059.001_powershell_encoded"

# 4. Roll the VM back to snapshot.
```

Each atomic folder has its own `README.md` with the full kill-chain, the exact execution command, the expected Sysmon EventIDs, and a pointer to the detection rule.

---

## Methodology

See [`docs/methodology.md`](docs/methodology.md). Short version:

1. **Pick a technique** that a real threat group uses (APT29, FIN7, LAPSUS$, Vice Spider…).
2. **Recreate** the minimum viable variant — no unnecessary OPSEC, we want noise.
3. **Capture** every event the SIEM receives (Sysmon, 4688, PowerShell 4104, Security 4624…).
4. **Abstract** the detection: what field(s) are *intrinsic* to the technique? Avoid detecting the tool, detect the behaviour.
5. **Baseline** against 24h of benign activity. If FP > 1/day on a workstation, the rule needs tuning — document the tuning.
6. **Ship** the pair: atomic + rule + analysis.

---

## Roadmap

- [x] First 3 atomics with Sigma + analysis
- [ ] ATT&CK Navigator layer (JSON export for the covered subset)
- [ ] Elastic detection rules package (ready-to-import `.ndjson`)
- [ ] Wazuh custom rules mapping (same IDs, local_rules.xml)
- [ ] Purple-team report template (executive + technical sections)
- [ ] Adversary emulation plans: APT29 · FIN7 · LAPSUS$
- [ ] Linux coverage: `T1053.003` (cron), `T1548.003` (sudo), `T1222.002` (chmod)

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — inspiration for the atomic format
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — rule syntax & conversion tooling
- [The DFIR Report](https://thedfirreport.com/) — real-world intrusions that inform technique selection
- [Sysmon Modular](https://github.com/olafhartong/sysmon-modular) — telemetry baseline

---

<div align="center">
<sub>Built by <a href="https://github.com/cyberknight91">cyberknight91</a> · Part of the <a href="https://github.com/cyberknight91">Purple Team portfolio</a> · MIT License</sub>
</div>
