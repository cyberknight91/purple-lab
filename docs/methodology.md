# Purple-Lab Methodology

> *Detection without simulation is theatre. Simulation without detection is showing off.*

This document describes the workflow I use for every atomic in this repo. It is the same workflow I use in paid engagements — condensed, but not cut.

---

## The loop

```
┌────────────┐   ┌────────────┐   ┌──────────────┐   ┌────────────┐   ┌────────────┐
│ 1. Select  │──▶│ 2. Simulate│──▶│ 3. Observe   │──▶│ 4. Detect  │──▶│ 5. Baseline│
│  technique │   │            │   │  telemetry   │   │            │   │            │
└────────────┘   └────────────┘   └──────────────┘   └────────────┘   └────────────┘
      ▲                                                                      │
      └──────────────────────────────────────────────────────────────────────┘
                               (iterate, tune, publish)
```

---

## 1. Select the technique

Pick from **real intrusion reports**, not from a list of cool hacks.

Primary sources:
- [The DFIR Report](https://thedfirreport.com/) — detailed intrusion walk-throughs
- [CISA advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) — state-aligned adversary TTPs
- [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/)
- [Mandiant M-Trends](https://www.mandiant.com/m-trends)

For each technique I'm considering, I capture:

| Field | Example |
|-------|---------|
| ATT&CK ID | T1059.001 |
| Last seen (report) | DFIR Report, March 2025 |
| Adversary | Pikabot, BlackBasta affiliate |
| Platform | Windows 10/11, Server 2019+ |
| Pre-req | Initial execution, any shell |
| OPSEC level | Low (raw) to High (defender-evading) |

I prefer **raw / low-OPSEC** variants for the atomic. The point is to produce the telemetry the technique *fundamentally* generates, not to emulate a specific evader.

---

## 2. Simulate

The atomic script (`execute.ps1` / `execute.sh`) has three invariants:

1. **Benign payload.** Whatever the technique *does* must be harmless (write to stdout, spawn notepad, create a self-removing task). The invocation *pattern* must be identical to hostile.
2. **Idempotent.** Running the atomic twice leaves the system in the same state as running it once.
3. **Self-documenting.** First lines print technique ID, timestamp, what's about to happen. The last lines print what to look for in the SIEM.

I avoid:
- Third-party tooling (Mimikatz, Rubeus, SharpHound binaries) in the atomic itself. Those go in a separate `/tools` directory with clear warnings. The atomic should not require network downloads at run-time.
- Obfuscation tricks. The atomic is a control sample, not an evasion test.

---

## 3. Observe telemetry

After firing, I record **every** event the SIEM receives that is causally linked to the atomic. This includes irrelevant noise — it's critical for FP analysis later.

Minimum telemetry stack:
- **Sysmon** with [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) or [sysmon-modular](https://github.com/olafhartong/sysmon-modular). The latter gives richer events 10/22/23 coverage.
- **Security** log with Advanced Audit Policy set per [Malware Archaeology cheat-sheets](https://www.malwarearchaeology.com/cheat-sheets).
- **PowerShell** 4103 + 4104 + 400 enabled via GPO.
- **TaskScheduler/Operational** enabled.
- **WMI-Activity/Operational** enabled.

Every event I care about goes into `expected_events.md` with real field values from my lab run.

---

## 4. Detect

The Sigma rule has to pass three tests:

1. **Technique-level, not tool-level.** Detect the behaviour (e.g., `rundll32 + comsvcs + MiniDump`) not the binary name (`mimikatz.exe`). The latter breaks the moment the attacker renames.
2. **Field-economical.** The smallest set of fields that uniquely identifies the technique. Extra conditions mean more places for an attacker to slip.
3. **Backend-portable.** Converts cleanly with `sigma-cli` to at least Elastic EQL, Wazuh `<rule>`, Splunk SPL.

I keep the Sigma YAML as the canonical form. Compiled outputs for the target backends live under `detections/elastic/`, `detections/wazuh/`, etc.

---

## 5. Baseline and tune

Before a rule reaches `stable`, I run it against **24 hours of benign workstation activity** and measure:

- False positives per day
- Top 5 sources of FP (parent process, user, host role)
- Proposed exclusions

If FP/day > 1 on a workstation profile, the rule stays `experimental` until tuned. Documented FPs are **always** listed in the rule's `falsepositives:` block — never hidden.

For each rule I also attach a **hunt query** — the broader, noisier version meant for human investigation rather than alert. It lives in `detections/<id>_analysis.md`.

---

## Reporting

Every atomic-rule pair produces two artefacts a consultant should be able to hand a client:

- **Technical note** — the files in `atomics/<id>/` and `detections/sigma/<id>.yml`.
- **Executive paragraph** — one paragraph, no jargon, answering: *what is this, why should you care, what's our current coverage*.

I include the executive paragraph at the top of each atomic's README under a dedicated heading when a full client-facing report is needed.

---

## Tooling

- **sigma-cli** — Sigma rule validation & backend conversion.
- **sigma-test** — unit-style tests for rules against known good/bad events.
- **Elastic Detection Rules repo** — reference detection library.
- **ATT&CK Navigator** — coverage visualisation.
- **sysmon-config.xml** validator — https://github.com/mkorman90/sysmon-config-validator

---

## Definition of "shipped"

An atomic is **shipped** when the repo contains, at minimum:

- [ ] `atomics/<id>_<slug>/README.md` — kill-chain, refs, executive paragraph
- [ ] `atomics/<id>_<slug>/execute.{ps1,sh}` — simulation script
- [ ] `atomics/<id>_<slug>/expected_events.md` — telemetry reference
- [ ] `detections/sigma/<id>.yml` — Sigma rule, status ≥ `experimental`
- [ ] Rule validates under CI (`sigma-cli check`)
- [ ] FP note filled in or explicitly "none observed in 24h baseline"

Partial atomics live on branches, never in `main`.
