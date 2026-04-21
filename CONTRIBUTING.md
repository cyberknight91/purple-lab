# Contributing

This repo is primarily a personal lab but PRs that follow the format are welcome.

## Adding a new atomic

A complete atomic is **five files**:

```
atomics/T<id>_<slug>/
├── README.md              technique description, kill-chain, refs
├── execute.ps1|.sh         simulation (benign payload, hostile pattern)
├── expected_events.md      SIEM telemetry reference

detections/sigma/
└── T<id>_<slug>.yml        canonical Sigma rule

detections/
└── T<id>_<slug>_analysis.md  (optional) hunt queries + FP analysis
```

## Naming

- Folder & rule file: `T<ATT&CK ID>_<snake_slug>` — e.g. `T1218.010_regsvr32_scriptlet`.
- Sigma `id:` field: a real UUID **or** the pattern `<uuid>-purple-lab-T<id>`. Do not reuse SigmaHQ IDs.
- Rule `title:` is present tense, describes the *behaviour*, not the tool.

## Sigma rule checklist

- [ ] `status:` is `experimental` until baselined; never ship directly to `stable`.
- [ ] `tags:` include `attack.<tactic>` and `attack.t<id>`.
- [ ] `falsepositives:` is non-empty (list real cases, not "None").
- [ ] `level:` is justified in the rule or the analysis doc.
- [ ] Rule validates with `sigma check`.
- [ ] Rule converts cleanly with `sigma convert -t lucene` and `-t splunk`.

## Atomic script checklist

- [ ] First block prints technique ID + timestamp + what's about to happen.
- [ ] Payload is benign. If that is not possible, script refuses to run without an explicit `-IAcceptRisk` flag.
- [ ] Script is **idempotent** — two runs leave the system in the same state as one.
- [ ] Final block prints what to look for in the SIEM.
- [ ] Clean-up happens automatically, or the flag to do it is obvious.

## PR process

1. Branch off `main` with the atomic ID: `atomic/T1218.010-regsvr32`.
2. Commit atomically — one commit for the atomic, one for the detection, one for the docs. No mega-commits.
3. Open PR. CI will run `sigma check` on the rules.
4. At least one run on an isolated VM with screenshots of the SIEM firing goes in the PR description.

## Code style

- PowerShell: approved verbs, `[CmdletBinding()]`, comment-based help, `$ErrorActionPreference = "Stop"`.
- Bash: `set -euo pipefail`, shellcheck-clean.
- Sigma: 2-space indent, YAML 1.2.

## What I will reject

- Atomics without a detection rule.
- Detection rules without an atomic that proves they fire.
- Payloads that exfiltrate real data, persist without opt-in cleanup, or require paid tools.
- Copy-pasted SigmaHQ rules without substantive changes and attribution.
