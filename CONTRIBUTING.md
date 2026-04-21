# Contribuir

Este repo es principalmente un lab personal pero los PRs que sigan el formato son bienvenidos.

## Añadir un nuevo atomic

Un atomic completo son **cinco archivos**:

```
atomics/T<id>_<slug>/
├── README.md              descripción de la técnica, kill-chain, refs
├── execute.ps1|.sh         simulación (payload benigno, patrón hostil)
├── expected_events.md      referencia de telemetría SIEM

detections/sigma/
└── T<id>_<slug>.yml        regla Sigma canónica

detections/
└── T<id>_<slug>_analysis.md  (opcional) hunt queries + análisis de FP
```

## Nombrado

- Carpeta y archivo de regla: `T<ATT&CK ID>_<snake_slug>` — ej. `T1218.010_regsvr32_scriptlet`.
- Campo `id:` del Sigma: UUID real **o** el patrón `<uuid>-purple-lab-T<id>`. No reutilices IDs de SigmaHQ.
- El `title:` de la regla va en presente, describe el *comportamiento*, no la herramienta.

## Checklist regla Sigma

- [ ] `status:` es `experimental` hasta hacer baseline; nunca directo a `stable`.
- [ ] `tags:` incluyen `attack.<tactic>` y `attack.t<id>`.
- [ ] `falsepositives:` no está vacío (lista casos reales, no "None").
- [ ] `level:` está justificado en la regla o en el doc de análisis.
- [ ] La regla valida con `sigma check`.
- [ ] La regla convierte limpio con `sigma convert -t lucene` y `-t splunk`.

## Checklist script del atomic

- [ ] El primer bloque imprime ID de la técnica + timestamp + qué va a pasar.
- [ ] El payload es benigno. Si no es posible, el script se niega a correr sin un flag explícito `-IAcceptRisk`.
- [ ] El script es **idempotente** — dos runs dejan el sistema igual que uno.
- [ ] El último bloque imprime qué buscar en el SIEM.
- [ ] La limpieza pasa automáticamente, o el flag para hacerla es obvio.

## Proceso de PR

1. Rama desde `main` con el ID del atomic: `atomic/T1218.010-regsvr32`.
2. Commits atómicos — uno para el atomic, uno para la detección, uno para los docs. Sin mega-commits.
3. Abre PR. CI correrá `sigma check` sobre las reglas.
4. Al menos un run en VM aislada con capturas del SIEM disparando va en la descripción del PR.

## Estilo de código

- PowerShell: verbos aprobados, `[CmdletBinding()]`, comment-based help, `$ErrorActionPreference = "Stop"`.
- Bash: `set -euo pipefail`, shellcheck limpio.
- Sigma: indent de 2 espacios, YAML 1.2.

## Qué voy a rechazar

- Atomics sin regla de detección.
- Reglas de detección sin un atomic que pruebe que disparan.
- Payloads que exfiltran datos reales, persisten sin opt-in a limpieza o requieren herramientas de pago.
- Reglas de SigmaHQ copy-pasted sin cambios sustantivos y atribución.
