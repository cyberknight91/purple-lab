<div align="center">

# purple-lab

### Simulación de adversarios emparejada con detection engineering.

<p>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-cubierto-BA0C2F?style=flat-square">
  <img src="https://img.shields.io/badge/Sigma-validado-8B0000?style=flat-square">
  <img src="https://img.shields.io/badge/plataforma-Win%20%7C%20Linux-2496ED?style=flat-square">
  <img src="https://img.shields.io/badge/licencia-MIT-blue?style=flat-square">
  <a href="./.github/workflows/validate-sigma.yml"><img src="https://img.shields.io/badge/CI-sigma--validate-success?style=flat-square"></a>
</p>

<p><i>Cada test ofensivo de este repo se publica con la detección que lo caza.</i></p>

</div>

---

## Por qué existe

La mayoría de repos red team te dan el payload. La mayoría de repos blue team te dan la regla. Muy pocos te dan **los dos, emparejados y probados uno contra el otro**.

`purple-lab` es el banco de trabajo que uso para practicar engagements purple team:

1. **Simular** una técnica ATT&CK conocida en un laboratorio controlado.
2. **Capturar** la telemetría que deja el ataque.
3. **Escribir** una regla Sigma que lo detecte — después una query Elastic EQL y una hunt query.
4. **Medir** la tasa de falsos positivos contra una línea base benigna.
5. **Documentar** todo: kill-chain, regla, notas de FP, runbook.

Si falta cualquiera de esos cinco pasos, la técnica no llega a `main`.

---

## Cobertura ATT&CK

| ID | Técnica | Táctica | Atomic | Sigma | Estado |
|----|---------|---------|--------|:-----:|:------:|
| `T1059.001` | PowerShell · Encoded Command | Execution | [link](atomics/T1059.001_powershell_encoded) | [regla](detections/sigma/T1059.001_powershell_encoded.yml) | listo |
| `T1053.005` | Scheduled Task / Job | Persistence | [link](atomics/T1053.005_scheduled_task) | [regla](detections/sigma/T1053.005_scheduled_task.yml) | listo |
| `T1003.001` | OS Credential Dumping · LSASS | Credential Access | [link](atomics/T1003.001_lsass_dump) | [regla](detections/sigma/T1003.001_lsass_dump.yml) | listo |
| `T1566.001` | Spearphishing Attachment · Macro → child | Initial Access | [link](atomics/T1566.001_office_macro_spawn) | [regla](https://github.com/cyberknight91/detection-engineering/blob/main/rules/sigma/windows/initial_access/office_macro_suspicious_child.yml) | listo |
| `T1018` | Remote System Discovery | Discovery | — | — | planeado |
| `T1021.001` | Remote Services · RDP | Lateral Movement | — | — | planeado |
| `T1047` | Windows Management Instrumentation | Execution | — | — | planeado |
| `T1087.002` | Account Discovery · Domain | Discovery | — | — | planeado |
| `T1136.001` | Create Account · Local | Persistence | — | — | planeado |
| `T1218.011` | Signed Binary Proxy · Rundll32 | Defense Evasion | — | — | planeado |

---

## Estructura del repo

```
purple-lab/
├── atomics/                             lado ofensivo
│   └── T<id>_<slug>/
│       ├── README.md                    kill-chain, referencias, impacto
│       ├── execute.ps1 / .sh            la simulación en sí
│       └── expected_events.md           qué llega al SIEM
├── detections/                          lado azul
│   ├── sigma/                           reglas Sigma canónicas
│   ├── elastic/                         EQL / KQL compilado
│   └── <id>_analysis.md                 por qué funciona + notas FP
├── docs/
│   ├── lab-setup.md                     cómo montar las VMs de lab
│   ├── methodology.md                   mi workflow purple team
│   └── attack-navigator.json            export ATT&CK Navigator
├── scripts/
│   └── run-atomic.ps1                   dispatcher para todos los atomics
└── .github/workflows/
    └── validate-sigma.yml               CI: sigma-cli valida cada regla
```

---

## Requisitos del laboratorio

- VM Windows 10/11 **totalmente aislada** (sin puente a producción).
- Sysmon con [config de SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) instalada.
- PowerShell ScriptBlock + Module logging activados (ver [`docs/lab-setup.md`](docs/lab-setup.md)).
- Forwarder de logs enviando `Microsoft-Windows-Sysmon/Operational` y `Security` a un SIEM.
- SIEM de referencia para este repo: el compañero [`siem-homelab`](https://github.com/cyberknight91/siem-homelab) (Wazuh + Elastic, un compose file).

> **Aviso.** Estos atomics tocan LSASS, crean tareas programadas y lanzan payloads encodeados. No los ejecutes en ningún host que te importe. Haz snapshot de la VM antes y restaura después.

---

## Uso

```powershell
# 1. Disparar el atomic
pwsh ./scripts/run-atomic.ps1 -Id T1059.001

# 2. Enviar los logs al SIEM (cualquier forwarder sirve)
# 3. Confirmar que la regla Sigma dispara. En Wazuh/Elastic:
#    rule_id:"T1059.001_powershell_encoded"

# 4. Restaurar la VM al snapshot.
```

Cada carpeta de atomic tiene su propio `README.md` con la kill-chain completa, el comando exacto de ejecución, los EventIDs de Sysmon esperados y un puntero a la regla de detección.

---

## Metodología

Ver [`docs/methodology.md`](docs/methodology.md). Versión corta:

1. **Elegir una técnica** que use un threat group real (APT29, FIN7, LAPSUS$, Vice Spider…).
2. **Reproducir** la variante mínima viable — sin OPSEC innecesaria, queremos ruido.
3. **Capturar** cada evento que reciba el SIEM (Sysmon, 4688, PowerShell 4104, Security 4624…).
4. **Abstraer** la detección: ¿qué campo(s) son *intrínsecos* a la técnica? No detectes la herramienta, detecta el comportamiento.
5. **Baseline** contra 24h de actividad benigna. Si FP > 1/día en una workstation, la regla necesita tuning — documéntalo.
6. **Publicar** el par: atomic + regla + análisis.

---

## Roadmap

- [x] Primeros 4 atomics con Sigma + análisis
- [ ] Capa ATT&CK Navigator (export JSON del subset cubierto)
- [ ] Paquete de reglas Elastic (`.ndjson` listo para importar)
- [ ] Mapeo a reglas custom de Wazuh (mismos IDs, local_rules.xml)
- [ ] Plantilla de informe purple team (sección ejecutiva + técnica)
- [ ] Planes de emulación de adversario: APT29 · FIN7 · LAPSUS$
- [ ] Cobertura Linux: `T1053.003` (cron), `T1548.003` (sudo), `T1222.002` (chmod)

---

## Referencias

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — inspiración para el formato atomic
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — sintaxis de reglas y herramientas de conversión
- [The DFIR Report](https://thedfirreport.com/) — intrusiones reales que informan la selección de técnicas
- [Sysmon Modular](https://github.com/olafhartong/sysmon-modular) — baseline de telemetría

---

<div align="center">
<sub>Por <a href="https://github.com/cyberknight91">cyberknight91</a> · Parte del <a href="https://github.com/cyberknight91">portfolio Purple Team</a> · Licencia MIT</sub>
</div>
