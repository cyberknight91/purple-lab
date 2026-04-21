# Metodología Purple-Lab

> *Detección sin simulación es teatro. Simulación sin detección es postureo.*

Este documento describe el workflow que uso para cada atomic del repo. Es el mismo workflow que uso en engagements pagados — condensado, pero no recortado.

---

## El loop

```
┌────────────┐   ┌────────────┐   ┌──────────────┐   ┌────────────┐   ┌────────────┐
│ 1. Elegir  │──▶│ 2. Simular │──▶│ 3. Observar  │──▶│ 4. Detectar│──▶│ 5. Baseline│
│  técnica   │   │            │   │  telemetría  │   │            │   │            │
└────────────┘   └────────────┘   └──────────────┘   └────────────┘   └────────────┘
      ▲                                                                      │
      └──────────────────────────────────────────────────────────────────────┘
                               (iterar, tunear, publicar)
```

---

## 1. Elegir la técnica

Tira de **informes de intrusiones reales**, no de una lista de hacks molones.

Fuentes primarias:
- [The DFIR Report](https://thedfirreport.com/) — walk-throughs detallados de intrusiones
- [CISA advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) — TTPs de adversarios state-aligned
- [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/)
- [Mandiant M-Trends](https://www.mandiant.com/m-trends)

Para cada técnica candidata capturo:

| Campo | Ejemplo |
|-------|---------|
| ATT&CK ID | T1059.001 |
| Last seen (informe) | DFIR Report, marzo 2025 |
| Adversario | Pikabot, afiliado BlackBasta |
| Plataforma | Windows 10/11, Server 2019+ |
| Pre-requisito | Execution inicial, cualquier shell |
| Nivel OPSEC | Bajo (raw) a Alto (evader) |

Prefiero variantes **raw / low-OPSEC** para el atomic. El objetivo es producir la telemetría que la técnica genera *fundamentalmente*, no emular un evader específico.

---

## 2. Simular

El script del atomic (`execute.ps1` / `execute.sh`) tiene tres invariantes:

1. **Payload benigno.** Lo que la técnica *hace* tiene que ser inocuo (escribir a stdout, abrir notepad, crear una tarea auto-eliminable). El *patrón* de invocación tiene que ser idéntico al hostil.
2. **Idempotente.** Ejecutar el atomic dos veces deja el sistema en el mismo estado que ejecutarlo una.
3. **Auto-documentado.** Las primeras líneas imprimen el ID de la técnica, timestamp y qué va a pasar. Las últimas imprimen qué buscar en el SIEM.

Evito:
- Herramientas de terceros (Mimikatz, Rubeus, binarios de SharpHound) en el atomic mismo. Eso va en un directorio `/tools` separado con avisos claros. El atomic no debería requerir descargas de red en tiempo de ejecución.
- Trucos de ofuscación. El atomic es una muestra de control, no un test de evasión.

---

## 3. Observar telemetría

Tras disparar, registro **todos** los eventos que el SIEM recibe causalmente ligados al atomic. Eso incluye ruido irrelevante — es crítico para el análisis de FP después.

Stack mínimo de telemetría:
- **Sysmon** con [config de SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) o [sysmon-modular](https://github.com/olafhartong/sysmon-modular). El segundo da eventos 10/22/23 con cobertura más rica.
- Log de **Security** con Advanced Audit Policy según los [cheat-sheets de Malware Archaeology](https://www.malwarearchaeology.com/cheat-sheets).
- **PowerShell** 4103 + 4104 + 400 habilitados vía GPO.
- **TaskScheduler/Operational** habilitado.
- **WMI-Activity/Operational** habilitado.

Todo evento que me importa va a `expected_events.md` con valores de campo reales de mi lab run.

---

## 4. Detectar

La regla Sigma tiene que pasar tres tests:

1. **Nivel técnica, no nivel herramienta.** Detecta el comportamiento (ej. `rundll32 + comsvcs + MiniDump`) no el nombre del binario (`mimikatz.exe`). Lo segundo se rompe en cuanto el atacante renombra.
2. **Económica en campos.** El conjunto mínimo de campos que identifica unívocamente la técnica. Condiciones extra significan más sitios por donde el atacante se escurre.
3. **Portable entre backends.** Convierte limpiamente con `sigma-cli` a al menos Elastic EQL, Wazuh `<rule>`, Splunk SPL.

Mantengo el YAML Sigma como forma canónica. Salidas compiladas para los backends target viven bajo `detections/elastic/`, `detections/wazuh/`, etc.

---

## 5. Baseline y tuning

Antes de que una regla llegue a `stable`, la ejecuto contra **24 horas de actividad benigna de workstation** y mido:

- Falsos positivos por día
- Top 5 fuentes de FP (proceso padre, usuario, rol del host)
- Exclusiones propuestas

Si FP/día > 1 en un perfil workstation, la regla se queda `experimental` hasta tunearse. Los FPs documentados **siempre** aparecen en el bloque `falsepositives:` de la regla — nunca escondidos.

Para cada regla también adjunto una **hunt query** — la versión más amplia y ruidosa pensada para investigación humana en lugar de alerta. Vive en `detections/<id>_analysis.md`.

---

## Reporting

Cada pareja atomic-regla produce dos artefactos que un consultor debería poder entregar a un cliente:

- **Nota técnica** — los archivos en `atomics/<id>/` y `detections/sigma/<id>.yml`.
- **Párrafo ejecutivo** — un párrafo, sin jerga, respondiendo: *qué es esto, por qué debería importarte, cuál es nuestra cobertura actual*.

Incluyo el párrafo ejecutivo al principio del README de cada atomic bajo un heading dedicado cuando hace falta un informe completo cara al cliente.

---

## Tooling

- **sigma-cli** — validación de reglas Sigma y conversión a backends.
- **sigma-test** — tests tipo unit para reglas contra eventos good/bad conocidos.
- **Repo Elastic Detection Rules** — librería de detección de referencia.
- **ATT&CK Navigator** — visualización de cobertura.
- Validador de **sysmon-config.xml** — https://github.com/mkorman90/sysmon-config-validator

---

## Definición de "shipped"

Un atomic está **shipped** cuando el repo contiene, como mínimo:

- [ ] `atomics/<id>_<slug>/README.md` — kill-chain, refs, párrafo ejecutivo
- [ ] `atomics/<id>_<slug>/execute.{ps1,sh}` — script de simulación
- [ ] `atomics/<id>_<slug>/expected_events.md` — referencia de telemetría
- [ ] `detections/sigma/<id>.yml` — regla Sigma, status ≥ `experimental`
- [ ] La regla valida bajo CI (`sigma-cli check`)
- [ ] Nota FP rellenada o explícitamente "none observed in 24h baseline"

Los atomics parciales viven en ramas, nunca en `main`.
