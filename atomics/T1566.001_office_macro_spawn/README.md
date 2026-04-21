# T1566.001 — Macro de Office generando proceso hijo

| Campo | Valor |
|-------|-------|
| **Táctica** | Initial Access → Execution |
| **Técnica** | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) (Spearphishing Attachment) |
| **Sub-técnica** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (User Execution: Malicious File) |
| **Plataforma** | Windows |
| **Permisos** | Usuario |
| **Fuentes de datos** | `Process: Process Creation`, `Process: Parent → Child lineage` |
| **Detección (mismo repo)** | [`sigma/T1059.001_powershell_encoded.yml`](../../detections/sigma/T1059.001_powershell_encoded.yml) (caza el payload) |
| **Detección (cross-repo)** | [`cyberknight91/detection-engineering · office_macro_suspicious_child.yml`](https://github.com/cyberknight91/detection-engineering/blob/main/rules/sigma/windows/initial_access/office_macro_suspicious_child.yml) (caza el lineage) |

## Por qué los adversarios la usan

La macro de Office es el vector de initial-access por phishing más duradero
en la historia de la seguridad Windows. Emotet, Qakbot, IcedID, TrickBot,
Dridex, Hancitor — los nombres de los loaders cambian cada 18 meses pero
la primitiva es la misma:

1. Email de phishing con adjunto `.docm` / `.xlsm` / `.docx`
2. El usuario abre, hace clic en "Habilitar contenido"
3. La macro VBA en `Document_Open()` llama a `Shell()` o usa `WScript.Shell.Run`
4. El proceso hijo (cmd, powershell, mshta, rundll32, wscript…) descarga la stage 2

Microsoft desactivó la ejecución de macros de internet por defecto en 2022,
lo que bajó la tasa de éxito notablemente. Pero muchas PYMEs siguen con
instalaciones viejas de Office o configuraciones con macros firmadas en
allow-list — la clase no está extinta, solo es menos común.

## Simulación

El atomic simula **solo el lineage padre→hijo** — lo que vigila cualquier
detección de esta clase. **No** suelta un payload real. El proceso hijo
escribe un timestamp a stdout y sale.

Qué producto de Office se "simula" es controlable. Por defecto usamos
`notepad.exe` como sustituto del padre (porque es desechable y está en
todas las instalaciones Windows) pero `execute.ps1` acepta una ruta a un
binario real de Office si quieres que el campo ParentImage cuadre
exactamente en tu SIEM.

```powershell
# Por defecto — usa notepad.exe como padre (seguro, universal)
pwsh ./execute.ps1

# Opcional — binario real de Office (requiere Office instalado y path override)
pwsh ./execute.ps1 -ParentBinary "$env:ProgramFiles\Microsoft Office\root\Office16\WINWORD.EXE"
```

## Telemetría esperada

| Fuente | Evento | Campos clave |
|--------|--------|--------------|
| Sysmon | `EventID 1` | `ParentImage|endswith: '\winword.exe'` (o `\notepad.exe` en modo por defecto), `Image|endswith: '\powershell.exe'`, `CommandLine contains '-EncodedCommand'` |
| Security | `EventID 4688` | Igual; requiere Audit Process Creation + command-line logging |
| PowerShell | `EventID 4104` | ScriptBlock con el payload decodificado |

## Mapeo kill-chain

```
Initial Access (T1566.001) ──► El usuario abre .docm malicioso
User Execution (T1204.002) ──► Hace clic en "Habilitar contenido"
Execution     (T1059.001)  ──► La macro genera powershell.exe
                                │
                                └─► ESTE ATOMIC reproduce el lineage
Defense Evasion (T1140)    ──►  Argumento base64 / encodeado
Command & Control (T1105)  ──►  (fuera de alcance) descarga stage-2
```

## Limpieza

Ninguna requerida — sin persistencia, sin archivos, sin registro.

## Por qué emparejarlo con `office_macro_suspicious_child.yml`

La regla de detección es intencionalmente parent-driven: vigila que
ejecutables de Office sean padres de un shell/scripting host
independientemente de cómo sea la command line del hijo. La mayoría de
reglas públicas se apoyan en heurísticas de command-line de PowerShell —
que los atacantes bypassean usando `mshta` o `rundll32` en su lugar. Al
baseline-ear contra el lineage, la regla sobrevive al churn de
primitivas.

Este atomic existe para **probar que la regla dispara contra el lineage
canónico** sin necesitar un lab de phishing real, y para ejercitar el
caso negativo `filter_office_help` si cambias el hijo de `powershell.exe`
a `mshta.exe` con una URL de office.com.

## Referencias

- [ATT&CK · T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [ATT&CK · T1204.002 — User Execution Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [Microsoft — Macro execution blocked by default (2022)](https://learn.microsoft.com/en-us/DeployOffice/security/internet-macros-blocked)
- [Red Canary — 2024 Threat Detection Report · T1566.001](https://redcanary.com/threat-detection-report/techniques/spearphishing-attachment/)
