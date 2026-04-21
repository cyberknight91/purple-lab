# T1059.001 — PowerShell: Encoded Command

| Campo | Valor |
|-------|-------|
| **Táctica** | Execution |
| **Técnica** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| **Plataforma** | Windows |
| **Permisos** | Usuario |
| **Fuentes de datos** | `Process: Process Creation`, `Script: Script Execution`, `Command: Command Execution` |
| **Detección** | [`sigma/T1059.001_powershell_encoded.yml`](../../detections/sigma/T1059.001_powershell_encoded.yml) |

## Por qué los adversarios la usan

`powershell.exe -EncodedCommand <b64>` (forma corta `-enc`) es la primitiva de ejecución living-off-the-land más común en Windows. Evade firmas AV basadas en substring de command-line, no deja artefactos en disco y sobrevive a GPOs de script-blocking cuando ScriptBlock logging no está forzado.

Ejemplos del mundo real:
- **Emotet** loader — PowerShell base64 stage-1 soltado por macros maliciosas de Office.
- **TrickBot** persistencia — payload de tarea programada con PowerShell encodeado.
- **LAPSUS$** — payloads encodeados para dumping de credenciales en sesiones secuestradas.

## Simulación

El payload que ejecuta este atomic es **benigno** — escribe una sola cadena a stdout. Pero el patrón de invocación (PowerShell con `-EncodedCommand`, flags concretos, cuerpo base64) es idéntico al caso malicioso, que es lo único que le importa a la detección.

```powershell
pwsh ./execute.ps1
```

Por debajo:
```powershell
$cmd = 'Write-Host "atomic-test: T1059.001 ($(Get-Date -Format o))"'
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $b64 -NoNewWindow -Wait
```

## Telemetría esperada

| Fuente | Evento | Campos clave |
|--------|--------|--------------|
| Sysmon | `EventID 1` · Process Creation | `Image` termina en `powershell.exe`, `CommandLine` contiene `-EncodedCommand` (o `-enc`, `-ec`) |
| Security | `EventID 4688` | Igual; requiere "Audit Process Creation" + GPO de command-line logging |
| PowerShell | `EventID 4104` · ScriptBlock | `ScriptBlockText` tras decodificar es la cadena anterior |
| PowerShell | `EventID 4103` · ModuleLogging | Registro de invocación si Module Logging está activado |

## Mapeo kill-chain

```
Initial Access         ──►  (fuera de alcance — asume phish / macro)
Execution  (T1059.001) ──►  ESTE ATOMIC
Defense Evasion        ──►  (ofuscación del payload decodificado en intrusiones reales)
```

## Limpieza

Ninguna requerida — el atomic es efímero. No escribe archivos, ni claves de registro, ni tareas programadas.

## Referencias

- [ATT&CK · T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Red Canary · 2024 Threat Detection Report — Encoded PowerShell](https://redcanary.com/threat-detection-report/)
- [Microsoft · about_PowerShell_exe](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe)
