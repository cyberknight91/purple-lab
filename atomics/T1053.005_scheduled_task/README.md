# T1053.005 — Scheduled Task / Job

| Campo | Valor |
|-------|-------|
| **Táctica** | Persistence · Privilege Escalation · Execution |
| **Técnica** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| **Plataforma** | Windows |
| **Permisos** | Usuario (scope usuario) / Admin (scope `SYSTEM`) |
| **Fuentes de datos** | `Scheduled Job: Scheduled Job Creation`, `Process Creation`, `File: File Creation` |
| **Detección** | [`sigma/T1053.005_scheduled_task.yml`](../../detections/sigma/T1053.005_scheduled_task.yml) |

## Por qué los adversarios la usan

El Task Scheduler de Windows es el mecanismo de persistencia más común después de las run keys. Le da al atacante:

- **Re-entrada basada en tiempo** (`/SC ONLOGON`, `/SC HOURLY`, triggers de arranque)
- **Privilegio** — creada con `/RU SYSTEM` y el token adecuado, los payloads se ejecutan como SYSTEM sin tocar servicios.
- **Longevidad** — las tareas persisten reinicios, logoffs e incluso algunas cuarentenas de AV.
- **Plausible deniability** — nombradas como tareas legítimas de Microsoft, se esconden en `\Microsoft\Windows\*`.

Ejemplos del mundo real:
- **TrickBot** — `schtasks /create /ru SYSTEM /sc ONLOGON /tn ...` para persistencia en arranque.
- **Cobalt Strike** Beacon — módulo `schtasks` para persistencia lateral.
- **APT29 (Cozy Bear)** — tareas programadas disfrazadas bajo el árbol `Microsoft\Windows\`.

## Simulación

Crea una tarea programada llamada `PurpleLab-AtomicTest` que ejecuta `notepad.exe` cada vez que cualquier usuario inicia sesión. El payload es benigno; el patrón de creación es idéntico al uso hostil.

```powershell
pwsh ./execute.ps1
```

Para borrar la tarea inmediatamente después de crearla (ejecución pura de telemetría, sin persistencia residual):

```powershell
pwsh ./execute.ps1 -CleanupAfter
```

## Telemetría esperada

| Fuente | Evento | Campos clave |
|--------|--------|--------------|
| Sysmon | `EventID 1` · Process Creation | `Image` = `schtasks.exe` o `svchost.exe` alojando el Scheduler; `CommandLine` con `/create` |
| Security | `EventID 4698` · Tarea programada creada | `TaskName`, `TaskContent` (XML), `SubjectUserName` |
| Security | `EventID 4700` / `4702` | Tarea activada / actualizada |
| TaskScheduler | `EventID 106` (Microsoft-Windows-TaskScheduler/Operational) | `TaskName`, `UserContext` |
| File | `FileCreate` bajo `C:\Windows\System32\Tasks\` | Nuevo archivo XML con la definición de la tarea |

El 4698 es el más valioso — lleva el XML completo de la tarea, incluyendo triggers y acciones. Con eso puedes fingerprintar tareas sospechosas (usuario no-admin creando triggers de arranque, tareas ejecutando binarios fuera de `%SystemRoot%`, etc.).

## Mapeo kill-chain

```
Execution  (T1059.*)    ──►  foothold inicial
Persistence (T1053.005) ──►  ESTE ATOMIC
Privilege Escalation    ──►  si se combina con /RU SYSTEM + bypass UAC
```

## Limpieza

`execute.ps1 -Cleanup` elimina la tarea. O manualmente:

```powershell
schtasks /delete /tn "PurpleLab-AtomicTest" /f
```

El archivo en `C:\Windows\System32\Tasks\PurpleLab-AtomicTest` se elimina junto con el registro.

## Referencias

- [ATT&CK · T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [Microsoft · schtasks.exe reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
- [The DFIR Report · 2023 Year in Review — Persistence](https://thedfirreport.com/)
