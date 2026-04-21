# T1003.001 — OS Credential Dumping: LSASS Memory

| Campo | Valor |
|-------|-------|
| **Táctica** | Credential Access |
| **Técnica** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| **Plataforma** | Windows |
| **Permisos** | Admin (SeDebugPrivilege) |
| **Fuentes de datos** | `Process: Process Access`, `Process Creation`, `File Creation` |
| **Detección** | [`sigma/T1003.001_lsass_dump.yml`](../../detections/sigma/T1003.001_lsass_dump.yml) |

> **Nota de seguridad.** Este atomic **NO** dumpea `lsass.exe`. Reproduce el
> patrón exacto de invocación `rundll32 + comsvcs.dll MiniDump` contra un
> proceso **`notepad.exe` desechable** lanzado por el script. Ese patrón es
> la señal que caza la regla Sigma. Un adversario real sustituiría el PID
> de `notepad` por el de `lsass` — todo lo demás es idéntico. Ver §
> "Hacerlo de verdad" más abajo.

## Por qué los adversarios la usan

`lsass.exe` guarda credenciales en claro (hashes NTLM, tickets Kerberos, credenciales cacheadas) de cada sesión interactiva en la máquina. Volcar su memoria y exfiltrar el `.dmp` resultante permite al atacante ejecutar Mimikatz offline en infraestructura controlada por él y extraer credenciales sin disparar escaneos de memoria del AV on-host.

El export `comsvcs.dll, MiniDump` es atractivo porque:

- **Sin herramienta de terceros** en disco — `comsvcs.dll` viene con Windows.
- **LOLBAS-compatible** — `rundll32.exe` ya está en allow-list prácticamente en todas partes.
- **One-liner** — cabe en un `shell` de Cobalt Strike.

```text
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> <out.dmp> full
```

Uso en el mundo real:
- **LAPSUS$** (2022) — cosecha de credenciales post-compromiso en sesiones VDI secuestradas.
- **Conti / BlackCat** — paso de playbook tras initial domain admin.
- **APT29** — documentado en varios informes de intrusión.

## Simulación

```powershell
pwsh ./execute.ps1
```

Lo que pasa:
1. Lanza `notepad.exe` como target desechable (captura su PID).
2. Llama a `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID> <tmp>\atomic.dmp full`.
3. Espera al dump, luego lo elimina y cierra notepad.

La telemetría generada es funcionalmente idéntica a la variante hostil **excepto** por el `TargetImage` (notepad, no lsass).

## Telemetría esperada

| Fuente | Evento | Campos clave |
|--------|--------|--------------|
| Sysmon | `EventID 1` · creación de rundll32 | `CommandLine` contiene `comsvcs` + `MiniDump` |
| Sysmon | `EventID 10` · ProcessAccess | `SourceImage` rundll32, `TargetImage` la víctima. `GrantedAccess` 0x1FFFFF o 0x1410 (PROCESS_VM_READ + PROCESS_QUERY_INFORMATION). En el caso real `TargetImage` termina en `\lsass.exe`. |
| Sysmon | `EventID 11` · FileCreate | Archivo `.dmp` escrito. |

## Hacerlo de verdad (sólo lab)

En una VM de laboratorio **totalmente aislada con sesión admin** y un EDR sin anti-tamper, para dumpear `lsass` de verdad:

```powershell
# PowerShell elevada
$pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $pid C:\lab\lsass.dmp full
```

Microsoft Defender moderno marcará esto con `HackTool:Win32/LsassDumper.A!MTB` en segundos — que es exactamente lo que queremos observar desde el lado azul.

## Mapeo kill-chain

```
Execution              ──►  exec de código como admin
Privilege Escalation   ──►  SeDebugPrivilege (default admin)
Credential Access (T1003.001) ──►  ESTE ATOMIC
Lateral Movement       ──►  Pass-the-Hash / Pass-the-Ticket con las creds
```

## Limpieza

El script elimina el archivo `.dmp` y mata el notepad desechable. Si el dump queda (script interrumpido), bórralo manualmente — contiene la memoria de un notepad benigno, pero la higiene importa.

## Referencias

- [ATT&CK · T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [LOLBAS · comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/Comsvcs/)
- [Red Canary · Mimikatz Threat Detection](https://redcanary.com/threat-detection-report/techniques/credential-dumping/)
- [MDSec · Detecting & Preventing LSASS Credential Dumping](https://www.mdsec.co.uk/)
