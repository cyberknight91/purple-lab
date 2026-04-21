# Eventos esperados — T1059.001

Tras ejecutar `execute.ps1` deberías ver, en orden de aparición:

## 1. Sysmon `EventID 1` — Process Creation

```xml
<Event>
  <System>
    <EventID>1</EventID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">"powershell.exe" -NoProfile -ExecutionPolicy Bypass -EncodedCommand V3JpdGUtSG9zdCAi...</Data>
    <Data Name="ParentImage">...</Data>
    <Data Name="OriginalFileName">PowerShell.EXE</Data>
    <Data Name="User">...</Data>
  </EventData>
</Event>
```

Campos clave para la detección:
- `Image` termina en `\powershell.exe`
- `CommandLine` contiene `-EncodedCommand` / `-enc` / `-ec`

## 2. Security `EventID 4688` — Process Creation (si está activado)

Misma semántica que Sysmon 1. Requiere:
- `Audit Process Creation` — Success (Advanced Audit Policy)
- `Include command line in process creation events` — Enabled

## 3. PowerShell `EventID 4104` — ScriptBlock Logging

```
ScriptBlockText: Write-Host "atomic-test: T1059.001 fired at 2026-04-20T12:34:56.7890123+02:00"
Path:          :
```

Requiere:
- Directiva de grupo → Configuración del equipo → Plantillas admin → Componentes de Windows → Windows PowerShell
  - `Turn on PowerShell Script Block Logging` — Enabled

> El script decodificado aparece **aquí** aunque la invocación fuera encodeada. Por eso 4104 es una de las fuentes de telemetría PowerShell más valiosas.

## 4. PowerShell `EventID 4103` — Module Logging (opcional)

Si module logging está habilitado para `Microsoft.PowerShell.*`, la invocación de `Write-Host` se registra con sus parámetros.

## Queries de verificación

**Wazuh / OSSEC**
```
rule.id:"T1059.001_powershell_encoded"
```

**Elastic (KQL)**
```
process.name:"powershell.exe" and process.command_line:(*-enc* or *-EncodedCommand* or *-ec*)
```

**Splunk**
```
index=* EventCode=1 Image="*\\powershell.exe"
  (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*-ec *")
```
