# Telemetría esperada — T1566.001 Office macro spawn

Eventos que el SIEM debería ver en ~2 segundos tras el retorno de `execute.ps1`.

## Sysmon · EventID 1 (Process Creation) — el hijo

Evento más importante: el lineage padre→hijo.

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-04-20T16:14:02.442Z"/>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAYQB0AG8AbQBpAGMALQB0AGUAcwB0ADoAIABUADEANQA2ADYALgAwADAAMQAnAA==</Data>
    <Data Name="ParentImage">C:\Windows\System32\notepad.exe</Data>
    <!-- O con -ParentBinary apuntando a Office: -->
    <!-- <Data Name="ParentImage">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data> -->
    <Data Name="User">LAB\alice</Data>
    <Data Name="IntegrityLevel">Medium</Data>
  </EventData>
</Event>
```

Regla que dispara:
`cyberknight91/detection-engineering` → `office_macro_suspicious_child.yml`.

## Sysmon · EventID 1 — el padre

```xml
<Event>
  <EventData>
    <Data Name="Image">C:\Windows\System32\notepad.exe</Data>
    <Data Name="ParentImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ParentCommandLine">pwsh ./execute.ps1</Data>
  </EventData>
</Event>
```

Nota: en una intrusión real el padre es Word/Excel; aquí es notepad. La
regla de detección se apoya en `ParentImage` sin importar cuál — pon
`-ParentBinary` si necesitas la demo con match exacto.

## Security · EventID 4688 (Process Creation, audit)

Sólo presente cuando **"Audit Process Creation"** está habilitado con
`ProcessCreationIncludeCmdLine_Enabled=1` en `HKLM\Software\
Microsoft\Windows\CurrentVersion\Policies\System\Audit`.

```
A new process has been created.
Creator Subject:   LAB\alice
Creator Process Name: C:\Windows\System32\notepad.exe
Target Subject:    LAB\alice
New Process Name:  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: powershell.exe -NoProfile ... -EncodedCommand <b64>
```

## PowerShell · EventID 4104 (ScriptBlock)

Tras decodificar el payload base64 por powershell.exe:

```
Creating Scriptblock text (1 of 1):
Write-Host 'atomic-test: T1566.001 (2026-04-20T16:14:02.442Z)'
```

## Validación de apoyo contra el caso filtro

Ejecuta `execute.ps1 -ChildMode mshta` y confirma que la regla **no**
alerta (filter_office_help dispara con la URL de office.com).

## Qué capturar para el portfolio

1. Kibana Discover: filtrado en `rule.id: 100xxx` mostrando la fila de alerta.
2. XML del evento Sysmon expandido para el proceso hijo.
3. Árbol de procesos (Process Hacker / Sysinternals Process Explorer) mostrando
   `notepad.exe → powershell.exe` antes de que el padre salga.

Guarda las tres imágenes bajo `purple-lab/atomics/T1566.001_office_macro_spawn/assets/`.
