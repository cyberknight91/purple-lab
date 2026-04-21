# Eventos esperados — T1053.005

## 1. Security `EventID 4698` — Tarea programada creada

El evento más importante para esta técnica. El payload XML contiene la definición completa de la tarea.

```xml
<Event>
  <System>
    <EventID>4698</EventID>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserName">mario</Data>
    <Data Name="SubjectDomainName">LAB</Data>
    <Data Name="TaskName">\PurpleLab-AtomicTest</Data>
    <Data Name="TaskContent">
      <Task ...>
        <Triggers><LogonTrigger>...</LogonTrigger></Triggers>
        <Actions><Exec><Command>notepad.exe</Command></Exec></Actions>
        <Principals><Principal><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
      </Task>
    </Data>
  </EventData>
</Event>
```

Requiere:
- `Audit Other Object Access Events` — Success (Advanced Audit Policy)

## 2. Sysmon `EventID 1` — Process Creation

```
Image:       C:\Windows\System32\schtasks.exe
CommandLine: schtasks.exe /create /tn PurpleLab-AtomicTest /tr notepad.exe /sc ONLOGON /rl LIMITED /f
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

El padre suele ser la pista — `schtasks.exe` lanzado por `cmd.exe`, `powershell.exe` o (peor) binarios de Office es más sospechoso que el propio servicio Task Scheduler.

## 3. TaskScheduler `EventID 106` — Microsoft-Windows-TaskScheduler/Operational

```
User "LAB\mario" registered Task Scheduler task "\PurpleLab-AtomicTest"
```

## 4. File creation — `C:\Windows\System32\Tasks\PurpleLab-AtomicTest`

Se crea archivo XML. Sysmon `EventID 11` (FileCreate) si está monitorizado.

## Queries de verificación

**Wazuh / OSSEC**
```
rule.id:"T1053.005_scheduled_task" AND data.win.eventdata.taskName:"*PurpleLab*"
```

**Elastic (EQL)**
```eql
process where process.name == "schtasks.exe" and process.command_line like "*/create*"
```

**Splunk**
```
index=* EventCode=4698 TaskName="*PurpleLab-AtomicTest*"
```
