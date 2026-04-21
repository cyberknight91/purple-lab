# Expected events — T1059.001

After running `execute.ps1` you should see, in order of appearance:

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

Key fields for the detection:
- `Image` ends in `\powershell.exe`
- `CommandLine` contains `-EncodedCommand` / `-enc` / `-ec`

## 2. Security `EventID 4688` — Process Creation (if enabled)

Same semantics as Sysmon 1. Requires:
- `Audit Process Creation` — Success (Advanced Audit Policy)
- `Include command line in process creation events` — Enabled

## 3. PowerShell `EventID 4104` — ScriptBlock Logging

```
ScriptBlockText: Write-Host "atomic-test: T1059.001 fired at 2026-04-20T12:34:56.7890123+02:00"
Path:          :
```

Requires:
- Group Policy → Computer Config → Admin Templates → Windows Components → Windows PowerShell
  - `Turn on PowerShell Script Block Logging` — Enabled

> The decoded script text appears **here** even though the invocation was encoded. This is why 4104 is one of the most valuable PowerShell telemetry sources.

## 4. PowerShell `EventID 4103` — Module Logging (optional)

If module logging is enabled for `Microsoft.PowerShell.*`, the `Write-Host` invocation is logged with its parameters.

## Verification queries

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
