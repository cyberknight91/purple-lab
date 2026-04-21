# Expected telemetry — T1566.001 Office macro spawn

Events the SIEM should see within ~2 seconds of `execute.ps1` returning.

## Sysmon · EventID 1 (Process Creation) — the child

Most important event: the parent→child lineage.

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
    <!-- OR with -ParentBinary pointing at Office: -->
    <!-- <Data Name="ParentImage">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data> -->
    <Data Name="User">LAB\alice</Data>
    <Data Name="IntegrityLevel">Medium</Data>
  </EventData>
</Event>
```

Rule that fires:
`cyberknight91/detection-engineering` → `office_macro_suspicious_child.yml`.

## Sysmon · EventID 1 — the parent

```xml
<Event>
  <EventData>
    <Data Name="Image">C:\Windows\System32\notepad.exe</Data>
    <Data Name="ParentImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ParentCommandLine">pwsh ./execute.ps1</Data>
  </EventData>
</Event>
```

Note: in a real intrusion the parent is Word/Excel; here it's notepad. The
detection rule pins on `ParentImage` regardless — set `-ParentBinary` if
you need the exact-match demo.

## Security · EventID 4688 (Process Creation, audit)

Only present when **"Audit Process Creation"** is enabled with
`ProcessCreationIncludeCmdLine_Enabled=1` under `HKLM\Software\
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

After the base64 payload is decoded by powershell.exe:

```
Creating Scriptblock text (1 of 1):
Write-Host 'atomic-test: T1566.001 (2026-04-20T16:14:02.442Z)'
```

## Companion validation against the filter case

Run `execute.ps1 -ChildMode mshta` and confirm the rule does **not**
alert (filter_office_help triggers on the office.com URL).

## What to screenshot for the portfolio

1. Kibana Discover: filtered on `rule.id: 100xxx` showing the alert row.
2. Sysmon event XML expanded for the child process.
3. Process tree (Process Hacker / Sysinternals Process Explorer) showing
   `notepad.exe → powershell.exe` before the parent exits.

Drop the three images under `purple-lab/atomics/T1566.001_office_macro_spawn/assets/`.
