# Lab setup

Instructions to build a minimum-viable Windows endpoint that produces useful telemetry for this repo.

---

## Hardware

Anything that can run a Windows 10/11 VM plus a small Linux SIEM VM.

- 16 GB RAM host (8 GB guest Win + 4 GB SIEM + 4 GB host)
- 80 GB disk
- Hypervisor: Hyper-V, VMware Workstation, or Virtualbox. I use Hyper-V.

---

## Isolation

**Do this first, everything else after.** Put the lab network in its own virtual switch with no route to the host LAN. Verify:

```powershell
# From the Windows lab VM
Test-NetConnection -ComputerName 1.1.1.1 -Port 53
# → Should fail.

Test-NetConnection -ComputerName siem-lab.local -Port 514
# → Should succeed.
```

The SIEM VM gets a route out to download updates; the Windows target does not.

---

## Windows target

Base image: Windows 10 22H2 Enterprise Evaluation or Windows 11 23H2 Eval. 90-day eval licences are enough for lab cycles.

### 1. Install Sysmon

```powershell
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\temp\Sysmon.zip
Expand-Archive C:\temp\Sysmon.zip -DestinationPath C:\temp\Sysmon

# SwiftOnSecurity baseline — good default for atomics
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml `
  -OutFile C:\temp\sysmon-config.xml

C:\temp\Sysmon\Sysmon64.exe -accepteula -i C:\temp\sysmon-config.xml
```

Verify:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5
```

### 2. Enable advanced audit policy

Save as `audit.csv`, apply with `auditpol /restore /file:audit.csv`:

```csv
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Process Termination,{0CCE922C-69AE-11D9-BED3-505054503030},Success,,1
,System,Other Object Access Events,{0CCE9227-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Filtering Platform Connection,{0CCE9226-69AE-11D9-BED3-505054503030},Success,,1
,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Special Logon,{0CCE921B-69AE-11D9-BED3-505054503030},Success,,1
```

Plus, in `gpedit.msc`:

- Computer Configuration → Admin Templates → System → Audit Process Creation
  - **Include command line in process creation events** = Enabled

### 3. PowerShell logging

In `gpedit.msc`:

- Computer Config → Admin Templates → Windows Components → Windows PowerShell
  - **Turn on Module Logging** = Enabled, `*` as module
  - **Turn on PowerShell Script Block Logging** = Enabled
  - **Turn on PowerShell Transcription** = Enabled (optional, noisy)

Verify:

```powershell
# Fire a harmless command
Write-Host "hello"

# Check 4104 lands
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 3
```

### 4. Log shipping

Ship these to your SIEM:

| Log | Channel |
|-----|---------|
| Sysmon | `Microsoft-Windows-Sysmon/Operational` |
| Security | `Security` |
| System | `System` |
| PowerShell ops | `Microsoft-Windows-PowerShell/Operational` |
| PowerShell classic | `Windows PowerShell` |
| TaskScheduler | `Microsoft-Windows-TaskScheduler/Operational` |
| WMI-Activity | `Microsoft-Windows-WMI-Activity/Operational` |

For Wazuh, add to `ossec.conf` on the agent:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-TaskScheduler/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

For Elastic Agent / Winlogbeat, enable the equivalent channels in the policy.

---

## SIEM

Use the companion repo [`siem-homelab`](https://github.com/cyberknight91/siem-homelab):

```bash
git clone https://github.com/cyberknight91/siem-homelab
cd siem-homelab
docker compose up -d
```

Ports after startup:

- Wazuh dashboard: `https://siem-lab.local:443`
- Elastic / Kibana: `https://siem-lab.local:5601`

---

## Snapshots

Take a snapshot of the Windows VM **after** all the above is configured and **before** running atomics. Every atomic run ends with "roll back to snapshot".

```powershell
# From the Hyper-V host
Checkpoint-VM -Name "lab-win11" -SnapshotName "baseline-sysmon-ready"

# After an atomic run
Restore-VMSnapshot -VMName "lab-win11" -Name "baseline-sysmon-ready" -Confirm:$false
```

---

## Verifying everything works

Run this on the target as a final smoke test:

```powershell
# Should produce Sysmon 1 + Security 4688 + PowerShell 4104
powershell.exe -NoProfile -Command "Write-Host 'lab-smoke-test'"
```

Then query the SIEM for `lab-smoke-test` — if all three event sources land, you're ready.
