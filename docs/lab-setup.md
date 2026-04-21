# Setup del lab

Instrucciones para montar un endpoint Windows mínimo viable que produzca telemetría útil para este repo.

---

## Hardware

Cualquier cosa que corra una VM Windows 10/11 más una VM Linux pequeña para el SIEM.

- 16 GB RAM host (8 GB guest Win + 4 GB SIEM + 4 GB host)
- 80 GB disco
- Hypervisor: Hyper-V, VMware Workstation o Virtualbox. Yo uso Hyper-V.

---

## Aislamiento

**Esto primero, todo lo demás después.** Pon la red del lab en su propio virtual switch sin ruta a la LAN del host. Verifica:

```powershell
# Desde la VM Windows del lab
Test-NetConnection -ComputerName 1.1.1.1 -Port 53
# → Debería fallar.

Test-NetConnection -ComputerName siem-lab.local -Port 514
# → Debería funcionar.
```

La VM del SIEM tiene salida a internet para actualizar; el target Windows no.

---

## Target Windows

Imagen base: Windows 10 22H2 Enterprise Evaluation o Windows 11 23H2 Eval. Las licencias de eval de 90 días sobran para ciclos de lab.

### 1. Instalar Sysmon

```powershell
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\temp\Sysmon.zip
Expand-Archive C:\temp\Sysmon.zip -DestinationPath C:\temp\Sysmon

# Baseline SwiftOnSecurity — buen default para atomics
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml `
  -OutFile C:\temp\sysmon-config.xml

C:\temp\Sysmon\Sysmon64.exe -accepteula -i C:\temp\sysmon-config.xml
```

Verifica:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5
```

### 2. Habilitar advanced audit policy

Guarda como `audit.csv`, aplica con `auditpol /restore /file:audit.csv`:

```csv
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Process Termination,{0CCE922C-69AE-11D9-BED3-505054503030},Success,,1
,System,Other Object Access Events,{0CCE9227-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Filtering Platform Connection,{0CCE9226-69AE-11D9-BED3-505054503030},Success,,1
,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Special Logon,{0CCE921B-69AE-11D9-BED3-505054503030},Success,,1
```

Además, en `gpedit.msc`:

- Computer Configuration → Admin Templates → System → Audit Process Creation
  - **Include command line in process creation events** = Enabled

### 3. PowerShell logging

En `gpedit.msc`:

- Computer Config → Admin Templates → Windows Components → Windows PowerShell
  - **Turn on Module Logging** = Enabled, `*` como módulo
  - **Turn on PowerShell Script Block Logging** = Enabled
  - **Turn on PowerShell Transcription** = Enabled (opcional, ruidoso)

Verifica:

```powershell
# Dispara un comando inofensivo
Write-Host "hello"

# Comprueba que aterriza 4104
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 3
```

### 4. Envío de logs

Envía estos al SIEM:

| Log | Canal |
|-----|-------|
| Sysmon | `Microsoft-Windows-Sysmon/Operational` |
| Security | `Security` |
| System | `System` |
| PowerShell ops | `Microsoft-Windows-PowerShell/Operational` |
| PowerShell classic | `Windows PowerShell` |
| TaskScheduler | `Microsoft-Windows-TaskScheduler/Operational` |
| WMI-Activity | `Microsoft-Windows-WMI-Activity/Operational` |

Para Wazuh, añade en el `ossec.conf` del agente:

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

Para Elastic Agent / Winlogbeat, habilita los canales equivalentes en la policy.

---

## SIEM

Usa el repo compañero [`siem-homelab`](https://github.com/cyberknight91/siem-homelab):

```bash
git clone https://github.com/cyberknight91/siem-homelab
cd siem-homelab
docker compose up -d
```

Puertos tras arrancar:

- Dashboard Wazuh: `https://siem-lab.local:443`
- Elastic / Kibana: `https://siem-lab.local:5601`

---

## Snapshots

Haz un snapshot de la VM Windows **después** de configurar todo lo anterior y **antes** de ejecutar atomics. Cada atomic run acaba con "rollback al snapshot".

```powershell
# Desde el host Hyper-V
Checkpoint-VM -Name "lab-win11" -SnapshotName "baseline-sysmon-ready"

# Tras un atomic run
Restore-VMSnapshot -VMName "lab-win11" -Name "baseline-sysmon-ready" -Confirm:$false
```

---

## Verificar que todo funciona

Ejecuta esto en el target como smoke test final:

```powershell
# Debería producir Sysmon 1 + Security 4688 + PowerShell 4104
powershell.exe -NoProfile -Command "Write-Host 'lab-smoke-test'"
```

Luego busca `lab-smoke-test` en el SIEM — si las tres fuentes de eventos llegan, estás listo.
