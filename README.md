# Threat Hunt Report: The Great Admin Heist

**Participant:** Wilson  
**Date:** May 2025  

## Platforms and Tools Used
- **Platform:** Microsoft Defender for Endpoint (MDE), Log Analytics Workspace, Windows 10 host `anthony-001`
- **Languages & Tools:** Kusto Query Language (KQL), native Windows executables (powershell.exe, schtasks.exe, cmd.exe, csc.exe)

---

## Scenario Summary
Acme Corp’s admin fell victim to a targeted phishing attack launched by an advanced persistent threat (APT) group known as *The Phantom Hackers*. The attackers deployed a fake antivirus app named `BitSentinelCore.exe`, which initiated a chain of persistence and surveillance techniques leveraging both native Windows tools (LOLBins) and registry modifications. This hunt focused on uncovering that full attack chain.

---

## 🔎 Flag Analysis & Findings

### 🏁 Flag 1 – Fake Antivirus Dropper
- **Answer:** `BitSentinelCore.exe`
- **Discovery:** Located in `C:\ProgramData\`, the file was confirmed as the fake antivirus that launched the attack chain.

```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
| project Timestamp, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```

---

### 🏁 Flag 2 – Dropper Method
- **Answer:** `csc.exe`
- **Discovery:** BitSentinelCore.exe was created via the C# compiler (`csc.exe`), a signed Microsoft binary abused by attackers.

---

### 🏁 Flag 3 – Initial Execution
- **Answer:** `BitSentinelCore.exe`
- **Notes:** Execution appeared manual via `explorer.exe`, indicating user interaction (likely Bubba himself).
- **Key Timestamp:** `2025-05-07T02:00:36.794406Z`

---

### 🏁 Flag 4 – Keylogger File Dropped
- **Answer:** `systemreport.lnk`
- **Notes:** Created shortly after BitSentinelCore execution, placed in the AppData Startup folder.
- **Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp between (datetime(2025-05-07T01:59:00Z) .. datetime(2025-05-07T02:10:00Z))
| where InitiatingProcessFileName in~ ("BitSentinelCore.exe", "explorer.exe", "csc.exe", "svchost.exe", "powershell.exe", "cmd.exe", "wscript.exe", "rundll32.exe")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

---

### 🏁 Flag 5 – Registry Persistence
- **Answer:** `HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- **Key Detail:** Created by BitSentinelCore to auto-run malware at logon.

```kql
DeviceRegistryEvents 
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName == "bitsentinelcore.exe"
```

---

### 🏁 Flag 6 – Scheduled Task Created
- **Answer:** `UpdateHealthTelemetry`
- **Notes:** Scheduled to run daily, providing long-term persistence. The name mimics legitimate telemetry functions to evade detection.

```kql
let Timespan = datetime("2025-05-07T02:06:51.0000000Z");
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where TimeGenerated between (Timespan - 10m .. Timespan + 15m)
| where ProcessCommandLine has_any ("schtasks", "/create", "/sc", "daily", "Task", "BitSentinel", "systemreport")
```

---

### 🏁 Flag 7 – Process Spawn Chain
- **Answer:** `BitSentinelCore.exe -> cmd.exe -> schtasks.exe`
- **Notes:** Clear lateral process relationship confirming scheduled task was malware-controlled.

---

### 🏁 Flag 8 – Root Cause Timestamp
- **Answer:** `2025-05-07T02:00:36.794406Z`
- **Notes:** This timestamp was confirmed to align with malware execution, file drop, and registry modification—all tracing back to BitSentinelCore.exe.

---

## 🧠 Summary Table
| Flag | Description                        | Value |
|------|------------------------------------|-------|
| 1    | Fake AV binary                     | BitSentinelCore.exe |
| 2    | Dropper used to write malware      | csc.exe |
| 3    | Initial execution method           | BitSentinelCore.exe |
| 4    | Keylogger file dropped             | systemreport.lnk |
| 5    | Registry persistence path          | HKCU\...\Run |
| 6    | Scheduled task name                | UpdateHealthTelemetry |
| 7    | Process chain                      | BitSentinelCore.exe -> cmd.exe -> schtasks.exe |
| 8    | Root cause timestamp               | 2025-05-07T02:00:36.794406Z |

---

## 🛡️ Response Actions Taken
- Blocklisted the file hash and command signatures of BitSentinelCore.exe
- Deleted registry autorun key, scheduled task, and systemreport.lnk manually
- Queried for lateral movement attempts across endpoints
- Shared findings with Blue Team for detection rule creation

---

## 📘 Lessons Learned
- Even signed binaries like `csc.exe` can be abused to drop and compile malware
- Scheduled tasks with innocuous names (e.g., `UpdateHealthTelemetry`) may mask persistence
- Startup folders and Run keys remain prime real estate for stealthy malware
- Behavioral telemetry is essential to detecting non-obvious attacks

