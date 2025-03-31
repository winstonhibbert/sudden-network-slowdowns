# Sudden Network Slowdowns

<img src="https://github.com/user-attachments/assets/0b6aea87-15cb-4d72-9c28-7051e868bf6b" width="50%">

## 🛠️ Scenario Overview
During routine security monitoring, the server team noticed significant network performance degradation on older devices attached to the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team began investigating internal sources of potential threats.

## 🔍 Hypothesis
- Could there be lateral movement in the network?
- Are large file downloads or port scanning activities occurring?
- Since internal traffic is allowed by default, could unrestricted PowerShell use be exploited?

---

## 📊 Data Collection

### 📝 Query 1: Identify Devices with Excessive Failed Connections
```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

**Findings:**
- The device `whibbert-edr-md` failed 186 connection requests against itself.
- The IP `10.0.0.159` showed sequential failed connection attempts, indicating a possible port scan.

![image](https://github.com/user-attachments/assets/5f308acc-7675-4f18-82c1-2d29532f90a1)


### 📝 Query 2: Identify Port Scanning Activity
```kql
let IPInQuestion = "10.0.0.159";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

**Findings:**
- Sequential failed connections suggest automated port scanning.

![image](https://github.com/user-attachments/assets/b78597a4-d6af-4c3d-bb60-7c6a71741445)


---

## 🚀 Data Analysis

### 📝 Query 3: Identify Suspicious Process Execution
```kql
let VMName = "whibbert-edr-md";
let specificTime = datetime(2025-03-29T00:38:19.127148Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 60m) .. (specificTime + 60m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```

**Findings:**
- A PowerShell script `portscan.ps1` was executed at `2025-02-28T00:37:05.8693723Z`.
- The script was executed by the `SYSTEM` account, which is highly unusual.
- Manual inspection confirmed the presence of `portscan.ps1` on the device.

![image](https://github.com/user-attachments/assets/34d57381-5f23-4214-9278-f47cb3ebc8b0)

![image](https://github.com/user-attachments/assets/bc9c98f1-eb7a-45eb-8587-6b2982743385)

![image](https://github.com/user-attachments/assets/2a556480-92fe-4aed-8488-f73644725dc4)

---

## ⚡ Investigation Insights
### 🔎 How did this happen?
- The `SYSTEM` account executed a PowerShell-based port scanning script.
- The device was not known to be running any legitimate scanning tools.
- No malware was detected, but unauthorized activity was evident.

### 🔎 **Relevant MITRE ATT&CK TTPs**
| **TTP ID** | **Technique** | **Description** |
|------------|--------------|----------------|
| **T1595.002**  | **Active Scanning: Port Scanning** | Sequential failed connections indicate a network scan. |
| **T1046**  | **Network Service Discovery** | PowerShell script enumerating active hosts and services. |
| **T1059.001**  | **Command and Scripting Interpreter: PowerShell** | Execution of a suspicious PowerShell script. |
| **T1548.002**  | **Abuse Elevation Control Mechanism: SYSTEM Execution** | The script ran under SYSTEM privileges, indicating unauthorized execution. |

---

## 🛡️ Response & Mitigation

### ✅ **Actions Taken**
1. **Isolated the affected device** (`whibbert-edr-md`) from the network.

![image](https://github.com/user-attachments/assets/f2212b0e-9699-48c3-8990-29fbbfc6013b)

2. **Conducted a malware scan**, which returned no results.
3. **Investigated for persistence mechanisms** (scheduled tasks, registry changes, etc.).
4. **Reimaged/rebuilt the machine** as a precautionary measure.

### 🔹 **Preventative & Hardening Measures**
✔️ Enable **PowerShell script logging** and network activity monitoring.  
✔️ Restrict **SYSTEM account execution** of non-administrative scripts.  
✔️ Improve **EDR policies** to detect PowerShell-based reconnaissance and port scans.  
✔️ Configure **firewall rules** to block unauthorized internal scanning.  

---

## 📚 Areas for Improvement

### 🔹 **Security Enhancements**
 - Implement **proactive network segmentation** to prevent lateral movement.
 - Restrict **PowerShell execution policies** to authorized users only.

### 🔹 **Threat Hunting Improvements**
 - Strengthen **SIEM alerts** for anomalous PowerShell execution.
 - Enhance **KQL threat hunting queries** for early detection of scans.

---

## 📖 Final Summary
✅ A **port scanning script** was identified running under the SYSTEM account.  
✅ The script leveraged **T1595 (Active Scanning)** and **T1046 (Network Service Discovery)** techniques.  
✅ **No malware was found**, but as a precaution, the device was isolated and reimaged.  
✅ Future hunts should focus on **detecting unauthorized PowerShell activity earlier**.  

🔐 **Next Steps:** Strengthen **endpoint monitoring**, **restrict PowerShell execution**, and **enhance network segmentation** to prevent future incidents.  

