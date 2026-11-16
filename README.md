# Microsoft Sentinel SOC Lab — Threat Detection & Incident Investigation

## Project Overview

Built a hands-on Security Operations Centre (SOC) lab using **Microsoft Azure, Microsoft Sentinel, Azure Monitor Agent and Sysmon** to collect, monitor and investigate Windows security events.

Used **Kusto Query Language (KQL)** to analyse failed authentication attempts and process activity, configured an automated detection rule for potential brute-force attacks, and investigated a security incident through to classification and closure.

The project demonstrates practical experience in **SIEM monitoring, log analysis, threat detection, incident triage and security incident documentation**.
## Lab Architecture

The SOC lab was built using Microsoft Azure, with a Windows Server virtual machine acting as the monitored endpoint and Microsoft Sentinel providing centralised security monitoring and threat detection.

### Architecture and Log Flow

**Windows Server VM → Azure Monitor Agent → Log Analytics Workspace → Microsoft Sentinel → Security Alert & Incident Investigation**

### Infrastructure Components

| Component | Configuration / Purpose |
|---|---|
| **Azure Resource Group** | `rg-soc-lab` — Organises the lab resources |
| **Windows Virtual Machine** | `soc-lab-vm` — Windows Server 2022, hosted in UK West |
| **Sysmon** | Captures detailed endpoint activity, including process creation events |
| **Azure Monitor Agent (AMA)** | Collects Windows Security and Sysmon events from the VM |
| **Data Collection Rules (DCRs)** | `dcr-security-events` and `dcr-sysmon` — Define which events are collected |
| **Log Analytics Workspace** | `law-soc-lab` — Stores collected security logs in UK South |
| **Microsoft Sentinel** | SIEM used for KQL queries, automated threat detection and incident management |
| **Microsoft Defender Portal** | Used to investigate alerts, document findings and classify incidents |

### How the Lab Works

Windows Security and Sysmon events are generated on the virtual machine and collected through Azure Monitor Agent using configured Data Collection Rules.

These events are sent to the Log Analytics workspace, where they can be queried using Kusto Query Language (KQL).

Microsoft Sentinel uses a scheduled analytics rule to detect repeated failed authentication attempts and generate security incidents for investigation.
## Lab Setup & Log Collection

### 1. Azure Environment Setup

- Created an Azure resource group, `rg-soc-lab`, to organise the lab infrastructure.
- Deployed a Log Analytics workspace, `law-soc-lab`, to store and analyse security logs.
- Enabled Microsoft Sentinel on the workspace to provide SIEM monitoring and incident management capabilities.
- Configured an Azure budget alert to monitor resource usage.

### 2. Windows Virtual Machine Setup

- Deployed a Windows Server 2022 virtual machine named `soc-lab-vm` in Azure.
- Configured Remote Desktop Protocol (RDP) to access and manage the VM remotely.
- Installed Microsoft Sysmon with the SwiftOnSecurity configuration to capture detailed endpoint activity.
- Verified that the Sysmon service was running and generating events in Windows Event Viewer.

### 3. Security Log Collection

Configured the Azure Monitor Agent (AMA) and two Data Collection Rules to forward security events from the VM to Log Analytics:

- **dcr-security-events:** Collects Windows Security logs, including successful and failed authentication events.
- **dcr-sysmon:** Collects Sysmon Operational events, including process creation and other monitored system activity.

Installed the relevant Microsoft Sentinel data connectors and confirmed successful Azure Monitor Agent provisioning.

### 4. Log Collection Verification
Used Kusto Query Language (KQL) to confirm that both log sources were successfully transmitting events to the Log Analytics workspace.

- **SecurityEvent:** Verified Windows Security events were arriving, including authentication events.
- **WindowsEvent:** Verified Sysmon events were arriving from the `Microsoft-Windows-Sysmon/Operational` channel.

Both queries returned results, confirming that the VM was successfully forwarding security telemetry to Microsoft Sentinel.

## KQL Queries & Threat Detection

Used Kusto Query Language (KQL) to investigate Windows Security and Sysmon logs collected from the Azure virtual machine.

### 1. Investigating Failed Login Attempts (Event ID 4625)

The following query identifies source IP addresses and accounts associated with failed Windows authentication attempts.

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by TargetAccount, IpAddress
| sort by Attempts desc
```

**Purpose:** Identify repeated login failures that may indicate password guessing or brute-force activity.

### 2. Monitoring Process Creation with Sysmon

Queried Sysmon Event ID 1 to examine process creation activity on the monitored endpoint.

```kql
WindowsEvent
| where Channel == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| take 30
```

**Purpose:** Verify endpoint visibility and investigate process execution activity.

**Result:** Successfully collected Sysmon process creation events, including activity generated while running commands such as `whoami`, `ipconfig /all` and `nslookup github.com` on the VM.

### 3. Automated Brute-Force Detection Rule

Created an enabled Microsoft Sentinel scheduled analytics rule named **Multiple Failed Login Attempts - SOC Lab**.

```kql
SecurityEvent
| where EventID == 4625
| where Computer startswith "soc-lab-vm"
| summarize FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer, TargetAccount, IpAddress
| where FailedAttempts >= 10
| project TimeGenerated = LastSeen, Computer,
    TargetAccount, IpAddress, FailedAttempts, FirstSeen
```

**Detection configuration:**
- **Severity:** Medium
- **MITRE ATT&CK:** Credential Access — Brute Force (T1110)
- **Threshold:** 10 or more failed login attempts per account and source IP within the query window
- **Query frequency:** Every 15 minutes
- **Lookback period:** 1 hour
- **Incident creation:** Enabled

**Result:** The analytics rule successfully generated a security incident in Microsoft Sentinel following repeated failed authentication attempts.

### 4. Investigating Suspicious Authentication Activity

Used a time-bounded KQL query to investigate the failed login attempts associated with the incident.

```kql
SecurityEvent
| where EventID == 4625
| where Computer startswith "soc-lab-vm"
| where TimeGenerated between (
    datetime(2026-11-15T17:00:00Z) ..
    datetime(2026-11-15T18:30:00Z)
)
| summarize FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by TargetAccount, IpAddress
| sort by FailedAttempts desc
```

**Findings:**

| Source IP | Failed Login Attempts |
|---|---:|
| 45.88.138.5 | 6,536 |
| 144.225.43.82 | 3 |
| 220.71.237.220 | 3 |

The results revealed substantial authentication activity from one external IP address, consistent with suspected brute-force behaviour.

Additional investigation was performed to determine whether the suspicious IP addresses had successfully authenticated. The results and incident classification are documented in the following section.
## Security Incident Investigation

### Incident Overview

On **15 November 2026**, Microsoft Sentinel generated an automated security incident after detecting repeated failed authentication attempts against the Windows Server VM.

| Field | Details |
|---|---|
| **Incident** | Multiple Failed Login Attempts - SOC Lab |
| **Severity** | Medium |
| **Affected System** | `soc-lab-vm` |
| **Detection** | Windows Security Event ID 4625 |
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Classification** | True Positive |
| **Final Status** | Closed |

### Investigation Process

**1. Investigated the alert**

Reviewed the incident and queried Windows Security logs using KQL to identify affected accounts, source IP addresses and failed authentication attempts.

The investigation identified **6,536 failed login attempts from a single external IP address** within the examined 90-minute period.

**2. Checked for successful authentication**

Used Windows Security Event ID 4624 to investigate successful logins and determine whether the suspicious source IP addresses had authenticated.

```kql
SecurityEvent
| where EventID == 4624
| where Computer startswith "soc-lab-vm"
| where TimeGenerated between (
    datetime(2026-11-15T17:00:00Z) ..
    datetime(2026-11-15T18:30:00Z)
)
| where IpAddress in (
    "45.88.138.5",
    "144.225.43.82",
    "220.71.237.220"
)
| project TimeGenerated, Account, IpAddress, LogonType
| sort by TimeGenerated desc
```

**Result:** No successful logins were identified from the three suspicious IP addresses during the investigated period. Separately observed successful administrator RDP activity was verified as legitimate.

**3. Documented findings**

Recorded the investigation using a structured SOC ticket template, including:

- Alert details, affected system and evidence
- Relevant Windows event IDs, IP addresses and timestamps
- Confirmed facts versus assumptions
- Potential impact, investigation actions and recommended next steps

**4. Classified and closed the incident**

Classified the incident as **True Positive**, consistent with suspected brute-force activity, and closed it after documenting the investigation.

### Investigation Outcome

The collected evidence confirmed repeated failed authentication attempts consistent with potential brute-force behaviour.

**No successful unauthorised access was identified in the reviewed logs.** However, the investigation did not establish that compromise was impossible.

The exercise demonstrated the SOC investigation lifecycle: **Detection → Triage → Log Analysis → Evidence Review → Documentation → Classification → Closure**.
## Screenshots & Evidence

The following screenshots document the SOC lab environment, log collection, automated detection and incident investigation.

### 1. Lab Setup & Log Collection

**Microsoft Sentinel environment**

![Microsoft Sentinel Overview](screenshots/01-Lab-Setup/Sentinel%20Overview.png)

**Windows Security event collection**

![Windows Security Events](screenshots/02-Log-Collection-and-Verification/Windows%20Security%20Events.png)

**Sysmon process creation monitoring**

![Sysmon Event ID 1](screenshots/02-Log-Collection-and-Verification/Sysmon%20Event%20ID%201.png)

### 2. Threat Detection

**Scheduled analytics rule for detecting repeated failed logins**

![Failed Login Analytics Rule](screenshots/03-Threat-Detection/Failed%20Login%20Analytics%20Rule.png)

**Security incident generated by Microsoft Sentinel**

![Security Incident](screenshots/03-Threat-Detection/Security%20Incident.png)

### 3. Incident Investigation & Resolution

**KQL investigation of failed authentication attempts**

![Failed Login Investigation](screenshots/04-Incident-Investigation/Failed%20Logins.png)

**Checking for successful logins from suspicious IP addresses**

![Suspicious IP Login Check](screenshots/04-Incident-Investigation/Suspicious%20IP%20Login%20Check.png)

**Documented SOC investigation ticket**

![Alert Investigation Ticket](screenshots/04-Incident-Investigation/Alert%20Investigation%20Ticket.png)

**Incident classified as True Positive and closed**

![Closed Incident](screenshots/04-Incident-Investigation/Case%20Closed.png)

### Additional Evidence

The remaining screenshots, including Sysmon setup, PowerShell commands, process execution logs and successful authentication checks, are available in the repository's `screenshots` directory.
## What I'd Add Next

To build on this SOC lab and develop my practical security monitoring and incident response skills, the next improvements I'd make are:

- **Additional Detection Rules:** Create rules for suspicious PowerShell activity, unusual account behaviour and other potential security threats.
- **More Attack Scenarios:** Simulate different types of attacks to practise detecting, investigating and responding to security incidents.
- **Incident Response Automation:** Explore Microsoft Sentinel playbooks and automation rules to automate parts of the investigation and response process.
- **Threat Intelligence Integration:** Incorporate threat intelligence sources to provide additional context when investigating suspicious IP addresses.
- **Expanded MITRE ATT&CK Coverage:** Map more detection rules to MITRE ATT&CK techniques to improve threat detection coverage.
