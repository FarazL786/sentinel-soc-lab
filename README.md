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
