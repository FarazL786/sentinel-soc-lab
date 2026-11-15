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
