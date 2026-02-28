# Microsoft Sentinel Brute-Force Detection Lab

## Project Overview

This project focuses on detecting brute-force authentication attempts using Microsoft Sentinel. Custom KQL queries were developed to identify repeated failed login attempts within a defined time window. An analytic rule was created to trigger security alerts based on detection thresholds.

The objective was to simulate SOC-level monitoring and detection engineering in a cloud-based SIEM environment.

---

## Objectives

- Identify failed authentication attempts (Event ID 4625)
- Detect brute-force behavior patterns
- Create and configure analytic rules in Microsoft Sentinel
- Generate and validate security alerts
- Perform basic alert triage and analysis

---

## Technologies Used

- Microsoft Sentinel  
- Log Analytics Workspace  
- Windows Security Event Logs  
- KQL (Kusto Query Language)  

---

## Detection Logic

Brute-force activity was defined as:

- Multiple failed authentication attempts (Event ID 4625)  
- Targeting the same user account  
- Occurring on the same machine  
- Within a 5-minute time window  
- Threshold: 3 or more failed attempts   

### Detection Query Example

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
