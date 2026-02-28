# Analytic Rule Configuration – Brute-Force Detection



## Rule Name
**Brute-Force Detection Rule**



## Data Source
- Windows Security Event Logs  
- Event ID: 4625 (Failed logins)

## Severity
- Medium


## Detection Query
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
