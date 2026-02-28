# Analytic Rule Configuration – Brute-Force Detection



## Rule Name
**Brute-Force Detection Rule**



## Data Source
- Windows Security Event Logs  
- Event ID: 4625 (Failed logins)

## Severity
- Medium

## Notes / Testing
- Rule was tested on lab Windows VMs by generating failed login attempts to validate alert creation.
- Threshold (≥3 failed attempts) was chosen for lab simulation; in production, thresholds should be tuned based on baseline authentication patterns to reduce false positives.


## Detection Query
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3

