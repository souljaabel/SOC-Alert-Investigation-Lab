# SOC Alert Investigation Lab

## Overview

This project demonstrates a Security Operations Center (SOC) investigation workflow using Splunk Cloud and a synthetic Windows security event dataset.

The investigation focuses on a simulated suspicious authentication sequence involving repeated failed login attempts, a subsequent successful login, encoded PowerShell execution, and command-line activity.

The goal was to identify suspicious behavior, develop SPL detection searches, correlate security events, and document investigation findings.

## Project Objectives

- Identify repeated failed authentication attempts.
- Investigate successful logins following authentication failures.
- Detect suspicious PowerShell execution involving encoded commands.
- Examine Windows process creation events.
- Build a chronological incident timeline.
- Document findings in a SOC-style investigation report.

## Tools and Technologies

| Tool | Purpose |
|---|---|
| Splunk Cloud | SIEM searches and event investigation |
| SPL | Detection queries and event correlation |
| Windows Security Event IDs | Authentication and process activity analysis |
| GitHub | Project documentation and version control |
| CSV | Synthetic security event dataset |

## Environment

- SIEM: Splunk Cloud
- Index: `main`
- Sourcetype: `csv`
- Simulated workstation: `WIN11-WS01`
- Dataset size: 14 events
- Dataset type: Synthetic training data

## Investigation Scenario

The simulated scenario follows this sequence:

1. Eight failed login attempts against the `j.smith` account.
2. A successful remote interactive login from the same source IP.
3. PowerShell launched with an encoded command.
4. Command Prompt launched.
5. `whoami.exe` executed.
6. A separate administrator login and normal application launch occurred.

The investigation examines whether these events form a suspicious sequence that would warrant escalation in a real SOC environment.

## Detection Results

| Detection | Result |
|---|---|
| Failed authentication attempts (Event ID 4625) | 8 |
| Successful authentication events (Event ID 4624) | 2 |
| Process creation events (Event ID 4688) | 4 |
| Suspicious encoded PowerShell event | 1 |
| Total events analyzed | 14 |

## Key Findings

- Eight failed login attempts targeted `j.smith`.
- The attempts originated from `203.0.113.77`.
- A successful remote interactive login followed at 09:02:10 UTC.
- At 09:03:05 UTC, PowerShell launched with the `-EncodedCommand` argument.
- Subsequent process activity included `cmd.exe` and `whoami.exe`.

**Assessment:** The sequence represents suspicious behavior that warrants further investigation. The synthetic evidence does not establish a real compromise.

## Splunk Detection Queries

The repository includes four SPL detection and investigation searches:

| File | Purpose |
|---|---|
| `01_failed_login_detection.spl` | Identifies repeated failed logins |
| `02_successful_login_detection.spl` | Reviews successful authentication |
| `03_suspicious_powershell_detection.spl` | Detects encoded PowerShell execution |
| `04_incident_timeline.spl` | Displays events chronologically |

All searches use the uploaded dataset's Splunk index and sourcetype:

- `index=main`
- `sourcetype=csv`

## MITRE ATT&CK Mapping

| Technique | ID | Observed behavior |
|---|---|---|
| Brute Force | T1110 | Repeated failed authentication |
| Valid Accounts | T1078 | Successful authentication |
| PowerShell | T1059.001 | PowerShell process execution |
| Command and Scripting Interpreter | T1059 | Command-line activity |

These mappings are investigative hypotheses based on the simulated events, not confirmed adversary techniques.

## Repository Structure

```text
SOC-Alert-Investigation-Lab/
│
├── README.md
│
├── data/
│   └── security_events.csv
│
├── detections/
│   ├── 01_failed_login_detection.spl
│   ├── 02_successful_login_detection.spl
│   ├── 03_suspicious_powershell_detection.spl
│   └── 04_incident_timeline.spl
│
├── investigation/
│   └── incident_report.md
│
└── screenshots/
    └── README.md
```

## Evidence and Documentation

The `screenshots/` directory contains Splunk screenshots demonstrating the detection and investigation process.

The `investigation/incident_report.md` file contains the detailed investigation, event timeline, indicators of interest, MITRE ATT&CK mappings, and recommended response actions.

## Important Dataset Limitations

- All events are synthetic and created for educational purposes.
- The source IP `203.0.113.77` belongs to a documentation-reserved IP range.
- The encoded PowerShell command is truncated in the supplied dataset.
- No actual endpoint compromise or malicious execution was verified.
- The investigation demonstrates SOC detection and analysis techniques rather than a confirmed real-world incident.

## Skills Demonstrated

- Security event analysis
- Splunk Cloud and SPL
- Windows authentication monitoring
- Failed login detection
- Process creation analysis
- Suspicious PowerShell investigation
- Event correlation and timeline construction
- MITRE ATT&CK mapping
- Incident documentation and reporting

## Project Status

Completed initial detection searches and synthetic incident investigation. Splunk screenshots and final repository evidence are being documented.

---

**Disclaimer:** This project uses synthetic security data for educational and portfolio demonstration purposes. No real organization, user account, or security incident is represented.
