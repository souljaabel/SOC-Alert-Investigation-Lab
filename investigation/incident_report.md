# SOC Incident Investigation Report

## 1. Executive Summary

This investigation analyzes a synthetic Windows security event dataset using Splunk Cloud.

The simulated scenario involves repeated failed authentication attempts against the `j.smith` account, followed by a successful remote interactive login and suspicious process execution involving encoded PowerShell, Command Prompt, and user identity enumeration.

**Assessment:** Suspicious activity requiring investigation. The synthetic evidence demonstrates a possible compromised-account scenario but does not establish that a real compromise occurred.

## 2. Environment

- SIEM: Splunk Cloud
- Dataset: Synthetic Windows security events
- Workstation: WIN11-WS01
- Index: main
- Sourcetype: csv
- Total events analyzed: 14

## 3. Key Findings

| Finding | Result |
|---|---|
| Failed logins | 8 |
| Successful logins | 2 |
| Process creation events | 4 |
| Suspicious account | j.smith |
| Source IP | 203.0.113.77 |
| Suspicious process | powershell.exe |
| Workstation | WIN11-WS01 |

## 4. Incident Timeline

All timestamps are UTC.

| Time | Event | Description |
|---|---|---|
| 09:00:00–09:00:56 | Event ID 4625 | Eight failed login attempts against j.smith |
| 09:02:10 | Event ID 4624 | Successful remote interactive login |
| 09:03:05 | Event ID 4688 | PowerShell launched with an encoded command |
| 09:04:15 | Event ID 4688 | Command Prompt launched |
| 09:05:20 | Event ID 4688 | whoami.exe executed |
| 09:06:30 | Event ID 4624 | Administrator local console login |
| 09:07:10 | Event ID 4688 | Notepad launched |

## 5. Detection and Investigation

### Detection 1: Repeated Failed Logins

Eight Event ID 4625 events were identified against the same account and source IP within approximately one minute.

### Detection 2: Successful Authentication

An Event ID 4624 event showed a successful remote interactive login for j.smith shortly after the failed attempts.

### Detection 3: Suspicious PowerShell Execution

An Event ID 4688 event recorded PowerShell launching with the `-EncodedCommand` argument.

Encoded PowerShell commands can conceal script contents and warrant further investigation.

### Detection 4: Command Execution and Enumeration

The subsequent process events showed:

- cmd.exe
- whoami.exe

These commands can be used for command execution and user-context discovery.

## 6. Indicators of Interest

| Indicator | Value |
|---|---|
| Source IP | 203.0.113.77 |
| Account | j.smith |
| Workstation | WIN11-WS01 |
| PowerShell argument | -EncodedCommand |
| Follow-up command | whoami |

**Important:** 203.0.113.77 is an IP address reserved for documentation examples. It is not evidence of a real external attacker.

## 7. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | T1110 | Repeated failed authentication attempts |
| Valid Accounts | T1078 | Successful authentication after failures |
| PowerShell | T1059.001 | PowerShell process execution |
| Command and Scripting Interpreter | T1059 | Command-line execution |

These are potential technique mappings based on the simulated behavior, not confirmed adversary attribution.

## 8. Recommended Response Actions

1. Validate the authentication activity with the account owner.
2. Review the source IP and remote access logs.
3. Inspect the complete PowerShell command and determine what it would execute.
4. Review subsequent process activity and related endpoint telemetry.
5. If this were a real confirmed incident, follow organizational procedures for account containment and credential resets.
6. Preserve relevant logs for additional investigation.

## 9. Final Assessment

The synthetic dataset demonstrates a suspicious sequence involving repeated authentication failures, successful remote access, encoded PowerShell execution, and subsequent command-line activity.

The sequence warrants escalation for further investigation in a real SOC environment.

No actual compromise, malware execution, or data exfiltration has been established.

## 10. Evidence Limitations

- The dataset is synthetic and created for training.
- The encoded PowerShell command is truncated in the supplied data.
- No actual endpoint execution results are available.
- No network traffic or malware samples were collected.
- The source IP is documentation-reserved.
- Findings demonstrate detection and investigation techniques, not a confirmed real-world incident.

