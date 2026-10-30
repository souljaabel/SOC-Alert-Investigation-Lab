# SOC Incident Investigation Report

## Case Information

| Field | Details |
|---|---|
| Case ID | SOC-2026-001 |
| Incident Type | Suspicious Authentication and PowerShell Execution |
| Provisional Severity | High |
| Affected Host | WIN11-WS01 |
| Affected Account | j.smith |
| Investigation Date | October 28, 2026 |
| Analyst Role | SOC Tier 1 Analyst |
| Dataset | Synthetic Windows Security Events |

## 1. Executive Summary

An investigation of Windows Security events identified
multiple failed remote authentication attempts against
the account j.smith.

Eight failed login attempts were followed by a successful
remote interactive login from the same source IP address.

Shortly afterward, PowerShell launched with an encoded
command-line argument.

The sequence is consistent with a possible account
compromise followed by suspicious command execution.

However, the available evidence does not establish what
the encoded command executed or whether the workstation
was actually compromised.

## 2. Indicators of Compromise

| Indicator | Observed Value |
|---|---|
| Source IP | 203.0.113.77 |
| Target Host | WIN11-WS01 |
| Target Account | j.smith |
| Failed Logins | 8 |
| Successful Logins | 1 |
| Event IDs | 4625, 4624, 4688 |
| Suspicious Process | powershell.exe |
| Command Argument | -EncodedCommand |

Note: The source IP is reserved for documentation
examples and is not a real attacker IP.

## 3. Incident Timeline

All timestamps are UTC.

| Time | Event |
|---|---|
| 09:00:00 | First failed login |
| 09:00:56 | Eighth failed login |
| 09:02:10 | Successful remote login |
| 09:03:05 | PowerShell launched with encoded command |
| 09:04:15 | cmd.exe launched |
| 09:05:20 | whoami.exe executed |

## 4. Authentication Analysis

Windows Event ID 4625 recorded eight failed
authentication attempts against j.smith.

Windows Event ID 4624 subsequently recorded a
successful remote interactive login from the same
source IP address.

The sequence warrants investigation for possible
credential compromise.

## 5. Process Execution Analysis

Windows Event ID 4688 recorded PowerShell execution
with an encoded command-line argument.

Additional process events showed:

- cmd.exe execution
- whoami.exe execution
- User identity enumeration

These behaviors warrant further investigation.

## 6. MITRE ATT&CK Mapping

Potential behavioral mappings:

| Technique | Description |
|---|---|
| T1110 | Brute Force |
| T1021.001 | Remote Desktop Protocol |
| T1059.001 | PowerShell |
| T1033 | System Owner/User Discovery |

These mappings represent investigative hypotheses,
not confirmed attacker techniques.

## 7. Recommended Response Actions

1. Validate the successful login with the account owner.
2. Review additional authentication events.
3. Investigate the encoded PowerShell command.
4. Review process execution and parent-child relationships.
5. Check for additional suspicious account activity.
6. If compromise is confirmed, isolate the workstation
   according to incident response policy.
7. Reset compromised credentials and investigate
   potential persistence mechanisms.

## 8. Final Assessment

The combination of repeated failed authentication,
a subsequent successful remote login, and encoded
PowerShell execution warrants escalation.

Final determination:

Suspicious activity requiring additional validation.

## 9. Evidence Limitations

This investigation uses simulated Windows Security events.

No real workstation compromise, malware execution,
or attacker activity occurred.

The dataset does not establish the contents or effects
of the encoded PowerShell command.

Additional endpoint and authentication evidence would
be necessary to reach a definitive conclusion.
