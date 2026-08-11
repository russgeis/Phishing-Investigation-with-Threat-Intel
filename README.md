# Cloudora — Account Takeover Investigation (CLD-0001)

> **Type:** SOC Analyst Lab | **Platform:** Azure Data Explorer + KQL | **Source:** MyFirstHack — Sarvesh Murali  
> **Difficulty:** Beginner-friendly | **Estimated time:** 4–6 hours | **Completed:** August 2026

---

## Scenario

Cloudora is a 150-person B2B HR software company based in London. At 08:55 one morning, the IT admin flagged anomalous sign-in activity: an employee account appeared to have been accessed from Lagos, Nigeria at 03:12 — while the user was asleep in London.

**Ticket:** CLD-0001 — Suspicious sign-in activity  
**Priority:** P1 — Active enterprise deal in progress, executive mailbox at risk  
**Analyst role:** SOC Analyst, working under vCISO Sarvesh

The objective: confirm or refute the compromise, build a full timeline, identify any persistence mechanisms, check for lateral movement, and produce an incident report.

---

## What I Found

The account of `alice.mehra@cloudora.com` was successfully compromised via a password spray attack originating from **185.220.101.14** (Bucharest, Romania — a known Tor exit node). Within 12 minutes of gaining access, the attacker established four persistence and staging mechanisms before being detected.

| | |
|---|---|
| **Primary victim** | alice.mehra@cloudora.com |
| **Attacker IP** | 185.220.101.14 (Tor exit node, Bucharest RO) |
| **Compromise window** | 03:11 – 03:25 UTC, Aug 5 2026 (14 minutes) |
| **Accounts targeted** | 4 (1 compromised, 3 spray attempts blocked) |
| **Persistence mechanisms** | MFA device registration, inbox rule, refresh token manipulation |
| **MITRE techniques** | 5 (T1110.003, T1078.004, T1098.005, T1564.008, T1098.003, T1550.001) |

---

## Attack Chain

```
[02:14 UTC]  alice.mehra → legitimate login from Pune, India (49.36.12.45)

[03:02 UTC]  185.220.101.14 (Bucharest) → FAIL — ErrorCode 50126 (bad password)
[03:04 UTC]  185.220.101.14 (Bucharest) → FAIL — ErrorCode 50126
[03:05 UTC]  185.220.101.14 (Bucharest) → FAIL — ErrorCode 50053 (account LOCKED)

                ↓ ~6 minutes later (account unlocked / reset)

[03:11 UTC]  185.220.101.14 (Bucharest) → ✅ SUCCESS — COMPROMISE CONFIRMED
[03:12 UTC]  185.220.101.14 (Bucharest) → ✅ SUCCESS (session established)

[03:13 UTC]  Attacker: Update user            → profile modified
[03:14 UTC]  Attacker: Register security info  → OWN MFA DEVICE ENROLLED (persistence)
[03:16 UTC]  Attacker: Set-Mailbox             → mailbox configuration changed
[03:17 UTC]  Attacker: New-InboxRule           → inbox rule created (BEC staging)
[03:21 UTC]  Attacker: Add app role to SP      → privilege escalation attempt
[03:25 UTC]  Attacker: Update STS refresh token → token manipulation (maintains access)

[05:47 UTC]  41.203.72.5 (Lagos, NG)      → spray attempt on vikram.singh — FAIL
[09:40 UTC]  192.0.2.44  (Unknown)        → spray on admin@cloudora.com — MFA BLOCKED
[11:52 UTC]  156.146.55.201 (Amsterdam)   → spray on priya.nair — FAIL
[13:33 UTC]  196.52.43.19  (Cairo, EG)    → spray on vikram.singh — FAIL
```

---

## Repository Structure

```
cloudora-ato-investigation/
├── README.md                         ← this file
├── data/
│   ├── cloudora_signin_logs.csv      ← Entra ID sign-in logs (22 events)
│   └── cloudora_audit_logs.csv       ← Entra ID audit logs (8 events)
├── queries/
│   └── investigation_queries.kql     ← all KQL queries used in Azure Data Explorer
├── analysis/
│   ├── timeline.md                   ← full timestamped attack timeline
│   ├── findings.md                   ← findings with evidence and log references
│   └── mitre_attack_mapping.md       ← MITRE ATT&CK technique mapping
└── report/
    └── incident_report.md            ← completed incident report (CLD-IR-0001)
```

---

## Skills Demonstrated

- **KQL (Kusto Query Language)** — filtering, aggregation, joins, time-windowed analysis
- **Azure Data Explorer** — ingesting CSV logs, querying Entra ID sign-in and audit tables
- **Identity threat analysis** — password spray detection, impossible travel, MFA abuse
- **Post-compromise forensics** — inbox rule identification, token manipulation, app role escalation
- **MITRE ATT&CK mapping** — technique identification from log evidence
- **Incident reporting** — structured SOC report writing following professional IR templates
- **OSINT** — IOC verification (attacker IP corroborated as Tor exit node)

---

## Tools Used

| Tool | Purpose |
|---|---|
| Azure Data Explorer | Log ingestion and KQL querying |
| KQL (Kusto Query Language) | Log analysis and threat hunting |
| Microsoft Entra ID logs | Sign-in and audit telemetry source |
| MITRE ATT&CK Navigator | Technique mapping |
| VirusTotal / Shodan | IP reputation / IOC enrichment |

---

## Data Scope & Limitations

- Logs cover a single day: **Aug 5, 2026** (22 sign-in events, 8 audit events)
- Inbox rule criteria (exact forwarding target) not captured in available telemetry
- Service principal name targeted in app role assignment not included in audit log export
- No endpoint/EDR logs — attacker device characteristics partially inferred from DeviceDetail field
- The `admin@cloudora.com` successful login at 16:47 from Pune is noted but could not be confirmed as legitimate vs. attacker — flagged for follow-up

---

## Source

Training scenario by **[MyFirstHack — Sarvesh Murali](https://www.youtube.com/@MyFirstHack)**, from the Cloudora Security Operations lab pack (fictional client). Data, template, and scenario design by MyFirstHack.
