# Attack Timeline — CLD-0001

All times UTC. Sources: `CloudoraSignIn_CL` (sign-in logs), `CloudoraAudit_CL` (audit logs).

---

## Phase 1 — Baseline (Pre-Attack)

| Time (UTC) | Source | Event | Evidence / Notes |
|---|---|---|---|
| 2026-08-05 02:14 | Sign-in | alice.mehra logs in normally from Pune, India | IP 49.36.12.45, ErrorCode 0, Status: Success |
| 2026-08-05 02:31 | Sign-in | rahul.deshpande logs in from Mumbai | IP 103.27.9.201 — normal activity |

---

## Phase 2 — Password Spray / Brute Force (T1110.003)

| Time (UTC) | Source | Event | Evidence / Notes |
|---|---|---|---|
| 2026-08-05 03:02 | Sign-in | **FAIL** — alice.mehra targeted from Bucharest | IP 185.220.101.14, RO, ErrorCode 50126 (bad password) |
| 2026-08-05 03:04 | Sign-in | **FAIL** — alice.mehra targeted from Bucharest | IP 185.220.101.14, RO, ErrorCode 50126 |
| 2026-08-05 03:05 | Sign-in | **FAIL** — Account locked | IP 185.220.101.14, RO, ErrorCode 50053 (account lockout) |

> **Note:** 185.220.101.14 is a known Tor exit node (Bucharest, Romania). Low-volume spray (3 attempts) consistent with slow-and-low credential stuffing to avoid lockout detection.

---

## Phase 3 — Initial Access (T1078.004)

| Time (UTC) | Source | Event | Evidence / Notes |
|---|---|---|---|
| 2026-08-05 03:11 | Sign-in | ✅ **COMPROMISE** — alice.mehra accessed from Bucharest | IP 185.220.101.14, RO, ErrorCode 0, Status: Success |
| 2026-08-05 03:12 | Sign-in | ✅ Second successful login from same IP | Session established, attacker active |

> **Impossible travel confirmed:** alice.mehra's last known legitimate login was from Pune, India (02:14 UTC). A Bucharest login at 03:11 UTC — 57 minutes later — is geographically impossible by normal travel.

---

## Phase 4 — Post-Compromise Actions (13 minutes, 6 audit events)

| Time (UTC) | Source | Event | MITRE | Evidence / Notes |
|---|---|---|---|---|
| 2026-08-05 03:13 | Audit | Update user — alice.mehra | T1078 | Profile modification; IP 185.220.101.14 |
| 2026-08-05 03:14 | Audit | **Register security info** | T1098.005 | Attacker enrolled own MFA device on alice.mehra's account — persistence established |
| 2026-08-05 03:16 | Audit | **Set-Mailbox** | T1114.002 | Mailbox configuration changed; likely delegation or forwarding enabled |
| 2026-08-05 03:17 | Audit | **New-InboxRule** | T1564.008 | Inbox rule created — classic BEC staging (finance/invoice email filtering) |
| 2026-08-05 03:21 | Audit | **Add app role assignment to service principal** | T1098.003 | Privilege escalation attempt via application permissions |
| 2026-08-05 03:25 | Audit | **Update StsRefreshTokenValidFrom Timestamp** | T1550.001 | Refresh token manipulated — attacker maintaining their own session while potentially invalidating others |

> **13-minute compromise window:** All post-compromise actions occurred between 03:13 and 03:25 — consistent with a scripted or automated playbook, not manual operation.

---

## Phase 5 — Lateral Spray Attempts

| Time (UTC) | Source | Event | Evidence / Notes |
|---|---|---|---|
| 2026-08-05 05:47 | Sign-in | **FAIL** — vikram.singh targeted from Lagos | IP 41.203.72.5, NG, ErrorCode 50126 |
| 2026-08-05 09:40 | Sign-in | **FAIL** — admin@cloudora.com MFA challenged | IP 192.0.2.44, Unknown, ErrorCode 50076 — MFA blocked this |
| 2026-08-05 09:41 | Audit | **FAIL** — Add member to Global Administrator role | IP 192.0.2.44 — privilege escalation blocked by MFA |
| 2026-08-05 11:52 | Sign-in | **FAIL** — priya.nair targeted from Amsterdam | IP 156.146.55.201, NL, ErrorCode 50126 |
| 2026-08-05 11:53 | Audit | **FAIL** — Update user (priya.nair) | IP 156.146.55.201 — sign-in failed, audit event still logged |
| 2026-08-05 13:33 | Sign-in | **FAIL** — vikram.singh targeted from Cairo | IP 196.52.43.19, EG, ErrorCode 50126 |

> **Analysis:** The attacker attempted 4 additional accounts from 4 different IPs across 5 countries — indicative of distributed infrastructure (possibly different Tor exit nodes or rented proxies). The attempt on `admin@cloudora.com` is most concerning — targeting the highest-privilege account and attempting Global Administrator role assignment.

---

## Summary

| Metric | Value |
|---|---|
| Attack start | 03:02 UTC Aug 5 2026 |
| Compromise time | 03:11 UTC Aug 5 2026 |
| Time from first fail to compromise | ~9 minutes |
| Post-compromise dwell time (active) | 14 minutes (03:11–03:25) |
| Accounts targeted | 4 (alice.mehra, vikram.singh, priya.nair, admin) |
| Accounts compromised | 1 (alice.mehra) |
| Persistence mechanisms deployed | 3 (MFA enrollment, inbox rule, token manipulation) |
| Attacker IPs identified | 5 |
