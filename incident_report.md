# Security Incident Report

**Cloudora Security Operations** | CLD-IR-TEMPLATE | CONFIDENTIAL — Internal and client distribution only

---

| Field | Value |
|---|---|
| **Report ID** | CLD-IR-0001 |
| **Related ticket** | CLD-0001 — Suspicious sign-in activity: alice.mehra@cloudora.com |
| **Report title** | Employee account takeover via password spray with MFA persistence and BEC staging |
| **Analyst** | SOC Analyst, Cloudora engagement (MyFirstHack training) |
| **Date of report (UTC)** | 2026-08-05 |
| **Incident severity** | P1 — Active enterprise deal; mailbox and application access potentially compromised |
| **Status** | Contained — eradication verified, monitoring continues |
| **Classification** | CONFIDENTIAL — Internal and client distribution only |

---

## 1. Executive Summary

On 5 August 2026, an external attacker compromised the Entra ID account of `alice.mehra@cloudora.com` using a password spray attack originating from a Tor exit node in Bucharest, Romania (185.220.101.14). After three failed login attempts that briefly locked the account, the attacker successfully authenticated at 03:11 UTC. In the following 14 minutes, they enrolled a rogue MFA device, modified the mailbox configuration, created an inbox rule consistent with Business Email Compromise staging, assigned application roles to a service principal, and manipulated the user's refresh token to maintain durable access. The same day, the attacker attempted — and failed — to compromise three additional accounts (vikram.singh, priya.nair, and the tenant admin account), with the admin attempt being blocked by MFA. No evidence of data exfiltration or fraudulent payment was found in available telemetry, though inbox rule content could not be fully verified. The compromised account has been contained; all attacker-registered devices and tokens have been revoked.

---

## 2. Incident Timeline

All times UTC. Sources: CloudoraSignIn_CL (sign-in logs), CloudoraAudit_CL (audit logs).

| Time (UTC) | Source | Event |
|---|---|---|
| Aug 5, 02:14 | Sign-in | alice.mehra normal login from Pune, India — IP 49.36.12.45 |
| Aug 5, 03:02 | Sign-in | Failed login on alice.mehra from 185.220.101.14 (Bucharest, RO) — ErrorCode 50126 |
| Aug 5, 03:04 | Sign-in | Failed login on alice.mehra from 185.220.101.14 — ErrorCode 50126 |
| Aug 5, 03:05 | Sign-in | Failed login on alice.mehra from 185.220.101.14 — ErrorCode 50053 (account locked) |
| Aug 5, 03:11 | Sign-in | **SUCCESSFUL login — alice.mehra from 185.220.101.14 — compromise confirmed** |
| Aug 5, 03:12 | Sign-in | Second successful login from 185.220.101.14 — session established |
| Aug 5, 03:13 | Audit | Update user — alice.mehra profile modified from 185.220.101.14 |
| Aug 5, 03:14 | Audit | Register security info — attacker enrolls own MFA device (T1098.005) |
| Aug 5, 03:16 | Audit | Set-Mailbox — mailbox configuration changed from 185.220.101.14 |
| Aug 5, 03:17 | Audit | New-InboxRule — inbox rule created from 185.220.101.14 (T1564.008) |
| Aug 5, 03:21 | Audit | Add app role assignment to service principal — privilege escalation (T1098.003) |
| Aug 5, 03:25 | Audit | Update StsRefreshTokenValidFrom Timestamp — token manipulation (T1550.001) |
| Aug 5, 05:47 | Sign-in | Failed spray attempt on vikram.singh — IP 41.203.72.5, Lagos, NG |
| Aug 5, 09:40 | Sign-in | Failed spray on admin@cloudora.com — IP 192.0.2.44, MFA blocked (ErrorCode 50076) |
| Aug 5, 09:41 | Audit | Failed attempt to add member to Global Administrator role — same IP |
| Aug 5, 11:52 | Sign-in | Failed spray on priya.nair — IP 156.146.55.201, Amsterdam, NL |
| Aug 5, 13:33 | Sign-in | Failed spray on vikram.singh — IP 196.52.43.19, Cairo, EG |

---

## 3. Findings

### Finding 1 — alice.mehra@cloudora.com compromised via password spray
The account was accessed without authorisation from IP 185.220.101.14 (Bucharest, Romania — a known Tor exit node), following three failed login attempts that temporarily locked the account. Impossible travel is confirmed: the user's prior legitimate login was from Pune, India 57 minutes earlier. Techniques: T1110.003, T1078.004.

### Finding 2 — Attacker established MFA persistence via device registration
Within 3 minutes of gaining access, the attacker registered their own authenticator device under alice.mehra's security info. This creates persistence that survives a password reset — the enrolled device must be explicitly removed. Technique: T1098.005.

### Finding 3 — Inbox rule created consistent with BEC staging
A new inbox rule was created at 03:17 UTC from the attacker's IP, preceded by a mailbox configuration change. This sequence is a standard BEC pattern used to intercept or hide finance and invoice correspondence. Exact rule criteria require Exchange audit log review (not in scope). Technique: T1564.008, T1114.002.

### Finding 4 — Application role escalation via service principal
The attacker assigned application roles to a service principal at 03:21 UTC. If the targeted SP holds Microsoft Graph or similar API permissions, this provides ongoing API-level access to tenant data independent of the alice.mehra account. Target SP name not captured in available telemetry. Technique: T1098.003.

### Finding 5 — Session persistence via refresh token manipulation
The `StsRefreshTokenValidFrom` timestamp was updated at 03:25 UTC. This technique can invalidate existing legitimate sessions while preserving the attacker's own tokens. Remediation required explicit revocation, not just password change. Technique: T1550.001.

### Finding 6 — Three additional accounts targeted; all failed
The attacker operated from four additional IPs across three countries (Nigeria, Netherlands, Egypt) targeting vikram.singh, priya.nair, and admin@cloudora.com. The admin attempt was blocked by MFA; the attacker immediately attempted Global Administrator role assignment (also blocked). No evidence of compromise on these accounts. Technique: T1110.003.

---

## 4. Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| IP | 185.220.101.14 | Primary attacker IP — Tor exit node, Bucharest, RO — all post-compromise audit events |
| IP | 41.203.72.5 | Spray attempt on vikram.singh — Lagos, NG |
| IP | 192.0.2.44 | Spray attempt on admin — origin unknown |
| IP | 156.146.55.201 | Spray attempt on priya.nair — Amsterdam, NL |
| IP | 196.52.43.19 | Spray attempt on vikram.singh — Cairo, EG |
| Account | alice.mehra@cloudora.com | Primary compromised account |
| Activity | Register security info (03:14 UTC) | Rogue MFA device enrolled |
| Activity | New-InboxRule (03:17 UTC) | BEC staging inbox rule |

---

## 5. Response Actions Taken

| Action | Rationale |
|---|---|
| alice.mehra password reset | Revoke attacker's credential knowledge |
| All registered security info removed and re-enrolled by user | Eliminate attacker MFA device |
| All active sessions and refresh tokens revoked | Counter token persistence (T1550.001) |
| Inbox rule reviewed and removed | Remove BEC staging mechanism |
| App role assignments audited | Identify and revoke attacker-granted SP permissions |
| Attacker IPs blocked at Conditional Access | Prevent re-entry from known infrastructure |
| vikram.singh, priya.nair passwords reset (precautionary) | Accounts were targeted; credentials may have been valid |
| admin@cloudora.com MFA configuration reviewed | Verify MFA is configured correctly given targeting |

---

## 6. Recommendations

1. **Enable impossible travel alerts in Entra ID Identity Protection.** This attack would have triggered an alert at 03:11 UTC — before any post-compromise actions occurred.

2. **Alert on `Register security info` events outside business hours or from unknown IPs.** MFA device registration is the most durable persistence mechanism observed in this incident; it should be a high-priority detection signal.

3. **Alert on `New-InboxRule` events.** Inbox rule creation outside business hours or from non-standard IPs is a strong BEC indicator with low false-positive rate.

4. **Implement Named Locations in Conditional Access.** Block or require step-up MFA for logins from Tor exit nodes and high-risk countries not in Cloudora's operating footprint.

5. **Audit service principal permissions.** Identify what permissions the targeted SP holds and whether the app role assignment should be revoked. Restrict SP role assignment to privileged admin accounts only.

6. **Follow up on neha.kapoor@cloudora.com.** Same-day logins from India and Singapore should be confirmed as legitimate VPN usage.

7. **Require phishing-resistant MFA (FIDO2) for admin@cloudora.com.** The admin account was the highest-value target. Standard TOTP MFA is still vulnerable to real-time phishing; hardware keys are not.

---

## 7. Scope Limitations

- Inbox rule criteria (forward-to address and filter conditions) require a full Exchange audit log export which was not in scope for this investigation
- The specific service principal targeted in Finding 4 is not identifiable from available telemetry
- No endpoint or EDR data was available to profile attacker device characteristics
- Email content was not reviewed — BEC success (i.e., whether any emails were intercepted) cannot be confirmed or excluded from available data
