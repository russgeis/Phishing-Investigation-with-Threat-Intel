# MITRE ATT&CK Mapping — CLD-0001

Framework: MITRE ATT&CK for Enterprise v15 (Cloud / Identity focus)

---

## Techniques Identified

| Phase | Technique ID | Technique Name | Evidence from Logs |
|---|---|---|---|
| Reconnaissance | — | Not directly observable in available telemetry | Attacker had valid credential — likely from prior breach or phishing |
| Initial Access | **T1078.004** | Valid Accounts: Cloud Accounts | Successful login from 185.220.101.14 after spray |
| Credential Access | **T1110.003** | Brute Force: Password Spraying | 3 failed attempts across alice.mehra before success; separate attempts on 3 other accounts from different IPs |
| Persistence | **T1098.005** | Account Manipulation: Device Registration | `Register security info` audit event — own MFA device enrolled |
| Persistence | **T1550.001** | Use Alternate Authentication Material: Application Access Tokens | `Update StsRefreshTokenValidFrom Timestamp` — token anchoring |
| Collection | **T1114.002** | Email Collection: Remote Email Collection | `Set-Mailbox` change enabling mailbox access |
| Defense Evasion | **T1564.008** | Hide Artifacts: Email Hiding Rules | `New-InboxRule` — email rule hiding or forwarding specific mail |
| Privilege Escalation | **T1098.003** | Account Manipulation: Additional Cloud Roles | `Add app role assignment to service principal` |
| Privilege Escalation | **T1098.003** | Account Manipulation: Additional Cloud Roles | Attempted `Add member to Global Administrator role` on admin account (blocked by MFA) |

---

## Technique Detail

### T1110.003 — Password Spraying
**Tactic:** Credential Access  
The attacker used a low-volume, distributed spray pattern — 3 attempts against alice.mehra from a single IP before moving to a different IP for the next account. This pattern avoids triggering high-volume lockout alerts. The use of Tor exit nodes across multiple countries (Romania, Nigeria, Netherlands, Egypt) is consistent with automated credential stuffing infrastructure.

### T1078.004 — Valid Accounts: Cloud Accounts
**Tactic:** Initial Access, Persistence, Defense Evasion  
Once credentials were obtained, the attacker used them to authenticate to Microsoft Entra ID (Azure AD). Valid account usage blends with legitimate traffic and bypasses many network-based detections. The sign-in appeared as a standard Entra ID authentication event with no behavioral anomaly flag beyond impossible travel.

### T1098.005 — Account Manipulation: Device Registration
**Tactic:** Persistence  
Immediately after access, the attacker registered their own authenticator as a security info method. This is one of the most durable persistence mechanisms in Entra ID — it survives password resets, persists across sessions, and allows the attacker to pass MFA challenges independently. Detection: monitor `Register security info` audit events from unexpected IP addresses or outside business hours.

### T1564.008 — Hide Artifacts: Email Hiding Rules
**Tactic:** Defense Evasion, Collection  
Inbox rules are used in BEC attacks to silently filter incoming mail — typically hiding alerts, replies, or delivery receipts from the compromised user while forwarding copies to the attacker. The combination of `Set-Mailbox` + `New-InboxRule` in sequence is a well-known BEC pattern. Detection: alert on `New-InboxRule` events outside business hours or from non-standard IPs.

### T1098.003 — Additional Cloud Roles
**Tactic:** Privilege Escalation  
Two separate escalation attempts observed: (1) app role assignment to a service principal from alice.mehra's account (succeeded), and (2) adding a member to the Global Administrator role from the admin account (failed — MFA). This shows the attacker's intent to escalate beyond the initial compromised account's permissions.

### T1550.001 — Application Access Tokens
**Tactic:** Defense Evasion, Lateral Movement  
Modifying the `StsRefreshTokenValidFrom` timestamp is a double-edged technique: it can revoke existing refresh tokens (e.g., alice.mehra's own active sessions) while preserving the attacker's freshly-issued tokens. Effective remediation requires explicit token revocation, not just password change.

### T1114.002 — Remote Email Collection
**Tactic:** Collection  
The `Set-Mailbox` configuration change likely enabled external mail access or forwarding. Without Exchange audit log details, the exact configuration is unknown — but the technique is confirmed by the audit event from the attacker's IP.

---

## ATT&CK Navigator Layer

The following techniques map to this investigation. Import this JSON at https://mitre-attack.github.io/attack-navigator/

```json
{
  "name": "CLD-0001 Cloudora ATO",
  "versions": { "attack": "15", "navigator": "4.9", "layer": "4.5" },
  "domain": "enterprise-attack",
  "techniques": [
    { "techniqueID": "T1078.004", "color": "#e60d0d", "comment": "Valid cloud account used post-spray", "enabled": true },
    { "techniqueID": "T1110.003", "color": "#e60d0d", "comment": "Password spray — 4 accounts, 5 IPs", "enabled": true },
    { "techniqueID": "T1098.005", "color": "#e60d0d", "comment": "MFA device registered by attacker", "enabled": true },
    { "techniqueID": "T1098.003", "color": "#e60d0d", "comment": "App role + GA escalation attempt", "enabled": true },
    { "techniqueID": "T1550.001", "color": "#e60d0d", "comment": "STS refresh token timestamp update", "enabled": true },
    { "techniqueID": "T1564.008", "color": "#e60d0d", "comment": "Inbox rule created (BEC staging)", "enabled": true },
    { "techniqueID": "T1114.002", "color": "#e60d0d", "comment": "Set-Mailbox — remote email collection", "enabled": true }
  ]
}
```
