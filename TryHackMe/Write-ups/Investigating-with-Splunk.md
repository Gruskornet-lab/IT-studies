# TryHackMe — Investigating with Splunk

| | |
|---|---|
| **URL** | https://tryhackme.com/room/investigatingwithsplunk |
| **Category** | Blue Team / SOC / Log Analysis (Splunk) |
| **Difficulty** | Medium |
| **Estimated Time** | 30 minutes |
| **Completions** | 43,734 |
| **Date Completed** | YYYY-MM-DD |

## Overview
SOC Analyst Johny has observed anomalous behaviour in the logs of a few Windows machines. The adversary appears to have access to some of them and has created a backdoor. His manager asked him to pull the logs from the suspected hosts and ingest them into Splunk for quick investigation. The task is to examine the logs and identify the anomalies.

All required logs are ingested in the Splunk index `main`.

Recommended background rooms: [Splunk 101](https://tryhackme.com/room/splunk101) and [Splunk 201](https://tryhackme.com/room/splunk201).

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID |
|--------|-----------|----|
| Execution | Windows Management Instrumentation | T1047 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Persistence | Create Account: Local Account | T1136.001 |
| Defense Evasion | Masquerading | T1036 |
| Defense Evasion | Modify Registry | T1112 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |

---

## Task 1 — Investigating with Splunk

---

**Q1: How many events were collected and ingested in the index main?**

**MITRE ATT&CK:** N/A (scoping question)

**Approach:**

**SPL query:**
```spl
index=main
```

**Answer:**
12256

---

**Q2: On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
| Persistence | Create Account: Local Account | T1136.001 |

**Approach:**

**SPL query:**
```spl
index=main EventCode=4720
| table _time host SubjectUserName TargetUserName
```

**Answer:**
A1berto

---

**Q3: On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
| Defense Evasion | Modify Registry | T1112 |

**Approach:**

**SPL query:**
```spl
index=main host="<infected host>" "<backdoor user>" (EventCode=12 OR EventCode=13 OR EventCode=4657)
| table _time host EventCode TargetObject Image
```

**Answer:**
HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto

---

**Q4: Examine the logs and identify the user that the adversary was trying to impersonate.**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
| Defense Evasion | Masquerading | T1036 |

**Approach:**

**SPL query:**
```spl
index=main
| stats count by User
```

**Answer:**
Alberto

---

**Q5: What is the command used to add a backdoor user from a remote computer?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
| Execution | Windows Management Instrumentation | T1047 |
| Persistence | Create Account: Local Account | T1136.001 |

**Approach:**

**SPL query:**
```spl
index=main "<backdoor user>" (CommandLine="*WMIC*" OR CommandLine="*net user*")
| table _time host User ParentImage CommandLine
```

**Answer:**
C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1

---

**Q6: How many times was the login attempt from the backdoor user observed during the investigation?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
| Persistence / Defense Evasion | Valid Accounts: Local Accounts | T1078.003 |

**Approach:**

**SPL query:**
```spl
index=main (EventCode=4624 OR EventCode=4625) "<backdoor user>"
| stats count by EventCode host
```

**Answer:**
0

---

**Q7: What is the name of the infected host on which suspicious PowerShell commands were executed?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |

**Approach:**

**SPL query:**
```spl
index=main powershell
| stats count by host
```

**Answer:**
James.browne

---

**Q8: PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

**Approach:**

**SPL query:**
```spl
index=main host="<infected host>" source="*PowerShell*" 
| stats count by EventCode
```

**Answer:**
79

---

**Q9: An encoded PowerShell script from the infected host initiated a web request. What is the full URL?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

**Approach:**

**SPL query:**
```spl
index=main host="<infected host>" EventCode=4104 "*FromBase64String*"
| table _time ScriptBlockText
```

Decode in CyberChef: `From Base64` → `Decode text` (UTF-16LE). Defang the URL before saving it in the IOC table.

**Answer:**
hxxp[://]10[.]10[.]10[.]5/news[.]php

---

## Tools & Commands

```spl
# Count all events in the index
index=main

# Backdoor account creation
index=main EventCode=4720

# Login attempts (success / failure)
index=main (EventCode=4624 OR EventCode=4625) "<user>"
| stats count by EventCode

# Remote account creation via WMIC
index=main CommandLine="*WMIC*" CommandLine="*net user*"

# Suspicious PowerShell
index=main powershell
| stats count by host
```

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| User |  | Backdoor user created by the adversary |
| Host |  | Host with suspicious PowerShell activity |
| Registry key |  | Key updated for the backdoor user |
| Command |  | Remote command used to add the backdoor user |
| URL |  | Web request from encoded PowerShell (defanged) |

## Key Takeaways
- 
- 

---

*Source: [TryHackMe — Investigating with Splunk](https://tryhackme.com/room/investigatingwithsplunk)*
