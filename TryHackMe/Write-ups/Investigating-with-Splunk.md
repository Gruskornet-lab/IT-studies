# TryHackMe — Investigating with Splunk

| | |
|---|---|
| **URL** | https://tryhackme.com/room/investigatingwithsplunk |
| **Category** | Blue Team / SOC / Log Analysis (Splunk) |
| **Difficulty** | Medium |
| **Estimated Time** | 30 minutes |
| **Completions** | 43,734 |
| **Date Completed** | 2026-10-07 |

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
Use the correct time frame and index=main and you will find all collected events.

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
The EventID for creating a new user is 4720. So when you filter for the right eventid you will en up with 1 matching event and in the message you will find the account name of th enew user 
<img width="1052" height="176" alt="image" src="https://github.com/user-attachments/assets/35af2e87-f0aa-421a-850b-c2bb909effa8" />


**SPL query:**
```spl
index=main EventID=4720
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
We know the new username "A1berto" and the EventID of 13 that gives us RegistryEvent
<img width="1012" height="323" alt="image" src="https://github.com/user-attachments/assets/5d085a11-b885-4dce-96a6-d5437c3c9d63" />


**SPL query:**
```spl
index=main EventID="13" A1berto
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
The name Alberto has the lowercase l switched with a 1 to look the same.

**SPL query:**
```spl
index=main
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
<img width="1835" height="530" alt="image" src="https://github.com/user-attachments/assets/51b99bc2-c046-44b4-affb-c63e2aa36a6b" />

**SPL query:**
```spl
index=main WMIC A1berto
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
To find out if there was any successful loggin with this backdoor user we will filter the search bar for the user and eventid: of 4624 and 4625. 
<img width="786" height="302" alt="image" src="https://github.com/user-attachments/assets/da80c91e-becf-4f9e-b0c5-ee926ae928cb" />


**SPL query:**
```spl
index=main (EventID="4624" OR EventID="4625") A1berto
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
<img width="2526" height="522" alt="image" src="https://github.com/user-attachments/assets/72da8805-4e2f-4c6c-9191-3096b04eafb9" />


**SPL query:**
```spl
index=main SourceName="Microsoft-Windows-PowerShell"
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
index=main SourceName="Microsoft-Windows-PowerShell"
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
Inspecting the suspicious powershell command we find this long Base64 string.
<img width="1793" height="494" alt="image" src="https://github.com/user-attachments/assets/0eace0e5-86c5-4e2a-aa2b-530a78bfc1a5" />
We can take this Base64 string into CyberChef to decode it and see what it says. In the output we find yet another Base64 string that has /news.php behind it. 
<img width="1277" height="506" alt="image" src="https://github.com/user-attachments/assets/3a36d973-341b-4858-8eea-09c8a2e9b488" />
Decoding this Base64 string we get this.
<img width="424" height="726" alt="image" src="https://github.com/user-attachments/assets/1839fa79-3764-478f-937a-5d6a5cbb6f1f" />
and so we know the C2 the attacker is likely using.

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
index=main EventID=4720

# Login attempts (success / failure)
index=main (EventCode=4624 OR EventCode=4625) "<user>"
| stats count by EventID

# Remote account creation via WMIC
index=main CommandLine="*WMIC*" CommandLine="*net user*"

# Suspicious PowerShell
index=main SourceName="Microsoft-Windows-PowerShell"
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
