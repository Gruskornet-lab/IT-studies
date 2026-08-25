# TryHackMe — Benign

| | |
|---|---|
| **URL** | https://tryhackme.com/room/benign |
| **Category** | Blue Team / SOC / Log Analysis (Splunk) |
| **Difficulty** | Medium |
| **Estimated Time** | 150 minutes |
| **Completions** | 41,283 |
| **Date Completed** | YYYY-MM-DD |

## Overview
Challenge room where you investigate host-centric Windows event logs (Event ID 4688 — process creation) ingested into a Splunk index called `win_eventlogs`. A host in the HR department is suspected of being compromised; the goal is to trace the suspicious process execution, identify LOLBIN usage, payload delivery, and C2 activity.

**Network segments:**

| Department | Users |
|---|---|
| IT | James, Moin, Katrina |
| HR | Haroon, Chris, Diana |
| Marketing | Bell, Amelia, Deepak |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID |
|--------|-----------|----|
| Execution | | |
| Discovery | | |
| Scheduled Task/Job | | |
| Command and Control | | |

---

## Task 1 — Set up your virtual environment

Deploy the AttackBox/VPN and the Room Machine. Logs are pre-ingested into the Splunk index `win_eventlogs`. No questions — just connect to the lab.

---

## Task 2 — Scenario: Identify and Investigate an Infected Host

---

**Q1: How many logs are ingested from the month of March, 2022?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q2: Imposter Alert — there seems to be an imposter account observed in the logs. What is the name of that user?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q3: Which user from the HR department was observed to be running scheduled tasks?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q4: Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q5: To bypass the security controls, which system process (LOLBIN) was used to download a payload from the internet?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q6: What was the date that this binary was executed by the infected host? (format: YYYY-MM-DD)**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q7: Which third-party site was accessed to download the malicious payload?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q8: What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q9: The suspicious file downloaded from the C2 server contained malicious content with the pattern `THM{..........}`. What is that pattern?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q10: What is the URL that the infected host connected to?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

## Tools & Commands

```spl
# Splunk SPL queries go here
# e.g. index=win_eventlogs EventCode=4688 ...
```

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP | | |
| Domain | | |
| URL | | |
| File name | | |
| Hash | | |

## Key Takeaways
-

---

*Source: [TryHackMe — Benign](https://tryhackme.com/room/benign)*
