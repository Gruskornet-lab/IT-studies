# TryHackMe — Promotion Night

| | |
|---|---|
| **URL** | https://tryhackme.com/room/promotionnight |
| **Category** | Blue Team / SOC / SIEM (Splunk) |
| **Difficulty** | Medium |
| **Estimated Time** | 120 minutes |
| **Completions** | 476 |
| **Date Completed** | 2026-11-20 |

## Overview
Earn the quickest promotion ever, or make it your last day at ProbablyFine. As the Level 1 night-shift SOC analyst at an MSSP, you triage a critical alert ("Potential Ransom Note on DC-01") for the newly onboarded customer DeceptiTech. Using a Splunk instance with the scenario index, you reconstruct the full intrusion: beachhead, C2, discovery, lateral movement, ransomware deployment, and AWS credential theft, exfiltration and wiping.

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

---

## Task 1 — Promotion Night

---

**Q1: What was the network share path where ransomware was placed?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**
We now that alert we are working with is related to DC-01. If we make a simple search ´´´index=* \\DC-01´´´ we get a couple events that shows a "gaze.exe" 
<img width="1581" height="763" alt="image" src="https://github.com/user-attachments/assets/2df7e4dd-a98a-404f-9344-300e155b41c3" />. 
Making a quick search on the web we can get the information that this "gaze.exe" file is highly related to a ransomware group called Medusa 

**Answer:**
\\DC-01\SYSVOL\gaze.exe

---

**Q2: What is the value ransomware created to persist on reboot?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**
Looking for a persistence that survives a reboot I start with the two obvious schedule task and registry. Filtering for schedule task gives us a couple events but doesn't give us anything strongly related directly to the gaze.exe file. So searching for HKU which is registry keys for individual user we find events with the gaze.exe process as the Image file. Here we find the value the ransomware created for persistence. 
<img width="1362" height="525" alt="image" src="https://github.com/user-attachments/assets/1a87cb69-a4ea-46e8-a5ad-5385705d9b1f" />

**Answer:**
BabyLockerKZ

---

**Q3: Which MITRE technique ID was used to deploy ransomware?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

**Q4: What ports of SRV-ITFS did the adversary successfully scan?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

**Q5: What is the full path to the malware that performed the Discovery?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

**Q6: Which artifact did the adversary create to persist on the beachhead?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

**Q7: What is the MD5 hash of the embedded initial shellcode?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

**Q8: Which C2 framework was used by the adversary in the intrusion?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

**Q9: What hostname did the adversary log in from on the beachhead?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

**Q10: What was the UNC path that likely contained AWS credentials?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

**Q11: From which IP address did the adversary access AWS?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

**Q12: Which two sensitive files did the adversary exfiltrate from AWS?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

**Q13: What file did the adversary upload to S3 in place of the wiped ones?**

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**


**Answer:**


---

## Tools & Commands

```bash
# Add commands here
```

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP |  |  |
| Domain |  |  |
| Hash |  |  |

## Key Takeaways
-
