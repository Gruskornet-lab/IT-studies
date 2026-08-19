# TryHackMe — Invite Only

| | |
|---|---|
| **URL** | https://tryhackme.com/room/invite-only |
| **Category** | Threat Intelligence / SOC |
| **Difficulty** | Easy |
| **Estimated Time** | 60 minutes |
| **Completions** | 13,570 |
| **Date Completed** | YYYY-MM-DD |

## Overview
Extract insight from a set of flagged artefacts, and distil the information into usable threat intelligence.
As an analyst on the SOC team at Managed Server Provider TrySecureMe, you are supporting an L3 analyst in investigating flagged IPs, hashes, URLs, or domains.
An L1 analyst flagged two suspicious findings — an IP and a SHA256 hash — and escalated them for further analysis using the threat intelligence tool TryDetectThis2.0.

**Flagged IP:** 101[.]99[.]76[.]120
**Flagged SHA256 hash:** 5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

---

## Task 1 — Investigate the Flagged Indicators

---

**Q1: What is the name of the file identified with the flagged SHA256 hash?**
**Approach:**
For this task we have been provided with a ip address and a SHA256 hash. To get the answer for this question we simply take the provided hash and paste it in virustotal
to get the identified file. 

<img width="769" height="261" alt="image" src="https://github.com/user-attachments/assets/65131568-a65d-47e7-a1be-bdc12bce5d67" />


**Answer:**
syshelpers.exe

---

**Q2: What is the file type associated with the flagged SHA256 hash?**

**Approach:**
In the details tab we can see more information about the malicious file and there we find the file type

<img width="1563" height="346" alt="image" src="https://github.com/user-attachments/assets/3405c4d9-8046-47f2-814c-4f826e21b170" />


**Answer:**
Win32 EXE
---

**Q3: What are the execution parents of the flagged hash? List the names chronologically, using a comma as a separator. Note down the hashes for later use.**

**Approach:**
To find the execution parents I searched for parents using Ctrl + F in the relations tab to find the header where the answer is.
Using the provided VM from TryHackMe that has it's own Virustotal tool we can also retrive the sha256 hashes for the two parents.

**Note**
| Parent | sha256 |
| 361GJX7J | 047c5eec0445746862710d20e50a5dd04510b7e625fa5c1f5d48ce078001c0de |
| installer.exe | fa102d4e3cfbe85f5189da70a52c1d266925f3efd122091cdc8fe0fc39033942 |

**Answer:**
361GJX7J,installer.exe

---

**Q4: What is the name of the file being dropped? Note down the hash value for later use.**

**Approach:**
In TryHackMes Virustotal we can scrool down a from the execution parents to find the dropped file. We also find the sha256 hash.

**Note**
dd02c105809e4ca41a5489e585ba025eddb89a91703b73a566c9903e6406a08c

**Answer:**
AClient.exe
---

**Q5: Research the second hash in question 3 and list the four malicious dropped files in the order they appear (from up to down), separated by commas.**

**Approach:**
Taking the 2nd hash from question 3 that we noted down as told, we can use the hash to search up and find the dropped files in the same place as we
did for the other questions similar to this. 
<img width="1672" height="1157" alt="image" src="https://github.com/user-attachments/assets/863c448d-fdd2-4c83-ab19-fde83582d154" />
<img width="1679" height="1159" alt="image" src="https://github.com/user-attachments/assets/8797f892-b528-4775-af7b-ed086cf992d0" />

**Answer:**
searchhost.exe,syshelpers.exe,nat.vbs,runsys.vbs
---

**Q6: Analyse the files related to the flagged IP. What is the malware family that links these files?**

**Approach:**
If we search for the IP given in the beginning (101[.]99[.]76[.]120) we can head over to the relations tab to look at the communicating files related to the IP.
Here we can copy the hashes for the files and search them up or head over to the community tab where we will find the answer.
**Answer:**
<img width="1670" height="1151" alt="image" src="https://github.com/user-attachments/assets/087befa9-7c6e-4033-bd32-764fe8c21049" />

---

**Q7: What is the title of the original report where these flagged indicators are mentioned? (Use Google to find the report.)**

**Approach:**
I searched for this "101[.]99[.]76[.]120 original report" to find the oroginal report from check point research.
<img width="1487" height="1033" alt="image" src="https://github.com/user-attachments/assets/28397f91-7a81-451d-bca3-bea4f35512ed" />

**Answer:**
From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery
---

**Q8: Which tool did the attackers use to steal cookies from the Google Chrome browser?**

**Approach:**
Reading the report you will find the answer in the "Campaign Evolution and Addition of New Modules"

**Answer:**
ChromeKatz

---

**Q9: Which phishing technique did the attackers use? (Use the report to answer the question.)**

**Approach:**

**Answer:**
ClickFix

---

**Q10: What is the name of the platform that was used to redirect a user to malicious servers?**

**Approach:**
Discord was the targeted platform for this phishing attack witch you will find reading through the report.

**Answer:**
Discord
---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP | 101.99.76.120 | Flagged by L1 analyst, escalated for review |
| Hash (SHA256) | 5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f | Flagged by L1 analyst, escalated for review |

## Key Takeaways
- Deep analysis with virustotal.
- Investigating related files to the malicious IP to find out more. 
