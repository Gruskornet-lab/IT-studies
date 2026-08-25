# TryHackMe — ItsyBitsy

| | |
|---|---|
| **URL** | https://tryhackme.com/room/itsybitsy |
| **Category** | SOC / SIEM / Incident Investigation (Elastic/ELK) |
| **Difficulty** | Medium |
| **Estimated Time** | 30 minutes |
| **Completions** | 38,787 |
| **Date Completed** | 2026-08-24 |

## Overview
Put your ELK knowledge together and investigate an incident. During normal monitoring, Analyst John observed an alert from an IDS indicating a potential C2 communication involving a user named Browne from the HR department. A suspicious file was accessed containing a malicious pattern. A week-long connection log has been pulled and ingested into the `connection_logs` index for investigation.

---

---
## Task 1 — Introduction

Deploy the room machine (IP assigned on deploy). Log in to the Discover tab in Elastic with:
- **Username:** `Admin`
- **Password:** `elastic123`

*No questions — setup/deploy task.*

---

## Task 2 — Scenario: Investigate a potential C2 communication alert

---

**Q1: How many events were returned for the month of March 2022?**
**Approach:**
Starting the machine and entering the given ealstic platform with the logs that we wanna inspect for this task we first have to go to http://<MACHINE IP ADDRESS>:80 and filter the time range etween 1 of march 2022 and 31 march 2022. Here we will find all the logs for the task and the answer to the forst question

<img width="2485" height="529" alt="image" src="https://github.com/user-attachments/assets/fb29c2f1-7e4f-4c65-8f5a-42cf3223a06d" />


**Answer:**
1482

---

**Q2: What is the IP associated with the suspected user in the logs?**

**Approach:**
To find the suspected ip address we wanna check the source ip since we know that this case is about Browne begin a suspected C2 reaching out to external ip. To find the answer we can click the source ip filter to see all source ip addresses and find the suspected ip

<img width="1199" height="1041" alt="image" src="https://github.com/user-attachments/assets/9c66d6a0-8847-4dec-88e8-19ad9ca442ba" />

**Answer:**
192.166.65.54

---

**Q3: The user's machine used a legit Windows binary to download a file from the C2 server. What is the name of the binary?**

**Approach:**
Knowing the suspected ip address we can now inspect the trafic that is connected to the source ip of Browne. Finding wht windows binary downloaded the file whe can check the user_agent

<img width="2493" height="1049" alt="image" src="https://github.com/user-attachments/assets/55f4593a-71f3-4865-b26d-533c9b0ea7a8" />


**Answer:**
bitsadmin

---

**Q4: The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?**

**Approach:**
We will find this answer inspecting the same traffic as before

<img width="2501" height="1044" alt="image" src="https://github.com/user-attachments/assets/f096ea86-f73c-4b4d-90dd-627c888dc53b" />


**Answer:**
pastebin.com

---

**Q5: What is the full URL of the C2 to which the infected host is connected?**

**Approach:**
We have found the host "pastebin.com" and the full URL for the C2 is the host combined with the uri that we will find a bit further sown again above the user_agent from before

<img width="2498" height="1044" alt="image" src="https://github.com/user-attachments/assets/2df75f0e-4298-4e41-99f6-a8b2c67c2347" />


**Answer:**
pastebin.com/yTg0Ah6a

---

**Q6: A file was accessed on the filesharing site. What is the name of the file accessed?**

**Approach:**
Following the full URL that we found in the question before will take us to the pastebin.com website and file that was accessed from the file sharing site.

<img width="2507" height="1046" alt="image" src="https://github.com/user-attachments/assets/6d8e0115-9d43-40c5-b4cd-146a1135e743" />


**Answer:**
secret.txt

---

**Q7: The file contains a secret code with the format THM{_____}. What is the code?**

**Approach:**
On the same website we will also see the contents of the file that contains the THM flag for this last question.

<img width="2507" height="1046" alt="image" src="https://github.com/user-attachments/assets/3ed3d42d-c3e4-4095-a1dc-40ba29da98ef" />


**Answer:**
THM{SECRET__CODE}

---

## Tools & Commands

\`\`\`
 source_ip: 192.166.65.54
\`\`\`

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP | 192.166.65.54 | Suspected C2 IP Address |
| Domain | Pastebin.com | Common filesharing website |

## Key Takeaways
- Traffic inspection
- Narrowing traffic
- Taking all useful information from available http traffic
- More understanding of inspecting and filtering with Elastic
