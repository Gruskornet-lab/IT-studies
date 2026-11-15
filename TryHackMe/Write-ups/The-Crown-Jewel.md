# TryHackMe — The Crown Jewel

| | |
|---|---|
| **URL** | https://tryhackme.com/room/thecrownjewel |
| **Category** | Blue Team / SOC (Wireshark, Splunk) |
| **Difficulty** | Easy |
| **Estimated Time** | 60 minutes |
| **Completions** | 2,048 |
| **Date Completed** | 2026-11-15 |

## Overview
Triage a critical alert using Wireshark and Splunk to trace the network intrusion attempt. The alert `Reverse Shell Outbound Connection Detected` comes from Imperium Labs, a company monitored by an MSSP. Using the raw PCAP (`challenge.pcap`) and pre-ingested Splunk logs (`index=network_logs`), reconstruct the attack aimed at stealing the "Crown Jewel" data from the GitLab and Jira servers.

---

## Task 1 — The Crown Jewel

---

**Q1:** From which internal IP did the suspicious connection originate?

**Approach:**
Using splunk we can filter by log types.
<img width="331" height="97" alt="bild" src="https://github.com/user-attachments/assets/73d6b573-fde9-4215-905c-590b925834b7" />
sorting by the ids gives us the detected activity witch gives us alot of valuable information to start of our investigation with. 
<img width="611" height="226" alt="bild" src="https://github.com/user-attachments/assets/ef59b55f-9a2f-4200-81d0-7217e5274005" />


**Answer:**
10.10.10.100

---

**Q2:** What outbound connection was detected as a C2 channel? (Answer example: 1.2.3.4:9996)

**Approach:**
<img width="728" height="223" alt="bild" src="https://github.com/user-attachments/assets/277dffc3-2497-4d32-95e1-e8c78043b15e" />


**Answer:**
1[.]1[.]1[.]1[:]8000

---

**Q3:** Which MAC address is impersonating the gateway 10.10.10.1?

**Approach:**

<img width="945" height="235" alt="bild" src="https://github.com/user-attachments/assets/4255a648-57f9-45fd-ae20-57fa7b29f451" />


**Answer:**
00:0c:29:11:22:33

---

**Q4:** What is the non-standard User-Agent hitting the Jira instance?

**Approach:**
<img width="945" height="367" alt="bild" src="https://github.com/user-attachments/assets/738e7142-1891-4a23-bfbe-c7df59bb23eb" />


**Answer:**
CVE-202X-EXPLOIT

---

**Q5:** How many ARP spoofing attacks were observed in the PCAP?

**Approach:**
<img width="945" height="333" alt="bild" src="https://github.com/user-attachments/assets/54d7a82e-c2a2-4e27-a609-ffe3b8502191" />


**Answer:**
90

---

**Q6:** What's the payload containing the plaintext creds found in the POST request?

**Approach:**
<img width="945" height="487" alt="bild" src="https://github.com/user-attachments/assets/4f3b2a78-05ef-4b96-8db5-809c26ec8758" />
<img width="945" height="669" alt="bild" src="https://github.com/user-attachments/assets/2d0fb7c9-8f07-4474-9d0f-bf56e83c8cc0" />


**Answer:**
username=dev_user&password=SecretPassword!

---

**Q7:** What domain, owned by the attacker, was used for data exfiltration?

**Approach:**
<img width="945" height="483" alt="bild" src="https://github.com/user-attachments/assets/7469290f-446e-4648-9439-2546c38ba3ff" />


**Answer:**
exfil-domain.xyz

---

**Q8:** After examining the logs, which protocol was used for data exfiltration?

**Approach:**
The domain we found in the question before this one (Q7) show up in the dns log types which gives us the answer for this question. 

**Answer:**
DNS

---

## Tools & Commands

```bash
#Splunk
index=network_logs log_type=ids "event.msg"="Reverse Shell Outbound Connection Detected"

index=network_logs log_type=arp
| head 3

index=network_logs log_type=arp event.sender_ip="10.10.10.1"
| stats count by event.sender_mac

index=network_logs extracted_host=jira
| stats count by event.agent
| sort count

index=network_logs log_type=dns
| stats count by event.query
| sort count

#Wireshark
http.request.method == "POST"
```

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP | 10.10.10.100 | First internal ip address that did the suspicious connection |
| Domain | exfil-domain[.]xyz | data exfiltration through DNS |

