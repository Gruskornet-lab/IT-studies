# TryHackMe — Just a VPN Login

| | |
|---|---|
| **URL** | https://tryhackme.com/room/justavpnlogin |
| **Category** | Blue Team — SOC / Threat Intelligence |
| **Difficulty** | Easy |
| **Estimated Time** | 45 minutes |
| **Completions** | 3,162 |
| **Date Completed** | 2026-09-29 |

## Overview
Gather threat intel to determine the risks and assist incident response.

As a new SOC analyst, you receive an alert: "Unusual VPN login of susan[.]martin@probablyfine[.]thm from 37[.]19[.]201[.]132 (Singapore)". According to the handover notes, Susan is attending a conference in Singapore, but she confirms she did not log in to the VPN. While on a public café Wi-Fi hotspot she was prompted to install a "security check" tool, and host telemetry shows a suspicious binary (SHA256: `b8e02f2bc0ffb42e8cf28e37a26d8d825f639079bf6d948f8debab6440ee5630`). The goal is to verify the IP and the file in TryDetectThis and work out what the binary does.

**Tool:** TryDetectThis — https://static-labs.tryhackme.cloud/apps/trydetectthis/

---

## Task 1 — Just a VPN Login

---

**Q1:** What is the ASN number related to the IP?

**Approach:**
Using the TryHackMe's own virustotal type site we can search fot the IP and the ASN will be found in the middle of the screen.
<img width="1269" height="302" alt="image" src="https://github.com/user-attachments/assets/a2d91562-48d0-497c-aa13-3c76e3bd85c1" />


**Answer:**
212238

---

**Q2:** Which service is offered from this IP?

**Approach:**
Looking at the "File Relations" section we can see that the IP regularly communicates with a vpn provider. The IP from the introduction of the room is also introduced
"Unusual VPN login of susan.martin@probablyfine.thm from 37[.]19[.]201[.]132 (Singapore)."
<img width="1232" height="1145" alt="image" src="https://github.com/user-attachments/assets/7647cc62-e0c0-4e23-8004-8be7006f144f" />

**Answer:**
vpn 

---

**Q3:** What is the filename of the file related to the hash?

**Approach:**
Copying the provided hash in the detection site we will find a File Details section the information about the file. At the top we find the name of the file from the hash.
<img width="591" height="359" alt="image" src="https://github.com/user-attachments/assets/119d9863-0be7-4269-89e2-277b485fdb33" />


**Answer:**
zY9sqWs.exe

---

**Q4:** What is the threat signature that Microsoft assigned to the file?

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**
We can use Ctrl + F shortcut to search for Microsoft on the site and in the vendor analysis list we find Microsoft threat signature.
<img width="702" height="29" alt="image" src="https://github.com/user-attachments/assets/037258a8-f697-4da5-bbe6-1eb521ce4a7b" />


**Answer:**
Trojan:Win32/LummaStealer.PM!MTB

---

**Q5:** One of the contacted domains is part of a large malicious infrastructure cluster. Based on its HTTPS certificate, how many domains are linked to the same campaign?

**Approach:**
To find the answer for this we have to find the domains the file is communicating with and if we check in the file communication behavior [1] section we find 3 domains that stand out from the rest. If we enter each on and go to Latest HTTPS Certificate and look at the details we find SAN (subject alternative name). Adding all SAN from the 3 suspicious domains related to the malicious file we get the answer. 
[1]
<img width="1216" height="466" alt="image" src="https://github.com/user-attachments/assets/0c77fdea-4c42-4b4a-b7b2-7ae6d5780cc3" />
[2]
<img width="486" height="1232" alt="image" src="https://github.com/user-attachments/assets/4f8249e6-de46-4041-aa53-d02c6dcbffae" />


**Answer:**
151

---

**Q6:** The file matches one of the YARA rules made by "kevoreilly". What line is present in the rule's "condition" field?


**Approach:**
If we search for kevoreilly who is the developer of CAPEv2 

**Answer:**
uint16(0) == 0x5a4d and any of them

---

**Q7:** The file is also mentioned in a threat intel report. What is the title of the report mentioning this hash?

**Approach:**
Searching on google we find the incident report mentioning this hash

**Answer:**
Behind the Curtain: How Lumma Affiliates Operate

---

**Q8:** Which team did the author of the malware start collaborating with in early 2024?

**Approach:**
In the report

**Answer:**
GhostSocks

---

**Q9:** A Mexican-based affiliate related to the malware family also uses other infostealers. Which mentioned infostealer targets Android systems?

**Approach:**
In the report

**Answer:**
CraxsRAT

---

**Q10:** The report states that the affiliates behind the malware use the services of AnonRDP. Which MITRE ATT&CK sub-technique does this align with?

**Approach:**
CraxsRAT uses AnonRDP which align with the MITRE ATT&CK sub-technique of Virtual Private Server which we can find the answer for at the bottom of the page as the incident report provides "Appendix C — MITRE ATT&CK Techniques"
<img width="1039" height="594" alt="image" src="https://github.com/user-attachments/assets/f29764bc-2e2d-4108-8560-4829d3acb746" />


**Answer:**
T1583.003

---


## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP | 37[.]19[.]201[.]132 | Source of unusual VPN login (Singapore) |
| Domain |  |  |
| Hash | b8e02f2bc0ffb42e8cf28e37a26d8d825f639079bf6d948f8debab6440ee5630 | Suspicious "security check" binary (SHA256) |

## Key Takeaways
- Analysis
- SAN
- CAPE which I haven't heard of until now and is for sure a valuable tool for SOC use.
- MITRE ATT&CT
