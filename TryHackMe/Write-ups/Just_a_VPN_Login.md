# TryHackMe — Just a VPN Login

| | |
|---|---|
| **URL** | https://tryhackme.com/room/justavpnlogin |
| **Category** | Blue Team — SOC / Threat Intelligence |
| **Difficulty** | Easy |
| **Estimated Time** | 45 minutes |
| **Completions** | 3,162 |
| **Date Completed** | YYYY-MM-DD |

## Overview
Gather threat intel to determine the risks and assist incident response.

As a new SOC analyst, you receive an alert: "Unusual VPN login of susan.martin@probablyfine.thm from 37.19.201.132 (Singapore)". According to the handover notes, Susan is attending a conference in Singapore, but she confirms she did not log in to the VPN. While on a public café Wi-Fi hotspot she was prompted to install a "security check" tool, and host telemetry shows a suspicious binary (SHA256: `b8e02f2bc0ffb42e8cf28e37a26d8d825f639079bf6d948f8debab6440ee5630`). The goal is to verify the IP and the file in TryDetectThis and work out what the binary does.

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

U
---

**Q3:** What is the filename of the file related to the hash?

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q4:** What is the threat signature that Microsoft assigned to the file?

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q5:** One of the contacted domains is part of a large malicious infrastructure cluster. Based on its HTTPS certificate, how many domains are linked to the same campaign?

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q6:** The file matches one of the YARA rules made by "kevoreilly". What line is present in the rule's "condition" field?

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q7:** The file is also mentioned in a threat intel report. What is the title of the report mentioning this hash?

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q8:** Which team did the author of the malware start collaborating with in early 2024?

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q9:** A Mexican-based affiliate related to the malware family also uses other infostealers. Which mentioned infostealer targets Android systems?

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

**Q10:** The report states that the affiliates behind the malware use the services of AnonRDP. Which MITRE ATT&CK sub-technique does this align with?

**MITRE ATT&CK:**

| Tactic | Technique | ID |
|--------|-----------|----|
|  |  |  |

**Approach:**

**Answer:**

---

## Tools & Commands

```bash
Virustotal.com
```

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP | 37.19.201.132 | Source of unusual VPN login (Singapore) |
| Domain |  |  |
| Hash | b8e02f2bc0ffb42e8cf28e37a26d8d825f639079bf6d948f8debab6440ee5630 | Suspicious "security check" binary (SHA256) |

## Key Takeaways
-
