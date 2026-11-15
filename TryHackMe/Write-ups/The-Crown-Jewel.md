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


**Answer:**


---

**Q2:** What outbound connection was detected as a C2 channel? (Answer example: 1.2.3.4:9996)

**Approach:**


**Answer:**


---

**Q3:** Which MAC address is impersonating the gateway 10.10.10.1?

**Approach:**


**Answer:**


---

**Q4:** What is the non-standard User-Agent hitting the Jira instance?

**Approach:**


**Answer:**


---

**Q5:** How many ARP spoofing attacks were observed in the PCAP?

**Approach:**


**Answer:**


---

**Q6:** What's the payload containing the plaintext creds found in the POST request?

**Approach:**


**Answer:**


---

**Q7:** What domain, owned by the attacker, was used for data exfiltration?

**Approach:**


**Answer:**


---

**Q8:** After examining the logs, which protocol was used for data exfiltration?

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
