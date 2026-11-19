# TryHackMe — Zero Tolerance

| | |
|---|---|
| **URL** | https://tryhackme.com/room/zerotolerance |
| **Category** | Blue Team / SOC (Splunk, KAPE) |
| **Difficulty** | Medium |
| **Estimated Time** | 90 minutes |
| **Completions** | 879 |
| **Date Completed** | 2026-11-16 |

## Overview
A full attack chain investigation CTF challenge using Splunk logs and KAPE artifacts.

---

## Task 1 — Zero Tolerance

---

**Q1:** What is the hostname where the Initial Access occurred?

**Approach:**

<img width="926" height="202" alt="bild" src="https://github.com/user-attachments/assets/189cf190-a732-4719-a30d-36d24ee413ee" />


**Answer:**
JP-BROWN-WS

---

**Q2:** What MITRE ATT&CK sub-technique ID describes the initial code execution method on the beachhead?

**Approach:**
The .pdf.lnk is a trick to make the victim thinking its a pdf but in reality its not. This is made to trick the victim to execute code in the file provided which is also known as "User execution"

**Answer:**
T1204.002

---

**Q3:** What is the full path of the malicious file that led to Initial Access?

**Approach:**
As we can see in the event in Q1 we can see the full path to the file that led to the initial access. 
<img width="493" height="33" alt="bild" src="https://github.com/user-attachments/assets/e0772825-5852-4269-a065-9adac4938fdf" />


**Answer:**
C:\Users\jp.brown\Downloads\TravisClart_Resume.pdf.lnk

---

**Q4:** What is the full path to the LOLBin abused by the attacker for Initial Access?

**Approach:**
The full path leading to binary the malicious file is living of we can look for some common ones that are known to be exploited in this use and one of thoose commonly used is mshta.exe.  
<img width="398" height="186" alt="bild" src="https://github.com/user-attachments/assets/cfa4ebb9-f1ad-4821-af35-69c874dfe9bf" />
Here we are left with two events and from inspecting one of the events we can se that the mshta.exe is used to contact the suspicious web-address
<img width="673" height="286" alt="bild" src="https://github.com/user-attachments/assets/93de587b-79f8-46be-a2a0-dfb4c6d15cf5" />

**Answer:**
C:\Windows\System32\mshta.exe

---

**Q5:** What is the IP address of the attacker's Command & Control server?

**Approach:**
From the same event that we were in the question before we find the attackers ip address for the C2 
<img width="662" height="33" alt="bild" src="https://github.com/user-attachments/assets/c4314e5a-312b-4e56-9f56-f4b1813827a3" />

**Answer:**
10.10.14.174

---

**Q6:** What is the full path of the process responsible for the C2 beaconing?

**Approach:**
While looking around the events previously inspected to the questions above I looked in to other "http://" matches in the events and there are 7 in total. One of the 7 events is a powershell command
that downloads a called Runtimebroker.exe in the "C:\Windows\Temp\RuntimeBroker.exe" folder. Runtimebroker.exe is a legit windows process but the known Runtimebroker.exe is located in the System32 folder. 
<img width="1067" height="67" alt="bild" src="https://github.com/user-attachments/assets/c6ad702f-1119-4789-81e0-94a73cff3de7" />


**Answer:**
C:\Windows\Temp\RuntimeBroker.exe

---

**Q7:** What is the full registry path that the threat actor modified for persistence on the beachhead host?

**Approach:**
Making a search for reg.exe process for registry events and EventCode 13 to see any files that has been changed since we are looking for a modified registry key in this case and also on the affected host JP-BROWN-WS.
´´´ index=* reg.exe host="JP-BROWN-WS" EventCode=13´´´ 
<img width="1522" height="696" alt="bild" src="https://github.com/user-attachments/assets/c512eaf5-edc3-4aa4-934b-fa5779310386" />
Here we can see 2 events and the one marked in the picture above tells us that when this user  jp.brown loggs in the registry key runs "C:\Windows\Temp\RuntimeBroker.exe"

**Answer:**
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemMonitor

---

**Q8:** What tool and parameter did the threat actor use for credential dumping?

**Approach:**
We saw from the related files to this room that there was a mention of Mimikatz which is a credential dumping tool. So adding "Mimikatz to the search bar we find 16 events. <img width="297" height="137" alt="bild" src="https://github.com/user-attachments/assets/4616b9ba-1f2c-4c5c-a52b-58f00fdf75f2" />
So we can see that the tool has clearly been used in the system. Looking at the "CommandLine" filter on the side we find that a powershell was executed with Mimikatz. <img width="860" height="306" alt="bild" src="https://github.com/user-attachments/assets/9225f5aa-eedf-4f60-8764-423714e2f83b" />


**Answer:**
Invoke-Mimikatz -DumpCreds

---

**Q9:** The threat actor used PowerShell to weaken endpoint defenses. What specific parameter did they attempt to change?

**Approach:**


**Answer:**
DisableRealtimeMonitoring

---

**Q10:** The threat actor used a remote administration tool to execute commands on another machine. What is the PID of the process that initiated the remote execution?

**Approach:**


**Answer:**
6612

---

**Q11:** At what time did the threat actor successfully log in to the remote system from the beachhead?

**Approach:**
Taking the ip we found in the PsExec command "10.10.152.240" we can filter for this ip and the beachhead host ´´´index=* host="JP-BROWN-WS" DestinationIp="10.10.152.240"´´´ <img width="775" height="453" alt="image" src="https://github.com/user-attachments/assets/f566b0ff-6dd3-4385-9310-fc3a82306d5f" />

**Answer:**
2025-11-14 05:19:42

---

**Q12:** What is the full path of the PowerShell script used by the threat actor to collect data?

**Approach:**
<img width="1820" height="960" alt="image" src="https://github.com/user-attachments/assets/42940b91-7f69-446b-8a98-6106bede4da6" />

**Answer:**
C:\Windows\Temp\Setup-BackupServer.ps1

---

**Q13:** What are the first four file extensions targeted by this script for collection?

**Approach:**


**Answer:**
.bak, .backup, .sql, .mdb

---

**Q14:** What is the full path to the staged file containing collected files?

**Approach:**


**Answer:**
C:\Users\bkup-svc\AppData\Local\Temp\sysbackup_20251114.dat

---

## Key Takeaways
- Some questions are not found by me, the files related to the task was not downloaded and I used all my knowledge to find the answers until I suspect that the answers is not in splunk and the explonation and answer was grabbed from the internet.
