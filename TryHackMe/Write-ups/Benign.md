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

## Task 1 — Set up your virtual environment

Deploy the AttackBox/VPN and the Room Machine. Logs are pre-ingested into the Splunk index `win_eventlogs`. No questions — just connect to the lab.

---

## Task 2 — Scenario: Identify and Investigate an Infected Host

---

**Q1: How many logs are ingested from the month of March, 2022?**

**Approach:**
To figure out how many logs that were ingested in th month och march 2022 we need to costume our date of range to only include logs between 03/01/2022 - 03/31/2022 which we can do on the right side of the search bar. When we have selected the correct date range we get our answer on the left side of our screen beside events

<img width="1531" height="282" alt="bild" src="https://github.com/user-attachments/assets/7f18fa7e-f17e-43f5-a046-44cd31556dee" />


**Answer:**
13959

---

**Q2: Imposter Alert — there seems to be an imposter account observed in the logs. What is the name of that user?**

**Approach:**
To find out the imposters username we can inspect the user.name filter to check all the user names in the logs. Checking the filter we can see that there is a value of 11 which means there is 11 different user names observed in these logs
<img width="713" height="555" alt="bild" src="https://github.com/user-attachments/assets/fe8ba4e6-035d-4bd1-b950-ebcba9e9f5ac" />
To find out what the username of the 11 user name is we can simply press the "top values" to display the top 20 usernames and in the bottom of the bar chart thats displayed we can see a misspelled version of Amelia.

<img width="1535" height="472" alt="bild" src="https://github.com/user-attachments/assets/eff64de2-210d-4c60-9676-6fc613c326ec" />

**Answer:**
Amel1a

---

**Q3: Which user from the HR department was observed to be running scheduled tasks?**

**Approach:**
Finding this answer we need to do some filtering. After inspecting the imposter before in the logs we can see that the imposter only have one logged event as the user of Amel1a. <img width="1173" height="725" alt="bild" src="https://github.com/user-attachments/assets/e08d86bf-1e9c-418d-b886-f3a941916429" />
What makes this one log valuable for this question in particular is that is asks from with user in the HR department is observed to be running scheduled task but we know its not Amel1a. Since this is the only log for this user. But from this log we can see that Amel1a is a part of the HR_02 group. 
We can then use the filter displayed in the picture to inspect if the HR_02 group has any logs related to scheduled tasks by adding the filter "ProcessName=*schtasks* 
<img width="1392" height="785" alt="bild" src="https://github.com/user-attachments/assets/95ae9342-718b-4087-84b6-1ffad85aa8d5" />
Here we can see a suspicious command line run by the user Chris.fort from the HR department.

**Answer:**
Chris.fort

---

**Q4: Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host?**

**Approach:**
LOLBIN stands for Living Off The Land Binaries and there are many different type of possible binares that can be used in this scenario tho we do know from the question that downloads a payload. I for this searched for LOLBIN on the internet and found the github LOLBAS. Here you can find a wide range of different binaries and more and they are all labled with what functions they have. Since we are loooking for a "Download" function we can filter out the ones we don't suspect to be used in the task. From here on I used a bit of brute force and tested binaries with download function from A-Z and ended up finding Haroon using Certutil.exe to download a payload from the web. 
<img width="1186" height="657" alt="bild" src="https://github.com/user-attachments/assets/1420260c-6241-4557-986f-818fadd212a0" />

After finding the answer to this question, I really wish I just searched for http or https. But you learn by doing.  :')

**Answer:**
haroon

---

**Q5: To bypass the security controls, which system process (LOLBIN) was used to download a payload from the internet?**

**Approach:**
<img width="688" height="406" alt="bild" src="https://github.com/user-attachments/assets/e4779ed4-80cb-4fc7-b859-a54d323c9522" />

**Answer:**
certutil.exe

---

**Q6: What was the date that this binary was executed by the infected host? (format: YYYY-MM-DD)**

**Approach:**
<img width="811" height="407" alt="bild" src="https://github.com/user-attachments/assets/98931e51-5cd9-4f1d-9edb-2c543d00e105" />

**Answer:**
22-03-04

---

**Q7: Which third-party site was accessed to download the malicious payload?**

**Approach:**
<img width="677" height="392" alt="bild" src="https://github.com/user-attachments/assets/6c552465-c211-4964-bb65-f8bf97c07f1c" />

**Answer:**
controlc.com

---

**Q8: What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?**

**Approach:**
<img width="700" height="380" alt="bild" src="https://github.com/user-attachments/assets/2c29eb01-8fa4-4012-a563-80a6bc28d3b5" />

**Answer:**
benign.exe

---

**Q9: The suspicious file downloaded from the C2 server contained malicious content with the pattern `THM{..........}`. What is that pattern?**

**Approach:**
we have the full URL from where the file was downloaded from we can check the contents of this file by checking out he URL https://controlc[.]com/e4d11035 the URL in its self is safe to visit and when we do we find the flag in the file.
<img width="447" height="373" alt="bild" src="https://github.com/user-attachments/assets/81d44daa-ef70-47be-bcbf-d8d17a5b5263" />


**Answer:**
THM{KJ&*H^B0}

---

**Q10: What is the URL that the infected host connected to?**


**Approach:**
The URL in the task that the infected host visited is found in the same log as we have been finding answers to the last few questions 
<img width="622" height="355" alt="bild" src="https://github.com/user-attachments/assets/c56017ff-811d-42fd-be9f-4ae94fb7d320" />

**Answer:**
https://controlc[.]com/e4d11035

---

## Key Takeaways
- The answer is dosen't always have to be so complicated.
- One suspicious log can give of  valuable information for further investigation.
 
---

*Source: [TryHackMe — Benign](https://tryhackme.com/room/benign)*
