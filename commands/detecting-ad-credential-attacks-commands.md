# Detecting AD Credential Attacks

Source: [TryHackMe: Detecting AD Credential Attacks](https://tryhackme.com/room/detectingadcredentialattacks)

## Kerberoasting

### RC4 service ticket requests

Lists TGS requests with RC4 encryption, the main Kerberoasting signal in an AES environment. Computer accounts and `krbtgt` are excluded as noise.

```spl
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
# 4769 = service ticket request, 0x17 = RC4, !="*$" drops computer accounts
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
# pick the fields needed for triage
| sort _time
# chronological order shows the burst
# many RC4 requests from one account to different services in a short window = textbook Kerberoasting
```

### Who, from where, how many

Aggregates the same events to answer the triage questions: which account ran it, from which IP, and how many service accounts were targeted.

```spl
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| stats dc(Service_Name) as targeted_services count by Account_Name, Client_Address
# dc() = distinct count of targeted SPNs, grouped per requesting account and source IP
```

### Volume-based detection (works for AES too)

Groups requests into 5-minute windows and flags accounts that asked for tickets to more than 5 unique SPNs. Catches Kerberoasting even when the attacker avoids RC4.

```spl
index=task2 EventCode=4769 Service_Name!="*$" Service_Name!="krbtgt"
# no encryption filter here, so AES tickets are included
| bin _time span=5m
# round each timestamp into a 5-minute bucket
| stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
# unique SPNs requested per account and source IP in each bucket
| where unique_spns > 5
# threshold tuned for the lab, baseline normal activity in production
```

## AS-REP Roasting

### All TGT requests (baseline)

Shows what normal TGT traffic looks like before hunting for the anomaly.

```spl
index=task3 EventCode=4768
# 4768 = Kerberos TGT request
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
| sort _time
# normal: Pre_Authentication_Type=2 with AES (0x12), 15 = certificate-based
```

### Isolate the AS-REP Roasting event

Pre-authentication type 0 means the account has preauth disabled and a TGT was handed out without proof of the password.

```spl
index=task3 EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
# the account found here is the targeted one, RC4 (0x17) is expected
```

### Check for follow-up activity

Looks for a logon (4624) or service ticket request (4769) for the same account. Nothing after the TGT request suggests it was requested only for cracking.

```spl
index=task3 (EventCode=4624 OR EventCode=4769)
| search Account_Name="{ACCOUNT_NAME}"
# replace with the account from the previous query
| table _time, EventCode, Account_Name, Client_Address
# zero results = no follow-up, strong (not definitive) sign of offline cracking
```

## LSASS Credential Dumping

### Every process that accessed LSASS

Start broad so nothing is missed by filtering too early. Shows each source process with its access mask.

```spl
index=task4 EventCode=10 TargetImage="*\\lsass.exe"
# Sysmon Event 10 = ProcessAccess, target must be lsass.exe
| stats count by SourceImage, GrantedAccess
# legitimate system processes plus one suspicious entry
```

### CallTrace of the suspicious process

Shows which account ran the tool and how the dump was made: known DLLs like `dbgcore.dll` mean MiniDump API, `UNKNOWN(...)` offsets mean injected code.

```spl
index=task4 EventCode=10 TargetImage="*\\lsass.exe" SourceImage={SUSPICIOUS_PROCESS}
# replace with the process found in the previous query
| table _time, SourceImage, SourceUser, GrantedAccess, CallTrace
# SourceUser: SYSTEM = service/scheduled task, domain user = that account is compromised
```

## DCSync

### Non-machine accounts performing replication

Finds replication rights being used by a human account. The GUID is only in the raw event, so it is searched as a keyword.

```spl
index=task5 EventCode=4662 "1131f6ad" user!="*$"
# 4662 = operation on a directory object, 1131f6ad = DS-Replication-Get-Changes-All, !="*$" drops machine accounts
| table _time, user, Access_Mask, Properties
| sort _time
# Access_Mask 0x100 / "Control Access" confirms an extended right was exercised
```

### Get the Logon_ID of the DCSync session

Event 4662 has no source IP, so first grab the session identifier.

```spl
index=task5 EventCode=4662 Access_Mask=0x100 user={COMPROMISED_USER} "1131f6ad"
# replace with the account found in the previous query
| table _time, host, user, Logon_ID
```

### Source IP from the logon event

Correlates the Logon_ID with the 4624 logon for the same session to get where the DCSync came from.

```spl
index=task5 EventCode=4624 Logon_ID={LOGON_ID}
# replace with the Logon_ID from the previous query
| table _time, host, user, Source_Network_Address, Logon_Type
```

## NTDS.dit Extraction

### ntdsutil execution

Looks for `ntdsutil.exe` being run, the most common extraction method (IFM). Sysmon Event 1 has the full command line.

```spl
index=task6 EventCode=1 Image="*\\ntdsutil.exe"
# Sysmon Event 1 = process creation
| table _time, host, User, ParentImage, Image, CommandLine
# CommandLine shows the exact ntdsutil usage, ParentImage shows how it was launched
```

### ntds.dit written to disk

Confirms the extraction actually produced the file and where it was saved.

```spl
index=task6 EventCode=11 TargetFilename="*ntds.dit" Image="*\\ntdsutil.exe"
# Sysmon Event 11 = file creation
| table _time, Image, TargetFilename
# TargetFilename = where the attacker saved the copy
```

### Shadow copy creation

Finds `vssadmin` creating a volume shadow copy. Alone it can be legitimate (backups), so continue with the next query.

```spl
index=task6 EventCode=1 Image="*\\vssadmin.exe" CommandLine="*create shadow*"
| table _time, host, User, ParentImage, Image, CommandLine
```

### Copying ntds.dit and SYSTEM from the shadow copy

This is what confirms credential theft: both files together allow offline extraction of every hash in the domain.

```spl
index=task6 EventCode=1 CommandLine="*HarddiskVolumeShadowCopy*" (CommandLine="*ntds*" OR CommandLine="*SYSTEM*")
# command lines that touch the shadow copy path and the sensitive files
| table _time, host, User, ParentImage, Image, CommandLine
# without Sysmon, Security Event 4688 with command-line logging gives the same visibility
```

### Command lines to recognize: vssadmin shadow copy

What the shadow copy method looks like in a process creation event.

```cmd
vssadmin create shadow /for=C:    # snapshot of C: bypasses the lock on ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit    # AD database
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM    # hive needed to decrypt the hashes
vssadmin delete shadows /shadow={shadow-id} /quiet    # cover tracks
```

### Command line to recognize: ntdsutil IFM

What the Install From Media method looks like. Creates a clean copy of `ntds.dit` and the SYSTEM hive in one command.

```cmd
ntdsutil "ac i ntds" "ifm" "create full C:\temp" q q    # activate instance ntds, IFM, full copy to C:\temp
```
