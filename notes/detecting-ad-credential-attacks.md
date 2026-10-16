# Detecting AD Credential Attacks

Source: [TryHackMe: Detecting AD Credential Attacks](https://tryhackme.com/room/detectingadcredentialattacks)

## Kerberoasting

### What it is

Any domain user can request a service ticket (TGS) for any SPN. The DC encrypts it with the service account's password hash, so the attacker cracks it offline. It only needs a regular domain account. Targets are service accounts with weak passwords and often high privileges (e.g. a SQL service account running as Domain Admin).

### Detection: Event 4769

Modern AD defaults to AES-256 (`0x12`). Rubeus and Impacket's `GetUserSPNs.py` downgrade to RC4 (`0x17`) because it cracks much faster. An RC4 TGS request in an AES environment is a strong signal. Filter out noise from computer accounts (names ending in `$`) and `krbtgt`.

| Field | Contains | Why it matters |
|---|---|---|
| `Service_Name` | The SPN requested | The targeted service account |
| `Ticket_Encryption_Type` | `0x12` (AES) or `0x17` (RC4) | RC4 is the primary signal |
| `Account_Name` | Account requesting the ticket | The compromised user running the attack |
| `Client_Address` | Source IP (often `::ffff:10.5.90.1`, meaning `10.5.90.1`) | The attacker's machine |

### Evasion and volume-based detection

- TrustedSec's Orpheus (2022) can Kerberoast with AES, bypassing an RC4-only filter. RC4 is being phased out (AES default from Windows Server 2025), so RC4 detection alone will not last.
- Volume-based detection catches both: the tools request tickets for every SPN account, causing a burst of TGS requests. Flag accounts requesting more than 5 unique SPNs in a 5-minute window. The threshold is tuned for the lab, so baseline normal activity in production.
- Triage: check whether the targeted accounts are in Domain Admins or other privileged groups. That separates a routine alert from an active domain compromise.

## AS-REP Roasting

### What it is

Targets user accounts with preauthentication disabled (`DONT_REQUIRE_PREAUTH`). The DC issues a TGT without verifying the password, and the AS-REP is encrypted with the account's password hash, so it can be cracked offline. The attacker needs no valid domain account, only the username.

The flag exists because some legacy apps (older ERP or payroll systems) fail Kerberos unless preauth is off. Admins disable it to make the app work and forget about it.

### Normal flow vs attack

| | Normal TGT flow | AS-REP Roasting |
|---|---|---|
| Preauth | User proves the password with an encrypted timestamp | Skipped |
| 4768 | `Pre_Authentication_Type=2` | `Pre_Authentication_Type=0` |
| 4769 (service ticket) | Follows | None |
| 4624 (logon) | Follows | None |
| Purpose | Authenticate | Get a crackable hash |

`Pre_Authentication_Type` values: `2` = encrypted timestamp (normal), `15` = certificate-based, `0` = no preauth (the anomaly).

No follow-up 4769 or 4624 for the account strongly suggests the TGT was requested only for cracking. It is not definitive: a legitimate app could fail early or use a cached ticket.

### Kerberoasting vs AS-REP Roasting

| | Kerberoasting | AS-REP Roasting |
|---|---|---|
| Target | Service accounts with an SPN | Accounts with preauth disabled |
| Attacker needs | A regular domain account | Only the username |
| Trigger | TGS request for an SPN | TGT request (AS-REQ) for the account |
| Key signal | 4769 with RC4 (`0x17`), or burst of unique SPNs | 4768 with `Pre_Authentication_Type=0` |
| Follow-up events | Not the discriminator | None (no 4769, no 4624) |

## LSASS Credential Dumping

### What it is

Direct credential theft on the endpoint where the credentials live. No cracking is needed: if a Domain Admin has logged into the machine, their credentials are already in LSASS memory.

What LSASS stores:

- NTLM password hashes for all authenticated users
- Kerberos tickets (TGTs and TGS tickets) for active sessions
- Plaintext passwords where WDigest is enabled (default on Windows 8/Server 2012 and earlier, or newer systems with the `UseLogonCredential` registry value set to 1)
- Cached domain credentials for offline logon

Stolen credentials feed offline cracking, Pass-the-Hash and Pass-the-Ticket (lateral movement with their own detections).

### Detection: Sysmon Event 10

Fires when one process opens a handle to another. Default Sysmon does **not** log this: the config needs explicit ProcessAccess rules for `lsass.exe`, otherwise dumping is invisible.

| Field | Contains | Why it matters |
|---|---|---|
| `SourceImage` | Full path of the process accessing LSASS | Identifies the dump tool |
| `SourceUser` | Account running the source process | `SYSTEM` is expected (service or scheduled task); a domain user means that account is compromised |
| `TargetImage` | Target process | Confirms LSASS was targeted |
| `GrantedAccess` | Hex access mask | Different tools request different access |
| `CallTrace` | DLL call stack leading to the access | Reveals the dump method |

### GrantedAccess

The mask is a sum of access rights. `0x1010` = `0x1000` + `0x0010`, and the `0x0010` bit (VM_READ) is what matters, since reading LSASS memory is how credentials are extracted.

| Access right | Hex | Purpose |
|---|---|---|
| `PROCESS_QUERY_LIMITED_INFORMATION` | `0x1000` | Query basic process info |
| `PROCESS_QUERY_INFORMATION` | `0x0400` | Query detailed process info |
| `PROCESS_VM_READ` | `0x0010` | Read process memory |
| `PROCESS_ALL_ACCESS` | `0x1FFFFF` | Full access |

In practice `0x1010` is associated with Mimikatz, and `0x1FFFFF` with ProcDump, comsvcs.dll and Task Manager. These masks are not malicious on their own; context decides.

### CallTrace

| Pattern | Meaning | Typical tools | Attacker type |
|---|---|---|---|
| Known DLLs (`dbgcore.dll`, `dbghelp.dll`) | MiniDump API, a legitimate API abused | ProcDump, comsvcs.dll | Hands-on-keyboard with LOLBins |
| `UNKNOWN(address)` | Injected code, not mapped to any DLL | Cobalt Strike, Meterpreter | More sophisticated implant |

### What normal looks like

| Full path | Typical GrantedAccess | Why |
|---|---|---|
| `C:\Windows\System32\csrss.exe` | `0x1000` or `0x1400` | Windows subsystem, manages processes |
| `C:\Windows\System32\WerFault.exe` | `0x1000` | Windows Error Reporting crash handler |
| `C:\Windows\System32\svchost.exe` | `0x1010` | Service functions (normal at this level) |
| AV/EDR agent paths | Varies | Security products monitor LSASS |

Always match on the **full path**, not just the file name. A tool named `svchost.exe` in `C:\Users\Public\` or `C:\Temp\` is suspicious. Anything outside `C:\Windows\System32\` is treated as suspicious regardless of name.

### Other credential stores

| Store | Holds | Notes |
|---|---|---|
| SAM (`C:\Windows\System32\config\SAM`) | Local account hashes only | Extracted with `reg save` or Mimikatz `lsadump::sam`; no domain credentials |
| Cached domain credentials (`SECURITY\Cache`) | DCC2 hashes for offline logon | Slow to crack (bcrypt-based), cannot be used for Pass-the-Hash, low priority |
| NTDS.dit (on DCs) | Every account hash in the domain | Needs privileged access on the DC, see below |

LSASS is the primary target because it holds live domain credentials in a directly usable form.

## DCSync

### What it is

The attacker's machine pretends to be a domain controller and requests password data over the AD replication protocol (DRSUAPI). If the account has replication rights, the real DC complies. It never touches the DC's disk and needs no shadow copy.

Replication rights belong to Domain Admins, Enterprise Admins and DC machine accounts by default. They can also be obtained through ACL abuse (e.g. WriteDACL on the domain object) without joining Domain Admins.

| Replication extended right | GUID | Note |
|---|---|---|
| DS-Replication-Get-Changes-All | `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` | Allows pulling password data; the primary DCSync indicator |
| DS-Replication-Get-Changes | `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` | |
| DS-Replication-Get-Changes-In-Filtered-Set | `{89e95b76-444d-4c62-991a-0facbeda640c}` | |

### Detection: Event 4662

Signal: `Access_Mask=0x100` (Control Access), a replication GUID in the raw event, and a user that is not a machine account (no trailing `$`).

| Field | Contains | Why it matters |
|---|---|---|
| `user` | Account performing the replication | Who ran DCSync |
| `Access_Mask` | `0x100` (Control Access) | An extended right was exercised |
| `Properties` | Shows "Control Access"; GUIDs only in the raw event | Search the GUID (e.g. `1131f6ad`) as a keyword, not as a field |
| `Logon_ID` | Hex session identifier | Links to the 4624 logon for the source IP |

**Prerequisites (neither is default):** "Audit Directory Service Access" enabled via Group Policy, and a SACL on the domain partition auditing replication. Without both, DCSync is invisible. This is a common real-world detection gap.

### Normal vs suspicious replication

| | Normal | Suspicious |
|---|---|---|
| `user` | Machine account ending in `$` (e.g. `THM-DC$`) | Human account |
| Source host | Another domain controller | Workstation or non-DC server |
| Frequency | Regular, matching the replication schedule | One-time or a burst |
| Scope | Specific partition changes | Requests all credentials |

The `user!="*$"` filter misses attackers using a compromised machine account (via ADCS abuse, unconstrained delegation, etc.). In mature environments monitor all replicating accounts and baseline which machine accounts normally replicate. The lab has a single DC, so no legitimate DC-to-DC replication is visible.

### Finding the source IP

4662 has no source IP field. Pivot on `Logon_ID` to the 4624 logon event for the same session, which has `Source_Network_Address` and `Logon_Type`.

## NTDS.dit Extraction

### What it is

NTDS.dit is the AD database on every DC (typically `C:\Windows\NTDS\ntds.dit`) with the hashes of every account. Windows locks it while AD DS runs, and the SYSTEM registry hive is also needed to decrypt the hashes. The result is an offline copy that is parsed with `secretsdump.py` or NTDSDumpEx. It is the older, noisier alternative to DCSync.

### Methods and detection

| Method | How it works | Privilege needed | Detection signal |
|---|---|---|---|
| Volume Shadow Copy (`vssadmin`) | Snapshot bypasses the file lock; copy `ntds.dit` and SYSTEM from the snapshot, then delete it | Local admin on the DC | Sysmon 1: `vssadmin.exe` with `create shadow`, then copy commands with `HarddiskVolumeShadowCopy` plus `ntds` or `SYSTEM` |
| Install From Media (`ntdsutil`) | Legitimate DC promotion feature abused to write a clean `ntds.dit` and SYSTEM hive to a folder | Domain Admin or equivalent | Sysmon 1: `ntdsutil.exe` with `ifm` and `create`; Sysmon 11: `ntds.dit` written by `ntdsutil.exe` (MITRE CAR-2019-08-002) |

- A shadow copy alone has legitimate uses (backups, system restore). What confirms theft is the follow-up copy of `ntds.dit` and SYSTEM from the shadow path.
- Without Sysmon on the DCs, Security Event 4688 with command-line logging gives the same process visibility.

### DCSync vs NTDS.dit extraction

| | DCSync | NTDS.dit extraction |
|---|---|---|
| Method | Remote replication via DRSUAPI | Local file copy via shadow copy or IFM |
| Access needed | Replication rights (DA by default) | Local admin on the DC |
| Log source | 4662 | Sysmon 1 and 11 (or 4688) |
| Network visibility | Replication traffic from a non-DC IP | None (local operation) |
| Noise level | Low, blends with normal replication | High (shadow copy creation, file writes) |

## Event IDs

| ID | Log | What it is | Why it matters |
|---|---|---|---|
| Sysmon 1 | Sysmon | Process creation | Full command line: `ntdsutil.exe` with `ifm`/`create`, `vssadmin.exe` with `create shadow`, copies from `HarddiskVolumeShadowCopy` |
| Sysmon 10 | Sysmon | ProcessAccess | Shows who opened `lsass.exe`, with which `GrantedAccess` and `CallTrace`; needs explicit ProcessAccess rules |
| Sysmon 11 | Sysmon | File creation | `ntds.dit` written by `ntdsutil.exe` to an unusual location |
| 4624 | Security | Successful logon | Pivot from 4662 via `Logon_ID` to find the DCSync source IP; absence after a 4768 points to AS-REP Roasting |
| 4662 | Security (DC) | Operation performed on a directory object | DCSync: `Access_Mask=0x100` plus replication GUID from a non-`$` user; needs audit policy and SACL |
| 4688 | Security | Process creation | Alternative to Sysmon 1 for NTDS.dit detection when command-line logging is on |
| 4768 | Security (DC) | Kerberos TGT request | `Pre_Authentication_Type=0` points to AS-REP Roasting; `2` is normal, `15` is certificate-based |
| 4769 | Security (DC) | Kerberos service ticket (TGS) request | Kerberoasting: RC4 (`0x17`) or a burst of unique SPNs from one account |
