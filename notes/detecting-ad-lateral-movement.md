# Detecting AD Lateral Movement

Source: [TryHackMe: Detecting AD Lateral Movement](https://tryhackme.com/room/detectingadlateralmovement)

## Discovery and Reconnaissance

### AD discovery commands

After gaining access, attackers map the environment before moving laterally: domain controllers, trusts, accounts, groups, and reachable systems.

| Category | Command | What it reveals |
|---|---|---|
| Domain/Trust | `nltest /dclist:domain` | Domain controllers in the environment |
| Domain/Trust | `nltest /domain_trusts` | Trusted domains the attacker could pivot to |
| Accounts/Groups | `net user /domain` | All domain user accounts |
| Accounts/Groups | `net group "Domain Admins" /domain` | Members of the Domain Admins group |
| Accounts/Groups | `net group "Enterprise Admins" /domain` | Members of the Enterprise Admins group |
| Accounts/Groups | `net localgroup administrators` | Local admin accounts on the current machine |
| Systems | `net view` | Machines visible on the network |
| Systems | `net view \\THM-SHR-SRV /all` | Shares on a specific remote system |
| PowerShell | `Get-ADUser -Filter *` | AD user enumeration via PowerShell |
| PowerShell | `Get-ADGroupMember "Domain Admins"` | Admin group members via PowerShell |
| PowerShell | `Get-ADComputer -Filter *` | All computer accounts in the domain |

None of these require admin rights — AD grants read access to all authenticated domain users by default, so even a low-privilege compromised account can enumerate the whole domain. This is by design, not a misconfiguration. Attackers also use third-party tools such as `adfind.exe`, `dsquery`, or PowerShell's `[System.DirectoryServices.DirectorySearcher]` class for raw LDAP queries, instead of the built-ins above.

### Log sources for discovery

| Source | Captures |
|---|---|
| Sysmon Event 1 | Process creation — CMD/PowerShell commands appear in the command line |
| PowerShell Event 4104 (Script Block Logging) | Full script block content, including cmdlet and parameters |

If Script Block Logging isn't enabled (it's noisy, so some orgs only turn it on for high-value targets or active investigations), fall back to Sysmon Event 1 or Security Event 4688. The trade-off: those only capture the `powershell.exe` process launch — individual cmdlets run interactively inside a session won't each generate a process creation event. Script Block Logging captures every command regardless.

Base64-encoded PowerShell (`powershell -enc ...`) still generates a Sysmon Event 1, but the command line shows the encoded form. Script Block Logging is more resistant here since it logs the decoded script block after processing.

## SMB Lateral Movement (Admin Shares)

### Default administrative shares

Created by the Server service at boot, used for remote management over SMB (port 445).

| Share | Maps to |
|---|---|
| `C$` (and `D$`, `E$`, ...) | Root of the corresponding drive |
| `ADMIN$` | `%SystemRoot%` (typically `C:\Windows`) |
| `IPC$` | Logical share for inter-process communication via named pipes, used for remote RPC calls |

Regular users access named shares (e.g. `Marketing`, `IT`), not admin shares. Admin share access is either legitimate admin maintenance or lateral movement.

### Investigating admin share access

Event 5140 (share accessed) gives host, source IP, account used, and share name in one event. A single source IP accessing `ADMIN$`/`C$` across multiple hosts is a strong indicator, especially from a workstation that doesn't normally do that. Confirm by baselining: check what shares that account normally accesses, from where.

To pivot from a source IP to a hostname: every AD computer authenticates with a machine account matching its hostname plus `$`. Searching Event 4624 logons from that IP with `user=*$` reveals the hostname (drop the `$`).

On the source host, Sysmon Event 1 filtered for `ADMIN$` in the command line shows the actual tool and user behind the activity. If the `User` field differs from the credentials used in the command line, that's credential misuse. Event 4648 (Explicit Credential Usage) on the source machine is the corresponding source-side event for each share connection — and it still appears even when a C2 framework's SMB module (Cobalt Strike, Metasploit) connects without spawning `net.exe` and so produces no Sysmon Event 1. Event 5140 on the destination also still fires regardless of how the connection was made.

## PsExec Lateral Movement

### How PsExec works

PsExec combines SMB admin share access with Windows service installation to execute commands remotely, leaving a specific artifact trail even if the binary is renamed:

1. Connects to the target's `ADMIN$` share over SMB
2. Copies a service binary (`PSEXESVC.exe`) to the target's `C:\Windows`
3. Creates and starts a new Windows service on the target (Event 7045)
4. The service creates named pipes for stdin/stdout/stderr (Sysmon Event 17)
5. Executes the attacker's command
6. Removes the service and binary when the session ends

By default the remote command runs as the authenticating user; with the `-s` flag it runs as `LocalSystem` (SYSTEM-level).

### Finding PsExec activity

| Step | Source | What to look for |
|---|---|---|
| Service install | Destination, Event 7045 | Service name `PSEXESVC`, binary path `C:\Windows\PSEXESVC.exe`, `Service_Account` field |
| Commands executed | Destination, Sysmon Event 1 | `ParentImage` = `*PSEXESVC*` |
| Named pipes | Destination, Sysmon Event 17 | Pipe names like `\PSEXESVC-<hostname>-<pid>-stdin/-stdout/-stderr` — even a renamed binary often keeps this naming |
| File/pipe access detail | Destination, Event 5145 | `Relative_Target_Name` includes the pipe name, which contains the source hostname |
| Source-side launch | Source, Sysmon Event 1 | `Image` = `*PsExec*`, full command line with target and command |

Events 5140 and 5145 require "Audit File Share" / "Audit Detailed File Share" enabled via Group Policy — zero results doesn't necessarily mean no activity happened, it may mean the audit policy isn't on.

### Renamed or alternative PsExec tooling

The `-r` flag lets an operator set a custom service name instead of `PSEXESVC`. Tools like Impacket's `psexec.py` or Cobalt Strike's PsExec module generate random service names by default. Event 7045 still fires regardless of the name — the consistent signature to hunt for is `Service_Type` = "user mode service" with `Service_Start_Type` = "demand start".

## RDP Lateral Movement

RDP gives a full interactive session but leaves fewer obvious artifacts than SMB/PsExec — no service install, no share access pattern, no distinctive destination-side process. RDP is usually found as the delivery mechanism after something else (e.g. discovery commands) draws attention, rather than hunted directly, since RDP logs are noisy.

### Logon type and NLA

| Logon_Type | Protocol |
|---|---|
| 3 (Network) | SMB, PsExec |
| 10 (RemoteInteractive) | RDP |

With Network Level Authentication (NLA, default on modern Windows), the user authenticates at the network level before the session starts, producing a brief Type 3 logon seconds before the Type 10. That Type 3 is the NLA prelude for the same RDP connection, not a separate SMB/PsExec session.

### Normal vs suspicious direction

| Pattern | Typical? | Why |
|---|---|---|
| Workstation → Server | Yes | Standard pattern for IT admins managing servers |
| Workstation → Workstation | Rare | Regular users don't RDP into each other's machines (helpdesk may, from designated IT workstations) |
| Server → Server | Suspicious | Servers don't normally initiate outbound RDP on their own — implies someone is pivoting from within an active session (exception: environments using jump boxes) |

### Correlating a session

- `LogonId` on a process-creation event (e.g. a discovery command) ties it to a specific logon session; matching that `Logon_ID` against Event 4624 on the same host shows how that session was established (logon type, source IP).
- The same machine-account technique from SMB investigation (searching Event 4624 for `user=*$` from a source IP) maps the source IP to a hostname.
- `mstsc.exe` in Sysmon Event 1 on a host is evidence that host initiated an outbound RDP connection.

### RDP chaining

An attacker pivots through one or more intermediate machines to reach a sensitive target (e.g. a Domain Controller), opening a new RDP connection from within each session using (often) different, more privileged credentials at each hop. Each hop is RDP, but the source IP changes at every hop since the connection originates from the intermediate machine rather than the attacker's original host.

## Event IDs

| ID | Log | What it is | Why it matters |
|---|---|---|---|
| 1 | Sysmon | Process creation | Shows discovery/PsExec/RDP-related command lines; `ParentImage=*PSEXESVC*` isolates PsExec-spawned commands, `Image=*mstsc.exe*` shows outbound RDP initiation |
| 17 | Sysmon | Pipe Created | PsExec's stdin/stdout/stderr named pipes (`\PSEXESVC-<hostname>-<pid>-...`), often unchanged even if the binary is renamed |
| 4104 | PowerShell | Script Block Logging | Full decoded script block incl. cmdlets and parameters — resilient to PowerShell command-line obfuscation unlike Event 1/4688 |
| 4624 | Security | Successful logon | `Logon_Type` 3 = SMB/PsExec, 10 = RDP; `user=*$` from a given source IP maps that IP to its hostname |
| 4648 | Security | Explicit Credential Usage | Source-side confirmation of alternate credentials used per share connection; still logged even when a C2 SMB module skips `net.exe` |
| 4688 | Security | Process creation | Fallback for Sysmon Event 1 if Sysmon isn't deployed; same single-event-per-launch limitation as Sysmon 1 |
| 5140 | Security | Network share object accessed | Reveals `ADMIN$`/`C$` access with source IP, account and share name; fires regardless of the tool used to connect |
| 5145 | Security | Detailed File Share | `Relative_Target_Name` shows specific files/named pipes accessed — for PsExec, reveals the source hostname via the pipe name; requires "Audit Detailed File Share" enabled |
| 7045 | System | New service installed | Signature artifact for PsExec (default name `PSEXESVC`); still fires even with a renamed service, identifiable by `Service_Type`="user mode service" + `Service_Start_Type`="demand start" |
