# Mythic

{{#include ../banners/hacktricks-training.md}}

## Was ist Mythic?

Mythic ist ein Open-Source-, modulares, kollaboratives command and control (C2)-Framework, das für red teaming entwickelt wurde. Es ermöglicht Operatoren, Agents (payloads) über verschiedene Betriebssysteme hinweg zu verwalten und bereitzustellen, einschließlich Windows, Linux und macOS. Mythic bietet eine Browser-UI für Multi-Operator-Tasking, Dateiverwaltung, SOCKS/rpfwd-Management und Payload-Generierung.

Im Gegensatz zu monolithischen Frameworks liefert das Mythic-Repository selbst **keine** payload-Typen oder C2-Profile aus. Agents, Wrappers und C2-Profile werden typischerweise als externe Komponenten installiert und können unabhängig vom Mythic-Kern aktualisiert werden.

### Installation

Um Mythic zu installieren, befolge die Anweisungen im offiziellen **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Ein gängiger Bootstrap aus dem Mythic-Verzeichnis ist:
```bash
sudo make
sudo ./mythic-cli start
```
Wenn Mythic bereits läuft, kannst du normalerweise mit `./mythic-cli install github ...` einen neuen Agent oder ein neues Profil hinzufügen und dann entweder Mythic neu starten oder die neue Komponente direkt starten.

### Agents

Mythic unterstützt mehrere Agents, die die **payloads sind, die Aufgaben auf den kompromittierten Systemen ausführen**. Jeder Agent kann an spezifische Anforderungen angepasst werden und auf verschiedenen Betriebssystemen laufen.

Standardmäßig sind in Mythic keine Agents installiert. Die Open-Source-Community-Agents befinden sich in [**https://github.com/MythicAgents**](https://github.com/MythicAgents), und die [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) ist nützlich, um schnell unterstützte Betriebssysteme, payload-Formate, wrappers und C2 profiles zu prüfen.

Um einen Agent aus dieser Organisation zu installieren, kannst du ausführen:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Die `sudo -E`-Form ist nützlich, wenn du aus einer Non-Root-Umgebung installierst. Du kannst mit dem vorherigen Befehl neue Agents hinzufügen, selbst wenn Mythic bereits läuft.

### C2 Profiles

C2 profiles in Mythic definieren **wie agents mit dem Mythic server kommunizieren**. Sie legen das Kommunikationsprotokoll, die Verschlüsselungsmethoden und weitere Einstellungen fest. Du kannst C2 profiles über die Mythic web interface erstellen und verwalten.

Standardmäßig wird Mythic ohne profiles installiert, allerdings ist es möglich, einige profiles aus dem Repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) herunterzuladen, indem du Folgendes ausführst:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): grundlegender asynchroner GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): flexiblerer HTTP traffic mit mehreren Callback-Domains, Fail-over-/Round-robin-Rotation, benutzerdefinierten Headers/Query-Parametern und Message-Transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`), die in Cookies, Headers, Query-Parametern oder dem Body platziert werden.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-gesteuertes Shaping von HTTP-Messages, wenn das statische `http`-Profil zu auffällig ist.

### Current platform notes

- Viele öffentliche Agents und Profiles installieren inzwischen mit vorgefertigten Remote-Container-Images.
Wenn du eine Komponente forkst oder lokal patchst und Mythic weiterhin das alte
Verhalten verwendet, prüfe die erzeugten `.env`-Einträge für `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` und `*_USE_VOLUME`; das Aktivieren von
`*_USE_BUILD_CONTEXT="true"` ist normalerweise das, was Mythic dazu bringt, aus deinem
lokalen Docker-Kontext neu zu bauen, statt stillschweigend das Remote-Image
weiterzuverwenden.
- Browser scripts gehören zu den wertvollsten Quality-of-life-Features von Mythic
für Operatoren: Sie können rohe Befehlsausgaben in Tabellen, Screenshot-
Viewer, Download-Links und Buttons umwandeln, die direkt aus der UI
nachfolgende Tasking-Aufträge auslösen. Das ist besonders nützlich für
wiederholte `ls`, `ps`, Triage- und File-Browser-Workflows.
- Neuere Mythic-Builds unterstützen außerdem interaktives Tasking und Push-C2-Muster,
die den Bedarf an `sleep 0`-Polling bei PTY-/SOCKS-/rpfwd-lastigen
Operationen reduzieren. Wenn ein Agent/Profile das unterstützt, ist das
normalerweise mit geringerem Overhead verbunden als das ständige Anfragen
des Servers, nur um einen interaktiven Kanal nutzbar zu halten.

### Wrapper payloads

Wrapper payloads erlauben dir, die gleiche Agent-Logik beizubehalten, während du die On-Disk-Repräsentation änderst, die ausgeliefert oder persistiert wird.

- `service_wrapper`: verwandelt ein anderes Payload in eine Windows-Service-Executable, was nützlich ist, wenn der Ausführungspfad eine gültige Service-Binary erfordert.
- `scarecrow_wrapper`: umhüllt kompatiblen shellcode mit dem ScareCrow-Loader, um loader-gestützte Ausgaben wie EXE/DLL/CPL zu erzeugen.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ist ein Windows-Agent, geschrieben in C# unter Verwendung des 4.0 .NET Framework, der für die Nutzung in SpecterOps-Training-Angeboten entwickelt wurde.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Aktuelle Build/Profile-Notizen

- Apollo kann derzeit `WinExe`, `Shellcode`, `Service` und `Source` Payloads ausgeben.
- Die häufig verwendeten Apollo-Profile sind `http`, `httpx`, `smb`, `tcp` und `websocket`.
- `httpx` ist normalerweise die flexiblere Option, wenn du Domain-Rotation, Proxy-Support, benutzerdefinierte Message-Platzierung und Message-Transforms statt des älteren statischen `http`-Profils brauchst.
- Apollo unterstützt Wrapper-Payloads wie `service_wrapper` und `scarecrow_wrapper`.
- `register_file` und `register_assembly` sind die Staging-Primitiven für `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` und `powerpick`. In aktuellen Apollo-Builds werden diese gestagten Artefakte clientseitig als DPAPI-geschützte AES256-Blobs gecacht.
- `ls`- und `ps`-Ergebnisse integrieren sich besonders gut mit Mythic's Browser-Skripten und dem File-/Process-Browser, was das Triage für Operatoren bei kollaborativen Operationen deutlich schneller macht.
- Apollo's Fork-and-Run-Jobs übernehmen ihre Sacrificial-Process-Einstellungen von
`spawnto_x86` / `spawnto_x64`, übernehmen die Parent-Auswahl von `ppid` und
verwenden dann die aktuell ausgewählte Injection-Primitiv. In der Praxis bedeutet
das, dass dein OPSEC-Tuning für einen Befehl oft gleichzeitig
`execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` und `spawn`
beeinflusst.
- Zu den aktuell dokumentierten Apollo-Injection-Backends gehören `CreateRemoteThread`,
`QueueUserAPC` (Early-Bird-Stil) und `NtCreateThreadEx` via syscalls. Verwende
`get_injection_techniques` vor lautem Post-Exploitation und
`set_injection_technique`, wenn du von einer Primitiv wegwechseln musst, die
mit dem Zielsystem oder dem auszuführenden Befehl kollidiert.
- `blockdlls` betrifft nur Sacrificial Processes, die für Post-Exploitation
Jobs erstellt werden. Zusammen mit einem weniger verdächtigen `spawnto_x64`-Ziel als dem standardmäßigen
nackten `rundll32.exe` ist das eine der einfachsten Änderungen auf Apollo-Seite vor
dem Ausführen von assembly-/PowerShell-lastigem Tasking.

Dieser Agent hat viele Befehle, was ihn Cobalt Strike's Beacon mit einigen Extras sehr ähnlich macht. Unter anderem unterstützt er:

### Häufige Aktionen

- `cat`: Den Inhalt einer Datei ausgeben
- `cd`: Das aktuelle Arbeitsverzeichnis ändern
- `cp`: Eine Datei von einem Ort an einen anderen kopieren
- `ls`: Dateien und Verzeichnisse im aktuellen Verzeichnis oder im angegebenen Pfad auflisten
- `ifconfig`: Netzwerkadapter und Interfaces abrufen
- `netstat`: TCP- und UDP-Verbindungsinformationen abrufen
- `pwd`: Das aktuelle Arbeitsverzeichnis ausgeben
- `ps`: Laufende Prozesse auf dem Zielsystem auflisten (mit zusätzlichen Infos)
- `jobs`: Alle laufenden Jobs auflisten, die mit Long-Running-Tasking verbunden sind
- `download`: Eine Datei vom Zielsystem auf den lokalen Rechner herunterladen
- `upload`: Eine Datei vom lokalen Rechner auf das Zielsystem hochladen
- `reg_query`: Registry-Keys und -Werte auf dem Zielsystem abfragen
- `reg_write_value`: Einen neuen Wert in einen angegebenen Registry-Key schreiben
- `sleep`: Das Schlafintervall des Agents ändern, das bestimmt, wie oft er sich beim Mythic-Server meldet
- Und viele weitere, verwende `help`, um die vollständige Liste der verfügbaren Befehle zu sehen.

### Privilege Escalation

- `getprivs`: So viele Privilegien wie möglich auf dem aktuellen Thread-Token aktivieren
- `getsystem`: Einen Handle zu winlogon öffnen und den Token duplizieren, wodurch die Privilegien effektiv auf SYSTEM-Level erhöht werden
- `make_token`: Eine neue Logon-Session erstellen und auf den Agent anwenden, sodass die Impersonation eines anderen Users möglich wird
- `steal_token`: Einen Primary Token von einem anderen Prozess stehlen, sodass der Agent den User dieses Prozesses impersonieren kann
- `pth`: Pass-the-Hash-Angriff, der es dem Agenten ermöglicht, sich als User mit dessen NTLM-Hash zu authentifizieren, ohne das Klartextpasswort zu benötigen
- `mimikatz`: Mimikatz-Befehle ausführen, um Credentials, Hashes und andere sensible Informationen aus dem Speicher oder der SAM-Datenbank zu extrahieren
- `rev2self`: Den Token des Agents auf seinen Primary Token zurücksetzen, wodurch die Privilegien effektiv wieder auf das ursprüngliche Level fallen
- `ppid`: Den Parent Process für Post-Exploitation-Jobs ändern, indem eine neue Parent-Process-ID angegeben wird, was eine bessere Kontrolle über den Ausführungskontext des Jobs ermöglicht
- `printspoofer`: PrintSpoofer-Befehle ausführen, um Sicherheitsmaßnahmen des Print Spoolers zu umgehen, was Privilege Escalation oder Codeausführung ermöglicht
- `dcsync`: Die Kerberos-Keys eines Users mit dem lokalen Rechner synchronisieren, was Offline-Passwort-Cracking oder weitere Angriffe ermöglicht
- `ticket_cache_add`: Ein Kerberos-Ticket zur aktuellen Logon-Session oder zu einer angegebenen hinzufügen, was Ticket-Reuse oder Impersonation ermöglicht

### Process execution

- `assembly_inject`: Ermöglicht das Injizieren eines .NET-Assembly-Loaders in einen Remote-Prozess
- `blockdlls`: Das Laden nicht von Microsoft signierter DLLs in Post-Exploitation-Jobs blockieren
- `execute_assembly`: Führt eine .NET-Assembly im Kontext des Agents aus
- `execute_coff`: Führt eine COFF-Datei im Speicher aus und ermöglicht damit In-Memory-Ausführung von kompiliertem Code
- `execute_pe`: Führt eine unmanaged Executable (PE) aus
- `keylog_inject`: Injiziert einen Keylogger in einen anderen Prozess und streamt Tastatureingaben zurück in Mythic's Keylog-Ansicht
- `screenshot` / `screenshot_inject`: Den aktuellen Desktop direkt erfassen oder
durch Injizieren einer Screenshot-Assembly in einen Zielprozess/-Session
- `get_injection_techniques`: Verfügbare Injection-Techniken und die aktuell ausgewählte anzeigen
- `inline_assembly`: Führt eine .NET-Assembly in einer disposablen AppDomain aus und ermöglicht so temporäre Codeausführung, ohne den Hauptprozess des Agents zu beeinflussen
- `register_assembly`: Eine .NET-Assembly für spätere Ausführung registrieren
- `register_file`: Eine Datei im Agent-Cache für späteres `execute_*`- oder PowerShell-Tasking registrieren
- `run`: Führt ein Binary auf dem Zielsystem aus und verwendet den systemeigenen PATH, um das Executable zu finden
- `set_injection_technique`: Die von Post-Exploitation-Jobs verwendete Injection-Primitiv ändern
- `shinject`: Injiziert Shellcode in einen Remote-Prozess und ermöglicht damit In-Memory-Ausführung beliebigen Codes
- `inject`: Injiziert Agent-Shellcode in einen Remote-Prozess und ermöglicht damit In-Memory-Ausführung des Agent-Codes
- `spawn`: Startet eine neue Agent-Session in dem angegebenen Executable und ermöglicht damit die Ausführung von Shellcode in einem neuen Prozess
- `spawnto_x64` und `spawnto_x86`: Das Standard-Binary für Post-Exploitation-Jobs auf einen angegebenen Pfad ändern, statt `rundll32.exe` ohne Parameter zu verwenden, was sehr auffällig ist.

### Mythic Forge

Dies erlaubt das **Laden von COFF/BOF**-Dateien aus der Mythic Forge, einem Repository vorcompilierter Payloads und Tools, die auf dem Zielsystem ausgeführt werden können. Mit all den ladbaren Befehlen wird es möglich sein, gängige Aktionen auszuführen, indem sie im aktuellen Agent-Prozess als BOFs ausgeführt werden (normalerweise mit besserem OPSEC als das Starten eines separaten Prozesses).

Beginne mit der Installation über:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Dann nutze `forge_collections`, um die COFF/BOF-Module aus dem Mythic Forge anzuzeigen, damit sie ausgewählt und in den Speicher des Agents für die Ausführung geladen werden können. Standardmäßig werden in Apollo die folgenden 2 collections hinzugefügt:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nachdem ein Modul geladen wurde, erscheint es in der Liste als weiterer Befehl wie `forge_bof_sa-whoami` oder `forge_bof_sa-netuser`.

Bei BOFs gilt: Forge übergibt an Apollo **nicht** einfach nur einen flachen Argument-String. Stattdessen mappt Forge die BOF-Parameter in Mythics typed-array-Format und leitet sie dann in Apollos `execute_coff`-Flow weiter. Wenn sich ein von Forge geladenes BOF seltsam verhält, prüfe die erwarteten BOF-Argumenttypen bzw. den Entrypoint und nicht nur die Commandline, die du eingegeben hast.

### PowerShell & scripting execution

- `powershell_import`: Importiert ein neues PowerShell-Skript (.ps1) in den Agent-Cache zur späteren Ausführung
- `powershell`: Führt einen PowerShell-Befehl im Kontext des Agents aus und ermöglicht so fortgeschrittenes Scripting und Automation
- `powerpick`: Injiziert eine PowerShell-Loader-Assembly in einen Opferprozess und führt einen PowerShell-Befehl aus (ohne powershell logging).
- `psinject`: Führt PowerShell in einem angegebenen Prozess aus und ermöglicht so die gezielte Ausführung von Skripten im Kontext eines anderen Prozesses
- `shell`: Führt einen Shell-Befehl im Kontext des Agents aus, ähnlich wie ein Befehl in cmd.exe

### Lateral Movement

- `jump_psexec`: Nutzt die PsExec-Technik, um lateral zu einem neuen Host zu wechseln, indem zuerst die Apollo-Agent-Executable (apollo.exe) kopiert und ausgeführt wird.
- `jump_wmi`: Nutzt die WMI-Technik, um lateral zu einem neuen Host zu wechseln, indem zuerst die Apollo-Agent-Executable (apollo.exe) kopiert und ausgeführt wird.
- `link` und `unlink`: Erstellen und entfernen P2P-Links (zum Beispiel über SMB/TCP) zwischen Callbacks.
- `wmiexecute`: Führt einen Befehl auf dem lokalen oder angegebenen entfernten System mithilfe von WMI aus, optional mit Credentials zur Impersonation.
- `net_dclist`: Ruft eine Liste von Domain Controllern für die angegebene Domain ab, nützlich zur Identifizierung potenzieller Ziele für lateral movement.
- `net_localgroup`: Listet lokale Gruppen auf dem angegebenen Computer auf und verwendet standardmäßig localhost, wenn kein Computer angegeben ist.
- `net_localgroup_member`: Ruft die lokale Gruppenmitgliedschaft für eine angegebene Gruppe auf dem lokalen oder entfernten Computer ab und ermöglicht so die Enumeration von Benutzern in bestimmten Gruppen.
- `net_shares`: Listet entfernte Shares und deren Erreichbarkeit auf dem angegebenen Computer auf, nützlich zur Identifizierung potenzieller Ziele für lateral movement.
- `socks`: Aktiviert einen SOCKS-5-konformen Proxy im Zielnetzwerk und ermöglicht so das Tunneling von Traffic über den kompromittierten Host. Kompatibel mit Tools wie proxychains.
- `rpfwd`: Startet das Lauschen auf einem angegebenen Port auf dem Zielhost und leitet Traffic über Mythic an eine entfernte IP und einen Port weiter, was den Fernzugriff auf Dienste im Zielnetzwerk ermöglicht.
- `listpipes`: Listet alle Named Pipes auf dem lokalen System auf, was für lateral movement oder privilege escalation nützlich sein kann, indem mit IPC-Mechanismen interagiert wird.

Für die darunterliegenden WMI-Ausführungsprimitive, die von `jump_wmi` oder `wmiexecute` verwendet werden, siehe [WmiExec](lateral-movement/wmiexec.md). Für allgemeinere Pivoting-Muster siehe [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Zeigt detaillierte Informationen zu bestimmten Befehlen oder allgemeine Informationen zu allen verfügbaren Befehlen im Agenten an.
- `clear`: Markiert Tasks als 'cleared', sodass sie nicht von Agents aufgenommen werden können. Du kannst `all` angeben, um alle Tasks zu löschen, oder `task Num`, um einen bestimmten Task zu löschen.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon ist ein Golang-Agent, der in **Linux- und macOS**-Executables kompiliert wird.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Aktuelle Build-/Profil-Hinweise

- Aktuelle Poseidon-Builds zielen auf Linux und macOS auf `x86_64` und `arm64` ab.
- Unterstützte Ausgabeformate umfassen native Executables sowie Shared-Library-artige Ausgaben wie `dylib` und `so`.
- Poseidon unterstützt `http`, `websocket`, `tcp` und `dynamichttp`, und aktuelle Builder bieten Multi-Egress-Einstellungen wie `egress_order` und Failover-Schwellenwerte.
- Build-Time-Optionen wie `proxy_bypass` und `garble` solltest du prüfen, wenn du entweder saubereres Netzwerkverhalten oder zusätzliche Go-Binary-Obfuskation brauchst.
- `pty` ist einer der nützlichsten neueren Quality-of-Life-Commands für Linux/macOS
  operationen, weil es ein interaktives PTY öffnet und einen Mythic-seitigen
  Port für umfassendere Terminal-Interaktion bereitstellen kann, ohne auf den älteren `sleep 0`
  + SOCKS-Workaround zurückgreifen zu müssen.
- Poseidons aktuelle Doku ist besonders interessant für macOS-lastiges
  Tradecraft: `jxa` führt JavaScript for Automation in-memory aus,
  `screencapture` greift den angemeldeten Desktop ab, `clipboard_monitor` streamt
  Änderungen der Zwischenablage, `execute_library` lädt eine lokale dylib und ruft
  eine Funktion daraus auf, und `libinject` zwingt einen Remote-Prozess, eine
  auf der Festplatte liegende dylib zu laden.
- Bei lang laufenden Jobs solltest du daran denken, dass Poseidon Post-Exploitation-Arbeit
  in Goroutines/Threads ausführt, die kooperativ statt hart beendbar sind. Die
  Doku weist außerdem ausdrücklich darauf hin, dass es derzeit keine eingebaute Agent-
  Obfuskation gibt, sodass Build-/Profil-Level-Tradecraft wichtiger ist als bei stark
  obfuskierten kommerziellen Implants.

Für macOS-spezifisches Tradecraft rund um Mythic-gestützte Operationen, JAMF-Missbrauch oder MDM-as-C2-Ideen, siehe [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Wenn es unter Linux oder macOS verwendet wird, hat es einige interessante Commands:

### Common actions

- `cat`: Den Inhalt einer Datei ausgeben
- `cd`: Das aktuelle Arbeitsverzeichnis ändern
- `chmod`: Die Berechtigungen einer Datei ändern
- `config`: Aktuelle Konfiguration und Host-Informationen anzeigen
- `cp`: Eine Datei von einem Ort an einen anderen kopieren
- `curl`: Eine einzelne Web-Anfrage mit optionalen Headern und Methode ausführen
- `upload`: Eine Datei auf das Ziel hochladen
- `download`: Eine Datei vom Zielsystem auf den lokalen Rechner herunterladen
- Und viele mehr

### Search Sensitive Information

- `triagedirectory`: Interessante Dateien innerhalb eines Verzeichnisses auf einem Host finden, etwa sensible Dateien oder Credentials.
- `getenv`: Alle aktuellen Umgebungsvariablen abrufen.

### macOS-specific tradecraft

- `jxa`: JavaScript for Automation in-memory via `OSAScript` ausführen, was
  für native macOS Post-Exploitation ohne das Ablegen separater Skript-
  Dateien nützlich ist.
- `clipboard_monitor`: Das Pasteboard abfragen und Änderungen an Mythic
  zurückmelden, was für Credential-/Token-Diebstahl-Workflows praktisch ist, die auf Copy/Paste beruhen.
- `screencapture`: Den Desktop des Benutzers unter macOS erfassen.
- `execute_library`: Eine dylib von der Festplatte laden und eine bestimmte exportierte Funktion aufrufen.
- `libinject`: Einen Shellcode-Stub injizieren, der einen anderen macOS-Prozess dazu zwingt, eine dylib von der Festplatte zu laden.
- `persist_launchd`: LaunchAgent / LaunchDaemon-Persistenz direkt vom Agenten aus erstellen.

### Move laterally

- `ssh`: Per SSH mit den angegebenen Credentials zum Host verbinden und ein PTY öffnen, ohne ssh zu starten.
- `sshauth`: Mit den angegebenen Credentials zu den angegebenen Hosts per SSH verbinden. Du kannst dies auch verwenden, um über SSH einen bestimmten Befehl auf den Remote-Hosts auszuführen oder Dateien per SCP zu kopieren.
- `link_tcp`: Über TCP mit einem anderen Agenten verbinden, was direkte Kommunikation zwischen Agenten ermöglicht.
- `link_webshell`: Mit einem Agenten über das webshell P2P-Profil verbinden, was Remote-Zugriff auf die Web-Oberfläche des Agents ermöglicht.
- `rpfwd`: Einen Reverse Port Forward starten oder stoppen, um Remote-Zugriff auf Services im Zielnetzwerk zu ermöglichen.
- `socks`: Einen SOCKS5-Proxy im Zielnetzwerk starten oder stoppen, um Traffic durch den kompromittierten Host zu tunneln. Kompatibel mit Tools wie proxychains.
- `portscan`: Host(s) nach offenen Ports scannen, nützlich zur Identifizierung potenzieller Ziele für laterale Bewegung oder weitere Angriffe.

### Process execution

- `shell`: Einen einzelnen Shell-Command via /bin/sh ausführen, was die direkte Ausführung von Commands auf dem Zielsystem ermöglicht.
- `run`: Einen Command von der Festplatte mit Argumenten ausführen, was die Ausführung von Binaries oder Skripten auf dem Zielsystem ermöglicht.
- `pty`: Ein interaktives PTY öffnen, was die direkte Interaktion mit der Shell auf dem Zielsystem ermöglicht.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
