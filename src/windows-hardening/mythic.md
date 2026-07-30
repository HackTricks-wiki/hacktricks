# Mythic

{{#include ../banners/hacktricks-training.md}}

## Was ist Mythic?

Mythic ist ein open-source, modulares und kollaboratives Command-and-Control-(C2)-Framework für Red Teaming. Es ermöglicht Operatoren, Agents (Payloads) auf verschiedenen Betriebssystemen zu verwalten und bereitzustellen, darunter Windows, Linux und macOS. Mythic bietet eine Browser-UI für Multi-Operator-Tasking, Dateiverwaltung, SOCKS/rpfwd-Management und die Payload-Generierung.

Im Gegensatz zu monolithischen Frameworks enthält das Mythic-Repository selbst keine Payload-Typen oder C2-Profile. Agents, Wrapper und C2-Profile werden normalerweise als externe Komponenten installiert und können unabhängig vom Mythic-Kern aktualisiert werden.

### Installation

Um Mythic zu installieren, folge den Anweisungen im offiziellen **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Ein gängiger Bootstrap-Vorgang aus dem Mythic-Verzeichnis ist:
```bash
sudo make
sudo ./mythic-cli start
```
Wenn Mythic bereits läuft, kannst du normalerweise mit `./mythic-cli install github ...` einen neuen Agenten oder ein neues Profil hinzufügen und anschließend entweder Mythic neu starten oder die neue Komponente direkt starten.

### Agenten

Mythic unterstützt mehrere Agenten, also **Payloads, die Aufgaben auf den kompromittierten Systemen ausführen**. Jeder Agent kann an spezifische Anforderungen angepasst werden und auf unterschiedlichen Betriebssystemen laufen.

Standardmäßig sind in Mythic keine Agenten installiert. Die Agenten der Open-Source-Community befinden sich unter [**https://github.com/MythicAgents**](https://github.com/MythicAgents), und die [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) ist hilfreich, um schnell unterstützte Betriebssysteme, Payload-Formate, Wrappers und C2 profiles zu überprüfen.

Um einen Agenten aus dieser Organisation zu installieren, kannst du Folgendes ausführen:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Die Form `sudo -E` ist nützlich, wenn du die Installation aus einer Umgebung ohne Root-Rechte durchführst. Du kannst mit dem vorherigen Befehl neue Agenten hinzufügen, auch wenn Mythic bereits ausgeführt wird.

### C2 Profiles

C2 profiles in Mythic definieren, **wie Agents mit dem Mythic-Server kommunizieren**. Sie legen das Kommunikationsprotokoll, die Verschlüsselungsmethoden und weitere Einstellungen fest. Du kannst C2 profiles über die Mythic-Weboberfläche erstellen und verwalten.

Standardmäßig wird Mythic ohne Profiles installiert. Es ist jedoch möglich, einige Profiles aus dem Repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) mit folgendem Befehl herunterzuladen:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Aktuelle für Operatoren relevante Profile, die es zu beachten gilt:

- [`http`](https://github.com/MythicC2Profiles/http): grundlegender asynchroner GET/POST-Traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): flexiblerer HTTP-Traffic mit mehreren Callback-Domains, Fail-over-/Round-robin-Rotation, benutzerdefinierten Headern/Query-Parametern und Message-Transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`), die in Cookies, Headern, Query-Parametern oder dem Body platziert werden.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-gesteuerte Gestaltung von HTTP-Nachrichten, wenn das statische `http`-Profil zu leicht erkennbar ist.

### Aktuelle Hinweise zur Plattform

- Viele öffentliche Agents und Profile werden inzwischen mit vorgefertigten Remote-Container-Images installiert.
Wenn du eine Komponente forkt oder lokal patchst und Mythic weiterhin das alte
Verhalten verwendet, prüfe die generierten `.env`-Einträge für
`*_REMOTE_IMAGE`, `*_USE_BUILD_CONTEXT` und `*_USE_VOLUME`; das Aktivieren von
`*_USE_BUILD_CONTEXT="true"` sorgt normalerweise dafür, dass Mythic aus deinem
lokalen Docker-Kontext neu baut, anstatt unbemerkt das Remote-Image
wiederzuverwenden.
- Browser-Skripte gehören zu den wertvollsten Quality-of-Life-Features von Mythic
für Operatoren: Sie können rohe Command-Ausgaben in Tabellen, Screenshot-Viewer,
Download-Links, Such-Links und Buttons umwandeln, die direkt aus der UI
Folge-Tasks auslösen. Aktuelle Mythic-Builds ermöglichen es jedem Operator,
eigene Skripte zu verwalten, sie global oder pro Task zu aktivieren bzw. zu
deaktivieren, und erzielen die besten Ergebnisse, wenn Agents strukturierte JSON-
Daten statt Plaintext zurückgeben. Das ist besonders nützlich für wiederholte
`ls`-, `ps`-, Triage- und File-Browser-Workflows.
- Neuere Mythic-Builds unterstützen außerdem interaktives Tasking und Push-C2-Muster,
wodurch der Bedarf an `sleep 0`-Polling bei PTY-/SOCKS-/rpfwd-lastigen
Operationen sinkt. Wenn ein Agent/Profil dies unterstützt, verursacht das
normalerweise weniger Overhead als den Server ständig mit Check-ins zu belasten,
nur um einen interaktiven Channel nutzbar zu halten.
- Die aktuellen Mythic-Builder der 3.4-Ära sind kontextbewusster, als ältere
Anleitungen vermuten lassen: Build-Parameter können jetzt abhängig vom
ausgewählten OS oder anderen Build-Optionen gruppiert oder ausgeblendet werden,
Payload-Typen können angeben, ob sie mehrere C2-Profile oder mehrere Instanzen
desselben C2 in einem Build unterstützen, und C2-Parameterabweichungen
ermöglichen es einem Agent, Felder auszublenden, die er tatsächlich nicht
implementiert. Das ist relevant, wenn du zwischen `http`, `httpx`, `smb`,
`tcp` und `websocket` wechselst, da die sichere/gültige Build-Oberfläche keine
flache statische Form mehr ist.
- Wenn du ein benutzerdefiniertes Agent/Profile-Paar erstellst und nicht möchtest,
dass Mythics JSON-Nachrichtenformat oder die standardmäßige Crypto über das
Netz übertragen wird, verwende einen
`translation_container`: Mythic entfernt die UUID, übergibt den verschlüsselten
Blob und das Schlüsselmaterial über gRPC an den Translator und erwartet dafür
agent-native Bytes zurück. Das ist der saubere Weg, binäre Protokolle,
benutzerdefiniertes Framing oder eine agent-seitige Verschlüsselung zu
unterstützen, ohne den gesamten Server neu zu schreiben.
- Denke daran, dass verknüpfte/P2P-Callbacks nicht nur Tasking weiterleiten. Mythics
`get_tasking`-Ablauf kann auch Responses sowie `delegates`,
`socks`, `rpfwd`- und `interactive`-Daten übertragen. In der Praxis kann ein
Egress-Callback innere Callbacks und Pivot-Channels in derselben Polling-Schleife
bedienen. Wenn die Child-Agents eigene regelmäßige Check-ins durchführen,
verhindert `get_delegate_tasks=false`, dass der Parent versehentlich die
wartenden Jobs des inneren Callbacks abruft.

### Wrapper-Payloads

Wrapper-Payloads ermöglichen es dir, dieselbe Agent-Logik beizubehalten und
gleichzeitig die On-Disk-Repräsentation zu ändern, die ausgeliefert oder
gespeichert wird.

- `service_wrapper`: wandelt einen anderen Payload in eine Windows-Service-Executable um, was nützlich ist, wenn der Ausführungspfad eine gültige Service-Binary erfordert.
- `scarecrow_wrapper`: verpackt kompatiblen Shellcode mit dem ScareCrow-Loader, um Loader-basierte Outputs wie EXE/DLL/CPL zu erzeugen.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ist ein in C# geschriebener Windows-Agent, der das 4.0 .NET Framework
verwendet und für den Einsatz in SpecterOps-Trainingsangeboten entwickelt wurde.

Installiere ihn mit:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Aktuelle Build-/Profil-Hinweise

- Apollo kann derzeit `WinExe`-, `Shellcode`-, `Service`- und `Source`-Payloads erzeugen.
- Die häufig verwendeten Apollo-Profile sind `http`, `httpx`, `smb`, `tcp` und `websocket`.
- `httpx` ist normalerweise die flexiblere Option, wenn du Domain-Rotation, Proxy-Unterstützung, benutzerdefinierte Nachrichtenplatzierung und Message-Transforms anstelle des älteren statischen `http`-Profils benötigst.
- Apollo ist einer der funktionsreicheren Community-Agenten und bietet derzeit Mythic-seitige Integrationen wie Browser-Skripte, Datei-/Prozess-Browseransichten, Screenshots, Keylogging, SOCKS, rpfwd, Push C2 und P2P-Routing.
- Apollo unterstützt Wrapper-Payloads wie `service_wrapper` und `scarecrow_wrapper`.
- Apollo unterstützt das dynamische Laden von Commands. Dadurch kann der initiale Payload schlank gehalten und zusätzliche Commands oder Forge-Module später geladen werden, anstatt jede Post-Exploitation-Funktion in den ersten Build zu kompilieren.
- Beim Erzeugen von Shellcode-Output bietet Apollo's aktueller Builder außerdem Donut-Formatoptionen (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) und Donut-Bypass-Verhalten (`None`, `Abort on fail`, `Continue on fail`). Das ist hilfreich, wenn das Endziel darin besteht, den Shellcode mit `service_wrapper`, `scarecrow_wrapper` oder einem benutzerdefinierten Loader erneut zu wrappen.
- `register_file` und `register_assembly` sind die Staging-Primitives für `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` und `powerpick`. In aktuellen Apollo-Builds werden diese gestagten Artefakte clientseitig als durch DPAPI geschützte AES256-Blobs zwischengespeichert.
- Die Ergebnisse von `ls` und `ps` integrieren sich besonders gut in Mythic's Browser-Skripte sowie den Datei-/Prozess-Browser, wodurch die Operator-Triage in kollaborativen Operationen deutlich schneller wird.
- Apollo's Fork-and-Run-Jobs übernehmen ihre Einstellungen für sacrificial processes von
`spawnto_x86` / `spawnto_x64`, übernehmen die Parent-Auswahl von `ppid` und verwenden
anschließend das aktuell ausgewählte Injection-Primitive. In der Praxis bedeutet das, dass
dein OPSEC-Tuning für einen Command häufig gleichzeitig `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` und `spawn` beeinflusst.
- Zu den aktuell dokumentierten Apollo-Injection-Backends gehören `CreateRemoteThread`,
`QueueUserAPC` (Early-Bird-Stil) und `NtCreateThreadEx` über Syscalls. Verwende
`get_injection_techniques` vor geräuschintensiver Post-Exploitation und
`set_injection_technique`, wenn du von einem Primitive wechseln musst, das mit dem
Ziel oder dem auszuführenden Command kollidiert.
- `blockdlls` wirkt sich nur auf sacrificial processes aus, die für Post-Exploitation-Jobs
erstellt werden. Zusammen mit einem weniger verdächtigen `spawnto_x64`-Ziel als dem standardmäßigen
reinen `rundll32.exe` ist dies eine der einfachsten Apollo-seitigen Änderungen, die vor dem
Ausführen von assembly-/PowerShell-lastigem Tasking vorgenommen werden kann.

Dieser Agent verfügt über zahlreiche Commands, wodurch er Cobalt Strike's Beacon mit einigen Extras sehr ähnlich ist. Dazu gehören:

### Häufige Aktionen

- `cat`: Gibt den Inhalt einer Datei aus
- `cd`: Wechselt das aktuelle Arbeitsverzeichnis
- `cp`: Kopiert eine Datei von einem Ort an einen anderen
- `ls`: Listet Dateien und Verzeichnisse im aktuellen Verzeichnis oder im angegebenen Pfad auf
- `ifconfig`: Ruft Netzwerkadapter und Interfaces ab
- `netstat`: Ruft Informationen zu TCP- und UDP-Verbindungen ab
- `pwd`: Gibt das aktuelle Arbeitsverzeichnis aus
- `ps`: Listet laufende Prozesse auf dem Zielsystem auf (mit zusätzlichen Informationen)
- `jobs`: Listet alle laufenden Jobs auf, die mit länger laufendem Tasking verbunden sind
- `download`: Lädt eine Datei vom Zielsystem auf den lokalen Rechner herunter
- `upload`: Lädt eine Datei vom lokalen Rechner auf das Zielsystem hoch
- `reg_query`: Fragt Registry-Keys und -Werte auf dem Zielsystem ab
- `reg_write_value`: Schreibt einen neuen Wert in einen angegebenen Registry-Key
- `sleep`: Ändert das Sleep-Intervall des Agents, das bestimmt, wie häufig er beim Mythic-Server eincheckt
- Und viele weitere; verwende `help`, um die vollständige Liste der verfügbaren Commands anzuzeigen.

### Privilege Escalation

- `getprivs`: Aktiviert so viele Privileges wie möglich im Token des aktuellen Threads
- `getsystem`: Öffnet ein Handle zu winlogon und dupliziert den Token, wodurch Privileges effektiv auf SYSTEM-Ebene erhöht werden
- `make_token`: Erstellt eine neue Logon-Session und wendet sie auf den Agent an, wodurch die Impersonation eines anderen Benutzers ermöglicht wird
- `steal_token`: Stiehlt einen Primary Token aus einem anderen Prozess, wodurch der Agent den Benutzer dieses Prozesses impersonieren kann
- `pth`: Pass-the-Hash-Angriff, der es dem Agent ermöglicht, sich mit dem NTLM-Hash eines Benutzers zu authentifizieren, ohne das Klartextpasswort zu benötigen
- `mimikatz`: Führt Mimikatz-Commands aus, um Credentials, Hashes und andere sensible Informationen aus dem Speicher oder der SAM-Datenbank zu extrahieren
- `rev2self`: Setzt den Token des Agents auf seinen Primary Token zurück und senkt dadurch die Privileges effektiv wieder auf das ursprüngliche Niveau
- `ppid`: Ändert den Parent-Prozess für Post-Exploitation-Jobs durch Angabe einer neuen Parent-Prozess-ID, wodurch eine bessere Kontrolle über den Ausführungskontext des Jobs ermöglicht wird
- `printspoofer`: Führt PrintSpoofer-Commands aus, um Sicherheitsmaßnahmen des Print Spoolers zu umgehen und dadurch Privilege Escalation oder Code Execution zu ermöglichen
- `dcsync`: Synchronisiert die Kerberos-Keys eines Benutzers mit dem lokalen Rechner und ermöglicht dadurch Offline-Passwort-Cracking oder weitere Angriffe
- `ticket_cache_add`: Fügt ein Kerberos-Ticket zur aktuellen Logon-Session oder zu einer angegebenen Session hinzu und ermöglicht dadurch die Wiederverwendung oder Impersonation des Tickets

### Process Execution

- `assembly_inject`: Ermöglicht die Injection eines .NET-Assembly-Loaders in einen Remote-Prozess
- `blockdlls`: Blockiert das Laden von nicht von Microsoft signierten DLLs in Post-Exploitation-Jobs
- `execute_assembly`: Führt ein .NET-Assembly im Kontext des Agents aus
- `execute_coff`: Führt eine COFF-Datei im Speicher aus und ermöglicht dadurch die In-Memory-Ausführung kompilierten Codes
- `execute_pe`: Führt ein unmanaged Executable (PE) aus
- `keylog_inject`: Injiziert einen Keylogger in einen anderen Prozess und streamt die Keystrokes zurück in Mythic's Keylog-Ansicht
- `screenshot` / `screenshot_inject`: Erfasst den aktuellen Desktop direkt oder
durch Injection eines Screenshot-Assemblies in einen Zielprozess bzw. eine Zielsession
- `get_injection_techniques`: Zeigt verfügbare Injection-Techniken und die aktuell ausgewählte an
- `inline_assembly`: Führt ein .NET-Assembly in einer verworfenen AppDomain aus und ermöglicht dadurch die temporäre Ausführung von Code, ohne den Hauptprozess des Agents zu beeinflussen
- `register_assembly`: Registriert ein .NET-Assembly zur späteren Ausführung
- `register_file`: Registriert eine Datei im Agent-Cache für späteres `execute_*`- oder PowerShell-Tasking
- `run`: Führt eine Binary auf dem Zielsystem aus und verwendet den System-PATH, um das Executable zu finden
- `set_injection_technique`: Ändert das von Post-Exploitation-Jobs verwendete Injection-Primitive
- `shinject`: Injiziert Shellcode in einen Remote-Prozess und ermöglicht dadurch die In-Memory-Ausführung beliebigen Codes
- `inject`: Injiziert Agent-Shellcode in einen Remote-Prozess und ermöglicht dadurch die In-Memory-Ausführung des Agent-Codes
- `spawn`: Startet eine neue Agent-Session im angegebenen Executable und ermöglicht dadurch die Ausführung von Shellcode in einem neuen Prozess
- `spawnto_x64` und `spawnto_x86`: Ändern die standardmäßig von Post-Exploitation-Jobs verwendete Binary in einen angegebenen Pfad, anstatt `rundll32.exe` ohne Parameter zu verwenden, was sehr auffällig ist.

### Mythic Forge

Dies ermöglicht das **Laden von COFF/BOF**-Dateien aus der Mythic Forge, einem Repository vorkompilierter Payloads und Tools, die auf dem Zielsystem ausgeführt werden können. Mit allen ladbaren Commands wird es möglich sein, häufige Aktionen auszuführen, indem diese im aktuellen Agent-Prozess als BOFs ausgeführt werden (üblicherweise mit besserem OPSEC als beim Starten eines separaten Prozesses).

Beginne die Installation mit:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Dann verwenden Sie `forge_collections`, um die COFF/BOF-Module aus der Mythic Forge anzuzeigen und sie zur Auswahl zu laden, damit sie zur Ausführung in den Speicher des agents geladen werden können. Standardmäßig werden in Apollo die folgenden 2 collections hinzugefügt:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nachdem ein Modul geladen wurde, erscheint es in der Liste als ein weiterer Befehl wie `forge_bof_sa-whoami` oder `forge_bof_sa-netuser`.

Denken Sie bei BOFs daran, dass Forge nicht einfach eine flache Argumentzeichenfolge an Apollo übergibt. Stattdessen werden BOF-Parameter in das typisierte Array-Format von Mythic übertragen und anschließend an Apollos `execute_coff`-Ablauf weitergeleitet. Wenn sich ein über Forge geladenes BOF ungewöhnlich verhält, überprüfen Sie die erwarteten BOF-Argumenttypen bzw. den Entry-Point und nicht nur die eingegebene Befehlszeile. Beachten Sie außerdem, dass Apollos neuerer BOF loader die Argumentverarbeitung im Vergleich zu deutlich älteren Builds aus der 2.3.1-Ära geändert hat. Daher können veraltete BOFs oder alte collections allein deshalb fehlschlagen, weil sich die Erwartungen an das Marshaling geändert haben.

### PowerShell & scripting execution

- `powershell_import`: Importiert ein neues PowerShell-Script (.ps1) in den agent cache zur späteren Ausführung
- `powershell`: Führt einen PowerShell-Befehl im Kontext des agents aus und ermöglicht fortgeschrittenes scripting und automation
- `powerpick`: Injiziert eine PowerShell-loader assembly in einen sacrificial process und führt einen PowerShell-Befehl aus (ohne PowerShell-Logging).
- `psinject`: Führt PowerShell in einem angegebenen process aus und ermöglicht die gezielte Ausführung von Scripts im Kontext eines anderen processes
- `shell`: Führt einen shell-Befehl im Kontext des agents aus, ähnlich wie bei der Ausführung eines Befehls in cmd.exe

### Lateral Movement

- `jump_psexec`: Verwendet die PsExec-Technik, um sich lateral zu einem neuen Host zu bewegen, indem zunächst die ausführbare Apollo-agent-Datei (apollo.exe) kopiert und ausgeführt wird.
- `jump_wmi`: Verwendet die WMI-Technik, um sich lateral zu einem neuen Host zu bewegen, indem zunächst die ausführbare Apollo-agent-Datei (apollo.exe) kopiert und ausgeführt wird.
- `link` und `unlink`: Erstellen und beenden P2P-Links (beispielsweise über SMB/TCP) zwischen callbacks.
- `wmiexecute`: Führt einen Befehl auf dem lokalen oder einem angegebenen remote system über WMI aus, optional mit Credentials zur Impersonation.
- `net_dclist`: Ruft eine Liste der Domain Controller für die angegebene Domain ab, was bei der Identifizierung potenzieller Ziele für Lateral Movement hilfreich ist.
- `net_localgroup`: Listet die lokalen Gruppen auf dem angegebenen Computer auf. Wenn kein Computer angegeben ist, wird standardmäßig localhost verwendet.
- `net_localgroup_member`: Ruft die Mitgliedschaft einer lokalen Gruppe für eine angegebene Gruppe auf dem lokalen oder remote computer ab und ermöglicht so die Enumeration von Benutzern in bestimmten Gruppen.
- `net_shares`: Listet die remote shares und deren Zugänglichkeit auf dem angegebenen Computer auf, was bei der Identifizierung potenzieller Ziele für Lateral Movement hilfreich ist.
- `socks`: Aktiviert einen SOCKS-5-kompatiblen Proxy im Zielnetzwerk und ermöglicht das Tunneling von Traffic über den kompromittierten Host. Kompatibel mit Tools wie proxychains.
- `rpfwd`: Beginnt, auf einem angegebenen Port auf dem Zielhost zu lauschen, und leitet Traffic über Mythic an eine remote IP-Adresse und einen remote Port weiter, wodurch der remote Zugriff auf Services im Zielnetzwerk ermöglicht wird.
- `listpipes`: Listet alle named pipes auf dem lokalen System auf, was für Lateral Movement oder Privilege Escalation durch die Interaktion mit IPC-Mechanismen hilfreich sein kann.

Informationen zu den darunterliegenden WMI-Ausführungsprimitiven, die von `jump_wmi` oder `wmiexecute` verwendet werden, finden Sie unter [WmiExec](lateral-movement/wmiexec.md). Informationen zu umfassenderen Pivoting-Mustern finden Sie unter [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Zeigt detaillierte Informationen zu bestimmten Befehlen oder allgemeine Informationen zu allen im agent verfügbaren Befehlen an.
- `clear`: Markiert Tasks als „cleared“, sodass sie nicht von agents abgeholt werden können. Sie können `all` angeben, um alle Tasks zu löschen, oder `task Num`, um einen bestimmten Task zu löschen.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon ist ein Golang-agent, der in **Linux- und macOS**-Executables kompiliert wird.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Aktuelle Build-/Profilhinweise

- Aktuelle Poseidon-Builds zielen auf Linux und macOS auf `x86_64` und `arm64` ab.
- Zu den unterstützten Ausgabeformaten gehören native Executables sowie Shared-Library-ähnliche Ausgaben wie `dylib` und `so`.
- Poseidon unterstützt `http`, `websocket`, `tcp` und `dynamichttp`, und die aktuellen Builder bieten Multi-Egress-Einstellungen wie `egress_order` und Failover-Schwellenwerte.
- Poseidons aktuelle Capability-Metadaten weisen außerdem Browser-Skripte, File-/Process-Browser-Integration, interaktives Tasking, Keylogging, Screenshots, Push C2, SOCKS, rpfwd und P2P aus. Dadurch kann Poseidon als echter Linux-/macOS-Pivot-Knoten statt nur als einfache Remote-Shell eingesetzt werden.
- Build-Time-Optionen wie `proxy_bypass` und `garble` sind eine Prüfung wert, wenn entweder ein saubereres Netzwerkverhalten oder zusätzliche Go-Binary-Obfuscation benötigt wird.
- `pty` ist einer der nützlichsten neueren Quality-of-Life-Befehle für Linux-/macOS-
Operationen, da er ein interaktives PTY öffnet und einen Mythic-seitigen
Port für eine umfassendere Terminal-Interaktion bereitstellen kann, ohne auf
den älteren `sleep 0`- plus SOCKS-Workaround zurückgreifen zu müssen.
- Poseidons aktuelle Dokumentation ist besonders für macOS-lastiges
Tradecraft interessant: `jxa` führt JavaScript for Automation im Speicher aus,
`screencapture` erfasst den Desktop des angemeldeten Benutzers,
`clipboard_monitor` streamt Änderungen am Pasteboard, `execute_library` lädt
eine lokale dylib und ruft eine Funktion daraus auf, und `libinject` zwingt
einen entfernten Prozess, eine auf der Festplatte befindliche dylib zu laden.
- Bei länger laufenden Jobs sollte beachtet werden, dass Poseidon
Post-Exploitation-Arbeiten in Goroutines/Threads ausführt, die kooperativ
statt sofort hart beendbar sind. Die Dokumentation weist außerdem ausdrücklich
darauf hin, dass derzeit keine integrierte Agent-Obfuscation vorhanden ist.
Daher ist Tradecraft auf Build-/Profilebene wichtiger als bei stark
obfuskierten kommerziellen Implants.

Für macOS-spezifisches Tradecraft rund um Mythic-gestützte Operationen,
JAMF-Abuse oder MDM-as-C2-Ideen siehe [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Bei Verwendung unter Linux oder macOS bietet es einige interessante Befehle:

### Häufige Aktionen

- `cat`: Den Inhalt einer Datei ausgeben
- `cd`: Das aktuelle Arbeitsverzeichnis ändern
- `chmod`: Die Berechtigungen einer Datei ändern
- `config`: Die aktuelle Konfiguration und Host-Informationen anzeigen
- `cp`: Eine Datei von einem Ort an einen anderen kopieren
- `curl`: Eine einzelne Webanfrage mit optionalen Headern und Methode ausführen
- `upload`: Eine Datei auf das Ziel hochladen
- `download`: Eine Datei vom Zielsystem auf den lokalen Rechner herunterladen
- Und vieles mehr

### Nach vertraulichen Informationen suchen

- `triagedirectory`: Interessante Dateien innerhalb eines Verzeichnisses auf einem Host finden, etwa vertrauliche Dateien oder Credentials.
- `getenv`: Alle aktuellen Umgebungsvariablen abrufen.

### macOS-spezifisches Tradecraft

- `jxa`: JavaScript for Automation über `OSAScript` im Speicher ausführen. Dies
ist für natives macOS-Post-Exploitation nützlich, ohne separate Skriptdateien
abzulegen.
- `clipboard_monitor`: Das Pasteboard abfragen und Änderungen an Mythic melden.
Dies ist praktisch für Workflows zum Diebstahl von Credentials/Tokens, die auf
Copy/Paste beruhen.
- `screencapture`: Den Desktop des Benutzers unter macOS erfassen.
- `execute_library`: Eine dylib von der Festplatte laden und eine bestimmte exportierte Funktion aufrufen.
- `libinject`: Einen Shellcode-Stub injizieren, der einen anderen macOS-Prozess zwingt, eine dylib von der Festplatte zu laden.
- `persist_launchd`: Persistence über einen LaunchAgent / LaunchDaemon direkt vom Agent erstellen.

### Seitlich bewegen

- `ssh`: Über SSH mit den angegebenen Credentials eine Verbindung zu einem Host herstellen und ein PTY öffnen, ohne ssh zu starten.
- `sshauth`: Über SSH mit den angegebenen Credentials eine Verbindung zu den angegebenen Hosts herstellen. Kann auch verwendet werden, um einen bestimmten Befehl auf den entfernten Hosts über SSH auszuführen oder Dateien per SCP zu übertragen.
- `link_tcp`: Eine Verbindung zu einem anderen Agent über TCP herstellen und dadurch direkte Kommunikation zwischen Agents ermöglichen.
- `link_webshell`: Über das Webshell-P2P-Profil eine Verbindung zu einem Agent herstellen und dadurch Remote-Zugriff auf dessen Weboberfläche ermöglichen.
- `rpfwd`: Ein Reverse Port Forward starten oder stoppen und dadurch Remote-Zugriff auf Services im Zielnetzwerk ermöglichen.
- `socks`: Einen SOCKS5-Proxy im Zielnetzwerk starten oder stoppen und dadurch das Tunneln von Traffic über den kompromittierten Host ermöglichen. Kompatibel mit Tools wie proxychains.
- `portscan`: Hosts auf offene Ports scannen, um potenzielle Ziele für laterale Bewegungen oder weitere Angriffe zu identifizieren.

### Prozessausführung

- `shell`: Einen einzelnen Shell-Befehl über /bin/sh ausführen und dadurch Befehle direkt auf dem Zielsystem ausführen.
- `run`: Einen Befehl von der Festplatte mit Argumenten ausführen und dadurch Binaries oder Skripte auf dem Zielsystem ausführen.
- `pty`: Ein interaktives PTY öffnen und dadurch direkte Interaktion mit der Shell auf dem Zielsystem ermöglichen.






## Referenzen

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transforming Red Team Ops with Mythic’s Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
