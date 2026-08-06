# Mythic

{{#include ../banners/hacktricks-training.md}}

## Was ist Mythic?

Mythic ist ein open-source, modulares, kollaboratives Command-and-Control-(C2)-Framework für red teaming. Es ermöglicht Operatoren, Agents (Payloads) auf verschiedenen Betriebssystemen zu verwalten und bereitzustellen, einschließlich Windows, Linux und macOS. Mythic stellt eine Browser-UI für Multi-Operator-Tasking, Dateiverarbeitung, SOCKS/rpfwd-Management und Payload-Generierung bereit.

Im Gegensatz zu monolithischen Frameworks enthält das Mythic-Repository selbst keine Payload-Typen oder C2-Profile. Agents, Wrapper und C2-Profile werden typischerweise als externe Komponenten installiert und können unabhängig vom Mythic-Core aktualisiert werden.

### Installation

Um Mythic zu installieren, folge den Anweisungen im offiziellen **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Ein übliches Bootstrap aus dem Mythic-Verzeichnis ist:
```bash
sudo make
sudo ./mythic-cli start
```
Wenn Mythic bereits läuft, kannst du normalerweise mit `./mythic-cli install github ...` einen neuen Agenten oder ein neues Profil hinzufügen und anschließend entweder Mythic neu starten oder die neue Komponente direkt starten.

### Agents

Mythic unterstützt mehrere Agents. Dabei handelt es sich um die **Payloads, die Aufgaben auf den kompromittierten Systemen ausführen**. Jeder Agent kann an spezifische Anforderungen angepasst werden und auf unterschiedlichen Betriebssystemen laufen.

Standardmäßig sind in Mythic keine Agents installiert. Die Agents der Open-Source-Community befinden sich unter [**https://github.com/MythicAgents**](https://github.com/MythicAgents), und die [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) ist hilfreich, um schnell unterstützte Betriebssysteme, Payload-Formate, Wrapper und C2-Profile zu überprüfen.<sup>[[1]](#references)</sup>

Um einen Agenten aus dieser Organisation zu installieren, kannst du Folgendes ausführen:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Die Form `sudo -E` ist nützlich, wenn du die Installation aus einer Umgebung ohne Root-Rechte durchführst. Mit dem vorherigen Befehl kannst du neue Agents hinzufügen, auch wenn Mythic bereits läuft.

### C2 Profiles

C2 profiles in Mythic legen fest, **wie Agents mit dem Mythic-Server kommunizieren**. Sie definieren das Kommunikationsprotokoll, die Verschlüsselungsmethoden und weitere Einstellungen. Du kannst C2 profiles über die Mythic-Weboberfläche erstellen und verwalten.

Standardmäßig wird Mythic ohne Profiles installiert. Es ist jedoch möglich, einige Profiles aus dem Repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) mit folgendem Befehl herunterzuladen:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Aktuelle für Operator relevante Profile, die Sie im Blick behalten sollten:

- [`http`](https://github.com/MythicC2Profiles/http): grundlegender asynchroner GET/POST-Traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): flexiblerer HTTP-Traffic mit mehreren Callback-Domains, Fail-over-/Round-robin-Rotation, benutzerdefinierten Headern/Query-Parametern und Message-Transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`), die in Cookies, Headern, Query-Parametern oder im Body platziert werden.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON-/TOML-gesteuerte HTTP-Message-Gestaltung, wenn das statische `http`-Profil zu leicht erkennbar ist.

### Aktuelle Plattform-Hinweise

- Viele öffentliche Agents und Profile werden inzwischen mit vorgefertigten Remote-Container-Images installiert.
Wenn Sie eine Komponente forken oder lokal patchen und Mythic weiterhin das alte
Verhalten verwendet, prüfen Sie die generierten `.env`-Einträge für
`*_REMOTE_IMAGE`, `*_USE_BUILD_CONTEXT` und `*_USE_VOLUME`; das Aktivieren von
`*_USE_BUILD_CONTEXT="true"` sorgt normalerweise dafür, dass Mythic aus Ihrem
lokalen Docker-Kontext neu baut, statt stillschweigend das Remote-Image
wiederzuverwenden.
- Browser-Scripts gehören zu den wertvollsten Quality-of-Life-Features von Mythic
für Operatoren: Sie können rohe Command-Ausgaben in Tabellen, Screenshot-Viewer,
Download-Links, Search-Links und Buttons umwandeln, die direkt aus der UI
weiterführendes Tasking auslösen. Aktuelle Mythic-Builds ermöglichen es jedem
Operator, eigene Scripts zu verwalten, sie global oder pro Task zu aktivieren
oder zu deaktivieren, und erzielen die besten Ergebnisse, wenn Agents
strukturiertes JSON statt Plaintext zurückgeben. Das ist besonders nützlich für
sich wiederholende `ls`-, `ps`-, Triage- und File-Browser-Workflows.<sup>[[4]](#references)[[6]](#references)</sup>
- Neuere Mythic-Builds unterstützen außerdem interaktives Tasking und Push-C2-Muster,
wodurch der Bedarf an `sleep 0`-Polling während PTY-/SOCKS-/rpfwd-lastiger
Operationen sinkt. Wenn ein Agent/Profil dies unterstützt, verursacht das
normalerweise weniger Overhead als den Server ständig mit Check-ins zu
belasten, nur um einen interaktiven Channel nutzbar zu halten.<sup>[[3]](#references)</sup>
- Aktuelle Mythic-Builder aus der 3.4-Ära sind kontextbewusster, als ältere Write-ups
vermuten lassen: Build-Parameter können jetzt abhängig vom ausgewählten OS
oder anderen Build-Optionen gruppiert oder ausgeblendet werden, Payload-Typen
können angeben, ob sie mehrere C2-Profile oder mehrere Instanzen desselben C2
in einem Build unterstützen, und C2-Parameterabweichungen ermöglichen es einem
Agent, Felder auszublenden, die er tatsächlich nicht implementiert. Das ist
relevant, wenn Sie zwischen `http`, `httpx`, `smb`,
`tcp` und `websocket` wechseln, da die sichere/gültige Build-Oberfläche nicht
mehr aus einem flachen, statischen Formular besteht.<sup>[[5]](#references)</sup>
- Wenn Sie ein benutzerdefiniertes Agent-/Profil-Paar erstellen und nicht möchten,
dass Mythics JSON-Message-Format oder die standardmäßige Kryptografie über das
Wire übertragen wird, verwenden Sie einen
`translation_container`: Mythic entfernt die UUID, übergibt den verschlüsselten
Blob und das Schlüsselmaterial über gRPC an den Translator und erwartet
anschließend agent-native Bytes. Dies ist der saubere Weg, um binäre Protokolle,
benutzerdefiniertes Framing oder agentenseitige Verschlüsselung zu unterstützen,
ohne den gesamten Server neu zu schreiben.
- Denken Sie daran, dass verknüpfte/P2P-Callbacks nicht nur Tasking
weiterleiten. Mythics `get_tasking`-Ablauf kann auch Responses sowie `delegates`,
`socks`, `rpfwd`- und `interactive`-Daten übertragen. In der Praxis kann ein
Egress-Callback innere Callbacks und Pivot-Channels in derselben Polling-Schleife
bedienen; wenn die Child-Agents ihre eigenen regelmäßigen Check-ins durchführen,
verhindert `get_delegate_tasks=false`, dass der Parent versehentlich die
wartenden Jobs des inneren Callbacks abruft.

### Wrapper-Payloads

Wrapper-Payloads ermöglichen es Ihnen, dieselbe Agent-Logik beizubehalten und
gleichzeitig die Darstellung auf dem Datenträger zu ändern, die ausgeliefert
oder gespeichert wird.

- `service_wrapper`: wandelt eine andere Payload in eine Windows-Service-Executable
um. Das ist nützlich, wenn der Ausführungspfad eine gültige Service-Binary
erfordert.
- `scarecrow_wrapper`: verpackt kompatiblen Shellcode mit dem ScareCrow-Loader,
um Loader-basierte Ausgaben wie EXE/DLL/CPL zu erzeugen.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ist ein in C# geschriebener Windows-Agent, der das 4.0 .NET Framework
verwendet und für den Einsatz in SpecterOps-Trainingsangeboten entwickelt wurde.<sup>[[2]](#references)</sup>

Installieren Sie ihn mit:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Aktuelle Build-/Profil-Hinweise

- Apollo kann derzeit `WinExe`-, `Shellcode`-, `Service`- und `Source`-Payloads erzeugen.
- Die häufig verwendeten Apollo-Profile sind `http`, `httpx`, `smb`, `tcp` und `websocket`.
- `httpx` ist normalerweise die flexiblere Option, wenn du Domain-Rotation, Proxy-Support, benutzerdefinierte Nachrichtenplatzierung und Message-Transforms benötigst, anstatt des älteren statischen `http`-Profils.
- Apollo ist einer der funktionsreicheren Community-Agents und bietet derzeit Mythic-seitige Integrationen wie Browser-Scripts, Datei-/Prozess-Browser-Ansichten, Screenshots, Keylogging, SOCKS, rpfwd, Push C2 und P2P-Routing.
- Apollo unterstützt Wrapper-Payloads wie `service_wrapper` und `scarecrow_wrapper`.
- Apollo unterstützt dynamisches Command-Loading. Dadurch kann der initiale Payload schlank gehalten und zusätzliche Commands oder Forge-Module später geladen werden, anstatt jede Post-Ex-Funktionalität in den ersten Build zu kompilieren.
- Bei der Erzeugung von Shellcode-Output bietet der aktuelle Apollo-Builder außerdem Donut-Formatoptionen (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) und Donut-Bypass-Verhalten (`None`, `Abort on fail`, `Continue on fail`). Dies ist nützlich, wenn das endgültige Ziel darin besteht, den Shellcode mit `service_wrapper`, `scarecrow_wrapper` oder einem benutzerdefinierten Loader erneut zu verpacken.
- `register_file` und `register_assembly` sind die Staging-Primitives für `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` und `powerpick`. In aktuellen Apollo-Builds werden diese gestagten Artefakte clientseitig als durch DPAPI geschützte AES256-Blobs zwischengespeichert.
- Die Ergebnisse von `ls` und `ps` integrieren sich besonders gut in Mythics Browser-Scripts sowie den Datei-/Prozess-Browser, wodurch die Operator-Triage in kollaborativen Operationen deutlich schneller wird.
- Apollo-Fork-and-Run-Jobs übernehmen ihre Einstellungen für Sacrificial Processes von
`spawnto_x86` / `spawnto_x64`, übernehmen die Parent-Auswahl von `ppid` und
verwenden anschließend die aktuell ausgewählte Injection-Primitive. In der Praxis
bedeutet dies, dass dein OPSEC-Tuning für ein Command häufig gleichzeitig
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` und
`spawn` beeinflusst.
- Zu den aktuell dokumentierten Apollo-Injection-Backends gehören `CreateRemoteThread`,
`QueueUserAPC` (Early-Bird-Stil) und `NtCreateThreadEx` über Syscalls. Verwende
`get_injection_techniques` vor geräuschintensiver Post-Exploitation und
`set_injection_technique`, wenn du von einer Primitive wechseln musst, die mit dem
Target oder dem auszuführenden Command kollidiert.
- `blockdlls` betrifft nur Sacrificial Processes, die für Post-Exploitation-Jobs
erstellt werden. In Kombination mit einem weniger verdächtigen `spawnto_x64`-Target
als dem standardmäßigen, unveränderten `rundll32.exe` ist dies eine der
einfachsten Apollo-seitigen Änderungen, die vor Assembly-/PowerShell-lastigem
Tasking vorgenommen werden können.

Dieser Agent verfügt über zahlreiche Commands und ähnelt dadurch stark Cobalt Strikes Beacon, bietet jedoch einige Extras. Dazu gehören:

### Häufige Aktionen

- `cat`: Gibt den Inhalt einer Datei aus
- `cd`: Wechselt das aktuelle Arbeitsverzeichnis
- `cp`: Kopiert eine Datei von einem Ort an einen anderen
- `ls`: Listet Dateien und Verzeichnisse im aktuellen Verzeichnis oder im angegebenen Pfad auf
- `ifconfig`: Ruft Informationen zu Netzwerkadaptern und -schnittstellen ab
- `netstat`: Ruft Informationen zu TCP- und UDP-Verbindungen ab
- `pwd`: Gibt das aktuelle Arbeitsverzeichnis aus
- `ps`: Listet laufende Prozesse auf dem Zielsystem auf (mit zusätzlichen Informationen)
- `jobs`: Listet alle laufenden Jobs auf, die mit lang laufendem Tasking verbunden sind
- `download`: Lädt eine Datei vom Zielsystem auf den lokalen Rechner herunter
- `upload`: Lädt eine Datei vom lokalen Rechner auf das Zielsystem hoch
- `reg_query`: Fragt Registry-Keys und -Werte auf dem Zielsystem ab
- `reg_write_value`: Schreibt einen neuen Wert in einen angegebenen Registry-Key
- `sleep`: Ändert das Sleep-Intervall des Agents, das festlegt, wie oft er sich beim Mythic-Server meldet
- Und viele weitere; verwende `help`, um die vollständige Liste der verfügbaren Commands anzuzeigen.

### Privilege Escalation

- `getprivs`: Aktiviert so viele Privileges wie möglich im Token des aktuellen Threads
- `getsystem`: Öffnet ein Handle auf winlogon und dupliziert den Token, wodurch Privileges effektiv auf SYSTEM-Ebene eskaliert werden
- `make_token`: Erstellt eine neue Logon-Session und wendet sie auf den Agent an, wodurch die Impersonation eines anderen Users ermöglicht wird
- `steal_token`: Stiehlt einen Primary Token aus einem anderen Prozess, wodurch der Agent den User dieses Prozesses impersonieren kann
- `pth`: Pass-the-Hash-Angriff, der dem Agent ermöglicht, sich mit dem NTLM-Hash eines Users zu authentifizieren, ohne das Klartextpasswort zu benötigen
- `mimikatz`: Führt Mimikatz-Commands aus, um Credentials, Hashes und andere vertrauliche Informationen aus dem Speicher oder der SAM-Datenbank zu extrahieren
- `rev2self`: Setzt den Token des Agents auf seinen Primary Token zurück und verwirft dadurch die Privileges bis zur ursprünglichen Ebene
- `ppid`: Ändert den Parent Process für Post-Exploitation-Jobs durch Angabe einer neuen Parent Process ID, wodurch eine bessere Kontrolle über den Ausführungskontext des Jobs ermöglicht wird
- `printspoofer`: Führt PrintSpoofer-Commands aus, um Sicherheitsmaßnahmen des Print Spoolers zu umgehen und dadurch Privilege Escalation oder Code-Ausführung zu ermöglichen
- `dcsync`: Synchronisiert die Kerberos-Keys eines Users auf den lokalen Rechner und ermöglicht dadurch Offline-Passwort-Cracking oder weitere Angriffe
- `ticket_cache_add`: Fügt der aktuellen Logon-Session oder einer angegebenen Session ein Kerberos-Ticket hinzu und ermöglicht dadurch die Wiederverwendung oder Impersonation des Tickets

### Prozessausführung

- `assembly_inject`: Ermöglicht die Injection eines .NET-Assembly-Loaders in einen Remote-Prozess
- `blockdlls`: Verhindert das Laden von nicht von Microsoft signierten DLLs in Post-Exploitation-Jobs
- `execute_assembly`: Führt ein .NET-Assembly im Kontext des Agents aus
- `execute_coff`: Führt eine COFF-Datei im Speicher aus und ermöglicht dadurch die In-Memory-Ausführung kompilierten Codes
- `execute_pe`: Führt ein unmanaged Executable (PE) aus
- `keylog_inject`: Injiziert einen Keylogger in einen anderen Prozess und streamt die Tastatureingaben zurück in Mythics Keylog-Ansicht
- `screenshot` / `screenshot_inject`: Erfasst den aktuellen Desktop direkt oder
durch Injizieren eines Screenshot-Assemblies in einen Zielprozess bzw. eine Zielsession
- `get_injection_techniques`: Zeigt die verfügbaren Injection-Techniken und die aktuell ausgewählte an
- `inline_assembly`: Führt ein .NET-Assembly in einer wegwerfbaren AppDomain aus und ermöglicht dadurch die temporäre Ausführung von Code, ohne den Hauptprozess des Agents zu beeinflussen
- `register_assembly`: Registriert ein .NET-Assembly zur späteren Ausführung
- `register_file`: Registriert eine Datei im Agent-Cache für späteres `execute_*`- oder PowerShell-Tasking
- `run`: Führt ein Binary auf dem Zielsystem aus und verwendet den System-PATH, um das Executable zu finden
- `set_injection_technique`: Ändert die von Post-Exploitation-Jobs verwendete Injection-Primitive
- `shinject`: Injiziert Shellcode in einen Remote-Prozess und ermöglicht dadurch die In-Memory-Ausführung beliebigen Codes
- `inject`: Injiziert Agent-Shellcode in einen Remote-Prozess und ermöglicht dadurch die In-Memory-Ausführung des Agent-Codes
- `spawn`: Startet eine neue Agent-Session im angegebenen Executable und ermöglicht dadurch die Ausführung von Shellcode in einem neuen Prozess
- `spawnto_x64` und `spawnto_x86`: Ändern das standardmäßige Binary für Post-Exploitation-Jobs in einen angegebenen Pfad, anstatt `rundll32.exe` ohne Parameter zu verwenden, was sehr geräuschintensiv ist.

### Mythic Forge

Damit können **COFF/BOF**-Dateien aus der Mythic Forge geladen werden, einem Repository vorkompilierter Payloads und Tools, die auf dem Zielsystem ausgeführt werden können. Mit allen ladbaren Commands lassen sich häufige Aktionen ausführen, indem sie im aktuellen Agent-Prozess als BOFs ausgeführt werden (normalerweise mit besserem OPSEC als beim Starten eines separaten Prozesses).

Beginne die Installation mit:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Dann verwenden Sie `forge_collections`, um die COFF/BOF-Module aus der Mythic Forge anzuzeigen und sie auswählen und zur Ausführung in den Speicher des Agents laden zu können. Standardmäßig werden in Apollo die folgenden 2 Collections hinzugefügt:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nachdem ein Modul geladen wurde, erscheint es in der Liste als weiterer Befehl wie `forge_bof_sa-whoami` oder `forge_bof_sa-netuser`.

Bei BOFs sollten Sie beachten, dass Forge nicht einfach eine flache Argumentzeichenkette an Apollo übergibt. Stattdessen werden BOF-Parameter in Mythics typisierten Array-Format abgebildet und anschließend an den `execute_coff`-Ablauf von Apollo weitergeleitet. Wenn sich ein über Forge geladener BOF ungewöhnlich verhält, überprüfen Sie die erwarteten BOF-Argumenttypen bzw. den Entrypoint und nicht nur die eingegebene Befehlszeile. Beachten Sie außerdem, dass Apollos neuerer BOF-Loader die Argumentverarbeitung im Vergleich zu deutlich älteren Builds aus der 2.3.1-Ära geändert hat. Daher können veraltete BOFs oder alte Collections allein deshalb fehlschlagen, weil sich die Erwartungen an das Marshaling geändert haben.

### PowerShell- & Scripting-Ausführung

- `powershell_import`: Importiert ein neues PowerShell-Skript (.ps1) in den Agent-Cache zur späteren Ausführung
- `powershell`: Führt einen PowerShell-Befehl im Kontext des Agents aus und ermöglicht erweitertes Scripting und Automatisierung
- `powerpick`: Injiziert eine PowerShell-Loader-Assembly in einen opferbaren Prozess und führt einen PowerShell-Befehl aus (ohne PowerShell-Logging).
- `psinject`: Führt PowerShell in einem angegebenen Prozess aus und ermöglicht die gezielte Ausführung von Skripten im Kontext eines anderen Prozesses
- `shell`: Führt einen Shell-Befehl im Kontext des Agents aus, ähnlich wie die Ausführung eines Befehls in cmd.exe

### Lateral Movement

- `jump_psexec`: Verwendet die PsExec-Technik, um sich lateral zu einem neuen Host zu bewegen, indem zunächst die ausführbare Apollo-Agent-Datei (apollo.exe) kopiert und ausgeführt wird.
- `jump_wmi`: Verwendet die WMI-Technik, um sich lateral zu einem neuen Host zu bewegen, indem zunächst die ausführbare Apollo-Agent-Datei (apollo.exe) kopiert und ausgeführt wird.
- `link` und `unlink`: Erstellen und beenden P2P-Links (beispielsweise über SMB/TCP) zwischen Callbacks.
- `wmiexecute`: Führt einen Befehl auf dem lokalen oder einem angegebenen entfernten System über WMI aus, optional mit Zugangsdaten zur Identitätsübernahme.
- `net_dclist`: Ruft eine Liste der Domain Controller für die angegebene Domain ab, was bei der Identifizierung potenzieller Ziele für Lateral Movement hilfreich ist.
- `net_localgroup`: Listet lokale Gruppen auf dem angegebenen Computer auf. Wenn kein Computer angegeben ist, wird standardmäßig localhost verwendet.
- `net_localgroup_member`: Ruft die Mitgliedschaft einer lokalen Gruppe für eine angegebene Gruppe auf dem lokalen oder entfernten Computer ab und ermöglicht so die Enumeration von Benutzern in bestimmten Gruppen.
- `net_shares`: Listet entfernte Shares und deren Zugänglichkeit auf dem angegebenen Computer auf, was bei der Identifizierung potenzieller Ziele für Lateral Movement hilfreich ist.
- `socks`: Aktiviert einen SOCKS-5-konformen Proxy im Zielnetzwerk und ermöglicht das Tunneln von Datenverkehr über den kompromittierten Host. Kompatibel mit Tools wie proxychains.
- `rpfwd`: Beginnt mit dem Lauschen an einem angegebenen Port auf dem Zielhost und leitet Datenverkehr über Mythic an eine entfernte IP-Adresse und einen entfernten Port weiter, wodurch der Fernzugriff auf Dienste im Zielnetzwerk ermöglicht wird.
- `listpipes`: Listet alle Named Pipes auf dem lokalen System auf, was für Lateral Movement oder Privilege Escalation durch die Interaktion mit IPC-Mechanismen nützlich sein kann.

Informationen zu den grundlegenden WMI-Ausführungsprimitiven, die von `jump_wmi` oder `wmiexecute` verwendet werden, finden Sie unter [WmiExec](lateral-movement/wmiexec.md). Weitere Pivoting-Muster finden Sie unter [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Verschiedene Befehle
- `help`: Zeigt detaillierte Informationen zu bestimmten Befehlen oder allgemeine Informationen zu allen verfügbaren Befehlen im Agent an.
- `clear`: Markiert Tasks als „cleared“, sodass sie nicht von Agents übernommen werden können. Sie können `all` angeben, um alle Tasks zu löschen, oder `task Num`, um einen bestimmten Task zu löschen.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon ist ein Golang-Agent, der in **Linux- und macOS**-Executables kompiliert wird.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Aktuelle Build-/Profilhinweise

- Aktuelle Poseidon-Builds zielen auf Linux und macOS sowohl für `x86_64` als auch für `arm64`.
- Zu den unterstützten Ausgabeformaten gehören native Executables sowie Shared-Library-artige Ausgaben wie `dylib` und `so`.
- Poseidon unterstützt `http`, `websocket`, `tcp` und `dynamichttp`, und die aktuellen Builder stellen Multi-Egress-Einstellungen wie `egress_order` und Failover-Schwellenwerte bereit.
- Poseidons aktuelle Capability-Metadaten werben außerdem mit Browser-Skripten, Datei-/Prozess-Browser-Integration, interaktivem Tasking, Keylogging, Screenshots, Push C2, SOCKS, rpfwd und P2P. Dadurch kann Poseidon als echter Linux-/macOS-Pivot-Knoten statt nur als einfache Remote-Shell eingesetzt werden.
- Build-Time-Optionen wie `proxy_bypass` und `garble` sollten geprüft werden, wenn entweder ein saubereres Netzwerkverhalten oder zusätzliche Go-Binary-Obfuscation benötigt wird.
- `pty` ist einer der nützlichsten neueren Quality-of-Life-Befehle für Linux-/macOS-Operationen, da er ein interaktives PTY öffnet und einen Mythic-seitigen Port für umfassendere Terminal-Interaktion bereitstellen kann, ohne auf den älteren Workaround mit `sleep 0` + SOCKS zurückzugreifen.
- Poseidons aktuelle Dokumentation ist besonders für macOS-orientiertes Tradecraft interessant: `jxa` führt JavaScript for Automation per `OSAScript` im Speicher aus, `screencapture` erstellt einen Screenshot des angemeldeten Desktops, `clipboard_monitor` streamt Änderungen am Pasteboard, `execute_library` lädt eine lokale dylib und ruft eine Funktion daraus auf, und `libinject` zwingt einen Remote-Prozess dazu, eine auf der Festplatte befindliche dylib zu laden.
- Bei lang laufenden Jobs sollte beachtet werden, dass Poseidon Post-Exploitation-Arbeit in Goroutines/Threads ausführt, die kooperativ statt hart beendbar sind. Die Dokumentation weist außerdem ausdrücklich darauf hin, dass es derzeit keine integrierte Agent-Obfuscation gibt. Daher ist Tradecraft auf Build-/Profilebene wichtiger als bei stark obfuskierten kommerziellen Implants.

Für macOS-spezifisches Tradecraft rund um Mythic-gestützte Operationen, JAMF-Abuse oder MDM-as-C2-Ideen siehe [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Bei Verwendung unter Linux oder macOS bietet es einige interessante Befehle:

### Häufige Aktionen

- `cat`: Den Inhalt einer Datei ausgeben
- `cd`: Das aktuelle Arbeitsverzeichnis ändern
- `chmod`: Die Berechtigungen einer Datei ändern
- `config`: Aktuelle Konfiguration und Hostinformationen anzeigen
- `cp`: Eine Datei von einem Ort an einen anderen kopieren
- `curl`: Eine einzelne Webanforderung mit optionalen Headern und einer optionalen Methode ausführen
- `upload`: Eine Datei auf das Zielsystem hochladen
- `download`: Eine Datei vom Zielsystem auf den lokalen Rechner herunterladen
- Und viele weitere

### Suche nach sensiblen Informationen

- `triagedirectory`: Interessante Dateien innerhalb eines Verzeichnisses auf einem Host finden, etwa sensible Dateien oder Credentials.
- `getenv`: Alle aktuellen Umgebungsvariablen abrufen.

### macOS-spezifisches Tradecraft

- `jxa`: JavaScript for Automation per `OSAScript` im Speicher ausführen. Dies ist für natives macOS-Post-Exploitation-Tradecraft nützlich, ohne separate Skriptdateien abzulegen.
- `clipboard_monitor`: Das Pasteboard abfragen und Änderungen an Mythic melden. Dies ist praktisch für Credential-/Token-Diebstahl-Workflows, die auf Copy/Paste basieren.
- `screencapture`: Den Desktop des Benutzers unter macOS erfassen.
- `execute_library`: Eine dylib von der Festplatte laden und eine bestimmte exportierte Funktion aufrufen.
- `libinject`: Einen Shellcode-Stub injizieren, der einen anderen macOS-Prozess zwingt, eine dylib von der Festplatte zu laden.
- `persist_launchd`: Persistence über LaunchAgent / LaunchDaemon direkt aus dem Agent erstellen.

### Laterale Bewegung

- `ssh`: Per SSH mit den angegebenen Credentials eine Verbindung zu einem Host herstellen und ein PTY öffnen, ohne ssh zu starten.
- `sshauth`: Mit den angegebenen Credentials per SSH eine Verbindung zu den angegebenen Hosts herstellen. Damit kann auch ein bestimmter Befehl auf den Remote-Hosts per SSH ausgeführt oder SCP zum Übertragen von Dateien verwendet werden.
- `link_tcp`: Eine Verbindung zu einem anderen Agenten über TCP herstellen und dadurch direkte Kommunikation zwischen Agenten ermöglichen.
- `link_webshell`: Über das Webshell-P2P-Profil eine Verbindung zu einem Agenten herstellen und dadurch Remote-Zugriff auf dessen Weboberfläche ermöglichen.
- `rpfwd`: Einen Reverse Port Forward starten oder stoppen und dadurch Remote-Zugriff auf Services im Zielnetzwerk ermöglichen.
- `socks`: Einen SOCKS5-Proxy im Zielnetzwerk starten oder stoppen und dadurch das Tunneln von Traffic über den kompromittierten Host ermöglichen. Kompatibel mit Tools wie proxychains.
- `portscan`: Hosts auf offene Ports scannen, um potenzielle Ziele für laterale Bewegung oder weitere Angriffe zu identifizieren.

### Prozessausführung

- `shell`: Einen einzelnen Shell-Befehl über /bin/sh ausführen und dadurch Befehle direkt auf dem Zielsystem ausführen.
- `run`: Einen Befehl von der Festplatte mit Argumenten ausführen und dadurch Binaries oder Skripte auf dem Zielsystem ausführen.
- `pty`: Ein interaktives PTY öffnen und dadurch direkte Interaktion mit der Shell auf dem Zielsystem ermöglichen.

## Referenzen

- [1] [Mythic-Community-Agent-Feature-Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo-README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 – Highlights: Interaktives Tasking, Push C2 und dynamischer Datei-Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser-Skripte – Mythic-Dokumentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic-Updates von 3.3 auf 3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Red-Team-Operationen mit Mythics verborgenen Schätzen transformieren: Browser-Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
