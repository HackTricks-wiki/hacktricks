# Mythic

{{#include ../banners/hacktricks-training.md}}

## Was ist Mythic?

Mythic ist ein Open-Source-, modulares, kollaboratives Command-and-Control-(C2)-Framework, das für Red Teaming entwickelt wurde. Es ermöglicht Operatoren, Agenten (Payloads) über verschiedene Betriebssysteme hinweg zu verwalten und bereitzustellen, einschließlich Windows, Linux und macOS. Mythic bietet eine Browser-UI für Multi-Operator-Tasking, Datei-Handling, SOCKS/rpfwd-Management und Payload-Generierung.

Im Gegensatz zu monolithischen Frameworks liefert das Mythic-Repository selbst **keine** Payload-Typen oder C2-Profile aus. Agents, Wrappers und C2-Profile werden typischerweise als externe Komponenten installiert und können unabhängig vom Mythic-Core aktualisiert werden.

### Installation

Um Mythic zu installieren, befolge die Anweisungen im offiziellen **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Ein gängiger Bootstrap aus dem Mythic-Verzeichnis ist:
```bash
sudo make
sudo ./mythic-cli start
```
Wenn Mythic bereits läuft, kannst du normalerweise einen neuen Agent oder ein neues Profil mit `./mythic-cli install github ...` hinzufügen und dann entweder Mythic neu starten oder einfach die neue Komponente direkt starten.

### Agents

Mythic unterstützt mehrere Agents, die die **payloads sind, die Aufgaben auf den kompromittierten Systemen ausführen**. Jeder Agent kann an spezifische Anforderungen angepasst werden und auf verschiedenen Betriebssystemen laufen.

Standardmäßig sind in Mythic keine Agents installiert. Die Open-Source-Community-Agents findest du unter [**https://github.com/MythicAgents**](https://github.com/MythicAgents), und die [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) ist nützlich, um schnell unterstützte Betriebssysteme, payload-Formate, wrappers und C2-Profile zu prüfen.

Um einen Agent aus dieser Organisation zu installieren, kannst du ausführen:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Die Form `sudo -E` ist nützlich, wenn du aus einer Non-root-Umgebung installierst. Du kannst mit dem vorherigen Befehl neue Agents hinzufügen, auch wenn Mythic bereits läuft.

### C2 Profiles

C2 profiles in Mythic definieren **wie agents mit dem Mythic server kommunizieren**. Sie legen das Kommunikationsprotokoll, die Verschlüsselungsmethoden und andere Einstellungen fest. Du kannst C2 profiles über die Mythic web interface erstellen und verwalten.

Standardmäßig wird Mythic ohne profiles installiert, jedoch ist es möglich, einige profiles aus dem repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) herunterzuladen, indem du Folgendes ausführst:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Aktuelle operator-relevante Profile, die man im Blick behalten sollte:

- [`http`](https://github.com/MythicC2Profiles/http): einfacher asynchroner GET/POST-Traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): flexiblerer HTTP-Traffic mit mehreren Callback-Domains, Fail-over-/Round-Robin-Rotation, benutzerdefinierten Headers/Query-Parametern und Message-Transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`), die in Cookies, Headers, Query-Parametern oder dem Body platziert werden.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-gesteuertes HTTP-Message-Shaping, wenn das statische `http`-Profil zu erkennbar ist.

### Wrapper payloads

Wrapper payloads erlauben es dir, dieselbe Agent-Logik beizubehalten, während du die On-Disk-Repräsentation änderst, die ausgeliefert oder persistent gemacht wird.

- `service_wrapper`: macht aus einem anderen payload eine Windows-Service-Executable, was nützlich ist, wenn der Ausführungspfad eine gültige Service-Binary erfordert.
- `scarecrow_wrapper`: umhüllt kompatiblen shellcode mit dem ScareCrow-Loader, um loader-gestützte Ausgaben wie EXE/DLL/CPL zu erzeugen.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ist ein Windows-Agent, geschrieben in C# und basierend auf dem 4.0 .NET Framework, der für den Einsatz in den SpecterOps-Trainingsangeboten entwickelt wurde.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Aktuelle Build-/Profil-Hinweise

- Apollo kann derzeit `WinExe`, `Shellcode`, `Service` und `Source` Payloads ausgeben.
- Die häufig verwendeten Apollo-Profile sind `http`, `httpx`, `smb`, `tcp` und `websocket`.
- `httpx` ist normalerweise die flexiblere Option, wenn du Domain-Rotation, Proxy-Support, benutzerdefinierte Message-Placement und Message-Transforms statt des älteren statischen `http`-Profils brauchst.
- Apollo unterstützt Wrapper-Payloads wie `service_wrapper` und `scarecrow_wrapper`.
- `register_file` und `register_assembly` sind die Staging-Primitives für `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` und `powerpick`. In aktuellen Apollo-Builds werden diese gestagten Artefakte clientseitig als DPAPI-geschützte AES256-Blobs gecacht.
- `ls`- und `ps`-Ergebnisse integrieren sich besonders gut mit Mythic's Browser-Skripten und dem File-/Process-Browser, was das Triaging für Operatoren in kollaborativen Operationen spürbar beschleunigt.

Dieser Agent hat viele Commands, wodurch er Cobalt Strikes Beacon sehr ähnlich ist, mit einigen Extras. Dazu unterstützt er:

### Häufige Aktionen

- `cat`: Den Inhalt einer Datei ausgeben
- `cd`: Das aktuelle Arbeitsverzeichnis ändern
- `cp`: Eine Datei von einem Ort an einen anderen kopieren
- `ls`: Dateien und Verzeichnisse im aktuellen Verzeichnis oder im angegebenen Pfad auflisten
- `ifconfig`: Netzwerkadapter und Interfaces anzeigen
- `netstat`: TCP- und UDP-Verbindungsinformationen anzeigen
- `pwd`: Das aktuelle Arbeitsverzeichnis ausgeben
- `ps`: Laufende Prozesse auf dem Zielsystem auflisten (mit zusätzlichen Infos)
- `jobs`: Alle laufenden Jobs auflisten, die mit langlaufendem Tasking verbunden sind
- `download`: Eine Datei vom Zielsystem auf die lokale Maschine herunterladen
- `upload`: Eine Datei von der lokalen Maschine auf das Zielsystem hochladen
- `reg_query`: Registry-Keys und -Werte auf dem Zielsystem abfragen
- `reg_write_value`: Einen neuen Wert in einen angegebenen Registry-Key schreiben
- `sleep`: Das Sleep-Intervall des Agents ändern, also festlegen, wie oft er sich beim Mythic-Server meldet
- Und viele andere, nutze `help`, um die vollständige Liste der verfügbaren Commands zu sehen.

### Privilege Escalation

- `getprivs`: So viele Privilegien wie möglich auf dem aktuellen Thread-Token aktivieren
- `getsystem`: Einen Handle zu winlogon öffnen und das Token duplizieren, wodurch die Privilegien effektiv auf SYSTEM-Ebene erhöht werden
- `make_token`: Eine neue Logon-Session erstellen und auf den Agent anwenden, sodass die Identität eines anderen Benutzers übernommen werden kann
- `steal_token`: Ein Primary Token aus einem anderen Prozess stehlen, sodass der Agent die Identität dieses Prozess-Benutzers annehmen kann
- `pth`: Pass-the-Hash-Angriff, der es dem Agenten ermöglicht, sich als Benutzer mit dessen NTLM-Hash zu authentifizieren, ohne das Klartextpasswort zu benötigen
- `mimikatz`: Mimikatz-Commands ausführen, um Credentials, Hashes und andere sensible Informationen aus dem Speicher oder der SAM-Datenbank zu extrahieren
- `rev2self`: Das Token des Agents auf sein Primary Token zurücksetzen und damit die Privilegien effektiv wieder auf das ursprüngliche Level zurückstufen
- `ppid`: Den Parent Process für post-exploitation Jobs ändern, indem eine neue Parent-Process-ID angegeben wird, was eine bessere Kontrolle über den Ausführungskontext des Jobs ermöglicht
- `printspoofer`: PrintSpoofer-Commands ausführen, um die Sicherheitsmaßnahmen des Print Spoolers zu umgehen und so Privilege Escalation oder Codeausführung zu ermöglichen
- `dcsync`: Die Kerberos-Keys eines Benutzers mit der lokalen Maschine synchronisieren, was Offline-Passwort-Cracking oder weitere Angriffe ermöglicht
- `ticket_cache_add`: Ein Kerberos-Ticket zur aktuellen Logon-Session oder einer angegebenen Session hinzufügen, was Ticket-Wiederverwendung oder Impersonation ermöglicht

### Prozessausführung

- `assembly_inject`: Ermöglicht das Injizieren eines .NET Assembly Loaders in einen Remote-Prozess
- `blockdlls`: Das Laden von nicht von Microsoft signierten DLLs in post-exploitation Jobs blockieren
- `execute_assembly`: Führt eine .NET Assembly im Kontext des Agents aus
- `execute_coff`: Führt eine COFF-Datei im Speicher aus und ermöglicht damit die In-Memory-Ausführung kompilierten Codes
- `execute_pe`: Führt ein unmanaged Executable (PE) aus
- `get_injection_techniques`: Verfügbare Injection-Techniken und die aktuell ausgewählte anzeigen
- `inline_assembly`: Führt eine .NET Assembly in einer disposable AppDomain aus und ermöglicht so die temporäre Ausführung von Code, ohne den Hauptprozess des Agents zu beeinflussen
- `register_assembly`: Eine .NET Assembly für die spätere Ausführung registrieren
- `register_file`: Eine Datei im Agent-Cache für spätere `execute_*`- oder PowerShell-Tasking registrieren
- `run`: Ein Binary auf dem Zielsystem ausführen und dabei den PATH des Systems verwenden, um das Executable zu finden
- `set_injection_technique`: Die von post-exploitation Jobs verwendete Injection-Primitve ändern
- `shinject`: Shellcode in einen Remote-Prozess injizieren und so die In-Memory-Ausführung beliebigen Codes ermöglichen
- `inject`: Agent-Shellcode in einen Remote-Prozess injizieren und so die In-Memory-Ausführung des Agent-Codes ermöglichen
- `spawn`: Eine neue Agent-Session im angegebenen Executable starten und so die Ausführung von Shellcode in einem neuen Prozess ermöglichen
- `spawnto_x64` und `spawnto_x86`: Das standardmäßig für post-exploitation Jobs verwendete Binary auf einen angegebenen Pfad ändern, statt `rundll32.exe` ohne Parameter zu verwenden, was sehr auffällig ist.

### Mythic Forge

Dies ermöglicht das **Laden von COFF/BOF**-Dateien aus der Mythic Forge, einem Repository vorab kompilierter Payloads und Tools, die auf dem Zielsystem ausgeführt werden können. Mit all den Commands, die geladen werden können, ist es möglich, häufige Aktionen auszuführen, indem sie im aktuellen Agent-Prozess als BOFs ausgeführt werden (meist mit besserer OPSEC als das Starten eines separaten Prozesses).

Beginne mit der Installation mit:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Dann nutze `forge_collections`, um die COFF/BOF-Module aus der Mythic Forge anzuzeigen, damit du sie auswählen und in den Speicher des Agents zur Ausführung laden kannst. Standardmäßig werden in Apollo die folgenden 2 Collections hinzugefügt:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nachdem ein Modul geladen wurde, erscheint es in der Liste als ein weiterer Befehl wie `forge_bof_sa-whoami` oder `forge_bof_sa-netuser`.

### PowerShell- und Scripting-Ausführung

- `powershell_import`: Importiert ein neues PowerShell-Skript (.ps1) in den Cache des Agents für die spätere Ausführung
- `powershell`: Führt einen PowerShell-Befehl im Kontext des Agents aus und ermöglicht so fortgeschrittenes Scripting und Automatisierung
- `powerpick`: Injiziert eine PowerShell-Loader-Assembly in einen Opferprozess und führt einen PowerShell-Befehl aus (ohne powershell logging).
- `psinject`: Führt PowerShell in einem angegebenen Prozess aus und ermöglicht so die gezielte Ausführung von Skripten im Kontext eines anderen Prozesses
- `shell`: Führt einen Shell-Befehl im Kontext des Agents aus, ähnlich wie das Ausführen eines Befehls in cmd.exe

### Lateral Movement

- `jump_psexec`: Nutzt die PsExec-Technik, um sich lateral auf einen neuen Host zu bewegen, indem zuerst die Apollo-Agent-Executable (apollo.exe) kopiert und dann ausgeführt wird.
- `jump_wmi`: Nutzt die WMI-Technik, um sich lateral auf einen neuen Host zu bewegen, indem zuerst die Apollo-Agent-Executable (apollo.exe) kopiert und dann ausgeführt wird.
- `link` und `unlink`: Erstellen und entfernen P2P-Verbindungen (zum Beispiel über SMB/TCP) zwischen Callbacks.
- `wmiexecute`: Führt einen Befehl auf dem lokalen oder angegebenen Remote-System mittels WMI aus, mit optionalen Credentials zur Impersonation.
- `net_dclist`: Ruft eine Liste der Domain Controller für die angegebene Domain ab, nützlich zur Identifizierung potenzieller Ziele für Lateral Movement.
- `net_localgroup`: Listet lokale Gruppen auf dem angegebenen Computer auf; standardmäßig localhost, wenn kein Computer angegeben ist.
- `net_localgroup_member`: Ruft die Mitgliedschaft lokaler Gruppen für eine angegebene Gruppe auf dem lokalen oder Remote-Computer ab und ermöglicht so die Enumeration von Benutzern in bestimmten Gruppen.
- `net_shares`: Listet Remote-Shares und deren Erreichbarkeit auf dem angegebenen Computer auf, nützlich zur Identifizierung potenzieller Ziele für Lateral Movement.
- `socks`: Aktiviert einen SOCKS-5-konformen Proxy im Zielnetzwerk und ermöglicht so das Tunneling von Traffic durch den kompromittierten Host. Kompatibel mit Tools wie proxychains.
- `rpfwd`: Beginnt mit dem Lauschen auf einem angegebenen Port auf dem Zielhost und leitet Traffic über Mythic an eine entfernte IP und einen Port weiter, wodurch Remote-Zugriff auf Dienste im Zielnetzwerk möglich wird.
- `listpipes`: Listet alle Named Pipes auf dem lokalen System auf, was für Lateral Movement oder Privilege Escalation nützlich sein kann, indem mit IPC-Mechanismen interagiert wird.

Für die darunterliegenden WMI-Ausführungs-Primitiven, die von `jump_wmi` oder `wmiexecute` verwendet werden, siehe [WmiExec](lateral-movement/wmiexec.md). Für allgemeinere Pivoting-Muster siehe [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Sonstige Befehle
- `help`: Zeigt detaillierte Informationen zu bestimmten Befehlen oder allgemeine Informationen zu allen im Agenten verfügbaren Befehlen an.
- `clear`: Markiert Tasks als 'cleared', sodass sie nicht von Agents übernommen werden können. Du kannst `all` angeben, um alle Tasks zu löschen, oder `task Num`, um einen bestimmten Task zu löschen.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon ist ein Golang-Agent, der in **Linux- und macOS**-Executables kompiliert wird.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Aktuelle Build-/Profil-Notizen

- Aktuelle Poseidon-Builds zielen auf Linux und macOS auf `x86_64` und `arm64` ab.
- Unterstützte Ausgabeformate umfassen native ausführbare Dateien sowie Shared-Library-artige Ausgaben wie `dylib` und `so`.
- Poseidon unterstützt `http`, `websocket`, `tcp` und `dynamichttp`, und aktuelle Builder bieten Multi-Egress-Einstellungen wie `egress_order` und Failover-Schwellenwerte.
- Build-Zeit-Optionen wie `proxy_bypass` und `garble` sind prüfenswert, wenn du entweder ein saubereres Netzwerkverhalten oder zusätzliche Go-Binary-Obfuskation brauchst.

Für macOS-spezifisches Tradecraft rund um Mythic-gestützte Operationen, JAMF-Missbrauch oder MDM-as-C2-Ideen, siehe [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Wenn es unter Linux oder macOS verwendet wird, hat es einige interessante Befehle:

### Häufige Aktionen

- `cat`: Den Inhalt einer Datei ausgeben
- `cd`: Das aktuelle Arbeitsverzeichnis ändern
- `chmod`: Die Berechtigungen einer Datei ändern
- `config`: Die aktuelle Konfiguration und Host-Informationen anzeigen
- `cp`: Eine Datei von einem Ort an einen anderen kopieren
- `curl`: Eine einzelne Webanfrage mit optionalen Headern und Methode ausführen
- `upload`: Eine Datei zum Ziel hochladen
- `download`: Eine Datei vom Zielsystem auf die lokale Maschine herunterladen
- Und viele mehr

### Nach sensiblen Informationen suchen

- `triagedirectory`: Interessante Dateien innerhalb eines Verzeichnisses auf einem Host finden, etwa sensible Dateien oder Credentials.
- `getenv`: Alle aktuellen Umgebungsvariablen abrufen.

### Seitliche Bewegung

- `ssh`: Per SSH auf den Host mit den angegebenen Credentials verbinden und eine PTY öffnen, ohne `ssh` zu starten.
- `sshauth`: Mit den angegebenen Credentials per SSH zu den angegebenen Hosts verbinden. Du kannst dies auch verwenden, um einen bestimmten Befehl auf den Remote-Hosts via SSH auszuführen oder Dateien per SCP zu übertragen.
- `link_tcp`: Über TCP mit einem anderen Agenten verbinden und direkte Kommunikation zwischen Agenten ermöglichen.
- `link_webshell`: Einen Agenten mit dem webshell P2P-Profil verbinden, um Fernzugriff auf die Weboberfläche des Agenten zu erhalten.
- `rpfwd`: Einen Reverse Port Forward starten oder stoppen, um Fernzugriff auf Dienste im Zielnetzwerk zu ermöglichen.
- `socks`: Einen SOCKS5-Proxy im Zielnetzwerk starten oder stoppen, um Traffic über den kompromittierten Host zu tunneln. Kompatibel mit Tools wie proxychains.
- `portscan`: Host(s) auf offene Ports scannen, nützlich zum Identifizieren möglicher Ziele für laterale Bewegung oder weitere Angriffe.

### Prozessausführung

- `shell`: Einen einzelnen Shell-Befehl via /bin/sh ausführen und so direkte Befehlsausführung auf dem Zielsystem ermöglichen.
- `run`: Einen Befehl von der Festplatte mit Argumenten ausführen und so die Ausführung von Binaries oder Skripten auf dem Zielsystem ermöglichen.
- `pty`: Eine interaktive PTY öffnen und so direkte Interaktion mit der Shell auf dem Zielsystem ermöglichen.




## Referenzen

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
