# Mythic

## Was ist Mythic?

Mythic ist ein Open-Source, modulares Command and Control (C2) Framework, das für Red Teaming entwickelt wurde. Es ermöglicht Sicherheitsfachleuten, verschiedene Agenten (Payloads) über verschiedene Betriebssysteme hinweg zu verwalten und bereitzustellen, einschließlich Windows, Linux und macOS. Mythic bietet eine benutzerfreundliche Weboberfläche zur Verwaltung von Agenten, Ausführung von Befehlen und Sammlung von Ergebnissen, was es zu einem leistungsstarken Werkzeug zur Simulation von realen Angriffen in einer kontrollierten Umgebung macht.

### Installation

Um Mythic zu installieren, folgen Sie den Anweisungen im offiziellen **[Mythic repo](https://github.com/its-a-feature/Mythic)**.

### Agenten

Mythic unterstützt mehrere Agenten, die die **Payloads sind, die Aufgaben auf den kompromittierten Systemen ausführen**. Jeder Agent kann an spezifische Bedürfnisse angepasst werden und kann auf verschiedenen Betriebssystemen ausgeführt werden.

Standardmäßig hat Mythic keine Agenten installiert. Es bietet jedoch einige Open-Source-Agenten in [**https://github.com/MythicAgents**](https://github.com/MythicAgents).

Um einen Agenten aus diesem Repo zu installieren, müssen Sie einfach Folgendes ausführen:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
Sie können mit dem vorherigen Befehl neue Agenten hinzufügen, auch wenn Mythic bereits läuft.

### C2-Profile

C2-Profile in Mythic definieren **wie Agenten mit dem Mythic-Server kommunizieren**. Sie geben das Kommunikationsprotokoll, die Verschlüsselungsmethoden und andere Einstellungen an. Sie können C2-Profile über die Mythic-Weboberfläche erstellen und verwalten.

Standardmäßig wird Mythic ohne Profile installiert, jedoch ist es möglich, einige Profile aus dem Repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) herunterzuladen, indem Sie Folgendes ausführen:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ist ein Windows-Agent, der in C# unter Verwendung des .NET Framework 4.0 geschrieben wurde und für die Verwendung in den Schulungsangeboten von SpecterOps konzipiert ist.

Installiere es mit:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Dieser Agent hat viele Befehle, die ihn sehr ähnlich zu Cobalt Strike's Beacon machen, mit einigen Extras. Unter ihnen unterstützt er:

### Häufige Aktionen

- `cat`: Gibt den Inhalt einer Datei aus
- `cd`: Ändert das aktuelle Arbeitsverzeichnis
- `cp`: Kopiert eine Datei von einem Ort an einen anderen
- `ls`: Listet Dateien und Verzeichnisse im aktuellen Verzeichnis oder im angegebenen Pfad auf
- `pwd`: Gibt das aktuelle Arbeitsverzeichnis aus
- `ps`: Listet laufende Prozesse auf dem Zielsystem auf (mit zusätzlichen Informationen)
- `download`: Lädt eine Datei vom Zielsystem auf die lokale Maschine herunter
- `upload`: Lädt eine Datei von der lokalen Maschine auf das Zielsystem hoch
- `reg_query`: Abfragen von Registrierungsschlüsseln und -werten auf dem Zielsystem
- `reg_write_value`: Schreibt einen neuen Wert in einen angegebenen Registrierungsschlüssel
- `sleep`: Ändert das Schlafintervall des Agents, das bestimmt, wie oft er sich beim Mythic-Server meldet
- Und viele andere, benutze `help`, um die vollständige Liste der verfügbaren Befehle zu sehen.

### Privilegieneskalation

- `getprivs`: Aktiviert so viele Berechtigungen wie möglich auf dem aktuellen Thread-Token
- `getsystem`: Öffnet einen Handle zu winlogon und dupliziert das Token, wodurch die Berechtigungen auf SYSTEM-Ebene eskaliert werden
- `make_token`: Erstellt eine neue Anmeldesitzung und wendet sie auf den Agenten an, was die Nachahmung eines anderen Benutzers ermöglicht
- `steal_token`: Stiehlt ein primäres Token von einem anderen Prozess, wodurch der Agent den Benutzer dieses Prozesses nachahmen kann
- `pth`: Pass-the-Hash-Angriff, der es dem Agenten ermöglicht, sich als Benutzer mit ihrem NTLM-Hash zu authentifizieren, ohne das Klartextpasswort zu benötigen
- `mimikatz`: Führt Mimikatz-Befehle aus, um Anmeldeinformationen, Hashes und andere sensible Informationen aus dem Speicher oder der SAM-Datenbank zu extrahieren
- `rev2self`: Setzt das Token des Agents auf sein primäres Token zurück, wodurch die Berechtigungen auf das ursprüngliche Niveau zurückgesetzt werden
- `ppid`: Ändert den übergeordneten Prozess für Post-Exploitation-Jobs, indem eine neue übergeordnete Prozess-ID angegeben wird, was eine bessere Kontrolle über den Ausführungskontext der Jobs ermöglicht
- `printspoofer`: Führt PrintSpoofer-Befehle aus, um Sicherheitsmaßnahmen des Druckspoolers zu umgehen, was eine Privilegieneskalation oder Codeausführung ermöglicht
- `dcsync`: Synchronisiert die Kerberos-Schlüssel eines Benutzers mit der lokalen Maschine, was Offline-Passwort-Cracking oder weitere Angriffe ermöglicht
- `ticket_cache_add`: Fügt ein Kerberos-Ticket zur aktuellen Anmeldesitzung oder einer angegebenen hinzu, was die Wiederverwendung von Tickets oder die Nachahmung ermöglicht

### Prozesse ausführen

- `assembly_inject`: Ermöglicht das Injizieren eines .NET-Assembly-Loaders in einen Remote-Prozess
- `execute_assembly`: Führt eine .NET-Assembly im Kontext des Agents aus
- `execute_coff`: Führt eine COFF-Datei im Speicher aus, was die Ausführung von kompiliertem Code im Speicher ermöglicht
- `execute_pe`: Führt eine unmanaged ausführbare Datei (PE) aus
- `inline_assembly`: Führt eine .NET-Assembly in einem temporären AppDomain aus, was die temporäre Ausführung von Code ermöglicht, ohne den Hauptprozess des Agents zu beeinträchtigen
- `run`: Führt eine Binärdatei auf dem Zielsystem aus, wobei der PATH des Systems verwendet wird, um die ausführbare Datei zu finden
- `shinject`: Injiziert Shellcode in einen Remote-Prozess, was die Ausführung von beliebigem Code im Speicher ermöglicht
- `inject`: Injiziert Agent-Shellcode in einen Remote-Prozess, was die Ausführung des Codes des Agents im Speicher ermöglicht
- `spawn`: Startet eine neue Agentensitzung im angegebenen ausführbaren Programm, was die Ausführung von Shellcode in einem neuen Prozess ermöglicht
- `spawnto_x64` und `spawnto_x86`: Ändert die Standard-Binärdatei, die in Post-Exploitation-Jobs verwendet wird, auf einen angegebenen Pfad, anstatt `rundll32.exe` ohne Parameter zu verwenden, was sehr laut ist.

### Mithic Forge

Dies ermöglicht das **Laden von COFF/BOF**-Dateien aus der Mythic Forge, die ein Repository von vorcompilierten Payloads und Tools ist, die auf dem Zielsystem ausgeführt werden können. Mit all den Befehlen, die geladen werden können, wird es möglich sein, häufige Aktionen auszuführen, indem sie im aktuellen Agentenprozess als BOFs ausgeführt werden (meistens stealthier).

Beginne mit der Installation:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Dann verwenden Sie `forge_collections`, um die COFF/BOF-Module aus dem Mythic Forge anzuzeigen, um sie in den Arbeitsspeicher des Agenten zu laden und auszuführen. Standardmäßig werden die folgenden 2 Sammlungen in Apollo hinzugefügt:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nachdem ein Modul geladen wurde, erscheint es in der Liste als ein weiterer Befehl wie `forge_bof_sa-whoami` oder `forge_bof_sa-netuser`.

### Powershell & Skriptausführung

- `powershell_import`: Importiert ein neues PowerShell-Skript (.ps1) in den Agenten-Cache zur späteren Ausführung
- `powershell`: Führt einen PowerShell-Befehl im Kontext des Agenten aus, was fortgeschrittenes Skripting und Automatisierung ermöglicht
- `powerpick`: Injektiert eine PowerShell-Laderoutine in einen opfernden Prozess und führt einen PowerShell-Befehl aus (ohne PowerShell-Protokollierung).
- `psinject`: Führt PowerShell in einem bestimmten Prozess aus, was eine gezielte Ausführung von Skripten im Kontext eines anderen Prozesses ermöglicht
- `shell`: Führt einen Shell-Befehl im Kontext des Agenten aus, ähnlich wie das Ausführen eines Befehls in cmd.exe

### Laterale Bewegung

- `jump_psexec`: Verwendet die PsExec-Technik, um lateral zu einem neuen Host zu wechseln, indem zuerst die Apollo-Agenten-Executable (apollo.exe) kopiert und ausgeführt wird.
- `jump_wmi`: Verwendet die WMI-Technik, um lateral zu einem neuen Host zu wechseln, indem zuerst die Apollo-Agenten-Executable (apollo.exe) kopiert und ausgeführt wird.
- `wmiexecute`: Führt einen Befehl auf dem lokalen oder angegebenen Remote-System mithilfe von WMI aus, mit optionalen Anmeldeinformationen zur Identitätsübernahme.
- `net_dclist`: Ruft eine Liste von Domänencontrollern für die angegebene Domäne ab, nützlich zur Identifizierung potenzieller Ziele für laterale Bewegung.
- `net_localgroup`: Listet lokale Gruppen auf dem angegebenen Computer auf, standardmäßig localhost, wenn kein Computer angegeben ist.
- `net_localgroup_member`: Ruft die Mitgliedschaft in lokalen Gruppen für eine angegebene Gruppe auf dem lokalen oder Remote-Computer ab, was die Aufzählung von Benutzern in bestimmten Gruppen ermöglicht.
- `net_shares`: Listet Remote-Freigaben und deren Zugänglichkeit auf dem angegebenen Computer auf, nützlich zur Identifizierung potenzieller Ziele für laterale Bewegung.
- `socks`: Aktiviert einen SOCKS 5-konformen Proxy im Zielnetzwerk, der das Tunneln von Datenverkehr durch den kompromittierten Host ermöglicht. Kompatibel mit Tools wie proxychains.
- `rpfwd`: Beginnt, auf einem angegebenen Port auf dem Zielhost zu lauschen und leitet den Datenverkehr über Mythic an eine Remote-IP und einen Port weiter, was den Remote-Zugriff auf Dienste im Zielnetzwerk ermöglicht.
- `listpipes`: Listet alle benannten Pipes im lokalen System auf, was nützlich für laterale Bewegung oder Privilegieneskalation durch Interaktion mit IPC-Mechanismen sein kann.

### Verschiedene Befehle
- `help`: Zeigt detaillierte Informationen zu bestimmten Befehlen oder allgemeine Informationen zu allen verfügbaren Befehlen im Agenten an.
- `clear`: Markiert Aufgaben als 'bereinigt', sodass sie nicht von Agenten übernommen werden können. Sie können `all` angeben, um alle Aufgaben zu bereinigen, oder `task Num`, um eine bestimmte Aufgabe zu bereinigen.


## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon ist ein Golang-Agent, der in **Linux- und macOS**-Executables kompiliert.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
Wenn Benutzer über Linux arbeitet, gibt es einige interessante Befehle:

### Häufige Aktionen

- `cat`: Gibt den Inhalt einer Datei aus
- `cd`: Ändert das aktuelle Arbeitsverzeichnis
- `chmod`: Ändert die Berechtigungen einer Datei
- `config`: Zeigt die aktuelle Konfiguration und Hostinformationen an
- `cp`: Kopiert eine Datei von einem Ort an einen anderen
- `curl`: Führt eine einzelne Webanfrage mit optionalen Headern und Methoden aus
- `upload`: Lädt eine Datei auf das Ziel hoch
- `download`: Lädt eine Datei vom Zielsystem auf die lokale Maschine herunter
- Und viele mehr

### Sensible Informationen suchen

- `triagedirectory`: Findet interessante Dateien innerhalb eines Verzeichnisses auf einem Host, wie z.B. sensible Dateien oder Anmeldeinformationen.
- `getenv`: Holt alle aktuellen Umgebungsvariablen.

### Laterale Bewegung

- `ssh`: SSH zu einem Host mit den angegebenen Anmeldeinformationen und öffnet ein PTY, ohne ssh zu starten.
- `sshauth`: SSH zu angegebenen Host(s) mit den vorgesehenen Anmeldeinformationen. Sie können dies auch verwenden, um einen bestimmten Befehl auf den Remote-Hosts über SSH auszuführen oder um Dateien mit SCP zu übertragen.
- `link_tcp`: Verbindet sich über TCP mit einem anderen Agenten, was eine direkte Kommunikation zwischen den Agenten ermöglicht.
- `link_webshell`: Verbindet sich mit einem Agenten über das Webshell-P2P-Profil, was den Remote-Zugriff auf die Weboberfläche des Agenten ermöglicht.
- `rpfwd`: Startet oder stoppt eine Reverse-Port-Weiterleitung, die den Remote-Zugriff auf Dienste im Zielnetzwerk ermöglicht.
- `socks`: Startet oder stoppt einen SOCKS5-Proxy im Zielnetzwerk, der das Tunneln von Datenverkehr durch den kompromittierten Host ermöglicht. Kompatibel mit Tools wie proxychains.
- `portscan`: Scannt Host(s) nach offenen Ports, nützlich zur Identifizierung potenzieller Ziele für laterale Bewegungen oder weitere Angriffe.

### Prozesse ausführen

- `shell`: Führt einen einzelnen Shell-Befehl über /bin/sh aus, was die direkte Ausführung von Befehlen auf dem Zielsystem ermöglicht.
- `run`: Führt einen Befehl von der Festplatte mit Argumenten aus, was die Ausführung von Binärdateien oder Skripten auf dem Zielsystem ermöglicht.
- `pty`: Öffnet ein interaktives PTY, was die direkte Interaktion mit der Shell auf dem Zielsystem ermöglicht.
