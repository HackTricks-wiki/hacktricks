# Mythic

{{#include ../banners/hacktricks-training.md}}

## Was ist Mythic?

Mythic ist ein Open-Source-, modulares und kollaboratives Command-and-Control-Framework (C2) für Red Teaming. Es ermöglicht Operatoren, Agents (Payloads) auf verschiedenen Betriebssystemen, darunter Windows, Linux und macOS, zu verwalten und bereitzustellen. Mythic bietet eine Browser-UI für das Tasking mehrerer Operatoren, die Dateiverwaltung, die Verwaltung von SOCKS/rpfwd und die Payload-Generierung.

Im Gegensatz zu monolithischen Frameworks enthält das Mythic-Repository selbst **keine** Payload-Typen oder C2-Profile. Agents, Wrapper und C2-Profile werden üblicherweise als externe Komponenten installiert und können unabhängig vom Mythic-Core aktualisiert werden.

### Installation

Folge zur Installation von Mythic den Anweisungen im offiziellen **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Ein üblicher Bootstrap aus dem Mythic-Verzeichnis ist:

```bash
sudo make
sudo ./mythic-cli start
```

Wenn Mythic bereits läuft, kannst du normalerweise mit `./mythic-cli install github ...` einen neuen Agent oder ein neues Profil hinzufügen und anschließend entweder Mythic neu starten oder die neue Komponente direkt starten.

### Agents

Mythic unterstützt mehrere Agents. Dabei handelt es sich um die **Payloads, die Aufgaben auf den kompromittierten Systemen ausführen**. Jeder Agent kann an bestimmte Anforderungen angepasst werden und auf verschiedenen Betriebssystemen laufen.

Standardmäßig sind in Mythic keine Agents installiert. Die Agents der Open-Source-Community findest du unter [**https://github.com/MythicAgents**](https://github.com/MythicAgents). Mit der [**Community-Übersicht der Funktionen**](https://mythicmeta.github.io/overview/agent_matrix.html) kannst du schnell prüfen, welche Betriebssysteme, Payload-Formate, Wrapper und C2-Profile unterstützt werden.<sup>[[1]](#references)</sup>

Um einen Agent aus dieser Organisation zu installieren, kannst du Folgendes ausführen:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

Die Form `sudo -E` ist nützlich, wenn du aus einer Nicht-root-Umgebung installierst. Mit dem vorherigen Befehl kannst du neue Agents hinzufügen, selbst wenn Mythic bereits läuft.

### C2 Profiles

C2 Profiles in Mythic legen fest, **wie Agents mit dem Mythic-Server kommunizieren**. Sie definieren das Kommunikationsprotokoll, Verschlüsselungsmethoden und weitere Einstellungen. Du kannst C2 Profiles über die Mythic-Weboberfläche erstellen und verwalten.

Standardmäßig wird Mythic ohne Profiles installiert. Es ist jedoch möglich, einige Profiles aus dem Repository [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) herunterzuladen, indem du Folgendes ausführst:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Aktuelle, für Operatoren relevante Profile, die du im Blick behalten solltest:

- [`http`](https://github.com/MythicC2Profiles/http): einfacher asynchroner GET/POST-Datenverkehr.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): flexiblerer HTTP-Datenverkehr mit mehreren Callback-Domains, Failover-/Round-Robin-Rotation, benutzerdefinierten Headern/Query-Parametern und Nachrichtentransformationen (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`), die in Cookies, Headern, Query-Parametern oder im Body platziert werden.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON-/TOML-gesteuerte Anpassung von HTTP-Nachrichten, wenn das statische `http`-Profil zu leicht erkennbar ist.

### Aktuelle Hinweise zur Plattform

- Viele öffentliche Agents und Profile werden inzwischen mit vorgefertigten Remote-Container-Images installiert.
  Wenn du eine Komponente forkt oder lokal patchst und Mythic weiterhin das alte
  Verhalten zeigt, prüfe die generierten `.env`-Einträge für `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT` und `*_USE_VOLUME`. Mit
  `*_USE_BUILD_CONTEXT="true"` sorgst du normalerweise dafür, dass Mythic aus
  deinem lokalen Docker-Kontext neu baut, statt unbemerkt das Remote-Image
  wiederzuverwenden.
- Browser-Skripte gehören für Operatoren zu den wertvollsten Funktionen für
  mehr Bedienkomfort in Mythic: Sie können rohe Kommandoausgaben in Tabellen,
  Screenshot-Viewer, Download-Links, Suchlinks und Buttons umwandeln, die direkt
  über die UI Folgeaufgaben auslösen. Aktuelle Mythic-Builds ermöglichen es
  jedem Operator, eigene Skripte zu verwenden, sie global oder pro Task ein- und
  auszuschalten und erzielen die besten Ergebnisse, wenn Agents strukturierte
  JSON-Daten statt Klartext zurückgeben. Das ist besonders nützlich bei
  wiederkehrenden Workflows mit `ls`, `ps`, Triage und Dateibrowsern.<sup>[[4]](#references)[[6]](#references)</sup>
- Neuere Mythic-Builds unterstützen außerdem interaktives Tasking und Push-C2-Muster,
  wodurch bei PTY-/SOCKS-/rpfwd-intensiven Operationen weniger häufiges Polling
  mit `sleep 0` nötig ist. Wenn ein Agent/Profil dies unterstützt, verursacht
  diese Methode in der Regel weniger Overhead als ständige Check-ins beim Server,
  nur um einen interaktiven Kanal nutzbar zu halten.<sup>[[3]](#references)</sup>
- Aktuelle Mythic-Builder der 3.4-Ära sind kontextbewusster, als ältere
  Beschreibungen vermuten lassen: Build-Parameter können jetzt abhängig vom
  ausgewählten Betriebssystem oder anderen Build-Optionen gruppiert oder
  ausgeblendet werden. Payload-Typen können festlegen, ob sie mehrere C2-Profile
  oder mehrere Instanzen desselben C2 in einem Build unterstützen, und C2-
  Parameterabweichungen ermöglichen es einem Agent, Felder auszublenden, die
  er tatsächlich nicht implementiert. Das ist wichtig, wenn du zwischen `http`,
  `httpx`, `smb`, `tcp` und `websocket` wechselst, da der sichere/gültige
  Build-Bereich kein statisches, einheitliches Formular mehr ist.<sup>[[5]](#references)</sup>
- Wenn du ein benutzerdefiniertes Agent-/Profil-Paar erstellst und weder Mythics
  JSON-Nachrichtenformat noch die standardmäßige Verschlüsselung über das Netz
  verwenden möchtest, nutze einen `translation_container`: Mythic entfernt die
  UUID, übergibt dem Übersetzer den verschlüsselten Blob und das Schlüsselmaterial
  per gRPC und erwartet native Bytes des Agents zurück. So lassen sich
  Binärprotokolle, benutzerdefinierte Framing-Verfahren oder agentseitige
  Verschlüsselung unterstützen, ohne den gesamten Server neu zu schreiben.
- Denk daran, dass verknüpfte/P2P-Callbacks nicht nur Tasking weiterleiten.
  Mythics `get_tasking`-Ablauf kann auch Antworten sowie Daten für `delegates`,
  `socks`, `rpfwd` und `interactive` übertragen. In der Praxis kann ein
  Egress-Callback innere Callbacks und Pivot-Kanäle in derselben Polling-Schleife
  bedienen. Wenn die Child-Agents ihre eigenen regelmäßigen Check-ins
  durchführen, verhindert `get_delegate_tasks=false`, dass der Parent
  versehentlich die in der Warteschlange befindlichen Jobs des inneren Callbacks
  abruft.

### Wrapper-Payloads

Mit Wrapper-Payloads kannst du dieselbe Agent-Logik beibehalten und gleichzeitig
die Darstellung auf der Festplatte ändern, die ausgeliefert oder gespeichert wird.

- `service_wrapper`: Wandelt eine andere Payload in eine Windows-Service-Executable
  um. Das ist nützlich, wenn der Ausführungspfad eine gültige Service-Binärdatei
  voraussetzt.
- `scarecrow_wrapper`: Verpackt kompatibles Shellcode mit dem ScareCrow-Loader,
  um loadergestützte Ausgaben wie EXE/DLL/CPL zu erzeugen.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ist ein Windows-Agent in C#, der mit dem .NET Framework 4.0 geschrieben
wurde und für den Einsatz in den Schulungsangeboten von SpecterOps entwickelt
wurde.<sup>[[2]](#references)</sup>

Installiere ihn mit:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Hinweise zu aktuellem Build/Profil

- Apollo kann derzeit Payloads vom Typ `WinExe`, `Shellcode`, `Service` und `Source` ausgeben.
- Die häufig verwendeten Apollo-Profile sind `http`, `httpx`, `smb`, `tcp` und `websocket`.
- `httpx` ist in der Regel die flexiblere Option, wenn du Domain-Rotation, Proxy-Unterstützung, benutzerdefinierte Nachrichtenplatzierung und Nachrichtentransformationen anstelle des älteren statischen `http`-Profils benötigst.
- Apollo ist einer der funktionsreichsten Community-Agents und bietet derzeit Mythic-seitige Integrationen wie Browser-Skripte, Datei-/Prozess-Browseransichten, Screenshots, Keylogging, SOCKS, rpfwd, Push C2 und P2P-Routing.
- Apollo unterstützt Wrapper-Payloads wie `service_wrapper` und `scarecrow_wrapper`.
- Apollo unterstützt das dynamische Laden von Befehlen. So kannst du den initialen Payload schlank halten und später zusätzliche Befehle oder Forge-Module laden, anstatt alle Post-Exploitation-Funktionen in den ersten Build zu kompilieren.
- Bei der Ausgabe von Shellcode bietet der aktuelle Apollo-Builder auch Donut-Formatoptionen (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) und Donut-Bypass-Verhalten (`None`, `Abort on fail`, `Continue on fail`). Das ist nützlich, wenn du den Shellcode anschließend mit `service_wrapper`, `scarecrow_wrapper` oder einem eigenen Loader neu verpacken möchtest.
- `register_file` und `register_assembly` sind die Staging-Primitiven für `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` und `powerpick`. In aktuellen Apollo-Builds werden diese bereitgestellten Artefakte clientseitig als DPAPI-geschützte AES256-Blobs zwischengespeichert.
- Die Ergebnisse von `ls` und `ps` lassen sich besonders gut in Mythics Browser-Skripte sowie den Datei-/Prozess-Browser integrieren. Dadurch wird die Triage durch Operatoren bei kollaborativen Operationen deutlich schneller.
- Die Fork-and-Run-Jobs von Apollo übernehmen ihre Einstellungen für sacrificial processes von
  `spawnto_x86` / `spawnto_x64`, wählen den übergeordneten Prozess anhand von `ppid` aus und
  verwenden anschließend das aktuell ausgewählte Injection-Primitiv. In der Praxis bedeutet
  das, dass deine OPSEC-Einstellungen für einen Befehl häufig gleichzeitig `execute_assembly`,
  `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` und `spawn` beeinflussen.
- Zu den derzeit dokumentierten Apollo-Injection-Backends gehören `CreateRemoteThread`,
  `QueueUserAPC` (Early-Bird-Stil) und `NtCreateThreadEx` über Syscalls. Verwende
  `get_injection_techniques` vor auffälliger Post-Exploitation und
  `set_injection_technique`, wenn du von einem Primitiv wechseln musst, das mit dem Ziel oder
  dem auszuführenden Befehl kollidiert.
- `blockdlls` wirkt sich nur auf sacrificial processes aus, die für Post-Exploitation-Jobs erstellt werden. Zusammen mit einem weniger verdächtigen `spawnto_x64`-Ziel als dem standardmäßigen, unveränderten `rundll32.exe` ist dies eine der einfachsten Apollo-seitigen Anpassungen, die du vor dem Ausführen von Assembly-/PowerShell-lastigen Tasks vornehmen kannst.

### Detection-bewusste .NET-Agent-Build-Pipeline

Ein Detection-bewusster Apollo-Fork sollte als **Problem des gesamten Build-Systems** betrachtet werden, nicht als abschließender Schritt mit `obfuscate.exe`. Diese Fallstudie ergänzt die allgemeine [AV-Evasion-Methodik](av-bypass.md) und die [Tools zur .NET-Inspektion](../reversing/reversing-tools-basic-methods/README.md): Änderungen an Wire-Identifiers, IL-Metadaten, Dependency-Paketierung, Reflection und dynamisch kompilierten Tasks bilden eine gemeinsame Kompatibilitätsgrenze.<sup>[[8]](#references)</sup>

#### YARA-bewusste Protokollmutation

Prüfe öffentliche Datei-/Speicherregeln, bevor du den Code änderst. Elastic's `Multi_Trojan_Mythic_4beb7e17` löst beispielsweise aus, wenn **7 von 11** Mythic-JSON-/Aktions-Strings vorkommen, darunter `task_id`, `post_response`, `c2_profile`, `get_tasking` und `get_delegate_tasks`. Wenn genügend Felder umbenannt werden, kann dieser Schwellenwert unterschritten werden. Dabei handelt es sich jedoch um Protokollwerte und nicht um kosmetische Symbole: Agent und entsprechende Server-/Profilimplementierung müssen gemeinsam geändert werden.<sup>[[7]](#references)[[8]](#references)</sup>

Damit wird nur ein statischer Merkmalsumfang entfernt. Check-in-Taktung, Nachrichtenform, Task-/Response-Ablauf und String-Rekonstruktion zur Laufzeit können weiterhin verhaltens- oder speicherbasierte Indikatoren sein. Prüfe deshalb sowohl das erstellte Artefakt als auch einen tatsächlich ausgelösten Callback, statt einen unauffälligen String-Scan als Erfolg zu werten.<sup>[[8]](#references)</sup>

#### Vor globalen Transformationen zusammenführen

Das Einbetten von Ressourcen mit Tools wie Costura hinterlässt Companion-Assemblies als komprimierte Ressourcen. Ein Obfuscator, der nur das äußere Modul verarbeitet, übersieht daher deren Typnamen und Metadaten; die separate Obfuscation jeder DLL kann stattdessen inkompatible Namen für assemblyübergreifende Verträge vergeben. Führe zuerst die Build-Ausgaben auf IL-Ebene zusammen (zum Beispiel mit [ILRepack](https://github.com/gluck/il-repack)) und wende anschließend eine einzelne Rename-Map auf das resultierende Modul an.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

Ein benutzerdefinierter Pass kann [dnlib](https://github.com/0xd4d/dnlib) für verwaltete IL-/Metadata-Transformationen und [AsmResolver](https://github.com/Washi1337/AsmResolver) für PE-/Ressourcen-Patching nach dem Schreiben verwenden. In der Fallstudie wurden geeignete `ldstr`-Anweisungen durch Aufrufe ersetzt, die Integer-Tokens und einen Decryptor verwenden und auf einem neuen 16-Byte-Rolling-XOR-Schlüssel basieren. Symbole und Namespaces wurden plausiblen, unternehmenstypischen Namen zugeordnet, statt kurzen, sequenziellen Bezeichnern. Weitere Pässe entfernten ausgewählte Compiler-/Debugger-Attribute, bereinigten Verweise auf Merger/Embedding, benannten Ressourcen um und patchten Versionsinformationen. Erzeuge für jeden unabhängigen Build neue Namen, neuen Dead Code und neues Verschlüsselungsmaterial: Geänderter Ciphertext beseitigt stabile Bytes, aber ein stabiler Decryptor oder ein erkennbares Transformationsmuster ist selbst eine Signatur.<sup>[[8]](#references)</sup>

#### Dynamische Tasks mit dem Payload synchronisieren

Apollo kann Task-Quellcode serverseitig kompilieren, die DLL-Bytes senden und sie mit `Assembly.Load()` laden. Sobald die öffentlichen Typen des Basis-Agenten umbenannt sind, lassen sich spätere Tasks, die gegen die ursprüngliche API kompiliert wurden, nicht mehr auflösen. Behandle die exportierte Rename-Map als ein payloadspezifisches ABI-Artefakt:<sup>[[8]](#references)</sup>

1. Verknüpfe die Map und den Typkontext mit der exakten Payload-/Build-Kennung.
2. Rufe für jeden Task-Build diese Map ab und schreibe einen temporären Quellcodebaum um.
3. Schreibe nur aufgelöste Verweise auf Namespaces, Typen, verschachtelte/generische Typen, Felder und Eigenschaften um und kompiliere anschließend gegen die obfuskierte, zusammengeführte Assembly.
4. Lehne fehlende oder nicht passende Maps vor der Task-Zustellung ab und führe nach der Kompilierung einen Initialisierungstest aus.

Blinde globale Ersetzungen sind unsicher, da ein Bezeichner auch in einem String, einer lokalen Deklaration, einem Member-Zugriff, einem Framework-Typ oder einem nicht verwandten Namespace vorkommen kann. Wenn ein text-/regexbasierter Rewriter verwendet wird, schütze diese Kontexte ausdrücklich und teste ihn bei jeder Änderung am Map-Schema oder an einem Rename-Pass erneut mit Regressionstests.<sup>[[8]](#references)</sup>

#### Reflection-Verträge unabhängig vom Namespace gestalten

Discovery-Code, der `t.FullName.StartsWith("Tasks.")` prüft, macht den Namespace zu einer erforderlichen Abhängigkeit und schlägt nach einer Umbenennung von Namespaces fehl. Suche stattdessen anhand einer stabilen Typbeziehung und behalte Klassennamen von Commands bei, wenn die Dispatch-Logik weiterhin `t.Name` verwendet:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Maintain eine explizite Allowlist mit reflection-sichtbaren Namen, Serializer-Feldern, Einstiegspunkten und assemblyübergreifenden APIs, die nicht umbenannt werden dürfen. Decompile das Ergebnis schließlich mit ILSpy/dnSpy, untersuche sowohl Datei- als auch Speicherrepräsentationen und teste jeden Command- und Loader-Pfad in einem EDR-Lab; ein Build, der erfolgreich startet, kann trotzdem Tasks enthalten, die durch das Umbenennen beschädigt wurden, oder Verhalten zeigen, das erst bei der Ausführung erkannt wird.<sup>[[8]](#references)</sup>

Dieser Agent verfügt über viele Commands, wodurch er Cobalt Strikes Beacon sehr ähnlich ist, bietet aber auch einige Extras. Dazu gehören:

### Häufige Aktionen

- `cat`: Den Inhalt einer Datei ausgeben
- `cd`: Das aktuelle Arbeitsverzeichnis ändern
- `cp`: Eine Datei von einem Speicherort an einen anderen kopieren
- `ls`: Dateien und Verzeichnisse im aktuellen Verzeichnis oder im angegebenen Pfad auflisten
- `ifconfig`: Netzwerkadapter und Schnittstellen abrufen
- `netstat`: Informationen zu TCP- und UDP-Verbindungen abrufen
- `pwd`: Das aktuelle Arbeitsverzeichnis ausgeben
- `ps`: Laufende Prozesse auf dem Zielsystem auflisten (mit zusätzlichen Informationen)
- `jobs`: Alle laufenden Jobs auflisten, die mit lang laufenden Tasks verbunden sind
- `download`: Eine Datei vom Zielsystem auf den lokalen Rechner herunterladen
- `upload`: Eine Datei vom lokalen Rechner auf das Zielsystem hochladen
- `reg_query`: Registrierungsschlüssel und -werte auf dem Zielsystem abfragen
- `reg_write_value`: Einen neuen Wert in einen angegebenen Registrierungsschlüssel schreiben
- `sleep`: Das Sleep-Intervall des Agents ändern, das bestimmt, wie oft er sich beim Mythic-Server meldet
- Und viele weitere; verwende `help`, um die vollständige Liste der verfügbaren Commands anzuzeigen.

### Privilegieneskalation

- `getprivs`: So viele Privilegien wie möglich für das aktuelle Thread-Token aktivieren
- `getsystem`: Ein Handle zu winlogon öffnen und das Token duplizieren, wodurch die Privilegien effektiv auf SYSTEM-Ebene eskaliert werden
- `make_token`: Eine neue Logon-Session erstellen und auf den Agent anwenden, um die Impersonation eines anderen Benutzers zu ermöglichen
- `steal_token`: Ein primäres Token aus einem anderen Prozess stehlen, damit der Agent den Benutzer dieses Prozesses impersonieren kann
- `pth`: Pass-the-Hash-Angriff, bei dem sich der Agent mit dem NTLM-Hash eines Benutzers authentifizieren kann, ohne das Klartextpasswort zu benötigen
- `mimikatz`: Mimikatz-Commands ausführen, um Credentials, Hashes und andere sensible Informationen aus dem Speicher oder der SAM-Datenbank auszulesen
- `rev2self`: Das Token des Agents auf sein primäres Token zurücksetzen und damit die Privilegien effektiv auf das ursprüngliche Niveau zurückstufen
- `ppid`: Den Parent-Prozess für Post-Exploitation-Jobs ändern, indem eine neue Parent-Prozess-ID angegeben wird; so lässt sich der Ausführungskontext von Jobs besser kontrollieren
- `printspoofer`: PrintSpoofer-Commands ausführen, um Sicherheitsmaßnahmen des Print Spoolers zu umgehen und dadurch Privilegieneskalation oder Codeausführung zu ermöglichen
- `dcsync`: Die Kerberos-Schlüssel eines Benutzers mit dem lokalen Rechner synchronisieren, um Offline-Passwort-Cracking oder weitere Angriffe zu ermöglichen
- `ticket_cache_add`: Ein Kerberos-Ticket zur aktuellen oder einer angegebenen Logon-Session hinzufügen, um die Wiederverwendung oder Impersonation des Tickets zu ermöglichen

### Prozessausführung

- `assembly_inject`: Einen .NET-Assembly-Loader in einen Remote-Prozess injizieren
- `blockdlls`: Das Laden nicht von Microsoft signierter DLLs in Post-Exploitation-Jobs blockieren
- `execute_assembly`: Eine .NET-Assembly im Kontext des Agents ausführen
- `execute_coff`: Eine COFF-Datei im Speicher ausführen und so die Ausführung von kompiliertem Code im Speicher ermöglichen
- `execute_pe`: Eine nicht verwaltete ausführbare Datei (PE) ausführen
- `keylog_inject`: Einen Keylogger in einen anderen Prozess injizieren und Tastatureingaben in die Keylog-Ansicht von Mythic streamen
- `screenshot` / `screenshot_inject`: Den aktuellen Desktop direkt erfassen oder
  eine Screenshot-Assembly in einen Zielprozess/eine Zielsitzung injizieren
- `get_injection_techniques`: Verfügbare Injektionstechniken und die aktuell ausgewählte anzeigen
- `inline_assembly`: Eine .NET-Assembly in einer entbehrlichen AppDomain ausführen und so Code vorübergehend ausführen, ohne den Hauptprozess des Agents zu beeinflussen
- `register_assembly`: Eine .NET-Assembly für die spätere Ausführung registrieren
- `register_file`: Eine Datei im Agent-Cache für spätere `execute_*`- oder PowerShell-Tasks registrieren
- `run`: Eine Binärdatei auf dem Zielsystem ausführen und dabei den System-PATH verwenden, um die ausführbare Datei zu finden
- `set_injection_technique`: Die von Post-Exploitation-Jobs verwendete Injektionsprimitive ändern
- `shinject`: Shellcode in einen Remote-Prozess injizieren und so die Ausführung beliebigen Codes im Speicher ermöglichen
- `inject`: Agent-Shellcode in einen Remote-Prozess injizieren und so die Ausführung des Agent-Codes im Speicher ermöglichen
- `spawn`: Eine neue Agent-Session in der angegebenen ausführbaren Datei starten, um Shellcode in einem neuen Prozess auszuführen
- `spawnto_x64` und `spawnto_x86`: Die Standard-Binärdatei für Post-Exploitation-Jobs auf einen angegebenen Pfad ändern, anstatt `rundll32.exe` ohne Parameter zu verwenden, was sehr auffällig ist.

### Mythic Forge

Damit lassen sich **COFF/BOF**-Dateien aus der Mythic Forge laden, einem Repository mit vorkompilierten Payloads und Tools, die auf dem Zielsystem ausgeführt werden können. Mit allen ladbaren Commands lassen sich häufige Aktionen ausführen, indem sie als BOFs im aktuellen Agent-Prozess ausgeführt werden (üblicherweise mit besserer OPSEC als beim Starten eines separaten Prozesses).

Beginne mit der Installation:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Verwende dann `forge_collections`, um die COFF/BOF-Module aus der Mythic Forge anzuzeigen und sie auszuwählen und zur Ausführung in den Speicher des Agents zu laden. Standardmäßig werden in Apollo die folgenden 2 Collections hinzugefügt:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Sobald ein Modul geladen ist, erscheint es in der Liste als weiterer Befehl, z. B. `forge_bof_sa-whoami` oder `forge_bof_sa-netuser`.

Denke bei BOFs daran, dass Forge nicht einfach eine einzige, flache Argumentzeichenfolge an Apollo übergibt. Stattdessen ordnet Forge BOF-Parameter dem typisierten Array-Format von Mythic zu und leitet sie dann an den `execute_coff`-Ablauf von Apollo weiter. Wenn sich ein über Forge geladenes BOF ungewöhnlich verhält, überprüfe die erwarteten BOF-Argumenttypen bzw. den Entry Point, statt nur die eingegebene Befehlszeile zu prüfen. Beachte außerdem, dass sich die Argumentverarbeitung im neueren BOF-Loader von Apollo gegenüber deutlich älteren Builds aus der 2.3.1-Ära geändert hat. Veraltete BOFs oder alte Collections können daher allein deshalb fehlschlagen, weil sich die Anforderungen an das Marshaling geändert haben.

### PowerShell- und Skriptausführung

- `powershell_import`: Importiert ein neues PowerShell-Skript (.ps1) in den Agent-Cache, damit es später ausgeführt werden kann
- `powershell`: Führt einen PowerShell-Befehl im Kontext des Agents aus und ermöglicht so fortgeschrittene Skripterstellung und Automatisierung
- `powerpick`: Injiziert eine PowerShell-Loader-Assembly in einen entbehrlichen Prozess und führt einen PowerShell-Befehl aus (ohne PowerShell-Logging).
- `psinject`: Führt PowerShell in einem angegebenen Prozess aus und ermöglicht so die gezielte Ausführung von Skripten im Kontext eines anderen Prozesses
- `shell`: Führt einen Shell-Befehl im Kontext des Agents aus, ähnlich wie die Ausführung eines Befehls in cmd.exe

### Laterale Bewegung

- `jump_psexec`: Verwendet die PsExec-Technik, um sich lateral auf einen neuen Host zu bewegen, indem zunächst die ausführbare Datei des Apollo-Agents (apollo.exe) dorthin kopiert und anschließend ausgeführt wird.
- `jump_wmi`: Verwendet die WMI-Technik, um sich lateral auf einen neuen Host zu bewegen, indem zunächst die ausführbare Datei des Apollo-Agents (apollo.exe) dorthin kopiert und anschließend ausgeführt wird.
- `link` und `unlink`: Erstellen und beenden P2P-Verbindungen (z. B. über SMB/TCP) zwischen Callbacks.
- `wmiexecute`: Führt mit WMI einen Befehl auf dem lokalen oder einem angegebenen Remote-System aus, optional mit Zugangsdaten zur Impersonation.
- `net_dclist`: Ruft eine Liste der Domain Controller für die angegebene Domäne ab. Dies ist hilfreich, um potenzielle Ziele für laterale Bewegung zu identifizieren.
- `net_localgroup`: Listet lokale Gruppen auf dem angegebenen Computer auf. Wenn kein Computer angegeben ist, wird localhost verwendet.
- `net_localgroup_member`: Ruft die Mitgliedschaft einer angegebenen lokalen Gruppe auf dem lokalen oder Remote-Computer ab und ermöglicht so die Auflistung der Benutzer bestimmter Gruppen.
- `net_shares`: Listet Remote-Shares und deren Zugänglichkeit auf dem angegebenen Computer auf. Dies ist hilfreich, um potenzielle Ziele für laterale Bewegung zu identifizieren.
- `socks`: Aktiviert einen SOCKS-5-kompatiblen Proxy im Zielnetzwerk und ermöglicht so das Tunneln von Datenverkehr über den kompromittierten Host. Kompatibel mit Tools wie proxychains.
- `rpfwd`: Lauscht auf einem angegebenen Port auf dem Zielhost und leitet Datenverkehr über Mythic an eine Remote-IP-Adresse und einen Port weiter. Dadurch wird der Remote-Zugriff auf Dienste im Zielnetzwerk ermöglicht.
- `listpipes`: Listet alle Named Pipes auf dem lokalen System auf. Dies kann für laterale Bewegung oder Privilegieneskalation nützlich sein, wenn IPC-Mechanismen verwendet werden.

Informationen zu den WMI-Ausführungsprimitiven auf niedrigerer Ebene, die von `jump_wmi` oder `wmiexecute` verwendet werden, findest du unter [WmiExec](lateral-movement/wmiexec.md). Weitere Muster für Pivoting findest du unter [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Verschiedene Befehle
- `help`: Zeigt detaillierte Informationen zu bestimmten Befehlen oder allgemeine Informationen zu allen verfügbaren Befehlen im Agent an.
- `clear`: Markiert Tasks als „cleared“, sodass Agents sie nicht mehr abrufen können. Du kannst `all` angeben, um alle Tasks zu löschen, oder `task Num`, um einen bestimmten Task zu löschen.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon ist ein Golang-Agent, der für **Linux und macOS** kompiliert wird.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Hinweise zu aktuellen Builds/Profilen

- Aktuelle Poseidon-Builds zielen auf Linux und macOS auf `x86_64` und `arm64` ab.
- Zu den unterstützten Ausgabeformaten gehören native Executables sowie Shared-Library-artige Ausgaben wie `dylib` und `so`.
- Poseidon unterstützt `http`, `websocket`, `tcp` und `dynamichttp`, und aktuelle Builder bieten Multi-Egress-Einstellungen wie `egress_order` und Failover-Schwellenwerte.
- Poseidons aktuelle Capability-Metadaten werben außerdem mit Browser-Scripts, Browser-Integration für Dateien und Prozesse, interaktivem Tasking, Keylogging, Screenshots, Push C2, SOCKS, rpfwd und P2P. Damit kann Poseidon als echter Linux/macOS-Pivot-Knoten dienen und nicht nur als einfache Remote-Shell.
- Build-Optionen wie `proxy_bypass` und `garble` sind einen Blick wert, wenn du entweder ein saubereres Netzwerkverhalten oder zusätzliche Go-Binary-Obfuscation benötigst.
- `pty` ist einer der nützlichsten neueren Quality-of-Life-Befehle für Linux/macOS-Operationen, da er eine interaktive PTY öffnet und einen Mythic-seitigen Port für eine umfassendere Terminal-Interaktion bereitstellen kann, ohne auf den älteren Workaround `sleep 0` + SOCKS zurückgreifen zu müssen.
- Poseidons aktuelle Dokumentation ist besonders interessant für macOS-lastige Tradecraft: `jxa` führt JavaScript for Automation im Arbeitsspeicher aus, `screencapture` erfasst den Desktop des angemeldeten Benutzers, `clipboard_monitor` streamt Änderungen im Pasteboard, `execute_library` lädt eine lokale dylib und ruft eine Funktion daraus auf, und `libinject` zwingt einen Remote-Prozess dazu, eine dylib von der Festplatte zu laden.
- Bei lang laufenden Jobs solltest du beachten, dass Poseidon Post-Exploitation-Aufgaben in kooperativen Goroutinen/Threads ausführt, die sich nicht hart beenden lassen. Die Dokumentation weist außerdem ausdrücklich darauf hin, dass es derzeit keine integrierte Agent-Obfuscation gibt. Daher ist Tradecraft auf Build-/Profilebene wichtiger als bei stark obfuskierten kommerziellen Implants.

Für macOS-spezifisches Tradecraft rund um Mythic-gestützte Operationen, JAMF-Missbrauch oder MDM-as-C2-Ideen siehe [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Bei Verwendung unter Linux oder macOS bietet es einige interessante Befehle:

### Häufige Aktionen

- `cat`: Gibt den Inhalt einer Datei aus
- `cd`: Ändert das aktuelle Arbeitsverzeichnis
- `chmod`: Ändert die Berechtigungen einer Datei
- `config`: Zeigt die aktuelle Konfiguration und Host-Informationen an
- `cp`: Kopiert eine Datei von einem Ort an einen anderen
- `curl`: Führt eine einzelne Webanfrage mit optionalen Headern und Methode aus
- `upload`: Lädt eine Datei auf das Ziel hoch
- `download`: Lädt eine Datei vom Zielsystem auf den lokalen Rechner herunter
- Und vieles mehr

### Suche nach sensiblen Informationen

- `triagedirectory`: Findet interessante Dateien in einem Verzeichnis auf einem Host, etwa sensible Dateien oder Zugangsdaten.
- `getenv`: Ruft alle aktuellen Umgebungsvariablen ab.

### macOS-spezifisches Tradecraft

- `jxa`: Führt JavaScript for Automation über `OSAScript` im Arbeitsspeicher aus. Das ist nützlich für native macOS-Post-Exploitation, ohne separate Script-Dateien abzulegen.
- `clipboard_monitor`: Überwacht das Pasteboard und meldet Änderungen an Mythic zurück. Das ist praktisch für Workflows zum Diebstahl von Zugangsdaten/Tokens, die auf Kopieren und Einfügen beruhen.
- `screencapture`: Erfasst den Desktop des Benutzers unter macOS.
- `execute_library`: Lädt eine dylib von der Festplatte und ruft eine bestimmte exportierte Funktion auf.
- `libinject`: Injiziert einen Shellcode-Stub, der einen anderen macOS-Prozess dazu zwingt, eine dylib von der Festplatte zu laden.
- `persist_launchd`: Erstellt direkt über den Agenten eine LaunchAgent-/LaunchDaemon-Persistenz.

### Seitliche Bewegung

- `ssh`: Verbindet sich mit den angegebenen Zugangsdaten per SSH zu einem Host und öffnet eine PTY, ohne ssh zu starten.
- `sshauth`: Verbindet sich mit den angegebenen Zugangsdaten per SSH zu den angegebenen Hosts. Damit kannst du auch einen bestimmten Befehl auf den Remote-Hosts ausführen oder Dateien per SCP übertragen.
- `link_tcp`: Verbindet sich über TCP mit einem anderen Agenten und ermöglicht so die direkte Kommunikation zwischen Agenten.
- `link_webshell`: Verbindet sich über das P2P-Profil webshell mit einem Agenten und ermöglicht den Remote-Zugriff auf dessen Weboberfläche.
- `rpfwd`: Startet oder beendet eine Reverse-Port-Weiterleitung und ermöglicht so den Remote-Zugriff auf Dienste im Zielnetzwerk.
- `socks`: Startet oder beendet einen SOCKS5-Proxy im Zielnetzwerk und ermöglicht das Tunneln von Datenverkehr über den kompromittierten Host. Kompatibel mit Tools wie proxychains.
- `portscan`: Sucht auf Hosts nach offenen Ports und hilft dabei, potenzielle Ziele für seitliche Bewegung oder weitere Angriffe zu identifizieren.

### Prozessausführung

- `shell`: Führt über /bin/sh einen einzelnen Shell-Befehl aus und ermöglicht die direkte Ausführung von Befehlen auf dem Zielsystem.
- `run`: Führt einen Befehl von der Festplatte mit Argumenten aus und ermöglicht die Ausführung von Binaries oder Scripts auf dem Zielsystem.
- `pty`: Öffnet eine interaktive PTY und ermöglicht die direkte Interaktion mit der Shell auf dem Zielsystem.

## References

- [1] [Funktionsmatrix der Mythic-Community-Agents](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo-README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2: Highlights zu interaktivem Tasking, Push C2 und dynamischem Dateibrowser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser-Scripts – Mythic-Dokumentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic-Updates von 3.3 auf 3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Red-Team-Operationen mit Mythics verborgenen Schätzen transformieren: Browser-Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: YARA-Regeln für Multi_Trojan_Mythic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Vom Fork zum Framework: Was uns die Modifizierung von Apollo über Agent-Invasion gelehrt hat](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
