# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Prozessen

Ein Prozess ist eine Instanz einer laufenden ausführbaren Datei; allerdings führen Prozesse keinen Code aus, sondern Threads. Daher sind **Prozesse lediglich Container für laufende Threads**, die Speicher, Deskriptoren, Ports, Berechtigungen usw. bereitstellen.

Traditionell wurden Prozesse innerhalb anderer Prozesse gestartet (außer PID 1), indem **`fork`** aufgerufen wurde. Dadurch entstand eine exakte Kopie des aktuellen Prozesses, und anschließend rief der **Kindprozess** in der Regel **`execve`** auf, um die neue ausführbare Datei zu laden und auszuführen. Danach wurde **`vfork`** eingeführt, um diesen Vorgang ohne Speicherkopieren zu beschleunigen.\
Anschließend wurde **`posix_spawn`** eingeführt, das **`vfork`** und **`execve`** in einem Aufruf kombiniert und Flags akzeptiert:

- `POSIX_SPAWN_RESETIDS`: Effektive IDs auf reale IDs zurücksetzen
- `POSIX_SPAWN_SETPGROUP`: Prozessgruppenzugehörigkeit festlegen
- `POSUX_SPAWN_SETSIGDEF`: Standardverhalten für Signale festlegen
- `POSIX_SPAWN_SETSIGMASK`: Signalmaske festlegen
- `POSIX_SPAWN_SETEXEC`: Im selben Prozess ausführen (wie `execve`, aber mit mehr Optionen)
- `POSIX_SPAWN_START_SUSPENDED`: Angehalten starten
- `_POSIX_SPAWN_DISABLE_ASLR`: Ohne ASLR starten
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Den Nano-Allocator von libmalloc verwenden
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` `rwx` für Datensegmente erlauben
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Standardmäßig alle Dateibeschreibungen bei exec(2) schließen
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Die hohen Bits des ASLR-Slides randomisieren

Außerdem akzeptiert `posix_spawn` Einstellungen für **`posix_spawnattr`**, die Aspekte des gestarteten Prozesses steuern, sowie Einträge für **`posix_spawn_file_actions`**, die Dateideskriptoren ändern.

Wenn ein Prozess beendet wird, sendet er den **Rückgabecode an den Elternprozess** (wenn der Elternprozess beendet wurde, ist der neue Elternprozess PID 1) und löst das Signal `SIGCHLD` aus. Der Elternprozess muss diesen Wert mit `wait4()` oder `waitid()` abrufen. Bis dahin verbleibt der Kindprozess in einem Zombie-Zustand: Er wird weiterhin aufgelistet, verbraucht aber keine Ressourcen.

### PIDs

PIDs (Prozesskennungen) identifizieren jeweils einen eindeutigen Prozess. In XNU sind **PIDs** 64-Bit-Werte, die monoton ansteigen und **niemals überlaufen** (um Missbrauch zu verhindern).

### Prozessgruppen, Sitzungen und Koalitionen

**Prozesse** können in **Gruppen** zusammengefasst werden, um ihre Verwaltung zu erleichtern. Beispielsweise befinden sich Befehle in einem Shell-Skript in derselben Prozessgruppe, sodass sie etwa mit `kill` **gemeinsam signalisiert** werden können.\
Es ist auch möglich, **Prozesse in Sitzungen zu gruppieren**. Wenn ein Prozess eine Sitzung startet (`setsid(2)`), werden seine Kindprozesse dieser Sitzung zugeordnet, sofern sie keine eigene Sitzung starten.

Eine Koalition ist eine weitere Möglichkeit, Prozesse in Darwin zu gruppieren. Wenn ein Prozess einer Koalition beitritt, kann er auf Pool-Ressourcen zugreifen, ein Ledger gemeinsam nutzen oder von Jetsam betroffen sein. Koalitionen haben verschiedene Rollen: Leader, XPC-Dienst und Extension.

### Anmeldedaten und Personae

Jeder Prozess verfügt über **Anmeldedaten**, die seine **Berechtigungen** im System festlegen. Jeder Prozess hat eine primäre `uid` und eine primäre `gid` (kann aber mehreren Gruppen angehören).\
Es ist auch möglich, die Benutzer- und Gruppen-ID zu ändern, wenn die Binärdatei das Bit `setuid/setgid` gesetzt hat.\
Es gibt mehrere Funktionen, um **neue UIDs/GIDs festzulegen**.

Der Systemaufruf **`persona`** stellt einen **alternativen** Satz von **Anmeldedaten** bereit. Wenn ein Prozess eine Persona annimmt, übernimmt er deren UID, GID und Gruppenzugehörigkeiten **gleichzeitig**. Im [**Quellcode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) ist folgende Struktur zu finden:

```c
struct kpersona_info { uint32_t persona_info_version;
    uid_t    persona_id; /* overlaps with UID */
    int      persona_type;
    gid_t    persona_gid;
    uint32_t persona_ngroups;
    gid_t    persona_groups[NGROUPS];
    uid_t    persona_gmuid;
    char     persona_name[MAXLOGNAME + 1];

    /* TODO: MAC policies?! */
}
```

## Grundlegende Informationen zu Threads

1. **POSIX Threads (pthreads):** macOS unterstützt POSIX-Threads (`pthreads`), die Teil einer standardisierten Threading-API für C/C++ sind. Die Implementierung von pthreads in macOS befindet sich in `/usr/lib/system/libsystem_pthread.dylib` und stammt aus dem öffentlich verfügbaren Projekt `libpthread`. Diese Bibliothek stellt die erforderlichen Funktionen zum Erstellen und Verwalten von Threads bereit.
2. **Threads erstellen:** Die Funktion `pthread_create()` wird verwendet, um neue Threads zu erstellen. Intern ruft diese Funktion `bsdthread_create()` auf, einen Low-Level-Systemaufruf speziell für den XNU-Kernel (den Kernel, auf dem macOS basiert). Dieser Systemaufruf übernimmt verschiedene Flags, die von `pthread_attr` (Attributen) abgeleitet werden und das Verhalten des Threads festlegen, einschließlich der Scheduling-Richtlinien und der Stack-Größe.
   - **Standard-Stack-Größe:** Die Standard-Stack-Größe für neue Threads beträgt 512 KB. Das ist für typische Vorgänge ausreichend, kann aber über Thread-Attribute angepasst werden, wenn mehr oder weniger Speicherplatz benötigt wird.
3. **Thread-Initialisierung:** Die Funktion `__pthread_init()` spielt bei der Thread-Einrichtung eine wichtige Rolle. Sie verwendet das Argument `env[]`, um Umgebungsvariablen auszulesen, die beispielsweise Angaben zur Position und Größe des Stacks enthalten können.

#### Thread-Beendigung in macOS

1. **Threads beenden:** Threads werden üblicherweise durch den Aufruf von `pthread_exit()` beendet. Diese Funktion ermöglicht es einem Thread, kontrolliert zu enden, notwendige Bereinigungen durchzuführen und einen Rückgabewert an alle Threads zurückzugeben, die auf ihn warten.
2. **Thread-Bereinigung:** Beim Aufruf von `pthread_exit()` wird die Funktion `pthread_terminate()` aufgerufen, die alle zugehörigen Thread-Strukturen entfernt. Sie gibt Mach-Thread-Ports frei (Mach ist das Kommunikationssubsystem im XNU-Kernel) und ruft `bsdthread_terminate` auf, einen Systemaufruf, der die zum Thread gehörenden Strukturen auf Kernel-Ebene entfernt.

#### Synchronisierungsmechanismen

macOS stellt verschiedene Synchronisierungsprimitiven bereit, um den Zugriff auf gemeinsam genutzte Ressourcen zu verwalten und Race Conditions zu vermeiden. Diese sind in Multithreading-Umgebungen entscheidend, um die Datenintegrität und Systemstabilität sicherzustellen:

1. **Mutexes:**
   - **Regulärer Mutex (Signatur: 0x4D555458):** Standard-Mutex mit einem Speicherbedarf von 60 Byte (56 Byte für den Mutex und 4 Byte für die Signatur).
   - **Fast Mutex (Signatur: 0x4d55545A):** Ähnlich wie ein regulärer Mutex, aber für schnellere Vorgänge optimiert; ebenfalls 60 Byte groß.
2. **Condition Variables:**
   - Werden verwendet, um auf bestimmte Bedingungen zu warten. Sie sind 44 Byte groß (40 Byte plus eine 4-Byte-Signatur).
   - **Condition-Variable-Attribute (Signatur: 0x434e4441):** Konfigurationsattribute für Condition Variables, 12 Byte groß.
3. **Once-Variable (Signatur: 0x4f4e4345):**
   - Stellt sicher, dass ein Initialisierungscode nur einmal ausgeführt wird. Sie ist 12 Byte groß.
4. **Read-Write-Locks:**
   - Ermöglichen mehreren Lesern oder jeweils einem Schreiber den Zugriff und sorgen so für einen effizienten Zugriff auf gemeinsam genutzte Daten.
   - **Read-Write-Lock (Signatur: 0x52574c4b):** 196 Byte groß.
   - **Read-Write-Lock-Attribute (Signatur: 0x52574c41):** Attribute für Read-Write-Locks, 20 Byte groß.

> [!TIP]
> Die letzten 4 Byte dieser Objekte werden verwendet, um Überläufe zu erkennen.

### Thread-lokale Variablen (TLV)

**Thread-lokale Variablen (TLV)** werden im Kontext von Mach-O-Dateien (dem Format für ausführbare Dateien in macOS) verwendet, um Variablen zu deklarieren, die in einer Multithread-Anwendung **für jeden Thread spezifisch** sind. Dadurch erhält jeder Thread eine eigene Instanz einer Variablen. So lassen sich Konflikte vermeiden und die Datenintegrität wahren, ohne explizite Synchronisierungsmechanismen wie Mutexes zu benötigen.

In C und verwandten Sprachen können Sie eine thread-lokale Variable mit dem Schlüsselwort **`__thread`** deklarieren. So funktioniert es in Ihrem Beispiel:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Dieser Ausschnitt definiert `tlv_var` als threadlokale Variable. Jeder Thread, der diesen Code ausführt, hat eine eigene `tlv_var`. Änderungen, die ein Thread an `tlv_var` vornimmt, wirken sich nicht auf `tlv_var` in anderen Threads aus.

In der Mach-O-Binärdatei sind die Daten zu threadlokalen Variablen in bestimmten Sections organisiert:

- **`__DATA.__thread_vars`**: Diese Section enthält Metadaten zu den threadlokalen Variablen, etwa deren Typen und Initialisierungsstatus.
- **`__DATA.__thread_bss`**: Diese Section wird für threadlokale Variablen verwendet, die nicht explizit initialisiert sind. Sie ist Teil des für nullinitialisierte Daten reservierten Speichers.

Mach-O stellt außerdem eine spezielle API namens **`tlv_atexit`** bereit, um threadlokale Variablen beim Beenden eines Threads zu verwalten. Mit dieser API kannst du **Destruktoren registrieren** – spezielle Funktionen, die threadlokale Daten bereinigen, wenn ein Thread beendet wird.

### Thread-Prioritäten

Um Thread-Prioritäten zu verstehen, muss man sich ansehen, wie das Betriebssystem entscheidet, welche Threads wann ausgeführt werden. Diese Entscheidung hängt von der jedem Thread zugewiesenen Prioritätsstufe ab. In macOS und Unix-ähnlichen Systemen kommen dabei Konzepte wie `nice`, `renice` und Quality-of-Service-Klassen (QoS) zum Einsatz.

#### Nice und Renice

1. **Nice:**
   - Der `nice`-Wert eines Prozesses beeinflusst dessen Priorität. Jeder Prozess hat einen `nice`-Wert zwischen -20 (höchste Priorität) und 19 (niedrigste Priorität). Der Standardwert bei der Erstellung eines Prozesses ist in der Regel 0.
   - Ein niedrigerer `nice`-Wert (näher an -20) macht einen Prozess „eigennütziger“: Er erhält im Vergleich zu Prozessen mit höheren `nice`-Werten mehr CPU-Zeit.
2. **Renice:**
   - Mit dem Befehl `renice` lässt sich der `nice`-Wert eines bereits laufenden Prozesses ändern. So kann die Priorität von Prozessen dynamisch angepasst und abhängig vom neuen `nice`-Wert ihre CPU-Zuteilung erhöht oder verringert werden.
   - Benötigt ein Prozess beispielsweise vorübergehend mehr CPU-Ressourcen, kannst du seinen `nice`-Wert mit `renice` senken.

#### Quality-of-Service-Klassen (QoS)

QoS-Klassen sind ein modernerer Ansatz zur Verwaltung von Thread-Prioritäten, insbesondere auf Systemen wie macOS, die **Grand Central Dispatch (GCD)** unterstützen. Entwickler können damit Aufgaben je nach Wichtigkeit oder Dringlichkeit in verschiedene Kategorien **einteilen**. macOS verwaltet die Thread-Priorisierung anhand dieser QoS-Klassen automatisch:

1. **User Interactive:**
   - Diese Klasse ist für Aufgaben vorgesehen, die gerade mit dem Benutzer interagieren oder sofortige Ergebnisse erfordern, damit eine gute Benutzererfahrung gewährleistet ist. Diese Aufgaben erhalten die höchste Priorität, damit die Oberfläche reaktionsfähig bleibt (z. B. Animationen oder Ereignisverarbeitung).
2. **User Initiated:**
   - Aufgaben, die der Benutzer startet und für die er sofortige Ergebnisse erwartet, etwa das Öffnen eines Dokuments oder das Klicken auf eine Schaltfläche, die Berechnungen auslöst. Sie haben eine hohe Priorität, aber eine niedrigere als User Interactive.
3. **Utility:**
   - Diese Aufgaben laufen lange und zeigen typischerweise einen Fortschrittsindikator an (z. B. beim Herunterladen von Dateien oder Importieren von Daten). Sie haben eine niedrigere Priorität als vom Benutzer initiierte Aufgaben und müssen nicht sofort abgeschlossen werden.
4. **Background:**
   - Diese Klasse ist für Aufgaben vorgesehen, die im Hintergrund laufen und für den Benutzer nicht sichtbar sind, etwa Indizierung, Synchronisierung oder Backups. Sie haben die niedrigste Priorität und wirken sich möglichst wenig auf die Systemleistung aus.

QoS-Klassen ersparen Entwicklern die Verwaltung konkreter Prioritätswerte. Stattdessen können sie sich auf die Art der Aufgabe konzentrieren, während das System die CPU-Ressourcen entsprechend optimiert.

Außerdem gibt es verschiedene **Thread-Scheduling-Richtlinien**, mit denen sich Scheduling-Parameter festlegen lassen, die der Scheduler berücksichtigt. Dazu kann `thread_policy_[set/get]` verwendet werden. Das kann bei Race-Condition-Angriffen nützlich sein.

## macOS Process Abuse

macOS bietet zahlreiche Mechanismen, mit denen **Prozesse interagieren, kommunizieren und Daten austauschen** können. Diese Mechanismen sind für den normalen Systembetrieb unerlässlich, können von Angreifern aber für Injection, Codeausführung oder Datenzugriff missbraucht werden.

### Library Injection

Library Injection ist eine Technik, bei der ein Angreifer **einen Prozess zum Laden einer bösartigen Library zwingt**. Nach der Injection läuft die Library im Kontext des Zielprozesses und gewährt dem Angreifer dieselben Berechtigungen und Zugriffsrechte wie dem Prozess.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Beim Function Hooking werden Funktionsaufrufe oder Nachrichten innerhalb eines Softwarecodes **abgefangen**. Durch das Hooking von Funktionen kann ein Angreifer **das Verhalten** eines Prozesses verändern, sensible Daten beobachten oder sogar den Ausführungsablauf kontrollieren.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Diese Seite behandelt ARM64-Unwind-Metadaten, arm64e-PAC-Einschränkungen und synthetische Call-Chains.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) bezeichnet verschiedene Methoden, mit denen getrennte Prozesse **Daten austauschen und gemeinsam nutzen**. IPC ist zwar für viele legitime Anwendungen grundlegend, kann aber auch missbraucht werden, um die Prozessisolation zu umgehen, sensible Informationen zu leaken oder unbefugte Aktionen auszuführen.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-Anwendungen, die mit bestimmten Umgebungsvariablen ausgeführt werden, können für Process Injection anfällig sein:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Mit den Flags `--load-extension` und `--use-fake-ui-for-media-stream` lässt sich ein **man in the browser attack** durchführen, um Tastenanschläge, Datenverkehr und Cookies zu stehlen, Scripts in Seiten einzuschleusen usw.:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-Dateien **definieren Elemente der Benutzeroberfläche (UI)** und deren Interaktionen innerhalb einer Anwendung. Sie können jedoch **beliebige Befehle ausführen**, und **Gatekeeper verhindert nicht**, dass eine bereits ausgeführte Anwendung erneut gestartet wird, wenn eine **NIB-Datei geändert wurde**. Sie können daher dazu verwendet werden, beliebige Programme beliebige Befehle ausführen zu lassen:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Über **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** oder **`JDK_JAVA_OPTIONS`** lassen sich JVM-Optionen einschleusen und ein Java- oder nativer Agent laden, bevor die Anwendung startet.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** lädt über `--require` (Datei) oder `--import data:text/javascript,…` (dateilos, Node ≥ 20.6) vorab JavaScript des Angreifers; **`NODE_REPL_EXTERNAL_MODULE`** lädt ein Modul in eine interaktive REPL, und **`ELECTRON_RUN_AS_NODE`** aktiviert all dies erneut für Electron-Binärdateien.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Code lässt sich über **`DOTNET_STARTUP_HOOKS`** vor `Main` in .NET-Anwendungen einschleusen oder durch Missbrauch der .NET-Debugging-Funktionalität ausführen, sofern deren Voraussetzungen erfüllt sind.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nichtinteraktive Bash liest **`BASH_ENV`**; interaktive POSIX-Shells lesen **`ENV`**; zsh liest **`$ZDOTDIR/.zshenv`**; und fish liest Konfigurationen unter **`XDG_CONFIG_HOME`** oder **`XDG_DATA_DIRS`**. Jede davon kann vor dem vorgesehenen Befehl eine kontrollierte Startdatei ausführen. Bash führt außerdem eine Command Substitution in **`PS4`** aus, sobald xtrace aktiviert ist (z. B. durch geerbtes **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Wird `/bin/zsh -s` gestartet, liest die Shell ein Programm von der Standardeingabe. Ein Downloader, der ein nicht vertrauenswürdiges strukturiertes Dokument ohne vorherige Auswertung in die stdin des Kindprozesses kopiert, übergibt damit das gesamte Dokument als Shell-Quelltext. Bei einem beobachteten Loader wurde eine öffentliche iCalendar-Datei zeilenweise über eine anonyme Pipe eingelesen. Die Kalender-Metadaten schlugen als Befehle fehl, doch zsh lief weiter, bis es ausführbare Zeilen nach `DESCRIPTION:` erreichte. Diese Zeilen luden das nächste Application Bundle herunter und starteten es. Der erwartete Inhaltstyp und ein vertrauenswürdiger Hosting-Anbieter machten dies nicht sicher; die gefährliche Grenze war die Übergabe der Bytes an einen Interpreter.<sup>[[5]](#references)</sup>

Verwandte Schritte werden in [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) und [macOS auto-start locations](../../macos-auto-start-locations.md) behandelt.

### PHP Injection

**`PHPRC`** oder **`PHP_INI_SCAN_DIR`** können eine kontrollierte PHP-Konfiguration laden, deren **`auto_prepend_file`** vor dem Zielskript ausgeführt wird.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Der eigenständige Lua-Interpreter führt vor der Verarbeitung des Zielskripts Code oder eine `@file` aus **`LUA_INIT`** (oder dessen versionsspezifischer Variante) aus.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** und **`R_PROFILE`** leiten auf Startprofile mit R-Code um. Über **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** und einen R-Library-Pfad kann stattdessen automatisch ein installiertes Package geladen werden.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** leitet auf das Depot um, dessen `config/startup.jl` automatisch ausgeführt wird.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

Über **`ERL_AFLAGS`**, **`ERL_FLAGS`** oder **`ERL_ZFLAGS`** lässt sich ein Erlang-VM-Ausdruck mit **`-eval`** einschleusen, ohne eine Payload-Datei zu benötigen; Elixir-Workloads starten häufig dieselbe VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** und **`OCTAVE_VERSION_INITFILE`** leiten auf Octave-Startskripte um.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` ist eine plattformübergreifende .NET-App. Daher ermöglichen mehrere Umgebungsvariablen die Ausführung von Code vor dem Befehl: **`XDG_CONFIG_HOME`** leitet die beim Start ausgeführten Profilscripts um, **`PSModulePath`** ermöglicht das Hijacking des automatischen Ladens von Modulen (ein platziertes `.psm1` wird beim Import ausgeführt und kann integrierte Cmdlets überschreiben), und die .NET-Variablen **`CORECLR_PROFILER`**/**`COR_PROFILER`** sowie **`DOTNET_STARTUP_HOOKS`** laden den Code des Angreifers vor `Main` in den Prozess.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Sieh dir die verschiedenen Möglichkeiten an, mit denen ein Perl-Script beliebigen Code ausführen kann:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Es ist auch möglich, Ruby-Umgebungsvariablen (**`RUBYOPT`**, **`RUBYLIB`**) zu missbrauchen, damit beliebige Scripts beliebigen Code ausführen:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die Standardbibliothekskette **`PYTHONWARNINGS`** und **`BROWSER`** kann beim Parsen von Warnungsfiltern einen Befehl ausführen. Eine dateibasierte Alternative platziert `sitecustomize.py` in **`PYTHONPATH`**, sodass es während der normalen `site`-Initialisierung vor dem Zielskript importiert wird. **`PYTHONBREAKPOINT`** führt ein ausgewähltes Callable/Modul aus, wenn der Code `breakpoint()` erreicht. Nur interaktive Variablen wie **`PYTHONSTARTUP`** sind weniger breit anwendbar.

Beachte, dass mit **`pyinstaller`** kompilierte Executables diese Umgebungsvariablen nicht verwenden, selbst wenn sie mit einem eingebetteten Python ausgeführt werden.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (und als Fallback `EXINIT`) werden beim normalen Start als Ex-Befehle ausgeführt. Daher ermöglichen `:!cmd` / `:call system(...)` die Codeausführung, wenn ein Opfer Vim/Neovim mit einer kontrollierten Umgebung öffnet:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Unabhängig davon installiert Homebrew Python häufig unter `/opt/homebrew`, wo Mitglieder der lokalen Gruppe `admin` möglicherweise den Launcher ersetzen können. Dabei handelt es sich um ein Hijacking einer beschreibbaren Binärdatei und nicht um eine Injection über Umgebungsvariablen. Prüfe Eigentümerschaft und ACLs, bevor du dies als ausnutzbar einstufst.


## Erkennung

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ist eine Open-Source-Anwendung auf Basis von **EndpointSecurity**, die Process Injection erkennt und blockiert. Sie ist eine gute Referenz dafür, welche Signale über Endpoint Security beobachtbar sind, da sie auf Folgendes aufmerksam macht:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-Umgebungsvariablen** beim Prozessstart: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` und `ELECTRON_RUN_AS_NODE`.
- Aufrufe von **`task_for_pid`** – ein Prozess fordert den Task-Port eines anderen Prozesses an, was Voraussetzung für eine Injection in diesen Prozess ist.
- **Electron-Debugging-Argumente** – `--inspect`, `--inspect-brk` und `--remote-debugging-port`, die eine Electron-App im Debug-Modus starten und beliebigen Personen ermöglichen, eine Verbindung herzustellen und darin Code auszuführen.<sup>[[3]](#references)</sup>
- **Erstellung von Symlinks/Hardlinks über Berechtigungsgrenzen hinweg** – die klassische Methode „als normaler Benutzer einen Link anlegen und auf einen privilegierten Speicherort verweisen“. Beachte, dass **Symlinks zwar erkannt, aber nicht blockiert werden können**: EndpointSecurity stellt das Linkziel vor der Erstellung nicht bereit.

### Aufrufe anderer Prozesse

In [**diesem Blogbeitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) erfährst du, wie sich mit der Funktion **`task_name_for_pid`** Informationen über andere **Prozesse abrufen lassen, die Code in einen Prozess einschleusen**, und anschließend Informationen über den jeweiligen Prozess ermittelt werden können.<sup>[[4]](#references)</sup>

Beachte, dass du zum Aufrufen dieser Funktion dieselbe UID wie der Prozess oder **root** benötigst (und sie Informationen über den Prozess zurückgibt, aber keine Möglichkeit zur Code-Injection bietet).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — Open-Source-Erkennung von macOS-Process-Injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-Framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Warum Electron-Apps deine Secrets nicht vertraulich speichern können: die Option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Erkennung von Task-Modifikationen](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Eine neue Version des MacSync-macOS-Stealers zielt auf Krypto-Enthusiasten und Entwickler ab](https://securelist.com/macsync-new-version/121383/)
