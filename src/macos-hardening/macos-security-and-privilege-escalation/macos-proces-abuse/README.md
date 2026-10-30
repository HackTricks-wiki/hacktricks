# Missbrauch von macOS-Prozessen

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Prozessen

Ein Prozess ist eine Instanz einer laufenden ausführbaren Datei. Prozesse führen jedoch keinen Code aus, sondern Threads. Daher sind **Prozesse lediglich Container für laufende Threads**, die Speicher, Deskriptoren, Ports, Berechtigungen usw. bereitstellen.

Traditionell wurden Prozesse innerhalb anderer Prozesse gestartet (außer PID 1), indem **`fork`** aufgerufen wurde. Dadurch wurde eine exakte Kopie des aktuellen Prozesses erstellt, und anschließend rief der **Kindprozess** üblicherweise **`execve`** auf, um die neue ausführbare Datei zu laden und auszuführen. Danach wurde **`vfork`** eingeführt, um diesen Vorgang ohne Kopieren des Speichers zu beschleunigen.\
Anschließend wurde **`posix_spawn`** eingeführt, das **`vfork`** und **`execve`** in einem Aufruf kombiniert und Flags akzeptiert:

- `POSIX_SPAWN_RESETIDS`: Effektive IDs auf reale IDs zurücksetzen
- `POSIX_SPAWN_SETPGROUP`: Zugehörigkeit zur Prozessgruppe festlegen
- `POSUX_SPAWN_SETSIGDEF`: Standardverhalten für Signale festlegen
- `POSIX_SPAWN_SETSIGMASK`: Signalmaske festlegen
- `POSIX_SPAWN_SETEXEC`: Im selben Prozess ausführen (wie `execve`, aber mit mehr Optionen)
- `POSIX_SPAWN_START_SUSPENDED`: Angehalten starten
- `_POSIX_SPAWN_DISABLE_ASLR`: Ohne ASLR starten
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Den Nano-Allocator von libmalloc verwenden
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` `rwx` für Datensegmente erlauben
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Standardmäßig alle Dateideskriptoren bei exec(2) schließen
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Die hohen Bits des ASLR-Slides randomisieren

Außerdem akzeptiert `posix_spawn` **`posix_spawnattr`**-Einstellungen, die Aspekte des gestarteten Prozesses steuern, sowie **`posix_spawn_file_actions`**-Einträge, die Dateideskriptoren ändern.

Wenn ein Prozess beendet wird, sendet er den **Rückgabecode an den Elternprozess** (falls der Elternprozess beendet wurde, ist PID 1 der neue Elternprozess) und das Signal `SIGCHLD`. Der Elternprozess muss diesen Wert mit `wait4()` oder `waitid()` abrufen. Bis dahin verbleibt der Kindprozess in einem Zombie-Zustand: Er wird weiterhin aufgelistet, verbraucht aber keine Ressourcen.

### PIDs

PIDs (Prozesskennungen) identifizieren einen einzelnen Prozess. In XNU sind **PIDs** **64 Bit** groß, steigen monoton an und **laufen niemals über** (um Missbrauch zu verhindern).

### Prozessgruppen, Sitzungen und Koalitionen

**Prozesse** können in **Gruppen** zusammengefasst werden, um ihre Verwaltung zu vereinfachen. Beispielsweise befinden sich Befehle in einem Shell-Skript in derselben Prozessgruppe, sodass sie etwa mit `kill` **gemeinsam signalisiert** werden können.\
Prozesse können auch **in Sitzungen gruppiert** werden. Wenn ein Prozess eine Sitzung startet (`setsid(2)`), werden die Kindprozesse dieser Sitzung zugeordnet, sofern sie keine eigene Sitzung starten.

Koalitionen bieten in Darwin eine weitere Möglichkeit, Prozesse zu gruppieren. Wenn ein Prozess einer Koalition beitritt, kann er auf Pool-Ressourcen zugreifen, ein Ledger gemeinsam nutzen oder von Jetsam betroffen sein. Koalitionen haben verschiedene Rollen: Leader, XPC service, Extension.

### Anmeldedaten und Personas

Jeder Prozess besitzt **Anmeldedaten**, die seine **Berechtigungen** im System festlegen. Jeder Prozess hat eine primäre `uid` und eine primäre `gid` (kann aber mehreren Gruppen angehören).\
Die Benutzer- und Gruppen-ID lässt sich auch ändern, wenn die Binärdatei das Bit `setuid/setgid` gesetzt hat.\
Es gibt mehrere Funktionen, um **neue UIDs/GIDs festzulegen**.

Der Systemaufruf **`persona`** stellt einen alternativen Satz von **Anmeldedaten** bereit. Durch die Übernahme einer Persona werden deren UID, GID und Gruppenmitgliedschaften **gleichzeitig** angenommen. Im [**Quellcode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) lässt sich folgende Struktur finden:

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
2. **Threads erstellen:** Mit der Funktion `pthread_create()` werden neue Threads erstellt. Intern ruft diese Funktion `bsdthread_create()` auf, einen Low-Level-Systemaufruf speziell für den XNU-Kernel (den Kernel, auf dem macOS basiert). Dieser Systemaufruf akzeptiert verschiedene Flags aus `pthread_attr` (Attributen), die das Verhalten des Threads festlegen, einschließlich Scheduling-Richtlinien und Stackgröße.
   - **Standard-Stackgröße:** Die Standard-Stackgröße für neue Threads beträgt 512 KB. Das reicht für typische Vorgänge aus, kann aber über Thread-Attribute angepasst werden, wenn mehr oder weniger Speicher benötigt wird.
3. **Thread-Initialisierung:** Die Funktion `__pthread_init()` ist während der Thread-Einrichtung entscheidend. Sie verwendet das Argument `env[]`, um Umgebungsvariablen auszuwerten, die Angaben zum Speicherort und zur Größe des Stacks enthalten können.

#### Thread-Beendigung in macOS

1. **Threads beenden:** Threads werden normalerweise durch den Aufruf von `pthread_exit()` beendet. Diese Funktion ermöglicht es einem Thread, sauber zu beenden, notwendige Aufräumarbeiten durchzuführen und einen Rückgabewert an wartende Threads zu übermitteln.
2. **Thread-Aufräumarbeiten:** Beim Aufruf von `pthread_exit()` wird die Funktion `pthread_terminate()` aufgerufen, die alle zugehörigen Thread-Strukturen entfernt. Sie gibt Mach-Thread-Ports frei (Mach ist das Kommunikationssubsystem im XNU-Kernel) und ruft `bsdthread_terminate` auf, einen Systemaufruf, der die mit dem Thread verbundenen Strukturen auf Kernel-Ebene entfernt.

#### Synchronisierungsmechanismen

Um den Zugriff auf gemeinsam genutzte Ressourcen zu verwalten und Race Conditions zu vermeiden, bietet macOS mehrere Synchronisierungsprimitive. Diese sind in Multithreading-Umgebungen entscheidend, um die Datenintegrität und Systemstabilität sicherzustellen:

1. **Mutexe:**
   - **Regulärer Mutex (Signatur: 0x4D555458):** Standard-Mutex mit einem Speicherbedarf von 60 Bytes (56 Bytes für den Mutex und 4 Bytes für die Signatur).
   - **Fast Mutex (Signatur: 0x4d55545A):** Ähnlich wie ein regulärer Mutex, aber für schnellere Vorgänge optimiert; ebenfalls 60 Bytes groß.
2. **Condition Variables:**
   - Dienen dazu, auf das Eintreten bestimmter Bedingungen zu warten. Sie sind 44 Bytes groß (40 Bytes plus eine 4-Byte-Signatur).
   - **Attribute von Condition Variables (Signatur: 0x434e4441):** Konfigurationsattribute für Condition Variables, 12 Bytes groß.
3. **Once Variable (Signatur: 0x4f4e4345):**
   - Stellt sicher, dass ein Initialisierungscode nur einmal ausgeführt wird. Sie ist 12 Bytes groß.
4. **Read-Write Locks:**
   - Ermöglichen mehrere Leser oder jeweils einen Schreiber und sorgen so für einen effizienten Zugriff auf gemeinsam genutzte Daten.
   - **Read-Write-Lock (Signatur: 0x52574c4b):** 196 Bytes groß.
   - **Attribute von Read-Write-Locks (Signatur: 0x52574c41):** Attribute für Read-Write-Locks, 20 Bytes groß.

> [!TIP]
> Die letzten 4 Bytes dieser Objekte werden verwendet, um Überläufe zu erkennen.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** werden im Kontext von Mach-O-Dateien (dem Format für ausführbare Dateien in macOS) verwendet, um Variablen zu deklarieren, die in einer Multithread-Anwendung **für jeden Thread** spezifisch sind. Dadurch erhält jeder Thread eine eigene Instanz der Variablen. So lassen sich Konflikte vermeiden und die Datenintegrität sicherstellen, ohne explizite Synchronisierungsmechanismen wie Mutexe zu benötigen.

In C und verwandten Sprachen kann eine Thread-Local-Variable mit dem Schlüsselwort **`__thread`** deklariert werden. So funktioniert es im folgenden Beispiel:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Dieser Ausschnitt definiert `tlv_var` als thread-local Variable. Jeder Thread, der diesen Code ausführt, hat eine eigene `tlv_var`. Änderungen, die ein Thread an `tlv_var` vornimmt, wirken sich nicht auf `tlv_var` in einem anderen Thread aus.

In der Mach-O-Binärdatei sind die Daten zu thread-local Variablen in bestimmten Sections organisiert:

- **`__DATA.__thread_vars`**: Diese Section enthält Metadaten zu den thread-local Variablen, etwa deren Typen und Initialisierungsstatus.
- **`__DATA.__thread_bss`**: Diese Section wird für thread-local Variablen verwendet, die nicht explizit initialisiert werden. Sie ist Teil des Speichers, der für mit Nullen initialisierte Daten reserviert ist.

Mach-O bietet außerdem eine spezielle API namens **`tlv_atexit`**, um thread-local Variablen beim Beenden eines Threads zu verwalten. Mit dieser API lassen sich **Destruktoren registrieren** – spezielle Funktionen, die thread-local Daten bereinigen, wenn ein Thread beendet wird.

### Thread-Prioritäten

Um Thread-Prioritäten zu verstehen, muss man sich ansehen, wie das Betriebssystem entscheidet, welche Threads wann ausgeführt werden. Diese Entscheidung wird von der jedem Thread zugewiesenen Prioritätsstufe beeinflusst. In macOS und Unix-ähnlichen Systemen geschieht dies mithilfe von Konzepten wie `nice`, `renice` und Quality of Service (QoS)-Klassen.

#### Nice und Renice

1. **Nice:**
   - Der `nice`-Wert eines Prozesses ist eine Zahl, die seine Priorität beeinflusst. Jeder Prozess hat einen `nice`-Wert zwischen -20 (höchste Priorität) und 19 (niedrigste Priorität). Der Standardwert für einen neu erstellten Prozess ist üblicherweise 0.
   - Ein niedrigerer `nice`-Wert (näher an -20) macht einen Prozess „eigennütziger“ und verschafft ihm im Vergleich zu Prozessen mit höheren `nice`-Werten mehr CPU-Zeit.
2. **Renice:**
   - `renice` ist ein Befehl, mit dem sich der `nice`-Wert eines bereits laufenden Prozesses ändern lässt. Damit kann die Priorität von Prozessen dynamisch angepasst und ihre CPU-Zuteilung anhand der neuen `nice`-Werte erhöht oder verringert werden.
   - Benötigt ein Prozess beispielsweise vorübergehend mehr CPU-Ressourcen, kann man seinen `nice`-Wert mit `renice` senken.

#### Quality of Service (QoS)-Klassen

QoS-Klassen sind ein modernerer Ansatz für die Verwaltung von Thread-Prioritäten, insbesondere auf Systemen wie macOS, die **Grand Central Dispatch (GCD)** unterstützen. Mit QoS-Klassen können Entwickler Arbeit anhand ihrer Wichtigkeit oder Dringlichkeit in verschiedene Stufen **einordnen**. macOS verwaltet die Thread-Priorisierung automatisch anhand dieser QoS-Klassen:

1. **User Interactive:**
   - Diese Klasse ist für Aufgaben vorgesehen, die gerade mit dem Benutzer interagieren oder sofortige Ergebnisse erfordern, um eine gute Benutzererfahrung zu ermöglichen. Diese Aufgaben erhalten die höchste Priorität, damit die Benutzeroberfläche reaktionsfähig bleibt (z. B. Animationen oder Ereignisbehandlung).
2. **User Initiated:**
   - Aufgaben, die der Benutzer startet und für die er sofortige Ergebnisse erwartet, etwa das Öffnen eines Dokuments oder ein Klick auf eine Schaltfläche, der Berechnungen erfordert. Sie haben eine hohe Priorität, liegen aber unter User Interactive.
3. **Utility:**
   - Diese Aufgaben laufen lange und zeigen typischerweise eine Fortschrittsanzeige an (z. B. beim Herunterladen von Dateien oder Importieren von Daten). Sie haben eine niedrigere Priorität als vom Benutzer gestartete Aufgaben und müssen nicht sofort abgeschlossen werden.
4. **Background:**
   - Diese Klasse ist für Aufgaben vorgesehen, die im Hintergrund ausgeführt werden und für den Benutzer nicht sichtbar sind. Dazu zählen etwa Indizierung, Synchronisierung oder Backups. Sie haben die niedrigste Priorität und wirken sich nur minimal auf die Systemleistung aus.

Mit QoS-Klassen müssen Entwickler keine konkreten Prioritätswerte verwalten, sondern können sich auf die Art der Aufgabe konzentrieren. Das System optimiert die CPU-Ressourcen entsprechend.

Darüber hinaus gibt es verschiedene **Thread-Scheduling-Richtlinien**, die eine Reihe von Scheduling-Parametern festlegen, die der Scheduler berücksichtigt. Dies lässt sich mit `thread_policy_[set/get]` umsetzen. Das kann bei Race-Condition-Angriffen nützlich sein.

## Missbrauch von macOS-Prozessen

macOS bietet viele Mechanismen, mit denen **Prozesse interagieren, kommunizieren und Daten austauschen** können. Diese Mechanismen sind zwar für den normalen Systembetrieb unerlässlich, können von Angreifern aber für Injection, Codeausführung oder Datenzugriff missbraucht werden.

### Library Injection

Library Injection ist eine Technik, bei der ein Angreifer **einen Prozess dazu zwingt, eine bösartige Bibliothek zu laden**. Nach der Injection wird die Bibliothek im Kontext des Zielprozesses ausgeführt. Dadurch erhält der Angreifer dieselben Berechtigungen und Zugriffsmöglichkeiten wie der Prozess.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking umfasst das **Abfangen von Funktionsaufrufen** oder Nachrichten innerhalb eines Softwarecodes. Durch das Hooking von Funktionen kann ein Angreifer **das Verhalten** eines Prozesses ändern, sensible Daten beobachten oder sogar den Ausführungsfluss kontrollieren.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Diese Seite behandelt ARM64-Unwind-Metadaten, arm64e-PAC-Einschränkungen und synthetische Call-Chains.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) bezeichnet verschiedene Methoden, mit denen separate Prozesse **Daten austauschen und gemeinsam nutzen**. IPC ist zwar für viele legitime Anwendungen grundlegend, kann aber auch missbraucht werden, um die Prozessisolation zu umgehen, sensible Informationen offenzulegen oder nicht autorisierte Aktionen auszuführen.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-Anwendungen, die mit bestimmten Umgebungsvariablen ausgeführt werden, können für Process Injection anfällig sein:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Mit den Flags `--load-extension` und `--use-fake-ui-for-media-stream` lässt sich ein **man-in-the-browser-Angriff** durchführen, mit dem Tastatureingaben, Datenverkehr und Cookies gestohlen sowie Skripte in Seiten eingeschleust werden können:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-Dateien **definieren Elemente der Benutzeroberfläche (UI)** und deren Interaktionen innerhalb einer Anwendung. Sie können jedoch **beliebige Befehle ausführen**, und **Gatekeeper verhindert nicht**, dass eine bereits ausgeführte Anwendung erneut ausgeführt wird, wenn eine **NIB-Datei geändert wurde**. Sie können daher dazu verwendet werden, beliebige Programme beliebige Befehle ausführen zu lassen:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Es ist möglich, JVM-Optionen über **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** oder **`JDK_JAVA_OPTIONS`** einzuschleusen und vor dem Start der Anwendung einen Java- oder nativen Agent zu laden.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** lädt über `--require` (Datei) oder `--import data:text/javascript,…` (dateilos, Node ≥ 20.6) JavaScript eines Angreifers vor; **`NODE_REPL_EXTERNAL_MODULE`** lädt ein Modul in eine interaktive REPL, und **`ELECTRON_RUN_AS_NODE`** aktiviert all dies erneut auf Electron-Binärdateien.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Es ist möglich, Code vor `Main` über **`DOTNET_STARTUP_HOOKS`** in .NET-Anwendungen einzuschleusen oder die .NET-Debugging-Funktion auszunutzen, wenn deren Voraussetzungen erfüllt sind.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nicht-interaktives Bash liest **`BASH_ENV`**; interaktive POSIX-Shells lesen **`ENV`**; zsh liest **`$ZDOTDIR/.zshenv`**; und fish liest Konfigurationsdateien unter **`XDG_CONFIG_HOME`** oder **`XDG_DATA_DIRS`**. Jede dieser Variablen kann vor dem vorgesehenen Befehl eine kontrollierte Startdatei ausführen. Bash führt außerdem eine Command Substitution aus, die in **`PS4`** steht, sobald xtrace aktiviert ist (z. B. über das geerbte **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Wird `/bin/zsh -s` gestartet, liest die Shell ein Programm von der Standardeingabe. Ein Downloader, der ein nicht vertrauenswürdiges strukturiertes Dokument ohne vorherige Analyse in die Standardeingabe des Kindprozesses kopiert, macht dadurch das gesamte Dokument zu Shell-Code. Bei einem beobachteten Loader wurde eine öffentliche iCalendar-Datei zeilenweise über eine anonyme Pipe übergeben. Kalender-Metadaten schlugen als Befehle fehl, aber zsh fuhr fort, bis es ausführbare Zeilen nach `DESCRIPTION:` erreichte. Diese Zeilen luden das nächste Anwendungs-Bundle herunter und starteten es. Der erwartete Inhaltstyp des Überträgers und ein vertrauenswürdiger Hosting-Anbieter machten dies nicht sicher; die gefährliche Grenze war die Übergabe seiner Bytes an einen Interpreter.<sup>[[5]](#references)</sup>

Verwandte Schritte werden in [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) und [macOS auto-start locations](../../macos-auto-start-locations.md) behandelt.

### PHP Injection

**`PHPRC`** oder **`PHP_INI_SCAN_DIR`** kann kontrollierte PHP-Konfiguration laden, deren **`auto_prepend_file`** vor dem Zielscripte ausgeführt wird.

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Der eigenständige Lua-Interpreter führt Code oder eine `@file` aus **`LUA_INIT`** (oder dessen versionsspezifischer Variante) aus, bevor das Zielscript verarbeitet wird.

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** und **`R_PROFILE`** leiten zu Startprofilen mit R-Code um. Mit **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** und einem R-Bibliothekspfad kann stattdessen automatisch ein installiertes Paket geladen werden.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** leitet zu dem Depot um, dessen `config/startup.jl` automatisch ausgeführt wird.

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** oder **`ERL_ZFLAGS`** können einen Erlang-VM-Ausdruck mit **`-eval`** einschleusen, ohne dass eine Payload-Datei erforderlich ist; Elixir-Workloads starten üblicherweise dieselbe VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** und **`OCTAVE_VERSION_INITFILE`** leiten zu Octave-Startskripten um.

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` ist eine plattformübergreifende .NET-App, daher ermöglichen mehrere Umgebungsvariablen die Ausführung vor dem Befehl: **`XDG_CONFIG_HOME`** leitet die beim Start ausgeführten Profilscripts um, **`PSModulePath`** ermöglicht das Hijacking des automatischen Modul-Ladens (ein abgelegtes `.psm1` wird beim Import ausgeführt und kann integrierte Cmdlets überschreiben), und die .NET-Variablen **`CORECLR_PROFILER`**/**`COR_PROFILER`** sowie **`DOTNET_STARTUP_HOOKS`** laden vor `Main` Code eines Angreifers in den Prozess.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Prüfe die verschiedenen Möglichkeiten, ein Perl-Script beliebigen Code ausführen zu lassen:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Es ist auch möglich, Ruby-Umgebungsvariablen (**`RUBYOPT`**, **`RUBYLIB`**) zu missbrauchen, damit beliebige Scripts beliebigen Code ausführen:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die Standardbibliothekskette **`PYTHONWARNINGS`** und **`BROWSER`** kann während der Verarbeitung des Warnungsfilters einen Befehl ausführen. Eine dateibasierte Alternative legt `sitecustomize.py` über **`PYTHONPATH`** bereit, sodass es bei der normalen `site`-Initialisierung vor dem Zielscripte importiert wird. **`PYTHONBREAKPOINT`** führt eine ausgewählte Callable oder ein ausgewähltes Modul aus, wenn der Code `breakpoint()` erreicht. Variablen, die nur interaktiv genutzt werden, etwa **`PYTHONSTARTUP`**, sind in ihrer Anwendbarkeit eingeschränkter.

Beachte, dass mit **`pyinstaller`** kompilierte ausführbare Dateien diese Umgebungsvariablen nicht verwenden, selbst wenn sie mit eingebettetem Python ausgeführt werden.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (und dessen Rückfalloption `EXINIT`) werden beim normalen Start als Ex-Befehle ausgeführt. Daher ermöglichen `:!cmd` / `:call system(...)` Codeausführung, wenn ein Opfer Vim/Neovim mit einer kontrollierten Umgebung öffnet:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Unabhängig davon installiert Homebrew Python häufig unter `/opt/homebrew`, wo Mitglieder der lokalen Gruppe `admin` möglicherweise den Launcher ersetzen können. Das ist ein Writable-Binary-Hijack und keine Injection über Umgebungsvariablen; prüfe Eigentümerschaft und ACLs, bevor du es als ausnutzbar einstufst.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ist eine Open-Source-Anwendung auf Basis von **EndpointSecurity**, die Process Injection erkennt und blockiert. Sie ist eine gute Referenz dafür, welche Signale über Endpoint Security sichtbar sind, da sie auf Folgendes aufmerksam macht:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-Umgebungsvariablen** beim Prozessstart: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` und `ELECTRON_RUN_AS_NODE`.
- Aufrufe von **`task_for_pid`** – dabei fordert ein Prozess den Task-Port eines anderen Prozesses an, was Voraussetzung für eine Injection in diesen Prozess ist.
- **Electron-Debugging-Argumente** – `--inspect`, `--inspect-brk` und `--remote-debugging-port`; sie starten eine Electron-App im Debug-Modus und ermöglichen es beliebigen Personen, sich anzuhängen und Code darin auszuführen.<sup>[[3]](#references)</sup>
- **Erstellung von Symlinks/Hardlinks über Berechtigungsstufen hinweg** – die klassische Methode „als normaler Benutzer einen Link erstellen und auf einen privilegierten Speicherort zeigen lassen“. Beachte, dass **Symlinks erkannt, aber nicht blockiert werden können**: EndpointSecurity stellt das Linkziel vor der Erstellung nicht bereit.

### Calls made by other processes

In [**diesem Blogbeitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) erfährst du, wie sich mit der Funktion **`task_name_for_pid`** Informationen über andere **Prozesse abrufen lassen, die Code in einen Prozess injizieren**, und anschließend weitere Informationen über diesen anderen Prozess ermittelt werden können.<sup>[[4]](#references)</sup>

Beachte, dass du zum Aufruf dieser Funktion dieselbe UID wie der Prozess oder **root** benötigst (und sie Informationen über den Prozess zurückgibt, aber keine Möglichkeit bietet, Code einzuschleusen).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — Open-Source-Erkennung von macOS-Process-Injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-Framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew – Warum Electron-Apps deine Geheimnisse nicht vertraulich speichern können: die Option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight – Erkennung von Task-Modifikationen](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist – Eine neue Version des MacSync-macOS-Stealers zielt auf Krypto-Enthusiasten und Entwickler](https://securelist.com/macsync-new-version/121383/)
