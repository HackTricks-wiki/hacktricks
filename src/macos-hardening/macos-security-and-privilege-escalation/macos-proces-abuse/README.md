# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Prozessen

Ein Prozess ist eine Instanz einer laufenden ausführbaren Datei. Prozesse führen jedoch keinen Code aus, sondern Threads. Daher **sind Prozesse lediglich Container für laufende Threads**, die Speicher, Deskriptoren, Ports, Berechtigungen usw. bereitstellen.

Traditionell wurden Prozesse innerhalb anderer Prozesse gestartet (außer PID 1), indem **`fork`** aufgerufen wurde. Dadurch wurde eine exakte Kopie des aktuellen Prozesses erstellt, und anschließend rief der **Child-Prozess** normalerweise **`execve`** auf, um die neue ausführbare Datei zu laden und auszuführen. Danach wurde **`vfork`** eingeführt, um diesen Vorgang ohne Kopieren des Speichers zu beschleunigen.\
Anschließend wurde **`posix_spawn`** eingeführt, das **`vfork`** und **`execve`** in einem Aufruf kombiniert und Flags akzeptiert:

- `POSIX_SPAWN_RESETIDS`: Effektive IDs auf die realen IDs zurücksetzen
- `POSIX_SPAWN_SETPGROUP`: Prozessgruppenzugehörigkeit festlegen
- `POSUX_SPAWN_SETSIGDEF`: Standardverhalten für Signale festlegen
- `POSIX_SPAWN_SETSIGMASK`: Signalmaske festlegen
- `POSIX_SPAWN_SETEXEC`: Im selben Prozess ausführen (wie `execve`, aber mit mehr Optionen)
- `POSIX_SPAWN_START_SUSPENDED`: Angehalten starten
- `_POSIX_SPAWN_DISABLE_ASLR`: Ohne ASLR starten
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Den Nano-Allocator von libmalloc verwenden
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` `rwx` für Datensegmente erlauben
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Standardmäßig alle Dateideskriptoren bei exec(2) schließen
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Hohe Bits des ASLR-Slides randomisieren

Außerdem akzeptiert `posix_spawn` **`posix_spawnattr`**-Einstellungen, die Aspekte des gestarteten Prozesses steuern, sowie **`posix_spawn_file_actions`**-Einträge, die Dateideskriptoren ändern.

Wenn ein Prozess beendet wird, sendet er den **Rückgabecode an den Parent-Prozess** (wenn der Parent beendet wurde, ist der neue Parent PID 1) zusammen mit dem Signal `SIGCHLD`. Der Parent muss diesen Wert mit `wait4()` oder `waitid()` abrufen. Bis dahin bleibt der Child in einem Zombie-Zustand, in dem er weiterhin aufgelistet wird, aber keine Ressourcen verbraucht.

### PIDs

PIDs (Prozesskennungen) identifizieren einen eindeutigen Prozess. In XNU sind die **PIDs** **64 Bit** groß, steigen monoton an und laufen **niemals über** (um Missbrauch zu verhindern).

### Prozessgruppen, Sessions und Coalitions

**Prozesse** können in **Gruppen** zusammengefasst werden, um sie einfacher zu verwalten. Beispielsweise befinden sich Befehle in einem Shell-Skript in derselben Prozessgruppe, sodass sie etwa mit `kill` **gemeinsam signalisiert** werden können.\
Es ist auch möglich, **Prozesse in Sessions zusammenzufassen**. Wenn ein Prozess eine Session startet (`setsid(2)`), werden die Child-Prozesse dieser Session zugeordnet, sofern sie nicht ihre eigene Session starten.

Eine Coalition ist eine weitere Möglichkeit, Prozesse in Darwin zu gruppieren. Wenn ein Prozess einer Coalition beitritt, kann er auf Pool-Ressourcen zugreifen, ein Ledger gemeinsam nutzen oder von Jetsam betroffen sein. Coalitions haben unterschiedliche Rollen: Leader, XPC service, Extension.

### Credentials und Personae

Jeder Prozess verfügt über **Credentials**, die **seine Berechtigungen** im System festlegen. Jeder Prozess hat eine primäre `uid` und eine primäre `gid` (kann aber mehreren Gruppen angehören).\
Es ist auch möglich, die User- und Group-ID zu ändern, wenn die Binärdatei das `setuid/setgid`-Bit gesetzt hat.\
Es gibt mehrere Funktionen, um **neue uids/gids festzulegen**.

Der Syscall **`persona`** stellt einen **alternativen** Satz von **Credentials** bereit. Durch die Annahme einer Persona werden deren uid, gid und Gruppenmitgliedschaften **auf einmal** übernommen. Im [**Quellcode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) ist folgende Struktur zu finden:

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

1. **POSIX Threads (pthreads):** macOS unterstützt POSIX Threads (`pthreads`), die Teil einer standardisierten Threading-API für C/C++ sind. Die Implementierung von pthreads in macOS befindet sich in `/usr/lib/system/libsystem_pthread.dylib` und stammt aus dem öffentlich verfügbaren Projekt `libpthread`. Diese Bibliothek stellt die erforderlichen Funktionen zum Erstellen und Verwalten von Threads bereit.
2. **Threads erstellen:** Mit der Funktion `pthread_create()` werden neue Threads erstellt. Intern ruft diese Funktion `bsdthread_create()` auf, einen Low-Level-Systemaufruf, der spezifisch für den XNU-Kernel ist (auf dem macOS basiert). Dieser Systemaufruf übernimmt verschiedene Flags, die von `pthread_attr` (Attributen) abgeleitet werden und das Verhalten des Threads festlegen, einschließlich Scheduling-Richtlinien und Stack-Größe.
   - **Standard-Stack-Größe:** Die Standard-Stack-Größe für neue Threads beträgt 512 KB. Das reicht für typische Vorgänge aus, kann aber über Thread-Attribute angepasst werden, wenn mehr oder weniger Speicherplatz benötigt wird.
3. **Thread-Initialisierung:** Die Funktion `__pthread_init()` ist für die Einrichtung eines Threads entscheidend. Sie verwendet das Argument `env[]`, um Umgebungsvariablen auszuwerten, die Angaben zum Speicherort und zur Größe des Stacks enthalten können.

#### Thread-Beendigung in macOS

1. **Threads beenden:** Threads werden üblicherweise durch den Aufruf von `pthread_exit()` beendet. Diese Funktion ermöglicht es einem Thread, ordnungsgemäß zu enden, notwendige Aufräumarbeiten durchzuführen und einen Rückgabewert an Threads zu übermitteln, die auf ihn warten.
2. **Thread-Bereinigung:** Beim Aufruf von `pthread_exit()` wird die Funktion `pthread_terminate()` aufgerufen, die alle zugehörigen Thread-Strukturen entfernt. Sie gibt Mach-Thread-Ports frei (Mach ist das Kommunikationssubsystem im XNU-Kernel) und ruft `bsdthread_terminate` auf, einen Syscall, der die dem Thread zugeordneten Strukturen auf Kernel-Ebene entfernt.

#### Synchronisierungsmechanismen

macOS stellt mehrere Synchronisierungsprimitive bereit, um den Zugriff auf gemeinsam genutzte Ressourcen zu verwalten und Race Conditions zu vermeiden. Sie sind in Multithreading-Umgebungen entscheidend, um die Datenintegrität und Systemstabilität sicherzustellen:

1. **Mutexes:**
   - **Regulärer Mutex (Signatur: 0x4D555458):** Standard-Mutex mit einem Speicherbedarf von 60 Bytes (56 Bytes für den Mutex und 4 Bytes für die Signatur).
   - **Fast Mutex (Signatur: 0x4d55545A):** Ähnlich wie ein regulärer Mutex, aber für schnellere Vorgänge optimiert; ebenfalls 60 Bytes groß.
2. **Condition Variables:**
   - Werden verwendet, um auf bestimmte Bedingungen zu warten. Sie sind 44 Bytes groß (40 Bytes plus eine 4-Byte-Signatur).
   - **Condition-Variable-Attribute (Signatur: 0x434e4441):** Konfigurationsattribute für Condition Variables, 12 Bytes groß.
3. **Once Variable (Signatur: 0x4f4e4345):**
   - Stellt sicher, dass ein Initialisierungscode nur einmal ausgeführt wird. Sie ist 12 Bytes groß.
4. **Read-Write Locks:**
   - Ermöglichen mehrere Leser oder jeweils einen Schreiber und sorgen so für effizienten Zugriff auf gemeinsam genutzte Daten.
   - **Read-Write-Lock (Signatur: 0x52574c4b):** 196 Bytes groß.
   - **Read-Write-Lock-Attribute (Signatur: 0x52574c41):** Attribute für Read-Write Locks, 20 Bytes groß.

> [!TIP]
> Die letzten 4 Bytes dieser Objekte werden verwendet, um Overflows zu erkennen.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** werden im Kontext von Mach-O-Dateien (dem Format für ausführbare Dateien in macOS) verwendet, um Variablen zu deklarieren, die in einer Multithreading-Anwendung für **jeden Thread einzeln** gelten. Dadurch hat jeder Thread eine eigene Instanz einer Variable. So lassen sich Konflikte vermeiden und die Datenintegrität wahren, ohne explizite Synchronisierungsmechanismen wie Mutexes zu benötigen.

In C und verwandten Sprachen können Sie mit dem Schlüsselwort **`__thread`** eine thread-lokale Variable deklarieren. So funktioniert es in Ihrem Beispiel:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Dieser Ausschnitt definiert `tlv_var` als thread-lokale Variable. Jeder Thread, der diesen Code ausführt, hat eine eigene `tlv_var`. Änderungen, die ein Thread an `tlv_var` vornimmt, wirken sich nicht auf `tlv_var` in einem anderen Thread aus.

In der Mach-O-Binärdatei sind die Daten zu thread-lokalen Variablen in bestimmten Sections organisiert:

- **`__DATA.__thread_vars`**: Diese Section enthält Metadaten zu den thread-lokalen Variablen, etwa deren Typen und Initialisierungsstatus.
- **`__DATA.__thread_bss`**: Diese Section wird für thread-lokale Variablen verwendet, die nicht explizit initialisiert sind. Sie ist ein Speicherbereich für auf null initialisierte Daten.

Mach-O bietet außerdem die spezielle API **`tlv_atexit`**, um thread-lokale Variablen beim Beenden eines Threads zu verwalten. Mit dieser API lassen sich **Destruktoren registrieren** – spezielle Funktionen, die thread-lokale Daten bereinigen, wenn ein Thread beendet wird.

### Threading-Prioritäten

Um Thread-Prioritäten zu verstehen, muss man betrachten, wie das Betriebssystem entscheidet, welche Threads wann ausgeführt werden. Diese Entscheidung wird durch die jedem Thread zugewiesene Prioritätsstufe beeinflusst. In macOS und Unix-ähnlichen Systemen kommen dafür Konzepte wie `nice`, `renice` und Quality-of-Service-Klassen (QoS) zum Einsatz.

#### Nice und Renice

1. **Nice:**
   - Der `nice`-Wert eines Prozesses ist eine Zahl, die dessen Priorität beeinflusst. Der Wert reicht von -20 (höchste Priorität) bis 19 (niedrigste Priorität). Der Standardwert für einen neu erstellten Prozess ist normalerweise 0.
   - Ein niedrigerer `nice`-Wert (näher an -20) macht einen Prozess „egoistischer“: Er erhält mehr CPU-Zeit als Prozesse mit höheren `nice`-Werten.
2. **Renice:**
   - `renice` ist ein Befehl, mit dem sich der `nice`-Wert eines bereits laufenden Prozesses ändern lässt. Damit kann die Priorität eines Prozesses dynamisch angepasst und seine CPU-Zuteilung anhand des neuen `nice`-Werts erhöht oder verringert werden.
   - Wenn ein Prozess beispielsweise vorübergehend mehr CPU-Ressourcen benötigt, kann sein `nice`-Wert mit `renice` gesenkt werden.

#### Quality-of-Service-Klassen (QoS)

QoS-Klassen sind ein modernerer Ansatz zur Verwaltung von Thread-Prioritäten, insbesondere in Systemen wie macOS, die **Grand Central Dispatch (GCD)** unterstützen. Mit QoS-Klassen können Entwickler Aufgaben je nach Wichtigkeit oder Dringlichkeit **kategorisieren**. macOS verwaltet die Priorisierung von Threads automatisch anhand dieser QoS-Klassen:

1. **User Interactive:**
   - Diese Klasse ist für Aufgaben gedacht, die gerade mit dem Benutzer interagieren oder sofortige Ergebnisse liefern müssen, damit die Benutzererfahrung gut bleibt. Diese Aufgaben erhalten die höchste Priorität, damit die Oberfläche reaktionsschnell bleibt (z. B. Animationen oder Ereignisverarbeitung).
2. **User Initiated:**
   - Aufgaben, die der Benutzer startet und für die er sofortige Ergebnisse erwartet, etwa das Öffnen eines Dokuments oder ein Klick auf eine Schaltfläche, der Berechnungen auslöst. Sie haben eine hohe Priorität, liegen aber unter User Interactive.
3. **Utility:**
   - Diese Aufgaben laufen länger und zeigen typischerweise eine Fortschrittsanzeige an (z. B. Dateien herunterladen oder Daten importieren). Sie haben eine niedrigere Priorität als vom Benutzer gestartete Aufgaben und müssen nicht sofort abgeschlossen werden.
4. **Background:**
   - Diese Klasse ist für Aufgaben vorgesehen, die im Hintergrund laufen und für den Benutzer nicht sichtbar sind. Dazu zählen etwa Indizierung, Synchronisierung oder Backups. Sie haben die niedrigste Priorität und nur minimale Auswirkungen auf die Systemleistung.

Mit QoS-Klassen müssen Entwickler keine genauen Prioritätszahlen verwalten, sondern können sich auf die Art der Aufgabe konzentrieren. Das System optimiert die CPU-Ressourcen entsprechend.

Außerdem gibt es verschiedene **Thread-Scheduling-Richtlinien**, mit denen sich Scheduling-Parameter festlegen lassen, die der Scheduler berücksichtigt. Dazu kann `thread_policy_[set/get]` verwendet werden. Das kann bei Race-Condition-Angriffen nützlich sein.

## macOS-Prozessmissbrauch

macOS bietet viele Mechanismen, mit denen **Prozesse interagieren, kommunizieren und Daten austauschen können**. Diese Mechanismen sind zwar für den normalen Systembetrieb unerlässlich, Angreifer können sie jedoch für Injection, Codeausführung oder Datenzugriff missbrauchen.

### Library Injection

Library Injection ist eine Technik, bei der ein Angreifer **einen Prozess dazu zwingt, eine bösartige Library zu laden**. Nach der Injection wird die Library im Kontext des Zielprozesses ausgeführt und gewährt dem Angreifer dieselben Berechtigungen und Zugriffe wie dem Prozess.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Beim Function Hooking werden **Funktionsaufrufe** oder Nachrichten innerhalb eines Programmcodes abgefangen. Durch das Hooking von Funktionen kann ein Angreifer **das Verhalten** eines Prozesses ändern, vertrauliche Daten beobachten oder sogar den Ablauf der Ausführung kontrollieren.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Diese Seite behandelt ARM64-Unwind-Metadaten, arm64e-PAC-Einschränkungen und synthetische Call-Chains.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) bezeichnet verschiedene Methoden, mit denen getrennte Prozesse **Daten austauschen und gemeinsam nutzen**. IPC ist zwar für viele legitime Anwendungen grundlegend, kann aber auch missbraucht werden, um die Prozessisolation zu unterlaufen, vertrauliche Informationen zu leaken oder unbefugte Aktionen auszuführen.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-Anwendungen, die mit bestimmten Umgebungsvariablen ausgeführt werden, können für Process Injection anfällig sein:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Mit den Flags `--load-extension` und `--use-fake-ui-for-media-stream` lässt sich ein **man-in-the-browser-Angriff** durchführen, um Tastatureingaben, Datenverkehr und Cookies zu stehlen sowie Skripte in Seiten einzuschleusen …:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-Dateien **definieren Elemente der Benutzeroberfläche (UI)** und deren Interaktionen innerhalb einer Anwendung. Sie können jedoch **beliebige Befehle ausführen**, und **Gatekeeper verhindert nicht**, dass eine bereits ausgeführte Anwendung erneut ausgeführt wird, wenn eine **NIB-Datei geändert wurde**. Daher können sie dazu verwendet werden, beliebige Programme beliebige Befehle ausführen zu lassen:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Über **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** oder **`JDK_JAVA_OPTIONS`** lassen sich JVM-Optionen einschleusen und ein Java- oder nativer Agent laden, bevor die Anwendung startet.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** lädt über `--require` (Datei) oder `--import data:text/javascript,…` (dateilos, Node ≥ 20.6) JavaScript des Angreifers vor. **`NODE_REPL_EXTERNAL_MODULE`** lädt ein Modul in eine interaktive REPL, und **`ELECTRON_RUN_AS_NODE`** aktiviert all das erneut für Electron-Binärdateien.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Code lässt sich über **`DOTNET_STARTUP_HOOKS`** vor `Main` in .NET-Anwendungen einschleusen. Alternativ kann die .NET-Debugging-Funktion missbraucht werden, sofern deren Voraussetzungen erfüllt sind.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nicht-interaktive Bash liest **`BASH_ENV`**; interaktive POSIX-Shells lesen **`ENV`**; zsh liest **`$ZDOTDIR/.zshenv`**; und fish liest Konfiguration aus **`XDG_CONFIG_HOME`** oder **`XDG_DATA_DIRS`**. Jede davon kann eine kontrollierte Startup-Datei ausführen, bevor der vorgesehene Befehl gestartet wird. Bash führt außerdem eine Command Substitution in **`PS4`** jedes Mal aus, wenn xtrace aktiviert ist (z. B. über das geerbte **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Wird `/bin/zsh -s` gestartet, liest die Shell ein Programm von der Standardeingabe. Kopiert ein Downloader also ein nicht vertrauenswürdiges strukturiertes Dokument ungeprüft in die stdin des untergeordneten Prozesses, wird das gesamte Dokument zu Shell-Code. Ein beobachteter Loader leitete eine öffentliche iCalendar-Datei zeilenweise über eine anonyme Pipe weiter. Kalender-Metadaten schlugen als Befehle fehl, doch zsh fuhr fort, bis es auf ausführbare Zeilen nach `DESCRIPTION:` stieß. Diese Zeilen luden das nächste Application Bundle herunter und starteten es. Der erwartete Inhaltstyp und ein vertrauenswürdiger Hosting-Anbieter machten dies nicht sicher; die gefährliche Grenze war die Übergabe der Bytes an einen Interpreter.<sup>[[5]](#references)</sup>

Verwandte Schritte werden in [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) und [macOS auto-start locations](../../macos-auto-start-locations.md) behandelt.

### PHP Injection

**`PHPRC`** oder **`PHP_INI_SCAN_DIR`** kann eine kontrollierte PHP-Konfiguration laden, deren **`auto_prepend_file`** vor dem Zielsynchron ausgeführt wird.

[PHP-Konfiguration und `auto_prepend_file`-Startup-Injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Der eigenständige Lua-Interpreter führt Code oder eine `@file` aus **`LUA_INIT`** (oder dessen versionsspezifischer Variante) aus, bevor er das Zielsynchron verarbeitet.

[Lua-`LUA_INIT`-Startup-Injection (Datei und Inline-Code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** und **`R_PROFILE`** leiten zu Startup-Profilen mit R-Code um. Über **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** zusammen mit einem R-Library-Pfad kann stattdessen automatisch ein installiertes Package geladen werden.

[R-Startup-Profile und Package-Laden](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** leitet zum Depot um, dessen `config/startup.jl` automatisch ausgeführt wird.

[Julia-`JULIA_DEPOT_PATH`- und `startup.jl`-Injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

Mit **`ERL_AFLAGS`**, **`ERL_FLAGS`** oder **`ERL_ZFLAGS`** lässt sich ein Erlang-VM-Ausdruck mit **`-eval`** einschleusen, ohne eine Payload-Datei zu benötigen. Elixir-Workloads starten häufig dieselbe VM.

[Erlang/Elixir-VM-Flag-Injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** und **`OCTAVE_VERSION_INITFILE`** leiten zu Octave-Startup-Skripten um.

[GNU-Octave-Startup-Datei-Injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` ist eine plattformübergreifende .NET-Anwendung, daher ermöglichen mehrere Umgebungsvariablen die Ausführung vor dem Befehl: **`XDG_CONFIG_HOME`** leitet die beim Start ausgeführten Profilskripte um, **`PSModulePath`** ermöglicht das Hijacking des automatischen Modul-Ladens (ein platziertes `.psm1` wird beim Import ausgeführt und kann integrierte Cmdlets überschreiben), und die .NET-Variablen **`CORECLR_PROFILER`**/**`COR_PROFILER`** sowie **`DOTNET_STARTUP_HOOKS`** laden Code des Angreifers in den Prozess, bevor `Main` ausgeführt wird.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Prüfe die verschiedenen Optionen, mit denen sich ein Perl-Skript dazu bringen lässt, beliebigen Code auszuführen:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Ruby-Umgebungsvariablen (**`RUBYOPT`**, **`RUBYLIB`**) lassen sich ebenfalls missbrauchen, um beliebige Skripte beliebigen Code ausführen zu lassen:


[Ruby-Loader-Optionen `RUBYOPT`/`RUBYLIB`](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Die Standardbibliothekskette **`PYTHONWARNINGS`** und **`BROWSER`** kann beim Parsen des Warning-Filters einen Befehl ausführen. Eine dateibasierte Alternative legt `sitecustomize.py` in **`PYTHONPATH`** ab, sodass der normale `site`-Initialisierungsprozess die Datei vor dem Zielskript importiert. **`PYTHONBREAKPOINT`** führt ein ausgewähltes Callable/Modul aus, wenn der Code `breakpoint()` erreicht.

Ab CPython 3.13 kann **`PYTHONINSPECT`** außerdem eine **`PYTHONSTARTUP`**-Datei ausführen, nachdem ein Skript beendet wurde, sofern dessen PyREPL in einem Terminal startet.<sup>[[6]](#references)</sup>

Beachte, dass mit **`pyinstaller`** kompilierte ausführbare Dateien diese Umgebungsvariablen nicht verwenden, auch wenn sie mit eingebettetem Python ausgeführt werden.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (und dessen Fallback **`EXINIT`**) werden bei einem normalen Start als Ex-Befehle ausgeführt. Daher ermöglichen `:!cmd` / `:call system(...)` Codeausführung, wenn ein Opfer Vim/Neovim mit einer kontrollierten Umgebung öffnet:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Homebrew installiert Python häufig unter `/opt/homebrew`, wo Mitglieder der lokalen Gruppe `admin` möglicherweise den Launcher ersetzen können. Das ist ein Hijacking einer beschreibbaren Binärdatei und keine Injection über Umgebungsvariablen. Prüfe Eigentümerschaft und ACLs, bevor du dies als ausnutzbar einstufst.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ist eine Open-Source-Anwendung auf Basis von **EndpointSecurity**, die Process Injection erkennt und blockiert. Sie ist eine gute Referenz dafür, welche Signale über Endpoint Security sichtbar sind, da sie auf Folgendes aufmerksam macht:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-Umgebungsvariablen** beim Process Exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` und `ELECTRON_RUN_AS_NODE`.
- Aufrufe von **`task_for_pid`** – dabei fordert ein Prozess den Task-Port eines anderen Prozesses an, was Voraussetzung für eine Injection in diesen Prozess ist.
- **Electron-Debugging-Argumente** – `--inspect`, `--inspect-brk` und `--remote-debugging-port`. Damit wird eine Electron-Anwendung im Debug-Modus gestartet, sodass sich beliebige Nutzer verbinden und Code darin ausführen können.<sup>[[3]](#references)</sup>
- **Erstellung von Symlinks/Hardlinks über Berechtigungsstufen hinweg** – das klassische Vorgehen: „Als normaler Benutzer einen Link erstellen und auf einen privilegierten Speicherort zeigen lassen“. Beachte, dass **Symlinks erkannt, aber nicht blockiert werden können**: EndpointSecurity stellt das Linkziel vor der Erstellung nicht bereit.

### Aufrufe durch andere Prozesse

In [**diesem Blogbeitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) erfährst du, wie sich die Funktion **`task_name_for_pid`** verwenden lässt, um Informationen über andere **Prozesse zu erhalten, die Code in einen Prozess einschleusen**, und anschließend Informationen über diesen anderen Prozess abzurufen.<sup>[[4]](#references)</sup>

Beachte, dass du zum Aufruf dieser Funktion dieselbe UID wie der Prozess oder **root** benötigst (und sie liefert Informationen über den Prozess, aber keine Möglichkeit, Code einzuschleusen).



## References

- [1] [Shield — Open-Source-Erkennung von macOS-Process-Injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-Framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew – Warum Electron-Apps deine Geheimnisse nicht vertraulich speichern können: die Option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight – Erkennung von Task-Manipulationen](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist – Eine neue Version des MacSync-macOS-Stealers zielt auf Krypto-Enthusiasten und Entwickler ab](https://securelist.com/macsync-new-version/121383/)
- [6] [Python-Befehlszeile und Umgebung — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
