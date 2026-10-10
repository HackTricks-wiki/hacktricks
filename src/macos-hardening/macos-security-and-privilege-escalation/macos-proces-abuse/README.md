# macOS-Prozessmissbrauch

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Prozessen

Ein Prozess ist eine Instanz einer laufenden ausführbaren Datei. Prozesse führen jedoch keinen Code aus; das übernehmen Threads. Daher **sind Prozesse lediglich Container für laufende Threads**, die Speicher, Deskriptoren, Ports, Berechtigungen usw. bereitstellen.

Traditionell wurden Prozesse innerhalb anderer Prozesse gestartet (mit Ausnahme von PID 1), indem **`fork`** aufgerufen wurde. Dadurch wurde eine exakte Kopie des aktuellen Prozesses erstellt. Anschließend rief der **Kindprozess** üblicherweise **`execve`** auf, um die neue ausführbare Datei zu laden und auszuführen. Danach wurde **`vfork`** eingeführt, um diesen Vorgang ohne Kopieren des Speichers zu beschleunigen.\
Anschließend wurde **`posix_spawn`** eingeführt, das **`vfork`** und **`execve`** in einem Aufruf kombiniert und Flags entgegennimmt:

- `POSIX_SPAWN_RESETIDS`: Effektive IDs auf die realen IDs zurücksetzen
- `POSIX_SPAWN_SETPGROUP`: Prozessgruppenzugehörigkeit festlegen
- `POSUX_SPAWN_SETSIGDEF`: Standardverhalten für Signale festlegen
- `POSIX_SPAWN_SETSIGMASK`: Signalmaske festlegen
- `POSIX_SPAWN_SETEXEC`: Im selben Prozess ausführen (wie `execve`, aber mit mehr Optionen)
- `POSIX_SPAWN_START_SUSPENDED`: Angehalten starten
- `_POSIX_SPAWN_DISABLE_ASLR`: Ohne ASLR starten
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Den Nano-Allocator von libmalloc verwenden
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` `rwx` auf Datensegmenten erlauben
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Standardmäßig alle Dateibeschreibungen bei exec(2) schließen
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Hohe Bits des ASLR-Slides randomisieren

Außerdem akzeptiert `posix_spawn` **`posix_spawnattr`**-Einstellungen, die Aspekte des gestarteten Prozesses steuern, sowie **`posix_spawn_file_actions`**-Einträge, die Dateideskriptoren ändern.

Wenn ein Prozess beendet wird, sendet er den **Rückgabecode an den Elternprozess** (ist der Elternprozess beendet, wird PID 1 zum neuen Elternprozess) und löst das Signal `SIGCHLD` aus. Der Elternprozess muss diesen Wert mit `wait4()` oder `waitid()` abrufen. Bis dahin verbleibt das Kind in einem Zombie-Zustand: Es wird weiterhin aufgelistet, verbraucht aber keine Ressourcen.

### PIDs

PIDs (Prozess-IDs) identifizieren einen einzelnen Prozess. In XNU sind **PIDs** **64 Bit** groß, steigen monoton an und **laufen niemals über** (um Missbrauch zu verhindern).

### Prozessgruppen, Sitzungen und Koalitionen

**Prozesse** können in **Gruppen** zusammengefasst werden, um sie einfacher zu verwalten. Befinden sich beispielsweise Befehle in einem Shell-Skript in derselben Prozessgruppe, können sie gemeinsam signalisiert werden, etwa mit `kill`.\
Es ist auch möglich, **Prozesse in Sitzungen zusammenzufassen**. Wenn ein Prozess eine Sitzung startet (`setsid(2)`), werden seine Kindprozesse dieser Sitzung zugeordnet, sofern sie nicht selbst eine Sitzung starten.

Koalitionen bieten in Darwin eine weitere Möglichkeit, Prozesse zu gruppieren. Wenn ein Prozess einer Koalition beitritt, kann er auf gemeinsame Ressourcenpools zugreifen, ein Ledger gemeinsam nutzen oder von Jetsam betroffen sein. Koalitionen haben unterschiedliche Rollen: Leader, XPC-Dienst und Extension.

### Anmeldedaten und Personas

Jeder Prozess verfügt über **Anmeldedaten**, die **seine Berechtigungen im System festlegen**. Jeder Prozess hat eine primäre `uid` und eine primäre `gid` (kann aber mehreren Gruppen angehören).\
Benutzer- und Gruppen-ID lassen sich auch ändern, wenn die Binärdatei das `setuid/setgid`-Bit gesetzt hat.\
Es gibt mehrere Funktionen, um **neue uids/gids festzulegen**.

Der Systemaufruf **`persona`** stellt einen alternativen Satz von **Anmeldedaten** bereit. Durch die Übernahme einer Persona werden deren uid, gid und Gruppenmitgliedschaften **gleichzeitig** angenommen. Im [**Quellcode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) ist folgende Struktur zu finden:

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
2. **Threads erstellen:** Die Funktion `pthread_create()` wird verwendet, um neue Threads zu erstellen. Intern ruft diese Funktion `bsdthread_create()` auf, einen Systemaufruf auf niedrigerer Ebene, der spezifisch für den XNU-Kernel ist (den Kernel, auf dem macOS basiert). Dieser Systemaufruf übernimmt verschiedene Flags, die von `pthread_attr` (Attributen) abgeleitet werden und das Verhalten des Threads festlegen, darunter Scheduling-Richtlinien und Stack-Größe.
   - **Standard-Stack-Größe:** Die Standard-Stack-Größe für neue Threads beträgt 512 KB. Das reicht für typische Vorgänge aus, kann aber über Thread-Attribute angepasst werden, wenn mehr oder weniger Speicher benötigt wird.
3. **Thread-Initialisierung:** Die Funktion `__pthread_init()` ist beim Einrichten eines Threads entscheidend. Sie verwendet das Argument `env[]`, um Umgebungsvariablen zu analysieren, die Angaben zu Speicherort und Größe des Stacks enthalten können.

#### Thread-Beendigung in macOS

1. **Threads beenden:** Threads werden üblicherweise durch Aufruf von `pthread_exit()` beendet. Diese Funktion ermöglicht es einem Thread, sauber zu beenden, notwendige Aufräumarbeiten durchzuführen und einen Rückgabewert an wartende Threads zu übermitteln.
2. **Thread-Bereinigung:** Beim Aufruf von `pthread_exit()` wird die Funktion `pthread_terminate()` aufgerufen, die alle zugehörigen Thread-Strukturen entfernt. Sie gibt Mach-Thread-Ports frei (Mach ist das Kommunikationssubsystem im XNU-Kernel) und ruft `bsdthread_terminate` auf, einen Systemaufruf, der die dem Thread zugeordneten Kernel-Strukturen entfernt.

#### Synchronisierungsmechanismen

Um den Zugriff auf gemeinsam genutzte Ressourcen zu verwalten und Race Conditions zu vermeiden, stellt macOS mehrere Synchronisierungsprimitiven bereit. In Multithreading-Umgebungen sind diese entscheidend, um Datenintegrität und Systemstabilität sicherzustellen:

1. **Mutexes:**
   - **Regulärer Mutex (Signatur: 0x4D555458):** Standard-Mutex mit einem Speicherbedarf von 60 Byte (56 Byte für den Mutex und 4 Byte für die Signatur).
   - **Fast Mutex (Signatur: 0x4d55545A):** Ähnlich wie ein regulärer Mutex, aber für schnellere Vorgänge optimiert; ebenfalls 60 Byte groß.
2. **Condition Variables:**
   - Werden verwendet, um auf das Eintreten bestimmter Bedingungen zu warten. Sie sind 44 Byte groß (40 Byte plus eine 4-Byte-Signatur).
   - **Attribute von Condition Variables (Signatur: 0x434e4441):** Konfigurationsattribute für Condition Variables, 12 Byte groß.
3. **Once-Variable (Signatur: 0x4f4e4345):**
   - Stellt sicher, dass ein Initialisierungscode nur einmal ausgeführt wird. Sie ist 12 Byte groß.
4. **Read-Write-Locks:**
   - Ermöglichen mehrere Leser oder jeweils einen Schreiber und sorgen so für einen effizienten Zugriff auf gemeinsam genutzte Daten.
   - **Read-Write-Lock (Signatur: 0x52574c4b):** 196 Byte groß.
   - **Attribute von Read-Write-Locks (Signatur: 0x52574c41):** Attribute für Read-Write-Locks, 20 Byte groß.

> [!TIP]
> Die letzten 4 Byte dieser Objekte werden verwendet, um Overflows zu erkennen.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** werden im Kontext von Mach-O-Dateien (dem Format für ausführbare Dateien in macOS) verwendet, um Variablen zu deklarieren, die in einer Multithread-Anwendung **für jeden Thread spezifisch** sind. Dadurch erhält jeder Thread eine eigene Instanz einer Variablen. So lassen sich Konflikte vermeiden und die Datenintegrität wahren, ohne explizite Synchronisierungsmechanismen wie Mutexes zu benötigen.

In C und verwandten Sprachen können Sie eine threadlokale Variable mit dem Schlüsselwort **`__thread`** deklarieren. So funktioniert es in Ihrem Beispiel:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Dieses Snippet definiert `tlv_var` als thread-lokale Variable. Jeder Thread, der diesen Code ausführt, hat eine eigene `tlv_var`. Änderungen, die ein Thread an `tlv_var` vornimmt, wirken sich nicht auf `tlv_var` in einem anderen Thread aus.

Im Mach-O-Binary sind die Daten zu thread-lokalen Variablen in bestimmten Sections organisiert:

- **`__DATA.__thread_vars`**: Diese Section enthält Metadaten zu den thread-lokalen Variablen, etwa deren Typen und Initialisierungsstatus.
- **`__DATA.__thread_bss`**: Diese Section wird für thread-lokale Variablen verwendet, die nicht explizit initialisiert werden. Sie ist Teil des Speichers, der für mit Null initialisierte Daten reserviert ist.

Mach-O bietet auch eine spezielle API namens **`tlv_atexit`**, um thread-lokale Variablen beim Beenden eines Threads zu verwalten. Mit dieser API können **Destruktoren registriert** werden – spezielle Funktionen, die thread-lokale Daten bereinigen, wenn ein Thread beendet wird.

### Threading-Prioritäten

Um Thread-Prioritäten zu verstehen, muss man sich ansehen, wie das Betriebssystem entscheidet, welche Threads wann ausgeführt werden. Diese Entscheidung hängt von der jedem Thread zugewiesenen Prioritätsstufe ab. In macOS und Unix-ähnlichen Systemen kommen dabei Konzepte wie `nice`, `renice` und Quality-of-Service-Klassen (QoS) zum Einsatz.

#### Nice und Renice

1. **Nice:**
   - Der `nice`-Wert eines Prozesses ist eine Zahl, die seine Priorität beeinflusst. Jeder Prozess hat einen `nice`-Wert zwischen -20 (höchste Priorität) und 19 (niedrigste Priorität). Der standardmäßige `nice`-Wert beim Erstellen eines Prozesses ist normalerweise 0.
   - Ein niedrigerer `nice`-Wert (näher an -20) macht einen Prozess „egoistischer“: Er erhält mehr CPU-Zeit als andere Prozesse mit höheren `nice`-Werten.
2. **Renice:**
   - `renice` ist ein Befehl, mit dem sich der `nice`-Wert eines bereits laufenden Prozesses ändern lässt. Damit kann die Priorität von Prozessen dynamisch angepasst und ihre CPU-Zuteilung anhand neuer `nice`-Werte erhöht oder verringert werden.
   - Wenn ein Prozess beispielsweise vorübergehend mehr CPU-Ressourcen benötigt, kann sein `nice`-Wert mit `renice` gesenkt werden.

#### Quality-of-Service-Klassen (QoS)

QoS-Klassen sind ein modernerer Ansatz für die Verwaltung von Thread-Prioritäten, insbesondere in Systemen wie macOS, die **Grand Central Dispatch (GCD)** unterstützen. Mit QoS-Klassen können Entwickler Arbeit je nach Wichtigkeit oder Dringlichkeit in verschiedene Stufen **einordnen**. macOS verwaltet die Priorisierung von Threads automatisch anhand dieser QoS-Klassen:

1. **User Interactive:**
   - Diese Klasse ist für Aufgaben vorgesehen, die gerade mit dem Benutzer interagieren oder sofortige Ergebnisse erfordern, um eine gute Benutzererfahrung zu gewährleisten. Solche Aufgaben erhalten die höchste Priorität, damit die Benutzeroberfläche reaktionsfähig bleibt (z. B. Animationen oder Ereignisverarbeitung).
2. **User Initiated:**
   - Aufgaben, die der Benutzer startet und für die er sofortige Ergebnisse erwartet, etwa das Öffnen eines Dokuments oder das Klicken auf eine Schaltfläche, die Berechnungen auslöst. Diese Aufgaben haben eine hohe Priorität, aber eine niedrigere als Aufgaben der Klasse User Interactive.
3. **Utility:**
   - Diese Aufgaben laufen länger und zeigen üblicherweise einen Fortschrittsindikator an (z. B. beim Herunterladen von Dateien oder Importieren von Daten). Sie haben eine niedrigere Priorität als vom Benutzer gestartete Aufgaben und müssen nicht sofort abgeschlossen werden.
4. **Background:**
   - Diese Klasse ist für Aufgaben vorgesehen, die im Hintergrund ausgeführt werden und für den Benutzer nicht sichtbar sind. Dazu gehören etwa Indizierung, Synchronisierung oder Backups. Sie haben die niedrigste Priorität und wirken sich nur minimal auf die Systemleistung aus.

Mit QoS-Klassen müssen Entwickler keine genauen Prioritätszahlen verwalten, sondern können sich auf die Art der Aufgabe konzentrieren. Das System optimiert die CPU-Ressourcen entsprechend.

Außerdem gibt es verschiedene **Thread-Scheduling-Richtlinien**, die eine Reihe von Scheduling-Parametern festlegen, die der Scheduler berücksichtigt. Dies lässt sich mit `thread_policy_[set/get]` umsetzen. Das kann bei Race-Condition-Angriffen nützlich sein.

## Missbrauch von macOS-Prozessen

macOS bietet viele Mechanismen, mit denen **Prozesse interagieren, kommunizieren und Daten austauschen** können. Obwohl diese Mechanismen für den normalen Systembetrieb unerlässlich sind, können Angreifer sie für Injection, Codeausführung oder Datenzugriff missbrauchen.

### Library Injection

Library Injection ist eine Technik, bei der ein Angreifer **einen Prozess dazu zwingt, eine bösartige Library zu laden**. Nach der Injection wird die Library im Kontext des Zielprozesses ausgeführt und bietet dem Angreifer dieselben Berechtigungen und Zugriffsmöglichkeiten wie dem Prozess.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking umfasst das **Abfangen von Funktionsaufrufen** oder Nachrichten innerhalb eines Softwarecodes. Durch das Hooking von Funktionen kann ein Angreifer **das Verhalten** eines Prozesses ändern, vertrauliche Daten beobachten oder sogar den Ausführungsfluss kontrollieren.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) bezeichnet verschiedene Methoden, mit denen separate Prozesse **Daten austauschen und gemeinsam nutzen**. IPC ist zwar für viele legitime Anwendungen grundlegend, kann aber auch missbraucht werden, um die Prozessisolierung zu umgehen, vertrauliche Informationen zu leaken oder nicht autorisierte Aktionen auszuführen.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-Anwendungen, die mit bestimmten Umgebungsvariablen ausgeführt werden, können für Process Injection anfällig sein:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Mit den Flags `--load-extension` und `--use-fake-ui-for-media-stream` lässt sich ein **man-in-the-browser-Angriff** durchführen, mit dem Tastenanschläge, Datenverkehr und Cookies gestohlen sowie Skripte in Seiten eingeschleust werden können:


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

**`NODE_OPTIONS`** lädt über `--require` (Datei) oder `--import data:text/javascript,…` (dateilos, Node ≥ 20.6) vorab JavaScript des Angreifers. **`NODE_REPL_EXTERNAL_MODULE`** lädt ein Modul in eine interaktive REPL, und **`ELECTRON_RUN_AS_NODE`** aktiviert all dies erneut für Electron-Binaries.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Code lässt sich über **`DOTNET_STARTUP_HOOKS`** vor `Main` in .NET-Anwendungen einschleusen oder durch Missbrauch der .NET-Debugging-Funktionalität, sofern deren Voraussetzungen erfüllt sind.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nicht-interaktive Bash-Shells lesen **`BASH_ENV`**; interaktive POSIX-Shells lesen **`ENV`**; zsh liest **`$ZDOTDIR/.zshenv`**; und fish liest Konfigurationsdateien unter **`XDG_CONFIG_HOME`** oder **`XDG_DATA_DIRS`**. Jede dieser Variablen kann eine kontrollierte Startdatei ausführen, bevor der vorgesehene Befehl ausgeführt wird. Bash führt außerdem eine Command Substitution aus, die in **`PS4`** steht, sobald xtrace aktiviert ist (z. B. über die geerbte Variable **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

Mit **`PHPRC`** oder **`PHP_INI_SCAN_DIR`** lässt sich eine kontrollierte PHP-Konfiguration laden, deren **`auto_prepend_file`** vor dem Zielscrpt ausgeführt wird.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Der eigenständige Lua-Interpreter führt Code oder eine `@file` aus **`LUA_INIT`** (oder dessen versionsspezifischer Variante) aus, bevor er das Zielscrpt verarbeitet.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** und **`R_PROFILE`** leiten zu Startprofilen mit R-Code um. Alternativ können **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** zusammen mit einem R-Library-Pfad ein installiertes Paket automatisch laden.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** leitet zum Depot um, dessen `config/startup.jl` automatisch ausgeführt wird.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

Mit **`ERL_AFLAGS`**, **`ERL_FLAGS`** oder **`ERL_ZFLAGS`** lässt sich ein Erlang-VM-Ausdruck mit **`-eval`** einschleusen, ohne eine Payload-Datei zu benötigen. Elixir-Workloads starten häufig dieselbe VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** und **`OCTAVE_VERSION_INITFILE`** leiten zu Octave-Startskripten um.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` ist eine plattformübergreifende .NET-App. Daher ermöglichen mehrere Umgebungsvariablen eine Ausführung vor dem eigentlichen Befehl: **`XDG_CONFIG_HOME`** leitet die beim Start ausgeführten Profilskripte um, **`PSModulePath`** ermöglicht das Hijacking des automatischen Modul-Loads (eine abgelegte `.psm1` wird beim Import ausgeführt und kann integrierte Cmdlets überschreiben), und die .NET-Variablen **`CORECLR_PROFILER`**/**`COR_PROFILER`** sowie **`DOTNET_STARTUP_HOOKS`** laden Code des Angreifers in den Prozess, bevor `Main` ausgeführt wird.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Prüfe verschiedene Möglichkeiten, ein Perl-Skript dazu zu bringen, beliebigen Code auszuführen:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Es ist auch möglich, Ruby-Umgebungsvariablen (**`RUBYOPT`**, **`RUBYLIB`**) zu missbrauchen, damit beliebige Skripte beliebigen Code ausführen:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die Standardbibliothekskette **`PYTHONWARNINGS`** und **`BROWSER`** kann während der Verarbeitung von Warnungsfiltern einen Befehl ausführen. Eine dateibasierte Alternative legt `sitecustomize.py` in **`PYTHONPATH`** ab, sodass der normale `site`-Initialisierungsvorgang die Datei vor dem Zielscrpt importiert. **`PYTHONBREAKPOINT`** führt ein ausgewähltes Callable/Modul aus, wenn der Code `breakpoint()` erreicht. Nur interaktive Variablen wie **`PYTHONSTARTUP`** sind weniger breit anwendbar.

Beachte, dass mit **`pyinstaller`** kompilierte Executables diese Umgebungsvariablen nicht verwenden, selbst wenn sie ein eingebettetes Python ausführen.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (und dessen Fallback `EXINIT`) werden beim normalen Start als Ex-Befehle ausgeführt. Daher ermöglichen `:!cmd` / `:call system(...)` die Codeausführung, wenn ein Opfer Vim/Neovim mit einer kontrollierten Umgebung startet:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Unabhängig davon installiert Homebrew Python häufig unter `/opt/homebrew`, wo Mitglieder der lokalen Gruppe `admin` möglicherweise den Launcher ersetzen können. Das ist ein Hijacking einer beschreibbaren Binary und keine Injection über Umgebungsvariablen. Prüfe Eigentümerschaft und ACLs, bevor du dies als ausnutzbar einstufst.


## Erkennung

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ist eine Open-Source-Anwendung auf Basis von **EndpointSecurity**, die Process Injection erkennt und blockiert. Sie ist eine gute Referenz dafür, welche Signale über Endpoint Security beobachtbar sind, denn sie meldet:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-Umgebungsvariablen** beim Prozess-Exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` und `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-Aufrufe – ein Prozess fordert den Task-Port eines anderen Prozesses an; dies ist eine Voraussetzung für eine Injection in diesen Prozess.
- **Electron-Debugging-Argumente** – `--inspect`, `--inspect-brk` und `--remote-debugging-port`, die eine Electron-App im Debug-Modus starten und anderen ermöglichen, eine Verbindung herzustellen und Code darin auszuführen.<sup>[[3]](#references)</sup>
- **Erstellung von Symlinks/Hardlinks über Berechtigungsstufen hinweg** – die klassische Methode: „Als normaler Benutzer einen Link anlegen und auf einen privilegierten Speicherort verweisen lassen“. Beachte, dass **Symlinks zwar gemeldet, aber nicht blockiert werden können**: EndpointSecurity stellt das Link-Ziel vor der Erstellung nicht bereit.

### Von anderen Prozessen ausgeführte Aufrufe

In [**diesem Blogbeitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) erfährst du, wie sich mit der Funktion **`task_name_for_pid`** Informationen über andere **Prozesse, die Code in einen Prozess injizieren**, abrufen lassen und wie man anschließend Informationen über diesen anderen Prozess erhält.<sup>[[4]](#references)</sup>

Beachte, dass du zum Aufrufen dieser Funktion **dieselbe uid** wie der Prozess oder **root** sein musst (sie gibt Informationen über den Prozess zurück, bietet aber keine Möglichkeit, Code einzuschleusen).

## References

- [1] [Shield — macOS-Erkennung von Process Injection als Open Source (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-Framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew – Warum Electron-Apps deine Geheimnisse nicht vertraulich speichern können: Option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight – Erkennung von Task-Modifikationen](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
