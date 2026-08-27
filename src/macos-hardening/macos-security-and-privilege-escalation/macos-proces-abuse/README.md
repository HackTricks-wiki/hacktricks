# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Processes

Ein Process ist eine Instanz einer laufenden ausführbaren Datei. Allerdings führen Processes keinen Code aus, sondern Threads. Daher sind **Processes lediglich Container für laufende Threads**, die den Speicher, Deskriptoren, Ports, Berechtigungen usw. bereitstellen.

Traditionell wurden Processes innerhalb anderer Processes (außer PID 1) durch Aufruf von **`fork`** gestartet. Dabei wurde eine exakte Kopie des aktuellen Processes erstellt, und anschließend rief der **Child Process** normalerweise **`execve`** auf, um die neue ausführbare Datei zu laden und auszuführen. Danach wurde **`vfork`** eingeführt, um diesen Vorgang ohne Kopieren des Speichers zu beschleunigen.\
Anschließend wurde **`posix_spawn`** eingeführt, das **`vfork`** und **`execve`** in einem Aufruf kombiniert und Flags akzeptiert:

- `POSIX_SPAWN_RESETIDS`: Effektive IDs auf reale IDs zurücksetzen
- `POSIX_SPAWN_SETPGROUP`: Zugehörigkeit zur Process Group festlegen
- `POSUX_SPAWN_SETSIGDEF`: Standardverhalten für Signale festlegen
- `POSIX_SPAWN_SETSIGMASK`: Signalmaske festlegen
- `POSIX_SPAWN_SETEXEC`: Im selben Process ausführen (wie `execve` mit zusätzlichen Optionen)
- `POSIX_SPAWN_START_SUSPENDED`: Angehalten starten
- `_POSIX_SPAWN_DISABLE_ASLR`: Ohne ASLR starten
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Den Nano-Allocator von libmalloc verwenden
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` `rwx` für Datensegmente erlauben
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Standardmäßig alle File Descriptions bei exec(2) schließen
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Die hohen Bits des ASLR-Slides randomisieren

Außerdem akzeptiert `posix_spawn` **`posix_spawnattr`**-Einstellungen, die Aspekte des gestarteten Processes steuern, sowie **`posix_spawn_file_actions`**-Einträge, die File Descriptors verändern.

Wenn ein Process beendet wird, sendet er den **Return Code an den Parent Process** (falls der Parent beendet wurde, ist der neue Parent PID 1) mit dem Signal `SIGCHLD`. Der Parent muss diesen Wert durch Aufruf von `wait4()` oder `waitid()` abrufen. Bis dies geschieht, verbleibt der Child in einem Zombie-Zustand, in dem er weiterhin aufgelistet wird, aber keine Ressourcen verbraucht.

### PIDs

PIDs, also Process Identifiers, identifizieren einen eindeutigen Process. In XNU sind die **PIDs** 64 Bit groß, steigen monoton an und laufen **nie über** (um Missbrauch zu verhindern).

### Process Groups, Sessions & Coalitions

**Processes** können in **Groups** eingefügt werden, um ihre Verwaltung zu vereinfachen. Beispielsweise befinden sich Befehle in einem Shell-Script in derselben Process Group, sodass sie gemeinsam signalisiert werden können, etwa mit kill.\
Processes können außerdem in **Sessions** gruppiert werden. Wenn ein Process eine Session startet (`setsid(2)`), werden die Child Processes in diese Session eingeordnet, sofern sie nicht ihre eigene Session starten.

Coalition ist eine weitere Möglichkeit, Processes in Darwin zu gruppieren. Wenn ein Process einer Coalition beitritt, kann er auf Pool-Ressourcen zugreifen, ein Ledger gemeinsam nutzen oder von Jetsam betroffen sein. Coalitions haben verschiedene Rollen: Leader, XPC service, Extension.

### Credentials & Personae

Jeder Process verfügt über **Credentials**, die **seine Privilegien** im System identifizieren. Jeder Process besitzt eine primäre `uid` und eine primäre `gid` (kann jedoch mehreren Groups angehören).\
Die User- und Group-ID kann ebenfalls geändert werden, wenn die Binary über das **`setuid/setgid`**-Bit verfügt.\
Es gibt mehrere Funktionen zum **Setzen neuer UIDs/GIDs**.

Der Syscall **`persona`** stellt einen **alternativen** Satz von **Credentials** bereit. Die Annahme einer Persona übernimmt deren UID, GID und Group-Mitgliedschaften **gleichzeitig**. Im [**Source Code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) kann die Struktur gefunden werden:
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

1. **POSIX Threads (pthreads):** macOS unterstützt POSIX Threads (`pthreads`), die Teil einer standardisierten Threading-API für C/C++ sind. Die Implementierung von pthreads in macOS befindet sich in `/usr/lib/system/libsystem_pthread.dylib` und stammt aus dem öffentlich verfügbaren `libpthread`-Projekt. Diese Library stellt die erforderlichen Funktionen zum Erstellen und Verwalten von Threads bereit.
2. **Erstellen von Threads:** Die Funktion `pthread_create()` wird zum Erstellen neuer Threads verwendet. Intern ruft diese Funktion `bsdthread_create()` auf, einen systemnahen Systemaufruf, der spezifisch für den XNU-Kernel (den Kernel, auf dem macOS basiert) ist. Dieser Systemaufruf übernimmt verschiedene aus `pthread_attr` (Attributen) abgeleitete Flags, die das Thread-Verhalten festlegen, einschließlich Scheduling-Richtlinien und Stack-Größe.
- **Standardmäßige Stack-Größe:** Die standardmäßige Stack-Größe für neue Threads beträgt 512 KB. Dies ist für typische Vorgänge ausreichend, kann jedoch über Thread-Attribute angepasst werden, wenn mehr oder weniger Speicher benötigt wird.
3. **Thread-Initialisierung:** Die Funktion `__pthread_init()` ist während der Einrichtung eines Threads entscheidend. Sie verwendet das Argument `env[]`, um Umgebungsvariablen zu analysieren, die Angaben zum Ort und zur Größe des Stacks enthalten können.

#### Thread-Beendigung in macOS

1. **Beenden von Threads:** Threads werden typischerweise durch den Aufruf von `pthread_exit()` beendet. Diese Funktion ermöglicht es einem Thread, ordnungsgemäß zu beenden, erforderliche Bereinigungen durchzuführen und einen Rückgabewert an wartende Threads zu senden.
2. **Thread-Bereinigung:** Beim Aufruf von `pthread_exit()` wird die Funktion `pthread_terminate()` aufgerufen. Sie übernimmt die Entfernung aller zugehörigen Thread-Strukturen. Sie gibt Mach-Thread-Ports frei (Mach ist das Kommunikationssubsystem im XNU-Kernel) und ruft `bsdthread_terminate` auf, einen Syscall, der die mit dem Thread verbundenen Strukturen auf Kernel-Ebene entfernt.

#### Synchronisierungsmechanismen

Um den Zugriff auf gemeinsam genutzte Ressourcen zu verwalten und Race Conditions zu vermeiden, stellt macOS mehrere Synchronisierungsprimitive bereit. Diese sind in Multi-Threading-Umgebungen entscheidend, um Datenintegrität und Systemstabilität sicherzustellen:

1. **Mutexes:**
- **Regulärer Mutex (Signatur: 0x4D555458):** Standard-Mutex mit einem Speicherbedarf von 60 Bytes (56 Bytes für den Mutex und 4 Bytes für die Signatur).
- **Fast Mutex (Signatur: 0x4d55545A):** Ähnlich wie ein regulärer Mutex, jedoch für schnellere Vorgänge optimiert und ebenfalls 60 Bytes groß.
2. **Condition Variables:**
- Werden verwendet, um auf das Eintreten bestimmter Bedingungen zu warten, und haben eine Größe von 44 Bytes (40 Bytes plus eine 4-Byte-Signatur).
- **Attribute von Condition Variables (Signatur: 0x434e4441):** Konfigurationsattribute für Condition Variables mit einer Größe von 12 Bytes.
3. **Once Variable (Signatur: 0x4f4e4345):**
- Stellt sicher, dass ein Initialisierungscode nur einmal ausgeführt wird. Ihre Größe beträgt 12 Bytes.
4. **Read-Write Locks:**
- Ermöglichen mehrere Leser oder jeweils einen Writer und erleichtern dadurch den effizienten Zugriff auf gemeinsam genutzte Daten.
- **Read Write Lock (Signatur: 0x52574c4b):** Hat eine Größe von 196 Bytes.
- **Attribute von Read Write Locks (Signatur: 0x52574c41):** Attribute für Read-Write Locks mit einer Größe von 20 Bytes.

> [!TIP]
> Die letzten 4 Bytes dieser Objekte werden verwendet, um Overflows zu erkennen.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** werden im Kontext von Mach-O-Dateien (dem Format für ausführbare Dateien in macOS) verwendet, um Variablen zu deklarieren, die für **jeden Thread** in einer Multi-Threading-Anwendung spezifisch sind. Dadurch hat jeder Thread eine eigene Instanz einer Variablen. Dies bietet eine Möglichkeit, Konflikte zu vermeiden und die Datenintegrität aufrechtzuerhalten, ohne explizite Synchronisierungsmechanismen wie Mutexes zu benötigen.

In C und verwandten Sprachen kann eine Thread Local Variable mit dem Schlüsselwort **`__thread`** deklariert werden. So funktioniert dies in deinem Beispiel:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Dieses Snippet definiert `tlv_var` als thread-lokale Variable. Jeder Thread, der diesen Code ausführt, verfügt über eine eigene `tlv_var`, und Änderungen, die ein Thread an `tlv_var` vornimmt, wirken sich nicht auf `tlv_var` in einem anderen Thread aus.

Im Mach-O-Binary werden die Daten zu thread-lokalen Variablen in bestimmten Sections organisiert:

- **`__DATA.__thread_vars`**: Diese Section enthält Metadaten zu den thread-lokalen Variablen, etwa deren Typen und Initialisierungsstatus.
- **`__DATA.__thread_bss`**: Diese Section wird für thread-lokale Variablen verwendet, die nicht explizit initialisiert wurden. Sie ist ein für nullinitialisierte Daten reservierter Speicherbereich.

Mach-O stellt außerdem eine spezielle API namens **`tlv_atexit`** zur Verwaltung thread-lokaler Variablen beim Beenden eines Threads bereit. Mit dieser API können **Destruktoren registriert** werden – spezielle Funktionen, die thread-lokale Daten beim Beenden eines Threads bereinigen.

### Threading Priorities

Beim Verständnis von Thread-Prioritäten muss betrachtet werden, wie das Betriebssystem entscheidet, welche Threads wann ausgeführt werden. Diese Entscheidung wird durch die jedem Thread zugewiesene Prioritätsstufe beeinflusst. In macOS und Unix-ähnlichen Systemen wird dies mithilfe von Konzepten wie `nice`, `renice` und Quality-of-Service-(QoS-)Klassen umgesetzt.

#### Nice und Renice

1. **Nice:**
- Der `nice`-Wert eines Prozesses ist eine Zahl, die seine Priorität beeinflusst. Jeder Prozess hat einen Nice-Wert zwischen -20 (höchste Priorität) und 19 (niedrigste Priorität). Der Standardwert bei der Erstellung eines Prozesses ist normalerweise 0.
- Ein niedrigerer Nice-Wert (näher an -20) macht einen Prozess „eigennütziger“, sodass er im Vergleich zu anderen Prozessen mit höheren Nice-Werten mehr CPU-Zeit erhält.
2. **Renice:**
- `renice` ist ein Befehl, mit dem der Nice-Wert eines bereits laufenden Prozesses geändert wird. Damit kann die Priorität von Prozessen dynamisch angepasst und ihre CPU-Zuteilung abhängig von den neuen Nice-Werten erhöht oder verringert werden.
- Wenn ein Prozess beispielsweise vorübergehend mehr CPU-Ressourcen benötigt, kann sein Nice-Wert mithilfe von `renice` gesenkt werden.

#### Quality-of-Service-(QoS-)Klassen

QoS-Klassen sind ein modernerer Ansatz zur Verwaltung von Thread-Prioritäten, insbesondere in Systemen wie macOS, die **Grand Central Dispatch (GCD)** unterstützen. QoS-Klassen ermöglichen es Entwicklern, Arbeit anhand ihrer Bedeutung oder Dringlichkeit in verschiedene Stufen zu **kategorisieren**. macOS verwaltet die Thread-Priorisierung automatisch auf Grundlage dieser QoS-Klassen:

1. **User Interactive:**
- Diese Klasse ist für Aufgaben vorgesehen, die gerade mit dem Benutzer interagieren oder sofortige Ergebnisse benötigen, um eine gute Benutzererfahrung zu gewährleisten. Diese Aufgaben erhalten die höchste Priorität, damit die Benutzeroberfläche reaktionsfähig bleibt (z. B. Animationen oder Ereignisverarbeitung).
2. **User Initiated:**
- Aufgaben, die vom Benutzer initiiert werden und sofortige Ergebnisse erwarten lassen, etwa das Öffnen eines Dokuments oder das Klicken auf eine Schaltfläche, die Berechnungen erfordert. Diese Aufgaben haben eine hohe Priorität, liegen jedoch unter User Interactive.
3. **Utility:**
- Diese Aufgaben laufen lange und zeigen typischerweise einen Fortschrittsindikator an (z. B. das Herunterladen von Dateien oder der Import von Daten). Ihre Priorität ist niedriger als die von benutzerinitiierten Aufgaben, und sie müssen nicht sofort abgeschlossen werden.
4. **Background:**
- Diese Klasse ist für Aufgaben vorgesehen, die im Hintergrund ausgeführt werden und für den Benutzer nicht sichtbar sind. Dazu können Indexierung, Synchronisierung oder Backups gehören. Sie haben die niedrigste Priorität und nur minimale Auswirkungen auf die Systemleistung.

Durch die Verwendung von QoS-Klassen müssen Entwickler keine exakten Prioritätswerte verwalten, sondern können sich auf die Art der Aufgabe konzentrieren. Das System optimiert die CPU-Ressourcen entsprechend.

Darüber hinaus gibt es verschiedene **Thread-Scheduling-Policies**, mit denen eine Reihe von Scheduling-Parametern festgelegt wird, die der Scheduler berücksichtigt. Dies kann mithilfe von `thread_policy_[set/get]` erfolgen. Dies kann bei Race-Condition-Angriffen nützlich sein.

## macOS Process Abuse

macOS stellt viele Mechanismen bereit, über die **Prozesse interagieren, kommunizieren und Daten gemeinsam nutzen** können. Obwohl diese Mechanismen für den normalen Systembetrieb unerlässlich sind, können Angreifer sie für Injection, Codeausführung oder Datenzugriff missbrauchen.

### Library Injection

Library Injection ist eine Technik, bei der ein Angreifer **einen Prozess dazu zwingt, eine bösartige Library zu laden**. Nach der Injection wird die Library im Kontext des Zielprozesses ausgeführt und bietet dem Angreifer dieselben Berechtigungen und Zugriffe wie der Prozess.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking umfasst das **Abfangen von Funktionsaufrufen** oder Nachrichten innerhalb eines Software-Codes. Durch das Hooking von Funktionen kann ein Angreifer **das Verhalten** eines Prozesses ändern, sensible Daten beobachten oder sogar die Kontrolle über den Ausführungsfluss erlangen.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) bezeichnet verschiedene Methoden, mit denen getrennte Prozesse **Daten gemeinsam nutzen und austauschen**. Obwohl IPC für viele legitime Anwendungen grundlegend ist, kann es auch missbraucht werden, um die Prozessisolation zu umgehen, sensible Informationen zu leaken oder nicht autorisierte Aktionen auszuführen.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron applications, die mit bestimmten Umgebungsvariablen ausgeführt werden, können für Process Injection anfällig sein:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Es ist möglich, die Flags `--load-extension` und `--use-fake-ui-for-media-stream` zu verwenden, um einen **man in the browser attack** durchzuführen, der das Stehlen von Tastenanschlägen und Traffic, den Diebstahl von Cookies sowie die Injection von Scripts in Seiten ermöglicht:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-Dateien **definieren Elemente der Benutzeroberfläche (UI)** und deren Interaktionen innerhalb einer Anwendung. Sie können jedoch **beliebige Befehle ausführen**, und **Gatekeeper verhindert nicht**, dass eine bereits ausgeführte Anwendung erneut ausgeführt wird, wenn eine **NIB-Datei geändert** wurde. Daher könnten sie verwendet werden, um beliebige Programme beliebige Befehle ausführen zu lassen:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Es ist möglich, JVM-Optionen über **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** oder **`JDK_JAVA_OPTIONS`** zu injizieren und vor dem Start der Anwendung einen Java- oder nativen Agent zu laden.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Es ist möglich, Code über **`DOTNET_STARTUP_HOOKS`** vor `Main` in .NET-Anwendungen zu injizieren oder die .NET-Debugging-Funktionalität zu missbrauchen, wenn deren Voraussetzungen erfüllt sind.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nicht-interaktives Bash liest **`BASH_ENV`**; zsh liest **`$ZDOTDIR/.zshenv`**; und fish liest Konfigurationen unter **`XDG_CONFIG_HOME`** oder **`XDG_DATA_DIRS`**. Jede dieser Shells kann vor dem vorgesehenen Befehl eine kontrollierte Startup-Datei ausführen:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** oder **`PHP_INI_SCAN_DIR`** können eine kontrollierte PHP-Konfiguration laden, deren **`auto_prepend_file`** vor dem Ziel-Script ausgeführt wird.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Der eigenständige Lua-Interpreter führt Code oder eine `@file` aus **`LUA_INIT`** (oder dessen versionsspezifischer Variante) aus, bevor das Ziel-Script verarbeitet wird.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** und **`R_PROFILE`** leiten Startup-Profile um, die R-Code enthalten. Mit **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** und einem R-Library-Pfad kann stattdessen automatisch ein installiertes Package geladen werden.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** leitet das Depot um, dessen `config/startup.jl` automatisch ausgeführt wird.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** oder **`ERL_ZFLAGS`** können einen Erlang-VM-**`-eval`**-Ausdruck injizieren, ohne dass eine Payload-Datei erforderlich ist; Elixir-Workloads starten üblicherweise dieselbe VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** und **`OCTAVE_VERSION_INITFILE`** leiten Octave-Startup-Scripts um.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

Unter macOS und Linux kann **`XDG_CONFIG_HOME`** PowerShell-Benutzerprofile umleiten, die beim Start von `pwsh` ausgeführt werden.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Prüfe verschiedene Optionen, mit denen ein Perl-Script beliebigen Code ausführen kann:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Es ist ebenfalls möglich, Ruby-Umgebungsvariablen zu missbrauchen, damit beliebige Scripts beliebigen Code ausführen:

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die Standard-Library-Kette aus **`PYTHONWARNINGS`** und **`BROWSER`** kann während der Verarbeitung von Warning-Filtern einen Befehl ausführen. Eine dateibasierte Alternative platziert `sitecustomize.py` über **`PYTHONPATH`**, sodass die normale `site`-Initialisierung die Datei vor dem Ziel-Script importiert. Variablen, die nur interaktiv gelten, wie **`PYTHONSTARTUP`**, sind nur eingeschränkt einsetzbar.

Beachte, dass mit **`pyinstaller`** kompilierte Executables diese Umgebungsvariablen nicht verwenden, selbst wenn sie einen eingebetteten Python-Interpreter ausführen.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

Unabhängig davon installiert Homebrew Python häufig unter `/opt/homebrew`, wo Mitglieder der lokalen Gruppe `admin` möglicherweise den Launcher ersetzen können. Dabei handelt es sich um einen Hijack eines beschreibbaren Binaries und nicht um eine Injection über Umgebungsvariablen. Überprüfe Eigentümer und ACLs, bevor du dies als ausnutzbar einstufst.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ist eine auf **EndpointSecurity** basierende Open-Source-Anwendung, die Process Injection erkennt und blockiert. Sie ist eine gute Referenz dafür, welche Signale über Endpoint Security beobachtbar sind, da sie Folgendes meldet:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-Umgebungsvariablen** bei der Process Execution: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` und `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-Aufrufe – ein Prozess fordert den Task-Port eines anderen Prozesses an, was eine Voraussetzung für die Injection in diesen Prozess ist.
- **Electron-Debugging-Argumente** – `--inspect`, `--inspect-brk` und `--remote-debugging-port`, die eine Electron-App im Debug-Modus starten und jedem ermöglichen, eine Verbindung herzustellen und darin Code auszuführen.<sup>[[3]](#references)</sup>
- **Symlink-/Hardlink-Erstellung über Berechtigungsstufen hinweg** – das klassische Primitive „als normaler Benutzer einen Link anlegen und auf einen privilegierten Speicherort zeigen lassen“. Beachte, dass **Symlinks zwar gemeldet, aber nicht blockiert werden können**: EndpointSecurity stellt das Linkziel vor der Erstellung nicht bereit.

### Calls made by other processes

In [**diesem Blogbeitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) wird beschrieben, wie die Funktion **`task_name_for_pid`** verwendet werden kann, um Informationen über andere **Prozesse zu erhalten, die Code in einen Prozess injizieren**, und anschließend Informationen über diesen anderen Prozess abzurufen.<sup>[[4]](#references)</sup>

Beachte, dass du zum Aufrufen dieser Funktion **dieselbe UID** wie der Prozess benötigen oder **root** sein musst (und sie Informationen über den Prozess zurückgibt, jedoch keine Möglichkeit zur Code-Injection).

## References

- [1] [Shield — Open-Source-Erkennung von macOS-Process-Injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-Framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Warum Electron-Apps deine Secrets nicht vertraulich speichern können: --inspect-Option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Erkennung von Task-Modifikationen](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
