# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Prozessen

Ein Prozess ist eine Instanz einer laufenden ausführbaren Datei. Code wird jedoch nicht von Prozessen ausgeführt, sondern von Threads. Daher sind **Prozesse lediglich Container für laufende Threads**, die Speicher, Deskriptoren, Ports, Berechtigungen usw. bereitstellen.

Traditionell wurden Prozesse innerhalb anderer Prozesse gestartet (mit Ausnahme von PID 1), indem **`fork`** aufgerufen wurde. Dadurch wurde eine exakte Kopie des aktuellen Prozesses erstellt. Anschließend rief der **Child-Prozess** im Allgemeinen **`execve`** auf, um die neue ausführbare Datei zu laden und auszuführen. Danach wurde **`vfork`** eingeführt, um diesen Prozess ohne Speicherkopieren zu beschleunigen.\
Anschließend wurde **`posix_spawn`** eingeführt, das **`vfork`** und **`execve`** in einem Aufruf kombiniert und Flags akzeptiert:

- `POSIX_SPAWN_RESETIDS`: Effektive IDs auf reale IDs zurücksetzen
- `POSIX_SPAWN_SETPGROUP`: Prozessgruppenzugehörigkeit festlegen
- `POSUX_SPAWN_SETSIGDEF`: Standardverhalten von Signalen festlegen
- `POSIX_SPAWN_SETSIGMASK`: Signalmaske festlegen
- `POSIX_SPAWN_SETEXEC`: Im selben Prozess ausführen (wie `execve` mit mehr Optionen)
- `POSIX_SPAWN_START_SUSPENDED`: Suspendiert starten
- `_POSIX_SPAWN_DISABLE_ASLR`: Ohne ASLR starten
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Den Nano-Allocator von libmalloc verwenden
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` `rwx` für Datensegmente erlauben
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Standardmäßig alle Dateideskriptoren bei exec(2) schließen
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Die hohen Bits des ASLR-Slides randomisieren

Außerdem akzeptiert `posix_spawn` **`posix_spawnattr`**-Einstellungen, die Aspekte des gestarteten Prozesses steuern, sowie **`posix_spawn_file_actions`**-Einträge, die Dateideskriptoren verändern.

Wenn ein Prozess beendet wird, sendet er den **Rückgabecode an den übergeordneten Prozess** (falls der übergeordnete Prozess beendet wurde, ist der neue übergeordnete Prozess PID 1) mit dem Signal `SIGCHLD`. Der übergeordnete Prozess muss diesen Wert durch den Aufruf von `wait4()` oder `waitid()` abrufen. Bis dies geschieht, verbleibt der Child-Prozess in einem Zombie-Zustand, in dem er weiterhin aufgelistet wird, aber keine Ressourcen verbraucht.

### PIDs

PIDs, also Prozesskennungen, identifizieren einen eindeutigen Prozess. In XNU sind die **PIDs** 64-Bit-Werte, die monoton ansteigen und **niemals überlaufen** (um Missbrauch zu verhindern).

### Prozessgruppen, Sessions & Coalitions

**Prozesse** können in **Gruppen** eingefügt werden, um ihre Verwaltung zu vereinfachen. Befehle in einem Shell-Script befinden sich beispielsweise in derselben Prozessgruppe, sodass sie etwa mit kill gemeinsam **signalisiert** werden können.\
Es ist auch möglich, **Prozesse in Sessions zu gruppieren**. Wenn ein Prozess eine Session startet (`setsid(2)`), werden die Child-Prozesse in diese Session aufgenommen, sofern sie nicht ihre eigene Session starten.

Coalition ist eine weitere Möglichkeit, Prozesse in Darwin zu gruppieren. Wenn ein Prozess einer Coalition beitritt, kann er auf Ressourcen-Pools zugreifen, ein Ledger gemeinsam nutzen oder von Jetsam betroffen sein. Coalitions haben verschiedene Rollen: Leader, XPC service, Extension.

### Anmeldedaten & Personas

Jeder Prozess verfügt über **Anmeldedaten**, die **seine Berechtigungen** im System identifizieren. Jeder Prozess besitzt eine primäre `uid` und eine primäre `gid` (kann jedoch mehreren Gruppen angehören).\
Es ist auch möglich, die Benutzer- und Gruppen-ID zu ändern, wenn die Binärdatei über das **`setuid/setgid`**-Bit verfügt.\
Es gibt mehrere Funktionen zum **Setzen neuer uids/gids**.

Der Syscall **`persona`** stellt einen alternativen Satz von **Anmeldedaten** bereit. Die Übernahme einer Persona übernimmt gleichzeitig deren UID, GID und Gruppenmitgliedschaften. Im [**Quellcode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) ist die Struktur zu finden:
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

1. **POSIX Threads (pthreads):** macOS unterstützt POSIX Threads (`pthreads`), die Teil einer standardisierten Threading-API für C/C++ sind. Die Implementierung von pthreads in macOS befindet sich in `/usr/lib/system/libsystem_pthread.dylib` und stammt aus dem öffentlich verfügbaren Projekt `libpthread`. Diese Bibliothek stellt die notwendigen Funktionen zum Erstellen und Verwalten von Threads bereit.
2. **Erstellen von Threads:** Die Funktion `pthread_create()` wird verwendet, um neue Threads zu erstellen. Intern ruft diese Funktion `bsdthread_create()` auf, einen spezifischen Systemaufruf des XNU-Kernels (des Kernels, auf dem macOS basiert). Dieser Systemaufruf übernimmt verschiedene aus `pthread_attr` (Attributen) abgeleitete Flags, die das Verhalten des Threads festlegen, einschließlich Scheduling-Richtlinien und Stack-Größe.
- **Standard-Stackgröße:** Die Standard-Stackgröße für neue Threads beträgt 512 KB. Dies ist für typische Vorgänge ausreichend, kann aber über Thread-Attribute angepasst werden, wenn mehr oder weniger Speicher benötigt wird.
3. **Thread-Initialisierung:** Die Funktion `__pthread_init()` ist während der Einrichtung eines Threads entscheidend. Sie verwendet das Argument `env[]`, um Umgebungsvariablen zu analysieren, die unter anderem Angaben zur Position und Größe des Stacks enthalten können.

#### Beenden von Threads in macOS

1. **Beenden von Threads:** Threads werden normalerweise durch den Aufruf von `pthread_exit()` beendet. Diese Funktion ermöglicht es einem Thread, sich ordnungsgemäß zu beenden, notwendige Bereinigungen durchzuführen und einen Rückgabewert an wartende Threads zu senden.
2. **Thread-Bereinigung:** Beim Aufruf von `pthread_exit()` wird die Funktion `pthread_terminate()` aufgerufen, die das Entfernen aller zugehörigen Thread-Strukturen übernimmt. Sie gibt Mach-Thread-Ports frei (Mach ist das Kommunikationssubsystem im XNU-Kernel) und ruft `bsdthread_terminate` auf, einen syscall, der die mit dem Thread verbundenen Strukturen auf Kernel-Ebene entfernt.

#### Synchronisierungsmechanismen

Um den Zugriff auf gemeinsam genutzte Ressourcen zu verwalten und Race Conditions zu vermeiden, stellt macOS mehrere Synchronisierungsprimitive bereit. Diese sind in Multithreading-Umgebungen entscheidend, um Datenintegrität und Systemstabilität sicherzustellen:

1. **Mutexes:**
- **Regulärer Mutex (Signatur: 0x4D555458):** Standard-Mutex mit einem Speicherbedarf von 60 Bytes (56 Bytes für den Mutex und 4 Bytes für die Signatur).
- **Schneller Mutex (Signatur: 0x4d55545A):** Ähnlich wie ein regulärer Mutex, jedoch für schnellere Vorgänge optimiert, ebenfalls mit einer Größe von 60 Bytes.
2. **Bedingungsvariablen:**
- Werden verwendet, um auf das Eintreten bestimmter Bedingungen zu warten, und haben eine Größe von 44 Bytes (40 Bytes plus eine 4-Byte-Signatur).
- **Attribute von Bedingungsvariablen (Signatur: 0x434e4441):** Konfigurationsattribute für Bedingungsvariablen mit einer Größe von 12 Bytes.
3. **Once-Variable (Signatur: 0x4f4e4345):**
- Stellt sicher, dass ein Initialisierungscode nur einmal ausgeführt wird. Ihre Größe beträgt 12 Bytes.
4. **Read-Write-Locks:**
- Ermöglichen mehrere Leser oder jeweils einen Schreiber und sorgen so für einen effizienten Zugriff auf gemeinsam genutzte Daten.
- **Read Write Lock (Signatur: 0x52574c4b):** Hat eine Größe von 196 Bytes.
- **Read Write Lock Attributes (Signatur: 0x52574c41):** Attribute für Read-Write-Locks mit einer Größe von 20 Bytes.

> [!TIP]
> Die letzten 4 Bytes dieser Objekte werden verwendet, um Overflows zu erkennen.

### Thread-lokale Variablen (TLV)

**Thread Local Variables (TLV)** im Kontext von Mach-O-Dateien (dem Format für ausführbare Dateien in macOS) werden verwendet, um Variablen zu deklarieren, die für **jeden Thread** in einer Multithreading-Anwendung spezifisch sind. Dadurch verfügt jeder Thread über eine eigene separate Instanz einer Variablen. So lassen sich Konflikte vermeiden und die Datenintegrität aufrechterhalten, ohne explizite Synchronisierungsmechanismen wie Mutexes zu benötigen.

In C und verwandten Sprachen kann eine thread-lokale Variable mit dem Schlüsselwort **`__thread`** deklariert werden. So funktioniert es in Ihrem Beispiel:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Dieser Ausschnitt definiert `tlv_var` als thread-lokale Variable. Jeder Thread, der diesen Code ausführt, verfügt über eine eigene `tlv_var`, und Änderungen, die ein Thread an `tlv_var` vornimmt, wirken sich nicht auf `tlv_var` in einem anderen Thread aus.

In der Mach-O-Binärdatei sind die Daten zu thread-lokalen Variablen in bestimmten Sections organisiert:

- **`__DATA.__thread_vars`**: Diese Section enthält Metadaten zu den thread-lokalen Variablen, etwa deren Typen und Initialisierungsstatus.
- **`__DATA.__thread_bss`**: Diese Section wird für thread-lokale Variablen verwendet, die nicht explizit initialisiert werden. Sie ist ein für nullinitialisierte Daten reservierter Speicherbereich.

Mach-O stellt außerdem eine spezielle API namens **`tlv_atexit`** zur Verwaltung thread-lokaler Variablen beim Beenden eines Threads bereit. Diese API ermöglicht es, **Destruktoren zu registrieren** – spezielle Funktionen, die thread-lokale Daten bereinigen, wenn ein Thread beendet wird.

### Threading-Prioritäten

Um Thread-Prioritäten zu verstehen, muss betrachtet werden, wie das Betriebssystem entscheidet, welche Threads wann ausgeführt werden. Diese Entscheidung wird durch die jedem Thread zugewiesene Prioritätsstufe beeinflusst. In macOS und Unix-ähnlichen Systemen wird dies mithilfe von Konzepten wie `nice`, `renice` und Quality-of-Service-(QoS-)Klassen umgesetzt.

#### Nice und Renice

1. **Nice:**
- Der `nice`-Wert eines Prozesses ist eine Zahl, die dessen Priorität beeinflusst. Jeder Prozess hat einen Nice-Wert zwischen -20 (höchste Priorität) und 19 (niedrigste Priorität). Der Standard-Nice-Wert bei der Erstellung eines Prozesses ist normalerweise 0.
- Ein niedrigerer Nice-Wert (näher an -20) macht einen Prozess „egoistischer“, sodass er im Vergleich zu anderen Prozessen mit höheren Nice-Werten mehr CPU-Zeit erhält.
2. **Renice:**
- `renice` ist ein Befehl, mit dem der Nice-Wert eines bereits laufenden Prozesses geändert wird. Damit kann die Priorität von Prozessen dynamisch angepasst und abhängig von den neuen Nice-Werten deren Zuteilung an CPU-Zeit erhöht oder verringert werden.
- Wenn ein Prozess beispielsweise vorübergehend mehr CPU-Ressourcen benötigt, kann sein Nice-Wert mit `renice` gesenkt werden.

#### Quality-of-Service-(QoS-)Klassen

QoS-Klassen sind ein modernerer Ansatz zur Verwaltung von Thread-Prioritäten, insbesondere in Systemen wie macOS, die **Grand Central Dispatch (GCD)** unterstützen. QoS-Klassen ermöglichen es Entwicklern, Arbeit anhand ihrer Bedeutung oder Dringlichkeit in verschiedene Stufen zu **kategorisieren**. macOS verwaltet die Thread-Priorisierung automatisch auf Grundlage dieser QoS-Klassen:

1. **User Interactive:**
- Diese Klasse ist für Aufgaben vorgesehen, die momentan mit dem Benutzer interagieren oder sofortige Ergebnisse benötigen, um eine gute Benutzererfahrung zu gewährleisten. Diese Aufgaben erhalten die höchste Priorität, damit die Benutzeroberfläche reaktionsfähig bleibt (z. B. Animationen oder Ereignisverarbeitung).
2. **User Initiated:**
- Aufgaben, die vom Benutzer gestartet werden und sofortige Ergebnisse erwarten lassen, etwa das Öffnen eines Dokuments oder das Klicken auf eine Schaltfläche, die Berechnungen erfordert. Sie haben eine hohe Priorität, liegen aber unter User Interactive.
3. **Utility:**
- Diese Aufgaben laufen lange und zeigen normalerweise einen Fortschrittsindikator an (z. B. das Herunterladen von Dateien oder der Import von Daten). Sie haben eine niedrigere Priorität als vom Benutzer gestartete Aufgaben und müssen nicht sofort abgeschlossen werden.
4. **Background:**
- Diese Klasse ist für Aufgaben vorgesehen, die im Hintergrund ausgeführt werden und für den Benutzer nicht sichtbar sind. Dazu gehören beispielsweise Indexierung, Synchronisierung oder Backups. Sie haben die niedrigste Priorität und nur minimale Auswirkungen auf die Systemleistung.

Durch die Verwendung von QoS-Klassen müssen Entwickler nicht die genauen Prioritätswerte verwalten, sondern können sich auf die Art der Aufgabe konzentrieren, während das System die CPU-Ressourcen entsprechend optimiert.

Außerdem gibt es verschiedene **Thread-Scheduling-Richtlinien**, mit denen sich eine Reihe von Scheduling-Parametern festlegen lässt, die der Scheduler berücksichtigt. Dies kann mithilfe von `thread_policy_[set/get]` erfolgen. Das kann bei Race-Condition-Angriffen nützlich sein.

## macOS Process Abuse

macOS stellt viele Mechanismen bereit, damit **Prozesse interagieren, kommunizieren und Daten gemeinsam nutzen** können. Obwohl diese Mechanismen für den normalen Systembetrieb essenziell sind, können Angreifer sie für Injection, Codeausführung oder Datenzugriff missbrauchen.

### Library Injection

Library Injection ist eine Technik, bei der ein Angreifer **einen Prozess dazu zwingt, eine schädliche Library zu laden**. Nach der Injection läuft die Library im Kontext des Zielprozesses und gewährt dem Angreifer dieselben Berechtigungen und Zugriffe wie dem Prozess.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking beinhaltet das **Abfangen von Funktionsaufrufen** oder Nachrichten innerhalb eines Softwarecodes. Durch das Hooking von Funktionen kann ein Angreifer **das Verhalten** eines Prozesses ändern, vertrauliche Daten beobachten oder sogar die Kontrolle über den Ausführungsfluss erlangen.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) bezeichnet verschiedene Methoden, mit denen getrennte Prozesse **Daten gemeinsam nutzen und austauschen**. Obwohl IPC für viele legitime Anwendungen grundlegend ist, kann es auch missbraucht werden, um die Prozessisolation zu umgehen, vertrauliche Informationen zu leaken oder nicht autorisierte Aktionen auszuführen.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-Anwendungen, die mit bestimmten Umgebungsvariablen ausgeführt werden, können anfällig für Process Injection sein:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Es ist möglich, die Flags `--load-extension` und `--use-fake-ui-for-media-stream` für einen **man-in-the-browser-Angriff** zu verwenden, durch den sich Tastatureingaben und Datenverkehr stehlen sowie Cookies und Scripts in Seiten injizieren lassen:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-Dateien **definieren Elemente der Benutzeroberfläche (UI)** und deren Interaktionen innerhalb einer Anwendung. Sie können jedoch **beliebige Befehle ausführen**, und **Gatekeeper verhindert nicht**, dass eine bereits ausgeführte Anwendung erneut ausgeführt wird, wenn eine **NIB-Datei geändert** wurde. Daher könnten sie verwendet werden, damit beliebige Programme beliebige Befehle ausführen:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Es ist möglich, JVM-Optionen über **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** oder **`JDK_JAVA_OPTIONS`** zu injizieren und vor dem Start der Anwendung einen Java- oder nativen Agent zu laden.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** lädt über `--require` (Datei) oder **`--import data:text/javascript,…`** (fileless, Node ≥ 20.6) vorab JavaScript des Angreifers; **`NODE_REPL_EXTERNAL_MODULE`** lädt ein Modul in eine interaktive REPL, und **`ELECTRON_RUN_AS_NODE`** aktiviert all dies für Electron-Binärdateien erneut.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Es ist möglich, Code vor `Main` über **`DOTNET_STARTUP_HOOKS`** in .NET-Anwendungen zu injizieren oder bei vorhandenen Voraussetzungen die .NET-Debugging-Funktionalität zu missbrauchen.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nicht-interaktive Bash liest **`BASH_ENV`**; interaktive POSIX-Shells lesen **`ENV`**; zsh liest **`$ZDOTDIR/.zshenv`**; und fish liest Konfigurationen unter **`XDG_CONFIG_HOME`** oder **`XDG_DATA_DIRS`**. Jede dieser Shells kann vor dem vorgesehenen Befehl eine kontrollierte Startup-Datei ausführen. Bash führt außerdem eine in **`PS4`** platzierte Command Substitution aus, sobald xtrace aktiviert ist (z. B. durch geerbtes **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** oder **`PHP_INI_SCAN_DIR`** können eine kontrollierte PHP-Konfiguration laden, deren **`auto_prepend_file`** vor dem Zielscript ausgeführt wird.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Der eigenständige Lua-Interpreter führt vor der Verarbeitung des Zielscripts Code oder eine `@file` aus **`LUA_INIT`** (oder dessen versionsspezifischer Variante) aus.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** und **`R_PROFILE`** leiten Startup-Profile um, die R-Code enthalten. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** können zusammen mit einem R-Library-Pfad stattdessen ein installiertes Package automatisch laden.

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

`pwsh` ist eine plattformübergreifende .NET-Anwendung, daher ermöglichen mehrere Umgebungsvariablen eine Ausführung vor dem Befehl: **`XDG_CONFIG_HOME`** leitet die beim Start ausgeführten Profile-Scripts um, **`PSModulePath`** hijackt das automatische Laden von Modulen (ein platziertes `.psm1` wird beim Import ausgeführt und kann integrierte Cmdlets überschatten), und die .NET-Variablen **`CORECLR_PROFILER`**/**`COR_PROFILER`** sowie **`DOTNET_STARTUP_HOOKS`** laden vor `Main` Code des Angreifers in den Prozess.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Prüfe verschiedene Optionen, um ein Perl-Script dazu zu bringen, beliebigen Code auszuführen:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Es ist ebenfalls möglich, Ruby-Umgebungsvariablen (**`RUBYOPT`**, **`RUBYLIB`**) zu missbrauchen, damit beliebige Scripts beliebigen Code ausführen:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die **`PYTHONWARNINGS`**- und **`BROWSER`**-Standard-Library-Chain kann während der Analyse von Warnungsfiltern einen Befehl ausführen. Eine dateibasierte Alternative platziert `sitecustomize.py` auf **`PYTHONPATH`**, sodass die normale `site`-Initialisierung die Datei vor dem Zielscript importiert. **`PYTHONBREAKPOINT`** führt einen ausgewählten Callable bzw. ein Modul aus, wenn der Code `breakpoint()` erreicht. Nur interaktive Variablen wie **`PYTHONSTARTUP`** sind weniger breit einsetzbar.

Beachte, dass mit **`pyinstaller`** kompilierte Executables diese Umgebungsvariablen nicht verwenden, selbst wenn sie einen eingebetteten Python-Interpreter nutzen.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (und dessen Fallback **`EXINIT`**) wird bei einem normalen Start als Ex-Befehle ausgeführt. Daher ermöglichen `:!cmd` / `:call system(...)` Codeausführung, wenn ein Opfer Vim/Neovim mit einer kontrollierten Umgebung öffnet:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Unabhängig davon installiert Homebrew Python häufig unter `/opt/homebrew`, wo Mitglieder der lokalen Gruppe `admin` möglicherweise den Launcher ersetzen können. Das ist ein Binary-Hijacking mit beschreibbarer Datei und keine Injection über Umgebungsvariablen. Überprüfe Eigentümer und ACLs, bevor du dies als ausnutzbar einstufst.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ist eine auf **EndpointSecurity** basierende Open-Source-Anwendung, die Process Injection erkennt und blockiert. Sie ist eine gute Referenz dafür, welche Signale über Endpoint Security beobachtbar sind, da sie auf Folgendes reagiert:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-Umgebungsvariablen** bei der Prozessausführung: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` und `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-Aufrufe – ein Prozess fordert den Task-Port eines anderen Prozesses an, was die Voraussetzung für eine Injection in diesen Prozess ist.
- **Electron-Debugging-Argumente** – `--inspect`, `--inspect-brk` und `--remote-debugging-port`, die eine Electron-Anwendung im Debug-Modus starten und es jedem ermöglichen, sich anzuhängen und darin Code auszuführen.<sup>[[3]](#references)</sup>
- **Erstellung von Symlinks/Hardlinks über Berechtigungsstufen hinweg** – das klassische Primitive „als normaler Benutzer einen Link platzieren und auf einen privilegierten Speicherort verweisen“. Beachte, dass **Symlinks erkannt, aber nicht blockiert werden können**: EndpointSecurity stellt das Linkziel vor der Erstellung nicht bereit.

### Calls made by other processes

In [**diesem Blogbeitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) wird beschrieben, wie sich die Funktion **`task_name_for_pid`** verwenden lässt, um Informationen über andere **Prozesse zu erhalten, die Code in einen Prozess injizieren**, und anschließend Informationen über diesen anderen Prozess abzurufen.<sup>[[4]](#references)</sup>

Beachte, dass du zum Aufrufen dieser Funktion **dieselbe UID** wie der Prozess oder **root** benötigst (und sie Informationen über den Prozess zurückgibt, aber keine Möglichkeit zur Code-Injection).

## References

- [1] [Shield – Open-Source-Erkennung von macOS Process Injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer – EndpointSecurity-Framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew – Warum Electron-Apps deine Secrets nicht vertraulich speichern können: --inspect-Option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight – Erkennung von Task-Modifikationen](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
