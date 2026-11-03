# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Prozessen

Ein Prozess ist eine Instanz einer laufenden ausführbaren Datei. Prozesse führen jedoch keinen Code aus – das tun Threads. Daher **sind Prozesse lediglich Container für laufende Threads**, die Speicher, Deskriptoren, Ports, Berechtigungen usw. bereitstellen.

Traditionell wurden Prozesse innerhalb anderer Prozesse gestartet (außer PID 1), indem **`fork`** aufgerufen wurde. Dadurch wurde eine exakte Kopie des aktuellen Prozesses erstellt. Anschließend rief der **Kindprozess** üblicherweise **`execve`** auf, um die neue ausführbare Datei zu laden und auszuführen. Danach wurde **`vfork`** eingeführt, um diesen Vorgang ohne Speicherkopien zu beschleunigen.\
Anschließend wurde **`posix_spawn`** eingeführt, das **`vfork`** und **`execve`** in einem Aufruf kombiniert und Flags akzeptiert:

- `POSIX_SPAWN_RESETIDS`: Effektive IDs auf reale IDs zurücksetzen
- `POSIX_SPAWN_SETPGROUP`: Prozessgruppenzugehörigkeit festlegen
- `POSUX_SPAWN_SETSIGDEF`: Standardverhalten für Signale festlegen
- `POSIX_SPAWN_SETSIGMASK`: Signalmaske festlegen
- `POSIX_SPAWN_SETEXEC`: Im selben Prozess ausführen (wie `execve`, aber mit mehr Optionen)
- `POSIX_SPAWN_START_SUSPENDED`: Angehalten starten
- `_POSIX_SPAWN_DISABLE_ASLR`: Ohne ASLR starten
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Den Nano-Allocator von libmalloc verwenden
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` `rwx` für Datensegmente zulassen
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Standardmäßig alle Dateibeschreibungen bei exec(2) schließen
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Hohe Bits des ASLR-Slides randomisieren

Außerdem akzeptiert `posix_spawn` **`posix_spawnattr`**-Einstellungen, die Aspekte des gestarteten Prozesses steuern, sowie **`posix_spawn_file_actions`**-Einträge, die Dateideskriptoren ändern.

Wenn ein Prozess beendet wird, sendet er seinen **Rückgabecode an den Elternprozess** (falls der Elternprozess beendet wurde, ist PID 1 der neue Elternprozess) und löst dabei das Signal `SIGCHLD` aus. Der Elternprozess muss diesen Wert mit `wait4()` oder `waitid()` abrufen. Bis dahin bleibt der Kindprozess in einem Zombie-Zustand: Er wird weiterhin aufgelistet, verbraucht aber keine Ressourcen.

### PIDs

PIDs (Prozesskennungen) identifizieren einen eindeutigen Prozess. In XNU sind **PIDs** **64 Bit** groß, steigen monoton an und **laufen niemals über** (um Missbrauch zu verhindern).

### Prozessgruppen, Sitzungen & Koalitionen

**Prozesse** können zu **Gruppen** zusammengefasst werden, um ihre Verwaltung zu vereinfachen. Beispielsweise gehören Befehle in einem Shell-Skript derselben Prozessgruppe an, sodass sie gemeinsam signalisiert werden können, etwa mit kill.\
Prozesse können auch zu **Sitzungen zusammengefasst** werden. Wenn ein Prozess eine Sitzung startet (`setsid(2)`), werden seine Kindprozesse dieser Sitzung zugeordnet, sofern sie nicht selbst eine Sitzung starten.

Eine Koalition ist eine weitere Möglichkeit, Prozesse in Darwin zu gruppieren. Ein Prozess, der einer Koalition beitritt, kann auf gemeinsam genutzte Pool-Ressourcen zugreifen, ein Ledger gemeinsam nutzen oder von Jetsam betroffen sein. Koalitionen haben verschiedene Rollen: Leader, XPC-Dienst und Extension.

### Anmeldedaten & Personas

Jeder Prozess besitzt **Anmeldedaten**, die seine **Berechtigungen** im System festlegen. Jeder Prozess hat eine primäre `uid` und eine primäre `gid` (kann aber mehreren Gruppen angehören).\
Die Benutzer- und Gruppen-ID kann außerdem geändert werden, wenn die ausführbare Datei das `setuid/setgid`-Bit gesetzt hat.\
Es gibt mehrere Funktionen, um **neue UIDs/GIDs festzulegen**.

Der Systemaufruf **`persona`** stellt einen alternativen Satz von **Anmeldedaten** bereit. Die Annahme einer Persona übernimmt deren UID, GID und Gruppenmitgliedschaften **auf einmal**. Im [**Quellcode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) lässt sich folgende Struktur finden:

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
2. **Threads erstellen:** Mit der Funktion `pthread_create()` werden neue Threads erstellt. Intern ruft diese Funktion `bsdthread_create()` auf, einen niedrigeren Systemaufruf, der spezifisch für den XNU-Kernel ist (den Kernel, auf dem macOS basiert). Dieser Systemaufruf erhält verschiedene Flags, die von `pthread_attr` (Attributen) abgeleitet werden und das Verhalten des Threads festlegen, darunter Scheduling-Richtlinien und die Stack-Größe.
   - **Standard-Stack-Größe:** Die Standard-Stack-Größe für neue Threads beträgt 512 KB. Das reicht für typische Vorgänge aus, kann aber über Thread-Attribute angepasst werden, wenn mehr oder weniger Speicher benötigt wird.
3. **Thread-Initialisierung:** Die Funktion `__pthread_init()` ist beim Einrichten eines Threads entscheidend. Sie verwendet das Argument `env[]`, um Umgebungsvariablen auszuwerten, die Angaben zum Speicherort und zur Größe des Stacks enthalten können.

#### Thread-Beendigung in macOS

1. **Threads beenden:** Threads werden üblicherweise durch den Aufruf von `pthread_exit()` beendet. Diese Funktion ermöglicht es einem Thread, sauber zu beenden, notwendige Bereinigungsarbeiten durchzuführen und einen Rückgabewert an alle Threads zu übermitteln, die auf ihn warten.
2. **Thread-Bereinigung:** Beim Aufruf von `pthread_exit()` wird die Funktion `pthread_terminate()` aufgerufen. Sie entfernt alle zugehörigen Thread-Strukturen. Sie gibt Mach-Thread-Ports frei (Mach ist das Kommunikationssubsystem im XNU-Kernel) und ruft `bsdthread_terminate` auf, einen Systemaufruf, der die dem Thread zugeordneten Strukturen auf Kernel-Ebene entfernt.

#### Synchronisierungsmechanismen

macOS stellt verschiedene Synchronisierungsprimitive bereit, um den Zugriff auf gemeinsam genutzte Ressourcen zu verwalten und Race Conditions zu vermeiden. Diese sind in Multithreading-Umgebungen entscheidend, um die Datenintegrität und Systemstabilität zu gewährleisten:

1. **Mutexes:**
   - **Regulärer Mutex (Signatur: 0x4D555458):** Standard-Mutex mit einem Speicherbedarf von 60 Bytes (56 Bytes für den Mutex und 4 Bytes für die Signatur).
   - **Fast Mutex (Signatur: 0x4d55545A):** Ähnlich wie ein regulärer Mutex, aber für schnellere Operationen optimiert; ebenfalls 60 Bytes groß.
2. **Condition Variables:**
   - Werden verwendet, um auf bestimmte Bedingungen zu warten. Sie sind 44 Bytes groß (40 Bytes plus eine 4-Byte-Signatur).
   - **Condition-Variable-Attribute (Signatur: 0x434e4441):** Konfigurationsattribute für Condition Variables mit einer Größe von 12 Bytes.
3. **Once Variable (Signatur: 0x4f4e4345):**
   - Stellt sicher, dass ein Initialisierungscode nur einmal ausgeführt wird. Sie ist 12 Bytes groß.
4. **Read-Write Locks:**
   - Ermöglichen mehrere Leser oder jeweils einen Schreiber und damit einen effizienten Zugriff auf gemeinsam genutzte Daten.
   - **Read-Write-Lock (Signatur: 0x52574c4b):** 196 Bytes groß.
   - **Read-Write-Lock-Attribute (Signatur: 0x52574c41):** Attribute für Read-Write Locks mit einer Größe von 20 Bytes.

> [!TIP]
> Die letzten 4 Bytes dieser Objekte werden verwendet, um Overflows zu erkennen.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** werden im Kontext von Mach-O-Dateien (dem Format für ausführbare Dateien in macOS) verwendet, um Variablen zu deklarieren, die in einer Multithread-Anwendung **für jeden Thread** spezifisch sind. Dadurch verfügt jeder Thread über eine eigene Instanz einer Variable. So lassen sich Konflikte vermeiden und die Datenintegrität wahren, ohne explizite Synchronisierungsmechanismen wie Mutexes zu benötigen.

In C und verwandten Sprachen können Sie eine threadlokale Variable mit dem Schlüsselwort **`__thread`** deklarieren. So funktioniert es in Ihrem Beispiel:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Dieser Ausschnitt definiert `tlv_var` als threadlokale Variable. Jeder Thread, der diesen Code ausführt, hat seine eigene `tlv_var`. Änderungen, die ein Thread an `tlv_var` vornimmt, wirken sich nicht auf die `tlv_var` eines anderen Threads aus.

In der Mach-O-Binärdatei sind die Daten zu threadlokalen Variablen in bestimmten Sektionen organisiert:

- **`__DATA.__thread_vars`**: Diese Sektion enthält Metadaten zu den threadlokalen Variablen, etwa deren Typen und Initialisierungsstatus.
- **`__DATA.__thread_bss`**: Diese Sektion wird für threadlokale Variablen verwendet, die nicht explizit initialisiert werden. Sie ist ein Speicherbereich für nullinitialisierte Daten.

Mach-O stellt außerdem eine spezielle API namens **`tlv_atexit`** bereit, um threadlokale Variablen beim Beenden eines Threads zu verwalten. Mit dieser API können **Destruktoren registriert** werden – spezielle Funktionen, die threadlokale Daten beim Beenden eines Threads bereinigen.

### Threading-Prioritäten

Um Thread-Prioritäten zu verstehen, muss man betrachten, wie das Betriebssystem entscheidet, welche Threads wann ausgeführt werden. Diese Entscheidung wird durch die jedem Thread zugewiesene Prioritätsstufe beeinflusst. In macOS und Unix-ähnlichen Systemen wird dies mithilfe von Konzepten wie `nice`, `renice` und Quality-of-Service-Klassen (QoS) gehandhabt.

#### Nice und Renice

1. **Nice:**
   - Der `nice`-Wert eines Prozesses ist eine Zahl, die seine Priorität beeinflusst. Jeder Prozess hat einen `nice`-Wert zwischen -20 (höchste Priorität) und 19 (niedrigste Priorität). Der Standardwert für einen neu erstellten Prozess ist normalerweise 0.
   - Ein niedrigerer `nice`-Wert (näher an -20) macht einen Prozess „selbstsüchtiger“: Er erhält mehr CPU-Zeit als andere Prozesse mit höheren `nice`-Werten.
2. **Renice:**
   - `renice` ist ein Befehl, mit dem sich der `nice`-Wert eines bereits laufenden Prozesses ändern lässt. Damit kann die Priorität von Prozessen dynamisch angepasst und ihre CPU-Zuteilung anhand der neuen `nice`-Werte erhöht oder verringert werden.
   - Wenn ein Prozess beispielsweise vorübergehend mehr CPU-Ressourcen benötigt, kann man seinen `nice`-Wert mit `renice` senken.

#### Quality-of-Service-Klassen (QoS)

QoS-Klassen sind ein modernerer Ansatz zur Verwaltung von Thread-Prioritäten, insbesondere in Systemen wie macOS, die **Grand Central Dispatch (GCD)** unterstützen. Mit QoS-Klassen können Entwickler Arbeit je nach Bedeutung oder Dringlichkeit in verschiedene Stufen **einteilen**. macOS verwaltet die Thread-Priorisierung automatisch anhand dieser QoS-Klassen:

1. **User Interactive:**
   - Diese Klasse ist für Aufgaben vorgesehen, die gerade mit dem Benutzer interagieren oder sofortige Ergebnisse erfordern, damit eine gute Benutzererfahrung gewährleistet ist. Solche Aufgaben erhalten die höchste Priorität, damit die Benutzeroberfläche reaktionsfähig bleibt (z. B. Animationen oder Ereignisverarbeitung).
2. **User Initiated:**
   - Aufgaben, die der Benutzer startet und für die er sofortige Ergebnisse erwartet, etwa das Öffnen eines Dokuments oder das Anklicken einer Schaltfläche, die Berechnungen auslöst. Diese Aufgaben haben eine hohe Priorität, aber eine niedrigere als User Interactive.
3. **Utility:**
   - Diese Aufgaben laufen länger und zeigen typischerweise einen Fortschrittsindikator an (z. B. beim Herunterladen von Dateien oder Importieren von Daten). Sie haben eine niedrigere Priorität als vom Benutzer gestartete Aufgaben und müssen nicht sofort abgeschlossen werden.
4. **Background:**
   - Diese Klasse ist für Aufgaben vorgesehen, die im Hintergrund laufen und für den Benutzer nicht sichtbar sind. Dazu gehören etwa Indizierung, Synchronisierung oder Backups. Sie haben die niedrigste Priorität und wirken sich nur minimal auf die Systemleistung aus.

Mit QoS-Klassen müssen Entwickler keine genauen Prioritätswerte verwalten, sondern können sich auf die Art der Aufgabe konzentrieren. Das System optimiert die CPU-Ressourcen entsprechend.

Darüber hinaus gibt es verschiedene **Thread-Scheduling-Richtlinien**, mit denen sich eine Reihe von Scheduling-Parametern festlegen lässt, die der Scheduler berücksichtigt. Dies ist über `thread_policy_[set/get]` möglich und kann bei Race-Condition-Angriffen nützlich sein.

## Missbrauch von macOS-Prozessen

macOS bietet zahlreiche Mechanismen, mit denen **Prozesse miteinander interagieren, kommunizieren und Daten austauschen** können. Diese Mechanismen sind für den normalen Systembetrieb unverzichtbar, können von Angreifern jedoch für Injection, Codeausführung oder Datenzugriff missbraucht werden.

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

Inter Process Communication (IPC) bezeichnet verschiedene Methoden, mit denen getrennte Prozesse **Daten austauschen und gemeinsam nutzen**. IPC ist für viele legitime Anwendungen grundlegend, kann aber auch dazu missbraucht werden, die Prozessisolation zu unterlaufen, sensible Informationen zu leaken oder unbefugte Aktionen auszuführen.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-Anwendungen, die mit bestimmten Umgebungsvariablen gestartet werden, können für Process Injection anfällig sein:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Mit den Flags `--load-extension` und `--use-fake-ui-for-media-stream` lässt sich ein **man-in-the-browser-Angriff** durchführen, der das Stehlen von Tastenanschlägen, Traffic und Cookies sowie das Injizieren von Scripts in Seiten ermöglicht:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-Dateien **definieren Elemente der Benutzeroberfläche (UI)** und deren Interaktionen innerhalb einer Anwendung. Sie können jedoch **beliebige Befehle ausführen**, und **Gatekeeper verhindert nicht**, dass eine bereits ausgeführte Anwendung erneut ausgeführt wird, wenn eine **NIB-Datei verändert wurde**. Daher lassen sie sich dazu verwenden, beliebige Programme beliebige Befehle ausführen zu lassen:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Über **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** oder **`JDK_JAVA_OPTIONS`** lassen sich JVM-Optionen injizieren und ein Java- oder nativer Agent laden, bevor die Anwendung startet.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** lädt über `--require` (Datei) oder `--import data:text/javascript,…` (dateilos, Node ≥ 20.6) JavaScript des Angreifers vor. **`NODE_REPL_EXTERNAL_MODULE`** lädt ein Modul in eine interaktive REPL, und **`ELECTRON_RUN_AS_NODE`** reaktiviert all dies auf Electron-Binärdateien.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Code lässt sich vor `Main` in .NET-Anwendungen injizieren, indem **`DOTNET_STARTUP_HOOKS`** verwendet oder die .NET-Debugging-Funktion missbraucht wird, sofern deren Voraussetzungen erfüllt sind.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nicht-interaktive Bash liest **`BASH_ENV`**; interaktive POSIX-Shells lesen **`ENV`**; zsh liest **`$ZDOTDIR/.zshenv`**; und fish liest Konfigurationsdateien unter **`XDG_CONFIG_HOME`** oder **`XDG_DATA_DIRS`**. Jede dieser Variablen kann vor dem vorgesehenen Befehl eine kontrollierte Startdatei ausführen. Bash führt außerdem eine Command Substitution in **`PS4`** aus, wenn xtrace aktiviert ist (z. B. durch geerbtes **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Wird `/bin/zsh -s` gestartet, liest die Shell ein Programm von der Standardeingabe. Ein Downloader, der ein nicht vertrauenswürdiges strukturiertes Dokument ohne vorherige Analyse in die Standardeingabe eines untergeordneten Prozesses kopiert, macht daher das gesamte Dokument zum Shell-Code. Ein beobachteter Loader leitete eine öffentliche iCalendar-Datei zeilenweise durch eine anonyme Pipe. Kalender-Metadaten schlugen als Befehle fehl, aber zsh fuhr fort, bis ausführbare Zeilen nach `DESCRIPTION:` erreicht wurden. Diese Zeilen luden das nächste Application Bundle herunter und starteten es. Weder der erwartete Inhaltstyp des Trägers noch das vertrauenswürdige Hosting machten dies sicher; die gefährliche Grenze entstand dadurch, dass seine Bytes an einen Interpreter übergeben wurden.<sup>[[5]](#references)</sup>

Verwandte Schritte werden unter [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) und [macOS auto-start locations](../../macos-auto-start-locations.md) behandelt.

### PHP Injection

**`PHPRC`** oder **`PHP_INI_SCAN_DIR`** können eine kontrollierte PHP-Konfiguration laden, deren **`auto_prepend_file`** vor dem ZielsScript ausgeführt wird.

[PHP-Konfiguration und `auto_prepend_file`-Startup-Injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Der eigenständige Lua-Interpreter führt Code oder eine `@file` aus **`LUA_INIT`** (oder dessen versionsspezifischer Variante) aus, bevor er das ZielsScript verarbeitet.

[Lua-`LUA_INIT`-Startup-Injection (Datei und Inline-Code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** und **`R_PROFILE`** leiten zu Startprofilen mit R-Code um. Über **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** und einen R-Bibliothekspfad kann stattdessen ein installiertes Package automatisch geladen werden.

[R-Startprofile und Package-Laden](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** leitet zu einem Depot um, dessen `config/startup.jl` automatisch ausgeführt wird.

[Julia-`JULIA_DEPOT_PATH`- und `startup.jl`-Injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

Mit **`ERL_AFLAGS`**, **`ERL_FLAGS`** oder **`ERL_ZFLAGS`** lässt sich ein Erlang-VM-Ausdruck mit **`-eval`** injizieren, ohne eine Payload-Datei zu benötigen; Elixir-Workloads starten üblicherweise dieselbe VM.

[Erlang/Elixir-VM-Flag-Injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** und **`OCTAVE_VERSION_INITFILE`** leiten zu Octave-Startscripts um.

[GNU-Octave-Startup-File-Injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` ist eine plattformübergreifende .NET-Anwendung. Daher ermöglichen mehrere Umgebungsvariablen die Ausführung vor einem Befehl: **`XDG_CONFIG_HOME`** leitet die beim Start ausgeführten Profilscripts um, **`PSModulePath`** ermöglicht das Hijacking des automatischen Modul-Ladens (ein platziertes `.psm1` wird beim Import ausgeführt und kann integrierte Cmdlets überlagern), und die .NET-Variablen **`CORECLR_PROFILER`**/**`COR_PROFILER`** sowie **`DOTNET_STARTUP_HOOKS`** laden Code des Angreifers in den Prozess, bevor `Main` ausgeführt wird.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Prüfen Sie verschiedene Möglichkeiten, mit denen ein Perl-Script beliebigen Code ausführen kann:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Ruby-Umgebungsvariablen (**`RUBYOPT`**, **`RUBYLIB`**) lassen sich ebenfalls missbrauchen, damit beliebige Scripts beliebigen Code ausführen:


[Ruby-`RUBYOPT`-/`RUBYLIB`-Loader-Optionen](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Die Standardbibliothekskette **`PYTHONWARNINGS`** und **`BROWSER`** kann beim Parsen von Warning-Filtern einen Befehl ausführen. Eine dateibasierte Alternative platziert `sitecustomize.py` in **`PYTHONPATH`**, sodass die normale `site`-Initialisierung das Modul vor dem ZielsScript importiert. **`PYTHONBREAKPOINT`** führt eine ausgewählte Callable oder ein Modul aus, wenn der Code `breakpoint()` erreicht. Nur interaktiv verwendete Variablen wie **`PYTHONSTARTUP`** sind weniger vielseitig einsetzbar.

Beachten Sie, dass mit **`pyinstaller`** kompilierte ausführbare Dateien diese Umgebungsvariablen nicht verwenden, selbst wenn sie einen eingebetteten Python-Interpreter nutzen.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (und dessen Fallback `EXINIT`) werden beim normalen Start als Ex-Befehle ausgeführt. Daher ermöglichen `:!cmd` / `:call system(...)` die Codeausführung, wenn ein Opfer Vim/Neovim mit einer kontrollierten Umgebung öffnet:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Außerdem installiert Homebrew Python häufig unter `/opt/homebrew`, wo Mitglieder der lokalen Gruppe `admin` möglicherweise den Launcher ersetzen können. Dabei handelt es sich um das Hijacking einer beschreibbaren Binärdatei, nicht um eine Injection über Umgebungsvariablen. Prüfen Sie Eigentümer und ACLs, bevor Sie dies als ausnutzbar einstufen.


## Erkennung

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ist eine auf **EndpointSecurity** basierende Open-Source-Anwendung, die Process Injection erkennt und blockiert. Sie ist eine gute Referenz dafür, welche Signale über Endpoint Security beobachtbar sind, da sie bei Folgendem Alarm auslöst:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-Umgebungsvariablen** beim Process Exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` und `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-Aufrufe – ein Prozess fordert den Task-Port eines anderen Prozesses an. Das ist die Voraussetzung für eine Injection in diesen Prozess.
- **Electron-Debugging-Argumente** – `--inspect`, `--inspect-brk` und `--remote-debugging-port`. Damit wird eine Electron-Anwendung im Debug-Modus gestartet, sodass beliebige Personen eine Verbindung herstellen und darin Code ausführen können.<sup>[[3]](#references)</sup>
- **Erstellen von Symlinks/Hardlinks über Berechtigungsstufen hinweg** – die klassische Methode „als normaler Benutzer einen Link erstellen und auf einen privilegierten Speicherort zeigen lassen“. Beachten Sie, dass **Symlinks zwar erkannt, aber nicht blockiert werden können**: EndpointSecurity stellt das Link-Ziel vor dem Erstellen nicht bereit.

### Aufrufe durch andere Prozesse

In [**diesem Blogbeitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) erfahren Sie, wie sich die Funktion **`task_name_for_pid`** verwenden lässt, um Informationen über andere **Prozesse abzurufen, die Code in einen Prozess injizieren**, und anschließend Informationen über diesen anderen Prozess zu erhalten.<sup>[[4]](#references)</sup>

Beachten Sie, dass Sie zum Aufrufen dieser Funktion **dieselbe uid** wie der Prozess oder **root** sein müssen (und dass sie Informationen über den Prozess zurückgibt, aber keine Möglichkeit zur Code-Injection bietet).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — Open-Source-Erkennung von macOS-Process-Injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-Framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew – Warum Electron-Apps Ihre Geheimnisse nicht vertraulich speichern können: die Option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight – Erkennen von Task-Modifikationen](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist – Eine neue Version des MacSync-macOS-Stealers zielt auf Krypto-Enthusiasten und Entwickler ab](https://securelist.com/macsync-new-version/121383/)
