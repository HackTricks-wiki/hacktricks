# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Prozessen

Ein Prozess ist eine Instanz einer laufenden ausführbaren Datei. Prozesse führen jedoch keinen Code aus, sondern Threads. Daher sind **Prozesse lediglich Container für laufende Threads**, die Speicher, Deskriptoren, Ports, Berechtigungen usw. bereitstellen.

Traditionell wurden Prozesse innerhalb anderer Prozesse gestartet (außer PID 1), indem **`fork`** aufgerufen wurde. Dadurch wurde eine exakte Kopie des aktuellen Prozesses erstellt. Anschließend rief der **Kindprozess** in der Regel **`execve`** auf, um die neue ausführbare Datei zu laden und auszuführen. Danach wurde **`vfork`** eingeführt, um diesen Prozess ohne Kopieren des Speichers zu beschleunigen.\
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
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Standardmäßig alle Dateideskriptoren bei exec(2) schließen
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Die hohen Bits des ASLR-Slides randomisieren

Außerdem akzeptiert `posix_spawn` **`posix_spawnattr`**-Einstellungen, die Aspekte des gestarteten Prozesses steuern, sowie **`posix_spawn_file_actions`**-Einträge, die Dateideskriptoren ändern.

Wenn ein Prozess beendet wird, sendet er den **Rückgabecode an den Elternprozess** (falls der Elternprozess beendet wurde, ist der neue Elternprozess PID 1) und löst dabei das Signal `SIGCHLD` aus. Der Elternprozess muss diesen Wert mit `wait4()` oder `waitid()` abrufen. Bis dahin bleibt der Kindprozess in einem Zombie-Zustand, in dem er weiterhin aufgelistet wird, aber keine Ressourcen verbraucht.

### PIDs

PIDs, also Prozesskennungen, identifizieren einen eindeutigen Prozess. In XNU sind **PIDs** **64 Bit** breit, steigen monoton an und laufen **niemals über** (um Missbrauch zu verhindern).

### Prozessgruppen, Sitzungen & Coalitions

**Prozesse** können in **Gruppen** zusammengefasst werden, um ihre Verwaltung zu vereinfachen. Beispielsweise gehören Befehle in einem Shell-Skript derselben Prozessgruppe an, sodass sie etwa mit kill gemeinsam **signalisiert werden können**.\
Prozesse können außerdem **in Sitzungen gruppiert werden**. Wenn ein Prozess eine Sitzung startet (`setsid(2)`), werden seine Kindprozesse dieser Sitzung zugeordnet, es sei denn, sie starten eine eigene Sitzung.

Coalition ist eine weitere Möglichkeit, Prozesse in Darwin zu gruppieren. Wenn ein Prozess einer Coalition beitritt, kann er auf Pool-Ressourcen zugreifen, ein Ledger gemeinsam nutzen oder von Jetsam betroffen sein. Coalitions haben verschiedene Rollen: Leader, XPC service, Extension.

### Anmeldedaten & Personae

Jeder Prozess verfügt über **Anmeldedaten**, die seine **Berechtigungen** im System festlegen. Jeder Prozess hat eine primäre `uid` und eine primäre `gid` (kann aber mehreren Gruppen angehören).\
Wenn die Binärdatei das `setuid/setgid`-Bit gesetzt hat, können außerdem Benutzer- und Gruppen-ID geändert werden.\
Es gibt mehrere Funktionen, um **neue uids/gids festzulegen**.

Der Systemaufruf **`persona`** stellt einen **alternativen** Satz von **Anmeldedaten** bereit. Durch die Übernahme einer Persona werden deren uid, gid und Gruppenmitgliedschaften **auf einmal** übernommen. Im [**Quellcode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) lässt sich die Struktur finden:

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
2. **Threads erstellen:** Mit der Funktion `pthread_create()` werden neue Threads erstellt. Intern ruft diese Funktion `bsdthread_create()` auf, einen Low-Level-Systemaufruf, der spezifisch für den XNU-Kernel ist (auf dem macOS basiert). Dieser Systemaufruf übernimmt verschiedene Flags, die von `pthread_attr` (Attributen) abgeleitet werden und das Verhalten des Threads festlegen, darunter Scheduling-Richtlinien und Stack-Größe.
   - **Standard-Stack-Größe:** Die Standard-Stack-Größe für neue Threads beträgt 512 KB. Das ist für typische Vorgänge ausreichend, kann aber über Thread-Attribute angepasst werden, wenn mehr oder weniger Speicher benötigt wird.
3. **Thread-Initialisierung:** Die Funktion `__pthread_init()` ist während der Einrichtung eines Threads entscheidend. Sie verwendet das Argument `env[]`, um Umgebungsvariablen auszulesen, die Angaben zum Speicherort und zur Größe des Stacks enthalten können.

#### Thread-Beendigung in macOS

1. **Threads beenden:** Threads werden üblicherweise durch Aufruf von `pthread_exit()` beendet. Diese Funktion ermöglicht es einem Thread, ordnungsgemäß zu beenden, die erforderlichen Aufräumarbeiten durchzuführen und einen Rückgabewert an wartende Threads zu übermitteln.
2. **Thread-Bereinigung:** Beim Aufruf von `pthread_exit()` wird die Funktion `pthread_terminate()` aufgerufen, die alle zugehörigen Thread-Strukturen entfernt. Sie gibt Mach-Thread-Ports frei (Mach ist das Kommunikationssubsystem im XNU-Kernel) und ruft `bsdthread_terminate` auf, einen Systemaufruf, der die dem Thread zugeordneten Strukturen auf Kernel-Ebene entfernt.

#### Synchronisierungsmechanismen

macOS stellt mehrere Synchronisierungsprimitiven bereit, um den Zugriff auf gemeinsam genutzte Ressourcen zu verwalten und Race Conditions zu vermeiden. Diese sind in Multithreading-Umgebungen entscheidend, um Datenintegrität und Systemstabilität zu gewährleisten:

1. **Mutexes:**
   - **Regulärer Mutex (Signatur: 0x4D555458):** Standard-Mutex mit einem Speicherbedarf von 60 Bytes (56 Bytes für den Mutex und 4 Bytes für die Signatur).
   - **Fast Mutex (Signatur: 0x4d55545A):** Ähnlich wie ein regulärer Mutex, aber für schnellere Vorgänge optimiert; ebenfalls 60 Bytes groß.
2. **Condition Variables:**
   - Dienen dazu, auf bestimmte Bedingungen zu warten; sie sind 44 Bytes groß (40 Bytes plus eine 4-Byte-Signatur).
   - **Condition-Variable-Attribute (Signatur: 0x434e4441):** Konfigurationsattribute für Condition Variables; 12 Bytes groß.
3. **Once-Variable (Signatur: 0x4f4e4345):**
   - Stellt sicher, dass ein Initialisierungscode nur einmal ausgeführt wird. Sie ist 12 Bytes groß.
4. **Read-Write Locks:**
   - Ermöglichen mehrere gleichzeitige Leser oder jeweils einen Schreiber und sorgen so für effizienten Zugriff auf gemeinsam genutzte Daten.
   - **Read-Write-Lock (Signatur: 0x52574c4b):** 196 Bytes groß.
   - **Read-Write-Lock-Attribute (Signatur: 0x52574c41):** Attribute für Read-Write-Locks; 20 Bytes groß.

> [!TIP]
> Die letzten 4 Bytes dieser Objekte dienen dazu, Überläufe zu erkennen.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** werden im Kontext von Mach-O-Dateien (dem Format für ausführbare Dateien in macOS) verwendet, um Variablen zu deklarieren, die in einer Multithread-Anwendung für **jeden Thread** spezifisch sind. So erhält jeder Thread eine eigene Instanz einer Variablen. Dadurch lassen sich Konflikte vermeiden und die Datenintegrität wahren, ohne explizite Synchronisierungsmechanismen wie Mutexes zu benötigen.

In C und verwandten Sprachen können Sie mit dem Schlüsselwort **`__thread`** eine Thread-lokale Variable deklarieren. So funktioniert es in Ihrem Beispiel:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Dieses Snippet definiert `tlv_var` als thread-lokale Variable. Jeder Thread, der diesen Code ausführt, hat seine eigene `tlv_var`, und Änderungen, die ein Thread an `tlv_var` vornimmt, wirken sich nicht auf `tlv_var` in einem anderen Thread aus.

In der Mach-O-Binärdatei sind die Daten zu thread-lokalen Variablen in bestimmten Sections organisiert:

- **`__DATA.__thread_vars`**: Diese Section enthält Metadaten zu den thread-lokalen Variablen, etwa ihre Typen und ihren Initialisierungsstatus.
- **`__DATA.__thread_bss`**: Diese Section wird für thread-lokale Variablen verwendet, die nicht explizit initialisiert sind. Sie ist ein Speicherbereich für auf null initialisierte Daten.

Mach-O bietet außerdem eine spezielle API namens **`tlv_atexit`**, um thread-lokale Variablen beim Beenden eines Threads zu verwalten. Mit dieser API lassen sich **Destruktoren registrieren** – spezielle Funktionen, die thread-lokale Daten bereinigen, wenn ein Thread beendet wird.

### Thread-Prioritäten

Um Thread-Prioritäten zu verstehen, muss man sich ansehen, wie das Betriebssystem entscheidet, welche Threads wann ausgeführt werden. Diese Entscheidung wird durch die jedem Thread zugewiesene Prioritätsstufe beeinflusst. In macOS und Unix-ähnlichen Systemen geschieht dies mithilfe von Konzepten wie `nice`, `renice` und Quality-of-Service-Klassen (QoS).

#### Nice und Renice

1. **Nice:**
   - Der `nice`-Wert eines Prozesses ist eine Zahl, die seine Priorität beeinflusst. Jeder Prozess hat einen `nice`-Wert zwischen -20 (höchste Priorität) und 19 (niedrigste Priorität). Der Standardwert für einen neu erstellten Prozess ist normalerweise 0.
   - Ein niedrigerer `nice`-Wert (näher an -20) macht einen Prozess „selbstsüchtiger“: Er erhält mehr CPU-Zeit als andere Prozesse mit höheren `nice`-Werten.
2. **Renice:**
   - `renice` ist ein Befehl, mit dem sich der `nice`-Wert eines bereits laufenden Prozesses ändern lässt. Damit kann die Priorität von Prozessen dynamisch angepasst und ihre CPU-Zuteilung anhand neuer `nice`-Werte erhöht oder verringert werden.
   - Wenn ein Prozess beispielsweise vorübergehend mehr CPU-Ressourcen benötigt, kann man seinen `nice`-Wert mit `renice` senken.

#### Quality-of-Service-Klassen (QoS)

QoS-Klassen sind ein modernerer Ansatz zur Verwaltung von Thread-Prioritäten, insbesondere in Systemen wie macOS, die **Grand Central Dispatch (GCD)** unterstützen. Mit QoS-Klassen können Entwickler Arbeit je nach Wichtigkeit oder Dringlichkeit in verschiedene Stufen **einordnen**. macOS verwaltet die Priorisierung von Threads automatisch anhand dieser QoS-Klassen:

1. **User Interactive:**
   - Diese Klasse ist für Aufgaben vorgesehen, die gerade mit dem Benutzer interagieren oder sofortige Ergebnisse erfordern, um eine gute Benutzererfahrung zu gewährleisten. Diese Aufgaben erhalten die höchste Priorität, damit die Benutzeroberfläche reaktionsfähig bleibt (z. B. Animationen oder die Ereignisverarbeitung).
2. **User Initiated:**
   - Aufgaben, die der Benutzer startet und für die er sofortige Ergebnisse erwartet, etwa das Öffnen eines Dokuments oder ein Klick auf eine Schaltfläche, der Berechnungen erfordert. Sie haben hohe Priorität, liegen aber unter „User Interactive“.
3. **Utility:**
   - Diese Aufgaben laufen länger und zeigen typischerweise eine Fortschrittsanzeige an (z. B. das Herunterladen von Dateien oder der Import von Daten). Sie haben eine niedrigere Priorität als benutzerinitiierte Aufgaben und müssen nicht sofort abgeschlossen werden.
4. **Background:**
   - Diese Klasse ist für Aufgaben vorgesehen, die im Hintergrund laufen und für den Benutzer nicht sichtbar sind. Dazu zählen beispielsweise Indizierung, Synchronisierung oder Backups. Sie haben die niedrigste Priorität und wirken sich nur minimal auf die Systemleistung aus.

Mithilfe von QoS-Klassen müssen Entwickler keine genauen Prioritätswerte verwalten, sondern können sich auf die Art der Aufgabe konzentrieren. Das System optimiert die CPU-Ressourcen entsprechend.

Darüber hinaus gibt es verschiedene **Thread-Scheduling-Richtlinien**, mit denen sich Scheduling-Parameter festlegen lassen, die der Scheduler berücksichtigt. Dies ist über `thread_policy_[set/get]` möglich. Das kann bei race condition attacks nützlich sein.

## Missbrauch von macOS-Prozessen

macOS bietet zahlreiche Mechanismen, mit denen **Prozesse interagieren, kommunizieren und Daten austauschen** können. Obwohl diese Mechanismen für den normalen Systembetrieb unverzichtbar sind, können Angreifer sie für Injection, Codeausführung oder den Zugriff auf Daten missbrauchen.

### Library Injection

Library Injection ist eine Technik, bei der ein Angreifer **einen Prozess dazu zwingt, eine schädliche Bibliothek zu laden**. Nach der Injection wird die Bibliothek im Kontext des Zielprozesses ausgeführt und bietet dem Angreifer dieselben Berechtigungen und Zugriffsrechte wie dem Prozess.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Beim Function Hooking werden **Funktionsaufrufe** oder Nachrichten innerhalb eines Softwarecodes **abgefangen**. Durch das Hooking von Funktionen kann ein Angreifer **das Verhalten** eines Prozesses ändern, vertrauliche Daten beobachten oder sogar den Ausführungsablauf kontrollieren.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Diese Seite behandelt ARM64-Unwind-Metadaten, arm64e-PAC-Beschränkungen und synthetische Call-Chains.

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

Mit den Flags `--load-extension` und `--use-fake-ui-for-media-stream` lässt sich ein **man in the browser attack** ausführen, bei dem Tastatureingaben und Datenverkehr gestohlen, Cookies abgegriffen und Skripte in Seiten eingeschleust werden können …:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-Dateien **definieren Elemente der Benutzeroberfläche (UI)** und deren Interaktionen innerhalb einer Anwendung. Sie können jedoch **beliebige Befehle ausführen**, und **Gatekeeper verhindert nicht**, dass eine bereits ausgeführte Anwendung erneut ausgeführt wird, wenn eine **NIB-Datei geändert wurde**. Daher können sie dazu verwendet werden, beliebige Programme beliebige Befehle ausführen zu lassen:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Es ist möglich, JVM-Optionen über **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** oder **`JDK_JAVA_OPTIONS`** einzuschleusen und vor dem Start der Anwendung einen Java- oder nativen Agent zu laden.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** lädt über `--require` (Datei) oder `--import data:text/javascript,…` (dateilos, Node ≥ 20.6) vorab JavaScript eines Angreifers; **`NODE_REPL_EXTERNAL_MODULE`** lädt ein Modul in eine interaktive REPL, und **`ELECTRON_RUN_AS_NODE`** aktiviert all dies für Electron-Binärdateien erneut.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Code lässt sich über **`DOTNET_STARTUP_HOOKS`** vor `Main` in .NET-Anwendungen einschleusen oder durch Missbrauch der .NET-Debugging-Funktionalität ausführen, sofern deren Voraussetzungen erfüllt sind.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nicht-interaktive Bash-Shells lesen **`BASH_ENV`**; interaktive POSIX-Shells lesen **`ENV`**; zsh liest **`$ZDOTDIR/.zshenv`**; und fish liest Konfigurationen aus **`XDG_CONFIG_HOME`** oder **`XDG_DATA_DIRS`**. Jede dieser Shells kann vor dem vorgesehenen Befehl eine kontrollierte Startdatei ausführen. Bash führt außerdem eine Command Substitution in **`PS4`** aus, wenn xtrace aktiviert ist (z. B. durch geerbtes **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

Über **`PHPRC`** oder **`PHP_INI_SCAN_DIR`** lässt sich eine kontrollierte PHP-Konfiguration laden, deren **`auto_prepend_file`** vor dem Zielskript ausgeführt wird.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Der eigenständige Lua-Interpreter führt **`LUA_INIT`** (oder dessen versionsspezifische Variante) aus, bevor das Zielskript verarbeitet wird. Der Inhalt kann Code oder ein `@file` sein.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** und **`R_PROFILE`** leiten auf Startprofile mit R-Code um. Mit **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** und einem R-Bibliothekspfad lässt sich stattdessen ein installiertes Paket automatisch laden.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** leitet auf das Depot um, dessen `config/startup.jl` automatisch ausgeführt wird.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

Mit **`ERL_AFLAGS`**, **`ERL_FLAGS`** oder **`ERL_ZFLAGS`** lässt sich ein Erlang-VM-Ausdruck mit **`-eval`** einschleusen, ohne eine Payload-Datei zu benötigen; Elixir-Workloads starten üblicherweise dieselbe VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** und **`OCTAVE_VERSION_INITFILE`** leiten auf Octave-Startskripte um.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` ist eine plattformübergreifende .NET-Anwendung, daher ermöglichen mehrere Umgebungsvariablen die Ausführung vor dem Befehl: **`XDG_CONFIG_HOME`** leitet auf die beim Start ausgeführten Profildateien um, **`PSModulePath`** ermöglicht das Hijacking des automatischen Ladens von Modulen (eine platzierte `.psm1` wird beim Import ausgeführt und kann integrierte Cmdlets überschreiben), und die .NET-Variablen **`CORECLR_PROFILER`**/**`COR_PROFILER`** sowie **`DOTNET_STARTUP_HOOKS`** laden Code eines Angreifers vor `Main` in den Prozess.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Sieh dir die verschiedenen Möglichkeiten an, mit denen ein Perl-Skript beliebigen Code ausführen kann:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Auch Ruby-Umgebungsvariablen (**`RUBYOPT`**, **`RUBYLIB`**) lassen sich missbrauchen, damit beliebige Skripte beliebigen Code ausführen:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die Standardbibliotheks-Kette **`PYTHONWARNINGS`** und **`BROWSER`** kann während der Verarbeitung von Warnungsfiltern einen Befehl ausführen. Eine dateibasierte Alternative platziert `sitecustomize.py` in **`PYTHONPATH`**, sodass die normale `site`-Initialisierung das Modul vor dem Zielskript importiert. **`PYTHONBREAKPOINT`** führt ein ausgewähltes Callable/Modul aus, wenn der Code `breakpoint()` erreicht. Variablen, die nur für interaktive Sitzungen gelten, wie **`PYTHONSTARTUP`**, sind weniger vielseitig einsetzbar.

Beachte, dass mit **`pyinstaller`** kompilierte ausführbare Dateien diese Umgebungsvariablen nicht verwenden, selbst wenn sie einen eingebetteten Python-Interpreter nutzen.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (und als Fallback `EXINIT`) werden beim normalen Start als Ex-Befehle ausgeführt. Daher ermöglichen `:!cmd` / `:call system(...)` die Codeausführung, wenn ein Opfer Vim/Neovim mit einer kontrollierten Umgebung öffnet:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Separat dazu installiert Homebrew Python üblicherweise unter `/opt/homebrew`, wo Mitglieder der lokalen Gruppe `admin` den Launcher möglicherweise ersetzen können. Dabei handelt es sich um ein Hijacking einer beschreibbaren Binärdatei und nicht um eine Injection über Umgebungsvariablen; prüfe Eigentümerschaft und ACLs, bevor du dies als ausnutzbar einstufst.


## Erkennung

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ist eine Open-Source-Anwendung auf Basis von **EndpointSecurity**, die Process Injection erkennt und blockiert. Sie ist eine gute Referenz dafür, welche Signale über Endpoint Security beobachtbar sind, da sie auf Folgendes hinweist:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-Umgebungsvariablen** beim Prozessstart: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` und `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-Aufrufe – ein Prozess fordert den Task-Port eines anderen Prozesses an, was die Voraussetzung für eine Injection in diesen Prozess ist.
- **Electron-Debugging-Argumente** – `--inspect`, `--inspect-brk` und `--remote-debugging-port`, die eine Electron-Anwendung im Debug-Modus starten und beliebigen Personen erlauben, sich mit ihr zu verbinden und Code auszuführen.<sup>[[3]](#references)</sup>
- **Symlink-/Hardlink-Erstellung über Berechtigungsstufen hinweg** – das klassische Vorgehen: „Als normaler Benutzer einen Link anlegen und auf einen privilegierten Speicherort verweisen“. Beachte, dass **Symlinks erkannt, aber nicht blockiert werden können**: EndpointSecurity stellt das Link-Ziel vor der Erstellung nicht bereit.

### Aufrufe durch andere Prozesse

In [**diesem Blogbeitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) erfährst du, wie sich die Funktion **`task_name_for_pid`** verwenden lässt, um Informationen über andere **Prozesse zu erhalten, die Code in einen Prozess injizieren**, und anschließend weitere Informationen über diesen anderen Prozess abzurufen.<sup>[[4]](#references)</sup>

Beachte, dass du zum Aufrufen dieser Funktion dieselbe UID wie der Prozess oder **root** sein musst (sie liefert Informationen über den Prozess, bietet aber keine Möglichkeit, Code einzuschleusen).

## References

- [1] [Shield — Open-Source-Erkennung von macOS-Prozessinjektionen (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-Framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew – Warum Electron-Apps deine Geheimnisse nicht vertraulich speichern können: Option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight – Erkennung von Task-Modifikationen](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
