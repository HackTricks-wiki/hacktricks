# macOS-Prozessmissbrauch

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Prozessen

Ein Prozess ist eine Instanz einer laufenden ausführbaren Datei. Allerdings führen Prozesse keinen Code aus, sondern Threads. Daher sind **Prozesse lediglich Container für laufende Threads**, die den Speicher, Deskriptoren, Ports, Berechtigungen usw. bereitstellen.

Traditionell wurden Prozesse innerhalb anderer Prozesse gestartet (außer PID 1), indem **`fork`** aufgerufen wurde. Dadurch wurde eine exakte Kopie des aktuellen Prozesses erstellt, woraufhin der **child process** normalerweise **`execve`** aufrief, um die neue ausführbare Datei zu laden und auszuführen. Danach wurde **`vfork`** eingeführt, um diesen Vorgang ohne Speicherkopieren zu beschleunigen.\
Anschließend wurde **`posix_spawn`** eingeführt, das **`vfork`** und **`execve`** in einem Aufruf kombiniert und Flags akzeptiert:

- `POSIX_SPAWN_RESETIDS`: Effektive IDs auf die realen IDs zurücksetzen
- `POSIX_SPAWN_SETPGROUP`: Zugehörigkeit zur Prozessgruppe festlegen
- `POSUX_SPAWN_SETSIGDEF`: Standardverhalten von Signalen festlegen
- `POSIX_SPAWN_SETSIGMASK`: Signalmaske festlegen
- `POSIX_SPAWN_SETEXEC`: Im selben Prozess ausführen (wie `execve` mit weiteren Optionen)
- `POSIX_SPAWN_START_SUSPENDED`: Angehalten starten
- `_POSIX_SPAWN_DISABLE_ASLR`: Ohne ASLR starten
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Den Nano-Allocator von libmalloc verwenden
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` `rwx` für Datensegmente erlauben
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Standardmäßig alle Dateibeschreibungen bei exec(2) schließen
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Die hohen Bits des ASLR-Slides randomisieren

Außerdem ermöglicht `posix_spawn`, ein Array von **`posix_spawnattr`** anzugeben, das einige Aspekte des gestarteten Prozesses steuert, sowie **`posix_spawn_file_actions`**, um den Zustand der Deskriptoren zu ändern.

Wenn ein Prozess beendet wird, sendet er den **Rückgabecode an den Elternprozess** (falls der Elternprozess beendet wurde, ist der neue Elternprozess PID 1) mit dem Signal `SIGCHLD`. Der Elternprozess muss diesen Wert durch den Aufruf von `wait4()` oder `waitid()` abrufen. Bis dahin verbleibt der child process in einem Zombie-Zustand, in dem er weiterhin aufgelistet wird, aber keine Ressourcen verbraucht.

### PIDs

PIDs (Prozessbezeichner) identifizieren einen eindeutigen Prozess. In XNU sind **PIDs** 64 Bit groß, steigen monoton an und laufen **nie über** (um Missbrauch zu verhindern).

### Prozessgruppen, Sessions & Coalations

**Prozesse** können in **Gruppen** eingefügt werden, um ihre Verwaltung zu erleichtern. Beispielsweise befinden sich Befehle in einem Shell-Script in derselben Prozessgruppe, sodass sie gemeinsam **signalisiert** werden können, etwa mit kill.\
Es ist auch möglich, **Prozesse in Sessions zu gruppieren**. Wenn ein Prozess eine Session startet (`setsid(2)`), werden die child processes in diese Session eingefügt, sofern sie nicht ihre eigene Session starten.

Coalition ist eine weitere Möglichkeit, Prozesse in Darwin zu gruppieren. Wenn ein Prozess einer Coalition beitritt, kann er auf Pool-Ressourcen zugreifen, ein Ledger gemeinsam nutzen oder von Jetsam betroffen sein. Coalations haben verschiedene Rollen: Leader, XPC service, Extension.

### Credentials & Personae

Jeder Prozess verfügt über **Credentials**, die **seine Berechtigungen** im System identifizieren. Jeder Prozess besitzt eine primäre `uid` und eine primäre `gid` (kann jedoch mehreren Gruppen angehören).\
Es ist auch möglich, die Benutzer- und Gruppen-ID zu ändern, wenn die Binärdatei über das **`setuid/setgid`**-Bit verfügt.\
Es gibt mehrere Funktionen, um **neue uids/gids festzulegen**.

Der Systemaufruf **`persona`** stellt einen alternativen Satz von **Credentials** bereit. Die Annahme einer Persona übernimmt gleichzeitig deren UID, GID und Gruppenmitgliedschaften. Im [**Quellcode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) kann die Struktur gefunden werden:
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

1. **POSIX Threads (pthreads):** macOS unterstützt POSIX Threads (`pthreads`), die Teil einer standardisierten Threading-API für C/C++ sind. Die Implementierung von pthreads in macOS befindet sich in `/usr/lib/system/libsystem_pthread.dylib` und stammt aus dem öffentlich verfügbaren `libpthread`-Projekt. Diese Library stellt die notwendigen Funktionen zum Erstellen und Verwalten von Threads bereit.
2. **Erstellen von Threads:** Die Funktion `pthread_create()` wird zum Erstellen neuer Threads verwendet. Intern ruft diese Funktion `bsdthread_create()` auf, einen Low-Level-Systemaufruf, der spezifisch für den XNU-Kernel ist, auf dem macOS basiert. Dieser Systemaufruf übernimmt verschiedene aus `pthread_attr` (Attributen) abgeleitete Flags, die das Thread-Verhalten festlegen, einschließlich Scheduling-Richtlinien und Stack-Größe.
- **Standardmäßige Stack-Größe:** Die standardmäßige Stack-Größe für neue Threads beträgt 512 KB. Dies ist für typische Vorgänge ausreichend, kann jedoch über Thread-Attribute angepasst werden, wenn mehr oder weniger Speicher benötigt wird.
3. **Thread-Initialisierung:** Die Funktion `__pthread_init()` ist während der Einrichtung eines Threads entscheidend. Sie verwendet das Argument `env[]`, um Umgebungsvariablen zu analysieren, die Details zum Speicherort und zur Größe des Stacks enthalten können.

#### Thread-Terminierung in macOS

1. **Beenden von Threads:** Threads werden normalerweise durch den Aufruf von `pthread_exit()` beendet. Diese Funktion ermöglicht es einem Thread, sich sauber zu beenden, notwendige Bereinigungen durchzuführen und einen Rückgabewert an wartende Threads zu übermitteln.
2. **Thread-Bereinigung:** Beim Aufruf von `pthread_exit()` wird die Funktion `pthread_terminate()` aufgerufen. Sie kümmert sich um die Entfernung aller zugehörigen Thread-Strukturen. Sie gibt Mach-Thread-Ports frei (Mach ist das Kommunikationssubsystem im XNU-Kernel) und ruft `bsdthread_terminate` auf, einen Syscall, der die mit dem Thread verbundenen Strukturen auf Kernel-Ebene entfernt.

#### Synchronisationsmechanismen

Um den Zugriff auf gemeinsam genutzte Ressourcen zu verwalten und Race Conditions zu vermeiden, stellt macOS mehrere Synchronisationsprimitive bereit. Diese sind in Multithreading-Umgebungen entscheidend, um Datenintegrität und Systemstabilität sicherzustellen:

1. **Mutexes:**
- **Regulärer Mutex (Signatur: 0x4D555458):** Standard-Mutex mit einem Speicherbedarf von 60 Bytes (56 Bytes für den Mutex und 4 Bytes für die Signatur).
- **Fast Mutex (Signatur: 0x4d55545A):** Ähnelt einem regulären Mutex, ist jedoch für schnellere Operationen optimiert und ebenfalls 60 Bytes groß.
2. **Condition Variables:**
- Werden verwendet, um auf das Eintreten bestimmter Bedingungen zu warten, und sind 44 Bytes groß (40 Bytes plus eine 4-Byte-Signatur).
- **Attribute von Condition Variables (Signatur: 0x434e4441):** Konfigurationsattribute für Condition Variables mit einer Größe von 12 Bytes.
3. **Once Variable (Signatur: 0x4f4e4345):**
- Stellt sicher, dass ein Teil des Initialisierungscodes nur einmal ausgeführt wird. Ihre Größe beträgt 12 Bytes.
4. **Read-Write Locks:**
- Ermöglichen mehrere Leser oder jeweils einen Schreiber und erleichtern dadurch den effizienten Zugriff auf gemeinsam genutzte Daten.
- **Read Write Lock (Signatur: 0x52574c4b):** 196 Bytes groß.
- **Attribute von Read Write Locks (Signatur: 0x52574c41):** Attribute für Read-Write-Locks mit einer Größe von 20 Bytes.

> [!TIP]
> Die letzten 4 Bytes dieser Objekte werden verwendet, um Overflows zu erkennen.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** werden im Kontext von Mach-O-Dateien (dem Format für ausführbare Dateien in macOS) verwendet, um Variablen zu deklarieren, die für **jeden Thread** in einer Multithreading-Anwendung spezifisch sind. Dadurch hat jeder Thread seine eigene separate Instanz einer Variable. Dies bietet eine Möglichkeit, Konflikte zu vermeiden und die Datenintegrität aufrechtzuerhalten, ohne explizite Synchronisationsmechanismen wie Mutexes zu benötigen.

In C und verwandten Sprachen kann eine Thread Local Variable mit dem Schlüsselwort **`__thread`** deklariert werden. So funktioniert dies in deinem Beispiel:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Dieser Ausschnitt definiert `tlv_var` als thread-lokale Variable. Jeder Thread, der diesen Code ausführt, verfügt über eine eigene `tlv_var`, und Änderungen, die ein Thread an `tlv_var` vornimmt, wirken sich nicht auf `tlv_var` in einem anderen Thread aus.

Im Mach-O-Binary werden die Daten zu thread-lokalen Variablen in bestimmten Sections organisiert:

- **`__DATA.__thread_vars`**: Diese Section enthält Metadaten zu den thread-lokalen Variablen, beispielsweise deren Typen und Initialisierungsstatus.
- **`__DATA.__thread_bss`**: Diese Section wird für thread-lokale Variablen verwendet, die nicht explizit initialisiert wurden. Sie ist ein Teil des Speichers, der für mit Nullen initialisierte Daten reserviert ist.

Mach-O stellt außerdem eine spezielle API namens **`tlv_atexit`** zur Verwaltung thread-lokaler Variablen beim Beenden eines Threads bereit. Mit dieser API können **Destruktoren registriert** werden – spezielle Funktionen, die thread-lokale Daten bereinigen, wenn ein Thread beendet wird.

### Threading-Prioritäten

Um Thread-Prioritäten zu verstehen, muss man betrachten, wie das Betriebssystem entscheidet, welche Threads wann ausgeführt werden. Diese Entscheidung wird durch die jedem Thread zugewiesene Prioritätsstufe beeinflusst. In macOS und Unix-ähnlichen Systemen wird dies mithilfe von Konzepten wie `nice`, `renice` und Quality-of-Service-(QoS-)Klassen umgesetzt.

#### Nice und Renice

1. **Nice:**
- Der `nice`-Wert eines Prozesses ist eine Zahl, die seine Priorität beeinflusst. Jeder Prozess besitzt einen Nice-Wert zwischen -20 (höchste Priorität) und 19 (niedrigste Priorität). Der Standardwert bei der Erstellung eines Prozesses ist normalerweise 0.
- Ein niedrigerer Nice-Wert (näher an -20) macht einen Prozess „egoistischer“, sodass er im Vergleich zu Prozessen mit höheren Nice-Werten mehr CPU-Zeit erhält.
2. **Renice:**
- `renice` ist ein Befehl, mit dem der Nice-Wert eines bereits laufenden Prozesses geändert wird. Damit kann die Priorität von Prozessen dynamisch angepasst werden, indem ihre Zuteilung von CPU-Zeit abhängig von den neuen Nice-Werten erhöht oder verringert wird.
- Wenn ein Prozess beispielsweise vorübergehend mehr CPU-Ressourcen benötigt, kann sein Nice-Wert mit `renice` gesenkt werden.

#### Quality-of-Service-(QoS-)Klassen

QoS-Klassen sind ein modernerer Ansatz zur Verwaltung von Thread-Prioritäten, insbesondere in Systemen wie macOS, die **Grand Central Dispatch (GCD)** unterstützen. QoS-Klassen ermöglichen es Entwicklern, Arbeit je nach Wichtigkeit oder Dringlichkeit in verschiedene Stufen zu **kategorisieren**. macOS verwaltet die Thread-Priorisierung automatisch anhand dieser QoS-Klassen:

1. **User Interactive:**
- Diese Klasse ist für Aufgaben vorgesehen, die derzeit mit dem Benutzer interagieren oder sofortige Ergebnisse erfordern, um eine gute Benutzererfahrung zu gewährleisten. Diese Aufgaben erhalten die höchste Priorität, damit die Benutzeroberfläche reaktionsfähig bleibt (z. B. Animationen oder Event-Handling).
2. **User Initiated:**
- Aufgaben, die vom Benutzer initiiert werden und sofortige Ergebnisse erwarten lassen, etwa das Öffnen eines Dokuments oder das Anklicken einer Schaltfläche, die Berechnungen erfordert. Sie besitzen eine hohe Priorität, liegen aber unterhalb von User Interactive.
3. **Utility:**
- Diese Aufgaben laufen lange und zeigen typischerweise einen Fortschrittsindikator an (z. B. das Herunterladen von Dateien oder der Import von Daten). Ihre Priorität liegt unter der von benutzerinitiierten Aufgaben, und sie müssen nicht sofort beendet werden.
4. **Background:**
- Diese Klasse ist für Aufgaben vorgesehen, die im Hintergrund ausgeführt werden und für den Benutzer nicht sichtbar sind. Dazu gehören beispielsweise Indexierung, Synchronisierung oder Backups. Sie besitzen die niedrigste Priorität und nur minimale Auswirkungen auf die Systemleistung.

Durch die Verwendung von QoS-Klassen müssen Entwickler nicht die exakten Prioritätswerte verwalten, sondern können sich auf die Art der Aufgabe konzentrieren. Das System optimiert die CPU-Ressourcen entsprechend.

Darüber hinaus gibt es verschiedene **Thread-Scheduling-Policies**, mit denen sich eine Gruppe von Scheduling-Parametern festlegen lässt, die der Scheduler berücksichtigt. Dies kann mithilfe von `thread_policy_[set/get]` erfolgen. Das kann bei Race-Condition-Angriffen nützlich sein.

## MacOS Process Abuse

MacOS bietet wie jedes andere Betriebssystem verschiedene Methoden und Mechanismen, mit denen **Prozesse interagieren, kommunizieren und Daten gemeinsam nutzen** können. Obwohl diese Techniken für einen effizienten Systembetrieb unverzichtbar sind, können sie von Threat Actors auch missbraucht werden, um **bösartige Aktivitäten auszuführen**.

### Library Injection

Library Injection ist eine Technik, bei der ein Angreifer **einen Prozess dazu zwingt, eine bösartige Library zu laden**. Nach der Injection wird die Library im Kontext des Zielprozesses ausgeführt und gewährt dem Angreifer dieselben Berechtigungen und Zugriffsmöglichkeiten wie dem Prozess.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking umfasst das **Abfangen von Funktionsaufrufen** oder Nachrichten innerhalb eines Software-Codes. Durch das Hooking von Funktionen kann ein Angreifer das **Verhalten** eines Prozesses ändern, vertrauliche Daten beobachten oder sogar die Kontrolle über den Ausführungsfluss erlangen.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) bezeichnet verschiedene Methoden, mit denen separate Prozesse **Daten gemeinsam nutzen und austauschen**. Obwohl IPC für viele legitime Anwendungen grundlegend ist, kann es auch missbraucht werden, um die Prozessisolation zu umgehen, vertrauliche Informationen zu leaken oder nicht autorisierte Aktionen auszuführen.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-Anwendungen, die mit bestimmten Umgebungsvariablen ausgeführt werden, könnten für Process Injection anfällig sein:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Es ist möglich, die Flags `--load-extension` und `--use-fake-ui-for-media-stream` für einen **man in the browser attack** zu verwenden, mit dem sich Tastatureingaben und Datenverkehr stehlen sowie Cookies und Scripts in Seiten injizieren lassen ...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-Dateien **definieren Elemente der Benutzeroberfläche (UI)** und deren Interaktionen innerhalb einer Anwendung. Sie können jedoch **beliebige Befehle ausführen**, und **Gatekeeper verhindert nicht**, dass eine bereits ausgeführte Anwendung erneut ausgeführt wird, wenn eine **NIB-Datei verändert** wurde. Daher könnten sie verwendet werden, um beliebige Programme beliebige Befehle ausführen zu lassen:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Es ist möglich, bestimmte Java-Funktionen (wie die Umgebungsvariable **`_JAVA_OPTS`**) zu missbrauchen, damit eine Java-Anwendung **beliebigen Code bzw. beliebige Befehle** ausführt.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Es ist möglich, Code in .Net-Anwendungen zu injizieren, indem die **.Net-Debugging-Funktionalität missbraucht** wird (die nicht durch macOS-Schutzmechanismen wie Runtime Hardening geschützt ist).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Siehe verschiedene Möglichkeiten, ein Perl-Script dazu zu bringen, beliebigen Code auszuführen:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Es ist ebenfalls möglich, Ruby-Umgebungsvariablen zu missbrauchen, damit beliebige Scripts beliebigen Code ausführen:

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Wenn die Umgebungsvariable **`PYTHONINSPECT`** gesetzt ist, wechselt der Python-Prozess nach Abschluss in eine Python-CLI. Außerdem kann **`PYTHONSTARTUP`** verwendet werden, um ein Python-Script anzugeben, das zu Beginn einer interaktiven Session ausgeführt wird.\
Beachte jedoch, dass das **`PYTHONSTARTUP`**-Script nicht ausgeführt wird, wenn **`PYTHONINSPECT`** die interaktive Session erstellt.

Andere Umgebungsvariablen wie **`PYTHONPATH`** und **`PYTHONHOME`** könnten ebenfalls nützlich sein, um einen Python-Befehl beliebigen Code ausführen zu lassen.

Beachte, dass mit **`pyinstaller`** kompilierte Executables diese Umgebungsvariablen nicht verwenden, selbst wenn sie mit einem eingebetteten Python ausgeführt werden.

> [!CAUTION]
> Insgesamt konnte ich keine Möglichkeit finden, Python durch den Missbrauch von Umgebungsvariablen beliebigen Code ausführen zu lassen.\
> Die meisten Leute installieren Python jedoch mit **Hombrew**, wodurch Python an einem **beschreibbaren Speicherort** für den standardmäßigen Admin-Benutzer installiert wird. Du kannst es beispielsweise wie folgt hijacken:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Selbst **root** wird diesen Code ausführen, wenn Python gestartet wird.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ist eine auf **EndpointSecurity** basierende Open-Source-Anwendung, die Process Injection erkennt und blockiert. Sie ist eine gute Referenz dafür, welche Signale von ES tatsächlich beobachtbar sind, da sie Folgendes meldet:<sup>[1]</sup>

- **Injection-Umgebungsvariablen** bei der Prozessausführung: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` und `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-Aufrufe – ein Prozess fordert den Task-Port eines anderen Prozesses an, was die Voraussetzung für eine Injection in diesen Prozess ist.
- **Electron-Debugging-Argumente** – `--inspect`, `--inspect-brk` und `--remote-debugging-port`, die eine Electron-App im Debug-Modus starten und es jedem ermöglichen, eine Verbindung herzustellen und darin Code auszuführen.
- **Das Erstellen von Symlinks/Hardlinks über Berechtigungsstufen hinweg** – das klassische Primitive „als normaler Benutzer einen Link anlegen und auf einen privilegierten Speicherort zeigen lassen“. Beachte, dass **Symlinks erkannt, aber nicht blockiert werden können**: EndpointSecurity stellt das Link-Ziel vor der Erstellung nicht zur Verfügung.

### Calls made by other processes

In [**diesem Blogpost**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) wird beschrieben, wie sich die Funktion **`task_name_for_pid`** verwenden lässt, um Informationen über andere **Prozesse, die Code in einen Prozess injizieren**, abzurufen und anschließend Informationen über diesen anderen Prozess zu erhalten.<sup>[4]</sup>

Beachte, dass du zum Aufruf dieser Funktion **dieselbe UID** wie der Prozess oder **root** benötigen (und sie Informationen über den Prozess zurückgibt, aber keine Möglichkeit zur Code-Injection).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
