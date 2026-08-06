# Ausnutzung von Kernel-Race-Conditions über langsame Object-Manager-Pfade

{{#include ../../banners/hacktricks-training.md}}

## Warum das Verlängern des Race-Fensters wichtig ist

Viele Windows-Kernel-LPEs folgen dem klassischen Muster `check_state(); NtOpenX("name"); privileged_action();`. Auf moderner Hardware löst ein kaltes `NtOpenEvent`/`NtOpenSection` einen kurzen Namen in etwa 2 µs auf, sodass kaum Zeit bleibt, den geprüften Zustand zu ändern, bevor die privilegierte Aktion erfolgt. Indem der Angreifer die Object Manager Namespace (OMNS)-Suche in Schritt 2 absichtlich auf mehrere zehn Mikrosekunden verlängert, erhält er ausreichend Zeit, um ansonsten unzuverlässige Races konsistent zu gewinnen, ohne Tausende von Versuchen zu benötigen.<sup>[[1]](#references)</sup>

## Object-Manager-Suchinterna kurz zusammengefasst

* **OMNS-Struktur** – Namen wie `\BaseNamedObjects\Foo` werden Verzeichnis für Verzeichnis aufgelöst. Jede Komponente veranlasst den Kernel, ein *Object Directory* zu finden bzw. zu öffnen und Unicode-Zeichenfolgen zu vergleichen. Symbolic Links (z. B. Laufwerksbuchstaben) können auf diesem Weg durchlaufen werden.
* **UNICODE_STRING-Limit** – OM-Pfade werden in einem `UNICODE_STRING` übertragen, dessen `Length` ein 16-Bit-Wert ist. Das absolute Limit beträgt 65 535 Bytes (32 767 UTF-16-Codepoints). Bei Präfixen wie `\BaseNamedObjects\` kontrolliert ein Angreifer weiterhin ≈32 000 Zeichen.
* **Voraussetzungen für den Angreifer** – Jeder Benutzer kann Objekte unter beschreibbaren Verzeichnissen wie `\BaseNamedObjects` erstellen. Wenn der verwundbare Code einen darin befindlichen Namen verwendet oder einem Symbolic Link folgt, der dort endet, kontrolliert der Angreifer die Suchleistung ohne besondere Berechtigungen.<sup>[[1]](#references)</sup>

## Slowdown Primitive #1 – Eine einzelne maximale Komponente

Die Kosten für die Auflösung einer Komponente steigen ungefähr linear mit ihrer Länge, da der Kernel einen Unicode-Vergleich mit jedem Eintrag im übergeordneten Verzeichnis durchführen muss. Das Erstellen eines Events mit einem 32-kB-langen Namen erhöht die Latenz von `NtOpenEvent` unter Windows 11 24H2 (Snapdragon X Elite-Testsystem) unmittelbar von etwa 2 µs auf etwa 35 µs.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktische Hinweise*

- Sie können das Längenlimit mit jedem benannten Kernelobjekt erreichen (events, sections, semaphores …).
- Symbolic links oder reparse points können einen kurzen „victim“-Namen auf diese riesige Komponente verweisen, sodass die Verlangsamung transparent angewendet wird.
- Da alles in von Benutzern beschreibbaren namespaces liegt, funktioniert der Payload von einem standardmäßigen user integrity level aus.<sup>[[1]](#references)</sup>

## Slowdown-Primitiv Nr. 2 – Tief verschachtelte Verzeichnisse

Eine aggressivere Variante weist eine Kette aus Tausenden von Verzeichnissen zu (`\BaseNamedObjects\A\A\...\X`). Jeder Sprung löst Logik zur Verzeichnisauflösung aus (ACL-Prüfungen, hash lookups, reference counting), sodass die Latenz pro Ebene höher ist als bei einem einzelnen string compare. Bei etwa 16.000 Ebenen (begrenzt durch dieselbe `UNICODE_STRING`-Größe) überschreiten die empirischen Messwerte die 35-µs-Schwelle, die mit langen einzelnen Komponenten erreicht wird.
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
Tipps:

* Wechsle die Zeichen pro Ebene (`A/B/C/...`), wenn das übergeordnete Verzeichnis Duplikate zurückweist.
* Halte ein Handle-Array vor, damit du die Kette nach der Ausnutzung sauber löschen kannst und den Namespace nicht verunreinigst.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (Minuten statt Mikrosekunden)

Objektverzeichnisse unterstützen **Shadow directories** (Fallback-Lookups) und gehashte Buckettabellen für Einträge. Missbrauche beides zusammen mit dem 64-Komponenten-Limit für symbolische Link-Reparses, um die Verlangsamung zu vervielfachen, ohne die Länge von `UNICODE_STRING` zu überschreiten:

1. Erstelle zwei Verzeichnisse unter `\BaseNamedObjects`, z. B. `A` (Shadow) und `A\A` (Ziel). Erstelle das zweite unter Verwendung des ersten als Shadow directory (`NtCreateDirectoryObjectEx`), sodass fehlgeschlagene Lookups in `A` auf `A\A` zurückfallen.
2. Fülle jedes Verzeichnis mit Tausenden **kollidierenden Namen**, die im selben Hash-Bucket landen (z. B. durch variierende abschließende Ziffern bei gleichbleibendem `RtlHashUnicodeString`-Wert). Lookups verschlechtern sich nun zu linearen O(n)-Scans innerhalb eines einzelnen Verzeichnisses.
3. Erstelle eine Kette aus etwa 63 **symbolischen Object-Manager-Links**, die wiederholt in das lange Suffix `A\A\…` reparsen und dabei das Reparse-Budget aufbrauchen. Jeder Reparse startet das Parsen von oben neu und vervielfacht die Kollisionskosten.
4. Das Lookup der finalen Komponente (`...\\0`) dauert unter Windows 11 bei 16.000 Kollisionen pro Verzeichnis nun **Minuten** und ermöglicht dadurch bei einmaligen Kernel-LPEs praktisch garantiert den Gewinn der Race Condition.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Warum es wichtig ist*: Eine minutenlange Verlangsamung verwandelt einmalige race-basierte LPEs in deterministische Exploits.<sup>[[1]](#references)</sup>

### Hinweise zum Retest 2025 und fertige Tools

- James Forshaw hat die Technik mit aktualisierten Timings unter Windows 11 24H2 (ARM64) erneut veröffentlicht. Baseline-Öffnungen bleiben bei etwa 2 µs; eine 32 kB-Komponente erhöht diesen Wert auf etwa 35 µs, und shadow-dir + collision + 63-reparse-Ketten erreichen weiterhin etwa 3 Minuten. Damit ist bestätigt, dass die Primitives aktuelle Builds überstehen. Der Quellcode und der Performance-Harness befinden sich im aktualisierten Project-Zero-Post.<sup>[[1]](#references)</sup>
- Du kannst das Setup mithilfe des öffentlichen Bundles `symboliclink-testing-tools` skripten: `CreateObjectDirectory.exe`, um das shadow/target-Paar zu erzeugen, und `NativeSymlink.exe` in einer Schleife, um die 63-Hop-Kette zu erstellen. Dadurch entfallen selbst geschriebene `NtCreate*`-Wrapper, und die ACLs bleiben konsistent.<sup>[[2]](#references)</sup>

## Dein race window messen

Bette einen kurzen Harness in deinen Exploit ein, um zu messen, wie groß das Fenster auf der Hardware des Opfers wird. Das folgende Snippet öffnet das Zielobjekt `iterations`-mal und gibt mithilfe von `QueryPerformanceCounter` die durchschnittlichen Kosten pro Öffnung zurück.<sup>[[1]](#references)</sup>
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
Die Ergebnisse fließen direkt in Ihre Race-Orchestrierungsstrategie ein (z. B. Anzahl der benötigten Worker-Threads, Sleep-Intervalle und wie früh Sie den gemeinsamen Zustand umschalten müssen).

## Exploitations-Workflow

1. **Das verwundbare Open lokalisieren** – Verfolgen Sie den Kernel-Pfad (über Symbole, ETW, Hypervisor-Tracing oder Reverse Engineering), bis Sie einen `NtOpen*`-/`ObOpenObjectByName`-Aufruf finden, der einen vom Angreifer kontrollierten Namen oder einen symbolischen Link in einem benutzerschreibbaren Verzeichnis verarbeitet.
2. **Diesen Namen durch einen langsamen Pfad ersetzen**
- Erstellen Sie die lange Komponente oder Verzeichniskette unter `\BaseNamedObjects` (oder einem anderen beschreibbaren OM-Root).
- Erstellen Sie einen symbolischen Link, sodass der vom Kernel erwartete Name nun auf den langsamen Pfad aufgelöst wird. Sie können die Verzeichnissuche des verwundbaren Treibers auf Ihre Struktur verweisen lassen, ohne das ursprüngliche Ziel zu verändern.
3. **Die Race Condition auslösen**
- Thread A (Opfer) führt den verwundbaren Code aus und blockiert innerhalb der langsamen Suche.
- Thread B (Angreifer) ändert den geschützten Zustand (z. B. durch Austauschen eines Datei-Handles, Neuschreiben eines symbolischen Links oder Umschalten der Objektsicherheit), während Thread A beschäftigt ist.
- Wenn Thread A fortfährt und die privilegierte Aktion ausführt, sieht er einen veralteten Zustand und führt die vom Angreifer kontrollierte Operation aus.
4. **Aufräumen** – Löschen Sie die Verzeichniskette und die symbolischen Links, um keine verdächtigen Artefakte zu hinterlassen oder legitime IPC-Benutzer zu beeinträchtigen.<sup>[[1]](#references)</sup>

## Betriebliche Überlegungen

- **Primitives kombinieren** – Sie können für jede Ebene einer Verzeichniskette einen langen Namen verwenden, um die Latenz noch weiter zu erhöhen, bis Sie die Größe von `UNICODE_STRING` ausschöpfen.
- **One-Shot-Bugs** – Das vergrößerte Zeitfenster (von einigen zehn Mikrosekunden bis zu Minuten) macht „Single-Trigger“-Bugs realistisch, wenn sie mit CPU-Affinitätsbindung oder Hypervisor-gestützter Preemption kombiniert werden.
- **Nebenwirkungen** – Die Verlangsamung betrifft nur den bösartigen Pfad, sodass die Gesamtsystemleistung unbeeinträchtigt bleibt. Verteidiger werden dies nur selten bemerken, sofern sie das Wachstum des Namespace überwachen.
- **Aufräumen** – Bewahren Sie Handles für jedes von Ihnen erstellte Verzeichnis bzw. Objekt auf, damit Sie anschließend `NtMakeTemporaryObject`/`NtClose` aufrufen können. Unbegrenzte Verzeichnisketten können andernfalls über Neustarts hinweg bestehen bleiben.
- **Dateisystem-Races** – Wenn der verwundbare Pfad letztlich über NTFS aufgelöst wird, können Sie während der OM-Verlangsamung ein Oplock (z. B. `SetOpLock.exe` aus demselben Toolkit) auf der zugrunde liegenden Datei setzen. Dadurch wird der Verbraucher für zusätzliche Millisekunden eingefroren, ohne den OM-Graphen zu verändern.<sup>[[2]](#references)</sup>

## Hinweise zur Abwehr

- Kernel-Code, der auf benannten Objekten basiert, sollte sicherheitsrelevanten Zustand *nach* dem Open erneut validieren oder vor der Prüfung eine Referenz übernehmen (wodurch die TOCTOU-Lücke geschlossen wird).
- Erzwingen Sie obere Grenzen für Tiefe und Länge von OM-Pfaden, bevor Sie vom Benutzer kontrollierte Namen dereferenzieren. Durch das Zurückweisen übermäßig langer Namen werden Angreifer wieder in das Mikrosekunden-Zeitfenster gedrängt.
- Instrumentieren Sie das Wachstum des Object-Manager-Namespaces (ETW `Microsoft-Windows-Kernel-Object`), um verdächtige Ketten mit Tausenden von Komponenten unter `\BaseNamedObjects` zu erkennen.

## Referenzen

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
