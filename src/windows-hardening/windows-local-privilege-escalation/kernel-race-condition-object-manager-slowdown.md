# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Warum das Vergrößern des Race-Fensters wichtig ist

Viele Windows-Kernel-LPEs folgen dem klassischen Muster `check_state(); NtOpenX("name"); privileged_action();`. Auf moderner Hardware löst ein kalter `NtOpenEvent`/`NtOpenSection` einen kurzen Namen in ~2 µs auf und lässt damit kaum Zeit, den geprüften Zustand umzuschalten, bevor die sichere Aktion ausgeführt wird. Durch gezieltes Verlängern des Object Manager-Namespace (OMNS)-Lookups in Schritt 2 auf einige Dutzend Mikrosekunden gewinnt der Angreifer genug Zeit, um sonst unzuverlässige Races konsistent zu gewinnen, ohne Tausende Versuche zu benötigen.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Namen wie `\BaseNamedObjects\Foo` werden Verzeichnis für Verzeichnis aufgelöst. Jede Komponente veranlasst den Kernel, ein *Object Directory* zu finden/zu öffnen und Unicode-Strings zu vergleichen. Symbolische Links (z. B. Laufwerksbuchstaben) können dabei durchlaufen werden.
* **UNICODE_STRING limit** – OM-Pfade werden in einem `UNICODE_STRING` transportiert, dessen `Length` ein 16-Bit-Wert ist. Das absolute Limit liegt bei 65 535 Bytes (32 767 UTF-16-Codepunkte). Mit Präfixen wie `\BaseNamedObjects\` kontrolliert ein Angreifer immer noch ≈32 000 Zeichen.
* **Attacker prerequisites** – Jeder Benutzer kann Objekte unter schreibbaren Verzeichnissen wie `\BaseNamedObjects` erstellen. Wenn der verwundbare Code einen Namen darin verwendet oder einem symbolischen Link folgt, der dorthin führt, kontrolliert der Angreifer die Lookup-Performance ohne besondere Privilegien.

## Slowdown primitive #1 – Single maximal component

Die Kosten für das Auflösen einer Komponente sind ungefähr linear zur Länge, da der Kernel einen Unicode-Vergleich gegen jeden Eintrag im übergeordneten Verzeichnis durchführen muss. Das Erstellen eines Events mit einem 32 kB langen Namen erhöht die `NtOpenEvent`-Latenz sofort von ~2 µs auf ~35 µs unter Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktische Hinweise*

- Du kannst das Längenlimit mit jedem benannten Kernel-Objekt erreichen (events, sections, semaphores…).
- Symbolic links oder reparse points können einen kurzen „victim“-Namen auf diese riesige Komponente verweisen, sodass die Verlangsamung transparent angewendet wird.
- Da alles in user-writable namespaces liegt, funktioniert der payload vom Standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Eine aggressivere Variante legt eine Kette aus tausenden Verzeichnissen (`\BaseNamedObjects\A\A\...\X`) an. Jeder Schritt löst die directory resolution logic (ACL checks, hash lookups, reference counting) aus, weshalb die Latenz pro Ebene höher ist als bei einem einzelnen String-Vergleich. Bei ~16 000 Ebenen (begrenzt durch dieselbe `UNICODE_STRING`-Größe) übersteigen empirische Messungen die 35 µs-Grenze, die durch lange einzelne Komponenten erreicht wurde.
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
Tips:

* Wechsle das Zeichen pro Ebene (`A/B/C/...`), falls das übergeordnete Verzeichnis anfängt, Duplikate abzulehnen.
* Behalte ein Handle-Array, damit du die Kette nach der exploitation sauber löschen kannst, um eine Verschmutzung des Namensraums zu vermeiden.

## Verlangsamungsprimitive #3 – Schattenverzeichnisse, Hash-Kollisionen & Symlink-Reparses (Minuten statt Mikrosekunden)

Objektverzeichnisse unterstützen **Schattenverzeichnisse** (Fallback-Lookups) und bucketbasierte Hash-Tabellen für Einträge. Missbrauche beides plus das 64-Komponenten-Limit für das Reparse von symbolischen Links, um die Verlangsamung zu vervielfachen, ohne die Länge von `UNICODE_STRING` zu überschreiten:

1. Erstelle zwei Verzeichnisse unter `\BaseNamedObjects`, z. B. `A` (Schatten) und `A\A` (Ziel). Erstelle das zweite so, dass das erste als Schattenverzeichnis verwendet wird (`NtCreateDirectoryObjectEx`), damit fehlende Lookups in `A` auf `A\A` fallen.
2. Fülle jedes Verzeichnis mit Tausenden von **kollidierenden Namen**, die im selben Hash-Bucket landen (z. B. unterschiedliche Endziffern, dabei denselben `RtlHashUnicodeString`-Wert beibehaltend). Lookup-Vorgänge degradieren nun zu O(n)-linearen Scans innerhalb eines einzelnen Verzeichnisses.
3. Baue eine Kette von ~63 **symbolische Links des Object Managers**, die wiederholt in den langen `A\A\…`-Suffix reparsen und somit das Reparse-Budget aufbrauchen. Jedes Reparse startet das Parsen wieder von oben und vervielfacht so die Kollisionskosten.
4. Die Suche nach der finalen Komponente (`...\\0`) dauert nun **Minuten** auf Windows 11, wenn pro Verzeichnis 16 000 Kollisionen vorhanden sind, was einen praktisch garantierten Race-Gewinn für One-Shot kernel LPEs bietet.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Warum es wichtig ist*: Eine minutenlange Verlangsamung verwandelt einmalige, race-basierte LPEs in deterministische Exploits.

## Messung Ihres Race-Fensters

Bette ein schnelles Harness in deinen Exploit ein, um zu messen, wie groß das Fenster auf der Zielhardware wird. Der folgende Ausschnitt öffnet das Zielobjekt `iterations`-mal und gibt die durchschnittlichen Kosten pro Open zurück, gemessen mit `QueryPerformanceCounter`.
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
Die Ergebnisse fließen direkt in deine race orchestration strategy ein (z. B. Anzahl der benötigten Worker-Threads, Sleep-Intervalle, wie früh du den gemeinsamen Zustand umschalten musst).

## Exploitation workflow

1. **Locate the vulnerable open** – Verfolge den Kernel-Pfad (mittels Symbols, ETW, hypervisor tracing oder Reversing), bis du einen `NtOpen*`/`ObOpenObjectByName`-Aufruf findest, der einen vom Angreifer kontrollierten Namen oder einen symbolischen Link in einem vom Benutzer beschreibbaren Verzeichnis abläuft.
2. **Replace that name with a slow path**
- Erstelle die lange Komponente oder die Verzeichnis-Kette unter `\BaseNamedObjects` (oder einem anderen beschreibbaren OM-Root).
- Erstelle einen symbolischen Link, sodass der vom Kernel erwartete Name jetzt auf den slow path aufgelöst wird. Du kannst die Verzeichnisauflösung des verwundbaren Treibers auf deine Struktur zeigen lassen, ohne das ursprüngliche Ziel zu verändern.
3. **Trigger the race**
- Thread A (victim) führt den verwundbaren Code aus und blockiert innerhalb des slow lookup.
- Thread B (attacker) ändert den geschützten Zustand (z. B. tauscht ein File-Handle, überschreibt einen symbolic link, toggelt Objekt-Security), während Thread A beschäftigt ist.
- Wenn Thread A fortfährt und die privilegierte Aktion ausführt, sieht es veralteten Zustand und führt die vom Angreifer kontrollierte Operation aus.
4. **Clean up** – Lösche die Verzeichnis-Kette und die symbolischen Links, um verdächtige Artefakte zu vermeiden oder legitime IPC-Nutzer nicht zu beeinträchtigen.

## Operational considerations

- **Combine primitives** – Du kannst pro Ebene einer Verzeichnis-Kette einen langen Namen verwenden (*per level*), um die Latenz weiter zu erhöhen, bis du die `UNICODE_STRING`-Größe erschöpfst.
- **One-shot bugs** – Das vergrößerte Zeitfenster (von einigen Dutzend Mikrosekunden bis Minuten) macht „single trigger“-Bugs realistisch, wenn sie mit CPU-Affinity-Pinning oder hypervisor-assisted preemption kombiniert werden.
- **Side effects** – Die Verlangsamung betrifft nur den bösartigen Pfad, sodass die Gesamtleistung des Systems unbeeinflusst bleibt; Verteidiger bemerken das selten, es sei denn, sie überwachen das Wachstum des Namespace.
- **Cleanup** – Behalte Handles zu jedem Verzeichnis/Objekt, das du erstellst, damit du anschließend `NtMakeTemporaryObject`/`NtClose` aufrufen kannst. Ansonsten können unbeschränkte Verzeichnis-Ketten über Reboots hinweg bestehen bleiben.

## Defensive notes

- Kernelcode, der sich auf benannte Objekte verlässt, sollte sicherheitsrelevanten Zustand *nach* dem Open erneut validieren oder vor der Prüfung eine Referenz nehmen (um die TOCTOU-Lücke zu schließen).
- Setze obere Grenzen für OM-Pfad-Tiefe/-Länge, bevor user-kontrollierte Namen dereferenziert werden. Das Zurückweisen überlanger Namen zwingt Angreifer wieder in das Mikrosekunden-Fenster.
- Instrumentiere das Wachstum des Object Manager Namespace (ETW `Microsoft-Windows-Kernel-Object`), um verdächtige Tausende-Komponenten-Ketten unter `\BaseNamedObjects` zu erkennen.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
