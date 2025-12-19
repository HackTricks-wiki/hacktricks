# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Why stretching the race window matters

Viele Windows-Kernel-LPEs folgen dem klassischen Muster `check_state(); NtOpenX("name"); privileged_action();`. Auf moderner Hardware löst ein kaltes `NtOpenEvent`/`NtOpenSection` einen kurzen Namen in ~2 µs auf und lässt praktisch keine Zeit mehr, den überprüften Zustand umzuschalten, bevor die sichere Aktion ausgeführt wird. Indem der Angreifer das Object Manager Namespace (OMNS)-Lookup in Schritt 2 absichtlich auf einige zehn Mikrosekunden verlängert, gewinnt er genug Zeit, um sonst unzuverlässige Races konsistent zu gewinnen, ohne tausende Versuche zu benötigen.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Namen wie `\BaseNamedObjects\Foo` werden Verzeichnis für Verzeichnis aufgelöst. Jede Komponente veranlasst, dass der Kernel ein *Object Directory* findet/öffnet und Unicode-Strings vergleicht. symbolische Links (z. B. Laufwerksbuchstaben) können unterwegs durchlaufen werden.
* **UNICODE_STRING limit** – OM-Pfade werden in einem `UNICODE_STRING` transportiert, dessen `Length` ein 16-Bit-Wert ist. Das absolute Limit sind 65 535 Bytes (32 767 UTF-16-Codepunkte). Mit Präfixen wie `\BaseNamedObjects\` kontrolliert ein Angreifer immer noch ≈32 000 Zeichen.
* **Attacker prerequisites** – Jeder Benutzer kann Objekte unter schreibbaren Verzeichnissen wie `\BaseNamedObjects` erstellen. Wenn der verwundbare Code einen dortigen Namen verwendet oder einem symbolischen Link folgt, der dorthin führt, kontrolliert der Angreifer die Lookup-Leistung ohne besondere Berechtigungen.

## Slowdown primitive #1 – Single maximal component

Die Kosten für das Auflösen einer Komponente skalieren annähernd linear mit ihrer Länge, da der Kernel für jeden Eintrag im übergeordneten Verzeichnis einen Unicode-Vergleich durchführen muss. Das Erstellen eines Events mit einem 32 kB-langen Namen erhöht die `NtOpenEvent`-Latenz sofort von ~2 µs auf ~35 µs unter Windows 11 24H2 (Snapdragon X Elite Testumgebung).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktische Hinweise*

- Sie können das Längenlimit mit jedem benannten Kernel-Objekt erreichen (events, sections, semaphores…).
- Symbolic links oder reparse points können einen kurzen „victim“-Namen auf diese riesige Komponente verweisen, sodass die Verlangsamung transparent angewendet wird.
- Da alles in user-writable namespaces liegt, funktioniert der payload auf einem Standard-User-Integrity-Level.

## Slowdown primitive #2 – Tiefe rekursive Verzeichnisse

Eine aggressivere Variante legt eine Kette von Tausenden Verzeichnissen an (`\BaseNamedObjects\A\A\...\X`). Jeder Schritt löst die Verzeichnisauflösungslogik aus (ACL checks, hash lookups, reference counting), sodass die Latenz pro Ebene höher ist als bei einem einzelnen String-Vergleich. Bei ~16 000 Ebenen (begrenzt durch dieselbe `UNICODE_STRING`-Größe) überschreiten empirische Messungen die 35 µs-Grenze, die durch lange einzelne Komponenten erreicht wurde.
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

* Wechsle das Zeichen pro Ebene (`A/B/C/...`), falls das übergeordnete Verzeichnis anfängt, Duplikate abzulehnen.
* Behalte ein Handle-Array, damit du die Kette nach exploitation sauber löschen kannst, um die namespace nicht zu verschmutzen.

## Messen des race window

Bette ein kurzes harness in dein exploit ein, um zu messen, wie groß das race window auf der victim hardware wird. Der folgende Ausschnitt öffnet das Zielobjekt `iterations`-mal und gibt die durchschnittlichen Kosten pro Öffnung unter Verwendung von `QueryPerformanceCounter` zurück.
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
Die Ergebnisse fließen direkt in deine Race-Orchestrierungsstrategie ein (z. B. Anzahl benötigter Worker-Threads, Sleep-Intervalle, wie früh du den geteilten Zustand umschalten musst).

## Exploitation workflow

1. **Locate the vulnerable open** – Verfolge den Kernel-Pfad (via symbols, ETW, hypervisor tracing, or reversing), bis du einen Aufruf von `NtOpen*`/`ObOpenObjectByName` findest, der einen vom Angreifer kontrollierten Namen oder einen symbolischen Link in einem für Benutzer beschreibbaren Verzeichnis durchläuft.
2. **Replace that name with a slow path**
- Erstelle die lange Komponente oder die Verzeichnis-Kette unter `\BaseNamedObjects` (oder einem anderen beschreibbaren OM root).
- Erstelle einen symbolischen Link, sodass der vom Kernel erwartete Name jetzt auf den langsamen Pfad aufgelöst wird. Du kannst den Verzeichnis-Lookup des verwundbaren Treibers auf deine Struktur lenken, ohne das ursprüngliche Ziel zu verändern.
3. **Trigger the race**
- Thread A (victim) führt den verwundbaren Code aus und blockiert während des langsamen Lookups.
- Thread B (attacker) ändert den geschützten Zustand (z. B. tauscht ein File-Handle, überschreibt einen symbolischen Link, ändert die Objektsicherheit), während Thread A beschäftigt ist.
- Wenn Thread A fortfährt und die privilegierte Aktion ausführt, sieht es veralteten Zustand und führt die vom Angreifer gesteuerte Operation aus.
4. **Clean up** – Lösche die Verzeichnis-Kette und symbolische Links, um keine verdächtigen Artefakte zu hinterlassen oder legitime IPC-Nutzer zu beeinträchtigen.

## Operational considerations

- **Combine primitives** – Du kannst auf jeder Ebene einer Verzeichnis-Kette einen langen Namen verwenden, um noch höhere Latenzen zu erzeugen, bis du die Größe von `UNICODE_STRING` ausreizt.
- **One-shot bugs** – Das erweiterte Zeitfenster (Zehner von Mikrosekunden) macht “single trigger” Bugs realistisch, wenn sie mit CPU-Affinitäts-Pinning oder hypervisor-unterstützter Preemption kombiniert werden.
- **Side effects** – Die Verlangsamung betrifft nur den bösartigen Pfad, sodass die Systemgesamtleistung unberührt bleibt; Verteidiger bemerken es selten, es sei denn, sie überwachen das Wachstum des Namespace.
- **Cleanup** – Behalte Handles zu jedem von dir erstellten Verzeichnis/Objekt, damit du anschließend `NtMakeTemporaryObject`/`NtClose` aufrufen kannst. Andernfalls können unbeschränkte Verzeichnis-Ketten über Neustarts hinweg bestehen bleiben.

## Defensive notes

- Kernel-Code, der auf benannten Objekten basiert, sollte sicherheitsrelevanten Zustand *nach* dem open erneut validieren oder vor der Überprüfung eine Referenz nehmen (schließt die TOCTOU-Lücke).
- Setze obere Grenzen für OM-Pfad-Tiefe/-Länge, bevor du benutzerkontrollierte Namen dereferenzierst. Das Zurückweisen übermäßig langer Namen zwingt Angreifer zurück in das Mikrosekunden-Zeitfenster.
- Instrumentiere das Wachstum des Object Manager Namensraums (ETW `Microsoft-Windows-Kernel-Object`), um verdächtige Tausende-Komponenten-Ketten unter `\BaseNamedObjects` zu erkennen.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
