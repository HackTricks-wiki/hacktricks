# Ausnutzung von Kernel Race Conditions über Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Warum das Strecken des race-Fensters wichtig ist

Viele Windows kernel LPEs folgen dem klassischen Muster `check_state(); NtOpenX("name"); privileged_action();`. Auf moderner Hardware löst ein kaltes `NtOpenEvent`/`NtOpenSection` einen kurzen Namen in ~2 µs auf, wodurch kaum Zeit bleibt, den geprüften Zustand umzuschalten, bevor die geschützte Aktion ausgeführt wird. Indem der Angreifer das Object Manager Namespace (OMNS)-Lookup in Schritt 2 absichtlich auf einige zehn Mikrosekunden verlängert, gewinnt er genug Zeit, um sonst instabile races konsistent zu gewinnen, ohne tausende Versuche zu benötigen.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Namen wie `\BaseNamedObjects\Foo` werden Verzeichnis für Verzeichnis aufgelöst. Jede Komponente veranlasst den Kernel, ein *Object Directory* zu finden/zu öffnen und Unicode-Strings zu vergleichen. Symbolische Links (z. B. Laufwerksbuchstaben) können unterwegs durchlaufen werden.
* **UNICODE_STRING limit** – OM-Pfade werden in einer `UNICODE_STRING` transportiert, deren `Length` ein 16-Bit-Wert ist. Das absolute Limit sind 65 535 Bytes (32 767 UTF-16 codepoints). Mit Präfixen wie `\BaseNamedObjects\` kontrolliert ein Angreifer immer noch ≈32 000 Zeichen.
* **Attacker prerequisites** – Jeder Benutzer kann Objekte unterhalb beschreibbarer Verzeichnisse wie `\BaseNamedObjects` erstellen. Wenn der verwundbare Code einen Namen innerhalb verwendet oder einem symbolischen Link folgt, der dort landet, kontrolliert der Angreifer die Lookup-Performance ohne spezielle Privilegien.

## Slowdown primitive #1 – Single maximal component

Die Kosten für das Auflösen einer Komponente sind ungefähr linear zu ihrer Länge, da der Kernel einen Unicode-Vergleich gegen jeden Eintrag im übergeordneten Verzeichnis durchführen muss. Das Erstellen eines Events mit einem 32 kB-langen Namen erhöht die `NtOpenEvent`-Latenz sofort von ~2 µs auf ~35 µs unter Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktische Hinweise*

- Sie können das Längenlimit mit jedem named kernel object (events, sections, semaphores…) erreichen.
- Symbolic links oder reparse points können einen kurzen „victim“-Namen auf diese riesige Komponente verweisen, sodass die Verlangsamung transparent angewendet wird.
- Da alles in user-writable namespaces liegt, funktioniert die payload mit einem standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Eine aggressivere Variante reserviert eine Kette von Tausenden von Verzeichnissen (`\BaseNamedObjects\A\A\...\X`). Jeder Schritt löst die directory resolution logic aus (ACL checks, hash lookups, reference counting), daher ist die Latenz pro Ebene höher als bei einem einzelnen Stringvergleich. Bei ~16 000 Ebenen (begrenzt durch dieselbe `UNICODE_STRING`-Größe) übersteigen empirische Messungen die 35 µs-Grenze, die durch lange einzelne Komponenten erreicht wurde.
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
* Behalte ein Handle-Array, damit du die Kette nach der Ausnutzung sauber löschen kannst, um eine Verschmutzung des Namespace zu vermeiden.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (Minuten statt Mikrosekunden)

Object directories unterstützen **shadow directories** (fallback lookups) und bucketed hash tables für Einträge. Missbrauche beides plus das 64-Komponenten symbolic-link reparse-Limit, um die Verlangsamung zu vervielfachen, ohne die Länge von `UNICODE_STRING` zu überschreiten:

1. Erstelle zwei Verzeichnisse unter `\BaseNamedObjects`, z. B. `A` (shadow) und `A\A` (target). Erstelle das zweite unter Verwendung des ersten als shadow directory (`NtCreateDirectoryObjectEx`), sodass fehlende Lookups in `A` auf `A\A` durchfallen.
2. Fülle jedes Verzeichnis mit tausenden von **colliding names**, die im selben Hash-Bucket landen (z. B. variiere die abschließenden Ziffern, während derselbe `RtlHashUnicodeString`-Wert erhalten bleibt). Lookups degenerieren nun zu O(n)-linearen Scans innerhalb eines einzelnen Verzeichnisses.
3. Baue eine Kette von ~63 **object manager symbolic links**, die wiederholt in das lange `A\A\…`-Suffix reparse, wodurch das Reparse-Budget verbraucht wird. Jeder Reparse startet das Parsen von oben neu und multipliziert die Kosten der Kollision.
4. Die Suche nach der finalen Komponente (`...\\0`) dauert jetzt **Minuten** auf Windows 11, wenn pro Verzeichnis 16 000 Kollisionen vorhanden sind, und liefert damit einen praktisch garantierten race win für one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Warum das wichtig ist*: Eine minutenlange Verlangsamung verwandelt one-shot race-basierte LPEs in deterministische Exploits.

### 2025 Retest-Notizen & fertige Tools

- James Forshaw hat die Technik mit aktualisierten Timings auf Windows 11 24H2 (ARM64) neu veröffentlicht. Baseline-Opens bleiben bei ~2 µs; eine 32 kB Komponente erhöht dies auf ~35 µs, und shadow-dir + collision + 63-reparse chains erreichen weiterhin ~3 Minuten, was bestätigt, dass die Primitives aktuelle Builds überleben. Source code und perf harness sind im aktualisierten Project Zero post.
- Du kannst die Einrichtung mit dem öffentlichen `symboliclink-testing-tools`-Bundle skripten: `CreateObjectDirectory.exe`, um das shadow/target-Paar zu erzeugen, und `NativeSymlink.exe` in einer Schleife, um die 63-hop chain zu erzeugen. Das vermeidet handgeschriebene `NtCreate*` wrappers und hält ACLs konsistent.

## Messung deines Race-Fensters

Bette einen kurzen harness in dein exploit ein, um zu messen, wie groß das Fenster auf der Zielhardware wird. Der folgende Ausschnitt öffnet das Zielobjekt `iterations`-mal und gibt die durchschnittlichen Kosten pro Open zurück, gemessen mit `QueryPerformanceCounter`.
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
Die Ergebnisse fließen direkt in deine race orchestration strategy ein (z. B. Anzahl benötigter Worker-Threads, Schlafintervalle, wie früh du den gemeinsamen Zustand umschalten musst).

## Exploitation workflow

1. **Locate the vulnerable open** – Verfolge den Kernel-Pfad (via symbols, ETW, hypervisor tracing oder reversing), bis du einen `NtOpen*`/`ObOpenObjectByName`-Aufruf findest, der einen von einem Angreifer kontrollierten Namen oder einen symbolischen Link in einem für Benutzer beschreibbaren Verzeichnis auflöst.
2. **Replace that name with a slow path**
- Erstelle die lange Komponente oder Verzeichniskette unter `\BaseNamedObjects` (oder einem anderen writable OM root).
- Erstelle einen symbolischen Link, sodass der vom Kernel erwartete Name jetzt auf den slow path aufgelöst wird. Du kannst die Verzeichnisauflösung des verwundbaren Treibers auf deine Struktur umleiten, ohne das Originalziel zu verändern.
3. **Trigger the race**
- Thread A (victim) führt den verwundbaren Code aus und blockiert innerhalb des slow lookup.
- Thread B (attacker) ändert den geschützten Zustand (z. B. tauscht einen File-Handle, schreibt einen symbolic link neu, toggles object security), während Thread A beschäftigt ist.
- Wenn Thread A fortfährt und die privilegierte Aktion ausführt, sieht es veralteten Zustand und führt die vom Angreifer kontrollierte Operation aus.
4. **Clean up** – Lösche die Verzeichniskette und symbolischen Links, um zu vermeiden, dass verdächtige Artefakte zurückbleiben oder legitime IPC-Nutzer gestört werden.

## Operational considerations

- **Combine primitives** – Du kannst pro Ebene in einer Verzeichniskette einen langen Namen verwenden (*per level*), um noch höhere Latenz zu erzeugen, bis du die `UNICODE_STRING`-Größe erschöpfst.
- **One-shot bugs** – Das erweiterte Zeitfenster (Zehner Mikrosekunden bis Minuten) macht “single trigger”-Bugs realistisch, wenn sie mit CPU affinity pinning oder hypervisor-assisted preemption kombiniert werden.
- **Side effects** – Die Verlangsamung betrifft nur den malicious path, sodass die Gesamtleistung des Systems unbeeinträchtigt bleibt; Verteidiger werden dies selten bemerken, es sei denn, sie überwachen das Namespace-Wachstum.
- **Cleanup** – Halte Handles zu jedem Verzeichnis/Objekt, das du erstellst, damit du anschließend `NtMakeTemporaryObject`/`NtClose` aufrufen kannst. Andernfalls können unbeschränkte Verzeichnisketten über Reboots hinweg bestehen bleiben.
- **File-system races** – Wenn der verwundbare Pfad schließlich über NTFS aufgelöst wird, kannst du einen Oplock (z. B. `SetOpLock.exe` aus demselben Toolkit) auf die zugrunde liegende Datei stacken, während der OM slowdown läuft, und den Consumer für zusätzliche Millisekunden einfrieren, ohne den OM-Graph zu verändern.

## Defensive notes

- Kernel-Code, der sich auf named objects verlässt, sollte sicherheitsrelevanten Zustand *nach* dem Open erneut validieren oder vor der Prüfung eine Referenz nehmen (um die TOCTOU-Lücke zu schließen).
- Setze obere Grenzen für OM-Pfad-Tiefe/-Länge, bevor user-controlled names dereferenziert werden. Das Ablehnen übermäßig langer Namen zwingt Angreifer zurück in das Mikrosekunden-Fenster.
- Instrumentiere object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`), um verdächtige Tausende-Komponenten-Ketten unter `\BaseNamedObjects` zu erkennen.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
