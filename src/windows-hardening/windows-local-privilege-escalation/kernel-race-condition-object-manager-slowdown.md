# Ausnutzung von Kernel-Race-Conditions über langsame Object Manager-Pfade

{{#include ../../banners/hacktricks-training.md}}

## Warum das Vergrößern des Race-Fensters wichtig ist

Viele Windows-Kernel-LPEs folgen dem klassischen Muster `check_state(); NtOpenX("name"); privileged_action();`. Auf moderner Hardware löst ein kaltes `NtOpenEvent`/`NtOpenSection` einen kurzen Namen in ~2 µs auf, sodass kaum Zeit bleibt, den geprüften Zustand umzuschalten, bevor die sichere Aktion ausgeführt wird. Indem der Angreifer die Object Manager-Namensauflösung (OMNS) in Schritt 2 bewusst auf Zehner von Mikrosekunden streckt, gewinnt er genug Zeit, um sonst unzuverlässige Rennen konsistent zu gewinnen, ohne tausende Versuche zu benötigen.

## Interna der Object Manager-Suche kurz gefasst

* **OMNS-Struktur** – Namen wie `\BaseNamedObjects\Foo` werden Verzeichnis- für Verzeichnis aufgelöst. Jede Komponente veranlasst den Kernel, ein *Object Directory* zu finden/zu öffnen und Unicode-Strings zu vergleichen. Symbolische Links (z. B. Laufwerksbuchstaben) können unterwegs durchlaufen werden.
* **UNICODE_STRING-Limit** – OM-Pfade werden in einem `UNICODE_STRING` übertragen, dessen `Length` ein 16-Bit-Wert ist. Die absolute Grenze liegt bei 65 535 Bytes (32 767 UTF-16-Codepunkte). Mit Präfixen wie `\BaseNamedObjects\` kontrolliert ein Angreifer immer noch ≈32 000 Zeichen.
* **Voraussetzungen für Angreifer** – Jeder Benutzer kann Objekte unter beschreibbaren Verzeichnissen wie `\BaseNamedObjects` erstellen. Wenn der verwundbare Code einen Namen darin verwendet oder einem symbolischen Link folgt, der dorthin zeigt, kontrolliert der Angreifer die Lookup-Performance ohne besondere Rechte.

## Verlangsamungsprimitive #1 – Einzelne maximale Komponente

Die Kosten für das Auflösen einer Komponente sind ungefähr linear zu ihrer Länge, weil der Kernel einen Unicode-Vergleich gegen jeden Eintrag im übergeordneten Verzeichnis durchführen muss. Das Erstellen eines Events mit einem 32 kB langen Namen erhöht die Latenz von `NtOpenEvent` sofort von ~2 µs auf ~35 µs unter Windows 11 24H2 (Snapdragon X Elite Testumgebung).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktische Hinweise*

- Die Längenbegrenzung lässt sich mit jedem benannten Kernel-Objekt (events, sections, semaphores…) erreichen.
- Symbolic links oder reparse points können einen kurzen „victim“-Namen auf diese riesige Komponente verweisen, sodass die Verlangsamung transparent angewendet wird.
- Da alles in user-writable namespaces lebt, funktioniert die payload vom standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Eine aggressivere Variante allokiert eine Kette aus tausenden Verzeichnissen (`\BaseNamedObjects\A\A\...\X`). Jeder Hop löst die directory resolution logic aus (ACL checks, hash lookups, reference counting), sodass die Latenz pro Ebene höher ist als bei einem einzelnen String-Vergleich. Bei ~16 000 Ebenen (beschränkt durch dieselbe `UNICODE_STRING`-Größe) übersteigen empirische Messwerte die 35 µs-Grenze, die durch lange einzelne Komponenten erreicht wurde.
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
* Behalte ein handle array, damit du die Kette nach der exploitation sauber löschen kannst, um das namespace nicht zu verschmutzen.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (Minuten statt Mikrosekunden)

Object directories unterstützen **shadow directories** (Fallback-Lookups) und bucketed Hash-Tabellen für Einträge. Missbrauche beides zusammen mit dem 64-Komponenten symbolic-link reparse limit, um die Verlangsamung zu vervielfachen, ohne die `UNICODE_STRING`-Länge zu überschreiten:

1. Erstelle zwei Verzeichnisse unter `\BaseNamedObjects`, z.B. `A` (shadow) und `A\A` (target). Erstelle das zweite unter Verwendung des ersten als shadow directory (`NtCreateDirectoryObjectEx`), sodass fehlende Lookups in `A` auf `A\A` durchfallen.
2. Fülle jedes Verzeichnis mit Tausenden von **colliding names**, die im selben Hash-Bucket landen (z.B. durch Variation der nachgestellten Ziffern bei beibehaltetem `RtlHashUnicodeString`-Wert). Die Lookups degenerieren nun zu O(n)-linearen Scans innerhalb eines einzelnen Verzeichnisses.
3. Baue eine Kette von ~63 **object manager symbolic links**, die wiederholt in das lange `A\A\…`-Suffix reparsen und so das Reparse-Budget verbrauchen. Jede Reparse startet das Parsen wieder von oben und multipliziert die Kosten der Kollision.
4. Das Lookup der letzten Komponente (`...\\0`) dauert nun **Minuten** auf Windows 11, wenn pro Verzeichnis 16 000 Kollisionen vorhanden sind, und bietet damit einen praktisch garantierten race win für one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Warum es wichtig ist*: Eine minutenlange Verlangsamung verwandelt one-shot race-based LPEs in deterministische Exploits.

## Messung Ihres Race-Fensters

Fügen Sie ein kurzes harness in Ihr exploit ein, um zu messen, wie groß das Fenster auf der victim hardware wird. Der folgende Ausschnitt öffnet das Zielobjekt `iterations`-mal und liefert die durchschnittlichen Kosten pro Open mithilfe von `QueryPerformanceCounter`.
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
Die Ergebnisse fließen direkt in deine Race-Orchestrierungsstrategie ein (z. B. Anzahl benötigter Worker-Threads, Sleep-Intervalle, wie früh du den gemeinsamen Zustand umschalten musst).

## Exploitation workflow

1. **Locate the vulnerable open** – Trace the kernel path (via symbols, ETW, hypervisor tracing, or reversing) until you find an `NtOpen*`/`ObOpenObjectByName` call that walks an attacker-controlled name or a symbolic link in a user-writable directory.
2. **Replace that name with a slow path**
- Erstelle die lange Komponente oder Verzeichniskette unter `\BaseNamedObjects` (oder einer anderen beschreibbaren OM root).
- Erstelle eine symbolische Verknüpfung, sodass der vom Kernel erwartete Name jetzt auf den langsamen Pfad auflöst. Du kannst die Verzeichnissuche des verwundbaren Treibers auf deine Struktur verweisen lassen, ohne das ursprüngliche Ziel zu verändern.
3. **Trigger the race**
- Thread A (victim) führt den verwundbaren Code aus und blockiert während der langsamen Suche.
- Thread B (attacker) kippt den geschützten Zustand um (z. B. tauscht einen File-Handle, überschreibt eine symbolische Verknüpfung, ändert die Objekt-Security), während Thread A beschäftigt ist.
- Wenn Thread A fortfährt und die privilegierte Aktion ausführt, sieht es veralteten Zustand und führt die vom Angreifer kontrollierte Operation aus.
4. **Clean up** – Lösche die Verzeichniskette und die symbolischen Verknüpfungen, um zu vermeiden, verdächtige Artefakte zu hinterlassen oder legitime IPC-Nutzer zu stören.

## Operational considerations

- **Combine primitives** – Du kannst pro Ebene einer Verzeichniskette einen langen Namen verwenden, um noch höhere Latenz zu erreichen, bis du die Größe von `UNICODE_STRING` erschöpfst.
- **One-shot bugs** – Das erweiterte Zeitfenster (Zehntel-Mikrosekunden bis Minuten) macht „Single trigger“-Bugs realistisch, wenn sie mit CPU-affinity pinning oder hypervisor-assisted preemption kombiniert werden.
- **Side effects** – Die Verlangsamung betrifft nur den bösartigen Pfad, sodass die Gesamtleistung des Systems unbeeinflusst bleibt; Verteidiger bemerken das selten, außer sie beobachten das Namespace-Wachstum.
- **Cleanup** – Behalte Handles für jedes Verzeichnis/Objekt, das du erstellst, damit du anschließend `NtMakeTemporaryObject`/`NtClose` aufrufen kannst. Andernfalls können unbeschränkte Verzeichnisketten über Reboots hinweg bestehen bleiben.

## Defensive notes

- Kernel-Code, der sich auf benannte Objekte verlässt, sollte sicherheitsrelevanten Zustand *nach* dem open revalidieren oder vor der Prüfung eine Referenz nehmen (schließt die TOCTOU-Lücke).
- Erzwinge obere Grenzen für OM-Pfad-Tiefe/Länge, bevor du benutzerkontrollierte Namen dereferenzierst. Das Ablehnen übermäßig langer Namen zwingt Angreifer zurück ins Mikrosekundenfenster.
- Überwache das Wachstum des Object Manager Namespace (ETW `Microsoft-Windows-Kernel-Object`), um verdächtige Tausende-Komponenten-Ketten unter `\BaseNamedObjects` zu erkennen.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
