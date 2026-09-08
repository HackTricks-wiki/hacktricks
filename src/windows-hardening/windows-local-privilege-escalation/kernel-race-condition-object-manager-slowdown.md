# Ausnutzung einer Kernel Race Condition über langsame Pfade des Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Warum die Vergrößerung des Race-Fensters wichtig ist

Viele Windows-Kernel-LPEs folgen dem klassischen Muster `check_state(); NtOpenX("name"); privileged_action();`. Auf moderner Hardware löst ein kalter `NtOpenEvent`/`NtOpenSection` einen kurzen Namen in etwa 2 µs auf, wodurch kaum Zeit bleibt, den geprüften Zustand zu ändern, bevor die sichere Aktion ausgeführt wird. Indem der Angreifer die Object Manager Namespace (OMNS)-Suche in Schritt 2 absichtlich auf mehrere Dutzend Mikrosekunden verlängert, erhält er genügend Zeit, um ansonsten unzuverlässige Races konsistent zu gewinnen, ohne Tausende von Versuchen zu benötigen.<sup>[[1]](#references)</sup>

## Object Manager-Lookup-Interna im Überblick

* **OMNS-Struktur** – Namen wie `\BaseNamedObjects\Foo` werden Verzeichnis für Verzeichnis aufgelöst. Jede Komponente veranlasst den Kernel, ein *Object Directory* zu finden bzw. zu öffnen und Unicode-Zeichenfolgen zu vergleichen. Symbolische Links (z. B. Laufwerksbuchstaben) können dabei durchlaufen werden.
* **UNICODE_STRING-Limit** – OM-Pfade werden in einem `UNICODE_STRING` gespeichert, dessen `Length` ein 16-Bit-Wert ist. Das absolute Limit beträgt 65 535 Bytes (32 767 UTF-16-Codepoints). Bei Präfixen wie `\BaseNamedObjects\` kontrolliert der Angreifer weiterhin etwa 32 000 Zeichen.
* **Voraussetzungen für den Angreifer** – Jeder Benutzer kann Objekte unter beschreibbaren Verzeichnissen wie `\BaseNamedObjects` erstellen. Wenn der verwundbare Code einen Namen darin verwendet oder einem symbolischen Link folgt, der dorthin führt, kontrolliert der Angreifer die Lookup-Performance ohne besondere Berechtigungen.<sup>[[1]](#references)</sup>

## Verlangsamungsprimitive Nr. 1 – Einzelne maximale Komponente

Die Kosten für die Auflösung einer Komponente steigen ungefähr linear mit ihrer Länge, da der Kernel einen Unicode-Vergleich mit jedem Eintrag im übergeordneten Verzeichnis durchführen muss. Das Erstellen eines Events mit einem 32-kB-langen Namen erhöht die Latenz von `NtOpenEvent` unter Windows 11 24H2 (Snapdragon-X-Elite-Testsystem) sofort von etwa 2 µs auf etwa 35 µs.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktische Hinweise*

- Du kannst das Längenlimit mit jedem benannten Kernelobjekt erreichen (events, sections, semaphores …).
- Symbolic links oder reparse points können einen kurzen „victim“-Namen auf diese riesige Komponente verweisen, sodass die Verlangsamung transparent angewendet wird.
- Da alles in Namespaces liegt, die vom Benutzer beschreibbar sind, funktioniert der payload bereits mit einem standardmäßigen user integrity level.<sup>[[1]](#references)</sup>

## Verlangsamungsprimitive #2 – Tief rekursive Verzeichnisse

Eine aggressivere Variante weist eine Kette aus Tausenden von Verzeichnissen zu (`\BaseNamedObjects\A\A\...\X`). Jeder Hop löst Logik zur Verzeichnisauflösung aus (ACL-Prüfungen, Hash-Lookups, Referenzzählung), sodass die Latenz pro Ebene höher ist als bei einem einzelnen Stringvergleich. Mit etwa 16 000 Ebenen (begrenzt durch dieselbe `UNICODE_STRING`-Größe) überschreiten empirische Messungen die durch lange einzelne Komponenten erreichte Schwelle von 35 µs.
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

* Wechsle pro Ebene das Zeichen (`A/B/C/...`), wenn das übergeordnete Verzeichnis Duplikate zurückweist.
* Halte ein Handle-Array vor, damit du die Kette nach der Ausnutzung sauber löschen kannst und den Namespace nicht verschmutzt.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, Hash-Kollisionen & Symlink-Reparses (Minuten statt Mikrosekunden)

Object directories unterstützen **shadow directories** (Fallback-Lookups) und gebucketete Hash-Tabellen für Einträge. Missbrauche beides zusammen mit dem 64-Komponenten-Limit für Symbolic-Link-Reparses, um die Verlangsamung zu vervielfachen, ohne die Länge von `UNICODE_STRING` zu überschreiten:

1. Erstelle zwei Verzeichnisse unter `\BaseNamedObjects`, z. B. `A` (shadow) und `A\A` (target). Erstelle das zweite unter Verwendung des ersten als shadow directory (`NtCreateDirectoryObjectEx`), sodass fehlende Lookups in `A` auf `A\A` zurückfallen.
2. Fülle jedes Verzeichnis mit Tausenden von **kollidierenden Namen**, die im selben Hash-Bucket landen (z. B. durch variierende Endziffern bei gleichbleibendem `RtlHashUnicodeString`-Wert). Lookups verschlechtern sich dadurch innerhalb eines einzelnen Verzeichnisses zu linearen O(n)-Scans.
3. Baue eine Kette aus ungefähr 63 **object manager symbolic links**, die wiederholt in das lange Suffix `A\A\…` reparsen und das Reparse-Budget aufbrauchen. Jeder Reparse startet das Parsen von oben neu und vervielfacht die Kosten der Kollisionen.
4. Der Lookup der finalen Komponente (`...\\0`) dauert unter Windows 11 bei 16 000 Kollisionen pro Verzeichnis nun **Minuten** und ermöglicht dadurch bei One-Shot-Kernel-LPEs praktisch garantiert einen erfolgreichen Race-Win.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Warum das wichtig ist*: Eine minutenlange Verlangsamung verwandelt einmalige race-basierte LPEs in deterministische Exploits.<sup>[[1]](#references)</sup>

### Retest-Notizen für 2025 und fertige Tools

- James Forshaw veröffentlichte die Technik mit aktualisierten Timings unter Windows 11 24H2 (ARM64) erneut. Baseline-Öffnungen bleiben bei etwa 2 µs; eine 32-kB-Komponente erhöht diesen Wert auf etwa 35 µs, und shadow-dir + collision + 63-reparse-Ketten erreichen weiterhin etwa 3 Minuten. Damit ist bestätigt, dass die Primitives aktuelle Builds überstehen. Quellcode und der perf harness befinden sich im aktualisierten Project-Zero-Post.<sup>[[1]](#references)</sup>
- Du kannst die Einrichtung mit dem öffentlichen Bundle `symboliclink-testing-tools` skripten: `CreateObjectDirectory.exe`, um das shadow/target-Paar zu erzeugen, und `NativeSymlink.exe` in einer Schleife, um die 63-Hop-Kette auszugeben. Dadurch entfallen selbst geschriebene `NtCreate*`-Wrapper und die ACLs bleiben konsistent.<sup>[[2]](#references)</sup>

## Measuring your race window

Bette einen kurzen Harness in deinen Exploit ein, um zu messen, wie groß das Zeitfenster auf der Zielhardware wird. Das folgende Snippet öffnet das Zielobjekt `iterations`-mal und gibt mithilfe von `QueryPerformanceCounter` die durchschnittlichen Kosten pro Öffnung zurück.<sup>[[1]](#references)</sup>
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
Die Ergebnisse fließen direkt in deine Race-Orchestrierungsstrategie ein (z. B. in die Anzahl der benötigten Worker-Threads, die Sleep-Intervalle und wie früh du den gemeinsamen Zustand umschalten musst).

## Exploitation workflow

1. **Locate the vulnerable open** – Verfolge den Kernel-Pfad (über Symbole, ETW, Hypervisor-Tracing oder Reversing), bis du einen `NtOpen*`-/`ObOpenObjectByName`-Aufruf findest, der einen vom Angreifer kontrollierten Namen oder einen symbolischen Link in einem für Benutzer beschreibbaren Verzeichnis durchläuft.
2. **Replace that name with a slow path**
- Erstelle die lange Komponente oder Verzeichniskette unter `\BaseNamedObjects` (oder einem anderen beschreibbaren OM-Root).
- Erstelle einen symbolischen Link, sodass der vom Kernel erwartete Name nun zum Slow Path aufgelöst wird. Du kannst die Verzeichnissuche des verwundbaren Treibers auf deine Struktur verweisen lassen, ohne das ursprüngliche Ziel anzufassen.
3. **Trigger the race**
- Thread A (Opfer) führt den verwundbaren Code aus und wird innerhalb der langsamen Suche blockiert.
- Thread B (Angreifer) ändert den geschützten Zustand (z. B. durch Austauschen eines File-Handles, Umschreiben eines symbolischen Links oder Umschalten der Objektsicherheit), während Thread A beschäftigt ist.
- Wenn Thread A fortfährt und die privilegierte Aktion ausführt, sieht es einen veralteten Zustand und führt die vom Angreifer kontrollierte Operation aus.
4. **Clean up** – Lösche die Verzeichniskette und die symbolischen Links, damit keine verdächtigen Artefakte zurückbleiben oder legitime IPC-Benutzer beeinträchtigt werden.<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), veröffentlicht als Bypass für RoguePlanet (CVE-2026-50656), demonstriert ein umfassenderes Exploitation-Muster: Einen privilegierten Scanner dazu bringen, eine Darstellung einer logischen Datei zu klassifizieren, und anschließend sowohl deren Bytes als auch die Namespace-Auflösung zu ändern, bevor die Behebung sie verwendet. Der PoC kombiniert eine Cloud Files hydration TOCTOU, einen Object Manager shadow-directory fallback, die Erfassung eines CLFS-generated-name und einen local administrative-share link, um die Defender-Bereinigung in einen protected DLL write umzuwandeln.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substitute content through Cloud Files hydration

Registriere ein für den Angreifer beschreibbares Verzeichnis als Cloud Files sync root, verbinde einen `CF_CALLBACK_TYPE_FETCH_DATA`-Callback und erstelle einen Placeholder, dessen angegebene Größe einem deterministischen Detection-Trigger wie dem EICAR ZIP entspricht. Der erste Fetch gibt den Trigger zurück und schaltet den Callback-Zustand um; spätere Fetches geben das Payload zurück. Nachdem der Scanner die erste Darstellung klassifiziert hat, beschaffe den Transfer-Key und starte die Hydration mit Metadaten in Payload-Größe neu. Erzwinge anschließend die Hydration bis zu EOF.<sup>[[4]](#references)</sup>
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
Die Sicherheitsgrenze versagt, wenn sich Scan, Bewertung und Behebung nur auf einen Pfadnamen oder eine Platzhalteridentität beziehen: Keine dieser Angaben garantiert, dass ein späteres Laden die geprüften Bytes zurückgibt.<sup>[[4]](#references)</sup>

### 2. Einen invarianten Pfad über ein Shadow-Directory-Fallback umschalten

Erstelle mit `NtCreateDirectoryObjectEx` ein Zielverzeichnis im Object Manager sowie ein zweites Verzeichnis und übergib dabei das Handle des Zielverzeichnisses als dessen Shadow-/Fallback-Verzeichnis. Lege in beiden Auflösungsebenen einen gleichnamigen `WD_SCAN`-Eintrag an: Der sichtbare Eintrag verweist auf das normale Arbeitsverzeichnis, während der Fallback-Eintrag auf `\CLFS\??\<working-directory>` verweist. Übergib Defender nur den folgenden invarianten Pfad; wird der sichtbare Link gelöscht, während der Vorgang aktiv ist, fällt dieselbe Zeichenfolge auf den CLFS-gestützten Eintrag zurück.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Dies unterscheidet sich davon, Shadow-Verzeichnisse ausschließlich zur Verlangsamung der Suche zu verwenden: Der Angreifer ändert die **Bedeutung** eines zuvor akzeptierten Pfads, ohne dessen Zeichenfolge zu verändern.<sup>[[4]](#references)</sup>

### 3. Den generierten Namen erfassen und einen dateinamensspezifischen Link installieren

Überwache das Arbeitsverzeichnis mit `ReadDirectoryChangesW`. Entferne beim ersten `FILE_ACTION_ADDED`-Ereignis den sichtbaren `WD_SCAN`-Link, um die Fallback-Suche zu aktivieren. Erfasse den zweiten generierten Dateinamen, öffne die zugehörige CLFS-Datei und sperre den Bereich `0..MAXLONGLONG` mit `LockFileEx`. Während der privilegierte Vorgang angehalten ist, ersetze `WD_SCAN` im sichtbaren Verzeichnis durch ein echtes Object Manager-Verzeichnis und erstelle einen untergeordneten symbolischen Link mit dem beobachteten Dateinamen (der PoC entfernt dessen letzte vier Zeichen). Verweise ihn über lokales SMB auf das geschützte Ziel:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Der unprivilegierte Prozess kann selbst nicht in dieses Ziel schreiben, aber der SYSTEM-Kontext von Defender kann die administrative Loopback-Freigabe durchqueren. Die Kombination aus der Beobachtung generierter Namen und einem dateinamenspezifischen Object-Manager-Link macht es unnötig, das Behebungsartefakt im Voraus vorherzusagen.<sup>[[4]](#references)</sup>

### 4. Den Cleanup-Race stabilisieren und einen privilegierten Loader auslösen

Vor dem Scannen speichert der PoC ein gültiges PE (`ntdll.dll`) im `:stream`-NTFS-Alternate-Data-Stream des Platzhalters. Nachdem die Umleitung die geschützte Basisdatei erstellt hat, öffnet er `phoneinfo.dll:stream` mit Execute-Zugriff und hält ein `PAGE_EXECUTE_READ | SEC_IMAGE`-Mapping aktiv, während der Cleanup fortgesetzt wird; die aktiven Datei-/Section-Objekte erschweren das Löschen oder Ersetzen während des finalen Race. Die neu gestartete Hydration gibt nun die Payload-DLL anstelle von EICAR zurück, sodass die geschützte Basisdatei vom Angreifer kontrollierten Code enthält.<sup>[[4]](#references)</sup>

Ein geschützter Schreibvorgang wird anschließend durch das Ablegen einer präparierten `Report.wer` unter `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` und das Aufrufen von `\Microsoft\Windows\Windows Error Reporting\QueueReporting` über die Task-Scheduler-COM-API in SYSTEM-Ausführung umgewandelt. In dieser Chain lädt die privilegierte WER-Verarbeitung die platzierte `C:\Windows\System32\phoneinfo.dll`; eine Named-Pipe-Verbindung dient als Signal für die Payload-Ausführung.<sup>[[4]](#references)</sup>

### Detection-Pivots

Nützliche Korrelationen sind spezifischer als jeder einzelne temporäre Dateiname und decken alle Namespace-Übergänge in der Chain ab:<sup>[[4]](#references)</sup>

- Ein neu registrierter Cloud-Files-Provider, gefolgt von einer EICAR-Erkennung und `CF_OPERATION_TYPE_RESTART_HYDRATION` für denselben Platzhalter.
- Object-Manager-Pfade mit `WD_TARGET_*`, `WD_SHADOW_*` oder `WD_SCAN`, insbesondere ein Scan-Pfad unterhalb von `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Erstellung einer CLFS-Datei, gefolgt von einer exklusiven Sperre der gesamten Datei und einem Loopback-Zugriff auf `\\127.0.0.1\C$\Windows\System32\*.dll` durch einen privilegierten Security-Prozess.
- Erstellung einer System32-DLL zusammen mit einem NTFS-ADS, gefolgt von einem `SEC_IMAGE`-Mapping des Streams.
- Ein vom Angreifer erstellter WER-Queue-Eintrag, gefolgt von einer ungewöhnlichen manuellen Ausführung von `\Microsoft\Windows\Windows Error Reporting\QueueReporting` und dem Laden eines Images aus der platzierten DLL.

## Angewandte Chain: durch Oplock gesteuerter Mount-Point-Wechsel gegen privilegierte Behebung

Ein wiederverwendbares LPE-Muster tritt auf, wenn ein privilegierter Scanner eine vom Angreifer kontrollierte Datei prüft und sie später behebt, indem er den **Pfadnamen** erneut öffnet, anstatt weiterhin validierte Handles zu verwenden. FalconFlank ist ein öffentliches Beispiel, das auf den Workflow zur Entfernung von Office-Makros in CrowdStrike Falcon abzielt; das Repository behauptet Tests unter Windows 11 25H2 und Windows Server 2025 bei aktivierter relevanter Richtlinie, veröffentlicht jedoch keine CVE, keinen Bereich betroffener Builds, keine Herstellerempfehlung und keinen Patch-Status. Daher ist die produktspezifische Behauptung als unverifiziert und buildabhängig zu behandeln.<sup>[[5]](#references)[[6]](#references)</sup>

### Race-Aufbau

1. Erstelle einen beschreibbaren Verzeichnisbaum, dessen letzter relativer Name am vorgesehenen Zielort nützlich ist. Das Beispiel verwendet `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, schreibt zunächst jedoch kein PE-DLL, sondern ein OLE-Makrodokument nach `bcrypt.dll`. Die inhaltsbasierte Erkennung löst die Behebung aus, während der vom Angreifer kontrollierte Basisname für den späteren Side-Load erhalten bleibt.<sup>[[5]](#references)</sup>
2. Öffne die Verzeichnisse mit weit gefasstem Sharing und `FILE_OPEN_REPARSE_POINT`, und fordere anschließend mit `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` und `REQUEST_OPLOCK_INPUT_FLAG_REQUEST` einen asynchronen RH-Oplock für den Trigger an. Warte auf das Overlapped-Event und verwende dessen Abschluss als Signal für den Pfadwechsel. Eine RH-Oplock-Break-Benachrichtigung ist lediglich ein Hinweis und kein Beweis dafür, dass jeder konkurrierende Vorgang blockiert ist. Die Ausnutzbarkeit hängt daher weiterhin von der exakten Open-/Remediation-Sequenz des Opfers ab.<sup>[[5]](#references)[[7]](#references)</sup>
3. Entferne nach dem Break das Leaf-Verzeichnis mit `FileDispositionInformationEx` (Informationsklasse 64), wobei Lösch- und POSIX-Semantik-Flags verwendet werden. Schließe anschließend dessen Handle und setze mit `FSCTL_SET_REPARSE_POINT_EX` ein `IO_REPARSE_TAG_MOUNT_POINT` auf den nun leeren übergeordneten Ordner. Der Mount Point leitet das unveränderte Suffix in einen geschützten Baum wie `\\SystemRoot\\System32\\WindowsPowerShell` um. Das Setzen eines Reparse Points schlägt fehl, wenn das Verzeichnis nicht leer ist, was den vorherigen Löschschritt erklärt.<sup>[[5]](#references)[[8]](#references)</sup>
4. Setze den privilegierten Workflow fort. Wenn dieser die Zeichenfolge erneut auflöst, ohne nachzuweisen, dass die Verzeichniskette und das endgültige Objekt mit den zuvor geprüften übereinstimmen, erreicht derselbe logische Pfad nun das vom Angreifer ausgewählte geschützte Verzeichnis. Im Beispiel wird der Erfolg geprüft, indem `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` aus dem ursprünglichen Prozess erneut mit Lese-/Schreibzugriff geöffnet wird. Dadurch lässt sich die Confused-Deputy-Schreibprimitive von der späteren Code-Execution-Phase unterscheiden.<sup>[[5]](#references)</sup>
5. Ersetze die resultierende Datei durch die echte DLL und aktiviere einen privilegierten Loader. Der PoC verwendet `CreateTransaction` und `CreateFileTransacted`, kürzt die Datei, mappt den DLL-großen Ersatz, kopiert das PE und führt den Commit aus. TxF bindet den Datei-Handle und nachfolgende handlebasierte Vorgänge an die Transaktion, ist jedoch ein Replacement-Mechanismus nach dem Race und nicht die Ursache für den Fehler an der Privilege Boundary.<sup>[[5]](#references)[[9]](#references)</sup>
6. Führe abschließend eine vorhandene privilegierte Scheduled Task aus, deren ausführbare Datei den benachbarten Dateinamen abfragt. FalconFlank ruft `\\Microsoft\\Windows\\Application Experience\\MareBackup` auf, wartet darauf, dass die DLL eine Verbindung zu `\\??\\pipe\\FALCONFLANK` herstellt, und löscht anschließend die platzierte Datei. Leite nicht allein aus dem Task-Namen einen bestimmten resultierenden Token ab, sondern überprüfe den gestarteten Prozess, den Modulpfad, das Integrity Level und den Token auf dem getesteten Build.<sup>[[5]](#references)</sup>

Die zentrale Audit-Frage lautet daher nicht „validiert der Dienst den ursprünglichen Eingabepfad?“, sondern „bleibt jede privilegierte Mutation an dieselben geöffneten Datei- und Verzeichnisobjekte gebunden, die validiert wurden?“ Das Halten von Handles über Prüfung und Verwendung hinweg, das Öffnen untergeordneter Objekte relativ zu einem vertrauenswürdigen Verzeichnis-Handle, das Zurückweisen unerwarteter Reparse-Tags und die erneute Validierung der Dateiidentität vor der Mutation schließen diese Klasse von Pathname-Substitution-Bugs.<sup>[[1]](#references)[[8]](#references)</sup>

### Detection und PoC-Triage

Eine Detection mit hoher Aussagekraft korreliert den Namespace-Übergang mit dem privilegierten Consumer: ein OLE-Header unter einem DLL-Basisnamen in einem temporären Verzeichnisbaum mit GUID-Namen, ein Oplock-Break, die Entfernung des Leaf-Verzeichnisses mit POSIX-Semantik, die Erstellung eines Mount Points mit Ziel in einem geschützten Windows-Verzeichnis sowie die Erstellung oder Änderung desselben Basisnamens unterhalb dieses Ziels. Für das öffentliche Beispiel sollten `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, die manuelle Ausführung von `MareBackup` und die Named Pipe `FALCONFLANK` als engere Pivots ergänzt werden; keines davon reicht allein aus.<sup>[[5]](#references)</sup>

Bei der Reproduktion des PoC sind drei Zuverlässigkeitsfehler in der veröffentlichten Quelle zu berücksichtigen: Sie ruft `FlushFileBuffers` mit dem Zeiger auf das eingebettete Byte-Array anstelle des Datei-Handles auf, prüft nach `GetFolder`, `GetTask` und `Run` einen veralteten `HRESULT` und verwendet unbeschränkte Retry-/Wait-Schleifen für das Löschen von Verzeichnissen, die Erstellung des Reparse Points, das Oplock-Event und die Pipe-Verbindung.<sup>[[5]](#references)</sup>

## Betriebstechnische Überlegungen

- **Primitives kombinieren** – Du kannst pro Ebene in einer Verzeichniskette einen langen Namen verwenden, um die Latenz weiter zu erhöhen, bis die Größe von `UNICODE_STRING` ausgeschöpft ist.
- **One-Shot-Bugs** – Das vergrößerte Zeitfenster (von mehreren zehn Mikrosekunden bis zu Minuten) macht „Single-Trigger“-Bugs realistisch, wenn sie mit CPU-Affinitätsbindung oder Hypervisor-gestützter Preemption kombiniert werden.
- **Nebenwirkungen** – Die Verlangsamung betrifft nur den bösartigen Pfad, daher bleibt die Gesamtleistung des Systems unbeeinträchtigt. Ohne Überwachung des Namespace-Wachstums werden Defender dies selten bemerken.
- **Cleanup** – Halte Handles auf jedes von dir erstellte Verzeichnis/Objekt, damit du anschließend `NtMakeTemporaryObject`/`NtClose` aufrufen kannst. Unbeschränkte Verzeichnisketten können andernfalls über Neustarts hinweg bestehen bleiben.
- **Dateisystem-Races** – Wenn der verwundbare Pfad letztlich über NTFS aufgelöst wird, kannst du während der OM-Verlangsamung einen Oplock (z. B. `SetOpLock.exe` aus demselben Toolkit) auf die zugrunde liegende Datei setzen. Dadurch wird der Consumer für zusätzliche Millisekunden eingefroren, ohne den OM-Graphen zu verändern.<sup>[[2]](#references)</sup>

## Hinweise zur Abwehr

- Kernel-Code, der sich auf benannte Objekte stützt, sollte sicherheitsrelevante Zustände *nach* dem Öffnen erneut validieren oder vor der Prüfung eine Referenz übernehmen, um die TOCTOU-Lücke zu schließen.
- Erzwinge Obergrenzen für Tiefe und Länge von OM-Pfaden, bevor benutzerkontrollierte Namen dereferenziert werden. Das Zurückweisen übermäßig langer Namen zwingt Angreifer zurück in das Mikrosekunden-Zeitfenster.
- Instrumentiere das Wachstum des Object-Manager-Namespace (ETW `Microsoft-Windows-Kernel-Object`), um verdächtige Ketten mit Tausenden von Komponenten unter `\BaseNamedObjects` zu erkennen.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - How to Use Transactional NTFS](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
