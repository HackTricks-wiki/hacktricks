# Fuzzing Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Beim **mutational grammar fuzzing** werden Inputs mutiert, wobei sie **grammatikkonform** bleiben. Im coverage-guided-Modus werden nur Samples, die **neue Coverage** auslösen, als Corpus-Seeds gespeichert. Bei **Sprachzielen** (Parsern, Interpretern, Engines) können so Bugs übersehen werden, die **semantische Datenflussketten** erfordern, bei denen die Ausgabe eines Konstrukts zur Eingabe eines anderen wird.<sup>[[1]](#references)</sup>

**Fehlermodus:** Der Fuzzer findet Seeds, die einzeln `document()` und `generate-id()` (oder ähnliche Primitiven) ausführen, bewahrt aber **den verketteten Datenfluss nicht**. Dadurch wird das „bugnähere“ Sample verworfen, weil es keine zusätzliche Coverage erzielt. Bei **3+ abhängigen Schritten** wird zufällige Rekombination aufwendig, und das Coverage-Feedback lenkt die Suche nicht.<sup>[[1]](#references)</sup>

**Folgerung:** Bei Grammatiken mit vielen Abhängigkeiten empfiehlt es sich, **mutationale und generative Phasen zu kombinieren** oder die Generierung auf Muster mit **Funktionsverkettungen** auszurichten (nicht nur auf Coverage).<sup>[[1]](#references)</sup>

## Fallstricke bei der Corpus-Diversität

Coverage-gesteuerte Mutation ist **gierig**: Ein Sample mit neuer Coverage wird sofort gespeichert und enthält oft große, unveränderte Bereiche. Mit der Zeit bestehen Corpora aus **Beinahe-Duplikaten** mit geringer struktureller Vielfalt. Aggressive Minimierung kann nützlichen Kontext entfernen. Ein praktischer Kompromiss ist daher eine **grammatikbewusste Minimierung**, die **nach Erreichen einer Mindestanzahl an Tokens stoppt** (Rauschen reduzieren und zugleich genug umgebende Struktur für mutationsfreundliche Seeds erhalten).<sup>[[1]](#references)</sup>

Eine praktische Corpus-Regel für mutational fuzzing lautet: **Eine kleine Menge strukturell unterschiedlicher Seeds, die die Coverage maximiert, ist einem großen Haufen Beinahe-Duplikate vorzuziehen.** In der Praxis bedeutet das meist Folgendes.<sup>[[1]](#references)[[3]](#references)</sup>

- Mit **realen Samples** beginnen (öffentliche Corpora, Crawling, aufgezeichneter Traffic, Dateisammlungen aus dem Ökosystem des Ziels).
- Diese mit **Coverage-basierter Corpus-Minimierung** reduzieren, statt jedes gültige Sample zu behalten.
- Seeds **klein genug** halten, damit Mutationen sinnvolle Felder treffen, anstatt die meisten Zyklen mit irrelevanten Bytes zu verbringen.
- Nach größeren Änderungen an Harness oder Instrumentierung die Corpus-Minimierung erneut ausführen, da sich das „beste“ Corpus ändert, wenn sich die Erreichbarkeit ändert.

## Vergleichsbewusste Mutation für Magic Values

Ein häufiger Grund dafür, dass Fuzzer stagnieren, sind nicht Syntaxprobleme, sondern **harte Vergleiche**: Magic Bytes, Längenprüfungen, Enum-Strings, Checksummen oder Parser-Dispatch-Werte, die durch `memcmp`, Switch-Tabellen oder verkettete Vergleiche abgesichert sind. Bei reiner Zufallsmutation werden Zyklen damit verschwendet, diese Werte Byte für Byte zu erraten.

Für solche Ziele sollte **Comparison Tracing** eingesetzt werden (zum Beispiel Workflows mit AFL++ `CMPLOG` oder im Redqueen-Stil), damit der Fuzzer Operanden fehlgeschlagener Vergleiche beobachten und Mutationen auf Werte ausrichten kann, die diese Vergleiche bestehen.<sup>[[3]](#references)</sup>

```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```

**Praktische Hinweise:**

- Dies ist besonders nützlich, wenn das Ziel tiefer liegende Logik hinter **Dateisignaturen**, **Protokollverben**, **Typ-Tags** oder **versionsabhängigen Feature-Bits** verbirgt.
- Kombiniere dies mit **Wörterbüchern**, die aus echten Beispielen, Protokollspezifikationen oder Debug-Logs extrahiert wurden. Ein kleines Wörterbuch mit Grammatik-Tokens, Chunk-Namen, Verben und Trennzeichen ist oft wertvoller als eine riesige generische Wortliste.
- Wenn das Ziel viele sequenzielle Prüfungen durchführt, löse zuerst die frühesten „Magic“-Vergleiche und minimiere anschließend den resultierenden Korpus erneut, damit spätere Stufen mit bereits gültigen Präfixen beginnen.

## Fuzzing von Datei-APIs, die eine Dateinamensprache verbergen

Ein Parameter namens `filename`, `path` oder `URL` kann ein Einstiegspunkt für einen Interpreter sein und nicht bloß eine wörtliche Dateisuche. Beispielsweise wertet die Extended Filename Syntax (EFS) von CFITSIO Selektoren in eckigen Klammern, Zeilen-/Pixelausdrücke, berechnete Spalten, Histogramme und Transformationen aus, bevor sie das geöffnete Objekt zurückgibt; einige Formen erstellen außerdem temporäre Kopien. Klassifiziere beim Mapping der Angriffsfläche jede Open-/Import-API als **wörtlicher Pfad** oder **interpretierter Pfad** und fuzze anschließend den produktiven Einstiegspunkt, den Anwendungen tatsächlich aufrufen.<sup>[[20]](#references)[[22]](#references)</sup>

Zu den daraus entstehenden SSRF-, Dateikopier- und Protokollhandler-Primitiven sowie sichereren APIs für wörtliche Pfade siehe [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Das zugrunde liegende Objekt vom gefuzzten Programm getrennt halten

Wenn die Grammatik in einem Dateinamensuffix steckt, verfehlt das Mutieren ausschließlich der Bytes der referenzierten Datei den Parser. Ein kleiner Harness kann stattdessen einen Testfall als String einlesen und an die interpretierende Open-API übergeben; die CFITSIO-Kampagne erreichte die meisten EFS-Parser und -Evaluatoren, indem sie `fits_open_file()` im schreibgeschützten Modus aufrief. Halte gültige Basisdateien separat verfügbar, damit sich Mutationen auf die Selektor-/Ausdruckssprache konzentrieren können, anstatt ständig den Basispfad unbrauchbar zu machen.<sup>[[22]](#references)</sup>

Verwende Seeds, die jeweils eine andere Grammatikfamilie erreichen, und leite anschließend aus der Spezifikation sowie dem Lexer-/Parser-Quellcode ein kompaktes Wörterbuch ab. Wenn die Coverage stagniert und Eingaben wiederholt am selben Syntaxfehlerpfad scheitern, bewahre gültige Präfixe und füge Trennzeichen, Operatoren, Schlüsselwörter, Funktionsnamen und repräsentative Feldnamen hinzu, anstatt nur die Laufzeit zufälliger Mutationen zu erhöhen.<sup>[[22]](#references)</sup>

Führe den Harness mit dem Grammatik-Wörterbuch aus, zum Beispiel:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Nebenwirkungen des „read-only“-Harness begrenzen

Ein „read-only“-Flag der Bibliothek garantiert keine testcase ohne Nebenwirkungen: Die Dateinamensprache kann die Eingabe umschreiben, Ausgabedateien erstellen oder temporäre Objekte materialisieren. Die CFITSIO-Kampagne zerstörte zunächst Seed-Dateien und hinterließ unerwartete Dateien im Dateisystem, weshalb Bereinigung und Isolation erforderlich waren.<sup>[[22]](#references)</sup>

- Gib jedem Worker ein entbehrliches Arbeitsverzeichnis und ein privates temporäres Verzeichnis.
- Stelle Kopien kanonischer Backing-Dateien bereit; lasse das Ziel niemals die einzige Kopie des Corpus verändern.
- Deaktiviere den Netzwerkzugriff, sofern Remote-Backends nicht das eigentliche Ziel sind, und beschränke beschreibbare Pfade mit einem Container, einem Mount-Namespace oder einer gleichwertigen Sandbox.
- Setze das Verzeichnis nach jeder Ausführung oder jedem Worker-Batch zurück und werte unerwartete Änderungen am Dateisystem als zusätzliche Findings.

### Crash-to-Patch-to-Fuzz-Schleife

Gruppiere Crashes vor der Behebung, damit aus Tausenden Artefakten nicht Tausende Patch-Aufgaben werden. Bei der CFITSIO-Bewertung reduzierte AFLTriage die anfängliche Crash-Menge auf wenige Ursachen; der daraus entstandene Sicherheitshinweis beschreibt unterschiedliche Fehler, darunter fehlerhafte Prüfungen der Zielgröße, veraltete Pointer nach `realloc()`, arithmetische Fehler und unsichere Parser-Bereinigungspfade.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimiere eine repräsentative Eingabe für jeden Cluster und reproduziere den Fehler unter AddressSanitizer.
2. Dokumentiere den genauen fehlerhaften Zugriff, die Quellcodeposition, die Allokations-/Freigabehistorie und den Parser-Zustand, durch den die Invariante verletzt wurde.
3. Wende einen eng begrenzten Kandidaten-Patch an und baue mit derselben Coverage- und Sanitizer-Instrumentierung neu.
4. Spiele den ursprünglichen Reproducer **und jede Eingabe in seinem Cluster** erneut ab; aktiviere außerdem die Leak-Erkennung, da eine Memory-Safety-Korrektur die Speicherverwaltung in einem Fehlerpfad beeinträchtigen kann.
5. Führe Funktionstests mit echten Dateien aus und setze den Test mit der angesammelten Queue fort (oder importiere diese Queue erneut, wenn die Engine nach einer Änderung der Binärdatei ein frisches Ausgabeverzeichnis benötigt).
6. Wiederhole den Vorgang: Wird der erste oberflächliche Crash beseitigt, können vorhandene Seeds oft einen tieferen Parser-Zustand erreichen.

Ein LLM kann Schritt 2 beschleunigen und einen Entwurf für Schritt 3 erstellen, wenn es die abstürzende Eingabe, den Sanitizer-Bericht, den Harness und den relevanten Quellcode erhält; sein Patch bleibt jedoch nicht vertrauenswürdig. Ob die Korrektur akzeptiert wird, entscheiden der Sanitizer-Replay und die Regressionstests, nicht die Erklärung des Modells.<sup>[[22]](#references)</sup>

## Aussagekräftigeres Feedback, wenn Edge-Coverage unterschiedliche Pfade zusammenfasst

Normale Edge-Coverage kann nicht zwischen zwei Ausführungen unterscheiden, die denselben Helper über unterschiedliche Aufrufer durchlaufen oder innerhalb einer Funktion unterschiedliche Kombinationen von Branches nehmen. Das ist bei gemeinsam genutzten Decodern, Protokoll-Dispatchern und Interpreter-Helpern wichtig, bei denen der **Weg** zu einer Edge den aktiven Zustand bestimmt. Jeden Aufrufkontext naiv zu verfolgen, ist ebenfalls gefährlich: Die Coverage-Map und die Queue können explodieren. Die Forschung zu kontextsensitive Fuzzing empfiehlt daher, nur vielversprechende Kontexte gezielt zu verfeinern, statt den gesamten Call Graph als kontextsensitiv zu behandeln.<sup>[[14]](#references)</sup>

Aktuelle AFL++-Builds bieten zusätzlich zu normaler Edge-Coverage **Ball-Larus-Path-Coverage pro Funktion**. Dabei wird jedem azyklischen Pfad durch eine Funktion ein Feature zugewiesen; Loop-Back-Edges werden entfernt, sodass dieses Feedback Kombinationen von Branches unterscheidet, **nicht aber die Anzahl der Schleifendurchläufe**. Beginne mit dem lockeren Level `1` und beschränke strengere Modi anschließend auf verdächtigen Parser- oder State-Machine-Code, da die Anzahl der Pfade exponentiell wachsen kann.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Für einen Helper, der von vielen sicherheitsrelevanten Stellen aus aufgerufen wird, kann der LTO-Modus jeden Funktionspfad mit seiner direkten Aufrufstelle kombinieren:<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

**Hinweise zur Kampagne:** Setze reichhaltigeres Feedback mit Bedacht ein und überwache dessen Kosten für Coverage-Map und Queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Führe parallel eine gewöhnliche Edge-Coverage-Instanz aus; reichhaltigeres Feedback ist nur dann nützlich, wenn die zusätzlichen Kosten für Queue und Map die Anzahl der Ausführungen pro Sekunde nicht beeinträchtigen.
- Verwende `AFL_LLVM_ALLOWLIST`, um die Pfad-/Caller-Instrumentierung einzuschränken, wenn große, template-lastige Bibliotheken oder generischer Utility-Code die Map dominieren.
- Funktionen mit übermäßig vielen azyklischen Pfaden können von AFL++ übersprungen werden; Warnungen während der Kompilierung sind ein Hinweis darauf, dass das Ziel Allowlisting oder eine weniger strenge Einstellung benötigt.
- Caller- und Path-Coverage unterstützen nur eine Caller-Tiefe. Kombiniere sie nicht mit tieferen Kontext-Stacks.
- Pfad-IDs können sich zwischen den Hauptversionen von LLVM ändern. Verwende während einer Kampagne eine feste Toolchain und synchronisiere keine PATH-basierten Korpora, als wären ihre Feature-IDs über verschiedene Builds hinweg stabil.
- Dieses Feedback ergänzt `CMPLOG`: Comparison-Tracing ermittelt, **welcher Wert eine Guard-Bedingung passiert**, während Path-/Caller-Feedback festhält, **welcher Pfad und welche Zweigkombination dorthin geführt haben**.

## Zustandsbehaftetes Fuzzing: Sequenzen sind Seeds

Bei **Protokollen**, **authentifizierten Workflows** und **mehrstufigen Parsern** ist die interessante Einheit oft kein einzelner Blob, sondern eine **Nachrichtensequenz**. Das gesamte Transkript in eine Datei zu schreiben und blind zu mutieren, ist meist ineffizient, weil der Fuzzer jeden Schritt gleichermaßen mutiert, selbst wenn nur die spätere Nachricht den fragilen Zustand erreicht.<sup>[[4]](#references)</sup>

Effektiver ist es, die **Sequenz selbst als Seed** zu behandeln und **beobachtbaren Zustand** (Antwortcodes, Protokollzustände, Parserphasen, zurückgegebene Objekttypen) als zusätzliches Feedback zu verwenden.<sup>[[4]](#references)</sup>

- Behalte **gültige Präfixnachrichten** unverändert bei und konzentriere Mutationen auf die Nachricht, die den **Zustandsübergang auslöst**.
- Speichere Bezeichner und vom Server erzeugte Werte aus vorherigen Antworten zwischen, wenn der nächste Schritt davon abhängt.
- Ziehe Mutationen und Splicing pro Nachricht dem Mutieren des gesamten serialisierten Transkripts als undurchsichtigem Blob vor.
- Wenn das Protokoll aussagekräftige Antwortcodes bereitstellt, verwende sie als **kostengünstigen Zustandsorakel**, um Sequenzen zu priorisieren, die tiefer in den Ablauf gelangen.

Aus demselben Grund werden authentifizierte Bugs, versteckte Übergänge oder Parser-Bugs, die „erst nach dem Handshake“ auftreten, beim herkömmlichen dateibasierten Fuzzing oft übersehen: Der Fuzzer muss **Reihenfolge, Zustand und Abhängigkeiten** erhalten, nicht nur die Struktur.<sup>[[4]](#references)</sup>

### Android Binder: Fuzzing mit Treibern für mehrere Clients

Eine hohe Edge-Coverage kann trotzdem IPC-Treiber-Bugs übersehen, da die Coverage **Objektbesitz, Referenzzähler, ausstehende Nachrichten, Bereinigungsreihenfolge oder Thread-Interleavings** nicht abbildet. Die Seite [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) behandelt das Treiberobjektmodell; dieses Beispiel konzentriert sich auf den Fuzzer-Harness. Android Binder ist ein nützliches Modell: Es reicht nicht aus, sowohl die Allokations- als auch die Freigabepfade zu erreichen, wenn der Fuzzer mehrere Prozesse nicht dazu bringen kann, dasselbe Kernelobjekt in der erforderlichen Reihenfolge zu verwenden.<sup>[[15]](#references)</sup>

#### Das Protokoll modellieren, nicht isolierte `ioctl`-Puffer

Stelle einen Testfall als geordnete Grammatik aus **Client-Identität + Operation + strukturierten Argumenten** dar. Der Binder-LKL-Fuzzer verwendet protobuf und `libprotobuf-mutator` mit einem persistenten Context-Manager-Client und zwei gewöhnlichen Clients. Ein semantischer Harness bewahrt anschließend die Beziehungen, die durch blinde Byte-Mutationen zerstört würden.<sup>[[15]](#references)</sup>

- Zwischenspeichern von Werten, die von früheren Operationen zurückgegeben wurden. Beispielsweise muss `BC_FREE_BUFFER` einen Transaktionspufferzeiger wiederverwenden, der von einem vorherigen `ioctl` zurückgegeben wurde.
- Gültige Standardantworten erzeugen, damit synchrone Transaktionen abgeschlossen werden können und spätere Operationen erreichbar bleiben.
- Unmögliche Übergänge wie Selbsttransaktionen oder mehrere ausstehende Transaktionen an dasselbe Ziel zurückweisen.
- Den Singleton-Bootstrap-Zustand außerhalb des Resets pro Eingabe halten. Binder erlaubt pro Bootvorgang nur eine `BINDER_SET_CONTEXT_MGR`-Registrierung, daher würden wiederholtes Zerstören und Neuerstellen dieses Clients spätere Eingaben ungültig machen.

Ein nützliches Muster für Lifetime-Races besteht darin, einen Client ein Objekt übertragen zu lassen, die Bereinigung eines Threads oder Prozesses zu starten und den empfangenden Client gleichzeitig den Transaktionspuffer freigeben zu lassen. Im Beispiel CVE-2020-0423 konnte eine Übertragung von `BINDER_TYPE_WEAK_BINDER`, gefolgt von einem `BINDER_THREAD_EXIT`, das mit `BC_FREE_BUFFER` konkurrierte, ein eingebettetes `binder_work` freigeben, während der Bereinigungspfad des beendenden Threads es noch verwendete.<sup>[[15]](#references)</sup>

#### Kontrollierte Interleavings in einem Userspace-Kernel wieder einführen

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) bindet den echten Kernel-Code in einen Userspace-Harness ein und stellt dessen Syscall-Schnittstelle über `lkl_syscall` bereit. Dadurch lassen sich protobuf-Zustand, Coverage und KASAN einfach in einem Prozess koordinieren. Normalerweise führt LKL einen Syscall jedoch aus, ohne dass ein anderer Kernel-Thread ihn unterbricht. Füge für Race-Kampagnen `schedule()`-Punkte an ausgewählten Grenzen von Locks und Objektlebenszeiten ein und lass den Harness bei jeder Übergabe zufällig den nächsten Client auswählen. Platziere diese Punkte gezielt, da jeder einzelne den Suchraum für die Scheduling-Reihenfolge vervielfacht. Der von den Forschern beschriebene randomisierte Scheduler ist **nicht** Bestandteil des upstream Binder-Fuzzers.<sup>[[15]](#references)</sup>

#### Serialisierte Regression-Seeds erstellen und wiedergeben

Der upstream Harness legt eine kompatible Version von `libprotobuf-mutator` fest, aktiviert die LKL-Fuzzing-Instrumentierung und KASAN mit `LKL_FUZZING=1` und aktiviert `CONFIG_MMU` für Binder mit `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nach dem Auschecken einer absichtlich verwundbaren Revision oder dem Anwenden der upstream dokumentierten Rollback-Patches kann ein serialisierter Seed den gesamten Zustandsübergang mehrerer Clients reproduzieren, ohne ihn in einem ad-hoc-C-Proof-of-Concept rekonstruieren zu müssen:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandle den resultierenden KASAN-use-after-free als Bestätigung dafür, dass der Seed den anfälligen Lifetime-Pfad erreicht hat. Er belegt **nicht** die späteren Primitives, die für die Ausführung von Kernel-Code oder eine Privilegienausweitung erforderlich sind.<sup>[[16]](#references)</sup>

## Diversity-Trick auf einer einzelnen Maschine (im Jackalope-Stil)

Eine praktische Möglichkeit, **generative Neuartigkeit** mit **wiederverwendeter Coverage** zu kombinieren, besteht darin, kurzlebige Worker gegen einen persistenten Server **neu zu starten**. Jeder Worker beginnt mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden mit dem kombinierten Corpus, synchronisiert erneut und wird dann beendet. So entstehen **in jeder Generation frische Strukturen**, während gleichzeitig die angesammelte Coverage genutzt wird.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sequenzielle Worker (Beispielschleife):**

<details>
<summary>Jackalope-Worker-Neustartschleife</summary>

```python
import subprocess
import time

T = 3600

while True:
  subprocess.run(["rm", "-rf", "workerout"])
  p = subprocess.Popen([
      "/path/to/fuzzer",
      "-grammar", "grammar.txt",
      "-instrumentation", "sancov",
      "-in", "empty",
      "-out", "workerout",
      "-t", "1000",
      "-delivery", "shmem",
      "-iterations", "10000",
      "-mute_child",
      "-nthreads", "6",
      "-server", "127.0.0.1:8337",
      "-server_update_interval", str(T),
      "--", "./harness", "-m", "@@",
  ])
  time.sleep(T * 2)
  p.kill()
```

</details>

**Hinweise:**

- `-in empty` erzwingt bei jeder Generation ein **frisches Corpus**.
- `-server_update_interval T` approximiert eine **verzögerte Synchronisierung** (zuerst neue Eingaben, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird die **anfängliche Serversynchronisierung standardmäßig übersprungen** (`-skip_initial_server_sync` ist nicht erforderlich).
- Der optimale Wert für `T` ist **zielabhängig**; am besten funktioniert es meist, nach dem Auffinden des Großteils der „einfachen“ Coverage durch den Worker umzuschalten.

## Snapshot Fuzzing für schwer zu harnessende Ziele

Wenn der Code, den Sie testen möchten, erst **nach erheblichem Einrichtungsaufwand erreichbar wird** (Starten einer VM, Abschließen eines Logins, Empfangen eines Pakets, Parsen eines Containers, Initialisieren eines Dienstes), ist **Snapshot Fuzzing** eine nützliche Alternative: Erfassen Sie den bereitstehenden Prozess- oder VM-Zustand, injizieren Sie jeden Testfall in den Eingabepfad des Ziels, führen Sie ihn bis zum Crash/Timeout aus und stellen Sie den Snapshot wieder her. So müssen Initialisierung oder Protokollpräfixe nicht wiederholt werden. Das ist nützlich für **Netzwerkdienste**, **Firmware**, **Angriffsflächen nach der Authentifizierung** und **Binary-only-Ziele**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Führen Sie das Ziel aus, bis der relevante Zustand bereit ist.
2. Erstellen Sie an diesem Punkt einen Snapshot von **Speicher + Registern**.
3. Schreiben Sie für jeden Testfall die mutierte Eingabe direkt in den relevanten Gast-/Prozesspuffer.
4. Führen Sie die Ausführung bis zum Crash/Timeout/Reset fort.
5. Stellen Sie den Snapshot wieder her; bei VM-Zielen können Sie, sofern unterstützt, nur die **veränderten Seiten** wiederherstellen und den Vorgang wiederholen.

Platzieren Sie den Snapshot so nahe wie praktisch möglich am ersten aufwendigen Parse-/Dispatch-Schritt, etwa nach einem `recv`/`read` oder an einem Punkt der Paketdeserialisierung, und erfassen Sie den vom Ziel verwendeten Eingabepuffer. Dies folgt dem Prinzip der adaptiven Platzierung: Der Snapshot wird tiefer in die Eingabeverarbeitung verschoben, um wiederholte Arbeit zu vermeiden.<sup>[[11]](#references)</sup>

### Inkrementelle Snapshots für Protokollzustände

Ein fester Snapshot vermeidet zwar den Einrichtungsaufwand, erkundet aber nicht automatisch Übergänge, für die mehrere gültige Nachrichten erforderlich sind. Ein LibAFL-Qemu-Harness kann Schreibvorgänge in ein Protokollzustandsfeld überwachen und bei einer Zustandsänderung einen neuen Snapshot speichern. Im [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful) überwacht es `tcpcb.t_state`, hasht Zustand und Antwort-Flags, um Snapshots zu deduplizieren, und speichert veränderte Seiten relativ zu einem übergeordneten Snapshot. Vor der Mutation der nächsten strukturierten Nachricht stellt es den ausgewählten Snapshot über dessen übergeordnete Snapshots wieder her. Der Testfall enthält eine `SnapshotId` und generierte Eingabebytes (`gen_bytes`); der Snapshot-Manager verfolgt die für die Wiederholung benötigte Elternbeziehung.<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemus user-mode-`SnapshotModule` speichert Mappings und Ziel-Speicher, aber keine CPU-Register; sichern Sie diese bei Bedarf separat. Der beschriebene Manager unterstützt einen einzigen Snapshot-Baum mit Wurzel und kann Snapshot-IDs nicht zwischen Workern gemeinsam nutzen. Sein Multi-Snapshot-Modus kann außerdem den QASAN-Schattenzustand nicht direkt wiederverwenden. Für die Offline-Triage rekonstruieren Sie die Eingabekette in einem separaten instrumentierten Prozess. Bei Verwendung von `AsanHostModule` und `DrCovModule` führt `fuzzer.evaluate_input` die erforderlichen `pre_exec`-/`post_exec`-Callbacks aus; `qemu.run` allein tut dies nicht.<sup>[[27]](#references)[[28]](#references)</sup>

### Logische Ringpuffer-Überlesevorgänge erkennen

Ein Lesezugriff über die *Anzahl gültiger Daten* eines Puffers hinaus kann innerhalb seiner Host-Allokation bleiben und gewöhnliches ASAN umgehen. Das [libslirp-Beispiel für Urgent Data](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) verursacht außerdem einen Underflow bei einer vorzeichenlosen Byteanzahl. Wenn der Quellcode verfügbar ist, kann die Instrumentierung für vorzeichenbehafteten/vorzeichenlosen Integer-Overflow diesen Nebeneffekt erkennen; unterscheiden Sie absichtliches TCP-Sequenznummern-Wrapping, bevor Sie Meldungen unterdrücken. Ein stärkerer, vorgeschlagener Oracle besteht darin, die benutzerdefinierte Ringpuffer-Allokation zu vergiften, nur gültige Bereiche beim Vorrücken des internen Allokators zu entgiften und freigegebene Bereiche erneut zu vergiften. LibAFL-Qemu stellt eine ASAN-Poisoning-API für Ziele bereit, bei denen die Instrumentierung des Quellcodes unpraktisch ist.<sup>[[27]](#references)</sup>

## Race-Exploration im Linux-Kernel mit MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) macht timingabhängige Races im Linux-Kernel zu reproduzierbaren Speicherzugriffsabläufen. Das Tool kann **A-B-A**-Ausführungen in zwei Kontexten automatisch aufzählen oder Analysten die Reihenfolge über Einschränkungen in einer Terminal-UI/GUI vorgeben lassen. Es handelt sich um experimentelle Forschungswerkzeuge, nicht um einen vollständigen Concurrency-Fuzzer: Derzeit sind LLVM 23+ und der gepatchte Kernel des Projekts erforderlich, die Kommandozeilen-Tools unterstützen zwei Test-Threads, und die vorgeschlagene Userspace-Fuzzing-Schicht ist noch nicht implementiert.<sup>[[17]](#references)[[18]](#references)</sup>

### Kommunikationspunkte zwischen Kontexten erfassen

Erstellen Sie den instrumentierten Kernel mit KASAN-Outline-Callbacks und der gepatchten KCOV-Unterstützung für Speicheraufzeichnungen. Die README des Projekts empfiehlt außerdem, die Optimierung von Geschwisteraufrufen zu deaktivieren, damit Call-Stacks weiterhin verwendbar sind.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

Der KASAN-Outline-Modus (`asan-instrumentation-with-call-threshold=0`) wandelt instrumentierte Zugriffe in Helferaufrufe um. Die MAccConc-Kernel-Patches deaktivieren `asan-opt-same-temp`, damit aufeinanderfolgende Zugriffe nicht zusammengeführt werden; deaktiviere auch die Optimierung `asan-opt-globals`, wenn Races auf globale Variablen sichtbar sein müssen. KCOV überträgt die resultierenden Datensätze an den Userspace. Vergleiche Zugriffe aus verschiedenen Ausführungskontexten und behalte Paare bei, deren Bytebereiche sich überschneiden und bei denen mindestens eine Seite schreibt; behandle `kfree()` als Schreibzugriff, damit auch Lebensdauerübergänge als Kandidaten erfasst werden.<sup>[[17]](#references)</sup>

Bei Arbeit, die den initiierenden Task verlässt, etwa der Paketverarbeitung oder RCU-Callbacks, muss das Subsystem ein KCOV-Remote-Coverage-Handle weitergeben. Upstream-Remote-KCOV ist Opt-in und für beliebige Hintergrundarbeit nicht automatisch verfügbar. Eine fehlende Weitergabe kann daher eine reale Interaktion unsichtbar machen.<sup>[[17]](#references)[[19]](#references)</sup>

### Denselben dynamischen Zugriff bei jedem Lauf identifizieren

Wiederhole den Test nicht mit einer konkreten Heap-Adresse, die sich nach jeder Allokation ändern kann, und verwende auch nicht nur eine Instruktionsadresse, die innerhalb von Helfern wie `memcpy()` und `spin_lock()` mehrdeutig ist. MAccConc verwendet einen **Stacktrace mit Aufrufzählern**: Jeder Frame identifiziert einen Callee sowie dessen Aufrufzähler innerhalb des aufrufenden Frames, und das letzte Element identifiziert die Speicherzugriffs-Instruktion. SanitizerCoverage-Aufzeichungen von Funktionsaufrufen und -rückgaben ermöglichen es dem Userspace, diesen dynamischen Bezeichner zu rekonstruieren, der trotz Adressänderungen und irrelevanter Kontrollflussänderungen stabil bleibt.<sup>[[17]](#references)</sup>

### Kandidatenpaare in erzwungene Schedules umwandeln

Der gepatchte `KCOV_SET_DI`-Ioctl ordnet einem zugriffsspezifischen Bezeichner mit Aufrufzählern eine Aktion für ein gemeinsames Flag zu.<sup>[[17]](#references)</sup>

| Aktion | Semantik |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Setzt Flag *N* unmittelbar vor dem ausgewählten Zugriff. |
| `DI_STACK_WAIT` | Wartet vor dem ausgewählten Zugriff in einer Schleife, bis Flag *N* gesetzt ist oder das konfigurierte Limit abläuft. |
| `DI_STACK_WAKE_POST` | Setzt Flag *N* unmittelbar nach dem ausgewählten Zugriff. |

Für eine partielle **A-happens-before-B**-Bedingung ordne A `DI_STACK_WAKE_POST` und B `DI_STACK_WAIT` zu und verwende dasselbe Flag. Für einen vollständig festgelegten Schedule mit zwei Kontexten blockierst du zunächst B und lässt dann A B aufwecken und am ersten Übergabepunkt warten; beim nächsten Übergabepunkt führt B die umgekehrte Operation aus. Letzteres wirkt wie deterministisches Kontextwechseln und wird vom automatischen A-B-A-Explorer verwendet.<sup>[[17]](#references)</sup>

Eine minimale Kampagne besteht darin, den Testfall mit vier Hooks (`test_setup`, zwei Thread-Funktionen und `test_end`) als Shared Library zu kompilieren, zunächst einen Trace ohne Einschränkungen aufzuzeichnen und anschließend A-B-A-Kandidaten aufzuzählen oder manuelle Einschränkungen um verdächtige Zugriffe hinzuzufügen.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeouts separat von erfolgreichen Umordnungen betrachten: Eine angeforderte Reihenfolge ist möglicherweise unmöglich, weil eine Sperre oder eine Abhängigkeit bei der Initialisierung/Veröffentlichung verhindert, dass der zweite Kontext seinen Injection Point erreicht. Berücksichtige auch die blinden Flecken von KASAN: Direkte Stack-Zugriffe werden normalerweise nicht instrumentiert, außer wenn sie möglicherweise außerhalb der Grenzen liegen, globale Variablen werden bei der Standardoptimierung ausgelassen, und aktuelle Compiler können ASAN- und TSAN-Hooks nicht gleichzeitig ausgeben. Außerdem verliert der Prototyp den KCOV-Puffer, wenn eine Gast-VM abstürzt. Bewahre daher eine unabhängige Crash-Konsole bzw. ein unabhängiges Crash-Orakel.<sup>[[17]](#references)</sup>

Für zukünftiges Concurrency-guided Fuzzing sollten Speicherzugriffsübersichten pro Eingabe oder Systemaufruf aufgezeichnet, Operationen zusammengeführt werden, die Cross-Context-Kommunikationspunkte bilden würden, und anschließend nur diese Kombinationen untersucht werden. VM-Snapshots stabilisieren globalen Zustand und Adressen; ohne Snapshots können Metadaten zum Allokationsort Objekte über mehrere Läufe hinweg abstrahieren. Dies ist eine vorgeschlagene Erweiterung und keine Funktion der aktuellen MAccConc-Userspace-Tools.<sup>[[17]](#references)</sup>

## Harness-Introspektion: Flache Fuzzer frühzeitig finden

Wenn eine Kampagne ins Stocken gerät, liegt das Problem oft nicht am Mutator, sondern am **Harness**. Nutze die **Introspektion von Erreichbarkeit und Coverage**, um Funktionen zu finden, die statisch von deinem Fuzz-Target aus erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Solche Funktionen weisen meist auf eines von drei Problemen hin.<sup>[[12]](#references)</sup>

- Der Harness erreicht das Target zu spät oder zu früh.
- Dem Seed-Corpus fehlt eine ganze Feature-Familie.
- Das Target benötigt tatsächlich einen **zweiten Harness** statt eines überladenen „Alles-erledigen“-Harness.

Wenn du Workflows im Stil von OSS-Fuzz / ClusterFuzz verwendest, kann Fuzz Introspector die statische Erreichbarkeit mit der Laufzeit-Coverage vergleichen und Berichte aus einem zeitlich begrenzten Lauf oder einem öffentlichen Corpus erstellen.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Nutze den Bericht, um zu entscheiden, ob du einen neuen Harness für einen bislang nicht getesteten Parser-Pfad hinzufügen, die Corpus-Abdeckung für ein bestimmtes Feature erweitern oder einen monolithischen Harness in kleinere Einstiegspunkte aufteilen solltest.

## Graphbasierte Auswahl von Fuzzing-Zielen und Mutation-Triage

Wenn du bereits **Static-Analysis-Findings**, **Mutation-Testing-Survivors** und **Coverage-Reports** hast, solltest du sie nicht als unabhängige Listen triagieren. Erstelle zuerst einen **Call Graph**, annotiere die Knoten mit **zyklomatischer Komplexität**, **Erreichbarkeit über Entry Points und nicht vertrauenswürdige Eingaben** sowie externen Findings und untersuche dann den Graphen.<sup>[[5]](#references)[[6]](#references)</sup>

- Welche Funktionen mit hoher Komplexität sind über nicht vertrauenswürdige Eingaben erreichbar?
- Welche Mutation Survivors liegen auf Pfaden von Parsern/Handlern zu sicherheitskritischem Code?
- Welche Funktionen sind architektonische Engpässe mit ungewöhnlich großem **Blast Radius**?

So findest du in der Regel bessere Fuzzing-Ziele als allein anhand der „niedrigsten Coverage“. Ein Parser/Decoder mit **hoher Komplexität** und bestätigter **externer Erreichbarkeit** ist ein vielversprechenderer Harness-Kandidat als ein isolierter interner Helper mit schwacher Coverage, aber ohne vom Angreifer kontrollierbaren Pfad.

### Praktischer Triage-Workflow

1. Erstelle einen **Code-Graphen** aus der Codebasis und ermittle Komplexitäts- und Branch-Metriken für jede Funktion.
2. Liste **Entry Points** auf, die vom Angreifer kontrollierte Eingaben annehmen: Request-Handler, Decoder, Importer, Protokoll-Parser, CLI-/Datei-Reader.
3. Führe **Pfadabfragen** von diesen Entry Points zu Kandidatenfunktionen aus, um erreichbare Angriffsfläche von totem bzw. nur internem Code zu unterscheiden.
4. Priorisiere Knoten, die Folgendes kombinieren:
   - hohe **zyklomatische Komplexität**
   - bestätigte **Erreichbarkeit über nicht vertrauenswürdige Eingaben**
   - großer **Blast Radius** oder viele abhängige Funktionen
   - bestätigende Hinweise wie **SARIF**-Findings, Audit-Notizen oder Mutation Survivors
5. Schreibe zuerst fokussierte Harnesses für die am höchsten bewerteten Knoten, insbesondere für **Parser/Codecs** wie Hex-/Base64-/IP-/Message-Decoder.

### Mutation Survivors: äquivalent oder relevant

Mutation Testing erzeugt oft eine unübersichtliche Liste von Survivors. Bevor du jeden Survivor als Sicherheitslücke behandelst, untersuche anhand des Graphen Folgendes:

- Ist die mutierte Funktion über einen vom Angreifer kontrollierten Entry Point erreichbar?
- Sind alle Aufrufpfade durch stärkere Invarianten eingeschränkt als die mutierte Prüfung?
- Liegt der Knoten in totem Code, rein formatierungsbezogener Logik oder in einem arithmetischen/parserbezogenen Pfad mit hoher Auswirkung?

Weiterhin unerreichbare oder strukturell eingeschränkte Survivors sind oft **äquivalente Mutanten**. Survivors, die **erreichbar** bleiben und **Grenzfälle**, **Overflow-/Carry-Pfade** oder **sicherheitskritische Arithmetik/Parsing** betreffen, sollten zu Folgendem weiterverfolgt werden:

- neuen Fuzz-Harnesses
- direkten Property-/Invarianten-Tests
- gezielten Edge-Case-Vektoren

### Externe Findings auf den Graphen übertragen

Wenn deine SAST-Pipeline **SARIF** exportiert, übertrage Findings anhand von **Datei + Zeilenbereich** auf Graphknoten und nutze den Graphen, um die Auswirkungen zu ermitteln.<sup>[[6]](#references)</sup>

- Ermittle den **Blast Radius** der markierten Funktion.
- Prüfe, ob das Finding auf einem Pfad von einem Entry Point liegt.
- Gruppiere nahe beieinanderliegende Findings, die auf denselben Engpass hinauslaufen.

Das ist hilfreich, wenn du entscheiden musst, ob du Zeit in das Fuzzing einer bestimmten Funktion investieren solltest: Ein Knoten, der **erreichbar**, **komplex** und bereits von **SAST-Findings** betroffen ist, ist oft ein besseres Ziel als ein lediglich komplexer Knoten ohne Angreiferpfad.

Beispiel-Workflow mit Trailmark.<sup>[[6]](#references)</sup>

```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```

Die entscheidende Methodik ist die Schnittmenge: **Komplexität x Angriffsfläche x Auswirkung**. Nutze das Diagramm, um Fuzzing-Ziele mit dem höchsten erwarteten Sicherheitsnutzen auszuwählen. Nutze anschließend die überlebenden Mutationen, um zu entscheiden, welche Grenzen und Invarianten dein Harness besonders beanspruchen muss.<sup>[[5]](#references)</sup>

## Differentiales Fuzzing kryptografischer Schlüsselcodierungen

Beginne mit gültigen serialisierten Schlüsseln oder standardisierten Testvektoren. Verändere codierte Felder, ohne die Länge und Struktur zu beschädigen, die nötig sind, um Import- und Operationspfade zu erreichen. Übergib dann dieselben Bytes an unabhängige Implementierungen. Vergleiche Annahme und Fehler. Randomisierte Signaturen und Chiffretexte benötigen Korrektheitsorakel statt eines Byte-für-Byte-Vergleichs: Verifiziere Signaturen oder vergleiche die gemeinsam genutzten Geheimnisse aus einem Kapselungs-/Entkapselungs-Roundtrip. Testvektoren belegen die Konformität für bekannte Fälle; differentielle Mutationen untersuchen darüber hinaus fehlerhafte Codierungen.<sup>[[23]](#references)[[26]](#references)</sup>

Verwende für diese Schlüsselformate formatspezifische Orakel:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Erweiterte ML-DSA-Signaturschlüssel:** Verändere gepackte `s1`- oder `s2`-Koeffizienten so, dass sie außerhalb von `[-η, η]` liegen, während der Schlüssel weiterhin geparst werden kann. Prüfe, ob der Import oder das Signieren den Schlüssel zurückweist und ob eine resultierende Signatur verifiziert werden kann. Unterschiede bei der Annahme allein stellen keine Verstöße gegen Standards dar, da FIPS 204 keine zusätzlichen Prüfungen privater Schlüssel vorschreibt. Siehe den [Mechanismus für bedingte Leaks](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM-Schlüsselpaare:** Unterscheide die erforderlichen Prüfungen des Kapselungsschlüssels und der Entkapselungseingabe von der optionalen paarweisen Konsistenzprüfung (PCT) eines importierten Schlüsselpaars. Kapsle mit dem öffentlichen Schlüssel, entkapsle mit dem privaten Schlüssel und vergleiche die gemeinsam genutzten Geheimnisse. Eine Abweichung kann die verschlüsselte Kommunikation beeinträchtigen, selbst wenn die einzelnen Schlüssel die Eingabeprüfungen bestehen. Prüfe, ob die API die Eingaben während der Operation oder über einen separaten Aufruf validiert. libcrux stellt `validate_public_key(pk)` und `validate_private_key(sk, ct)` bereit; diese ersetzen keine PCT.
- **Rohe XMSS-/XMSSMT-Schlüssel:** Teste Roundtrips serialisierter **Signatur- und Verifikationsschlüssel** über verschiedene Parametersätze hinweg, nicht nur Operationen mit Schlüsseln im Arbeitsspeicher. XMSS und XMSSMT verwenden separate Vier-Byte-OID-Namespaces. Ein OID-basierter Parser, der zuerst XMSS ausprobiert, kann daher einen kollidierenden XMSSMT-Schlüssel falsch zuordnen und den Import zurückweisen. Der beschriebene RustCrypto-Parser veranschaulicht einen Interoperabilitäts-/Verfügbarkeitsfehler, keine Signaturfälschung.

## Go-Fuzzing mit gosentry: leistungsstärkere Engine, typisierte Eingaben und differentielle Prüfungen

Wenn ein Go-Ziel bereits über ein natives `testing.F`-Harness verfügt, ist es ein praktikabler Upgrade-Pfad, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen. Dabei handelt es sich um eine geforkte Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend durch **LibAFL** ersetzt.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

This ist nützlich, wenn der native Go-Fuzzer bei **schwierigen Vergleichen**, **typisierten Eingaben** oder **parserlastigen Formaten** ins Stocken gerät. Die Methodik bleibt gleich:

- Verwende weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback.
- Verwende denselben Harness, führe ihn aber mit gosentrys `go`-Binary statt mit der Standard-Toolchain aus.
- Behandle die resultierende Kampagne wie einen normalen coverage-guided Lauf, jedoch mit LibAFL-Scheduling/Mutation und besseren umgebenden Detektoren.

### Stille Fehler in Fuzzing-Befunde umwandeln

Ein wiederkehrendes Problem bei Go-Assessments ist, dass gefährliches Verhalten standardmäßig oft **keinen** Absturz verursacht. Mit gosentry kannst du mehrere Arten von „schlechten, aber stillen“ Zuständen zu Befunden machen.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, damit ausgewählte Logging-/Fehlerpfade wie Abstürze behandelt werden (nützlich für `log.Fatal`-artige Codepfade, die sonst nur loggen und fortfahren).
- `--catch-races=true`, um neu entdeckte Queue-Einträge mit dem Go-Race-Detector erneut auszuführen.
- `--catch-leaks=true`, um neue Queue-Einträge mit `goleak` erneut auszuführen und bei Goroutine-Leaks abzubrechen.
- LibAFL-Hang-Handling, damit **Endlosschleifen / sehr langsame Eingaben** als Fuzzing-Befunde erfasst werden, statt als Timeouts zu verschwinden.
- Standardmäßig integrierte Prüfungen auf arithmetischen Overflow sowie optionale Truncation-Prüfungen durch go-panikint-ähnliche Instrumentierung.

Das ist besonders wertvoll für Ziele, bei denen die Sicherheitsauswirkung eher ein **panicloser Parserfehler**, ein **Concurrency-Bug** oder ein **DoS-bedingter Hang** als eine Speicherbeschädigung ist.

### Struct-aware Fuzzing für typisierte Go-APIs

Native Go-Fuzzing erwartet hauptsächlich skalare Werte wie `[]byte`, `string` und Zahlen. Wenn der getestete Code typisierte Objekte verarbeitet, kann gosentry **zusammengesetzte Werte** direkt fuzzing-basiert testen (Structs, Slices, Arrays, Pointer) und dabei weiterhin die zugrunde liegenden Bytes mutieren.<sup>[[7]](#references)[[8]](#references)</sup>

```go
type Input struct {
    Data []byte
    S    string
    N    int
}

func FuzzStructInput(f *testing.F) {
    f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
    f.Fuzz(func(t *testing.T, in Input) {
        Process(in)
    })
}
```

Verwende dies, wenn ein gefälschtes Wire-Format nur fürs Fuzzing Logikfehler hinter Parsing-Code auf Harness-Ebene verbergen würde. Bei Differential- oder grammatikbasierten Kampagnen sollte die Harness-Eingabe ein einzelnes `[]byte` oder `string` sein, und das Parsing sollte stattdessen innerhalb des Callbacks erfolgen.

### Grammatikbasiertes Fuzzing für Parser und Protokolleingaben

Für Parser, Formate und Eingabesprachen kann gosentry **Nautilus grammar fuzzing** auf LibAFL ausführen. Die Grammatik ist ein JSON-Array mit Produktionsregeln, und der Harness sollte normalerweise ein einzelnes Argument vom Typ `[]byte` oder `string` annehmen.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodikhinweise:

- Verwende den Grammar-Modus, wenn byteweise Mutationen meist schon an frühen Syntaxprüfungen scheitern.
- Beschränke die Grammatik auf die **sicherheitsrelevante Teilmenge** der Sprache/des Protokolls, statt die vollständige Spezifikation abzubilden.
- Verwende große Grenzwerte in Terminals/Nichtterminalen, um Integer-, Längen- und Zustandsmaschinen-Grenzen zu testen.
- Im Grammar-Modus bleiben die Eingaben grammatikalisch gültig, aber das Ziel erhält weiterhin **Bytes/Strings**. Parsing und semantische Prüfungen finden daher weiterhin im gehärteten Code statt.

### Differential Fuzzing: Implementierungen statt nur Abstürze vergleichen

Ein bewährtes Muster für Go-Ökosysteme ist **grammatikbasiertes Differential Fuzzing**: Gültige strukturierte Eingaben erzeugen und sie an zwei Parser, Clients oder Zustandsmaschinen übergeben.<sup>[[7]](#references)[[8]](#references)</sup>

```go
f.Fuzz(func(t *testing.T, data []byte) {
    gotA, errA := ParseA(data)
    gotB, errB := ParseB(data)
    if (errA == nil) != (errB == nil) {
        t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
    }
    _ = gotA
    _ = gotB
})
```

Behandle Folgendes als Findings:

- eine Implementierung gerät in einen Panic, während die andere die Eingabe ordnungsgemäß zurückweist
- Abweichungen bei akzeptierten/zurückgewiesenen Eingaben
- unterschiedliche Parse-Bäume oder decodierte Objekte
- abweichende Zustandsübergänge, Nonces, Salden oder State Roots

So lassen sich **Consensus-Mismatches**, **Parser-Ambiguität** und **Abweichungen zwischen Spezifikation und Implementierung** auf praktische Weise finden, die beim reinen Crash-Fuzzing oft unentdeckt bleiben.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Das Kampagnen-Korpus für die Coverage-Berichterstattung wiederverwenden

Spiele nach einer Kampagne das gespeicherte Queue-Korpus erneut ab, um einen Go-Coverage-Bericht zu erstellen, ohne ein separates Korpus manuell exportieren zu müssen.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Führe den Befehl im selben Paket und mit demselben `-fuzz`-Ziel aus, damit gosentry den richtigen gecachten Kampagnenstatus auflöst.

## References

- [1] [Mutational Grammar-Fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++-Fuzzing im Detail](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet fünf Jahre später: Coverage-gesteuertes Protokoll-Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verwandelt Code in Graphen](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-Fuzzing fehlte die Hälfte des Toolkits. Wir haben die Toolchain geforkt, um das zu beheben.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ein schneller Greybox-Fuzzer für zustandsbehaftete Netzwerkprotokolle mithilfe von Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Keine Grammatik, kein Problem: Fuzzing des Linux-Kernels ohne Systemaufrufbeschreibungen](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Effizientes Fuzzing mit adaptiven und veränderlichen Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++-LLVM-Instrumentierung: Pfad- und Aufrufer-Coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prädiktives kontextsensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog – Binder-Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL-Android-Binder-Fuzzer – Dokumentation zu Build und Regression-Seeds](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Untersuchung von Race Conditions im Linux-Kernel mit kontrollierten Speicherzugriffs-Interleavings](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: Code-Coverage für Fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Erweiterte Dateinamensyntax von CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec-Advisory: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing der erweiterten Dateinamensyntax von CFITSIO: 16 Speicher-Sicherheitslücken und Codex-unterstützte Triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Differenzielles Fuzzing für Kryptografie](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Standard für ein auf Modullattice basierendes Schlüssel-Kapselungsverfahren](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT-OID-Parsing-Fehler – RustCrypto-Issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stand der Implementierungen post-quantenkryptografischer Verfahren](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Wie Snapshots uns zu CVE-2026-9539 führten](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
