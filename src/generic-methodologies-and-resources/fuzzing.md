# Fuzzing-Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantik

Beim **mutational grammar fuzzing** werden Eingaben verändert, wobei sie **grammatikkonform** bleiben. Im Coverage-guided-Modus werden nur Samples, die eine **neue Coverage** auslösen, als Corpus-Seeds gespeichert. Bei **Sprachzielen** (Parsern, Interpretern, Engines) können dadurch Bugs übersehen werden, die **semantische Datenflussketten** erfordern, bei denen die Ausgabe eines Konstrukts zur Eingabe eines anderen wird.<sup>[[1]](#references)</sup>

**Fehlermodus:** Der Fuzzer findet Seeds, die einzeln `document()` und `generate-id()` (oder ähnliche Primitive) ausführen, aber **den verketteten Datenfluss nicht erhalten**. Dadurch wird das Sample, das dem Bug „näher kommt“, verworfen, weil es keine zusätzliche Coverage erzeugt. Bei **3 oder mehr abhängigen Schritten** wird zufällige Rekombination aufwendig, und die Coverage-Rückmeldung leitet die Suche nicht.<sup>[[1]](#references)</sup>

**Auswirkung:** Bei Grammatiken mit vielen Abhängigkeiten sollten Sie **mutationale und generative Phasen kombinieren** oder die Generierung auf Muster mit **Funktionsverkettungen** ausrichten (nicht nur auf Coverage).<sup>[[1]](#references)</sup>

## Fallstricke bei der Corpus-Diversität

Coverage-gesteuerte Mutation ist **gierig**: Ein Sample mit neuer Coverage wird sofort gespeichert und enthält oft große, unveränderte Bereiche. Mit der Zeit entstehen im Corpus **Beinahe-Duplikate** mit geringer struktureller Vielfalt. Aggressive Minimierung kann nützlichen Kontext entfernen. Ein praktikabler Kompromiss ist daher eine **grammatikbewusste Minimierung**, die **bei einer Mindestanzahl an Tokens stoppt** (Rauschen reduzieren und zugleich genügend umgebende Struktur erhalten, damit sich das Sample weiterhin gut für Mutationen eignet).<sup>[[1]](#references)</sup>

Eine praktische Corpus-Regel für mutational fuzzing lautet: **Bevorzugen Sie eine kleine Menge strukturell unterschiedlicher Seeds, die die Coverage maximieren**, statt eines großen Haufens von Beinahe-Duplikaten. In der Praxis bedeutet das meist Folgendes.<sup>[[1]](#references)[[3]](#references)</sup>

- Beginnen Sie mit **realen Samples** (öffentlichen Corpora, Crawling, erfasstem Datenverkehr und Dateisammlungen aus dem Ökosystem des Ziels).
- Reduzieren Sie sie mit **Coverage-basierter Corpus-Minimierung**, statt jedes gültige Sample zu behalten.
- Halten Sie Seeds **klein genug**, damit Mutationen auf sinnvolle Felder treffen, statt die meiste Zeit mit irrelevanten Bytes zu verbringen.
- Führen Sie die Corpus-Minimierung nach größeren Änderungen am Harness oder an der Instrumentierung erneut aus, da sich der „beste“ Corpus ändert, wenn sich die Erreichbarkeit ändert.

## Vergleichsorientierte Mutation für Magic Values

Ein häufiger Grund dafür, dass Fuzzer stagnieren, sind nicht Syntaxprobleme, sondern **strikte Vergleiche**: Magic Bytes, Längenprüfungen, Enum-Strings, Checksummen oder Parser-Dispatch-Werte, die durch `memcmp`, Switch-Tabellen oder verkettete Vergleiche geschützt sind. Reine Zufallsmutation verschwendet Zyklen damit, diese Werte Byte für Byte zu erraten.

Verwenden Sie für solche Ziele **Comparison Tracing** (zum Beispiel AFL++-Workflows mit `CMPLOG` oder im Redqueen-Stil), damit der Fuzzer Operanden fehlgeschlagener Vergleiche beobachten und Mutationen gezielt auf passende Werte ausrichten kann.<sup>[[3]](#references)</sup>

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

- Das ist besonders nützlich, wenn das Ziel tiefe Logik hinter **Dateisignaturen**, **Protokollverben**, **Typ-Tags** oder **versionsabhängigen Feature-Bits** verbirgt.
- Kombiniere es mit **Wörterbüchern**, die aus echten Samples, Protokollspezifikationen oder Debug-Logs extrahiert wurden. Ein kleines Wörterbuch mit Grammatik-Tokens, Chunk-Namen, Verben und Trennzeichen ist oft wertvoller als eine riesige generische Wortliste.
- Wenn das Ziel viele Prüfungen nacheinander durchführt, löse zuerst die frühesten „Magic“-Vergleiche und minimiere anschließend den daraus entstandenen Corpus erneut, damit spätere Phasen mit bereits gültigen Präfixen beginnen.

## Fuzzing von Datei-APIs, die eine Dateinamensprache verbergen

Ein Parameter namens `filename`, `path` oder `URL` kann ein Interpreter-Einstiegspunkt statt einer direkten Dateisuche sein. Beispielsweise wertet CFITSIO Extended Filename Syntax (EFS) Selektoren in eckigen Klammern, Zeilen-/Pixelausdrücke, berechnete Spalten, Histogramme und Transformationen aus, bevor das geöffnete Objekt zurückgegeben wird; einige Formen erstellen außerdem temporäre Kopien. Ordne beim Mapping der Angriffsfläche jede Open-/Import-API als **literal-path** oder **interpreted-path** ein und fuzze anschließend den Produktionseinstiegspunkt, den Anwendungen tatsächlich aufrufen.<sup>[[20]](#references)[[22]](#references)</sup>

Zu den daraus entstehenden SSRF-, Dateikopier- und Protokollhandler-Primitiven sowie sichereren literal-path-APIs siehe [Dateinamen-Mini-Sprachen als SSRF-/Datei-Primitiven](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Das zugrunde liegende Objekt vom gefuzzten Programm getrennt halten

Wenn die Grammatik in einem Dateinamensuffix steckt, verfehlt die Mutation nur der referenzierten Dateibytes den Parser. Ein kleiner Harness kann stattdessen einen Testfall als String einlesen und an die interpretierte Open-API übergeben; die CFITSIO-Kampagne erreichte die meisten EFS-Parser und -Evaluatoren durch den Aufruf von `fits_open_file()` im Read-only-Modus. Halte gültige zugrunde liegende Dateien separat verfügbar, damit sich die Mutationen auf die Selektor-/Ausdruckssprache konzentrieren können, statt ständig den Basispfad zu beschädigen.<sup>[[22]](#references)</sup>

Verwende Seeds, die jeweils eine andere Grammatikfamilie erreichen, und erstelle anschließend ein kompaktes Wörterbuch aus Spezifikation und Lexer-/Parser-Quellcode. Wenn die Coverage stagniert und die Eingaben wiederholt im selben Syntaxfehlerpfad scheitern, bewahre gültige Präfixe und ergänze Trennzeichen, Operatoren, Schlüsselwörter, Funktionsnamen und repräsentative Feldnamen, statt lediglich die Zeit für zufällige Mutationen zu erhöhen.<sup>[[22]](#references)</sup>

Führe den Harness mit dem Grammatikwörterbuch aus, zum Beispiel:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Nebenwirkungen des „read-only“-Harness eindämmen

Ein read-only-Bibliotheksflag garantiert keinen testcase ohne Nebenwirkungen: Die Dateinamensprache kann die Eingabe umschreiben, Ausgabedateien erstellen oder temporäre Objekte materialisieren. Die CFITSIO-Kampagne zerstörte zunächst Seed-Dateien und hinterließ unerwartete Dateien im Dateisystem, weshalb Bereinigung und Isolation erforderlich waren.<sup>[[22]](#references)</sup>

- Gib jedem Worker ein entbehrliches Arbeitsverzeichnis und ein privates temporäres Verzeichnis.
- Stelle Kopien kanonischer Backing-Dateien bereit; lass das Zielprogramm niemals die einzige Korpus-Kopie verändern.
- Deaktiviere den Netzwerkzugriff, sofern Remote-Backends nicht das eigentliche Ziel sind, und beschränke beschreibbare Pfade mit einem Container, einem Mount-Namespace oder einer gleichwertigen Sandbox.
- Setze das Verzeichnis nach jeder Ausführung oder jedem Worker-Batch zurück und behandle unerwartete Änderungen am Dateisystem als zusätzliche Findings.

### Crash-zu-Patch-zu-Fuzz-Schleife

Gruppiere Crashes vor der Reparatur, damit aus Tausenden von Artefakten nicht Tausende von Patch-Aufgaben werden. Bei der CFITSIO-Bewertung reduzierte AFLTriage die anfängliche Crash-Menge auf wenige Ursachen; der daraus entstandene Advisory zeigt verschiedene Fehler, darunter fehlerhafte Prüfungen der Zielgröße, veraltete Pointer nach `realloc()`, arithmetische Fehler und unsichere Parser-Bereinigungspfade.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimiere eine repräsentative Eingabe für jedes Cluster und reproduziere sie mit AddressSanitizer.
2. Halte den genauen fehlerhaften Zugriff, die Quellcodeposition, den Allokations-/Freigabeverlauf und den Parser-Zustand fest, durch den die Invariante verletzt wurde.
3. Wende einen eng umrissenen Patch-Kandidaten an und baue mit derselben Coverage- und Sanitizer-Instrumentierung neu.
4. Spiele den ursprünglichen Reproducer **und jede Eingabe in seinem Cluster** erneut ab; aktiviere außerdem leak detection, da eine Speicher-Sicherheitskorrektur die Ownership auf einem Fehlerpfad beeinträchtigen kann.
5. Führe Funktionstests mit echten Dateien aus und fahre dann mit der angesammelten Queue fort (oder importiere diese Queue erneut, falls die Engine nach einer Änderung der Binärdatei ein neues Ausgabeverzeichnis erfordert).
6. Wiederhole den Vorgang: Wenn der erste oberflächliche Crash behoben ist, können vorhandene Seeds oft einen tieferen Parser-Zustand erreichen.

Ein LLM kann Schritt 2 beschleunigen und einen Entwurf für Schritt 3 erstellen, wenn es die abstürzende Eingabe, den Sanitizer-Bericht, den Harness und den relevanten Quellcode erhält; sein Patch bleibt jedoch nicht vertrauenswürdig. Ob die Reparatur akzeptiert wird, entscheiden der erneute Sanitizer-Lauf und die Regressionstests – nicht die Erklärung des Modells.<sup>[[22]](#references)</sup>

## Aussagekräftigeres Feedback, wenn Edge Coverage verschiedene Pfade zusammenfasst

Normale Edge Coverage kann nicht zwischen zwei Ausführungen unterscheiden, die denselben Helper über verschiedene Aufrufer durchlaufen oder unterschiedliche Kombinationen von Branches innerhalb einer Funktion nehmen. Das ist bei gemeinsam genutzten Decodern, Protokoll-Dispatchern und Interpreter-Helpern wichtig, bei denen der **Weg** zu einer Edge den aktiven Zustand bestimmt. Jeden Aufrufkontext naiv nachzuverfolgen ist ebenfalls riskant: Coverage-Map und Queue können explodieren. Die Forschung zu kontextsensitivem Fuzzing empfiehlt daher, nur aussichtsreiche Kontexte genauer zu untersuchen, anstatt den gesamten Call-Graph als kontextsensitiv zu behandeln.<sup>[[14]](#references)</sup>

Aktuelle AFL++-Builds bieten zusätzlich zur normalen Edge Coverage **Ball-Larus-Pfad-Coverage pro Funktion**. Dabei wird jedem azyklischen Pfad durch eine Funktion ein Feature zugewiesen; Loop-Back-Edges werden entfernt, sodass dieses Feedback Kombinationen von Branches unterscheidet, **nicht jedoch die Anzahl der Schleifendurchläufe**. Beginne mit dem entspannten Level `1` und beschränke strengere Modi auf verdächtigen Parser-/State-Machine-Code, da die Anzahl der Pfade exponentiell wachsen kann.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Für einen Helper, der von vielen sicherheitsrelevanten Stellen aufgerufen wird, kann der LTO-Modus jeden Funktionspfad mit seiner unmittelbaren Aufrufstelle kombinieren:<sup>[[13]](#references)</sup>

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

**Kampagnenhinweis:** Setze umfangreicheres Feedback zurückhaltend ein und überwache dessen Kosten für Coverage-Map und Queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Führe parallel eine gewöhnliche Edge-Coverage-Instanz aus; umfangreicheres Feedback ist nur dann sinnvoll, wenn die zusätzlichen Kosten für Queue und Map die Anzahl der Ausführungen pro Sekunde nicht beeinträchtigen.
- Verwende `AFL_LLVM_ALLOWLIST`, um die Instrumentierung von Pfaden und Aufrufern einzuschränken, wenn große template-lastige Bibliotheken oder generischer Utility-Code die Map dominieren.
- Funktionen mit übermäßig vielen azyklischen Pfaden können von AFL++ übersprungen werden; Warnungen während der Kompilierung sind ein Hinweis darauf, dass das Target eine Allowlist oder eine weniger strenge Stufe benötigt.
- Caller- und Path-Coverage unterstützen nur eine Aufruftiefe. Kombiniere sie nicht mit tieferen Kontext-Stacks.
- Pfad-IDs können sich zwischen LLVM-Hauptversionen ändern. Verwende für eine Kampagne eine festgelegte Toolchain und synchronisiere PATH-basierte Corpora nicht so, als wären ihre Feature-IDs über Builds hinweg stabil.
- Dieses Feedback ergänzt `CMPLOG`: Comparison Tracing ermittelt, **welcher Wert eine Guard-Bedingung passiert**, während Path-/Caller-Feedback festhält, **welche Route und Zweigkombination sie erreicht hat**.

## Stateful Fuzzing: Sequenzen sind Seeds

Bei **Protokollen**, **authentifizierten Workflows** und **mehrstufigen Parsern** ist die interessante Einheit oft nicht ein einzelner Blob, sondern eine **Nachrichtensequenz**. Das gesamte Transkript in eine Datei zu schreiben und blind zu mutieren, ist meist ineffizient, weil der Fuzzer jeden Schritt gleichermaßen mutiert, selbst wenn nur die spätere Nachricht den fragilen Zustand erreicht.<sup>[[4]](#references)</sup>

Effektiver ist es, die **Sequenz selbst als Seed** zu behandeln und **beobachtbaren Zustand** (Antwortcodes, Protokollzustände, Parserphasen, zurückgegebene Objekttypen) als zusätzliches Feedback zu verwenden.<sup>[[4]](#references)</sup>

- Halte **gültige Präfixnachrichten** stabil und konzentriere Mutationen auf die Nachricht, die den **Übergang auslöst**.
- Speichere Kennungen und vom Server erzeugte Werte aus früheren Antworten zwischen, wenn der nächste Schritt davon abhängt.
- Bevorzuge Mutationen und Splicing pro Nachricht, statt das gesamte serialisierte Transkript als undurchsichtigen Blob zu mutieren.
- Wenn das Protokoll aussagekräftige Antwortcodes bereitstellt, verwende sie als **kostengünstigen Zustandsorakel**, um Sequenzen zu priorisieren, die weiter vorankommen.

Aus demselben Grund werden authentifizierte Bugs, verborgene Übergänge oder Parser-Bugs, die „erst nach dem Handshake“ auftreten, oft beim gewöhnlichen dateibasierten Fuzzing übersehen: Der Fuzzer muss **Reihenfolge, Zustand und Abhängigkeiten** bewahren, nicht nur die Struktur.<sup>[[4]](#references)</sup>

### Android Binder: Fuzzing von Treibern mit mehreren Clients

Eine hohe Edge-Coverage kann IPC-Treiber-Bugs dennoch übersehen, denn Coverage beschreibt weder **Objektbesitz, Referenzzähler, ausstehende Nachrichten und Bereinigungsreihenfolge noch Thread-Interleavings**. Die Seite [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) behandelt das Treiber-Objektmodell; dieses Beispiel konzentriert sich auf das Fuzzer-Harness. Android Binder ist ein nützliches Modell: Es reicht nicht aus, sowohl den Allokations- als auch den Freigabepfad zu erreichen, wenn der Fuzzer nicht mehrere Prozesse in der erforderlichen Reihenfolge auf dasselbe Kernelobjekt zugreifen lassen kann.<sup>[[15]](#references)</sup>

#### Das Protokoll modellieren, nicht isolierte `ioctl`-Puffer

Stelle einen Testfall als geordnete Grammatik aus **Client-Identität + Operation + strukturierten Argumenten** dar. Der Binder-LKL-Fuzzer verwendet protobuf und `libprotobuf-mutator`, mit einem persistenten Context-Manager-Client und zwei gewöhnlichen Clients. Ein semantisches Harness erhält dann Zusammenhänge, die blinde Byte-Mutationen zerstören würden.<sup>[[15]](#references)</sup>

- Speichere Werte früherer Operationen zwischen. Zum Beispiel muss `BC_FREE_BUFFER` einen Transaktionspufferzeiger wiederverwenden, der von einem vorherigen `ioctl` zurückgegeben wurde.
- Erzeuge gültige Standardantworten, damit synchrone Transaktionen abgeschlossen werden können und spätere Operationen erreichbar bleiben.
- Verwirf unmögliche Übergänge, etwa Transaktionen an sich selbst oder mehrere ausstehende Transaktionen an dasselbe Ziel.
- Halte den Singleton-Bootstrap-Zustand außerhalb des Zurücksetzens pro Eingabe. Binder erlaubt pro Boot nur eine `BINDER_SET_CONTEXT_MGR`-Registrierung; würde dieser Client wiederholt zerstört und neu erstellt, wären spätere Eingaben ungültig.

Eine nützliche Vorlage für Lifetime-Races besteht darin, einen Client ein Objekt übertragen zu lassen, die Bereinigung durch einen Thread oder Prozess zu starten und den empfangenden Client gleichzeitig den Transaktionspuffer freigeben zu lassen. Im CVE-2020-0423-Beispiel konnte eine Übertragung von `BINDER_TYPE_WEAK_BINDER`, gefolgt von einem `BINDER_THREAD_EXIT`, das mit `BC_FREE_BUFFER` konkurrierte, ein eingebettetes `binder_work` freigeben, während der Bereinigungspfad des beendenden Threads es noch verwendete.<sup>[[15]](#references)</sup>

#### Kontrollierte Interleavings in einem Userspace-Kernel wieder einführen

Die [Linux Kernel Library (LKL)](https://github.com/lkl/linux) bindet den echten Kernelcode in ein Userspace-Harness ein und stellt dessen Syscall-Schnittstelle über `lkl_syscall` bereit. Dadurch lassen sich protobuf-Zustand, Coverage und KASAN einfach in einem Prozess koordinieren. LKL führt einen Syscall normalerweise jedoch aus, ohne dass ein anderer Kernel-Thread ihn unterbricht. Füge für Race-Kampagnen `schedule()`-Punkte an ausgewählten Grenzen von Lock/Unlock und Objektlebensdauer ein und lasse das Harness bei jedem Yield zufällig den nächsten Client auswählen. Halte diese Punkte gezielt, denn jeder einzelne vergrößert den Suchraum für das Scheduling. Der von den Forschern beschriebene randomisierte Scheduler ist **nicht** Teil des Upstream-Binder-Fuzzers.<sup>[[15]](#references)</sup>

#### Serialisierte Regression-Seeds erstellen und erneut ausführen

Das Upstream-Harness pinnt eine kompatible Version von `libprotobuf-mutator`, aktiviert die LKL-Fuzzing-Instrumentierung und KASAN mit `LKL_FUZZING=1` und aktiviert `CONFIG_MMU` für Binder mit `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nach dem Auschecken einer absichtlich verwundbaren Revision oder dem Anwenden der upstream dokumentierten Rollback-Patches kann ein serialisierter Seed den gesamten Zustandsübergang über mehrere Clients reproduzieren, ohne ihn in einem Ad-hoc-C-Proof-of-Concept rekonstruieren zu müssen:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandle den daraus resultierenden KASAN-use-after-free als Bestätigung dafür, dass der Seed den anfälligen Lifetime-Pfad erreicht hat. Er belegt **nicht** die später erforderlichen Primitives für Kernel-Codeausführung oder Privilegienausweitung.<sup>[[16]](#references)</sup>

## Diversitätstrick auf einer einzelnen Maschine (Jackalope-Stil)

Eine praktische Möglichkeit, **generative Neuheit** mit **wiederverwendeter Coverage** zu kombinieren, besteht darin, kurzlebige Worker gegen einen persistenten Server neu zu starten. Jeder Worker beginnt mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden mit dem kombinierten Corpus, synchronisiert erneut und wird dann beendet. So entstehen **in jeder Generation neue Strukturen**, während zugleich die angesammelte Coverage genutzt wird.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` erzwingt bei jeder Generierung ein **frisches Corpus**.
- `-server_update_interval T` simuliert eine **verzögerte Synchronisierung** (zuerst neue Eingaben, später Wiederverwendung).
- Im Modus „grammar fuzzing“ wird die **initiale Serversynchronisierung standardmäßig übersprungen** (kein Bedarf für `-skip_initial_server_sync`).
- Der optimale Wert für `T` hängt vom **Ziel ab**; am besten funktioniert es meist, umzuschalten, nachdem der Worker den Großteil der „einfachen“ Coverage gefunden hat.

## Snapshot Fuzzing für schwer instrumentierbare Ziele

Wenn der Code, den du testen möchtest, erst **nach einem hohen Einrichtungsaufwand erreichbar ist** (Starten einer VM, Abschließen eines Logins, Empfangen eines Pakets, Parsen eines Containers, Initialisieren eines Dienstes), ist **Snapshot Fuzzing** eine nützliche Alternative: Erfasse den Zustand des bereiten Prozesses oder der VM, speise jeden Testfall in den Eingabepfad des Ziels ein, führe ihn bis zu einem Crash/Timeout aus und stelle den Snapshot wieder her. So muss die Initialisierung oder das Protokollpräfix nicht wiederholt werden. Das ist nützlich für **Netzwerkdienste**, **Firmware**, **Angriffsflächen nach der Authentifizierung** und **rein binäre Ziele**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Führe das Ziel aus, bis der interessante Zustand erreicht ist.
2. Erstelle an diesem Punkt einen Snapshot von **Speicher + Registern**.
3. Schreibe bei jedem Testfall die mutierte Eingabe direkt in den relevanten Gast-/Prozesspuffer.
4. Führe die Ausführung bis zu einem Crash/Timeout/Reset fort.
5. Stelle den Snapshot wieder her; bei VM-Zielen kannst du, sofern unterstützt, nur die **dirty pages** wiederherstellen und anschließend den Vorgang wiederholen.

Platziere den Snapshot so nah wie praktisch möglich am ersten aufwendigen Parse-/Dispatch-Schritt, etwa nach einem `recv`-/`read`- oder Paketdeserialisierungspunkt, und ermittle den vom Ziel verwendeten Eingabepuffer. Das entspricht dem Prinzip der adaptiven Platzierung: Den Snapshot tiefer in die Eingabeverarbeitung verschieben, um wiederholte Arbeit zu vermeiden.<sup>[[11]](#references)</sup>

## Linux-Kernel-Race-Exploration mit MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) macht zeitkritische Linux-Kernel-Races zu wiederholbaren Speicherzugriffsplänen. Das Tool kann Zwei-Kontext-Ausführungen im Muster **A-B-A** automatisch aufzählen oder Analysten ermöglichen, Reihenfolgebedingungen in einer Terminal-UI/GUI festzulegen. Es handelt sich um experimentelle Forschungswerkzeuge und nicht um einen vollständigen Concurrency-Fuzzer: Derzeit werden LLVM 23+ und der gepatchte Kernel des Projekts benötigt, die Kommandozeilentools unterstützen zwei Test-Threads, und die vorgeschlagene Fuzzing-Schicht für Userspace ist nicht implementiert.<sup>[[17]](#references)[[18]](#references)</sup>

### Kommunikationspunkte zwischen Kontexten erfassen

Erstelle den instrumentierten Kernel mit KASAN-Outline-Callbacks und der gepatchten KCOV-Unterstützung zur Speicheraufzeichnung. Die README des Projekts empfiehlt außerdem, die Sibling-Call-Optimierung zu deaktivieren, damit Call Stacks weiterhin verwendbar sind.<sup>[[17]](#references)[[18]](#references)</sup>

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

Der KASAN-Outline-Modus (`asan-instrumentation-with-call-threshold=0`) wandelt instrumentierte Zugriffe in Helper-Aufrufe um. Die MAccConc-Kernel-Patches deaktivieren `asan-opt-same-temp`, damit aufeinanderfolgende Zugriffe nicht zusammengeführt werden; deaktiviere auch die Optimierung `asan-opt-globals`, wenn Rennen bei globalen Variablen sichtbar sein müssen. KCOV überträgt die resultierenden Datensätze an den Userspace. Vergleiche Zugriffe aus verschiedenen Ausführungskontexten und behalte Paare, deren Bytebereiche sich überschneiden und bei denen mindestens eine Seite schreibt; behandle `kfree()` als Schreibzugriff, damit auch Lebensdauerübergänge zu Kandidaten werden.<sup>[[17]](#references)</sup>

Bei Arbeit, die den initiierenden Task verlässt, etwa der Paketverarbeitung oder RCU-Callbacks, muss das Subsystem ein KCOV-Remote-Coverage-Handle weitergeben. Upstream-Remote-KCOV ist standardmäßig deaktiviert und für beliebige Hintergrundarbeit nicht automatisch verfügbar. Eine fehlende Weitergabe kann daher dazu führen, dass eine tatsächliche Interaktion unsichtbar bleibt.<sup>[[17]](#references)[[19]](#references)</sup>

### Dieselben dynamischen Zugriffe bei jedem Lauf identifizieren

Wiederhole die Ausführung nicht anhand einer konkreten Heap-Adresse, die sich nach jeder Allokation ändern kann, oder nur anhand einer Instruktionsadresse, die innerhalb von Helpern wie `memcpy()` und `spin_lock()` mehrdeutig ist. MAccConc verwendet einen **um Zähler erweiterten Stack-Trace**: Jeder Frame identifiziert einen Callee sowie dessen Aufrufzähler innerhalb des Callers; das letzte Element identifiziert die Speicherzugriffs-Instruktion. SanitizerCoverage-Records für Funktionsaufrufe und -rückgaben ermöglichen dem Userspace, diesen dynamischen Bezeichner zu rekonstruieren. Er bleibt trotz Adressänderungen und nicht zusammenhängender Kontrollflussänderungen stabil.<sup>[[17]](#references)</sup>

### Kandidatenpaare in erzwungene Abläufe umwandeln

Der gepatchte `KCOV_SET_DI`-ioctl verknüpft einen um Zähler erweiterten Zugriffsbezeichner mit einer Aktion für ein gemeinsames Flag.<sup>[[17]](#references)</sup>

| Aktion | Semantik |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Setzt Flag *N* unmittelbar vor dem ausgewählten Zugriff. |
| `DI_STACK_WAIT` | Wartet vor dem ausgewählten Zugriff in einer Schleife, bis Flag *N* gesetzt ist oder das konfigurierte Limit abläuft. |
| `DI_STACK_WAKE_POST` | Setzt Flag *N* unmittelbar nach dem ausgewählten Zugriff. |

Für eine partielle **A-happens-before-B**-Bedingung weise A `DI_STACK_WAKE_POST` und B `DI_STACK_WAIT` mit demselben Flag zu. Für einen vollständig festgelegten Ablauf mit zwei Kontexten blockiere B zunächst; lasse dann A B aufwecken und am ersten Übergabepunkt warten. B führt am nächsten Übergabepunkt die umgekehrte Operation aus. Letzteres entspricht einem deterministischen Kontextwechsel und wird vom automatischen A-B-A-Explorer verwendet.<sup>[[17]](#references)</sup>

Eine minimale Kampagne besteht darin, den Testfall mit vier Hooks (`test_setup`, zwei Thread-Funktionen und `test_end`) als Shared Library zu kompilieren, zunächst einen Trace ohne Einschränkungen zu erfassen und anschließend A-B-A-Kandidaten aufzuzählen oder manuelle Bedingungen für verdächtige Zugriffe hinzuzufügen.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpretiere Timeouts getrennt von erfolgreichen Umordnungen: Eine angeforderte Reihenfolge ist möglicherweise nicht erreichbar, weil ein Lock oder eine Initialisierungs-/Veröffentlichungsabhängigkeit verhindert, dass der zweite Kontext seinen Injection Point erreicht. Behalte auch KASANs blinde Flecken im Blick: Direkte Stack-Zugriffe werden normalerweise nicht instrumentiert, sofern sie nicht möglicherweise außerhalb der Grenzen liegen, globale Variablen werden bei der Standardoptimierung ausgelassen, und aktuelle Compiler können ASAN- und TSAN-Hooks nicht gleichzeitig ausgeben. Außerdem verliert der Prototyp seinen KCOV-Puffer, wenn eine VM abstürzt. Bewahre daher eine unabhängige Crash-Konsole bzw. ein unabhängiges Oracle auf.<sup>[[17]](#references)</sup>

Für zukünftiges Concurrency-guided Fuzzing kannst du Speicherzugriffsübersichten pro Input oder Syscall aufzeichnen, Operationen paaren, die Kommunikationspunkte zwischen Kontexten bilden würden, und anschließend nur diese Kombinationen untersuchen. VM-Snapshots stabilisieren den globalen Zustand und die Adressen; ohne Snapshots können Metadaten zum Allokationsort Objekte über mehrere Läufe hinweg abstrahieren. Dies ist eine vorgeschlagene Erweiterung, kein Feature der aktuellen MAccConc-Userspace-Tools.<sup>[[17]](#references)</sup>

## Harness-Introspektion: Flache Fuzzer frühzeitig erkennen

Wenn eine Kampagne ins Stocken gerät, liegt das Problem oft nicht am Mutator, sondern am **Harness**. Nutze die **Introspektion von Erreichbarkeit und Coverage**, um Funktionen zu finden, die statisch von deinem Fuzz-Target aus erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Diese Funktionen weisen meist auf eines von drei Problemen hin.<sup>[[12]](#references)</sup>

- Der Harness steigt zu spät oder zu früh in das Target ein.
- Im Seed-Corpus fehlt eine ganze Feature-Familie.
- Das Target benötigt tatsächlich einen **zweiten Harness** statt eines überladenen „Alles-erledigen“-Harness.

Wenn du Workflows im Stil von OSS-Fuzz / ClusterFuzz verwendest, kann Fuzz Introspector die statische Erreichbarkeit mit der Laufzeit-Coverage vergleichen und Berichte aus einem zeitlich begrenzten Lauf oder einem öffentlichen Corpus erstellen.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Nutze den Bericht, um zu entscheiden, ob ein neuer Harness für einen bisher ungetesteten Parserpfad hinzugefügt, das Corpus für ein bestimmtes Feature erweitert oder ein monolithischer Harness in kleinere Einstiegspunkte aufgeteilt werden soll.

## Fuzzing-Ziele anhand des Graphen auswählen und Mutationsergebnisse triagieren

Wenn du bereits **Ergebnisse statischer Analysen**, **Überlebende des Mutation Testing** und **Coverage-Berichte** hast, solltest du sie nicht als unabhängige Listen triagieren. Erstelle zuerst einen **Aufrufgraphen**, annotiere die Knoten mit **zyklomatischer Komplexität**, **Erreichbarkeit von Einstiegspunkten und nicht vertrauenswürdigen Eingaben** sowie externen Findings und stelle dann Fragen zum Graphen.<sup>[[5]](#references)[[6]](#references)</sup>

- Welche Funktionen mit hoher Komplexität sind von nicht vertrauenswürdigen Eingaben aus erreichbar?
- Welche Mutation Survivors liegen auf Pfaden von Parsern/Handlern zu sicherheitskritischem Code?
- Welche Funktionen sind architektonische Engpässe mit ungewöhnlich großem **Wirkungsradius**?

So findest du in der Regel bessere Fuzzing-Ziele als allein anhand der „niedrigsten Coverage“. Ein Parser/Decoder mit **hoher Komplexität** und bestätigter **externer Erreichbarkeit** eignet sich besser als Harness-Kandidat als ein isolierter interner Helper mit geringer Coverage, aber ohne vom Angreifer kontrollierbaren Pfad.

### Praktischer Triage-Workflow

1. Erstelle einen **Code-Graphen** aus der Codebasis und ermittle Komplexitäts- und Branch-Metriken für jede Funktion.
2. Liste **Einstiegspunkte** auf, die vom Angreifer kontrollierte Eingaben akzeptieren: Request-Handler, Decoder, Importer, Protokoll-Parser, CLI-/Datei-Reader.
3. Führe **Pfadabfragen** von diesen Einstiegspunkten zu den Kandidatenfunktionen durch, um erreichbare Angriffsfläche von totem oder ausschließlich internem Code zu unterscheiden.
4. Priorisiere Knoten, die Folgendes vereinen:
   - hohe **zyklomatische Komplexität**
   - bestätigte **Erreichbarkeit über nicht vertrauenswürdige Eingaben**
   - großen **Wirkungsradius** oder viele nachgelagerte Abhängigkeiten
   - bestätigende Hinweise wie **SARIF**-Findings, Audit-Notizen oder Mutation Survivors
5. Schreibe zuerst gezielte Harnesses für die am besten bewerteten Knoten, insbesondere für **Parser/Codecs** wie Hex-, Base64-, IP- und Message-Decoder.

### Mutation Survivors: äquivalent oder relevant

Mutation Testing erzeugt oft eine unübersichtliche Liste von Survivors. Bevor du jeden Survivor als Sicherheitslücke behandelst, solltest du anhand des Graphen Folgendes prüfen:

- Ist die mutierte Funktion von einem vom Angreifer kontrollierten Einstiegspunkt aus erreichbar?
- Sind alle Aufrufpfade durch stärkere Invarianten als die mutierte Prüfung eingeschränkt?
- Liegt der Knoten in totem Code, in reiner Formatierungslogik oder in einem Rechen-/Parserpfad mit hohen Auswirkungen?

Survivors, die unerreichbar oder strukturell eingeschränkt bleiben, sind oft **äquivalente Mutanten**. Survivors, die **erreichbar** bleiben und **Grenzbedingungen**, **Overflow-/Carry-Pfade** oder sicherheitskritische Arithmetik/Parsing betreffen, sollten in Folgendes aufgenommen werden:

- neue Fuzz-Harnesses
- direkte Property-/Invarianztests
- gezielte Edge-Case-Vektoren

### Externe Findings im Graphen korrelieren

Wenn deine SAST-Pipeline **SARIF** exportiert, ordne Findings anhand von **Datei + Zeilenbereich** den Graphenknoten zu und nutze den Graphen, um die Auswirkungen genauer zu bestimmen.<sup>[[6]](#references)</sup>

- Ermittle den **Wirkungsradius** der markierten Funktion.
- Prüfe, ob das Finding auf einem Pfad von einem Einstiegspunkt liegt.
- Gruppiere nahe beieinanderliegende Findings, die auf denselben Engpass hinauslaufen.

Das hilft bei der Entscheidung, ob sich Fuzzing-Aufwand für eine bestimmte Funktion lohnt: Ein Knoten, der **erreichbar**, **komplex** und bereits von **SAST-Findings** betroffen ist, ist oft ein besseres Ziel als ein lediglich komplexer Knoten ohne Angreiferpfad.

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

Die wichtige Methodik ist die Schnittmenge: **Komplexität x Angriffsfläche x Auswirkungen**. Nutze das Diagramm, um Fuzzing-Ziele mit dem höchsten erwarteten Sicherheitswert auszuwählen. Anhand der überlebenden Mutationen kannst du dann entscheiden, welche Grenzen und Invarianten dein Harness besonders beanspruchen muss.<sup>[[5]](#references)</sup>

## Go-Fuzzing mit gosentry: Leistungsstärkere Engine, typisierte Eingaben und differentielle Prüfungen

Wenn ein Go-Ziel bereits über ein natives `testing.F`-Harness verfügt, ist es ein praktischer Upgrade-Pfad, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen – einer geforkten Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend durch **LibAFL** ersetzt.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

This ist nützlich, wenn der native Go-Fuzzer bei **schwierigen Vergleichen**, **typisierten Eingaben** oder **parserlastigen Formaten** ins Stocken gerät. Die Methodik bleibt gleich:

- Verwende weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback.
- Verwende denselben Harness, führe ihn aber mit gosentrys `go`-Binary statt mit der Standard-Toolchain aus.
- Behandle die resultierende Kampagne wie einen normalen coverage-guided Lauf, aber mit LibAFL-Scheduling und -Mutation sowie besseren umgebenden Detektoren.

### Stille Fehler in Fuzzing-Funde verwandeln

Ein wiederkehrendes Problem bei Go-Assessments ist, dass gefährliches Verhalten standardmäßig oft **keinen** Crash auslöst. Mit gosentry kannst du mehrere Arten von „schlechten, aber stillen“ Zuständen in Funde umwandeln.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, damit ausgewählte Logging- und Fehlerpfade wie Crashes behandelt werden (nützlich bei `log.Fatal`-ähnlichen Codepfaden, die andernfalls nur protokollieren und fortfahren).
- `--catch-races=true`, um neu entdeckte Queue-Einträge mit dem Go Race Detector erneut auszuführen.
- `--catch-leaks=true`, um neue Queue-Einträge mit `goleak` erneut auszuführen und bei Goroutine-Leaks anzuhalten.
- LibAFL-Hang-Behandlung, damit **Endlosschleifen / sehr langsame Eingaben** als Fuzzing-Funde erhalten bleiben, statt als Timeouts zu verschwinden.
- Standardmäßig integrierte Prüfungen auf arithmetischen Überlauf sowie optionale Abschneideprüfungen durch Instrumentierung im Stil von go-panikint.

Das ist besonders wertvoll für Ziele, bei denen die Sicherheitsauswirkung ein **Parserfehler ohne Panic**, ein **Nebenläufigkeitsfehler** oder ein **DoS-Hänger** statt Speicherkorruption ist.

### Struct-aware Fuzzing für typisierte Go-APIs

Natives Go-Fuzzing erwartet hauptsächlich Skalare wie `[]byte`, `string` und Zahlen. Wenn der getestete Code typisierte Objekte verarbeitet, kann gosentry **zusammengesetzte Werte** direkt fuzzten (Structs, Slices, Arrays, Pointer) und dabei weiterhin die zugrunde liegenden Bytes mutieren.<sup>[[7]](#references)[[8]](#references)</sup>

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

Verwende dies, wenn das Erstellen eines gefälschten Wire-Formats nur fürs Fuzzing Logikfehler hinter Parsing-Code verbergen würde, der nur im Harness vorhanden ist. Bei Differential- oder grammarbasierten Kampagnen sollte die Harness-Eingabe ein einzelnes `[]byte` oder ein einzelner `string` sein. Parse stattdessen innerhalb des Callbacks.

### Grammatikbasiertes Fuzzing für Parser und Protokolleingaben

Für Parser, Formate und Eingabesprachen kann gosentry **Nautilus-Grammatik-Fuzzing** auf Basis von LibAFL ausführen. Die Grammatik ist ein JSON-Array aus Produktionsregeln, und der Harness sollte üblicherweise ein einzelnes Argument vom Typ `[]byte` oder `string` entgegennehmen.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodiknotizen:

- Verwende den Grammar-Modus, wenn Byte-Level-Mutationen größtenteils bereits an frühen Syntaxprüfungen scheitern.
- Halte die Grammar auf die **sicherheitsrelevante Teilmenge** der Sprache/des Protokolls beschränkt, statt die vollständige Spezifikation abzubilden.
- Verwende große Grenzwerte in Terminals/Nonterminals, um Integer-, Längen- und Zustandsautomaten-Grenzen zu belasten.
- Der Grammar-Modus hält Eingaben grammar-valid, aber das Ziel erhält weiterhin **Bytes/Strings** – Parsing und semantische Prüfungen bleiben also im instrumentierten Code.

### Differential Fuzzing: Implementierungen vergleichen, nicht nur Abstürze

Ein bewährtes Muster im Go-Ökosystem ist **grammar-based differential fuzzing**: gültige strukturierte Eingaben erzeugen und sie an zwei Parser, Clients oder Zustandsautomaten übergeben.<sup>[[7]](#references)[[8]](#references)</sup>

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

Behandle Folgendes als Befunde:

- eine Implementierung löst einen Panic aus, während die andere die Eingabe sauber zurückweist
- Unterschiede bei akzeptierten und zurückgewiesenen Eingaben
- unterschiedliche Parse-Bäume oder dekodierte Objekte
- abweichende Zustandsübergänge, Nonces, Kontostände oder State Roots

So lassen sich **Konsensabweichungen**, **Parser-Mehrdeutigkeiten** und **Abweichungen zwischen Spezifikation und Implementierung** auf praktische Weise finden, die beim reinen Crash-Fuzzing oft unentdeckt bleiben.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Das Campaign-Corpus für die Coverage-Berichterstellung wiederverwenden

Spiele nach einer Campaign das gespeicherte Queue-Corpus erneut ab, um einen Go-Coverage-Bericht zu erstellen, ohne manuell ein separates Corpus zu exportieren.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Führen Sie den Befehl aus demselben **Paket** und mit demselben **`-fuzz`-Ziel** aus, damit gosentry den richtigen zwischengespeicherten Kampagnenstatus auflöst.



## References

- [1] [Mutationsgrammatik-Fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++-Fuzzing im Detail](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet fünf Jahre später: Coverage-gesteuertes Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark wandelt Code in Graphen um](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-Fuzzing fehlte die Hälfte des Toolkits. Wir haben die Toolchain geforkt, um das zu beheben.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ein schneller Greybox-Fuzzer für zustandsbehaftete Netzwerkprotokolle mit Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Keine Grammatik, kein Problem: Linux-Kernel-Fuzzing ohne Systemaufrufbeschreibungen](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Effizientes Fuzzing mit adaptiven und veränderlichen Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++-LLVM-Instrumentierung: Pfad- und Caller-Coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prädiktives kontextsensitives Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog – Binder-Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL-Android-Binder-Fuzzer – Dokumentation zu Build und Regression-Seeds](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Untersuchung von Race Conditions im Linux-Kernel mit kontrolliert verschachtelten Speicherzugriffen](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: Code-Coverage für Fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO-Syntax für erweiterte Dateinamen](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec-Sicherheitshinweis: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing der CFITSIO-Syntax für erweiterte Dateinamen: 16 Memory-Safety-Schwachstellen und Codex-gestützte Triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
