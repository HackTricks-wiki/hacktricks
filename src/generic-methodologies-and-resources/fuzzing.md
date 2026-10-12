# Fuzzing-Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantik

Beim **mutational grammar fuzzing** werden Inputs mutiert, während sie **grammatikkonform** bleiben. Im coverage-guided-Modus werden nur Samples, die **neue Coverage** auslösen, als Corpus-Seeds gespeichert. Bei **Sprachzielen** (Parsern, Interpretern, Engines) kann dadurch die Entdeckung von Bugs ausbleiben, die **semantische/Datenfluss-Ketten** erfordern, bei denen die Ausgabe eines Konstrukts zur Eingabe eines anderen wird.<sup>[[1]](#references)</sup>

**Fehlermodus:** Der Fuzzer findet Seeds, die jeweils einzeln `document()` und `generate-id()` (oder ähnliche Primitives) ausführen, **erhält aber nicht den verketteten Datenfluss**. Dadurch wird das Sample, das dem Bug näherkommt, verworfen, weil es keine zusätzliche Coverage liefert. Bei **3 oder mehr abhängigen Schritten** wird zufällige Rekombination kostspielig, und das Coverage-Feedback leitet die Suche nicht an.<sup>[[1]](#references)</sup>

**Folgerung:** Bei grammatikbasierten Zielen mit vielen Abhängigkeiten solltest du **mutationale und generative Phasen kombinieren** oder die Generierung auf Muster mit **function chaining** ausrichten (nicht nur auf Coverage).<sup>[[1]](#references)</sup>

## Fallstricke bei der Corpus-Diversität

Coverage-gesteuerte Mutation ist **greedy**: Ein Sample mit neuer Coverage wird sofort gespeichert und enthält oft große, unveränderte Bereiche. Mit der Zeit entstehen im Corpus **nahezu identische Duplikate** mit geringer struktureller Vielfalt. Aggressive Minimierung kann nützlichen Kontext entfernen. Ein praktikabler Kompromiss ist daher eine **grammatikbewusste Minimierung**, die **bei einer Mindestanzahl von Tokens stoppt** (Rauschen reduzieren und zugleich genügend umgebende Struktur erhalten, damit Mutationen weiterhin sinnvoll sind).<sup>[[1]](#references)</sup>

Eine praktische Corpus-Regel beim mutational fuzzing lautet: **Eine kleine Menge strukturell unterschiedlicher Seeds, die die Coverage maximieren, ist einem großen Haufen nahezu identischer Duplikate vorzuziehen.** In der Praxis bedeutet das meist Folgendes.<sup>[[1]](#references)[[3]](#references)</sup>

- Beginne mit **realen Samples** (öffentlichen Corpora, Daten aus Crawling, aufgezeichnetem Traffic und Dateisammlungen aus dem Ökosystem des Ziels).
- Reduziere sie mit **Coverage-basierter Corpus-Minimierung**, statt jedes gültige Sample zu behalten.
- Halte Seeds **klein genug**, damit Mutationen sinnvolle Felder treffen, anstatt die meisten Zyklen mit irrelevanten Bytes zu verbringen.
- Führe die Corpus-Minimierung nach größeren Änderungen am Harness oder an der Instrumentierung erneut aus, da sich der „beste“ Corpus ändert, wenn sich die Erreichbarkeit ändert.

## Comparison-Aware Mutation für Magic Values

Ein häufiger Grund, warum Fuzzer an ihre Grenzen stoßen, sind nicht Syntaxprobleme, sondern **strikte Vergleiche**: Magic Bytes, Längenprüfungen, Enum-Strings, Checksummen oder Parser-Dispatch-Werte, die durch `memcmp`, Switch-Tabellen oder eine Reihe verketteter Vergleiche geschützt sind. Reine Zufallsmutation verschwendet Zyklen damit, diese Werte Byte für Byte zu erraten.

Verwende für diese Ziele **Comparison Tracing** (zum Beispiel Workflows im Stil von AFL++ `CMPLOG` / Redqueen), damit der Fuzzer Operanden fehlgeschlagener Vergleiche beobachten und Mutationen auf Werte ausrichten kann, die diese Vergleiche bestehen.<sup>[[3]](#references)</sup>

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

- Das ist besonders nützlich, wenn das Ziel tiefer liegende Logik hinter **Dateisignaturen**, **Protokollverben**, **Typ-Tags** oder **versionsabhängigen Feature-Bits** verbirgt.
- Kombiniere es mit **Wörterbüchern**, die aus echten Beispielen, Protokollspezifikationen oder Debug-Logs extrahiert wurden. Ein kleines Wörterbuch mit Grammatik-Tokens, Chunk-Namen, Verben und Trennzeichen ist oft wertvoller als eine riesige generische Wortliste.
- Wenn das Ziel viele aufeinanderfolgende Prüfungen durchführt, löse zuerst die frühesten „Magic“-Vergleiche und minimiere anschließend den resultierenden Korpus erneut, damit spätere Phasen mit bereits gültigen Präfixen beginnen.

## Aussagekräftigeres Feedback, wenn Edge-Coverage verschiedene Pfade zusammenfasst

Normale Edge-Coverage kann nicht zwischen zwei Ausführungen unterscheiden, die denselben Helper über verschiedene Aufrufer durchlaufen oder innerhalb einer Funktion unterschiedliche Branch-Kombinationen nehmen. Das ist bei gemeinsam genutzten Decodern, Protokoll-Dispatchern und Interpreter-Helpern wichtig, bei denen die **Route** zu einer Edge den aktiven Zustand bestimmt. Jeden Aufrufkontext naiv zu erfassen, ist ebenfalls riskant: Die Coverage-Map und die Queue können riesig werden. Die Forschung zu kontextsensitive Fuzzing empfiehlt daher, nur vielversprechende Kontexte gezielt zu verfeinern, statt den gesamten Call-Graph kontextsensitiv zu behandeln.<sup>[[14]](#references)</sup>

Neuere AFL++-Builds bieten zusätzlich zur normalen Edge-Coverage **Ball-Larus-Pfad-Coverage pro Funktion**. Dabei wird jedem azyklischen Pfad durch eine Funktion ein Feature zugewiesen; Loop-Back-Edges werden entfernt, sodass dieses Feedback Branch-Kombinationen unterscheidet, **nicht aber die Anzahl der Schleifendurchläufe**. Beginne mit der lockeren Stufe `1` und beschränke strengere Modi anschließend auf verdächtigen Parser-/Zustandsautomaten-Code, da die Anzahl der Pfade exponentiell wachsen kann.<sup>[[13]](#references)</sup>

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

**Hinweise zur Kampagne:** Setze umfangreicheres Feedback zurückhaltend ein und überwache dessen Kosten für Coverage-Map und Queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Führe parallel eine gewöhnliche Edge-Coverage-Instanz aus; umfangreicheres Feedback ist nur dann nützlich, wenn die zusätzlichen Kosten für Queue und Map die Anzahl der Ausführungen pro Sekunde nicht zu stark verringern.
- Verwende `AFL_LLVM_ALLOWLIST`, um die Instrumentierung von Pfaden und Aufrufern einzuschränken, wenn große, vorlagenlastige Bibliotheken oder generischer Utility-Code die Map dominieren.
- Funktionen mit übermäßig vielen azyklischen Pfaden können von AFL++ übersprungen werden; Warnungen während der Kompilierung sind ein Hinweis darauf, dass das Ziel Allowlisting oder eine weniger strenge Stufe benötigt.
- Caller + Path Coverage unterstützt nur eine Caller-Tiefe. Kombiniere es nicht mit tieferen Context Stacks.
- Pfad-IDs können sich zwischen größeren LLVM-Versionen ändern. Verwende während einer Kampagne eine feste Toolchain und synchronisiere PATH-basierte Corpora nicht so, als wären ihre Feature-IDs über verschiedene Builds hinweg stabil.
- Dieses Feedback ergänzt `CMPLOG`: Comparison Tracing ermittelt, **welcher Wert eine Guard-Bedingung erfüllt**, während Path-/Caller-Feedback festhält, **welcher Pfad und welche Zweigkombination dorthin geführt haben**.

## Stateful Fuzzing: Sequenzen sind Seeds

Bei **Protokollen**, **authentifizierten Workflows** und **mehrstufigen Parsern** ist die interessante Einheit oft nicht ein einzelner Blob, sondern eine **Nachrichtensequenz**. Das gesamte Transkript in eine Datei zu schreiben und blind zu mutieren, ist in der Regel ineffizient, weil der Fuzzer jeden Schritt gleichermaßen mutiert, selbst wenn nur die spätere Nachricht den fragilen Zustand erreicht.<sup>[[4]](#references)</sup>

Effektiver ist es, die **Sequenz selbst als Seed** zu behandeln und **beobachtbaren Zustand** (Antwortcodes, Protokollzustände, Parserphasen, zurückgegebene Objekttypen) als zusätzliches Feedback zu verwenden.<sup>[[4]](#references)</sup>

- Lasse **gültige Präfixnachrichten** unverändert und konzentriere Mutationen auf die Nachricht, die den **Zustandsübergang auslöst**.
- Speichere Kennungen und vom Server generierte Werte aus vorherigen Antworten zwischen, wenn der nächste Schritt davon abhängt.
- Bevorzuge Mutationen und Splicing pro Nachricht gegenüber der Mutation des gesamten serialisierten Transkripts als undurchsichtigem Blob.
- Wenn das Protokoll aussagekräftige Antwortcodes bereitstellt, verwende sie als **kostengünstigen Zustandsorakel**, um Sequenzen zu priorisieren, die weiter vorankommen.

Aus demselben Grund werden authentifizierte Bugs, verborgene Zustandsübergänge oder Parser-Bugs, die „erst nach dem Handshake“ auftreten, beim gewöhnlichen dateibasierten Fuzzing oft übersehen: Der Fuzzer muss **Reihenfolge, Zustand und Abhängigkeiten** bewahren, nicht nur die Struktur.<sup>[[4]](#references)</sup>

### Android Binder: Fuzzing mit mehreren Clients

Eine hohe Edge-Coverage kann IPC-Treiber-Bugs trotzdem übersehen, da Coverage **Objektbesitz, Referenzzähler, ausstehende Nachrichten, Bereinigungsreihenfolge oder Thread-Interleavings** nicht abbildet. Die Seite [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) behandelt das Treiber-Objektmodell; dieses Beispiel konzentriert sich auf das Fuzzer-Harness. Android Binder ist ein nützliches Modell: Es reicht nicht aus, sowohl die Allokations- als auch die Freigabepfade zu erreichen, wenn der Fuzzer nicht mehrere Prozesse in der erforderlichen Reihenfolge auf dasselbe Kernel-Objekt zugreifen lassen kann.<sup>[[15]](#references)</sup>

#### Das Protokoll modellieren, nicht isolierte `ioctl`-Puffer

Stelle einen Testfall als geordnete Grammatik aus **Client-Identität + Operation + strukturierten Argumenten** dar. Der Binder-LKL-Fuzzer verwendet protobuf und `libprotobuf-mutator`, mit einem persistenten Context-Manager-Client und zwei gewöhnlichen Clients. Ein semantisches Harness bewahrt dann die Beziehungen, die durch blinde Byte-Mutationen zerstört würden.<sup>[[15]](#references)</sup>

- Speichere Werte aus früheren Operationen zwischen. Beispielsweise muss `BC_FREE_BUFFER` einen Transaktionspufferzeiger wiederverwenden, der von einem vorherigen `ioctl` zurückgegeben wurde.
- Erzeuge gültige Standardantworten, damit synchrone Transaktionen abgeschlossen werden können und spätere Operationen erreichbar bleiben.
- Verwirf unmögliche Übergänge wie Self-Transaktionen oder mehrere ausstehende Transaktionen an dasselbe Ziel.
- Halte den einmaligen Bootstrap-Zustand außerhalb des Resets pro Eingabe. Binder erlaubt pro Boot nur eine `BINDER_SET_CONTEXT_MGR`-Registrierung; würde dieser Client wiederholt zerstört und neu erstellt, wären spätere Eingaben ungültig.

Ein nützliches Template für Lifetime-Races besteht darin, einen Client ein Objekt übertragen zu lassen, die Bereinigung eines Threads oder Prozesses zu starten und den empfangenden Client gleichzeitig den Transaktionspuffer freigeben zu lassen. Im Beispiel zu CVE-2020-0423 konnte eine Übertragung von `BINDER_TYPE_WEAK_BINDER`, gefolgt von `BINDER_THREAD_EXIT`, die mit `BC_FREE_BUFFER` konkurrierte, ein eingebettetes `binder_work` freigeben, während der Bereinigungspfad des beendenden Threads es noch verwendete.<sup>[[15]](#references)</sup>

#### Kontrollierte Interleavings in einem Userspace-Kernel wieder einführen

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) bindet den echten Kernel-Code in ein Userspace-Harness ein und stellt dessen Syscall-Schnittstelle über `lkl_syscall` bereit. Dadurch lassen sich protobuf-Zustand, Coverage und KASAN leicht in einem Prozess koordinieren. Normalerweise führt LKL einen Syscall jedoch aus, ohne dass ein anderer Kernel-Thread ihn unterbricht. Füge für Race-Kampagnen `schedule()`-Punkte an ausgewählten Grenzen von Sperren und Lebenszyklen ein und lasse das Harness bei jeder Übergabe zufällig den nächsten Client wählen. Setze diese Punkte gezielt ein, da jeder davon den Suchraum für die Planung vervielfacht. Der von den Forschenden beschriebene randomisierte Scheduler ist **nicht** Teil des upstream Binder-Fuzzers.<sup>[[15]](#references)</sup>

#### Serialisierte Regression-Seeds erstellen und erneut ausführen

Das upstream Harness pinnt eine kompatible Version von `libprotobuf-mutator`, aktiviert LKL-Fuzzing-Instrumentierung und KASAN mit `LKL_FUZZING=1` und aktiviert `CONFIG_MMU` für Binder mit `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nachdem eine absichtlich verwundbare Revision ausgecheckt oder die upstream dokumentierten Rollback-Patches angewendet wurden, kann ein serialisierter Seed den gesamten Zustandsübergang mehrerer Clients reproduzieren, ohne ihn in einem Ad-hoc-C-Proof-of-Concept rekonstruieren zu müssen:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Betrachten Sie den resultierenden KASAN use-after-free als Bestätigung dafür, dass der Seed den anfälligen Lifetime-Pfad erreicht hat. Er belegt **nicht** die später erforderlichen Primitives für die Ausführung von Kernel-Code oder eine Privilegieneskalation.<sup>[[16]](#references)</sup>

## Diversitätstrick auf einem einzelnen Rechner (Jackalope-Style)

Eine praktische Möglichkeit, **generative Neuartigkeit** mit der **Wiederverwendung von Coverage** zu verbinden, besteht darin, **kurzlebige Worker** gegen einen persistenten Server neu zu starten. Jeder Worker startet mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden mit dem kombinierten Corpus, synchronisiert erneut und wird dann beendet. So entstehen **in jeder Generation neue Strukturen**, während die angesammelte Coverage weiterhin genutzt wird.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sequenzielle Worker (Beispielschleife):**

<details>
<summary>Neustartschleife für Jackalope-Worker</summary>

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

- `-in empty` erzwingt bei jeder Generierung einen **frischen Corpus**.
- `-server_update_interval T` bildet eine **verzögerte Synchronisierung** nach (zuerst neue Eingaben, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird die **anfängliche Serversynchronisierung standardmäßig übersprungen** (`-skip_initial_server_sync` ist nicht erforderlich).
- Das optimale `T` hängt vom **Ziel** ab. Am besten funktioniert es in der Regel, wenn man umschaltet, nachdem der Worker den Großteil der „einfachen“ Coverage gefunden hat.

## Snapshot-Fuzzing für schwer zu instrumentierende Ziele

Wenn der Code, den Sie testen möchten, erst **nach einem umfangreichen Setup** erreichbar ist (Start einer VM, Abschluss eines Logins, Empfang eines Pakets, Parsen eines Containers, Initialisierung eines Dienstes), ist **Snapshot-Fuzzing** eine nützliche Alternative: Erfassen Sie den bereitstehenden Prozess- oder VM-Zustand, speisen Sie jeden Testfall in den Eingabepfad des Ziels ein, führen Sie die Ausführung bis zu einem Crash oder Timeout fort und stellen Sie den Snapshot wieder her. So muss die Initialisierung oder das Protokollpräfix nicht wiederholt werden. Das ist nützlich für **Netzwerkdienste**, **Firmware**, **Angriffsflächen nach der Authentifizierung** und **Binärdatei-Ziele**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Führen Sie das Ziel aus, bis der gewünschte Zustand erreicht ist.
2. Erstellen Sie an diesem Punkt einen Snapshot von **Speicher + Registern**.
3. Schreiben Sie bei jedem Testfall die veränderte Eingabe direkt in den relevanten Guest-/Prozesspuffer.
4. Führen Sie die Ausführung bis zu einem Crash, Timeout oder Reset fort.
5. Stellen Sie den Snapshot wieder her. Bei VM-Zielen sollten Sie, sofern unterstützt, nur die **dirty pages** wiederherstellen und den Vorgang anschließend wiederholen.

Platzieren Sie den Snapshot so nah wie praktikabel am ersten aufwendigen Parse- oder Dispatch-Schritt, etwa nach einem `recv`/`read` oder einem Punkt der Paketdeserialisierung, und halten Sie fest, welchen Eingabepuffer das Ziel verwendet. Dies folgt dem Prinzip der adaptiven Platzierung: Der Snapshot wird tiefer in die Eingabeverarbeitung verschoben, um wiederholte Arbeit zu vermeiden.<sup>[[11]](#references)</sup>

## Erkundung von Linux-Kernel-Races mit MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) macht zeitkritische Linux-Kernel-Races zu reproduzierbaren Speicherzugriffsabläufen. Das Tool kann Ausführungen mit zwei Kontexten nach dem **A-B-A**-Muster automatisch aufzählen oder Analysten mithilfe einer Terminal-UI/GUI Reihenfolgebedingungen festlegen lassen. Es handelt sich um experimentelle Forschungswerkzeuge und nicht um einen vollständigen Concurrency-Fuzzer: Derzeit sind LLVM 23+ und der gepatchte Kernel des Projekts erforderlich, die Kommandozeilenwerkzeuge unterstützen zwei Test-Threads, und die vorgeschlagene Fuzzing-Schicht im Userspace ist nicht implementiert.<sup>[[17]](#references)[[18]](#references)</sup>

### Kommunikationspunkte zwischen Kontexten erfassen

Erstellen Sie den instrumentierten Kernel mit KASAN-Outline-Callbacks und der gepatchten KCOV-Unterstützung für Speicheraufzeichnungen. Die Projekt-README empfiehlt außerdem, die Optimierung für Sibling Calls zu deaktivieren, damit die Call Stacks weiterhin verwendbar sind.<sup>[[17]](#references)[[18]](#references)</sup>

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

Der KASAN-Outline-Modus (`asan-instrumentation-with-call-threshold=0`) wandelt instrumentierte Zugriffe in Helper-Aufrufe um. Die MAccConc-Kernel-Patches deaktivieren `asan-opt-same-temp`, damit aufeinanderfolgende Zugriffe nicht zusammengeführt werden. Deaktiviere auch die Optimierung `asan-opt-globals`, wenn Datenrennen auf globalen Variablen sichtbar sein müssen. KCOV überträgt die resultierenden Einträge an den Userspace. Vergleiche Zugriffe aus verschiedenen Ausführungskontexten und behalte Paare bei, deren Bytebereiche sich überschneiden und bei denen mindestens eine Seite schreibt. Behandle `kfree()` als Schreibzugriff, damit auch Änderungen der Objektlebensdauer als Kandidaten erfasst werden.<sup>[[17]](#references)</sup>

Für Arbeit, die den initiierenden Task verlässt, etwa Paketverarbeitung oder RCU-Callbacks, muss das Subsystem ein KCOV-Remote-Coverage-Handle weitergeben. Upstream-Remote-KCOV ist opt-in und steht nicht automatisch für beliebige Hintergrundarbeit zur Verfügung. Eine fehlende Weitergabe kann daher dazu führen, dass eine tatsächliche Interaktion unsichtbar bleibt.<sup>[[17]](#references)[[19]](#references)</sup>

### Dieselbe dynamische Speicherzugriffsoperation bei jedem Durchlauf identifizieren

Wiederhole den Test nicht anhand einer konkreten Heap-Adresse, die sich nach jeder Allokation ändern kann, oder nur anhand einer Instruktionsadresse, die innerhalb von Helfern wie `memcpy()` und `spin_lock()` mehrdeutig ist. MAccConc verwendet einen **um Aufrufzähler erweiterten Stacktrace**: Jeder Frame identifiziert einen Callee sowie dessen Aufrufzähler innerhalb des Callers, und das letzte Element identifiziert die Instruktion, die auf den Speicher zugreift. SanitizerCoverage-Eintritts- und -Austrittsdatensätze für Funktionen ermöglichen es dem Userspace, diesen dynamischen Bezeichner zu rekonstruieren, der trotz Adressänderungen und unabhängigem Kontrollflussrauschen stabil bleibt.<sup>[[17]](#references)</sup>

### Kandidatenpaare in erzwungene Ablaufpläne umwandeln

Der gepatchte `KCOV_SET_DI`-Ioctl verknüpft einen um Aufrufzähler erweiterten Zugriffsbezeichner mit einer Aktion für ein gemeinsames Flag.<sup>[[17]](#references)</sup>

| Aktion | Semantik |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Setzt Flag *N* unmittelbar vor dem ausgewählten Zugriff. |
| `DI_STACK_WAIT` | Wartet vor dem ausgewählten Zugriff in einer Schleife, bis Flag *N* gesetzt ist oder das konfigurierte Zeitlimit abläuft. |
| `DI_STACK_WAKE_POST` | Setzt Flag *N* unmittelbar nach dem ausgewählten Zugriff. |

Für eine partielle **A-passiert-vor-B-Bedingung** verknüpfe `DI_STACK_WAKE_POST` mit A und `DI_STACK_WAIT` mit B, jeweils mit demselben Flag. Für einen vollständig festgelegten Ablaufplan mit zwei Kontexten blockiere B zunächst. A weckt dann B auf und wartet am ersten Übergabepunkt; beim nächsten Übergabepunkt führt B die umgekehrte Aktion aus. Das entspricht einem deterministischen Kontextwechsel und wird vom automatischen A-B-A-Explorer verwendet.<sup>[[17]](#references)</sup>

Eine minimale Testkampagne besteht darin, den Testfall mit vier Hooks (`test_setup`, zwei Thread-Funktionen und `test_end`) als Shared Library zu kompilieren, einen unbeschränkten Trace zu erfassen und anschließend A-B-A-Kandidaten aufzuzählen oder manuelle Bedingungen um verdächtige Zugriffe herum hinzuzufügen.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpretiere Timeouts getrennt von erfolgreichen Umordnungen: Eine angeforderte Reihenfolge ist möglicherweise unmöglich, weil eine Sperre oder eine Abhängigkeit bei Initialisierung/Veröffentlichung verhindert, dass der zweite Kontext seinen Injection Point erreicht. Behalte auch KASANs blinde Flecken im Blick: Direkte Stack-Zugriffe werden normalerweise nicht abgefangen, sofern sie nicht möglicherweise außerhalb der Grenzen liegen; Globals werden bei der Standardoptimierung ausgelassen, und aktuelle Compiler können ASAN- und TSAN-Hooks nicht gleichzeitig ausgeben. Außerdem verliert der Prototyp den KCOV-Puffer, wenn ein Gast in Panik gerät. Bewahre daher eine unabhängige Crash-Konsole/einen unabhängigen Oracle.<sup>[[17]](#references)</sup>

Für zukünftiges Concurrency-guided Fuzzing solltest du pro Input oder Syscall Zusammenfassungen der Speicherzugriffe aufzeichnen, Operationen paaren, die Cross-Context-Kommunikationspunkte bilden würden, und anschließend nur diese Kombinationen untersuchen. VM-Snapshots stabilisieren den globalen Zustand und die Adressen; ohne Snapshots können Metadaten der Allokationsstelle Objekte über mehrere Runs hinweg abstrahieren. Dies ist eine vorgeschlagene Erweiterung, keine Funktion der aktuellen MAccConc-Userspace-Tools.<sup>[[17]](#references)</sup>

## Harness-Introspektion: Flache Fuzzer früh erkennen

Wenn eine Kampagne ins Stocken gerät, liegt das Problem oft nicht am Mutator, sondern am **Harness**. Nutze **Reachability-/Coverage-Introspektion**, um Funktionen zu finden, die statisch von deinem Fuzz-Target aus erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Solche Funktionen weisen normalerweise auf eines von drei Problemen hin.<sup>[[12]](#references)</sup>

- Der Harness steigt zu spät oder zu früh in das Target ein.
- Im Seed-Corpus fehlt eine ganze Feature-Familie.
- Das Target benötigt tatsächlich einen **zweiten Harness** statt eines übergroßen „Alles-erledigen“-Harnesses.

Wenn du Workflows im Stil von OSS-Fuzz / ClusterFuzz verwendest, kann Fuzz Introspector die statische Erreichbarkeit mit der Laufzeit-Coverage vergleichen und Berichte aus einem zeitlich begrenzten Run oder einem öffentlichen Corpus erstellen.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Verwende den Bericht, um zu entscheiden, ob du einen neuen Harness für einen nicht getesteten Parserpfad hinzufügen, das Corpus für ein bestimmtes Feature erweitern oder einen monolithischen Harness in kleinere Einstiegspunkte aufteilen solltest.

## Graph-first Auswahl von Fuzz-Zielen und Mutationstriage

Wenn dir bereits **Ergebnisse der statischen Analyse**, **überlebende Mutationen** und **Coverage-Berichte** vorliegen, solltest du sie nicht als unabhängige Listen triagieren. Erstelle zuerst einen **Call Graph**, ergänze die Knoten um **zyklomatische Komplexität**, **Erreichbarkeit über Einstiegspunkte oder nicht vertrauenswürdige Eingaben** sowie externe Findings und stelle anschließend Fragen zum Graphen.<sup>[[5]](#references)[[6]](#references)</sup>

- Welche Funktionen mit hoher Komplexität sind über nicht vertrauenswürdige Eingaben erreichbar?
- Welche überlebenden Mutationen liegen auf Pfaden von Parsern oder Handlern zu sicherheitskritischem Code?
- Welche Funktionen sind architektonische Engpässe mit ungewöhnlich großer **Blast Radius**?

So findest du in der Regel bessere Fuzz-Ziele als allein anhand der „niedrigsten Coverage“. Ein Parser/Decoder mit **hoher Komplexität** und bestätigter **externer Erreichbarkeit** eignet sich besser als ein isolierter interner Helper mit geringer Coverage, aber ohne vom Angreifer kontrollierbaren Pfad.

### Praktischer Triage-Workflow

1. Erstelle aus der Codebasis einen **Code-Graphen** und ermittle für jede Funktion Metriken zu Komplexität und Verzweigungen.
2. Liste **Einstiegspunkte** auf, die vom Angreifer kontrollierte Eingaben annehmen: Request-Handler, Decoder, Importer, Protokoll-Parser, CLI-/Datei-Reader.
3. Führe **Pfadabfragen** von diesen Einstiegspunkten zu potenziellen Funktionen aus, um erreichbare Angriffsfläche von totem oder ausschließlich internem Code zu trennen.
4. Priorisiere Knoten, die Folgendes vereinen:
   - hohe **zyklomatische Komplexität**
   - bestätigte **Erreichbarkeit über nicht vertrauenswürdige Eingaben**
   - große **Blast Radius** oder viele abhängige Funktionen
   - bestätigende Hinweise wie **SARIF**-Findings, Audit-Notizen oder überlebende Mutationen
5. Schreibe zuerst gezielte Harnesses für die am besten bewerteten Knoten, insbesondere für **Parser/Codecs** wie Hex-, Base64-, IP- und Message-Decoder.

### Überlebende Mutationen: äquivalent oder relevant

Mutation Testing liefert oft eine verrauschte Liste überlebender Mutationen. Bevor du jede einzelne als Sicherheitslücke behandelst, nutze den Graphen und frage:

- Ist die mutierte Funktion über einen vom Angreifer kontrollierten Einstiegspunkt erreichbar?
- Sind alle Aufrufpfade durch stärkere Invarianten eingeschränkt als durch die mutierte Prüfung?
- Befindet sich der Knoten in totem Code, rein formatierungsbezogener Logik oder einem wirkungsstarken arithmetischen bzw. Parserpfad?

Überlebende Mutationen, die unerreichbar oder strukturell eingeschränkt bleiben, sind oft **äquivalente Mutanten**. Mutationen, die **erreichbar** bleiben und **Grenzfälle**, **Overflow-/Carry-Pfade** oder **sicherheitskritische Arithmetik bzw. Parsing** betreffen, solltest du in Folgendes aufnehmen:

- neue Fuzz-Harnesses
- direkte Property-/Invarianten-Tests
- gezielte Edge-Case-Testvektoren

### Externe Findings auf den Graphen abbilden

Wenn deine SAST-Pipeline **SARIF** exportiert, ordne Findings anhand von **Datei und Zeilenbereich** den Graphknoten zu und nutze den Graphen, um die Auswirkungen zu erweitern.<sup>[[6]](#references)</sup>

- Ermittle die **Blast Radius** der betroffenen Funktion.
- Prüfe, ob das Finding auf einem Pfad von einem Einstiegspunkt liegt.
- Gruppiere nahe beieinanderliegende Findings, die auf denselben Engpass hinauslaufen.

Das ist hilfreich, wenn du entscheiden willst, ob du Zeit in das Fuzzing einer bestimmten Funktion investieren solltest: Ein Knoten, der **erreichbar** und **komplex** ist und bereits **SAST-Treffer** aufweist, ist oft ein besseres Ziel als ein lediglich komplexer Knoten ohne Angreiferpfad.

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

Die wichtige Methodik ist die Schnittmenge: **Komplexität x Angriffsfläche x Auswirkung**. Nutze das Diagramm, um Fuzzing-Ziele mit dem höchsten erwarteten Sicherheitswert auszuwählen, und verwende überlebende Mutationen, um zu bestimmen, welche Grenzen und Invarianten dein Harness gezielt prüfen muss.<sup>[[5]](#references)</sup>

## Go-Fuzzing mit gosentry: Leistungsstärkere Engine, typisierte Eingaben und Differentialprüfungen

Wenn ein Go-Ziel bereits über ein natives `testing.F`-Harness verfügt, ist es ein praktikabler Upgrade-Pfad, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen: einer geforkten Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend durch **LibAFL** ersetzt.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Dies ist nützlich, wenn der native Go-Fuzzer bei **schwierigen Vergleichen**, **typisierten Eingaben** oder **parserlastigen Formaten** ins Stocken gerät. Die Methodik bleibt dieselbe:

- Verwende weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback.
- Verwende denselben Harness, führe ihn aber mit gosentrys `go`-Binary statt mit der Standard-Toolchain aus.
- Behandle die resultierende Kampagne wie einen normalen coverage-guided Run, jedoch mit LibAFL-Scheduling und -Mutation sowie besseren umgebenden Detektoren.

### Stille Fehler in Fuzzing-Funde umwandeln

Ein wiederkehrendes Problem bei Go-Assessments ist, dass gefährliches Verhalten standardmäßig oft **keinen** Absturz verursacht. Mit gosentry kannst du mehrere Arten von „schlechten, aber stillen“ Zuständen zu Funden machen.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, damit ausgewählte Logging-/Fehlerpfade sich wie Abstürze verhalten (nützlich für `log.Fatal`-artige Codepfade, die andernfalls nur protokollieren und fortfahren).
- `--catch-races=true`, um neu entdeckte Queue-Einträge mit dem Go-Race-Detector erneut auszuführen.
- `--catch-leaks=true`, um neue Queue-Einträge mit `goleak` erneut auszuführen und bei Goroutine-Leaks abzubrechen.
- LibAFL-Hang-Behandlung, damit **Endlosschleifen / sehr langsame Eingaben** als Fuzzing-Funde erhalten bleiben, anstatt als Timeouts zu verschwinden.
- Standardmäßig integrierte Prüfungen auf arithmetischen Overflow sowie optionale Truncation-Prüfungen durch go-panikint-artige Instrumentierung.

Das ist besonders wertvoll bei Zielen, bei denen die Sicherheitsauswirkung eher ein **Parserfehler ohne Panic**, ein **Nebenläufigkeitsfehler** oder ein **DoS-Hänger** als eine Speicherbeschädigung ist.

### Struct-aware Fuzzing für typisierte Go-APIs

Natives Go-Fuzzing erwartet hauptsächlich Skalare wie `[]byte`, `string` und Zahlen. Wenn der getestete Code typisierte Objekte verarbeitet, kann gosentry **zusammengesetzte Werte** direkt fuzzing-basiert testen (Structs, Slices, Arrays, Pointer) und dabei weiterhin die zugrunde liegenden Bytes mutieren.<sup>[[7]](#references)[[8]](#references)</sup>

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

Wenn du beim Fuzzing ein gefälschtes Wire-Format verwendest, würde dies Logikfehler hinter Parsing-Code verbergen, der nur im Harness vorhanden ist. Bei Differential- oder grammatikbasierten Kampagnen sollte die Harness-Eingabe ein einzelnes `[]byte` oder `string` sein; parse sie stattdessen innerhalb des Callbacks.

### Grammatikbasiertes Fuzzing für Parser und Protokolleingaben

Für Parser, Formate und Eingabesprachen kann gosentry **Nautilus-Grammatik-Fuzzing** auf LibAFL ausführen. Die Grammatik ist ein JSON-Array mit Produktionsregeln, und das Harness sollte in der Regel ein einzelnes Argument vom Typ `[]byte` oder `string` annehmen.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodik-Notizen:

- Verwende den Grammar-Modus, wenn Byte-Level-Mutationen größtenteils bereits an frühen Syntaxprüfungen scheitern.
- Halte die Grammatik auf die **sicherheitsrelevante Teilmenge** der Sprache/des Protokolls beschränkt, statt die vollständige Spezifikation abzubilden.
- Verwende große Grenzwerte in Terminals/Nichtterminals, um Integer-, Längen- und Zustandsmaschinen-Grenzfälle zu testen.
- Der Grammar-Modus hält Eingaben grammatikalisch gültig, aber das Ziel erhält weiterhin **Bytes/Strings**; Parsing und semantische Prüfungen bleiben daher im instrumentierten Code.

### Differential Fuzzing: Implementierungen vergleichen, nicht nur Abstürze

Ein wirkungsvolles Muster für Go-Ökosysteme ist **grammar-based differential fuzzing**: gültige, strukturierte Eingaben generieren und sie an zwei Parser, Clients oder Zustandsübergangs-Engines übergeben.<sup>[[7]](#references)[[8]](#references)</sup>

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

Betrachte Folgendes als Befunde:

- Eine Implementierung löst eine Panic aus, während die andere die Eingabe sauber zurückweist
- Abweichungen bei akzeptierten/zurückgewiesenen Eingaben
- Unterschiedliche Parse-Bäume oder dekodierte Objekte
- Abweichende Zustandsübergänge, Nonces, Kontostände oder State Roots

So lassen sich **Konsensabweichungen**, **Parser-Mehrdeutigkeiten** und **Abweichungen zwischen Spezifikation und Implementierung** auf praktische Weise finden, die beim reinen Crash-Fuzzing oft unentdeckt bleiben.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Das Kampagnen-Corpus für die Coverage-Berichterstellung wiederverwenden

Spiele nach einer Kampagne das gespeicherte Queue-Corpus erneut ab, um einen Go-Coverage-Bericht zu erstellen, ohne manuell ein separates Corpus exportieren zu müssen.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Führe den Befehl im **selben Package** und mit demselben **`-fuzz`-Ziel** aus, damit gosentry den richtigen gecachten Campaign-Status auflöst.



## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing im Detail](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet fünf Jahre später: Coverage-gesteuertes Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark wandelt Code in Graphen um](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-Fuzzing fehlte die Hälfte des Toolkits. Wir haben die Toolchain geforkt, um das zu beheben.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ein schneller Greybox-Fuzzer für zustandsbehaftete Netzwerkprotokolle mit Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Keine Grammatik, kein Problem: Fuzzing des Linux-Kernels ohne Systemaufrufbeschreibungen](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Effizientes Fuzzing mit adaptiven und veränderbaren Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM-Instrumentierung: Pfad- und Caller-Coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prädiktives kontextsensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog – Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder-Fuzzer – Dokumentation zum Build und zu Regression-Seeds](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Untersuchung von Race Conditions im Linux-Kernel mit kontrollierten Speicherzugriffsverschachtelungen](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: Code-Coverage für Fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
