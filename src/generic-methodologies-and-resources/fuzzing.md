# Fuzzing-Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantik

Beim **mutational grammar fuzzing** werden Eingaben mutiert, während sie **grammar-valid** bleiben. Im Coverage-guided-Modus werden nur Samples, die **neue Coverage** auslösen, als Corpus-Seeds gespeichert. Bei **Language-Targets** (Parsern, Interpretern, Engines) können dadurch Bugs übersehen werden, die **semantische/dataflow-Ketten** erfordern, bei denen die Ausgabe eines Konstrukts zur Eingabe eines anderen wird.

**Fehlermodus:** Der Fuzzer findet Seeds, die einzeln `document()` und `generate-id()` (oder ähnliche Primitives) ausführen, **bewahrt jedoch den verketteten Dataflow nicht**, sodass das dem Bug „nähere“ Sample verworfen wird, weil es keine Coverage hinzufügt. Bei **3+ abhängigen Schritten** wird zufällige Rekombination teuer, und das Coverage-Feedback steuert die Suche nicht.

**Implikation:** Bei Grammars mit vielen Abhängigkeiten sollte man **mutationale und generative Phasen hybridisieren** oder die Generierung in Richtung von **function-chaining**-Mustern lenken (nicht nur in Richtung Coverage).<sup>[[1]](#references)</sup>

## Fallstricke bei der Corpus-Diversität

Coverage-guided Mutation ist **greedy**: Ein Sample mit neuer Coverage wird sofort gespeichert und behält häufig große unveränderte Bereiche. Mit der Zeit bestehen Corpora aus **Near-Duplicates** mit geringer struktureller Diversität. Aggressive Minimierung kann nützlichen Kontext entfernen. Ein praktischer Kompromiss ist daher eine **grammar-aware Minimierung**, die **nach Erreichen eines Mindestschwellenwerts für Tokens stoppt** (Rauschen reduzieren und gleichzeitig genug umgebende Struktur erhalten, damit Mutationen sinnvoll bleiben).<sup>[[1]](#references)</sup>

Eine praktische Corpus-Regel für mutational fuzzing lautet: **Eine kleine Menge strukturell unterschiedlicher Seeds bevorzugen, die die Coverage maximiert**, statt eines großen Haufens an Near-Duplicates. In der Praxis bedeutet das normalerweise:<sup>[[1]](#references)</sup>

- Mit **real-world Samples** beginnen (öffentliche Corpora, Crawling, erfasster Traffic, Dateisammlungen aus dem Ökosystem des Targets).
- Sie mithilfe einer **coverage-basierten Corpus-Minimierung** reduzieren, statt jedes valide Sample zu behalten.
- Seeds **klein genug** halten, damit Mutationen auf sinnvolle Felder treffen, anstatt den Großteil der Zyklen auf irrelevante Bytes zu verwenden.
- Die Corpus-Minimierung nach größeren Änderungen am Harness oder an der Instrumentierung erneut ausführen, da sich die „beste“ Corpus-Zusammenstellung ändert, wenn sich die Erreichbarkeit ändert.

## Comparison-Aware Mutation Für Magic Values

Ein häufiger Grund dafür, dass Fuzzer stagnieren, ist nicht die Syntax, sondern das Vorhandensein von **harten Vergleichen**: Magic Bytes, Längenprüfungen, Enum-Strings, Checksummen oder Parser-Dispatch-Werte, die durch `memcmp`, Switch-Tabellen oder Kaskaden von Vergleichen geschützt sind. Reine zufällige Mutation verschwendet Zyklen damit, diese Werte Byte für Byte zu erraten.

Für solche Targets sollte **Comparison Tracing** verwendet werden (beispielsweise AFL++ `CMPLOG`- oder Redqueen-ähnliche Workflows), damit der Fuzzer Operanden aus fehlgeschlagenen Vergleichen beobachten und Mutationen in Richtung von Werten lenken kann, die diese Vergleiche erfüllen.<sup>[[3]](#references)</sup>
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

- Dies ist besonders nützlich, wenn das Ziel tiefe Logik hinter **file signatures**, **protocol verbs**, **type tags** oder **version-dependent feature bits** verbirgt.
- Kombiniere es mit **dictionaries**, die aus echten Samples, Protokollspezifikationen oder Debug-Logs extrahiert wurden. Ein kleines Dictionary mit Grammatik-Tokens, Chunk-Namen, Verben und Delimitern ist oft wertvoller als eine riesige generische Wordlist.
- Wenn das Ziel viele sequenzielle Checks durchführt, löse zuerst die frühesten „magic“-Vergleiche und minimiere anschließend die resultierende Corpus erneut, damit spätere Stufen bereits mit gültigen Prefixes beginnen.

## Stateful Fuzzing: Sequences Are Seeds

Bei **protocols**, **authenticated workflows** und **multi-stage parsers** ist die interessante Einheit häufig nicht ein einzelner Blob, sondern eine **message sequence**. Das gesamte Transcript in eine Datei zu konkatenieren und blind zu mutieren, ist gewöhnlich ineffizient, da der Fuzzer jeden Schritt gleichermaßen mutiert, selbst wenn nur die spätere Nachricht den fragilen Zustand erreicht.

Ein effektiveres Muster besteht darin, die **sequence selbst als seed** zu behandeln und **observable state** (Response-Codes, Protokollzustände, Parser-Phasen, zurückgegebene Objekttypen) als zusätzliches Feedback zu verwenden:<sup>[[4]](#references)</sup>

- Halte **valid prefix messages** stabil und konzentriere Mutationen auf die **transition-driving**-Nachricht.
- Cache Identifiers und vom Server generierte Werte aus vorherigen Responses, wenn der nächste Schritt von ihnen abhängt.
- Bevorzuge Mutation/Splicing pro Message gegenüber der Mutation des gesamten serialisierten Transcripts als opaque Blob.
- Wenn das Protokoll aussagekräftige Response-Codes bereitstellt, verwende sie als **cheap state oracle**, um Sequences zu priorisieren, die tiefer vordringen.

Aus demselben Grund werden authenticated Bugs, versteckte Transitions oder Parser-Bugs, die „only-after-handshake“ auftreten, vom gewöhnlichen File-style Fuzzing häufig übersehen: Der Fuzzer muss **Reihenfolge, Zustand und Abhängigkeiten** bewahren, nicht nur die Struktur.

## Single-Machine Diversity Trick (Jackalope-Style)

Eine praktische Möglichkeit, **generative novelty** mit **coverage reuse** zu kombinieren, besteht darin, kurzlebige Worker gegen einen persistenten Server neu zu starten. Jeder Worker beginnt mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden mit dem kombinierten Corpus, synchronisiert erneut und beendet sich anschließend. Dadurch entstehen **fresh structures each generation**, während gleichzeitig die gesammelte Coverage genutzt wird.<sup>[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequentielle Worker (Beispielschleife):**

<details>
<summary>Neustartschleife des Jackalope-Workers</summary>
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

- `-in empty` erzwingt bei jeder Generation ein **neues Corpus**.
- `-server_update_interval T` approximiert **verzögerte Synchronisierung** (zuerst neue Ergebnisse, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird die **initiale Server-Synchronisierung** standardmäßig übersprungen (kein `-skip_initial_server_sync` erforderlich).
- Das optimale `T` ist **zielabhängig**; ein Wechsel, nachdem der Worker den größten Teil der „einfachen“ Coverage gefunden hat, funktioniert in der Regel am besten.

## Snapshot Fuzzing für schwer zu harnessende Ziele

Wenn der zu testende Code erst **nach hohen Initialisierungskosten** erreichbar wird (Booten einer VM, Abschließen eines Logins, Empfangen eines Pakets, Parsen eines Containers, Initialisieren eines Dienstes), ist **Snapshot Fuzzing** eine nützliche Alternative:

1. Führe das Ziel aus, bis der interessante Zustand bereit ist.
2. Erstelle an diesem Punkt einen Snapshot von **Speicher + Registern**.
3. Schreibe für jeden Testfall den mutierten Input direkt in den relevanten Guest-/Prozess-Buffer.
4. Führe die Ausführung bis zu einem Crash/Timeout/Reset fort.
5. Stelle nur die **veränderten Pages** wieder her und wiederhole den Vorgang.

Dadurch entfallen die vollständigen Initialisierungskosten bei jeder Iteration. Das ist besonders nützlich für **Network Services**, **Firmware**, **Post-Auth-Angriffsflächen** und **binäre Ziele**, die sich nur schwer in ein klassisches In-Process-Harness umstrukturieren lassen.

Ein praktischer Trick besteht darin, direkt nach einem `recv`-/`read`-/Packet-Deserialisierungs-Punkt zu unterbrechen, die Adresse des Input-Buffers zu notieren, dort einen Snapshot zu erstellen und anschließend diesen Buffer in jeder Iteration direkt zu mutieren. So kannst du die tiefe Parsing-Logik fuzzing, ohne jedes Mal den gesamten Handshake neu aufzubauen.

## Harness Introspection: Flache Fuzzer früh erkennen

Wenn eine Kampagne ins Stocken gerät, liegt das Problem häufig nicht am Mutator, sondern am **Harness**. Verwende **Reachability-/Coverage-Introspection**, um Funktionen zu finden, die statisch von deinem Fuzz-Target aus erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Diese Funktionen weisen normalerweise auf eines von drei Problemen hin:

- Das Harness tritt zu spät oder zu früh in das Ziel ein.
- Dem Seed-Corpus fehlt eine gesamte Feature-Familie.
- Das Ziel benötigt tatsächlich ein **zweites Harness** anstelle eines übergroßen „Alles-erledigen“-Harness.

Wenn du OSS-Fuzz-/ClusterFuzz-ähnliche Workflows verwendest, ist Fuzz Introspector für diese Triage nützlich:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Nutze den Bericht, um zu entscheiden, ob du einen neuen Harness für einen bisher nicht getesteten Parser-Pfad hinzufügen, die Corpus für ein bestimmtes Feature erweitern oder einen monolithischen Harness in kleinere Entry-Points aufteilen solltest.

## Graph-First Fuzz Target Selection And Mutation Triage

Wenn bereits **static-analysis findings**, **mutation-testing survivors** und **coverage reports** vorliegen, solltest du sie nicht als unabhängige Listen triagieren. Erstelle zuerst einen **call graph**, annotiere die Nodes mit **cyclomatic complexity**, **entrypoint/untrusted-input reachability** und allen externen Findings und stelle anschließend Fragen zum Graphen:<sup>[[5]](#references)[[6]](#references)</sup>

- Welche Funktionen mit hoher Komplexität sind von untrusted input aus erreichbar?
- Welche mutation survivors liegen auf Pfaden von Parsern/Handlern zu security-critical code?
- Welche Funktionen sind architektonische Engpässe mit ungewöhnlich großer **blast radius**?

Dadurch werden meist bessere Fuzz Targets sichtbar als allein durch die "niedrigste Coverage". Ein Parser/Decoder mit **high complexity** und bestätigter **external reachability** ist ein besserer Kandidat für einen Harness als ein isolierter interner Helper mit schwacher Coverage, aber ohne attacker-controlled path.

### Praktischer Triage-Workflow

1. Erstelle einen **code graph** aus der Codebase und ermittle Complexity-/Branch-Metriken pro Funktion.
2. Liste **entrypoints** auf, die attacker-controlled input akzeptieren: Request-Handler, Decoder, Importer, Protocol-Parser, CLI-/File-Reader.
3. Führe **path queries** von diesen Entry-Points zu den Kandidatenfunktionen aus, um erreichbare Attack Surface von internem oder totem Code zu trennen.
4. Priorisiere Nodes, die Folgendes kombinieren:
- hohe **cyclomatic complexity**
- bestätigte **reachability from untrusted input**
- große **blast radius** oder viele nachgelagerte Dependents
- zusätzliche Hinweise wie **SARIF**-Findings, Audit-Notizen oder mutation survivors
5. Schreibe zuerst fokussierte Harnesses für die am besten bewerteten Nodes, insbesondere für **parsers/codecs** wie Hex-/Base64-/IP-/Message-Decoder.

### Mutation Survivors: Equivalent vs Actionable

Mutation Testing erzeugt häufig eine verrauschte Liste von Survivors. Bevor du jeden Survivor als Security-Lücke behandelst, nutze den Graphen für folgende Fragen:

- Ist die mutierte Funktion von einem attacker-controlled entrypoint aus erreichbar?
- Sind alle Call Paths durch stärkere Invarianten eingeschränkt als der mutierte Check?
- Befindet sich der Node in totem Code, ausschließlich für Formatting zuständiger Logik oder in einem wirkungsstarken Arithmetic-/Parser-Pfad?

Survivors, die weiterhin nicht erreichbar oder strukturell eingeschränkt sind, sind häufig **equivalent mutants**. Survivors, die **reachable** bleiben und **boundary conditions**, **overflow/carry paths** oder **security-critical arithmetic/parsing** betreffen, sollten in Folgendes überführt werden:

- neue Fuzz-Harnesses
- direkte Property-/Invariant-Tests
- gezielte Edge-Case-Vektoren

### Externe Findings auf den Graphen abbilden

Wenn deine SAST-Pipeline **SARIF** exportiert, projiziere die Findings anhand von **file + line range** auf die Graph-Nodes und nutze den Graphen, um die Auswirkungen zu erweitern:

- Berechne die **blast radius** der markierten Funktion.
- Prüfe, ob das Finding auf einem Pfad von einem Entrypoint liegt.
- Gruppiere nahe beieinander liegende Findings, die auf denselben Choke Point zusammenlaufen.

Das ist hilfreich, wenn du entscheiden musst, ob du Fuzzing-Zeit in eine bestimmte Funktion investieren solltest: Ein Node, der **reachable**, komplex ist und bereits **SAST hits** aufweist, ist häufig ein besseres Target als ein lediglich komplexer Node ohne Angreiferpfad.

Beispiel-Workflow mit Trailmark:<sup>[[6]](#references)</sup>
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
Die wichtige Methodik ist die Schnittmenge: **Komplexität x Exposure x Auswirkung**. Verwende das Diagramm, um Fuzz-Ziele mit dem höchsten erwarteten Sicherheitswert auszuwählen, und nutze anschließend die Mutation-Survivors, um zu bestimmen, welche Grenzen und Invarianten dein Harness stressen muss.

## Go Fuzzing mit gosentry: Stärkerer Engine, typisierte Inputs und differentielle Checks

Wenn ein Go-Ziel bereits über ein natives `testing.F`-Harness verfügt, besteht ein praktischer Upgrade-Pfad darin, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen, einer geforkten Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend auf **LibAFL** umstellt.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Dies ist nützlich, wenn der native Go fuzzer bei **hard comparisons**, **typed inputs** oder **parser-heavy formats** ins Stocken gerät. Die Methodik bleibt gleich:

- Verwende weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback.
- Verwende denselben Harness erneut, führe ihn aber mit der `go`-Binary von gosentry statt mit der standardmäßigen Toolchain aus.
- Behandle die resultierende Campaign wie einen normalen coverage-guided Run, jedoch mit LibAFL-Scheduling/Mutation und besseren umgebenden Detektoren.

### Stille Fehler in Fuzzing-Funde umwandeln

Ein wiederkehrendes Problem bei Go-Assessments besteht darin, dass gefährliches Verhalten standardmäßig oft **keinen** Crash verursacht. Mit gosentry kannst du mehrere Klassen von „schlechten, aber stillen“ Zuständen in Findings umwandeln:

- `--panic-on=pkg.Func,...`, damit ausgewählte Logging-/Error-Pfade wie Crashes behandelt werden (nützlich für `log.Fatal`-artige Codepfade, die andernfalls nur loggen und fortfahren).
- `--catch-races=true`, um neu entdeckte Queue-Einträge mit dem Go race detector erneut auszuführen.
- `--catch-leaks=true`, um neue Queue-Einträge mit `goleak` erneut auszuführen und bei Goroutine-Leaks zu stoppen.
- LibAFL-Hang-Handling, damit **infinite loops / very slow inputs** als Fuzzing-Funde erhalten bleiben, statt als Timeouts zu verschwinden.
- Standardmäßig integrierte Checks auf arithmetische Overflows sowie optionale Truncation-Checks durch Instrumentierung im Stil von go-panikint.

Dies ist besonders wertvoll für Targets, bei denen die Security-Auswirkung eher in einem **panicless parser failure**, einem **concurrency bug** oder einem **DoS-only hang** als in Memory Corruption besteht.

### Struct-aware Fuzzing für typisierte Go-APIs

Native Go fuzzing erwartet hauptsächlich Skalare wie `[]byte`, `string` und Zahlen. Wenn der getestete Code typisierte Objekte verarbeitet, kann gosentry **composite values** direkt fuzzing unterziehen (Structs, Slices, Arrays, Pointer) und gleichzeitig weiterhin die zugrunde liegenden Bytes mutieren.
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
Verwende dies, wenn beim Erstellen eines gefälschten Wire-Formats nur für Fuzzing Logikfehler hinter ausschließlich im Harness vorhandener Parsing-Logik verbergen würde. Für differentielle oder grammatikbasierte Kampagnen sollte der Harness-Input als einzelnes `[]byte` oder als `string` beibehalten und stattdessen innerhalb des Callbacks geparst werden.

### Grammatikbasiertes Fuzzing für Parser und Protokoll-Inputs

Für Parser, Formate und Input-Sprachen kann gosentry **Nautilus grammar fuzzing** auf LibAFL ausführen. Die Grammatik ist ein JSON-Array aus Produktionsregeln, und der Harness sollte normalerweise ein einzelnes `[]byte`- oder `string`-Argument entgegennehmen.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodiknotizen:

- Verwende den grammar mode, wenn Mutationen auf Byte-Ebene größtenteils an frühen Syntaxprüfungen scheitern.
- Halte die Grammar auf die **sicherheitsrelevante Teilmenge** der Sprache/des Protokolls fokussiert, anstatt die vollständige Spezifikation zu modellieren.
- Verwende große Grenzwerte in Terminals/Nichtterminals, um Integer-, Längen- und Zustandsmaschinen-Grenzfälle zu stressen.
- Der grammar mode hält Inputs grammatikalisch valide, aber das Ziel empfängt weiterhin **Bytes/Strings**, sodass Parsing- und semantische Prüfungen innerhalb des instrumentierten Codes verbleiben.

### Differential fuzzing: Implementierungen vergleichen, nicht nur Crashes

Ein starkes Muster für Go-Ökosysteme ist **grammar-based differential fuzzing**: Erzeuge valide strukturierte Inputs und übergib sie an zwei Parser, Clients oder Zustandsübergangs-Engines.
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

- eine Implementierung gerät in einen Panic, während die andere die Eingabe sauber ablehnt
- Abweichungen zwischen akzeptierten und abgelehnten Eingaben
- unterschiedliche Parse-Trees oder decodierte Objekte
- abweichende Zustandsübergänge, Nonces, Salden oder State Roots

Dies ist eine praktische Möglichkeit, **Konsensabweichungen**, **Parser-Ambiguität** und **Abweichungen zwischen Spezifikation und Implementierung** zu finden, die reines Crash-Fuzzing häufig nicht erkennt.

### Das Kampagnen-Corpus für Coverage-Reports wiederverwenden

Spiele nach einer Kampagne das gespeicherte Queue-Corpus erneut ab, um einen Go-Coverage-Report zu erstellen, ohne manuell ein separates Corpus zu exportieren:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Führe den Befehl aus dem **gleichen Package** und mit demselben **`-fuzz`-Target** aus, damit gosentry den richtigen gecachten Campaign-Status auflöst.

## Referenzen

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
