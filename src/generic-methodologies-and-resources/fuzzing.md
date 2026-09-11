# Fuzzing-Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantik

Beim **mutational grammar fuzzing** werden Inputs mutiert, während sie **grammar-valid** bleiben. Im coverage-guided-Modus werden nur Samples als Corpus-Seeds gespeichert, die eine **neue Coverage** auslösen. Bei **Language Targets** (Parsern, Interpretern, Engines) können dadurch Bugs übersehen werden, die **semantische Datenflussketten** erfordern, bei denen die Ausgabe eines Constructs zum Input eines anderen wird.<sup>[[1]](#references)</sup>

**Fehlermodus:** Der Fuzzer findet Seeds, die jeweils einzeln `document()` und `generate-id()` (oder ähnliche Primitives) ausführen, **erhält jedoch den verketteten Datenfluss nicht**, sodass das „bug-nähere“ Sample verworfen wird, weil es keine zusätzliche Coverage erzeugt. Bei **3+ abhängigen Schritten** wird zufällige Rekombination teuer, und Coverage-Feedback lenkt die Suche nicht.<sup>[[1]](#references)</sup>

**Implikation:** Bei grammars mit vielen Abhängigkeiten sollte man **mutationale und generative Phasen hybridisieren** oder die Generierung auf **Function-Chaining**-Muster ausrichten (nicht nur auf Coverage).<sup>[[1]](#references)</sup>

## Fallstricke bei der Corpus-Diversität

Coverage-guided Mutation ist **gierig**: Ein Sample mit neuer Coverage wird sofort gespeichert und enthält häufig große unveränderte Bereiche. Mit der Zeit bestehen Corpora aus **nahezu identischen Samples** mit geringer struktureller Diversität. Aggressive Minimierung kann nützlichen Kontext entfernen. Ein praktikabler Kompromiss ist daher eine **grammar-aware Minimierung**, die **nach Erreichen eines minimalen Token-Schwellenwerts stoppt** (Rauschen reduzieren und gleichzeitig genügend umgebende Struktur erhalten, damit weitere Mutationen sinnvoll bleiben).<sup>[[1]](#references)</sup>

Eine praktische Corpus-Regel für mutational fuzzing lautet: **Eine kleine Menge strukturell unterschiedlicher Seeds bevorzugen, die die Coverage maximiert**, statt eine große Ansammlung nahezu identischer Samples zu behalten. In der Praxis bedeutet das in der Regel Folgendes.<sup>[[1]](#references)[[3]](#references)</sup>

- Mit **realen Samples** beginnen (öffentliche Corpora, Crawling, aufgezeichneter Traffic, Dateisammlungen aus dem Ökosystem des Targets).
- Sie durch **coverage-basierte Corpus-Minimierung** reduzieren, statt jedes valide Sample zu behalten.
- Seeds **klein genug** halten, damit Mutationen auf bedeutungsvollen Feldern landen, anstatt die meisten Zyklen mit irrelevanten Bytes zu verbringen.
- Die Corpus-Minimierung nach größeren Änderungen an Harness oder Instrumentierung erneut ausführen, da sich das „beste“ Corpus ändert, wenn sich die Erreichbarkeit ändert.

## Comparison-Aware Mutation Für Magic Values

Ein häufiger Grund dafür, dass Fuzzer stagnieren, ist nicht die Syntax, sondern das Vorhandensein von **harten Vergleichen**: Magic Bytes, Längenprüfungen, Enum-Strings, Checksummen oder durch `memcmp`, Switch-Tabellen oder Kaskaden von Vergleichen geschützte Parser-Dispatch-Werte. Reine zufällige Mutation verschwendet Zyklen damit, diese Werte Byte für Byte zu erraten.

Für solche Targets sollte **Comparison Tracing** verwendet werden (beispielsweise AFL++-`CMPLOG`-/Redqueen-ähnliche Workflows), damit der Fuzzer Operanden aus fehlgeschlagenen Vergleichen beobachten und Mutationen auf Werte ausrichten kann, die diese Vergleiche erfüllen.<sup>[[3]](#references)</sup>
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
- Kombiniere dies mit **dictionaries**, die aus echten Samples, Protokollspezifikationen oder Debug-Logs extrahiert wurden. Ein kleines Dictionary mit Grammatik-Tokens, Chunk-Namen, Verben und Delimitern ist oft wertvoller als eine riesige generische Wordlist.
- Wenn das Ziel viele sequenzielle Prüfungen durchführt, löse zuerst die frühesten „magic“-Vergleiche und minimiere anschließend das resultierende Corpus erneut, damit spätere Stufen mit bereits gültigen Präfixen beginnen.

## Aussagekräftigeres Feedback, wenn Edge Coverage verschiedene Pfade zusammenfasst

Normale Edge Coverage kann zwei Ausführungen nicht unterscheiden, die denselben Helper über verschiedene Aufrufer durchlaufen oder innerhalb einer Funktion unterschiedliche Kombinationen von Branches nehmen. Dies ist bei gemeinsam verwendeten Decodern, Protokoll-Dispatchern und Interpreter-Helpern relevant, bei denen der **route** zu einer Edge den aktiven Zustand bestimmt. Jeden Aufrufkontext naiv zu verfolgen, ist ebenfalls gefährlich: Die Coverage Map und die Queue können explodieren. Die Forschung zu kontextsensitivem Fuzzing empfiehlt daher, nur vielversprechende Kontexte zu verfeinern, anstatt den gesamten Call Graph als kontextsensitiv zu behandeln.<sup>[[14]](#references)</sup>

Aktuelle AFL++-Builds bieten zusätzlich zur normalen Edge Coverage eine **Ball-Larus per-function path coverage**. Dabei wird jedem azyklischen Pfad durch eine Funktion ein Feature zugewiesen; Loop-Back-Edges werden entfernt, sodass dieses Feedback Branch-Kombinationen, **nicht jedoch die Anzahl der Loop-Iterationen** unterscheidet. Beginne mit dem lockeren Level `1` und beschränke strengere Modi anschließend auf verdächtigen Parser-/State-Machine-Code, da die Anzahl der Pfade exponentiell wachsen kann.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Für einen von vielen sicherheitsrelevanten Stellen aufgerufenen Helfer kann der LTO-Modus jeden Funktionspfad mit seiner unmittelbaren Aufrufstelle kombinieren:<sup>[[13]](#references)</sup>
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
**Kampagnenhinweis:** Wende reichhaltigeres Feedback vorsichtig an und überwache dessen Kosten für Coverage-Map und Queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Führe parallel eine gewöhnliche Edge-Coverage-Instanz aus; reichhaltigeres Feedback ist nur dann nützlich, wenn die zusätzlichen Queue-/Map-Kosten nicht die Anzahl der Ausführungen pro Sekunde beeinträchtigen.
- Verwende `AFL_LLVM_ALLOWLIST`, um die Instrumentierung von Pfaden und Aufrufern einzuschränken, wenn große template-lastige Bibliotheken oder generischer Utility-Code die Map dominieren.
- Funktionen mit übermäßig vielen azyklischen Pfaden können in AFL++ übersprungen werden; Warnungen während der Kompilierung sind ein Hinweis darauf, dass das Ziel Allowlisting oder eine weniger strenge Stufe benötigt.
- Caller + path coverage unterstützt nur eine Aufruftiefe. Kombiniere es nicht mit tieferen Context-Stacks.
- Path-IDs können sich zwischen größeren LLVM-Versionen ändern. Halte die Toolchain für eine Kampagne unverändert und synchronisiere PATH-basierte Corpora nicht so, als wären ihre Feature-IDs buildübergreifend stabil.
- Dieses Feedback ergänzt `CMPLOG`: Comparison Tracing ermittelt, **welcher Wert einen Guard passiert**, während Path-/Caller-Feedback bewahrt, **welche Routen- und Branch-Kombination ihn erreicht hat**.

## Stateful Fuzzing: Sequenzen sind Seeds

Bei **Protokollen**, **authentifizierten Workflows** und **mehrstufigen Parsern** ist die interessante Einheit oft kein einzelner Blob, sondern eine **Nachrichtenfolge**. Das gesamte Transkript in eine Datei zu konkatenieren und blind zu mutieren, ist gewöhnlich ineffizient, weil der Fuzzer jeden Schritt gleichermaßen mutiert, selbst wenn nur die spätere Nachricht den anfälligen Zustand erreicht.<sup>[[4]](#references)</sup>

Ein effektiveres Muster besteht darin, die **Sequenz selbst als Seed** zu behandeln und **beobachtbaren Zustand** (Response-Codes, Protokollzustände, Parserphasen, zurückgegebene Objekttypen) als zusätzliches Feedback zu verwenden.<sup>[[4]](#references)</sup>

- Halte **gültige Präfixnachrichten** stabil und konzentriere Mutationen auf die **den Übergang auslösende** Nachricht.
- Cache Identifikatoren und vom Server generierte Werte aus vorherigen Responses, wenn der nächste Schritt von ihnen abhängt.
- Bevorzuge Mutation/Splicing pro Nachricht gegenüber der Mutation des gesamten serialisierten Transkripts als opakem Blob.
- Wenn das Protokoll aussagekräftige Response-Codes bereitstellt, verwende sie als **kostengünstige Zustandsoracle**, um Sequenzen zu priorisieren, die tiefer vordringen.

Aus demselben Grund werden authentifizierte Bugs, verborgene Übergänge oder Parser-Bugs, die „erst nach dem Handshake“ auftreten, beim gewöhnlichen dateibasierten Fuzzing häufig übersehen: Der Fuzzer muss **Reihenfolge, Zustand und Abhängigkeiten** bewahren, nicht nur die Struktur.<sup>[[4]](#references)</sup>

## Diversitätstrick für eine einzelne Maschine (Jackalope-Stil)

Eine praktische Möglichkeit, **generative Neuartigkeit** mit der **Wiederverwendung von Coverage** zu kombinieren, besteht darin, kurzlebige Worker gegen einen persistenten Server neu zu starten. Jeder Worker beginnt mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden mit dem kombinierten Corpus, synchronisiert erneut und beendet sich anschließend. Dadurch entstehen **in jeder Generation neue Strukturen**, während die angesammelte Coverage weiterhin genutzt wird.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` approximiert **verzögerte Synchronisierung** (zuerst Neuheiten, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird die **initiale Server-Synchronisierung** standardmäßig übersprungen (kein Bedarf für `-skip_initial_server_sync`).
- Das optimale `T` ist **zielabhängig**; ein Wechsel, nachdem der Worker den größten Teil der „einfachen“ Coverage gefunden hat, funktioniert meist am besten.

## Snapshot Fuzzing Für Schwer Zu Erreichende Targets

Wenn der Code, den Sie testen möchten, erst **nach hohen Setup-Kosten** erreichbar wird (Booten einer VM, Abschließen eines Logins, Empfangen eines Pakets, Parsen eines Containers, Initialisieren eines Service), ist **Snapshot Fuzzing** eine nützliche Alternative: Erfassen Sie den bereiten Prozess- oder VM-Zustand, injizieren Sie jeden Testfall in den Input-Pfad des Targets, führen Sie die Ausführung bis zum Crash/Timeout fort und stellen Sie den Snapshot wieder her. Dadurch wird die wiederholte Initialisierung oder Wiederholung von Protokollpräfixen vermieden. Dies ist nützlich für **Netzwerkdienste**, **Firmware**, **Post-Auth-Angriffsflächen** und **binäre Targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Führen Sie das Target aus, bis der interessante Zustand bereit ist.
2. Erstellen Sie zu diesem Zeitpunkt einen Snapshot von **Speicher + Registern**.
3. Schreiben Sie für jeden Testfall den mutierten Input direkt in den relevanten Guest-/Prozesspuffer.
4. Führen Sie die Ausführung bis zum Crash/Timeout/Reset fort.
5. Stellen Sie den Snapshot wieder her; bei VM-Targets stellen Sie, sofern unterstützt, nur die **veränderten Seiten** wieder her und wiederholen Sie den Vorgang.

Platzieren Sie den Snapshot so nah wie praktisch möglich am ersten teuren Parse-/Dispatch-Schritt, beispielsweise nach einem `recv`-/`read`- oder Paket-Deserialisierungspunkt, und protokollieren Sie den vom Target verwendeten Input-Puffer. Dies folgt dem Prinzip der adaptiven Platzierung, den Snapshot tiefer in die Input-Verarbeitung zu verschieben, um die Wiederholung von Arbeit zu vermeiden.<sup>[[11]](#references)</sup>

## Harness-Introspektion: Flache Fuzzer Frühzeitig Finden

Wenn eine Kampagne ins Stocken gerät, liegt das Problem häufig nicht am Mutator, sondern am **Harness**. Verwenden Sie **Reachability-/Coverage-Introspektion**, um Funktionen zu finden, die von Ihrem Fuzz-Target aus statisch erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Diese Funktionen weisen normalerweise auf eines von drei Problemen hin.<sup>[[12]](#references)</sup>

- Der Harness betritt das Target zu spät oder zu früh.
- Im Seed-Corpus fehlt eine vollständige Feature-Familie.
- Das Target benötigt tatsächlich einen **zweiten Harness** anstelle eines überdimensionierten „Alles-erledigen“-Harness.

Wenn Sie OSS-Fuzz-/ClusterFuzz-ähnliche Workflows verwenden, kann Fuzz Introspector die statische Erreichbarkeit mit der Laufzeit-Coverage vergleichen und Reports aus einem zeitlich begrenzten Lauf oder einem öffentlichen Corpus generieren.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Verwende den Report, um zu entscheiden, ob ein neuer Harness für einen ungetesteten Parser-Pfad hinzugefügt, die Corpus für ein bestimmtes Feature erweitert oder ein monolithischer Harness in kleinere Entrypoints aufgeteilt werden soll.

## Graph-First-Auswahl von Fuzz Targets und Triage von Mutationen

Wenn bereits **Static-Analysis-Findings**, **Mutation-Testing-Survivors** und **Coverage-Reports** vorliegen, sollten diese nicht als voneinander unabhängige Listen behandelt werden. Erstelle zuerst einen **Call Graph**, annotiere die Nodes mit **Cyclomatic Complexity**, **Erreichbarkeit von Entrypoints ausgehend von Untrusted Input** und allen externen Findings und stelle anschließend Fragen zum Graphen.<sup>[[5]](#references)[[6]](#references)</sup>

- Welche Funktionen mit hoher Komplexität sind von Untrusted Input aus erreichbar?
- Welche Mutation Survivors liegen auf Pfaden von Parsern/Handlern zu Security-Critical Code?
- Welche Funktionen sind architektonische Choke Points mit ungewöhnlich hoher **Blast Radius**?

Dadurch werden meist bessere Fuzz Targets gefunden als allein durch die "niedrigste Coverage". Ein Parser/Decoder mit **hoher Komplexität** und bestätigter **externer Erreichbarkeit** ist ein stärkerer Kandidat für einen Harness als ein isolierter interner Helper mit schwacher Coverage, aber ohne vom Angreifer kontrollierten Pfad.

### Praktischer Triage-Workflow

1. Erstelle einen **Code Graph** aus der Codebasis und extrahiere Complexity-/Branch-Metriken pro Funktion.
2. Ermittle **Entrypoints**, die vom Angreifer kontrollierten Input akzeptieren: Request Handler, Decoder, Importer, Protocol Parser, CLI-/File-Reader.
3. Führe **Path Queries** von diesen Entrypoints zu Kandidatenfunktionen aus, um erreichbare Attack Surface von totem bzw. ausschließlich internem Code zu trennen.
4. Priorisiere Nodes, die Folgendes kombinieren:
- hohe **Cyclomatic Complexity**
- bestätigte **Erreichbarkeit ausgehend von Untrusted Input**
- hohe **Blast Radius** oder viele nachgelagerte Dependents
- unterstützende Hinweise wie **SARIF**-Findings, Audit Notes oder Mutation Survivors
5. Schreibe zuerst fokussierte Harnesses für die Nodes mit der höchsten Bewertung, insbesondere für **Parser/Codecs** wie Hex-/Base64-/IP-/Message-Decoder.

### Mutation Survivors: equivalent vs actionable

Mutation Testing erzeugt häufig eine verrauschte Survivor-Liste. Bevor jeder Survivor als Security Gap behandelt wird, sollte mithilfe des Graphen gefragt werden:

- Ist die mutierte Funktion von einem vom Angreifer kontrollierten Entrypoint aus erreichbar?
- Werden alle Call Paths durch stärkere Invariants als den mutierten Check eingeschränkt?
- Befindet sich der Node in totem Code, reinem Formatting-Code oder in einem Arithmetic-/Parser-Pfad mit hohen Auswirkungen?

Survivors, die weiterhin unerreichbar oder strukturell eingeschränkt sind, sind häufig **Equivalent Mutants**. Survivors, die **erreichbar** bleiben und **Boundary Conditions**, **Overflow-/Carry-Pfade** oder **Security-Critical Arithmetic/Parsing** betreffen, sollten aufgewertet werden zu:

- neuen Fuzz Harnesses
- direkten Property-/Invariant-Tests
- gezielten Edge-Case-Vektoren

### Externe Findings auf den Graphen korrelieren

Wenn die SAST-Pipeline **SARIF** exportiert, projiziere Findings anhand von **Datei + Zeilenbereich** auf Graph-Nodes und verwende den Graphen, um die Auswirkungen zu erweitern.<sup>[[6]](#references)</sup>

- Berechne die **Blast Radius** der markierten Funktion.
- Prüfe, ob das Finding auf einem Pfad von einem Entrypoint liegt.
- Clustere benachbarte Findings, die auf denselben Choke Point zusammenfallen.

Das ist nützlich, wenn entschieden werden soll, ob Fuzzing-Zeit in eine bestimmte Funktion investiert werden sollte: Ein Node, der **erreichbar** und **komplex** ist und bereits **SAST-Hits** aufweist, ist oft ein besseres Target als ein lediglich komplexer Node ohne Angreiferpfad.

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
Die wichtige Methodik ist die Schnittmenge aus: **Komplexität x Exposure x Impact**. Verwende das Diagramm, um Fuzz-Ziele mit dem höchsten erwarteten Sicherheitswert auszuwählen, und nutze anschließend die Mutation Survivors, um zu entscheiden, welche Grenzen und Invarianten dein Harness belasten muss.<sup>[[5]](#references)</sup>

## Go Fuzzing mit gosentry: Stärkerer Engine, typisierte Inputs und Differential Checks

Wenn ein Go-Ziel bereits über ein natives `testing.F`-Harness verfügt, besteht ein praktischer Upgrade-Pfad darin, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen, einer geforkten Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend gegen **LibAFL** austauscht.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Dies ist nützlich, wenn der native Go fuzzer bei **hard comparisons**, **typed inputs** oder **parser-heavy formats** ins Stocken gerät. Die Methodik bleibt gleich:

- Weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback verwenden.
- Dasselbe Harness wiederverwenden, es jedoch mit der gosentry-`go`-Binary statt mit der standardmäßigen Toolchain ausführen.
- Die resultierende Campaign als normalen coverage-guided Run behandeln, jedoch mit LibAFL-Scheduling/Mutation und besseren umgebenden Detectors.

### Stille Fehler in Fuzzing-Findings umwandeln

Ein wiederkehrendes Problem bei Go-Assessments besteht darin, dass gefährliches Verhalten standardmäßig oft **keinen** Crash verursacht. Mit gosentry können mehrere Klassen von „schlechten, aber stillen“ Zuständen in Findings umgewandelt werden.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, damit ausgewählte Logging-/Error-Pfade wie Crashs behandelt werden (nützlich für `log.Fatal`-artige Codepfade, die sonst nur loggen und fortfahren).
- `--catch-races=true`, um neu entdeckte Queue-Einträge mit dem Go race detector erneut auszuführen.
- `--catch-leaks=true`, um neue Queue-Einträge mit `goleak` erneut auszuführen und bei Goroutine-Leaks abzubrechen.
- LibAFL-Hang-Handling, damit **infinite loops / very slow inputs** als Fuzzing-Findings erhalten bleiben, anstatt als Timeouts zu verschwinden.
- Standardmäßig integrierte Checks auf arithmetischen Overflow sowie optionale Truncation-Checks durch go-panikint-style instrumentation.

Dies ist besonders wertvoll für Targets, bei denen die Security-Auswirkung in einem **panicless parser failure**, einem **concurrency bug** oder einem **DoS-only hang** statt in Memory Corruption besteht.

### Struct-aware Fuzzing für typisierte Go-APIs

Native Go-Fuzzing erwartet hauptsächlich Scalars wie `[]byte`, `string` und Zahlen. Wenn der getestete Code typisierte Objekte verarbeitet, kann gosentry **composite values** direkt fuzzingfähig machen (Structs, Slices, Arrays, Pointer), während darunter weiterhin Bytes mutiert werden.<sup>[[7]](#references)[[8]](#references)</sup>
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
Verwende dies beim Erstellen eines gefälschten Wire-Formats nur für Fuzzing, da Logikfehler durch Parsing-Code verborgen würden, der ausschließlich im Harness vorhanden ist. Bei differentiellen oder grammatikbasierten Kampagnen sollte die Eingabe des Harness als einzelnes `[]byte` oder als `string` beibehalten und stattdessen innerhalb des Callbacks geparst werden.

### Grammatikbasiertes Fuzzing für Parser und Protokolleingaben

Für Parser, Formate und Eingabesprachen kann gosentry **Nautilus grammar fuzzing** auf LibAFL ausführen. Die Grammatik ist ein JSON-Array aus Produktionsregeln, und das Harness sollte normalerweise ein einzelnes `[]byte`- oder `string`-Argument akzeptieren.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodiknotizen:

- Verwende den Grammar mode, wenn Mutationen auf Byte-Ebene größtenteils in frühen Syntaxprüfungen scheitern.
- Halte die Grammar auf die **sicherheitsrelevante Teilmenge** der Sprache/des Protokolls fokussiert, statt die vollständige Spezifikation zu modellieren.
- Verwende große Grenzwerte in Terminals/Nichtterminalen, um Integer-, Längen- und Zustandsmaschinen-Grenzfälle zu belasten.
- Der Grammar mode hält Inputs grammatikalisch gültig, aber das Ziel empfängt weiterhin **Bytes/Strings**, sodass Parsing und semantische Prüfungen innerhalb des instrumentierten Codes verbleiben.

### Differential fuzzing: Implementierungen vergleichen, nicht nur Crashes

Ein starkes Muster für Go-Ökosysteme ist **grammar-based differential fuzzing**: Erzeuge gültige strukturierte Inputs und übergib sie zwei Parsern, Clients oder Zustandsübergangs-Engines.<sup>[[7]](#references)[[8]](#references)</sup>
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

- eine Implementierung gerät in Panik, während die andere die Eingabe sauber ablehnt
- Abweichungen bei akzeptierten/abgelehnten Eingaben
- unterschiedliche Parse-Bäume oder decodierte Objekte
- abweichende Zustandsübergänge, Nonces, Salden oder State Roots

Dies ist eine praktische Methode, um **Consensus Mismatches**, **Parser Ambiguity** und **Spec-vs-Implementation Drift** zu finden, die reines Crash-Fuzzing häufig übersieht.

### Das Campaign-Corpus für Coverage-Reports wiederverwenden

Nach einer Campaign kann das gespeicherte Queue-Corpus erneut ausgeführt werden, um einen Go-Coverage-Report zu erstellen, ohne manuell ein separates Corpus zu exportieren.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Führe den Befehl aus dem **gleichen package** und mit demselben **-fuzz target** aus, damit gosentry den richtigen zwischengespeicherten campaign state auflöst.



## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing im Detail](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet fünf Jahre später: Über coverage-guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark wandelt Code in Graphen um](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Beim Go-Fuzzing fehlte die Hälfte des Toolkits. Wir haben die Toolchain geforkt, um das zu beheben.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ein schneller Greybox-Fuzzer für zustandsbehaftete Netzwerkprotokolle mit Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Keine Grammar, kein Problem: Auf dem Weg zum Fuzzing des Linux-Kernels ohne System-Call-Beschreibungen](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Effizientes Fuzzing mit adaptiven und veränderbaren Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM-Instrumentierung: Pfad- und Caller-Coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
