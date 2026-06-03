# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Beim **mutational grammar fuzzing** werden Inputs mutiert, während sie **grammar-valid** bleiben. Im coverage-guided Modus werden nur Samples, die **neue coverage** auslösen, als corpus seeds gespeichert. Bei **language targets** (parsers, interpreters, engines) kann das Bugs übersehen, die **semantic/dataflow chains** erfordern, bei denen die Ausgabe eines Konstrukts zum Input eines anderen wird.

**Failure mode:** der fuzzer findet seeds, die jeweils `document()` und `generate-id()` (oder ähnliche Primitives) ausführen, aber **er erhält die verkettete dataflow nicht aufrecht**, sodass das Sample, das „näher am Bug“ liegt, verworfen wird, weil es keine coverage hinzufügt. Bei **3+ abhängigen Schritten** wird zufällige Rekombination teuer und coverage feedback steuert die Suche nicht.

**Implikation:** Für grammars mit vielen Abhängigkeiten sollte man **mutational und generative Phasen hybridisieren** oder die Generierung in Richtung **function chaining**-Muster lenken (nicht nur coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation ist **greedy**: Ein Sample mit neuer coverage wird sofort gespeichert und behält oft große unveränderte Bereiche. Mit der Zeit werden corpora zu **near-duplicates** mit geringer struktureller Vielfalt. Aggressive Minimierung kann nützlichen Kontext entfernen, daher ist ein praktischer Kompromiss **grammar-aware minimization**, die **nach einem minimum token threshold stoppt** (Rauschen reduzieren, aber genug umgebende Struktur behalten, um mutation-freundlich zu bleiben).

Eine praktische corpus-Regel für mutational fuzzing ist: **lieber einen kleinen Satz strukturell unterschiedlicher seeds, die coverage maximieren**, statt einen großen Haufen von near-duplicates. In der Praxis bedeutet das meist:

- Starte mit **real-world samples** (öffentliche corpora, crawling, aufgezeichnetem traffic, Dateisätzen aus dem Ziel-Ökosystem).
- Reduziere sie mit **coverage-based corpus minimization** statt jedes valide Sample zu behalten.
- Halte seeds **klein genug**, damit Mutationen auf sinnvollen Feldern landen, statt die meiste Zeit auf irrelevante Bytes zu gehen.
- Führe corpus minimization nach größeren Harness-/Instrumentierungsänderungen erneut aus, weil sich das „beste“ corpus ändert, wenn sich die Erreichbarkeit ändert.

## Comparison-Aware Mutation For Magic Values

Ein häufiger Grund, warum fuzzer auf einem Plateau landen, ist nicht die Syntax, sondern **hard comparisons**: magic bytes, Längenprüfungen, enum strings, Checksums oder Parser-Dispatch-Werte, die durch `memcmp`, switch tables oder verkettete Vergleiche abgesichert sind. Reines Random Mutation verschwendet Zyklen damit, diese Werte Byte für Byte zu erraten.

Für diese Targets nutze **comparison tracing** (zum Beispiel AFL++ `CMPLOG` / Redqueen-style workflows), damit der fuzzer Operanden aus fehlgeschlagenen Vergleichen beobachten und Mutationen auf Werte ausrichten kann, die diese erfüllen.
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

- Das ist besonders nützlich, wenn das Ziel tiefe Logik hinter **file signatures**, **protocol verbs**, **type tags** oder **version-dependent feature bits** verbirgt.
- Kombiniere es mit **dictionaries**, die aus echten Samples, Protocol-Specs oder Debug-Logs extrahiert wurden. Ein kleines Dictionary mit Grammatik-Tokens, Chunk-Namen, Verben und Delimitern ist oft wertvoller als eine riesige generische Wordlist.
- Wenn das Ziel viele sequentielle Checks durchführt, löse zuerst die frühesten „magic“-Vergleiche und minimiere danach das resultierende Corpus erneut, damit spätere Stufen bereits mit gültigen Präfixen starten.

## Stateful Fuzzing: Sequences Are Seeds

Bei **protocols**, **authenticated workflows** und **multi-stage parsers** ist die interessante Einheit oft nicht ein einzelner Blob, sondern eine **message sequence**. Den gesamten Transcript in eine Datei zu verketten und blind zu mutieren ist normalerweise ineffizient, weil der Fuzzer jeden Schritt gleich stark mutiert, selbst wenn nur die spätere Message den fragilen State erreicht.

Ein wirksameres Muster ist es, die **sequence selbst als Seed** zu behandeln und **observable state** (Response-Codes, Protocol States, Parser-Phasen, zurückgegebene Objekttypen) als zusätzliches Feedback zu verwenden:

- Behalte **valid prefix messages** stabil und konzentriere Mutationen auf die **transition-driving** Message.
- Cache Identifiers und server-generierte Werte aus vorherigen Responses, wenn der nächste Schritt davon abhängt.
- Bevorzuge per-Message-Mutation/Splicing statt des Mutierens des gesamten serialisierten Transcripts als undurchsichtigen Blob.
- Wenn das Protocol aussagekräftige Response-Codes liefert, nutze sie als einen **cheap state oracle**, um Sequenzen zu priorisieren, die tiefer fortschreiten.

Das ist derselbe Grund, warum authenticated Bugs, versteckte Übergänge oder Parser-Bugs, die nur „after-handshake“ auftreten, bei klassischem file-style fuzzing oft übersehen werden: Der Fuzzer muss **Reihenfolge, State und Abhängigkeiten** erhalten, nicht nur die Struktur.

## Single-Machine Diversity Trick (Jackalope-Style)

Eine praktische Methode, **generative novelty** mit **coverage reuse** zu kombinieren, ist es, **kurzlebige Worker neu zu starten** gegen einen persistenten Server. Jeder Worker startet mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden auf dem kombinierten Corpus, synchronisiert erneut und beendet sich dann. Das erzeugt **frische Strukturen pro Generation**, während dennoch akkumulierte Coverage genutzt wird.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequentielle Worker (Beispielschleife):**

<details>
<summary>Jackalope Worker-Neustartschleife</summary>
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

- `-in empty` erzwingt ein **frisches Corpus** bei jeder Generierung.
- `-server_update_interval T` approximiert **verzögerten Sync** (zuerst Neuheit, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird der **erste Server-Sync standardmäßig übersprungen** (kein Bedarf für `-skip_initial_server_sync`).
- Das optimale `T` ist **zielabhängig**; ein Wechsel, nachdem der Worker den Großteil der „einfachen“ Coverage gefunden hat, funktioniert meist am besten.

## Snapshot Fuzzing Für Schwer Zu Harnessende Targets

Wenn der Code, den du testen willst, erst **nach einem hohen Setup-Aufwand** erreichbar wird (eine VM booten, ein Login abschließen, ein Packet empfangen, einen Container parsen, einen Service initialisieren), ist **Snapshot Fuzzing** eine nützliche Alternative:

1. Lass das Target laufen, bis der interessante Zustand bereit ist.
2. Snapshotte an diesem Punkt **Speicher + Register**.
3. Schreibe für jeden Testfall die mutierte Eingabe direkt in den relevanten Guest-/Prozess-Buffer.
4. Führe bis zu Crash/Timeout/Reset aus.
5. Stelle nur die **dirty pages** wieder her und wiederhole.

Das vermeidet, bei jeder Iteration die vollen Setup-Kosten zu zahlen, und ist besonders nützlich für **network services**, **firmware**, **post-auth attack surfaces** und **binary-only targets**, die nur schwer in einen klassischen In-Process-Harness umgebaut werden können.

Ein praktischer Trick ist, direkt nach einem `recv`/`read`/Packet-Deserialisierungspunkt zu unterbrechen, die Input-Buffer-Adresse zu notieren, dort ein Snapshot zu erstellen und dann diesen Buffer in jeder Iteration direkt zu mutieren. So kannst du die tiefe Parsing-Logik fuzzing, ohne jedes Mal den gesamten Handshake neu aufzubauen.

## Harness-Introspection: Shallow Fuzzers Früh Finden

Wenn eine Kampagne ins Stocken gerät, liegt das Problem oft nicht am Mutator, sondern am **Harness**. Verwende **Reachability/Coverage-Introspection**, um Funktionen zu finden, die statisch von deinem Fuzz-Target aus erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Solche Funktionen deuten normalerweise auf eines von drei Problemen hin:

- Das Harness betritt das Target zu spät oder zu früh.
- Dem Seed-Corpus fehlt eine ganze Feature-Familie.
- Das Target braucht wirklich ein **zweites Harness** statt eines übergroßen „do everything“-Harness.

Wenn du OSS-Fuzz / ClusterFuzz-ähnliche Workflows verwendest, ist Fuzz Introspector für dieses Triage nützlich:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Verwende den Bericht, um zu entscheiden, ob ein neuer Harness für einen ungetesteten Parser-Pfad hinzugefügt, die Corpus für ein bestimmtes Feature erweitert oder ein monolithischer Harness in kleinere Entry Points aufgeteilt werden sollte.

## Graph-First Fuzz Target Selection And Mutation Triage

Wenn du bereits **static-analysis findings**, **mutation-testing survivors** und **coverage reports** hast, triagiere sie nicht als unabhängige Listen. Erstelle zuerst einen **call graph**, annotiere Knoten mit **cyclomatic complexity**, **entrypoint/untrusted-input reachability** und allen externen Findings, und stelle dann Graph-Fragen:

- Welche Funktionen mit hoher Komplexität sind von untrusted input aus erreichbar?
- Welche mutation survivors liegen auf Pfaden von parsers/handlers zu security-critical code?
- Welche Funktionen sind architektonische Engpässe mit ungewöhnlich großem **blast radius**?

Das deckt meist bessere fuzz targets auf als nur „niedrigste coverage“. Ein parser/decoder mit **hoher Komplexität** und bestätigter **external reachability** ist ein stärkerer Harness-Kandidat als ein isolierter interner Helper mit schwacher coverage, aber ohne attacker-controlled path.

### Praktischer Triage-Workflow

1. Erstelle einen **code graph** aus der codebase und extrahiere pro Funktion complexity-/branch-Metriken.
2. Liste **entrypoints** auf, die attacker-controlled input akzeptieren: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Führe **path queries** von diesen entrypoints zu Kandidatenfunktionen aus, um erreichbare attack surface von totem/nur internem code zu trennen.
4. Priorisiere Knoten, die Folgendes kombinieren:
- hohe **cyclomatic complexity**
- bestätigte **reachability from untrusted input**
- hoher **blast radius** oder viele nachgelagerte Abhängige
- bestätigende Hinweise wie **SARIF** findings, Audit-Notizen oder mutation survivors
5. Schreibe zuerst fokussierte Harnesses für die am besten bewerteten Knoten, besonders **parsers/codecs** wie hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing erzeugt oft eine laute Survivor-Liste. Bevor du jeden Survivor als Sicherheitslücke behandelst, nutze den Graphen, um zu fragen:

- Ist die mutierte Funktion von einem attacker-controlled entrypoint aus erreichbar?
- Sind alle call paths durch stärkere invariants als die mutierte Prüfung eingeschränkt?
- Liegt der Knoten in dead code, in formatting-only logic oder in einem high-impact arithmetic/parser path?

Survivors, die unerreichbar bleiben oder strukturell eingeschränkt sind, sind oft **equivalent mutants**. Survivors, die **erreichbar** bleiben und **boundary conditions**, **overflow/carry paths** oder **security-critical arithmetic/parsing** berühren, sollten hochgestuft werden zu:

- neuen fuzz harnesses
- direkten property/invariant tests
- gezielten edge-case vectors

### Externe Findings auf den Graphen korrelieren

Wenn deine SAST-Pipeline **SARIF** exportiert, projiziere Findings auf Graph-Knoten über **file + line range** und nutze den Graphen, um die Auswirkung zu erweitern:

- berechne den **blast radius** der markierten Funktion
- prüfe, ob der Finding auf irgendeinem Pfad von einem entrypoint liegt
- clustere nahe beieinander liegende Findings, die in denselben choke point zusammenlaufen

Das ist nützlich, wenn du entscheidest, ob du Fuzzing-Zeit auf eine bestimmte Funktion verwenden solltest: Ein Knoten, der **erreichbar**, **komplex** ist und bereits **SAST hits** hat, ist oft ein besseres Ziel als ein bloß komplexer Knoten ohne attacker path.

Example workflow with Trailmark:
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
Die wichtige Methodik ist die Schnittmenge: **Komplexität x Exposition x Impact**. Nutze die Grafik, um fuzz targets mit dem höchsten erwarteten Sicherheitswert auszuwählen, und verwende dann Mutation Survivors, um zu entscheiden, welche Grenzen und Invarianten dein Harness stressen muss.

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Wenn ein Go-Target bereits ein natives `testing.F` Harness hat, ist ein praktischer Upgrade-Pfad, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen, einer geforkten Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend auf **LibAFL** umstellt.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Dies ist nützlich, wenn der native Go-fuzzer bei **hard comparisons**, **typed inputs** oder **parser-heavy formats** hängen bleibt. Die Methodik bleibt dieselbe:

- Weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback verwenden.
- Dasselbe Harness wiederverwenden, aber mit gosentrys `go`-Binary statt der Stock-toolchain ausführen.
- Die daraus resultierende Campaign als normalen coverage-guided Run behandeln, aber mit LibAFL scheduling/mutation und besseren umliegenden Detektoren.

### Stille Fehler in fuzz findings umwandeln

Ein wiederkehrendes Problem bei Go-Assessments ist, dass gefährliches Verhalten standardmäßig oft **nicht** crasht. Mit gosentry kannst du mehrere Klassen von „schlecht, aber stillen“ Zuständen in Findings umwandeln:

- `--panic-on=pkg.Func,...`, um ausgewählte logging/error paths wie crashes zu behandeln (nützlich für `log.Fatal`-ähnliche Code paths, die sonst nur loggen und weitermachen).
- `--catch-races=true`, um neu entdeckte Queue-Einträge mit dem Go race detector erneut abzuspielen.
- `--catch-leaks=true`, um neue Queue-Einträge mit `goleak` erneut abzuspielen und bei goroutine leaks zu stoppen.
- LibAFL hang handling, um **infinite loops / very slow inputs** als fuzz findings zu behalten, statt sie als Timeouts verschwinden zu lassen.
- Integrierte arithmetic overflow checks standardmäßig, plus optionale truncation checks über go-panikint-style instrumentation.

Das ist besonders wertvoll für Targets, bei denen die Security-Auswirkung ein **panicless parser failure**, ein **concurrency bug** oder ein **DoS-only hang** statt memory corruption ist.

### Struct-aware fuzzing für typed Go APIs

Native Go fuzzing erwartet hauptsächlich Scalars wie `[]byte`, `string` und Zahlen. Wenn der Code unter Test typed objects verarbeitet, kann gosentry **composite values** direkt fuzzing (structs, slices, arrays, pointers) und dabei weiterhin Bytes darunter mutieren.
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
Verwende dies, wenn du ein Fake-Wire-Format nur fürs fuzzing baust, würde logische Fehler hinter nur im Harness vorhandenem Parsing-Code verstecken. Für differential- oder grammar-based-Kampagnen solltest du die Harness-Eingabe stattdessen als einzelnes `[]byte` oder `string` belassen und innerhalb des Callbacks parsen.

### Grammar-based fuzzing for parsers and protocol inputs

Für Parser, Formate und Eingabesprachen kann gosentry auf LibAFL aufbauend **Nautilus grammar fuzzing** ausführen. Die Grammar ist ein JSON-Array von Produktionsregeln, und das Harness sollte normalerweise ein einzelnes `[]byte`- oder `string`-Argument nehmen.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodik-Notizen:

- Verwende grammar mode, wenn byte-level mutations größtenteils schon bei frühen Syntaxprüfungen sterben.
- Halte die grammar auf den **security-relevanten Teilbereich** der Sprache/des Protokolls fokussiert, statt die vollständige Spezifikation zu modellieren.
- Verwende große Grenzwerte in terminals/nonterminals, um integer-, length- und state-machine-Ränder zu stressen.
- Grammar mode hält Inputs grammar-valid, aber das Target erhält trotzdem **bytes/strings**, sodass Parsing- und Semantic-Prüfungen weiterhin im geharnessed Code bleiben.

### Differential fuzzing: Implementierungen vergleichen, nicht nur crashes

Ein starkes Muster für Go-Ökosysteme ist **grammar-based differential fuzzing**: gültige strukturierte Inputs generieren und sie an zwei Parser, Clients oder state-transition engines füttern.
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
Behandle das Folgende als Findings:

- eine Implementierung panikt, während die andere sauber ablehnt
- akzeptierte/abgelehnte Input-Mismatches
- unterschiedliche Parse Trees oder dekodierte Objekte
- abweichende State-Transitions, Nonces, Balances oder State Roots

Dies ist eine praktische Methode, um **Consensus-Mismatches**, **Parser-Ambiguity** und **Spec-vs-Implementation Drift** zu finden, die reines Crash-Fuzzing oft verpasst.

### Reuse the campaign corpus for coverage reporting

Nach einer Campaign, replaye den gespeicherten Queue Corpus, um einen Go Coverage Report zu erzeugen, ohne manuell einen separaten Corpus zu exportieren:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Führe den Befehl aus dem **gleichen Package** und mit demselben `-fuzz`-Target aus, damit gosentry den richtigen zwischengespeicherten Campaign-Status auflöst.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
