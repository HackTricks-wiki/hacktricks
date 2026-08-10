# Fuzzing-Methodik

## Mutational Grammar Fuzzing: Coverage vs. Semantik

Beim **mutational grammar fuzzing** werden Inputs mutiert, während sie **grammar-valid** bleiben. Im coverage-guided-Modus werden nur Samples als Corpus-Seeds gespeichert, die **neue Coverage** auslösen. Bei **Language-Targets** (Parsern, Interpretern, Engines) können dadurch Bugs übersehen werden, die **semantische/dataflow chains** erfordern, bei denen die Ausgabe eines Konstrukts zum Input eines anderen wird.<sup>[[1]](#references)</sup>

**Fehlermodus:** Der Fuzzer findet Seeds, die einzeln `document()` und `generate-id()` (oder ähnliche Primitives) ausführen, bewahrt jedoch **nicht den verketteten Dataflow**, sodass das „bug-nähere“ Sample verworfen wird, weil es keine zusätzliche Coverage erzeugt. Bei **3+ abhängigen Schritten** wird zufällige Rekombination teuer, und Coverage-Feedback steuert die Suche nicht.<sup>[[1]](#references)</sup>

**Implikation:** Für Grammars mit vielen Abhängigkeiten sollte man **mutationale und generative Phasen hybridisieren** oder die Generierung auf **function chaining**-Muster ausrichten (nicht nur auf Coverage).<sup>[[1]](#references)</sup>

## Fallstricke bei der Corpus-Diversität

Coverage-guided Mutation ist **greedy**: Ein Sample mit neuer Coverage wird sofort gespeichert und enthält häufig große unveränderte Bereiche. Mit der Zeit werden Corpora zu **Near-Duplicates** mit geringer struktureller Diversität. Aggressive Minimierung kann nützlichen Kontext entfernen. Ein praktikabler Kompromiss ist daher **grammar-aware minimization**, die **nach Erreichen eines Mindestschwellenwerts für Tokens stoppt** (Rauschen reduzieren und gleichzeitig genügend umgebende Struktur beibehalten, damit sie für Mutationen geeignet bleibt).<sup>[[1]](#references)</sup>

Eine praktische Corpus-Regel für mutational fuzzing lautet: **Eine kleine Menge strukturell unterschiedlicher Seeds bevorzugen, die die Coverage maximieren**, statt einer großen Ansammlung von Near-Duplicates. In der Praxis bedeutet das üblicherweise Folgendes.<sup>[[1]](#references)[[3]](#references)</sup>

- Mit **real-world samples** beginnen (öffentliche Corpora, Crawling, aufgezeichneter Traffic, Dateisammlungen aus dem Ökosystem des Targets).
- Sie mit **coverage-based corpus minimization** verdichten, statt jedes valide Sample beizubehalten.
- Seeds **klein genug** halten, damit Mutationen auf sinnvolle Felder treffen, anstatt die meisten Zyklen für irrelevante Bytes aufzuwenden.
- Die Corpus-Minimierung nach größeren Änderungen an Harness oder Instrumentation erneut ausführen, da sich das „beste“ Corpus ändert, wenn sich die Reachability verändert.

## Comparison-Aware Mutation Für Magic Values

Ein häufiger Grund dafür, dass Fuzzer stagnieren, ist nicht die Syntax, sondern sind **harte Vergleiche**: Magic Bytes, Längenprüfungen, Enum-Strings, Checksums oder Parser-Dispatch-Werte, die durch `memcmp`, Switch-Tabellen oder kaskadierte Vergleiche geschützt werden. Reine Random-Mutation verschwendet Zyklen damit, diese Werte Byte für Byte zu erraten.

Für solche Targets sollte **comparison tracing** verwendet werden (beispielsweise AFL++-`CMPLOG`-/Redqueen-ähnliche Workflows), damit der Fuzzer Operanden aus fehlgeschlagenen Vergleichen beobachten und Mutationen auf Werte ausrichten kann, die diese Vergleiche erfüllen.<sup>[[3]](#references)</sup>
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

## Stateful Fuzzing: Sequenzen sind Seeds

Bei **Protokollen**, **authentifizierten Workflows** und **mehrstufigen Parsern** ist die interessante Einheit oft nicht ein einzelner Blob, sondern eine **Nachrichtenfolge**. Das gesamte Transkript in eine Datei zu konkatenieren und blind zu mutieren, ist meist ineffizient, da der Fuzzer jeden Schritt gleich stark mutiert, selbst wenn nur die spätere Nachricht den anfälligen Zustand erreicht.<sup>[[4]](#references)</sup>

Ein effektiveres Vorgehen besteht darin, die **Sequenz selbst als Seed** zu behandeln und **beobachtbaren Zustand** (Response-Codes, Protokollzustände, Parser-Phasen, zurückgegebene Objekttypen) als zusätzliches Feedback zu verwenden.<sup>[[4]](#references)</sup>

- Halte **gültige Präfix-Nachrichten** stabil und konzentriere Mutationen auf die **den Übergang steuernde** Nachricht.
- Cache IDs und vom Server generierte Werte aus vorherigen Responses, wenn der nächste Schritt von ihnen abhängt.
- Bevorzuge Mutation/Splicing pro Nachricht gegenüber der Mutation des gesamten serialisierten Transkripts als opakem Blob.
- Wenn das Protokoll aussagekräftige Response-Codes offenlegt, verwende sie als **günstige Zustandsorakel**, um Sequenzen zu priorisieren, die tiefer vordringen.

Dies ist derselbe Grund, warum authentifizierte Bugs, versteckte Übergänge oder Parser-Bugs, die „nur nach dem Handshake“ auftreten, beim herkömmlichen dateibasierten Fuzzing oft übersehen werden: Der Fuzzer muss **Reihenfolge, Zustand und Abhängigkeiten** bewahren, nicht nur die Struktur.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Eine praktische Möglichkeit, **generative Neuartigkeit** mit der **Wiederverwendung von Coverage** zu kombinieren, besteht darin, kurzlebige Worker gegen einen persistenten Server neu zu starten. Jeder Worker beginnt mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden mit dem kombinierten Corpus, synchronisiert erneut und beendet sich anschließend. Dadurch entstehen **in jeder Generation frische Strukturen**, während gleichzeitig die angesammelte Coverage genutzt wird.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequentielle Worker (Beispielschleife):**

<details>
<summary>Neustartschleife des Jackalope Workers</summary>
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

- `-in empty` erzwingt bei jeder Generation ein **fresh corpus**.
- `-server_update_interval T` nähert eine **delayed sync** an (zuerst Neuheit, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird die **initial server sync** standardmäßig übersprungen (kein `-skip_initial_server_sync` erforderlich).
- Das optimale `T` ist **target-dependent**; ein Wechsel, nachdem der Worker den größten Teil der „einfachen“ Coverage gefunden hat, funktioniert meistens am besten.

## Snapshot Fuzzing For Hard-To-Harness Targets

Wenn der Code, den Sie testen möchten, erst **nach hohen Setup-Kosten** erreichbar wird (Starten einer VM, Abschließen eines Logins, Empfangen eines Pakets, Parsen eines Containers, Initialisieren eines Service), ist **snapshot fuzzing** eine nützliche Alternative: Erfassen Sie den bereiten Prozess- oder VM-Zustand, injizieren Sie jeden Testfall in den Input-Pfad des Targets, führen Sie die Ausführung bis zum Crash/Timeout fort und stellen Sie den Snapshot wieder her. Dadurch wird vermieden, die Initialisierung oder Protokollpräfixe zu wiederholen. Das ist nützlich für **network services**, **firmware**, **post-auth attack surfaces** und **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Führen Sie das Target aus, bis der interessante Zustand bereit ist.
2. Erstellen Sie zu diesem Zeitpunkt einen Snapshot von **memory + registers**.
3. Schreiben Sie für jeden Testfall den mutierten Input direkt in den relevanten Guest-/Prozess-Buffer.
4. Führen Sie die Ausführung bis zum Crash/Timeout/Reset fort.
5. Stellen Sie den Snapshot wieder her; bei VM-Targets stellen Sie, sofern unterstützt, nur die **dirty pages** wieder her und wiederholen den Vorgang.

Platzieren Sie den Snapshot so nah wie praktisch möglich am ersten aufwendigen Parse-/Dispatch-Schritt, beispielsweise nach einem `recv`-/`read`- oder Packet-Deserialisierungs-Punkt, und erfassen Sie den vom Target verwendeten Input-Buffer. Dies folgt dem Prinzip der adaptiven Platzierung: Der Snapshot wird tiefer in die Input-Verarbeitung verschoben, um die Wiederholung von Arbeit zu vermeiden.<sup>[[11]](#references)</sup>

## Harness Introspection: Shallow Fuzzers frühzeitig finden

Wenn eine Kampagne ins Stocken gerät, liegt das Problem häufig nicht am Mutator, sondern am **Harness**. Verwenden Sie **reachability/coverage introspection**, um Funktionen zu finden, die vom Fuzz-Target aus statisch erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Diese Funktionen weisen normalerweise auf eines von drei Problemen hin.<sup>[[12]](#references)</sup>

- Der Harness steigt zu spät oder zu früh in das Target ein.
- Im Seed-Corpus fehlt eine vollständige Feature-Familie.
- Das Target benötigt tatsächlich einen **zweiten Harness** anstelle eines übergroßen „do everything“-Harness.

Wenn Sie OSS-Fuzz-/ClusterFuzz-ähnliche Workflows verwenden, kann Fuzz Introspector die statische Erreichbarkeit mit der Runtime-Coverage vergleichen und Reports aus einem zeitlich begrenzten Lauf oder einem öffentlichen Corpus generieren.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Verwende den Bericht, um zu entscheiden, ob ein neuer Harness für einen nicht getesteten Parser-Pfad hinzugefügt, das Corpus für ein bestimmtes Feature erweitert oder ein monolithischer Harness in kleinere Einstiegspunkte aufgeteilt werden soll.

## Graph-First-Auswahl von Fuzzing-Zielen und Triage von Mutationen

Wenn bereits **Findings aus statischer Analyse**, **Überlebende aus Mutation Testing** und **Coverage-Reports** vorliegen, sollten diese nicht als voneinander unabhängige Listen triagiert werden. Erstelle zuerst einen **Call Graph**, versehe die Knoten mit **zyklomatischer Komplexität**, **Erreichbarkeit von Entry­points/ungeprüften Eingaben** und allen externen Findings und stelle anschließend Fragen zum Graphen.<sup>[[5]](#references)[[6]](#references)</sup>

- Welche Funktionen mit hoher Komplexität sind von ungeprüften Eingaben aus erreichbar?
- Welche Mutation Survivors liegen auf Pfaden von Parsern/Handlern zu sicherheitskritischem Code?
- Welche Funktionen sind architektonische Engpässe mit ungewöhnlich hoher **Blast Radius**?

Dadurch werden meist bessere Fuzzing-Ziele sichtbar als allein durch „niedrigste Coverage“. Ein Parser/Decoder mit **hoher Komplexität** und bestätigter **externer Erreichbarkeit** ist ein stärkerer Kandidat für einen Harness als ein isolierter interner Helper mit schwacher Coverage, aber ohne von Angreifern kontrollierten Pfad.

### Praktischer Triage-Workflow

1. Erstelle einen **Code-Graph** aus der Codebasis und extrahiere Komplexitäts-/Branch-Metriken pro Funktion.
2. Liste **Entry­points** auf, die von Angreifern kontrollierte Eingaben akzeptieren: Request-Handler, Decoder, Importer, Protokoll-Parser, CLI-/Datei-Reader.
3. Führe **Pfadabfragen** von diesen Entry­points zu den Kandidatenfunktionen aus, um erreichbare Angriffsfläche von totem bzw. ausschließlich internem Code zu trennen.
4. Priorisiere Knoten, die Folgendes kombinieren:
- hohe **zyklomatische Komplexität**
- bestätigte **Erreichbarkeit von ungeprüften Eingaben**
- hohe **Blast Radius** oder viele nachgelagerte Abhängigkeiten
- zusätzliche Belege wie **SARIF**-Findings, Audit-Notizen oder Mutation Survivors
5. Schreibe zuerst fokussierte Harnesses für die Knoten mit der höchsten Bewertung, insbesondere für **Parser/Codecs** wie Hex-/Base64-/IP-/Message-Decoder.

### Mutation Survivors: äquivalent vs. verwertbar

Mutation Testing erzeugt oft eine unübersichtliche Liste von Survivors. Bevor jeder Survivor als Sicherheitslücke behandelt wird, sollte anhand des Graphen Folgendes geprüft werden:

- Ist die mutierte Funktion von einem Entry­point mit von Angreifern kontrollierten Eingaben aus erreichbar?
- Sind alle Aufrufpfade durch stärkere Invarianten als die mutierte Prüfung eingeschränkt?
- Liegt der Knoten in totem Code, Formatierungslogik oder in einem sicherheitsrelevanten Arithmetic-/Parser-Pfad mit hoher Auswirkung?

Survivors, die weiterhin unerreichbar oder strukturell eingeschränkt sind, sind häufig **äquivalente Mutanten**. Survivors, die **erreichbar** bleiben und **Grenzbedingungen**, **Overflow-/Carry-Pfade** oder **sicherheitskritische Arithmetic-/Parsing-Logik** berühren, sollten in Folgendes überführt werden:

- neue Fuzzing-Harnesses
- direkte Property-/Invarianztests
- gezielte Edge-Case-Vektoren

### Externe Findings auf den Graphen abbilden

Wenn die SAST-Pipeline **SARIF** exportiert, projiziere Findings anhand von **Datei + Zeilenbereich** auf Graphknoten und nutze den Graphen, um die Auswirkungen zu erweitern.<sup>[[6]](#references)</sup>

- Berechne die **Blast Radius** der markierten Funktion.
- Prüfe, ob das Finding auf einem Pfad von einem Entry­point liegt.
- Gruppiere nahe beieinanderliegende Findings, die auf denselben Engpass zurückfallen.

Das ist nützlich, wenn entschieden werden soll, ob Fuzzing-Zeit in eine bestimmte Funktion investiert wird: Ein Knoten, der **erreichbar**, **komplex** ist und bereits **SAST-Treffer** aufweist, ist oft ein besseres Ziel als ein lediglich komplexer Knoten ohne Angriffs-Pfad.

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
Die wichtige Methodik ist die Schnittmenge: **complexity x exposure x impact**. Verwende die Grafik, um Fuzz-Ziele mit dem höchsten erwarteten Sicherheitswert auszuwählen, und nutze anschließend die Mutation Survivors, um zu bestimmen, welche Grenzen und Invarianten dein Harness testen muss.<sup>[[5]](#references)</sup>

## Go-Fuzzing mit gosentry: Leistungsstärkerer Engine, typisierte Inputs und Differential Checks

Wenn ein Go-Ziel bereits über ein natives `testing.F`-Harness verfügt, besteht ein praktischer Upgrade-Pfad darin, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen, einer geforkten Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend durch **LibAFL** ersetzt.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Dies ist nützlich, wenn der native Go fuzzer bei **hard comparisons**, **typed inputs** oder **parser-heavy formats** ins Stocken gerät. Die Methodik bleibt gleich:

- Weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback verwenden.
- Den gleichen Harness wiederverwenden, ihn aber mit gosentrys `go`-Binary statt mit der standardmäßigen Toolchain ausführen.
- Die resultierende Kampagne als normalen coverage-guided Run behandeln, jedoch mit LibAFL-Scheduling/Mutation und besseren umgebenden Detektoren.

### Stille Fehler in Fuzzing-Funde umwandeln

Ein wiederkehrendes Problem bei Go-Assessments ist, dass gefährliches Verhalten standardmäßig oft **keinen** Crash verursacht. Mit gosentry können mehrere Klassen von „schlechten, aber stillen“ Zuständen in Findings umgewandelt werden.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, damit ausgewählte Logging-/Error-Pfade wie Crashes reagieren (nützlich für `log.Fatal`-ähnliche Codepfade, die andernfalls nur loggen und fortfahren).
- `--catch-races=true`, um neu entdeckte Queue-Einträge mit dem Go race detector erneut auszuführen.
- `--catch-leaks=true`, um neue Queue-Einträge mit `goleak` erneut auszuführen und bei Goroutine-Leaks zu stoppen.
- LibAFL-Hang-Handling, damit **infinite loops / sehr langsame Inputs** als Fuzzing-Funde erhalten bleiben, anstatt als Timeouts zu verschwinden.
- Standardmäßig integrierte Checks auf arithmetischen Overflow sowie optionale Truncation-Checks durch go-panikint-style instrumentation.

Dies ist besonders wertvoll für Targets, bei denen die Security-Auswirkung ein **panicless parser failure**, ein **concurrency bug** oder ein **DoS-only hang** statt Memory Corruption ist.

### Struct-aware Fuzzing für typisierte Go APIs

Native Go fuzzing erwartet hauptsächlich Scalars wie `[]byte`, `string` und Zahlen. Wenn der getestete Code typisierte Objekte verarbeitet, kann gosentry **composite values** direkt fuzzing unterziehen (Structs, Slices, Arrays, Pointer), während weiterhin Bytes darunter mutiert werden.<sup>[[7]](#references)[[8]](#references)</sup>
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
Verwende dies beim Erstellen eines künstlichen Wire-Formats nur für fuzzing, da dadurch Logikfehler hinter ausschließlich im Harness vorhandenem Parsing-Code verborgen werden könnten. Für differentielle oder grammatikbasierte Kampagnen sollte der Harness-Input als einzelnes `[]byte` oder als `string` beibehalten und stattdessen innerhalb des Callbacks geparst werden.

### Grammatikbasiertes fuzzing für Parser- und Protokoll-Inputs

Für Parser, Formate und Input-Sprachen kann gosentry **Nautilus grammar fuzzing** auf Basis von LibAFL ausführen. Die Grammatik ist ein JSON-Array aus Produktionsregeln, und der Harness sollte normalerweise ein einzelnes `[]byte`- oder `string`-Argument übernehmen.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodiknotizen:

- Verwende den Grammar-Modus, wenn Byte-Level-Mutationen größtenteils bereits in frühen Syntaxprüfungen scheitern.
- Halte die Grammar auf die **sicherheitsrelevante Teilmenge** der Sprache/des Protokolls fokussiert, anstatt die vollständige Spezifikation zu modellieren.
- Verwende große Grenzwerte in Terminals/Nichtterminalen, um Grenzfälle bei Integern, Längen und Zustandsautomaten zu belasten.
- Der Grammar-Modus hält Inputs grammar-valid, aber das Ziel empfängt weiterhin **Bytes/Strings**, sodass Parsing- und semantische Prüfungen im Code innerhalb des Harness verbleiben.

### Differential Fuzzing: Implementierungen vergleichen, nicht nur Crashes

Ein starkes Muster für Go-Ökosysteme ist **Grammar-based Differential Fuzzing**: Erzeuge gültige strukturierte Inputs und übergib sie an zwei Parser, Clients oder Zustandsübergangs-Engines.<sup>[[7]](#references)[[8]](#references)</sup>
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
- Abweichungen bei akzeptierten/abgelehnten Eingaben
- unterschiedliche Parse Trees oder decodierte Objekte
- abweichende State-Transitions, Nonces, Balances oder State Roots

Dies ist eine praktische Möglichkeit, **Konsensabweichungen**, **Parser-Mehrdeutigkeit** und **Abweichungen zwischen Spezifikation und Implementierung** zu finden, die reines Crash-Fuzzing häufig nicht erkennt.

### Das Campaign-Corpus für Coverage-Reports wiederverwenden

Nach einer Campaign kann das gespeicherte Queue-Corpus erneut abgespielt werden, um einen Go-Coverage-Report zu erzeugen, ohne manuell ein separates Corpus zu exportieren.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Führe den Befehl aus dem **gleichen package** und mit demselben **`-fuzz` target** aus, damit gosentry den richtigen Zustand der gecachten Kampagne auflöst.

## References

- [1] [Mutationales Grammar Fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing im Detail](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet fünf Jahre später: Coverage-guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verwandelt Code in Graphen](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go Fuzzing fehlte die Hälfte des Toolkits. Wir haben die Toolchain geforkt, um das zu beheben.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ein schneller Greybox Fuzzer für Stateful Network Protocols mithilfe von Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Keine Grammar, kein Problem: Auf dem Weg zum Fuzzing des Linux-Kernels ohne System-Call-Beschreibungen](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Effizientes Fuzzing mit adaptiven und veränderbaren Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
