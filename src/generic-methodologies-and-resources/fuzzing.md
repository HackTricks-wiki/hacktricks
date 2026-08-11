# Fuzzing-Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantik

Beim **mutational grammar fuzzing** werden Inputs mutiert, während sie **grammatikkonform** bleiben. Im coverage-guided-Modus werden nur Samples, die eine **neue Coverage** auslösen, als Corpus-Seeds gespeichert. Bei **Language Targets** (Parsern, Interpretern, Engines) kann dies Bugs übersehen, die **semantische Datenflussketten** erfordern, bei denen die Ausgabe eines Konstrukts zur Eingabe eines anderen wird.<sup>[[1]](#references)</sup>

**Fehlermodus:** Der Fuzzer findet Seeds, die einzeln `document()` und `generate-id()` (oder ähnliche Primitives) ausführen, bewahrt jedoch **nicht den verketteten Datenfluss**, sodass das „bug-nähere“ Sample verworfen wird, weil es keine zusätzliche Coverage erzeugt. Bei **3+ abhängigen Schritten** wird die zufällige Rekombination teuer, und das Coverage-Feedback lenkt die Suche nicht.<sup>[[1]](#references)</sup>

**Auswirkung:** Bei grammatikabhängigen Strukturen sollte man **mutationale und generative Phasen hybridisieren** oder die Generierung auf Muster der **Funktionsverkettung** ausrichten (nicht nur auf Coverage).<sup>[[1]](#references)</sup>

## Fallstricke bei der Corpus-Diversität

Coverage-guided Mutation ist **gierig**: Ein Sample mit neuer Coverage wird sofort gespeichert und behält häufig große unveränderte Bereiche. Mit der Zeit werden Corpora zu **Beinahe-Duplikaten** mit geringer struktureller Diversität. Aggressive Minimierung kann nützlichen Kontext entfernen. Ein praktischer Kompromiss ist daher eine **grammatikbewusste Minimierung**, die **nach Erreichen eines Mindestschwellenwerts für Tokens stoppt** (Rauschen reduzieren und gleichzeitig genügend umgebende Struktur bewahren, damit Mutationen weiterhin sinnvoll möglich sind).<sup>[[1]](#references)</sup>

Eine praktische Corpus-Regel für mutational fuzzing lautet: **Eine kleine Menge strukturell unterschiedlicher Seeds bevorzugen, die die Coverage maximieren**, statt einer großen Sammlung von Beinahe-Duplikaten. In der Praxis bedeutet dies normalerweise Folgendes.<sup>[[1]](#references)[[3]](#references)</sup>

- Mit **Samples aus der Praxis** beginnen (öffentliche Corpora, Crawling, erfasster Traffic, Dateisammlungen aus dem Ökosystem des Targets).
- Sie mithilfe einer **Coverage-basierten Corpus-Minimierung** reduzieren, statt jedes gültige Sample zu behalten.
- Seeds **klein genug** halten, damit Mutationen auf sinnvolle Felder treffen, anstatt die meisten Zyklen für irrelevante Bytes aufzuwenden.
- Die Corpus-Minimierung nach größeren Änderungen am Harness oder an der Instrumentierung erneut ausführen, da sich das „beste“ Corpus ändert, wenn sich die Erreichbarkeit ändert.

## Vergleichsorientierte Mutation für Magic Values

Ein häufiger Grund dafür, dass Fuzzer stagnieren, sind nicht Syntaxprobleme, sondern **harte Vergleiche**: Magic Bytes, Längenprüfungen, Enum-Strings, Checksums oder Parser-Dispatch-Werte, die durch `memcmp`, Switch-Tabellen oder hintereinandergeschaltete Vergleiche geschützt sind. Reine Zufallsmutationen verschwenden Zyklen damit, diese Werte Byte für Byte zu erraten.

Für diese Targets sollte **Comparison Tracing** verwendet werden (zum Beispiel AFL++-Workflows mit `CMPLOG` oder nach dem Redqueen-Prinzip), damit der Fuzzer Operanden aus fehlgeschlagenen Vergleichen beobachten und Mutationen auf Werte ausrichten kann, die diese Vergleiche erfüllen.<sup>[[3]](#references)</sup>
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
- Kombiniere dies mit **dictionaries**, die aus echten Samples, Protokollspezifikationen oder Debug-Logs extrahiert wurden. Ein kleines Dictionary mit Grammatik-Tokens, Chunk-Namen, Verben und Begrenzern ist oft wertvoller als eine riesige generische Wordlist.
- Wenn das Ziel viele sequenzielle Prüfungen durchführt, löse zuerst die frühesten „magic“-Vergleiche und minimiere anschließend das resultierende Corpus erneut, damit spätere Stufen mit bereits gültigen Präfixen beginnen.

## Stateful Fuzzing: Sequenzen sind Seeds

Bei **protocols**, **authenticated workflows** und **multi-stage parsers** ist die interessante Einheit oft kein einzelner Blob, sondern eine **message sequence**. Das gesamte Transcript in eine Datei zu verketten und blind zu mutieren, ist normalerweise ineffizient, da der Fuzzer jeden Schritt gleich stark mutiert, selbst wenn nur die spätere Nachricht den fragilen Zustand erreicht.<sup>[[4]](#references)</sup>

Ein effektiveres Muster besteht darin, die **sequence selbst als seed** zu behandeln und **observable state** (Response-Codes, Protocol-States, Parser-Phasen, zurückgegebene Object-Types) als zusätzliches Feedback zu verwenden.<sup>[[4]](#references)</sup>

- Halte **valid prefix messages** stabil und konzentriere Mutationen auf die **transition-driving** Nachricht.
- Cache Identifiers und vom Server erzeugte Werte aus vorherigen Responses, wenn der nächste Schritt von ihnen abhängt.
- Bevorzuge Mutation/Splicing pro Nachricht gegenüber der Mutation des gesamten serialisierten Transcripts als opaque Blob.
- Wenn das Protokoll aussagekräftige Response-Codes bereitstellt, verwende sie als **cheap state oracle**, um Sequenzen zu priorisieren, die tiefer vordringen.

Aus demselben Grund werden authentifizierte Bugs, versteckte Transitions oder Parser-Bugs, die „only-after-handshake“ auftreten, beim gewöhnlichen File-Style-Fuzzing oft übersehen: Der Fuzzer muss **order, state und dependencies** bewahren, nicht nur die Struktur.<sup>[[4]](#references)</sup>

## Single-Machine-Diversity-Trick (Jackalope-Style)

Eine praktische Möglichkeit, **generative novelty** mit **coverage reuse** zu kombinieren, besteht darin, kurzlebige Worker gegen einen persistenten Server neu zu starten. Jeder Worker beginnt mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden mit dem kombinierten Corpus, synchronisiert erneut und beendet sich anschließend. Dadurch entstehen **fresh structures in jeder Generation**, während gleichzeitig die angesammelte Coverage genutzt wird.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` approximiert eine **verzögerte Synchronisierung** (zuerst Neuheiten, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird die **initiale Server-Synchronisierung** standardmäßig übersprungen (kein `-skip_initial_server_sync` erforderlich).
- Das optimale `T` ist **zielabhängig**; ein Wechsel, nachdem der Worker den größten Teil der „einfachen“ Coverage gefunden hat, funktioniert in der Regel am besten.

## Snapshot Fuzzing für schwer zu harnessende Ziele

Wenn der von Ihnen zu testende Code erst **nach hohen Einrichtungskosten** erreichbar wird (Booten einer VM, Abschließen eines Logins, Empfangen eines Pakets, Parsen eines Containers, Initialisieren eines Service), ist **Snapshot Fuzzing** eine nützliche Alternative: Erfassen Sie den bereiten Prozess- oder VM-Zustand, injizieren Sie jeden Testfall in den Input-Pfad des Ziels, führen Sie ihn bis zum Crash/Timeout aus und stellen Sie den Snapshot wieder her. Dadurch werden wiederholte Initialisierungen oder Protokollpräfixe vermieden. Dies ist nützlich für **Netzwerk-Services**, **Firmware**, **Post-Auth-Angriffsflächen** und **binäre Ziele**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Führen Sie das Ziel aus, bis der interessante Zustand bereit ist.
2. Erstellen Sie an diesem Punkt einen Snapshot von **Speicher + Registern**.
3. Schreiben Sie für jeden Testfall den mutierten Input direkt in den relevanten Guest-/Prozesspuffer.
4. Führen Sie ihn bis zum Crash/Timeout/Reset aus.
5. Stellen Sie den Snapshot wieder her; bei VM-Zielen stellen Sie, sofern unterstützt, nur die **veränderten Seiten** wieder her, und wiederholen Sie den Vorgang.

Platzieren Sie den Snapshot so nah wie praktisch möglich am ersten aufwendigen Parse-/Dispatch-Schritt, etwa nach einem `recv`/`read` oder einem Punkt der Paket-Deserialisierung, und protokollieren Sie den vom Ziel verwendeten Input-Puffer. Dies folgt dem Prinzip der adaptiven Platzierung, den Snapshot tiefer in die Input-Verarbeitung zu verschieben, um wiederholte Arbeit zu vermeiden.<sup>[[11]](#references)</sup>

## Harness-Introspektion: Flache Fuzzer frühzeitig finden

Wenn eine Kampagne ins Stocken gerät, liegt das Problem häufig nicht am Mutator, sondern am **Harness**. Verwenden Sie eine **Introspektion von Erreichbarkeit/Coverage**, um Funktionen zu finden, die von Ihrem Fuzz Target aus statisch erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Diese Funktionen weisen normalerweise auf eines von drei Problemen hin.<sup>[[12]](#references)</sup>

- Der Harness betritt das Ziel zu spät oder zu früh.
- Im Seed-Corpus fehlt eine vollständige Feature-Familie.
- Das Ziel benötigt tatsächlich einen **zweiten Harness** anstelle eines übergroßen „Do-Everything“-Harness.

Wenn Sie OSS-Fuzz-/ClusterFuzz-ähnliche Workflows verwenden, kann Fuzz Introspector die statische Erreichbarkeit mit der Runtime-Coverage vergleichen und Reports aus einem zeitlich begrenzten Lauf oder einem öffentlichen Corpus erzeugen.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Verwende den Report, um zu entscheiden, ob ein neuer Harness für einen ungetesteten Parser-Pfad hinzugefügt, die Corpus für ein bestimmtes Feature erweitert oder ein monolithischer Harness in kleinere Entry Points aufgeteilt werden soll.

## Graph-First Fuzz Target Selection And Mutation Triage

Wenn bereits **Ergebnisse der statischen Analyse**, **Mutation-Testing-Survivors** und **Coverage-Reports** vorhanden sind, sollten diese nicht als unabhängige Listen triagiert werden. Erstelle zuerst einen **Call Graph**, annotiere die Nodes mit **zyklomatischer Komplexität**, **Erreichbarkeit durch Entry Points/uner­trauenswürdige Eingaben** und externen Findings, und stelle anschließend Fragen zum Graphen.<sup>[[5]](#references)[[6]](#references)</sup>

- Welche Funktionen mit hoher Komplexität sind von uner­trauenswürdigen Eingaben aus erreichbar?
- Welche Mutation Survivors liegen auf Pfaden von Parsern/Handlern zu sicherheitskritischem Code?
- Welche Funktionen sind architektonische Choke Points mit ungewöhnlich hohem **Blast Radius**?

Dadurch werden normalerweise bessere Fuzz Targets sichtbar als durch alleinige Betrachtung der „niedrigsten Coverage“. Ein Parser/Decoder mit **hoher Komplexität** und bestätigter **externer Erreichbarkeit** ist ein besserer Harness-Kandidat als ein isolierter interner Helper mit schwacher Coverage, aber ohne vom Angreifer kontrollierten Pfad.

### Praktischer Triage-Workflow

1. Erstelle einen **Code Graph** aus der Codebase und extrahiere Komplexitäts-/Branch-Metriken für jede Funktion.
2. Ermittle **Entry Points**, die vom Angreifer kontrollierte Eingaben akzeptieren: Request Handler, Decoder, Importer, Protokoll-Parser, CLI-/File-Reader.
3. Führe **Path Queries** von diesen Entry Points zu den Kandidatenfunktionen aus, um erreichbare Angriffsfläche von nicht erreichbarem bzw. ausschließlich internem Code zu trennen.
4. Priorisiere Nodes, die Folgendes kombinieren:
- hohe **zyklomatische Komplexität**
- bestätigte **Erreichbarkeit durch uner­trauenswürdige Eingaben**
- hoher **Blast Radius** oder viele nachgelagerte Abhängigkeiten
- zusätzliche Belege wie **SARIF**-Findings, Audit-Notizen oder Mutation Survivors
5. Schreibe zuerst fokussierte Harnesses für die am besten bewerteten Nodes, insbesondere für **Parser/Codecs** wie Hex-/Base64-/IP-/Message-Decoder.

### Mutation Survivors: äquivalent vs. verwertbar

Mutation Testing erzeugt häufig eine umfangreiche Survivor-Liste. Bevor jeder Survivor als Sicherheitslücke behandelt wird, sollte anhand des Graphen geprüft werden:

- Ist die mutierte Funktion von einem vom Angreifer kontrollierten Entry Point aus erreichbar?
- Werden alle Call Paths durch stärkere Invarianten eingeschränkt als durch den mutierten Check?
- Befindet sich der Node in Dead Code, Formatierungslogik oder in einem sicherheitskritischen Arithmetic-/Parser-Pfad mit hoher Auswirkung?

Survivors, die weiterhin nicht erreichbar oder strukturell eingeschränkt sind, sind häufig **äquivalente Mutanten**. Survivors, die **erreichbar** bleiben und **Grenzbedingungen**, **Overflow-/Carry-Pfade** oder **sicherheitskritische Arithmetic-/Parsing-Logik** berühren, sollten aufgewertet werden zu:

- neuen Fuzz Harnesses
- direkten Property-/Invariant-Tests
- gezielten Edge-Case-Vektoren

### Externe Findings auf den Graphen abbilden

Wenn die SAST-Pipeline **SARIF** exportiert, projiziere die Findings anhand von **Datei + Zeilenbereich** auf Graph-Nodes und verwende den Graphen, um die Auswirkungen zu erweitern.<sup>[[6]](#references)</sup>

- Berechne den **Blast Radius** der markierten Funktion.
- Prüfe, ob das Finding auf einem Pfad von einem Entry Point liegt.
- Gruppiere benachbarte Findings, die auf denselben Choke Point zusammenfallen.

Das ist hilfreich, wenn entschieden werden soll, ob Fuzzing-Zeit in eine bestimmte Funktion investiert wird: Ein Node, der **erreichbar**, **komplex** ist und bereits **SAST-Treffer** aufweist, ist häufig ein besseres Target als ein lediglich komplexer Node ohne Angreiferpfad.

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
Die wichtige Methodik ist die Schnittmenge aus: **Komplexität x Exposure x Auswirkung**. Verwende das Diagramm, um Fuzzing-Ziele mit dem höchsten erwarteten Sicherheitswert auszuwählen, und nutze Mutation Survivors, um zu bestimmen, welche Grenzen und Invarianten dein Harness belasten muss.<sup>[[5]](#references)</sup>

## Go Fuzzing mit gosentry: Stärkerer Engine, typisierte Eingaben und Differential Checks

Wenn ein Go-Ziel bereits über ein natives `testing.F`-Harness verfügt, besteht ein praktischer Upgrade-Pfad darin, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen – einer geforkten Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend durch **LibAFL** ersetzt.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Dies ist nützlich, wenn der native Go-Fuzzer bei **hard comparisons**, **typed inputs** oder **parser-heavy formats** ins Stocken gerät. Die Methodik bleibt gleich:

- Verwende weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback.
- Verwende denselben Harness, führe ihn aber mit gosentrys `go`-Binary anstelle der standardmäßigen Toolchain aus.
- Behandle die resultierende Kampagne wie einen normalen coverage-guided Lauf, jedoch mit LibAFL-Scheduling/Mutation und besseren umgebenden Detektoren.

### Stille Fehler in Fuzzing-Funde umwandeln

Ein wiederkehrendes Problem bei Go-Assessments ist, dass gefährliches Verhalten standardmäßig oft **keinen** Crash verursacht. Mit gosentry kannst du mehrere Klassen von „schlechten, aber stillen“ Zuständen in Findings umwandeln.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, damit ausgewählte Logging-/Error-Pfade wie Crashes behandelt werden (nützlich für `log.Fatal`-artige Codepfade, die sonst nur loggen und fortfahren).
- `--catch-races=true`, um neu entdeckte Queue-Einträge mit dem Go Race Detector erneut abzuspielen.
- `--catch-leaks=true`, um neue Queue-Einträge mit `goleak` erneut abzuspielen und bei Goroutine-Leaks abzubrechen.
- LibAFL-Hang-Handling, damit **infinite loops / very slow inputs** als Fuzzing-Funde erhalten bleiben, anstatt als Timeouts zu verschwinden.
- Standardmäßig integrierte Checks auf arithmetischen Overflow sowie optionale Truncation-Checks durch go-panikint-artige Instrumentierung.

Dies ist besonders wertvoll für Targets, bei denen die Security-Auswirkung ein **panicless parser failure**, ein **concurrency bug** oder ein **DoS-only hang** anstelle von Memory Corruption ist.

### Struct-aware Fuzzing für typisierte Go-APIs

Native Go-Fuzzing erwartet hauptsächlich Skalare wie `[]byte`, `string` und Zahlen. Wenn der getestete Code typisierte Objekte verarbeitet, kann gosentry **zusammengesetzte Werte** direkt fuzzten (Structs, Slices, Arrays, Pointer) und dabei weiterhin die zugrunde liegenden Bytes mutieren.<sup>[[7]](#references)[[8]](#references)</sup>
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
Verwende dies beim Erstellen eines gefälschten Wire-Formats nur zum Fuzzing, da Logikfehler durch ausschließlich im Harness vorhandenen Parsing-Code verborgen werden könnten. Bei Differential- oder Grammar-based-Kampagnen sollte der Harness-Input ein einzelnes `[]byte` oder ein einzelner `string` bleiben, und das Parsing stattdessen innerhalb des Callbacks erfolgen.

### Grammar-based Fuzzing für Parser- und Protokoll-Inputs

Für Parser, Formate und Input-Sprachen kann gosentry **Nautilus grammar fuzzing** auf Basis von LibAFL ausführen. Die Grammar ist ein JSON-Array aus Produktionsregeln, und der Harness sollte normalerweise ein einzelnes `[]byte`- oder `string`-Argument entgegennehmen.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodiknotizen:

- Verwende den grammar mode, wenn byte-level mutations größtenteils an frühen Syntaxprüfungen scheitern.
- Beschränke die grammar auf den **sicherheitsrelevanten Teilbereich** der Sprache bzw. des Protokolls, anstatt die vollständige Spezifikation zu modellieren.
- Verwende große Grenzwerte in Terminals/Nichtterminals, um Integer-, Längen- und Zustandsmaschinen-Grenzfälle zu belasten.
- Der grammar mode hält Inputs grammatikalisch gültig, aber das Ziel empfängt weiterhin **Bytes/Strings**, sodass Parsing und semantische Prüfungen innerhalb des instrumentierten Codes verbleiben.

### Differential fuzzing: Implementierungen vergleichen, nicht nur Crashes

Ein starkes Muster für Go-Ökosysteme ist **grammatikbasiertes Differential fuzzing**: Erzeuge gültige strukturierte Inputs und übergib sie an zwei Parser, Clients oder Zustandsübergangs-Engines.<sup>[[7]](#references)[[8]](#references)</sup>
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

- eine Implementierung gerät in Panik, während die andere die Eingabe ordnungsgemäß ablehnt
- Abweichungen zwischen akzeptierten und abgelehnten Eingaben
- unterschiedliche Parse-Bäume oder dekodierte Objekte
- abweichende Zustandsübergänge, Nonces, Salden oder State Roots

Dies ist eine praktische Methode, um **Konsensabweichungen**, **Parser-Ambiguität** und **Abweichungen zwischen Spezifikation und Implementierung** zu finden, die beim reinen Crash-Fuzzing häufig übersehen werden.

### Das Campaign-Corpus für die Coverage-Berichterstattung wiederverwenden

Nach einer Campaign kann das gespeicherte Queue-Corpus erneut abgespielt werden, um einen Go-Coverage-Bericht zu erstellen, ohne manuell ein separates Corpus zu exportieren.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Führe den Befehl aus demselben **Paket** und mit demselben `-fuzz`-**Ziel** aus, damit gosentry den richtigen Zustand der zwischengespeicherten Kampagne auflöst.

## References

- [1] [Mutationales Grammar-Fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing im Detail](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet fünf Jahre später: Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verwandelt Code in Graphen](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Beim Go-Fuzzing fehlte die Hälfte des Toolkits. Wir haben die Toolchain geforkt, um das zu beheben.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ein schneller Greybox-Fuzzer für zustandsbehaftete Netzwerkprotokolle mit Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Keine Grammar, kein Problem: Auf dem Weg zum Fuzzing des Linux-Kernels ohne System-Call-Beschreibungen](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Effizientes Fuzzing mit adaptiven und veränderbaren Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
