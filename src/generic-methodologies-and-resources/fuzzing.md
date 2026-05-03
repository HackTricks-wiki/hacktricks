# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Beim **mutational grammar fuzzing** werden Eingaben mutiert, während sie **grammar-valid** bleiben. Im coverage-guided Modus werden nur Samples, die **neue Coverage** auslösen, als Corpus-Seeds gespeichert. Für **language targets** (Parser, Interpreter, Engines) kann das Bugs übersehen, die **semantic/dataflow chains** erfordern, bei denen die Ausgabe einer Konstruktion zur Eingabe einer anderen wird.

**Failure mode:** Der Fuzzer findet Seeds, die jeweils `document()` und `generate-id()` (oder ähnliche Primitives) ausführen, aber **er erhält die verkettete dataflow nicht aufrecht**, sodass das Sample, das „näher am Bug“ ist, verworfen wird, weil es keine Coverage hinzufügt. Mit **3+ abhängigen Schritten** wird zufällige Neukombination teuer, und Coverage-Feedback steuert die Suche nicht.

**Implication:** Bei Grammars mit vielen Abhängigkeiten sollte man **mutational und generative Phasen hybridisieren** oder die Generierung in Richtung **function chaining**-Muster biasen (nicht nur Coverage).

## Corpus Diversity Pitfalls

Coverage-guided Mutation ist **greedy**: Ein Sample mit neuer Coverage wird sofort gespeichert und behält oft große unveränderte Bereiche. Mit der Zeit werden Corpora zu **near-duplicates** mit geringer struktureller Diversität. Aggressive Minimierung kann nützlichen Kontext entfernen, daher ist ein praktischer Kompromiss **grammar-aware minimization**, die **nach einem minimalen Token-Threshold stoppt** (Rauschen reduzieren, aber genug umgebende Struktur behalten, um mutation-friendly zu bleiben).

Eine praktische Corpus-Regel für mutational fuzzing ist: **lieber einen kleinen Satz strukturell unterschiedlicher Seeds, der maximale Coverage erzielt, als einen großen Haufen near-duplicates**. In der Praxis bedeutet das meist:

- Mit **real-world samples** beginnen (öffentliche Corpora, Crawling, aufgezeichnete Traffic-Daten, Dateisätze aus dem Ziel-Ökosystem).
- Sie mit **coverage-based corpus minimization** verdichten, statt jedes gültige Sample zu behalten.
- Seeds **klein genug** halten, damit Mutationen auf sinnvolle Felder treffen, statt die meiste Zeit mit irrelevanten Bytes zu verbringen.
- Corpus-Minimierung nach größeren Änderungen am Harness/Instrumentation erneut ausführen, weil sich das „beste“ Corpus ändert, wenn sich die Erreichbarkeit ändert.

## Comparison-Aware Mutation For Magic Values

Ein häufiger Grund, warum Fuzzer stagnieren, ist nicht Syntax, sondern **hard comparisons**: Magic Bytes, Längenprüfungen, Enum-Strings, Checksums oder Parser-Dispatch-Werte, die durch `memcmp`, Switch-Tabellen oder verkettete Vergleiche geschützt sind. Reine Zufallsmutation verschwendet Zyklen damit, diese Werte Byte für Byte zu erraten.

Für diese Targets sollte man **comparison tracing** verwenden (zum Beispiel AFL++ `CMPLOG` / Redqueen-style Workflows), damit der Fuzzer Operanden aus fehlgeschlagenen Vergleichen beobachten und Mutationen in Richtung der Werte biasen kann, die sie erfüllen.
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

- Das ist besonders nützlich, wenn das Ziel tiefe Logik hinter **file signatures**, **protocol verbs**, **type tags** oder **version-dependent feature bits** versteckt.
- Kombiniere es mit **dictionaries**, die aus echten Samples, Protocol Specs oder Debug-Logs extrahiert wurden. Ein kleines Dictionary mit Grammar-Tokens, Chunk-Namen, Verben und Delimiters ist oft wertvoller als eine massive generische Wordlist.
- Wenn das Ziel viele sequentielle Checks ausführt, löse zuerst die frühesten „magic“-Vergleiche und minimiere anschließend den resultierenden Corpus erneut, damit spätere Stufen von bereits gültigen Prefixes ausgehen.

## Stateful Fuzzing: Sequences Are Seeds

Bei **protocols**, **authenticated workflows** und **multi-stage parsers** ist die interessante Einheit oft nicht ein einzelner Blob, sondern eine **message sequence**. Die gesamte Transkription in eine Datei zu concatenaten und blind zu mutieren ist meist ineffizient, weil der Fuzzer jeden Schritt gleich stark mutiert, selbst wenn nur die spätere Message den fragilen Zustand erreicht.

Ein effektiveres Muster ist, die **sequence selbst als Seed** zu behandeln und **observable state** (Response-Codes, Protocol-States, Parser-Phasen, zurückgegebene Objekt-Typen) als zusätzliches Feedback zu verwenden:

- Behalte **valid prefix messages** stabil und konzentriere die Mutationen auf die **transition-driving** Message.
- Cache Identifiers und server-generierte Werte aus vorherigen Responses, wenn der nächste Schritt davon abhängt.
- Bevorzuge Mutation/Splicing pro Message statt den gesamten serialisierten Transcript als opaque Blob zu mutieren.
- Wenn das Protocol aussagekräftige Response-Codes bereitstellt, nutze sie als einen **cheap state oracle**, um Sequenzen zu priorisieren, die tiefer fortschreiten.

Das ist derselbe Grund, warum authenticated bugs, hidden transitions oder Parser-Bugs, die nur „after-handshake“ auftreten, beim klassischen file-style fuzzing oft übersehen werden: Der Fuzzer muss **Reihenfolge, State und Abhängigkeiten** erhalten, nicht nur die Struktur.

## Single-Machine Diversity Trick (Jackalope-Style)

Eine praktische Methode, **generative novelty** mit **coverage reuse** zu hybridisieren, ist das **Neustarten kurzlebiger Workers** gegen einen persistenten Server. Jeder Worker startet mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden auf dem kombinierten Corpus, synchronisiert erneut und beendet sich dann. Das erzeugt **frische Strukturen pro Generation**, während die angesammelte Coverage weiterhin genutzt wird.

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

**Notizen:**

- `-in empty` erzwingt für jede Generation ein **frisches Korpus**.
- `-server_update_interval T` approximiert **verzögerten Sync** (zuerst Neuheit, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird der **erste Server-Sync standardmäßig übersprungen** (kein Bedarf für `-skip_initial_server_sync`).
- Das optimale `T` ist **zielabhängig**; ein Wechsel, nachdem der Worker den Großteil der „einfachen“ Coverage gefunden hat, funktioniert meist am besten.

## Snapshot Fuzzing Für Schwer Einzubindende Ziele

Wenn der Code, den du testen willst, erst **nach einem großen Setup-Aufwand** erreichbar wird (eine VM booten, einen Login abschließen, ein Paket empfangen, einen Container parsen, einen Service initialisieren), ist eine nützliche Alternative **snapshot fuzzing**:

1. Lass das Ziel laufen, bis der interessante Zustand bereit ist.
2. Erstelle an diesem Punkt einen Snapshot von **Speicher + Registern**.
3. Schreibe für jeden Testfall die mutierte Eingabe direkt in den relevanten Guest/Prozess-Buffer.
4. Führe bis Crash/Timeout/Reset aus.
5. Stelle nur die **dirty pages** wieder her und wiederhole.

Das vermeidet, bei jeder Iteration die vollen Setup-Kosten zu zahlen, und ist besonders nützlich für **Netzwerkdienste**, **Firmware**, **post-auth attack surfaces** und **binary-only targets**, die sich nur schwer in einen klassischen In-Process-Harness umrefaktorieren lassen.

Ein praktischer Trick ist, direkt nach einem `recv`/`read`/Packet-Deserialisierungs-Punkt anzuhalten, die Adresse des Input-Buffers zu notieren, dort einen Snapshot zu erstellen und dann diesen Buffer in jeder Iteration direkt zu mutieren. So kannst du die tiefe Parsing-Logik fuzzing, ohne jedes Mal den gesamten Handshake neu aufzubauen.

## Harness-Introspektion: Shallow Fuzzer Früh Finden

Wenn eine Kampagne stagniert, liegt das Problem oft nicht am Mutator, sondern am **Harness**. Nutze **Reachability/Coverage-Introspection**, um Funktionen zu finden, die statisch von deinem Fuzz-Ziel aus erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Diese Funktionen deuten normalerweise auf eines von drei Problemen hin:

- Das Harness betritt das Ziel zu spät oder zu früh.
- Dem Seed-Korpus fehlt eine ganze Feature-Familie.
- Das Ziel braucht wirklich ein **zweites Harness** statt eines übergroßen „do everything“-Harness.

Wenn du OSS-Fuzz / ClusterFuzz-ähnliche Workflows nutzt, ist Fuzz Introspector für dieses Triage nützlich:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Verwende den Report, um zu entscheiden, ob ein neues harness für einen ungetesteten parser path hinzugefügt, der Corpus für eine bestimmte feature erweitert oder ein monolithisches harness in kleinere entry points aufgeteilt werden soll.

## Graph-First Fuzz Target Selection And Mutation Triage

Wenn du bereits **static-analysis findings**, **mutation-testing survivors** und **coverage reports** hast, triagierst du sie nicht als unabhängige Listen. Erstelle zuerst einen **call graph**, annotiere Knoten mit **cyclomatic complexity**, **entrypoint/untrusted-input reachability** und allen externen Findings, und stelle dann Graph-Fragen:

- Welche Funktionen mit hoher Komplexität sind von untrusted input aus erreichbar?
- Welche mutation survivors liegen auf Pfaden von parsers/handlers zu security-critical code?
- Welche Funktionen sind architektonische choke points mit ungewöhnlich hoher **blast radius**?

Das liefert meist bessere fuzz targets als nur die „niedrigste coverage“. Ein parser/decoder mit **hoher Komplexität** und bestätigter **external reachability** ist ein stärkerer Kandidat für ein harness als ein isolierter interner helper mit schwacher coverage, aber ohne attacker-controlled path.

### Praktischer Triage-Workflow

1. Erstelle einen **code graph** aus der Codebase und extrahiere pro Funktion complexity-/branch-Metriken.
2. Liste **entrypoints** auf, die attacker-controlled input annehmen: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Führe **path queries** von diesen entrypoints zu Kandidatenfunktionen aus, um erreichbare attack surface von totem/nur internem Code zu trennen.
4. Priorisiere Knoten, die Folgendes kombinieren:
- hohe **cyclomatic complexity**
- bestätigte **reachability from untrusted input**
- hohe **blast radius** oder viele abhängige Downstream-Komponenten
- bestätigende Hinweise wie **SARIF** findings, Audit-Notizen oder mutation survivors
5. Schreibe fokussierte harnesses zuerst für die bestbewerteten Knoten, insbesondere **parsers/codecs** wie hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing erzeugt oft eine rauschige Survivor-Liste. Bevor du jeden Survivor als Security-Lücke behandelst, nutze den Graphen, um zu fragen:

- Ist die mutierte Funktion von einem attacker-controlled entrypoint aus erreichbar?
- Sind alle Call Paths durch stärkere Invarianten eingeschränkt als die mutierte Prüfung?
- Liegt der Knoten in totem Code, nur in formatting-Logik oder in einem High-Impact-Arithmetic/parser-Pfad?

Survivors, die unerreichbar bleiben oder strukturell eingeschränkt sind, sind oft **equivalent mutants**. Survivors, die **erreichbar** bleiben und **boundary conditions**, **overflow/carry paths** oder **security-critical arithmetic/parsing** berühren, sollten hochgestuft werden zu:

- neuen fuzz harnesses
- direkten property-/invariant tests
- gezielten edge-case vectors

### Externe Findings auf den Graphen korrelieren

Wenn deine SAST-Pipeline **SARIF** exportiert, projiziere Findings auf Graph-Knoten über **file + line range** und nutze den Graphen, um den Impact zu erweitern:

- berechne die **blast radius** der markierten Funktion
- prüfe, ob das Finding auf einem Pfad von einem entrypoint liegt
- clustere nahe beieinanderliegende Findings, die auf denselben choke point zusammenfallen

Das ist nützlich, wenn du entscheiden willst, ob du fuzzing-Zeit auf eine bestimmte Funktion verwenden solltest: Ein Knoten, der **erreichbar**, **komplex** und bereits mit **SAST hits** belegt ist, ist oft ein besseres Ziel als ein nur komplexer Knoten ohne attacker path.

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
Die wichtige Methodik ist die Schnittmenge: **Komplexität x Exposition x Auswirkung**. Verwende den Graphen, um Fuzz-Ziele mit dem höchsten erwarteten Sicherheitswert auszuwählen, und nutze Mutation survivors, um zu entscheiden, welche Grenzen und Invarianten dein Harness unter Stress setzen muss.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
