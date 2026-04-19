# Fuzzing-Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutationale Grammar-Fuzzing: Coverage vs. Semantik

Beim **mutational grammar fuzzing** werden Inputs mutiert, während sie **grammar-valid** bleiben. Im coverage-guided Modus werden nur Samples gespeichert, die **neue Coverage** auslösen, als Corpus-Seeds. Für **language targets** (Parser, Interpreter, Engines) kann dies Bugs übersehen, die **semantische/dataflow-Ketten** erfordern, bei denen die Ausgabe eines Konstrukts zur Eingabe eines anderen wird.

**Fehlermodus:** Der Fuzzer findet Seeds, die einzeln `document()` und `generate-id()` (oder ähnliche Primitiven) ausführen, aber **er erhält den verketteten Dataflow nicht aufrecht**, sodass das Sample, das „näher am Bug“ ist, verworfen wird, weil es keine zusätzliche Coverage bringt. Mit **3+ abhängigen Schritten** wird zufällige Rekombination teuer, und Coverage-Feedback steuert die Suche nicht.

**Implikation:** Für Grammars mit vielen Abhängigkeiten solltest du **mutationale und generative Phasen hybridisieren** oder die Generierung auf **function chaining**-Muster ausrichten (nicht nur auf Coverage).

## Fallstricke bei der Corpus-Diversität

Coverage-guided Mutation ist **greedy**: Ein Sample mit neuer Coverage wird sofort gespeichert, oft mit großen unveränderten Bereichen. Mit der Zeit werden Corpora zu **Near-Duplicates** mit geringer struktureller Diversität. Aggressive Minimierung kann nützlichen Kontext entfernen, daher ist ein praktischer Kompromiss **grammar-aware minimization**, die **nach Erreichen einer minimalen Token-Schwelle stoppt** (Rauschen reduzieren, aber genug umgebende Struktur erhalten, damit Mutationen weiterhin sinnvoll bleiben).

Eine praktische Corpus-Regel für mutational fuzzing ist: **bevorzuge eine kleine Menge strukturell unterschiedlicher Seeds, die maximale Coverage erzielen**, statt eines großen Haufens von Near-Duplicates. In der Praxis bedeutet das meist:

- Starte mit **real-world samples** (öffentliche Corpora, Crawling, aufgezeichnetem Traffic, Dateisätzen aus dem Ziel-Ökosystem).
- Destilliere sie mit **coverage-based corpus minimization**, statt jedes gültige Sample zu behalten.
- Halte Seeds **klein genug**, damit Mutationen auf bedeutenden Feldern landen, statt die meiste Zeit mit irrelevanten Bytes zu verbringen.
- Führe Corpus-Minimierung nach größeren Harness-/Instrumentierungsänderungen erneut aus, weil sich das „beste“ Corpus ändert, wenn sich die Erreichbarkeit ändert.

## Comparison-Aware Mutation Für Magic Values

Ein häufiger Grund, warum Fuzzer stagnieren, ist nicht Syntax, sondern **harte Vergleiche**: Magic Bytes, Längenprüfungen, Enum-Strings, Checksums oder Parser-Dispatch-Werte, die durch `memcmp`, switch tables oder kaskadierte Vergleiche abgesichert sind. Reine Zufallsmutation verschwendet Zyklen damit, diese Werte byteweise zu erraten.

Für diese Ziele verwende **comparison tracing** (zum Beispiel AFL++ `CMPLOG` / Redqueen-style Workflows), damit der Fuzzer Operanden aus fehlgeschlagenen Vergleichen beobachten und Mutationen in Richtung von Werten lenken kann, die sie erfüllen.
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

- Das ist besonders nützlich, wenn das Target tiefe Logik hinter **file signatures**, **protocol verbs**, **type tags** oder **version-dependent feature bits** verbirgt.
- Kombiniere es mit **dictionaries**, die aus echten Samples, Protocol Specs oder Debug-Logs extrahiert wurden. Ein kleines Dictionary mit Grammar-Tokens, Chunk-Namen, Verben und Delimitern ist oft wertvoller als eine riesige generische Wordlist.
- Wenn das Target viele sequenzielle Checks durchführt, löse zuerst die frühesten „magic“-Vergleiche und minimiere danach das resultierende Corpus erneut, damit spätere Stufen bereits mit gültigen Präfixen starten.

## Stateful Fuzzing: Sequences Are Seeds

Für **protocols**, **authenticated workflows** und **multi-stage parsers** ist die interessante Einheit oft nicht ein einzelner Blob, sondern eine **message sequence**. Das gesamte Transcript in eine Datei zu konkatenieren und blind zu mutieren ist meist ineffizient, weil der Fuzzer jeden Schritt gleich stark mutiert, selbst wenn nur die spätere Message den fragilen Zustand erreicht.

Ein effektiveres Muster ist, die **sequence selbst als Seed** zu behandeln und **observable state** (Response-Codes, protocol states, parser phases, returned object types) als zusätzliches Feedback zu nutzen:

- Behalte **valid prefix messages** stabil und konzentriere Mutationen auf die **transition-driving** Message.
- Cache Identifier und server-generierte Werte aus vorherigen Responses, wenn der nächste Schritt davon abhängt.
- Bevorzuge per-Message-Mutation/Splicing statt des Mutierens des gesamten serialisierten Transcripts als undurchsichtigen Blob.
- Wenn das Protocol aussagekräftige Response-Codes liefert, nutze sie als eine **cheap state oracle**, um Sequenzen zu priorisieren, die tiefer vorankommen.

Das ist derselbe Grund, warum authenticated bugs, hidden transitions oder „only-after-handshake“-Parser-Bugs von Vanilla file-style fuzzing oft übersehen werden: Der Fuzzer muss **order, state und dependencies** erhalten, nicht nur die Struktur.

## Single-Machine Diversity Trick (Jackalope-Style)

Eine praktische Möglichkeit, **generative novelty** mit **coverage reuse** zu hybridisieren, ist es, **kurzlebige Worker** gegen einen persistenten Server neu zu starten. Jeder Worker beginnt mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden mit dem kombinierten Corpus, synchronisiert erneut und beendet sich dann. Das erzeugt **frische Strukturen pro Generation**, während die akkumulierte Coverage weiterhin genutzt wird.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequenzielle Worker (Beispiel-Loop):**

<details>
<summary>Jackalope Worker-Neustart-Loop</summary>
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
- `-server_update_interval T` approximiert **verzögertes Sync** (Neuheit zuerst, Wiederverwendung später).
- Im Grammar-Fuzzing-Modus wird der **anfängliche Server-Sync standardmäßig übersprungen** (kein Bedarf für `-skip_initial_server_sync`).
- Das optimale `T` ist **zielabhängig**; ein Wechsel, nachdem der Worker den Großteil der „einfachen“ Coverage gefunden hat, funktioniert meist am besten.

## Snapshot Fuzzing Für Schwer Zu Umhüllende Ziele

Wenn der Code, den du testen willst, erst **nach einem großen Setup-Aufwand** erreichbar wird (Starten einer VM, Abschließen eines Logins, Empfangen eines Pakets, Parsen eines Containers, Initialisieren eines Dienstes), ist eine nützliche Alternative **Snapshot Fuzzing**:

1. Lass das Ziel laufen, bis der interessante Zustand bereit ist.
2. Erstelle an diesem Punkt einen Snapshot von **Speicher + Registern**.
3. Schreibe für jeden Testfall die mutierte Eingabe direkt in den relevanten Guest-/Prozess-Puffer.
4. Führe bis zu Crash/Timeout/Reset aus.
5. Stelle nur die **dirty pages** wieder her und wiederhole den Vorgang.

Das vermeidet, bei jeder Iteration die vollen Setup-Kosten zu zahlen, und ist besonders nützlich für **Netzwerkdienste**, **Firmware**, **post-auth attack surfaces** und **binary-only targets**, die sich nur schwer in einen klassischen In-Process-Harness umrefaktorieren lassen.

Ein praktischer Trick ist, direkt nach einem `recv`/`read`/Packet-Deserialisierungs-Punkt zu unterbrechen, die Adresse des Eingabepuffers zu notieren, dort einen Snapshot zu erstellen und dann diesen Puffer in jeder Iteration direkt zu mutieren. So kannst du die tiefe Parsing-Logik fuzzing, ohne jedes Mal den gesamten Handshake neu aufzubauen.

## Harness Introspection: Find Shallow Fuzzers Early

Wenn eine Kampagne ins Stocken gerät, liegt das Problem oft nicht am Mutator, sondern am **Harness**. Nutze **Reachability-/Coverage-Introspection**, um Funktionen zu finden, die statisch von deinem Fuzz-Ziel aus erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Diese Funktionen deuten normalerweise auf eines von drei Problemen hin:

- Das Harness betritt das Target zu spät oder zu früh.
- Dem Seed-Corpus fehlt eine ganze Feature-Familie.
- Das Target braucht wirklich ein **zweites Harness** statt eines übergroßen „do everything“-Harness.

Wenn du OSS-Fuzz / ClusterFuzz-ähnliche Workflows verwendest, ist Fuzz Introspector für dieses Triage nützlich:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Benutze den Report, um zu entscheiden, ob du ein neues Harness für einen ungetesteten Parser-Pfad hinzufügen, den Corpus für ein bestimmtes Feature erweitern oder ein monolithisches Harness in kleinere Entry Points aufteilen solltest.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
