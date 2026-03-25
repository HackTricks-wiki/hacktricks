# Fuzzing Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantik

In **mutational grammar fuzzing** werden Eingaben verändert, bleiben dabei aber **grammatikalisch gültig**. Im coverage-guided Modus werden nur Samples, die **neue Coverage** auslösen, als Corpus-Seeds gespeichert. Bei **language targets** (parsers, interpreters, engines) kann das Bugs übersehen, die **semantische/ dataflow-Ketten** erfordern, wobei die Ausgabe eines Konstrukts zur Eingabe eines anderen wird.

**Fehlermodus:** der Fuzzer findet Seeds, die einzeln `document()` und `generate-id()` (oder ähnliche Primitiven) ausführen, bewahrt aber nicht den verketteten Datenfluss, sodass das „näher-am-Bug“-Sample verworfen wird, weil es keine zusätzliche Coverage liefert. Bei 3+ abhängigen Schritten wird zufällige Rekombination teuer und Coverage-Feedback führt die Suche nicht.

**Folgerung:** Bei stark abhängigen Grammatiken sollte man erwägen, mutationale und generative Phasen zu hybridisieren oder die Generierung zugunsten von Function-Chaining-Mustern zu biasieren (nicht nur Coverage).

## Probleme bei Corpus-Diversität

Coverage-guided mutation ist gierig: Ein Sample mit neuer Coverage wird sofort gespeichert, häufig mit großen unveränderten Bereichen. Mit der Zeit werden die Corpora zu Nahe-Duplikaten mit geringer struktureller Diversität. Aggressive Minimierung kann nützlichen Kontext entfernen; ein praktischer Kompromiss ist grammar-aware Minimierung, die nach Erreichen einer minimalen Token-Schwelle stoppt (Rauschen reduzieren und gleichzeitig genug umgebende Struktur erhalten, damit Mutationen weiterhin funktionieren).

## Single-Machine Diversity Trick (Jackalope-Style)

Eine praktische Methode, generative Neuheiten mit Coverage-Wiederverwendung zu hybridisieren, ist das Neustarten kurzlebiger Workers gegen einen persistenten Server. Jeder Worker startet mit einem leeren Corpus, synchronisiert nach T Sekunden, läuft weitere T Sekunden auf dem kombinierten Corpus, synchronisiert erneut und beendet sich dann. Das erzeugt bei jeder Generation frische Strukturen, während die angesammelte Coverage weiterhin genutzt wird.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequenzielle Worker (Beispiel-Schleife):**

<details>
<summary>Jackalope worker Neustart-Schleife</summary>
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

- `-in empty` erzwingt bei jeder Generierung ein **frisches Korpus**.
- `-server_update_interval T` approximiert eine **verzögerte Synchronisation** (zuerst Neuheit, später Wiederverwendung).
- In grammar fuzzing mode wird die **initiale Server-Synchronisation standardmäßig übersprungen** (kein Bedarf für `-skip_initial_server_sync`).
- Optimales `T` ist **zielabhängig**; ein Wechsel, nachdem der worker den Großteil der „einfachen“ coverage gefunden hat, funktioniert meist am besten.

## Referenzen

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
