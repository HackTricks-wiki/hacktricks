# Metodologia di Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Copertura vs. Semantica

In **mutational grammar fuzzing**, gli input vengono mutati rimanendo **validi rispetto alla grammatica**. In modalità coverage-guided, solo i campioni che attivano **nuova coverage** vengono salvati come seed del corpus. Per i **language targets** (parsers, interpreters, engines), questo può far perdere bug che richiedono **semantic/dataflow chains** in cui l'output di una costruzione diventa l'input di un'altra.

**Failure mode:** il fuzzer trova seed che singolarmente esercitano `document()` e `generate-id()` (o primitive simili), ma **non preserva il dataflow concatenato**, quindi il campione “più vicino al bug” viene scartato perché non aggiunge coverage. Con **3+ passi dipendenti**, la ricombinazione casuale diventa costosa e il feedback di coverage non guida la ricerca.

**Implication:** per grammatiche con molte dipendenze, considera di ibridare le fasi mutational e generative o di biasare la generazione verso pattern di chaining di funzioni (non solo coverage).

## Insidie della diversità del corpus

La mutation coverage-guided è **greedy**: un campione che produce nuova coverage viene salvato immediatamente, spesso mantenendo ampie regioni invariate. Col tempo, i corpora diventano **quasi-duplicati** con bassa diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è una **minimizzazione grammar-aware** che **si arresta dopo una soglia minima di token** (riduce il rumore mantenendo abbastanza struttura circostante per rimanere mutation-friendly).

## Trucco per diversità su singola macchina (Jackalope-Style)

Un modo pratico per ibridare la novità generativa con il riuso della coverage è riavviare worker di breve durata contro un server persistente. Ogni worker parte da un corpus vuoto, si sincronizza dopo `T` secondi, esegue altri `T` secondi sul corpus combinato, si sincronizza di nuovo, poi termina. Questo genera **strutture fresche ad ogni generazione** sfruttando comunque la coverage accumulata.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Workers sequenziali (esempio di ciclo):**

<details>
<summary>Ciclo di riavvio del worker Jackalope</summary>
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

**Note:**

- `-in empty` forza un **fresh corpus** ad ogni generazione.
- `-server_update_interval T` approssima la **delayed sync** (novità prima, riuso dopo).
- In grammar fuzzing mode, **initial server sync is skipped by default** (non è necessario usare `-skip_initial_server_sync`).
- Il valore ottimale di `T` è **target-dependent**; cambiare dopo che il worker ha trovato la maggior parte della “easy” coverage tende a funzionare meglio.

## Riferimenti

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
