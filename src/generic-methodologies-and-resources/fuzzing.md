# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Nel **mutational grammar fuzzing**, gli input vengono mutati mantenendo la **validità grammaticale**. In modalità coverage-guided, solo i campioni che attivano **nuova coverage** vengono salvati come seed del corpus. Per i **target linguistici** (parser, interpreter, engine), questo può far perdere bug che richiedono **catene semantiche/dataflow** in cui l’output di una costruzione diventa l’input di un’altra.

**Modalità di errore:** il fuzzer trova seed che, singolarmente, esercitano `document()` e `generate-id()` (o primitive simili), ma **non preserva il dataflow concatenato**, quindi il campione “più vicino al bug” viene scartato perché non aggiunge coverage. Con **3+ step dipendenti**, la ricombinazione casuale diventa costosa e il feedback della coverage non guida la ricerca.

**Implicazione:** per grammatiche con molte dipendenze, considera di **ibridare fasi mutational e generative** oppure di orientare la generazione verso pattern di **function chaining** (non solo coverage).

## Corpus Diversity Pitfalls

La mutazione guidata dalla coverage è **greedy**: un campione con nuova coverage viene salvato immediatamente, spesso mantenendo grandi regioni invariate. Col tempo, i corpus diventano **quasi duplicati** con bassa diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è la **minimizzazione aware della grammar** che **si ferma dopo una soglia minima di token** (riduce il rumore mantenendo abbastanza struttura circostante da restare mutation-friendly).

Una regola pratica per il corpus nel mutational fuzzing è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzano la coverage** invece di una grande massa di quasi duplicati. In pratica, questo di solito significa:

- Parti da **sample reali** (public corpora, crawling, traffico catturato, set di file dell’ecosistema target).
- Distillali con **coverage-based corpus minimization** invece di tenere ogni campione valido.
- Mantieni i seed **abbastanza piccoli** da far sì che le mutazioni colpiscano campi significativi invece di sprecare la maggior parte dei cicli su byte irrilevanti.
- Riesegui la minimizzazione del corpus dopo grandi cambiamenti a harness/instrumentation, perché il corpus “migliore” cambia quando cambia la reachability.

## Comparison-Aware Mutation For Magic Values

Un motivo comune per cui i fuzzer vanno in plateau non è la sintassi ma i **confronti difficili**: magic bytes, controlli di lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, switch table o confronti a cascata. La mutazione puramente casuale spreca cicli cercando di indovinare questi valori byte per byte.

Per questi target, usa la **comparison tracing** (ad esempio workflow stile AFL++ `CMPLOG` / Redqueen) così il fuzzer può osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.
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
**Note pratiche:**

- Questo è particolarmente utile quando il target nasconde logica profonda dietro **file signatures**, **protocol verbs**, **type tags** o **version-dependent feature bits**.
- Combinalo con **dictionaries** estratti da campioni reali, specifiche di protocollo o debug logs. Un piccolo dizionario con grammar tokens, nomi di chunk, verbs e delimitatori è spesso più prezioso di una enorme wordlist generica.
- Se il target esegue molti controlli sequenziali, risolvi prima le comparazioni “magic” più iniziali e poi minimizza di nuovo il corpus risultante così che le fasi successive partano da prefissi già validi.

## Stateful Fuzzing: Le sequenze sono seed

Per **protocols**, **authenticated workflows** e **multi-stage parsers**, l’unità interessante spesso non è un singolo blob ma una **message sequence**. Concatenare l’intero transcript in un solo file e mutarlo alla cieca è di solito inefficiente perché il fuzzer muta ogni passo allo stesso modo, anche quando solo il messaggio finale raggiunge lo stato fragile.

Un pattern più efficace è trattare la **sequence stessa come seed** e usare lo **observable state** (response codes, protocol states, parser phases, returned object types) come feedback aggiuntivo:

- Mantieni stabili i **valid prefix messages** e concentra le mutazioni sul messaggio che **drives the transition**.
- Memorizza identificatori e valori generati dal server dalle risposte precedenti quando il passo successivo dipende da essi.
- Preferisci la mutazione/splicing per-messaggio invece di mutare l’intero transcript serializzato come un blob opaco.
- Se il protocollo espone response codes significativi, usali come un **cheap state oracle** per dare priorità alle sequenze che progrediscono più in profondità.

Questo è lo stesso motivo per cui bug autenticati, transizioni nascoste o bug di parser “only-after-handshake” vengono spesso persi dal file-style fuzzing classico: il fuzzer deve preservare **order, state, and dependencies**, non solo la struttura.

## Single-Machine Diversity Trick (Jackalope-Style)

Un modo pratico per ibridare **generative novelty** con **coverage reuse** è **riavviare worker a vita breve** contro un server persistente. Ogni worker parte da un corpus vuoto, si sincronizza dopo `T` secondi, esegue altri `T` secondi sul corpus combinato, si sincronizza di nuovo, poi termina. Questo produce **strutture fresche a ogni generazione** pur sfruttando la coverage accumulata.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Worker sequenziali (loop di esempio):**

<details>
<summary>Jackalope worker restart loop</summary>
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

- `-in empty` forza un **corpus fresco** a ogni generazione.
- `-server_update_interval T` approssima una **sync ritardata** (novelty prima, reuse dopo).
- In modalità grammar fuzzing, la **sync iniziale con il server viene saltata di default** (non serve `-skip_initial_server_sync`).
- Il valore ottimale di `T` dipende dal **target**; cambiare dopo che il worker ha trovato la maggior parte della coverage “facile” tende a funzionare meglio.

## Snapshot Fuzzing Per Target Difficili Da Harnessare

Quando il codice che vuoi testare diventa raggiungibile solo **dopo un grande costo di setup** (avviare una VM, completare un login, ricevere un packet, parsare un container, inizializzare un service), una valida alternativa è **snapshot fuzzing**:

1. Esegui il target finché lo stato interessante è pronto.
2. Fai uno snapshot di **memory + registers** in quel punto.
3. Per ogni test case, scrivi l’input mutato direttamente nel buffer rilevante del guest/process.
4. Esegui fino a crash/timeout/reset.
5. Ripristina solo le **dirty pages** e ripeti.

Questo evita di pagare il costo completo di setup a ogni iterazione ed è particolarmente utile per **network services**, **firmware**, **post-auth attack surfaces** e **binary-only targets** che sono difficili da rifattorizzare in un classico harness in-process.

Un trucco pratico è interrompere subito dopo un punto `recv`/`read`/packet-deserialization, annotare l’indirizzo del buffer di input, fare lo snapshot lì, e poi mutare direttamente quel buffer a ogni iterazione. Questo ti permette di fuzzare la logica di parsing profonda senza ricostruire ogni volta l’intero handshake.

## Harness Introspection: Trova Presto i Fuzzer Superficiali

Quando una campaign si blocca, il problema spesso non è il mutator ma l’**harness**. Usa l’**introspection di reachability/coverage** per trovare funzioni che sono staticamente raggiungibili dal tuo fuzz target ma che raramente o mai vengono coperte dinamicamente. Quelle funzioni di solito indicano uno di tre problemi:

- L’harness entra nel target troppo tardi o troppo presto.
- Il seed corpus manca di un’intera famiglia di feature.
- Il target ha davvero bisogno di un **second harness** invece di un unico harness enorme “fa tutto”.

Se usi workflow in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector è utile per questo triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa il report per decidere se aggiungere un nuovo harness per un parser path non testato, ampliare il corpus per una funzionalità specifica, oppure dividere un harness monolitico in entry point più piccoli.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
