# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Fuzzing di grammatica mutazionale: Coverage vs. Semantics

Nel **fuzzing di grammatica mutazionale**, gli input vengono mutati restando **validi secondo la grammatica**. In modalità coverage-guided, solo i campioni che attivano **nuova coverage** vengono salvati come seed del corpus. Per i **target linguistici** (parser, interpreter, engine), questo può far perdere bug che richiedono **catene semantiche/dataflow** in cui l’output di una costruzione diventa l’input di un’altra.

**Modalità di fallimento:** il fuzzer trova seed che singolarmente esercitano `document()` e `generate-id()` (o primitive simili), ma **non preserva il dataflow concatenato**, quindi il campione “più vicino al bug” viene scartato perché non aggiunge coverage. Con **3+ step dipendenti**, la ricombinazione casuale diventa costosa e il feedback della coverage non guida la ricerca.

**Implicazione:** per grammatiche con molte dipendenze, considera di **ibridare fasi mutazionali e generative** oppure di orientare la generazione verso pattern di **function chaining** (non solo coverage).

## Pitfall della diversità del corpus

La mutazione guidata dalla coverage è **greedy**: un campione con nuova coverage viene salvato immediatamente, spesso mantenendo ampie regioni invariate. Col tempo, i corpus diventano **quasi duplicati** con bassa diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è la **minimizzazione consapevole della grammatica** che **si ferma dopo una soglia minima di token** (riduce il rumore mantenendo abbastanza struttura circostante da restare adatta alla mutazione).

Una regola pratica per il corpus nel fuzzing mutazionale è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzano la coverage** invece di una grande pila di quasi duplicati. In pratica, questo di solito ნიშნავს:

- Parti da **campioni reali** (corpus pubblici, crawling, traffico catturato, set di file dall’ecosistema del target).
- Distillali con **minimizzazione del corpus basata sulla coverage** invece di tenere ogni campione valido.
- Mantieni i seed **abbastanza piccoli** da far sì che le mutazioni colpiscano campi significativi invece di spendere la maggior parte dei cicli su byte irrilevanti.
- Riesegui la minimizzazione del corpus dopo grandi cambiamenti al harness/instrumentation, perché il corpus “migliore” cambia quando cambia la raggiungibilità.

## Mutazione comparison-aware per Magic Values

Una ragione comune per cui i fuzzer si bloccano non è la sintassi ma i **confronti difficili**: magic bytes, controlli di lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, tabelle `switch` o confronti cascati. La mutazione puramente casuale spreca cicli cercando di indovinare questi valori byte per byte.

Per questi target, usa **comparison tracing** (per esempio workflow stile AFL++ `CMPLOG` / Redqueen) così il fuzzer può osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.
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
- Combinalo con **dictionaries** estratti da campioni reali, specifiche di protocollo o debug logs. Un piccolo dictionary con grammar tokens, nomi di chunk, verbs e delimitatori è spesso più prezioso di una enorme generic wordlist.
- Se il target esegue molti controlli sequenziali, risolvi prima le comparazioni “magic” iniziali e poi minimizza di nuovo il corpus risultante, così le fasi successive partono da prefissi già validi.

## Stateful Fuzzing: Sequences Are Seeds

Per **protocols**, **authenticated workflows** e **multi-stage parsers**, l’unità interessante spesso non è un singolo blob ma una **message sequence**. Concatenare l’intera trascrizione in un unico file e mutarla ciecamente è di solito inefficiente perché il fuzzer muta ogni step in modo uguale, anche quando solo il messaggio successivo raggiunge lo stato fragile.

Un pattern più efficace è trattare la **sequence stessa come seed** e usare lo **stato osservabile** (response codes, protocol states, parser phases, returned object types) come feedback aggiuntivo:

- Mantieni stabili i messaggi di **valid prefix** e concentra le mutazioni sul messaggio che guida la **transition**.
- Memorizza identifiers e valori generati dal server dalle risposte precedenti quando il passo successivo dipende da essi.
- Preferisci mutation/splicing per singolo messaggio invece di mutare l’intera trascrizione serializzata come un blob opaco.
- Se il protocollo espone response codes significativi, usali come una **cheap state oracle** per dare priorità alle sequence che progrediscono più in profondità.

È lo stesso motivo per cui bug autenticati, transizioni nascoste o bug di parser “only-after-handshake” spesso sfuggono al vanilla file-style fuzzing: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.

## Single-Machine Diversity Trick (Jackalope-Style)

Un modo pratico per ibridare **generative novelty** con **coverage reuse** è **riavviare worker di breve durata** contro un server persistente. Ogni worker parte da un corpus vuoto, si sincronizza dopo `T` secondi, esegue altri `T` secondi sul corpus combinato, si sincronizza di nuovo, poi termina. Questo produce **fresh structures each generation** sfruttando comunque la coverage accumulata.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Worker sequenziali (esempio di loop):**

<details>
<summary>Loop di riavvio del worker Jackalope</summary>
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

- `-in empty` forza un **corpus nuovo** a ogni generazione.
- `-server_update_interval T` approssima una **sync ritardata** (novità prima, riuso dopo).
- In modalità grammar fuzzing, la **sync iniziale del server viene saltata per default** (non serve `-skip_initial_server_sync`).
- Il valore ottimale di `T` è **dipendente dal target**; cambiare dopo che il worker ha trovato la maggior parte della coverage “facile” tende a funzionare meglio.

## Snapshot Fuzzing For Hard-To-Harness Targets

Quando il codice che vuoi testare diventa raggiungibile solo **dopo un grande costo di setup** (avviare una VM, completare un login, ricevere un packet, fare il parsing di un container, inizializzare un service), una valida alternativa è **snapshot fuzzing**:

1. Esegui il target fino a quando lo stato interessante è pronto.
2. Fai uno snapshot di **memoria + registri** in quel punto.
3. Per ogni test case, scrivi l'input mutato direttamente nel buffer guest/processo rilevante.
4. Esegui fino a crash/timeout/reset.
5. Ripristina solo le **dirty pages** e ripeti.

Questo evita di pagare il costo completo di setup a ogni iterazione ed è განსაკუთრებით utile per **network services**, **firmware**, **post-auth attack surfaces** e **binary-only targets** che sono difficili da rifattorizzare in un classico harness in-process.

Un trucco pratico è interrompersi subito dopo un punto `recv`/`read`/packet-deserialization, annotare l'indirizzo del buffer di input, fare lo snapshot lì, e poi mutare direttamente quel buffer a ogni iterazione. Questo ti permette di fare fuzzing della logica di parsing profonda senza ricostruire ogni volta l'intero handshake.

## Harness Introspection: Find Shallow Fuzzers Early

Quando una campagna si blocca, il problema spesso non è il mutator ma l'**harness**. Usa **reachability/coverage introspection** per trovare funzioni che sono staticamente raggiungibili dal tuo fuzz target ma raramente o mai coperte dinamicamente. Quelle funzioni di solito indicano uno di questi tre problemi:

- L'harness entra nel target troppo tardi o troppo presto.
- Il seed corpus manca di un'intera famiglia di feature.
- Il target ha davvero bisogno di un **second harness** invece di un unico harness sovradimensionato “do everything”.

Se usi workflow in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector è utile per questo triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, espandere il corpus per una feature specifica, oppure dividere un harness monolitico in punti di ingresso più piccoli.

## Selezione del target di fuzzing e triage delle mutazioni basati sul grafo

Se hai già **risultati di static-analysis**, **survivor di mutation-testing** e **report di coverage**, non fare il triage come liste indipendenti. Costruisci prima un **call graph**, annota i nodi con **complessità ciclomatica**, **raggiungibilità da entrypoint/input non fidato**, e qualsiasi risultato esterno, poi poni domande sul grafo:

- Quali funzioni ad alta complessità sono raggiungibili da input non fidato?
- Quali survivor di mutation si trovano su percorsi da parser/handler a codice critico per la sicurezza?
- Quali funzioni sono choke point architetturali con un **blast radius** insolitamente alto?

Questo di solito fa emergere target di fuzzing migliori rispetto alla sola "coverage più bassa". Un parser/decoder con **alta complessità** e raggiungibilità esterna confermata è un candidato più forte per un harness rispetto a un helper interno isolato con coverage debole ma senza percorso controllato dall'attaccante.

### Flusso pratico di triage

1. Costruisci un **code graph** dal codebase ed estrai metriche di complessità/branch per funzione.
2. Enumera gli **entrypoint** che accettano input controllato dall'attaccante: request handler, decoder, importer, parser di protocollo, lettori CLI/file.
3. Esegui query di **path** da questi entrypoint verso le funzioni candidate per separare la superficie d’attacco raggiungibile dal codice morto/solo interno.
4. Dai priorità ai nodi che combinano:
- alta **cyclomatic complexity**
- raggiungibilità confermata da **untrusted input**
- alto **blast radius** o molti dipendenti downstream
- evidenze corroboranti come finding **SARIF**, note di audit o mutation survivor
5. Scrivi harness mirati per i nodi con punteggio più alto per primi, soprattutto **parser/codecs** come decoder hex/Base64/IP/message.

### Mutation survivor: equivalenti vs azionabili

La mutation testing spesso produce una lista rumorosa di survivor. Prima di trattare ogni survivor come un gap di sicurezza, usa il grafo per chiederti:

- La funzione mutata è raggiungibile da un entrypoint controllato dall'attaccante?
- Tutti i call path sono vincolati da invarianti più forti rispetto al controllo mutato?
- Il nodo si trova in codice morto, logica solo di formattazione, oppure in un percorso aritmetico/parser ad alto impatto?

I survivor che restano irraggiungibili o strutturalmente vincolati sono spesso **equivalent mutant**. I survivor che restano **raggiungibili** e toccano **boundary conditions**, percorsi di **overflow/carry**, o **aritmetica/parsing critici per la sicurezza** dovrebbero essere promossi in:

- nuovi harness di fuzzing
- test diretti di proprietà/invarianti
- vettori mirati per edge case

### Correlare i risultati esterni sul grafo

Se la tua pipeline SAST esporta **SARIF**, proietta i finding sui nodi del grafo tramite **file + line range** e usa il grafo per espandere l’impatto:

- calcola il **blast radius** della funzione segnalata
- verifica se il finding è su un percorso da un entrypoint
- raggruppa finding vicini che collassano nello stesso choke point

Questo è utile quando decidi se spendere tempo di fuzzing su una funzione specifica: un nodo che è **raggiungibile**, **complesso**, e ha già **SAST hits** è spesso un target migliore di un nodo semplicemente complesso ma senza percorso attaccante.

Esempio di workflow con Trailmark:
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
La metodologia importante è l'intersezione: **complexity x exposure x impact**. Usa il graph per scegliere i fuzz targets con il più alto expected security value, poi usa i mutation survivors per decidere quali boundaries e invariants il tuo harness deve stressare.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
