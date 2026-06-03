# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Fuzzing di grammatica mutazionale: Coverage vs. Semantics

Nel **fuzzing di grammatica mutazionale**, gli input vengono mutati rimanendo **grammar-valid**. In modalità guidata dalla coverage, vengono salvati come corpus seed solo i campioni che attivano **nuova coverage**. Per i **target linguistici** (parser, interpreter, engine), questo può far perdere bug che richiedono **catene semantic/dataflow** in cui l’output di una costruzione diventa l’input di un’altra.

**Failure mode:** il fuzzer trova seed che singolarmente esercitano `document()` e `generate-id()` (o primitive simili), ma **non preserva il chained dataflow**, quindi il campione “più vicino al bug” viene scartato perché non aggiunge coverage. Con **3+ dependent steps**, la ricombinazione casuale diventa costosa e il feedback della coverage non guida la ricerca.

**Implicazione:** per grammatiche con molte dipendenze, considera di **ibridare fasi mutational e generative** oppure di dare un bias alla generazione verso pattern di **function chaining** (non solo coverage).

## Problemi di diversità del corpus

La mutazione guidata dalla coverage è **greedy**: un campione con nuova coverage viene salvato subito, spesso mantenendo grandi regioni invariate. Col tempo, i corpus diventano **near-duplicates** con bassa diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è la **grammar-aware minimization** che **si ferma dopo una soglia minima di token** (ridurre il rumore mantenendo abbastanza struttura circostante da restare adatta alla mutazione).

Una regola pratica per il corpus nel fuzzing mutazionale è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzano la coverage** invece di una grande pila di near-duplicates. In pratica, questo di solito significa:

- Partire da **campioni real-world** (public corpus, crawling, traffico catturato, file set dell’ecosistema target).
- Distillarli con **coverage-based corpus minimization** invece di conservare ogni campione valido.
- Tenere i seed **abbastanza piccoli** da far sì che le mutazioni colpiscano campi significativi invece di spendere la maggior parte dei cicli su byte irrilevanti.
- Rieseguire la minimizzazione del corpus dopo grandi cambiamenti al harness/instrumentation, perché il corpus “migliore” cambia quando cambia la reachability.

## Comparison-Aware Mutation Per Magic Values

Un motivo comune per cui i fuzzer si bloccano non è la sintassi ma le **hard comparisons**: magic bytes, controlli di lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, switch table o confronti cascata. La mutazione puramente casuale spreca cicli cercando di indovinare questi valori byte per byte.

Per questi target, usa la **comparison tracing** (per esempio AFL++ `CMPLOG` / workflow in stile Redqueen) così il fuzzer può osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.
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

- Questo è particolarmente utile quando il target nasconde logica profonda dietro **file signatures**, **protocol verbs**, **type tags**, o **version-dependent feature bits**.
- Combinalo con **dictionaries** estratti da campioni reali, specifiche di protocollo o debug logs. Un piccolo dizionario con grammar tokens, nomi di chunk, verbs e delimitatori è spesso più prezioso di una enorme generic wordlist.
- Se il target esegue molti controlli sequenziali, risolvi prima le comparazioni “magic” più precoci e poi minimizza di nuovo il corpus risultante, così gli stadi successivi partono da prefissi già validi.

## Stateful Fuzzing: Sequences Are Seeds

Per **protocols**, **authenticated workflows** e **multi-stage parsers**, l’unità interessante spesso non è un singolo blob ma una **message sequence**. Concatenare l’intero transcript in un unico file e mutarlo alla cieca è di solito inefficiente perché il fuzzer muta ogni passaggio allo stesso modo, anche quando solo il messaggio successivo raggiunge lo stato fragile.

Un pattern più efficace è trattare la **sequence stessa come seed** e usare lo **stato osservabile** (response codes, protocol states, parser phases, returned object types) come feedback aggiuntivo:

- Mantieni stabili i **valid prefix messages** e concentra le mutazioni sul messaggio che guida la **transition**.
- Metti in cache identifier e valori generati dal server dalle risposte precedenti quando lo step successivo dipende da essi.
- Preferisci la mutation/splicing per messaggio invece di mutare l’intero transcript serializzato come un blob opaco.
- Se il protocollo espone response codes significativi, usali come una **cheap state oracle** per dare priorità alle sequence che avanzano più in profondità.

Questo è lo stesso motivo per cui bug autenticati, transizioni nascoste o bug di parser “only-after-handshake” vengono spesso mancati dal vanilla file-style fuzzing: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.

## Single-Machine Diversity Trick (Jackalope-Style)

Un modo pratico per ibridare la **generative novelty** con il **coverage reuse** è **riavviare worker di breve durata** contro un server persistente. Ogni worker parte da un corpus vuoto, si sincronizza dopo `T` secondi, esegue altri `T` secondi sul corpus combinato, si sincronizza di nuovo, poi termina. Questo produce **strutture nuove a ogni generazione** pur sfruttando comunque la coverage accumulata.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Worker sequenziali (loop di esempio):**

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
- In modalità grammar fuzzing, la **sync iniziale del server viene saltata di default** (non serve `-skip_initial_server_sync`).
- Il valore ottimale di `T` dipende dal **target**; cambiare dopo che il worker ha trovato la maggior parte della coverage “facile” tende a funzionare meglio.

## Snapshot Fuzzing For Hard-To-Harness Targets

Quando il codice che vuoi testare diventa raggiungibile solo **dopo un grande costo di setup** (avviare una VM, completare un login, ricevere un packet, parsare un container, inizializzare un servizio), un’alternativa utile è **snapshot fuzzing**:

1. Esegui il target finché lo stato interessante è pronto.
2. Cattura uno snapshot di **memoria + registri** a quel punto.
3. Per ogni test case, scrivi l’input mutato direttamente nel buffer guest/process rilevante.
4. Esegui fino a crash/timeout/reset.
5. Ripristina solo le **dirty pages** e ripeti.

Questo evita di pagare il costo completo di setup a ogni iterazione ed è particolarmente utile per **network services**, **firmware**, **post-auth attack surfaces** e **binary-only targets** che è scomodo refactorare in un classico harness in-process.

Un trucco pratico è interrompere subito dopo un punto `recv`/`read`/packet-deserialization, annotare l’indirizzo del buffer di input e poi mutare direttamente quel buffer in ogni iterazione. Questo ti permette di fare fuzzing della logica di parsing profonda senza ricostruire ogni volta l’intera handshake.

## Harness Introspection: Find Shallow Fuzzers Early

Quando una campaign si blocca, il problema spesso non è il mutator ma l’**harness**. Usa **reachability/coverage introspection** per trovare funzioni che sono staticamente raggiungibili dal tuo fuzz target ma raramente o mai coperte dinamicamente. Quelle funzioni di solito indicano uno di tre problemi:

- L’harness entra nel target troppo tardi o troppo presto.
- Il seed corpus manca di un’intera family di feature.
- Il target ha davvero bisogno di un **second harness** invece di un unico harness sovradimensionato “do everything”.

Se usi workflow in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector è utile per questo triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, espandere il corpus per una funzionalità specifica, oppure dividere un harness monolitico in entry point più piccoli.

## Selezione del fuzz target e triage delle mutation con Graph-First

Se hai già **risultati di static-analysis**, **mutation-testing survivors** e **coverage report**, non fare il triage come liste indipendenti. Costruisci prima un **call graph**, annota i nodi con **cyclomatic complexity**, **raggiungibilità da entrypoint/untrusted-input** e qualsiasi finding esterno, poi fai domande sul graph:

- Quali funzioni ad alta complessità sono raggiungibili da un input non fidato?
- Quali mutation survivors si trovano su path da parser/handler a codice security-critical?
- Quali funzioni sono colli di bottiglia architetturali con un **blast radius** insolitamente alto?

Questo di solito fa emergere target di fuzzing migliori di "lowest coverage" da sola. Un parser/decoder con **alta complessità** e **raggiungibilità esterna** confermata è un candidato per un harness più forte rispetto a un helper interno isolato con coverage debole ma senza path controllabile da un attacker.

### Workflow pratico di triage

1. Costruisci un **code graph** dal codebase ed estrai metriche di complessità/branch per funzione.
2. Elenca gli **entrypoint** che accettano input controllato da attacker: request handler, decoder, importer, protocol parser, CLI/file reader.
3. Esegui **path query** da quegli entrypoint verso le funzioni candidate per separare l'attack surface raggiungibile dal codice morto/solo interno.
4. Dai priorità ai nodi che combinano:
- alta **cyclomatic complexity**
- **reachability** confermata da un input non fidato
- alto **blast radius** o molti dependenti downstream
- evidenze di supporto come finding **SARIF**, note di audit o mutation survivors
5. Scrivi harness mirati per primi sui nodi con punteggio migliore, specialmente **parsers/codecs** come decoder hex/Base64/IP/message.

### Mutation survivors: equivalenti vs azionabili

Il mutation testing spesso produce una lista rumorosa di survivors. Prima di trattare ogni survivor come un gap di sicurezza, usa il graph per chiedere:

- La funzione mutata è raggiungibile da un entrypoint controllato da attacker?
- Tutti i path di chiamata sono vincolati da invarianti più forti del check mutato?
- Il nodo si trova in codice morto, in logica solo di formattazione, oppure in un path aritmetico/parser ad alto impatto?

I survivors che restano irraggiungibili o strutturalmente vincolati sono spesso **equivalent mutants**. I survivors che restano **raggiungibili** e toccano **boundary conditions**, **overflow/carry paths** o **security-critical arithmetic/parsing** dovrebbero essere promossi a:

- nuovi harness di fuzzing
- test diretti di proprietà/invarianti
- vettori mirati per edge case

### Correlare i finding esterni sul graph

Se la tua pipeline SAST esporta **SARIF**, proietta i finding sui nodi del graph tramite **file + line range** e usa il graph per espandere l'impatto:

- calcola il **blast radius** della funzione segnalata
- verifica se il finding è su un path da un entrypoint
- raggruppa i finding vicini che collassano nello stesso punto di strozzatura

Questo è utile quando devi decidere se spendere tempo di fuzzing su una funzione specifica: un nodo che è **raggiungibile**, **complesso** e ha già **SAST hits** è spesso un target migliore di un nodo semplicemente complesso ma senza path da attacker.

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
La metodologia importante è l'intersezione: **complessità x esposizione x impatto**. Usa il grafico per scegliere i fuzz target con il valore di sicurezza atteso più alto, poi usa i mutation survivors per decidere quali boundary e invariants il tuo harness deve stressare.

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Se un target Go ha già un harness nativo `testing.F`, un percorso pratico di upgrade è eseguire lo stesso harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain Go forkata che mantiene `go test -fuzz` ma sostituisce il backend con **LibAFL**.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Questo è utile quando il fuzzer Go nativo si blocca su **hard comparisons**, **typed inputs** o **parser-heavy formats**. La metodologia resta la stessa:

- Continua a usare `f.Add(...)` per i seed e `f.Fuzz(...)` per il callback.
- Riusa lo stesso harness, ma eseguilo con il binario `go` di gosentry invece della toolchain standard.
- Considera la campagna risultante come una normale esecuzione coverage-guided, ma con scheduling/mutation di LibAFL e detector circostanti migliori.

### Trasforma i silent failures in fuzz findings

Un problema ricorrente nelle assessment Go è che un comportamento pericoloso spesso **non** va in crash per default. Con gosentry, puoi promuovere diverse classi di stati “bad but silent” in findings:

- `--panic-on=pkg.Func,...` per far sì che i percorsi di logging/error selezionati si comportino come crash (utile per percorsi di codice in stile `log.Fatal` che altrimenti si limitano a fare log e continuare).
- `--catch-races=true` per rieseguire le nuove entry della queue con il Go race detector.
- `--catch-leaks=true` per rieseguire le nuove entry della queue con `goleak` e fermarti sui leak di goroutine.
- Gestione degli hang di LibAFL per mantenere **infinite loops / input molto lenti** come fuzz findings invece di lasciarli sparire come timeout.
- Controlli integrati di overflow aritmetico per default, più controlli opzionali di truncation tramite instrumentazione in stile go-panikint.

Questo è particolarmente prezioso per target in cui l’impatto security è un **panicless parser failure**, un **concurrency bug** o un **DoS-only hang** invece della memory corruption.

### Struct-aware fuzzing per API Go tipizzate

Il fuzzing Go nativo si aspetta principalmente scalari come `[]byte`, `string` e numeri. Se il codice sotto test consuma oggetti tipizzati, gosentry può fuzzare direttamente **composite values** (struct, slice, array, pointer) mutando comunque i byte sottostanti.
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
Usare questo quando si costruisce un falso wire format solo per il fuzzing nasconderebbe i bug logici dietro codice di parsing solo dell'harness. Per campagne differenziali o basate su grammar, mantieni l'input dell'harness come un singolo `[]byte` o `string` e fai il parsing all'interno della callback invece.

### Grammar-based fuzzing per parser e input di protocollo

Per parser, format e linguaggi di input, gosentry può eseguire **Nautilus grammar fuzzing** sopra LibAFL. La grammar è un array JSON di production rules, e l'harness dovrebbe di solito accettare un singolo argomento `[]byte` o `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Note metodologiche:

- Usa la modalità grammar quando le mutazioni a livello di byte muoiono principalmente nei primi controlli di sintassi.
- Mantieni la grammar focalizzata sul **sottoinsieme rilevante per la sicurezza** del linguaggio/protocollo invece di modellare la specifica completa.
- Usa grandi valori di boundary nei terminali/nonterminali per stressare i bordi di integer, length e state-machine.
- La modalità grammar mantiene gli input grammar-valid, ma il target riceve comunque **bytes/strings**, quindi il parsing e i controlli semantici restano dentro il codice sottoposto a harness.

### Differential fuzzing: confronta le implementazioni, non solo i crash

Un pattern forte per gli ecosistemi Go è il **grammar-based differential fuzzing**: genera input strutturati validi e inviali a due parser, client o motori di state-transition.
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
Considera i seguenti come findings:

- una implementazione va in panic mentre l’altra rifiuta in modo pulito
- mismatch tra input accettati/rifiutati
- albero di parsing o oggetti decodificati diversi
- transizioni di stato, nonce, balance o state root divergenti

Questo è un modo pratico per trovare **consensus mismatches**, **parser ambiguity** e **spec-vs-implementation drift** che il puro crash fuzzing spesso non rileva.

### Riutilizza il corpus della campaign per il coverage reporting

Dopo una campaign, riesegui il saved queue corpus per generare un Go coverage report senza esportare manualmente un corpus separato:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Esegui il comando dallo **stesso package** e con lo **stesso target `-fuzz`** così gosentry risolve lo stato della campaign cache corretto.

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
