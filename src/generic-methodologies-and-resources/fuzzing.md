# Metodologia di Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantica

Nel **mutational grammar fuzzing**, gli input vengono mutati mantenendo la **validità rispetto alla grammatica**. In modalità guidata dalla coverage, vengono salvati come seed del corpus solo i campioni che attivano una **nuova coverage**. Per i **target linguistici** (parser, interpreti, motori), questo può far perdere bug che richiedono **catene semantiche/dataflow**, in cui l'output di un costrutto diventa l'input di un altro.

**Modalità di errore:** il fuzzer trova seed che esercitano individualmente `document()` e `generate-id()` (o primitive simili), ma **non preserva il dataflow concatenato**, quindi il campione “più vicino al bug” viene scartato perché non aggiunge coverage. Con **3 o più passaggi dipendenti**, la ricombinazione casuale diventa costosa e il feedback della coverage non guida la ricerca.

**Implicazione:** per le grammatiche con molte dipendenze, valuta l'uso di fasi **ibride, mutazionali e generative**, oppure orienta la generazione verso pattern di **concatenamento di funzioni** (non solo verso la coverage).<sup>[[1]](#references)</sup>

## Problemi di Diversità del Corpus

La mutazione guidata dalla coverage è **greedy**: un campione con nuova coverage viene salvato immediatamente, spesso mantenendo ampie regioni invariate. Nel tempo, i corpus diventano **quasi duplicati** con una bassa diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è la **minimizzazione consapevole della grammatica**, che **si interrompe dopo una soglia minima di token** (riduce il rumore mantenendo una struttura circostante sufficiente a rendere le mutazioni efficaci).<sup>[[1]](#references)</sup>

Una regola pratica per il corpus nel mutational fuzzing è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzi la coverage** rispetto a una grande quantità di quasi duplicati. In pratica, questo solitamente significa:<sup>[[1]](#references)</sup>

- Iniziare da **campioni reali** (corpus pubblici, crawling, traffico catturato, insiemi di file provenienti dall'ecosistema del target).
- Distillarli con la **minimizzazione del corpus basata sulla coverage**, invece di conservare ogni campione valido.
- Mantenere seed **sufficientemente piccoli**, in modo che le mutazioni agiscano su campi significativi invece di spendere la maggior parte dei cicli su byte irrilevanti.
- Eseguire nuovamente la minimizzazione del corpus dopo modifiche importanti all'harness o alla strumentazione, perché il corpus “migliore” cambia quando cambia la raggiungibilità.

## Mutazione Consapevole dei Confronti per i Magic Values

Un motivo comune per cui i fuzzer raggiungono un plateau non è la sintassi, ma i **confronti difficili**: magic bytes, controlli sulla lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, tabelle switch o confronti concatenati. La mutazione puramente casuale spreca cicli tentando di indovinare questi valori byte per byte.

Per questi target, usa il **tracciamento dei confronti** (ad esempio i workflow in stile `CMPLOG` / Redqueen di AFL++) così che il fuzzer possa osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.<sup>[[3]](#references)</sup>
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

- Questo è particolarmente utile quando il target limita la logica profonda tramite **firme dei file**, **verbi del protocollo**, **tag di tipo** o **feature bit dipendenti dalla versione**.
- Affiancalo a **dizionari** estratti da campioni reali, specifiche del protocollo o log di debug. Un dizionario ridotto con token della grammatica, nomi dei chunk, verbi e delimitatori è spesso più utile di una wordlist generica enorme.
- Se il target esegue molti controlli sequenziali, risolvi prima i confronti “magic” iniziali e poi minimizza nuovamente il corpus risultante, in modo che le fasi successive partano da prefissi già validi.

## Stateful Fuzzing: le sequenze sono seed

Per **protocolli**, **workflow autenticati** e **parser multi-stage**, l'unità interessante spesso non è un singolo blob, ma una **sequenza di messaggi**. Concatenare l'intera trascrizione in un unico file e mutarla alla cieca è solitamente inefficiente, perché il fuzzer muta ogni passaggio allo stesso modo, anche quando solo il messaggio successivo raggiunge lo stato fragile.

Un pattern più efficace consiste nel trattare la **sequenza stessa come seed** e usare lo **stato osservabile** (codici di risposta, stati del protocollo, fasi del parser, tipi degli oggetti restituiti) come feedback aggiuntivo:<sup>[[4]](#references)</sup>

- Mantieni stabili i **messaggi di prefisso validi** e concentra le mutazioni sul messaggio che **guida la transizione**.
- Memorizza nella cache gli identificatori e i valori generati dal server nelle risposte precedenti quando il passaggio successivo dipende da essi.
- Preferisci la mutazione/splicing per singolo messaggio invece di mutare l'intera trascrizione serializzata come un blob opaco.
- Se il protocollo espone codici di risposta significativi, usali come **oracolo di stato economico** per dare priorità alle sequenze che avanzano più in profondità.

È per lo stesso motivo che i bug autenticati, le transizioni nascoste o i bug dei parser “solo dopo l'handshake” spesso non vengono rilevati dal fuzzing vanilla in stile file: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.

## Tecnica della diversità su una singola macchina (stile Jackalope)

Un modo pratico per ibridare la **novità generativa** con il **riutilizzo della coverage** consiste nel **riavviare worker di breve durata** contro un server persistente. Ogni worker parte da un corpus vuoto, si sincronizza dopo `T` secondi, esegue un altro ciclo di `T` secondi sul corpus combinato, si sincronizza nuovamente e poi termina. Questo produce **strutture nuove a ogni generazione**, continuando al contempo a sfruttare la coverage accumulata.<sup>[[2]](#references)</sup>

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

- `-in empty` forza un **fresh corpus** a ogni generazione.
- `-server_update_interval T` approssima una **delayed sync** (prima la novelty, poi il riutilizzo).
- In modalità grammar fuzzing, la **initial server sync** viene saltata per impostazione predefinita (non è necessario usare `-skip_initial_server_sync`).
- Il valore ottimale di `T` **dipende dal target**; in genere funziona meglio effettuare lo switch dopo che il worker ha trovato la maggior parte della coverage “facile”.

## Snapshot Fuzzing For Hard-To-Harness Targets

Quando il codice che vuoi testare diventa raggiungibile solo dopo un grande costo di setup (avvio di una VM, completamento di un login, ricezione di un pacchetto, parsing di un container, inizializzazione di un servizio), una valida alternativa è lo **snapshot fuzzing**:

1. Esegui il target fino a quando lo stato di interesse è pronto.
2. Esegui lo snapshot di **memoria + registri** in quel momento.
3. Per ogni test case, scrivi l'input mutato direttamente nel buffer rilevante del guest/processo.
4. Esegui fino al crash/timeout/reset.
5. Ripristina solo le **dirty pages** e ripeti.

In questo modo eviti di pagare il costo completo del setup a ogni iterazione; è particolarmente utile per **network services**, **firmware**, **post-auth attack surfaces** e target **binary-only** che sono difficili da rifattorizzare in un classico harness in-process.

Un accorgimento pratico consiste nell'interrompere immediatamente dopo un punto di `recv`/`read`/deserializzazione del pacchetto, annotare l'indirizzo del buffer di input, eseguire lo snapshot in quel punto e quindi mutare direttamente quel buffer a ogni iterazione. Questo consente di fare fuzzing della logica di parsing profonda senza ricostruire ogni volta l'intero handshake.

## Harness Introspection: Find Shallow Fuzzers Early

Quando una campaign si blocca, spesso il problema non è il mutator, ma l'**harness**. Usa l'**introspection della reachability/coverage** per individuare le funzioni staticamente raggiungibili dal fuzz target, ma coperte dinamicamente raramente o mai. Queste funzioni indicano solitamente uno dei seguenti tre problemi:

- L'harness entra nel target troppo tardi o troppo presto.
- Il seed corpus non contiene un'intera famiglia di funzionalità.
- Il target necessita realmente di un **second harness**, invece di un unico harness sovradimensionato che “fa tutto”.

Se usi workflow in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector è utile per questo triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, ampliare il corpus per una funzionalità specifica o suddividere un harness monolitico in entry point più piccoli.

## Selezione dei fuzz target e triage delle mutazioni con approccio graph-first

Se disponi già di **static-analysis findings**, **mutation-testing survivors** e **coverage reports**, non gestirli come liste indipendenti. Costruisci prima un **call graph**, annota i nodi con la **cyclomatic complexity**, la **raggiungibilità da entry point/input non attendibili** e qualsiasi finding esterno, quindi poni domande sul grafo:<sup>[[5]](#references)[[6]](#references)</sup>

- Quali funzioni ad alta complessità sono raggiungibili da input non attendibili?
- Quali mutation survivors si trovano sui percorsi dai parser/handler al codice critico per la sicurezza?
- Quali funzioni sono choke point architetturali con un **blast radius** insolitamente elevato?

Questo in genere fa emergere fuzz target migliori rispetto al solo criterio della "lowest coverage". Un parser/decoder con **high complexity** e **external reachability** confermata è un candidato migliore per un harness rispetto a un helper interno isolato con coverage debole ma senza un percorso controllato dall'attaccante.

### Workflow pratico di triage

1. Costruisci un **code graph** dal codebase ed estrai le metriche di complessità/branch per ogni funzione.
2. Enumera gli **entry point** che accettano input controllati dall'attaccante: request handler, decoder, importer, protocol parser, CLI/file reader.
3. Esegui **path queries** da questi entry point verso le funzioni candidate per separare la attack surface raggiungibile dal codice morto o accessibile solo internamente.
4. Dai priorità ai nodi che combinano:
- alta **cyclomatic complexity**
- **reachability from untrusted input** confermata
- **blast radius** elevato o numerosi downstream dependents
- evidenze di supporto come finding **SARIF**, note di audit o mutation survivors
5. Scrivi prima harness mirati per i nodi con il punteggio migliore, in particolare **parser/codec** come decoder hex/Base64/IP/message.

### Mutation survivors: equivalent vs actionable

Il mutation testing produce spesso un elenco rumoroso di survivors. Prima di considerare ogni survivor come un security gap, usa il grafo per chiederti:

- La funzione mutata è raggiungibile da un entry point controllato dall'attaccante?
- Tutti i call path sono vincolati da invarianti più forti rispetto al controllo mutato?
- Il nodo si trova in codice morto, in logica che riguarda solo la formattazione o in un percorso aritmetico/parser ad alto impatto?

I survivors che rimangono irraggiungibili o strutturalmente vincolati sono spesso **equivalent mutants**. I survivors che rimangono **reachable** e interessano **boundary conditions**, **overflow/carry paths** o **security-critical arithmetic/parsing** dovrebbero essere promossi a:

- nuovi fuzz harness
- test diretti di proprietà/invarianti
- vettori mirati per edge case

### Correlazione degli external findings sul grafo

Se la pipeline SAST esporta **SARIF**, proietta i finding sui nodi del grafo tramite **file + line range** e usa il grafo per espandere l'impatto:

- calcola il **blast radius** della funzione segnalata
- verifica se il finding si trova su un percorso da un entry point
- raggruppa i finding vicini che confluiscono nello stesso choke point

Questo è utile quando devi decidere se dedicare tempo al fuzzing di una funzione specifica: un nodo **reachable**, complesso e con **SAST hits** già presenti è spesso un target migliore di un nodo semplicemente complesso ma senza un percorso controllato dall'attaccante.

Esempio di workflow con Trailmark:<sup>[[6]](#references)</sup>
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
La metodologia importante è l'intersezione tra: **complessità x esposizione x impatto**. Usa il grafico per scegliere i fuzz target con il più alto valore di sicurezza atteso, quindi usa i mutation survivors per decidere quali boundary e invarianti il tuo harness deve sottoporre a stress.

## Fuzzing Go con gosentry: Engine più potente, input tipizzati e controlli differenziali

Se un target Go dispone già di un harness nativo `testing.F`, un percorso pratico di upgrade consiste nell'eseguire lo stesso harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain Go forked che mantiene `go test -fuzz`, ma sostituisce il backend con **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Questo è utile quando il fuzzer nativo di Go si blocca su **confronti difficili**, **input tipizzati** o **formati ricchi di parser**. La metodologia rimane la stessa:

- Continua a usare `f.Add(...)` per i seed e `f.Fuzz(...)` per il callback.
- Riutilizza lo stesso harness, ma eseguilo con il binario `go` di gosentry invece che con la toolchain standard.
- Considera la campaign risultante come una normale esecuzione guidata dalla coverage, ma con scheduling/mutation di LibAFL e detector aggiuntivi più efficaci.

### Trasformare i fallimenti silenziosi in fuzz findings

Un problema ricorrente nelle valutazioni di Go è che i comportamenti pericolosi spesso **non** causano crash per impostazione predefinita. Con gosentry, puoi trasformare diverse classi di stati “errati ma silenziosi” in findings:

- `--panic-on=pkg.Func,...` per fare in modo che determinati percorsi di logging/error si comportino come crash (utile per i percorsi di codice in stile `log.Fatal` che altrimenti effettuano solo il log e continuano l'esecuzione).
- `--catch-races=true` per rieseguire le nuove queue entries scoperte con il race detector di Go.
- `--catch-leaks=true` per rieseguire le nuove queue entries con `goleak` e interrompere l'esecuzione in presenza di goroutine leak.
- La gestione degli hang di LibAFL per conservare **loop infiniti / input molto lenti** come fuzz findings, invece di lasciarli scomparire come timeout.
- Controlli integrati degli overflow aritmetici per impostazione predefinita, oltre a controlli opzionali delle troncature tramite instrumentation in stile go-panikint.

Questo è particolarmente utile per i target in cui l'impatto sulla sicurezza consiste in un **fallimento panicless del parser**, in un **bug di concorrenza** o in un **hang che causa solo DoS**, anziché nella corruzione della memoria.

### Fuzzing consapevole delle struct per API Go tipizzate

Il fuzzing nativo di Go si aspetta principalmente scalari come `[]byte`, `string` e numeri. Se il codice sottoposto a test consuma oggetti tipizzati, gosentry può effettuare il fuzzing direttamente di **valori compositi** (struct, slice, array, puntatori), continuando a modificare i byte sottostanti.
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
Usalo quando costruire un fake wire format solo per il fuzzing nasconderebbe i bug logici dietro codice di parsing esclusivo dell'harness. Per campagne differential o grammar-based, mantieni l'input dell'harness come una singola `[]byte` o `string` ed esegui il parsing all'interno del callback.

### Grammar-based fuzzing per parser e input di protocolli

Per parser, formati e linguaggi di input, gosentry può eseguire **Nautilus grammar fuzzing** basato su LibAFL. La grammar è un array JSON di production rules e l'harness dovrebbe generalmente accettare un singolo argomento `[]byte` o `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Note sulla metodologia:

- Usa grammar mode quando le mutazioni a livello di byte falliscono per lo più nei primi controlli sintattici.
- Mantieni la grammar focalizzata sul **sottoinsieme rilevante per la sicurezza** del linguaggio/protocollo invece di modellare l'intera specifica.
- Usa valori limite elevati nei terminali/nonterminali per mettere sotto stress i limiti degli interi, delle lunghezze e delle macchine a stati.
- La grammar mode mantiene gli input grammar-valid, ma il target riceve comunque **byte/stringhe**, quindi il parsing e i controlli semantici rimangono all'interno del codice sottoposto a harness.

### Differential fuzzing: confrontare le implementazioni, non solo i crash

Un pattern efficace per gli ecosistemi Go è il **grammar-based differential fuzzing**: genera input strutturati validi e passali a due parser, client o motori di transizione di stato.
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
Considera i seguenti elementi come risultati:

- un'implementazione va in panic mentre l'altra rifiuta l'input correttamente
- differenze tra input accettati e rifiutati
- alberi di parsing o oggetti decodificati differenti
- transizioni di stato, nonce, saldi o state root divergenti

Questo è un metodo pratico per trovare **incongruenze di consenso**, **ambiguità del parser** e **disallineamenti tra specifica e implementazione**, che il puro crash fuzzing spesso non rileva.

### Riutilizza il corpus della campagna per la generazione dei report di coverage

Dopo una campagna, riproduci il corpus della queue salvato per generare un report di coverage Go senza esportare manualmente un corpus separato:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Esegui il comando dallo **stesso package** e con lo **stesso target `-fuzz`**, in modo che gosentry risolva lo stato corretto della campagna memorizzato nella cache.

## Riferimenti

- [1] [Fuzzing con grammatica mutazionale](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark trasforma il codice in grafi](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing in Go mancava metà del toolkit. Abbiamo fatto un fork della toolchain per risolvere il problema.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
