# Metodologia di Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing della grammatica mutazionale: Copertura vs. Semantica

Nel **fuzzing della grammatica mutazionale**, gli input vengono modificati mantenendosi **validi secondo la grammatica**. In modalità guidata dalla copertura, vengono salvati come seed del corpus solo i campioni che attivano **nuova copertura**. Per i **target linguistici** (parser, interpreti, motori), questo può non rilevare bug che richiedono **catene semantiche/dataflow** in cui l'output di un costrutto diventa l'input di un altro.<sup>[[1]](#references)</sup>

**Modalità di errore:** il fuzzer trova seed che esercitano individualmente `document()` e `generate-id()` (o primitive simili), ma **non preserva il dataflow concatenato**, quindi il campione “più vicino al bug” viene scartato perché non aggiunge copertura. Con **3 o più passaggi dipendenti**, la ricombinazione casuale diventa costosa e il feedback della copertura non guida la ricerca.<sup>[[1]](#references)</sup>

**Implicazione:** per le grammatiche con molte dipendenze, considera di **ibridare le fasi mutazionale e generativa** oppure di orientare la generazione verso pattern di **concatenamento di funzioni** (non solo verso la copertura).<sup>[[1]](#references)</sup>

## Problemi di diversità del corpus

La mutazione guidata dalla copertura è **greedy**: un campione con nuova copertura viene salvato immediatamente, spesso mantenendo ampie regioni invariate. Nel tempo, i corpus diventano **quasi-duplicati** con una bassa diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico consiste nella **minimizzazione consapevole della grammatica**, che **si interrompe dopo una soglia minima di token** (riducendo il rumore, ma conservando una struttura circostante sufficiente a rimanere favorevole alle mutazioni).<sup>[[1]](#references)</sup>

Una regola pratica per il corpus nel fuzzing mutazionale è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzi la copertura** rispetto a una grande raccolta di quasi-duplicati. In pratica, questo significa generalmente quanto segue.<sup>[[1]](#references)[[3]](#references)</sup>

- Parti da **campioni del mondo reale** (corpus pubblici, crawling, traffico catturato, raccolte di file dell'ecosistema del target).
- Distillali con la **minimizzazione del corpus basata sulla copertura** invece di conservare ogni campione valido.
- Mantieni i seed **abbastanza piccoli** affinché le mutazioni agiscano su campi significativi invece di spendere la maggior parte dei cicli su byte irrilevanti.
- Esegui nuovamente la minimizzazione del corpus dopo modifiche importanti all'harness o alla strumentazione, perché il corpus “migliore” cambia quando cambia la raggiungibilità.

## Mutazione consapevole dei confronti per i valori magici

Un motivo comune per cui i fuzzer raggiungono un plateau non è la sintassi, ma i **confronti rigidi**: magic bytes, controlli di lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, tabelle switch o confronti concatenati. La mutazione puramente casuale spreca cicli tentando di indovinare questi valori byte per byte.

Per questi target, usa il **tracciamento dei confronti** (ad esempio workflow in stile AFL++ `CMPLOG` / Redqueen), così il fuzzer può osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.<sup>[[3]](#references)</sup>
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

- Questo è particolarmente utile quando il target protegge la logica profonda tramite **firme di file**, **verbi di protocollo**, **type tag** o **feature bit** dipendenti dalla versione.
- Abbinalo a **dizionari** estratti da campioni reali, specifiche di protocollo o log di debug. Un dizionario ridotto con token della grammatica, nomi dei chunk, verbi e delimitatori è spesso più prezioso di una wordlist generica enorme.
- Se il target esegue molti controlli sequenziali, risolvi prima i confronti “magic” iniziali e poi minimizza nuovamente il corpus risultante, in modo che le fasi successive partano da prefissi già validi.

## Stateful Fuzzing: le sequenze sono seed

Per **protocolli**, **workflow autenticati** e **parser multi-stage**, l'unità interessante spesso non è un singolo blob, ma una **sequenza di messaggi**. Concatenare l'intera trascrizione in un unico file e mutarla alla cieca è solitamente inefficiente, perché il fuzzer modifica ogni passaggio allo stesso modo, anche quando solo il messaggio successivo raggiunge lo stato fragile.<sup>[[4]](#references)</sup>

Un approccio più efficace consiste nel trattare la **sequenza stessa come seed** e usare lo **stato osservabile** (codici di risposta, stati del protocollo, fasi del parser, tipi degli oggetti restituiti) come feedback aggiuntivo.<sup>[[4]](#references)</sup>

- Mantieni stabili i **messaggi di prefisso validi** e concentra le mutazioni sul messaggio che **guida la transizione**.
- Memorizza gli identificatori e i valori generati dal server nelle risposte precedenti quando il passaggio successivo dipende da essi.
- Preferisci la mutazione/splicing per messaggio invece di mutare l'intera trascrizione serializzata come blob opaco.
- Se il protocollo espone codici di risposta significativi, usali come **state oracle economico** per dare priorità alle sequenze che avanzano più in profondità.

È per lo stesso motivo che i bug autenticati, le transizioni nascoste o i bug dei parser che si verificano “solo dopo l'handshake” spesso non vengono individuati dal fuzzing vanilla in stile file: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (in stile Jackalope)

Un modo pratico per combinare la **novità generativa** con il **riutilizzo della coverage** consiste nel **riavviare worker di breve durata** su un server persistente. Ogni worker parte da un corpus vuoto, effettua la sincronizzazione dopo `T` secondi, esegue un altro ciclo di `T` secondi sul corpus combinato, effettua nuovamente la sincronizzazione e poi termina. In questo modo si ottengono **strutture nuove a ogni generazione**, sfruttando comunque la coverage accumulata.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` approssima la **delayed sync** (novità prima, riutilizzo dopo).
- In modalità grammar fuzzing, la **initial server sync** viene saltata per impostazione predefinita (non è necessario usare `-skip_initial_server_sync`).
- Il valore ottimale di `T` dipende dal **target**; in genere funziona meglio effettuare il passaggio dopo che il worker ha trovato la maggior parte della coverage “facile”.

## Snapshot Fuzzing For Hard-To-Harness Targets

Quando il codice che vuoi testare diventa raggiungibile solo dopo un grande costo di setup (avvio di una VM, completamento di un login, ricezione di un pacchetto, parsing di un container, inizializzazione di un servizio), una valida alternativa è lo **snapshot fuzzing**: cattura lo stato del processo o della VM pronto, inserisce ogni test case nel percorso di input del target, esegue fino a crash/timeout e ripristina lo snapshot. Questo evita di ripetere l'inizializzazione o i prefissi del protocollo ed è utile per **network services**, **firmware**, **post-auth attack surfaces** e **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Esegui il target fino a quando lo stato d'interesse è pronto.
2. Crea uno snapshot di **memory + registers** in quel punto.
3. Per ogni test case, scrivi l'input mutato direttamente nel buffer guest/processo pertinente.
4. Esegui fino a crash/timeout/reset.
5. Ripristina lo snapshot; per i target VM, ripristina solo le **dirty pages** quando supportato, quindi ripeti.

Posiziona lo snapshot il più vicino possibile al primo passaggio costoso di parsing/dispatch, ad esempio dopo un `recv`/`read` o un punto di deserializzazione dei pacchetti, e registra il buffer di input utilizzato dal target. Questo segue il principio del posizionamento adattivo, spostando lo snapshot più in profondità nell'elaborazione dell'input per evitare di ripetere il lavoro.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

Quando una campagna si blocca, spesso il problema non è il mutator, ma l'**harness**. Usa l'introspection della **reachability/coverage** per trovare le funzioni staticamente raggiungibili dal fuzz target, ma coperte raramente o mai dinamicamente. Queste funzioni indicano solitamente uno dei seguenti tre problemi.<sup>[[12]](#references)</sup>

- L'harness entra nel target troppo tardi o troppo presto.
- Al seed corpus manca un'intera famiglia di funzionalità.
- Il target ha realmente bisogno di un **second harness** invece di un unico harness sovradimensionato “do everything”.

Se utilizzi workflow in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector può confrontare la reachability statica con la coverage runtime e generare report da una timed run o da un public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, ampliare il corpus per una funzionalità specifica o suddividere un harness monolitico in entry point più piccoli.

## Selezione dei fuzz target e triage delle mutation con approccio graph-first

Se disponi già di **risultati dell'analisi statica**, **mutation-testing survivors** e **report di coverage**, non analizzarli come elenchi indipendenti. Costruisci prima un **call graph**, annota i nodi con **complessità ciclomatica**, **raggiungibilità da entry point/input non attendibili** e qualsiasi risultato esterno, quindi poni domande sul grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quali funzioni ad alta complessità sono raggiungibili da input non attendibili?
- Quali mutation survivors si trovano sui percorsi dai parser/handler al codice critico per la sicurezza?
- Quali funzioni sono colli di bottiglia architetturali con un **blast radius** insolitamente elevato?

Questo generalmente fa emergere fuzz target migliori rispetto al considerare soltanto la "coverage più bassa". Un parser/decoder con **complessità elevata** e **raggiungibilità esterna confermata** è un candidato migliore per un harness rispetto a un helper interno isolato con coverage limitata ma senza un percorso controllato dall'attaccante.

### Workflow pratico di triage

1. Costruisci un **code graph** dal codebase ed estrai le metriche di complessità/branch per ogni funzione.
2. Elenca gli **entry point** che accettano input controllato dall'attaccante: request handler, decoder, importer, parser di protocolli, reader di CLI/file.
3. Esegui **query sui percorsi** dagli entry point alle funzioni candidate per distinguere la superficie d'attacco raggiungibile dal codice morto o esclusivamente interno.
4. Dai priorità ai nodi che combinano:
- elevata **complessità ciclomatica**
- **raggiungibilità confermata da input non attendibili**
- **blast radius** elevato o numerosi dipendenti downstream
- elementi di conferma come risultati **SARIF**, note di audit o mutation survivors
5. Scrivi prima harness mirati per i nodi con il punteggio migliore, soprattutto **parser/codec** come decoder di hex/Base64/IP/messaggi.

### Mutation survivors: equivalenti o azionabili

Il mutation testing produce spesso un elenco rumoroso di survivor. Prima di considerare ogni survivor una lacuna di sicurezza, usa il grafo per chiederti:

- La funzione modificata è raggiungibile da un entry point controllato dall'attaccante?
- Tutti i percorsi di chiamata sono vincolati da invarianti più forti rispetto al controllo modificato?
- Il nodo si trova in codice morto, nella sola logica di formattazione o in un percorso aritmetico/parser ad alto impatto?

I survivor che rimangono irraggiungibili o strutturalmente vincolati sono spesso **mutanti equivalenti**. I survivor che restano **raggiungibili** e interessano **condizioni limite**, **percorsi di overflow/carry** o **parsing/aritmetica critici per la sicurezza** dovrebbero essere promossi a:

- nuovi fuzz harness
- test diretti di proprietà/invarianti
- vettori mirati per gli edge case

### Correlare i risultati esterni sul grafo

Se la pipeline SAST esporta **SARIF**, proietta i risultati sui nodi del grafo usando **file + intervallo di righe** e usa il grafo per espandere l'impatto.<sup>[[6]](#references)</sup>

- calcola il **blast radius** della funzione segnalata
- verifica se il risultato si trova su un percorso da un entry point
- raggruppa i risultati vicini che confluiscono nello stesso collo di bottiglia

Questo è utile quando decidi se dedicare tempo al fuzzing di una funzione specifica: un nodo **raggiungibile**, **complesso** e che presenta già **risultati SAST** è spesso un target migliore di un nodo semplicemente complesso senza un percorso d'attacco.

Esempio di workflow con Trailmark.<sup>[[6]](#references)</sup>
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
La metodologia importante è l'intersezione: **complessità x esposizione x impatto**. Usa il grafico per scegliere i fuzz target con il più alto valore di sicurezza atteso, quindi usa i mutation survivors per decidere quali confini e invarianti il tuo harness deve sottoporre a stress.<sup>[[5]](#references)</sup>

## Fuzzing in Go con gosentry: motore più potente, input tipizzati e controlli differenziali

Se un target Go dispone già di un harness nativo `testing.F`, un pratico percorso di aggiornamento consiste nell'eseguire lo stesso harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain Go forked che mantiene `go test -fuzz`, ma sostituisce il backend con **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Questo è utile quando il fuzzer nativo di Go si blocca su **confronti complessi**, **input tipizzati** o **formati ricchi di parser**. La metodologia rimane la stessa:

- Continua a usare `f.Add(...)` per i seed e `f.Fuzz(...)` per la callback.
- Riutilizza lo stesso harness, ma eseguilo con il binario `go` di gosentry invece che con la toolchain standard.
- Considera la campaign risultante come una normale esecuzione guidata dalla coverage, ma con scheduling/mutation di LibAFL e detector di supporto migliori.

### Trasformare i fallimenti silenziosi in fuzz findings

Un problema ricorrente nelle valutazioni di Go è che i comportamenti pericolosi spesso **non** causano un crash per impostazione predefinita. Con gosentry, puoi trasformare diverse classi di stati “negativi ma silenziosi” in findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` per fare in modo che determinati percorsi di logging/error si comportino come crash (utile per i percorsi di codice nello stile di `log.Fatal` che altrimenti eseguono solo il logging e continuano).
- `--catch-races=true` per rieseguire le nuove queue entries scoperte con il race detector di Go.
- `--catch-leaks=true` per rieseguire le nuove queue entries con `goleak` e interrompere l'esecuzione in presenza di goroutine leak.
- La gestione degli hang di LibAFL per mantenere **loop infiniti / input molto lenti** come fuzz findings invece di lasciarli scomparire come timeout.
- Controlli integrati dell'overflow aritmetico per impostazione predefinita, oltre a controlli opzionali di troncamento tramite instrumentation in stile go-panikint.

Questo è particolarmente utile per i target in cui l'impatto sulla sicurezza consiste in un **fallimento del parser senza panic**, in un **bug di concorrenza** o in un **hang causato esclusivamente da DoS**, invece che nella corruzione della memoria.

### Fuzzing consapevole delle struct per le API Go tipizzate

Il fuzzing nativo di Go prevede principalmente scalari come `[]byte`, `string` e numeri. Se il codice sotto test utilizza oggetti tipizzati, gosentry può eseguire il fuzzing direttamente su **valori compositi** (struct, slice, array, puntatori), continuando comunque a mutare i byte sottostanti.<sup>[[7]](#references)[[8]](#references)</sup>
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
Usa questo quando la costruzione di un fake wire format destinato solo al fuzzing nasconderebbe i bug logici dietro codice di parsing specifico dell’harness. Per campagne differential o basate su grammar, mantieni l’input dell’harness come un singolo `[]byte` o `string` ed esegui il parsing all’interno della callback.

### Fuzzing basato su grammar per parser e input di protocolli

Per parser, formati e linguaggi di input, gosentry può eseguire il **Nautilus grammar fuzzing** basato su LibAFL. La grammar è un array JSON di production rules e l’harness dovrebbe generalmente accettare un singolo argomento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Note sulla metodologia:

- Usa la modalità grammar quando le mutazioni a livello di byte muoiono per lo più nei primi controlli sintattici.
- Mantieni la grammar focalizzata sul **sottoinsieme rilevante per la sicurezza** del linguaggio/protocollo invece di modellare l'intera specifica.
- Usa valori limite elevati nei terminali/nonterminali per sottoporre a stress i limiti relativi a interi, lunghezze e macchine a stati.
- La modalità grammar mantiene gli input validi secondo la grammar, ma il target riceve comunque **byte/stringhe**, quindi il parsing e i controlli semantici rimangono all'interno del codice sottoposto a harness.

### Differential fuzzing: confrontare le implementazioni, non solo i crash

Un pattern efficace per gli ecosistemi Go è il **grammar-based differential fuzzing**: genera input strutturati validi e passali a due parser, client o motori di transizione dello stato.<sup>[[7]](#references)[[8]](#references)</sup>
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
Considera i seguenti elementi come findings:

- un'implementazione va in panic mentre l'altra rifiuta correttamente l'input
- differenze tra gli input accettati e rifiutati
- alberi di parsing o oggetti decodificati differenti
- transizioni di stato, nonce, bilanci o state root divergenti

Questo è un metodo pratico per individuare **consensus mismatches**, **parser ambiguity** e **spec-vs-implementation drift** che il puro crash fuzzing spesso non rileva.

### Riutilizzare il corpus della campagna per il reporting della coverage

Dopo una campagna, riproduci il corpus della coda salvata per generare un report di coverage Go senza esportare manualmente un corpus separato.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Esegui il comando dallo **stesso package** e con lo stesso target `-fuzz`, in modo che gosentry risolva lo stato corretto della campaign memorizzato nella cache.

## References

- [1] [Fuzzing con grammatiche mutazionali](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ in profondità](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinque anni dopo: sul fuzzing dei protocolli guidato dalla coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark trasforma il codice in grafi](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing di Go mancava metà del toolkit. Abbiamo fatto il fork della toolchain per risolvere il problema.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer Greybox veloce per i protocolli di rete stateful che utilizza snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Niente grammatica, nessun problema: verso il fuzzing del kernel Linux senza descrizioni delle system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing efficiente con snapshot adattivi e mutabili](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
