# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Nel **mutational grammar fuzzing**, gli input vengono mutati mantenendo la validità rispetto alla **grammar**. In modalità guidata dalla coverage, vengono salvati come corpus seed solo i sample che attivano una **nuova coverage**. Per i **language target** (parser, interpreter, engine), questo può non rilevare bug che richiedono **catene semantiche/dataflow** in cui l'output di un costrutto diventa l'input di un altro.<sup>[[1]](#references)</sup>

**Failure mode:** il fuzzer trova seed che esercitano individualmente `document()` e `generate-id()` (o primitive simili), ma **non preserva il dataflow concatenato**, quindi il sample “più vicino al bug” viene scartato perché non aggiunge coverage. Con **3+ passaggi dipendenti**, la ricombinazione casuale diventa costosa e il feedback della coverage non guida la ricerca.<sup>[[1]](#references)</sup>

**Implicazione:** per le grammar con molte dipendenze, valuta di **ibridare le fasi mutational e generative** o di orientare la generazione verso pattern di **function chaining** (non solo verso la coverage).<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

La mutazione guidata dalla coverage è **greedy**: un sample con nuova coverage viene salvato immediatamente, spesso mantenendo ampie regioni invariate. Nel tempo, i corpus diventano **near-duplicates** con una bassa diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è la **minimizzazione grammar-aware** che **si arresta dopo il raggiungimento di una soglia minima di token** (riducendo il rumore e mantenendo al contempo una struttura circostante sufficiente a rendere le mutazioni efficaci).<sup>[[1]](#references)</sup>

Una regola pratica per il corpus nel mutational fuzzing è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzino la coverage** rispetto a una grande raccolta di near-duplicates. In pratica, questo comporta quanto segue.<sup>[[1]](#references)[[3]](#references)</sup>

- Parti da **sample real-world** (corpus pubblici, crawling, traffico catturato, file set dell'ecosistema del target).
- Distillali tramite la **minimizzazione del corpus basata sulla coverage** invece di conservare ogni sample valido.
- Mantieni i seed **sufficientemente piccoli** affinché le mutazioni interessino campi significativi, invece di consumare la maggior parte dei cicli su byte irrilevanti.
- Esegui nuovamente la minimizzazione del corpus dopo importanti modifiche all'harness o alla strumentazione, perché il corpus “migliore” cambia quando cambia la reachability.

## Comparison-Aware Mutation For Magic Values

Un motivo comune per cui i fuzzer raggiungono un plateau non è la sintassi, ma i **confronti rigidi**: magic byte, controlli sulla lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, tabelle switch o confronti a cascata. La mutazione puramente casuale spreca cicli tentando di indovinare questi valori byte per byte.

Per questi target, usa il **comparison tracing** (ad esempio workflow in stile AFL++ `CMPLOG` / Redqueen), così il fuzzer può osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.<sup>[[3]](#references)</sup>
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

- Questo è particolarmente utile quando il target protegge la logica profonda tramite **file signatures**, **protocol verbs**, **type tags** o **feature bits** dipendenti dalla versione.
- Abbinalo a **dictionaries** estratti da campioni reali, specifiche dei protocolli o debug logs. Un dizionario ridotto con token della grammatica, nomi dei chunk, verbi e delimitatori è spesso più prezioso di una wordlist generica enorme.
- Se il target esegue molti controlli sequenziali, risolvi prima i confronti “magic” iniziali e poi minimizza nuovamente il corpus risultante, in modo che le fasi successive partano da prefissi già validi.

## Feedback più ricco quando l'Edge Coverage collassa percorsi diversi

La normale edge coverage non può distinguere due esecuzioni che attraversano lo stesso helper tramite caller diversi o che seguono combinazioni di branch differenti all'interno di una funzione. Questo è importante nei decoder condivisi, nei dispatcher dei protocolli e negli helper degli interpreti, dove il **percorso** verso un edge determina lo stato attivo. Tracciare ingenuamente ogni calling context è inoltre rischioso: la coverage map e la queue possono esplodere. La ricerca sul context-sensitive fuzzing raccomanda quindi di perfezionare solo i contesti promettenti, invece di trattare l'intero call graph come context-sensitive.<sup>[[14]](#references)</sup>

Le build recenti di AFL++ forniscono la **Ball-Larus per-function path coverage**, oltre alla normale edge coverage. Assegnano una feature a ogni percorso aciclico attraverso una funzione; i loop back-edge vengono rimossi, quindi questo feedback distingue le combinazioni di branch ma **non il numero di iterazioni dei loop**. Inizia con il livello rilassato `1`, quindi limita le modalità più rigide al codice sospetto dei parser/state machine, perché il numero di percorsi può crescere esponenzialmente.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Per un helper chiamato da molti punti rilevanti per la sicurezza, la modalità LTO può combinare ogni percorso della funzione con il sito di chiamata immediato:<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
**Indicazioni per la campagna:** applica feedback più ricchi con cautela e monitora il relativo costo in termini di coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Esegui in parallelo un'istanza con edge-coverage ordinaria; il feedback più ricco è utile solo se il costo aggiuntivo di queue/map non riduce eccessivamente le execution per second.
- Usa `AFL_LLVM_ALLOWLIST` per limitare la path/caller instrumentation quando librerie molto basate su template o codice utility generico dominano la map.
- Le funzioni con un numero eccessivo di path aciclici possono essere escluse da AFL++; gli avvisi durante la compilazione indicano che il target necessita di allowlisting o di un livello meno rigoroso.
- La caller + path coverage supporta una sola caller depth. Non combinarla con context stack più profondi.
- I path ID possono cambiare tra versioni major di LLVM. Mantieni fisso il toolchain per una campagna e non sincronizzare corpus basati su PATH come se i loro feature ID fossero stabili tra le build.
- Questo feedback completa `CMPLOG`: il comparison tracing risolve **quale valore supera una guard**, mentre il feedback su path/caller conserva **quale route e combinazione di branch l'ha raggiunta**.

## Stateful Fuzzing: le sequenze sono seed

Per **protocolli**, **workflow autenticati** e **parser multi-stage**, l'unità interessante spesso non è un singolo blob, ma una **sequenza di messaggi**. Concatenare l'intero transcript in un unico file e mutarlo alla cieca è solitamente inefficiente, perché il fuzzer muta ogni step allo stesso modo, anche quando solo il messaggio successivo raggiunge lo stato fragile.<sup>[[4]](#references)</sup>

Un pattern più efficace consiste nel trattare la **sequenza stessa come seed** e usare lo **stato osservabile** (codici di risposta, stati del protocollo, fasi del parser, tipi degli oggetti restituiti) come feedback aggiuntivo.<sup>[[4]](#references)</sup>

- Mantieni stabili i **messaggi di prefisso validi** e concentra le mutazioni sul messaggio che **guida la transizione**.
- Memorizza gli identificatori e i valori generati dal server nelle risposte precedenti quando lo step successivo dipende da essi.
- Preferisci la mutazione/splicing per singolo messaggio invece di mutare l'intero transcript serializzato come un blob opaco.
- Se il protocollo espone codici di risposta significativi, usali come **state oracle economico** per dare priorità alle sequenze che avanzano più in profondità.

È per lo stesso motivo che i bug autenticati, le transizioni nascoste o i bug dei parser “solo-dopo-handshake” vengono spesso ignorati dal fuzzing vanilla in stile file: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (stile Jackalope)

Un modo pratico per ibridare la **novità generativa** con il **riutilizzo della coverage** consiste nel **riavviare worker di breve durata** contro un server persistente. Ogni worker parte da un corpus vuoto, esegue il sync dopo `T` secondi, lavora per altri `T` secondi sul corpus combinato, esegue nuovamente il sync e poi termina. In questo modo si ottengono **strutture nuove a ogni generazione**, continuando al contempo a sfruttare la coverage accumulata.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Worker sequenziali (ciclo di esempio):**

<details>
<summary>Ciclo di riavvio del worker di Jackalope</summary>
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
- `-server_update_interval T` approssima la **sincronizzazione ritardata** (prima la novità, poi il riutilizzo).
- In modalità grammar fuzzing, la **sincronizzazione iniziale con il server** viene saltata per impostazione predefinita (non è necessario usare `-skip_initial_server_sync`).
- Il valore ottimale di `T` **dipende dal target**; in genere funziona meglio cambiare strategia dopo che il worker ha trovato la maggior parte della coverage “facile”.

## Snapshot Fuzzing Per Target Difficili Da Sottoporre A Fuzzing

Quando il codice che vuoi testare diventa raggiungibile solo **dopo un costo di setup elevato** (avvio di una VM, completamento di un login, ricezione di un pacchetto, parsing di un container, inizializzazione di un servizio), una valida alternativa è lo **snapshot fuzzing**: acquisisci lo stato del processo o della VM pronta, inserisci ogni test case nel percorso di input del target, esegui fino a un crash/timeout e ripristina lo snapshot. Questo evita di ripetere l'inizializzazione o i prefissi del protocollo ed è utile per **network services**, **firmware**, **superfici di attacco post-auth** e **target binari**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Esegui il target fino a quando lo stato interessante è pronto.
2. Acquisisci lo snapshot di **memoria + registri** in quel punto.
3. Per ogni test case, scrivi l'input mutato direttamente nel buffer rilevante del guest/processo.
4. Esegui fino a crash/timeout/reset.
5. Ripristina lo snapshot; per i target VM, ripristina solo le **pagine dirty** quando supportato, quindi ripeti.

Posiziona lo snapshot il più vicino possibile al primo passaggio costoso di parsing/dispatch, ad esempio dopo un punto `recv`/`read` o di deserializzazione dei pacchetti, e registra il buffer di input utilizzato dal target. Questo segue il principio del posizionamento adattivo, spostando lo snapshot più in profondità nell'elaborazione dell'input per evitare di ripetere il lavoro.<sup>[[11]](#references)</sup>

## Introspezione dell'Harness: Individuare Presto i Fuzzer Superficiali

Quando una campagna si blocca, spesso il problema non è il mutator, ma l'**harness**. Usa l'**introspezione della raggiungibilità/coverage** per trovare le funzioni staticamente raggiungibili dal fuzz target, ma coperte dinamicamente raramente o mai. Queste funzioni indicano solitamente uno dei tre problemi seguenti.<sup>[[12]](#references)</sup>

- L'harness entra nel target troppo tardi o troppo presto.
- Nel seed corpus manca un'intera famiglia di funzionalità.
- Il target ha realmente bisogno di un **secondo harness**, invece di un unico harness sovradimensionato che “fa tutto”.

Se utilizzi workflow in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector può confrontare la raggiungibilità statica con la coverage runtime e generare report da una run temporizzata o da un corpus pubblico.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, ampliare il corpus per una funzionalità specifica o suddividere un harness monolitico in entry point più piccoli.

## Selezione dei fuzz target e triage delle mutazioni con approccio Graph-First

Se disponi già di **risultati dell’analisi statica**, **superstiti del mutation testing** e **report di coverage**, non analizzarli come elenchi indipendenti. Costruisci prima un **call graph**, annota i nodi con la **complessità ciclomatica**, la **raggiungibilità dagli entrypoint/input non attendibili** e qualsiasi risultato esterno, quindi poni domande sul grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quali funzioni ad alta complessità sono raggiungibili da input non attendibili?
- Quali superstiti delle mutazioni si trovano sui percorsi dai parser/handler al codice critico per la sicurezza?
- Quali funzioni sono colli di bottiglia architetturali con un **blast radius** insolitamente elevato?

Questo di solito fa emergere fuzz target migliori rispetto al solo criterio della “coverage più bassa”. Un parser/decoder con **complessità elevata** e **raggiungibilità esterna** confermata è un candidato per un harness più forte rispetto a un helper interno isolato con coverage debole ma senza un percorso controllato dall’attaccante.

### Workflow pratico di triage

1. Costruisci un **code graph** dal codebase ed estrai le metriche di complessità/branch per ogni funzione.
2. Elenca gli **entrypoint** che accettano input controllati dall’attaccante: request handler, decoder, importer, parser di protocolli, reader di CLI/file.
3. Esegui **query sui percorsi** dagli entrypoint alle funzioni candidate per separare la attack surface raggiungibile dal codice morto o accessibile solo internamente.
4. Dai priorità ai nodi che combinano:
- elevata **complessità ciclomatica**
- **raggiungibilità confermata da input non attendibili**
- **blast radius** elevato o numerose dipendenze downstream
- prove corroboranti come risultati **SARIF**, note di audit o superstiti delle mutazioni
5. Scrivi prima harness mirati per i nodi con il punteggio migliore, soprattutto **parser/codec** come decoder di hex/Base64/IP/messaggi.

### Superstiti delle mutazioni: equivalenti o azionabili

Il mutation testing produce spesso un elenco rumoroso di superstiti. Prima di trattare ogni superstite come una lacuna di sicurezza, usa il grafo per chiederti:

- La funzione modificata è raggiungibile da un entrypoint controllato dall’attaccante?
- Tutti i percorsi di chiamata sono vincolati da invarianti più forti rispetto al controllo modificato?
- Il nodo si trova in codice morto, nella sola logica di formattazione o in un percorso aritmetico/parser ad alto impatto?

I superstiti che rimangono irraggiungibili o strutturalmente vincolati sono spesso **mutanti equivalenti**. I superstiti che restano **raggiungibili** e interessano **condizioni limite**, **percorsi di overflow/carry** o **parsing/aritmetica critici per la sicurezza** devono essere promossi a:

- nuovi fuzz harness
- test diretti di proprietà/invarianti
- vettori mirati per casi limite

### Correlare i risultati esterni sul grafo

Se la pipeline SAST esporta **SARIF**, proietta i risultati sui nodi del grafo in base a **file + intervallo di righe** e usa il grafo per espandere l’impatto.<sup>[[6]](#references)</sup>

- calcola il **blast radius** della funzione segnalata
- verifica se il risultato si trova su un percorso da un entrypoint
- raggruppa i risultati vicini che confluiscono nello stesso collo di bottiglia

Questo è utile quando devi decidere se dedicare tempo al fuzzing di una funzione specifica: un nodo **raggiungibile**, **complesso** e con risultati **SAST** preesistenti è spesso un target migliore rispetto a un nodo semplicemente complesso senza alcun percorso controllato dall’attaccante.

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
La metodologia importante è l'intersezione tra: **complessità x esposizione x impatto**. Usa il grafico per scegliere i fuzz target con il maggior valore di sicurezza atteso, quindi usa i mutation survivors per decidere quali confini e invarianti il tuo harness deve sottoporre a stress.<sup>[[5]](#references)</sup>

## Fuzzing in Go con gosentry: motore più robusto, input tipizzati e controlli differenziali

Se un target Go dispone già di un harness nativo `testing.F`, un pratico percorso di upgrade consiste nell'eseguire lo stesso harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain Go forked che mantiene `go test -fuzz`, ma sostituisce il backend con **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Questo è utile quando il fuzzer nativo di Go si blocca su **hard comparisons**, **typed inputs** o **parser-heavy formats**. La metodologia rimane la stessa:

- Continua a usare `f.Add(...)` per i seed e `f.Fuzz(...)` per la callback.
- Riutilizza lo stesso harness, ma eseguilo con il binary `go` di gosentry invece che con la toolchain standard.
- Tratta la campaign risultante come una normale esecuzione coverage-guided, ma con scheduling/mutation di LibAFL e detector aggiuntivi più efficaci.

### Trasformare i fallimenti silenziosi in fuzz findings

Un problema ricorrente nelle valutazioni Go è che i comportamenti pericolosi spesso **non** causano un crash per impostazione predefinita. Con gosentry, puoi trasformare diverse categorie di stati “negativi ma silenziosi” in findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` per fare in modo che determinati percorsi di logging/error si comportino come crash (utile per i percorsi di codice in stile `log.Fatal` che altrimenti effettuano solo il logging e continuano).
- `--catch-races=true` per rieseguire le nuove queue entries scoperte con il race detector di Go.
- `--catch-leaks=true` per rieseguire le nuove queue entries con `goleak` e interrompere l'esecuzione in presenza di goroutine leak.
- La gestione degli hang di LibAFL per mantenere gli **infinite loops / very slow inputs** come fuzz findings invece di lasciarli scomparire come timeout.
- Controlli integrati dell'overflow aritmetico per impostazione predefinita, oltre a controlli opzionali di troncamento tramite instrumentation in stile go-panikint.

Questo è particolarmente utile per i target in cui l'impatto sulla sicurezza consiste in un **panicless parser failure**, in un **concurrency bug** o in un **DoS-only hang**, anziché nella corruzione della memoria.

### Struct-aware fuzzing per API Go tipizzate

Il fuzzing nativo di Go si aspetta principalmente scalari come `[]byte`, `string` e numeri. Se il codice sottoposto a test consuma oggetti tipizzati, gosentry può effettuare il fuzzing direttamente su **composite values** (struct, slice, array, puntatori), continuando al contempo a mutare i byte sottostanti.<sup>[[7]](#references)[[8]](#references)</sup>
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
Usa questo quando costruisci un fake wire format solo per il fuzzing: nasconderebbe i bug logici dietro codice di parsing esclusivo dell’harness. Per campagne differential o grammar-based, mantieni l’input dell’harness come un singolo `[]byte` o `string` ed esegui il parsing all’interno della callback.

### Grammar-based fuzzing per parser e input di protocolli

Per parser, formati e linguaggi di input, gosentry può eseguire il **Nautilus grammar fuzzing** sopra LibAFL. La grammar è un array JSON di production rules e l’harness dovrebbe solitamente accettare un singolo argomento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Note metodologiche:

- Usa la grammar mode quando le mutazioni a livello di byte falliscono principalmente nei primi controlli sintattici.
- Mantieni la grammar focalizzata sul **sottoinsieme rilevante per la sicurezza** del linguaggio/protocollo invece di modellare l'intera specifica.
- Usa valori limite elevati nei terminali/nonterminali per sottoporre a stress i limiti degli interi, delle lunghezze e delle macchine a stati.
- La grammar mode mantiene gli input validi secondo la grammar, ma il target riceve comunque **byte/stringhe**, quindi il parsing e i controlli semantici restano all'interno del codice sottoposto a harness.

### Differential fuzzing: confrontare le implementazioni, non solo i crash

Un pattern efficace per gli ecosistemi Go è il **grammar-based differential fuzzing**: genera input strutturati validi e passali a due parser, client o motori di transizione degli stati.<sup>[[7]](#references)[[8]](#references)</sup>
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

- un’implementazione va in panic mentre l’altra rifiuta l’input correttamente
- discrepanze tra input accettati/rifiutati
- alberi di parsing o oggetti decodificati differenti
- transizioni di stato, nonce, saldi o state root divergenti

Questo è un metodo pratico per trovare **consensus mismatches**, **parser ambiguity** e **spec-vs-implementation drift** che il puro crash fuzzing spesso non rileva.

### Riutilizzare il campaign corpus per i report di coverage

Dopo una campagna, riproduci il queue corpus salvato per generare un report di coverage Go senza esportare manualmente un corpus separato.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Esegui il comando dallo **stesso package** e con lo stesso target `-fuzz` in modo che gosentry risolva lo stato corretto della campagna memorizzato nella cache.



## References

- [1] [Fuzzing con grammatica mutazionale](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ in profondità](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinque anni dopo: fuzzing dei protocolli guidato dalla coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark trasforma il codice in grafi](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing di Go mancava metà del toolkit. Abbiamo fatto il fork della toolchain per risolvere il problema.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox veloce per protocolli di rete stateful usando snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Niente grammatica, nessun problema: verso il fuzzing del kernel Linux senza descrizioni delle system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing efficiente con snapshot adattivi e modificabili](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM di AFL++: coverage dei percorsi e dei caller](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predittivo sensibile al contesto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
