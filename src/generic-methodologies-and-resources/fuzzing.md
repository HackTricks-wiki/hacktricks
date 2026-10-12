# Metodologia di fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. semantica

Nel **mutational grammar fuzzing**, gli input vengono mutati mantenendo la **validità grammaticale**. In modalità guidata dalla coverage, vengono salvati come seed del corpus solo i campioni che attivano **nuova coverage**. Per i **target linguistici** (parser, interpreti, motori), questo può far perdere bug che richiedono **catene semantiche e di flusso dei dati**, in cui l’output di un costrutto diventa l’input di un altro.<sup>[[1]](#references)</sup>

**Modalità di errore:** il fuzzer trova seed che esercitano singolarmente `document()` e `generate-id()` (o primitive simili), ma **non preserva il flusso dei dati concatenato**, quindi il campione «più vicino al bug» viene scartato perché non aggiunge coverage. Con **3 o più passaggi dipendenti**, la ricombinazione casuale diventa costosa e il feedback della coverage non guida la ricerca.<sup>[[1]](#references)</sup>

**Implicazione:** per grammatiche con molte dipendenze, valuta di **combinare fasi mutazionali e generative** o di orientare la generazione verso pattern di **concatenazione di funzioni** (non solo verso la coverage).<sup>[[1]](#references)</sup>

## Insidie della diversità del corpus

La mutazione guidata dalla coverage è **greedy**: un campione che aggiunge nuova coverage viene salvato subito, spesso conservando ampie porzioni invariate. Col tempo, i corpus diventano **quasi duplicati** con scarsa diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile; un compromesso pratico è una **minimizzazione consapevole della grammatica** che **si interrompe al raggiungimento di una soglia minima di token** (riduce il rumore mantenendo abbastanza struttura circostante da favorire le mutazioni).<sup>[[1]](#references)</sup>

Una regola pratica per il corpus nel fuzzing mutazionale è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzano la coverage** a una grande raccolta di quasi duplicati. In pratica, questo significa di solito quanto segue.<sup>[[1]](#references)[[3]](#references)</sup>

- Parti da **campioni del mondo reale** (corpus pubblici, dati raccolti con crawling, traffico acquisito, insiemi di file dell’ecosistema target).
- Riducili con la **minimizzazione del corpus basata sulla coverage**, invece di conservare ogni campione valido.
- Mantieni i seed **abbastanza piccoli** da far sì che le mutazioni agiscano su campi significativi, invece di sprecare la maggior parte dei cicli su byte irrilevanti.
- Ripeti la minimizzazione del corpus dopo modifiche importanti all’harness o alla strumentazione, perché il corpus «migliore» cambia quando cambia la raggiungibilità.

## Mutazione consapevole dei confronti per i valori magici

Un motivo comune per cui i fuzzer si bloccano non è la sintassi, ma la presenza di **confronti rigidi**: byte magici, controlli sulla lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, tabelle `switch` o confronti a cascata. La mutazione puramente casuale spreca cicli nel tentativo di indovinare questi valori byte per byte.

Per questi target, usa il **tracciamento dei confronti** (per esempio, flussi di lavoro basati su AFL++ `CMPLOG` / Redqueen), così il fuzzer può osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.<sup>[[3]](#references)</sup>

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

- È particolarmente utile quando il target protegge la logica più profonda tramite **firme dei file**, **verbi di protocollo**, **tag di tipo** o **bit di funzionalità dipendenti dalla versione**.
- Affiancalo a **dizionari** estratti da campioni reali, specifiche di protocollo o log di debug. Un piccolo dizionario con token grammaticali, nomi di chunk, verbi e delimitatori è spesso più utile di una wordlist generica enorme.
- Se il target esegue molti controlli sequenziali, risolvi prima i confronti “magic” più precoci e poi minimizza di nuovo il corpus risultante, così le fasi successive partono da prefissi già validi.

## Feedback più ricco quando l’edge coverage accorpa percorsi diversi

La normale edge coverage non può distinguere due esecuzioni che attraversano lo stesso helper partendo da chiamanti diversi o seguendo combinazioni di branch differenti all’interno di una funzione. Questo è importante nei decoder condivisi, nei dispatcher di protocollo e negli helper degli interpreti, dove il **percorso** che conduce a un edge determina lo stato attivo. Tracciare ingenuamente ogni contesto di chiamata è anche rischioso: la mappa di coverage e la coda possono esplodere. La ricerca sul fuzzing context-sensitive raccomanda quindi di affinare solo i contesti promettenti, invece di trattare l’intero grafo delle chiamate come context-sensitive.<sup>[[14]](#references)</sup>

Le versioni recenti di AFL++ offrono la **coverage dei percorsi per funzione Ball-Larus**, oltre alla normale edge coverage. Assegna una feature a ogni percorso aciclico attraverso una funzione; gli archi di ritorno dei loop vengono rimossi, quindi questo feedback distingue le combinazioni di branch ma **non il numero di iterazioni dei loop**. Inizia con il livello permissivo `1`, poi applica modalità più rigorose solo al codice sospetto di parser o state machine, perché il numero di percorsi può crescere in modo esponenziale.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Per un helper chiamato da molti punti rilevanti per la sicurezza, la modalità LTO può combinare il percorso di ciascuna funzione con il relativo sito di chiamata immediato:<sup>[[13]](#references)</sup>

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

**Indicazioni per la campagna:** applica feedback più ricchi con cautela e monitora il costo in termini di coverage map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Esegui in parallelo un'istanza ordinaria con edge coverage; il feedback più ricco è utile solo se il costo aggiuntivo in termini di queue/map non riduce eccessivamente le esecuzioni al secondo.
- Usa `AFL_LLVM_ALLOWLIST` per limitare l'instrumentation dei path/caller quando le librerie con molti template o il codice utility generico dominano la map.
- Le funzioni con un numero eccessivo di path aciclici possono essere escluse da AFL++; i warning durante la compilazione indicano che il target necessita di allowlisting o di un livello meno rigoroso.
- La coverage caller + path supporta un solo livello di caller. Non combinarla con stack di contesto più profondi.
- Gli ID dei path possono cambiare tra le versioni major di LLVM. Mantieni fissa la toolchain per tutta la campagna e non sincronizzare corpus basati su PATH come se i loro feature ID fossero stabili tra build diverse.
- Questo feedback integra `CMPLOG`: il comparison tracing risolve **quale valore supera una guardia**, mentre il feedback path/caller conserva **quale percorso e combinazione di branch l'hanno raggiunta**.

## Fuzzing stateful: le sequenze sono seed

Per **protocolli**, **workflow autenticati** e **parser multi-stage**, l'unità interessante spesso non è un singolo blob, ma una **sequenza di messaggi**. Concatenare l'intera trascrizione in un unico file e mutarla alla cieca è di solito inefficiente, perché il fuzzer muta ogni passaggio allo stesso modo, anche quando solo il messaggio successivo raggiunge lo stato fragile.<sup>[[4]](#references)</sup>

Un approccio più efficace consiste nel trattare la **sequenza stessa come seed** e usare lo **stato osservabile** (codici di risposta, stati del protocollo, fasi del parser, tipi degli oggetti restituiti) come feedback aggiuntivo.<sup>[[4]](#references)</sup>

- Mantieni stabili i **messaggi validi del prefisso** e concentra le mutazioni sul messaggio che **guida la transizione**.
- Memorizza gli identificatori e i valori generati dal server nelle risposte precedenti, quando il passaggio successivo dipende da essi.
- Preferisci la mutazione/splicing dei singoli messaggi alla mutazione dell'intera trascrizione serializzata come blob opaco.
- Se il protocollo espone codici di risposta significativi, usali come **oracolo di stato economico** per dare priorità alle sequenze che avanzano più a fondo.

È per lo stesso motivo che i bug autenticati, le transizioni nascoste o i bug del parser che si verificano “solo dopo l'handshake” spesso sfuggono al fuzzing vanilla in stile file: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing del driver multi-client

Una coverage degli edge elevata può comunque non rilevare bug nel driver IPC, perché la coverage non descrive **proprietà degli oggetti, reference count, messaggi in sospeso, ordine di cleanup o interleaving dei thread**. La pagina [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) descrive il modello degli oggetti del driver; questo esempio si concentra sull'harness del fuzzer. Android Binder è un modello utile: raggiungere sia i path di allocazione sia quelli di free non basta se il fuzzer non riesce a far operare più processi sullo stesso oggetto kernel nell'ordine richiesto.<sup>[[15]](#references)</sup>

#### Modella il protocollo, non i buffer `ioctl` isolati

Rappresenta un test case come una grammatica ordinata di **identità del client + operazione + argomenti strutturati**. Il fuzzer Binder LKL usa protobuf e `libprotobuf-mutator`, con un client context-manager persistente e due client ordinari. Un harness semantico preserva quindi le relazioni che la mutazione cieca dei byte distruggerebbe.<sup>[[15]](#references)</sup>

- Memorizza i valori restituiti dalle operazioni precedenti. Ad esempio, `BC_FREE_BUFFER` deve riutilizzare un puntatore al transaction buffer restituito da una precedente `ioctl`.
- Genera reply predefinite valide, così che le transazioni sincrone possano terminare e le operazioni successive restino raggiungibili.
- Rifiuta transizioni impossibili, come le transazioni verso se stessi o più transazioni in sospeso verso lo stesso target.
- Mantieni lo stato singleton di bootstrap al di fuori del reset per-input. Binder consente una sola registrazione `BINDER_SET_CONTEXT_MGR` per boot, quindi distruggere e ricreare ripetutamente quel client renderebbe non validi gli input successivi.

Un modello utile per una race sulle lifetime consiste nel far trasferire un oggetto a un client, avviare il cleanup di un thread o processo e, contemporaneamente, far rilasciare al client ricevente il transaction buffer. Nell'esempio CVE-2020-0423, il trasferimento di un `BINDER_TYPE_WEAK_BINDER`, seguito da `BINDER_THREAD_EXIT` in race con `BC_FREE_BUFFER`, poteva liberare un `binder_work` incorporato mentre il path di cleanup del thread in uscita lo stava ancora usando.<sup>[[15]](#references)</sup>

#### Reintroduci interleaving controllati in un kernel userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) collega il codice reale del kernel a un harness userspace ed espone la sua syscall interface tramite `lkl_syscall`. In questo modo è facile coordinare protobuf state, coverage e KASAN in un unico processo. Tuttavia, normalmente LKL esegue una syscall senza che un altro thread kernel la interrompa. Per le campagne di race, inserisci punti `schedule()` attorno a confini selezionati di lock/unlock e lifetime, quindi lascia che l'harness scelga casualmente il client successivo a ogni yield. Mantieni questi punti mirati, perché ognuno moltiplica lo spazio di ricerca dello scheduling. Lo scheduler randomizzato descritto dai ricercatori **non** fa parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila e riproduci i seed di regressione serializzati

L'harness upstream fissa una versione compatibile di `libprotobuf-mutator`, abilita l'instrumentation per il fuzzing LKL e KASAN con `LKL_FUZZING=1` e abilita `CONFIG_MMU` per Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Dopo aver verificato una revisione deliberatamente vulnerabile o applicato le patch di rollback documentate a monte, un seed serializzato può riprodurre l’intera transizione di stato multi-client senza doverla ricostruire in una proof of concept C ad hoc:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Considera il risultato KASAN use-after-free come conferma che il seed abbia raggiunto il percorso vulnerabile del ciclo di vita. **Non** dimostra le primitive successive necessarie per eseguire codice nel kernel o ottenere un’escalation dei privilegi.<sup>[[16]](#references)</sup>

## Tecnica della diversità su una singola macchina (stile Jackalope)

Un modo pratico per combinare **novità generativa** e **riutilizzo della copertura** consiste nel **riavviare worker di breve durata** contro un server persistente. Ogni worker parte da un corpus vuoto, esegue la sincronizzazione dopo `T` secondi, lavora per altri `T` secondi sul corpus combinato, sincronizza di nuovo e poi termina. In questo modo si ottengono **strutture nuove a ogni generazione**, sfruttando al contempo la copertura accumulata.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Worker sequenziali (loop di esempio):**

<details>
<summary>Loop di riavvio del worker di Jackalope</summary>

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
- `-server_update_interval T` approssima una **sincronizzazione ritardata** (prima la novità, poi il riutilizzo).
- In modalità grammar fuzzing, la **sincronizzazione iniziale con il server viene saltata per impostazione predefinita** (non serve `-skip_initial_server_sync`).
- Il valore ottimale di `T` **dipende dal target**; di solito funziona meglio modificarlo quando il worker ha trovato la maggior parte della coverage “facile”.

## Snapshot Fuzzing Per Target Difficili Da Sottoporre A Test

Quando il codice che vuoi testare diventa raggiungibile solo **dopo un lungo lavoro di setup** (avvio di una VM, completamento di un login, ricezione di un pacchetto, parsing di un container, inizializzazione di un servizio), una valida alternativa è **snapshot fuzzing**: acquisire lo stato del processo o della VM già pronto, iniettare ogni test case nel percorso di input del target, eseguire fino a un crash o a un timeout e ripristinare lo snapshot. Questo evita di ripetere l’inizializzazione o i prefissi del protocollo ed è utile per **servizi di rete**, **firmware**, **superfici di attacco post-autenticazione** e **target solo binari**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Esegui il target finché lo stato di interesse è pronto.
2. Acquisisci uno snapshot di **memoria + registri** in quel momento.
3. Per ogni test case, scrivi l’input mutato direttamente nel buffer pertinente del guest/processo.
4. Esegui fino a un crash, un timeout o un reset.
5. Ripristina lo snapshot; per i target VM, se supportato, ripristina solo le **pagine modificate**, quindi ripeti.

Posiziona lo snapshot il più vicino possibile al primo passaggio costoso di parsing/dispatch, ad esempio dopo una `recv`/`read` o la deserializzazione di un pacchetto, e individua il buffer di input usato dal target. Questo segue il principio di posizionamento adattivo: spostare lo snapshot più in profondità nell’elaborazione dell’input per evitare di ripetere il lavoro.<sup>[[11]](#references)</sup>

## Introspezione Dell’Harness: Individuare Subito I Fuzzer Superficiali

Quando una campagna si blocca, spesso il problema non è il mutator, ma l’**harness**. Usa l’**introspezione della raggiungibilità/coverage** per trovare le funzioni raggiungibili staticamente dal target di fuzzing, ma coperte raramente o mai in modo dinamico. Queste funzioni di solito indicano uno di tre problemi.<sup>[[12]](#references)</sup>

- L’harness entra nel target troppo tardi o troppo presto.
- Nel seed corpus manca un’intera famiglia di funzionalità.
- Il target ha davvero bisogno di un **secondo harness**, anziché di un unico harness sovradimensionato che “fa tutto”.

Se usi workflow in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector può confrontare la raggiungibilità statica con la coverage runtime e generare report a partire da un’esecuzione temporizzata o da un corpus pubblico.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, ampliare il corpus per una funzionalità specifica o suddividere un harness monolitico in entry point più piccoli.

## Selezione dei target di fuzzing e triage delle mutazioni basati sul grafo

Se hai già **risultati dell’analisi statica**, **mutanti sopravvissuti ai test di mutazione** e **report di copertura**, non esaminarli come elenchi indipendenti. Crea prima un **grafo delle chiamate**, annota i nodi con la **complessità ciclomatica**, la **raggiungibilità da entry point/input non attendibili** e gli eventuali risultati esterni, poi poni domande sul grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quali funzioni ad alta complessità sono raggiungibili da input non attendibili?
- Quali mutanti sopravvissuti si trovano sui percorsi dai parser/handler al codice critico per la sicurezza?
- Quali funzioni sono colli di bottiglia architetturali con un **raggio d’impatto** insolitamente ampio?

In genere, questo fa emergere target di fuzzing migliori rispetto alla sola «copertura più bassa». Un parser/decoder con **alta complessità** e **raggiungibilità esterna** confermata è un candidato per un harness migliore rispetto a un helper interno isolato con copertura bassa ma senza percorsi controllati dall’attaccante.

### Flusso di lavoro pratico per il triage

1. Crea un **grafo del codice** a partire dal codebase ed estrai metriche di complessità/ramificazione per ogni funzione.
2. Elenca gli **entry point** che accettano input controllati dall’attaccante: request handler, decoder, importer, parser di protocollo, reader di CLI/file.
3. Esegui query sui percorsi dagli entry point alle funzioni candidate per separare la superficie d’attacco raggiungibile dal codice morto o accessibile solo internamente.
4. Assegna la priorità ai nodi che combinano:
   - alta **complessità ciclomatica**
   - **raggiungibilità da input non attendibili** confermata
   - **raggio d’impatto** ampio o molti componenti dipendenti a valle
   - elementi di riscontro, come risultati **SARIF**, note di audit o mutanti sopravvissuti
5. Scrivi per primi harness mirati per i nodi con il punteggio più alto, in particolare per **parser/codec** come i decoder di hex/Base64/IP/messaggi.

### Mutanti sopravvissuti: equivalenti o sfruttabili

Il mutation testing spesso produce elenchi rumorosi di mutanti sopravvissuti. Prima di considerarli tutti lacune di sicurezza, usa il grafo per chiederti:

- La funzione mutata è raggiungibile da un entry point controllato dall’attaccante?
- Tutti i percorsi di chiamata sono vincolati da invarianti più forti del controllo modificato?
- Il nodo si trova in codice morto, in logica che riguarda solo la formattazione o in un percorso aritmetico/di parsing ad alto impatto?

I mutanti che restano irraggiungibili o sono vincolati strutturalmente sono spesso **mutanti equivalenti**. I mutanti che restano **raggiungibili** e riguardano **condizioni limite**, **percorsi di overflow/riporto** o **operazioni aritmetiche di sicurezza/parsing critiche** dovrebbero essere promossi a:

- nuovi harness di fuzzing
- test diretti di proprietà/invarianti
- vettori mirati per casi limite

### Proietta sul grafo i risultati esterni

Se la tua pipeline SAST esporta **SARIF**, proietta i risultati sui nodi del grafo usando **file + intervallo di righe** e usa il grafo per espandere l’impatto.<sup>[[6]](#references)</sup>

- calcola il **raggio d’impatto** della funzione segnalata
- verifica se il risultato si trova su un percorso che parte da un entry point
- raggruppa i risultati vicini che confluiscono nello stesso collo di bottiglia

Questo è utile per decidere se dedicare tempo al fuzzing di una funzione specifica: un nodo **raggiungibile**, **complesso** e con risultati **SAST** è spesso un target migliore di un nodo solo complesso, senza percorsi controllabili dall’attaccante.

Esempio di flusso di lavoro con Trailmark.<sup>[[6]](#references)</sup>

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

La metodologia importante è l'intersezione: **complessità x esposizione x impatto**. Usa il grafico per scegliere i target di fuzzing con il più alto valore di sicurezza atteso, quindi usa i sopravvissuti alle mutazioni per decidere quali confini e invarianti il tuo harness deve mettere alla prova.<sup>[[5]](#references)</sup>

## Fuzzing Go con gosentry: motore più potente, input tipizzati e controlli differenziali

Se un target Go dispone già di un harness nativo `testing.F`, un percorso pratico di aggiornamento consiste nell'eseguire lo stesso harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain Go derivata che mantiene `go test -fuzz`, ma sostituisce il backend con **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Questo è utile quando il fuzzer nativo di Go si blocca su **confronti difficili**, **input tipizzati** o **formati con parser complessi**. La metodologia rimane la stessa:

- Continua a usare `f.Add(...)` per i seed e `f.Fuzz(...)` per la callback.
- Riutilizza lo stesso harness, ma eseguilo con il binario `go` di gosentry invece che con la toolchain standard.
- Considera la campagna risultante come una normale esecuzione guidata dalla coverage, ma con scheduling e mutazione di LibAFL e detector aggiuntivi più efficaci.

### Trasformare i fallimenti silenziosi in finding del fuzzing

Un problema ricorrente nelle valutazioni Go è che spesso i comportamenti pericolosi **non** causano un crash per impostazione predefinita. Con gosentry, puoi trasformare diverse classi di stati «negativi ma silenziosi» in finding.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` per far sì che percorsi selezionati di logging/errori si comportino come crash (utile per i percorsi di codice in stile `log.Fatal` che altrimenti si limitano a registrare l’errore e continuano).
- `--catch-races=true` per rieseguire le nuove entry scoperte nella queue con il race detector di Go.
- `--catch-leaks=true` per rieseguire le nuove entry nella queue con `goleak` e fermarsi in caso di goroutine leak.
- La gestione degli hang di LibAFL per mantenere **loop infiniti / input molto lenti** come finding del fuzzing, invece di lasciarli scomparire come timeout.
- Controlli integrati di overflow aritmetico per impostazione predefinita, oltre a controlli opzionali di troncamento tramite strumentazione in stile go-panikint.

Questo è particolarmente utile per i target in cui l’impatto sulla sicurezza consiste in un **errore del parser senza panic**, un **bug di concorrenza** o un **hang che causa solo DoS**, anziché nella corruzione della memoria.

### Fuzzing consapevole delle struct per le API Go tipizzate

Il fuzzing nativo di Go si aspetta principalmente valori scalari come `[]byte`, `string` e numeri. Se il codice in esame usa oggetti tipizzati, gosentry può applicare il fuzzing direttamente a **valori composti** (struct, slice, array, pointer), continuando a mutare i byte sottostanti.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usa questo quando la creazione di un wire format fittizio, solo per il fuzzing, nasconderebbe bug logici dietro codice di parsing usato solo dall'harness. Per le campagne differential o basate su grammatiche, mantieni l'input dell'harness come un singolo `[]byte` o `string` e analizzalo all'interno della callback.

### Fuzzing basato su grammatiche per parser e input di protocollo

Per parser, formati e linguaggi di input, gosentry può eseguire **Nautilus grammar fuzzing** su LibAFL. La grammatica è un array JSON di regole di produzione e, di solito, l'harness dovrebbe accettare un singolo argomento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Note metodologiche:

- Usa la modalità grammar quando le mutazioni a livello di byte si bloccano per lo più nei controlli sintattici iniziali.
- Mantieni la grammar focalizzata sul **sottoinsieme del linguaggio/protocollo rilevante per la sicurezza**, invece di modellare l’intera specifica.
- Usa valori limite elevati nei terminali/non terminali per mettere sotto stress i limiti degli interi, delle lunghezze e delle macchine a stati.
- La modalità grammar mantiene gli input validi rispetto alla grammar, ma il target riceve comunque **byte/stringhe**: il parsing e i controlli semantici restano all’interno del codice sottoposto a harness.

### Fuzzing differenziale: confrontare le implementazioni, non solo i crash

Un approccio efficace negli ecosistemi Go è il **fuzzing differenziale basato su grammar**: generare input strutturati validi e passarli a due parser, client o motori di transizione di stato.<sup>[[7]](#references)[[8]](#references)</sup>

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

Considera questi risultati:

- un'implementazione va in panic mentre l'altra rifiuta correttamente l'input
- discrepanze tra input accettati e rifiutati
- alberi di parsing o oggetti decodificati diversi
- transizioni di stato, nonce, saldi o state root divergenti

È un metodo pratico per individuare **incongruenze di consenso**, **ambiguità del parser** e **discrepanze tra specifica e implementazione**, che spesso sfuggono al fuzzing basato solo sui crash.

### Riutilizzare il corpus della campagna per generare report di coverage

Al termine di una campagna, riproduci il corpus della coda salvato per generare un report di coverage Go senza esportare manualmente un corpus separato.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Esegui il comando dallo **stesso package** e con lo **stesso target `-fuzz`**, così gosentry risolve lo stato della campagna memorizzato nella cache corretto.



## References

- [1] [Fuzzing con grammatiche mutazionali](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing con AFL++ in dettaglio](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinque anni dopo: fuzzing dei protocolli guidato dalla copertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark trasforma il codice in grafi](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing di Go mancava metà del toolkit. Abbiamo creato un fork della toolchain per risolvere il problema.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox veloce per protocolli di rete stateful basato su snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Niente grammatica, nessun problema: verso il fuzzing del kernel Linux senza descrizioni delle system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing efficiente con snapshot adattivi e mutabili](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Strumentazione LLVM di AFL++: copertura dei percorsi e dei chiamanti](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predittivo sensibile al contesto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog sulla sicurezza offensiva di Android - fuzzing di Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL per Android Binder - documentazione di compilazione e dei seed di regressione](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
