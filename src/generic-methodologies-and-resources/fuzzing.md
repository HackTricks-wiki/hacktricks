# Metodologia di fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing con grammatica mutazionale: coverage vs. semantica

Nel **fuzzing con grammatica mutazionale**, gli input vengono modificati mantenendoli **validi rispetto alla grammatica**. In modalità guidata dalla coverage, vengono salvati come seed del corpus solo i campioni che attivano **nuova coverage**. Per i **target linguistici** (parser, interpreti, engine), questo può non individuare bug che richiedono **catene semantiche/di flusso dei dati** in cui l'output di un costrutto diventa l'input di un altro.<sup>[[1]](#references)</sup>

**Modalità di errore:** il fuzzer trova seed che esercitano singolarmente `document()` e `generate-id()` (o primitive simili), ma **non preserva la catena del flusso dei dati**, quindi il campione “più vicino al bug” viene scartato perché non aggiunge coverage. Con **3 o più passaggi dipendenti**, la ricombinazione casuale diventa costosa e il feedback sulla coverage non guida la ricerca.<sup>[[1]](#references)</sup>

**Implicazione:** per le grammatiche con molte dipendenze, valuta di **combinare fasi mutazionali e generative** oppure di favorire la generazione di pattern di **concatenazione di funzioni** (non solo la coverage).<sup>[[1]](#references)</sup>

## Insidie nella diversità del corpus

La mutazione guidata dalla coverage è **greedy**: un campione che aggiunge nuova coverage viene salvato immediatamente, spesso mantenendo ampie regioni invariate. Col tempo, i corpus diventano **quasi duplicati** con scarsa diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è la **minimizzazione consapevole della grammatica**, che **si arresta al raggiungimento di una soglia minima di token** (riduce il rumore mantenendo abbastanza struttura circostante da favorire le mutazioni).<sup>[[1]](#references)</sup>

Una regola pratica per i corpus nel fuzzing mutazionale è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzano la coverage** a una grande raccolta di quasi duplicati. In pratica, questo di solito significa quanto segue.<sup>[[1]](#references)[[3]](#references)</sup>

- Parti da **campioni del mondo reale** (corpus pubblici, crawling, traffico acquisito, insiemi di file dell'ecosistema target).
- Riducili con la **minimizzazione del corpus basata sulla coverage**, invece di conservare ogni campione valido.
- Mantieni i seed **abbastanza piccoli** da far sì che le mutazioni agiscano su campi significativi, anziché spendere la maggior parte dei cicli su byte irrilevanti.
- Ripeti la minimizzazione del corpus dopo importanti modifiche all'harness o alla strumentazione, perché il corpus “migliore” cambia quando cambia la raggiungibilità.

## Mutazione consapevole dei confronti per i valori magici

Un motivo comune per cui i fuzzer si bloccano non è la sintassi, ma i **confronti rigidi**: byte magici, controlli sulla lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, tabelle `switch` o confronti concatenati. La mutazione puramente casuale spreca cicli nel tentativo di indovinare questi valori byte per byte.

Per questi target, usa il **tracciamento dei confronti** (per esempio, workflow in stile AFL++ `CMPLOG` / Redqueen), così il fuzzer può osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.<sup>[[3]](#references)</sup>

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

- È particolarmente utile quando il target protegge la logica più profonda dietro **firme dei file**, **verbi di protocollo**, **tag di tipo** o **bit delle funzionalità dipendenti dalla versione**.
- Abbinalo a **dizionari** estratti da campioni reali, specifiche di protocollo o log di debug. Un piccolo dizionario con token della grammatica, nomi dei chunk, verbi e delimitatori è spesso più utile di una wordlist generica enorme.
- Se il target esegue molti controlli in sequenza, risolvi per primi i confronti “magic” iniziali, quindi minimizza di nuovo il corpus risultante, così le fasi successive partono da prefissi già validi.

## Fuzzing delle API per file che nascondono un linguaggio per i nomi file

Un parametro chiamato `filename`, `path` o `URL` può essere un punto di ingresso per un interprete, anziché una semplice ricerca di file. Per esempio, la Extended Filename Syntax (EFS) di CFITSIO valuta selettori tra parentesi quadre, espressioni di righe/pixel, colonne calcolate, istogrammi e trasformazioni prima di restituire l'oggetto aperto; alcune forme creano anche copie temporanee. Durante la mappatura della superficie di attacco, classifica ogni API di apertura/importazione come **percorso letterale** o **percorso interpretato**, quindi esegui il fuzzing sull'entry point di produzione effettivamente chiamato dalle applicazioni.<sup>[[20]](#references)[[22]](#references)</sup>

Per le primitive SSRF, di copia dei file e di gestione dei protocolli che ne derivano, e per le API più sicure con percorsi letterali, vedi [I mini-linguaggi per i nomi file come primitive SSRF/per i file](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Mantieni separato l'oggetto di supporto dal programma sottoposto a fuzzing

Quando la grammatica risiede in un suffisso del nome file, modificare solo i byte del file referenziato non raggiunge il parser. Un piccolo harness può invece leggere un testcase come stringa e passarlo all'API di apertura interpretata; la campagna su CFITSIO ha raggiunto la maggior parte dei parser e valutatori EFS chiamando `fits_open_file()` in modalità di sola lettura. Tieni a disposizione separatamente file di supporto validi, così le mutazioni possono concentrarsi sul linguaggio di selettori/espressioni senza compromettere continuamente il percorso di base.<sup>[[22]](#references)</sup>

Usa seed che raggiungano ciascuno una famiglia grammaticale diversa, quindi ricava un dizionario compatto sia dalla specifica sia dal codice sorgente del lexer/parser. Se la copertura si stabilizza mentre gli input falliscono ripetutamente nello stesso percorso di errore sintattico, conserva i prefissi validi e aggiungi delimitatori, operatori, parole chiave, nomi di funzioni e nomi rappresentativi dei campi, invece di aumentare soltanto il tempo dedicato alle mutazioni casuali.<sup>[[22]](#references)</sup>

Esegui l'harness con il dizionario della grammatica, per esempio:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contenere gli effetti collaterali dell'harness "read-only"

Un flag read-only della libreria non garantisce un testcase privo di effetti collaterali: il linguaggio dei nomi dei file può riscrivere l'input, creare file di output o materializzare oggetti temporanei. La campagna CFITSIO inizialmente distruggeva i seed e lasciava file imprevisti nel filesystem, rendendo necessarie pulizia e isolamento.<sup>[[22]](#references)</sup>

- Assegna a ogni worker una directory di lavoro usa e getta e una directory temporanea privata.
- Esponi copie dei file di backing canonici; non permettere mai al target di modificare l'unica copia del corpus.
- Disabilita l'accesso alla rete, a meno che i backend remoti non siano il target previsto, e limita i percorsi scrivibili con un container, un mount namespace o una sandbox equivalente.
- Reimposta la directory dopo ogni esecuzione o batch di worker e considera le modifiche impreviste al filesystem come ulteriori rilievi.

### Ciclo crash-to-patch-to-fuzz

Raggruppa i crash prima di correggerli, così migliaia di artefatti non diventano migliaia di attività di patch. Nella valutazione di CFITSIO, AFLTriage ha ridotto l'insieme iniziale dei crash a poche cause radice; il relativo advisory mostra errori distinti, tra cui controlli errati della dimensione della destinazione, puntatori obsoleti dopo `realloc()`, errori aritmetici e percorsi di cleanup del parser non sicuri.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimizza un input rappresentativo per ogni cluster e riproducilo con AddressSanitizer.
2. Registra l'accesso esatto che causa il problema, la posizione nel sorgente, la cronologia di allocazione/liberazione e lo stato del parser che ha reso falsa l'invariante.
3. Applica una patch candidata circoscritta e ricompila con la stessa strumentazione per coverage e sanitizer.
4. Riproduci il caso originale **e ogni input del suo cluster**; abilita anche il rilevamento dei leak, perché una correzione di memory safety può compromettere la gestione della proprietà lungo un percorso di errore.
5. Esegui test funzionali con file reali, poi riprendi dalla queue accumulata (oppure reimportala se l'engine richiede una nuova directory di output dopo la modifica del binario).
6. Ripeti: rimuovere il primo crash superficiale spesso permette ai seed esistenti di raggiungere uno stato più profondo del parser.

Un LLM può velocizzare il passaggio 2 e preparare una bozza per il passaggio 3 se riceve l'input che causa il crash, il report del sanitizer, l'harness e il sorgente pertinente, ma la sua patch resta non attendibile. Sono la riproduzione con il sanitizer e i controlli di regressione, non la spiegazione del modello, a determinare se la correzione viene accettata.<sup>[[22]](#references)</sup>

## Feedback più ricco quando la edge coverage appiattisce percorsi diversi

La normale edge coverage non distingue due esecuzioni che attraversano lo stesso helper da chiamanti diversi o seguono combinazioni differenti di branch all'interno di una funzione. Questo è importante nei decoder condivisi, nei dispatcher di protocollo e negli helper degli interpreti, dove il **percorso** che porta a un edge determina lo stato attivo. Tracciare ingenuamente ogni contesto di chiamata è altrettanto rischioso: la mappa di coverage e la queue possono crescere a dismisura. La ricerca sul fuzzing sensibile al contesto raccomanda quindi di raffinare solo i contesti promettenti, anziché rendere sensibile al contesto l'intero grafo delle chiamate.<sup>[[14]](#references)</sup>

Le versioni recenti di AFL++ offrono la **coverage dei percorsi Ball-Larus per funzione**, in aggiunta alla normale edge coverage. Assegnano una feature a ogni percorso aciclico all'interno di una funzione; gli archi di ritorno dei loop vengono rimossi, quindi questo feedback distingue le combinazioni di branch ma **non il numero di iterazioni dei loop**. Inizia dal livello permissivo `1`, poi limita le modalità più rigorose al codice sospetto del parser o della macchina a stati, perché il numero di percorsi può crescere esponenzialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Per un helper chiamato da molti punti rilevanti per la sicurezza, la modalità LTO può combinare ciascun percorso della funzione con il relativo call site immediato:<sup>[[13]](#references)</sup>

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

**Indicazioni per la campagna:** applica con cautela feedback più ricchi e monitora il costo in termini di coverage map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Esegui in parallelo un’istanza ordinaria con edge coverage; il feedback più ricco è utile solo se il costo aggiuntivo in termini di queue/map non riduce eccessivamente le esecuzioni al secondo.
- Usa `AFL_LLVM_ALLOWLIST` per limitare l’instrumentation di path/caller quando librerie con molti template o codice utility generico dominano la map.
- AFL++ può escludere funzioni con un numero eccessivo di path aciclici; gli avvisi durante la compilazione indicano che il target richiede un’allowlist o un livello meno rigoroso.
- La coverage di caller + path supporta una sola profondità di caller. Non combinarla con stack di contesto più profondi.
- Gli ID dei path possono cambiare tra versioni principali di LLVM. Mantieni fissa la toolchain per tutta la campagna e non sincronizzare corpus basati su PATH come se i loro feature ID fossero stabili tra build diverse.
- Questo feedback integra `CMPLOG`: il tracing dei confronti risolve **quale valore supera una guard**, mentre il feedback su path/caller conserva **quale percorso e combinazione di branch l’ha raggiunta**.

## Fuzzing stateful: le sequenze sono seed

Per **protocolli**, **workflow autenticati** e **parser multi-stage**, spesso l’unità interessante non è un singolo blob, ma una **sequenza di messaggi**. Concatenare l’intera trascrizione in un unico file e mutarla alla cieca è solitamente inefficiente, perché il fuzzer muta ogni passaggio allo stesso modo, anche quando solo il messaggio successivo raggiunge lo stato fragile.<sup>[[4]](#references)</sup>

Un approccio più efficace consiste nel trattare la **sequenza stessa come seed** e usare lo **stato osservabile** (codici di risposta, stati del protocollo, fasi del parser, tipi di oggetti restituiti) come feedback aggiuntivo.<sup>[[4]](#references)</sup>

- Mantieni stabili i **messaggi prefisso validi** e concentra le mutazioni sul messaggio che **guida la transizione**.
- Memorizza identificatori e valori generati dal server nelle risposte precedenti, quando il passaggio successivo dipende da essi.
- Preferisci mutazioni/splicing per singolo messaggio anziché mutare l’intera trascrizione serializzata come blob opaco.
- Se il protocollo espone codici di risposta significativi, usali come **oracolo di stato economico** per dare priorità alle sequenze che avanzano più in profondità.

È per lo stesso motivo che i bug autenticati, le transizioni nascoste o i bug nei parser che si verificano “solo dopo l’handshake” spesso sfuggono al fuzzing tradizionale basato su file: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing del driver multi-client

Un’elevata edge coverage può comunque non rilevare bug nei driver IPC, perché la coverage non descrive **proprietà degli oggetti, conteggi dei riferimenti, messaggi in attesa, ordine di cleanup o interleaving dei thread**. La pagina [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) descrive il modello a oggetti del driver; questo esempio si concentra sull’harness del fuzzer. Android Binder è un modello utile: raggiungere sia i path di allocazione sia quelli di free non basta se il fuzzer non riesce a far operare più processi sullo stesso oggetto kernel nell’ordine richiesto.<sup>[[15]](#references)</sup>

#### Modella il protocollo, non buffer `ioctl` isolati

Rappresenta un caso di test come una grammatica ordinata di **identità del client + operazione + argomenti strutturati**. Il fuzzer Binder LKL usa protobuf e `libprotobuf-mutator`, con un client context-manager persistente e due client ordinari. Un harness semantico preserva quindi le relazioni che la mutazione cieca dei byte distruggerebbe.<sup>[[15]](#references)</sup>

- Memorizza i valori restituiti dalle operazioni precedenti. Per esempio, `BC_FREE_BUFFER` deve riutilizzare un puntatore al transaction buffer restituito da una precedente `ioctl`.
- Genera risposte predefinite valide affinché le transazioni sincrone possano terminare e le operazioni successive restino raggiungibili.
- Rifiuta transizioni impossibili, come le transazioni verso sé stessi o più transazioni in attesa verso lo stesso destinatario.
- Mantieni lo stato singleton di bootstrap fuori dal reset per singolo input. Binder consente una sola registrazione `BINDER_SET_CONTEXT_MGR` per avvio, quindi distruggere e ricreare ripetutamente quel client renderebbe non validi gli input successivi.

Un modello utile per una race sulle lifetime consiste nel far trasferire un oggetto a un client, avviare il cleanup di un thread o processo e, contemporaneamente, far rilasciare al client ricevente il transaction buffer. Nell’esempio CVE-2020-0423, un trasferimento `BINDER_TYPE_WEAK_BINDER` seguito da `BINDER_THREAD_EXIT` in race con `BC_FREE_BUFFER` poteva liberare un `binder_work` incorporato mentre il percorso di cleanup del thread in uscita lo stava ancora usando.<sup>[[15]](#references)</sup>

#### Reintroduci interleaving controllati in un kernel userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) collega il codice reale del kernel a un harness userspace ed espone la sua interfaccia di syscall tramite `lkl_syscall`. Questo permette di coordinare facilmente protobuf, coverage e KASAN in un unico processo. Di norma, però, LKL esegue una syscall senza che un altro thread kernel la interrompa. Per le campagne di race, inserisci punti `schedule()` attorno a specifici confini di lock/unlock e lifetime, quindi lascia che l’harness scelga casualmente il client successivo a ogni yield. Limita questi punti a quelli necessari, perché ognuno moltiplica lo spazio di ricerca dello scheduling. Lo scheduler randomizzato descritto dai ricercatori **non** fa parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila e riproduci seed di regressione serializzati

L’harness upstream fissa una versione compatibile di `libprotobuf-mutator`, abilita l’instrumentation per il fuzzing LKL e KASAN con `LKL_FUZZING=1` e abilita `CONFIG_MMU` per Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Dopo aver effettuato il checkout di una revisione deliberatamente vulnerabile o applicato le patch di rollback documentate upstream, un seed serializzato può riprodurre l’intera transizione di stato multi-client senza ricostruirla in una proof of concept C ad hoc:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Considera il risultato KASAN use-after-free come conferma che il seed ha raggiunto il percorso di lifetime vulnerabile. **Non** dimostra la presenza delle primitive successive necessarie per eseguire codice nel kernel o ottenere un'escalation dei privilegi.<sup>[[16]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Un modo pratico per combinare la **novità generativa** con il **riutilizzo della coverage** consiste nel **riavviare worker di breve durata** contro un server persistente. Ogni worker parte da un corpus vuoto, sincronizza dopo `T` secondi, esegue per altri `T` secondi sul corpus combinato, sincronizza di nuovo e poi termina. In questo modo si ottengono **strutture nuove a ogni generazione**, sfruttando al contempo la coverage accumulata.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Worker sequenziali (esempio di ciclo):**

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

- `-in empty` forza un **corpus nuovo** a ogni generazione.
- `-server_update_interval T` simula una **sincronizzazione ritardata** (prima la novità, poi il riutilizzo).
- In modalità grammar fuzzing, la **sincronizzazione iniziale con il server viene saltata per impostazione predefinita** (non serve `-skip_initial_server_sync`).
- Il valore ottimale di `T` **dipende dal target**; in genere funziona meglio cambiare valore dopo che il worker ha trovato la maggior parte della coverage «facile».

## Snapshot Fuzzing per target difficili da predisporre

Quando il codice da testare diventa raggiungibile solo **dopo una lunga fase di setup** (avvio di una VM, completamento di un login, ricezione di un pacchetto, parsing di un container, inizializzazione di un servizio), un'alternativa utile è lo **snapshot fuzzing**: acquisire lo stato del processo o della VM pronto, iniettare ogni caso di test nel percorso di input del target, eseguire fino a un crash o a un timeout e ripristinare lo snapshot. Questo evita di ripetere l'inizializzazione o i prefissi del protocollo ed è utile per **servizi di rete**, **firmware**, **superfici di attacco post-autenticazione** e **target solo binari**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Esegui il target finché lo stato di interesse non è pronto.
2. Acquisisci uno snapshot di **memoria + registri** in quel momento.
3. Per ogni caso di test, scrivi l'input mutato direttamente nel buffer pertinente del processo o del guest.
4. Esegui fino a un crash, un timeout o un reset.
5. Ripristina lo snapshot; per i target VM, se supportato, ripristina solo le **pagine dirty**, quindi ripeti.

Posiziona lo snapshot il più vicino possibile al primo passaggio costoso di parsing o dispatch, ad esempio dopo una `recv`/`read` o la deserializzazione del pacchetto, e registra il buffer di input usato dal target. Questo segue il principio del posizionamento adattivo: spostare lo snapshot più in profondità nell'elaborazione dell'input per evitare di ripetere il lavoro.<sup>[[11]](#references)</sup>

## Esplorazione delle race nel kernel Linux con MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) trasforma le race nel kernel Linux sensibili al timing in sequenze ripetibili di accessi alla memoria. Può enumerare automaticamente esecuzioni **A-B-A** in due contesti oppure consentire a un analista di imporre vincoli di ordinamento tramite un'interfaccia UI/GUI a terminale. È uno strumento di ricerca sperimentale, non un fuzzer di concorrenza completo: attualmente richiede LLVM 23+ e il kernel modificato del progetto; gli strumenti a riga di comando supportano due thread di test e il livello di fuzzing userspace proposto non è implementato.<sup>[[17]](#references)[[18]](#references)</sup>

### Raccogliere i punti di comunicazione tra contesti

Compila il kernel strumentato con le callback outline di KASAN e il supporto modificato di KCOV per la registrazione della memoria. Il README del progetto raccomanda inoltre di disabilitare l'ottimizzazione sibling-call affinché gli stack delle chiamate restino utilizzabili.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

La modalità outline di KASAN (`asan-instrumentation-with-call-threshold=0`) converte gli accessi strumentati in chiamate a funzioni helper. Le patch MAccConc per il kernel disabilitano `asan-opt-same-temp` per evitare che gli accessi consecutivi vengano unificati; disabilita anche l’ottimizzazione `asan-opt-globals` quando è necessario rendere visibili le race sulle variabili globali. KCOV trasmette i record risultanti allo userspace. Confronta gli accessi provenienti da diversi contesti di esecuzione e conserva le coppie i cui intervalli di byte si sovrappongono e in cui almeno uno dei due accessi è una scrittura; considera `kfree()` una scrittura, in modo che anche le transizioni del ciclo di vita diventino candidate.<sup>[[17]](#references)</sup>

Per il lavoro che esce dal task iniziale, come l’elaborazione dei pacchetti o le callback RCU, il sottosistema deve propagare un handle di remote-coverage KCOV. Il remote KCOV upstream è opt-in e non è automaticamente disponibile per attività arbitrarie in background, quindi la mancata propagazione può rendere invisibile un’interazione reale.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificare lo stesso accesso dinamico a ogni esecuzione

Non riprodurre l’esecuzione usando un indirizzo concreto dell’heap, che può cambiare dopo ogni allocazione, né usando soltanto un indirizzo di istruzione, che è ambiguo all’interno di helper come `memcpy()` e `spin_lock()`. MAccConc usa uno **stack trace con conteggi**: ogni frame identifica un callee e il numero di invocazioni al suo interno da parte del caller, mentre l’elemento finale identifica l’istruzione che accede alla memoria. I record di entrata/uscita delle funzioni SanitizerCoverage consentono allo userspace di ricostruire questo identificatore dinamico, che rimane stabile al variare degli indirizzi e in presenza di rumore dovuto a flussi di controllo non correlati.<sup>[[17]](#references)</sup>

### Convertire le coppie candidate in schedulazioni forzate

L’ioctl `KCOV_SET_DI` aggiunto dalla patch associa un identificatore di accesso con conteggi a un’azione su un flag condiviso.<sup>[[17]](#references)</sup>

| Azione | Semantica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Imposta il flag *N* immediatamente prima dell’accesso selezionato. |
| `DI_STACK_WAIT` | Prima dell’accesso selezionato, attende in un ciclo attivo finché il flag *N* non viene impostato o non scade il limite configurato. |
| `DI_STACK_WAKE_POST` | Imposta il flag *N* immediatamente dopo l’accesso selezionato. |

Per un vincolo parziale **A-happens-before-B**, associa `DI_STACK_WAKE_POST` ad A e `DI_STACK_WAIT` a B usando lo stesso flag. Per una schedulazione completamente specificata su due contesti, avvia B in stato di attesa, quindi fai sì che A risvegli B e attenda al primo punto di trasferimento; B esegue l’operazione inversa al trasferimento successivo. Quest’ultimo approccio funziona come un context switch deterministico ed è quello usato dall’esploratore automatico A-B-A.<sup>[[17]](#references)</sup>

Una campagna minima consiste nel compilare il test case con quattro hook (`test_setup`, due funzioni di thread e `test_end`) come libreria condivisa, raccogliere una traccia senza vincoli, quindi enumerare le candidate A-B-A o aggiungere vincoli manuali attorno agli accessi sospetti.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreta i timeout separatamente dai riordinamenti riusciti: l’ordine richiesto potrebbe essere impossibile perché un lock o una dipendenza di inizializzazione/pubblicazione impedisce al secondo contesto di raggiungere il proprio punto di injection. Tieni inoltre presenti i punti ciechi di KASAN: gli accessi diretti allo stack in genere non vengono intercettati, a meno che non possano andare fuori dai limiti; le variabili globali vengono omesse con l’ottimizzazione predefinita; e i compilatori attuali non possono generare hook ASAN e TSAN simultaneamente. Infine, il prototipo perde il proprio buffer KCOV quando un guest va in panic, quindi conserva una console/oracle di crash indipendente.<sup>[[17]](#references)</sup>

Per il fuzzing guidato dalla concorrenza in futuro, registra riepiloghi degli accessi alla memoria per input o syscall, abbina le operazioni che formerebbero punti di comunicazione tra contesti, quindi esplora solo quelle combinazioni. Gli snapshot delle VM stabilizzano lo stato globale e gli indirizzi; senza snapshot, i metadati dei siti di allocazione possono astrarre gli oggetti tra le esecuzioni. Questa è un’estensione proposta, non una funzionalità degli attuali strumenti userspace di MAccConc.<sup>[[17]](#references)</sup>

## Introspezione dell’harness: individuare subito i fuzzer superficiali

Quando una campagna si arena, spesso il problema non è il mutator, ma l’**harness**. Usa l’**introspezione di raggiungibilità/copertura** per individuare le funzioni staticamente raggiungibili dal target di fuzzing, ma raramente o mai coperte dinamicamente. Queste funzioni di solito indicano uno di tre problemi.<sup>[[12]](#references)</sup>

- L’harness raggiunge il target troppo presto o troppo tardi.
- Nel corpus di seed manca un’intera famiglia di funzionalità.
- Il target ha davvero bisogno di un **secondo harness**, invece di un unico harness sovradimensionato che “fa tutto”.

Se usi workflow in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector può confrontare la raggiungibilità statica con la copertura runtime e generare report da un’esecuzione a tempo limitato o da un corpus pubblico.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, ampliare il corpus per una funzionalità specifica oppure suddividere un harness monolitico in entry point più piccoli.

## Selezione dei target di fuzzing basata sul grafo e triage delle mutazioni

Se hai già **risultati dell'analisi statica**, **mutazioni sopravvissute ai test di mutation testing** e **report di coverage**, non esaminarli come elenchi indipendenti. Prima crea un **grafo delle chiamate**, annota i nodi con la **complessità ciclomatica**, la **raggiungibilità dagli entry point e dagli input non attendibili** e gli eventuali risultati esterni, poi poni domande sul grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quali funzioni ad alta complessità sono raggiungibili da input non attendibili?
- Quali mutazioni sopravvissute si trovano sui percorsi dai parser/handler al codice critico per la sicurezza?
- Quali funzioni sono colli di bottiglia architetturali con un **blast radius** insolitamente ampio?

In genere, questo fa emergere target di fuzzing migliori rispetto alla sola "coverage più bassa". Un parser/decoder con **alta complessità** e **raggiungibilità esterna** confermata è un candidato per un harness migliore di un helper interno isolato, con coverage limitata ma senza percorsi controllabili da un attaccante.

### Flusso di lavoro pratico per il triage

1. Crea un **grafo del codice** a partire dalla codebase ed estrai metriche di complessità e branching per ogni funzione.
2. Elenca gli **entry point** che accettano input controllati da un attaccante: handler di richieste, decoder, importer, parser di protocolli, lettori di CLI/file.
3. Esegui query sui percorsi dagli entry point alle funzioni candidate per separare la superficie d'attacco raggiungibile dal codice morto o accessibile solo internamente.
4. Dai priorità ai nodi che combinano:
   - alta **complessità ciclomatica**
   - **raggiungibilità confermata da input non attendibili**
   - **blast radius** elevato o molti dipendenti a valle
   - elementi di riscontro, come risultati **SARIF**, note di audit o mutazioni sopravvissute
5. Scrivi prima harness mirati per i nodi con il punteggio più alto, in particolare per **parser/codec** come decoder di hex/Base64/IP/messaggi.

### Mutazioni sopravvissute: equivalenti o rilevanti

Il mutation testing spesso produce un elenco rumoroso di mutazioni sopravvissute. Prima di considerarle tutte lacune di sicurezza, usa il grafo per chiederti:

- La funzione modificata è raggiungibile da un entry point controllato da un attaccante?
- Tutti i percorsi di chiamata sono vincolati da invarianti più forti del controllo modificato?
- Il nodo si trova in codice morto, in logica che si limita alla formattazione o in un percorso aritmetico/parser ad alto impatto?

Le mutazioni sopravvissute che restano irraggiungibili o strutturalmente vincolate sono spesso **mutanti equivalenti**. Quelle che restano **raggiungibili** e interessano **condizioni al limite**, **percorsi di overflow/riporto** o **aritmetica/parsing critici per la sicurezza** dovrebbero essere trasformate in:

- nuovi harness di fuzzing
- test diretti di proprietà/invarianti
- vettori mirati per i casi limite

### Correlare i risultati esterni al grafo

Se la tua pipeline SAST esporta **SARIF**, associa i risultati ai nodi del grafo usando **file + intervallo di righe** e usa il grafo per estenderne l'analisi d'impatto.<sup>[[6]](#references)</sup>

- calcola il **blast radius** della funzione segnalata
- verifica se il risultato si trova su un percorso che parte da un entry point
- raggruppa i risultati vicini che riconducono allo stesso collo di bottiglia

Questo è utile per decidere se dedicare tempo al fuzzing di una funzione specifica: un nodo **raggiungibile**, **complesso** e che presenta già risultati **SAST** è spesso un target migliore di un nodo semplicemente complesso, ma senza percorsi accessibili a un attaccante.

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

La metodologia importante è l’intersezione: **complessità x esposizione x impatto**. Usa il grafico per scegliere i target di fuzzing con il maggior valore di sicurezza atteso, poi usa i mutanti sopravvissuti per decidere quali confini e invarianti il tuo harness deve mettere alla prova.<sup>[[5]](#references)</sup>

## Fuzzing Go con gosentry: motore più potente, input tipizzati e controlli differenziali

Se un target Go ha già un harness nativo `testing.F`, un percorso pratico di aggiornamento consiste nell’eseguire lo stesso harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain Go forked che mantiene `go test -fuzz`, ma sostituisce il backend con **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

È utile quando il fuzzer nativo di Go si blocca su **confronti difficili**, **input tipizzati** o **formati con parser complessi**. La metodologia resta la stessa:

- Continua a usare `f.Add(...)` per i seed e `f.Fuzz(...)` per la callback.
- Riutilizza lo stesso harness, ma eseguilo con il binario `go` di gosentry invece che con la toolchain standard.
- Considera la campagna risultante come una normale esecuzione guidata dalla coverage, ma con lo scheduling e le mutazioni di LibAFL e detector aggiuntivi.

### Trasformare i fallimenti silenziosi in finding del fuzzer

Un problema ricorrente nelle valutazioni Go è che spesso i comportamenti pericolosi **non** causano un crash per impostazione predefinita. Con gosentry, puoi trasformare diverse categorie di stati «negativi ma silenziosi» in finding.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` per fare in modo che i percorsi selezionati di logging/errori si comportino come crash (utile per i percorsi di codice in stile `log.Fatal` che altrimenti si limitano a registrare l'errore e continuare).
- `--catch-races=true` per rieseguire le nuove entry scoperte nella queue con il race detector di Go.
- `--catch-leaks=true` per rieseguire le nuove entry nella queue con `goleak` e fermarsi in caso di leak di goroutine.
- La gestione degli hang di LibAFL per mantenere i **loop infiniti / input molto lenti** come finding del fuzzer, anziché lasciarli scomparire come timeout.
- Controlli integrati di overflow aritmetico per impostazione predefinita, oltre a controlli opzionali di troncamento tramite strumentazione in stile go-panikint.

Questo è particolarmente utile per i target in cui l'impatto sulla sicurezza consiste in un **errore del parser senza panic**, un **bug di concorrenza** o un **hang che causa solo DoS**, anziché in una corruzione della memoria.

### Fuzzing consapevole delle struct per le API Go tipizzate

Il fuzzing nativo di Go si aspetta principalmente valori scalari come `[]byte`, `string` e numeri. Se il codice sotto test usa oggetti tipizzati, gosentry può fare fuzzing direttamente di **valori compositi** (struct, slice, array, puntatori), continuando a mutare i byte sottostanti.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usare questo per creare un formato wire fittizio solo per il fuzzing nasconderebbe i bug logici dietro il codice di parsing usato solo dall’harness. Per le campagne differential o basate su grammar, mantieni l’input dell’harness come singolo `[]byte` o `string` e analizzalo invece all’interno della callback.

### Fuzzing basato su grammar per parser e input di protocollo

Per parser, formati e linguaggi di input, gosentry può eseguire il **fuzzing grammar Nautilus** basato su LibAFL. La grammar è un array JSON di regole di produzione e, in genere, l’harness dovrebbe accettare un singolo argomento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Note sulla metodologia:

- Usa la modalità grammar quando le mutazioni a livello di byte vengono perlopiù scartate dai controlli sintattici iniziali.
- Mantieni la grammar focalizzata sul **sottoinsieme del linguaggio/protocollo rilevante per la sicurezza**, invece di modellare l’intera specifica.
- Usa valori limite elevati nei terminali/nonterminali per mettere alla prova i limiti di interi, lunghezze e macchine a stati.
- La modalità grammar mantiene gli input validi secondo la grammar, ma il target riceve comunque **byte/stringhe**, quindi il parsing e i controlli semantici restano all’interno del codice sottoposto a harness.

### Differential fuzzing: confrontare le implementazioni, non solo i crash

Un approccio efficace negli ecosistemi Go è il **differential fuzzing basato su grammar**: generare input strutturati validi e passarli a due parser, client o motori di transizione di stato.<sup>[[7]](#references)[[8]](#references)</sup>

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

Considera i seguenti casi come risultati:

- un'implementazione genera un panic mentre l'altra rifiuta l'input correttamente
- discrepanze tra input accettati e rifiutati
- alberi di parsing o oggetti decodificati diversi
- transizioni di stato, nonce, saldi o state root divergenti

È un metodo pratico per individuare **discrepanze di consenso**, **ambiguità nei parser** e **scostamenti tra specifiche e implementazioni**, spesso non rilevati dal solo fuzzing volto a provocare crash.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Riutilizzare il corpus della campagna per generare report sulla copertura

Al termine di una campagna, riproduci il corpus della coda salvato per generare un report sulla copertura di Go, senza dover esportare manualmente un corpus separato.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Esegui il comando dallo **stesso package** e con lo **stesso target `-fuzz`** affinché gosentry risolva lo stato corretto della campagna memorizzato nella cache.



## References

- [1] [Fuzzing con grammatiche mutazionali](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ in profondità](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinque anni dopo: sul fuzzing dei protocolli guidato dalla copertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark trasforma il codice in grafi](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing di Go mancava metà del toolkit. Abbiamo forkato la toolchain per risolvere il problema.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox veloce per protocolli di rete stateful basato su snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Nessuna grammatica, nessun problema: verso il fuzzing del kernel Linux senza descrizioni delle system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing efficiente con snapshot adattivi e modificabili](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Strumentazione LLVM di AFL++: copertura dei percorsi e dei chiamanti](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predittivo sensibile al contesto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog di Android Offensive Security - Fuzzing di Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL per Android Binder - documentazione di build e seed di regressione](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: esplorare le race condition nel kernel Linux con interleaving controllati degli accessi alla memoria](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: copertura del codice per il fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintassi dei nomi file estesi di CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Avviso Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing della sintassi dei nomi file estesi di CFITSIO: 16 vulnerabilità di memory-safety e triage assistito da Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
