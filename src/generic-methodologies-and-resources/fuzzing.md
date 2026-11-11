# Metodologia del fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: copertura vs. semantica

Nel **mutational grammar fuzzing**, gli input vengono mutati rimanendo **validi secondo la grammatica**. In modalità guidata dalla copertura, vengono salvati come seed del corpus solo i campioni che producono **nuova copertura**. Per i **target linguistici** (parser, interpreti, engine), questo può far perdere bug che richiedono **catene semantiche/di flusso dei dati**, in cui l'output di un costrutto diventa l'input di un altro.<sup>[[1]](#references)</sup>

**Modalità di errore:** il fuzzer trova seed che esercitano singolarmente `document()` e `generate-id()` (o primitive simili), ma **non preserva il flusso dei dati concatenato**, quindi il campione “più vicino al bug” viene scartato perché non aggiunge copertura. Con **3 o più passaggi dipendenti**, la ricombinazione casuale diventa costosa e il feedback sulla copertura non guida la ricerca.<sup>[[1]](#references)</sup>

**Implicazione:** per le grammatiche con molte dipendenze, valuta di **combinare fasi mutazionali e generative** o di orientare la generazione verso pattern di **concatenamento delle funzioni** (non solo verso la copertura).<sup>[[1]](#references)</sup>

## Problemi di diversità del corpus

La mutazione guidata dalla copertura è **greedy**: un campione che introduce nuova copertura viene salvato subito, spesso mantenendo ampie regioni invariate. Col tempo, i corpus diventano **quasi duplicati** con poca diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è la **minimizzazione consapevole della grammatica**, che **si interrompe dopo una soglia minima di token** (riduce il rumore mantenendo una struttura circostante sufficiente a favorire le mutazioni).<sup>[[1]](#references)</sup>

Una regola pratica per il corpus nel mutational fuzzing è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzano la copertura** a una grande raccolta di quasi duplicati. In pratica, questo di solito significa quanto segue.<sup>[[1]](#references)[[3]](#references)</sup>

- Parti da **campioni del mondo reale** (corpus pubblici, crawling, traffico acquisito, insiemi di file provenienti dall'ecosistema del target).
- Riducili con la **minimizzazione del corpus basata sulla copertura**, invece di conservare ogni campione valido.
- Mantieni i seed **abbastanza piccoli** da far sì che le mutazioni agiscano su campi significativi, invece di sprecare la maggior parte dei cicli su byte irrilevanti.
- Ripeti la minimizzazione del corpus dopo modifiche importanti all'harness o alla strumentazione, perché il corpus “migliore” cambia quando cambia la raggiungibilità.

## Programmi generati di grandi dimensioni e bias dei timeout

Nel fuzzing di compilatori e interpreti, un input potrebbe dover superare una **soglia di dimensione del codice generato** invece di raggiungere un nuovo ramo del parser. Nell'esempio di V8 relativo all'offset dell'exception handler [exception-handler offset example](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size), un testcase valido doveva superare i 256 MiB di bytecode prima che l'offset troncato dell'handler diventasse rilevante. Costrutti `yield*` ripetuti potevano raggiungere quella soglia, ma la compilazione del testcase richiedeva alcuni secondi in una build di debug. Le preferenze per input piccoli e timeout di esecuzione brevi possono penalizzare questa categoria, anche quando la copertura della grammatica è elevata. Quando analizzi offset compressi o altri metadati sensibili alla lunghezza, valuta separatamente le soglie di dimensione e la politica dei timeout; questo consiglio per la campagna è un'inferenza basata sulla modalità di errore riportata.<sup>[[29]](#references)</sup>

## Mutazione consapevole dei confronti per i valori magici

Un motivo comune per cui i fuzzer raggiungono un plateau non è la sintassi, ma i **confronti rigidi**: byte magici, controlli di lunghezza, stringhe enum, checksum o valori di dispatch del parser verificati tramite `memcmp`, tabelle switch o confronti a cascata. La mutazione puramente casuale spreca cicli nel tentativo di indovinare questi valori byte per byte.

Per questi target, usa il **tracing dei confronti** (ad esempio, workflow in stile AFL++ `CMPLOG` / Redqueen), così il fuzzer può osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.<sup>[[3]](#references)</sup>

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

- È particolarmente utile quando il target protegge la logica più profonda dietro **firme di file**, **verbi di protocollo**, **tag di tipo** o **bit di funzionalità dipendenti dalla versione**.
- Abbinalo a **dizionari** estratti da campioni reali, specifiche di protocollo o log di debug. Un piccolo dizionario con token della grammatica, nomi di chunk, verbi e delimitatori è spesso più utile di una wordlist generica enorme.
- Se il target esegue molti controlli sequenziali, risolvi prima i confronti “magic” iniziali e poi minimizza di nuovo il corpus risultante, così le fasi successive partono da prefissi già validi.

## Fuzzing delle API per file che nascondono un linguaggio per i nomi file

Un parametro chiamato `filename`, `path` o `URL` potrebbe essere un punto di ingresso per un interprete anziché una ricerca letterale di file. Ad esempio, la Extended Filename Syntax (EFS) di CFITSIO valuta selettori tra parentesi quadre, espressioni su righe/pixel, colonne calcolate, istogrammi e trasformazioni prima di restituire l'oggetto aperto; alcune forme creano anche copie temporanee. Durante la mappatura della superficie d'attacco, classifica ogni API di apertura/importazione come **percorso letterale** o **percorso interpretato**, quindi esegui il fuzzing sul punto di ingresso di produzione effettivamente chiamato dalle applicazioni.<sup>[[20]](#references)[[22]](#references)</sup>

Per le primitive SSRF, di copia dei file e di gestione dei protocolli che ne derivano — e per API più sicure con percorsi letterali — consulta [Mini-linguaggi per i nomi file come primitive SSRF/per i file](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Tieni separato l'oggetto di supporto dal programma sottoposto a fuzzing

Quando la grammatica si trova in un suffisso del nome file, modificare solo i byte del file referenziato non raggiunge il parser. Un piccolo harness può invece leggere un caso di test come stringa e passarla all'API di apertura interpretata; la campagna su CFITSIO ha raggiunto la maggior parte dei parser e valutatori EFS chiamando `fits_open_file()` in modalità di sola lettura. Tieni disponibili separatamente file di supporto validi, così le mutazioni possono concentrarsi sul linguaggio dei selettori e delle espressioni invece di corrompere continuamente il percorso di base.<sup>[[22]](#references)</sup>

Usa seed che raggiungano ciascuno una famiglia grammaticale diversa, poi ricava un dizionario compatto sia dalla specifica sia dal codice sorgente del lexer/parser. Se la copertura si stabilizza mentre gli input continuano a fallire nello stesso percorso di errore sintattico, conserva i prefissi validi e aggiungi delimitatori, operatori, parole chiave, nomi di funzioni e nomi di campi rappresentativi, invece di aumentare soltanto il tempo dedicato alle mutazioni casuali.<sup>[[22]](#references)</sup>

Esegui l'harness con il dizionario grammaticale, ad esempio:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contenere gli effetti collaterali del harness "read-only"

Un flag read-only della libreria non garantisce un testcase privo di effetti collaterali: il linguaggio dei nomi file può riscrivere l'input, creare file di output o materializzare oggetti temporanei. La campagna CFITSIO inizialmente distruggeva i seed file e lasciava file imprevisti nel filesystem, quindi sono state necessarie operazioni di pulizia e isolamento.<sup>[[22]](#references)</sup>

- Assegnare a ogni worker una directory di lavoro sacrificabile e una directory temporanea privata.
- Esporre copie dei file di supporto canonici; non consentire mai al target di modificare l'unica copia del corpus.
- Disabilitare l'accesso alla rete, a meno che i backend remoti non siano il target previsto, e limitare i percorsi scrivibili con un container, un mount namespace o una sandbox equivalente.
- Ripristinare la directory dopo ogni esecuzione o batch di worker e considerare le modifiche inattese al filesystem come ulteriori finding.

### Ciclo crash-to-patch-to-fuzz

Raggruppare i crash prima della correzione, così da non trasformare migliaia di artifact in migliaia di task di patch. Nella valutazione di CFITSIO, AFLTriage ha ridotto il set iniziale di crash a poche cause principali; il successivo advisory mostra malfunzionamenti distinti, tra cui controlli errati delle dimensioni di destinazione, puntatori obsoleti dopo `realloc()`, errori aritmetici e percorsi di cleanup del parser non sicuri.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimizzare un input rappresentativo per ogni cluster e riprodurlo con AddressSanitizer.
2. Registrare l'accesso esatto che causa il malfunzionamento, la posizione nel sorgente, la cronologia di allocazione/liberazione e lo stato del parser che ha reso falsa l'invariante.
3. Applicare una patch candidata circoscritta e ricompilare con la stessa strumentazione di coverage e sanitizer.
4. Riprodurre il reproducer originale **e ogni input del suo cluster**; attivare anche il rilevamento dei leak, perché una correzione di memory-safety può compromettere la gestione delle risorse in un percorso di errore.
5. Eseguire test funzionali con file reali, quindi riprendere dalla queue accumulata (o reimportarla se il motore richiede una directory di output nuova dopo la modifica del binario).
6. Ripetere: la rimozione del primo crash superficiale spesso consente ai seed esistenti di avanzare fino a uno stato più profondo del parser.

Un LLM può velocizzare il passaggio 2 e preparare una bozza per il passaggio 3 se riceve l'input che causa il crash, il report del sanitizer, l'harness e il sorgente pertinente, ma la sua patch resta non attendibile. Sono la riproduzione con sanitizer e i controlli di regressione, non la spiegazione del modello, a determinare se la correzione viene accettata.<sup>[[22]](#references)</sup>

## Feedback più ricco quando l'edge coverage accorpa percorsi diversi

La normale edge coverage non distingue due esecuzioni che attraversano lo stesso helper da chiamanti diversi o seguono combinazioni di branch differenti all'interno di una funzione. Questo è importante nei decoder condivisi, nei dispatcher di protocollo e negli helper degli interpreti, dove il **percorso** che porta a un edge determina lo stato attivo. Anche tracciare ingenuamente ogni contesto di chiamata è rischioso: la coverage map e la queue possono crescere a dismisura. La ricerca sul fuzzing sensibile al contesto raccomanda quindi di affinare solo i contesti promettenti, invece di rendere sensibile al contesto l'intero call graph.<sup>[[14]](#references)</sup>

Le versioni recenti di AFL++ offrono la **coverage dei percorsi per funzione Ball-Larus**, oltre alla normale edge coverage. Assegnano una feature a ogni percorso aciclico all'interno di una funzione; gli archi di ritorno dei loop vengono rimossi, quindi questo feedback distingue le combinazioni di branch ma **non il numero di iterazioni dei loop**. Iniziare con il livello permissivo `1`, quindi limitare le modalità più rigide al codice sospetto di parser e state machine, perché il numero di percorsi può crescere esponenzialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Per una funzione helper chiamata da molti punti rilevanti per la sicurezza, la modalità LTO può combinare ogni percorso della funzione con il relativo sito di chiamata immediato:<sup>[[13]](#references)</sup>

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

- Esegui in parallelo un'istanza con la normale edge coverage; il feedback più ricco è utile solo se il costo aggiuntivo in termini di queue/map non riduce troppo le esecuzioni al secondo.
- Usa `AFL_LLVM_ALLOWLIST` per limitare l'instrumentation dei percorsi/chiamanti quando le librerie con molti template o il codice utility generico dominano la map.
- AFL++ può saltare le funzioni con un numero eccessivo di percorsi aciclici; gli avvisi durante la compilazione indicano che il target richiede un'allowlist o un livello meno rigoroso.
- La coverage di chiamante + percorso supporta un solo livello di chiamante. Non combinarla con stack di contesto più profondi.
- Gli ID dei percorsi possono cambiare tra le versioni major di LLVM. Mantieni fissa la toolchain per tutta la campagna e non sincronizzare corpus basati su PATH come se i loro feature ID fossero stabili tra le build.
- Questo feedback integra `CMPLOG`: il tracing dei confronti risolve **quale valore supera una guardia**, mentre il feedback su percorso/chiamante preserva **quale route e combinazione di branch vi hanno portato**.

## Fuzzing stateful: le sequenze sono seed

Per **protocolli**, **workflow autenticati** e **parser multifase**, l'unità interessante spesso non è un singolo blob, ma una **sequenza di messaggi**. Concatenare l'intera trascrizione in un unico file e mutarla alla cieca è di solito inefficiente, perché il fuzzer muta ogni passaggio allo stesso modo, anche quando solo il messaggio successivo raggiunge lo stato fragile.<sup>[[4]](#references)</sup>

Un approccio più efficace consiste nel trattare la **sequenza stessa come seed** e usare lo **stato osservabile** (codici di risposta, stati del protocollo, fasi del parser, tipi degli oggetti restituiti) come feedback aggiuntivo.<sup>[[4]](#references)</sup>

- Mantieni stabili i **messaggi di prefisso validi** e concentra le mutazioni sul messaggio che **guida la transizione**.
- Memorizza gli identificatori e i valori generati dal server nelle risposte precedenti, se il passaggio successivo dipende da essi.
- Preferisci la mutazione/splicing per singolo messaggio alla mutazione dell'intera trascrizione serializzata come blob opaco.
- Se il protocollo espone codici di risposta significativi, usali come **oracle di stato economico** per dare priorità alle sequenze che avanzano più in profondità.

È per lo stesso motivo che i bug di autenticazione, le transizioni nascoste o i bug dei parser che si manifestano “solo dopo l'handshake” spesso sfuggono al fuzzing tradizionale basato sui file: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing del driver multi-client

Un'elevata edge coverage può comunque non rilevare bug nel driver IPC, perché la coverage non descrive **la proprietà degli oggetti, i reference count, i messaggi in sospeso, l'ordine di cleanup o gli interleaving dei thread**. La pagina [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) tratta il modello degli oggetti del driver; questo esempio si concentra sull'harness del fuzzer. Android Binder è un modello utile: raggiungere sia i percorsi di allocazione sia quelli di free non basta se il fuzzer non riesce a far operare più processi sullo stesso oggetto del kernel nell'ordine richiesto.<sup>[[15]](#references)</sup>

#### Modella il protocollo, non buffer `ioctl` isolati

Rappresenta un test case come una grammatica ordinata di **identità del client + operazione + argomenti strutturati**. Il fuzzer LKL per Binder usa protobuf e `libprotobuf-mutator`, con un client persistent context-manager e due client ordinari. Un harness semantico preserva quindi le relazioni che la mutazione cieca dei byte distruggerebbe.<sup>[[15]](#references)</sup>

- Memorizza i valori restituiti dalle operazioni precedenti. Ad esempio, `BC_FREE_BUFFER` deve riutilizzare un puntatore al transaction buffer restituito da un precedente `ioctl`.
- Genera risposte predefinite valide, in modo che le transazioni sincrone possano completarsi e le operazioni successive restino raggiungibili.
- Rifiuta le transizioni impossibili, come le transazioni verso sé stessi o più transazioni in sospeso verso lo stesso target.
- Mantieni lo stato singleton di bootstrap al di fuori del reset per ogni input. Binder consente una sola registrazione `BINDER_SET_CONTEXT_MGR` per avvio, quindi distruggere e ricreare ripetutamente quel client renderebbe non validi gli input successivi.

Un modello utile per una race sulle lifetime consiste nel far trasferire un oggetto a un client, avviare il cleanup di un thread o processo e, in parallelo, far rilasciare al client ricevente il transaction buffer. Nell'esempio CVE-2020-0423, un trasferimento `BINDER_TYPE_WEAK_BINDER` seguito da `BINDER_THREAD_EXIT` in race con `BC_FREE_BUFFER` poteva liberare un `binder_work` incorporato mentre il percorso di cleanup del thread in uscita lo stava ancora usando.<sup>[[15]](#references)</sup>

#### Reintroduci interleaving controllati in un kernel userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) collega il codice reale del kernel a un harness userspace ed espone la sua interfaccia syscall tramite `lkl_syscall`. Questo rende semplice coordinare protobuf state, coverage e KASAN in un unico processo. Di norma, però, LKL esegue una syscall senza che un altro thread del kernel la interrompa. Per le campagne di race, inserisci punti `schedule()` intorno a confini selezionati di lock/unlock e lifetime, poi lascia che l'harness scelga casualmente il client successivo a ogni yield. Mantieni questi punti mirati, perché ognuno moltiplica lo spazio di ricerca dello scheduling. Lo scheduler randomizzato descritto dai ricercatori **non** fa parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila e riproduci i seed di regressione serializzati

L'harness upstream fissa una versione compatibile di `libprotobuf-mutator`, abilita l'instrumentation per il fuzzing LKL e KASAN con `LKL_FUZZING=1`, e abilita `CONFIG_MMU` per Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Dopo aver esaminato una revisione deliberatamente vulnerabile o applicato le patch di rollback documentate upstream, un seed serializzato può riprodurre l’intera transizione di stato multi-client senza ricostruirla in una proof of concept in C ad hoc:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Considera il use-after-free rilevato da KASAN come conferma che il seed abbia raggiunto il percorso vulnerabile di lifetime. **Non** dimostra le primitive successive necessarie per l’esecuzione di codice nel kernel o l’escalation dei privilegi.<sup>[[16]](#references)</sup>

## Trucco di diversità su singola macchina (stile Jackalope)

Un modo pratico per combinare la **novità generativa** con il **riutilizzo della coverage** consiste nel **riavviare worker di breve durata** collegati a un server persistente. Ogni worker parte da un corpus vuoto, si sincronizza dopo `T` secondi, lavora per altri `T` secondi sul corpus combinato, si sincronizza di nuovo e poi termina. In questo modo si ottengono **strutture nuove a ogni generazione**, sfruttando comunque la coverage accumulata.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` approssima una **sincronizzazione ritardata** (prima la novità, poi il riutilizzo).
- In modalità grammar fuzzing, la **sincronizzazione iniziale con il server viene saltata per impostazione predefinita** (non serve `-skip_initial_server_sync`).
- Il valore ottimale di `T` **dipende dal target**; in genere conviene cambiarlo dopo che il worker ha trovato la maggior parte della coverage “facile”.

## Snapshot Fuzzing per target difficili da predisporre

Quando il codice che vuoi testare diventa raggiungibile solo **dopo una lunga fase di setup** (avvio di una VM, completamento di un login, ricezione di un pacchetto, parsing di un container, inizializzazione di un servizio), una valida alternativa è lo **snapshot fuzzing**: acquisisci lo stato del processo o della VM già pronto, inietta ogni caso di test nel percorso di input del target, esegui fino a un crash/timeout e ripristina lo snapshot. In questo modo eviti di ripetere l'inizializzazione o i prefissi del protocollo. È utile per **servizi di rete**, **firmware**, **superfici di attacco post-autenticazione** e **target binari**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Esegui il target fino a quando lo stato interessante è pronto.
2. Acquisisci uno snapshot di **memoria + registri** in quel punto.
3. Per ogni caso di test, scrivi l'input mutato direttamente nel buffer pertinente della guest/del processo.
4. Esegui fino a crash/timeout/reset.
5. Ripristina lo snapshot; per i target VM, se supportato, ripristina solo le **pagine dirty**, poi ripeti.

Posiziona lo snapshot il più vicino possibile al primo passaggio costoso di parsing/dispatch, ad esempio dopo una `recv`/`read` o il punto di deserializzazione del pacchetto, e annota il buffer di input usato dal target. Questo segue il principio di posizionamento adattivo: spostare lo snapshot più in profondità nell'elaborazione dell'input per evitare di ripetere il lavoro.<sup>[[11]](#references)</sup>

### Snapshot incrementali per gli stati del protocollo

Uno snapshot fisso evita i costi di setup, ma da solo non esplora le transizioni che richiedono diversi messaggi validi. Un harness LibAFL-Qemu può monitorare le scritture in un campo dello stato del protocollo e salvare un nuovo snapshot quando lo stato cambia. Nell'[harness TCP di libslirp](https://github.com/quarkslab/slirp_snapshots_stateful), monitora `tcpcb.t_state`, calcola l'hash dello stato e dei flag di risposta per deduplicare gli snapshot e memorizza le pagine dirty rispetto a un genitore. Prima di mutare il successivo messaggio strutturato, ripristina lo snapshot selezionato attraverso la relativa catena di genitori. Il testcase conserva un `SnapshotId` e i byte di input generati (`gen_bytes`); il gestore degli snapshot tiene traccia della relazione tra genitori necessaria per il replay.<sup>[[27]](#references)[[28]](#references)</sup>

Il `SnapshotModule` user-mode di LibAFL-Qemu salva le mappature e la memoria del target, ma non i registri della CPU; quando necessario, conservali separatamente. Il gestore descritto supporta un solo albero di snapshot radice e non può condividere gli ID degli snapshot tra i worker. Inoltre, la modalità multi-snapshot non può riutilizzare direttamente lo stato shadow di QASAN. Per il triage offline, ricostruisci la catena di input in un processo strumentato separato. Quando usi `AsanHostModule` e `DrCovModule`, `fuzzer.evaluate_input` esegue i callback `pre_exec`/`post_exec` necessari; `qemu.run` da solo non lo fa.<sup>[[27]](#references)[[28]](#references)</sup>

### Rilevare le letture oltre i limiti logici dei ring buffer

Una lettura oltre il *conteggio dei dati validi* di un buffer può rimanere all'interno della sua allocazione host e sfuggire al normale ASAN. L'[esempio dei dati urgenti di libslirp](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) causa anche un underflow di un conteggio di byte unsigned. Se il sorgente è disponibile, la strumentazione per rilevare l'overflow di interi signed/unsigned può rilevare questo effetto collaterale; prima di sopprimere le segnalazioni, distingui il wrap intenzionale del numero di sequenza TCP. Un oracle proposto più robusto consiste nel mettere in poison l'allocazione del ring buffer personalizzato, rimuovere il poison solo dagli intervalli validi man mano che l'allocatore interno avanza e rimetterlo sugli intervalli rilasciati. LibAFL-Qemu espone un'API di poisoning ASAN per i target in cui la strumentazione del sorgente non è praticabile.<sup>[[27]](#references)</sup>

## Esplorazione delle race nel kernel Linux con MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) trasforma le race del kernel Linux sensibili al timing in pianificazioni ripetibili degli accessi alla memoria. Può enumerare automaticamente le esecuzioni **A-B-A** in due contesti oppure consentire a un analista di imporre vincoli di ordinamento tramite un'interfaccia terminale/GUI. È uno strumento di ricerca sperimentale, non un fuzzer completo per la concorrenza: al momento richiede LLVM 23+ e il kernel patchato del progetto; gli strumenti a riga di comando supportano due thread di test e il livello di fuzzing userspace proposto non è implementato.<sup>[[17]](#references)[[18]](#references)</sup>

### Raccogliere i punti di comunicazione tra contesti

Compila il kernel strumentato con i callback outline di KASAN e il supporto patchato di KCOV per la registrazione della memoria. Il README del progetto raccomanda anche di disabilitare l'ottimizzazione sibling-call affinché gli stack delle chiamate restino utilizzabili.<sup>[[17]](#references)[[18]](#references)</sup>

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

La modalità outline di KASAN (`asan-instrumentation-with-call-threshold=0`) converte gli accessi strumentati in chiamate a funzioni helper. Le patch del kernel MAccConc disabilitano `asan-opt-same-temp` per evitare che gli accessi consecutivi vengano uniti; disabilita anche l’ottimizzazione `asan-opt-globals` quando è necessario rendere visibili le race sulle variabili globali. KCOV trasmette i record risultanti allo spazio utente. Confronta gli accessi provenienti da contesti di esecuzione diversi e conserva le coppie i cui intervalli di byte si sovrappongono e in cui almeno uno dei due accessi è una scrittura; considera `kfree()` come una scrittura, così anche le transizioni del ciclo di vita diventano candidate.<sup>[[17]](#references)</sup>

Per le attività che proseguono al di fuori del task iniziale, come l’elaborazione dei pacchetti o le callback RCU, il sottosistema deve propagare un handle di copertura remota KCOV. Il supporto upstream di KCOV remoto è opt-in e non è automaticamente disponibile per attività arbitrarie in background, quindi la mancata propagazione può rendere invisibile un’interazione reale.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificare lo stesso accesso dinamico a ogni esecuzione

Non riprodurre l’esecuzione usando un indirizzo heap concreto, che può cambiare dopo ogni allocazione, né basandoti soltanto sull’indirizzo di un’istruzione, che è ambiguo all’interno di helper come `memcpy()` e `spin_lock()`. MAccConc usa una **traccia dello stack arricchita con contatori**: ogni frame identifica una funzione chiamata e il conteggio delle sue invocazioni all’interno della funzione chiamante, mentre l’elemento finale identifica l’istruzione di accesso alla memoria. I record di entrata/uscita delle funzioni di SanitizerCoverage consentono allo spazio utente di ricostruire questo identificatore dinamico, che rimane stabile anche se cambiano gli indirizzi e in presenza di rumore di controllo del flusso non correlato.<sup>[[17]](#references)</sup>

### Convertire le coppie candidate in pianificazioni forzate

L’ioctl `KCOV_SET_DI` aggiunto dalla patch associa un identificatore di accesso arricchito con contatori a un’azione su un flag condiviso.<sup>[[17]](#references)</sup>

| Azione | Semantica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Imposta il flag *N* immediatamente prima dell’accesso selezionato. |
| `DI_STACK_WAIT` | Prima dell’accesso selezionato, attende in un ciclo finché il flag *N* non viene impostato o scade il limite configurato. |
| `DI_STACK_WAKE_POST` | Imposta il flag *N* immediatamente dopo l’accesso selezionato. |

Per un vincolo parziale **A-happens-before-B**, associa `DI_STACK_WAKE_POST` ad A e `DI_STACK_WAIT` a B usando lo stesso flag. Per una pianificazione completamente specificata tra due contesti, avvia B in stato di attesa, poi fai in modo che A risvegli B e attenda al primo punto di trasferimento; al trasferimento successivo, B esegue l’operazione inversa. Quest’ultimo approccio agisce come un cambio di contesto deterministico ed è quello usato dall’esploratore automatico A-B-A.<sup>[[17]](#references)</sup>

Una campagna minima consiste nel compilare il test case a quattro hook (`test_setup`, le due funzioni dei thread e `test_end`) come libreria condivisa, raccogliere una traccia senza vincoli e poi enumerare le candidate A-B-A oppure aggiungere vincoli manuali attorno agli accessi sospetti.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreta i timeout separatamente dai riordinamenti riusciti: l’ordine richiesto potrebbe essere impossibile perché un lock o una dipendenza di inizializzazione/pubblicazione impedisce al secondo contesto di raggiungere il punto di injection. Tieni inoltre presenti i punti ciechi di KASAN: gli accessi diretti allo stack di solito non vengono intercettati, a meno che non possano essere out-of-bounds; le variabili globali vengono omesse con l’ottimizzazione predefinita; e i compilatori attuali non possono generare hook ASAN e TSAN contemporaneamente. Quando un guest va in panic, il prototipo perde il buffer KCOV: conserva quindi una console/oracle di crash indipendente.<sup>[[17]](#references)</sup>

Per il fuzzing guidato dalla concorrenza, registra riepiloghi degli accessi alla memoria per input o syscall, abbina le operazioni che creerebbero punti di comunicazione tra contesti ed esplora solo quelle combinazioni. Gli snapshot delle VM stabilizzano lo stato globale e gli indirizzi; senza snapshot, i metadati dei siti di allocazione possono astrarre gli oggetti tra un’esecuzione e l’altra. Questa è un’estensione proposta, non una funzionalità degli attuali strumenti userspace di MAccConc.<sup>[[17]](#references)</sup>

## Introspezione dell’harness: individuare presto i fuzzer superficiali

Quando una campagna si blocca, spesso il problema non è il mutator, ma l’**harness**. Usa l’**introspezione di raggiungibilità/copertura** per trovare le funzioni staticamente raggiungibili dal target di fuzzing, ma coperte raramente o mai durante l’esecuzione. Queste funzioni indicano di solito uno di tre problemi.<sup>[[12]](#references)</sup>

- L’harness entra nel target troppo tardi o troppo presto.
- Nel seed corpus manca un’intera famiglia di funzionalità.
- Il target ha davvero bisogno di un **secondo harness**, anziché di un unico harness sovradimensionato che “fa tutto”.

Se usi workflow in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector può confrontare la raggiungibilità statica con la copertura runtime e generare report a partire da un’esecuzione a tempo limitato o da un corpus pubblico.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, ampliare il corpus per una funzionalità specifica o suddividere un harness monolitico in entry point più piccoli.

## Selezione dei target di fuzzing basata sul grafo e triage delle mutazioni

Se hai già **risultati dell’analisi statica**, **mutanti sopravvissuti ai test di mutazione** e **report di coverage**, non eseguire il triage trattandoli come elenchi indipendenti. Prima crea un **call graph**, annota i nodi con la **complessità ciclomatica**, la **raggiungibilità da entry point/input non attendibili** e gli eventuali risultati esterni, quindi poni domande sul grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quali funzioni ad alta complessità sono raggiungibili da input non attendibili?
- Quali mutanti sopravvissuti si trovano sui percorsi dai parser/handler al codice critico per la sicurezza?
- Quali funzioni sono colli di bottiglia architetturali con un **raggio d’impatto** insolitamente ampio?

Questo di solito fa emergere target di fuzzing migliori rispetto alla sola «coverage più bassa». Un parser/decoder con **alta complessità** e **raggiungibilità esterna** confermata è un candidato più valido per un harness rispetto a un helper interno isolato, con coverage debole ma senza percorsi controllati da un attaccante.

### Workflow pratico di triage

1. Crea un **grafo del codice** a partire dal codebase ed estrai le metriche di complessità e dei branch per ogni funzione.
2. Elenca gli **entry point** che accettano input controllati da un attaccante: handler delle richieste, decoder, importer, parser di protocollo, reader di CLI/file.
3. Esegui query sui percorsi da questi entry point alle funzioni candidate per distinguere la superficie d’attacco raggiungibile dal codice morto o accessibile solo internamente.
4. Assegna la priorità ai nodi che combinano:
   - alta **complessità ciclomatica**
   - **raggiungibilità da input non attendibili** confermata
   - ampio **raggio d’impatto** o molti componenti dipendenti a valle
   - elementi di conferma, come risultati **SARIF**, note di audit o mutanti sopravvissuti
5. Scrivi prima harness mirati per i nodi con il punteggio più alto, soprattutto per **parser/codec** come decoder hex/Base64/IP/messaggi.

### Mutanti sopravvissuti: equivalenti o sfruttabili

Il testing delle mutazioni spesso produce un elenco rumoroso di mutanti sopravvissuti. Prima di considerarli tutti lacune di sicurezza, usa il grafo per chiederti:

- La funzione mutata è raggiungibile da un entry point controllato da un attaccante?
- Tutti i percorsi di chiamata sono vincolati da invarianti più forti del controllo mutato?
- Il nodo si trova in codice morto, in logica dedicata solo alla formattazione oppure in un percorso aritmetico/parser ad alto impatto?

I mutanti sopravvissuti che restano irraggiungibili o sono vincolati strutturalmente sono spesso **mutanti equivalenti**. Quelli che restano **raggiungibili** e riguardano **condizioni limite**, **percorsi di overflow/carry** o **operazioni aritmetiche/parsing critiche per la sicurezza** andrebbero promossi a:

- nuovi harness di fuzzing
- test diretti di proprietà/invarianti
- vettori mirati per i casi limite

### Correlare i risultati esterni al grafo

Se la tua pipeline SAST esporta **SARIF**, proietta i risultati sui nodi del grafo usando **file + intervallo di righe** e usa il grafo per estenderne l’impatto.<sup>[[6]](#references)</sup>

- calcola il **raggio d’impatto** della funzione segnalata
- verifica se il risultato si trova su un percorso da un entry point
- raggruppa i risultati vicini che confluiscono nello stesso collo di bottiglia

Questo è utile per decidere se dedicare tempo al fuzzing di una funzione specifica: un nodo **raggiungibile**, **complesso** e con risultati **SAST** è spesso un target migliore di un nodo semplicemente complesso, privo di percorsi accessibili a un attaccante.

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

La metodologia importante è l’intersezione tra **complessità x esposizione x impatto**. Usa il grafico per scegliere i target di fuzzing con il maggior valore di sicurezza atteso, poi usa i sopravvissuti alle mutazioni per stabilire quali confini e invarianti il tuo harness deve sottoporre a stress.<sup>[[5]](#references)</sup>

## Fuzzing differenziale delle codifiche delle chiavi crittografiche

Parti da chiavi serializzate valide o da vettori di test standard. Modifica i campi codificati senza compromettere la lunghezza e la struttura necessarie per raggiungere i percorsi di importazione e operazione, quindi invia gli stessi byte a implementazioni indipendenti. Confronta l’accettazione e gli errori. Le firme e i ciphertext randomizzati richiedono oracoli di correttezza, non un confronto byte per byte: verifica le firme oppure confronta i segreti condivisi ottenuti da un round trip di encapsulation/decapsulation. I vettori di test stabiliscono la conformità per i casi noti; le mutazioni differenziali sondano codifiche malformate che ne esulano.<sup>[[23]](#references)[[26]](#references)</sup>

Per questi formati di chiavi, usa oracoli specifici per il formato:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Chiavi di firma ML-DSA espanse:** modifica i coefficienti `s1` o `s2` impacchettati portandoli fuori da `[-η, η]`, mantenendo la chiave analizzabile. Verifica se l’importazione o la firma li rifiutano e se le firme risultanti vengono verificate. Le sole differenze di accettazione non costituiscono violazioni degli standard, perché FIPS 204 non impone controlli aggiuntivi sulle chiavi private. Vedi il [meccanismo di leakage condizionale](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Coppie di chiavi ML-KEM:** distingui i controlli obbligatori sulla chiave di encapsulation e sull’input di decapsulation dal controllo opzionale di coerenza della coppia (PCT) su una coppia importata. Esegui l’encapsulation con la chiave pubblica e la decapsulation con quella privata, quindi confronta i segreti condivisi; una discrepanza può interrompere la comunicazione cifrata anche quando le singole chiavi superano i controlli sugli input. Verifica se l’API convalida gli input durante l’operazione o tramite una chiamata separata; libcrux espone `validate_public_key(pk)` e `validate_private_key(sk, ct)`, che non sostituiscono un PCT.
- **Chiavi raw XMSS/XMSSMT:** verifica i round trip delle chiavi serializzate di **firma e verifica** tra diversi set di parametri, non solo le operazioni con chiavi in memoria. XMSS e XMSSMT hanno spazi dei nomi OID separati di quattro byte, quindi un parser che prova prima XMSS e controlla solo l’OID può classificare erroneamente una chiave XMSSMT con OID coincidente e rifiutarne l’importazione. Il parser RustCrypto segnalato illustra un problema di interoperabilità/disponibilità, non una falsificazione di firma.

## Fuzzing Go con gosentry: motore più potente, input tipizzati e controlli differenziali

Se un target Go ha già un harness nativo `testing.F`, un modo pratico per aggiornarlo è eseguire lo stesso harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain Go forkata che mantiene `go test -fuzz` ma sostituisce il backend con **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Questo è utile quando il fuzzer nativo di Go si blocca su **confronti difficili**, **input tipizzati** o **formati ricchi di parser**. La metodologia resta la stessa:

- Continua a usare `f.Add(...)` per i seed e `f.Fuzz(...)` per la callback.
- Riutilizza lo stesso harness, ma eseguilo con il binario `go` di gosentry invece che con la toolchain standard.
- Considera la campagna risultante come una normale esecuzione guidata dalla copertura, ma con lo scheduling e le mutazioni di LibAFL e detector aggiuntivi.

### Trasformare gli errori silenziosi in risultati del fuzzing

Un problema ricorrente nelle valutazioni Go è che spesso i comportamenti pericolosi **non** causano un crash per impostazione predefinita. Con gosentry puoi trasformare diverse classi di stati «negativi ma silenziosi» in risultati.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` per fare in modo che percorsi selezionati di logging/errore si comportino come crash (utile per i percorsi di codice in stile `log.Fatal` che altrimenti si limiterebbero a registrare l’errore e continuare).
- `--catch-races=true` per rieseguire le nuove voci scoperte nella queue con il race detector di Go.
- `--catch-leaks=true` per rieseguire le nuove voci nella queue con `goleak` e interrompere l’esecuzione in caso di leak di goroutine.
- La gestione degli hang di LibAFL per mantenere **loop infiniti / input molto lenti** tra i risultati del fuzzing, invece di lasciarli scomparire tra i timeout.
- Controlli integrati per gli overflow aritmetici attivi per impostazione predefinita, oltre a controlli opzionali di troncamento tramite strumentazione in stile go-panikint.

Questo è particolarmente utile per i target in cui l’impatto sulla sicurezza consiste in un **errore di parser senza panic**, un **bug di concorrenza** o un **hang che causa solo DoS**, anziché in una corruzione della memoria.

### Fuzzing consapevole delle struct per le API Go tipizzate

Il fuzzing nativo di Go si aspetta principalmente valori scalari come `[]byte`, `string` e numeri. Se il codice sottoposto a test consuma oggetti tipizzati, gosentry può eseguire il fuzzing direttamente di **valori composti** (struct, slice, array, puntatori), continuando a mutare i byte sottostanti.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usarlo per creare un wire format fittizio solo per il fuzzing nasconderebbe i bug logici dietro codice di parsing usato solo dall’harness. Per campagne differential o grammar-based, mantieni l’input dell’harness come un singolo `[]byte` o `string` ed esegui il parsing all’interno della callback.

### Fuzzing basato su grammatica per parser e input di protocollo

Per parser, formati e linguaggi di input, gosentry può eseguire il **fuzzing grammaticale Nautilus** basato su LibAFL. La grammatica è un array JSON di regole di produzione e, di norma, l’harness dovrebbe accettare un singolo argomento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Note metodologiche:

- Usa la modalità grammar quando le mutazioni a livello di byte falliscono perlopiù durante i controlli sintattici iniziali.
- Mantieni la grammar focalizzata sul **sottoinsieme del linguaggio/protocollo rilevante per la sicurezza**, invece di modellare l’intera specifica.
- Usa valori limite elevati nei terminali/nonterminali per mettere sotto stress i limiti di interi, lunghezze e macchine a stati.
- La modalità grammar mantiene gli input validi secondo la grammar, ma il target riceve comunque **byte/stringhe**, quindi il parsing e i controlli semantici restano all’interno del codice sottoposto a harness.

### Fuzzing differenziale: confrontare le implementazioni, non solo i crash

Un approccio efficace per gli ecosistemi Go è il **fuzzing differenziale basato su grammar**: generare input strutturati validi e passarli a due parser, client o motori di transizione di stato.<sup>[[7]](#references)[[8]](#references)</sup>

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

Considera questi elementi come risultati:

- un'implementazione genera un panic mentre l'altra rifiuta l'input correttamente
- discrepanze tra input accettati e rifiutati
- alberi di parsing o oggetti decodificati diversi
- transizioni di stato, nonce, saldi o state root divergenti

È un modo pratico per individuare **discrepanze di consenso**, **ambiguità del parser** e **scostamenti tra specifica e implementazione**, spesso non rilevati dal solo fuzzing dei crash.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Riutilizzare il corpus della campagna per i report di coverage

Al termine di una campagna, riproduci il corpus salvato nella queue per generare un report di coverage Go senza esportare manualmente un corpus separato.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Esegui il comando dallo **stesso package** e con lo **stesso target `-fuzz`**, così gosentry risolve lo stato della campagna memorizzato nella cache corretta.

## References

- [1] [Fuzzing grammaticale mutazionale](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in profondità](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinque anni dopo: fuzzing dei protocolli guidato dalla copertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark trasforma il codice in grafi](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing di Go mancava metà del toolkit. Abbiamo creato un fork della toolchain per risolvere il problema.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox veloce per protocolli di rete stateful basato su snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Niente grammatica, nessun problema: verso il fuzzing del kernel Linux senza descrizioni delle system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing efficiente con snapshot adattivi e modificabili](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Strumentazione LLVM di AFL++: copertura dei percorsi e dei chiamanti](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predittivo sensibile al contesto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - Fuzzing di Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL per Android Binder - documentazione di build e dei seed di regressione](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: analisi delle race condition nel kernel Linux con interleaving controllati degli accessi alla memoria](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: copertura del codice per il fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintassi estesa dei nomi file di CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Avviso di sicurezza Doyensec: CFITSIO, quarto trimestre 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing della sintassi estesa dei nomi file di CFITSIO: 16 vulnerabilità di sicurezza della memoria e triage assistito da Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing differenziale per la crittografia](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: standard per il meccanismo di incapsulamento delle chiavi basato su reticoli modulari](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Bug nel parsing dell’OID di XMSSMT - issue #1442 di RustCrypto](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stato delle implementazioni della crittografia post-quantistica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Come abbiamo ottenuto CVE-2026-9539 tramite snapshot](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzer contro IA: confronto tra Fuzzilli e BigSleep sui motori JavaScript](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
