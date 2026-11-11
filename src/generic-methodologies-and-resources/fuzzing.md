# Metodologia di Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: copertura vs. semantica

Nel **mutational grammar fuzzing**, gli input vengono mutati mantenendo la **validità grammaticale**. In modalità coverage-guided, solo i campioni che generano **nuova copertura** vengono salvati come seed del corpus. Per i **target linguistici** (parser, interpreti, motori), questo può non individuare bug che richiedono **catene semantiche/di flusso dei dati**, in cui l’output di un costrutto diventa l’input di un altro.<sup>[[1]](#references)</sup>

**Modalità di errore:** il fuzzer trova seed che esercitano singolarmente `document()` e `generate-id()` (o primitive simili), ma **non mantiene la catena del flusso dei dati**, quindi il campione «più vicino al bug» viene scartato perché non aggiunge copertura. Con **3 o più passaggi dipendenti**, la ricombinazione casuale diventa costosa e il feedback sulla copertura non guida la ricerca.<sup>[[1]](#references)</sup>

**Implicazione:** per grammatiche con molte dipendenze, valuta di **combinare fasi mutazionali e generative** o di indirizzare la generazione verso pattern di **concatenamento di funzioni** (non solo verso la copertura).<sup>[[1]](#references)</sup>

## Insidie della diversità del corpus

La mutazione guidata dalla copertura è **greedy**: un campione che offre nuova copertura viene salvato subito, spesso mantenendo ampie porzioni invariate. Con il tempo, i corpus si riempiono di **quasi duplicati** con poca diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è la **minimizzazione consapevole della grammatica**, che **si ferma al raggiungimento di una soglia minima di token** (riduce il rumore mantenendo abbastanza struttura circostante da favorire le mutazioni).<sup>[[1]](#references)</sup>

Una regola pratica per il corpus nel mutational fuzzing è: **preferire un insieme ridotto di seed strutturalmente diversi che massimizzano la copertura** a una grande raccolta di quasi duplicati. In pratica, di solito significa quanto segue.<sup>[[1]](#references)[[3]](#references)</sup>

- Parti da **campioni del mondo reale** (corpus pubblici, crawling, traffico acquisito, insiemi di file dell’ecosistema del target).
- Riducili con la **minimizzazione del corpus basata sulla copertura**, invece di conservare ogni campione valido.
- Mantieni i seed **abbastanza piccoli**, affinché le mutazioni interessino campi significativi invece di impiegare la maggior parte dei cicli su byte irrilevanti.
- Ripeti la minimizzazione del corpus dopo importanti modifiche all’harness o alla strumentazione, perché il corpus «migliore» cambia quando cambia la raggiungibilità.

## Mutazione consapevole dei confronti per i valori magici

Un motivo comune per cui i fuzzer si bloccano non è la sintassi, ma i **confronti rigidi**: byte magici, controlli di lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, tabelle switch o confronti concatenati. La mutazione puramente casuale spreca cicli nel tentativo di indovinare questi valori byte per byte.

Per questi target, usa il **tracciamento dei confronti** (ad esempio, workflow in stile AFL++ `CMPLOG` / Redqueen), così il fuzzer può osservare gli operandi dei confronti falliti e indirizzare le mutazioni verso valori che li soddisfino.<sup>[[3]](#references)</sup>

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

- È particolarmente utile quando il target protegge la logica più approfondita con **firme di file**, **verbi di protocollo**, **tag di tipo** o **bit di funzionalità dipendenti dalla versione**.
- Abbinalo a **dizionari** estratti da campioni reali, specifiche di protocollo o log di debug. Un piccolo dizionario con token grammaticali, nomi di chunk, verbi e delimitatori è spesso più utile di una enorme wordlist generica.
- Se il target esegue molti controlli sequenziali, risolvi prima i confronti “magic” iniziali, quindi riduci di nuovo il corpus risultante, in modo che le fasi successive partano da prefissi già validi.

## Fuzzing di API per file che nascondono un linguaggio per i nomi di file

Un parametro denominato `filename`, `path` o `URL` può essere un punto di ingresso per un interprete, anziché una semplice ricerca di file. Ad esempio, la Extended Filename Syntax (EFS) di CFITSIO valuta selettori tra parentesi quadre, espressioni di righe/pixel, colonne calcolate, istogrammi e trasformazioni prima di restituire l’oggetto aperto; alcune forme creano anche copie temporanee. Durante la mappatura della superficie d’attacco, classifica ogni API di apertura/importazione come **literal-path** o **interpreted-path**, quindi esegui il fuzzing sul punto di ingresso di produzione effettivamente chiamato dalle applicazioni.<sup>[[20]](#references)[[22]](#references)</sup>

Per le primitive risultanti di SSRF, copia di file e gestori di protocollo, e per API literal-path più sicure, vedi [Mini-linguaggi per i nomi di file come primitive SSRF/file](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Mantieni separato l’oggetto di supporto dal programma sottoposto a fuzzing

Quando la grammatica si trova in un suffisso del nome di file, modificare solo i byte del file referenziato non raggiunge il parser. Un piccolo harness può invece leggere un testcase come stringa e passarlo all’API di apertura interpretata; la campagna su CFITSIO ha raggiunto la maggior parte dei parser e valutatori EFS chiamando `fits_open_file()` in modalità di sola lettura. Tieni separati i file di supporto validi, così le modifiche possono concentrarsi sul linguaggio di selettori/espressioni, invece di compromettere continuamente il percorso di base.<sup>[[22]](#references)</sup>

Usa seed che raggiungano ciascuno una famiglia grammaticale diversa, quindi ricava un dizionario compatto sia dalle specifiche sia dal codice sorgente del lexer/parser. Se la coverage si stabilizza mentre gli input falliscono ripetutamente nello stesso percorso di errore sintattico, conserva i prefissi validi e aggiungi delimitatori, operatori, parole chiave, nomi di funzione e nomi di campo rappresentativi, invece di aumentare soltanto il tempo dedicato alle mutazioni casuali.<sup>[[22]](#references)</sup>

Esegui l’harness con il dizionario grammaticale, ad esempio:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contenere gli effetti collaterali del harness "read-only"

Un flag di libreria read-only non garantisce che un testcase sia privo di effetti collaterali: il linguaggio dei filename può riscrivere l'input, creare file di output o materializzare oggetti temporanei. La campagna CFITSIO inizialmente distruggeva i file seed e lasciava file imprevisti nel filesystem, quindi sono stati necessari pulizia e isolamento.<sup>[[22]](#references)</sup>

- Assegna a ogni worker una working directory eliminabile e una directory temporanea privata.
- Esponi copie dei file di supporto canonici; non consentire mai al target di modificare l'unica copia del corpus.
- Disabilita l'accesso alla rete, a meno che i backend remoti non siano il target previsto, e limita i percorsi scrivibili usando un container, un mount namespace o una sandbox equivalente.
- Reimposta la directory dopo ogni esecuzione o batch di worker e considera le modifiche impreviste al filesystem come ulteriori finding.

### Ciclo crash-to-patch-to-fuzz

Raggruppa i crash prima della correzione, così migliaia di artefatti non diventano migliaia di attività di patch. Nella valutazione CFITSIO, AFLTriage ha ridotto il set iniziale di crash a poche cause radice; l'advisory risultante mostra errori distinti, tra cui controlli errati delle dimensioni della destinazione, puntatori obsoleti dopo `realloc()`, errori aritmetici e percorsi non sicuri di cleanup del parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Riduci un input rappresentativo per ogni cluster e riproducilo con AddressSanitizer.
2. Registra l'accesso che ha causato l'errore, la posizione nel sorgente, la cronologia di allocazione/liberazione e lo stato del parser che ha reso falsa l'invariante.
3. Applica una patch candidata circoscritta e ricompila con la stessa strumentazione per coverage e sanitizer.
4. Riproduci il testcase originale **e ogni input del suo cluster**; abilita anche il rilevamento dei leak, perché una correzione per la memory safety può compromettere la gestione della proprietà degli oggetti in un percorso di errore.
5. Esegui test funzionali con file reali, quindi riprendi dalla queue accumulata (oppure reimportala, se l'engine richiede una nuova directory di output dopo la modifica del binario).
6. Ripeti: rimuovere il primo crash superficiale spesso consente ai seed esistenti di raggiungere uno stato più profondo del parser.

Un LLM può velocizzare il passaggio 2 e preparare una bozza per il passaggio 3 se riceve l'input che causa il crash, il report del sanitizer, il harness e il sorgente pertinente, ma la sua patch resta non attendibile. Sono la riproduzione con il sanitizer e i controlli di regressione, non la spiegazione del modello, a determinare se la correzione viene accettata.<sup>[[22]](#references)</sup>

## Feedback più ricco quando la edge coverage non distingue percorsi diversi

La normale edge coverage non distingue due esecuzioni che attraversano lo stesso helper da chiamanti diversi o seguono combinazioni diverse di branch all'interno di una funzione. Questo è importante nei decoder condivisi, nei dispatcher di protocollo e negli helper degli interpreti, dove il **percorso** verso un edge determina lo stato attivo. Anche tracciare ingenuamente ogni contesto di chiamata è rischioso: la coverage map e la queue possono esplodere. La ricerca sul fuzzing sensibile al contesto raccomanda quindi di affinare solo i contesti promettenti, anziché trattare l'intero grafo delle chiamate come sensibile al contesto.<sup>[[14]](#references)</sup>

Le versioni recenti di AFL++ offrono la **coverage dei percorsi per funzione Ball-Larus**, oltre alla normale edge coverage. Assegna una feature a ogni percorso aciclico attraverso una funzione; i back-edge dei loop vengono rimossi, quindi questo feedback distingue le combinazioni di branch ma **non il numero di iterazioni dei loop**. Inizia con il livello permissivo `1`, poi limita le modalità più rigorose al codice sospetto del parser o della state machine, perché il numero di percorsi può crescere esponenzialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Per un helper chiamato da molti punti rilevanti per la sicurezza, la modalità LTO può combinare il percorso di ciascuna funzione con il relativo punto di chiamata immediato:<sup>[[13]](#references)</sup>

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

**Indicazioni per la campagna:** applica con cautela un feedback più ricco e monitora i costi in termini di coverage-map e queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Esegui in parallelo un’istanza con la normale edge coverage; un feedback più ricco è utile solo se i costi aggiuntivi per queue/map non riducono drasticamente le esecuzioni al secondo.
- Usa `AFL_LLVM_ALLOWLIST` per limitare l’instrumentation di path/caller quando le librerie con molti template o il codice utility generico dominano la map.
- AFL++ può ignorare le funzioni con un numero eccessivo di path aciclici; gli avvisi durante la compilazione indicano che il target richiede un allowlisting o un livello meno rigoroso.
- La coverage caller + path supporta una sola profondità di caller. Non combinarla con stack di contesto più profondi.
- Gli ID dei path possono cambiare tra le versioni major di LLVM. Mantieni fissa la toolchain durante una campagna e non sincronizzare corpus basati su PATH come se i loro feature ID fossero stabili tra le build.
- Questo feedback integra `CMPLOG`: il tracing delle comparazioni risolve **quale valore supera una guardia**, mentre il feedback path/caller preserva **quale percorso e combinazione di branch lo hanno raggiunto**.

## Fuzzing stateful: le sequenze sono seed

Per **protocolli**, **workflow autenticati** e **parser multi-stage**, spesso l’unità interessante non è un singolo blob, ma una **sequenza di messaggi**. Concatenare l’intera trascrizione in un solo file e mutarla alla cieca è solitamente inefficiente, perché il fuzzer muta ogni passaggio allo stesso modo, anche quando solo il messaggio successivo raggiunge lo stato fragile.<sup>[[4]](#references)</sup>

Un approccio più efficace consiste nel trattare la **sequenza stessa come seed** e usare lo **stato osservabile** (codici di risposta, stati del protocollo, fasi del parser, tipi di oggetti restituiti) come feedback aggiuntivo.<sup>[[4]](#references)</sup>

- Mantieni stabili i **messaggi validi del prefisso** e concentra le mutazioni sul messaggio che **guida la transizione**.
- Memorizza nella cache gli identificatori e i valori generati dal server nelle risposte precedenti quando il passaggio successivo dipende da essi.
- Preferisci mutazioni/splicing per singolo messaggio, anziché mutare l’intera trascrizione serializzata come un blob opaco.
- Se il protocollo espone codici di risposta significativi, usali come **oracle di stato economico** per dare priorità alle sequenze che avanzano più in profondità.

È per lo stesso motivo che i bug autenticati, le transizioni nascoste o i bug del parser che si verificano “solo dopo l’handshake” spesso sfuggono al fuzzing vanilla in stile file: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing del driver multi-client

Una coverage degli edge elevata può comunque non rilevare bug del driver IPC, perché la coverage non descrive **la proprietà degli oggetti, i conteggi dei riferimenti, i messaggi in sospeso, l’ordine di cleanup o le interleaving dei thread**. La pagina [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) descrive il modello degli oggetti del driver; questo esempio si concentra sull’harness del fuzzer. Android Binder è un modello utile: raggiungere sia i path di allocazione sia quelli di free non basta se il fuzzer non riesce a far operare più processi sullo stesso oggetto del kernel nell’ordine richiesto.<sup>[[15]](#references)</sup>

#### Modella il protocollo, non buffer `ioctl` isolati

Rappresenta un test case come una grammatica ordinata di **identità del client + operazione + argomenti strutturati**. Il fuzzer Binder LKL usa protobuf e `libprotobuf-mutator`, con un client persistent context-manager e due client ordinari. Un harness semantico preserva quindi le relazioni che la mutazione cieca dei byte distruggerebbe.<sup>[[15]](#references)</sup>

- Memorizza nella cache i valori restituiti dalle operazioni precedenti. Per esempio, `BC_FREE_BUFFER` deve riutilizzare un puntatore al transaction-buffer restituito da una precedente `ioctl`.
- Genera risposte predefinite valide, così che le transazioni sincrone possano terminare e le operazioni successive restino raggiungibili.
- Rifiuta le transizioni impossibili, come le transazioni verso sé stessi o più transazioni in sospeso verso lo stesso destinatario.
- Mantieni lo stato singleton di bootstrap fuori dal reset per singolo input. Binder consente una sola registrazione `BINDER_SET_CONTEXT_MGR` per avvio; distruggere e ricreare ripetutamente quel client renderebbe non validi gli input successivi.

Un modello utile per le race sulle lifetime consiste nel far trasferire un oggetto a un client, avviare il cleanup di un thread o processo e, in parallelo, far rilasciare al client ricevente il transaction buffer. Nell’esempio CVE-2020-0423, un trasferimento `BINDER_TYPE_WEAK_BINDER` seguito da `BINDER_THREAD_EXIT` in race con `BC_FREE_BUFFER` poteva liberare un `binder_work` incorporato mentre il percorso di cleanup del thread in uscita lo stava ancora usando.<sup>[[15]](#references)</sup>

#### Reintroduci interleaving controllate in un kernel userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) collega il codice reale del kernel a un harness userspace ed espone la sua interfaccia syscall tramite `lkl_syscall`. Questo permette di coordinare facilmente protobuf state, coverage e KASAN in un unico processo. Normalmente, però, LKL esegue una syscall senza che un altro thread del kernel la interrompa. Per le campagne di race, inserisci punti `schedule()` attorno a confini selezionati di lock/unlock e lifetime, poi lascia che l’harness scelga casualmente il client successivo a ogni yield. Mantieni questi punti mirati, perché ciascuno moltiplica lo spazio di ricerca dello scheduling. Lo scheduler randomizzato descritto dai ricercatori **non** fa parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila e riproduci seed di regressione serializzati

L’harness upstream fissa una versione compatibile di `libprotobuf-mutator`, abilita l’instrumentation per il fuzzing LKL e KASAN con `LKL_FUZZING=1`, e abilita `CONFIG_MMU` per Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Dopo aver effettuato il checkout di una revisione deliberatamente vulnerabile o applicato le patch di rollback documentate upstream, un seed serializzato può riprodurre l’intera transizione di stato multi-client senza doverla ricostruire in una proof of concept C ad hoc:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Considera il use-after-free risultante in KASAN come conferma che il seed ha raggiunto il percorso vulnerabile del lifetime. Non dimostra le primitive successive necessarie per eseguire codice nel kernel o ottenere un'escalation dei privilegi.<sup>[[16]](#references)</sup>

## Strategia di diversità su una singola macchina (stile Jackalope)

Un modo pratico per combinare la **novità generativa** con il **riutilizzo della coverage** consiste nel **riavviare worker di breve durata** collegati a un server persistente. Ogni worker parte da un corpus vuoto, esegue la sincronizzazione dopo `T` secondi, lavora per altri `T` secondi sul corpus combinato, esegue di nuovo la sincronizzazione e poi termina. In questo modo si ottengono **strutture nuove a ogni generazione**, sfruttando al contempo la coverage accumulata.<sup>[[1]](#references)[[2]](#references)</sup>

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
- Il valore ottimale di `T` **dipende dal target**; in genere conviene cambiare valore quando il worker ha trovato la maggior parte della copertura “facile”.

## Snapshot fuzzing per target difficili da sottoporre a harness

Quando il codice da testare diventa raggiungibile solo **dopo una lunga fase di setup** (avvio di una VM, completamento di un login, ricezione di un pacchetto, parsing di un container, inizializzazione di un servizio), una valida alternativa è lo **snapshot fuzzing**: acquisire lo stato pronto del processo o della VM, inserire ogni test case nel percorso di input del target, eseguire fino a un crash o a un timeout e ripristinare lo snapshot. In questo modo non è necessario ripetere l'inizializzazione o i prefissi del protocollo; è utile per **servizi di rete**, **firmware**, **superfici di attacco post-auth** e **target solo binari**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Esegui il target finché non raggiunge lo stato di interesse.
2. Acquisisci uno snapshot di **memoria + registri** in quel punto.
3. Per ogni test case, scrivi l'input mutato direttamente nel buffer pertinente del guest/processo.
4. Esegui fino a un crash, a un timeout o a un reset.
5. Ripristina lo snapshot; per i target VM, ripristina solo le **pagine dirty** quando supportato, quindi ripeti.

Posiziona lo snapshot il più vicino possibile al primo passaggio costoso di parsing/dispatch, ad esempio dopo una `recv`/`read` o un punto di deserializzazione dei pacchetti, e registra il buffer di input usato dal target. Questo segue il principio di posizionamento adattivo: spostare lo snapshot più in profondità nell'elaborazione dell'input per evitare di ripetere il lavoro.<sup>[[11]](#references)</sup>

### Snapshot incrementali per gli stati del protocollo

Uno snapshot fisso evita i costi di setup, ma da solo non esplora le transizioni che richiedono diversi messaggi validi. Un harness LibAFL-Qemu può monitorare le scritture in un campo dello stato del protocollo e salvare un nuovo snapshot quando lo stato cambia. Nell'[harness TCP di libslirp](https://github.com/quarkslab/slirp_snapshots_stateful), monitora `tcpcb.t_state`, calcola l'hash dello stato e dei flag di risposta per deduplicare gli snapshot e memorizza le pagine dirty rispetto a uno snapshot padre. Prima di mutare il messaggio strutturato successivo, ripristina lo snapshot selezionato attraverso la catena dei relativi snapshot padre. Il testcase mantiene un `SnapshotId` e i byte di input generati (`gen_bytes`); lo snapshot manager tiene traccia della relazione tra snapshot padre e figlio necessaria per il replay.<sup>[[27]](#references)[[28]](#references)</sup>

La modalità user-mode di `SnapshotModule` di LibAFL-Qemu salva le mappature e la memoria del target, ma non i registri della CPU; se necessario, conservali separatamente. Il manager descritto supporta un solo albero di snapshot radice e non può condividere gli ID degli snapshot tra worker. Inoltre, la modalità multi-snapshot non può riutilizzare direttamente lo stato shadow di QASAN. Per il triage offline, ricostruisci la catena di input in un processo strumentato separato. Quando usi `AsanHostModule` e `DrCovModule`, `fuzzer.evaluate_input` esegue le callback `pre_exec`/`post_exec` necessarie; `qemu.run` da solo non lo fa.<sup>[[27]](#references)[[28]](#references)</sup>

### Rilevare le letture oltre il limite logico di un ring buffer

Una lettura oltre il *conteggio dei dati validi* di un buffer può rimanere entro l'allocazione host e sfuggire al normale ASAN. L'[esempio dei dati urgenti di libslirp](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) causa anche un underflow del conteggio di byte unsigned. Se il sorgente è disponibile, la strumentazione per l'overflow di interi signed/unsigned può rilevare questo effetto collaterale; prima di sopprimere le segnalazioni, distingui il wrap intenzionale dei numeri di sequenza TCP. Un oracle proposto più robusto consiste nell'avvelenare l'allocazione personalizzata del ring buffer, rimuovere l'avvelenamento solo dagli intervalli validi man mano che l'allocatore interno avanza e avvelenare nuovamente gli intervalli rilasciati. LibAFL-Qemu espone un'API di avvelenamento ASAN per i target per cui la strumentazione del sorgente è impraticabile.<sup>[[27]](#references)</sup>

## Esplorazione delle race nel kernel Linux con MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) trasforma le race nel kernel Linux sensibili al timing in sequenze ripetibili di accessi alla memoria. Può enumerare automaticamente esecuzioni **A-B-A** a due contesti oppure consentire a un analista di imporre vincoli di ordinamento tramite un'interfaccia terminale/GUI. È uno strumento sperimentale di ricerca, non un concurrency fuzzer completo: attualmente richiede LLVM 23+ e il kernel modificato del progetto; gli strumenti da riga di comando supportano due thread di test e il livello di fuzzing userspace proposto non è implementato.<sup>[[17]](#references)[[18]](#references)</sup>

### Raccogliere i punti di comunicazione tra contesti

Compila il kernel strumentato con le callback KASAN outline e il supporto patched di KCOV per la registrazione degli accessi alla memoria. Il README del progetto consiglia inoltre di disabilitare l'ottimizzazione sibling-call per mantenere utilizzabili gli stack delle chiamate.<sup>[[17]](#references)[[18]](#references)</sup>

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

La modalità outline di KASAN (`asan-instrumentation-with-call-threshold=0`) converte gli accessi strumentati in chiamate a funzioni helper. Le patch MAccConc per il kernel disabilitano `asan-opt-same-temp` affinché gli accessi consecutivi non vengano uniti; disabilitare anche l’ottimizzazione `asan-opt-globals` quando è necessario rendere visibili le race sulle variabili globali. KCOV invia i record risultanti allo userspace. Confrontare gli accessi provenienti da contesti di esecuzione diversi e mantenere le coppie i cui intervalli di byte si sovrappongono e almeno uno dei cui lati scrive; modellare `kfree()` come una scrittura, così anche le transizioni del ciclo di vita diventano candidate.<sup>[[17]](#references)</sup>

Per le attività che proseguono al di fuori del task iniziale, come l’elaborazione dei pacchetti o le callback RCU, il sottosistema deve propagare un handle di remote coverage di KCOV. Il remote KCOV upstream è opt-in e non è disponibile automaticamente per attività arbitrarie in background; quindi, se la propagazione manca, un’interazione reale potrebbe non essere rilevata.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificare lo stesso accesso dinamico a ogni esecuzione

Non effettuare il replay usando un indirizzo heap concreto, che può cambiare dopo ogni allocazione, né usando solo un indirizzo di istruzione, che è ambiguo all’interno di helper come `memcpy()` e `spin_lock()`. MAccConc usa una **traccia dello stack arricchita con contatori**: ogni frame identifica un callee e il numero di invocazioni all’interno del caller; l’elemento finale identifica l’istruzione di accesso alla memoria. I record di ingresso/uscita delle funzioni di SanitizerCoverage consentono allo userspace di ricostruire questo identificatore dinamico, che rimane stabile al variare degli indirizzi e in presenza di rumore nel flusso di controllo non correlato.<sup>[[17]](#references)</sup>

### Convertire le coppie candidate in schedule forzati

L’ioctl `KCOV_SET_DI` modificato associa un identificatore di accesso arricchito con contatori a un’azione su un flag condiviso.<sup>[[17]](#references)</sup>

| Azione | Semantica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Imposta il flag *N* immediatamente prima dell’accesso selezionato. |
| `DI_STACK_WAIT` | Prima dell’accesso selezionato, esegue uno spin finché il flag *N* non viene impostato o non scade il limite configurato. |
| `DI_STACK_WAKE_POST` | Imposta il flag *N* immediatamente dopo l’accesso selezionato. |

Per un vincolo parziale **A-happens-before-B**, associare `DI_STACK_WAKE_POST` ad A e `DI_STACK_WAIT` a B usando lo stesso flag. Per uno schedule completo a due contesti, avviare B in stato bloccato, quindi fare in modo che A risvegli B e attenda al primo punto di trasferimento; B esegue l’operazione inversa al trasferimento successivo. Quest’ultimo comportamento equivale a un cambio di contesto deterministico ed è quello usato dall’explorer automatico A-B-A.<sup>[[17]](#references)</sup>

Una campagna minima consiste nel compilare il test case a quattro hook (`test_setup`, le due funzioni thread e `test_end`) come libreria condivisa, raccogliere una traccia senza vincoli, quindi enumerare i candidati A-B-A o aggiungere vincoli manuali attorno agli accessi sospetti.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreta i timeout separatamente dai riordini riusciti: l’ordine richiesto potrebbe essere impossibile perché un lock o una dipendenza di inizializzazione/pubblicazione impedisce al secondo contesto di raggiungere il punto di injection. Tieni presenti anche i punti ciechi di KASAN: gli accessi diretti allo stack di solito non vengono agganciati, a meno che non possano andare fuori dai limiti; le variabili globali vengono omesse con l’ottimizzazione predefinita; inoltre, i compilatori attuali non possono generare hook ASAN e TSAN simultaneamente. Infine, il prototipo perde il buffer KCOV quando un guest va in panic, quindi mantieni una console/oracolo indipendente per i crash.<sup>[[17]](#references)</sup>

Per il fuzzing guidato dalla concorrenza in futuro, registra riepiloghi degli accessi alla memoria per ogni input o syscall, abbina le operazioni che formerebbero punti di comunicazione tra contesti, quindi esplora solo quelle combinazioni. Gli snapshot delle VM stabilizzano lo stato globale e gli indirizzi; senza snapshot, i metadati dei siti di allocazione possono astrarre gli oggetti tra un’esecuzione e l’altra. Si tratta di un’estensione proposta, non di una funzionalità degli attuali strumenti userspace di MAccConc.<sup>[[17]](#references)</sup>

## Introspezione dell’harness: individua subito i fuzzer superficiali

Quando una campagna si blocca, spesso il problema non è il mutator, ma l’**harness**. Usa l’**introspezione di raggiungibilità/copertura** per individuare le funzioni raggiungibili staticamente dal tuo target di fuzzing, ma coperte raramente o mai durante l’esecuzione. Queste funzioni di solito indicano uno di tre problemi.<sup>[[12]](#references)</sup>

- L’harness entra nel target troppo tardi o troppo presto.
- Nel seed corpus manca un’intera famiglia di funzionalità.
- Il target ha davvero bisogno di un **secondo harness**, invece di un unico harness sovradimensionato che “fa tutto”.

Se usi flussi di lavoro in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector può confrontare la raggiungibilità statica con la copertura in fase di esecuzione e generare report a partire da un’esecuzione a tempo o da un corpus pubblico.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, ampliare il corpus per una funzionalità specifica o suddividere un harness monolitico in entrypoint più piccoli.

## Selezione dei fuzz target e triage delle mutation a partire dal grafo

Se hai già **risultati di analisi statica**, **mutanti sopravvissuti ai test** e **report di coverage**, non esaminarli come elenchi indipendenti. Crea prima un **grafo delle chiamate**, annota i nodi con la **complessità ciclomatica**, la **raggiungibilità da entrypoint/input non attendibili** e gli eventuali risultati esterni, quindi poni domande sul grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quali funzioni ad alta complessità sono raggiungibili da input non attendibili?
- Quali mutanti sopravvissuti si trovano sui percorsi dai parser/handler al codice critico per la sicurezza?
- Quali funzioni sono colli di bottiglia architetturali con un **blast radius** insolitamente ampio?

Questo metodo di solito individua fuzz target migliori rispetto al solo criterio della «coverage più bassa». Un parser/decoder con **alta complessità** e **raggiungibilità esterna** confermata è un candidato per un harness migliore di un helper interno isolato, con coverage debole ma senza percorsi controllabili da un attaccante.

### Workflow pratico di triage

1. Crea un **grafo del codice** a partire dal codebase ed estrai le metriche di complessità/branch per ogni funzione.
2. Elenca gli **entrypoint** che accettano input controllati da un attaccante: request handler, decoder, importer, parser di protocolli, reader CLI/file.
3. Esegui query sui percorsi dagli entrypoint alle funzioni candidate, per distinguere la superficie d’attacco raggiungibile dal codice morto o accessibile solo internamente.
4. Assegna priorità ai nodi che combinano:
   - alta **complessità ciclomatica**
   - **raggiungibilità da input non attendibili** confermata
   - **blast radius** elevato o molti dipendenti a valle
   - elementi di conferma, come risultati **SARIF**, note di audit o mutanti sopravvissuti
5. Scrivi prima gli harness mirati per i nodi con il punteggio più alto, soprattutto per **parser/codecs** come i decoder di hex/Base64/IP/messaggi.

### Mutanti sopravvissuti: equivalenti o rilevanti

Il mutation testing produce spesso un elenco rumoroso di mutanti sopravvissuti. Prima di considerare ogni mutante sopravvissuto una lacuna di sicurezza, usa il grafo per chiederti:

- La funzione modificata è raggiungibile da un entrypoint controllato da un attaccante?
- Tutti i percorsi di chiamata sono vincolati da invarianti più forti del controllo modificato?
- Il nodo si trova in codice morto, in logica che riguarda solo la formattazione o in un percorso di calcolo/parser ad alto impatto?

I mutanti sopravvissuti che restano irraggiungibili o sono vincolati strutturalmente sono spesso **mutanti equivalenti**. Quelli che restano **raggiungibili** e coinvolgono **condizioni al limite**, **percorsi di overflow/carry** o **calcoli/parsing critici per la sicurezza** dovrebbero essere trasformati in:

- nuovi fuzz harness
- test diretti di proprietà/invarianti
- vettori mirati per casi limite

### Correlare i risultati esterni al grafo

Se la tua pipeline SAST esporta **SARIF**, associa i risultati ai nodi del grafo usando **file + intervallo di righe** e usa il grafo per valutare l’impatto.<sup>[[6]](#references)</sup>

- calcola il **blast radius** della funzione segnalata
- verifica se il risultato si trova su un percorso da un entrypoint
- raggruppa i risultati vicini che confluiscono nello stesso collo di bottiglia

Questo è utile per decidere se dedicare tempo al fuzzing di una funzione specifica: un nodo **raggiungibile**, **complesso** e con risultati **SAST** è spesso un target migliore di un nodo solo complesso, senza percorsi accessibili a un attaccante.

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

La metodologia importante è l’intersezione: **complessità x esposizione x impatto**. Usa il grafico per scegliere i target di fuzzing con il più alto valore di sicurezza atteso, poi usa i mutanti che superano i test per decidere quali confini e invarianti il tuo harness deve stressare.<sup>[[5]](#references)</sup>

## Fuzzing differenziale delle codifiche di chiavi crittografiche

Parti da chiavi serializzate valide o da vettori di test standard. Modifica i campi codificati senza alterare la lunghezza e la struttura necessarie per raggiungere i percorsi di importazione e di operazione, poi invia gli stessi byte a implementazioni indipendenti. Confronta l’accettazione e gli errori. Per firme e testi cifrati randomizzati servono oracoli di correttezza, non confronti byte per byte: verifica le firme o confronta i segreti condivisi ottenuti da un round trip di incapsulamento/decapsulamento. I vettori di test stabiliscono la conformità per i casi noti; la mutazione differenziale esplora codifiche malformate che ne vanno oltre.<sup>[[23]](#references)[[26]](#references)</sup>

Per questi formati di chiavi, usa oracoli specifici per il formato:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Chiavi di firma ML-DSA espanse:** modifica i coefficienti `s1` o `s2` impacchettati, portandoli fuori dall’intervallo `[-η, η]` e mantenendo la chiave analizzabile. Verifica se l’importazione o la firma vengono rifiutate e se eventuali firme risultanti vengono verificate. Le differenze di accettazione da sole non costituiscono violazioni degli standard, perché FIPS 204 non impone controlli aggiuntivi sulle chiavi private. Vedi il [meccanismo di leakage condizionale](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Coppie di chiavi ML-KEM:** distingui i controlli obbligatori sulla chiave di incapsulamento e sull’input di decapsulamento dal controllo opzionale di coerenza della coppia (PCT) su una coppia importata. Incapsula con la chiave pubblica e decapsula con quella privata, quindi confronta i segreti condivisi; una mancata corrispondenza può compromettere la comunicazione cifrata anche quando le singole chiavi superano i controlli sugli input. Verifica se l’API convalida gli input durante l’operazione o tramite una chiamata separata; libcrux espone `validate_public_key(pk)` e `validate_private_key(sk, ct)`, che non sostituiscono un PCT.
- **Chiavi raw XMSS/XMSSMT:** testa i round trip delle chiavi serializzate di **firma e verifica** tra diversi set di parametri, non soltanto le operazioni con chiavi in memoria. XMSS e XMSSMT hanno namespace OID distinti di quattro byte, quindi un parser basato solo sull’OID che prova prima XMSS può classificare erroneamente una chiave XMSSMT con OID coincidente e rifiutarne l’importazione. Il parser RustCrypto segnalato illustra un problema di interoperabilità/disponibilità, non una falsificazione di firme.

## Fuzzing Go con gosentry: motore più potente, input tipizzati e controlli differenziali

Se un target Go ha già un harness nativo `testing.F`, un percorso pratico di aggiornamento consiste nell’eseguire lo stesso harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain Go con modifiche che mantiene `go test -fuzz` ma sostituisce il backend con **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Questo è utile quando il fuzzer nativo di Go si blocca su **confronti difficili**, **input tipizzati** o **formati con parser complessi**. La metodologia rimane la stessa:

- Continua a usare `f.Add(...)` per i seed e `f.Fuzz(...)` per la callback.
- Riutilizza lo stesso harness, ma eseguilo con il binario `go` di gosentry invece che con la toolchain standard.
- Considera la campagna risultante una normale esecuzione guidata dalla coverage, ma con scheduling e mutazioni di LibAFL e migliori detector di supporto.

### Trasformare gli errori silenziosi in finding del fuzzing

Un problema ricorrente nelle valutazioni Go è che spesso i comportamenti pericolosi **non** causano un crash per impostazione predefinita. Con gosentry, puoi trasformare diverse categorie di stati «negativi ma silenziosi» in finding.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` per fare in modo che percorsi selezionati di logging/errori si comportino come crash (utile per i percorsi di codice in stile `log.Fatal`, che altrimenti si limitano a registrare l'errore e proseguono).
- `--catch-races=true` per riprodurre le nuove entry della coda scoperte con il race detector di Go.
- `--catch-leaks=true` per riprodurre le nuove entry della coda con `goleak` e fermarsi in caso di goroutine leak.
- La gestione degli hang di LibAFL permette di mantenere i **loop infiniti / input molto lenti** come finding del fuzzing, invece di lasciarli scomparire come timeout.
- Controlli integrati di overflow aritmetico per impostazione predefinita, oltre a controlli opzionali di troncamento tramite strumentazione in stile go-panikint.

Questo è particolarmente utile per i target in cui l'impatto sulla sicurezza consiste in un **errore del parser senza panic**, un **bug di concorrenza** o un **hang che causa solo DoS**, anziché in una corruzione della memoria.

### Fuzzing consapevole delle struct per le API Go tipizzate

Il fuzzing nativo di Go si aspetta principalmente valori scalari come `[]byte`, `string` e numeri. Se il codice in esame riceve oggetti tipizzati, gosentry può eseguire il fuzzing direttamente su **valori compositi** (struct, slice, array, puntatori), continuando a mutare i byte sottostanti.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usalo quando creare un wire format fittizio solo per il fuzzing nasconderebbe bug logici dietro codice di parsing usato solo dall'harness. Per campagne differential o basate su grammatiche, mantieni l'input dell'harness come un singolo `[]byte` o `string` e analizzalo invece all'interno della callback.

### Fuzzing basato su grammatiche per parser e input di protocolli

Per parser, formati e linguaggi di input, gosentry può eseguire il **fuzzing grammaticale Nautilus** sopra LibAFL. La grammatica è un array JSON di regole di produzione e, di norma, l'harness dovrebbe accettare un singolo argomento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Note metodologiche:

- Usa la modalità grammar quando le mutazioni a livello di byte falliscono per lo più nei primi controlli sintattici.
- Mantieni la grammar focalizzata sul **sottoinsieme del linguaggio/protocollo rilevante per la sicurezza**, invece di modellare l’intera specifica.
- Usa valori limite elevati nei terminali/non terminali per mettere alla prova i limiti di interi, lunghezze e macchine a stati.
- La modalità grammar mantiene gli input validi secondo la grammar, ma il target riceve comunque **byte/stringhe**, quindi il parsing e i controlli semantici restano all’interno del codice sottoposto a test.

### Fuzzing differenziale: confronta le implementazioni, non solo i crash

Un approccio efficace negli ecosistemi Go è il **fuzzing differenziale basato su grammar**: genera input strutturati validi e li passa a due parser, client o motori di transizione di stato.<sup>[[7]](#references)[[8]](#references)</sup>

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

Considera come risultati:

- un’implementazione va in panic mentre l’altra rifiuta correttamente l’input
- discrepanze tra input accettati e rifiutati
- alberi di parsing o oggetti decodificati diversi
- transizioni di stato, nonce, saldi o state root divergenti

È un metodo pratico per individuare **discrepanze di consenso**, **ambiguità del parser** e **divergenze tra specifica e implementazione** che spesso il puro fuzzing dei crash non rileva.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Riutilizzare il corpus della campagna per generare report di coverage

Al termine di una campagna, riproduci il corpus della coda salvato per generare un report di coverage di Go senza esportare manualmente un corpus separato.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Esegui il comando dallo **stesso package** e con lo **stesso target `-fuzz`**, così gosentry risolve lo stato della campagna memorizzato nella cache corretto.

## References

- [1] [Fuzzing grammaticale mutazionale](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing approfondito con AFL++](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinque anni dopo: fuzzing dei protocolli guidato dalla copertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark trasforma il codice in grafi](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [A Go mancava metà degli strumenti per il fuzzing. Abbiamo fatto un fork della toolchain per risolvere il problema.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox veloce per protocolli di rete stateful basato su snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Nessuna grammatica? Nessun problema: verso il fuzzing del kernel Linux senza descrizioni delle system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing efficiente con snapshot adattivi e mutabili](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Strumentazione LLVM di AFL++: copertura dei percorsi e dei chiamanti](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predittivo sensibile al contesto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog sulla sicurezza offensiva di Android - Fuzzing di Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL per Android Binder - documentazione di build e seed di regressione](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: esplorazione delle condizioni di race nel kernel Linux con interleaving controllati degli accessi alla memoria](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: copertura del codice per il fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintassi dei nomi file estesi di CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Avviso Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing della sintassi dei nomi file estesi di CFITSIO: 16 vulnerabilità di sicurezza della memoria e triage assistito da Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing differenziale per la crittografia](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: standard per i meccanismi di incapsulamento delle chiavi basati su reticoli modulari](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Bug nell'analisi dell'OID di XMSSMT - issue #1442 di RustCrypto](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stato delle implementazioni della crittografia post-quantistica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Come lo snapshotting ci ha portati a CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
