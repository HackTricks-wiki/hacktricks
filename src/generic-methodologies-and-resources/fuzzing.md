# Metodologia del fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: coverage vs. semantica

Nel **mutational grammar fuzzing**, gli input vengono modificati mantenendo la **validità grammaticale**. In modalità guidata dalla coverage, vengono salvati come seed del corpus solo i campioni che attivano **nuova coverage**. Per i **target linguistici** (parser, interpreti, engine), questo può non rilevare i bug che richiedono **catene semantiche/di dataflow**, in cui l'output di un costrutto diventa l'input di un altro.<sup>[[1]](#references)</sup>

**Modalità di fallimento:** il fuzzer trova seed che esercitano singolarmente `document()` e `generate-id()` (o primitive simili), ma **non preserva il dataflow concatenato**, quindi il campione «più vicino al bug» viene scartato perché non aggiunge coverage. Con **3 o più passaggi dipendenti**, la ricombinazione casuale diventa costosa e il feedback della coverage non guida la ricerca.<sup>[[1]](#references)</sup>

**Implicazione:** per le grammatiche con molte dipendenze, valuta di **combinare le fasi mutazionale e generativa** o di orientare la generazione verso pattern di **concatenazione di funzioni** (non solo verso la coverage).<sup>[[1]](#references)</sup>

## Insidie della diversità del corpus

La mutazione guidata dalla coverage è **greedy**: un campione che produce nuova coverage viene salvato immediatamente, spesso mantenendo ampie porzioni invariate. Col tempo, i corpus si riempiono di **quasi duplicati** con poca diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è la **minimizzazione consapevole della grammatica**, che **si interrompe al raggiungimento di una soglia minima di token** (riducendo il rumore e mantenendo abbastanza struttura circostante da favorire le mutazioni).<sup>[[1]](#references)</sup>

Una regola pratica per il corpus del mutational fuzzing è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzano la coverage** a una grande raccolta di quasi duplicati. In pratica, questo significa solitamente quanto segue.<sup>[[1]](#references)[[3]](#references)</sup>

- Parti da **campioni del mondo reale** (corpus pubblici, crawling, traffico acquisito, raccolte di file dell'ecosistema del target).
- Riducili con la **minimizzazione del corpus basata sulla coverage** invece di conservare ogni campione valido.
- Mantieni i seed **abbastanza piccoli** da far sì che le mutazioni agiscano su campi significativi, invece di sprecare la maggior parte dei cicli su byte irrilevanti.
- Ripeti la minimizzazione del corpus dopo modifiche importanti all'harness o alla strumentazione, perché il corpus «migliore» cambia quando cambia la raggiungibilità.

## Mutazione consapevole dei confronti per i valori magici

Un motivo comune per cui i fuzzer si bloccano non è la sintassi, ma i **confronti rigidi**: byte magici, controlli di lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, tabelle `switch` o confronti concatenati. La mutazione puramente casuale spreca cicli cercando di indovinare questi valori byte per byte.

Per questi target, usa il **tracing dei confronti** (ad esempio, i workflow in stile AFL++ `CMPLOG` / Redqueen), così il fuzzer può osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.<sup>[[3]](#references)</sup>

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

- È particolarmente utile quando il target nasconde la logica approfondita dietro **firme di file**, **verbi di protocollo**, **tag di tipo** o **bit di funzionalità dipendenti dalla versione**.
- Abbinalo a **dizionari** estratti da campioni reali, specifiche di protocollo o log di debug. Un piccolo dizionario con token della grammatica, nomi di chunk, verbi e delimitatori è spesso più utile di una wordlist generica enorme.
- Se il target esegue molti controlli sequenziali, risolvi prima i confronti “magic” iniziali e poi minimizza di nuovo il corpus risultante, così le fasi successive partono da prefissi già validi.

## Fuzzing delle API per file che nascondono un linguaggio per i nomi di file

Un parametro denominato `filename`, `path` o `URL` potrebbe essere un punto di ingresso per un interprete anziché una ricerca letterale di file. Per esempio, la sintassi CFITSIO Extended Filename Syntax (EFS) valuta selettori tra parentesi quadre, espressioni per righe/pixel, colonne calcolate, istogrammi e trasformazioni prima di restituire l’oggetto aperto; alcune forme creano anche copie temporanee. Durante la mappatura della superficie di attacco, classifica ogni API di apertura/importazione come **percorso letterale** o **percorso interpretato**, quindi esegui il fuzzing sul punto di ingresso di produzione effettivamente chiamato dalle applicazioni.<sup>[[20]](#references)[[22]](#references)</sup>

Per le primitive SSRF, di copia di file e di gestione dei protocolli che ne derivano, e per API più sicure con percorsi letterali, vedi [Mini-linguaggi per i nomi di file come primitive SSRF/per la gestione dei file](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Tieni separato l’oggetto sottostante dal programma sottoposto a fuzzing

Quando la grammatica è contenuta in un suffisso del nome di file, modificare solo i byte del file referenziato non raggiunge il parser. Un piccolo harness può invece leggere un testcase come stringa e passarlo all’API di apertura interpretata; la campagna CFITSIO ha raggiunto la maggior parte dei parser e valutatori EFS chiamando `fits_open_file()` in modalità di sola lettura. Tieni separati i file validi da usare come base, così le mutazioni possono concentrarsi sul linguaggio di selettori/espressioni senza danneggiare continuamente il percorso di base.<sup>[[22]](#references)</sup>

Usa seed che raggiungano ciascuno una famiglia grammaticale diversa, quindi ricava un dizionario compatto sia dalla specifica sia dal codice sorgente del lexer/parser. Se la copertura si stabilizza mentre gli input falliscono ripetutamente nello stesso percorso di errore sintattico, conserva i prefissi validi e aggiungi delimitatori, operatori, parole chiave, nomi di funzione e nomi di campo rappresentativi, invece di aumentare soltanto il tempo dedicato alle mutazioni casuali.<sup>[[22]](#references)</sup>

Esegui l’harness con il dizionario grammaticale, ad esempio:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contenere gli effetti collaterali dell'harness "read-only"

Un flag read-only della libreria non garantisce un testcase privo di effetti collaterali: il linguaggio dei nomi file può riscrivere l'input, creare file di output o materializzare oggetti temporanei. La campagna su CFITSIO inizialmente distruggeva i seed e lasciava file imprevisti in varie parti del filesystem, rendendo necessari pulizia e isolamento.<sup>[[22]](#references)</sup>

- Assegna a ogni worker una directory di lavoro sacrificabile e una directory temporanea privata.
- Esponi copie dei file di supporto canonici; non permettere mai al target di modificare l'unica copia del corpus.
- Disabilita l'accesso alla rete, a meno che i backend remoti non siano il target previsto, e limita i percorsi scrivibili usando un container, un mount namespace o una sandbox equivalente.
- Ripristina la directory dopo ogni esecuzione o batch di worker e considera le modifiche inattese al filesystem come risultati aggiuntivi.

### Ciclo crash-patch-fuzz

Raggruppa i crash prima della correzione, così migliaia di artefatti non si trasformano in migliaia di attività di patch. Nella valutazione di CFITSIO, AFLTriage ha ridotto l'insieme iniziale di crash a pochi casi di causa principale; l'advisory risultante mostra guasti distinti, tra cui controlli errati sulla dimensione della destinazione, puntatori obsoleti dopo `realloc()`, errori aritmetici e percorsi non sicuri di cleanup del parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Riduci al minimo un input rappresentativo per ogni gruppo e riproducilo con AddressSanitizer.
2. Registra l'accesso esatto che ha causato il guasto, la posizione nel sorgente, la cronologia di allocazione/liberazione e lo stato del parser che ha reso falsa l'invariante.
3. Applica una patch candidata circoscritta e ricompila con la stessa strumentazione per coverage e sanitizer.
4. Riproduci il caso originale **e ogni input del suo gruppo**; abilita anche il rilevamento dei leak, perché una correzione di memory safety può compromettere la gestione della proprietà in un percorso di errore.
5. Esegui test funzionali con file reali, poi riprendi dalla coda accumulata (oppure reimporta tale coda se il motore richiede una directory di output nuova dopo la modifica del binario).
6. Ripeti: rimuovere il primo crash superficiale spesso permette ai seed esistenti di avanzare verso uno stato più profondo del parser.

Un LLM può velocizzare il passaggio 2 e preparare una bozza per il passaggio 3 se riceve l'input che provoca il crash, il report del sanitizer, l'harness e il sorgente pertinente, ma la sua patch resta non attendibile. Sono la riproduzione con il sanitizer e i controlli di regressione, non la spiegazione del modello, a determinare se la correzione viene accettata.<sup>[[22]](#references)</sup>

## Feedback più ricco quando Edge Coverage appiattisce percorsi diversi

La normale Edge Coverage non distingue due esecuzioni che attraversano lo stesso helper passando da chiamanti diversi o seguendo combinazioni di rami diverse all'interno di una funzione. Questo è importante nei decoder condivisi, nei dispatcher di protocollo e negli helper degli interpreti, dove il **percorso** che conduce a un edge determina lo stato attivo. Tracciare ingenuamente ogni contesto di chiamata è rischioso: la mappa di coverage e la coda possono crescere a dismisura. La ricerca sul fuzzing sensibile al contesto raccomanda quindi di affinare solo i contesti promettenti, invece di rendere sensibile al contesto l'intero grafo delle chiamate.<sup>[[14]](#references)</sup>

Le versioni recenti di AFL++ offrono la **coverage dei percorsi per funzione Ball-Larus** oltre alla normale Edge Coverage. Assegnano una feature a ogni percorso aciclico attraverso una funzione; gli archi di ritorno dei loop vengono rimossi, quindi questo feedback distingue le combinazioni di rami, ma **non il numero di iterazioni dei loop**. Inizia con il livello permissivo `1`, poi limita le modalità più rigorose al codice sospetto del parser o della macchina a stati, perché il numero di percorsi può crescere esponenzialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Per un helper richiamato da molti punti rilevanti per la sicurezza, la modalità LTO può combinare il percorso di ciascuna funzione con il relativo punto di chiamata immediato:<sup>[[13]](#references)</sup>

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

**Indicazioni per la campagna:** applica con cautela feedback più ricchi e monitora il costo in termini di coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Esegui in parallelo un'istanza con edge coverage ordinaria; il feedback più ricco è utile solo se il costo aggiuntivo per queue/map non riduce eccessivamente le esecuzioni al secondo.
- Usa `AFL_LLVM_ALLOWLIST` per limitare la strumentazione path/caller quando librerie con molti template o codice utility generico dominano la map.
- Le funzioni con un numero eccessivo di path aciclici possono essere escluse da AFL++; gli avvisi durante la compilazione indicano che il target necessita di allowlisting o di un livello meno rigoroso.
- Caller + path coverage supporta un solo livello di caller. Non combinarlo con stack di contesto più profondi.
- Gli ID dei path possono cambiare tra versioni major di LLVM. Mantieni fissa la toolchain per tutta la campagna e non sincronizzare corpora basati su PATH come se i loro feature ID fossero stabili tra build diverse.
- Questo feedback integra `CMPLOG`: il tracing dei confronti risolve **quale valore supera una guardia**, mentre il feedback path/caller conserva **quale percorso e combinazione di branch l'hanno raggiunta**.

## Fuzzing con stato: le sequenze sono seed

Per **protocolli**, **workflow autenticati** e **parser multi-stage**, spesso l'unità interessante non è un singolo blob, ma una **sequenza di messaggi**. Concatenare l'intera trascrizione in un unico file e mutarla alla cieca è solitamente inefficiente, perché il fuzzer muta ogni passaggio allo stesso modo, anche quando solo il messaggio successivo raggiunge lo stato fragile.<sup>[[4]](#references)</sup>

Un approccio più efficace consiste nel trattare la **sequenza stessa come seed** e usare lo **stato osservabile** (codici di risposta, stati del protocollo, fasi del parser, tipi di oggetti restituiti) come feedback aggiuntivo.<sup>[[4]](#references)</sup>

- Mantieni stabili i **messaggi di prefisso validi** e concentra le mutazioni sul messaggio che **guida la transizione**.
- Memorizza gli identificatori e i valori generati dal server nelle risposte precedenti quando il passaggio successivo dipende da essi.
- Preferisci mutazioni/splicing per singolo messaggio invece di mutare l'intera trascrizione serializzata come un blob opaco.
- Se il protocollo espone codici di risposta significativi, usali come **oracolo di stato economico** per dare priorità alle sequenze che avanzano più in profondità.

È per lo stesso motivo che i bug autenticati, le transizioni nascoste o i bug dei parser che si verificano “solo dopo l'handshake” spesso sfuggono al fuzzing vanilla in stile file: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing del driver multi-client

Un'elevata edge coverage può comunque non rilevare bug nei driver IPC, perché la coverage non descrive **la proprietà degli oggetti, i conteggi dei riferimenti, i messaggi in sospeso, l'ordine di cleanup o le interleaving dei thread**. La pagina [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) descrive il modello degli oggetti del driver; questo esempio si concentra sull'harness del fuzzer. Android Binder è un modello utile: raggiungere sia i percorsi di allocazione sia quelli di deallocazione non basta se il fuzzer non riesce a far operare più processi sullo stesso oggetto del kernel nell'ordine richiesto.<sup>[[15]](#references)</sup>

#### Modella il protocollo, non buffer `ioctl` isolati

Rappresenta un caso di test come una grammatica ordinata di **identità del client + operazione + argomenti strutturati**. Il fuzzer Binder LKL usa protobuf e `libprotobuf-mutator`, con un client context manager persistente e due client ordinari. Un harness semantico preserva quindi le relazioni che la mutazione cieca dei byte distruggerebbe.<sup>[[15]](#references)</sup>

- Memorizza i valori restituiti dalle operazioni precedenti. Per esempio, `BC_FREE_BUFFER` deve riutilizzare un puntatore al transaction buffer restituito da una precedente `ioctl`.
- Genera risposte predefinite valide, così le transazioni sincrone possono terminare e le operazioni successive restano raggiungibili.
- Rifiuta transizioni impossibili, come le transazioni verso sé stessi o più transazioni in sospeso verso lo stesso target.
- Mantieni lo stato di bootstrap singleton al di fuori del reset per ogni input. Binder consente una sola registrazione `BINDER_SET_CONTEXT_MGR` per boot, quindi distruggere e ricreare ripetutamente quel client renderebbe non validi gli input successivi.

Un modello utile per le race sulle lifetime consiste nel far trasferire un oggetto a un client, avviare il cleanup di un thread o processo e, contemporaneamente, far rilasciare al client ricevente il transaction buffer. Nell'esempio CVE-2020-0423, il trasferimento di un `BINDER_TYPE_WEAK_BINDER`, seguito da `BINDER_THREAD_EXIT` in race con `BC_FREE_BUFFER`, poteva liberare un `binder_work` incorporato mentre il percorso di cleanup del thread in uscita lo stava ancora usando.<sup>[[15]](#references)</sup>

#### Reintroduci interleaving controllate in un kernel userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) collega il codice reale del kernel a un harness userspace ed espone la sua interfaccia syscall tramite `lkl_syscall`. In questo modo è facile coordinare protobuf state, coverage e KASAN in un unico processo. Normalmente, però, LKL esegue una syscall senza che un altro thread del kernel la interrompa. Per le campagne di race, inserisci punti `schedule()` attorno a determinati confini di lock/unlock e lifetime, quindi lascia che l'harness scelga casualmente il client successivo a ogni yield. Mantieni questi punti mirati, perché ognuno moltiplica lo spazio di ricerca dello scheduling. Lo scheduler randomizzato descritto dai ricercatori **non** fa parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila e ripeti i seed di regressione serializzati

L'harness upstream blocca una versione compatibile di `libprotobuf-mutator`, abilita la strumentazione per il fuzzing LKL e KASAN con `LKL_FUZZING=1`, e abilita `CONFIG_MMU` per Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Dopo aver controllato una revisione deliberatamente vulnerabile o applicato le patch di rollback documentate upstream, un seed serializzato può riprodurre l’intera transizione di stato multi-client senza doverla ricostruire in una proof of concept C ad hoc:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Considera il risultato use-after-free di KASAN come conferma che il seed ha raggiunto il percorso vulnerabile del ciclo di vita. Non dimostra le primitive successive necessarie per l’esecuzione di codice nel kernel o l’escalation dei privilegi.<sup>[[16]](#references)</sup>

## Tecnica della diversità su una singola macchina (stile Jackalope)

Un modo pratico per combinare **novità generativa** e **riutilizzo della coverage** consiste nel **riavviare worker di breve durata** contro un server persistente. Ogni worker parte da un corpus vuoto, si sincronizza dopo `T` secondi, continua per altri `T` secondi sul corpus combinato, si sincronizza di nuovo e poi termina. In questo modo si ottengono **strutture nuove a ogni generazione**, sfruttando al contempo la coverage accumulata.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` approssima una **sincronizzazione ritardata** (prima la novità, poi il riutilizzo).
- In modalità grammar fuzzing, **la sincronizzazione iniziale del server viene saltata per impostazione predefinita** (non serve `-skip_initial_server_sync`).
- Il valore ottimale di `T` **dipende dal target**; in genere conviene passare a un altro valore quando il worker ha trovato la maggior parte della coverage “facile”.

## Snapshot Fuzzing Per Target Difficili Da Sottoporre A Harness

Quando il codice che vuoi testare diventa raggiungibile solo **dopo un lungo lavoro di setup** (avvio di una VM, completamento di un login, ricezione di un pacchetto, parsing di un container, inizializzazione di un servizio), una valida alternativa è **snapshot fuzzing**: acquisire lo stato del processo o della VM pronto, iniettare ogni test case nel percorso di input del target, eseguire fino a un crash o un timeout e ripristinare lo snapshot. In questo modo si evita di ripetere l'inizializzazione o i prefissi del protocollo; è utile per **servizi di rete**, **firmware**, **superfici di attacco post-autenticazione** e **target solo binari**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Esegui il target finché non è pronto nello stato di interesse.
2. Acquisisci uno snapshot di **memoria + registri** in quel punto.
3. Per ogni test case, scrivi l'input mutato direttamente nel buffer pertinente del guest/processo.
4. Esegui fino a un crash, timeout o reset.
5. Ripristina lo snapshot; per i target VM, se supportato, ripristina solo le **pagine sporche**, quindi ripeti.

Posiziona lo snapshot il più vicino possibile al primo passaggio costoso di parsing o dispatch, ad esempio dopo una chiamata a `recv`/`read` o dopo la deserializzazione di un pacchetto, e registra il buffer di input utilizzato dal target. Questo segue il principio di posizionamento adattivo: spostare lo snapshot più in profondità nell'elaborazione dell'input per evitare di ripetere le operazioni.<sup>[[11]](#references)</sup>

## Esplorazione delle Race nel Kernel Linux con MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) trasforma le race sensibili ai timing nel kernel Linux in sequenze ripetibili di accessi alla memoria. Può enumerare automaticamente le esecuzioni **A-B-A** in due contesti oppure consentire a un analista di imporre vincoli di ordinamento tramite un'interfaccia terminale o grafica. È uno strumento di ricerca sperimentale, non un fuzzer di concorrenza completo: al momento richiede LLVM 23+ e il kernel modificato del progetto; gli strumenti a riga di comando supportano due thread di test e il livello di fuzzing in userspace proposto non è ancora implementato.<sup>[[17]](#references)[[18]](#references)</sup>

### Raccogli i punti di comunicazione tra contesti

Compila il kernel strumentato con le callback outline di KASAN e il supporto modificato di KCOV per la registrazione della memoria. Il README del progetto consiglia anche di disabilitare l'ottimizzazione sibling-call, così gli stack delle chiamate restano utilizzabili.<sup>[[17]](#references)[[18]](#references)</sup>

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

La modalità outline di KASAN (`asan-instrumentation-with-call-threshold=0`) converte gli accessi strumentati in chiamate a helper. Le patch MAccConc per il kernel disabilitano `asan-opt-same-temp` per evitare che gli accessi consecutivi vengano uniti; disabilitate anche l’ottimizzazione `asan-opt-globals` quando è necessario rilevare le race sulle variabili globali. KCOV trasmette i record risultanti allo spazio utente. Confrontate gli accessi provenienti da contesti di esecuzione diversi e conservate le coppie i cui intervalli di byte si sovrappongono e in cui almeno un accesso è una scrittura; modellate `kfree()` come una scrittura, in modo da includere tra i candidati anche le transizioni del ciclo di vita.<sup>[[17]](#references)</sup>

Per le attività che proseguono al di fuori del task che le ha avviate, come l’elaborazione dei pacchetti o i callback RCU, il sottosistema deve propagare un handle KCOV remote-coverage. KCOV remote upstream è opt-in e non è disponibile automaticamente per attività arbitrarie in background; pertanto, la mancata propagazione può rendere invisibile un’interazione reale.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificare lo stesso accesso dinamico a ogni esecuzione

Non ripetete l’esecuzione usando un indirizzo heap concreto, che può cambiare dopo ogni allocazione, né soltanto un indirizzo di istruzione, che è ambiguo all’interno di helper come `memcpy()` e `spin_lock()`. MAccConc usa una **traccia dello stack arricchita con contatori**: ogni frame identifica un callee e il conteggio delle sue invocazioni all’interno del caller; l’elemento finale identifica l’istruzione di accesso alla memoria. I record di ingresso/uscita delle funzioni di SanitizerCoverage permettono allo spazio utente di ricostruire questo identificatore dinamico, che rimane stabile anche quando cambiano gli indirizzi o si verificano variazioni di controllo del flusso non correlate.<sup>[[17]](#references)</sup>

### Convertire le coppie candidate in schedulazioni forzate

L’ioctl `KCOV_SET_DI` aggiunto dalla patch associa un identificatore di accesso arricchito con contatori a un’azione su un flag condiviso.<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Imposta il flag *N* immediatamente prima dell’accesso selezionato. |
| `DI_STACK_WAIT` | Prima dell’accesso selezionato, attende in un ciclo finché il flag *N* non viene impostato o scade il limite configurato. |
| `DI_STACK_WAKE_POST` | Imposta il flag *N* immediatamente dopo l’accesso selezionato. |

Per un vincolo parziale **A-happens-before-B**, associate `DI_STACK_WAKE_POST` ad A e `DI_STACK_WAIT` a B usando lo stesso flag. Per una schedulazione completamente specificata tra due contesti, avviate B in stato di blocco, quindi fate in modo che A risvegli B e attenda al primo punto di trasferimento; al trasferimento successivo, B esegue l’operazione inversa. Quest’ultimo approccio funziona come un cambio di contesto deterministico ed è quello usato dall’explorer automatico A-B-A.<sup>[[17]](#references)</sup>

Una campagna minima consiste nel compilare il test case a quattro hook (`test_setup`, due funzioni thread e `test_end`) come libreria condivisa, raccogliere una traccia senza vincoli e poi enumerare i candidati A-B-A o aggiungere vincoli manuali attorno agli accessi sospetti.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreta i timeout separatamente dai riordinamenti riusciti: l’ordine richiesto potrebbe essere impossibile perché un lock o una dipendenza di inizializzazione/pubblicazione impedisce al secondo contesto di raggiungere il punto di injection. Tieni inoltre presenti i punti ciechi di KASAN: gli accessi diretti allo stack di solito non sono intercettati, a meno che non possano uscire dai limiti; le variabili globali sono omesse con l’ottimizzazione predefinita; e i compilatori attuali non possono generare hook ASAN e TSAN contemporaneamente. Infine, il prototipo perde il proprio buffer KCOV quando un guest va in panic, quindi mantieni una console/oracle per i crash indipendente.<sup>[[17]](#references)</sup>

Per il fuzzing guidato dalla concorrenza in futuro, registra riepiloghi degli accessi alla memoria per input o syscall, abbina le operazioni che potrebbero formare punti di comunicazione tra contesti, quindi esplora solo quelle combinazioni. Gli snapshot delle VM stabilizzano lo stato globale e gli indirizzi; senza snapshot, i metadati dei siti di allocazione possono astrarre gli oggetti tra un’esecuzione e l’altra. Si tratta di un’estensione proposta, non di una funzionalità degli attuali strumenti userspace di MAccConc.<sup>[[17]](#references)</sup>

## Introspezione degli harness: individua subito i fuzzer superficiali

Quando una campagna si blocca, spesso il problema non è il mutator, ma l’**harness**. Usa l’**introspezione di raggiungibilità/copertura** per individuare le funzioni staticamente raggiungibili dal tuo fuzz target, ma raramente o mai coperte dinamicamente. Queste funzioni di solito indicano uno di tre problemi.<sup>[[12]](#references)</sup>

- L’harness raggiunge il target troppo tardi o troppo presto.
- Nel seed corpus manca un’intera famiglia di funzionalità.
- Il target ha davvero bisogno di un **secondo harness**, invece di un unico harness sovradimensionato che «fa tutto».

Se usi workflow in stile OSS-Fuzz / ClusterFuzz, Fuzz Introspector può confrontare la raggiungibilità statica con la copertura runtime e generare report a partire da un’esecuzione a tempo limitato o da un corpus pubblico.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, ampliare il corpus per una funzionalità specifica o suddividere un harness monolitico in entrypoint più piccoli.

## Selezione dei target di fuzzing basata prima sul grafo e triage delle mutazioni

Se hai già **risultati di analisi statica**, **mutanti sopravvissuti ai mutation test** e **report di coverage**, non esaminarli come elenchi indipendenti. Crea prima un **grafo delle chiamate**, annota i nodi con la **complessità ciclomatica**, la **raggiungibilità dagli entrypoint/input non attendibili** e gli eventuali risultati esterni, poi analizza il grafo con alcune domande.<sup>[[5]](#references)[[6]](#references)</sup>

- Quali funzioni ad alta complessità sono raggiungibili da input non attendibili?
- Quali mutanti sopravvissuti si trovano sui percorsi dai parser/handler al codice critico per la sicurezza?
- Quali funzioni sono colli di bottiglia architetturali con un **raggio d'impatto** insolitamente ampio?

In genere, questo permette di individuare target di fuzzing migliori rispetto alla sola "coverage più bassa". Un parser/decoder con **alta complessità** e **raggiungibilità esterna** confermata è un candidato per un harness migliore rispetto a un helper interno isolato con coverage scarsa ma senza percorsi controllati da un attaccante.

### Workflow pratico di triage

1. Crea un **grafo del codice** a partire dalla codebase ed estrai le metriche di complessità/branch per ogni funzione.
2. Elenca gli **entrypoint** che accettano input controllati da un attaccante: request handler, decoder, importer, parser di protocollo, lettori di CLI/file.
3. Esegui query sui percorsi dagli entrypoint alle funzioni candidate per distinguere la superficie d'attacco raggiungibile dal codice morto o accessibile solo internamente.
4. Dai priorità ai nodi che combinano:
   - alta **complessità ciclomatica**
   - **raggiungibilità confermata da input non attendibili**
   - ampio **raggio d'impatto** o numerose dipendenze a valle
   - evidenze di supporto, come risultati **SARIF**, note di audit o mutanti sopravvissuti
5. Scrivi prima harness mirati per i nodi con il punteggio migliore, in particolare per **parser/codecs** come i decoder hex/Base64/IP/messaggi.

### Mutanti sopravvissuti: equivalenti o sfruttabili

Il mutation testing produce spesso un elenco rumoroso di mutanti sopravvissuti. Prima di considerarli tutti lacune di sicurezza, usa il grafo per chiederti:

- La funzione mutata è raggiungibile da un entrypoint controllato da un attaccante?
- Tutti i percorsi di chiamata sono vincolati da invarianti più forti del controllo mutato?
- Il nodo si trova in codice morto, in logica che riguarda solo la formattazione o in un percorso aritmetico/parser ad alto impatto?

I mutanti sopravvissuti che restano irraggiungibili o sono vincolati strutturalmente sono spesso **mutanti equivalenti**. Quelli che restano **raggiungibili** e interessano **condizioni limite**, **percorsi di overflow/carry** o **aritmetica/parsing critici per la sicurezza** dovrebbero essere trasformati in:

- nuovi harness di fuzzing
- test diretti di proprietà/invarianti
- vettori mirati per casi limite

### Proietta i risultati esterni sul grafo

Se la tua pipeline SAST esporta **SARIF**, proietta i risultati sui nodi del grafo usando **file + intervallo di righe** e usa il grafo per estenderne l'analisi dell'impatto.<sup>[[6]](#references)</sup>

- calcola il **raggio d'impatto** della funzione segnalata
- verifica se il risultato si trova su un percorso che parte da un entrypoint
- raggruppa i risultati vicini che convergono sullo stesso collo di bottiglia

Questo è utile per decidere se dedicare tempo al fuzzing di una funzione specifica: un nodo **raggiungibile**, **complesso** e con risultati SAST già presenti è spesso un target migliore di un nodo semplicemente complesso, ma privo di un percorso controllabile da un attaccante.

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

La metodologia importante è l’intersezione tra **complessità x esposizione x impatto**. Usa il grafico per scegliere i target di fuzzing con il più alto valore di sicurezza atteso, quindi usa le mutazioni sopravvissute per decidere quali confini e invarianti il tuo harness deve mettere alla prova.<sup>[[5]](#references)</sup>

## Fuzzing differenziale delle codifiche di chiavi crittografiche

Parti da chiavi serializzate valide o da vettori di test standard. Modifica i campi codificati senza compromettere la lunghezza e la struttura necessarie per raggiungere i percorsi di importazione e operativi, quindi invia gli stessi byte a implementazioni indipendenti. Confronta l’accettazione e gli errori. Le firme e i ciphertext randomizzati richiedono oracoli di correttezza, non confronti byte per byte: verifica le firme o confronta i segreti condivisi ottenuti da un round trip di incapsulamento/decapsulamento. I vettori di test stabiliscono la conformità per i casi noti; le mutazioni differenziali sondano codifiche malformate che ne vanno oltre.<sup>[[23]](#references)[[26]](#references)</sup>

Per questi formati di chiavi, usa oracoli specifici per il formato:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Chiavi di firma ML-DSA espanse:** modifica i coefficienti `s1` o `s2` impacchettati portandoli fuori da `[-η, η]`, mantenendo la chiave analizzabile. Verifica se l’importazione o la firma li rifiutano e se eventuali firme risultanti sono verificate. Le sole differenze di accettazione non costituiscono violazioni degli standard, perché FIPS 204 non impone controlli aggiuntivi sulle chiavi private. Vedi il [meccanismo di leakage condizionale](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Coppie di chiavi ML-KEM:** distingui i controlli obbligatori sulla chiave di incapsulamento e sull’input di decapsulamento dal controllo facoltativo di coerenza della coppia (PCT) su una coppia importata. Esegui l’incapsulamento con la chiave pubblica e il decapsulamento con quella privata, quindi confronta i segreti condivisi; una mancata corrispondenza può interrompere le comunicazioni cifrate anche quando le singole chiavi superano i controlli sugli input. Verifica se l’API convalida gli input durante l’operazione o tramite una chiamata separata; libcrux espone `validate_public_key(pk)` e `validate_private_key(sk, ct)`, che non sostituiscono un PCT.
- **Chiavi raw XMSS/XMSSMT:** verifica i round trip di **firma e verifica** delle chiavi serializzate tra diversi set di parametri, non soltanto le operazioni con chiavi in memoria. XMSS e XMSSMT hanno namespace OID distinti a quattro byte, quindi un parser basato solo sull’OID che prova prima XMSS può classificare erroneamente una chiave XMSSMT con OID in conflitto e rifiutarne l’importazione. Il parser RustCrypto segnalato illustra un problema di interoperabilità/disponibilità, non una falsificazione di firma.

## Fuzzing Go con gosentry: engine più potente, input tipizzati e controlli differenziali

Se un target Go dispone già di un harness nativo `testing.F`, un percorso pratico di aggiornamento consiste nell’eseguire lo stesso harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain Go derivata che mantiene `go test -fuzz`, ma sostituisce il backend con **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Questo è utile quando il fuzzer nativo di Go si blocca su **confronti difficili**, **input tipizzati** o **formati con parser complessi**. La metodologia resta invariata:

- Continua a usare `f.Add(...)` per i seed e `f.Fuzz(...)` per la callback.
- Riutilizza lo stesso harness, ma eseguilo con il binario `go` di gosentry invece che con la toolchain standard.
- Considera la campagna risultante come una normale esecuzione guidata dalla coverage, ma con scheduling/mutazione di LibAFL e detector aggiuntivi più efficaci.

### Trasformare i fallimenti silenziosi in risultati del fuzzing

Un problema ricorrente nelle valutazioni Go è che spesso i comportamenti pericolosi **non** causano un crash per impostazione predefinita. Con gosentry, puoi trasformare diverse classi di stati «negativi ma silenziosi» in risultati.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` per far sì che i percorsi selezionati di logging/errore si comportino come crash (utile per i percorsi di codice in stile `log.Fatal` che altrimenti si limitano a scrivere un log e continuare).
- `--catch-races=true` per rieseguire le nuove entry individuate nella coda con il race detector di Go.
- `--catch-leaks=true` per rieseguire le nuove entry della coda con `goleak` e fermarsi in caso di leak di goroutine.
- Gestione degli hang integrata in LibAFL per mantenere **loop infiniti / input molto lenti** come risultati del fuzzing, invece di lasciarli sparire come timeout.
- Controlli integrati dell’overflow aritmetico abilitati per impostazione predefinita, oltre a controlli opzionali della troncatura tramite strumentazione in stile go-panikint.

Questo è particolarmente utile per i target in cui l’impatto sulla sicurezza deriva da un **errore del parser senza panic**, da un **bug di concorrenza** o da un **hang che causa solo DoS**, invece che da una corruzione della memoria.

### Fuzzing delle struct per le API Go tipizzate

Il fuzzing nativo di Go si aspetta principalmente scalari come `[]byte`, `string` e numeri. Se il codice sotto test usa oggetti tipizzati, gosentry può eseguire il fuzzing direttamente su **valori compositi** (struct, slice, array, puntatori), continuando a mutare i byte sottostanti.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usare un formato wire fittizio solo per il fuzzing nasconderebbe i bug logici dietro codice di parsing presente solo nell'harness. Per campagne differential o basate su grammar, mantenere l'input dell'harness come singolo `[]byte` o `string` e fare il parsing all'interno della callback.

### Fuzzing basato su grammar per parser e input di protocolli

Per parser, formati e linguaggi di input, gosentry può eseguire **Nautilus grammar fuzzing** basato su LibAFL. La grammar è un array JSON di production rule e, di solito, l'harness dovrebbe accettare un singolo argomento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Note metodologiche:

- Usa grammar mode quando le mutazioni a livello di byte vengono perlopiù bloccate dai controlli sintattici iniziali.
- Mantieni la grammar focalizzata sul **sottoinsieme del linguaggio/protocollo rilevante per la sicurezza**, invece di modellare l’intera specifica.
- Usa valori limite elevati nei terminali/nonterminali per mettere sotto stress i limiti di interi, lunghezze e macchine a stati.
- Grammar mode mantiene gli input validi secondo la grammar, ma il target continua a ricevere **byte/stringhe**: il parsing e i controlli semantici restano nel codice sottoposto a harness.

### Fuzzing differenziale: confronta le implementazioni, non solo i crash

Un approccio efficace negli ecosistemi Go è il **fuzzing differenziale basato su grammar**: generare input strutturati validi e passarli a due parser, client o motori di transizione degli stati.<sup>[[7]](#references)[[8]](#references)</sup>

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

- un’implementazione genera un panic mentre l’altra rifiuta l’input in modo pulito
- discrepanze negli input accettati/rifiutati
- alberi di parsing o oggetti decodificati diversi
- transizioni di stato, nonce, saldi o state root divergenti

È un modo pratico per individuare **discrepanze di consenso**, **ambiguità del parser** e **divergenze tra specifica e implementazione**, spesso sfuggite al puro fuzzing dei crash.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Riutilizzare il corpus della campagna per generare report sulla copertura

Al termine di una campagna, riproduci il corpus della coda salvato per generare un report di copertura Go, senza esportare manualmente un corpus separato.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Esegui il comando dallo stesso package e con lo stesso target -fuzz, così gosentry risolve lo stato della cache della campagna corretto.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Fuzzing con grammatiche mutazionali](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing approfondito con AFL++](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinque anni dopo: sul fuzzing dei protocolli guidato dalla coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark trasforma il codice in grafi](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing di Go mancava metà degli strumenti. Abbiamo creato un fork della toolchain per risolvere il problema.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox veloce per protocolli di rete stateful che usa snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Nessuna grammatica? Nessun problema: verso il fuzzing del kernel Linux senza descrizioni delle system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing efficiente con snapshot adattivi e modificabili](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Strumentazione LLVM di AFL++: coverage dei percorsi e dei caller](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predittivo sensibile al contesto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - Fuzzing di Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL per Android Binder - documentazione di build e seed di regressione](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: esplorare le race condition del kernel Linux con interleaving controllati degli accessi alla memoria](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: coverage del codice per il fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintassi estesa dei nomi di file di CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Advisory Doyensec: CFITSIO, quarto trimestre 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing della sintassi estesa dei nomi di file di CFITSIO: 16 vulnerabilità di sicurezza della memoria e triage assistito da Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing differenziale per la crittografia](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: standard per il meccanismo di incapsulamento delle chiavi basato su reticoli modulari](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Bug nell'analisi dell'OID XMSSMT - issue #1442 di RustCrypto](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stato delle implementazioni della crittografia post-quantistica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
