# Metodologia di Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing con grammatica mutazionale: coverage vs. semantica

Nel **fuzzing con grammatica mutazionale**, gli input vengono mutati mantenendo la **validità grammaticale**. In modalità guidata dalla coverage, vengono salvati come seed del corpus solo i campioni che attivano **nuova coverage**. Per i **target linguistici** (parser, interpreti, engine), questo può far perdere bug che richiedono **catene semantiche/di dataflow**, in cui l’output di un costrutto diventa l’input di un altro.<sup>[[1]](#references)</sup>

**Modalità di fallimento:** il fuzzer trova seed che esercitano singolarmente `document()` e `generate-id()` (o primitive simili), ma **non preserva il dataflow concatenato**, perciò il campione “più vicino al bug” viene scartato perché non aggiunge coverage. Con **3 o più passaggi dipendenti**, la ricombinazione casuale diventa costosa e il feedback della coverage non guida la ricerca.<sup>[[1]](#references)</sup>

**Implicazione:** per grammatiche con molte dipendenze, valuta di **combinare fasi mutazionali e generative** oppure di orientare la generazione verso pattern di **concatenazione di funzioni** (non solo verso la coverage).<sup>[[1]](#references)</sup>

## Problemi di diversità del corpus

La mutazione guidata dalla coverage è **greedy**: un campione che introduce nuova coverage viene salvato subito, spesso mantenendo ampie regioni invariate. Col tempo, i corpus diventano **quasi duplicati** con poca diversità strutturale. Una minimizzazione aggressiva può rimuovere contesto utile, quindi un compromesso pratico è la **minimizzazione consapevole della grammatica**, che **si interrompe al raggiungimento di una soglia minima di token** (riduce il rumore mantenendo abbastanza struttura circostante da favorire le mutazioni).<sup>[[1]](#references)</sup>

Una regola pratica per il corpus nel fuzzing mutazionale è: **preferire un piccolo insieme di seed strutturalmente diversi che massimizzino la coverage** a una grande raccolta di quasi duplicati. In pratica, questo di solito significa quanto segue.<sup>[[1]](#references)[[3]](#references)</sup>

- Parti da **campioni del mondo reale** (corpus pubblici, dati raccolti tramite crawling, traffico acquisito, insiemi di file dell’ecosistema target).
- Riducili con la **minimizzazione del corpus basata sulla coverage**, invece di conservare ogni campione valido.
- Mantieni i seed **abbastanza piccoli**, così che le mutazioni agiscano su campi significativi invece di sprecare la maggior parte dei cicli su byte irrilevanti.
- Ripeti la minimizzazione del corpus dopo modifiche importanti a harness o strumentazione, perché il corpus “migliore” cambia quando cambia la raggiungibilità.

## Mutazione consapevole dei confronti per i valori magici

Un motivo comune per cui i fuzzer si bloccano non è la sintassi, ma i **confronti rigidi**: byte magici, controlli di lunghezza, stringhe enum, checksum o valori di dispatch del parser protetti da `memcmp`, tabelle switch o confronti concatenati. La mutazione puramente casuale spreca cicli nel tentativo di indovinare questi valori byte per byte.

Per questi target, usa il **tracciamento dei confronti** (ad esempio, i flussi di lavoro basati su AFL++ `CMPLOG` / Redqueen) affinché il fuzzer possa osservare gli operandi dei confronti falliti e orientare le mutazioni verso valori che li soddisfano.<sup>[[3]](#references)</sup>

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

- È particolarmente utile quando il target protegge la logica più profonda dietro **firme dei file**, **verbi di protocollo**, **tag di tipo** o **bit di funzionalità dipendenti dalla versione**.
- Affiancalo a **dizionari** estratti da campioni reali, specifiche di protocollo o log di debug. Un piccolo dizionario con token grammaticali, nomi di chunk, verbi e delimitatori è spesso più utile di una wordlist generica enorme.
- Se il target esegue molti controlli sequenziali, risolvi prima i confronti “magic” iniziali e poi minimizza di nuovo il corpus risultante, così le fasi successive partono da prefissi già validi.

## Feedback più ricco quando la copertura degli edge non distingue percorsi diversi

La normale copertura degli edge non riesce a distinguere due esecuzioni che attraversano lo stesso helper tramite chiamanti diversi o prendono combinazioni di branch diverse all'interno di una funzione. Questo è importante nei decoder condivisi, nei dispatcher di protocollo e negli helper degli interpreti, dove il **percorso** verso un edge determina lo stato attivo. Tracciare ingenuamente ogni contesto di chiamata è altrettanto rischioso: la mappa di copertura e la coda possono esplodere. La ricerca sul fuzzing sensibile al contesto raccomanda quindi di affinare solo i contesti promettenti, invece di rendere sensibile al contesto l'intero grafo delle chiamate.<sup>[[14]](#references)</sup>

Le versioni recenti di AFL++ forniscono la **copertura dei percorsi per funzione Ball-Larus** oltre alla normale copertura degli edge. Assegna una feature a ogni percorso aciclico attraverso una funzione; gli archi di ritorno dei loop vengono rimossi, quindi questo feedback distingue le combinazioni di branch ma **non il numero di iterazioni dei loop**. Inizia con il livello permissivo `1`, poi limita le modalità più rigide al codice sospetto di parser/macchine a stati, perché il numero di percorsi può crescere in modo esponenziale.<sup>[[13]](#references)</sup>

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

**Indicazioni per la campagna:** applica feedback più ricchi con cautela e monitora il costo sulla coverage map e sulla queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Esegui in parallelo un’istanza ordinaria con edge coverage; il feedback più ricco è utile solo se il costo aggiuntivo in termini di queue/map non riduce troppo le esecuzioni al secondo.
- Usa `AFL_LLVM_ALLOWLIST` per limitare la strumentazione di path/caller quando le librerie con molti template o il codice utility generico dominano la map.
- AFL++ può ignorare le funzioni con un numero eccessivo di path aciclici; gli avvisi durante la compilazione indicano che il target necessita di un allowlist o di un livello meno restrittivo.
- La coverage caller + path supporta un solo livello di caller. Non combinarla con context stack più profondi.
- Gli ID dei path possono cambiare tra versioni major di LLVM. Mantieni fisso il toolchain per tutta la campagna e non sincronizzare corpus basati sui PATH come se i loro feature ID fossero stabili tra build.
- Questo feedback integra `CMPLOG`: il comparison tracing risolve **quale valore supera una guardia**, mentre il feedback path/caller conserva **quale percorso e combinazione di branch lo hanno raggiunto**.

## Fuzzing stateful: le sequenze sono seed

Per **protocolli**, **workflow autenticati** e **parser multi-stage**, spesso l’unità interessante non è un singolo blob, ma una **sequenza di messaggi**. Concatenare l’intera trascrizione in un unico file e mutarla alla cieca è di solito inefficiente, perché il fuzzer muta ogni passaggio allo stesso modo, anche quando solo il messaggio successivo raggiunge lo stato fragile.<sup>[[4]](#references)</sup>

Un approccio più efficace consiste nel trattare la **sequenza stessa come seed** e usare lo **stato osservabile** (codici di risposta, stati del protocollo, fasi del parser, tipi di oggetti restituiti) come feedback aggiuntivo.<sup>[[4]](#references)</sup>

- Mantieni stabili i **messaggi validi del prefisso** e concentra le mutazioni sul messaggio che **guida la transizione**.
- Memorizza gli identificatori e i valori generati dal server nelle risposte precedenti quando il passaggio successivo dipende da essi.
- Preferisci mutazioni/splicing per singolo messaggio invece di mutare l’intera trascrizione serializzata come un blob opaco.
- Se il protocollo espone codici di risposta significativi, usali come **oracolo di stato** a basso costo per dare priorità alle sequenze che avanzano più in profondità.

È per questo stesso motivo che i bug autenticati, le transizioni nascoste o i bug del parser che si verificano “solo dopo l’handshake” spesso sfuggono al fuzzing vanilla basato su file: il fuzzer deve preservare **ordine, stato e dipendenze**, non solo la struttura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing del driver multi-client

Un’elevata edge coverage può comunque non rilevare i bug del driver IPC, perché la coverage non descrive **la proprietà degli oggetti, i reference count, i messaggi in sospeso, l’ordine di cleanup o gli interleaving dei thread**. La pagina [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) descrive il modello a oggetti del driver; questo esempio si concentra sull’harness del fuzzer. Android Binder è un modello utile: raggiungere sia i percorsi di allocazione sia quelli di free non basta se il fuzzer non riesce a far operare più processi sullo stesso oggetto kernel nell’ordine richiesto.<sup>[[15]](#references)</sup>

#### Modella il protocollo, non buffer `ioctl` isolati

Rappresenta un test case come una grammatica ordinata di **identità client + operazione + argomenti strutturati**. Il fuzzer Binder LKL usa protobuf e `libprotobuf-mutator`, con un client context-manager persistente e due client ordinari. Un harness semantico preserva quindi le relazioni che la mutazione cieca dei byte distruggerebbe.<sup>[[15]](#references)</sup>

- Memorizza i valori restituiti dalle operazioni precedenti. Ad esempio, `BC_FREE_BUFFER` deve riutilizzare un puntatore al transaction buffer restituito da una precedente `ioctl`.
- Genera risposte predefinite valide affinché le transazioni sincrone possano completarsi e le operazioni successive restino raggiungibili.
- Rifiuta transizioni impossibili, come le transazioni verso sé stessi o più transazioni in sospeso verso lo stesso destinatario.
- Mantieni lo stato singleton di bootstrap fuori dal reset per ogni input. Binder consente una sola registrazione `BINDER_SET_CONTEXT_MGR` per boot, quindi distruggere e ricreare ripetutamente quel client renderebbe non validi gli input successivi.

Un modello utile per una race sulle lifetime consiste nel far trasferire un oggetto a un client, avviare il cleanup di un thread o di un processo e, in parallelo, far rilasciare al client ricevente il transaction buffer. Nell’esempio CVE-2020-0423, il trasferimento di un `BINDER_TYPE_WEAK_BINDER`, seguito da una race tra `BINDER_THREAD_EXIT` e `BC_FREE_BUFFER`, poteva liberare un `binder_work` incorporato mentre il percorso di cleanup del thread in uscita lo stava ancora usando.<sup>[[15]](#references)</sup>

#### Reintroduci interleaving controllati in un kernel userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) collega il codice kernel reale a un harness userspace ed espone la sua interfaccia syscall tramite `lkl_syscall`. Questo semplifica il coordinamento di stato protobuf, coverage e KASAN in un unico processo. LKL normalmente esegue una syscall senza che un altro thread kernel la interrompa. Per le campagne di race, inserisci punti `schedule()` attorno a determinati confini di lock/unlock e lifetime, poi lascia che l’harness scelga casualmente il client successivo a ogni yield. Mantieni questi punti mirati, perché ognuno moltiplica lo spazio di ricerca dello scheduling. Lo scheduler randomizzato descritto dai ricercatori **non** fa parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila e riproduci i seed di regressione serializzati

L’harness upstream fissa una versione compatibile di `libprotobuf-mutator`, abilita la strumentazione per il fuzzing LKL e KASAN con `LKL_FUZZING=1`, e abilita `CONFIG_MMU` per Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Dopo aver verificato una revisione intenzionalmente vulnerabile o applicato le patch di rollback documentate upstream, un seed serializzato può riprodurre l’intera transizione di stato multi-client senza doverla ricostruire in una proof of concept C ad hoc:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Tratta il use-after-free di KASAN risultante come conferma che il seed abbia raggiunto il percorso vulnerabile legato al ciclo di vita. **Non** dimostra le primitive successive necessarie per eseguire codice nel kernel o ottenere un'escalation dei privilegi.<sup>[[16]](#references)</sup>

## Trucco della diversità su singola macchina (stile Jackalope)

Un modo pratico per combinare **novità generativa** e **riutilizzo della coverage** consiste nel **riavviare worker di breve durata** contro un server persistente. Ogni worker parte da un corpus vuoto, si sincronizza dopo `T` secondi, lavora per altri `T` secondi sul corpus combinato, si sincronizza di nuovo e poi termina. In questo modo si ottengono **strutture nuove a ogni generazione**, continuando al contempo a sfruttare la coverage accumulata.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` approssima una **sincronizzazione ritardata** (prima la novità, poi il riutilizzo).
- In modalità grammar fuzzing, la **sincronizzazione iniziale con il server viene saltata per impostazione predefinita** (non è necessario usare `-skip_initial_server_sync`).
- Il valore ottimale di `T` dipende dal **target**; in genere conviene cambiarlo quando il worker ha già trovato la maggior parte delle coverage “facili”.

## Snapshot Fuzzing Per Target Difficili Da Sottoporre A Test

Quando il codice che vuoi testare diventa raggiungibile solo **dopo una lunga fase di setup** (avvio di una VM, completamento di un login, ricezione di un pacchetto, parsing di un container, inizializzazione di un servizio), una valida alternativa è lo **snapshot fuzzing**: acquisisci lo stato del processo o della VM pronto, inietta ogni test case nel percorso di input del target, esegui fino a un crash o a un timeout e ripristina lo snapshot. In questo modo eviti di ripetere l'inizializzazione o i prefissi del protocollo; è utile per **servizi di rete**, **firmware**, **superfici d'attacco post-autenticazione** e **target disponibili solo in formato binario**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Esegui il target finché lo stato di interesse non è pronto.
2. Acquisisci uno snapshot di **memoria + registri** in quel momento.
3. Per ogni test case, scrivi l'input mutato direttamente nel buffer pertinente del processo/guest.
4. Esegui fino a un crash, un timeout o un reset.
5. Ripristina lo snapshot; per i target VM, ripristina solo le **pagine modificate** se supportato, quindi ripeti.

Posiziona lo snapshot il più vicino possibile al primo passaggio costoso di parsing/dispatch, ad esempio dopo una `recv`/`read` o la deserializzazione di un pacchetto, e annota il buffer di input usato dal target. Questo segue il principio di posizionamento adattivo: spostare lo snapshot più avanti nell'elaborazione dell'input per evitare di ripetere il lavoro.<sup>[[11]](#references)</sup>

## Esplorazione delle Race nel Kernel Linux con MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) trasforma le race nel kernel Linux sensibili ai timing in schedule ripetibili di accessi alla memoria. Può enumerare automaticamente esecuzioni **A-B-A** a due contesti oppure consentire a un analista di imporre vincoli d'ordine tramite un'interfaccia terminale o GUI. È uno strumento sperimentale di ricerca, non un fuzzer completo per la concorrenza: attualmente richiede LLVM 23+ e il kernel patched del progetto; gli strumenti a riga di comando supportano due thread di test e il livello di fuzzing userspace proposto non è implementato.<sup>[[17]](#references)[[18]](#references)</sup>

### Raccogliere i punti di comunicazione tra contesti

Compila il kernel strumentato con le callback KASAN outline e il supporto patched di KCOV per la registrazione della memoria. Il README del progetto raccomanda anche di disabilitare l'ottimizzazione delle chiamate tra funzioni, in modo che gli stack di chiamata restino utilizzabili.<sup>[[17]](#references)[[18]](#references)</sup>

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

La modalità outline di KASAN (`asan-instrumentation-with-call-threshold=0`) converte gli accessi strumentati in chiamate helper. Le patch MAccConc al kernel disabilitano `asan-opt-same-temp` affinché gli accessi consecutivi non vengano uniti; disabilitano anche l’ottimizzazione `asan-opt-globals` quando è necessario rendere visibili le race sulle variabili globali. KCOV trasmette i record risultanti allo userspace. Confronta gli accessi provenienti da contesti di esecuzione diversi e conserva le coppie i cui intervalli di byte si sovrappongono e in cui almeno uno dei due accessi è in scrittura; considera `kfree()` come una scrittura, in modo da includere anche le transizioni del ciclo di vita tra i candidati.<sup>[[17]](#references)</sup>

Per le attività che proseguono al di fuori del task iniziale, come l’elaborazione dei pacchetti o le callback RCU, il sottosistema deve propagare un handle di remote coverage KCOV. Il remote KCOV upstream è opt-in e non è disponibile automaticamente per attività arbitrarie in background; pertanto, la mancata propagazione può rendere invisibile un’interazione reale.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificare lo stesso accesso dinamico a ogni esecuzione

Non riprodurre usando un indirizzo concreto dell’heap, che può cambiare dopo ogni allocazione, né usando solo un indirizzo di istruzione, che è ambiguo all’interno di helper come `memcpy()` e `spin_lock()`. MAccConc usa una **traccia dello stack arricchita con contatori**: ogni frame identifica un callee e il relativo conteggio di invocazioni nel caller, mentre l’elemento finale identifica l’istruzione di accesso alla memoria. I record di entrata/uscita delle funzioni SanitizerCoverage permettono allo userspace di ricostruire questo identificatore dinamico, che rimane stabile nonostante le variazioni degli indirizzi e il rumore di controllo di flusso non correlato.<sup>[[17]](#references)</sup>

### Convertire le coppie candidate in schedule forzate

L’ioctl `KCOV_SET_DI` introdotto dalla patch associa un identificatore di accesso arricchito con contatori a un’azione su un flag condiviso.<sup>[[17]](#references)</sup>

| Azione | Semantica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Imposta il flag *N* immediatamente prima dell’accesso selezionato. |
| `DI_STACK_WAIT` | Prima dell’accesso selezionato, attende in un ciclo finché il flag *N* non viene impostato o scade il limite configurato. |
| `DI_STACK_WAKE_POST` | Imposta il flag *N* immediatamente dopo l’accesso selezionato. |

Per imporre un vincolo parziale **A-happens-before-B**, associa `DI_STACK_WAKE_POST` ad A e `DI_STACK_WAIT` a B usando lo stesso flag. Per uno schedule completamente specificato con due contesti, avvia B in stato bloccato, quindi fai in modo che A svegli B e attenda al primo punto di trasferimento; al trasferimento successivo, B esegue l’operazione inversa. Quest’ultimo metodo funziona come un context switch deterministico ed è quello usato dall’esploratore automatico A-B-A.<sup>[[17]](#references)</sup>

Una campagna minima consiste nel compilare il caso di test con quattro hook (`test_setup`, due funzioni thread e `test_end`) come libreria condivisa, raccogliere una trace senza vincoli e poi enumerare i candidati A-B-A o aggiungere vincoli manuali intorno agli accessi sospetti.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreta i timeout separatamente dai riordinamenti riusciti: l’ordine richiesto potrebbe essere impossibile perché un lock o una dipendenza di inizializzazione/pubblicazione impedisce al secondo contesto di raggiungere il proprio punto di injection. Tieni inoltre presenti i punti ciechi di KASAN: gli accessi diretti allo stack di solito non vengono intercettati, a meno che non possano causare un out-of-bounds; le variabili globali vengono omesse con l’ottimizzazione predefinita; e i compilatori attuali non possono generare simultaneamente gli hook ASAN e TSAN. Infine, il prototipo perde il buffer KCOV quando un guest va in panic, quindi mantieni una console/oracle per i crash indipendente.<sup>[[17]](#references)</sup>

Per il fuzzing futuro guidato dalla concorrenza, registra riepiloghi degli accessi alla memoria per input o syscall, accoppia le operazioni che potrebbero creare punti di comunicazione tra contesti, quindi esplora solo quelle combinazioni. Gli snapshot delle VM stabilizzano lo stato globale e gli indirizzi; senza snapshot, i metadati dei siti di allocazione possono astrarre gli oggetti tra un’esecuzione e l’altra. Questa è un’estensione proposta, non una funzionalità degli attuali strumenti userspace di MAccConc.<sup>[[17]](#references)</sup>

## Introspezione degli harness: individua subito i fuzzer superficiali

Quando una campagna si blocca, spesso il problema non è il mutator, ma l’**harness**. Usa l’**introspezione di raggiungibilità/copertura** per individuare le funzioni che sono staticamente raggiungibili dal target di fuzzing, ma raramente o mai coperte dinamicamente. Queste funzioni indicano di solito uno di tre problemi.<sup>[[12]](#references)</sup>

- L’harness entra nel target troppo presto o troppo tardi.
- Nel seed corpus manca un’intera famiglia di funzionalità.
- Il target ha davvero bisogno di un **secondo harness** invece di un unico harness sovradimensionato che “fa tutto”.

Se usi workflow nello stile di OSS-Fuzz / ClusterFuzz, Fuzz Introspector può confrontare la raggiungibilità statica con la copertura runtime e generare report a partire da un’esecuzione a tempo limitato o da un corpus pubblico.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa il report per decidere se aggiungere un nuovo harness per un percorso del parser non testato, ampliare il corpus per una funzionalità specifica o suddividere un harness monolitico in entry point più piccoli.

## Selezione dei target di fuzzing e triage delle mutazioni a partire dal grafo

Se hai già **risultati di analisi statica**, **mutanti sopravvissuti ai test di mutazione** e **report di coverage**, non eseguire il triage come se fossero elenchi indipendenti. Crea prima un **call graph**, annota i nodi con la **complessità ciclomatica**, la **raggiungibilità dagli entry point/input non attendibili** e gli eventuali risultati esterni, poi poni domande sul grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- Quali funzioni ad alta complessità sono raggiungibili da input non attendibili?
- Quali mutanti sopravvissuti si trovano su percorsi dai parser/handler al codice critico per la sicurezza?
- Quali funzioni sono colli di bottiglia architetturali con un **raggio d'impatto** insolitamente ampio?

Questo di solito permette di individuare target di fuzzing migliori rispetto alla sola "coverage più bassa". Un parser/decoder con **alta complessità** e **raggiungibilità esterna** confermata è un candidato per un harness migliore rispetto a un helper interno isolato, con coverage bassa ma senza un percorso controllabile da un attaccante.

### Workflow pratico di triage

1. Crea un **grafo del codice** a partire dal codebase ed estrai metriche di complessità e di branch per ogni funzione.
2. Elenca gli **entry point** che accettano input controllati da un attaccante: handler delle richieste, decoder, importer, parser di protocollo, reader da CLI/file.
3. Esegui query sui percorsi dagli entry point alle funzioni candidate per separare la superficie d'attacco raggiungibile dal codice morto o accessibile solo internamente.
4. Assegna priorità ai nodi che combinano:
   - alta **complessità ciclomatica**
   - **raggiungibilità da input non attendibili** confermata
   - elevato **raggio d'impatto** o molti componenti dipendenti a valle
   - evidenze a supporto, come risultati **SARIF**, note di audit o mutanti sopravvissuti
5. Scrivi per primi harness mirati per i nodi con il punteggio migliore, soprattutto **parser/codec** come decoder hex/Base64/IP/messaggi.

### Mutanti sopravvissuti: equivalenti o sfruttabili

Il mutation testing spesso produce un elenco rumoroso di mutanti sopravvissuti. Prima di considerare ogni mutante sopravvissuto una lacuna di sicurezza, usa il grafo per chiederti:

- La funzione modificata è raggiungibile da un entry point controllato da un attaccante?
- Tutti i percorsi di chiamata sono vincolati da invarianti più forti rispetto al controllo modificato?
- Il nodo si trova in codice morto, in logica che riguarda solo la formattazione o in un percorso aritmetico/parser ad alto impatto?

I mutanti sopravvissuti che restano irraggiungibili o strutturalmente vincolati sono spesso **mutanti equivalenti**. I mutanti sopravvissuti che restano **raggiungibili** e coinvolgono **casi limite**, **percorsi di overflow/riporto** o **aritmetica/parsing critici per la sicurezza** dovrebbero essere promossi a:

- nuovi fuzz harness
- test diretti di proprietà/invarianti
- vettori mirati per i casi limite

### Correlare i risultati esterni al grafo

Se la pipeline SAST esporta **SARIF**, associa i risultati ai nodi del grafo tramite **file + intervallo di righe** e usa il grafo per estendere l'analisi dell'impatto.<sup>[[6]](#references)</sup>

- calcola il **raggio d'impatto** della funzione segnalata
- controlla se il risultato si trova su un percorso da un entry point
- raggruppa i risultati vicini che confluiscono nello stesso collo di bottiglia

È utile per decidere se dedicare tempo al fuzzing di una funzione specifica: un nodo **raggiungibile**, **complesso** e già con risultati **SAST** è spesso un target migliore di un nodo semplicemente complesso, ma senza percorsi accessibili a un attaccante.

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

L'aspetto metodologico cruciale è l'intersezione: **complessità x esposizione x impatto**. Usa il grafico per scegliere i target di fuzzing con il più alto valore di sicurezza atteso, quindi usa le mutazioni sopravvissute per decidere quali confini e invarianti il tuo harness deve mettere alla prova.<sup>[[5]](#references)</sup>

## Go Fuzzing con gosentry: motore più potente, input tipizzati e controlli differenziali

Se un target Go ha già un harness nativo `testing.F`, un percorso pratico di aggiornamento consiste nell'eseguire lo stesso harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain Go forkata che mantiene `go test -fuzz`, ma sostituisce il backend con **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Questo è utile quando il fuzzer Go nativo si blocca su **confronti difficili**, **input tipizzati** o **formati con parser complessi**. La metodologia resta la stessa:

- Continua a usare `f.Add(...)` per i seed e `f.Fuzz(...)` per la callback.
- Riutilizza lo stesso harness, ma eseguilo con il binario `go` di gosentry invece che con la toolchain standard.
- Considera la campagna risultante come una normale esecuzione guidata dalla coverage, ma con lo scheduling e le mutazioni di LibAFL e detector aggiuntivi più efficaci.

### Trasformare gli errori silenziosi in findings di fuzzing

Un problema ricorrente nelle valutazioni Go è che spesso i comportamenti pericolosi **non** causano un crash per impostazione predefinita. Con gosentry, puoi trasformare diverse categorie di stati «problematici ma silenziosi» in findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` per fare in modo che i percorsi di logging/errori selezionati si comportino come crash (utile per percorsi di codice in stile `log.Fatal` che altrimenti registrano solo l'errore e continuano).
- `--catch-races=true` per rieseguire le voci della coda appena scoperte con il race detector di Go.
- `--catch-leaks=true` per rieseguire le nuove voci della coda con `goleak` e fermarsi in caso di leak di goroutine.
- La gestione degli hang di LibAFL per mantenere **loop infiniti / input molto lenti** tra i findings di fuzzing, invece di lasciarli sparire come timeout.
- Controlli integrati dell'overflow aritmetico per impostazione predefinita, oltre a controlli opzionali di troncamento tramite strumentazione in stile go-panikint.

Questo è particolarmente utile per i target in cui l'impatto sulla sicurezza consiste in un **errore del parser senza panic**, un **bug di concorrenza** o un **hang che causa solo DoS**, anziché nella corruzione della memoria.

### Fuzzing consapevole delle struct per le API Go tipizzate

Il fuzzing Go nativo si aspetta principalmente scalari come `[]byte`, `string` e numeri. Se il codice in esame riceve oggetti tipizzati, gosentry può sottoporre direttamente a fuzzing **valori compositi** (struct, slice, array, puntatori), continuando a mutare i byte sottostanti.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usare un formato wire fittizio solo per il fuzzing nasconderebbe i bug logici dietro codice di parsing presente solo nell’harness. Per campagne differenziali o basate su grammar, mantenere l’input dell’harness come un singolo `[]byte` o `string` e fare il parsing all’interno della callback.

### Fuzzing basato su grammar per parser e input di protocollo

Per parser, formati e linguaggi di input, gosentry può eseguire il **fuzzing grammaticale Nautilus** con LibAFL. La grammar è un array JSON di regole di produzione e, in genere, l’harness dovrebbe accettare un singolo argomento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Note sulla metodologia:

- Usa la modalità grammar quando le mutazioni a livello di byte vengono perlopiù bloccate dai controlli sintattici iniziali.
- Mantieni la grammar focalizzata sul **sottoinsieme del linguaggio/protocollo rilevante per la sicurezza**, invece di modellare l’intera specifica.
- Usa valori limite elevati nei terminali/non terminali per mettere sotto stress i limiti di interi e lunghezze, nonché i confini delle macchine a stati.
- La modalità grammar mantiene gli input validi rispetto alla grammar, ma il target riceve comunque **byte/stringhe**: il parsing e i controlli semantici restano all’interno del codice sottoposto a harness.

### Fuzzing differenziale: confrontare le implementazioni, non solo i crash

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

- un’implementazione va in panic mentre l’altra rifiuta correttamente
- input accettati/rifiutati in modo diverso
- alberi di parsing o oggetti decodificati diversi
- transizioni di stato, nonce, saldi o state root divergenti

È un metodo pratico per individuare **mismatch di consenso**, **ambiguità del parser** e **disallineamenti tra specifica e implementazione**, spesso non rilevati dal puro fuzzing dei crash.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Riutilizzare il corpus della campagna per generare report di coverage

Al termine di una campagna, riproduci il corpus della coda salvato per generare un report di coverage Go senza esportare manualmente un corpus separato.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Esegui il comando dallo **stesso package** e con lo **stesso target `-fuzz`**, così gosentry risolve lo stato della campagna memorizzato nella cache corretto.



## References

- [1] [Fuzzing con grammatiche mutazionali](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing con AFL++ nel dettaglio](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinque anni dopo: fuzzing dei protocolli guidato dalla coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark trasforma il codice in grafi](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing di Go mancava metà degli strumenti. Abbiamo fatto un fork della toolchain per risolvere il problema.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox veloce per protocolli di rete stateful che usa snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Niente grammatica, nessun problema: verso il fuzzing del kernel Linux senza descrizioni delle system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing efficiente con snapshot adattivi e mutabili](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Strumentazione LLVM di AFL++: coverage dei percorsi e dei chiamanti](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predittivo sensibile al contesto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog di Android Offensive Security - Fuzzing di Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL per Android Binder - documentazione su build e seed di regressione](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: esplorare le race condition del kernel Linux con interleaving controllati degli accessi alla memoria](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: code coverage per il fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
