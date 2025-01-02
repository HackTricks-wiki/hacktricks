# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Inizialmente, la funzione **`task_threads()`** viene invocata sulla porta del task per ottenere un elenco di thread dal task remoto. Un thread viene selezionato per l'hijacking. Questo approccio si discosta dai metodi convenzionali di iniezione di codice poiché la creazione di un nuovo thread remoto è vietata a causa della nuova mitigazione che blocca `thread_create_running()`.

Per controllare il thread, viene chiamato **`thread_suspend()`**, fermando la sua esecuzione.

Le uniche operazioni consentite sul thread remoto riguardano **fermare** e **avviare** il thread, **recuperare** e **modificare** i valori dei registri. Le chiamate a funzioni remote vengono avviate impostando i registri `x0` a `x7` sugli **argomenti**, configurando **`pc`** per mirare alla funzione desiderata e attivando il thread. Assicurarsi che il thread non si blocchi dopo il ritorno richiede la rilevazione del ritorno.

Una strategia prevede **la registrazione di un gestore di eccezioni** per il thread remoto utilizzando `thread_set_exception_ports()`, impostando il registro `lr` su un indirizzo non valido prima della chiamata alla funzione. Questo attiva un'eccezione dopo l'esecuzione della funzione, inviando un messaggio alla porta di eccezione, consentendo l'ispezione dello stato del thread per recuperare il valore di ritorno. In alternativa, come adottato dall'exploit triple_fetch di Ian Beer, `lr` viene impostato per eseguire un ciclo infinito. I registri del thread vengono quindi monitorati continuamente fino a quando **`pc` punta a quell'istruzione**.

## 2. Mach ports for communication

La fase successiva prevede l'istituzione di porte Mach per facilitare la comunicazione con il thread remoto. Queste porte sono strumentali nel trasferire diritti di invio e ricezione arbitrari tra i task.

Per la comunicazione bidirezionale, vengono create due autorizzazioni di ricezione Mach: una nel task locale e l'altra nel task remoto. Successivamente, un diritto di invio per ciascuna porta viene trasferito al task corrispondente, consentendo lo scambio di messaggi.

Concentrandosi sulla porta locale, il diritto di ricezione è detenuto dal task locale. La porta viene creata con `mach_port_allocate()`. La sfida consiste nel trasferire un diritto di invio a questa porta nel task remoto.

Una strategia prevede di sfruttare `thread_set_special_port()` per posizionare un diritto di invio alla porta locale nel `THREAD_KERNEL_PORT` del thread remoto. Quindi, al thread remoto viene istruito di chiamare `mach_thread_self()` per recuperare il diritto di invio.

Per la porta remota, il processo è essenzialmente invertito. Al thread remoto viene diretto di generare una porta Mach tramite `mach_reply_port()` (poiché `mach_port_allocate()` non è adatto a causa del suo meccanismo di ritorno). Una volta creata la porta, viene invocato `mach_port_insert_right()` nel thread remoto per stabilire un diritto di invio. Questo diritto viene quindi conservato nel kernel utilizzando `thread_set_special_port()`. Tornando al task locale, `thread_get_special_port()` viene utilizzato sul thread remoto per acquisire un diritto di invio alla nuova porta Mach allocata nel task remoto.

Il completamento di questi passaggi porta all'istituzione di porte Mach, ponendo le basi per la comunicazione bidirezionale.

## 3. Basic Memory Read/Write Primitives

In questa sezione, l'attenzione è rivolta all'utilizzo del primitivo di esecuzione per stabilire primitive di lettura e scrittura della memoria di base. Questi passaggi iniziali sono cruciali per ottenere un maggiore controllo sul processo remoto, anche se i primitivi in questa fase non serviranno a molti scopi. Presto, saranno aggiornati a versioni più avanzate.

### Memory Reading and Writing Using Execute Primitive

L'obiettivo è eseguire letture e scritture di memoria utilizzando funzioni specifiche. Per leggere la memoria, vengono utilizzate funzioni che somigliano alla seguente struttura:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
E per scrivere in memoria, vengono utilizzate funzioni simili a questa struttura:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Queste funzioni corrispondono alle istruzioni assembly fornite:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificazione delle Funzioni Adatte

Una scansione delle librerie comuni ha rivelato candidati appropriati per queste operazioni:

1. **Lettura della Memoria:**
La funzione `property_getName()` della [libreria runtime di Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) è identificata come una funzione adatta per la lettura della memoria. La funzione è descritta di seguito:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Questa funzione agisce efficacemente come il `read_func` restituendo il primo campo di `objc_property_t`.

2. **Scrittura della Memoria:**
Trovare una funzione predefinita per la scrittura della memoria è più difficile. Tuttavia, la funzione `_xpc_int64_set_value()` di libxpc è un candidato adatto con il seguente disassemblaggio:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Per eseguire una scrittura a 64 bit a un indirizzo specifico, la chiamata remota è strutturata come:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Con queste primitive stabilite, il terreno è pronto per creare memoria condivisa, segnando un progresso significativo nel controllo del processo remoto.

## 4. Configurazione della Memoria Condivisa

L'obiettivo è stabilire memoria condivisa tra compiti locali e remoti, semplificando il trasferimento dei dati e facilitando la chiamata di funzioni con più argomenti. L'approccio prevede di sfruttare `libxpc` e il suo tipo di oggetto `OS_xpc_shmem`, che si basa sulle voci di memoria Mach.

### Panoramica del Processo:

1. **Allocazione della Memoria**:

- Allocare la memoria per la condivisione utilizzando `mach_vm_allocate()`.
- Utilizzare `xpc_shmem_create()` per creare un oggetto `OS_xpc_shmem` per la regione di memoria allocata. Questa funzione gestirà la creazione della voce di memoria Mach e memorizzerà il diritto di invio Mach all'offset `0x18` dell'oggetto `OS_xpc_shmem`.

2. **Creazione della Memoria Condivisa nel Processo Remoto**:

- Allocare memoria per l'oggetto `OS_xpc_shmem` nel processo remoto con una chiamata remota a `malloc()`.
- Copiare il contenuto dell'oggetto locale `OS_xpc_shmem` nel processo remoto. Tuttavia, questa copia iniziale avrà nomi di voci di memoria Mach errati all'offset `0x18`.

3. **Correzione della Voce di Memoria Mach**:

- Utilizzare il metodo `thread_set_special_port()` per inserire un diritto di invio per la voce di memoria Mach nel compito remoto.
- Correggere il campo della voce di memoria Mach all'offset `0x18` sovrascrivendolo con il nome della voce di memoria remota.

4. **Finalizzazione della Configurazione della Memoria Condivisa**:
- Validare l'oggetto remoto `OS_xpc_shmem`.
- Stabilire la mappatura della memoria condivisa con una chiamata remota a `xpc_shmem_remote()`.

Seguendo questi passaggi, la memoria condivisa tra i compiti locali e remoti sarà configurata in modo efficiente, consentendo trasferimenti di dati semplici e l'esecuzione di funzioni che richiedono più argomenti.

## Codice Aggiuntivo

Per l'allocazione della memoria e la creazione dell'oggetto di memoria condivisa:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Per creare e correggere l'oggetto di memoria condivisa nel processo remoto:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Ricorda di gestire correttamente i dettagli dei port Mach e dei nomi delle voci di memoria per garantire che la configurazione della memoria condivisa funzioni correttamente.

## 5. Ottenere il Controllo Completo

Una volta stabilita con successo la memoria condivisa e acquisita la capacità di esecuzione arbitraria, abbiamo essenzialmente guadagnato il controllo completo sul processo target. Le funzionalità chiave che abilitano questo controllo sono:

1. **Operazioni di Memoria Arbitraria**:

- Eseguire letture di memoria arbitrarie invocando `memcpy()` per copiare dati dalla regione condivisa.
- Eseguire scritture di memoria arbitrarie utilizzando `memcpy()` per trasferire dati nella regione condivisa.

2. **Gestione delle Chiamate di Funzione con Più Argomenti**:

- Per le funzioni che richiedono più di 8 argomenti, disporre gli argomenti aggiuntivi nello stack in conformità con la convenzione di chiamata.

3. **Trasferimento di Port Mach**:

- Trasferire port Mach tra i task tramite messaggi Mach attraverso port precedentemente stabiliti.

4. **Trasferimento di Descrittori di File**:
- Trasferire descrittori di file tra i processi utilizzando fileports, una tecnica evidenziata da Ian Beer in `triple_fetch`.

Questo controllo completo è racchiuso all'interno della libreria [threadexec](https://github.com/bazad/threadexec), che fornisce un'implementazione dettagliata e un'API user-friendly per l'interazione con il processo vittima.

## Considerazioni Importanti:

- Assicurati di utilizzare correttamente `memcpy()` per le operazioni di lettura/scrittura della memoria per mantenere la stabilità del sistema e l'integrità dei dati.
- Quando trasferisci port Mach o descrittori di file, segui i protocolli appropriati e gestisci le risorse in modo responsabile per prevenire leak o accessi non intenzionati.

Seguendo queste linee guida e utilizzando la libreria `threadexec`, è possibile gestire e interagire con i processi a un livello granulare, ottenendo il controllo completo sul processo target.

## Riferimenti

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{{#include ../../../../banners/hacktricks-training.md}}
