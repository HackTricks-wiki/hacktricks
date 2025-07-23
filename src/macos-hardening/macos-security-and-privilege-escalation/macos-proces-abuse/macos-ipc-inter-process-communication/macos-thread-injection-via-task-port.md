# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Inizialmente, la funzione `task_threads()` viene invocata sulla porta del task per ottenere un elenco di thread dal task remoto. Un thread viene selezionato per l'hijacking. Questo approccio si discosta dai metodi convenzionali di iniezione di codice poiché la creazione di un nuovo thread remoto è vietata a causa della mitigazione che blocca `thread_create_running()`.

Per controllare il thread, viene chiamato `thread_suspend()`, fermando la sua esecuzione.

Le uniche operazioni consentite sul thread remoto riguardano **fermarlo** e **riavviarlo** e **recuperare**/**modificare** i suoi valori di registro. Le chiamate a funzioni remote vengono avviate impostando i registri `x0` a `x7` sugli **argomenti**, configurando `pc` per puntare alla funzione desiderata e riprendendo il thread. Assicurarsi che il thread non si blocchi dopo il ritorno richiede la rilevazione del ritorno.

Una strategia prevede la registrazione di un **gestore di eccezioni** per il thread remoto utilizzando `thread_set_exception_ports()`, impostando il registro `lr` su un indirizzo non valido prima della chiamata alla funzione. Questo attiva un'eccezione dopo l'esecuzione della funzione, inviando un messaggio alla porta di eccezione, consentendo l'ispezione dello stato del thread per recuperare il valore di ritorno. In alternativa, come adottato dall'exploit *triple_fetch* di Ian Beer, `lr` è impostato per eseguire un ciclo infinito; i registri del thread vengono quindi monitorati continuamente fino a quando `pc` punta a quell'istruzione.

## 2. Mach ports for communication

La fase successiva prevede l'istituzione di porte Mach per facilitare la comunicazione con il thread remoto. Queste porte sono strumentali nel trasferire diritti di invio/ricezione arbitrari tra i task.

Per la comunicazione bidirezionale, vengono create due porte di ricezione Mach: una nel task locale e l'altra nel task remoto. Successivamente, un diritto di invio per ciascuna porta viene trasferito al task corrispondente, consentendo lo scambio di messaggi.

Concentrandosi sulla porta locale, il diritto di ricezione è detenuto dal task locale. La porta viene creata con `mach_port_allocate()`. La sfida consiste nel trasferire un diritto di invio a questa porta nel task remoto.

Una strategia prevede di sfruttare `thread_set_special_port()` per posizionare un diritto di invio alla porta locale nel `THREAD_KERNEL_PORT` del thread remoto. Quindi, al thread remoto viene istruito di chiamare `mach_thread_self()` per recuperare il diritto di invio.

Per la porta remota, il processo è essenzialmente invertito. Al thread remoto viene diretto di generare una porta Mach tramite `mach_reply_port()` (poiché `mach_port_allocate()` non è adatto a causa del suo meccanismo di ritorno). Una volta creata la porta, viene invocato `mach_port_insert_right()` nel thread remoto per stabilire un diritto di invio. Questo diritto viene quindi conservato nel kernel utilizzando `thread_set_special_port()`. Tornando al task locale, `thread_get_special_port()` viene utilizzato sul thread remoto per acquisire un diritto di invio alla nuova porta Mach allocata nel task remoto.

Il completamento di questi passaggi porta all'istituzione di porte Mach, ponendo le basi per la comunicazione bidirezionale.

## 3. Basic Memory Read/Write Primitives

In questa sezione, l'attenzione è rivolta all'utilizzo del primitivo di esecuzione per stabilire primitivi di lettura/scrittura della memoria di base. Questi passaggi iniziali sono cruciali per ottenere un maggiore controllo sul processo remoto, anche se i primitivi in questa fase non serviranno a molti scopi. Presto, saranno aggiornati a versioni più avanzate.

### Memory reading and writing using the execute primitive

L'obiettivo è eseguire letture e scritture di memoria utilizzando funzioni specifiche. Per **leggere la memoria**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Per **scrivere in memoria**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Queste funzioni corrispondono al seguente assembly:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificazione delle funzioni adatte

Una scansione delle librerie comuni ha rivelato candidati appropriati per queste operazioni:

1. **Lettura della memoria — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Scrittura della memoria — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Per eseguire una scrittura a 64 bit a un indirizzo arbitrario:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Con queste primitive stabilite, il terreno è pronto per creare memoria condivisa, segnando un progresso significativo nel controllo del processo remoto.

## 4. Configurazione della Memoria Condivisa

L'obiettivo è stabilire memoria condivisa tra compiti locali e remoti, semplificando il trasferimento dei dati e facilitando la chiamata di funzioni con più argomenti. L'approccio sfrutta `libxpc` e il suo tipo di oggetto `OS_xpc_shmem`, che si basa sulle voci di memoria Mach.

### Panoramica del Processo

1. **Allocazione della memoria**
* Allocare memoria per la condivisione utilizzando `mach_vm_allocate()`.
* Utilizzare `xpc_shmem_create()` per creare un oggetto `OS_xpc_shmem` per la regione allocata.
2. **Creazione della memoria condivisa nel processo remoto**
* Allocare memoria per l'oggetto `OS_xpc_shmem` nel processo remoto (`remote_malloc`).
* Copiare l'oggetto modello locale; è ancora necessaria la correzione del diritto di invio Mach incorporato all'offset `0x18`.
3. **Correzione della voce di memoria Mach**
* Inserire un diritto di invio con `thread_set_special_port()` e sovrascrivere il campo `0x18` con il nome dell'entry remota.
4. **Finalizzazione**
* Validare l'oggetto remoto e mappare con una chiamata remota a `xpc_shmem_remote()`.

## 5. Ottenere il Controllo Completo

Una volta che l'esecuzione arbitraria e un canale di comunicazione in memoria condivisa sono disponibili, possiedi effettivamente il processo target:

* **R/W di memoria arbitraria** — utilizzare `memcpy()` tra regioni locali e condivise.
* **Chiamate di funzione con > 8 argomenti** — posizionare gli argomenti extra nello stack seguendo la convenzione di chiamata arm64.
* **Trasferimento di port Mach** — passare diritti nei messaggi Mach tramite i port stabiliti.
* **Trasferimento di descrittori di file** — sfruttare fileports (vedi *triple_fetch*).

Tutto questo è racchiuso nella libreria [`threadexec`](https://github.com/bazad/threadexec) per un facile riutilizzo.

---

## 6. Sfide di Apple Silicon (arm64e)

Su dispositivi Apple Silicon (arm64e) **Codici di Autenticazione dei Puntatori (PAC)** proteggono tutti gli indirizzi di ritorno e molti puntatori di funzione. Le tecniche di dirottamento dei thread che *riutilizzano codice esistente* continuano a funzionare perché i valori originali in `lr`/`pc` portano già firme PAC valide. I problemi sorgono quando si cerca di saltare a memoria controllata dall'attaccante:

1. Allocare memoria eseguibile all'interno del target (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Copiare il payload.
3. All'interno del processo *remoto* firmare il puntatore:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Imposta `pc = ptr` nello stato del thread compromesso.

In alternativa, rimani conforme a PAC concatenando gadget/funzioni esistenti (ROP tradizionale).

## 7. Rilevamento e Indurimento con EndpointSecurity

Il framework **EndpointSecurity (ES)** espone eventi del kernel che consentono ai difensori di osservare o bloccare i tentativi di iniezione di thread:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – attivato quando un processo richiede il porto di un altro task (ad es. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – emesso ogni volta che un thread viene creato in un *task* *diverso*.
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (aggiunto in macOS 14 Sonoma) – indica la manipolazione dei registri di un thread esistente.

Client Swift minimale che stampa eventi di thread remoti:
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
Interrogare con **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Considerazioni sul runtime rinforzato

Distribuire la tua applicazione **senza** il diritto `com.apple.security.get-task-allow` impedisce agli attaccanti non root di ottenere il suo task-port. La Protezione dell'Integrità di Sistema (SIP) blocca ancora l'accesso a molti binari Apple, ma il software di terze parti deve disattivarlo esplicitamente.

## 8. Strumenti Pubblici Recenti (2023-2025)

| Strumento | Anno | Osservazioni |
|-----------|------|--------------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC compatto che dimostra l'hijacking di thread consapevole del PAC su Ventura/Sonoma |
| `remote_thread_es` | 2024 | Helper di EndpointSecurity utilizzato da diversi fornitori di EDR per visualizzare eventi `REMOTE_THREAD_CREATE` |

> Leggere il codice sorgente di questi progetti è utile per comprendere le modifiche all'API introdotte in macOS 13/14 e per rimanere compatibili tra Intel ↔ Apple Silicon.

## Riferimenti

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
