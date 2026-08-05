# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Inizialmente, la funzione `task_threads()` viene invocata sulla task port per ottenere un elenco di thread dal task remoto. Viene selezionato un thread da sottoporre a hijacking. Questo approccio differisce dai metodi convenzionali di code injection, poiché la creazione di un nuovo thread remoto è vietata dalla mitigazione che blocca `thread_create_running()`.<sup>[1]</sup>

Per controllare il thread, viene chiamata `thread_suspend()`, interrompendone l'esecuzione.<sup>[1]</sup>

Le uniche operazioni consentite sul thread remoto consistono nel **fermarlo** e **avviarlo**, nonché nel **recuperare**/**modificare** i valori dei suoi registri. Le chiamate a funzioni remote vengono avviate impostando i registri da `x0` a `x7` sugli **argomenti**, configurando `pc` affinché punti alla funzione desiderata e riprendendo l'esecuzione del thread. Per evitare che il thread vada in crash dopo il ritorno, è necessario rilevare tale ritorno.<sup>[1]</sup>

Una strategia consiste nel registrare un **exception handler** per il thread remoto usando `thread_set_exception_ports()` e nell'impostare il registro `lr` su un indirizzo non valido prima della chiamata alla funzione. Questo attiva un'eccezione al termine dell'esecuzione della funzione, inviando un messaggio alla exception port e consentendo di ispezionare lo stato del thread per recuperare il valore restituito. In alternativa, seguendo l'approccio adottato nell'exploit *triple_fetch* di Ian Beer, `lr` viene impostato su un loop infinito; i registri del thread vengono quindi monitorati continuamente finché `pc` non punta a quell'istruzione.<sup>[1]</sup>

## 2. Mach ports for communication

La fase successiva consiste nello stabilire Mach ports per facilitare la comunicazione con il thread remoto. Queste porte sono fondamentali per trasferire arbitrary send/receive rights tra i task.<sup>[1]</sup>

Per la comunicazione bidirezionale, vengono creati due Mach receive rights: uno nel task locale e l'altro nel task remoto. Successivamente, un send right per ciascuna porta viene trasferito al task corrispondente, consentendo lo scambio di messaggi.<sup>[1]</sup>

Concentrandosi sulla porta locale, il receive right è detenuto dal task locale. La porta viene creata con `mach_port_allocate()`. La difficoltà consiste nel trasferire un send right per questa porta all'interno del task remoto.<sup>[1]</sup>

Una strategia consiste nell'usare `thread_set_special_port()` per inserire un send right alla porta locale nella `THREAD_KERNEL_PORT` del thread remoto. Il thread remoto viene quindi istruito a chiamare `mach_thread_self()` per recuperare il send right.<sup>[1]</sup>

Per la porta remota, il processo è sostanzialmente inverso. Il thread remoto viene istruito a generare una Mach port tramite `mach_reply_port()` (poiché `mach_port_allocate()` non è adatta a causa del suo meccanismo di restituzione). Dopo la creazione della porta, nel thread remoto viene invocata `mach_port_insert_right()` per stabilire un send right. Questo right viene quindi memorizzato nel kernel usando `thread_set_special_port()`. Tornati al task locale, `thread_get_special_port()` viene utilizzata sul thread remoto per acquisire un send right alla Mach port appena allocata nel task remoto.<sup>[1]</sup>

Il completamento di questi passaggi porta alla creazione delle Mach ports, gettando le basi per una comunicazione bidirezionale.<sup>[1]</sup>

## 3. Basic Memory Read/Write Primitives

In questa sezione, l'attenzione è rivolta all'utilizzo dell'execute primitive per stabilire primitive di memory read/write di base. Questi passaggi iniziali sono fondamentali per ottenere un maggiore controllo sul processo remoto, anche se le primitive a questo stadio non saranno molto utili. Presto verranno aggiornate a versioni più avanzate.<sup>[1]</sup>

### Memory reading and writing using the execute primitive

L'obiettivo è eseguire operazioni di memory reading e writing usando funzioni specifiche. Per **leggere la memoria**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Per la **scrittura in memoria**:
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

Una scansione delle librerie comuni ha rivelato candidati appropriati per queste operazioni:<sup>[1]</sup>

1. **Lettura della memoria — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Scrittura in memoria — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Per eseguire una scrittura a 64 bit a un indirizzo arbitrario:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Con queste primitive stabilite, è possibile creare memoria condivisa, compiendo un passo significativo nel controllo del processo remoto.<sup>[1]</sup>

## 4. Configurazione della memoria condivisa

L’obiettivo è stabilire memoria condivisa tra i task locali e remoti, semplificando il trasferimento dei dati e facilitando la chiamata di funzioni con più argomenti. L’approccio sfrutta `libxpc` e il relativo tipo di oggetto `OS_xpc_shmem`, basato sui memory entry Mach.<sup>[1]</sup>

### Panoramica del processo

1. **Allocazione della memoria**
* Allocare la memoria da condividere usando `mach_vm_allocate()`.
* Usare `xpc_shmem_create()` per creare un oggetto `OS_xpc_shmem` per la regione allocata.
2. **Creazione della memoria condivisa nel processo remoto**
* Allocare memoria per l’oggetto `OS_xpc_shmem` nel processo remoto (`remote_malloc`).
* Copiare l’oggetto template locale; è ancora necessario effettuare il fix-up del Mach send right incorporato all’offset `0x18`.
3. **Correzione del Mach memory entry**
* Inserire un send right con `thread_set_special_port()` e sovrascrivere il campo `0x18` con il nome dell’entry remota.
4. **Finalizzazione**
* Convalidare l’oggetto remoto e mapparlo con una chiamata remota a `xpc_shmem_remote()`.

## 5. Ottenere il controllo completo

Una volta disponibili l’esecuzione arbitraria e un back-channel di memoria condivisa, il processo target è di fatto sotto il tuo controllo:<sup>[1]</sup>

* **R/W arbitrario della memoria** — usare `memcpy()` tra le regioni locali e condivise.
* **Chiamate di funzioni con più di 8 argomenti** — collocare gli argomenti aggiuntivi nello stack seguendo la calling convention arm64.
* **Trasferimento di Mach port** — passare i rights nei Mach message tramite le porte stabilite.
* **Trasferimento di file descriptor** — sfruttare i fileport (vedi *triple_fetch*).

Tutto questo è racchiuso nella libreria [`threadexec`](https://github.com/bazad/threadexec) per facilitarne il riutilizzo.

---

## 6. Specificità di Apple Silicon (arm64e)

Nei dispositivi Apple Silicon (arm64e), i **Pointer Authentication Codes (PAC)** proteggono tutti gli indirizzi di ritorno e molti function pointer. Le tecniche di thread-hijacking che *riutilizzano codice esistente* continuano a funzionare perché i valori originali in `lr`/`pc` contengono già firme PAC valide. I problemi sorgono quando si tenta di effettuare un salto verso memoria controllata dall’attaccante:

1. Allocare memoria eseguibile all’interno del target (`mach_vm_allocate` remoto + `mprotect(PROT_EXEC)`).
2. Copiare il payload.
3. All’interno del processo *remoto*, firmare il puntatore:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Imposta `pc = ptr` nello stato del thread hijacked.

In alternativa, resta conforme a PAC concatenando gadget/funzioni esistenti (ROP tradizionale).

## 7. Rilevamento e hardening con EndpointSecurity

Il framework **EndpointSecurity (ES)** espone eventi del kernel che consentono ai difensori di osservare o bloccare i tentativi di thread injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – viene generato quando un processo richiede la port di un altro task (ad esempio `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – viene emesso ogni volta che un thread viene creato in un task *differente*.<sup>[3]</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (aggiunto in macOS 14 Sonoma) – indica la manipolazione dei registri di un thread esistente.

Client Swift minimale che stampa gli eventi dei thread remoti:
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
Esecuzione di query con **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Considerazioni sull’hardened runtime

Distribuire la tua applicazione **senza** l’entitlement `com.apple.security.get-task-allow` impedisce agli attacker non-root di ottenere il suo task-port. System Integrity Protection (SIP) continua a bloccare l’accesso a molti binari Apple, ma il software di terze parti deve effettuare esplicitamente l’opt-out.

## 8. Tool pubblici recenti (2023-2025)

| Tool | Anno | Note |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC compatto che dimostra il thread hijacking compatibile con PAC su Ventura/Sonoma |
| `remote_thread_es` | 2024 | Helper EndpointSecurity utilizzato da diversi vendor EDR per rilevare gli eventi `REMOTE_THREAD_CREATE` |

> Leggere il source code di questi progetti è utile per comprendere i cambiamenti alle API introdotti in macOS 13/14 e mantenere la compatibilità tra Intel e Apple Silicon.

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
