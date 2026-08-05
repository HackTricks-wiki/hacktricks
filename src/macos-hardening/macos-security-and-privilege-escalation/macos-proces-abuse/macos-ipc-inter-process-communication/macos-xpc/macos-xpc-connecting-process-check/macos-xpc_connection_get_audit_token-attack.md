# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Per ulteriori informazioni, consulta il post originale:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Questo è un riepilogo:

## Informazioni di base sui Mach Messages

Se non sai cosa sono i Mach Messages, inizia consultando questa pagina:


{{#ref}}
../../
{{#endref}}

Per il momento, ricorda che ([definizione disponibile qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
I Mach messages vengono inviati tramite una _mach port_, un canale di comunicazione **single receiver, multiple sender** integrato nel mach kernel. **Più processi possono inviare messaggi** a una mach port, ma in qualsiasi momento **solo un singolo processo può leggerli**. Come i file descriptor e i socket, le mach port vengono allocate e gestite dal kernel e i processi vedono soltanto un intero, che possono usare per indicare al kernel quale delle proprie mach port desiderano utilizzare.

## XPC Connection

Se non sai come viene stabilita una XPC connection, consulta:


{{#ref}}
../
{{#endref}}

## Riepilogo della vulnerabilità

È importante sapere che **l'astrazione XPC è una connessione one-to-one**, ma si basa su una tecnologia che **può avere più sender, quindi:**

- Le mach port hanno un singolo receiver e **più sender**.
- L'audit token di una XPC connection è l'audit token **copiato dal messaggio ricevuto più recentemente**.
- Ottenere l'**audit token** di una XPC connection è fondamentale per molti **controlli di sicurezza**.<sup>[[1]](#references)</sup>

Sebbene la situazione precedente sembri promettente, esistono alcuni scenari in cui non causerà problemi ([da qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Gli audit token vengono spesso utilizzati per un controllo di autorizzazione che decide se accettare una connection. Poiché ciò avviene usando un messaggio inviato alla service port, **non è ancora stata stabilita alcuna connection**. Gli altri messaggi su questa port verranno semplicemente gestiti come richieste di connessione aggiuntive. Pertanto, **i controlli eseguiti prima di accettare una connection non sono vulnerabili** (questo significa anche che all'interno di `-listener:shouldAcceptNewConnection:` l'audit token è sicuro). Stiamo quindi **cercando XPC connections che verificano azioni specifiche**.
- Gli XPC event handler vengono gestiti in modo sincrono. Ciò significa che l'event handler di un messaggio deve essere completato prima di essere chiamato per quello successivo, anche su dispatch queue concorrenti. Pertanto, all'interno di un **XPC event handler l'audit token non può essere sovrascritto** da altri messaggi normali (non di risposta!).<sup>[[1]](#references)</sup>

Esistono due metodi diversi con cui questa situazione potrebbe essere sfruttabile:

1. Variant1:
- L'**exploit** si **connette** al service **A** e al service **B**
- Il service **B** può chiamare una **funzionalità privilegiata** nel service A che l'utente non può chiamare
- Il service **A** chiama **`xpc_connection_get_audit_token`** mentre _**non**_ si trova **nell'**event handler** per una connection all'interno di un **`dispatch_async`**.
- Quindi un messaggio **diverso** potrebbe **sovrascrivere l'Audit Token**, perché viene eseguito in modo asincrono al di fuori dell'event handler.
- L'exploit passa al **service B** il **SEND right** verso il service A.
- Pertanto, svc **B** invierà effettivamente i **messaggi** al service **A**.
- L'**exploit** tenta di **chiamare l'azione privilegiata**. In una RC, svc **A** **controlla** l'autorizzazione di questa **azione** mentre **svc B ha sovrascritto l'Audit token** (fornendo all'exploit l'accesso per chiamare l'azione privilegiata).
2. Variant 2:
- Il service **B** può chiamare una **funzionalità privilegiata** nel service A che l'utente non può chiamare
- L'exploit si connette al **service A**, che **invia** all'exploit un **messaggio che si aspetta una risposta** su una specifica **replay** **port**.
- L'exploit invia al **service** B un messaggio passando **quella reply port**.
- Quando il service **B risponde**, **invia il messaggio al service A**, **mentre** l'**exploit** invia un **messaggio diverso al service A** tentando di **raggiungere una funzionalità privilegiata** e aspettandosi che la risposta del service B sovrascriva l'Audit token nel momento perfetto (Race Condition).

## Variant 1: chiamare xpc_connection_get_audit_token al di fuori di un event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Due mach service, **`A`** e **`B`**, a cui possiamo connetterci entrambi (in base al sandbox profile e ai controlli di autorizzazione eseguiti prima di accettare la connection).
- _**A**_ deve avere un **controllo di autorizzazione** per un'azione specifica che **B** può superare (ma la nostra app non può).
- Ad esempio, se B dispone di alcuni **entitlements** o viene eseguito come **root**, potrebbe consentirgli di chiedere ad A di eseguire un'azione privilegiata.
- Per questo controllo di autorizzazione, **A** ottiene l'audit token in modo asincrono, ad esempio chiamando `xpc_connection_get_audit_token` da `dispatch_async`.

> [!CAUTION]
> In questo caso, un attaccante potrebbe attivare una **Race Condition**, creando un **exploit** che chiede ad A di eseguire un'azione più volte mentre **B invia messaggi ad `A`**. Quando la RC ha **successo**, l'**audit token** di **B** viene copiato in memoria **mentre la richiesta del nostro exploit è in fase di gestione** da parte di A, fornendogli **accesso all'azione privilegiata che solo B potrebbe richiedere**.

Questo è accaduto con **`A`** come `smd` e **`B`** come `diagnosticd`. La funzione [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) di smb può essere utilizzata per installare un nuovo helper tool privilegiato (come **root**). Se un **processo in esecuzione come root contatta** **smd**, non verranno eseguiti altri controlli.

Pertanto, il service **B** è **`diagnosticd`**, perché viene eseguito come **root** e può essere utilizzato per **monitorare** un processo; una volta avviato il monitoraggio, **invierà più messaggi al secondo**.

Per eseguire l'attacco:

1. Avvia una **connection** al service denominato `smd` usando il protocollo XPC standard.
2. Crea una **connection** secondaria verso `diagnosticd`. Contrariamente alla procedura normale, invece di creare e inviare due nuove mach port, il client port send right viene sostituito con un duplicato del **send right** associato alla connection `smd`.
3. Di conseguenza, i messaggi XPC possono essere inviati a `diagnosticd`, ma le risposte da `diagnosticd` vengono reindirizzate a `smd`. Per `smd`, sembra che i messaggi provenienti sia dall'utente sia da `diagnosticd` abbiano origine dalla stessa connection.

![Immagine che raffigura il processo dell'exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Il passaggio successivo consiste nell'istruire `diagnosticd` ad avviare il monitoraggio di un processo scelto, potenzialmente quello dell'utente stesso. Contemporaneamente, viene inviata a `smd` un'ondata di messaggi di routine 1004. L'obiettivo è installare uno strumento con privilegi elevati.
5. Questa azione attiva una race condition all'interno della funzione `handle_bless`. Il timing è fondamentale: la chiamata alla funzione `xpc_connection_get_pid` deve restituire il PID del processo dell'utente (poiché lo strumento privilegiato si trova nell'app bundle dell'utente). Tuttavia, la funzione `xpc_connection_get_audit_token`, nello specifico all'interno della subroutine `connection_is_authorized`, deve fare riferimento all'audit token appartenente a `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: inoltro delle reply

In un ambiente XPC (Cross-Process Communication), sebbene gli event handler non vengano eseguiti contemporaneamente, la gestione dei reply message presenta un comportamento particolare. In particolare, esistono due metodi distinti per inviare messaggi che si aspettano una risposta:

1. **`xpc_connection_send_message_with_reply`**: in questo caso, il messaggio XPC viene ricevuto ed elaborato su una queue designata.
2. **`xpc_connection_send_message_with_reply_sync`**: al contrario, con questo metodo il messaggio XPC viene ricevuto ed elaborato sulla dispatch queue corrente.

Questa distinzione è fondamentale perché consente la possibilità che i **reply packet vengano analizzati contemporaneamente all'esecuzione di un XPC event handler**. In particolare, sebbene `_xpc_connection_set_creds` implementi il locking per proteggere dalla sovrascrittura parziale dell'audit token, questa protezione non viene estesa all'intero connection object. Di conseguenza, si crea una vulnerabilità in cui l'audit token può essere sostituito nell'intervallo tra l'analisi di un packet e l'esecuzione del relativo event handler.

Per sfruttare questa vulnerabilità, è necessaria la seguente configurazione:

- Due mach service, denominati **`A`** e **`B`**, ai quali è possibile stabilire una connection.
- Il service **`A`** deve includere un controllo di autorizzazione per un'azione specifica che solo **`B`** può eseguire (l'applicazione dell'utente non può).
- Il service **`A`** deve inviare un messaggio che prevede una risposta.
- L'utente può inviare un messaggio a **`B`**, che risponderà.

Il processo di exploitation prevede i seguenti passaggi:

1. Attendi che il service **`A`** invii un messaggio che prevede una risposta.
2. Invece di rispondere direttamente ad **`A`**, la reply port viene dirottata e utilizzata per inviare un messaggio al service **`B`**.
3. Successivamente, viene inviato un messaggio relativo all'azione vietata, aspettandosi che venga elaborato contemporaneamente alla risposta proveniente da **`B`**.<sup>[[1]](#references)</sup>

Di seguito è riportata una rappresentazione visiva dello scenario di attacco descritto:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemi di individuazione

- **Difficoltà nel localizzare le istanze**: cercare istanze di utilizzo di `xpc_connection_get_audit_token` è stato difficile, sia staticamente sia dinamicamente.
- **Metodologia**: Frida è stato utilizzato per fare hook sulla funzione `xpc_connection_get_audit_token`, filtrando le chiamate che non provenivano dagli event handler. Tuttavia, questo metodo era limitato al processo sottoposto a hook e richiedeva un utilizzo attivo.
- **Strumenti di analisi**: strumenti come IDA/Ghidra sono stati utilizzati per esaminare i mach service raggiungibili, ma il processo richiedeva molto tempo ed era complicato dalle chiamate che coinvolgevano la dyld shared cache.
- **Limitazioni dello scripting**: i tentativi di creare uno script per analizzare le chiamate a `xpc_connection_get_audit_token` provenienti da blocchi `dispatch_async` sono stati ostacolati dalla complessità dell'analisi dei blocchi e delle interazioni con la dyld shared cache.<sup>[[1]](#references)</sup>

## La correzione <a href="#the-fix" id="the-fix"></a>

- **Problemi segnalati**: è stato inviato ad Apple un report con i problemi generali e specifici individuati in `smd`.
- **Risposta di Apple**: Apple ha risolto il problema in `smd` sostituendo `xpc_connection_get_audit_token` con `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Natura della correzione**: la funzione `xpc_dictionary_get_audit_token` è considerata sicura perché recupera l'audit token direttamente dal mach message associato al messaggio XPC ricevuto. Tuttavia, non fa parte della public API, analogamente a `xpc_connection_get_audit_token`.
- **Assenza di una correzione più ampia**: non è chiaro perché Apple non abbia implementato una correzione più completa, come scartare i messaggi non corrispondenti all'audit token salvato della connection. La possibilità di cambiamenti legittimi dell'audit token in determinati scenari (ad esempio, l'utilizzo di `setuid`) potrebbe essere un fattore.
- **Stato attuale**: il problema persiste in iOS 17 e macOS 14, rappresentando una difficoltà per chi cerca di identificarlo e comprenderlo.<sup>[[1]](#references)</sup>

## Individuazione pratica dei code path vulnerabili (2024–2025)

Durante l'audit dei service XPC per questa classe di bug, concentrati sulle autorizzazioni eseguite al di fuori dell'event handler del messaggio o contemporaneamente all'elaborazione delle reply.

Indicazioni per il triage statico:
- Cerca le chiamate a `xpc_connection_get_audit_token` raggiungibili da blocchi accodati tramite `dispatch_async`/`dispatch_after` o altre worker queue eseguite al di fuori del message handler.
- Cerca gli authorization helper che combinano lo stato per-connection e per-message (ad esempio, recuperando il PID da `xpc_connection_get_pid`, ma l'audit token da `xpc_connection_get_audit_token`).
- Nel codice NSXPC, verifica che i controlli vengano eseguiti in `-listener:shouldAcceptNewConnection:` oppure, per i controlli per-message, che l'implementazione utilizzi un audit token per-message (ad esempio, il dictionary del messaggio tramite `xpc_dictionary_get_audit_token` nel codice di livello inferiore).

Indicazioni per il triage dinamico:
- Fai hook su `xpc_connection_get_audit_token` e segnala le invocazioni il cui user stack non include il percorso di event delivery (ad esempio, `_xpc_connection_mach_event`). Esempio di hook Frida:
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
Note:
- Su macOS, l'instrumentation di binari protetti/Apple potrebbe richiedere SIP disabilitato o un ambiente di sviluppo; preferisci testare le tue build o i servizi userland.
- Per le race di reply-forwarding (Variant 2), monitora il parsing concorrente dei pacchetti di risposta effettuando fuzzing dei timing di `xpc_connection_send_message_with_reply` rispetto alle richieste normali e verificando se l'audit token effettivo utilizzato durante l'autorizzazione può essere influenzato.

## Primitive di exploitation di cui probabilmente avrai bisogno

- Setup multi-sender (Variant 1): crea connessioni verso A e B; duplica il send right della client port di A e utilizzalo come client port di B, in modo che le reply di B vengano consegnate ad A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): cattura il send-once right dalla pending request di A (reply port), quindi invia un messaggio crafted a B usando quel reply port, in modo che la reply di B arrivi ad A mentre la tua privileged request viene analizzata.

Queste tecniche richiedono la creazione low-level di messaggi mach per i formati bootstrap e dei messaggi XPC; consulta le pagine introduttive su mach/XPC in questa sezione per i layout esatti dei pacchetti e i flag.

## Tool utili

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) può aiutare a enumerare le connessioni e osservare il traffico per validare configurazioni multi-sender e il timing. Esempio: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing per libxpc: usa l'interpose su `xpc_connection_send_message*` e `xpc_connection_get_audit_token` per registrare i call site e gli stack durante il black-box testing.



## Riferimenti

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
