# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Per ulteriori informazioni controlla il post originale:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Questa è una sintesi:

## Mach Messages Basic Info

Se non sai cosa sono i Mach Messages inizia a controllare questa pagina:


{{#ref}}
../../
{{#endref}}

Per ora ricorda che ([definizione da qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages sono inviati su una _mach port_, che è un canale di comunicazione **single receiver, multiple sender** implementato nel kernel Mach. **Più processi possono inviare messaggi** a una mach port, ma in ogni momento **solo un singolo processo può leggerli**. Proprio come file descriptor e socket, le mach ports sono allocate e gestite dal kernel e i processi vedono solo un intero che possono usare per indicare al kernel quale delle loro mach ports vogliono usare.

## XPC Connection

Se non sai come viene stabilita una XPC connection controlla:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Quello che è importante sapere è che **l'astrazione di XPC è una connessione one-to-one**, ma è costruita su una tecnologia che **può avere più sender, quindi:**

- Mach ports sono single receiver, **multiple sender**.
- L'audit token di una XPC connection è l'audit token **copiato dal messaggio più recentemente ricevuto**.
- Ottenere l'**audit token** di una XPC connection è critico per molti **security checks**.

Anche se la situazione precedente sembra promettente, ci sono alcuni scenari in cui questo non causa problemi ([da qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Gli audit tokens sono spesso usati per un controllo di autorizzazione per decidere se accettare una connection. Poiché questo avviene usando un messaggio alla service port, **non è ancora stata stabilita una connection**. Altri messaggi su questa porta saranno semplicemente trattati come richieste di connessione aggiuntive. Quindi qualsiasi **check prima di accettare una connection non è vulnerabile** (ciò significa anche che dentro `-listener:shouldAcceptNewConnection:` l'audit token è sicuro). Cerchiamo quindi **connessioni XPC che verificano azioni specifiche**.
- Gli XPC event handlers sono eseguiti in modo sincrono. Questo significa che l'event handler per un messaggio deve essere completato prima di invocarlo per il messaggio successivo, anche su concurrent dispatch queues. Quindi dentro un **XPC event handler l'audit token non può essere sovrascritto** da altri messaggi normali (non reply!).

Due diversi metodi in cui questo può essere sfruttato:

1. Variant1:
- L'**Exploit** **connects** al service **A** e al service **B**
- Il service **B** può chiamare una **privileged functionality** in A che l'utente non può
- Il service **A** chiama **`xpc_connection_get_audit_token`** mentre _**non**_ è dentro l'**event handler** per una connection in un **`dispatch_async`**.
- Quindi un **messaggio diverso** potrebbe **sovrascrivere l'Audit Token** perché viene dispatchato asincronamente fuori dall'event handler.
- L'exploit passa a **service B il SEND right verso service A**.
- Quindi svc **B** starà effettivamente **inviando** i **messaggi** a service **A**.
- L'**exploit** prova a **chiamare** l'**azione privilegiata.** In un RC svc **A** **controlla** l'autorizzazione di questa **azione** mentre **svc B ha sovrascritto l'Audit token** (dando all'exploit accesso per chiamare l'azione privilegiata).
2. Variant 2:
- Il service **B** può chiamare una **privileged functionality** in A che l'utente non può
- L'exploit si connette con **service A** che **invia** all'exploit un **messaggio aspettando una risposta** in una specifica **reply port**.
- L'exploit invia **a service B** un messaggio passando **quella reply port**.
- Quando service **B** risponde, esso **invia il messaggio a service A**, **mentre** l'**exploit** invia un messaggio diverso a service **A** cercando di **raggiungere una funzionalità privilegiata** e aspettandosi che la reply da service B sovrascriva l'Audit token al momento perfetto (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Due mach services **`A`** e **`B`** ai quali possiamo connetterci entrambi (in base al sandbox profile e ai controlli di autorizzazione prima di accettare la connection).
- _**A**_ deve avere un **authorization check** per una specifica azione che **`B`** può superare (ma la nostra app non può).
- Per esempio, se B ha alcuni **entitlements** o gira come **root**, potrebbe permettergli di chiedere ad A di eseguire un'azione privilegiata.
- Per questo authorization check, **`A`** ottiene l'audit token in modo asincrono, per esempio chiamando `xpc_connection_get_audit_token` da **`dispatch_async`**.

> [!CAUTION]
> In questo caso un attacker potrebbe innescare una **Race Condition** creando un **exploit** che **chiede A di eseguire un'azione** più volte mentre fa sì che **B invii messaggi ad `A`**. Quando il RC ha successo, l'**audit token** di **B** verrà copiato in memoria **mentre** la richiesta del nostro **exploit** viene **gestita** da A, dandogli l'accesso all'azione privilegiata che solo B poteva richiedere.

Questo è successo con **`A`** come `smd` e **`B`** come `diagnosticd`. La funzione [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) di smb può essere usata per installare un nuovo privileged helper tool (come **root**). Se un **process running as root contact** **smd**, non verranno eseguiti altri controlli.

Pertanto, il service **B** è **`diagnosticd`** perché gira come **root** e può essere usato per **monitorare** un processo, quindi una volta che il monitoring è iniziato, esso **invierà più messaggi al secondo.**

Per eseguire l'attacco:

1. Inizia una **connection** al service chiamato `smd` usando il protocollo XPC standard.
2. Forma una connection secondaria a `diagnosticd`. Contrariamente alla procedura normale, invece di creare e inviare due nuove mach ports, il client port send right è sostituito con un duplicato del **send right** associato alla connection `smd`.
3. Come risultato, i messaggi XPC possono essere dispatchati a `diagnosticd`, ma le risposte da `diagnosticd` vengono reindirizzate a `smd`. Per `smd`, sembra come se i messaggi sia dall'utente che da `diagnosticd` provenissero dalla stessa connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Il passo successivo è istruire `diagnosticd` a iniziare il monitoring di un processo scelto (potenzialmente l'app dell'utente). Contemporaneamente, viene inviato un flood di normali messaggi 1004 a `smd`. L'intento qui è installare uno strumento con privilegi elevati.
5. Questa azione innesca una race condition dentro la funzione `handle_bless`. Il timing è critico: la chiamata `xpc_connection_get_pid` deve restituire il PID del processo dell'utente (poiché lo strumento privilegiato risiede nel bundle dell'app dell'utente). Tuttavia, la funzione `xpc_connection_get_audit_token`, specificamente all'interno della subroutine `connection_is_authorized`, deve fare riferimento all'audit token appartenente a `diagnosticd`.

## Variant 2: reply forwarding

In un ambiente XPC (Cross-Process Communication), anche se gli event handlers non vengono eseguiti concorrentemente, la gestione dei reply messages ha un comportamento particolare. Nello specifico, esistono due metodi distinti per inviare messaggi che si aspettano una reply:

1. **`xpc_connection_send_message_with_reply`**: qui il messaggio XPC viene ricevuto e processato su una queue designata.
2. **`xpc_connection_send_message_with_reply_sync`**: al contrario, in questo metodo il messaggio XPC viene ricevuto e processato sulla current dispatch queue.

Questa distinzione è cruciale perché permette la possibilità che **i reply packets vengano parsati concorrentemente con l'esecuzione di un XPC event handler**. Nota che, mentre `_xpc_connection_set_creds` implementa locking per proteggere contro la parziale sovrascrittura dell'audit token, non estende questa protezione all'intero connection object. Di conseguenza, ciò crea una vulnerabilità dove l'audit token può essere sostituito nell'intervallo tra il parsing di un packet e l'esecuzione del suo event handler.

Per sfruttare questa vulnerabilità, è necessario il seguente setup:

- Due mach services, detti **`A`** e **`B`**, entrambi con i quali si può stabilire una connection.
- Il service **`A`** dovrebbe includere un authorization check per una specifica azione che solo **`B`** può eseguire (la app dell'utente non può).
- Il service **`A`** dovrebbe inviare un messaggio che si aspetta una reply.
- L'utente può mandare un messaggio a **`B`** a cui esso risponderà.

Il processo di exploitation coinvolge i seguenti passi:

1. Aspettare che il service **`A`** invii un messaggio che si aspetta una reply.
2. Invece di rispondere direttamente ad **`A`**, la reply port viene dirottata e usata per inviare un messaggio al service **`B`**.
3. Successivamente, viene inviato un messaggio che riguarda l'azione proibita, con l'aspettativa che venga processato contemporaneamente alla reply da **`B`**.

Di seguito è riportata una rappresentazione visuale dello scenario d'attacco descritto:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Difficoltà nel Trovare Istanza**: Cercare istanze di utilizzo di `xpc_connection_get_audit_token` è stato difficile, sia staticamente che dinamicamente.
- **Metodologia**: Frida è stato usato per hookare la funzione `xpc_connection_get_audit_token`, filtrando le chiamate che non originavano dagli event handlers. Tuttavia, questo metodo era limitato al processo hookato e richiedeva un utilizzo attivo.
- **Tooling di Analisi**: Strumenti come IDA/Ghidra sono stati usati per esaminare i mach services raggiungibili, ma il processo è stato dispendioso in termini di tempo, complicato dalle chiamate che coinvolgono la dyld shared cache.
- **Limitazioni nello Scripting**: I tentativi di automatizzare l'analisi per chiamate a `xpc_connection_get_audit_token` da blocchi `dispatch_async` sono stati ostacolati dalle complessità nel parsing dei blocks e dalle interazioni con la dyld shared cache.

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: È stato inviato un report ad Apple descrivendo i problemi generali e specifici trovati in `smd`.
- **Apple's Response**: Apple ha risolto il problema in `smd` sostituendo `xpc_connection_get_audit_token` con `xpc_dictionary_get_audit_token`.
- **Nature of the Fix**: La funzione `xpc_dictionary_get_audit_token` è considerata sicura poiché recupera l'audit token direttamente dal mach message associato al messaggio XPC ricevuto. Tuttavia, non fa parte della public API, come `xpc_connection_get_audit_token`.
- **Absence of a Broader Fix**: Non è chiaro perché Apple non abbia implementato una correzione più ampia, come scartare messaggi che non corrispondono all'audit token salvato della connection. La possibilità di cambi legittimi dell'audit token in certi scenari (per esempio, uso di `setuid`) potrebbe essere un fattore.
- **Current Status**: Il problema persiste in iOS 17 e macOS 14, rappresentando una sfida per chi cerca di identificarlo e comprenderlo.

## Finding vulnerable code paths in practice (2024–2025)

Quando auditi servizi XPC per questa classe di bug, concentrati su autorizzazioni effettuate al di fuori dell'event handler del messaggio o concurrentemente con l'elaborazione delle reply.

Suggerimenti per triage statico:
- Cerca chiamate a `xpc_connection_get_audit_token` raggiungibili da blocchi messi in coda tramite `dispatch_async`/`dispatch_after` o altre worker queues che girano fuori dall'event handler del messaggio.
- Cerca helper di autorizzazione che mescolano stato per-connection e per-message (es. recuperano PID da `xpc_connection_get_pid` ma audit token da `xpc_connection_get_audit_token`).
- Nel codice NSXPC, verifica che i controlli siano fatti in `-listener:shouldAcceptNewConnection:` o, per i controlli per-messaggio, che l'implementazione usi un audit token per-messaggio (es. il dictionary del messaggio via `xpc_dictionary_get_audit_token` nel codice di basso livello).

Suggerimenti per triage dinamico:
- Hook `xpc_connection_get_audit_token` e segnala le invocazioni la cui user stack non include il path di delivery dell'evento (es. `_xpc_connection_mach_event`). Esempio Frida hook:
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
- Su macOS, l'instrumentazione di binari protetti/Apple potrebbe richiedere SIP disabilitato o un ambiente di sviluppo; preferisci testare le tue build o i servizi userland.
- Per reply-forwarding races (Variant 2), monitora il parsing concorrente dei reply packets fuzzando i timing di `xpc_connection_send_message_with_reply` rispetto a richieste normali e verificando se l'effettivo audit token usato durante l'autorizzazione può essere influenzato.

## Exploitation primitives you will likely need

- Multi-sender setup (Variant 1): crea connessioni a A e B; duplica il send right della client port di A e usalo come client port di B in modo che le replies di B vengano consegnate ad A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): cattura il send-once right dalla pending request di A (reply port), poi invia un crafted message a B usando quel reply port in modo che la reply di B arrivi su A mentre la tua privileged request viene parsata.

These require low-level mach message crafting for the XPC bootstrap and message formats; review the mach/XPC primer pages in this section for the exact packet layouts and flags.

## Strumenti utili

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) può aiutare a enumerare le connessioni e osservare il traffico per validare configurazioni multi-sender e il timing. Example: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose on `xpc_connection_send_message*` and `xpc_connection_get_audit_token` per registrare i call site e gli stack durante il black-box testing.



## Riferimenti

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
