# macOS xpc_connection_get_audit_token Attacco

{{#include ../../../../../../banners/hacktricks-training.md}}

**Per ulteriori informazioni controlla il post originale:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Questo è un riassunto:

## Informazioni di base sui messaggi Mach

Se non sai cosa sono i messaggi Mach inizia a controllare questa pagina:

{{#ref}}
../../
{{#endref}}

Per il momento ricorda che ([definizione da qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
I messaggi Mach vengono inviati tramite un _mach port_, che è un canale di comunicazione **a singolo ricevitore, multiplo mittente** integrato nel kernel mach. **Più processi possono inviare messaggi** a un mach port, ma in qualsiasi momento **solo un singolo processo può leggerli**. Proprio come i descrittori di file e i socket, i mach port sono allocati e gestiti dal kernel e i processi vedono solo un intero, che possono usare per indicare al kernel quale dei loro mach port vogliono utilizzare.

## Connessione XPC

Se non sai come viene stabilita una connessione XPC controlla:

{{#ref}}
../
{{#endref}}

## Riepilogo delle vulnerabilità

Ciò che è interessante sapere è che **l'astrazione di XPC è una connessione uno a uno**, ma si basa su una tecnologia che **può avere più mittenti, quindi:**

- I mach port sono a singolo ricevitore, **multiplo mittente**.
- Il token di audit di una connessione XPC è il token di audit **copiato dal messaggio ricevuto più di recente**.
- Ottenere il **token di audit** di una connessione XPC è fondamentale per molti **controlli di sicurezza**.

Sebbene la situazione precedente sembri promettente, ci sono alcuni scenari in cui questo non causerà problemi ([da qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- I token di audit sono spesso utilizzati per un controllo di autorizzazione per decidere se accettare una connessione. Poiché ciò avviene utilizzando un messaggio al servizio port, **non c'è ancora una connessione stabilita**. Ulteriori messaggi su questo port saranno semplicemente gestiti come richieste di connessione aggiuntive. Quindi eventuali **controlli prima di accettare una connessione non sono vulnerabili** (questo significa anche che all'interno di `-listener:shouldAcceptNewConnection:` il token di audit è sicuro). Stiamo quindi **cercando connessioni XPC che verificano azioni specifiche**.
- I gestori di eventi XPC vengono gestiti in modo sincrono. Ciò significa che il gestore di eventi per un messaggio deve essere completato prima di chiamarlo per il successivo, anche su code di dispatch concorrenti. Quindi all'interno di un **gestore di eventi XPC il token di audit non può essere sovrascritto** da altri messaggi normali (non di risposta!).

Due diversi metodi in cui questo potrebbe essere sfruttabile:

1. Variante1:
- **L'exploit** **si connette** al servizio **A** e al servizio **B**
- Il servizio **B** può chiamare una **funzionalità privilegiata** nel servizio A che l'utente non può
- Il servizio **A** chiama **`xpc_connection_get_audit_token`** mentre _**non**_ è all'interno del **gestore di eventi** per una connessione in un **`dispatch_async`**.
- Quindi un **messaggio diverso** potrebbe **sovrascrivere il Token di Audit** perché viene dispatchato in modo asincrono al di fuori del gestore di eventi.
- L'exploit passa a **servizio B il diritto di INVIO al servizio A**.
- Quindi svc **B** invierà effettivamente i **messaggi** al servizio **A**.
- L'**exploit** cerca di **chiamare** l'**azione privilegiata.** In un RC svc **A** **controlla** l'autorizzazione di questa **azione** mentre **svc B ha sovrascritto il Token di Audit** (dando all'exploit accesso per chiamare l'azione privilegiata).
2. Variante 2:
- Il servizio **B** può chiamare una **funzionalità privilegiata** nel servizio A che l'utente non può
- L'exploit si connette con **servizio A** che **invia** all'exploit un **messaggio che si aspetta una risposta** in un **port di risposta** specifico.
- L'exploit invia a **servizio** B un messaggio passando **quel port di risposta**.
- Quando il servizio **B risponde**, **invia il messaggio al servizio A**, **mentre** l'**exploit** invia un **messaggio diverso al servizio A** cercando di **raggiungere una funzionalità privilegiata** e aspettandosi che la risposta dal servizio B sovrascriva il Token di Audit nel momento perfetto (Race Condition).

## Variante 1: chiamare xpc_connection_get_audit_token al di fuori di un gestore di eventi <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Due servizi mach **`A`** e **`B`** a cui possiamo entrambi connetterci (basato sul profilo sandbox e sui controlli di autorizzazione prima di accettare la connessione).
- _**A**_ deve avere un **controllo di autorizzazione** per un'azione specifica che **`B`** può passare (ma la nostra app non può).
- Ad esempio, se B ha alcuni **diritti** o sta funzionando come **root**, potrebbe consentirgli di chiedere ad A di eseguire un'azione privilegiata.
- Per questo controllo di autorizzazione, **`A`** ottiene il token di audit in modo asincrono, ad esempio chiamando `xpc_connection_get_audit_token` da **`dispatch_async`**.

> [!CAUTION]
> In questo caso un attaccante potrebbe innescare una **Race Condition** creando un **exploit** che **chiede ad A di eseguire un'azione** più volte mentre fa **B inviare messaggi a `A`**. Quando il RC è **riuscito**, il **token di audit** di **B** sarà copiato in memoria **mentre** la richiesta del nostro **exploit** viene **gestita** da A, dandogli **accesso all'azione privilegiata che solo B potrebbe richiedere**.

Questo è accaduto con **`A`** come `smd` e **`B`** come `diagnosticd`. La funzione [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) di smb può essere utilizzata per installare un nuovo helper privilegiato (come **root**). Se un **processo in esecuzione come root contatta** **smd**, non verranno eseguiti altri controlli.

Pertanto, il servizio **B** è **`diagnosticd`** perché funziona come **root** e può essere utilizzato per **monitorare** un processo, quindi una volta avviato il monitoraggio, **invierà più messaggi al secondo.**

Per eseguire l'attacco:

1. Iniziare una **connessione** al servizio denominato `smd` utilizzando il protocollo XPC standard.
2. Formare una **connessione secondaria** a `diagnosticd`. Contrariamente alla procedura normale, invece di creare e inviare due nuovi mach port, il diritto di invio del port client viene sostituito con un duplicato del **diritto di invio** associato alla connessione `smd`.
3. Di conseguenza, i messaggi XPC possono essere dispatchati a `diagnosticd`, ma le risposte da `diagnosticd` vengono reindirizzate a `smd`. Per `smd`, sembra che i messaggi provenienti sia dall'utente che da `diagnosticd` provengano dalla stessa connessione.

![Immagine che rappresenta il processo di exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Il passo successivo implica istruire `diagnosticd` ad avviare il monitoraggio di un processo scelto (potenzialmente quello dell'utente). Contestualmente, viene inviato un afflusso di messaggi di routine 1004 a `smd`. L'intento qui è installare uno strumento con privilegi elevati.
5. Questa azione innesca una condizione di gara all'interno della funzione `handle_bless`. Il tempismo è critico: la chiamata alla funzione `xpc_connection_get_pid` deve restituire il PID del processo dell'utente (poiché lo strumento privilegiato risiede nel pacchetto dell'app dell'utente). Tuttavia, la funzione `xpc_connection_get_audit_token`, specificamente all'interno della sottoroutine `connection_is_authorized`, deve fare riferimento al token di audit appartenente a `diagnosticd`.

## Variante 2: inoltro della risposta

In un ambiente XPC (Cross-Process Communication), sebbene i gestori di eventi non vengano eseguiti in modo concorrente, la gestione dei messaggi di risposta ha un comportamento unico. In particolare, esistono due metodi distinti per inviare messaggi che si aspettano una risposta:

1. **`xpc_connection_send_message_with_reply`**: Qui, il messaggio XPC viene ricevuto e elaborato su una coda designata.
2. **`xpc_connection_send_message_with_reply_sync`**: Al contrario, in questo metodo, il messaggio XPC viene ricevuto e elaborato sulla coda di dispatch corrente.

Questa distinzione è cruciale perché consente la possibilità che i **pacchetti di risposta vengano analizzati in modo concorrente con l'esecuzione di un gestore di eventi XPC**. È importante notare che, mentre `_xpc_connection_set_creds` implementa il locking per proteggere contro la sovrascrittura parziale del token di audit, non estende questa protezione all'intero oggetto di connessione. Di conseguenza, ciò crea una vulnerabilità in cui il token di audit può essere sostituito durante l'intervallo tra l'analisi di un pacchetto e l'esecuzione del suo gestore di eventi.

Per sfruttare questa vulnerabilità, è necessaria la seguente configurazione:

- Due servizi mach, denominati **`A`** e **`B`**, entrambi in grado di stabilire una connessione.
- Il servizio **`A`** dovrebbe includere un controllo di autorizzazione per un'azione specifica che solo **`B`** può eseguire (l'applicazione dell'utente non può).
- Il servizio **`A`** dovrebbe inviare un messaggio che prevede una risposta.
- L'utente può inviare un messaggio a **`B`** a cui risponderà.

Il processo di sfruttamento coinvolge i seguenti passaggi:

1. Aspettare che il servizio **`A`** invii un messaggio che si aspetta una risposta.
2. Invece di rispondere direttamente a **`A`**, il port di risposta viene dirottato e utilizzato per inviare un messaggio al servizio **`B`**.
3. Successivamente, viene dispatchato un messaggio riguardante l'azione vietata, con l'aspettativa che venga elaborato in modo concorrente con la risposta da **`B`**.

Di seguito è riportata una rappresentazione visiva dello scenario di attacco descritto:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemi di scoperta

- **Difficoltà nel localizzare le istanze**: La ricerca di istanze di utilizzo di `xpc_connection_get_audit_token` è stata difficile, sia staticamente che dinamicamente.
- **Metodologia**: Frida è stata utilizzata per collegare la funzione `xpc_connection_get_audit_token`, filtrando le chiamate non provenienti da gestori di eventi. Tuttavia, questo metodo era limitato al processo collegato e richiedeva un utilizzo attivo.
- **Strumenti di analisi**: Strumenti come IDA/Ghidra sono stati utilizzati per esaminare i servizi mach raggiungibili, ma il processo è stato lungo, complicato da chiamate che coinvolgono la cache condivisa dyld.
- **Limitazioni di scripting**: I tentativi di scriptare l'analisi per le chiamate a `xpc_connection_get_audit_token` da blocchi `dispatch_async` sono stati ostacolati da complessità nell'analisi dei blocchi e interazioni con la cache condivisa dyld.

## La soluzione <a href="#the-fix" id="the-fix"></a>

- **Problemi segnalati**: È stata presentata una segnalazione ad Apple dettagliando i problemi generali e specifici riscontrati all'interno di `smd`.
- **Risposta di Apple**: Apple ha affrontato il problema in `smd` sostituendo `xpc_connection_get_audit_token` con `xpc_dictionary_get_audit_token`.
- **Natura della soluzione**: La funzione `xpc_dictionary_get_audit_token` è considerata sicura poiché recupera il token di audit direttamente dal messaggio mach legato al messaggio XPC ricevuto. Tuttavia, non fa parte dell'API pubblica, simile a `xpc_connection_get_audit_token`.
- **Assenza di una soluzione più ampia**: Rimane poco chiaro perché Apple non abbia implementato una soluzione più completa, come scartare i messaggi che non si allineano con il token di audit salvato della connessione. La possibilità di cambiamenti legittimi del token di audit in alcuni scenari (ad es., utilizzo di `setuid`) potrebbe essere un fattore.
- **Stato attuale**: Il problema persiste in iOS 17 e macOS 14, rappresentando una sfida per coloro che cercano di identificarlo e comprenderlo.

{{#include ../../../../../../banners/hacktricks-training.md}}
