# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

**Apple events** sono messaggi interprocesso strutturati che le applicazioni usano per richiedere operazioni o dati ad altre applicazioni. **Apple Event Manager** fornisce le API per creare, inviare, ricevere e gestire questi messaggi.<sup>[[1]](#references)</sup>

Su macOS, il broker principale è `/System/Library/CoreServices/appleeventsd`, che registra il servizio Mach `com.apple.coreservices.appleevents`. Le applicazioni che ricevono eventi registrano una porta Mach per Apple event presso questo servizio; i mittenti ne ottengono la porta di destinazione tramite il servizio.<sup>[[3]](#references)</sup>

Le regole della sandbox e gli entitlement limitano questa comunicazione. Un profilo sandbox esprime comunemente le operazioni richieste come `allow appleevent-send` e una ricerca Mach per `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

L’entitlement pubblico `com.apple.security.temporary-exception.apple-events` può limitare un’applicazione sandboxed agli identificatori dei bundle di destinazione specificati. Quando analizzi componenti firmati da Apple, verifica anche la presenza dell’entitlement privato `com.apple.private.appleevents`; gli entitlement privati di Apple non sono normalmente disponibili alle applicazioni di terze parti.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Imposta la variabile d’ambiente **`AEDebugSends`** per registrare informazioni sugli Apple event inviati da un processo:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Per associare un’autorizzazione Automation al mittente e al destinatario, consulta [Autorizzazioni TCC Apple Events](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Documentazione Apple Developer - Gestore Apple Event](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Documentazione Apple Developer - Entitlement per eccezioni temporanee di App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X e iOS Internals - Variabili d’ambiente di debug di Apple-event](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
