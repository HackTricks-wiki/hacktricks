# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Gli **Apple events** sono messaggi interprocesso strutturati che le applicazioni utilizzano per richiedere operazioni o dati ad altre applicazioni. **Apple Event Manager** fornisce le API per creare, inviare, ricevere e rispondere a questi messaggi.<sup>[[1]](#references)</sup>

Su macOS, il broker principale è `/System/Library/CoreServices/appleeventsd`, che registra il Mach service `com.apple.coreservices.appleevents`. Le applicazioni che ricevono eventi registrano una porta Mach Apple-event presso questo servizio; i mittenti ottengono attraverso di esso la porta di destinazione.<sup>[[3]](#references)</sup>

Le regole della sandbox e gli entitlement limitano questa comunicazione. Un profilo sandbox esprime comunemente le operazioni richieste come `allow appleevent-send` e una ricerca Mach per `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
Il entitlement pubblico `com.apple.security.temporary-exception.apple-events` può limitare un'applicazione sandboxed agli identificatori bundle delle destinazioni nominate. Quando analizzi componenti firmati da Apple, controlla anche l'entitlement privato `com.apple.private.appleevents`; gli entitlement privati di Apple normalmente non sono disponibili per applicazioni di terze parti.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Imposta la variabile d'ambiente **`AEDebugSends`** per registrare informazioni sugli Apple events inviati da un processo:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Documentazione Apple Developer - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Documentazione Apple Developer - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Variabili d'ambiente di debug degli Apple event](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
