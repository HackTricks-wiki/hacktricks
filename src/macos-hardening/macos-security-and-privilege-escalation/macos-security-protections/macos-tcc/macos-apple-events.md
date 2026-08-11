# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Gli **Apple events** sono messaggi strutturati tra processi che le applicazioni utilizzano per richiedere operazioni o dati ad altre applicazioni. **Apple Event Manager** fornisce le API per creare, inviare, ricevere e rispondere a questi messaggi.<sup>[[1]](#references)</sup>

Su macOS, il broker principale è `/System/Library/CoreServices/appleeventsd`, che registra il servizio Mach `com.apple.coreservices.appleevents`. Le applicazioni che ricevono eventi registrano una porta Mach Apple-event presso questo servizio; i mittenti ottengono tramite esso la porta di destinazione.<sup>[[3]](#references)</sup>

Le regole della sandbox e gli entitlement limitano questa comunicazione. Un profilo sandbox deve avere l'autorizzazione a inviare Apple events e a cercare il servizio Mach del broker. L'entitlement `com.apple.security.temporary-exception.apple-events` può limitare ulteriormente un'applicazione in sandbox agli identificatori bundle delle destinazioni specificate.<sup>[[2]](#references)</sup>

> [!TIP]
> Imposta la variabile d'ambiente **`AEDebugSends`** per registrare informazioni sugli Apple events inviati da un processo:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Documentazione Apple per gli sviluppatori - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Documentazione Apple per gli sviluppatori - Entitlement per le eccezioni temporanee della App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Internals di Mac OS X e iOS - Variabili d'ambiente di debug degli Apple event](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
