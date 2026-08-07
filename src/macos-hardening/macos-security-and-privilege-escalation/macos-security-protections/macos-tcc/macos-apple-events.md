# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

**Apple Events** è una funzionalità di macOS di Apple che consente alle applicazioni di comunicare tra loro. Fa parte dell'**Apple Event Manager**, un componente del sistema operativo macOS responsabile della gestione della comunicazione tra processi. Questo sistema consente a un'applicazione di inviare un messaggio a un'altra applicazione per richiederle di eseguire una determinata operazione, come aprire un file, recuperare dati o eseguire un comando.

Il daemon principale è `/System/Library/CoreServices/appleeventsd`, che registra il servizio `com.apple.coreservices.appleevents`.

Ogni applicazione in grado di ricevere eventi comunica con questo daemon fornendo la propria Apple Event Mach Port. Quando un'app vuole inviarle un evento, richiede questa porta al daemon.

Le applicazioni in sandbox richiedono privilegi come `allow appleevent-send` e `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` per poter inviare eventi. Tuttavia, entitlements come `com.apple.security.temporary-exception.apple-events` possono limitare chi ha accesso all'invio di eventi, il quale richiederà entitlements come `com.apple.private.appleevents`.

> [!TIP]
> È possibile utilizzare la variabile d'ambiente **`AEDebugSends`** per registrare informazioni sul messaggio inviato:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
