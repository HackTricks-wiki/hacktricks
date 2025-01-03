# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

**Apple Events** sono una funzionalità del macOS di Apple che consente alle applicazioni di comunicare tra loro. Fanno parte del **Apple Event Manager**, che è un componente del sistema operativo macOS responsabile della gestione della comunicazione interprocesso. Questo sistema consente a un'applicazione di inviare un messaggio a un'altra applicazione per richiedere che esegua un'operazione particolare, come aprire un file, recuperare dati o eseguire un comando.

Il daemon mina è `/System/Library/CoreServices/appleeventsd` che registra il servizio `com.apple.coreservices.appleevents`.

Ogni applicazione che può ricevere eventi verificherà con questo daemon fornendo il suo Apple Event Mach Port. E quando un'app vuole inviare un evento a esso, l'app richiederà questo port dal daemon.

Le applicazioni sandboxed richiedono privilegi come `allow appleevent-send` e `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` per poter inviare eventi. Si noti che le autorizzazioni come `com.apple.security.temporary-exception.apple-events` potrebbero limitare chi ha accesso per inviare eventi, il che richiederà autorizzazioni come `com.apple.private.appleevents`.

> [!TIP]
> È possibile utilizzare la variabile env **`AEDebugSends`** per registrare informazioni sul messaggio inviato:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
