# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

**Apple Events** is 'n funksie in Apple se macOS wat toepassings toelaat om met mekaar te kommunikeer. Hulle vorm deel van die **Apple Event Manager**, wat 'n komponent van die macOS-bedryfstelsel is wat verantwoordelik is vir die hantering van interproseskommunikasie. Hierdie stelsel stel een toepassing in staat om 'n boodskap aan 'n ander toepassing te stuur om te versoek dat dit 'n bepaalde bewerking uitvoer, soos om 'n lêer oop te maak, data te verkry of 'n opdrag uit te voer.

Die hoof-daemon is `/System/Library/CoreServices/appleeventsd`, wat die diens `com.apple.coreservices.appleevents` registreer.

Elke toepassing wat events kan ontvang, sal by hierdie daemon registreer deur sy Apple Event Mach Port te verskaf. Wanneer 'n toepassing 'n event daarheen wil stuur, sal die toepassing hierdie port by die daemon aanvra.

Sandboxed applications benodig voorregte soos `allow appleevent-send` en `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` om events te kan stuur. Let daarop dat entitlements soos `com.apple.security.temporary-exception.apple-events` kan beperk wie toegang het om events te stuur, wat entitlements soos `com.apple.private.appleevents` sal vereis.

> [!TIP]
> Dit is moontlik om die omgewingsveranderlike **`AEDebugSends`** te gebruik om inligting oor die gestuurde boodskap te log:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
