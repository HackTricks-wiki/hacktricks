# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

**Apple Events** is 'n kenmerk in Apple se macOS wat toelaat dat toepassings met mekaar kommunikeer. Dit is deel van die **Apple Event Manager**, wat 'n komponent van die macOS-bedryfstelsel is wat verantwoordelik is vir die hantering van interproses kommunikasie. Hierdie stelsel stel een toepassing in staat om 'n boodskap aan 'n ander toepassing te stuur om te vra dat dit 'n spesifieke operasie uitvoer, soos om 'n lêer te open, data te verkry, of 'n opdrag uit te voer.

Die mina daemon is `/System/Library/CoreServices/appleeventsd` wat die diens `com.apple.coreservices.appleevents` registreer.

Elke toepassing wat gebeurtenisse kan ontvang, sal met hierdie daemon nagaan deur sy Apple Event Mach Port te verskaf. En wanneer 'n app 'n gebeurtenis na dit wil stuur, sal die app hierdie port van die daemon aan vra.

Sandboxed toepassings vereis voorregte soos `allow appleevent-send` en `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` om in staat te wees om gebeurtenisse te stuur. Let daarop dat regte soos `com.apple.security.temporary-exception.apple-events` kan beperk wie toegang het om gebeurtenisse te stuur, wat regte soos `com.apple.private.appleevents` sal benodig.

> [!TIP]
> Dit is moontlik om die env veranderlike **`AEDebugSends`** te gebruik om inligting oor die gestuurde boodskap te log:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
