# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese inligting

**Apple events** is gestruktureerde interprosesboodskappe wat toepassings gebruik om bewerkings of data van ander toepassings aan te vra. Die **Apple Event Manager** bied die API's om hierdie boodskappe te skep, te stuur, te ontvang en daarop te reageer.<sup>[[1]](#references)</sup>

Op macOS is die hoofmakelaar `/System/Library/CoreServices/appleeventsd`, wat die `com.apple.coreservices.appleevents` Mach-diens registreer. Toepassings wat gebeure ontvang, registreer 'n Apple-event Mach-poort by hierdie diens; senders verkry die bestemmingspoort daardeur.<sup>[[3]](#references)</sup>

Sandbox-reëls en regte beperk hierdie kommunikasie. 'n Sandbox-profiel druk die vereiste bewerkings gewoonlik uit as `allow appleevent-send` en 'n Mach-opsoek vir `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

Die publieke `com.apple.security.temporary-exception.apple-events`-entitlement kan ’n toepassing in ’n sandbox beperk tot benoemde bestemmingsbondel-identifiseerders. Wanneer jy Apple-ondertekende komponente ontleed, kyk ook na die private `com.apple.private.appleevents`-entitlement; private Apple-entitlements is gewoonlik nie vir derdepartytoepassings beskikbaar nie.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Stel die **`AEDebugSends`**-omgewingsveranderlike om inligting oor Apple events wat deur ’n proses gestuur word, aan te teken:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Om 'n Automation-toestemming aan sy sender en ontvanger te koppel, sien [TCC Apple Events-toestemmings](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Apple-ontwikkelaardokumentasie - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple-ontwikkelaardokumentasie - Tydelike uitsonderingstoestemmings vir App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X en iOS-internals - Apple-event-ontfoutingsomgewingsveranderlikes](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
