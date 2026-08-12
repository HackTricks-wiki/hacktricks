# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

**Apple events** is gestruktureerde interproses-boodskappe wat toepassings gebruik om bewerkings of data van ander toepassings te versoek. Die **Apple Event Manager** verskaf die APIs vir die skep, stuur, ontvang en beantwoording van hierdie boodskappe.<sup>[[1]](#references)</sup>

Op macOS is die hoofmakelaar `/System/Library/CoreServices/appleeventsd`, wat die `com.apple.coreservices.appleevents` Mach-diens registreer. Toepassings wat events ontvang, registreer 'n Apple-event Mach-poort by hierdie diens; senders verkry die bestemmingspoort daardeur.<sup>[[3]](#references)</sup>

Sandbox-reëls en entitlements beperk hierdie kommunikasie. 'n Sandbox-profiel druk die vereiste bewerkings gewoonlik uit as `allow appleevent-send` en 'n Mach-lookup vir `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
Die publieke `com.apple.security.temporary-exception.apple-events` entitlement kan 'n sandboxed toepassing beperk tot benoemde bestemming-bundle-identifiers. Wanneer Apple-ondertekende komponente ontleed word, moet die private `com.apple.private.appleevents` entitlement ook nagegaan word; private Apple entitlements is normaalweg nie vir derdeparty-toepassings beskikbaar nie.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Stel die **`AEDebugSends`**-omgewingsveranderlike in om inligting oor Apple events wat deur 'n proses gestuur word, te log:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
