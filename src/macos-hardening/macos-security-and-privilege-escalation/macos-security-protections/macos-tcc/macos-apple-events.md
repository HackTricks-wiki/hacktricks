# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese inligting

**Apple events** is gestruktureerde interprosesboodskappe wat toepassings gebruik om bewerkings of data van ander toepassings te versoek. Die **Apple Event Manager** verskaf die API's vir die skep, stuur, ontvangs en beantwoording van hierdie boodskappe.<sup>[[1]](#references)</sup>

Op macOS is die hoofmakelaar `/System/Library/CoreServices/appleeventsd`, wat die `com.apple.coreservices.appleevents` Mach-diens registreer. Toepassings wat events ontvang, registreer 'n Apple-event Mach-poort by hierdie diens; senders verkry die bestemmingspoort daardeur.<sup>[[3]](#references)</sup>

Sandbox-reëls en entitlements beperk hierdie kommunikasie. 'n Sandbox-profiel benodig toestemming om Apple events te stuur en die makelaar se Mach-diens op te soek. Die `com.apple.security.temporary-exception.apple-events` entitlement kan 'n sandbox-toepassing verder beperk tot benoemde bestemmings-bundel-identifiseerders.<sup>[[2]](#references)</sup>

> [!TIP]
> Stel die **`AEDebugSends`**-omgewingsveranderlike om inligting oor Apple events wat deur 'n proses gestuur word, te log:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple-ontwikkelaardokumentasie - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple-ontwikkelaardokumentasie - Tydelike uitsonderings-entitlements vir App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X en iOS Internals - Apple-event-ontfoutingsomgewingsveranderlikes](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
