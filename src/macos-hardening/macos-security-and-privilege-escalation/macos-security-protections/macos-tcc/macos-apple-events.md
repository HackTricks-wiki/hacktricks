# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

**Apple events** ni ujumbe wa interprocess ulioundwa kwa muundo maalum ambao applications hutumia kuomba operesheni au data kutoka kwa applications nyingine. **Apple Event Manager** hutoa APIs za kuunda, kutuma, kupokea na kujibu ujumbe huu.<sup>[[1]](#references)</sup>

Kwenye macOS, broker mkuu ni `/System/Library/CoreServices/appleeventsd`, unaosajili Mach service ya `com.apple.coreservices.appleevents`. Applications zinazopokea events husajili Apple-event Mach port kwenye service hii; senders hupata destination port kupitia service hiyo.<sup>[[3]](#references)</sup>

Sheria za sandbox na entitlements hupunguza mawasiliano haya. Sandbox profile kwa kawaida huonyesha operesheni zinazohitajika kama `allow appleevent-send` na Mach lookup ya `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
Entitlement ya umma ya `com.apple.security.temporary-exception.apple-events` inaweza kuzuia application iliyo kwenye sandbox kutuma kwa destination bundle identifiers zilizotajwa. Unapochanganua components zilizosainiwa na Apple, pia kagua entitlement ya private `com.apple.private.appleevents`; private Apple entitlements kwa kawaida hazipatikani kwa applications za third-party.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Weka environment variable ya **`AEDebugSends`** ili kurekodi taarifa kuhusu Apple events zinazotumwa na process:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - Entitlements za Temporary Exception za App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
