# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

**Apple events** ni ujumbe wa interprocess ulioundwa kwa muundo maalum ambao applications hutumia kuomba utendakazi au data kutoka kwa applications nyingine. **Apple Event Manager** hutoa APIs za kuunda, kutuma, kupokea na kujibu ujumbe huu.<sup>[[1]](#references)</sup>

Kwenye macOS, broker mkuu ni `/System/Library/CoreServices/appleeventsd`, ambao husajili huduma ya Mach `com.apple.coreservices.appleevents`. Applications zinazopokea events husajili Apple-event Mach port kwa huduma hii; watumaji hupata destination port kupitia huduma hiyo.<sup>[[3]](#references)</sup>

Sheria za sandbox na entitlements hupunguza mawasiliano haya. Sandbox profile inahitaji ruhusa ya kutuma Apple events na kutafuta huduma ya Mach ya broker. Entitlement ya `com.apple.security.temporary-exception.apple-events` inaweza kuzuia zaidi application iliyo kwenye sandbox kutuma kwa destination bundle identifiers zilizotajwa pekee.<sup>[[2]](#references)</sup>

> [!TIP]
> Weka environment variable ya **`AEDebugSends`** ili kurekodi taarifa kuhusu Apple events zinazotumwa na process:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
