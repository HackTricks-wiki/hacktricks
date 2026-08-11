# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## मूल जानकारी

**Apple events** संरचित interprocess messages हैं, जिनका उपयोग applications अन्य applications से operations या data का अनुरोध करने के लिए करती हैं। **Apple Event Manager** इन messages को बनाने, भेजने, प्राप्त करने और इनके उत्तर देने के लिए APIs प्रदान करता है।<sup>[[1]](#references)</sup>

macOS पर मुख्य broker `/System/Library/CoreServices/appleeventsd` है, जो `com.apple.coreservices.appleevents` Mach service को register करता है। Events प्राप्त करने वाली applications इस service के साथ Apple-event Mach port register करती हैं; senders इसके माध्यम से destination port प्राप्त करते हैं।<sup>[[3]](#references)</sup>

Sandbox rules और entitlements इस communication को सीमित करते हैं। किसी sandbox profile को Apple events भेजने और broker की Mach service देखने की अनुमति चाहिए। `com.apple.security.temporary-exception.apple-events` entitlement किसी sandboxed application को named destination bundle identifiers तक और अधिक सीमित कर सकता है।<sup>[[2]](#references)</sup>

> [!TIP]
> किसी process द्वारा भेजे गए Apple events की information log करने के लिए **`AEDebugSends`** environment variable सेट करें:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
