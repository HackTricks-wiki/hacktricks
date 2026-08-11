# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

**Apple events** are structured interprocess messages that applications use to request operations or data from other applications. The **Apple Event Manager** provides the APIs for creating, sending, receiving, and responding to these messages.<sup>[[1]](#references)</sup>

On macOS, the principal broker is `/System/Library/CoreServices/appleeventsd`, which registers the `com.apple.coreservices.appleevents` Mach service. Applications that receive events register an Apple-event Mach port with this service; senders obtain the destination port through it.<sup>[[3]](#references)</sup>

Sandbox rules and entitlements limit this communication. A sandbox profile commonly expresses the required operations as `allow appleevent-send` and a Mach lookup for `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

The public `com.apple.security.temporary-exception.apple-events` entitlement can restrict a sandboxed application to named destination bundle identifiers. When analyzing Apple-signed components, also check for the private `com.apple.private.appleevents` entitlement; private Apple entitlements are not normally available to third-party applications.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Set the **`AEDebugSends`** environment variable to log information about Apple events sent by a process:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
