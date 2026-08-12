# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

**Apple events** 是一种结构化的进程间消息，应用程序使用它们向其他应用程序请求操作或数据。**Apple Event Manager** 提供了创建、发送、接收和响应这些消息的 API。<sup>[[1]](#references)</sup>

在 macOS 上，主要 broker 是 `/System/Library/CoreServices/appleeventsd`，它注册了 `com.apple.coreservices.appleevents` Mach service。接收事件的应用程序会向此 service 注册 Apple-event Mach port；发送方则通过它获取目标 port。<sup>[[3]](#references)</sup>

Sandbox 规则和 entitlements 会限制这种通信。Sandbox profile 通常会将所需操作表示为 `allow appleevent-send`，并对 `com.apple.coreservices.appleevents` 执行 Mach lookup：<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
公开的 `com.apple.security.temporary-exception.apple-events` entitlement 可以将 sandboxed application 限制为指定的目标 bundle identifiers。在分析 Apple-signed components 时，还应检查私有的 `com.apple.private.appleevents` entitlement；私有 Apple entitlements 通常不向第三方 applications 提供。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> 设置 **`AEDebugSends`** environment variable，可以记录进程发送的 Apple events 信息：<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox 临时例外 Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event 调试环境变量](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
