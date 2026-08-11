# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

**Apple events** 是一种结构化的进程间消息，应用程序使用它们向其他应用程序请求操作或数据。**Apple Event Manager** 提供用于创建、发送、接收和响应这些消息的 API。<sup>[[1]](#references)</sup>

在 macOS 上，主要 broker 是 `/System/Library/CoreServices/appleeventsd`，它注册了 `com.apple.coreservices.appleevents` Mach service。接收事件的应用程序会向该 service 注册一个 Apple-event Mach port；发送方则通过它获取目标 port。<sup>[[3]](#references)</sup>

Sandbox 规则和 entitlements 会限制这种通信。Sandbox profile 需要具备发送 Apple events 以及查找 broker 的 Mach service 的权限。`com.apple.security.temporary-exception.apple-events` entitlement 还可以进一步将 sandboxed application 限制为指定的目标 bundle identifiers。<sup>[[2]](#references)</sup>

> [!TIP]
> 设置 **`AEDebugSends`** 环境变量，可以记录进程发送的 Apple events 信息：<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
