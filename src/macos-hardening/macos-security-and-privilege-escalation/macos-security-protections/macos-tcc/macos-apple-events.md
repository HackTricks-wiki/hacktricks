# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

**Apple events** 是结构化的进程间消息，应用程序使用它们向其他应用程序请求操作或数据。**Apple Event Manager** 提供用于创建、发送、接收和响应这些消息的 API。<sup>[[1]](#references)</sup>

在 macOS 上，主要的 broker 是 `/System/Library/CoreServices/appleeventsd`，它注册了 `com.apple.coreservices.appleevents` Mach 服务。接收事件的应用程序会向此服务注册一个 Apple-event Mach 端口；发送方则通过此服务获取目标端口。<sup>[[3]](#references)</sup>

Sandbox 规则和 entitlement 限制了这种通信。Sandbox profile 通常通过 `allow appleevent-send` 和对 `com.apple.coreservices.appleevents` 的 Mach lookup 来声明所需操作：<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

公开的 `com.apple.security.temporary-exception.apple-events` entitlement 可将沙盒应用限制为向指定的目标 bundle identifier 发送 Apple events。分析 Apple 签名的组件时，也要检查私有的 `com.apple.private.appleevents` entitlement；私有 Apple entitlement 通常不向第三方应用开放。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> 设置 **`AEDebugSends`** 环境变量，以记录进程发送的 Apple events 信息：<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

要将 Automation 授权映射到其发送方和接收方，请参阅 [TCC Apple Events 授权](index.html#identify-apple-events-sender-and-target-grants)。



## References

- [1] [Apple 开发者文档 - Apple Event 管理器](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple 开发者文档 - App Sandbox 临时例外授权](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X 和 iOS 内部机制 - Apple-event 调试环境变量](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
