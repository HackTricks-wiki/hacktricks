# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

**Apple Events** 是 Apple macOS 中的一项功能，允许应用程序相互通信。它们属于 **Apple Event Manager**，这是 macOS 操作系统中负责处理进程间通信的组件。该系统使一个应用程序能够向另一个应用程序发送消息，请求其执行特定操作，例如打开文件、检索数据或执行命令。

主要 daemon 是 `/System/Library/CoreServices/appleeventsd`，它注册了服务 `com.apple.coreservices.appleevents`。

每个能够接收事件的应用程序都会向该 daemon 注册，并提供其 Apple Event Mach Port。当某个应用程序希望向其发送事件时，该应用程序会向 daemon 请求此端口。

Sandboxed 应用程序需要 `allow appleevent-send` 和 `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` 等权限才能发送事件。请注意，`com.apple.security.temporary-exception.apple-events` 等 entitlement 可能会限制哪些对象有权发送事件，而这需要 `com.apple.private.appleevents` 等 entitlement。

> [!TIP]
> 可以使用环境变量 **`AEDebugSends`** 记录有关已发送消息的信息：
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
