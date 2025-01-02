# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

**Apple Events** 是苹果 macOS 中的一个功能，允许应用程序相互通信。它们是 **Apple Event Manager** 的一部分，这是 macOS 操作系统中负责处理进程间通信的组件。该系统使一个应用程序能够向另一个应用程序发送消息，请求其执行特定操作，例如打开文件、检索数据或执行命令。

mina 守护进程是 `/System/Library/CoreServices/appleeventsd`，它注册了服务 `com.apple.coreservices.appleevents`。

每个可以接收事件的应用程序都会与此守护进程检查，提供其 Apple Event Mach Port。当一个应用程序想要向其发送事件时，该应用程序将向守护进程请求此端口。

沙盒应用程序需要特权，如 `allow appleevent-send` 和 `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`，才能发送事件。注意，像 `com.apple.security.temporary-exception.apple-events` 的权限可能会限制谁可以发送事件，这将需要像 `com.apple.private.appleevents` 的权限。

> [!TIP]
> 可以使用环境变量 **`AEDebugSends`** 来记录发送的消息的信息：
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
