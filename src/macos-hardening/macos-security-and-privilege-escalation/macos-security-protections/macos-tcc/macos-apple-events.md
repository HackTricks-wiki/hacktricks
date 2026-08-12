# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

**Apple events** は、アプリケーションが他のアプリケーションに操作やデータを要求するために使用する、構造化されたプロセス間メッセージです。**Apple Event Manager** は、これらのメッセージを作成、送信、受信、応答するための API を提供します。<sup>[[1]](#references)</sup>

macOS では、主な broker は `/System/Library/CoreServices/appleeventsd` であり、`com.apple.coreservices.appleevents` Mach service を登録します。イベントを受信するアプリケーションは、この service に Apple-event Mach port を登録し、送信側はこの service を介して宛先 port を取得します。<sup>[[3]](#references)</sup>

Sandbox のルールと entitlements によって、この通信は制限されます。Sandbox profile では通常、必要な操作を `allow appleevent-send` と、`com.apple.coreservices.appleevents` に対する Mach lookup として表現します。<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
公開されている `com.apple.security.temporary-exception.apple-events` entitlement は、sandboxed application を名前付きの宛先 bundle identifier に制限できます。Apple-signed components を分析する際は、private の `com.apple.private.appleevents` entitlement も確認してください。private Apple entitlements は通常、third-party applications では利用できません。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> プロセスから送信された Apple events の情報をログに記録するには、**`AEDebugSends`** 環境変数を設定します:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
