# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

**Apple events** は、アプリケーションが他のアプリケーションに操作やデータを要求するために使用する、構造化されたプロセス間メッセージです。**Apple Event Manager** は、これらのメッセージの作成、送信、受信、応答を行うための API を提供します。<sup>[[1]](#references)</sup>

macOS では、主要なブローカーは `/System/Library/CoreServices/appleeventsd` で、`com.apple.coreservices.appleevents` Mach サービスを登録します。イベントを受信するアプリケーションは、このサービスに Apple-event Mach port を登録します。送信側は、このサービスを通じて宛先 port を取得します。<sup>[[3]](#references)</sup>

Sandbox のルールと entitlements によって、この通信は制限されます。Sandbox profile では、通常、必要な操作を `allow appleevent-send` と `com.apple.coreservices.appleevents` の Mach lookup として指定します。<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

公開されている `com.apple.security.temporary-exception.apple-events` entitlement を使うと、sandbox化されたアプリケーションの送信先を、指定した bundle identifier に制限できます。Apple署名済みのコンポーネントを分析する場合は、private entitlement である `com.apple.private.appleevents` も確認してください。private Apple entitlement は通常、サードパーティ製アプリケーションでは利用できません。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> **`AEDebugSends`** 環境変数を設定すると、プロセスが送信する Apple events に関する情報をログに記録できます。<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Automation grantを送信元と受信先に対応付ける方法については、[TCC Apple Events grants](index.html#identify-apple-events-sender-and-target-grants)を参照してください。



## References

- [1] [Apple Developer Documentation - Apple Event Manager（Apple Eventマネージャ）](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Temporary Exception Entitlements（App Sandbox一時例外Entitlements）](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables（Apple-eventデバッグ環境変数）](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
