# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 기본 정보

**Apple events**는 애플리케이션이 다른 애플리케이션에 작업이나 데이터를 요청하는 데 사용하는 구조화된 프로세스 간 메시지입니다. **Apple Event Manager**는 이러한 메시지를 생성, 전송, 수신하고 응답하기 위한 API를 제공합니다.<sup>[[1]](#references)</sup>

macOS에서 주요 broker는 `/System/Library/CoreServices/appleeventsd`이며, `com.apple.coreservices.appleevents` Mach service를 등록합니다. 이벤트를 수신하는 애플리케이션은 이 service에 Apple-event Mach port를 등록하고, sender는 이를 통해 destination port를 가져옵니다.<sup>[[3]](#references)</sup>

Sandbox 규칙과 entitlement는 이 통신을 제한합니다. Sandbox profile은 일반적으로 필요한 작업을 `allow appleevent-send`와 `com.apple.coreservices.appleevents`에 대한 Mach lookup으로 표현합니다:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
공개된 `com.apple.security.temporary-exception.apple-events` entitlement는 sandboxed application을 이름이 지정된 destination bundle identifier로 제한할 수 있습니다. Apple-signed components를 분석할 때는 private `com.apple.private.appleevents` entitlement도 확인해야 합니다. private Apple entitlements는 일반적으로 third-party applications에서 사용할 수 없습니다.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> 프로세스가 보낸 Apple events에 대한 정보를 기록하려면 **`AEDebugSends`** environment variable을 설정합니다:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
