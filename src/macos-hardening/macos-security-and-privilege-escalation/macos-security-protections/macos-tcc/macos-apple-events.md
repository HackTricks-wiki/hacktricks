# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 기본 정보

**Apple events**는 애플리케이션이 다른 애플리케이션에 작업이나 데이터를 요청할 때 사용하는 구조화된 프로세스 간 메시지입니다. **Apple Event Manager**는 이러한 메시지를 생성, 전송, 수신 및 응답하는 API를 제공합니다.<sup>[[1]](#references)</sup>

macOS에서 주요 브로커는 `/System/Library/CoreServices/appleeventsd`이며, `com.apple.coreservices.appleevents` Mach 서비스를 등록합니다. 이벤트를 수신하는 애플리케이션은 이 서비스에 Apple-event Mach 포트를 등록하고, 전송자는 이 서비스를 통해 대상 포트를 가져옵니다.<sup>[[3]](#references)</sup>

Sandbox 규칙과 entitlement는 이러한 통신을 제한합니다. Sandbox 프로필에는 일반적으로 필요한 작업으로 `allow appleevent-send`와 `com.apple.coreservices.appleevents`에 대한 Mach lookup이 지정됩니다:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

공개 `com.apple.security.temporary-exception.apple-events` entitlement를 사용하면 sandboxed 애플리케이션이 지정된 대상 bundle identifier로 제한될 수 있습니다. Apple 서명 구성 요소를 분석할 때는 비공개 `com.apple.private.appleevents` entitlement도 확인하세요. 비공개 Apple entitlement는 일반적으로 서드파티 애플리케이션에서 사용할 수 없습니다.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> **`AEDebugSends`** 환경 변수를 설정하면 프로세스가 보낸 Apple events에 관한 정보를 로그로 기록할 수 있습니다:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Automation 권한 부여를 발신자와 수신자에 연결하는 방법은 [TCC Apple Events 권한 부여](index.html#identify-apple-events-sender-and-target-grants)를 참조하세요.



## References

- [1] [Apple 개발자 문서 - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple 개발자 문서 - App Sandbox 임시 예외 권한](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X 및 iOS 내부 - Apple-event 디버그 환경 변수](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
