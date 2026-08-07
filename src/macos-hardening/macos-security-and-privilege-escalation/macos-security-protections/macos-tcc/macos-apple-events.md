# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## 기본 정보

**Apple Events**는 애플리케이션이 서로 통신할 수 있도록 하는 Apple macOS의 기능입니다. 이는 프로세스 간 통신을 처리하는 macOS 운영 체제 구성 요소인 **Apple Event Manager**의 일부입니다. 이 시스템을 사용하면 한 애플리케이션이 다른 애플리케이션에 메시지를 보내 파일 열기, 데이터 가져오기 또는 명령 실행과 같은 특정 작업을 수행하도록 요청할 수 있습니다.

주요 daemon은 `/System/Library/CoreServices/appleeventsd`이며, `com.apple.coreservices.appleevents` 서비스를 등록합니다.

이벤트를 수신할 수 있는 모든 애플리케이션은 Apple Event Mach Port를 제공하여 이 daemon에 등록합니다. 애플리케이션이 해당 애플리케이션으로 이벤트를 보내려는 경우, daemon에 이 port를 요청합니다.

Sandboxed 애플리케이션이 이벤트를 보낼 수 있으려면 `allow appleevent-send` 및 `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`와 같은 권한이 필요합니다. `com.apple.security.temporary-exception.apple-events`와 같은 entitlement는 이벤트 전송 권한이 있는 대상을 제한할 수 있으며, 이 경우 `com.apple.private.appleevents`와 같은 entitlement가 필요합니다.

> [!TIP]
> 전송된 메시지에 대한 정보를 기록하려면 환경 변수 **`AEDebugSends`**를 사용할 수 있습니다.
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
