# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

**Apple Events**는 애플의 macOS에서 애플리케이션 간의 통신을 가능하게 하는 기능입니다. 이는 macOS 운영 체제의 구성 요소인 **Apple Event Manager**의 일부로, 프로세스 간 통신을 처리하는 역할을 합니다. 이 시스템은 한 애플리케이션이 다른 애플리케이션에 메시지를 보내 특정 작업을 수행하도록 요청할 수 있게 합니다. 예를 들어, 파일을 열거나, 데이터를 검색하거나, 명령을 실행하는 등의 작업입니다.

mina 데몬은 `/System/Library/CoreServices/appleeventsd`로, 서비스 `com.apple.coreservices.appleevents`를 등록합니다.

이벤트를 받을 수 있는 모든 애플리케이션은 이 데몬과 함께 자신의 Apple Event Mach Port를 제공하여 확인합니다. 그리고 애플리케이션이 이벤트를 보내고자 할 때, 해당 애플리케이션은 데몬으로부터 이 포트를 요청합니다.

샌드박스 애플리케이션은 이벤트를 보낼 수 있도록 `allow appleevent-send` 및 `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`와 같은 권한이 필요합니다. `com.apple.security.temporary-exception.apple-events`와 같은 권한은 이벤트를 보낼 수 있는 접근을 제한할 수 있으며, 이는 `com.apple.private.appleevents`와 같은 권한이 필요합니다.

> [!TIP]
> 메시지 전송에 대한 정보를 기록하기 위해 env 변수 **`AEDebugSends`**를 사용할 수 있습니다:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
