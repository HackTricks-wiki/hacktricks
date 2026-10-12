# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 기본 정보

XPC는 macOS 및 iOS에서 **프로세스 간 통신**을 위한 프레임워크입니다. 프로세스 간에 **안전하고 비동기적인 호출**을 수행하는 메커니즘을 제공합니다. XPC는 **권한이 분리된 애플리케이션**을 지원하며, 각 **구성 요소**는 **필요한 권한만으로** 실행되어 프로세스가 손상되었을 때 발생할 수 있는 피해를 제한합니다.<sup>[[1]](#references)</sup>

XPC는 같은 시스템에서 실행되는 서로 다른 프로그램이 데이터를 주고받기 위한 일련의 메서드인 프로세스 간 통신(IPC)의 한 형태를 사용합니다.

XPC의 주요 장점은 다음과 같습니다.

1. **보안**: 작업을 여러 프로세스로 나누면 각 프로세스에 필요한 권한만 부여할 수 있습니다. 따라서 프로세스가 손상되더라도 피해를 일으킬 수 있는 범위가 제한됩니다.
2. **안정성**: XPC는 충돌이 발생한 구성 요소에만 영향을 주도록 격리합니다. 프로세스가 충돌하면 시스템의 나머지 부분에 영향을 주지 않고 다시 시작할 수 있습니다.
3. **성능**: XPC를 사용하면 서로 다른 프로세스에서 여러 작업을 동시에 실행할 수 있어 동시성 처리가 간편합니다.

주요 **단점**은 **애플리케이션을 여러 프로세스로 나누고** XPC를 통해 통신하게 하면 오버헤드가 발생한다는 것입니다. 최신 시스템에서는 이 오버헤드가 보통 보안 및 안정성 측면의 이점에 비해 작습니다.<sup>[[1]](#references)</sup>

## 애플리케이션별 XPC 서비스

애플리케이션의 XPC 구성 요소는 **애플리케이션 내부에** 있습니다. 예를 들어 Safari에서는 **`/Applications/Safari.app/Contents/XPCServices`**에서 찾을 수 있습니다. 이러한 구성 요소의 확장자는 **`.xpc`**(예: **`com.apple.Safari.SandboxBroker.xpc`**)이며, 내부에 기본 바이너리와 `Info.plist`가 있는 **번들**이기도 합니다. 예: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` 및 `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**XPC 구성 요소는 다른 XPC 구성 요소나 기본 애플리케이션 바이너리와 다른 권한 및 특권을 가질 수 있습니다**. 단, **Info.plist** 파일에서 **`JoinExistingSession`**을 `true`로 설정한 XPC 서비스는 예외입니다. 이 경우 XPC 서비스는 해당 서비스를 호출한 **애플리케이션과 동일한 보안 세션에 참여합니다**.<sup>[[4]](#references)</sup>

XPC 서비스는 필요할 때 **launchd**가 **시작**하며, 시스템 리소스를 확보하기 위해 작업이 **완료되면 종료**할 수 있습니다. **애플리케이션별 XPC 구성 요소는 이를 포함하는 애플리케이션만 사용할 수 있으므로** 잠재적인 취약점에 노출될 가능성이 줄어듭니다.<sup>[[2]](#references)</sup>

## 시스템 전체 XPC 서비스

애플리케이션별 서비스와 달리 시스템 전체 XPC 서비스는 이를 포함하는 애플리케이션에만 제한되지 않습니다. launchd 도메인과 서비스 자체의 권한 확인 방식에 따라 여러 사용자의 클라이언트가 접근할 수 있습니다. launchd가 관리하는 이러한 Mach 서비스는 **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** 또는 **`/Library/LaunchAgents`**와 같은 디렉터리에 있는 plist 파일에서 **정의해야 합니다**.<sup>[[2]](#references)[[3]](#references)</sup>

이 plist 파일에는 서비스 이름을 포함하는 **`MachServices`** 키와 바이너리 경로를 포함하는 **`Program`** 키가 있습니다:

```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Program</key>
	<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
	<key>AbandonProcessGroup</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>com.jamf.management.daemon</string>
	<key>MachServices</key>
	<dict>
		<key>com.jamf.management.daemon.aad</key>
		<true/>
		<key>com.jamf.management.daemon.agent</key>
		<true/>
		<key>com.jamf.management.daemon.binary</key>
		<true/>
		<key>com.jamf.management.daemon.selfservice</key>
		<true/>
		<key>com.jamf.management.daemon.service</key>
		<true/>
	</dict>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
```

**`LaunchDaemons`**의 서비스는 일반적으로 root 권한으로 실행됩니다. 따라서 권한이 없는 프로세스가 이러한 서비스가 노출한 취약한 메서드에 접근할 수 있다면 권한을 상승시킬 수 있습니다.

## XPC Objects

- **`xpc_object_t`**

XPC 요청 및 응답 페이로드는 일반적으로 직렬화와 역직렬화를 간소화하는 딕셔너리 객체입니다. `libxpc.dylib`에는 수신한 데이터가 예상한 유형인지 확인하는 데 필요한 데이터 유형도 선언되어 있습니다. C API에서는 모든 객체가 `xpc_object_t`이며(객체의 유형은 `xpc_get_type(object)`를 사용해 확인할 수 있습니다).<sup>[[2]](#references)</sup>\
또한 `xpc_copy_description(object)` 함수를 사용하면 디버깅에 유용한 객체의 문자열 표현을 가져올 수 있습니다.\
이 객체에는 `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` 등의 메서드도 있습니다.

`xpc_object_t` 객체는 `xpc_<objectType>_create` 함수를 호출해 생성되며, 이 함수는 내부적으로 `_xpc_base_create(Class, Size)`를 호출해 객체의 클래스(`XPC_TYPE_*` 중 하나)와 크기를 지정합니다. 메타데이터에 40바이트가 추가되므로 객체 데이터는 40바이트 오프셋에서 시작합니다.\
따라서 `xpc_<objectType>_t`는 `xpc_object_t`의 하위 클래스와 같은 유형이며, `xpc_object_t`는 `os_object_t*`의 하위 클래스입니다.

> [!WARNING]
> 키의 유형과 실제 값을 가져오거나 설정할 때는 개발자가 `xpc_dictionary_[get/set]_<objectType>`를 사용해야 합니다.

- **`xpc_pipe`**

**`xpc_pipe`**는 프로세스 간 통신에 사용할 수 있는 FIFO 파이프입니다(통신에는 Mach 메시지가 사용됩니다).\
`xpc_pipe_create()`를 호출하거나 특정 Mach 포트를 사용해 `xpc_pipe_create_from_port()`를 호출하면 XPC 서버를 만들 수 있습니다. 그런 다음 메시지를 수신하려면 `xpc_pipe_receive`와 `xpc_pipe_try_receive`를 호출할 수 있습니다.

**`xpc_pipe`** 객체는 두 개의 Mach 포트와 이름(있는 경우)에 대한 정보가 구조체에 담긴 **`xpc_object_t`**입니다. 예를 들어 데몬 `secinitd`는 plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`에서 `com.apple.secinitd`라는 파이프를 설정합니다.

**`xpc_pipe`**의 한 예로 **`launchd`**가 생성하는 **bootstrap pipe**가 있으며, 이를 통해 Mach 포트를 공유할 수 있습니다.

- **`NSXPC*`**

XPC 연결을 추상화하는 상위 수준의 Objective-C 객체입니다.\
또한 이전 객체보다 DTrace를 사용해 디버깅하기 쉽습니다.

- **`GCD Queues`**

XPC는 메시지를 전달할 때 GCD를 사용하며, `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` 등의 dispatch queue를 생성하기도 합니다.

## XPC Services

이들은 다른 프로젝트의 **`XPCServices`** 폴더에 있는 **`.xpc`** 확장자의 번들이며, `Info.plist`에서 `CFBundlePackageType`이 **`XPC!`**로 설정되어 있습니다.\
이 파일에는 `ServiceType`(Application, User 또는 System일 수 있음), sandbox를 정의할 수 있는 `_SandboxProfile`, 그리고 서비스에 연결하는 데 필요한 entitlement 또는 identity를 나타낼 수 있는 `_AllowedClients` 등의 설정 키도 있습니다. 이러한 옵션과 기타 옵션은 서비스가 실행될 때 서비스의 구성을 설정합니다.<sup>[[2]](#references)</sup>

### 서비스 시작

앱은 `xpc_connection_create_mach_service`를 사용해 XPC 서비스에 **연결**을 시도합니다. 그러면 launchd가 데몬을 찾아 **`xpcproxy`**를 시작합니다. **`xpcproxy`**는 설정된 제한을 적용하고, 제공된 file descriptor와 Mach 포트를 사용해 서비스를 실행합니다.<sup>[[3]](#references)</sup>

XPC 서비스 검색 속도를 높이기 위해 캐시를 사용합니다.

다음을 사용해 `xpcproxy`의 동작을 추적할 수 있습니다.

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

XPC library는 `xpc_ktrace_pid0` 및 `xpc_ktrace_pid1`을 호출해 작업을 기록할 때 `kdebug`를 사용합니다. 사용하는 코드는 문서화되어 있지 않으므로 `/usr/share/misc/trace.codes`에 추가해야 합니다. 코드의 접두사는 `0x29`입니다. 예를 들어 `0x29000004`는 `XPC_serializer_pack`입니다.\
유틸리티 `xpcproxy`는 `0x22` 접두사를 사용합니다. 예를 들면 다음과 같습니다. `0x2200001c: xpcproxy:will_do_preexec`.

## Application 유형 XPC helper 감사

`XPCService.ServiceType`이 `Application`인 서비스는 framework에서 제공하는 helper를 감사할 때 유용한 출발점입니다. 번들을 열거하고, 실행 중인 서비스를 유지한 다음, helper의 식별자와 entitlements를 검사합니다. `/System/Library/Frameworks`와 `/System/Library/PrivateFrameworks`를 모두 검색하세요. 정확한 목록은 macOS 릴리스에 따라 달라집니다.<sup>[[7]](#references)</sup>

```bash
find /System/Library/Frameworks /System/Library/PrivateFrameworks \
  -type d -name '*.xpc' -print0 2>/dev/null |
while IFS= read -r -d '' bundle; do
    plist="$bundle/Contents/Info.plist"
    [ "$(plutil -extract XPCService.ServiceType raw -o - "$plist" 2>/dev/null)" = Application ] || continue

    exe=$(plutil -extract CFBundleExecutable raw -o - "$plist" 2>/dev/null) || continue
    bin="$bundle/Contents/MacOS/$exe"
    ps -axo comm= | awk -v b="$bin" '{sub(/^[[:space:]]+/, ""); if ($0==b) found=1} END {exit !found}' || continue

    printf '\n%s\n  id: %s\n' "$bundle" \
      "$(plutil -extract CFBundleIdentifier raw -o - "$plist" 2>/dev/null)"
    codesign -d --entitlements :- "$bundle" 2>&1
done
```

### Listener를 분석하고 최소 프로토콜을 복원하기

helper에서 `-[<delegate> listener:shouldAcceptNewConnection:]`을 찾습니다. `exportedInterface`와 `exportedObject`를 설정하고, 연결을 재개한 뒤, 피어의 audit token, code requirement 또는 entitlement를 확인하지 않고 `YES`/`1`을 반환하는 경로가 있다면 서비스 이름을 확인할 수 있는 모든 클라이언트에 RPC 인터페이스가 노출됩니다. 이것은 **접근 가능성**만 입증합니다. 영향이 발생하려면 적절한 클라이언트별/메서드별 권한 확인 없이 권한 있는 작업을 수행하거나 공격자가 제어하는 입력을 안전하지 않게 처리하는 exported method가 있어야 합니다.<sup>[[7]](#references)</sup>

테스트에 필요한 selector만 복원합니다. Objective-C selector 메타데이터에서 인자 개수를 확인할 수 있습니다. 디컴파일러에서 인자가 사용되는 방식을 보면 대개 타입도 좁힐 수 있습니다(예: `-[EKEvent setStartDate:]`와 `setEndDate:`에 전달되는 값은 `NSDate *`). 메서드 끝부분의 간접 호출에서는 reply block의 매개변수를 확인할 수 있습니다. `NSXPCInterface`에는 일부만 정의한 로컬 프로토콜로 충분하며, 완전한 private protocol을 복원할 필요는 없습니다.<sup>[[7]](#references)</sup>

### 복원한 인터페이스로 연결하기

애플리케이션 XPC service의 경우, 필요한 private class를 정의하는 framework를 로드하고, `initWithServiceName:`으로 연결을 만든 뒤, 복원한 remote interface를 지정하고, error/interruption/invalidation handler를 설치한 다음에만 연결을 재개합니다. 비동기 응답을 받으려면 run loop를 계속 활성 상태로 유지합니다. sandbox 경계를 테스트할 때는 sandboxed application 안에서 클라이언트를 다시 실행합니다. standalone 클라이언트의 성공은 sandbox escape의 증거가 아닙니다.<sup>[[7]](#references)</sup>

<details>
<summary>최소 Objective-C 클라이언트</summary>

```objectivec
@protocol RecoveredProtocol
- (void)createEventIntentWithStartDate:(NSDate *)start
                               endDate:(NSDate *)end
                             withReply:(void (^)(id object, id error))reply;
@end

[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AppPredictionFoundation.framework"] load];
NSXPCConnection *c = [[NSXPCConnection alloc]
    initWithServiceName:@"com.apple.proactive.AppPredictionIntentsHelperService"];
c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
c.interruptionHandler = ^{ NSLog(@"interrupted"); };
c.invalidationHandler = ^{ NSLog(@"invalidated"); };
[c resume];
id proxy = [c remoteObjectProxyWithErrorHandler:^(NSError *e) { NSLog(@"%@", e); }];
[proxy createEventIntentWithStartDate:[NSDate date]
                              endDate:[NSDate dateWithTimeIntervalSinceNow:3600]
                            withReply:^(id obj, id err) { NSLog(@"%@ %@", obj, err); }];
[[NSRunLoop currentRunLoop] run];
```

컴파일하려면 `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`을 실행합니다.<sup>[[7]](#references)</sup>

</details>

### secure-coding 오류를 타입 오라클로 활용하기

`NSCocoaErrorDomain` 오류(예: 코드 `4101`)에는 유용한 직렬화 예외가 숨겨져 있을 수 있습니다. macOS 통합 로그/Console에서 서비스 이름을 검색하면 예외를 통해 예상하지 못한 클래스와 해당 셀렉터 인수에 허용된 클래스가 모두 확인됩니다. 응답의 경우 `setClasses:forSelector:argumentIndex:ofReply:`를 사용해 **클라이언트 측** 인터페이스 허용 목록을 확장합니다. `ofReply:YES`일 때 인덱스 `0`은 첫 번째 메서드 인수가 아니라 응답 블록의 첫 번째 매개변수를 뜻합니다.<sup>[[7]](#references)</sup>

연결에 인터페이스를 할당하고 `[c resume]`을 호출하기 전에 인터페이스를 구성합니다.<sup>[[7]](#references)</sup>

```objectivec
NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
NSMutableSet *classes = [NSMutableSet setWithArray:@[
    NSDate.class, NSString.class, NSNumber.class,
    NSDictionary.class, NSArray.class, NSData.class
]];
Class intentClass = NSClassFromString(@"INIntent");
if (intentClass) [classes addObject:intentClass];
[iface setClasses:classes
      forSelector:@selector(createEventIntentWithStartDate:endDate:withReply:)
    argumentIndex:0
          ofReply:YES];
c.remoteObjectInterface = iface;
```

반대의 경우도 유용합니다. 서버가 Foundation 입력을 거부하고 허용된 단일 private class를 로그에 남기면, 로그를 통해 예상되는 wire type과 해당 프레임워크를 알 수 있습니다. 해당 프레임워크를 로드하고 클래스의 메서드와 프로퍼티를 살펴 generic `id` 타입을 구체화한 다음, private object를 동적으로 생성합니다. `NSInvocation` 인수는 인덱스 `2`부터 시작합니다. 인덱스 `0`과 `1`은 숨겨진 `self` 및 `_cmd` 인수이기 때문입니다.<sup>[[7]](#references)</sup>

<details>
<summary>NSInvocation으로 private 인수 생성</summary>

```objectivec
Class cls = NSClassFromString(@"LNStaticDeferredLocalizedString");
id allocated = [cls alloc];
SEL initializer = NSSelectorFromString(@"initWithKey:table:bundleURL:");
NSMethodSignature *signature = [allocated methodSignatureForSelector:initializer];
NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
[invocation setTarget:allocated];
[invocation setSelector:initializer];

NSString *key = @"KEY";
NSString *table = @"Localizable";
NSURL *bundleURL = NSBundle.mainBundle.bundleURL;
[invocation setArgument:&key atIndex:2];
[invocation setArgument:&table atIndex:3];
[invocation setArgument:&bundleURL atIndex:4];
[invocation invoke];

__unsafe_unretained id privateObject = nil;
[invocation getReturnValue:&privateObject];
```

</details>

launchd에 등록된 시스템 전역 Mach 서비스에 대한 관련 절차는 다음을 참조하세요.

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## XPC 이벤트 메시지

애플리케이션은 다양한 이벤트 **메시지**를 **구독**할 수 있으며, 이러한 이벤트가 발생하면 **요청 시 시작**되도록 설정할 수 있습니다. 이러한 서비스의 **설정**은 이전과 **같은 디렉터리**에 있으며 추가 **`LaunchEvent`** 키를 포함하는 l**aunchd plist 파일**에서 이루어집니다.

### XPC 연결 프로세스 확인

프로세스가 XPC 연결을 통해 메서드를 호출하려고 하면, **XPC 서비스는 해당 프로세스의 연결이 허용되는지 확인해야 합니다**. 다음은 일반적인 확인 방법과 그에 따른 함정입니다:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC 권한 부여

Apple은 앱이 **권한과 호출자가 권한을 획득하는 방식을 설정**할 수 있도록 합니다. 따라서 필요한 권한을 가진 프로세스는 XPC 서비스가 노출하는 메서드를 **호출할 수 있습니다**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC 메시지를 스니핑하려면 **Frida**를 사용하는 **xpcspy**를 사용할 수 있습니다.<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

또 다른 도구로 **XPoCe2**가 있습니다.<sup>[[6]](#references)</sup>

## XPC 통신 C 코드 예제

{{#tabs}}
{{#tab name="xpc_server.c"}}

```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        // Print received message
        const char* received_message = xpc_dictionary_get_string(event, "message");
        printf("Received message: %s\n", received_message);

        // Create a response dictionary
        xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(response, "received", "received");

        // Send response
        xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
        xpc_connection_send_message(remote, response);

        // Clean up
        xpc_release(response);
    }
}

static void handle_connection(xpc_connection_t connection) {
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        handle_event(event);
    });
    xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
    xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
                                                                   dispatch_get_main_queue(),
                                                                   XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!service) {
        fprintf(stderr, "Failed to create service.\n");
        exit(EXIT_FAILURE);
    }

    xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        if (type == XPC_TYPE_CONNECTION) {
            handle_connection(event);
        }
    });

    xpc_connection_resume(service);
    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xpc_client.c"}}

```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            // Print received message
            const char* received_message = xpc_dictionary_get_string(event, "received");
            printf("Received message: %s\n", received_message);
        }
    });

    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "message", "Hello, Server!");

    xpc_connection_send_message(connection, message);

    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.service.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.service</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save the server in its configured location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```

## XPC 통신 Objective-C 코드 예제

{{#tabs}}
{{#tab name="oc_xpc_server.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
    NSLog(@"Received message: %@", some_string);
    NSString *response = @"Received";
    reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

    MyXPCObject *my_object = [MyXPCObject new];

    newConnection.exportedObject = my_object;

    [newConnection resume];
    return YES;
}
@end

int main(void) {

    NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

    id <NSXPCListenerDelegate> delegate = [MyDelegate new];
    listener.delegate = delegate;
    [listener resume];

    sleep(10); // Fake something is done and then it ends
}
```

{{#endtab}}

{{#tab name="oc_xpc_client.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
    [connection resume];

    [[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
        NSLog(@"Received response: %@", response);
    }];

    [[NSRunLoop currentRunLoop] run];

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.svcoc.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.svcoc</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/oc_xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/oc_xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```

## Dylib 내부의 클라이언트

```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
        NSString*  _serviceName = @"xyz.hacktricks.svcoc";

        NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

        [_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

        [_agentConnection resume];

        [[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
            (void)error;
            NSLog(@"Connection Failure");
        }] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
            NSLog(@"Received response: %@", response);
    }    ];
        NSLog(@"Done!");

    return;
}
```

## Remote XPC

`RemoteXPC.framework`(`libxpc`에서 제공)의 기능을 사용하면 서로 다른 호스트 간에 XPC 통신을 수행할 수 있습니다.\
Remote XPC를 지원하는 서비스는 plist에 `UsesRemoteXPC` 키가 있습니다. `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`가 그 예입니다. 서비스는 `launchd`에 등록되지만, 기능은 `UserEventAgent`와 해당 에이전트의 `com.apple.remoted.plugin`, `com.apple.remoteservicediscovery.events.plugin` 플러그인이 제공합니다.

또한 `RemoteServiceDiscovery.framework`는 `com.apple.remoted.plugin`에서 정보를 가져오며, `get_device`, `get_unique_device`, `connect` 등의 함수를 노출합니다.

`connect`가 서비스의 소켓 파일 디스크립터를 반환하면 `remote_xpc_connection_*` 클래스를 사용할 수 있습니다.

다음과 같은 명령을 사용하면 `/usr/libexec/remotectl` CLI로 원격 서비스에 관한 정보를 얻을 수 있습니다.

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

bridgeOS와 호스트 간 통신은 전용 IPv6 인터페이스를 통해 이루어집니다. `MultiverseSupport.framework`는 통신에 사용되는 파일 디스크립터를 가진 소켓을 생성합니다.\
이러한 통신은 `netstat`, `nettop` 또는 오픈소스 대안인 `netbottom`을 사용해 확인할 수 있습니다.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — XPC 서비스 생성하기](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - macOS XPC Helper 공격하기: 프로토콜 리버스 엔지니어링](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
