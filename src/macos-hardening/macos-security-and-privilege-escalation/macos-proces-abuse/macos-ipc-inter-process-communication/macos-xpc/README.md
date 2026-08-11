# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 기본 정보

XPC는 macOS 및 iOS에서 **프로세스 간 통신**을 위한 framework입니다. **프로세스 간 안전한 비동기 호출**을 수행하기 위한 메커니즘을 제공합니다. XPC는 **권한이 분리된 애플리케이션**을 지원하며, 각 **component**는 **필요한 권한만** 사용하여 실행되므로, 침해된 프로세스로 인해 발생할 수 있는 피해를 제한합니다.<sup>[[1]](#references)</sup>

XPC는 Inter-Process Communication (IPC)의 한 형태를 사용합니다. IPC는 동일한 시스템에서 실행 중인 서로 다른 프로그램이 데이터를 서로 주고받기 위한 방법의 집합입니다.

XPC의 주요 이점은 다음과 같습니다.

1. **보안**: 작업을 서로 다른 프로세스로 분리하면 각 프로세스에 필요한 권한만 부여할 수 있습니다. 따라서 프로세스가 침해되더라도 피해를 줄 수 있는 능력이 제한됩니다.
2. **안정성**: XPC는 crash가 발생한 component에 crash의 영향을 격리하는 데 도움을 줍니다. 프로세스가 crash하면 시스템의 나머지 부분에 영향을 주지 않고 다시 시작할 수 있습니다.
3. **성능**: XPC를 사용하면 서로 다른 프로세스에서 여러 작업을 동시에 실행할 수 있으므로 concurrency를 쉽게 구현할 수 있습니다.

주요 **단점**은 **애플리케이션을 여러 프로세스로 분리**하고 XPC를 통해 통신하도록 하면 overhead가 발생한다는 점입니다. 최신 시스템에서는 이러한 overhead가 일반적으로 보안 및 안정성상의 이점에 비해 작습니다.<sup>[[1]](#references)</sup>

## 애플리케이션별 XPC Services

애플리케이션의 XPC component는 **애플리케이션 자체 내부에** 있습니다. 예를 들어 Safari에서는 **`/Applications/Safari.app/Contents/XPCServices`**에서 찾을 수 있습니다. 이러한 component는 **`.xpc`** 확장자를 가지며(예: **`com.apple.Safari.SandboxBroker.xpc`**), 내부에 main binary와 `Info.plist`가 포함된 **bundle**이기도 합니다. 예: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` 및 `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**XPC component는** 다른 XPC component 또는 main application binary와 **서로 다른 entitlements 및 privileges**를 가질 수 있습니다. 한 가지 예외는 **Info.plist** 파일에서 **`JoinExistingSession`**이 `true`로 설정된 XPC service입니다. 이 경우 XPC service는 해당 service를 호출한 **애플리케이션과 동일한 security session에 참여합니다**.<sup>[[4]](#references)</sup>

XPC service는 필요할 때 **launchd에 의해 시작**되며, 시스템 리소스를 확보하기 위해 작업이 **완료되면 종료**될 수 있습니다. **애플리케이션별 XPC component는 이를 포함하는 애플리케이션만 사용할 수** 있으므로 잠재적인 vulnerability에 대한 노출을 줄일 수 있습니다.<sup>[[2]](#references)</sup>

## 시스템 전체 XPC Services

시스템 전체 XPC service는 단일 애플리케이션 외부에서도 접근할 수 있습니다. 이러한 launchd-managed Mach service는 **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** 또는 **`/Library/LaunchAgents`**와 같은 directory에 있는 **plist** 파일에서 정의해야 합니다.<sup>[[3]](#references)</sup>

이러한 plist 파일에는 service 이름이 포함된 **`MachServices`** key와 binary 경로가 포함된 **`Program`** key가 있습니다:
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
**`LaunchDaemons`**의 서비스는 일반적으로 root로 실행됩니다. 따라서 권한이 없는 프로세스가 이러한 서비스 중 하나가 노출한 취약한 메서드에 접근할 수 있다면, 권한을 상승할 수 있습니다.

## XPC Objects

- **`xpc_object_t`**

XPC 요청 및 응답 payload는 일반적으로 dictionary object이며, serialization 및 deserialization을 간소화합니다. `libxpc.dylib`는 수신된 데이터가 예상한 type인지 확인하는 데 필요한 data type도 선언합니다. C API에서 모든 object는 `xpc_object_t`이며, type은 `xpc_get_type(object)`를 사용해 확인할 수 있습니다.<sup>[[2]](#references)</sup>\
또한 `xpc_copy_description(object)` 함수를 사용하면 debugging에 유용한 object의 string representation을 얻을 수 있습니다.\
이러한 object에는 `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` 등 호출할 수 있는 메서드도 있습니다.

`xpc_object_t` object는 `xpc_<objectType>_create` 함수를 호출해 생성되며, 이 함수는 내부적으로 `_xpc_base_create(Class, Size)`를 호출하여 object의 class(`XPC_TYPE_*` 중 하나)와 size를 지정합니다. metadata에 40바이트가 추가되므로 object data는 40바이트 offset에서 시작합니다.\
따라서 `xpc_<objectType>_t`는 `xpc_object_t`의 일종의 subclass이며, `xpc_object_t`는 다시 `os_object_t*`의 subclass입니다.

> [!WARNING]
> type과 key의 실제 value를 가져오거나 설정할 때 `xpc_dictionary_[get/set]_<objectType>`를 사용하는 주체는 developer여야 합니다.

- **`xpc_pipe`**

**`xpc_pipe`**는 프로세스 간 통신에 사용할 수 있는 FIFO pipe입니다(통신에는 Mach message가 사용됩니다).\
`xpc_pipe_create()` 또는 `xpc_pipe_create_from_port()`를 호출하여 특정 Mach port를 사용하는 XPC server를 생성할 수 있습니다. 그런 다음 message를 수신하기 위해 `xpc_pipe_receive` 및 `xpc_pipe_try_receive`를 호출할 수 있습니다.

**`xpc_pipe`** object는 두 Mach port와 name(있는 경우)에 대한 정보가 struct에 포함된 **`xpc_object_t`** object라는 점에 유의해야 합니다. 예를 들어 daemon `secinitd`는 plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`에서 `com.apple.secinitd`라는 pipe를 configure합니다.

**`xpc_pipe`**의 예로는 **`launchd`**가 생성하는 **bootstrap pipe**가 있으며, 이를 통해 Mach port를 공유할 수 있습니다.

- **`NSXPC*`**

이는 XPC connection을 추상화하는 high-level Objective-C object입니다.\
또한 이전 object보다 DTrace를 사용해 이러한 object를 debugging하기가 더 쉽습니다.

- **`GCD Queues`**

XPC는 message를 전달하기 위해 GCD를 사용하며, `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` 등의 특정 dispatch queue도 생성합니다.

## XPC Services

이는 다른 project의 **`XPCServices`** folder 안에 위치하며 **`.xpc`** extension을 사용하는 bundle입니다. 또한 `Info.plist`에서 `CFBundlePackageType`이 **`XPC!`**로 설정되어 있습니다.\
이 file에는 `ServiceType`과 같은 다른 configuration key도 있으며, 값으로 Application, User 또는 System을 사용할 수 있습니다. `_SandboxProfile`은 sandbox를 정의할 수 있고, `_AllowedClients`는 service에 contact하는 데 필요한 entitlement 또는 identity를 나타낼 수 있습니다. 이러한 option과 기타 option이 service가 launch될 때의 동작을 configure합니다.<sup>[[2]](#references)</sup>

### Starting a Service

app은 `xpc_connection_create_mach_service`를 사용하여 XPC service에 **connect**하려고 시도합니다. 그러면 launchd가 daemon을 찾고 **`xpcproxy`**를 시작합니다. **`xpcproxy`**는 configure된 restriction을 적용하고 제공된 file descriptor 및 Mach port와 함께 service를 spawn합니다.<sup>[[3]](#references)</sup>

XPC service 검색 속도를 높이기 위해 cache가 사용됩니다.

다음을 사용하여 `xpcproxy`의 동작을 trace할 수 있습니다:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC library는 `xpc_ktrace_pid0` 및 `xpc_ktrace_pid1`을 호출하여 작업을 기록하는 데 `kdebug`를 사용합니다. 이때 사용하는 code는 문서화되어 있지 않으므로 `/usr/share/misc/trace.codes`에 추가해야 합니다. 해당 code에는 `0x29` prefix가 사용됩니다. 예를 들어 `0x29000004`는 `XPC_serializer_pack`입니다.\
utility `xpcproxy`는 `0x22` prefix를 사용합니다. 예: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC 이벤트 메시지

애플리케이션은 서로 다른 이벤트 **message**를 **subscribe**하여 이러한 이벤트가 발생할 때 **on-demand로 시작**되도록 할 수 있습니다. 이러한 서비스의 **설정**은 이전 항목과 **동일한 디렉터리**에 있는 **launchd plist 파일**에서 수행되며, 해당 파일에는 추가 **`LaunchEvent`** key가 포함됩니다.

### XPC 연결 프로세스 확인

프로세스가 XPC connection을 통해 method를 호출하려 하면 **XPC service는 해당 프로세스의 연결이 허용되는지 확인해야 합니다**. 일반적인 확인 방법과 그 문제점은 다음과 같습니다:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC 권한 부여

Apple은 앱이 **권한과 caller가 해당 권한을 획득하는 방법을 구성**할 수 있도록 허용합니다. 따라서 필요한 권한이 있는 프로세스는 **XPC service가 노출한 method를 호출할 수 있습니다**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC 스니퍼

XPC message를 sniff하려면 **xpcspy**를 사용할 수 있으며, 이는 **Frida**를 사용합니다.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
또 다른 가능한 tool은 **XPoCe2**입니다.<sup>[[6]](#references)</sup>

## XPC Communication C Code Example

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
## XPC Communication Objective-C Code Example

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
## Dylib 내부의 Client
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

`RemoteXPC.framework`(from `libxpc`)에서 제공하는 기능을 사용하면 서로 다른 host 간에 XPC 통신을 수행할 수 있습니다.\
Remote XPC를 지원하는 service에는 `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`의 경우처럼 plist에 `UsesRemoteXPC` key가 있습니다. 해당 service는 `launchd`에 등록되지만, 기능은 `UserEventAgent`와 해당 agent의 `com.apple.remoted.plugin` 및 `com.apple.remoteservicediscovery.events.plugin` plugin이 제공합니다.

또한 `RemoteServiceDiscovery.framework`는 `com.apple.remoted.plugin`에서 정보를 가져오며, `get_device`, `get_unique_device`, `connect`와 같은 function을 노출합니다.

`connect`가 service의 socket file descriptor를 반환하면 `remote_xpc_connection_*` class를 사용할 수 있습니다.

`/usr/libexec/remotectl` CLI에서 다음과 같은 command를 사용하면 remote service에 대한 정보를 가져올 수 있습니다:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
bridgeOS와 host 간 통신은 전용 IPv6 인터페이스를 통해 이루어집니다. `MultiverseSupport.framework`는 통신에 사용되는 file descriptor를 가진 socket을 생성합니다.\
이러한 통신은 `netstat`, `nettop` 또는 open-source 대안인 `netbottom`을 사용하여 확인할 수 있습니다.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — XPC 서비스 생성](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
