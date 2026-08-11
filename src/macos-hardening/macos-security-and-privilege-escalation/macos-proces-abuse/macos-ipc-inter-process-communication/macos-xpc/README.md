# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basic Information

XPC는 macOS 및 iOS에서 **프로세스 간 통신**을 위한 framework입니다. **프로세스 간 안전한 비동기 호출**을 수행하기 위한 메커니즘을 제공합니다. XPC는 **권한이 분리된 애플리케이션**을 지원하며, 각 **component**가 **필요한 권한만** 사용하도록 실행하여 침해된 프로세스로 인한 잠재적 피해를 제한합니다.<sup>[[1]](#references)</sup>

XPC는 Inter-Process Communication (IPC)의 한 형태를 사용합니다. IPC는 동일한 시스템에서 실행 중인 서로 다른 프로그램이 데이터를 주고받기 위한 방법들의 집합입니다.

XPC의 주요 이점은 다음과 같습니다.

1. **Security**: 작업을 서로 다른 프로세스로 분리하면 각 프로세스에 필요한 권한만 부여할 수 있습니다. 따라서 프로세스가 침해되더라도 피해를 일으킬 수 있는 능력이 제한됩니다.
2. **Stability**: XPC는 crash가 발생한 component에 crash의 영향을 격리하는 데 도움을 줍니다. 프로세스가 crash하더라도 시스템의 나머지 부분에 영향을 주지 않고 재시작할 수 있습니다.
3. **Performance**: XPC를 사용하면 서로 다른 프로세스에서 서로 다른 작업을 동시에 실행할 수 있으므로 concurrency를 쉽게 구현할 수 있습니다.

주요 **단점**은 **애플리케이션을 여러 프로세스로 분리**하고 XPC를 통해 서로 통신하게 하면 overhead가 발생한다는 것입니다. 최신 시스템에서는 이러한 overhead가 일반적으로 작으며, security 및 stability상의 이점과 비교하면 무시할 수 있는 수준입니다.<sup>[[1]](#references)</sup>

## Application-Specific XPC Services

애플리케이션의 XPC component는 **애플리케이션 자체 내부에** 있습니다. 예를 들어 Safari에서는 **`/Applications/Safari.app/Contents/XPCServices`**에서 찾을 수 있습니다. 이 component는 **`.xpc`** 확장자를 가지며(예: **`com.apple.Safari.SandboxBroker.xpc`**), 내부에 main binary와 `Info.plist`가 있는 **bundle**이기도 합니다. 예: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` 및 `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**XPC component는** 다른 XPC component 또는 main application binary와 **서로 다른 entitlements 및 privileges를 가질 수 있습니다**. 한 가지 예외는 **Info.plist** 파일에서 **`JoinExistingSession`**이 `true`로 설정된 XPC service입니다. 이 경우 XPC service는 해당 service를 호출한 **애플리케이션과 동일한 security session에 참여합니다**.<sup>[[4]](#references)</sup>

XPC service는 필요할 때 **launchd에 의해 시작**되며, system resources를 확보하기 위해 작업이 **완료되면 종료**될 수 있습니다. **Application-specific XPC component는 이를 포함하는 애플리케이션만 사용할 수 있으므로**, 잠재적인 vulnerabilities에 대한 노출을 줄일 수 있습니다.<sup>[[2]](#references)</sup>

## System-Wide XPC Services

Application-specific service와 달리 system-wide XPC service는 이를 포함하는 애플리케이션으로 제한되지 않습니다. launchd domain과 service 자체의 authorization checks에 따라 여러 사용자의 client가 접근할 수 있습니다. 이러한 launchd-managed Mach service는 **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** 또는 **`/Library/LaunchAgents`**와 같은 directory에 있는 **plist** 파일에 정의되어야 합니다.<sup>[[2]](#references)[[3]](#references)</sup>

이러한 plist 파일에는 service name을 포함하는 **`MachServices`** key와 binary 경로를 포함하는 **`Program`** key가 있습니다:
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
Services in **`LaunchDaemons`**는 일반적으로 root 권한으로 실행됩니다. 따라서 권한이 없는 프로세스가 이러한 Services 중 하나가 노출한 취약한 method에 접근할 수 있다면, 권한을 상승시킬 수 있습니다.

## XPC Objects

- **`xpc_object_t`**

XPC request 및 reply payload는 일반적으로 dictionary object이며, serialization 및 deserialization을 단순화합니다. `libxpc.dylib`는 수신한 data가 예상된 type인지 검증하는 데 필요한 data type도 선언합니다. C API에서 모든 object는 `xpc_object_t`이며, `xpc_get_type(object)`를 사용하여 type을 확인할 수 있습니다.<sup>[[2]](#references)</sup>\
또한 `xpc_copy_description(object)` function을 사용하면 debugging에 유용한 object의 string representation을 얻을 수 있습니다.\
이러한 object에는 `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` 등 호출할 수 있는 method도 있습니다.

`xpc_object_t` object는 `xpc_<objectType>_create` function을 호출하여 생성되며, 이 function은 내부적으로 `_xpc_base_create(Class, Size)`를 호출하여 object의 class(`XPC_TYPE_*` 중 하나)와 size를 지정합니다. Metadata에 40 bytes가 추가되므로 object data는 offset 40 bytes에서 시작합니다.\
따라서 `xpc_<objectType>_t`는 `xpc_object_t`의 일종의 subclass이며, `xpc_object_t`는 다시 `os_object_t*`의 subclass입니다.

> [!WARNING]
> type과 key의 실제 value를 가져오거나 설정할 때는 developer가 `xpc_dictionary_[get/set]_<objectType>`를 사용해야 합니다.

- **`xpc_pipe`**

**`xpc_pipe`**는 process가 서로 통신하는 데 사용할 수 있는 FIFO pipe입니다(communication에는 Mach message가 사용됩니다).\
`xpc_pipe_create()` 또는 `xpc_pipe_create_from_port()`를 호출하여 특정 Mach port를 사용해 생성하는 방식으로 XPC server를 만들 수 있습니다. 그런 다음 message를 수신하려면 `xpc_pipe_receive` 및 `xpc_pipe_try_receive`를 호출할 수 있습니다.

**`xpc_pipe`** object는 struct 안에 사용되는 두 Mach port와 name(있는 경우)에 대한 information을 포함하는 **`xpc_object_t`** object입니다. 예를 들어 daemon `secinitd`는 plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`에서 `com.apple.secinitd`라는 pipe를 configure합니다.

**`xpc_pipe`**의 예로 **`launchd`**가 생성하는 **bootstrap pipe**가 있으며, 이를 통해 Mach port를 공유할 수 있습니다.

- **`NSXPC*`**

이는 XPC connection을 abstract하는 high-level Objective-C object입니다.\
또한 이전 object보다 DTrace를 사용하여 이러한 object를 debugging하기가 더 쉽습니다.

- **`GCD Queues`**

XPC는 message를 전달하기 위해 GCD를 사용하며, `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` 등의 특정 dispatch queue도 생성합니다.

## XPC Services

이는 다른 project의 **`XPCServices`** folder 안에 위치하며 `.xpc` extension을 가진 **bundle**이고, `Info.plist`에서 `CFBundlePackageType`이 **`XPC!`**로 설정되어 있습니다.\
이 file에는 `ServiceType`과 같은 다른 configuration key도 있으며, 이 값은 Application, User 또는 System일 수 있습니다. 또한 sandbox를 정의할 수 있는 `_SandboxProfile`과 service에 contact하는 데 필요한 entitlement 또는 identity를 나타낼 수 있는 `_AllowedClients`도 있습니다. 이러한 option 및 기타 option이 service가 launch될 때 해당 service를 configure합니다.<sup>[[2]](#references)</sup>

### Service 시작

App은 `xpc_connection_create_mach_service`를 사용하여 XPC service에 **connect**하려고 시도합니다. 그러면 launchd가 daemon을 찾고 **`xpcproxy`**를 시작합니다. **`xpcproxy`**는 configure된 restriction을 적용하고 제공된 file descriptor와 Mach port를 사용하여 service를 spawn합니다.<sup>[[3]](#references)</sup>

XPC service 검색 속도를 향상하기 위해 cache가 사용됩니다.

다음을 사용하여 `xpcproxy`의 action을 trace할 수 있습니다:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC library는 `xpc_ktrace_pid0` 및 `xpc_ktrace_pid1`을 호출하여 작업을 기록하기 위해 `kdebug`를 사용합니다. 이때 사용하는 코드는 문서화되어 있지 않으므로 `/usr/share/misc/trace.codes`에 추가해야 합니다. 이 코드에는 `0x29` 접두사가 사용됩니다. 예를 들어 `0x29000004`는 `XPC_serializer_pack`입니다.\
`xpcproxy` utility는 `0x22` 접두사를 사용합니다. 예: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

애플리케이션은 서로 다른 이벤트 **메시지**를 **subscribe**할 수 있으며, 이러한 이벤트가 발생할 때 **on-demand로 시작**되도록 설정할 수 있습니다. 이러한 서비스의 **setup**은 이전 서비스와 **동일한 디렉터리**에 있는 **launchd plist files**에서 수행되며, 여기에 추가 **`LaunchEvent`** 키가 포함됩니다.

### XPC Connecting Process Check

프로세스가 XPC connection을 통해 method를 호출하려 하면, **XPC service는 해당 프로세스의 connection이 허용되는지 확인해야 합니다**. 일반적인 검증 방법과 그 함정은 다음과 같습니다.


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple은 앱이 **authorization rights와 caller가 이를 획득하는 방식을 configure**할 수 있도록 허용합니다. 따라서 필요한 rights를 가진 프로세스는 **XPC service가 expose한 method를 호출할 수 있습니다**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC 메시지를 sniff하려면 **Frida**를 사용하는 **xpcspy**를 이용할 수 있습니다.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
또 다른 가능한 도구는 **XPoCe2**입니다.<sup>[[6]](#references)</sup>

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
## XPC Communication Objective-C 코드 예제

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

`libxpc`의 `RemoteXPC.framework`가 제공하는 기능을 사용하면 서로 다른 host 간에 XPC communication을 수행할 수 있습니다.\
Remote XPC를 지원하는 service에는 plist에 `UsesRemoteXPC` key가 있으며, `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`가 이에 해당합니다. 이 service는 `launchd`에 등록되어 있지만, 해당 기능은 `UserEventAgent`와 그 안의 `com.apple.remoted.plugin` 및 `com.apple.remoteservicediscovery.events.plugin` plugins가 제공합니다.

또한 `RemoteServiceDiscovery.framework`는 `com.apple.remoted.plugin`에서 정보를 가져오며, `get_device`, `get_unique_device`, `connect`와 같은 functions를 노출합니다.

`connect`가 service의 socket file descriptor를 반환하면 `remote_xpc_connection_*` class를 사용할 수 있습니다.

다음과 같은 commands를 사용하여 `/usr/libexec/remotectl` CLI로 remote services에 대한 정보를 가져올 수 있습니다:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
bridgeOS와 호스트 간의 통신은 전용 IPv6 인터페이스를 통해 이루어집니다. `MultiverseSupport.framework`는 통신에 사용되는 파일 디스크립터를 가진 소켓을 설정합니다.\
이러한 통신은 `netstat`, `nettop` 또는 open-source 대안인 `netbottom`을 사용하여 확인할 수 있습니다.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — XPC 서비스 생성](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
