# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 기본 정보

XNU(macOS에서 사용되는 kernel) inter-Process Communication을 의미하는 XPC는 macOS 및 iOS에서 **process 간 communication**을 위한 framework입니다. XPC는 시스템의 서로 다른 process 간에 **안전한 비동기 method call**을 수행하는 mechanism을 제공합니다. 이는 Apple의 security paradigm의 일부로, 각 **component**가 작업에 필요한 **permission만** 사용하도록 하여 **privilege가 분리된 application**을 생성할 수 있도록 합니다. 이를 통해 process가 compromise되었을 때 발생할 수 있는 잠재적 피해를 제한합니다.

XPC는 Inter-Process Communication (IPC)의 한 형태를 사용합니다. IPC는 동일한 system에서 실행 중인 서로 다른 program이 데이터를 서로 주고받기 위한 method 집합입니다.

XPC의 주요 이점은 다음과 같습니다.

1. **Security**: 작업을 서로 다른 process로 분리하면 각 process에 필요한 permission만 부여할 수 있습니다. 따라서 process가 compromise되더라도 피해를 줄 수 있는 능력이 제한됩니다.
2. **Stability**: XPC는 crash가 발생한 component를 격리하는 데 도움을 줍니다. process가 crash되면 system의 나머지 부분에 영향을 주지 않고 재시작할 수 있습니다.
3. **Performance**: XPC를 사용하면 서로 다른 process에서 여러 작업을 동시에 실행할 수 있으므로 concurrency를 쉽게 구현할 수 있습니다.

유일한 **단점**은 **application을 여러 process로 분리**하고 XPC를 통해 통신하도록 만드는 것이 **효율성이 낮다**는 점입니다. 하지만 오늘날의 system에서는 그 차이가 거의 감지되지 않으며, 이점이 더 큽니다.

## Application Specific XPC services

application의 XPC component는 **application 자체 내부에 있습니다.** 예를 들어 Safari에서는 **`/Applications/Safari.app/Contents/XPCServices`**에서 찾을 수 있습니다. 이들은 **`.xpc`** extension을 가지며(**`com.apple.Safari.SandboxBroker.xpc`** 등), 내부에 main binary가 포함된 **bundle**이기도 합니다: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` 및 `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

예상할 수 있듯이 **XPC component는** 다른 XPC component 또는 main app binary와 **다른 entitlement와 privilege를 가집니다.** 단, XPC service가 해당 **Info.plist** file에서 [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)을 “True”로 설정하여 구성된 경우는 예외입니다. 이 경우 XPC service는 이를 호출한 **application과 동일한 security session**에서 실행됩니다.

XPC service는 필요할 때 **launchd에 의해 시작**되며, system resource를 확보하기 위해 모든 작업이 **완료되면** 종료됩니다. **Application-specific XPC component는 해당 application만 사용할 수 있으므로**, 잠재적인 vulnerability와 관련된 risk를 줄일 수 있습니다.

## System Wide XPC services

System-wide XPC service는 모든 user가 접근할 수 있습니다. 이러한 service는 launchd 또는 Mach-type이며, **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, 또는 **`/Library/LaunchAgents`**와 같은 지정된 directory에 있는 **plist** file에서 정의해야 합니다.

이러한 plist file에는 service name을 포함하는 **`MachServices`** key와 binary path를 포함하는 **`Program`** key가 있습니다.
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
`LaunchDameons`에 있는 것들은 root 권한으로 실행됩니다. 따라서 권한이 없는 프로세스가 이들 중 하나와 통신할 수 있다면 권한을 상승시킬 수 있습니다.

## XPC Objects

- **`xpc_object_t`**

모든 XPC 메시지는 직렬화와 역직렬화를 간소화하는 dictionary object입니다. 또한 `libxpc.dylib`는 대부분의 data type을 선언하므로, 수신된 data가 예상된 type인지 확인할 수 있습니다. C API에서 모든 object는 `xpc_object_t`이며 (`xpc_get_type(object)`를 사용해 type을 확인할 수 있음),\
`xpc_copy_description(object)` 함수를 사용하면 debugging에 유용한 object의 문자열 표현을 가져올 수 있습니다.\
이 object에는 `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` 등 호출할 수 있는 여러 method도 있습니다.

`xpc_object_t`는 `xpc_<objetType>_create` 함수를 호출해 생성되며, 이 함수는 내부적으로 `_xpc_base_create(Class, Size)`를 호출합니다. 여기에는 object class의 type(`XPC_TYPE_*` 중 하나)과 size가 지정됩니다(size에는 metadata를 위한 추가 40B가 더해짐). 즉, object의 data는 offset 40B에서 시작합니다.\
따라서 `xpc_<objectType>_t`는 `xpc_object_t`의 일종의 subclass이며, `xpc_object_t`는 다시 `os_object_t*`의 subclass입니다.

> [!WARNING]
> type과 key의 실제 값을 가져오거나 설정할 때는 developer가 `xpc_dictionary_[get/set]_<objectType>`를 사용해야 합니다.

- **`xpc_pipe`**

**`xpc_pipe`**는 프로세스가 통신에 사용할 수 있는 FIFO pipe입니다(통신에는 Mach message가 사용됨).\
`xpc_pipe_create()` 또는 `xpc_pipe_create_from_port()`를 호출해 특정 Mach port를 사용하는 XPC server를 생성할 수 있습니다. 그런 다음 메시지를 수신하려면 `xpc_pipe_receive` 및 `xpc_pipe_try_receive`를 호출할 수 있습니다.

**`xpc_pipe`** object는 두 Mach port와 name(있는 경우)에 대한 정보가 struct에 포함된 **`xpc_object_t`**입니다. 예를 들어 daemon `secinitd`는 plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`에서 `com.apple.secinitd`라는 pipe를 설정합니다.

**`xpc_pipe`**의 한 예는 **`launchd`**가 생성하는 **bootstrap pip**e로, Mach port를 공유할 수 있게 합니다.

- **`NSXPC*`**

이는 XPC connection을 추상화하는 Objective-C high-level object입니다.\
또한 앞서 설명한 object보다 DTrace를 사용해 debugging하기가 더 쉽습니다.

- **`GCD Queues`**

XPC는 메시지를 전달하기 위해 GCD를 사용하며, `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` 등의 특정 dispatch queue도 생성합니다.

## XPC Services

이는 다른 project의 **`XPCServices`** folder 내부에 위치하며 `.xpc` extension을 가진 **bundle**입니다. 해당 project의 `Info.plist`에서는 `CFBundlePackageType`이 **`XPC!`**로 설정되어 있습니다.\
이 file에는 `Application`, `User`, `System` 중 하나일 수 있는 `ServiceType`, sandbox를 정의할 수 있는 `_SandboxProfile`, 또는 service에 contact하는 데 필요한 entitlement나 ID를 나타낼 수 있는 `_AllowedClients` 등의 configuration key도 있습니다. 이러한 옵션과 다른 configuration option은 service가 launch될 때 service를 구성하는 데 유용합니다.

### Starting a Service

App은 `xpc_connection_create_mach_service`를 사용해 XPC service에 **connect**하려고 시도하고, 이후 launchd가 daemon을 찾아 **`xpcproxy`**를 시작합니다. **`xpcproxy`**는 구성된 restriction을 적용하고 제공된 FD와 Mach port를 사용해 service를 spawn합니다.

XPC service 검색 속도를 향상하기 위해 cache가 사용됩니다.

다음 방법으로 `xpcproxy`의 동작을 trace할 수 있습니다:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC library는 `xpc_ktrace_pid0` 및 `xpc_ktrace_pid1`을 호출하여 작업을 기록하기 위해 `kdebug`를 사용합니다. 이때 사용하는 코드는 문서화되어 있지 않으므로 `/usr/share/misc/trace.codes`에 추가해야 합니다. 해당 코드는 `0x29` 접두사를 사용하며, 예를 들어 `0x29000004`는 `XPC_serializer_pack`입니다.\
`xpcproxy` utility는 `0x22` 접두사를 사용합니다. 예: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

애플리케이션은 서로 다른 이벤트 **messages**를 **subscribe**할 수 있으며, 이를 통해 해당 이벤트가 발생할 때 필요에 따라 **initiated**될 수 있습니다. 이러한 서비스의 **setup**은 이전 파일과 **동일한 디렉터리**에 있는 **launchd plist files**에서 수행되며, 여기에 추가 **`LaunchEvent`** key가 포함됩니다.

### XPC Connecting Process Check

프로세스가 XPC connection을 통해 method 호출을 시도하면 **XPC service는 해당 프로세스가 connect할 수 있는 권한이 있는지 확인해야 합니다**. 이를 확인하는 일반적인 방법과 흔한 pitfalls는 다음과 같습니다:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple은 앱이 일부 rights와 이를 얻는 방법을 **configure**할 수 있도록 허용합니다. 따라서 calling process가 해당 rights를 가지고 있으면 XPC service의 method를 **call할 수 있습니다**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC messages를 sniff하려면 **Frida**를 사용하는 [**xpcspy**](https://github.com/hot3eed/xpcspy)를 사용할 수 있습니다.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
또 다른 사용 가능한 tool은 [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html)입니다.

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

# Save server on it's location
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
## Dylb code 내부의 Client
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

`RemoteXPC.framework` (`libxpc`에 포함)가 제공하는 이 기능을 사용하면 서로 다른 host를 통해 XPC로 통신할 수 있습니다.\
Remote XPC를 지원하는 service는 `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`의 경우처럼 plist에 `UsesRemoteXPC` key를 포함합니다. 그러나 service는 `launchd`에 등록되지만, 해당 기능을 제공하는 것은 `com.apple.remoted.plugin` 및 `com.apple.remoteservicediscovery.events.plugin` plugin이 포함된 `UserEventAgent`입니다.

또한 `RemoteServiceDiscovery.framework`를 사용하면 `com.apple.remoted.plugin`에서 정보를 가져올 수 있으며, `get_device`, `get_unique_device`, `connect` 등의 function을 노출합니다.

`connect`를 사용하고 service의 socket `fd`를 가져오면 `remote_xpc_connection_*` class를 사용할 수 있습니다.

다음과 같은 parameter를 사용하여 CLI tool `/usr/libexec/remotectl`로 remote service에 대한 정보를 가져올 수 있습니다:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOS와 host 간의 통신은 전용 IPv6 interface를 통해 이루어집니다. `MultiverseSupport.framework`를 사용하면 통신에 사용될 `fd`를 가진 socket을 설정할 수 있습니다.\
`netstat`, `nettop` 또는 open source 옵션인 `netbottom`을 사용하여 이러한 통신을 찾을 수 있습니다.

{{#include ../../../../../banners/hacktricks-training.md}}
