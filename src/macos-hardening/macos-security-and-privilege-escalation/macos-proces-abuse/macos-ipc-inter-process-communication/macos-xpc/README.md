# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 基本信息

XPC 是 macOS 和 iOS 上用于**进程间通信**的 framework。它提供了在进程之间进行**安全、异步调用**的机制。XPC 支持**权限分离的应用程序**，其中每个**组件**仅使用**所需的权限**运行，从而限制受 compromise 进程造成的潜在损害。<sup>[[1]](#references)</sup>

XPC 使用一种进程间通信（IPC）形式，这是在同一系统上运行的不同程序之间来回传输数据的一组方法。

XPC 的主要优势包括：

1. **Security**：通过将工作分离到不同进程中，可以只向每个进程授予其所需的权限。这意味着即使某个进程被 compromise，它造成危害的能力也会受到限制。
2. **Stability**：XPC 有助于将崩溃限制在发生崩溃的组件中。如果某个进程崩溃，可以在不影响系统其余部分的情况下重启它。
3. **Performance**：XPC 可以轻松实现并发，因为不同任务可以在不同进程中同时运行。

主要的**缺点**是，将**应用程序拆分为多个进程**并让它们通过 XPC 通信会增加开销。在现代系统中，与安全性和稳定性方面的收益相比，这种开销通常较小。<sup>[[1]](#references)</sup>

## 特定于应用程序的 XPC Services

应用程序的 XPC 组件位于**应用程序自身内部**。例如，在 Safari 中可以在 **`/Applications/Safari.app/Contents/XPCServices`** 找到它们。它们的扩展名为 **`.xpc`**（例如 **`com.apple.Safari.SandboxBroker.xpc`**），并且**也是 bundles**，其中包含主二进制文件和一个 `Info.plist`。例如：`/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` 和 `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`。<sup>[[2]](#references)</sup>

一个 **XPC component** 可以拥有不同于其他 XPC components 或主应用程序二进制文件的**entitlements 和 privileges**。一个例外是，在其 **Info.plist** 文件中将 **`JoinExistingSession`** 设置为 `true` 的 XPC service。在这种情况下，XPC service 会加入调用它的**应用程序所处的相同 security session**。<sup>[[4]](#references)</sup>

XPC services 在需要时由 **launchd** **启动**，并且可以在其任务**完成**后**关闭**，以释放系统资源。**特定于应用程序的 XPC 组件只能由其所属的应用程序使用**，从而减少潜在 vulnerabilities 的暴露面。<sup>[[2]](#references)</sup>

## 系统范围的 XPC Services

系统范围的 XPC services 可以在单个应用程序之外访问。这些由 launchd 管理的 Mach services 需要在位于 **`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`** 或 **`/Library/LaunchAgents`** 等目录中的 **plist** 文件内定义。<sup>[[3]](#references)</sup>

这些 plist 文件包含一个 **`MachServices`** key，其中存放 service 名称，以及一个 **`Program`** key，其中存放二进制文件的路径：
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
Services in **`LaunchDaemons`** 通常以 root 身份运行。因此，如果非特权进程能够访问这些服务暴露的易受攻击方法，就可能借此提升权限。

## XPC Objects

- **`xpc_object_t`**

XPC 请求和回复的 payload 通常是字典对象，这简化了序列化和反序列化。`libxpc.dylib` 还声明了验证接收数据是否为预期类型所需的数据类型。在 C API 中，每个对象都是一个 `xpc_object_t`（可以使用 `xpc_get_type(object)` 检查其类型）。<sup>[[2]](#references)</sup>\
此外，可以使用函数 `xpc_copy_description(object)` 获取对象的字符串表示，这对于调试很有用。\
这些对象还有一些可调用的方法，例如 `xpc_<object>_copy`、`xpc_<object>_equal`、`xpc_<object>_hash`、`xpc_<object>_serialize`、`xpc_<object>_deserialize`……

`xpc_object_t` 对象通过调用 `xpc_<objectType>_create` 函数创建，该函数内部会调用 `_xpc_base_create(Class, Size)`，用于指定对象的类（`XPC_TYPE_*` 之一）和大小。元数据会额外占用 40 字节，因此对象数据从偏移量 40 字节处开始。\
因此，`xpc_<objectType>_t` 可以看作 `xpc_object_t` 的一种子类，而后者又可以看作 `os_object_t*` 的子类。

> [!WARNING]
> 注意，应由开发者使用 `xpc_dictionary_[get/set]_<objectType>` 来获取或设置键的类型及实际值。

- **`xpc_pipe`**

**`xpc_pipe`** 是一种 FIFO 管道，进程可以使用它进行通信（通信使用 Mach 消息）。\
可以调用 `xpc_pipe_create()` 或 `xpc_pipe_create_from_port()` 创建 XPC server，后者使用指定的 Mach port 创建。随后，可以调用 `xpc_pipe_receive` 和 `xpc_pipe_try_receive` 接收消息。

请注意，**`xpc_pipe`** 对象是一个 **`xpc_object_t`**，其结构中包含所使用的两个 Mach port 以及名称（如果有）。例如，daemon `secinitd` 在其 plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` 中将名为 `com.apple.secinitd` 的管道配置为该名称。

**`xpc_pipe`** 的一个示例是由 **`launchd`** 创建的 **bootstrap pipe**，它能够共享 Mach port。

- **`NSXPC*`**

这些是用于抽象 XPC connections 的高级 Objective-C 对象。\
此外，与前面介绍的对象相比，使用 DTrace 调试这些对象更加容易。

- **`GCD Queues`**

XPC 使用 GCD 传递消息，同时还会生成一些 dispatch queues，例如 `xpc.transactionq`、`xpc.io`、`xpc-events.add-listenerq`、`xpc.service-instance`……

## XPC Services

这些是带有 `.xpc` 扩展名的 bundles，位于其他项目的 **`XPCServices`** 文件夹中，并且在 `Info.plist` 中将 `CFBundlePackageType` 设置为 **`XPC!`**。\
该文件还包含其他配置键，例如 `ServiceType`，其值可以是 Application、User 或 System；`_SandboxProfile`，可用于定义 sandbox；以及 `_AllowedClients`，可用于指示联系该 service 所需的 entitlements 或 identity。这些选项以及其他选项会在 service 启动时对其进行配置。<sup>[[2]](#references)</sup>

### Starting a Service

应用程序使用 `xpc_connection_create_mach_service` 尝试与 XPC service **建立连接**；随后，launchd 定位 daemon 并启动 **`xpcproxy`**。**`xpcproxy`** 强制执行已配置的限制，并使用提供的 file descriptors 和 Mach ports 生成 service。<sup>[[3]](#references)</sup>

为了提高搜索 XPC service 的速度，系统会使用缓存。

可以使用以下方式跟踪 `xpcproxy` 的操作：
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC library 使用 `kdebug`，通过调用 `xpc_ktrace_pid0` 和 `xpc_ktrace_pid1` 来记录操作。它使用的代码未公开，因此需要将其添加到 `/usr/share/misc/trace.codes` 中。这些代码以 `0x29` 为前缀；例如，`0x29000004` 表示 `XPC_serializer_pack`。\
实用程序 `xpcproxy` 使用前缀 `0x22`，例如：`0x2200001c: xpcproxy:will_do_preexec`。

## XPC 事件消息

应用程序可以**订阅**不同的事件**消息**，从而在此类事件发生时按需**启动**它们。这些服务的**配置**位于 l**aunchd plist 文件**中，这些文件位于**与之前文件相同的目录**中，并包含额外的 **`LaunchEvent`** 键。

### XPC 连接进程检查

当进程尝试通过 XPC 连接调用方法时，**XPC 服务应检查该进程是否被允许连接**。以下是常见的验证方法及其缺陷：


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC 授权

Apple 还允许应用**配置授权权限以及调用者获取这些权限的方式**，因此拥有所需权限的进程**可以调用 XPC 服务公开的方法**：


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

要嗅探 XPC 消息，可以使用 **xpcspy**，它使用 **Frida**。<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
另一个可能的工具是 **XPoCe2**。<sup>[[6]](#references)</sup>

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
## XPC Communication Objective-C 代码示例

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
## Dylib 内部的 Client
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

`RemoteXPC.framework`（来自 `libxpc`）提供了在不同主机之间进行 XPC 通信的功能。\
支持 remote XPC 的服务会在其 plist 中包含 `UsesRemoteXPC` key，例如 `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`。虽然该服务已向 `launchd` 注册，但实际功能由 `UserEventAgent` 及其 `com.apple.remoted.plugin` 和 `com.apple.remoteservicediscovery.events.plugin` plugins 提供。

此外，`RemoteServiceDiscovery.framework` 会从 `com.apple.remoted.plugin` 获取信息，并暴露诸如 `get_device`、`get_unique_device` 和 `connect` 等 functions。

当 `connect` 返回服务的 socket file descriptor 后，就可以使用 `remote_xpc_connection_*` class。

可以使用 `/usr/libexec/remotectl` CLI，通过以下命令获取 remote services 的信息：
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
bridgeOS 与 host 之间的通信通过专用 IPv6 接口进行。`MultiverseSupport.framework` 建立用于通信的 sockets，其文件描述符会被用于通信。\
可以使用 `netstat`、`nettop` 或开源替代工具 `netbottom` 找到这些通信。

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — 创建 XPC 服务](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
