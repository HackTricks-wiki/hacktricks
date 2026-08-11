# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 基本信息

XPC 是 macOS 和 iOS 上用于**进程间通信**的框架。它提供了在进程之间进行**安全、异步调用**的机制。XPC 支持**权限分离的应用程序**，其中每个**组件**仅以其所需的**权限**运行，从而限制进程遭到入侵后可能造成的损害。<sup>[[1]](#references)</sup>

XPC 使用一种进程间通信（IPC）形式，它是一组用于让同一系统上运行的不同程序相互发送数据的方法。

XPC 的主要优点包括：

1. **安全性**：通过将工作分配到不同进程中，可以仅向每个进程授予其所需的权限。这意味着即使某个进程遭到入侵，其造成危害的能力也受到限制。
2. **稳定性**：XPC 有助于将崩溃隔离在发生崩溃的组件中。如果某个进程崩溃，可以在不影响系统其余部分的情况下重新启动它。
3. **性能**：XPC 便于实现并发，因为不同任务可以在不同进程中同时运行。

主要的**缺点**是，将**应用程序拆分为多个进程**并让它们通过 XPC 通信会产生额外开销。在现代系统中，与安全性和稳定性带来的收益相比，这种开销通常很小。<sup>[[1]](#references)</sup>

## 应用程序专用的 XPC Services

应用程序的 XPC 组件位于**应用程序自身内部**。例如，在 Safari 中可以在 **`/Applications/Safari.app/Contents/XPCServices`** 找到它们。它们的扩展名为 **`.xpc`**（例如 **`com.apple.Safari.SandboxBroker.xpc`**），并且**也是 bundle**，其中包含主二进制文件和一个 `Info.plist`。例如：`/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` 和 `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`。<sup>[[2]](#references)</sup>

一个**XPC 组件可以拥有不同于其他 XPC 组件或主应用程序二进制文件的 entitlements 和权限**。有一个例外：如果 XPC service 在其 **Info.plist** 文件中将 **`JoinExistingSession`** 设置为 `true`，则该 XPC service 会加入调用它的**应用程序所使用的同一安全会话**。<sup>[[4]](#references)</sup>

XPC services 在需要时由 **launchd** **启动**，并且在其任务**完成**后可以被**关闭**，以释放系统资源。**应用程序专用的 XPC 组件只能由其所属应用程序使用**，从而减少潜在漏洞的暴露面。<sup>[[2]](#references)</sup>

## 系统范围的 XPC Services

与应用程序专用的 services 不同，系统范围的 XPC services 不受其所属应用程序限制。根据 launchd domain 和 service 自身的授权检查，它们可能可由多个用户的 clients 访问。这些由 launchd 管理的 Mach services 需要在位于 **`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`** 或 **`/Library/LaunchAgents`** 等目录中的 **plist** 文件内进行**定义**。<sup>[[2]](#references)[[3]](#references)</sup>

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

XPC 请求和回复 payload 通常是字典对象，这简化了序列化和反序列化。`libxpc.dylib` 还声明了验证接收数据是否为预期类型所需的数据类型。在 C API 中，每个对象都是一个 `xpc_object_t`（并且可以使用 `xpc_get_type(object)` 检查其类型）。<sup>[[2]](#references)</sup>\
此外，可以使用函数 `xpc_copy_description(object)` 获取对象的字符串表示，这对于调试很有用。\
这些对象还具有一些可调用的方法，例如 `xpc_<object>_copy`、`xpc_<object>_equal`、`xpc_<object>_hash`、`xpc_<object>_serialize`、`xpc_<object>_deserialize`……

`xpc_object_t` 对象通过调用 `xpc_<objectType>_create` 函数创建，该函数内部会调用 `_xpc_base_create(Class, Size)`，指明对象的类（`XPC_TYPE_*` 中的一个）和大小。元数据会额外增加 40 字节，因此对象数据从偏移 40 字节处开始。\
因此，`xpc_<objectType>_t` 可以看作 `xpc_object_t` 的子类，而后者又可以看作 `os_object_t*` 的子类。

> [!WARNING]
> 注意，应由开发者使用 `xpc_dictionary_[get/set]_<objectType>` 来获取或设置键的类型和实际值。

- **`xpc_pipe`**

**`xpc_pipe`** 是一种 FIFO 管道，进程可以使用它进行通信（通信使用 Mach messages）。\
可以调用 `xpc_pipe_create()` 或 `xpc_pipe_create_from_port()` 创建 XPC server，后者使用指定的 Mach port 创建。随后，可以调用 `xpc_pipe_receive` 和 `xpc_pipe_try_receive` 接收消息。

注意，**`xpc_pipe`** 对象是一个 **`xpc_object_t`**，其结构中包含所使用的两个 Mach ports 以及名称（如果有）。例如，daemon `secinitd` 在其 plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` 中将名为 `com.apple.secinitd` 的管道进行配置。

**`xpc_pipe`** 的一个示例是由 **`launchd`** 创建的 **bootstrap pipe**，它使 Mach ports 能够被共享。

- **`NSXPC*`**

这些是用于抽象 XPC connections 的高级 Objective-C objects。\
此外，与前面提到的对象相比，使用 DTrace 调试这些对象更加容易。

- **`GCD Queues`**

XPC 使用 GCD 传递消息，同时还会生成某些 dispatch queues，例如 `xpc.transactionq`、`xpc.io`、`xpc-events.add-listenerq`、`xpc.service-instance`……

## XPC Services

这些是扩展名为 `.xpc` 的 bundles，位于其他项目的 **`XPCServices`** 文件夹中，并且在 `Info.plist` 中将 `CFBundlePackageType` 设置为 **`XPC!`**。\
该文件还包含其他配置键，例如 `ServiceType`，其值可以是 Application、User 或 System；`_SandboxProfile`，用于定义 sandbox；以及 `_AllowedClients`，用于指示联系该 service 所需的 entitlements 或 identity。这些选项及其他选项会在 service 启动时对其进行配置。<sup>[[2]](#references)</sup>

### Starting a Service

应用程序通过 `xpc_connection_create_mach_service` 尝试连接到 XPC service；随后 launchd 定位 daemon 并启动 **`xpcproxy`**。**`xpcproxy`** 强制执行已配置的限制，并使用所提供的 file descriptors 和 Mach ports 派生该 service。<sup>[[3]](#references)</sup>

为了提高搜索 XPC service 的速度，系统会使用 cache。

可以使用以下方式跟踪 `xpcproxy` 的操作：
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC library 使用 `kdebug`，通过调用 `xpc_ktrace_pid0` 和 `xpc_ktrace_pid1` 记录操作。它使用的代码没有文档说明，因此需要将其添加到 `/usr/share/misc/trace.codes`。这些代码以 `0x29` 为前缀；例如，`0x29000004` 表示 `XPC_serializer_pack`。\
工具 `xpcproxy` 使用前缀 `0x22`，例如：`0x2200001c: xpcproxy:will_do_preexec`。

## XPC 事件消息

应用程序可以 **订阅** 不同的事件 **消息**，从而在此类事件发生时按需 **启动**。这些服务的 **配置** 位于 l**aunchd plist 文件**中，这些文件位于**与前面文件相同的目录**，并且包含额外的 **`LaunchEvent`** 键。

### XPC 连接进程检查

当进程尝试通过 XPC connection 调用某个方法时，**XPC service 应检查该进程是否被允许连接**。以下是常见的验证方法及其缺陷：


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple 还允许应用**配置 authorization rights 以及调用方获取这些 rights 的方式**，因此拥有所需 rights 的进程**可以调用 XPC service 暴露的方法**：


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

要 sniff XPC 消息，可以使用 **xpcspy**，它使用 **Frida**。<sup>[[5]](#references)</sup>
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

## XPC 通信 C 代码示例

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
## XPC 通信 Objective-C 代码示例

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
## Dylib 内的 Client
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
支持 remote XPC 的服务会在其 plist 中包含 `UsesRemoteXPC` key，例如 `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`。尽管该服务已向 `launchd` 注册，但实际功能由 `UserEventAgent` 及其 `com.apple.remoted.plugin` 和 `com.apple.remoteservicediscovery.events.plugin` plugins 提供。

此外，`RemoteServiceDiscovery.framework` 会从 `com.apple.remoted.plugin` 获取信息，并公开 `get_device`、`get_unique_device` 和 `connect` 等 functions。

当 `connect` 返回服务的 socket file descriptor 后，即可使用 `remote_xpc_connection_*` class。

可以使用 `/usr/libexec/remotectl` CLI，通过如下 commands 获取有关 remote services 的信息：
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
bridgeOS 与主机之间的通信通过专用 IPv6 接口进行。`MultiverseSupport.framework` 建立用于通信的 sockets，其文件描述符会被使用。\
可以使用 `netstat`、`nettop` 或开源替代工具 `netbottom` 查找这些通信。

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — 创建 XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
