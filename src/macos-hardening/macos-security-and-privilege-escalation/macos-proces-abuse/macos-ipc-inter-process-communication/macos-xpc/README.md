# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basic Information

XPC 代表 XNU（macOS 使用的 kernel）进程间通信，是 macOS 和 iOS 上用于**进程之间通信**的 framework。XPC 提供了一种机制，用于在系统上的不同进程之间进行**安全的异步方法调用**。它是 Apple security paradigm 的一部分，允许创建**权限分离的应用程序**，其中每个**组件**仅使用完成工作所需的**权限**，从而限制进程被 compromise 后可能造成的损害。

XPC 使用一种进程间通信（IPC）形式，即一组用于让运行在同一系统上的不同程序相互发送数据的方法。

XPC 的主要优势包括：

1. **Security**：通过将工作分离到不同进程中，可以只向每个进程授予其所需的权限。这意味着即使某个进程被 compromise，其造成危害的能力也会受到限制。
2. **Stability**：XPC 有助于将 crash 隔离在发生问题的组件中。如果某个进程 crash，可以在不影响系统其余部分的情况下重新启动。
3. **Performance**：XPC 可以轻松实现 concurrency，因为不同任务可以在不同进程中同时运行。

唯一的**缺点**是，将一个应用程序**分离为多个进程**并让它们通过 XPC 通信，效率会**更低**。但在如今的系统中，这种差异几乎无法察觉，而其优势更为明显。

## Application Specific XPC services

应用程序的 XPC 组件**位于应用程序自身内部**。例如，在 Safari 中可以在 **`/Applications/Safari.app/Contents/XPCServices`** 找到它们。它们的扩展名为 **`.xpc`**（例如 **`com.apple.Safari.SandboxBroker.xpc`**），并且**也是 bundles**，其中包含主 binary：`/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`，以及一个 `Info.plist`：`/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

正如你可能想到的，**XPC component 的 entitlements 和 privileges** 会与其他 XPC component 或主 app binary 不同。**例外情况**是：如果 XPC service 在其 **Info.plist** 文件中配置了 [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)，并将其设置为 “True”。在这种情况下，XPC service 将在**与调用它的应用程序相同的 security session 中**运行。

XPC services 会在需要时由 **launchd** **启动**，并在所有任务**完成**后关闭，以释放系统资源。**Application-specific XPC components 只能由所属应用程序使用**，从而降低潜在漏洞带来的风险。

## System Wide XPC services

System-wide XPC services 可供所有用户访问。这些 services 可以是 launchd 类型或 Mach 类型，需要在位于指定目录中的 **plist** 文件内进行**定义**，例如 **`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`** 或 **`/Library/LaunchAgents`**。

这些 plist 文件将包含一个名为 **`MachServices`** 的 key，其中记录 service 的名称；还会包含一个名为 **`Program`** 的 key，其中记录 binary 的路径：
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
`**LaunchDameons**` 中的服务由 root 运行。因此，如果非特权进程能够与其中一个服务通信，就可能实现权限提升。

## XPC 对象

- **`xpc_object_t`**

每条 XPC 消息都是一个字典对象，可简化序列化和反序列化过程。此外，`libxpc.dylib` 声明了大多数数据类型，因此可以确保接收到的数据属于预期类型。在 C API 中，每个对象都是一个 `xpc_object_t`（可以使用 `xpc_get_type(object)` 检查其类型）。\
此外，可以使用函数 `xpc_copy_description(object)` 获取对象的字符串表示，这对调试很有用。\
这些对象还提供了一些可调用的方法，例如 `xpc_<object>_copy`、`xpc_<object>_equal`、`xpc_<object>_hash`、`xpc_<object>_serialize`、`xpc_<object>_deserialize`……

调用 `xpc_<objetType>_create` 函数可以创建 `xpc_object_t`。该函数内部会调用 `_xpc_base_create(Class, Size)`，其中会指定对象类的类型（`XPC_TYPE_*` 之一）及其大小（大小中还会额外增加 40B 用于存储元数据）。这意味着对象的数据将从偏移量 40B 处开始。\
因此，`xpc_<objectType>_t` 类似于 `xpc_object_t` 的子类，而后者又可以视为 `os_object_t*` 的子类。

> [!WARNING]
> 注意，应由 developer 使用 `xpc_dictionary_[get/set]_<objectType>` 来获取或设置键的类型及实际值。

- **`xpc_pipe`**

**`xpc_pipe`** 是一种 FIFO 管道，进程可以使用它进行通信（通信使用 Mach 消息）。\
可以调用 `xpc_pipe_create()` 创建 XPC server，也可以调用 `xpc_pipe_create_from_port()` 使用指定的 Mach port 创建它。随后，可以调用 `xpc_pipe_receive` 和 `xpc_pipe_try_receive` 来接收消息。

注意，**`xpc_pipe`** 对象是一个 **`xpc_object_t`**，其结构体中包含所使用的两个 Mach port 以及名称（如果有）等信息。例如，daemon `secinitd` 在其 plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` 中配置了名为 `com.apple.secinitd` 的 pipe。

**`xpc_pipe`** 的一个例子是由 **`launchd`** 创建的 bootstrap pipe，它可以实现 Mach port 的共享。

- **`NSXPC*`**

这些是 Objective-C 高级对象，用于抽象 XPC connections。\
此外，与前面的对象相比，使用 DTrace 调试这些对象更加容易。

- **`GCD Queues`**

XPC 使用 GCD 传递消息，同时还会生成一些 dispatch queues，例如 `xpc.transactionq`、`xpc.io`、`xpc-events.add-listenerq`、`xpc.service-instance`……

## XPC Services

这些是扩展名为 `.xpc` 的 bundles，位于其他 projects 的 **`XPCServices`** 文件夹中，并且在其 `Info.plist` 中将 `CFBundlePackageType` 设置为 **`XPC!`**。\
该文件还包含其他配置键，例如可以是 Application、User 或 System 的 `ServiceType`，可以定义 sandbox 的 `_SandboxProfile`，或者可能指示联系该 service 所需的 entitlements 或 ID 的 `_AllowedClients`。这些及其他配置选项将在 service 启动时用于对其进行配置。

### 启动 Service

应用程序使用 `xpc_connection_create_mach_service` 尝试连接到 XPC service，随后 launchd 定位 daemon 并启动 **`xpcproxy`**。**`xpcproxy`** 强制执行已配置的限制，并使用提供的 FDs 和 Mach ports 生成 service。

为了提高 XPC service 的搜索速度，系统会使用 cache。

可以使用以下方式跟踪 `xpcproxy` 的操作：
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC library 使用 `kdebug` 记录操作，调用 `xpc_ktrace_pid0` 和 `xpc_ktrace_pid1`。它使用的代码没有文档说明，因此需要将其添加到 `/usr/share/misc/trace.codes` 中。这些代码以 `0x29` 为前缀，例如 `0x29000004`：`XPC_serializer_pack`。\
实用程序 `xpcproxy` 使用 `0x22` 前缀，例如：`0x2200001c: xpcproxy:will_do_preexec`。

## XPC Event Messages

应用程序可以 **订阅**不同的事件**消息**，从而在此类事件发生时按需**启动**。这些服务的**配置**在 **launchd plist 文件**中完成，这些文件位于**与前面文件相同的目录**中，并包含额外的 **`LaunchEvent`** 键。

### XPC Connecting Process Check

当进程尝试通过 XPC 连接调用某个方法时，**XPC service 应检查该进程是否被允许连接**。以下是常见的检查方式及常见陷阱：


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple 还允许应用程序**配置某些权限以及获取这些权限的方式**，因此，如果调用进程拥有这些权限，它就会被**允许调用** XPC service 中的方法：


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

要 sniff XPC 消息，可以使用 [**xpcspy**](https://github.com/hot3eed/xpcspy)，它使用 **Frida**。
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
另一个可使用的工具是 [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html)。

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
## Dylb 代码中的客户端
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

`RemoteXPC.framework`（来自 `libxpc`）提供的此功能允许通过 XPC 与不同主机进行通信。\
支持 remote XPC 的服务会在其 plist 中包含 `UsesRemoteXPC` 键，例如 `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`。不过，尽管该服务会注册到 `launchd`，但实际提供此功能的是 `UserEventAgent` 及其插件 `com.apple.remoted.plugin` 和 `com.apple.remoteservicediscovery.events.plugin`。

此外，`RemoteServiceDiscovery.framework` 允许从 `com.apple.remoted.plugin` 获取信息，并暴露了 `get_device`、`get_unique_device`、`connect` 等函数。

使用 `connect` 并获取服务的 socket `fd` 后，即可使用 `remote_xpc_connection_*` 类。

可以使用 CLI 工具 `/usr/libexec/remotectl` 并传入以下参数来获取远程服务的信息：
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOS 与主机之间的通信通过专用 IPv6 接口进行。`MultiverseSupport.framework` 可用于建立套接字，其 `fd` 将用于通信。\
可以使用 `netstat`、`nettop` 或开源选项 `netbottom` 查找这些通信。

{{#include ../../../../../banners/hacktricks-training.md}}
