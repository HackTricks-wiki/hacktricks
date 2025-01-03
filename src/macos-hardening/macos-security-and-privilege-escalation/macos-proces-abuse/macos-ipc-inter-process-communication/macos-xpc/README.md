# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 基本信息

XPC，即 XNU（macOS 使用的内核）进程间通信，是一个用于 **macOS 和 iOS 上进程之间通信** 的框架。XPC 提供了一种机制，用于在系统上进行 **安全的、异步的方法调用**。它是苹果安全范式的一部分，允许 **创建特权分离的应用程序**，每个 **组件** 仅以 **执行其工作所需的权限** 运行，从而限制了被攻陷进程可能造成的损害。

XPC 使用一种进程间通信（IPC）的形式，这是一组方法，允许在同一系统上运行的不同程序相互发送数据。

XPC 的主要优点包括：

1. **安全性**：通过将工作分离到不同的进程中，每个进程仅被授予所需的权限。这意味着即使一个进程被攻陷，它的危害能力也有限。
2. **稳定性**：XPC 有助于将崩溃隔离到发生崩溃的组件。如果一个进程崩溃，可以在不影响系统其余部分的情况下重新启动。
3. **性能**：XPC 允许轻松的并发，因为不同的任务可以在不同的进程中同时运行。

唯一的 **缺点** 是 **将应用程序分离为多个进程** 并通过 XPC 进行通信的 **效率较低**。但在今天的系统中，这几乎是不可察觉的，且其好处更为明显。

## 应用特定的 XPC 服务

应用程序的 XPC 组件是 **在应用程序内部**。例如，在 Safari 中，您可以在 **`/Applications/Safari.app/Contents/XPCServices`** 中找到它们。它们的扩展名为 **`.xpc`**（如 **`com.apple.Safari.SandboxBroker.xpc`**），并且 **也与主二进制文件捆绑** 在一起：`/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` 和 `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

正如您可能想到的，**XPC 组件将具有不同的权限和特权**，与其他 XPC 组件或主应用程序二进制文件不同。除非 XPC 服务在其 **Info.plist** 文件中配置了 [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) 设置为“True”。在这种情况下，XPC 服务将在 **与调用它的应用程序相同的安全会话中** 运行。

XPC 服务由 **launchd** 在需要时 **启动**，并在所有任务 **完成** 后 **关闭** 以释放系统资源。**应用程序特定的 XPC 组件只能由该应用程序使用**，从而降低了与潜在漏洞相关的风险。

## 系统范围的 XPC 服务

系统范围的 XPC 服务对所有用户可用。这些服务，无论是 launchd 还是 Mach 类型，都需要在指定目录中的 plist 文件中 **定义**，例如 **`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`** 或 **`/Library/LaunchAgents`**。

这些 plist 文件将具有一个名为 **`MachServices`** 的键，包含服务的名称，以及一个名为 **`Program`** 的键，包含二进制文件的路径：
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
**`LaunchDameons`** 中的进程由 root 运行。因此，如果一个无权限的进程能够与其中一个进程通信，它可能能够提升权限。

## XPC 对象

- **`xpc_object_t`**

每个 XPC 消息都是一个字典对象，简化了序列化和反序列化。此外，`libxpc.dylib` 声明了大多数数据类型，因此可以确保接收到的数据是预期的类型。在 C API 中，每个对象都是 `xpc_object_t`（其类型可以使用 `xpc_get_type(object)` 检查）。\
此外，函数 `xpc_copy_description(object)` 可用于获取对象的字符串表示，这对于调试非常有用。\
这些对象还具有一些可调用的方法，如 `xpc_<object>_copy`、`xpc_<object>_equal`、`xpc_<object>_hash`、`xpc_<object>_serialize`、`xpc_<object>_deserialize`...

`xpc_object_t` 是通过调用 `xpc_<objetType>_create` 函数创建的，该函数内部调用 `_xpc_base_create(Class, Size)`，其中指明了对象的类类型（`XPC_TYPE_*` 之一）和大小（额外的 40B 将被添加到大小以存储元数据）。这意味着对象的数据将从偏移量 40B 开始。\
因此，`xpc_<objectType>_t` 是 `xpc_object_t` 的一种子类，而 `xpc_object_t` 则是 `os_object_t*` 的子类。

> [!WARNING]
> 请注意，应该由开发者使用 `xpc_dictionary_[get/set]_<objectType>` 来获取或设置键的类型和实际值。

- **`xpc_pipe`**

**`xpc_pipe`** 是一个 FIFO 管道，进程可以用来进行通信（通信使用 Mach 消息）。\
可以通过调用 `xpc_pipe_create()` 或 `xpc_pipe_create_from_port()` 创建 XPC 服务器，后者使用特定的 Mach 端口创建它。然后，可以调用 `xpc_pipe_receive` 和 `xpc_pipe_try_receive` 来接收消息。

请注意，**`xpc_pipe`** 对象是一个 **`xpc_object_t`**，其结构中包含有关使用的两个 Mach 端口和名称（如果有）的信息。例如，守护进程 `secinitd` 在其 plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` 中配置了名为 `com.apple.secinitd` 的管道。

**`xpc_pipe`** 的一个示例是 **`launchd`** 创建的 **bootstrap pipe**，使得共享 Mach 端口成为可能。

- **`NSXPC*`**

这些是 Objective-C 高级对象，允许对 XPC 连接进行抽象。\
此外，使用 DTrace 调试这些对象比前面的对象更容易。

- **`GCD 队列`**

XPC 使用 GCD 传递消息，此外它生成某些调度队列，如 `xpc.transactionq`、`xpc.io`、`xpc-events.add-listenerq`、`xpc.service-instance`...

## XPC 服务

这些是位于其他项目的 **`XPCServices`** 文件夹中的 **`.xpc`** 扩展包，在 `Info.plist` 中，它们的 `CFBundlePackageType` 设置为 **`XPC!`**。\
该文件具有其他配置键，如 `ServiceType`，可以是 Application、User、System 或 `_SandboxProfile`，可以定义沙箱或 `_AllowedClients`，可能指示与服务联系所需的权限或 ID。这些和其他配置选项在服务启动时将有助于配置服务。

### 启动服务

应用程序尝试使用 `xpc_connection_create_mach_service` **连接** 到 XPC 服务，然后 launchd 定位守护进程并启动 **`xpcproxy`**。**`xpcproxy`** 强制执行配置的限制，并使用提供的 FDs 和 Mach 端口生成服务。

为了提高 XPC 服务搜索的速度，使用了缓存。

可以使用以下方法跟踪 `xpcproxy` 的操作：
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC库使用`kdebug`记录调用`xpc_ktrace_pid0`和`xpc_ktrace_pid1`的操作。它使用的代码没有文档，因此需要将其添加到`/usr/share/misc/trace.codes`中。它们的前缀是`0x29`，例如其中一个是`0x29000004`：`XPC_serializer_pack`。\
实用程序`xpcproxy`使用前缀`0x22`，例如：`0x2200001c: xpcproxy:will_do_preexec`。

## XPC事件消息

应用程序可以**订阅**不同的事件**消息**，使其能够在发生此类事件时**按需启动**。这些服务的**设置**在**launchd plist文件**中完成，位于**与之前相同的目录**中，并包含一个额外的**`LaunchEvent`**键。

### XPC连接进程检查

当一个进程尝试通过XPC连接调用一个方法时，**XPC服务应该检查该进程是否被允许连接**。以下是检查的常见方法和常见陷阱：

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC授权

苹果还允许应用程序**配置一些权限以及如何获取它们**，因此如果调用进程拥有这些权限，它将**被允许调用**XPC服务中的方法：

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC嗅探器

要嗅探XPC消息，可以使用[**xpcspy**](https://github.com/hot3eed/xpcspy)，它使用**Frida**。
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
另一个可能使用的工具是 [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html)。

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
## 客户端在 Dylb 代码中
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

此功能由 `RemoteXPC.framework`（来自 `libxpc`）提供，允许通过不同主机进行 XPC 通信。\
支持远程 XPC 的服务将在其 plist 中具有键 UsesRemoteXPC，就像 `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` 的情况一样。然而，尽管该服务将与 `launchd` 注册，但提供该功能的是 `UserEventAgent`，其插件为 `com.apple.remoted.plugin` 和 `com.apple.remoteservicediscovery.events.plugin`。

此外，`RemoteServiceDiscovery.framework` 允许从 `com.apple.remoted.plugin` 获取信息，暴露出如 `get_device`、`get_unique_device`、`connect` 等函数...

一旦使用 connect 并收集到服务的 socket `fd`，就可以使用 `remote_xpc_connection_*` 类。

可以使用 CLI 工具 `/usr/libexec/remotectl` 获取有关远程服务的信息，使用的参数包括：
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOS与主机之间的通信通过专用的IPv6接口进行。`MultiverseSupport.framework`允许建立套接字，其`fd`将用于通信。\
可以使用`netstat`、`nettop`或开源选项`netbottom`找到这些通信。

{{#include ../../../../../banners/hacktricks-training.md}}
