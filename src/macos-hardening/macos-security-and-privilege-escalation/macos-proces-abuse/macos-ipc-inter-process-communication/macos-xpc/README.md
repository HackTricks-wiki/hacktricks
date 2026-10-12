# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 基本信息

XPC 是 macOS 和 iOS 上用于**进程间通信**的框架。它提供了在进程之间进行**安全异步调用**的机制。XPC 支持**权限分离的应用程序**，其中每个**组件**仅以**所需的权限**运行，从而限制进程遭到入侵后可能造成的损害。<sup>[[1]](#references)</sup>

XPC 使用一种进程间通信（IPC）形式。IPC 是一组方法，可供在同一系统上运行的不同程序相互发送数据。

XPC 的主要优势包括：

1. **安全性**：将工作拆分到不同的进程中后，可以只为每个进程授予其所需的权限。这意味着即使某个进程遭到入侵，其造成损害的能力也有限。
2. **稳定性**：XPC 有助于将崩溃限制在发生崩溃的组件中。如果某个进程崩溃，可以重启该进程，而不会影响系统的其余部分。
3. **性能**：XPC 可以轻松实现并发，因为不同任务可以在不同进程中同时运行。

主要**缺点**是，**将应用程序拆分为多个进程**并通过 XPC 进行通信会带来额外开销。在现代系统上，与安全性和稳定性方面的优势相比，这种开销通常很小。<sup>[[1]](#references)</sup>

## 特定于应用程序的 XPC 服务

应用程序的 XPC 组件**位于应用程序本身内部**。例如，在 Safari 中，可以在 **`/Applications/Safari.app/Contents/XPCServices`** 找到它们。它们的扩展名为 **`.xpc`**（例如 **`com.apple.Safari.SandboxBroker.xpc`**），并且**也是 bundle**，内部包含主二进制文件和 `Info.plist`。例如：`/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` 和 `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`。<sup>[[2]](#references)</sup>

**XPC 组件可以拥有不同于其他 XPC 组件或主应用程序二进制文件的 entitlement 和权限**。例外情况是，在 **Info.plist** 文件中将 **`JoinExistingSession`** 设为 `true` 的 XPC 服务。在这种情况下，XPC 服务会加入**调用它的应用程序所在的同一个安全会话**。<sup>[[4]](#references)</sup>

XPC 服务会在需要时由 **launchd** **启动**，并可在任务**完成**后**关闭**，以释放系统资源。**特定于应用程序的 XPC 组件只能由其所属的应用程序使用**，从而减少潜在漏洞的暴露面。<sup>[[2]](#references)</sup>

## 系统范围的 XPC 服务

与特定于应用程序的服务不同，系统范围的 XPC 服务不受其所属应用程序的限制。根据 launchd 域和服务自身的授权检查，这些服务可能可由多个用户的客户端访问。这些由 launchd 管理的 Mach 服务需要在 **`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`** 或 **`/Library/LaunchAgents`** 等目录中的 **plist** 文件里定义。<sup>[[2]](#references)[[3]](#references)</sup>

这些 plist 文件包含一个 **`MachServices`** 键，用于指定服务名称，以及一个 **`Program`** 键，用于指定二进制文件的路径：

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

以 root 身份运行的 **`LaunchDaemons`** 服务很常见。因此，如果非特权进程能够访问这些服务暴露的易受攻击方法，就可能借此提升权限。

## XPC 对象

- **`xpc_object_t`**

XPC 请求和回复的 payload 通常是字典对象，可简化序列化和反序列化。`libxpc.dylib` 还声明了用于验证接收数据是否为预期类型的数据类型。在 C API 中，每个对象都是 `xpc_object_t`（其类型可使用 `xpc_get_type(object)` 检查）。<sup>[[2]](#references)</sup>\
此外，可以使用函数 `xpc_copy_description(object)` 获取对象的字符串表示，这有助于调试。\
这些对象还有一些可调用的方法，例如 `xpc_<object>_copy`、`xpc_<object>_equal`、`xpc_<object>_hash`、`xpc_<object>_serialize`、`xpc_<object>_deserialize`……

通过调用 `xpc_<objectType>_create` 函数创建 `xpc_object_t` 对象，该函数内部会调用 `_xpc_base_create(Class, Size)`，指定对象的类（`XPC_TYPE_*` 之一）和大小。元数据会额外占用 40 字节，因此对象数据从偏移量 40 字节处开始。\
因此，`xpc_<objectType>_t` 可以视为 `xpc_object_t` 的子类，而 `xpc_object_t` 又是 `os_object_t*` 的子类。

> [!WARNING]
> 请注意，应由开发者使用 `xpc_dictionary_[get/set]_<objectType>` 来获取或设置键的类型和实际值。

- **`xpc_pipe`**

**`xpc_pipe`** 是一种 FIFO 管道，进程可用它进行通信（通信使用 Mach 消息）。\
可以调用 `xpc_pipe_create()` 创建 XPC server，也可以调用 `xpc_pipe_create_from_port()` 使用指定的 Mach 端口创建。随后，可调用 `xpc_pipe_receive` 和 `xpc_pipe_try_receive` 接收消息。

请注意，**`xpc_pipe`** 对象是一个 **`xpc_object_t`**，其结构体中包含所用两个 Mach 端口的信息以及名称（如果有）。例如，守护进程 `secinitd` 在其 plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` 中配置了名为 `com.apple.secinitd` 的管道。

**`xpc_pipe`** 的一个示例是由 **`launchd`** 创建的 **bootstrap pipe**，它可用于共享 Mach 端口。

- **`NSXPC*`**

这些是用于抽象 XPC 连接的高层 Objective-C 对象。\
此外，相比前面提到的对象，使用 DTrace 调试这些对象更容易。

- **`GCD 队列`**

XPC 使用 GCD 传递消息，还会生成一些 dispatch 队列，例如 `xpc.transactionq`、`xpc.io`、`xpc-events.add-listenerq`、`xpc.service-instance`……

## XPC 服务

这些是扩展名为 **`.xpc`** 的 **bundles**，位于其他项目的 **`XPCServices`** 文件夹中；其 `Info.plist` 中的 `CFBundlePackageType` 设置为 **`XPC!`**。\
此文件还包含其他配置键，例如 `ServiceType`（可为 Application、User 或 System）、可定义 sandbox 的 `_SandboxProfile`，以及可能指明联系该服务所需 entitlement 或身份的 `_AllowedClients`。这些选项及其他选项会在服务启动时对其进行配置。<sup>[[2]](#references)</sup>

### 启动服务

应用会尝试使用 `xpc_connection_create_mach_service` 连接到 XPC 服务；随后 launchd 会定位守护进程并启动 **`xpcproxy`**。**`xpcproxy`** 会强制执行已配置的限制，并使用提供的文件描述符和 Mach 端口生成服务进程。<sup>[[3]](#references)</sup>

为了加快搜索 XPC 服务的速度，系统会使用缓存。

可以使用以下命令跟踪 `xpcproxy` 的操作：

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

XPC 库通过调用 `xpc_ktrace_pid0` 和 `xpc_ktrace_pid1`，使用 `kdebug` 记录操作。它使用的代码没有文档说明，因此需要将它们添加到 `/usr/share/misc/trace.codes`。这些代码以 `0x29` 为前缀；例如，`0x29000004` 表示 `XPC_serializer_pack`。\
`xpcproxy` 工具使用 `0x22` 前缀，例如：`0x2200001c: xpcproxy:will_do_preexec`。

## 审计 Application 类型的 XPC 辅助程序

审计框架提供的辅助程序时，`XPCService.ServiceType` 为 `Application` 是一个很好的起点：枚举 bundles，保留正在运行的服务，并检查辅助程序的标识符和 entitlements。在 `/System/Library/Frameworks` 和 `/System/Library/PrivateFrameworks` 中都进行搜索；具体清单会随 macOS 版本而变化。<sup>[[7]](#references)</sup>

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

### 梳理 listener 并还原最小协议

在 helper 中定位 `-[<delegate> listener:shouldAcceptNewConnection:]`。如果某条路径设置了 `exportedInterface` 和 `exportedObject`，恢复 connection，并在未检查对端的 audit token、code requirement 或 entitlement 的情况下返回 `YES`/`1`，那么任何能够解析该 service 的 client 都可以访问 RPC interface。这只能证明**可达性**：要产生实际影响，仍需存在某个导出方法，它在缺乏充分的按 client/按方法授权的情况下执行特权操作，或不安全地处理攻击者控制的输入。<sup>[[7]](#references)</sup>

只还原测试所需的 selectors。Objective-C selector 元数据会显示参数数量；反编译器中的参数用法通常可以进一步确定类型（例如，传递给 `-[EKEvent setStartDate:]` 和 `setEndDate:` 的值是 `NSDate *`），而方法末尾的间接调用则会显示 reply block 的参数。对于 `NSXPCInterface`，部分本地 protocol 已经足够；不需要还原完整的私有 protocol。<sup>[[7]](#references)</sup>

### 使用还原出的 interface 建立连接

对于 application XPC service，加载定义所需私有类的任意 framework，使用 `initWithServiceName:` 创建 connection，设置还原出的 remote interface，安装 error/interruption/invalidation handlers，然后再恢复 connection。保持 run loop 运行，以接收异步回复。测试 sandbox 边界时，应在 sandboxed application 内重新运行 client——独立运行的 client 成功，并不能证明发生了 sandbox escape。<sup>[[7]](#references)</sup>

<details>
<summary>最简 Objective-C client</summary>

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

使用 `clang -fblocks -framework Foundation -o xpc_client xpc_client.m` 编译。<sup>[[7]](#references)</sup>

</details>

### 将安全编码失败用作类型预言机

`NSCocoaErrorDomain` 错误（例如代码 `4101`）可能会隐藏有用的序列化异常。在 macOS unified log/Console 中搜索服务名称：异常会指出意外的类，以及该选择器参数允许使用的类。对于回复，使用 `setClasses:forSelector:argumentIndex:ofReply:` 扩展**客户端**接口的允许类列表；设置 `ofReply:YES` 时，索引 `0` 表示回复 block 的第一个参数，而不是方法的第一个参数。<sup>[[7]](#references)</sup>

在将接口分配给连接并调用 `[c resume]` 之前配置接口：<sup>[[7]](#references)</sup>

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

反向情况也很有用：如果服务器拒绝 Foundation 输入，并记录了一个允许的私有类，日志就会揭示预期的 wire 类型及其所属 framework。加载该 framework，检查类的方法/属性以进一步确定泛型 `id` 类型，并动态构造私有对象。`NSInvocation` 参数从索引 `2` 开始，因为索引 `0` 和 `1` 是隐藏的 `self` 和 `_cmd` 参数。<sup>[[7]](#references)</sup>

<details>
<summary>使用 NSInvocation 构造私有参数</summary>

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

对于针对由 launchd 注册的系统级 Mach 服务的相关工作流，请参阅：

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## XPC 事件消息

应用程序可以**订阅**不同的事件**消息**，从而在此类事件发生时**按需启动**。这些服务的**设置**在 l**aunchd plist files** 中完成，这些文件位于**与前述文件相同的目录**中，并包含额外的 **`LaunchEvent`** 键。

### XPC 连接进程检查

当进程尝试通过 XPC 连接调用方法时，**XPC 服务应检查该进程是否获准连接**。以下是常见的验证方法及其缺陷：


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC 授权

Apple 还允许应用程序**配置授权权限以及调用方如何获取这些权限**，因此，拥有所需权限的进程**可以调用 XPC 服务公开的方法**：


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

要捕获 XPC 消息，可以使用 **xpcspy**，它使用 **Frida**。<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

另一种可能的工具是 **XPoCe2**。<sup>[[6]](#references)</sup>

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

## Dylib 内部的客户端

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

`RemoteXPC.framework`（来自 `libxpc`）提供的功能允许不同主机之间进行 XPC 通信。\
支持 remote XPC 的服务会在其 plist 中包含 `UsesRemoteXPC` 键，例如 `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`。虽然该服务已向 `launchd` 注册，但相关功能由 `UserEventAgent` 及其 `com.apple.remoted.plugin` 和 `com.apple.remoteservicediscovery.events.plugin` 插件提供。

此外，`RemoteServiceDiscovery.framework` 会从 `com.apple.remoted.plugin` 获取信息，并公开 `get_device`、`get_unique_device` 和 `connect` 等函数。

`connect` 返回服务的 socket 文件描述符后，就可以使用 `remote_xpc_connection_*` 类。

可以使用 `/usr/libexec/remotectl` CLI 及以下命令获取远程服务的信息：

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

bridgeOS 与 host 之间通过专用 IPv6 接口进行通信。`MultiverseSupport.framework` 会创建用于通信的 socket，其文件描述符将用于通信。\
可以使用 `netstat`、`nettop` 或开源替代工具 `netbottom` 查找这些通信。

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — 创建 XPC 服务](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - 攻击 macOS XPC Helpers：协议逆向工程](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
