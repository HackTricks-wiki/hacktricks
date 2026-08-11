# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 基本情報

XPCは、macOSおよびiOSにおける**プロセス間の通信**のためのフレームワークです。**プロセス間で安全かつ非同期な呼び出しを行う**ためのメカニズムを提供します。XPCは**権限分離されたアプリケーション**をサポートしており、各**コンポーネント**は**必要な権限のみ**で実行されるため、プロセスが侵害された場合の潜在的な被害を制限できます。<sup>[[1]](#references)</sup>

XPCは、Inter-Process Communication（IPC）の一種を使用します。IPCは、同じシステム上で実行されている異なるプログラムがデータを相互に送受信するための一連の方式です。

XPCの主な利点は次のとおりです。

1. **Security**: 作業を異なるプロセスに分離することで、各プロセスには必要な権限のみを付与できます。つまり、プロセスが侵害された場合でも、害を及ぼす能力は制限されます。
2. **Stability**: XPCは、クラッシュを発生したコンポーネント内に隔離するのに役立ちます。プロセスがクラッシュした場合でも、システムの他の部分に影響を与えずに再起動できます。
3. **Performance**: XPCでは、異なるタスクを異なるプロセスで同時に実行できるため、並行処理を容易に実現できます。

主な**欠点**は、**アプリケーションを複数のプロセスに分離**し、それらをXPC経由で通信させることでオーバーヘッドが発生することです。最新のシステムでは、このオーバーヘッドは通常、SecurityとStabilityの利点と比較すれば小さいものです。<sup>[[1]](#references)</sup>

## Application-Specific XPC Services

アプリケーションのXPCコンポーネントは、**アプリケーション自体の内部**にあります。たとえばSafariでは、**`/Applications/Safari.app/Contents/XPCServices`**にあります。これらは**`.xpc`**拡張子（**`com.apple.Safari.SandboxBroker.xpc`**など）を持ち、**bundle**でもあります。bundle内にはメインバイナリと`Info.plist`があります。例: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`および`/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`。<sup>[[2]](#references)</sup>

**XPCコンポーネントは、他のXPCコンポーネントやメインアプリケーションバイナリとは異なるentitlementsと権限を持つことができます**。例外の1つは、**Info.plist**ファイルで**`JoinExistingSession`**を`true`に設定したXPC serviceです。この場合、XPC serviceは、それを呼び出した**アプリケーションと同じsecurity session**に参加します。<sup>[[4]](#references)</sup>

XPC servicesは、必要に応じて**launchd**によって**起動**され、タスクが**完了**するとシステムリソースを解放するために**停止**できます。**Application-specific XPCコンポーネントは、それを含むアプリケーションのみが使用できる**ため、潜在的な脆弱性への露出を低減できます。<sup>[[2]](#references)</sup>

## System-Wide XPC Services

Application-specific servicesとは異なり、system-wide XPC servicesは、それを含むアプリケーションに限定されません。launchd domainとservice自体のauthorization checksに応じて、複数のユーザーのclientから到達可能な場合があります。これらのlaunchd-managed Mach servicesは、**`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`**、**`/Library/LaunchAgents`**などのディレクトリにある**plist**ファイルで**定義**する必要があります。<sup>[[2]](#references)[[3]](#references)</sup>

これらのplistファイルには、service nameを含む**`MachServices`** keyと、バイナリへのpathを含む**`Program`** keyがあります:
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
`LaunchDaemons` のサービスは一般的に root として実行されます。したがって、権限のないプロセスがこれらのサービスによって公開された脆弱なメソッドにアクセスできる場合、権限昇格が可能になることがあります。

## XPC Objects

- **`xpc_object_t`**

XPC の request と reply の payload には、serialization と deserialization を簡単にする dictionary object が一般的に使用されます。`libxpc.dylib` には、受信したデータが想定された type であることを確認するために必要な data type も定義されています。C API では、すべての object が `xpc_object_t` であり、その type は `xpc_get_type(object)` を使用して確認できます。<sup>[[2]](#references)</sup>\
さらに、`xpc_copy_description(object)` 関数を使用すると、debugging に役立つ object の文字列表現を取得できます。\
これらの object には、`xpc_<object>_copy`、`xpc_<object>_equal`、`xpc_<object>_hash`、`xpc_<object>_serialize`、`xpc_<object>_deserialize` などの呼び出し可能なメソッドもあります。

`xpc_object_t` object は `xpc_<objectType>_create` 関数を呼び出して作成されます。この関数は内部で `_xpc_base_create(Class, Size)` を呼び出し、object の class（`XPC_TYPE_*` のいずれか）と size を指定します。metadata 用に追加で 40 bytes が追加されるため、object data は offset 40 bytes から始まります。\
したがって、`xpc_<objectType>_t` は `xpc_object_t` の subclass のようなものであり、`xpc_object_t` は `os_object_t*` の subclass です。

> [!WARNING]
> type と key の実際の value の取得または設定には、developer が `xpc_dictionary_[get/set]_<objectType>` を使用する必要があることに注意してください。

- **`xpc_pipe`**

**`xpc_pipe`** は、process 間の communication に使用できる FIFO pipe です（communication には Mach messages が使用されます）。\
`xpc_pipe_create()` または `xpc_pipe_create_from_port()` を呼び出すことで XPC server を作成できます。後者では、特定の Mach port を使用して作成します。messages を受信するには、`xpc_pipe_receive` と `xpc_pipe_try_receive` を呼び出せます。

**`xpc_pipe`** object は、2 つの Mach port と name（存在する場合）に関する情報を struct 内に持つ **`xpc_object_t`** であることに注意してください。例えば、daemon `secinitd` は plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` で、`com.apple.secinitd` という pipe を設定しています。

**`xpc_pipe`** の例として、**`launchd`** によって作成される **bootstrap pipe** があります。これにより Mach port を共有できます。

- **`NSXPC*`**

これらは XPC connections を抽象化する high-level の Objective-C objects です。\
さらに、これらの object は前述の object よりも DTrace で簡単に debug できます。

- **`GCD Queues`**

XPC は messages の受け渡しに GCD を使用し、`xpc.transactionq`、`xpc.io`、`xpc-events.add-listenerq`、`xpc.service-instance` などの特定の dispatch queues も生成します。

## XPC Services

これらは、他の project の **`XPCServices`** folder 内に配置された **`.xpc`** extension の bundles であり、`Info.plist` では `CFBundlePackageType` が **`XPC!`** に設定されています。\
この file には、`ServiceType` などの他の configuration key もあります。`ServiceType` には Application、User、System を指定できます。また、`_SandboxProfile` では sandbox を定義でき、`_AllowedClients` では service への contact に必要な entitlement または identity を示すことができます。これらの option などによって、service の launch 時の動作が設定されます。<sup>[[2]](#references)</sup>

### Starting a Service

app は `xpc_connection_create_mach_service` を使用して XPC service に **connect** しようとします。その後、launchd が daemon を検索して **`xpcproxy`** を起動します。**`xpcproxy`** は設定された restriction を適用し、提供された file descriptor と Mach port を使用して service を spawn します。<sup>[[3]](#references)</sup>

XPC service の検索速度を向上させるため、cache が使用されます。

以下を使用して `xpcproxy` の actions を trace できます：
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC libraryは、`xpc_ktrace_pid0`および`xpc_ktrace_pid1`を呼び出してアクションをログに記録するために、`kdebug`を使用します。使用されるコードは文書化されていないため、`/usr/share/misc/trace.codes`に追加する必要があります。これらのコードには`0x29`というプレフィックスが付いています。たとえば、`0x29000004`は`XPC_serializer_pack`です。\
`xpcproxy`ユーティリティは`0x22`というプレフィックスを使用します。たとえば、`0x2200001c: xpcproxy:will_do_preexec`です。

## XPCイベントメッセージ

アプリケーションは、さまざまなイベント**メッセージ**を**subscribe**できます。これにより、そのようなイベントが発生したときに、アプリケーションを**オンデマンドで開始**できます。これらのサービスの**設定**は、以前のものと**同じディレクトリにあるlaunchd plistファイル**で行われ、追加の**`LaunchEvent`**キーが含まれます。

### XPC接続プロセスのチェック

プロセスがXPC接続を介してメソッドを呼び出そうとすると、**XPC serviceは、そのプロセスが接続を許可されているか確認する必要があります**。一般的な検証方法と、その落とし穴を以下に示します。


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC認証

Appleは、アプリが**認証権限と、callerがそれを取得する方法を設定すること**も許可しています。そのため、必要な権限を持つプロセスは、XPC serviceによって公開された**メソッドを呼び出すことができます**。


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPCメッセージをsniffするには、**Frida**を使用する**xpcspy**を利用できます。<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
もう1つの可能な tool は **XPoCe2** です。<sup>[[6]](#references)</sup>

## XPC Communication C のコード例

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
## Dylib 内の Client
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

`RemoteXPC.framework`（`libxpc`由来）が提供する機能により、異なるホスト間でXPC通信を行えます。\
Remote XPCをサポートするサービスには、plist内に`UsesRemoteXPC`キーがあります。`/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`がその例です。このサービスは`launchd`に登録されていますが、機能は`UserEventAgent`と、その`com.apple.remoted.plugin`および`com.apple.remoteservicediscovery.events.plugin`プラグインによって提供されます。

さらに、`RemoteServiceDiscovery.framework`は`com.apple.remoted.plugin`から情報を取得し、`get_device`、`get_unique_device`、`connect`などの関数を公開します。

`connect`がサービスのソケットファイルディスクリプタを返した後は、`remote_xpc_connection_*`クラスを使用できます。

`/usr/libexec/remotectl` CLIで次のようなコマンドを使用すると、remote servicesに関する情報を取得できます。
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
bridgeOS とホスト間の通信は、専用の IPv6 インターフェースを介して行われます。`MultiverseSupport.framework` は、通信に使用されるファイルディスクリプターを持つソケットを確立します。\
これらの通信は、`netstat`、`nettop`、または open-source の代替ツールである `netbottom` を使用して確認できます。

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — XPC サービスの作成](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
