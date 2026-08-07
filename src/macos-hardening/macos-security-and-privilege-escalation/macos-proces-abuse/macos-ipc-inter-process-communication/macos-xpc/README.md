# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 基本情報

XPCは、XNU（macOSで使用されるkernel）のInter-Process Communicationを意味し、macOSおよびiOS上の**プロセス間の通信**のためのframeworkです。XPCは、システム上の異なるプロセス間で**安全かつ非同期なmethod callを行う**ためのmechanismを提供します。これはAppleのsecurity paradigmの一部であり、各**component**が業務に必要な**権限のみ**で実行される**権限分離されたapplication**の**作成**を可能にします。これにより、processがcompromiseされた場合に生じる潜在的な被害を制限できます。

XPCはInter-Process Communication（IPC）の一種を使用します。IPCは、同じsystem上で実行されている異なるprogramがデータを相互に送受信するためのmethod群です。

XPCの主な利点は次のとおりです。

1. **Security**: 処理を異なるprocessに分離することで、各processには必要な権限のみを付与できます。つまり、processがcompromiseされた場合でも、被害を及ぼす能力は限定されます。
2. **Stability**: XPCは、crashが発生したcomponent内にその影響を隔離するのに役立ちます。processがcrashした場合でも、systemの他の部分に影響を与えずに再起動できます。
3. **Performance**: XPCでは、異なるtaskを異なるprocessで同時に実行できるため、concurrencyを容易に利用できます。

唯一の**欠点**は、**applicationを複数のprocessに分割**し、それらをXPC経由で通信させることが**非効率的**になる点です。しかし、現在のsystemではこの差はほとんど感じられず、利点の方が大きくなっています。

## Application Specific XPC services

applicationのXPC componentは**application自体の内部にあります。** 例えばSafariでは、**`/Applications/Safari.app/Contents/XPCServices`** にあります。拡張子は **`.xpc`**（例: **`com.apple.Safari.SandboxBroker.xpc`**）で、**bundle**でもあります。bundle内にはmain binaryがあります: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` および `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

ご想像のとおり、**XPC componentは、他のXPC componentやmain app binaryとは異なるentitlementとprivilegeを持ちます。** ただし、XPC serviceがその **Info.plist** ファイルで [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) を「True」に設定して構成されている場合を除きます。この場合、XPC serviceは、それを呼び出した**applicationと同じsecurity session**で実行されます。

XPC serviceは必要に応じて**launchdによって起動**され、すべてのtaskが**完了**するとsystem resourceを解放するために**終了**します。**Application-specific XPC componentはそのapplicationからのみ利用できる**ため、潜在的なvulnerabilityに伴うriskが軽減されます。

## System Wide XPC services

System-wide XPC serviceはすべてのuserからアクセスできます。これらのserviceはlaunchd型またはMach型であり、**`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`**、**`/Library/LaunchAgents`** など、指定されたdirectoryにある **plist** ファイルで**定義**する必要があります。

これらのplist fileには、serviceのnameを指定する **`MachServices`** というkeyと、binaryへのpathを指定する **`Program`** というkeyがあります:
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
**`LaunchDameons`** にあるものは root として実行されます。そのため、権限のないプロセスがこれらのいずれかと通信できる場合、権限昇格が可能になることがあります。

## XPCオブジェクト

- **`xpc_object_t`**

すべての XPC メッセージは、シリアライズとデシリアライズを簡略化する辞書オブジェクトです。さらに、`libxpc.dylib` はほとんどのデータ型を宣言しているため、受信データが想定された型であることを確認できます。C API では、すべてのオブジェクトが `xpc_object_t` です（型は `xpc_get_type(object)` を使用して確認できます）。\
さらに、`xpc_copy_description(object)` 関数を使用すると、デバッグに役立つオブジェクトの文字列表現を取得できます。\
これらのオブジェクトには、`xpc_<object>_copy`、`xpc_<object>_equal`、`xpc_<object>_hash`、`xpc_<object>_serialize`、`xpc_<object>_deserialize` などの呼び出し可能なメソッドもあります。

`xpc_object_t` は `xpc_<objetType>_create` 関数を呼び出して作成されます。この関数は内部的に `_xpc_base_create(Class, Size)` を呼び出します。ここでは、オブジェクトのクラスの型（`XPC_TYPE_*` のいずれか）とサイズが指定されます（メタデータ用に追加で 40B がサイズに加算されます）。つまり、オブジェクトのデータはオフセット 40B から始まります。\
したがって、`xpc_<objectType>_t` は `xpc_object_t` のサブクラスのようなものであり、`xpc_object_t` は `os_object_t*` のサブクラスのようなものです。

> [!WARNING]
> 型とキーの実際の値を取得または設定するには、開発者が `xpc_dictionary_[get/set]_<objectType>` を使用する必要があることに注意してください。

- **`xpc_pipe`**

**`xpc_pipe`** は、プロセス間の通信に使用できる FIFO パイプです（通信には Mach メッセージを使用します）。\
`xpc_pipe_create()` または `xpc_pipe_create_from_port()` を呼び出すことで XPC サーバーを作成できます。後者は、指定した Mach ポートを使用して作成します。メッセージを受信するには、`xpc_pipe_receive` と `xpc_pipe_try_receive` を呼び出します。

**`xpc_pipe`** オブジェクトは **`xpc_object_t`** であり、その構造体には使用される 2 つの Mach ポートと名前（存在する場合）に関する情報が含まれていることに注意してください。例えば、daemon の `secinitd` は plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` で、`com.apple.secinitd` という名前の pipe を設定しています。

**`xpc_pipe`** の例として、**`launchd`** が作成する **bootstrap pipe** があります。これにより Mach ポートを共有できます。

- **`NSXPC*`**

これらは、XPC 接続を抽象化できる Objective-C の高レベルオブジェクトです。\
さらに、これらのオブジェクトは前述のものよりも DTrace で簡単にデバッグできます。

- **`GCD Queues`**

XPC はメッセージの受け渡しに GCD を使用します。また、`xpc.transactionq`、`xpc.io`、`xpc-events.add-listenerq`、`xpc.service-instance` などの特定の dispatch queues を生成します。

## XPC Services

これらは、他のプロジェクトの **`XPCServices`** フォルダ内に配置される、拡張子が **`.xpc`** の **bundles** です。また、`Info.plist` で `CFBundlePackageType` が **`XPC!`** に設定されています。\
このファイルには、`Application`、`User`、`System` のいずれかを指定できる `ServiceType` や、sandbox を定義できる `_SandboxProfile`、またはサービスへの接続に必要な entitlements や ID を示す可能性がある `_AllowedClients` など、その他の設定キーがあります。これらの設定オプションやその他の設定オプションは、サービスの起動時の設定に役立ちます。

### サービスの起動

アプリは `xpc_connection_create_mach_service` を使用して XPC サービスへの **接続** を試みます。その後、launchd が daemon を見つけて **`xpcproxy`** を起動します。**`xpcproxy`** は設定された制限を適用し、提供された FD と Mach ポートを使用してサービスを spawn します。

XPC サービスの検索速度を向上させるため、cache が使用されます。

次の方法で `xpcproxy` の動作を trace できます。
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC libraryは`kdebug`を使用して、`xpc_ktrace_pid0`および`xpc_ktrace_pid1`を呼び出してアクションをログに記録します。使用されるコードは未公開のため、`/usr/share/misc/trace.codes`に追加する必要があります。これらには`0x29`というprefixが付いており、例えば`0x29000004`は`XPC_serializer_pack`です。\
utilityの`xpcproxy`は`0x22`というprefixを使用します。例えば、`0x2200001c: xpcproxy:will_do_preexec`です。

## XPC Event Messages

アプリケーションは異なるイベント**メッセージ**を**subscribe**でき、そのようなイベントが発生したときに**on-demandで起動**できるようになります。これらのserviceの**setup**は、以前のものと**同じディレクトリ**にある**launchd plist files**で行われ、追加の**`LaunchEvent`** keyが含まれます。

### XPC Connecting Process Check

プロセスがXPC connection経由でmethodを呼び出そうとすると、**XPC serviceはそのプロセスが接続を許可されているかチェックする必要があります**。その一般的なチェック方法と、よくある落とし穴を以下に示します。


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Appleでは、アプリが一部の権限とその取得方法を**configure**することもできます。そのため、calling processがそれらを持っていれば、XPC serviceのmethodを呼び出すことが**許可されます**。


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC messagesをsniffするには、**Frida**を使用する[**xpcspy**](https://github.com/hot3eed/xpcspy)を利用できます。
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
使用できる別のツールとして、[**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html) があります。

## XPC通信のCコード例

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
## XPC通信 Objective-C コード例

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
## Dylb code 内の Client
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

`libxpc` の `RemoteXPC.framework` によって提供されるこの機能では、異なるホスト間で XPC を介して通信できます。\
Remote XPC をサポートするサービスの plist には、`/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` のように `UsesRemoteXPC` キーがあります。ただし、サービス自体は `launchd` に登録されるものの、この機能を提供するのは、`com.apple.remoted.plugin` と `com.apple.remoteservicediscovery.events.plugin` プラグインを備えた `UserEventAgent` です。

さらに、`RemoteServiceDiscovery.framework` を使用すると、`com.apple.remoted.plugin` から情報を取得でき、`get_device`、`get_unique_device`、`connect` などの関数を公開しています。

`connect` を使用してサービスのソケット `fd` を取得すると、`remote_xpc_connection_*` クラスを使用できます。

CLI ツール `/usr/libexec/remotectl` を次のようなパラメータで使用すると、remote services に関する情報を取得できます：
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOS とホスト間の通信は、専用の IPv6 インターフェースを介して行われます。`MultiverseSupport.framework` により、通信に使用される `fd` を持つソケットを確立できます。\
これらの通信は `netstat`、`nettop`、またはオープンソースの `netbottom` を使用して確認できます。

{{#include ../../../../../banners/hacktricks-training.md}}
