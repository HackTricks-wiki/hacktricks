# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 基本情報

XPCは、macOSで使用されるカーネルであるXNUのプロセス間通信のフレームワークで、macOSおよびiOS上の**プロセス間の通信**を提供します。XPCは、システム上の異なるプロセス間で**安全で非同期のメソッド呼び出し**を行うためのメカニズムを提供します。これはAppleのセキュリティパラダイムの一部であり、各**コンポーネント**がその仕事を行うために必要な**権限のみ**で実行される**特権分離アプリケーション**の**作成**を可能にします。これにより、侵害されたプロセスからの潜在的な損害を制限します。

XPCは、同じシステム上で実行されている異なるプログラムがデータを送受信するための一連のメソッドであるプロセス間通信（IPC）の一形態を使用します。

XPCの主な利点は次のとおりです。

1. **セキュリティ**: 作業を異なるプロセスに分離することで、各プロセスには必要な権限のみが付与されます。これにより、プロセスが侵害されても、害を及ぼす能力は制限されます。
2. **安定性**: XPCは、クラッシュを発生したコンポーネントに隔離するのに役立ちます。プロセスがクラッシュした場合、システムの他の部分に影響を与えることなく再起動できます。
3. **パフォーマンス**: XPCは、異なるタスクを異なるプロセスで同時に実行できるため、簡単な同時実行を可能にします。

唯一の**欠点**は、**アプリケーションを複数のプロセスに分離**し、それらがXPCを介して通信することが**効率が低い**ことです。しかし、今日のシステムではほとんど目立たず、利点の方が大きいです。

## アプリケーション固有のXPCサービス

アプリケーションのXPCコンポーネントは**アプリケーション自体の内部**にあります。たとえば、Safariでは**`/Applications/Safari.app/Contents/XPCServices`**に見つけることができます。これらは**`.xpc`**拡張子を持ち（例: **`com.apple.Safari.SandboxBroker.xpc`**）、メインバイナリの内部に**バンドル**されています: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`および`Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

あなたが考えているように、**XPCコンポーネントは他のXPCコンポーネントやメインアプリバイナリとは異なる権限と特権を持つ**ことになります。ただし、XPCサービスが**Info.plist**ファイルで[**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)を“True”に設定されている場合を除きます。この場合、XPCサービスは呼び出したアプリケーションと**同じセキュリティセッション**で実行されます。

XPCサービスは、必要に応じて**launchd**によって**開始され**、すべてのタスクが**完了**するとシステムリソースを解放するために**シャットダウン**されます。**アプリケーション固有のXPCコンポーネントはアプリケーションによってのみ利用可能**であり、潜在的な脆弱性に関連するリスクを低減します。

## システム全体のXPCサービス

システム全体のXPCサービスはすべてのユーザーがアクセス可能です。これらのサービスは、launchdまたはMachタイプであり、**`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`**、または**`/Library/LaunchAgents`**などの指定されたディレクトリにあるplistファイルで**定義する必要があります**。

これらのplistファイルには、サービスの名前を持つ**`MachServices`**というキーと、バイナリへのパスを持つ**`Program`**というキーがあります:
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
**`LaunchDameons`**内のものはrootによって実行されます。したがって、特権のないプロセスがこれらのいずれかと通信できる場合、特権を昇格させることができる可能性があります。

## XPCオブジェクト

- **`xpc_object_t`**

すべてのXPCメッセージは、シリアル化とデシリアル化を簡素化する辞書オブジェクトです。さらに、`libxpc.dylib`はほとんどのデータ型を宣言しているため、受信したデータが期待される型であることを確認できます。C APIでは、すべてのオブジェクトは`xpc_object_t`であり（その型は`xpc_get_type(object)`を使用して確認できます）。\
さらに、`xpc_copy_description(object)`関数を使用して、デバッグ目的に役立つオブジェクトの文字列表現を取得できます。\
これらのオブジェクトには、`xpc_<object>_copy`、`xpc_<object>_equal`、`xpc_<object>_hash`、`xpc_<object>_serialize`、`xpc_<object>_deserialize`などの呼び出し可能なメソッドもあります。

`xpc_object_t`は、`xpc_<objetType>_create`関数を呼び出すことで作成され、内部的に`_xpc_base_create(Class, Size)`を呼び出し、オブジェクトのクラスの型（`XPC_TYPE_*`のいずれか）とそのサイズ（メタデータ用に追加の40Bがサイズに加算されます）が指定されます。つまり、オブジェクトのデータはオフセット40Bから始まります。\
したがって、`xpc_<objectType>_t`は`xpc_object_t`のサブクラスのようなものであり、`os_object_t*`のサブクラスになります。

> [!WARNING]
> `xpc_dictionary_[get/set]_<objectType>`を使用して、キーの型と実際の値を取得または設定するのは開発者であるべきです。

- **`xpc_pipe`**

**`xpc_pipe`**は、プロセスが通信するために使用できるFIFOパイプです（通信はMachメッセージを使用します）。\
特定のMachポートを使用して作成するために、`xpc_pipe_create()`または`xpc_pipe_create_from_port()`を呼び出すことでXPCサーバーを作成できます。次に、メッセージを受信するには、`xpc_pipe_receive`および`xpc_pipe_try_receive`を呼び出すことができます。

**`xpc_pipe`**オブジェクトは、使用される2つのMachポートと名前（ある場合）の情報をその構造体に持つ**`xpc_object_t`**です。たとえば、plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`内のデーモン`secinitd`の名前は、`com.apple.secinitd`と呼ばれるパイプを構成します。

**`xpc_pipe`**の例は、**`launchd`**によって作成された**bootstrap pipe**で、Machポートの共有を可能にします。

- **`NSXPC*`**

これらは、XPC接続の抽象化を可能にするObjective-Cの高レベルオブジェクトです。\
さらに、これらのオブジェクトは、前のものよりもDTraceでデバッグしやすくなっています。

- **`GCD Queues`**

XPCはメッセージを渡すためにGCDを使用し、さらに`xpc.transactionq`、`xpc.io`、`xpc-events.add-listenerq`、`xpc.service-instance`などの特定のディスパッチキューを生成します。

## XPCサービス

これらは、他のプロジェクトの**`XPCServices`**フォルダー内にある`.xpc`拡張子を持つ**バンドル**であり、`Info.plist`では`CFBundlePackageType`が**`XPC!`**に設定されています。\
このファイルには、Application、User、System、またはサンドボックスを定義できる`_SandboxProfile`、またはサービスに連絡するために必要な権限やIDを示す可能性のある`_AllowedClients`など、他の構成キーがあります。これらおよび他の構成オプションは、サービスが起動されるときにサービスを構成するのに役立ちます。

### サービスの開始

アプリは、`xpc_connection_create_mach_service`を使用してXPCサービスに**接続**しようとし、その後launchdがデーモンを見つけて**`xpcproxy`**を起動します。**`xpcproxy`**は構成された制限を強制し、提供されたFDとMachポートでサービスを生成します。

XPCサービスの検索速度を向上させるために、キャッシュが使用されます。

`xpcproxy`のアクションをトレースすることができます:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPCライブラリは、`kdebug`を使用して、`xpc_ktrace_pid0`および`xpc_ktrace_pid1`を呼び出すアクションをログに記録します。使用されるコードは文書化されていないため、これらを`/usr/share/misc/trace.codes`に追加する必要があります。これらのコードはプレフィックス`0x29`を持ち、例えば`0x29000004`: `XPC_serializer_pack`のようになります。\
ユーティリティ`xpcproxy`はプレフィックス`0x22`を使用し、例えば`0x2200001c: xpcproxy:will_do_preexec`のようになります。

## XPCイベントメッセージ

アプリケーションは異なるイベント**メッセージ**に**サブスクライブ**でき、これによりそのようなイベントが発生したときに**オンデマンドで開始**できるようになります。これらのサービスの**セットアップ**は、**前述のディレクトリと同じディレクトリ**にある**launchd plistファイル**で行われ、追加の**`LaunchEvent`**キーが含まれています。

### XPC接続プロセスチェック

プロセスがXPC接続を介してメソッドを呼び出そうとするとき、**XPCサービスはそのプロセスが接続を許可されているかどうかを確認する必要があります**。以下は、その確認方法と一般的な落とし穴です：

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC認可

Appleは、アプリが**いくつかの権利を構成し、それを取得する方法を設定する**ことを許可しているため、呼び出しプロセスがそれらを持っている場合、**XPCサービスからメソッドを呼び出すことが許可されます**：

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPCスニファー

XPCメッセージをスニフするには、[**xpcspy**](https://github.com/hot3eed/xpcspy)を使用できます。これは**Frida**を使用しています。
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
別の使用可能なツールは [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html) です。

## XPC 通信 C コード例

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
## XPCコミュニケーション Objective-C コード例

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
## Dylbコード内のクライアント
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

この機能は `RemoteXPC.framework`（`libxpc`から）によって提供され、異なるホスト間でXPCを介して通信することができます。\
リモートXPCをサポートするサービスは、plistにUsesRemoteXPCキーを持っており、これは`/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`のようなケースです。しかし、サービスは`launchd`に登録されますが、機能を提供するのは`UserEventAgent`であり、プラグイン`com.apple.remoted.plugin`と`com.apple.remoteservicediscovery.events.plugin`です。

さらに、`RemoteServiceDiscovery.framework`は、`com.apple.remoted.plugin`から情報を取得することを可能にし、`get_device`、`get_unique_device`、`connect`などの関数を公開しています。

一度`connect`が使用され、サービスのソケット`fd`が収集されると、`remote_xpc_connection_*`クラスを使用することが可能です。

リモートサービスに関する情報は、次のようなパラメータを使用してCLIツール`/usr/libexec/remotectl`を使用することで取得できます：
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOSとホスト間の通信は、専用のIPv6インターフェースを介して行われます。`MultiverseSupport.framework`は、通信に使用される`fd`を持つソケットを確立することを可能にします。\
`netstat`、`nettop`、またはオープンソースのオプションである`netbottom`を使用して、これらの通信を見つけることができます。

{{#include ../../../../../banners/hacktricks-training.md}}
