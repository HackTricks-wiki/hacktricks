# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## 基本情報

XPCは、macOSおよびiOSにおける**プロセス間通信**のためのフレームワークです。**プロセス間で安全かつ非同期に呼び出しを行うための仕組み**を提供します。XPCは**権限を分離したアプリケーション**をサポートしており、各**コンポーネント**は**必要な権限のみで実行**されます。これにより、プロセスが侵害された場合に生じる潜在的な被害を抑えられます。<sup>[[1]](#references)</sup>

XPCは、同じシステム上で実行されている異なるプログラム間でデータをやり取りするための一連の手法である、プロセス間通信（IPC）の一種を使用します。

XPCの主な利点は次のとおりです。

1. **セキュリティ**: 作業を複数のプロセスに分けることで、各プロセスに必要な権限のみを付与できます。そのため、プロセスが侵害されても、被害を及ぼす能力は制限されます。
2. **安定性**: XPCは、クラッシュが発生したコンポーネント内にその影響をとどめます。プロセスがクラッシュしても、システムのほかの部分に影響を与えることなく再起動できます。
3. **パフォーマンス**: XPCでは、異なるプロセスで複数のタスクを同時に実行できるため、並行処理を容易に実現できます。

主な**欠点**は、**アプリケーションを複数のプロセスに分割**し、XPC経由で通信させることでオーバーヘッドが発生する点です。最新のシステムでは、セキュリティと安定性の利点に比べ、このオーバーヘッドは通常わずかです。<sup>[[1]](#references)</sup>

## アプリケーション固有のXPCサービス

アプリケーションのXPCコンポーネントは、**アプリケーション自体の内部にあります**。たとえばSafariの場合、**`/Applications/Safari.app/Contents/XPCServices`** にあります。これらのコンポーネントの拡張子は **`.xpc`**（例: **`com.apple.Safari.SandboxBroker.xpc`**）で、**バンドルでもあります**。バンドル内にはメインバイナリと `Info.plist` が含まれます。例: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` および `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`。<sup>[[2]](#references)</sup>

**XPCコンポーネントは、ほかのXPCコンポーネントやメインアプリケーションバイナリとは異なるentitlementsや権限を持つことができます**。例外として、**Info.plist** ファイルで **`JoinExistingSession`** が `true` に設定されたXPCサービスがあります。この場合、XPCサービスは、呼び出し元の**アプリケーションと同じセキュリティセッションに参加します**。<sup>[[4]](#references)</sup>

XPCサービスは、必要に応じて**launchd**によって**起動**され、タスクの**完了後**にシステムリソースを解放するため**終了**できます。**アプリケーション固有のXPCコンポーネントを使用できるのは、それを含むアプリケーションだけ**であり、潜在的な脆弱性にさらされる範囲を抑えられます。<sup>[[2]](#references)</sup>

## システム全体のXPCサービス

アプリケーション固有のサービスとは異なり、システム全体のXPCサービスは、それを含むアプリケーションに限定されません。launchdのドメインやサービス独自の認可チェックに応じて、複数のユーザーのクライアントからアクセスできる場合があります。launchdが管理するこれらのMachサービスは、**`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`**、**`/Library/LaunchAgents`** などのディレクトリにあるplistファイルで**定義する必要があります**。<sup>[[2]](#references)[[3]](#references)</sup>

これらのplistファイルには、サービス名を含む **`MachServices`** キーと、バイナリへのパスを含む **`Program`** キーがあります。

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

**`LaunchDaemons`** 内のサービスは、一般に root として実行されます。そのため、権限のないプロセスが、これらのサービスのいずれかが公開する脆弱なメソッドにアクセスできる場合、権限昇格が可能になることがあります。

## XPC Objects

- **`xpc_object_t`**

XPC のリクエストと応答のペイロードには、シリアライズとデシリアライズを簡略化する dictionary object がよく使われます。`libxpc.dylib` には、受信したデータが想定された型であることを検証するためのデータ型も宣言されています。C API では、すべての object は `xpc_object_t` であり、その型は `xpc_get_type(object)` を使って確認できます。<sup>[[2]](#references)</sup>\
また、関数 `xpc_copy_description(object)` を使うと、デバッグに役立つ object の文字列表現を取得できます。\
これらの object には、`xpc_<object>_copy`、`xpc_<object>_equal`、`xpc_<object>_hash`、`xpc_<object>_serialize`、`xpc_<object>_deserialize` などのメソッドもあります。

`xpc_object_t` object は、`xpc_<objectType>_create` 関数を呼び出して作成されます。この関数は内部で `_xpc_base_create(Class, Size)` を呼び出し、object の class（`XPC_TYPE_*` のいずれか）とサイズを指定します。メタデータ用にさらに 40 bytes が追加されるため、object のデータはオフセット 40 bytes から始まります。\
したがって、`xpc_<objectType>_t` は `xpc_object_t` の subclass のようなもので、さらに `os_object_t*` の subclass です。

> [!WARNING]
> キーの型と実際の値を取得または設定するために `xpc_dictionary_[get/set]_<objectType>` を使うのは、開発者であるべき点に注意してください。

- **`xpc_pipe`**

**`xpc_pipe`** は、プロセス間の通信に使われる FIFO pipe です（通信には Mach message を使用します）。\
`xpc_pipe_create()` を呼び出すか、特定の Mach port を使って作成する `xpc_pipe_create_from_port()` を呼び出すことで、XPC server を作成できます。その後、メッセージを受信するには `xpc_pipe_receive` と `xpc_pipe_try_receive` を呼び出します。

**`xpc_pipe`** object は、使用する2つの Mach port と名前（ある場合）に関する情報を struct に持つ **`xpc_object_t`** です。たとえば、daemon `secinitd` は plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` で、`com.apple.secinitd` という pipe を設定しています。

**`xpc_pipe`** の例として、Mach port の共有を可能にする **`launchd`** が作成する **bootstrap pipe** があります。

- **`NSXPC*`**

これらは、XPC connection を抽象化する高レベルの Objective-C object です。\
また、これらの object は前述のものより DTrace で簡単にデバッグできます。

- **`GCD Queues`**

XPC はメッセージの受け渡しに GCD を使い、さらに `xpc.transactionq`、`xpc.io`、`xpc-events.add-listenerq`、`xpc.service-instance` などの特定の dispatch queue を生成します。

## XPC Services

これらは、他の project の **`XPCServices`** folder 内にある拡張子が **`.xpc`** の bundle で、`Info.plist` では `CFBundlePackageType` が **`XPC!`** に設定されています。\
このファイルには、`ServiceType`（Application、User、System のいずれか）、sandbox を定義できる `_SandboxProfile`、およびサービスへの接続に必要な entitlement や identity を示す `_AllowedClients` など、他の設定キーも含まれています。これらのオプションなどにより、サービスの起動時の設定が行われます。<sup>[[2]](#references)</sup>

### Starting a Service

アプリは `xpc_connection_create_mach_service` を使って XPC service への **接続** を試みます。その後、launchd が daemon を特定して **`xpcproxy`** を起動します。**`xpcproxy`** は設定された制限を適用し、渡された file descriptor と Mach port を使ってサービスを起動します。<sup>[[3]](#references)</sup>

XPC service の検索を高速化するために、cache が使われます。

次の方法で `xpcproxy` の動作を trace できます：

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

XPC libraryは`xpc_ktrace_pid0`と`xpc_ktrace_pid1`を呼び出して、`kdebug`でアクションをログに記録します。使用するコードは文書化されていないため、`/usr/share/misc/trace.codes`に追加する必要があります。プレフィックスは`0x29`です。たとえば、`0x29000004`は`XPC_serializer_pack`を表します。\
ユーティリティ`xpcproxy`はプレフィックス`0x22`を使用します。例: `0x2200001c: xpcproxy:will_do_preexec`

## ApplicationタイプのXPCヘルパーの監査

`XPCService.ServiceType`が`Application`のものは、frameworkが提供するヘルパーを監査する際の有用な出発点です。バンドルを列挙し、実行中のサービスを保持して、ヘルパーの識別子とentitlementsを調べます。`/System/Library/Frameworks`と`/System/Library/PrivateFrameworks`の両方を検索してください。正確な一覧はmacOSのリリースごとに変わります。<sup>[[7]](#references)</sup>

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

### listenerをトリアージし、最小限のプロトコルを復元する

helper内で `-[<delegate> listener:shouldAcceptNewConnection:]` を探します。`exportedInterface` と `exportedObject` を設定し、接続を再開して `YES`/`1` を返す一方で、peerのaudit token、code requirement、entitlementを確認しない経路がある場合、そのサービスを解決できるすべてのクライアントにRPC interfaceが公開されています。ただし、これは**到達可能性**を証明するだけです。影響が生じるには、十分なクライアント単位またはメソッド単位の認可なしに特権操作を実行する、あるいは攻撃者が制御する入力を安全でない方法で処理するexported methodが必要です。<sup>[[7]](#references)</sup>

テストに必要なselectorだけを復元します。Objective-Cのselector metadataから引数の数が分かり、decompilerでの引数の使用箇所から通常は型を絞り込めます（たとえば、`-[EKEvent setStartDate:]` と `setEndDate:` に渡される値は `NSDate *` です）。また、メソッド末尾の間接呼び出しからreply blockのパラメータが分かります。`NSXPCInterface`には部分的なローカルプロトコルで十分であり、非公開プロトコル全体を復元する必要はありません。<sup>[[7]](#references)</sup>

### 復元したinterfaceで接続する

アプリケーションXPC serviceの場合は、必要な非公開クラスを定義するframeworkを読み込み、`initWithServiceName:` で接続を作成し、復元したremote interfaceを割り当て、error/interruption/invalidation handlerを設定してから再開します。非同期のreplyを受け取れるよう、run loopを動作させたままにします。sandbox境界をテストする場合は、sandbox化されたアプリケーション内でクライアントを再実行してください。単独のクライアントが成功しても、sandbox escapeの証拠にはなりません。<sup>[[7]](#references)</sup>

<details>
<summary>最小限のObjective-Cクライアント</summary>

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

`clang -fblocks -framework Foundation -o xpc_client xpc_client.m` でコンパイルします。<sup>[[7]](#references)</sup>

</details>

### secure-coding の失敗を型オラクルとして使う

`NSCocoaErrorDomain` のエラー（コード `4101` など）では、有用なシリアライズ例外が隠れていることがあります。macOS の unified log/Console でサービス名を検索すると、その例外から、想定外のクラスと、そのセレクター引数で許可されているクラスの両方がわかります。返信の場合は、`setClasses:forSelector:argumentIndex:ofReply:` を使って**クライアント側**のインターフェース許可リストを拡張します。`ofReply:YES` の場合、インデックス `0` は返信ブロックの最初のパラメーターを指し、メソッドの最初のパラメーターを指すわけではありません。<sup>[[7]](#references)</sup>

接続にインターフェースを設定し、`[c resume]` を呼び出す前に、インターフェースを構成します。<sup>[[7]](#references)</sup>

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

逆のケースも有用です。サーバーが Foundation の入力を拒否し、許可されている単一の private class をログに記録した場合、そのログから期待される wire type とその framework が分かります。その framework をロードし、クラスのメソッドやプロパティを調べて汎用的な `id` 型を絞り込み、private object を動的に構築します。`NSInvocation` の引数は、インデックス `0` と `1` が隠し引数の `self` と `_cmd` であるため、インデックス `2` から始まります。<sup>[[7]](#references)</sup>

<details>
<summary>NSInvocation で private argument を構築する</summary>

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

launchd に登録されたシステム全体の Mach サービスに対する関連ワークフローについては、こちらを参照してください。

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## XPC イベントメッセージ

アプリケーションはさまざまなイベント**メッセージ**を**購読**でき、イベントが発生したときに**オンデマンドで起動**されるようにできます。これらのサービスは、**前述のものと同じディレクトリにある l**aunchd plist ファイル**で設定され、追加の **`LaunchEvent`** キーを含みます。

### XPC 接続プロセスの確認

プロセスが XPC 接続経由でメソッドを呼び出そうとするとき、**XPC サービスは、そのプロセスに接続が許可されているかを確認する必要があります**。一般的な検証方法とその落とし穴を以下に示します。


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC 認可

Apple では、アプリが**認可権限と、呼び出し元がそれらを取得する方法を設定することもできます**。必要な権限を持つプロセスは、XPC サービスが公開する**メソッドを呼び出すことができます**。


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC スニファー

XPC メッセージのスニッフィングには、**Frida** を使用する **xpcspy** を利用できます。<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

別の選択肢として、**XPoCe2**があります。<sup>[[6]](#references)</sup>

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

## XPC Communication Objective-C コード例

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

## Dylib 内のクライアント

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

`libxpc` の `RemoteXPC.framework` が提供する機能により、異なるホスト間で XPC 通信を行えます。\
Remote XPC をサポートするサービスは、`/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` のように、plist に `UsesRemoteXPC` キーを持ちます。サービスは `launchd` に登録されていますが、この機能は `UserEventAgent` と、そのプラグインである `com.apple.remoted.plugin` および `com.apple.remoteservicediscovery.events.plugin` によって提供されます。

さらに、`RemoteServiceDiscovery.framework` は `com.apple.remoted.plugin` から情報を取得し、`get_device`、`get_unique_device`、`connect` などの関数を公開します。

`connect` がサービスのソケットファイルディスクリプターを返した後は、`remote_xpc_connection_*` クラスを使用できます。

次のようなコマンドを使って、`/usr/libexec/remotectl` CLI からリモートサービスに関する情報を取得できます：

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

bridgeOS とホスト間の通信は、専用の IPv6 インターフェースを介して行われます。`MultiverseSupport.framework` は通信に使用されるファイルディスクリプターを持つソケットを作成します。\
これらの通信は、`netstat`、`nettop`、またはオープンソースの代替ツール `netbottom` を使って確認できます。

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — XPCサービスの作成](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - macOS XPC Helperへの攻撃：プロトコルのリバースエンジニアリング](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
