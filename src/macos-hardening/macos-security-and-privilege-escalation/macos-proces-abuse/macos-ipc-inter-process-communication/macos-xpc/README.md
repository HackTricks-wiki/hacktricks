# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basic Information

XPC là một framework dùng để **giao tiếp giữa các process** trên macOS và iOS. Framework này cung cấp cơ chế thực hiện **các lệnh gọi an toàn, bất đồng bộ giữa các process**. XPC hỗ trợ **các ứng dụng phân tách đặc quyền**, trong đó mỗi **thành phần** chỉ chạy với **những quyền cần thiết**, qua đó hạn chế thiệt hại tiềm ẩn nếu một process bị xâm phạm.<sup>[[1]](#references)</sup>

XPC sử dụng một dạng Inter-Process Communication (IPC), tức tập hợp các phương thức cho phép những chương trình khác nhau chạy trên cùng hệ thống gửi dữ liệu qua lại.

Những lợi ích chính của XPC gồm:

1. **Bảo mật**: Việc chia công việc cho các process khác nhau cho phép chỉ cấp cho mỗi process những quyền cần thiết. Điều này có nghĩa là ngay cả khi một process bị xâm phạm, khả năng gây hại của nó vẫn bị hạn chế.
2. **Độ ổn định**: XPC giúp cô lập sự cố chỉ trong thành phần xảy ra sự cố. Nếu một process gặp sự cố, nó có thể được khởi động lại mà không ảnh hưởng đến phần còn lại của hệ thống.
3. **Hiệu năng**: XPC giúp việc chạy đồng thời dễ dàng hơn, vì các tác vụ khác nhau có thể chạy cùng lúc trong những process riêng biệt.

**Nhược điểm** chính là **chia một ứng dụng thành nhiều process** và để chúng giao tiếp qua XPC làm tăng overhead. Trên các hệ thống hiện đại, overhead này thường nhỏ so với lợi ích về bảo mật và độ ổn định.<sup>[[1]](#references)</sup>

## Application-Specific XPC Services

Các thành phần XPC của một ứng dụng **nằm bên trong chính ứng dụng đó**. Ví dụ, trong Safari, bạn có thể tìm thấy chúng tại **`/Applications/Safari.app/Contents/XPCServices`**. Chúng có phần mở rộng **`.xpc`** (chẳng hạn **`com.apple.Safari.SandboxBroker.xpc`**) và **cũng là các bundle**, bên trong có binary chính và một `Info.plist`. Ví dụ: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` và `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Một **thành phần XPC có thể có entitlements và đặc quyền khác** với các thành phần XPC khác hoặc binary chính của ứng dụng. Một ngoại lệ là XPC service được cấu hình với **`JoinExistingSession`** đặt thành `true` trong tệp **Info.plist**. Trong trường hợp này, XPC service tham gia **cùng security session với ứng dụng** đã gọi nó.<sup>[[4]](#references)</sup>

Các XPC service được **launch** bởi **launchd** khi cần thiết và có thể được **tắt** sau khi hoàn thành **nhiệm vụ** để giải phóng tài nguyên hệ thống. **Các thành phần XPC dành riêng cho ứng dụng chỉ có thể được ứng dụng chứa chúng sử dụng**, qua đó giảm nguy cơ lộ các lỗ hổng tiềm ẩn.<sup>[[2]](#references)</sup>

## System-Wide XPC Services

Không giống các service dành riêng cho ứng dụng, system-wide XPC service không bị giới hạn trong ứng dụng chứa chúng. Tùy thuộc vào launchd domain và các bước kiểm tra authorization của service, client từ nhiều user có thể truy cập chúng. Các Mach service do launchd quản lý này cần được **khai báo trong các tệp plist** nằm trong những thư mục như **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** hoặc **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Các tệp plist này có khóa **`MachServices`** chứa tên service và khóa **`Program`** chứa đường dẫn đến binary:

```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Program</key>
	<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
	<key>AbandonProcessGroup</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>com.jamf.management.daemon</string>
	<key>MachServices</key>
	<dict>
		<key>com.jamf.management.daemon.aad</key>
		<true/>
		<key>com.jamf.management.daemon.agent</key>
		<true/>
		<key>com.jamf.management.daemon.binary</key>
		<true/>
		<key>com.jamf.management.daemon.selfservice</key>
		<true/>
		<key>com.jamf.management.daemon.service</key>
		<true/>
	</dict>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
```

Các dịch vụ trong **`LaunchDaemons`** thường chạy với quyền root. Vì vậy, nếu một tiến trình không có đặc quyền có thể gọi một phương thức dễ bị tấn công do một trong các dịch vụ này cung cấp, nó có thể leo thang đặc quyền.

## XPC Objects

- **`xpc_object_t`**

Payload của yêu cầu và phản hồi XPC thường là các đối tượng dictionary, giúp đơn giản hóa việc serialization và deserialization. `libxpc.dylib` cũng khai báo các kiểu dữ liệu cần thiết để xác minh dữ liệu nhận được có đúng kiểu mong đợi hay không. Trong C API, mọi đối tượng đều là `xpc_object_t` (và có thể kiểm tra kiểu của đối tượng bằng `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Ngoài ra, có thể dùng hàm `xpc_copy_description(object)` để lấy biểu diễn dạng chuỗi của đối tượng, hữu ích cho mục đích debug.\
Các đối tượng này cũng có một số phương thức như `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Các đối tượng `xpc_object_t` được tạo bằng cách gọi hàm `xpc_<objectType>_create`, hàm này gọi nội bộ `_xpc_base_create(Class, Size)`, chỉ định class của đối tượng (một trong các `XPC_TYPE_*`) và kích thước. Có thêm 40 byte metadata, nên dữ liệu của đối tượng bắt đầu tại offset 40 byte.\
Do đó, `xpc_<objectType>_t` có thể xem như một subclass của `xpc_object_t`, vốn là subclass của `os_object_t*`.

> [!WARNING]
> Lưu ý rằng nhà phát triển phải dùng `xpc_dictionary_[get/set]_<objectType>` để lấy hoặc đặt kiểu và giá trị thực của một key.

- **`xpc_pipe`**

**`xpc_pipe`** là một pipe FIFO mà các tiến trình có thể dùng để giao tiếp (việc giao tiếp sử dụng Mach messages).\
Có thể tạo XPC server bằng cách gọi `xpc_pipe_create()` hoặc `xpc_pipe_create_from_port()` để tạo pipe bằng một Mach port cụ thể. Sau đó, để nhận message, có thể gọi `xpc_pipe_receive` và `xpc_pipe_try_receive`.

Lưu ý rằng đối tượng **`xpc_pipe`** là một **`xpc_object_t`** có struct chứa thông tin về hai Mach port được sử dụng và tên (nếu có). Ví dụ, daemon `secinitd` cấu hình pipe có tên `com.apple.secinitd` trong plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`.

Một ví dụ về **`xpc_pipe`** là **bootstrap pipe** do **`launchd`** tạo, cho phép chia sẻ Mach port.

- **`NSXPC*`**

Đây là các đối tượng Objective-C cấp cao giúp trừu tượng hóa các kết nối XPC.\
Ngoài ra, những đối tượng này dễ debug bằng DTrace hơn các đối tượng trước đó.

- **`GCD Queues`**

XPC sử dụng GCD để chuyển message; ngoài ra, nó tạo ra một số dispatch queue như `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Đây là các **bundle có phần mở rộng `.xpc`** nằm trong thư mục **`XPCServices`** của những project khác; trong `Info.plist`, chúng có `CFBundlePackageType` được đặt thành **`XPC!`**.\
File này có các key cấu hình khác như `ServiceType`, có thể là Application, User hoặc System; `_SandboxProfile`, có thể xác định sandbox; và `_AllowedClients`, có thể cho biết entitlement hoặc danh tính cần thiết để liên hệ với dịch vụ. Các tùy chọn này cùng những tùy chọn khác cấu hình dịch vụ khi nó được khởi chạy.<sup>[[2]](#references)</sup>

### Starting a Service

Ứng dụng cố **kết nối** với một XPC service bằng `xpc_connection_create_mach_service`; sau đó launchd tìm daemon và khởi chạy **`xpcproxy`**. **`xpcproxy`** thực thi các hạn chế đã cấu hình và khởi chạy service với các file descriptor cùng Mach port được cung cấp.<sup>[[3]](#references)</sup>

Để tăng tốc độ tìm kiếm XPC service, hệ thống sử dụng cache.

Có thể theo dõi các hành động của `xpcproxy` bằng:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

Thư viện XPC dùng `kdebug` để ghi nhật ký các hành động bằng cách gọi `xpc_ktrace_pid0` và `xpc_ktrace_pid1`. Các mã được dùng không có tài liệu, vì vậy cần thêm chúng vào `/usr/share/misc/trace.codes`. Chúng có tiền tố `0x29`; ví dụ: `0x29000004` là `XPC_serializer_pack`.\
Tiện ích `xpcproxy` dùng tiền tố `0x22`, ví dụ: `0x2200001c: xpcproxy:will_do_preexec`.

## Kiểm tra các XPC helper kiểu Application

`XPCService.ServiceType` có giá trị `Application` là điểm khởi đầu hữu ích khi kiểm tra các helper do framework cung cấp: liệt kê các bundle, giữ lại những service đang chạy, rồi kiểm tra identifier và entitlements của helper. Tìm trong cả `/System/Library/Frameworks` và `/System/Library/PrivateFrameworks`; danh sách chính xác thay đổi theo các bản phát hành macOS.<sup>[[7]](#references)</sup>

```bash
find /System/Library/Frameworks /System/Library/PrivateFrameworks \
  -type d -name '*.xpc' -print0 2>/dev/null |
while IFS= read -r -d '' bundle; do
    plist="$bundle/Contents/Info.plist"
    [ "$(plutil -extract XPCService.ServiceType raw -o - "$plist" 2>/dev/null)" = Application ] || continue

    exe=$(plutil -extract CFBundleExecutable raw -o - "$plist" 2>/dev/null) || continue
    bin="$bundle/Contents/MacOS/$exe"
    ps -axo comm= | awk -v b="$bin" '{sub(/^[[:space:]]+/, ""); if ($0==b) found=1} END {exit !found}' || continue

    printf '\n%s\n  id: %s\n' "$bundle" \
      "$(plutil -extract CFBundleIdentifier raw -o - "$plist" 2>/dev/null)"
    codesign -d --entitlements :- "$bundle" 2>&1
done
```

### Phân loại listener và khôi phục giao thức tối giản

Tìm `-[<delegate> listener:shouldAcceptNewConnection:]` trong helper. Nếu một nhánh thiết lập `exportedInterface` và `exportedObject`, resume connection rồi trả về `YES`/`1` mà không kiểm tra audit token, code requirement hoặc entitlement của peer, thì RPC interface sẽ được mở cho mọi client có thể tìm thấy service. Điều này chỉ chứng minh **khả năng truy cập**: để gây tác động, vẫn cần một method được export thực hiện thao tác đặc quyền mà không có cơ chế phân quyền phù hợp cho từng client/từng method, hoặc xử lý không an toàn input do attacker kiểm soát.<sup>[[7]](#references)</sup>

Chỉ khôi phục các selector cần cho việc kiểm thử. Metadata của Objective-C selector cho biết số lượng argument; cách sử dụng các argument trong decompiler thường giúp xác định rõ hơn kiểu dữ liệu (ví dụ: các giá trị truyền vào `-[EKEvent setStartDate:]` và `setEndDate:` là `NSDate *`), còn lời gọi gián tiếp ở cuối method cho biết các parameter của reply block. Một protocol cục bộ chưa đầy đủ là đủ cho `NSXPCInterface`; không cần tái dựng toàn bộ private protocol.<sup>[[7]](#references)</sup>

### Kết nối bằng interface đã tái dựng

Với một application XPC service, hãy load framework định nghĩa các private class cần thiết, tạo connection bằng `initWithServiceName:`, gán remote interface đã tái dựng, cài đặt các handler cho lỗi/gián đoạn/vô hiệu hóa, rồi mới resume connection. Giữ run loop hoạt động để nhận các reply bất đồng bộ. Khi kiểm thử ranh giới sandbox, hãy chạy lại client bên trong một ứng dụng được sandbox; standalone client chạy thành công không phải là bằng chứng cho thấy đã thoát sandbox.<sup>[[7]](#references)</sup>

<details>
<summary>Client Objective-C tối giản</summary>

```objectivec
@protocol RecoveredProtocol
- (void)createEventIntentWithStartDate:(NSDate *)start
                               endDate:(NSDate *)end
                             withReply:(void (^)(id object, id error))reply;
@end

[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AppPredictionFoundation.framework"] load];
NSXPCConnection *c = [[NSXPCConnection alloc]
    initWithServiceName:@"com.apple.proactive.AppPredictionIntentsHelperService"];
c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
c.interruptionHandler = ^{ NSLog(@"interrupted"); };
c.invalidationHandler = ^{ NSLog(@"invalidated"); };
[c resume];
id proxy = [c remoteObjectProxyWithErrorHandler:^(NSError *e) { NSLog(@"%@", e); }];
[proxy createEventIntentWithStartDate:[NSDate date]
                              endDate:[NSDate dateWithTimeIntervalSinceNow:3600]
                            withReply:^(id obj, id err) { NSLog(@"%@ %@", obj, err); }];
[[NSRunLoop currentRunLoop] run];
```

Biên dịch bằng `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Dùng lỗi secure-coding làm type oracle

Lỗi `NSCocoaErrorDomain` như mã `4101` có thể che giấu ngoại lệ serialization hữu ích. Tìm trong unified log/Console của macOS theo tên service: ngoại lệ sẽ xác định cả class không mong muốn lẫn các class được phép cho đối số selector đó. Với phản hồi, hãy mở rộng allowlist interface **phía client** bằng `setClasses:forSelector:argumentIndex:ofReply:`; khi `ofReply:YES`, index `0` là tham số đầu tiên của reply block, không phải tham số đầu tiên của method.<sup>[[7]](#references)</sup>

Cấu hình interface trước khi gán nó cho connection và gọi `[c resume]`:<sup>[[7]](#references)</sup>

```objectivec
NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
NSMutableSet *classes = [NSMutableSet setWithArray:@[
    NSDate.class, NSString.class, NSNumber.class,
    NSDictionary.class, NSArray.class, NSData.class
]];
Class intentClass = NSClassFromString(@"INIntent");
if (intentClass) [classes addObject:intentClass];
[iface setClasses:classes
      forSelector:@selector(createEventIntentWithStartDate:endDate:withReply:)
    argumentIndex:0
          ofReply:YES];
c.remoteObjectInterface = iface;
```

Trường hợp ngược lại cũng hữu ích: nếu server từ chối một đầu vào Foundation và ghi log một private class được phép duy nhất, log sẽ tiết lộ kiểu dữ liệu trên wire được mong đợi và framework của nó. Nạp framework đó, kiểm tra các method/property của class để xác định cụ thể hơn các kiểu `id` tổng quát, rồi tạo đối tượng private động. Các argument của `NSInvocation` bắt đầu ở index `2` vì index `0` và `1` là các argument `self` và `_cmd` ẩn.<sup>[[7]](#references)</sup>

<details>
<summary>Tạo argument private bằng NSInvocation</summary>

```objectivec
Class cls = NSClassFromString(@"LNStaticDeferredLocalizedString");
id allocated = [cls alloc];
SEL initializer = NSSelectorFromString(@"initWithKey:table:bundleURL:");
NSMethodSignature *signature = [allocated methodSignatureForSelector:initializer];
NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
[invocation setTarget:allocated];
[invocation setSelector:initializer];

NSString *key = @"KEY";
NSString *table = @"Localizable";
NSURL *bundleURL = NSBundle.mainBundle.bundleURL;
[invocation setArgument:&key atIndex:2];
[invocation setArgument:&table atIndex:3];
[invocation setArgument:&bundleURL atIndex:4];
[invocation invoke];

__unsafe_unretained id privateObject = nil;
[invocation getReturnValue:&privateObject];
```

</details>

Về workflow liên quan đến các Mach service toàn hệ thống được đăng ký với launchd, xem:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## Thông điệp sự kiện XPC

Ứng dụng có thể **đăng ký nhận** nhiều **thông điệp** sự kiện khác nhau, cho phép chúng được **khởi chạy theo yêu cầu** khi các sự kiện đó xảy ra. Các dịch vụ này được **thiết lập** trong các **tệp launchd plist**, nằm trong **cùng thư mục với các tệp trước đó** và có thêm khóa **`LaunchEvent`**.

### Kiểm tra tiến trình kết nối XPC

Khi một tiến trình cố gọi một phương thức thông qua kết nối XPC, **dịch vụ XPC nên kiểm tra xem tiến trình đó có được phép kết nối hay không**. Sau đây là các phương thức xác minh phổ biến và những hạn chế của chúng:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Xác thực XPC

Apple cũng cho phép ứng dụng **cấu hình các quyền xác thực và cách bên gọi nhận được chúng**, để một tiến trình có các quyền cần thiết **được phép gọi một phương thức** do dịch vụ XPC cung cấp:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Để sniff các thông điệp XPC, bạn có thể dùng **xpcspy**, công cụ sử dụng **Frida**.<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

Một công cụ khả thi khác là **XPoCe2**.<sup>[[6]](#references)</sup>

## Ví dụ mã C về giao tiếp XPC

{{#tabs}}
{{#tab name="xpc_server.c"}}

```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        // Print received message
        const char* received_message = xpc_dictionary_get_string(event, "message");
        printf("Received message: %s\n", received_message);

        // Create a response dictionary
        xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(response, "received", "received");

        // Send response
        xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
        xpc_connection_send_message(remote, response);

        // Clean up
        xpc_release(response);
    }
}

static void handle_connection(xpc_connection_t connection) {
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        handle_event(event);
    });
    xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
    xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
                                                                   dispatch_get_main_queue(),
                                                                   XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!service) {
        fprintf(stderr, "Failed to create service.\n");
        exit(EXIT_FAILURE);
    }

    xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        if (type == XPC_TYPE_CONNECTION) {
            handle_connection(event);
        }
    });

    xpc_connection_resume(service);
    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xpc_client.c"}}

```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            // Print received message
            const char* received_message = xpc_dictionary_get_string(event, "received");
            printf("Received message: %s\n", received_message);
        }
    });

    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "message", "Hello, Server!");

    xpc_connection_send_message(connection, message);

    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.service.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.service</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save the server in its configured location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```

## Ví dụ mã Objective-C về giao tiếp XPC

{{#tabs}}
{{#tab name="oc_xpc_server.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
    NSLog(@"Received message: %@", some_string);
    NSString *response = @"Received";
    reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

    MyXPCObject *my_object = [MyXPCObject new];

    newConnection.exportedObject = my_object;

    [newConnection resume];
    return YES;
}
@end

int main(void) {

    NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

    id <NSXPCListenerDelegate> delegate = [MyDelegate new];
    listener.delegate = delegate;
    [listener resume];

    sleep(10); // Fake something is done and then it ends
}
```

{{#endtab}}

{{#tab name="oc_xpc_client.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
    [connection resume];

    [[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
        NSLog(@"Received response: %@", response);
    }];

    [[NSRunLoop currentRunLoop] run];

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.svcoc.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.svcoc</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/oc_xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/oc_xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```

## Client bên trong một Dylib

```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
        NSString*  _serviceName = @"xyz.hacktricks.svcoc";

        NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

        [_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

        [_agentConnection resume];

        [[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
            (void)error;
            NSLog(@"Connection Failure");
        }] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
            NSLog(@"Received response: %@", response);
    }    ];
        NSLog(@"Done!");

    return;
}
```

## Remote XPC

Chức năng do `RemoteXPC.framework` (từ `libxpc`) cung cấp cho phép giao tiếp XPC giữa các host khác nhau.\
Các service hỗ trợ Remote XPC có khóa `UsesRemoteXPC` trong plist, như trường hợp của `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Mặc dù service được đăng ký với `launchd`, `UserEventAgent` cùng các plugin `com.apple.remoted.plugin` và `com.apple.remoteservicediscovery.events.plugin` cung cấp chức năng này.

Ngoài ra, `RemoteServiceDiscovery.framework` lấy thông tin từ `com.apple.remoted.plugin`, cung cấp các hàm như `get_device`, `get_unique_device` và `connect`.

Sau khi `connect` trả về file descriptor của socket của service, ta có thể sử dụng lớp `remote_xpc_connection_*`.

Có thể lấy thông tin về các service từ xa bằng CLI `/usr/libexec/remotectl` với các lệnh như:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

Việc giao tiếp giữa bridgeOS và host diễn ra thông qua một giao diện IPv6 chuyên dụng. `MultiverseSupport.framework` thiết lập các socket có file descriptor được dùng cho giao tiếp.\
Có thể tìm các giao tiếp này bằng `netstat`, `nettop` hoặc `netbottom`, một giải pháp thay thế mã nguồn mở.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Tạo XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - Tấn công các XPC Helper trên macOS: Reverse Engineering giao thức](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
