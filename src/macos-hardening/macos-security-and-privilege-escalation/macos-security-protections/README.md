# Các biện pháp bảo vệ an ninh của macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper thường được dùng để chỉ sự kết hợp của **Quarantine + Gatekeeper + XProtect**, 3 mô-đun bảo mật của macOS nhằm **ngăn người dùng thực thi phần mềm có khả năng độc hại được tải xuống**.

Tìm hiểu thêm tại:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Các giới hạn đối với tiến trình

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

macOS Sandbox **giới hạn các ứng dụng** chạy bên trong sandbox, chỉ cho phép chúng thực hiện **các hành động được chỉ định trong Sandbox profile** mà ứng dụng đang sử dụng. Điều này giúp đảm bảo **ứng dụng chỉ truy cập các tài nguyên dự kiến**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** là một framework bảo mật. Framework này được thiết kế để **quản lý quyền** của ứng dụng, cụ thể là kiểm soát quyền truy cập vào các tính năng nhạy cảm. Những tính năng này bao gồm **dịch vụ định vị, danh bạ, ảnh, microphone, camera, trợ năng và quyền truy cập toàn bộ ổ đĩa**. TCC đảm bảo ứng dụng chỉ có thể truy cập các tính năng này sau khi được người dùng đồng ý rõ ràng, qua đó tăng cường quyền riêng tư và khả năng kiểm soát dữ liệu cá nhân.


{{#ref}}
macos-tcc/
{{#endref}}

### Ràng buộc khởi chạy/môi trường và Trust Cache

Ràng buộc khởi chạy trong macOS là một tính năng bảo mật giúp **kiểm soát việc khởi chạy tiến trình** bằng cách xác định **ai có thể khởi chạy** một tiến trình, **bằng cách nào** và **từ đâu**. Được giới thiệu trong macOS Ventura, các ràng buộc này phân loại các binary của hệ thống thành các danh mục ràng buộc trong một **trust cache**. Mỗi binary thực thi đều có các **quy tắc** xác định cách **khởi chạy**, bao gồm các ràng buộc **self**, **parent** và **responsible**. Được mở rộng sang các ứng dụng bên thứ ba dưới dạng ràng buộc **Environment** trong macOS Sonoma, những tính năng này giúp giảm thiểu nguy cơ khai thác hệ thống bằng cách kiểm soát các điều kiện khởi chạy tiến trình.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Công cụ loại bỏ phần mềm độc hại

Malware Removal Tool (MRT) là một phần khác trong cơ sở hạ tầng bảo mật của macOS. Đúng như tên gọi, chức năng chính của MRT là **loại bỏ phần mềm độc hại đã biết khỏi các hệ thống bị nhiễm**.

Khi phần mềm độc hại được phát hiện trên máy Mac (bởi XProtect hoặc bằng cách khác), MRT có thể tự động **loại bỏ phần mềm độc hại**. MRT chạy âm thầm ở chế độ nền và thường được thực thi mỗi khi hệ thống được cập nhật hoặc khi có định nghĩa phần mềm độc hại mới được tải xuống (có vẻ như các quy tắc MRT dùng để phát hiện phần mềm độc hại nằm bên trong binary).

Mặc dù XProtect và MRT đều là một phần trong các biện pháp bảo mật của macOS, chúng thực hiện các chức năng khác nhau:

- **XProtect** là công cụ phòng ngừa. Công cụ này **kiểm tra các tệp khi chúng được tải xuống** (thông qua một số ứng dụng nhất định) và nếu phát hiện bất kỳ loại phần mềm độc hại đã biết nào, nó sẽ **ngăn tệp mở**, qua đó ngăn phần mềm độc hại lây nhiễm vào hệ thống ngay từ đầu.
- **MRT**, mặt khác, là một công cụ **phản ứng**. Công cụ này hoạt động sau khi phần mềm độc hại được phát hiện trên hệ thống, với mục tiêu loại bỏ phần mềm gây hại để dọn sạch hệ thống.

Ứng dụng MRT nằm tại **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Quản lý tác vụ nền

**macOS** hiện **cảnh báo** mỗi khi một công cụ sử dụng **kỹ thuật phổ biến để duy trì thực thi mã** (chẳng hạn như Login Items, Daemons...), giúp người dùng biết rõ hơn **phần mềm nào đang duy trì persistence**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Việc này được thực hiện bởi một **daemon** nằm tại `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` và **agent** nằm tại `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`** xác định một thành phần đã được cài đặt trong thư mục persistent bằng cách **nhận các FSEvents** và tạo một số **handler** cho chúng.<sup>[[1]](#references)</sup>

Ngoài ra, một tệp plist chứa danh sách **các ứng dụng phổ biến** thường xuyên duy trì persistence, do Apple quản lý, nằm tại: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>

```json
[...]
"us.zoom.ZoomDaemon" => {
    "AssociatedBundleIdentifiers" => [
      0 => "us.zoom.xos"
    ]
    "Attribution" => "Zoom"
    "Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
    "ProgramArguments" => [
      0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
    ]
    "TeamIdentifier" => "BJ4HAAB9B3"
  }
[...]
```

### Liệt kê

Có thể **liệt kê tất cả** các mục chạy nền đã cấu hình bằng công cụ cli của Apple:<sup>[[3]](#references)</sup>

```bash
# The tool will always ask for the users password
sfltool dumpbtm
```

Hơn nữa, cũng có thể liệt kê thông tin này bằng [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>

```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```

Thông tin này được lưu trong **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** và Terminal cần FDA.<sup>[[2]](#references)</sup>

### Can thiệp vào BTM

Khi phát hiện một persistence mới, một event thuộc loại **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** sẽ được tạo. Vì vậy, bất kỳ cách nào để **ngăn** event này được gửi hoặc **ngăn agent cảnh báo** người dùng đều giúp attacker _**bypass**_ BTM.<sup>[[1]](#references)</sup>

- **Resetting the database**: Chạy lệnh sau sẽ reset database (database sẽ được tạo lại từ đầu). Tuy nhiên, sau khi thực hiện việc này, **sẽ không có cảnh báo persistence mới nào xuất hiện cho đến khi hệ thống được khởi động lại**.<sup>[[1]](#references)</sup>
  - Cần quyền **root**.

```bash
# Reset the database
sfltool resettbtm
```

- **Dừng Agent**: Có thể gửi tín hiệu dừng đến agent để agent **không cảnh báo người dùng** khi phát hiện các mối đe dọa mới.<sup>[[1]](#references)</sup>

```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```

- **Bug**: Nếu **process tạo persistence thoát ngay sau đó**, daemon cố gắng **lấy thông tin** về process đó nhưng **thất bại**, và **không thể gửi sự kiện** cho biết một mục mới đang được persist.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "Giải mã (& Bypass) Background Task Management của macOS" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Công cụ mới dành cho nhà phát triển: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Quản lý mục đăng nhập và tác vụ nền trên Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
