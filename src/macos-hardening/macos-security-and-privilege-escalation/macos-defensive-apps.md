# Ứng dụng phòng thủ macOS

{{#include ../../banners/hacktricks-training.md}}

## Tường lửa

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Công cụ giám sát mọi kết nối do từng tiến trình tạo ra. Tùy theo chế độ (âm thầm cho phép kết nối, âm thầm chặn kết nối và cảnh báo), công cụ sẽ **hiển thị cảnh báo** mỗi khi có kết nối mới được thiết lập. Công cụ cũng có GUI rất trực quan để xem toàn bộ thông tin này.
- [**LuLu**](https://objective-see.org/products/lulu.html): Tường lửa của Objective-See. Đây là tường lửa cơ bản sẽ cảnh báo bạn về các kết nối đáng ngờ (có GUI nhưng không bắt mắt bằng Little Snitch).

## Phát hiện cơ chế duy trì hiện diện

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Ứng dụng của Objective-See tìm kiếm ở nhiều vị trí nơi **malware có thể duy trì hiện diện** (công cụ chạy một lần, không phải dịch vụ giám sát).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Tương tự KnockKnock, nhưng giám sát các tiến trình tạo cơ chế duy trì hiện diện.

## Phát hiện keylogger

- [**ReiKey**](https://objective-see.org/products/reikey.html): Ứng dụng của Objective-See dùng để tìm **keylogger** cài đặt các “event tap” cho bàn phím.

## Telemetry endpoint / kiểm soát thực thi

- [**Santa**](https://santa.dev/): Hệ thống cấp quyền và giám sát binary cho macOS. Công cụ sử dụng một client **Endpoint Security** để cấp quyền cho các sự kiện **`exec`** trước khi mã được chạy. Vì vậy, công cụ thường được dùng trong các hệ thống doanh nghiệp tập trung vào **allowlisting/denylisting**, thay vì chỉ phát hiện sau khi thực thi.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Công cụ phân tích động cho macOS tương tự Procmon. Công cụ thu thập **telemetry Endpoint Security** (các sự kiện về tiến trình, tệp, liên tiến trình, đăng nhập và XProtect) và hữu ích để hiểu một sensor dựa trên ES hoàn thiện có thể quan sát được những gì.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Các công cụ Objective-See nhẹ để thu thập telemetry về **tiến trình**, **tệp** và **DNS**. Trên macOS hiện đại, chúng có thêm các điều kiện tiên quyết như **root**, **Terminal có quyền Full Disk Access** hoặc **phê duyệt System/Network Extension**. Để tham khảo thêm các ý tưởng về instrumentation, xem [trang khác này về kiểm tra/gỡ lỗi ứng dụng macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Phân loại nhanh công cụ phòng thủ

Hầu hết sản phẩm bảo mật macOS hiện đại hoạt động dưới dạng kết hợp giữa **System Extensions / client Endpoint Security**, **agent/daemon launchd** và ứng dụng có **Full Disk Access**. Danh sách kiểm tra nhanh dành cho người vận hành:

```bash
# System / network extensions (EDRs, DNS filters, firewalls, VPNs)
systemextensionsctl list

# Legacy kernel agents on older boxes / upgraded fleets
kmutil showloaded 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'
# Older releases:
kextstat 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'

# Userland agents / helpers
launchctl print system | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'
launchctl print gui/$UID | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'

# Inspect code-signing and entitlements of a defensive app
codesign -dvv --entitlements :- /Applications/SomeAgent.app

# Check common TCC grants used by sensors / telemetry tools
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
  [ -f "$db" ] || continue
  echo "== $db =="
  sqlite3 "$db" 'SELECT service,client,auth_value,last_modified FROM access WHERE service IN ("kTCCServiceSystemPolicyAllFiles","kTCCServiceEndpointSecurityClient") ORDER BY last_modified DESC;'
done
```

Nếu `systemextensionsctl list` hiển thị một sensor ở trạng thái **`[activated enabled]`**, đây thường là dấu hiệu nhanh nhất cho thấy extension thực sự đang hoạt động. Trên **macOS 15 Sequoia trở lên**, MDM cũng có thể đánh dấu một số security extension là **không thể gỡ bỏ qua giao diện**, vì vậy không còn an toàn khi mặc định rằng có thể "tắt nó trong System Settings". Để tìm hiểu nội bộ, xem [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Telemetry gốc gần đây mà các bên phòng thủ có thể sử dụng

Các bản phát hành macOS gần đây khiến một số cách bypass do người dùng thực hiện vốn khó phát hiện trở nên dễ bị blue team phát hiện hơn:

- **macOS 15+**: Các Endpoint Security client có thể nhận sự kiện **`gatekeeper_user_override`**, nhờ đó các lần bypass Gatekeeper thủ công có thể được ghi log tập trung.
- **Các công cụ Endpoint Security hiện tại trên macOS** cũng có thể tiếp nhận sự kiện **phát hiện malware của XProtect**, giúp xác nhận dễ dàng hơn những gì Apple đã phát hiện trên endpoint.
- **macOS 15.4+**: Endpoint Security bổ sung **`tcc_modify`**, cuối cùng cung cấp cho các bên phòng thủ một cách được hỗ trợ để giám sát **các lần cấp/thu hồi quyền TCC**, thay vì phải thu thập log debug của TCC.<sup>[[1]](#references)</sup>

```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```

Điều này hữu ích cho cả defender lẫn red teamer đang tự đánh giá: nếu mục tiêu có stack dựa trên ES đã trưởng thành, **các chuỗi bypass Gatekeeper / TCC được người dùng phê duyệt có thể dễ bị phát hiện hơn trước rất nhiều**. Để tìm hiểu về các biện pháp bảo vệ này, xem [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) và [TCC](macos-security-protections/macos-tcc/README.md).

## References


- [1] [Objective-See - TCCing là Tin mới được! Apple cuối cùng đã thêm các sự kiện TCC vào Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Giới thiệu: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)
{{#include ../../banners/hacktricks-training.md}}
