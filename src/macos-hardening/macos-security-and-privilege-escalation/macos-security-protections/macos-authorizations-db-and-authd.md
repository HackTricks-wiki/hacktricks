# CSDL Authorization của macOS & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Cơ sở dữ liệu Authorization

Security framework's Authorization Services cho phép các helper có đặc quyền và những thành phần khác đánh giá các quyền authorization được đặt tên. Trên các phiên bản macOS hiện tại, nhiều quy tắc trong số đó được lưu trong `/var/db/auth.db` và được `authd` đánh giá; tệp này cùng schema SQLite của nó là chi tiết triển khai và có thể thay đổi giữa các bản phát hành.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Theo truyền thống, các giá trị mặc định của hệ thống được khởi tạo từ `/System/Library/Security/authorization.plist`, còn trình cài đặt hoặc dịch vụ có đặc quyền có thể thêm các quyền được đặt tên. Nên dùng giao diện được hỗ trợ `security authorizationdb read|write|remove` thay vì chỉnh sửa trực tiếp cơ sở dữ liệu.<sup>[[3]](#references)</sup>

Bảng `rules` được quan sát trên bản dựng được ghi nhận có các cột sau. Hãy xem đây là bản đồ pháp chứng, không phải schema công khai ổn định:

- **id**: Mã định danh duy nhất cho mỗi quy tắc, được tự động tăng và đóng vai trò khóa chính.
- **name**: Tên duy nhất của quy tắc, dùng để nhận diện và tham chiếu quy tắc trong hệ thống authorization.
- **type**: Chỉ định loại quy tắc, giới hạn ở giá trị 1 hoặc 2 để xác định logic authorization.
- **class**: Phân loại quy tắc vào một lớp cụ thể, đảm bảo đây là số nguyên dương.
  - Các lớp quy tắc phổ biến gồm `allow`, `deny`, `user`, `rule` và `evaluate-mechanisms`. Mechanism có thể là thành phần tích hợp sẵn hoặc plug-in Security Agent trong `/System/Library/CoreServices/SecurityAgentPlugins/` hoặc `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group**: Cho biết nhóm người dùng được liên kết với quy tắc để thực hiện authorization dựa trên nhóm.
- **kofn**: Thể hiện tham số "k-of-n", xác định cần đáp ứng bao nhiêu quy tắc con trong tổng số quy tắc.
- **timeout**: Xác định khoảng thời gian tính bằng giây trước khi authorization được cấp theo quy tắc hết hạn.
- **flags**: Chứa các cờ khác nhau để thay đổi hành vi và đặc tính của quy tắc.
- **tries**: Giới hạn số lần thử authorization được phép nhằm tăng cường bảo mật.
- **version**: Theo dõi phiên bản của quy tắc để kiểm soát phiên bản và cập nhật.
- **created**: Ghi lại dấu thời gian tạo quy tắc nhằm phục vụ kiểm tra.
- **modified**: Lưu dấu thời gian của lần chỉnh sửa quy tắc gần nhất.
- **hash**: Chứa giá trị hash của quy tắc để đảm bảo tính toàn vẹn và phát hiện hành vi giả mạo.
- **identifier**: Cung cấp chuỗi định danh duy nhất, chẳng hạn UUID, để tham chiếu quy tắc từ bên ngoài.
- **requirement**: Chứa dữ liệu đã tuần tự hóa, định nghĩa các yêu cầu và mechanism authorization cụ thể của quy tắc.
- **comment**: Cung cấp mô tả hoặc chú thích dễ đọc về quy tắc để tài liệu hóa và làm rõ.

### Ví dụ

```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>class</key>
	<string>rule</string>
	<key>comment</key>
	<string>For modification of TCC settings.</string>
	<key>created</key>
	<real>701369782.01043606</real>
	<key>modified</key>
	<real>701369782.01043606</real>
	<key>rule</key>
	<array>
		<string>authenticate-admin-nonshared</string>
	</array>
	<key>version</key>
	<integer>0</integer>
</dict>
</plist>
```

Quy tắc đã giải mã sau minh họa `authenticate-admin-nonshared` trên một phiên bản macOS đã được tài liệu hóa:<sup>[[1]](#references)</sup>

```json
{
  "allow-root": "false",
  "authenticate-user": "true",
  "class": "user",
  "comment": "Authenticate as an administrator.",
  "group": "admin",
  "session-owner": "false",
  "shared": "false",
  "timeout": "30",
  "tries": "10000",
  "version": "1"
}
```

## Authd

`authd` là dịch vụ XPC đánh giá các yêu cầu Authorization Services. Trên các bản dựng macOS hiện tại, có thể kiểm tra bundle của dịch vụ tại `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`; đường dẫn này là chi tiết triển khai và có thể khác nhau giữa các phiên bản. Các phiên bản cũ ghi log tại `/var/log/authd.log`; các phiên bản hiện tại chủ yếu dùng hệ thống unified logging, có thể truy vấn bằng `log show`/`log stream` với predicate cho tiến trình `authd`.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

Công cụ `security` cung cấp một số thao tác Authorization Services. Một ví dụ cũ gọi `AuthorizationExecuteWithPrivileges` bằng lệnh `security execute-with-privileges /bin/ls`. Apple đã ngừng hỗ trợ API đó trong macOS 10.7; các privileged helper hiện đại nên dùng helper do launchd quản lý và XPC authorization.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

Trên các phiên bản vẫn hỗ trợ tính năng này, lệnh sử dụng `/usr/libexec/security_authtrampoline` và hiển thị lời nhắc xác thực trước khi chạy lệnh dưới quyền root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Tổng quan về Authorization Right của macOS](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Hướng dẫn lập trình Apple Authorization Services (lưu trữ)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [Trang hướng dẫn sử dụng macOS `security(1)`](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Hướng dẫn lập trình Daemons and Services: Tạo các tác vụ launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Dự án Security mã nguồn mở của Apple - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
