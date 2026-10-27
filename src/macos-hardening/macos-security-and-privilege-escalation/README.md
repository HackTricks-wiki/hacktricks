# Bảo mật macOS & leo thang đặc quyền

{{#include ../../banners/hacktricks-training.md}}

## macOS cơ bản

Nếu chưa quen với macOS, hãy bắt đầu với những kiến thức cơ bản và các tài liệu tham khảo về ứng phó sự cố, phân tích malware và lệnh được liệt kê bên dưới.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

- **Tệp & quyền đặc biệt** của macOS:


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **Người dùng** macOS thường gặp


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- **Kiến trúc** của **kernel**


{{#ref}}
mac-os-architecture/
{{#endref}}

- **Dịch vụ mạng và giao thức** macOS thường gặp


{{#ref}}
macos-protocols.md
{{#endref}}

- macOS **mã nguồn mở**: [https://opensource.apple.com/](https://opensource.apple.com/)
  - Để tải `tar.gz`, hãy đổi URL như [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) thành [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM trên macOS

Trong môi trường doanh nghiệp, các hệ thống macOS thường được quản lý bằng giải pháp quản lý thiết bị di động (MDM). Vì vậy, từ góc nhìn của kẻ tấn công, việc hiểu cách MDM hoạt động rất hữu ích:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### macOS - Kiểm tra, gỡ lỗi và fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Các biện pháp bảo vệ bảo mật của macOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Bề mặt tấn công

### Quyền truy cập tệp

Nếu một **process chạy với quyền root ghi** vào một tệp mà người dùng có thể kiểm soát, người dùng có thể lợi dụng điều này để **leo thang đặc quyền**.\
Điều này có thể xảy ra trong các trường hợp sau:

- Tệp được sử dụng đã do người dùng tạo (thuộc sở hữu của người dùng)
- Người dùng có thể ghi vào tệp được sử dụng vì tệp thuộc một group
- Tệp được sử dụng nằm trong thư mục thuộc sở hữu của người dùng (người dùng có thể tạo tệp)
- Tệp được sử dụng nằm trong thư mục thuộc sở hữu của root nhưng người dùng có quyền ghi vào thư mục đó thông qua một group (người dùng có thể tạo tệp)

Việc **tạo được một tệp** sẽ được **root sử dụng** cho phép người dùng **lợi dụng nội dung của tệp**, hoặc thậm chí tạo **symlinks/hardlinks** trỏ đến một vị trí khác.

Đối với loại lỗ hổng này, đừng quên **kiểm tra các trình cài đặt `.pkg` dễ bị tấn công**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Phần mở rộng tệp và trình xử lý scheme URL của ứng dụng

Các ứng dụng bất ngờ được đăng ký để xử lý phần mở rộng tệp hoặc scheme URL có thể tạo ra bề mặt tấn công hữu ích hoặc cơ hội chiếm quyền trình xử lý.


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Leo thang đặc quyền macOS TCC / SIP

Trong macOS, **ứng dụng và binary có thể có quyền** truy cập vào các thư mục hoặc cài đặt, khiến chúng có đặc quyền cao hơn những ứng dụng và binary khác.

Do đó, kẻ tấn công muốn chiếm quyền thành công một máy macOS sẽ cần **leo thang đặc quyền TCC** (hoặc thậm chí **bypass SIP**, tùy theo nhu cầu).

Các đặc quyền này thường được cấp thông qua **entitlements** ký bằng code-signing hoặc thông qua quyền truy cập được người dùng phê duyệt và ghi lại trong **các cơ sở dữ liệu TCC**. Một số đặc quyền cũng có thể được kế thừa từ process cha, tùy thuộc vào chuỗi bảo vệ và thực thi.<sup>[[5]](#references)</sup>

Xem các liên kết sau để tìm hiểu cách [**leo thang đặc quyền TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**bypass TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) và tìm hiểu cách [**SIP đã bị bypass**](macos-security-protections/macos-sip.md#sip-bypasses) trong quá khứ.

## Leo thang đặc quyền truyền thống trên macOS

Từ góc nhìn red-team, leo thang lên root là một mục tiêu quan trọng khác. Trang sau trình bày các phương pháp phổ biến:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Tuân thủ tiêu chuẩn macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [1] [Ứng phó sự cố OS X: Lập trình và phân tích](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Nghệ thuật phân tích malware trên Mac, Tập 1 - Phân tích](https://taomm.org/)
- [3] [NicolasGrimonpont/Cheatsheet - Lệnh và công cụ bảo mật macOS/Linux/Windows](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne - Tài nguyên bảo mật macOS](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - Bảo mật cục bộ trên macOS: thoát sandbox và bypass TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)
{{#include ../../banners/hacktricks-training.md}}
