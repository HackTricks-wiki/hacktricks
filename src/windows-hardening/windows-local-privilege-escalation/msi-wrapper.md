# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper có thể đóng gói một tệp thực thi hoặc script thành tệp Windows Installer (`.msi`). Tải xuống và khởi chạy phiên bản miễn phí, sau đó chọn tệp thực thi cần đóng gói.<sup>[[3]](#references)</sup> Để chạy một chuỗi lệnh, hãy chọn tệp `.bat` làm đầu vào thay vì đóng gói `cmd.exe`.<sup>[[1]](#references)</sup>

![Chọn tệp thực thi nguồn hoặc batch script trong MSI Wrapper](<../../images/image (417).png>)

Cấu hình cẩn thận ngữ cảnh thực thi và các thuộc tính khác của trình cài đặt:

![Cấu hình ID ứng dụng và ngữ cảnh bảo mật trong MSI Wrapper](<../../images/image (312).png>)

![Cấu hình các thuộc tính của trình cài đặt trong MSI Wrapper](<../../images/image (346).png>)

![Kiểm tra cài đặt bản dựng MSI Wrapper](<../../images/image (1072).png>)

Có thể thay đổi các giá trị này khi đóng gói binary tùy chỉnh.

Tiếp tục qua các trang còn lại của trình hướng dẫn và chọn **Build** để tạo trình cài đặt.<sup>[[1]](#references)</sup>

> [!WARNING]
> Việc tạo MSI không tự cấp quyền nâng cao. Việc cài đặt có được nâng quyền hay không phụ thuộc vào chính sách Windows Installer, ngữ cảnh gói và sự cho phép của người dùng. Microsoft cảnh báo rằng bật `AlwaysInstallElevated` cho cả người dùng lẫn máy tính sẽ cho phép người không có quyền quản trị cài đặt các gói với đặc quyền hệ thống.<sup>[[2]](#references)</sup>

## References

- [1] [Tài liệu MSI Wrapper - Bắt đầu](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Cài đặt gói với quyền nâng cao cho người không có quyền quản trị](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Tải xuống](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
