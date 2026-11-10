# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper có thể đóng gói một tệp thực thi hoặc script thành tệp Windows Installer (`.msi`). Tải xuống và khởi chạy phiên bản miễn phí, sau đó chọn tệp thực thi cần đóng gói.<sup>[[3]](#references)</sup> Để chạy một chuỗi lệnh, hãy chọn tệp `.bat` làm đầu vào thay vì đóng gói `cmd.exe`.<sup>[[1]](#references)</sup>

![Chọn tệp thực thi nguồn hoặc batch script trong MSI Wrapper](<../../images/image (417).png>)

Cấu hình cẩn thận ngữ cảnh thực thi và các thuộc tính khác của trình cài đặt:

![Cấu hình ID ứng dụng và ngữ cảnh bảo mật trong MSI Wrapper](<../../images/image (312).png>)

![Cấu hình các thuộc tính của trình cài đặt trong MSI Wrapper](<../../images/image (346).png>)

![Xem lại cài đặt bản dựng của MSI Wrapper](<../../images/image (1072).png>)

Có thể thay đổi các giá trị này khi đóng gói một binary tùy chỉnh.

Tiếp tục qua các trang còn lại của trình hướng dẫn và chọn **Build** để tạo trình cài đặt.<sup>[[1]](#references)</sup>

## Xác minh ngữ cảnh thực thi của lệnh được bọc

Đối với gói thử nghiệm, hãy bọc một tệp `.bat` có chức năng ghi lại token của nó thay vì giả định rằng cài đặt nâng quyền của MSI cũng áp dụng cho tiến trình con.<sup>[[4]](#references)</sup> Trong trình hướng dẫn, chọn ngữ cảnh bảo mật **System** thay vì **User**, đồng thời chọn kiểu cài đặt cho toàn máy, có nâng quyền nếu đó là phương thức mong muốn.<sup>[[5]](#references)</sup> Tùy chọn **System** không vượt qua bước cấp quyền: người dùng không phải admin vẫn cần một phương thức cài đặt nâng quyền, chẳng hạn như [lỗi cấu hình `AlwaysInstallElevated` với hai policy](index.html#alwaysinstallelevated) hoặc quy trình cài đặt có đặc quyền.<sup>[[2]](#references)</sup> Thay vào đó, chọn **User** sẽ chạy lệnh được bọc trong ngữ cảnh của người dùng thực hiện cài đặt; điều này có thể cần thiết đối với tài nguyên dành riêng cho người dùng hoặc tài nguyên mạng.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Tạo MSI với batch file này làm đầu vào, sau đó chạy trên máy chủ kiểm thử và kiểm tra danh tính cùng các quyền đã ghi lại.<sup>[[4]](#references)</sup> MSI Wrapper ánh xạ mã thoát khác 0 của batch thành lỗi cài đặt 1603, vì vậy việc thoát rõ ràng với mã 0 sẽ tránh báo lỗi giả sau khi kiểm thử thành công.<sup>[[4]](#references)</sup> Tệp đầu ra chỉ là sản phẩm của quá trình kiểm thử; không suy luận rằng tiến trình chạy với quyền SYSTEM chỉ dựa trên việc `msiexec` thoát thành công hoặc quá trình cài đặt chạy im lặng.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` tắt giao diện MSI, nhưng không nhất thiết tắt giao diện riêng của executable được bọc.<sup>[[6]](#references)[[7]](#references)</sup> Với installer được bọc, hãy đặt các đối số silent được hỗ trợ trong wizard; thuộc tính động `WRAPPED_ARGUMENTS` của MSI Wrapper là tính năng PRO.<sup>[[1]](#references)[[7]](#references)</sup> Xem [cách tiếp cận custom-action của WiX](create-msi-with-wix.md) nếu bạn cần kiểm soát trực tiếp trình tự custom-action và impersonation.

> [!WARNING]
> Việc tạo MSI không tự cấp đặc quyền nâng cao. Việc cài đặt có được nâng quyền hay không phụ thuộc vào chính sách Windows Installer, ngữ cảnh gói và quyền của người dùng. Microsoft cảnh báo rằng bật `AlwaysInstallElevated` cho cả người dùng lẫn máy tính sẽ cho phép người không phải quản trị viên cài đặt gói với đặc quyền hệ thống.<sup>[[2]](#references)</sup>



## References

- [1] [Tài liệu MSI Wrapper - Bắt đầu](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Cài đặt gói với đặc quyền nâng cao cho người không phải quản trị viên](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Tải xuống](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Tạo msi từ tệp batch](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Các trang Wizard](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Tùy chọn dòng lệnh](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Đối số dòng lệnh](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
