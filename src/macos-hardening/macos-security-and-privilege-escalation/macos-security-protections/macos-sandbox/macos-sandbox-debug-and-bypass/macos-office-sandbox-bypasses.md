# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Sau đây là các **lỗ hổng thoát khỏi sandbox trong Microsoft Office for Mac đã được ghi nhận trong quá khứ**. Chúng cho thấy những sai sót về ranh giới tin cậy có thể tái sử dụng, nhưng không nên mặc định rằng các phiên bản Office/macOS đã được vá vẫn dễ bị tấn công nếu chưa tái hiện trên đúng phiên bản và chính sách.

### Word sandbox bypass qua LaunchAgents

Ứng dụng bị ảnh hưởng sử dụng quy tắc sandbox tùy chỉnh thông qua `com.apple.security.temporary-exception.sbpl`. Quy tắc này cho phép các file thông thường có tên cơ sở bắt đầu bằng `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Do đó, để thoát sandbox, chỉ cần **ghi một LaunchAgent `plist`** vào `~/Library/LaunchAgents/~$escape.plist`.

Xem [**báo cáo gốc tại đây**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass qua Login Items và zip

Như đã thấy trong lần thoát sandbox đầu tiên, Word có thể ghi các file tùy ý có tên bắt đầu bằng `~$`, dù sau khi lỗ hổng trước đó được vá, không thể ghi vào `/Library/Application Scripts` hoặc `/Library/LaunchAgents`.

Sandbox bị ảnh hưởng cho phép tạo một **Login Item**, được khởi chạy khi người dùng đăng nhập. Đường khai thác được trình diễn yêu cầu một ứng dụng đã ký/được notarize hợp lệ và không cho phép truyền các đối số tùy ý, vì vậy thêm `bash` cùng đối số reverse-shell là không đủ.<sup>[[2]](#references)</sup>

Sau Sandbox bypass trước đó, Microsoft đã vô hiệu hóa khả năng ghi file vào `~/Library/LaunchAgents`. Tuy nhiên, người ta phát hiện rằng nếu thêm **file zip làm Login Item**, `Archive Utility` sẽ **giải nén** file ngay tại vị trí hiện tại. Vì thư mục `LaunchAgents` trong `~/Library` thường chưa được tạo theo mặc định, có thể **nén một plist vào `LaunchAgents/~$escape.plist`** rồi **đặt** file zip trong **`~/Library`**. Khi giải nén, file sẽ được đưa đến vị trí cần thiết để duy trì quyền truy cập.

Xem [**báo cáo gốc tại đây**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass qua Login Items và .zshenv

(Như đã thấy trong lần thoát sandbox đầu tiên, Word có thể ghi các file tùy ý có tên bắt đầu bằng `~$`.)

Tuy nhiên, kỹ thuật trước có một hạn chế: nếu thư mục **`~/Library/LaunchAgents`** đã tồn tại do phần mềm khác tạo ra, kỹ thuật sẽ thất bại. Vì vậy, một chuỗi Login Items khác đã được phát hiện.

Kẻ tấn công có thể tạo **`.bash_profile`** và **`.zshenv`** chứa payload, nén chúng lại rồi ghi file ZIP vào thư mục home của **nạn nhân** với tên **`~/~$escape.zip`**.

Sau đó thêm file ZIP và **Terminal** làm Login Items. Ở lần đăng nhập tiếp theo, Archive Utility giải nén các file ẩn vào thư mục home của người dùng, rồi shell của Terminal đánh giá file khởi động tương ứng (`.bash_profile` đối với đường khai thác Bash được trình diễn hoặc `.zshenv` đối với Zsh).<sup>[[3]](#references)</sup>

Xem [**báo cáo gốc tại đây**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass với Open và biến môi trường

Các tiến trình trong sandbox vẫn có thể yêu cầu khởi chạy ứng dụng thông qua **`open`**. Ứng dụng được khởi chạy chạy trong ngữ cảnh bảo mật riêng, thay vì kế thừa chính xác profile sandbox của Word.<sup>[[4]](#references)</sup>

Tiện ích `open` bị ảnh hưởng có tùy chọn **`--env`** để cung cấp biến môi trường. Exploit tạo `.zshenv` bên trong sandbox, đặt `HOME` trỏ đến thư mục đó rồi khởi chạy Terminal để Zsh đánh giá file này. Chuỗi khai thác được báo cáo cũng đặt biến riêng bị viết sai chính tả `__OSINSTALL_ENVIROMENT`; hãy giữ nguyên chính tả đó khi tái hiện PoC lịch sử.<sup>[[4]](#references)</sup>

Xem [**báo cáo gốc tại đây**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass với Open và stdin

Tiện ích **`open`** cũng hỗ trợ tham số **`--stdin`** (và sau bypass trước đó, không thể sử dụng `--env` nữa).

Mặc dù ứng dụng Python của Apple từ chối chạy file script bị quarantine, quy trình dễ bị tấn công có thể đưa cùng script vào qua standard input, tránh được bước kiểm tra quarantine dựa trên file:<sup>[[5]](#references)</sup>

1. Tạo file **`~$exploit.py`** chứa các lệnh Python tùy ý.
2. Chạy `open --stdin='~$exploit.py' -a Python`. Ứng dụng Python được khởi chạy nhận mã đã tạo qua standard input và, trên các phiên bản dễ bị tấn công, chạy bên ngoài sandbox của Word vì LaunchServices tạo tiến trình đó dưới `launchd`.<sup>[[5]](#references)</sup>

## References

- [1] [Thoát khỏi Sandbox – Microsoft Office trên macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Rắc rối với Office trên macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Thoát khỏi Sandbox của Office365 trên MacOS](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Phân tích kỹ thuật CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Phát hiện lỗ hổng thoát khỏi App Sandbox trên macOS: Phân tích chuyên sâu về CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
