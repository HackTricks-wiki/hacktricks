# Mức độ toàn vẹn

{{#include ../../banners/hacktricks-training.md}}

## Mức độ toàn vẹn

Trong Windows Vista và các phiên bản mới hơn, các đối tượng có thể được bảo vệ có thể mang nhãn **mức độ toàn vẹn**. Hầu hết đối tượng được xem là có mức toàn vẹn trung bình, trong khi một số vị trí dành cho ứng dụng có mức toàn vẹn thấp có thể được gắn nhãn thấp. Các tiến trình do người dùng tiêu chuẩn khởi chạy thường chạy ở mức toàn vẹn trung bình, ứng dụng được nâng quyền chạy ở mức cao, và nhiều dịch vụ chạy ở mức hệ thống.<sup>[[1]](#references)</sup>

Một quy tắc quan trọng là tiến trình có mức toàn vẹn thấp hơn mức của đối tượng không thể sửa đổi đối tượng đó. Windows thực hiện bước kiểm tra Mandatory Integrity Control (MIC) này trước khi đánh giá danh sách kiểm soát truy cập tùy ý (DACL) của đối tượng. Các mức thường gặp gồm:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Mức thấp nhất, được biểu diễn bằng `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`). Không nên nhầm nhãn toàn vẹn này với danh tính **Anonymous Logon** (`S-1-5-7`); danh tính xác thực và nhãn MIC thuộc các không gian SID riêng biệt. Ví dụ thực tế, sandbox Windows của Chromium ban đầu gán mức toàn vẹn Low cho các tiến trình đích trong sandbox, sau đó hạ mức của các tiến trình đích renderer xuống Untrusted sau khi khởi động.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: Chủ yếu dùng cho các tương tác với internet, đặc biệt trong Protected Mode của Internet Explorer, ảnh hưởng đến các tệp và tiến trình liên quan cũng như một số thư mục như **Temporary Internet Folder**. Các tiến trình có mức toàn vẹn Low chịu nhiều hạn chế, bao gồm không có quyền ghi vào registry và quyền ghi hạn chế vào hồ sơ người dùng.
- **Medium**: Mức mặc định cho hầu hết hoạt động, được gán cho người dùng tiêu chuẩn và các đối tượng không có mức toàn vẹn cụ thể. Ngay cả thành viên của nhóm Administrators cũng hoạt động ở mức này theo mặc định.
- **High**: Dành cho quản trị viên, cho phép họ sửa đổi các đối tượng có mức toàn vẹn thấp hơn, bao gồm cả đối tượng ở chính mức High.
- **System**: Mức hoạt động cao nhất dành cho Windows kernel và các dịch vụ cốt lõi, nằm ngoài khả năng truy cập của cả quản trị viên, giúp bảo vệ các chức năng hệ thống thiết yếu.

Windows cũng định nghĩa một giá trị mức toàn vẹn cho tiến trình được bảo vệ, cao hơn System. Tuy nhiên, **TrustedInstaller** là danh tính dịch vụ Windows chứ không phải một mức MIC riêng; khả năng sửa đổi tài nguyên hệ điều hành được bảo vệ của danh tính này đến từ các quyền được cấp cho nó.

Không nên cho rằng một vị trí như thư mục gốc của ổ đĩa hệ thống luôn có nhãn mức toàn vẹn High cố định. Hãy kiểm tra DACL có hiệu lực và mọi nhãn bắt buộc được đặt rõ ràng bằng `icacls`; đối tượng không có nhãn sẽ được MIC xem là Medium, nhưng DACL và quyền sở hữu vẫn có thể hạn chế quyền truy cập một cách độc lập.<sup>[[1]](#references)[[4]](#references)</sup>

Bạn có thể xem mức toàn vẹn của một tiến trình bằng **Process Explorer** của **Sysinternals**: mở thuộc tính tiến trình rồi xem thẻ **Security**:<sup>[[3]](#references)</sup>

![Mức độ toàn vẹn - Mức độ toàn vẹn: Bạn có thể xem mức toàn vẹn của một tiến trình bằng Process Explorer của Sysinternals, bằng cách mở thuộc tính tiến trình và xem thẻ "...](<../../images/image (824).png>)

Bạn cũng có thể xem **mức toàn vẹn hiện tại** bằng `whoami /groups`:

![Mức độ toàn vẹn - Mức độ toàn vẹn: Bạn cũng có thể xem mức toàn vẹn hiện tại bằng whoami /groups](<../../images/image (325).png>)

### Mức độ toàn vẹn trong hệ thống tệp

Một đối tượng trong hệ thống tệp có thể có **yêu cầu mức toàn vẹn tối thiểu**. Tiến trình thấp hơn mức đó sẽ chịu chính sách bắt buộc của đối tượng, ngay cả khi DACL của đối tượng thông thường cho phép truy cập. Ví dụ: tạo một tệp thông thường từ console của người dùng tiêu chuẩn rồi kiểm tra quyền của tệp:<sup>[[1]](#references)[[4]](#references)</sup>

```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
        DESKTOP-IDJHTKP\user:(I)(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        NT AUTHORITY\INTERACTIVE:(I)(M,DC)
        NT AUTHORITY\SERVICE:(I)(M,DC)
        NT AUTHORITY\BATCH:(I)(M,DC)
```

Bây giờ, hãy gán mức integrity tối thiểu là **High** cho tệp. Việc này **phải được thực hiện từ console** chạy với quyền **administrator**, vì console thông thường chạy ở mức integrity Medium và **không được phép** gán mức integrity High cho một đối tượng:

```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
        DESKTOP-IDJHTKP\user:(I)(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        NT AUTHORITY\INTERACTIVE:(I)(M,DC)
        NT AUTHORITY\SERVICE:(I)(M,DC)
        NT AUTHORITY\BATCH:(I)(M,DC)
        Mandatory Label\High Mandatory Level:(NW)
```

Người dùng `DESKTOP-IDJHTKP\user` có **TOÀN QUYỀN** đối với tệp vì người dùng đó đã tạo tệp. Tuy nhiên, mandatory label ngăn người dùng sửa đổi tệp trừ khi tiến trình đang chạy ở mức High integrity. Người dùng vẫn có thể đọc tệp vì mandatory policy được hiển thị là `(NW)`, tức no-write-up:

```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```

> [!TIP]
> **Do đó, khi một tệp có mức toàn vẹn tối thiểu, bạn cần chạy ở mức toàn vẹn đó trở lên để sửa đổi tệp.**

### Mức toàn vẹn trong các tệp nhị phân

Ví dụ sau sử dụng một bản sao của `cmd.exe` tại `C:\Windows\System32\cmd-low.exe` và gán cho nó **mức toàn vẹn Thấp từ một cửa sổ dòng lệnh quản trị viên**:

```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
                                BUILTIN\Administrators:(I)(F)
                                BUILTIN\Users:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
                                Mandatory Label\Low Mandatory Level:(NW)
```

Bây giờ, khi chạy `cmd-low.exe`, nó sẽ **chạy ở mức toàn vẹn thấp** thay vì mức trung bình:

![Mức toàn vẹn trong hệ thống tệp - Mức toàn vẹn trong tệp nhị phân: Bây giờ, khi chạy cmd-low.exe, nó sẽ chạy ở mức toàn vẹn thấp thay vì mức trung bình](<../../images/image (313).png>)

Gán nhãn toàn vẹn Cao cho một tệp nhị phân (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) không khiến nó tự động chạy ở mức toàn vẹn Cao. Nếu được gọi từ một tiến trình có mức toàn vẹn Trung bình, nó sẽ chạy ở mức toàn vẹn Trung bình vì tiến trình mới nhận mức toàn vẹn thấp hơn giữa tệp thực thi và tiến trình gọi nó.<sup>[[1]](#references)</sup>

### Mức toàn vẹn trong tiến trình

Không phải mọi tệp và thư mục đều có nhãn toàn vẹn tối thiểu rõ ràng, **nhưng mọi tiến trình đều chạy ở một mức toàn vẹn**. Tương tự như các đối tượng hệ thống tệp, **một tiến trình muốn có quyền ghi vào tiến trình khác phải có mức toàn vẹn ít nhất bằng mức của tiến trình đó**. Vì vậy, tiến trình có mức toàn vẹn Thấp không thể mở tiến trình có mức toàn vẹn Trung bình với toàn quyền truy cập.<sup>[[1]](#references)</sup>

Do những hạn chế này, cách an toàn nhất là **chạy mỗi tiến trình ở mức toàn vẹn thấp nhất mà vẫn cho phép nó thực hiện công việc dự định**.

## References

- [1] [Microsoft Learn – Kiểm soát toàn vẹn bắt buộc](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Kiểu liệt kê MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Mã nguồn Chromium – Chính sách toàn vẹn mặc định của sandbox Windows](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – SID nổi tiếng](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
