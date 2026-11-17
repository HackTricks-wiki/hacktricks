# Phân tích file Office

{{#include ../../../banners/hacktricks-training.md}}

Để biết thêm thông tin, hãy xem [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Đây chỉ là bản tóm tắt:<sup>[[2]](#references)</sup>

Tài liệu Microsoft Office thường xuất hiện dưới các định dạng cũ như RTF và DOC, XLS, PPT dựa trên OLE/CFBF, hoặc các định dạng **Office Open XML (OOXML)** mới hơn như DOCX, XLSX và PPTX. Tài liệu Office có thể chứa nội dung chủ động như macro, khiến chúng thường được dùng để phát tán phishing và malware. File OOXML là các container ZIP; có thể kiểm tra cấu trúc thư mục và nội dung XML bằng cách giải nén chúng.<sup>[[1]](#references)[[2]](#references)</sup>

Để khám phá cấu trúc file OOXML, phần này cung cấp lệnh giải nén tài liệu cùng cấu trúc đầu ra. Các kỹ thuật ẩn dữ liệu trong những file này đã được ghi nhận, cho thấy các phương pháp che giấu dữ liệu trong thử thách CTF không ngừng được đổi mới.<sup>[[2]](#references)</sup>

Để phân tích, **oletools** và **OfficeDissector** cung cấp bộ công cụ toàn diện để kiểm tra cả tài liệu OLE lẫn OOXML. Những công cụ này giúp xác định và phân tích các macro được nhúng, vốn thường là phương tiện phát tán malware bằng cách tải xuống và thực thi thêm các payload độc hại. Có thể phân tích macro VBA mà không cần Microsoft Office bằng Libre Office, cho phép debugging với breakpoint và các biến theo dõi.<sup>[[2]](#references)</sup>

Cài đặt và sử dụng **oletools** khá đơn giản; các lệnh cài đặt bằng pip và trích xuất macro từ tài liệu được cung cấp. Trong Word, các macro tự động bao gồm `AutoExec` và `AutoOpen`, còn `Document_Open` là một thủ tục sự kiện mở tài liệu.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Phân tích macro VBA: mã rác và UserForms

## Mã rác

Macro có thể chứa **mã không thể thực thi hoặc không liên quan** nhằm làm chậm quá trình phân tích. Hãy xác định các điều kiện hằng và lần theo hành vi có thể thực thi trước khi dành thời gian đảo ngược một nhánh. Ví dụ bên dưới sử dụng điều kiện `If` không bao giờ đúng để che giấu mã rác.

![Macro Word có nhánh điều kiện không thể thực thi chứa mã rác](<../../../images/image (369).png>)

## Biểu mẫu Macro

UserForms của VBA có thể lưu trữ dữ liệu trong các điều khiển như hộp văn bản. Vì biểu mẫu, khung và trang đều có thể cung cấp một tập hợp `Controls`, chuyên viên phân tích nên liệt kê toàn bộ cấu trúc phân cấp của các điều khiển thay vì chỉ dựa vào những gì biểu mẫu hiển thị. Ví dụ bên dưới lưu trữ dữ liệu bị che giấu trong các hộp văn bản chồng lấp nhau.<sup>[[6]](#references)</sup>

Trong quá trình phân tích động, hàm `GetObject` của VBA có thể lấy một đối tượng Automation từ tệp hoặc kết nối với một máy chủ Automation đang chạy. Macro có thể dùng quyền truy cập đối tượng đó để lấy dữ liệu không dễ nhận thấy trong tài liệu đang hiển thị; hãy kiểm tra cả đối tượng được trả về lẫn cây điều khiển của UserForm.<sup>[[7]](#references)</sup>

![UserForm của macro có dữ liệu bị che giấu trong các hộp văn bản chồng lấp nhau](<../../../images/image (344).png>)

Để biết cách xử lý tài liệu Office được mã hóa bằng mật khẩu, xem [quy trình khôi phục ngoại tuyến dựa trên ngữ pháp](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Đối với các tệp Revit RFA sử dụng OLE/CFBF, xem [tính toán lại ECC, gzip có kiểm soát và khai thác deserializer](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); quy trình khai thác parser này tách biệt với việc phân loại ban đầu tài liệu Office.

## References

- [1] [Tài liệu về OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Cẩm nang thực địa Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [3] [Tài liệu olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Sự kiện Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Tập hợp, điều khiển và đối tượng (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - Hàm `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
