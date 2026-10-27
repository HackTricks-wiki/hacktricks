# Macro trong Word

{{#include ../banners/hacktricks-training.md}}

## Mã rác

Macro có thể chứa **mã không thể thực thi hoặc không liên quan** nhằm làm chậm quá trình phân tích. Hãy xác định các điều kiện hằng và lần theo hành vi có thể thực thi trước khi tốn thời gian reverse một nhánh. Ví dụ bên dưới dùng điều kiện `If` không bao giờ đúng để che giấu mã rác.

![Macro Word chứa một nhánh điều kiện không thể thực thi với mã rác](<../images/image (369).png>)

## Biểu mẫu Macro

VBA UserForms có thể lưu dữ liệu trong các control như hộp văn bản. Vì biểu mẫu, khung và trang đều có thể cung cấp một collection `Controls`, người phân tích nên liệt kê toàn bộ hệ thống phân cấp control thay vì chỉ dựa vào những gì biểu mẫu hiển thị. Ví dụ bên dưới lưu dữ liệu bị che giấu trong các hộp văn bản chồng lên nhau.<sup>[[1]](#references)</sup>

Trong quá trình phân tích động, hàm `GetObject` của VBA có thể lấy một đối tượng Automation từ tệp hoặc kết nối với một Automation server đang chạy. Macro có thể dùng quyền truy cập đối tượng đó để lấy dữ liệu không dễ nhận thấy trong tài liệu đang hiển thị; hãy kiểm tra cả đối tượng được trả về lẫn cây control của UserForm.<sup>[[2]](#references)</sup>

![UserForm của macro có dữ liệu bị che giấu trong các hộp văn bản chồng lên nhau](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections, controls và objects (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - Hàm `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
