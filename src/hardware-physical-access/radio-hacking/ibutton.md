# iButton

{{#include ../../banners/hacktricks-training.md}}

## Giới thiệu

iButton là tên gọi chung cho một khóa nhận dạng điện tử được đóng gói trong **vỏ kim loại hình đồng xu**. Thiết bị này còn được gọi là bộ nhớ Dallas Touch hoặc bộ nhớ tiếp xúc. Dù thường bị gọi nhầm là khóa “từ tính”, nhưng bên trong **không có gì mang tính từ tính**. Thực tế, bên trong có một **vi mạch** hoàn chỉnh hoạt động theo giao thức kỹ thuật số.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton là gì? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Tên gọi iButton mô tả lớp vỏ bền hình đồng xu và cách bố trí các điểm tiếp xúc. Các loại giá đỡ gồm móc khóa nhựa, nhẫn và mặt dây chuyền.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Khi cả hai điểm tiếp xúc chạm vào đầu đọc, thiết bị được cấp nguồn và trao đổi dữ liệu. Nếu hình dạng lõm của các điểm tiếp xúc khiến các điểm tiếp xúc mass bên ngoài không chạm được vào đầu đọc, hãy nghiêng khóa dựa vào thành đầu đọc để khôi phục kết nối.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Giao thức 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Các khóa Dallas/Maxim sử dụng giao thức 1-Wire: một điểm tiếp xúc dữ liệu truyền nhận hai chiều và cũng có thể cấp nguồn ký sinh, trong khi vỏ kim loại đóng vai trò là điểm tiếp xúc hồi dòng. Bộ điều khiển khởi tạo các giao dịch và thiết bị phản hồi.<sup>[[2]](#references)</sup>

Khi khóa (Slave) tiếp xúc với intercom (Master), chip bên trong khóa bật lên nhờ nguồn điện từ intercom và khóa được khởi tạo. Sau đó, intercom yêu cầu ID của khóa. Tiếp theo, chúng ta sẽ tìm hiểu quy trình này chi tiết hơn.

Flipper có thể hoạt động như bộ điều khiển khi đọc khóa và như thiết bị giả lập khi gửi một mã định danh đã lưu đến đầu đọc.<sup>[[1]](#references)</sup>

### Khóa Dallas, Cyfral và Metakom

Để biết cách hoạt động của các khóa này, hãy xem trang [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Tấn công

Có thể tấn công iButton bằng Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Chế ngự iButton bằng Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Giao tiếp 1-Wire bằng phần mềm](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
