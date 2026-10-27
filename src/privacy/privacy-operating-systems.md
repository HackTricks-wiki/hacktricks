# Hệ điều hành bảo vệ quyền riêng tư

{{#include ../banners/hacktricks-training.md}}

Các hệ điều hành tập trung vào quyền riêng tư giúp giảm lỗi định tuyến và lưu giữ dữ liệu, nhưng không hệ điều hành nào có thể bù đắp cho hành vi có thể nhận dạng hoặc phần cứng bị xâm phạm.

## Chọn mô hình cô lập

| Hệ thống | Phù hợp nhất với | Lưu giữ dữ liệu | Cơ chế cưỡng chế mạng | Đánh đổi chính |
|---|---|---|---|---|
| **Tor Browser trên một hệ điều hành được bảo trì** | Duyệt web ẩn danh không thường xuyên | Trạng thái trình duyệt thường chỉ tồn tại trong phiên | Chỉ lưu lượng của trình duyệt | Các ứng dụng khác và máy chủ vẫn nằm ngoài Tor |
| **Tails** | Các phiên di động, không lưu dấu, chỉ dùng cho một mục đích | Persistent Storage được mã hóa, tùy chọn | Lưu lượng Internet được buộc đi qua Tor | Khởi động lại/gây bất tiện cho quy trình; cần tin cậy firmware/phần cứng |
| **Whonix** | Các ứng dụng cần định tuyến bắt buộc qua Tor và lưu trạng thái | VM lưu trạng thái | Tách Gateway/Workstation | Máy chủ/hypervisor và việc trộn lẫn danh tính vẫn là rủi ro |
| **Qubes-Whonix** | Phân vùng mạnh cho người dùng nâng cao | Theo từng qube | Các network qube riêng và Whonix | Yêu cầu phần cứng và độ phức tạp khi vận hành |

## Tails

Tails khởi động độc lập từ phương tiện di động, định tuyến lưu lượng Internet qua Tor và được thiết kế để lưu lại rất ít trạng thái cục bộ. Các cảnh báo của Tails nhấn mạnh rằng hệ điều hành này không thể bảo vệ bạn khỏi BIOS/firmware/phần cứng bị xâm phạm, việc tiết lộ thông tin nhận dạng, metadata của tệp hoặc một đối thủ mạnh có thể đối chiếu lưu lượng ở cả hai đầu.<sup>[[1]](#references)</sup>

### Quy trình Tails chỉ dùng cho một mục đích

1. Tải Tails từ trang chính thức trên một máy tính đáng tin cậy, đã cập nhật và làm theo quy trình xác minh/cài đặt chính thức.
2. Chỉ dùng USB được hỗ trợ để khởi động Tails; không dùng USB đó làm ổ chuyển tệp thông thường.
3. Khởi động trên phần cứng do bạn trực tiếp kiểm soát. Hệ điều hành live không thể vô hiệu hóa keylogger phần cứng hoặc firmware độc hại.
4. Tắt Persistent Storage, trừ khi quy trình thực sự cần đến. Nếu bật, chỉ lưu lại các mục cần thiết và dùng mật khẩu mạnh.
5. Kết nối với mạng hợp pháp. Nếu không thể tránh captive portal, chỉ dùng Unsafe Browser của Tails cho portal, không tiết lộ thông tin nhận dạng không cần thiết, đóng trình duyệt ngay sau đó và kết nối Tor trước mọi hoạt động nhạy cảm.<sup>[[2]](#references)</sup>
6. Cấu hình Tor bridge nếu cần tránh bị phát hiện đang dùng Tor trực tiếp hoặc cần vượt chặn.
7. Thực hiện **một danh tính/mục đích theo ngữ cảnh cho mỗi phiên**. Tails khuyến nghị khởi động lại giữa các hoạt động không nên liên kết với nhau.<sup>[[1]](#references)</sup>
8. Kiểm tra và làm sạch tệp trước khi công bố. Không mở tài liệu chủ động đã tải xuống bằng ứng dụng có thể vượt qua ngữ cảnh dự kiến.
9. Tắt máy hoàn toàn khi xong và bảo vệ USB về mặt vật lý.

## Whonix

Whonix tách **Gateway** định tuyến Tor khỏi **Workstation**, nơi các ứng dụng không thể trực tiếp biết IP bên ngoài. Điều này giúp giảm đáng kể lỗi proxy/DNS, nhưng máy chủ, hypervisor, hành vi và tài liệu vẫn có thể tiết lộ danh tính. Whonix cảnh báo rõ rằng không nên dùng một workstation cho nhiều danh tính hoặc kết hợp hoạt động ẩn danh với hoạt động không ẩn danh.<sup>[[3]](#references)</sup>

### Quy trình phân vùng

1. Xác minh image Whonix và nền tảng ảo hóa từ các nguồn chính thức.
2. Cập nhật máy chủ, hypervisor, Gateway và Workstation trước khi sử dụng.
3. Tạo bản sao Workstation mới cho mỗi danh tính hoặc hoạt động; không bao giờ sao chép VM sau khi đã đưa trạng thái chứa thông tin nhận dạng vào đó.
4. Không đưa tài khoản cá nhân, thư mục chia sẻ trên máy chủ, đồng bộ clipboard, thiết bị USB và dữ liệu thời gian/vị trí vào Workstation.
5. Dùng snapshot để khôi phục, không thay thế cho sao lưu hoặc phân tách danh tính.
6. Xác nhận Workstation không thể truy cập Internet khi Gateway đã dừng.
7. Với các tệp đặc biệt rủi ro, dùng VM/qube dùng một lần và chỉ xuất kết quả đã được làm sạch.

## Qubes OS và Qubes-Whonix

Qubes triển khai bảo mật bằng cách phân vùng qua các qube chạy trên Xen. Thiết kế này hạn chế việc một miền bị xâm phạm tự động ảnh hưởng đến các miền khác, nhưng các ứng dụng bên trong **cùng một** qube không được cô lập khỏi nhau.<sup>[[4]](#references)</sup> Disposable qube cung cấp trạng thái mới cho các trang web, tệp và thiết bị không đáng tin cậy.<sup>[[5]](#references)</sup>

Bố cục thực tế:

```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```

Quy tắc:

- Gán cho mỗi qube một mức độ tin cậy và một mục đích nhận dạng.
- Lưu bí mật trong một qube vault ngoại tuyến và dùng thao tác sao chép/tệp liên qube có chủ đích.
- Mở tệp và liên kết không mong muốn trong disposable.
- Chỉ định tuyến các qube cần thiết qua Whonix hoặc một qube VPN chuyên dụng.
- Gắn nhãn cửa sổ rõ ràng và dừng các qube không liên quan khi xử lý công việc nhạy cảm.
- Đừng cho rằng hai qube sẽ ngăn được việc tương quan nếu chúng dùng chung tài khoản, nội dung, lịch trình hoặc phương thức thanh toán.

## Xác minh và bảo trì

- Xác minh chữ ký/checksum của trình cài đặt theo hướng dẫn chính thức.
- Cập nhật template trước, sau đó khởi động lại các qube/VM phụ thuộc.
- Xác nhận hành vi chặn mạng, DNS, IPv6, đồng hồ, clipboard, thư mục dùng chung và gán USB.
- Rà soát Persistent Storage và snapshot VM để tìm dữ liệu cũ có thể tiết lộ danh tính.
- Lưu bản sao lưu seed/key đã mã hóa ở chế độ ngoại tuyến và thử khôi phục trong môi trường cô lập.
- Dựng lại một compartment nếu nghi ngờ bị xâm phạm; đổi IP egress là chưa đủ.

## References

- [1] [Tails — Cảnh báo: Tails an toàn nhưng không phải phép màu](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Đăng nhập vào mạng qua captive portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Giới hạn của Whonix và Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Mục tiêu thiết kế bảo mật](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Cách dùng disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
