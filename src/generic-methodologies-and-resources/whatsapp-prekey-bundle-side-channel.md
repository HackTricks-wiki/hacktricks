# Kênh bên về việc làm cạn và bổ sung gói prekey WhatsApp

{{#include ../banners/hacktricks-training.md}}

WhatsApp lưu trữ khóa danh tính, prekey đã ký và một bộ prekey dùng một lần dự trữ cho mỗi thiết bị. Việc truy xuất bundle của một thiết bị sẽ tiêu thụ một prekey dùng một lần được lưu trên máy chủ, ngay cả khi bên yêu cầu không gửi tin nhắn nào. Điều này cho phép kẻ tấn công có tài khoản WhatsApp và số điện thoại của mục tiêu thực hiện một phép thăm dò **phía máy chủ**, khác với [thời gian nhận biên nhận giao tin ở phía client](side-channel-attacks-on-messaging-protocols.md). Việc thiếu một prekey dùng một lần cũng làm suy yếu tính bí mật chuyển tiếp của các tin nhắn *đầu tiên* trong một phiên mới được thiết lập; bản thân điều này không làm lộ văn bản thuần.<sup>[[1]](#references)[[2]](#references)</sup>

## Kiểm tra bundle thiết bị của mục tiêu

[Prekey Pogo artifact](https://github.com/sbaresearch/prekey-pogo) ghép nối dưới dạng một phiên đồng hành WhatsApp và hỗ trợ truy vấn thiết bị cũng như prekey **thủ công**. Ghép nối công cụ này với một tài khoản thử nghiệm, rồi dùng các lệnh tương tác `target`, `devices`, `prekey` (thiết bị chính) và `combine` (tất cả thiết bị). Artifact được phát hành cố ý không có chức năng làm cạn prekey tự động và gây nghẽn máy chủ.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Với mỗi phản hồi, ghi lại JID của thiết bị, timestamp của bundle `t`, ID của signed-prekey `skey.id` và liệu `key.id` dùng một lần có xuất hiện hay không. Device ID `0` là điện thoại; các ID khác `0` là thiết bị đồng hành. Trong các triển khai được kiểm thử trong bài báo, ID của signed-prekey ban đầu cũng giúp phân biệt một số client: Android bắt đầu từ `0`, iOS và macOS dùng giá trị ngẫu nhiên, còn WhatsApp Web và Windows Desktop bắt đầu từ `1`. Hãy xem đây là dấu vân tay của triển khai, không phải quy tắc giao thức bất biến.<sup>[[1]](#references)</sup>

## Biến việc nạp lại key thành một oracle trạng thái online

Trước tiên, hãy hiệu chuẩn trên thiết bị bạn kiểm soát: liên tục yêu cầu bundle của thiết bị đó cho đến khi server ngừng trả về `key` dùng một lần, đồng thời ghi lại timestamp và các ID key cuối cùng. Với thiết bị mục tiêu, lặp lại quá trình làm cạn key rồi truy vấn lại sau một khoảng thời gian có kiểm soát: key dùng một lần mới và timestamp bundle tăng cho thấy thiết bị đã tải lên một lô mới. Trong các thử nghiệm WhatsApp được báo cáo, server yêu cầu nạp lại khi còn dưới 11 key và client tải lên 812 key mới. Thực hiện quy trình riêng cho từng JID thiết bị để phân biệt điện thoại với thiết bị đồng hành. Việc nạp lại bị trì hoãn chỉ **gợi ý** rằng thiết bị đang offline: lịch chạy nền, mất mạng và độ trễ nạp lại riêng của client cũng có thể tạo ra quan sát tương tự. Không như RTT của receipt, phép thăm dò này không cần ciphertext được gửi đi hoặc xác nhận từ phía nạn nhân.<sup>[[1]](#references)[[2]](#references)</sup>

Mỗi truy vấn tiêu thụ một key dùng một lần, vì vậy để duy trì oracle cần một client tùy chỉnh có khả năng truy xuất prekey lặp lại; artifact công khai chỉ minh họa các truy vấn thủ công. Việc giữ cho số key dự trữ luôn bằng không có thể khiến những người dùng khác thiết lập session mới mà không có prekey dùng một lần. Điều đó làm giảm forward secrecy của các tin nhắn ban đầu cho đến khi có bước ratchet mới, nhưng để khai thác ciphertext đã ghi lại còn cần truy cập ciphertext E2EE và sau đó chiếm được các private key dài hạn và trung hạn liên quan. Các session đã thiết lập không tự động bị hạ cấp.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: Điều tra các vấn đề về bảo mật và quyền riêng tư trong cơ chế bắt tay của WhatsApp](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [Giao thức thỏa thuận khóa X3DH](https://signal.org/docs/specifications/x3dh/)
- [3] [Artifact Prekey Pogo](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
