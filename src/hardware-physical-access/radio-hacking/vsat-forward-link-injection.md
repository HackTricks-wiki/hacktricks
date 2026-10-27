# Chèn tín hiệu đường xuống VSAT

{{#include ../../banners/hacktricks-training.md}}

Thiết bị đầu cuối VSAT thường xem đường xuống vệ tinh là lưu lượng đến từ trạm trung tâm của nhà khai thác. Trong hệ thống DVB-RCS, đường truyền hướng xuống này có thể mang cả gói IP của người dùng lẫn thông điệp điều khiển modem. Nếu bộ thu xử lý thông điệp mà không xác thực trước, tín hiệu được chèn tại chỗ có thể vượt qua ranh giới tin cậy giữa vô tuyến và mặt phẳng điều khiển. Đây là **chèn tín hiệu đường xuống tại thiết bị đầu cuối**, không phải truyền lên vệ tinh hay nghe lén thụ động đường xuống. Kết quả đạt được phụ thuộc vào cách triển khai giao thức và cơ chế xác thực thông điệp của modem, chứ không chỉ riêng DVB-RCS.<sup>[[1]](#references)[[2]](#references)</sup>

## Kiểm thử trong phòng lab có cách ly RF

Sử dụng thiết bị đầu cuối do bạn sở hữu, firmware của thiết bị và SDR kết nối với đầu vào thu của modem qua bộ suy hao phù hợp, hoặc dùng thiết lập RF được che chắn. Không phát sóng trên kênh vệ tinh đang hoạt động. Trước tiên, ghi lại sóng mang khởi động, tốc độ ký hiệu và ID nhóm người dùng đã cấu hình trên thiết bị đầu cuối; các thông tin này giúp thu nhận đường truyền hướng xuống.<sup>[[1]](#references)[[3]](#references)</sup> Chuỗi thu nhận DVB-RCS dùng Network Information Table (NIT) để tìm RCS Map Table (RMT), sau đó dùng Program Association Table (PAT) và Program Map Table (PMT) để xác định các luồng báo hiệu của đường truyền hướng xuống. Thiết bị đầu cuối có thể dò qua nhiều sóng mang của luồng truyền tải trước khi đến luồng dữ liệu.<sup>[[3]](#references)</sup>

1. Giải mã hoặc dựng lại luồng truyền tải khởi động của mục tiêu, rồi kiểm tra NIT, RMT, ID dịch vụ, packet ID (PID) và cách xử lý tham chiếu đồng hồ. Đối chiếu tiêu chuẩn với parser và log của mục tiêu; thứ tự hoặc descriptor riêng của nhà cung cấp có thể khiến luồng hợp lệ theo tiêu chuẩn không được chấp nhận.
2. Trong bộ phát của phòng lab, đóng gói một gói UDP thăm dò vô hại theo chuỗi `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q`, rồi đưa qua đầu ra SDR đến đường thu đã cách ly. Giữ Program Clock Reference (PCR) của luồng truyền tải nhất quán với tốc độ byte, nếu không modem có thể mất đồng bộ trước khi xử lý gói thăm dò.
3. Xác nhận cả **khóa bộ giải điều chế** lẫn việc nhận được gói thăm dò tại một điểm cuối nội bộ do bạn sở hữu. Chỉ khóa thôi mới chứng minh được lớp vật lý đã chấp nhận dạng sóng. Sau đó, kiểm tra xem có lộ *báo hiệu* quản lý hoặc cập nhật chưa được xác thực hay không, mà không cài đặt image hoặc thay đổi cấu hình dịch vụ.

Trường hợp MDM2200 được công bố sử dụng một mô-đun nguồn GNU Radio cho DVB-RCS/MPE/MPEG-TS và `gr-dtv` để điều chế DVB-S2. Modem này cần các chi tiết khởi tạo riêng theo mục tiêu: SDT trước PAT/PMT, RCS content descriptor có table ID `0x3E`, và byte riêng của RMT là `0x01` cho chế độ GSE/4CPM. Không nên cho rằng các giá trị này sẽ hoạt động trên thiết bị đầu cuối khác.<sup>[[1]](#references)</sup> Các nhà nghiên cứu cũng quan sát thấy các gói MPE multicast đến được những modem đang thu trong thiết lập của họ, nên việc nhắm mục tiêu không chỉ giới hạn ở địa chỉ MAC unicast đã biết.<sup>[[1]](#references)</sup> Một phân tích riêng phát hiện báo hiệu điều khiển và cập nhật phần mềm không được bảo vệ trên hệ thống được nghiên cứu, nhưng cần xác minh phát hiện này trên từng cách triển khai.<sup>[[2]](#references)</sup>

Đường hầm IPsec hoặc VPN dành cho lưu lượng người dùng không xác thực báo hiệu DVB-RCS đi trước hoặc parser cập nhật của chính modem. Trong một đánh giá được ủy quyền, hãy phân biệt cơ chế bảo vệ mật mã đối với lưu lượng **IP của người dùng**, **điều khiển đường truyền hướng xuống** và lưu lượng **bảo trì/khôi phục**, thay vì xem đường hầm người dùng an toàn là bằng chứng cho thấy việc chèn tín hiệu vô tuyến đã bị chặn.<sup>[[1]](#references)[[2]](#references)</sup>

Để kiểm tra I/Q ban đầu, xem [phân tích tín hiệu vô tuyến](../hardware-hacking/radio.md). Để kiểm tra firmware và parser trên bo mạch, xem [phân tích firmware](../firmware-analysis/). Quay lại [tổng quan Radio Hacking](./) để xem các giao diện khác.

## References

- [1] [Bisping et al. - Các cuộc tấn công chèn tín hiệu không dây vào modem vệ tinh VSAT (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: Phát hiện các vấn đề bảo mật vốn có trong thực tiễn sử dụng hệ thống VSAT hiện nay (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - Kênh tương tác DVB cho các hệ thống phân phối vệ tinh](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
