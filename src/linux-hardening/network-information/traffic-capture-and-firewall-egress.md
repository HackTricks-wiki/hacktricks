# Phân loại lưu lượng bắt được, firewall và egress

{{#include ../../banners/hacktricks-training.md}}

Sau khi xác định [các tiến trình lắng nghe cục bộ và Unix socket](local-network-and-socket-triage.md), hãy kiểm tra các interface nào truyền lưu lượng của chúng và những quy tắc firewall hoặc proxy nào ảnh hưởng đến khả năng truy cập. Một dịch vụ chỉ lắng nghe trên loopback vẫn có thể mang các HTTP header nhạy cảm, ngay cả khi máy chủ khác không thể truy cập dịch vụ đó.

## Kiểm tra quyền bắt gói và chọn interface

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` có thể có khả năng bắt gói tin ngay cả khi người dùng hiện tại không có quyền sudo. Kiểm tra các capability thực tế và quyền nhóm của tệp thực thi. Chỉ bắt trên giao diện, trong khoảng thời gian và với bộ lọc cần thiết tối thiểu; dữ liệu bắt được có thể chứa thông tin xác thực hoặc dữ liệu cá nhân.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` tái dựng các luồng TCP dạng văn bản thuần; `tshark` có thể lọc và trích xuất các trường từ bản capture. Với lưu lượng TLS, cần có khóa của endpoint hoặc một client được hỗ trợ cấu hình `SSLKEYLOGFILE` trước khi kết nối để giải mã. [Trang phân loại sự cố mạng cục bộ](local-network-and-socket-triage.md#tls-key-logging) trình bày quy trình đó. Không xem bản capture đã mã hóa là văn bản thuần có thể đọc được.

Các artifact sự cố được lưu trữ có thể làm thay đổi đánh giá này. [Linux core dump là ảnh chụp bộ nhớ của tiến trình](https://man7.org/linux/man-pages/man5/core.5.html), trong đó có thể còn lưu khóa phiên; nếu bản dump có thể đọc được và bản capture gói tin đến từ cùng tiến trình và phiên, chuyên viên phân tích có thể giải mã lưu lượng đó. Trước tiên, hãy kiểm kê đường dẫn và quyền của artifact, sau đó xác minh riêng danh tính tiến trình, thời điểm capture, giao thức và định dạng khóa. Lưu lượng đã giải mã hoặc archive được khôi phục là manh mối về việc lộ dữ liệu, không phải bằng chứng cho thấy tài khoản khác đã truy cập: mọi phần vật liệu khóa SSH thu được vẫn cần được tái tạo, đối chiếu với khóa công khai tương ứng và được chính sách SSH của tài khoản đó chấp nhận. Tránh đưa nội dung core dump hoặc payload capture vào đầu ra liệt kê diện rộng.

## Xác định các lớp firewall

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` và `iptables` có thể được cung cấp thông qua các wrapper của bản phân phối như UFW hoặc firewalld. Đọc các quy tắc đang hoạt động và cấu hình đã lưu của wrapper; quy tắc hiển thị ở một dạng có thể do công cụ khác tạo ra. Kiểm tra giao diện mạng, hướng, nguồn, đích, giao thức, cổng và trạng thái kết nối trước khi quy kết dịch vụ bị chặn cho một quy tắc cụ thể. Xem [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) để biết ví dụ tập trung.

## Kiểm tra egress và hành vi của proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Phân biệt lỗi DNS với lỗi TCP, TLS hoặc proxy. Kiểm tra đích và giao thức cụ thể liên quan đến bài đánh giá; khả năng kết nối qua ICMP không có nghĩa là TCP hoặc UDP được cho phép. Nếu đã cấu hình proxy, hãy so sánh yêu cầu được gửi qua proxy dự kiến với yêu cầu đến cùng đích theo các quy tắc `no_proxy` áp dụng. Chuyển tiếp cổng cục bộ cũng có thể khiến một dịch vụ loopback khả dụng ở nơi khác, vì vậy hãy kiểm tra các listener đang hoạt động và SSH tunnel khi thông tin từ firewall không khớp với mức độ lộ diện quan sát được.
{{#include ../../banners/hacktricks-training.md}}
