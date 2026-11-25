# Thông tin mạng

{{#include ../../banners/hacktricks-training.md}}

Các dịch vụ lắng nghe cục bộ, Unix socket và phần mềm hướng mạng có thể để lộ những đường tấn công mà quá trình quét từ bên ngoài không phát hiện được. Hãy bắt đầu bằng cách kiểm tra các dịch vụ đang lắng nghe trên máy chủ và tiến trình sở hữu từng endpoint.

- [Thu thập lưu lượng, tường lửa và phân loại lưu lượng ra](traffic-capture-and-firewall-egress.md) đề cập đến việc thu thập gói tin, lọc, proxy và kiểm tra kết nối.
- [Phân loại mạng cục bộ và socket](local-network-and-socket-triage.md) đề cập đến các dịch vụ loopback, Unix socket và mạng container.
- [Socket command injection](socket-command-injection.md) đề cập đến các lệnh được chấp nhận qua những socket cục bộ bị lộ.
- Để tìm hiểu về các foothold trên thiết bị Cisco SD-WAN Manager, xem [vManage local privilege escalation](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md); ConfD CLI, REST API và các đường dẫn import do root sở hữu của thiết bị này khác với quy trình phân loại socket thông thường.
{{#include ../../banners/hacktricks-training.md}}
