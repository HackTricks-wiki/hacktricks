# Tăng cường bảo mật Linux

{{#include ../banners/hacktricks-training.md}}

Sử dụng phần này để khảo sát các máy chủ Linux, tìm hiểu ranh giới đặc quyền và xem xét các biện pháp kiểm soát giới hạn quyền truy cập cục bộ. Bắt đầu với [kiến thức cơ bản về Linux](linux-basics/README.md) và [danh sách kiểm tra leo thang đặc quyền](main-system-information/linux-privilege-escalation-checklist.md) để đánh giá tổng quát, sau đó xem chủ đề phù hợp bên dưới.

- [Kiến thức cơ bản về Linux](linux-basics/README.md): phương pháp leo thang đặc quyền, các lệnh hữu ích, biến môi trường và cách vượt qua các giới hạn.
- [Thông tin hệ thống chính](main-system-information/README.md): kernel, module, sudo, hành vi hệ thống tệp, jail và danh sách kiểm tra leo thang đặc quyền.
- [Thông tin người dùng](user-information/README.md): danh tính Linux, nhóm, chuyển tiếp SSH agent và tích hợp Active Directory.
- [Các tệp và quyền đáng chú ý](interesting-files-permissions/README.md): đường dẫn có thể ghi, capabilities, hành vi SUID, NFS, mở rộng wildcard và SELinux.
- [Thông tin mạng](network-information/README.md): dịch vụ cục bộ, socket và các ví dụ khai thác liên quan đến mạng.
- [Thông tin phần mềm](software-information/README.md): module xác thực và bề mặt tấn công dành riêng cho ứng dụng.
- [Tiến trình, crontab, systemd và D-Bus](processes-crontab-systemd-dbus/README.md): thực thi theo lịch và giao tiếp giữa các tiến trình.
- [Container và namespace](containers-namespaces/README.md): runtime, ranh giới cô lập và tăng cường bảo mật container.
- [Hậu khai thác](post-exploitation/README.md): tìm kiếm thông tin xác thực, duy trì quyền truy cập và các kỹ thuật tiếp theo ở cấp máy chủ.
{{#include ../banners/hacktricks-training.md}}
