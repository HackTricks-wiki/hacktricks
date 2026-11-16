# Tăng cường bảo mật Linux

{{#include ../banners/hacktricks-training.md}}

Sử dụng phần này để điều tra các máy chủ Linux, tìm hiểu ranh giới đặc quyền và xem xét các biện pháp kiểm soát giới hạn quyền truy cập cục bộ. Bắt đầu với [kiến thức cơ bản về Linux](linux-basics/README.md) và [danh sách kiểm tra privilege escalation](main-system-information/linux-privilege-escalation-checklist.md) để đánh giá tổng quát, sau đó xem chủ đề liên quan bên dưới.

- [Kiến thức cơ bản về Linux](linux-basics/README.md): phương pháp privilege escalation, các lệnh hữu ích, biến môi trường và cách bypass các hạn chế.
- [Thông tin hệ thống chính](main-system-information/README.md): kernel, module, sudo, hành vi của filesystem, jail và danh sách kiểm tra privilege escalation.
- [Thông tin người dùng](user-information/README.md): danh tính Linux, nhóm, chuyển tiếp SSH agent và tích hợp Active Directory.
- [Các tệp và quyền đáng chú ý](interesting-files-permissions/README.md): đường dẫn có thể ghi, capability, hành vi SUID, NFS, mở rộng wildcard và SELinux.
- [Thông tin mạng](network-information/README.md): dịch vụ cục bộ, socket và các ví dụ khai thác liên quan đến mạng.
- [Thông tin phần mềm](software-information/README.md): module xác thực và các bề mặt tấn công dành riêng cho ứng dụng.
- [Process, crontab, systemd và D-Bus](processes-crontab-systemd-dbus/README.md): thực thi theo lịch và giao tiếp liên tiến trình.
- [Container và namespace](containers-namespaces/README.md): runtime, ranh giới cô lập và tăng cường bảo mật container.
- [Lạm dụng tệp điều khiển policy của AppArmor](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): đánh giá xem một helper có đặc quyền có thể ghi vào tệp điều khiển AppArmor được người dùng cục bộ mở hay không.
- [Post-exploitation](post-exploitation/README.md): tìm kiếm thông tin xác thực, duy trì quyền truy cập và các kỹ thuật tiếp theo ở cấp máy chủ.

Trên các kernel bị ảnh hưởng, việc người dùng không có đặc quyền mở tệp điều khiển policy trong securityfs của AppArmor có thể thành công, dù thao tác ghi trực tiếp bị từ chối. Nếu một helper có đặc quyền kế thừa tệp đó làm stdout, thao tác ghi của helper có thể thay đổi policy đã nạp; đây là một đường tấn công cục bộ riêng biệt, không chỉ đơn thuần là tìm thấy một container profile yếu. Hãy kiểm tra các bản vá cho kernel và helper của nhà cung cấp trước khi thử nghiệm.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Thông báo kỹ thuật CrackArmor của Qualys](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Cơ sở kiến thức về lỗ hổng CrackArmor của Ubuntu](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
