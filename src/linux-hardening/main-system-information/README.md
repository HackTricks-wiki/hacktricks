# Thông tin hệ thống chính

{{#include ../../banners/hacktricks-training.md}}

Kiểm tra kernel, filesystem, các helper có đặc quyền và những đường thoát khả dụng trên máy chủ trước khi chọn kỹ thuật escalation cục bộ. [Checklist privilege escalation](linux-privilege-escalation-checklist.md) cung cấp thứ tự thao tác ngắn gọn.

- [Đánh giá lỗ hổng kernel và mức độ phơi nhiễm khi chạy](kernel-vulnerability-assessment.md) kiểm tra khả năng áp dụng của bản dựng, khả năng truy cập và các biện pháp giảm thiểu đang hoạt động.
- [Kernel modules và lạm dụng modprobe](kernel-modules-and-modprobe.md) đề cập đến việc tải module và mức độ phơi nhiễm của đường dẫn helper.
- [Lạm dụng lệnh Sudo](sudo-command-abuse.md) xem xét cách các lệnh được ủy quyền có thể vượt qua ranh giới đặc quyền.
- [Symlink, hardlink và file descriptor](filesystem-links-and-file-descriptors.md) đề cập đến việc chuyển hướng đường dẫn và các tệp được kế thừa hoặc đã xóa nhưng vẫn đang mở.
- [Filesystem, inode và khôi phục](filesystem-inodes-and-recovery.md) giải thích các hành vi của filesystem hữu ích trong quá trình điều tra.
- [Checklist: Linux privilege escalation](linux-privilege-escalation-checklist.md) liệt kê các bước kiểm tra máy chủ và liên kết đến tài liệu chuyên sâu hơn.
- [Thoát khỏi jail](escaping-from-limited-bash.md) đề cập đến shell giới hạn và môi trường bị hạn chế.
- [Tài liệu về Kernel/LPE/CVE](kernel-lpe-cves/README.md) tập hợp các bài viết chuyên sâu về local privilege escalation và lỗ hổng.
{{#include ../../banners/hacktricks-training.md}}
