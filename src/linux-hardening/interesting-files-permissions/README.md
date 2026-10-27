# Tệp và quyền truy cập đáng chú ý

{{#include ../../banners/hacktricks-training.md}}

Quyền sở hữu tệp, quyền ghi, tùy chọn mount và đặc quyền thực thi có thể thay đổi phạm vi truy cập thực tế của người dùng cục bộ. Hãy bắt đầu bằng cách xác định tệp hoặc đường dẫn thực thi mục tiêu, sau đó xem trang phù hợp:

- [SUID, SGID, ACL và tệp nhạy cảm](suid-sgid-and-acl-triage.md) cung cấp quy trình khởi đầu để kiểm tra đặc quyền thực thi và các quyền truy cập ẩn.
- [Ghi tùy ý vào tệp của root](write-to-root.md) mô tả cách biến quyền ghi vào các đường dẫn đặc quyền thành cơ hội leo thang đặc quyền.
- [Linux capabilities](linux-capabilities.md) giải thích capabilities theo tiến trình và theo tệp.
- [Lạm dụng thư viện dùng chung và linker với SUID](suid-shared-library-and-linker-abuse.md) đề cập đến việc tải động xung quanh các binary đặc quyền.
- [Ví dụ leo thang đặc quyền qua `ld.so`](ld.so.conf-example.md) trình bày một trường hợp liên quan đến cấu hình linker.
- [Cấu hình sai NFS `no_root_squash` và `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) đề cập đến ánh xạ danh tính trên hệ thống tệp từ xa.
- [Mẹo khai thác wildcard spare](wildcards-spare-tricks.md) đề cập đến việc mở rộng đối số trong các lệnh đặc quyền.
- [SELinux](selinux.md) giải thích việc thực thi chính sách và các bước điều tra liên quan.
{{#include ../../banners/hacktricks-training.md}}
