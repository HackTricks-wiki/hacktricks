# Tổng quan về các biện pháp bảo vệ container

{{#include ../../../../banners/hacktricks-training.md}}

Ý tưởng quan trọng nhất trong việc hardening container là không có một biện pháp kiểm soát đơn lẻ nào được gọi là "container security". Điều mà mọi người gọi là cô lập container thực chất là kết quả của nhiều cơ chế bảo mật và quản lý tài nguyên của Linux phối hợp với nhau. Nếu tài liệu chỉ mô tả một trong số đó, người đọc thường đánh giá quá cao sức mạnh của nó. Nếu tài liệu liệt kê tất cả mà không giải thích cách chúng tương tác, người đọc chỉ có một danh sách tên gọi mà không có mô hình thực sự. Phần này cố gắng tránh cả hai sai lầm đó.

Trọng tâm của mô hình là **namespaces**, giúp cô lập những gì workload có thể nhìn thấy. Chúng cung cấp cho tiến trình một góc nhìn riêng tư hoặc riêng tư một phần về các mount của filesystem, PID, networking, đối tượng IPC, hostname, ánh xạ user/group, đường dẫn cgroup và một số clock. Nhưng chỉ namespaces thì không quyết định tiến trình được phép làm gì. Đó là lúc các lớp tiếp theo phát huy tác dụng. <sup>[[1]](#references)</sup>

**cgroups** kiểm soát việc sử dụng tài nguyên. Chúng không phải chủ yếu là ranh giới cô lập theo cùng nghĩa với mount hoặc PID namespaces, nhưng có vai trò vận hành thiết yếu vì chúng giới hạn memory, CPU, PID, I/O và quyền truy cập device. Chúng cũng liên quan đến bảo mật vì các kỹ thuật breakout trước đây đã lạm dụng những tính năng cgroup có thể ghi, đặc biệt trong môi trường cgroup v1. <sup>[[2]](#references)</sup>

**Capabilities** chia mô hình root toàn quyền cũ thành các đơn vị đặc quyền nhỏ hơn. Điều này có ý nghĩa cơ bản đối với container vì nhiều workload vẫn chạy với UID 0 bên trong container. Vì vậy, câu hỏi không chỉ là "tiến trình có phải root không?", mà còn là "những capabilities nào còn lại, bên trong namespaces nào, và chịu những hạn chế seccomp và MAC nào?" Đó là lý do một tiến trình root trong container này có thể bị hạn chế tương đối, trong khi tiến trình root trong container khác trên thực tế gần như không thể phân biệt với root trên host. <sup>[[3]](#references)</sup>

**seccomp** lọc syscall và giảm bề mặt tấn công của kernel mà workload tiếp xúc. Đây thường là cơ chế chặn các lệnh gọi nguy hiểm như `unshare`, `mount`, `keyctl` và những syscall khác được dùng trong các chuỗi breakout khi profile đang hoạt động từ chối chúng. Ngay cả khi tiến trình có capability vốn cho phép một thao tác, seccomp vẫn có thể chặn đường gọi syscall trước khi kernel xử lý đầy đủ thao tác đó. <sup>[[4]](#references)</sup>

**AppArmor** và **SELinux** bổ sung Mandatory Access Control lên trên các bước kiểm tra filesystem và đặc quyền thông thường. Các cơ chế này đặc biệt quan trọng vì chúng vẫn có tác dụng ngay cả khi container có nhiều capabilities hơn mức cần thiết. Workload có thể có đặc quyền trên lý thuyết để thử thực hiện một hành động, nhưng vẫn bị ngăn cản vì label hoặc profile của nó cấm truy cập vào đường dẫn, đối tượng hoặc thao tác liên quan.

Cuối cùng, còn có các lớp hardening khác ít được chú ý hơn nhưng thường xuyên phát huy tác dụng trong các cuộc tấn công thực tế: `no_new_privs`, các đường dẫn procfs bị mask, các đường dẫn hệ thống chỉ đọc, root filesystem chỉ đọc và các thiết lập mặc định cẩn trọng của runtime. Những cơ chế này thường ngăn chặn "bước cuối cùng" của một vụ xâm nhập, đặc biệt khi attacker cố biến việc thực thi code thành sự gia tăng đặc quyền rộng hơn.

Phần còn lại của thư mục này giải thích chi tiết hơn từng cơ chế, bao gồm primitive thực sự do kernel cung cấp, cách quan sát nó trên máy cục bộ, cách các runtime phổ biến sử dụng nó và cách operator vô tình làm suy yếu nó.

## Đọc tiếp

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Nhiều vụ escape thực tế cũng phụ thuộc vào nội dung của host được mount vào workload. Vì vậy, sau khi đọc về các biện pháp bảo vệ cốt lõi, bạn nên đọc tiếp:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

## References

- [1] [namespaces(7) - trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [2] [Control Group v2 - tài liệu kernel Linux](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [3] [capabilities(7) - trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [4] [Seccomp BPF - tài liệu kernel Linux](https://docs.kernel.org/userspace-api/seccomp_filter.html)
{{#include ../../../../banners/hacktricks-training.md}}
