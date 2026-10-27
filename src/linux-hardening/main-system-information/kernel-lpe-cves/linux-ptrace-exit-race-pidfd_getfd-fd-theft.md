# Linux ptrace exit-race `pidfd_getfd()` đánh cắp FD

{{#include ../../../banners/hacktricks-training.md}}

Một **mẫu privesc hữu ích trên Linux kernel** là biến **lỗi ủy quyền ptrace** thành **hành vi đánh cắp file descriptor** từ một tiến trình có đặc quyền.

Trong case study `__ptrace_may_access()` của Qualys (CVE-2026-46333), attacker race với một **tiến trình có đặc quyền đang thoát hoặc hạ credentials** và dùng `pidfd_getfd()` để sao chép một FD vào tiến trình của attacker.<sup>[[1]](#references)[[2]](#references)</sup>

## Ý tưởng cốt lõi

`pidfd_getfd()` sao chép một file descriptor từ tiến trình khác, nhưng trước tiên sẽ kiểm tra quyền kiểu ptrace đối với tiến trình đích.<sup>[[3]](#references)</sup> Nếu việc ủy quyền được cấp sai trong **khoảng thời gian teardown**, attacker không có đặc quyền có thể sao chép:

- FD của **các file nhạy cảm** đã được một helper có đặc quyền mở
- FD của **các kênh IPC đã xác thực** được cấp quyền với tư cách root

Điều này biến lỗi ủy quyền phía kernel thành một primitive rất thực tế ở userspace.<sup>[[1]](#references)</sup>

## Vì sao primitive này nguy hiểm

Cuộc tấn công **không** cần có lỗi trong chính helper có đặc quyền. Helper chỉ cần tạm thời giữ thứ gì đó có giá trị:

- `/etc/shadow`
- `/etc/ssh/*_key`
- kết nối D-Bus / systemd có đặc quyền
- bất kỳ bí mật hoặc kênh đã được cấp quyền nào khác đang mở

Sau khi được sao chép vào tiến trình của attacker, FD bản sao trỏ đến cùng một open file description, vì vậy các lần đọc tiếp theo hoặc yêu cầu IPC sẽ dùng FD đã mở thay vì mở lại pathname ban đầu hoặc bắt đầu quy trình xác thực mới.<sup>[[2]](#references)[[3]](#references)</sup>

## Mẫu khai thác

1. Xác định một binary **setuid / setgid / có file-capability** hoặc **root daemon** mở các file nhạy cảm hay giữ các kết nối IPC hữu ích.<sup>[[2]](#references)</sup>
2. Tạo mối quan hệ đáp ứng các kiểm tra policy ptrace liên quan cho đường đi mục tiêu (ví dụ: là **parent** của một privileged child được tạo ra khi cấu hình YAMA cho phép rộng rãi).<sup>[[2]](#references)[[4]](#references)</sup>
3. Race với tiến trình khi nó đang **thoát**, **hạ credentials** hoặc chuyển sang trạng thái mà quyền truy cập ptrace lẽ ra phải không còn hiệu lực.<sup>[[2]](#references)</sup>
4. Dùng `pidfd_open()` + `pidfd_getfd()` để sao chép FD mục tiêu trong khoảng thời gian ủy quyền ngắn ngủi đó.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Tái sử dụng FD bị đánh cắp từ ngữ cảnh không có đặc quyền.<sup>[[2]](#references)</sup>
   - `read()` bí mật từ file descriptor có đặc quyền
   - gửi yêu cầu qua kênh IPC đã xác thực bị đánh cắp để thực hiện **các hành động phía root**

Dạng primitive tối thiểu.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```

## Các mục tiêu thực tế cần kiểm tra

Ưu tiên các binary và daemon mà, dù chỉ trong chốc lát, thực hiện một trong những việc sau:<sup>[[1]](#references)[[2]](#references)</sup>

- mở các tệp chỉ root mới truy cập được trước khi hoàn tất chuyển đổi đặc quyền
- kết nối với **system bus** và giữ lại một channel đã được cấp quyền
- chuyển các FD đặc quyền qua ranh giới giữa các helper
- thực hiện công việc nhạy cảm về bảo mật trong quá trình teardown liền kề `do_exit()`

Các mục tiêu tiềm năng đáng kiểm tra:<sup>[[1]](#references)</sup>

- helper quản lý mật khẩu / tài khoản
- helper SSH
- helper được trung gian hóa qua PolicyKit / D-Bus
- daemon desktop chạy với quyền root và cung cấp các phương thức D-Bus

## YAMA như một cổng kiểm soát exploit

`kernel.yama.ptrace_scope` là một cổng kiểm soát quan trọng trên thực tế đối với việc lạm dụng nhóm ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: hành vi ptrace cổ điển giữa các tiến trình cùng UID
- `1`: thường cho phép tiến trình cha theo dõi tiến trình con, giúp một số đường exploit công khai vẫn khả thi
- `2`: yêu cầu `CAP_SYS_PTRACE` để truy cập theo kiểu attach và chặn việc lạm dụng `pidfd_getfd()` không đặc quyền theo đường này
- `3`: vô hiệu hóa hoàn toàn ptrace attach cho đến khi khởi động lại

Đối với kỹ thuật này, `ptrace_scope=2` là một **biện pháp giảm thiểu tạm thời** hiệu quả vì nó khiến đường khai thác `pidfd_getfd()` công khai thất bại với lỗi `-EPERM` đối với người dùng không đặc quyền.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ý tưởng phát hiện / rà soát

Khi kiểm tra phần mềm Linux có đặc quyền, hãy tìm các tổ hợp sau:

- **tiến trình con có đặc quyền** + **tiến trình cha do attacker kiểm soát**.<sup>[[2]](#references)[[4]](#references)</sup>
- quyền truy cập tạm thời vào **các tệp đang mở có giá trị**
- quyền truy cập tạm thời vào **các channel D-Bus/systemd đã xác thực**.<sup>[[2]](#references)</sup>
- các quyết định bảo mật tái sử dụng cơ chế cấp quyền kiểu **ptrace** bên ngoài `ptrace(2)` cổ điển
- các API kernel có thể **sao chép, kế thừa hoặc xuất lại** các FD đặc quyền hiện có

Khi kiểm tra kernel, hãy coi mọi đường xử lý thực hiện **cơ chế cấp quyền tương đương ptrace** trong lúc **task teardown** là có rủi ro cao, đặc biệt nếu thành công sẽ cấp quyền truy cập trực tiếp vào `task->files` hoặc các tài nguyên tiến trình đã được cấp quyền khác.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Leo thang đặc quyền cục bộ lên root và tiết lộ thông tin xác thực trong đường xử lý ptrace của Linux Kernel (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Thông báo bảo mật Qualys TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Trang hướng dẫn sử dụng pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Tài liệu Yama của Linux kernel](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Trang hướng dẫn sử dụng pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
