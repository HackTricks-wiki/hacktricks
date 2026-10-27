# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces là tính năng của kernel giúp container tạo cảm giác như đang chạy trên “máy riêng”, dù thực chất nó chỉ là một cây tiến trình trên host. Chúng không tạo kernel mới và cũng không ảo hóa mọi thứ, nhưng cho phép kernel hiển thị các góc nhìn khác nhau về những tài nguyên được chọn cho các nhóm tiến trình khác nhau. Đây là cốt lõi của ảo giác container: workload thấy một filesystem, bảng tiến trình, network stack, hostname, tài nguyên IPC và mô hình định danh user/group có vẻ như thuộc về môi trường cục bộ, dù hệ thống bên dưới được chia sẻ. <sup>[[1]](#references)</sup>

Đây là lý do namespaces là khái niệm đầu tiên mà hầu hết mọi người gặp khi tìm hiểu cách container hoạt động. Đồng thời, đây cũng là một trong những khái niệm thường bị hiểu sai nhất, vì người đọc thường cho rằng “có namespaces” đồng nghĩa với “được cô lập an toàn”. Trên thực tế, một namespace chỉ cô lập đúng loại tài nguyên mà nó được thiết kế để xử lý. Một tiến trình có thể nằm trong PID namespace riêng nhưng vẫn nguy hiểm vì có bind mount của host cho phép ghi. Nó có thể nằm trong network namespace riêng nhưng vẫn nguy hiểm vì giữ `CAP_SYS_ADMIN` và chạy mà không có seccomp. Namespaces là nền tảng, nhưng chỉ là một lớp trong ranh giới bảo vệ cuối cùng.

## Các loại Namespace

Linux container thường dựa vào nhiều loại namespace cùng lúc. **Mount namespace** cung cấp cho tiến trình một bảng mount riêng, từ đó kiểm soát góc nhìn filesystem. **PID namespace** thay đổi khả năng hiển thị và cách đánh số tiến trình để workload thấy cây tiến trình của riêng nó. **Network namespace** cô lập các interface, route, socket và trạng thái firewall. **IPC namespace** cô lập SysV IPC và hàng đợi thông điệp POSIX. **UTS namespace** cô lập hostname và tên miền NIS. **User namespace** ánh xạ lại user ID và group ID để root bên trong container không nhất thiết là root trên host. **Cgroup namespace** ảo hóa hệ thống phân cấp cgroup hiển thị, còn **time namespace** ảo hóa một số clock được chọn trong các kernel mới hơn. <sup>[[1]](#references)</sup> <sup>[[2]](#references)</sup>

Mỗi namespace trong số này giải quyết một vấn đề khác nhau. Vì vậy, việc phân tích bảo mật container trong thực tế thường tập trung vào việc kiểm tra **những namespace nào được cô lập** và **những namespace nào được chủ ý chia sẻ với host**.

## Chia sẻ Namespace của Host

Nhiều vụ container breakout không bắt đầu từ lỗ hổng kernel. Chúng bắt đầu khi operator chủ ý làm suy yếu mô hình cô lập. Các ví dụ `--pid=host`, `--network=host` và `--userns=host` là **các cờ CLI kiểu Docker/Podman** được dùng ở đây làm ví dụ cụ thể về việc chia sẻ namespace của host. Các runtime khác thể hiện cùng ý tưởng theo cách khác. Trong Kubernetes, các thiết lập tương đương thường xuất hiện dưới dạng cài đặt Pod như `hostPID: true`, `hostNetwork: true` hoặc `hostIPC: true`. Trong các runtime stack cấp thấp hơn như containerd hoặc CRI-O, hành vi tương tự thường được thiết lập thông qua cấu hình runtime OCI được tạo ra, thay vì một cờ giao diện người dùng có cùng tên. Trong tất cả các trường hợp này, kết quả tương tự nhau: workload không còn nhận được góc nhìn namespace cô lập mặc định. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup>

Đây là lý do việc rà soát namespace không nên dừng lại ở kết luận “tiến trình nằm trong một namespace nào đó”. Câu hỏi quan trọng là namespace đó chỉ dành riêng cho container, được chia sẻ với các container cùng nhóm, hay được kết nối trực tiếp với host. Trong Kubernetes, ý tưởng tương tự được thể hiện qua các cờ như `hostPID`, `hostNetwork` và `hostIPC`. Tên gọi thay đổi tùy nền tảng, nhưng kiểu rủi ro vẫn giống nhau: namespace dùng chung với host khiến các đặc quyền còn lại của container và trạng thái host mà nó có thể truy cập trở nên đáng kể hơn nhiều.

## Kiểm tra

Tổng quan đơn giản nhất là:

```bash
ls -l /proc/self/ns
```

Mỗi mục là một symbolic link có mã định danh tương tự inode. Nếu hai process trỏ đến cùng một mã định danh namespace, chúng nằm trong cùng một namespace thuộc loại đó. Vì vậy, `/proc` là nơi rất hữu ích để so sánh process hiện tại với các process đáng chú ý khác trên máy.

Các lệnh nhanh sau đây thường đủ để bắt đầu:

```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```

Từ đó, bước tiếp theo là so sánh tiến trình trong container với các tiến trình trên host hoặc lân cận, rồi xác định namespace có thực sự riêng tư hay không.

### Liệt kê các phiên bản namespace từ host

Khi đã có quyền truy cập host và muốn biết có bao nhiêu namespace riêng biệt thuộc một loại nhất định, `/proc` cung cấp danh sách nhanh:

```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```

Nếu muốn tìm các tiến trình thuộc về một mã định danh namespace cụ thể, hãy thay `readlink` bằng `ls -l` rồi grep theo số namespace mục tiêu:

```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```

Các lệnh này hữu ích vì chúng giúp bạn xác định liệu host đang chạy một workload được cô lập, nhiều workload được cô lập hay kết hợp các instance namespace dùng chung và riêng tư.

### Vào Namespace Mục Tiêu

Khi caller có đủ quyền, `nsenter` là cách tiêu chuẩn để tham gia namespace của một tiến trình khác:

```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```

Mục đích của việc liệt kê các dạng này cùng nhau không phải là mọi đợt đánh giá đều cần tất cả, mà là hoạt động post-exploitation theo namespace thường dễ hơn nhiều khi operator biết chính xác cú pháp để tham gia namespace, thay vì chỉ nhớ dạng dùng cho tất cả namespace.

## Các trang

Các trang sau giải thích chi tiết hơn về từng namespace:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Khi đọc các trang này, hãy ghi nhớ hai ý. Thứ nhất, mỗi namespace chỉ cô lập một kiểu góc nhìn. Thứ hai, namespace riêng chỉ hữu ích nếu phần còn lại của mô hình đặc quyền vẫn khiến sự cô lập đó có ý nghĩa.

## Mặc định của runtime

| Runtime / nền tảng | Cấu hình namespace mặc định | Cách phổ biến để nới lỏng thủ công |
| --- | --- | --- |
| Docker Engine | Mặc định tạo namespace mount, PID, network, IPC và UTS mới; có hỗ trợ user namespace nhưng không bật mặc định trong các cấu hình rootful tiêu chuẩn | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Mặc định tạo namespace mới; Podman rootless tự động dùng user namespace; mặc định của cgroup namespace tùy thuộc vào phiên bản cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Mặc định, các Pod **không** dùng chung PID, network hoặc IPC của host; network của Pod là riêng cho Pod, không riêng cho từng container; user namespace phải được bật rõ ràng bằng `spec.hostUsers: false` trên các cluster được hỗ trợ | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / không bật user namespace, thiết lập workload privileged |
| containerd / CRI-O trên Kubernetes | Thường tuân theo mặc định của Kubernetes Pod | như hàng Kubernetes; các đặc tả CRI/OCI trực tiếp cũng có thể yêu cầu tham gia namespace của host |

Quy tắc chính để đảm bảo tính di động rất đơn giản: **khái niệm** chia sẻ namespace của host là phổ biến giữa các runtime, nhưng **cú pháp** thì tùy runtime.

## References

- [1] [namespaces(7) - trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [2] [Open Container Initiative - namespace container Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#namespaces)
- [3] [Tài liệu tham khảo API Kubernetes - namespace host của PodSpec](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#PodSpec)
{{#include ../../../../../banners/hacktricks-training.md}}
