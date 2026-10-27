# Namespace cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Tổng quan

Namespace cgroup không thay thế cgroups và bản thân nó không thực thi giới hạn tài nguyên. Thay vào đó, nó thay đổi **cách hệ thống phân cấp cgroup hiển thị với** tiến trình. Nói cách khác, nó ảo hóa thông tin đường dẫn cgroup hiển thị để workload thấy góc nhìn giới hạn trong container thay vì toàn bộ hệ thống phân cấp của host.

Đây chủ yếu là tính năng hiển thị và giảm lượng thông tin lộ ra. Nó giúp môi trường trông độc lập hơn và tiết lộ ít hơn về cách bố trí cgroup của host. Điều đó có thể nghe không đáng kể, nhưng vẫn quan trọng vì khả năng quan sát cấu trúc host không cần thiết có thể hỗ trợ reconnaissance và đơn giản hóa các chuỗi exploit phụ thuộc vào môi trường.

## Hoạt động

Nếu không có namespace cgroup riêng, tiến trình có thể thấy các đường dẫn cgroup tương đối với host, làm lộ nhiều phần trong hệ thống phân cấp của máy hơn mức cần thiết. Khi có namespace cgroup riêng, `/proc/self/cgroup` và các thông tin liên quan sẽ được giới hạn hơn trong góc nhìn của chính container. Điều này đặc biệt hữu ích với các stack runtime hiện đại muốn workload thấy một môi trường gọn gàng hơn, ít tiết lộ thông tin về host hơn.

Việc ảo hóa cũng ảnh hưởng đến `/proc/<pid>/mountinfo`, không chỉ `/proc/<pid>/cgroup`. Khi đọc thông tin về một tiến trình khác từ góc nhìn của namespace cgroup khác, các đường dẫn nằm ngoài root namespace của bạn sẽ hiển thị với các thành phần `../` ở đầu. Đây là dấu hiệu hữu ích cho biết bạn đang nhìn lên trên cây thư mục con được ủy quyền. Một điểm cần lưu ý trong lab và post-exploitation là namespace cgroup mới tạo thường cần **remount cgroupfs từ bên trong namespace đó** trước khi `mountinfo` phản ánh chính xác root mới. Nếu không, bạn vẫn có thể thấy mount root như `/..`, nghĩa là mount được kế thừa vẫn hiển thị góc nhìn bắt đầu từ root của một thư mục cha, dù namespace đã thay đổi.<sup>[[1]](#references)</sup>

## Lab

Bạn có thể kiểm tra namespace cgroup bằng lệnh:

```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```

Nếu bạn muốn `mountinfo` hiển thị rõ hơn root mới của cgroup namespace, hãy mount lại hệ thống tệp cgroup từ bên trong namespace mới rồi so sánh lại:

```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```

Và so sánh hành vi khi chạy với:

```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```

Sự thay đổi chủ yếu liên quan đến những gì process có thể nhìn thấy, chứ không phải việc cgroup enforcement có tồn tại hay không.

## Tác động bảo mật

Cách tốt nhất để hiểu cgroup namespace là một **lớp tăng cường bảo mật khả năng hiển thị**. Bản thân nó không ngăn được breakout nếu container có các mount cgroup có thể ghi, capabilities rộng hoặc môi trường cgroup v1 nguy hiểm. Tuy nhiên, nếu dùng chung host cgroup namespace, process sẽ biết thêm về cách hệ thống được tổ chức và có thể dễ dàng đối chiếu các đường dẫn cgroup tương đối với host với những quan sát khác.

Trên **cgroup v2**, namespace trở nên quan trọng hơn đôi chút vì các quy tắc delegation chặt chẽ hơn. Nếu hierarchy được mount với `nsdelegate`, kernel xem cgroup namespace là ranh giới delegation: các file điều khiển của ancestor phải nằm ngoài phạm vi truy cập của delegatee, và quyền ghi tại namespace root bị giới hạn ở các file an toàn cho delegation, chẳng hạn `cgroup.procs`, `cgroup.threads` và `cgroup.subtree_control`.<sup>[[2]](#references)</sup> Điều này vẫn không khiến namespace tự nó trở thành một primitive để escape, nhưng thay đổi những gì workload bị compromise có thể kiểm tra và nơi nó có thể tạo sub-cgroup một cách an toàn.

Vì vậy, dù namespace này thường không phải trọng tâm trong các bài viết về container breakout, nó vẫn góp phần vào mục tiêu rộng hơn là giảm thiểu rò rỉ thông tin về host và hạn chế cgroup delegation.

## Lạm dụng

Giá trị lạm dụng trước mắt chủ yếu là reconnaissance. Nếu dùng chung host cgroup namespace, hãy so sánh các đường dẫn hiển thị và tìm những chi tiết về hierarchy có thể tiết lộ thông tin về host:

```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```

Nếu các đường dẫn cgroup có quyền ghi cũng được hiển thị, hãy kết hợp khả năng quan sát đó với việc tìm kiếm các giao diện legacy nguy hiểm:

```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```

Namespace hiếm khi tự nó giúp thoát ngay lập tức, nhưng thường giúp lập bản đồ môi trường dễ hơn trước khi kiểm tra các primitive lạm dụng dựa trên cgroup.

Kiểm tra nhanh thực tế runtime cũng giúp ưu tiên đường tấn công. Docker cung cấp `--cgroupns=host|private`, trong khi Podman hỗ trợ `host`, `private`, `container:<id>` và `ns:<path>`. Riêng trên Podman, mặc định thường là **`host` trên cgroup v1** và **`private` trên cgroup v2**, vì vậy chỉ cần xác định phiên bản cgroup là đã biết được trạng thái namespace nào có khả năng cao hơn trước cả khi kiểm tra toàn bộ cấu hình OCI.

### Recon v2 hiện đại: Đây có phải là một subtree được ủy quyền?

Trên các host hiện đại, câu hỏi đáng quan tâm thường không phải là `release_agent`, mà là liệu tiến trình hiện tại có đang nằm trong một subtree **cgroup v2** được ủy quyền với đủ khả năng quan sát hoặc quyền ghi để tạo các nhóm lồng nhau hay không:

```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```

Diễn giải hữu ích:

- `cgroup2fs` nghĩa là bạn đang ở hệ thống phân cấp v2 thống nhất, vì vậy các chuỗi `release_agent` chỉ có trong v1 cổ điển không nên là phỏng đoán đầu tiên của bạn.
- `cgroup.controllers` cho biết những controller nào có sẵn từ cấp cha và do đó những controller nào cây con hiện tại có thể phân nhánh xuống các tiến trình con.
- `cgroup.subtree_control` cho biết những controller nào thực sự được bật cho các tiến trình con.
- `cgroup.events` hiển thị `populated=0/1`, hữu ích để theo dõi xem một cây con đã trở nên trống hay chưa, nhưng đây **không phải** là primitive thực thi mã trên host như `release_agent` của v1.

Nếu bạn đã có đủ đặc quyền để kiểm tra trực tiếp namespace của một tiến trình khác, hãy so sánh các chế độ xem bằng:

```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```

### Ví dụ đầy đủ: Namespace cgroup dùng chung + cgroup v1 có thể ghi

Chỉ riêng namespace cgroup thường không đủ để escape. Việc leo thang quyền trên thực tế xảy ra khi các đường dẫn cgroup làm lộ thông tin host kết hợp với các giao diện cgroup v1 có thể ghi:

```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```

Nếu có thể truy cập và ghi vào các tệp đó, hãy lập tức chuyển sang thực hiện đầy đủ quy trình khai thác `release_agent` trong [cgroups.md](../cgroups.md). Tác động là thực thi mã trên host từ bên trong container.

Nếu không thể ghi vào các giao diện cgroup, tác động thường chỉ giới hạn ở việc trinh sát.

## Checks

Mục đích của các lệnh này là kiểm tra xem tiến trình có chế độ xem namespace cgroup riêng hay đang tìm hiểu nhiều hơn mức cần thiết về phân cấp cgroup của host.

```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```

Điều thú vị ở đây:

- Nếu định danh namespace khớp với một tiến trình trên host mà bạn quan tâm, cgroup namespace có thể được chia sẻ.
- Các đường dẫn để lộ thông tin về host trong `/proc/self/cgroup` hoặc các mục trong `mountinfo` bắt nguồn từ thư mục gốc của ancestor là thông tin trinh sát hữu ích, ngay cả khi chúng không thể bị khai thác trực tiếp.
- Nếu đang dùng `cgroup2fs`, hãy tập trung vào việc ủy quyền, các controller hiển thị và các subtree có quyền ghi, thay vì cho rằng các primitive cũ của v1 vẫn tồn tại.
- Nếu các cgroup mount cũng có quyền ghi, vấn đề về khả năng hiển thị trở nên quan trọng hơn nhiều.

Cgroup namespace nên được xem là một lớp tăng cường bảo mật về khả năng hiển thị, chứ không phải cơ chế chính để ngăn thoát khỏi container. Việc để lộ cấu trúc cgroup của host một cách không cần thiết sẽ cung cấp thêm thông tin trinh sát cho attacker.

## References

- [1] [cgroup_namespaces(7) — Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — Tài liệu Linux Kernel](https://docs.kernel.org/admin-guide/cgroup-v2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
