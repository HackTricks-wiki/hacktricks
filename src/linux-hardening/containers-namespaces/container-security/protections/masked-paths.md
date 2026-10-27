# Đường dẫn bị che

{{#include ../../../../banners/hacktricks-training.md}}

Đường dẫn bị che là các biện pháp bảo vệ trong thời gian chạy, ẩn những vị trí nhạy cảm đặc biệt trên hệ thống tệp giao tiếp với kernel khỏi container bằng cách bind-mount đè lên chúng hoặc khiến chúng không thể truy cập theo cách khác. Đặc tả OCI runtime định nghĩa `maskedPaths` là các đường dẫn tuyệt đối không thể đọc được bên trong container. <sup>[[1]](#references)</sup>

Điều này quan trọng vì nhiều kỹ thuật container escape và gây ảnh hưởng đến host bắt đầu bằng việc đọc hoặc ghi các tệp đặc biệt trong `/proc` hoặc `/sys`. Nếu những vị trí đó bị che, kẻ tấn công sẽ mất quyền truy cập trực tiếp vào một phần hữu ích của bề mặt điều khiển kernel, ngay cả sau khi thực thi được mã bên trong container.

## Hoạt động

Các runtime thường che một số đường dẫn như:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Danh sách cụ thể phụ thuộc vào runtime và cấu hình host. Điều quan trọng là đường dẫn đó trở nên không thể truy cập hoặc bị thay thế theo góc nhìn của container, dù nó vẫn tồn tại trên host.

## Lab

Kiểm tra cấu hình đường dẫn bị che mà Docker cung cấp:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Kiểm tra hành vi mount thực tế bên trong workload:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

Một đường dẫn được liệt kê không nhất thiết có thể đọc được: runc có thể che một tệp bằng bind mount `/dev/null` và một thư mục bằng tmpfs rỗng chỉ đọc. Kiểm tra chính xác điểm mount, không chỉ kiểm tra xem `ls` có chạy thành công hay không. <sup>[[4]](#references)</sup>

## Security Impact

Việc che đường dẫn không tạo ra ranh giới cô lập chính, nhưng loại bỏ một số mục tiêu có giá trị cao sau khi khai thác. Nếu không che, container bị xâm nhập có thể kiểm tra trạng thái kernel, đọc thông tin nhạy cảm về tiến trình hoặc khóa, hoặc tương tác với các đối tượng procfs/sysfs vốn không bao giờ được phép hiển thị cho ứng dụng.

## Misconfigurations

Sai lầm chính là bỏ che các nhóm đường dẫn rộng để thuận tiện hoặc gỡ lỗi. Trong Podman, điều này có thể xuất hiện dưới dạng `--security-opt unmask=ALL` hoặc bỏ che một số đường dẫn cụ thể. <sup>[[2]](#references)</sup> Trong Kubernetes, việc để lộ proc quá rộng có thể xuất hiện qua `procMount: Unmasked`; Kubernetes hiện tại yêu cầu `spec.hostUsers: false` (user namespace) cho thiết lập này, trong khi các phiên bản 1.12–1.29 không thực thi yêu cầu đó. <sup>[[3]](#references)</sup> Một vấn đề nghiêm trọng khác là để lộ `/proc` hoặc `/sys` của host thông qua bind mount, điều này hoàn toàn vô hiệu hóa ý tưởng về một chế độ xem container bị thu hẹp.

## Abuse

Nếu việc che đường dẫn yếu hoặc không có, hãy bắt đầu bằng cách xác định những đường dẫn procfs/sysfs nhạy cảm nào có thể truy cập trực tiếp:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Nếu một đường dẫn được cho là đã bị mask vẫn có thể truy cập, hãy kiểm tra kỹ:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Những gì các lệnh này có thể tiết lộ:

- `/proc/timer_list` có thể để lộ dữ liệu về timer và bộ lập lịch của host. Đây chủ yếu là một primitive trinh sát, nhưng xác nhận rằng container có thể đọc thông tin hướng kernel vốn thường bị ẩn.
- `/proc/keys` chỉ liệt kê metadata của các key mà người đọc có quyền **view**, tùy thuộc vào các kiểm tra LSM. Nó có thể tiết lộ loại và mô tả của key, nhưng không dump payload của key. <sup>[[6]](#references)</sup>
- `/sys/firmware` giúp xác định chế độ khởi động, giao diện firmware và thông tin nền tảng hữu ích cho việc fingerprint host cũng như tìm hiểu workload có đang thấy trạng thái cấp host hay không.
- `/proc/config.gz` có thể tiết lộ cấu hình kernel đang chạy, hữu ích để đối chiếu các điều kiện tiên quyết của public kernel exploit hoặc tìm hiểu vì sao một tính năng cụ thể có thể truy cập được.
- `/proc/sched_debug` để lộ trạng thái bộ lập lịch và thường đi ngược kỳ vọng trực quan rằng PID namespace sẽ ẩn hoàn toàn thông tin về các process không liên quan.

Các kết quả đáng chú ý gồm đọc trực tiếp những file đó, bằng chứng cho thấy dữ liệu thuộc về host chứ không phải góc nhìn bị giới hạn của container, hoặc truy cập được các vị trí procfs/sysfs khác thường bị mask theo mặc định.

### Race ở nguồn mask trong lúc khởi động container

Trong các bản runc dễ bị lỗi, file mask phụ thuộc vào inode của `/dev/null` trong container. Kẻ tấn công có thể tạo ra các container chạy đồng thời với các mount dùng chung, bao gồm những bước BuildKit chạy song song, rồi race để xóa `/dev/null` trước khi runc bind nó lên các file procfs cần mask. Khi đó, runtime coi **source** bị thiếu như thể đích mask không tồn tại và âm thầm bỏ qua các file mask đó. Lỗi này phụ thuộc vào race trong lúc runtime thiết lập; xóa `/dev/null` sau khi khởi động sẽ không gỡ bỏ mask đã được cài đặt. <sup>[[4]](#references)</sup>

Sau khi kiểm thử có kiểm soát, hãy so sánh danh sách mask được yêu cầu với các mountpoint chính xác bên trong container mới. <sup>[[4]](#references)</sup> `findmnt -M` kiểm tra mountpoint được chỉ định thay vì chuyển sang mount cha; nếu không có `findmnt`, hãy kiểm tra `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> Lệnh `ls` chạy thành công hoặc `cat` trả về rỗng không thể chứng minh rằng mask đã bị bỏ qua. <sup>[[4]](#references)</sup>

Dùng [các bước kiểm tra bên dưới](#checks) để so sánh những mask được yêu cầu với các mount chính xác trong container mới.

File mask bị bỏ qua có thể làm lộ dữ liệu procfs nếu quyền thông thường và chính sách LSM cho phép. Điều đó **không** tự khiến `/proc/sys` có thể ghi được: đây là một kiểm soát [read-only-path](read-only-paths.md) riêng biệt. Việc thay thế symlink `/dev/null` riêng biệt, có thể chuyển hướng bind mount đến một đích procfs có thể ghi, được đề cập trong mục [race runtime của PID namespace](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Checks

Mục đích của các bước kiểm tra này là xác định những path nào đã được runtime chủ động ẩn và liệu workload hiện tại vẫn đang thấy một filesystem hướng kernel bị thu hẹp hay không.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Sử dụng kiểm tra mount chính xác vì file bị che vẫn có thể tồn tại và thao tác đọc có thể trả về kết quả rỗng từ `/dev/null`. Mountpoint không tồn tại là dấu hiệu cần điều tra, chứ tự nó không chứng minh rằng có thể đọc dữ liệu trên host. <sup>[[4]](#references)[[5]](#references)</sup>

Điểm đáng chú ý ở đây:

- Danh sách đường dẫn bị che dài là điều bình thường trong các runtime được hardening.
- Việc thiếu che chắn ở các mục procfs nhạy cảm cần được kiểm tra kỹ hơn.
- Nếu có thể truy cập một đường dẫn nhạy cảm và container cũng có capabilities mạnh hoặc mount rộng, mức độ lộ dữ liệu sẽ đáng lo ngại hơn.

## Runtime Defaults

| Runtime / platform | Trạng thái mặc định | Hành vi mặc định | Cách làm suy yếu thường gặp |
| --- | --- | --- | --- |
| Docker Engine | Mặc định được bật | Docker xác định danh sách đường dẫn bị che mặc định | cho phép truy cập các mount host proc/sys, `--privileged` |
| Podman | Mặc định được bật | Podman áp dụng các đường dẫn bị che mặc định, trừ khi được bỏ che thủ công | `--security-opt unmask=ALL`, bỏ che có chọn lọc, `--privileged` |
| Kubernetes | Kế thừa mặc định của runtime | Sử dụng hành vi che chắn của runtime bên dưới, trừ khi cấu hình Pod làm suy yếu việc bảo vệ proc | `procMount: Unmasked` (các phiên bản hiện tại yêu cầu `hostUsers: false`), cấu hình workload privileged, mount host rộng |
| containerd / CRI-O under Kubernetes | Mặc định của runtime | Thường áp dụng các đường dẫn bị che theo OCI/runtime, trừ khi bị ghi đè | thay đổi trực tiếp cấu hình runtime, các cách làm suy yếu tương tự trong Kubernetes |

Các đường dẫn bị che thường được thiết lập mặc định. Vấn đề vận hành chính không phải là runtime không có chúng, mà là việc chủ động bỏ che hoặc sử dụng bind mount từ host làm vô hiệu hóa biện pháp bảo vệ.

## References

- [1] [Open Container Initiative - Cấu hình container Linux: Đường dẫn bị che](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Tài liệu Podman - Tùy chọn bảo mật `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Tài liệu Kubernetes - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [Thông báo bảo mật runc: race ở nguồn mount của đường dẫn bị che](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Tài liệu hướng dẫn findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Tài liệu hướng dẫn keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
