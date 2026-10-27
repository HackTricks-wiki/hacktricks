# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` là một tính năng hardening của kernel, ngăn process có thêm privilege khi gọi `execve()`. Trên thực tế, khi flag này được bật, việc thực thi một binary setuid, binary setgid hoặc file có Linux file capabilities sẽ không cấp thêm privilege nào ngoài những gì process đã có. Trong môi trường container, điều này rất quan trọng vì nhiều chuỗi privilege-escalation dựa vào việc tìm một executable bên trong image có thể thay đổi privilege khi được khởi chạy.

Từ góc độ phòng thủ, `no_new_privs` không thay thế namespaces, seccomp hay việc loại bỏ capabilities. Đây là một lớp gia cố bổ sung. Nó chặn một nhóm cụ thể các bước leo thang tiếp theo sau khi đã có code execution. Điều này đặc biệt hữu ích trong những môi trường có image chứa helper binary, artifact của package manager hoặc công cụ cũ vốn sẽ nguy hiểm nếu kết hợp với một phần hệ thống bị xâm nhập.

## Cách hoạt động

Flag của kernel đứng sau hành vi này là `PR_SET_NO_NEW_PRIVS`. Khi được bật cho một process, các lần gọi `execve()` sau đó không thể làm tăng privilege. Điểm quan trọng là process vẫn có thể chạy binary; chỉ là nó không thể dùng những binary đó để vượt qua ranh giới privilege mà kernel vốn sẽ cho phép.<sup>[[1]](#references)</sup>

Hành vi của kernel cũng **được kế thừa và không thể đảo ngược**: khi một task bật `no_new_privs`, bit này được kế thừa qua `fork()`, `clone()` và `execve()`, đồng thời không thể bị tắt về sau.<sup>[[1]](#references)</sup> Điều này hữu ích khi đánh giá bảo mật vì một giá trị `NoNewPrivs: 1` trên process của container thường có nghĩa là các process con cũng phải giữ trạng thái đó, trừ khi bạn đang xem xét một cây process hoàn toàn khác.

Trong các môi trường hướng đến Kubernetes, `allowPrivilegeEscalation: false` ánh xạ tới hành vi này cho process của container.<sup>[[2]](#references)</sup> Trong các runtime kiểu Docker và Podman, tùy chọn tương đương thường được bật rõ ràng thông qua một tùy chọn bảo mật. Ở tầng OCI, cùng khái niệm này xuất hiện dưới dạng `process.noNewPrivileges`.

## Các điểm cần lưu ý

`no_new_privs` chặn việc tăng privilege **khi thực thi**, chứ không chặn mọi thay đổi privilege.<sup>[[1]](#references)</sup> Cụ thể:

- các chuyển đổi setuid và setgid không còn hoạt động qua `execve()`
- file capabilities không được thêm vào permitted set khi gọi `execve()`
- các LSM như AppArmor hoặc SELinux không nới lỏng các ràng buộc sau `execve()`
- privilege đã có vẫn được giữ nguyên

Điểm cuối này quan trọng trong thực tế. Nếu process đã chạy với quyền root, đã có một capability nguy hiểm, hoặc đã truy cập được API runtime mạnh hay mount host có thể ghi, thì bật `no_new_privs` không vô hiệu hóa những rủi ro đó. Nó chỉ loại bỏ một **bước tiếp theo** phổ biến trong chuỗi privilege-escalation.

Cũng cần lưu ý flag này không chặn những thay đổi privilege không phụ thuộc vào `execve()`.<sup>[[1]](#references)</sup> Ví dụ, một task đã có đủ privilege vẫn có thể gọi trực tiếp `setuid(2)` hoặc nhận một file descriptor có privilege qua Unix socket. Vì vậy, nên xem xét `no_new_privs` cùng với [seccomp](seccomp.md), các capability set và mức độ tiếp xúc của namespace, thay vì coi đây là giải pháp độc lập.

## Thực hành

Kiểm tra trạng thái của process hiện tại:

```bash
grep NoNewPrivs /proc/self/status
```

So sánh điều đó với một container mà runtime bật flag:

```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```

Trên workload đã được harden, kết quả sẽ hiển thị `NoNewPrivs: 1`.

Bạn cũng có thể minh họa tác động thực tế bằng một binary setuid:

```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```

Mục đích của phép so sánh không phải là `su` luôn có thể bị khai thác. Mà là cùng một image có thể hoạt động rất khác nhau, tùy thuộc vào việc `execve()` còn được phép vượt qua ranh giới đặc quyền hay không.

## Tác động bảo mật

Nếu không có `no_new_privs`, foothold bên trong container vẫn có thể được nâng cấp đặc quyền thông qua các helper setuid hoặc binary có file capabilities. Nếu được bật, các thay đổi đặc quyền sau khi thực thi sẽ bị chặn. Tác động này đặc biệt đáng chú ý trong các base image lớn có nhiều tiện ích mà ứng dụng vốn không cần đến.

Ngoài ra, còn có một tương tác quan trọng với seccomp. Các tác vụ không có đặc quyền thường cần bật `no_new_privs` trước khi có thể cài đặt seccomp filter ở chế độ filter.<sup>[[1]](#references)</sup> Đây là một lý do khiến các container được harden thường bật cả `Seccomp` lẫn `NoNewPrivs`. Từ góc nhìn của attacker, việc thấy cả hai thường có nghĩa là môi trường được cấu hình có chủ đích chứ không phải vô tình.

## Cấu hình sai

Vấn đề phổ biến nhất đơn giản là không bật cơ chế bảo vệ này trong những môi trường tương thích. Trong Kubernetes, để `allowPrivilegeEscalation` ở trạng thái bật là một lỗi vận hành mặc định thường gặp. Trong Docker và Podman, việc bỏ qua tùy chọn bảo mật liên quan cũng gây ra kết quả tương tự. Một lỗi thường gặp khác là cho rằng vì container “không có đặc quyền”, nên các chuyển đổi đặc quyền khi thực thi đương nhiên không còn liên quan.

Một cạm bẫy Kubernetes tinh vi hơn là `allowPrivilegeEscalation: false` **không** được áp dụng như mọi người mong đợi khi container ở trạng thái `privileged` hoặc có `CAP_SYS_ADMIN`. Tài liệu Kubernetes nêu rõ rằng `allowPrivilegeEscalation` trên thực tế luôn là true trong những trường hợp đó.<sup>[[2]](#references)</sup> Trên thực tế, điều này có nghĩa là nên xem trường này như một tín hiệu về cấu hình bảo mật cuối cùng, chứ không phải bảo đảm rằng runtime đã thiết lập `NoNewPrivs: 1`.

## Lạm dụng

Nếu `no_new_privs` chưa được bật, câu hỏi đầu tiên là liệu image có chứa các binary vẫn có thể nâng đặc quyền hay không:

```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```

Kết quả đáng chú ý bao gồm:

- `NoNewPrivs: 0`
- các helper setuid như `su`, `mount`, `passwd` hoặc công cụ quản trị dành riêng cho từng bản phân phối
- các binary có file capabilities cấp quyền mạng hoặc hệ thống tệp

Trong một assessment thực tế, những phát hiện này không tự chứng minh được khả năng leo thang đặc quyền, nhưng chúng xác định chính xác các binary đáng để kiểm tra tiếp.

Trong Kubernetes, hãy xác minh thêm rằng cấu hình YAML phản ánh đúng trạng thái thực tế của kernel:

```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```

Các tổ hợp đáng chú ý gồm:

- `allowPrivilegeEscalation: false` trong Pod spec nhưng `NoNewPrivs: 0` trong container
- Có `cap_sys_admin`, khiến trường Kubernetes kém đáng tin cậy hơn nhiều
- `Seccomp: 0` và `NoNewPrivs: 0`, thường cho thấy cấu hình bảo mật runtime bị suy yếu trên diện rộng, thay vì chỉ có một lỗi riêng lẻ

### Ví dụ đầy đủ: Leo thang đặc quyền trong container thông qua setuid

Kiểm soát này thường ngăn **leo thang đặc quyền trong container**, chứ không trực tiếp ngăn thoát ra host. Nếu `NoNewPrivs` là `0` và có một chương trình trợ giúp setuid, hãy kiểm tra cụ thể:

```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```

Nếu có một binary setuid đã biết và hoạt động, hãy thử khởi chạy nó theo cách duy trì quá trình chuyển đổi đặc quyền:

```bash
/bin/su -c id 2>/dev/null
```

Bản thân điều này không giúp thoát khỏi container, nhưng có thể biến foothold có đặc quyền thấp bên trong container thành quyền root trong container. Đây thường là điều kiện tiên quyết để thoát khỏi host về sau thông qua các mount, runtime socket hoặc giao diện tương tác với kernel.

## Kiểm tra

Mục tiêu của các bước kiểm tra này là xác định liệu việc nâng quyền tại thời điểm thực thi có bị chặn hay không, và liệu image vẫn chứa các helper có thể hữu ích nếu không bị chặn.

```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```

Điều gì đáng chú ý ở đây:

- `NoNewPrivs: 1` thường là kết quả an toàn hơn.
- `NoNewPrivs: 0` nghĩa là các đường leo thang đặc quyền dựa trên setuid và file-cap vẫn cần được xem xét.
- `NoNewPrivs: 1` cùng với `Seccomp: 2` thường là dấu hiệu cho thấy cấu hình hardening được chủ động thiết lập hơn.
- Manifest Kubernetes có `allowPrivilegeEscalation: false` là hữu ích, nhưng trạng thái kernel mới là thực tế chính xác.
- Image tối giản, có ít hoặc không có binary setuid/file-cap, khiến kẻ tấn công có ít lựa chọn hậu khai thác hơn ngay cả khi thiếu `no_new_privs`.

## Mặc định của runtime

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Cách thường dùng để nới lỏng thủ công |
| --- | --- | --- | --- |
| Docker Engine | Không được bật theo mặc định | Bật tường minh bằng `--security-opt no-new-privileges=true`; cũng có thiết lập mặc định trên toàn daemon qua `dockerd --no-new-privileges` | bỏ qua flag, `--privileged` |
| Podman | Không được bật theo mặc định | Bật tường minh bằng `--security-opt no-new-privileges` hoặc cấu hình bảo mật tương đương | bỏ qua tùy chọn, `--privileged` |
| Kubernetes | Được kiểm soát bởi chính sách workload | `allowPrivilegeEscalation: false` yêu cầu hiệu lực này, nhưng `privileged: true` và `CAP_SYS_ADMIN` khiến nó vẫn được bật trên thực tế | `allowPrivilegeEscalation: true`, `privileged: true`, thêm `CAP_SYS_ADMIN` |
| containerd / CRI-O dưới Kubernetes | Tuân theo thiết lập workload của Kubernetes / `process.noNewPrivileges` của OCI | Thường được kế thừa từ security context của Pod và chuyển thành cấu hình runtime OCI | tương tự hàng Kubernetes |

Biện pháp bảo vệ này thường vắng mặt chỉ vì chưa ai bật nó, chứ không phải vì runtime không hỗ trợ.

## References

- [1] [Tài liệu kernel Linux: Cờ No New Privileges](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Cấu hình Security Context cho Pod hoặc Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
