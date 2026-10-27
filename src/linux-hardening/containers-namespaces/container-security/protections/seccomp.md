# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Tổng quan

**seccomp** là cơ chế cho phép kernel áp dụng bộ lọc lên các syscall mà một process có thể gọi. Trong môi trường container, seccomp thường được dùng ở chế độ lọc để process không chỉ bị đánh dấu là “bị hạn chế” một cách mơ hồ, mà phải tuân theo một chính sách syscall cụ thể. Điều này rất quan trọng vì nhiều vụ thoát khỏi container cần truy cập đến những giao diện kernel rất cụ thể. Nếu process không thể gọi thành công các syscall liên quan, một nhóm lớn các cuộc tấn công sẽ bị ngăn chặn trước khi cần xét đến các chi tiết về namespace hay capability.

Mô hình tư duy cốt lõi rất đơn giản: namespace quyết định **process có thể nhìn thấy những gì**, capability quyết định **những hành động đặc quyền nào process được phép thử thực hiện**, còn seccomp quyết định **kernel có chấp nhận điểm vào syscall cho hành động được thử hay không**. Đây là lý do seccomp thường ngăn chặn các cuộc tấn công vốn có vẻ khả thi nếu chỉ xét đến capability.

## Tác động bảo mật

Nhiều bề mặt tấn công nguy hiểm của kernel chỉ có thể truy cập thông qua một số lượng tương đối nhỏ syscall. Các ví dụ thường quan trọng trong việc tăng cường bảo mật container gồm `mount`, `unshare`, `clone` hoặc `clone3` với các flag cụ thể, `bpf`, `ptrace`, `keyctl` và `perf_event_open`. Kẻ tấn công có thể gọi các syscall đó có khả năng tạo namespace mới, thao túng các subsystem của kernel hoặc tương tác với bề mặt tấn công mà một container ứng dụng thông thường hoàn toàn không cần đến.

Đây là lý do các profile seccomp mặc định của runtime rất quan trọng. Chúng không chỉ là “lớp bảo vệ bổ sung”. Trong nhiều môi trường, chúng tạo nên sự khác biệt giữa một container có thể sử dụng phần lớn chức năng của kernel và một container bị giới hạn trong phạm vi syscall gần với nhu cầu thực sự của ứng dụng hơn.

## Các chế độ và cách xây dựng bộ lọc

seccomp từng có chế độ nghiêm ngặt, trong đó chỉ còn một tập syscall rất nhỏ khả dụng, nhưng chế độ liên quan đến các runtime container hiện đại là chế độ lọc seccomp, thường được gọi là **seccomp-bpf**. Theo mô hình này, kernel đánh giá một chương trình bộ lọc để quyết định syscall sẽ được cho phép, bị từ chối kèm errno, bị chặn lại, được ghi log hay khiến process bị kết thúc.<sup>[[1]](#references)</sup> Các runtime container sử dụng cơ chế này vì nó đủ linh hoạt để chặn các nhóm syscall nguy hiểm trên diện rộng mà vẫn cho phép ứng dụng hoạt động bình thường.

Hai ví dụ cấp thấp sau đây rất hữu ích vì chúng giúp cơ chế này trở nên cụ thể, thay vì có vẻ như một điều kỳ bí. Chế độ nghiêm ngặt minh họa mô hình cũ: “chỉ một tập syscall tối thiểu còn hoạt động”:

```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
  int output = open("output.txt", O_WRONLY);
  const char *val = "test";
  prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
  write(output, val, strlen(val) + 1);
  open("output.txt", O_RDONLY);
}
```

Lệnh `open` cuối cùng khiến tiến trình bị kill vì nó không thuộc tập tối thiểu của strict mode.

Ví dụ về bộ lọc libseccomp cho thấy mô hình chính sách hiện đại rõ hơn:

```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
    SCMP_A0(SCMP_CMP_EQ, 1),
    SCMP_A2(SCMP_CMP_LE, 512));
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
    SCMP_A0(SCMP_CMP_NE, 1));
  seccomp_load(ctx);
  seccomp_release(ctx);
  printf("pid=%d\n", getpid());
}
```

Đây là kiểu policy mà hầu hết độc giả nên hình dung khi nghĩ đến các seccomp profile lúc runtime.

## Phòng thực hành

Một cách đơn giản để xác nhận seccomp đang hoạt động trong container là:

```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```

Bạn cũng có thể thử một thao tác mà các profile mặc định thường hạn chế:

```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```

Nếu container đang chạy với seccomp profile mặc định thông thường, các thao tác kiểu `unshare` thường bị chặn. Đây là một minh họa hữu ích vì nó cho thấy dù công cụ userspace có trong image, đường dẫn kernel mà công cụ cần vẫn có thể không khả dụng.
Nếu container đang chạy với seccomp profile mặc định thông thường, các thao tác kiểu `unshare` thường bị chặn, ngay cả khi công cụ userspace có trong image.

Để kiểm tra trạng thái tiến trình tổng quát hơn, hãy chạy:

```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```

## Cách sử dụng khi chạy

Docker hỗ trợ cả seccomp profile mặc định lẫn tùy chỉnh, đồng thời cho phép quản trị viên tắt chúng bằng `--security-opt seccomp=unconfined`.<sup>[[2]](#references)</sup> Podman có hỗ trợ tương tự và thường kết hợp seccomp với chế độ chạy rootless, tạo nên cấu hình mặc định rất hợp lý. Kubernetes cung cấp seccomp thông qua cấu hình workload, trong đó `RuntimeDefault` thường là cơ sở hợp lý, còn `Unconfined` nên được xem là ngoại lệ cần có lý do chính đáng thay vì một tùy chọn bật/tắt cho tiện.<sup>[[3]](#references)</sup>

Trong các môi trường dựa trên containerd và CRI-O, quy trình cụ thể có nhiều lớp hơn, nhưng nguyên tắc vẫn như nhau: engine hoặc trình điều phối cấp cao hơn quyết định điều gì cần được thực hiện, rồi runtime cuối cùng cài đặt chính sách seccomp tương ứng cho tiến trình container. Kết quả vẫn phụ thuộc vào cấu hình runtime cuối cùng được áp dụng cho kernel.

### Ví dụ về chính sách tùy chỉnh

Docker và các engine tương tự có thể tải seccomp profile tùy chỉnh từ JSON. Ví dụ tối giản sau đây chặn `chmod` nhưng cho phép mọi thứ khác:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "name": "chmod",
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
```

Được áp dụng với:

```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```

Lệnh thất bại với `Operation not permitted`, cho thấy hạn chế này đến từ chính sách syscall chứ không chỉ từ quyền truy cập tệp thông thường. Khi hardening thực tế, allowlist thường mạnh hơn các thiết lập mặc định dễ dãi kèm một blacklist nhỏ.

## Cấu hình sai

Sai lầm nghiêm trọng nhất là đặt seccomp thành **unconfined** vì ứng dụng gặp lỗi khi dùng chính sách mặc định. Điều này thường xảy ra trong quá trình khắc phục sự cố và rất nguy hiểm nếu trở thành giải pháp lâu dài. Khi filter bị gỡ bỏ, nhiều primitive thoát container dựa trên syscall lại có thể được sử dụng, đặc biệt khi container còn có các capability mạnh hoặc chia sẻ namespace với host.

Một vấn đề phổ biến khác là dùng **custom permissive profile** được sao chép từ một blog hoặc giải pháp tình thế nội bộ mà không được rà soát kỹ. Đôi khi các nhóm vẫn giữ lại gần như mọi syscall nguy hiểm chỉ vì profile được xây dựng theo hướng “đừng để ứng dụng gặp lỗi” thay vì “chỉ cấp những gì ứng dụng thực sự cần”. Một quan niệm sai lầm nữa là cho rằng seccomp kém quan trọng hơn đối với container không chạy dưới quyền root. Trên thực tế, vẫn còn rất nhiều bề mặt tấn công của kernel liên quan, ngay cả khi process không có UID 0.

## Lạm dụng

Nếu seccomp không được bật hoặc bị làm suy yếu nghiêm trọng, attacker có thể gọi các syscall tạo namespace, mở rộng bề mặt tấn công kernel có thể tiếp cận thông qua `bpf` hoặc `perf_event_open`, lạm dụng `keyctl`, hoặc kết hợp các đường dẫn syscall này với những capability nguy hiểm như `CAP_SYS_ADMIN`. Trong nhiều cuộc tấn công thực tế, seccomp không phải là biện pháp kiểm soát duy nhất bị thiếu, nhưng việc thiếu nó rút ngắn đáng kể đường khai thác vì loại bỏ một trong số ít lớp phòng thủ có thể chặn syscall rủi ro trước khi phần còn lại của mô hình phân quyền phát huy tác dụng.

Cách kiểm tra thực tế hữu ích nhất là thử chính xác các nhóm syscall mà profile mặc định thường chặn. Nếu chúng đột nhiên hoạt động, trạng thái bảo mật của container đã thay đổi đáng kể:

```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```

Nếu có `CAP_SYS_ADMIN` hoặc capability mạnh khác, hãy kiểm tra xem seccomp có phải là rào cản duy nhất còn thiếu trước khi lạm dụng mount hay không:

```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```

Trên một số mục tiêu, lợi ích trước mắt không phải là escape hoàn toàn mà là thu thập thông tin và mở rộng attack surface của kernel. Các lệnh này giúp xác định liệu có thể truy cập các đường dẫn syscall đặc biệt nhạy cảm hay không:

```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```

Nếu seccomp không được bật và container cũng có các đặc quyền khác, lúc đó bạn nên chuyển sang các kỹ thuật breakout cụ thể hơn đã được ghi lại trong các trang cũ về container escape.

### Ví dụ đầy đủ: seccomp là thứ duy nhất ngăn `unshare`

Trên nhiều mục tiêu, việc gỡ bỏ seccomp có thể khiến các syscall tạo namespace hoặc mount đột nhiên hoạt động. Nếu container cũng có `CAP_SYS_ADMIN`, chuỗi thao tác sau có thể thực hiện được:

```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
  mount -t tmpfs tmpfs /tmp/nsroot &&
  mkdir -p /tmp/nsroot/proc &&
  mount -t proc proc /tmp/nsroot/proc &&
  mount | grep /tmp/nsroot
'
```

Tự nó chưa phải là một vụ thoát khỏi host, nhưng nó cho thấy seccomp chính là rào cản ngăn chặn việc khai thác liên quan đến mount.

### Ví dụ đầy đủ: Tắt seccomp + `release_agent` của cgroup v1

Nếu seccomp bị tắt và container có thể mount các hierarchy của cgroup v1, kỹ thuật `release_agent` trong phần cgroups sẽ khả thi:

```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
  mkdir /tmp/c
  mount -t cgroup -o memory none /tmp/c
  echo 1 > /tmp/c/notify_on_release
  echo /proc/self/exe > /tmp/c/release_agent
  (sleep 1; echo 0 > /tmp/c/cgroup.procs) &
  while true; do sleep 1; done
'
```

Đây không phải là exploit chỉ nhắm vào seccomp. Điểm mấu chốt là khi seccomp không còn giới hạn, các chuỗi breakout dùng nhiều syscall vốn bị chặn trước đây có thể bắt đầu hoạt động đúng như mô tả.

## Kiểm tra

Mục đích của các bước kiểm tra này là xác định seccomp có đang được kích hoạt hay không, `no_new_privs` có đi kèm hay không, và cấu hình runtime có cho thấy seccomp bị tắt một cách rõ ràng hay không.

```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```

Điều đáng chú ý ở đây:

- Giá trị `Seccomp` khác 0 nghĩa là tính năng lọc đang hoạt động; `0` thường có nghĩa là không có biện pháp bảo vệ seccomp.
- Nếu các tùy chọn bảo mật của runtime có `seccomp=unconfined`, workload đã mất đi một trong những biện pháp phòng thủ ở cấp syscall hữu ích nhất.
- `NoNewPrivs` không phải bản thân seccomp, nhưng khi thấy cả hai cùng lúc thường cho thấy cấu hình hardening được cân nhắc kỹ hơn so với khi không có cả hai.

Nếu một container đã có các mount đáng ngờ, capabilities quá rộng hoặc dùng chung namespace của host, đồng thời seccomp cũng ở trạng thái unconfined, thì nên xem tổ hợp này là một tín hiệu leo thang nghiêm trọng. Container có thể vẫn không dễ bị phá vỡ, nhưng số điểm vào kernel mà attacker có thể truy cập đã tăng mạnh.

## Mặc định của runtime

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Cách làm suy yếu thường gặp |
| --- | --- | --- | --- |
| Docker Engine | Thường được bật theo mặc định | Sử dụng seccomp profile mặc định tích hợp của Docker, trừ khi được ghi đè | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Thường được bật theo mặc định | Áp dụng seccomp profile mặc định của runtime, trừ khi được ghi đè | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Không được đảm bảo theo mặc định** | Nếu không đặt `securityContext.seccompProfile`, mặc định là `Unconfined`, trừ khi kubelet bật `--seccomp-default`; nếu không, phải đặt rõ `RuntimeDefault` hoặc `Localhost` | `securityContext.seccompProfile.type: Unconfined`, không đặt seccomp trên các cluster không bật `seccompDefault`, `privileged: true` |
| containerd / CRI-O trên Kubernetes | Tuân theo cài đặt của node và Pod trong Kubernetes | Profile của runtime được sử dụng khi Kubernetes yêu cầu `RuntimeDefault` hoặc khi bật cơ chế đặt mặc định seccomp của kubelet | Tương tự hàng Kubernetes; cấu hình CRI/OCI trực tiếp cũng có thể bỏ hẳn seccomp |

Hành vi của Kubernetes là điều thường khiến các operator bất ngờ nhất. Ở nhiều cluster, seccomp vẫn chưa được áp dụng trừ khi Pod yêu cầu hoặc kubelet được cấu hình để mặc định dùng `RuntimeDefault`.<sup>[[3]](#references)</sup>

## References

- [1] [Tài liệu kernel Linux: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Tài liệu Docker: Seccomp security profile cho Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Tài liệu Kubernetes: Hạn chế syscall của container bằng seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)
{{#include ../../../../banners/hacktricks-training.md}}
