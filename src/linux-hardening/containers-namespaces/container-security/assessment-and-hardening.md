# Đánh Giá Và Gia Cố

{{#include ../../../banners/hacktricks-training.md}}

## Tổng Quan

Một cuộc đánh giá container tốt cần trả lời hai câu hỏi song song. Thứ nhất, kẻ tấn công có thể làm gì từ workload hiện tại? Thứ hai, những lựa chọn nào của operator đã khiến điều đó trở nên khả thi? Các công cụ enumeration hỗ trợ trả lời câu hỏi thứ nhất, còn hướng dẫn hardening giúp trả lời câu hỏi thứ hai. Đặt cả hai nội dung trên cùng một trang giúp phần này hữu ích hơn như tài liệu tham khảo thực tế, thay vì chỉ là danh mục các thủ thuật escape.

Một cập nhật thiết thực cho các môi trường hiện đại là nhiều bài viết cũ về container ngầm giả định đang dùng **rootful runtime**, **không cô lập user namespace**, và thường là **cgroup v1**. Những giả định đó hiện không còn an toàn. Trước khi dành thời gian tìm hiểu các primitive escape cũ, hãy xác nhận workload có chạy rootless hoặc dùng userns-remapped không, host có dùng cgroup v2 không, và Kubernetes hoặc runtime hiện có áp dụng các profile seccomp và AppArmor mặc định hay không. Những chi tiết này thường quyết định liệu một kỹ thuật breakout nổi tiếng còn áp dụng được hay không.

## Công Cụ Enumeration

Một số công cụ vẫn hữu ích để nhanh chóng xác định đặc điểm của môi trường container:

- `linpeas` có thể nhận diện nhiều dấu hiệu container, socket được mount, tập capability, filesystem nguy hiểm và gợi ý về breakout.
- `CDK` tập trung riêng vào môi trường container, bao gồm enumeration và một số kiểm tra escape tự động.
- `amicontained` gọn nhẹ, hữu ích để xác định các hạn chế của container, capability, mức độ lộ namespace và các loại breakout có khả năng xảy ra.
- `deepce` là một công cụ enumeration khác dành cho container, với các kiểm tra hướng đến breakout.
- `grype` hữu ích khi phạm vi đánh giá bao gồm rà soát lỗ hổng trong package của image, thay vì chỉ phân tích escape ở runtime.
- `Tracee` hữu ích khi cần **bằng chứng runtime** thay vì chỉ đánh giá posture tĩnh, đặc biệt để phát hiện việc thực thi process đáng ngờ, truy cập file và thu thập sự kiện có nhận biết container.
- `Inspektor Gadget` hữu ích trong các cuộc điều tra Kubernetes và Linux host khi cần khả năng quan sát dựa trên eBPF, liên kết với pod, container, namespace và các khái niệm cấp cao khác.

Giá trị của các công cụ này nằm ở tốc độ và phạm vi bao phủ, không phải độ chắc chắn. Chúng giúp nhanh chóng hé lộ posture tổng thể, nhưng các phát hiện đáng chú ý vẫn cần được diễn giải thủ công dựa trên mô hình runtime, namespace, capability và mount thực tế.

## Ưu Tiên Hardening

Các nguyên tắc hardening quan trọng nhất khá đơn giản về mặt khái niệm, dù cách triển khai khác nhau tùy nền tảng. Tránh container privileged. Tránh mount runtime socket. Không cấp cho container các host path có quyền ghi, trừ khi có lý do thật sự cụ thể. Dùng user namespace hoặc chạy rootless khi khả thi. Loại bỏ toàn bộ capability rồi chỉ thêm lại những capability workload thực sự cần. Duy trì seccomp, AppArmor và SELinux thay vì tắt chúng để khắc phục vấn đề tương thích ứng dụng. Giới hạn tài nguyên để container bị xâm nhập không thể dễ dàng gây từ chối dịch vụ cho host.

Vệ sinh image và quy trình build cũng quan trọng không kém posture runtime. Dùng image tối giản, thường xuyên build lại, quét image, yêu cầu provenance khi khả thi và không để secret trong các layer. Một container chạy non-root với image nhỏ và bề mặt syscall, capability hẹp sẽ dễ bảo vệ hơn nhiều so với một image tiện dụng cồng kềnh chạy bằng root tương đương host và được cài sẵn các công cụ debug.

Đối với Kubernetes, các baseline hardening hiện tại có yêu cầu cụ thể hơn nhiều operator vẫn nghĩ. **Pod Security Standards** tích hợp sẵn xem `restricted` là profile "best practice hiện tại": `allowPrivilegeEscalation` phải là `false`, workload phải chạy non-root, seccomp phải được đặt rõ ràng thành `RuntimeDefault` hoặc `Localhost`, và cần loại bỏ capability một cách triệt để. Khi đánh giá, điều này quan trọng vì một cluster chỉ dùng nhãn `warn` hoặc `audit` có thể trông như đã được harden trên giấy, trong khi thực tế vẫn cho phép các pod rủi ro.<sup>[[1]](#references)</sup>

Khi một Pod có mount service-account token, hãy đánh giá quyền của token **theo từng namespace đích**. Một rule liệt kê Pods trong một namespace không chứng minh được quyền trong namespace khác; token mount trong một Pod khác có thể có quyền khác. Dùng `kubectl auth can-i list pods -n <target-namespace>` và `kubectl auth can-i list secrets -n <target-namespace>` với chính identity đang được đánh giá. Nếu được phép liệt kê Secret, đó là một đầu mối nghiêm trọng vì phản hồi danh sách có thể chứa nội dung Secret, nhưng điều đó không chứng minh rằng có token privileged. Để truy cập host, còn cần có quyền tạo workload phù hợp, admission chấp nhận mount `hostPath` được đề xuất, và security context của node/pod cho phép thao tác file dự kiến. Xem [kiểm tra authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) và [hướng dẫn về leo thang đặc quyền RBAC](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) của Kubernetes.

## Câu Hỏi Triage Hiện Đại

Trước khi xem các trang chuyên về escape, hãy trả lời nhanh những câu hỏi sau:

1. Workload chạy **rootful**, **rootless** hay **userns-remapped**?
2. Node dùng **cgroup v1** hay **cgroup v2**?
3. **seccomp** và **AppArmor/SELinux** được cấu hình rõ ràng hay chỉ kế thừa khi có sẵn?
4. Trong Kubernetes, namespace thực sự đang **enforcing** `baseline` hoặc `restricted`, hay chỉ cảnh báo/kiểm tra audit?

Các kiểm tra hữu ích:

```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```

Điều gì đáng chú ý ở đây:

- Nếu `/proc/self/uid_map` cho thấy root trong container được ánh xạ sang **một dải UID host cao**, nhiều bài viết cũ về quyền ghi của host-root sẽ kém liên quan hơn, vì root trong container không còn tương đương với host-root.
- Nếu `/sys/fs/cgroup` là `cgroup2fs`, các bài viết cũ chỉ áp dụng cho **cgroup v1**, chẳng hạn lạm dụng `release_agent`, không nên là phỏng đoán đầu tiên của bạn.
- Nếu seccomp và AppArmor chỉ được kế thừa một cách ngầm định, tính tương thích giữa các môi trường có thể thấp hơn mức mà người phòng thủ kỳ vọng. Trong Kubernetes, thiết lập tường minh `RuntimeDefault` thường tốt hơn là âm thầm dựa vào mặc định của node.
- Nếu `supplementalGroupsPolicy` được đặt thành `Strict`, pod sẽ tránh âm thầm kế thừa các thành viên nhóm bổ sung từ `/etc/group` bên trong image, giúp hành vi truy cập volume và file dựa trên nhóm dễ dự đoán hơn.
- Nên kiểm tra trực tiếp các nhãn namespace như `pod-security.kubernetes.io/enforce=restricted`. `warn` và `audit` hữu ích, nhưng chúng không ngăn một pod có rủi ro được tạo.

## Phân loại nhanh baseline runtime

Baseline runtime là bước kiểm tra nhanh giúp bạn xác định container trông giống một workload được cô lập thông thường hay một foothold trong control plane có thể tác động đến host. Bước này cần thu thập đủ thông tin để ưu tiên nội dung tiếp theo cần xem: lạm dụng runtime socket, host mount, namespace, cgroup, capability hoặc rà soát image-secret.

Các bước kiểm tra hữu ích bên trong một workload:

```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

Diễn giải:

- `memory.max` / `pids.max` bị thiếu hoặc không giới hạn cho thấy các biện pháp kiểm soát phạm vi ảnh hưởng còn yếu, ngay cả khi không có một lối thoát rõ ràng.
- Một root shell với `NoNewPrivs: 0`, capabilities rộng và seccomp dễ dãi đáng chú ý hơn nhiều so với workload non-root bị giới hạn chặt chẽ.
- Runtime socket và host mount có quyền ghi thường cần được ưu tiên hơn kernel exploit vì chúng đã cung cấp sẵn đường dẫn để kiểm soát hệ thống quản lý hoặc filesystem.
- Namespace PID, network, IPC hoặc cgroup dùng chung không phải lúc nào cũng tự tạo thành lối thoát hoàn chỉnh, nhưng chúng giúp tìm bước tiếp theo dễ hơn.

## Ví dụ về cạn kiệt tài nguyên

Các biện pháp kiểm soát tài nguyên không hào nhoáng, nhưng là một phần của bảo mật container vì chúng giới hạn phạm vi ảnh hưởng khi bị xâm nhập. Không có giới hạn về memory, CPU hoặc PID, chỉ một shell đơn giản cũng có thể làm suy giảm host hoặc các workload lân cận.

Ví dụ về các bài kiểm tra ảnh hưởng đến host:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Các ví dụ này hữu ích vì cho thấy không phải mọi hậu quả nguy hiểm từ container đều là một “escape” hoàn chỉnh. Giới hạn cgroup yếu vẫn có thể biến việc thực thi mã thành tác động thực tế đến hoạt động.

Trong các môi trường chạy Kubernetes, hãy kiểm tra xem các biện pháp kiểm soát tài nguyên có tồn tại hay không trước khi xem DoS chỉ là giả thuyết:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Công cụ tăng cường bảo mật

Trong các môi trường tập trung vào Docker, `docker-bench-security` vẫn là một baseline hữu ích để kiểm tra host, vì công cụ này kiểm tra các vấn đề cấu hình phổ biến dựa trên hướng dẫn benchmark được công nhận rộng rãi. Cần xem xét riêng các thông báo bảo mật về runtime, vì benchmark cấu hình không thể phát hiện liệu runtime đã cài đặt có bị ảnh hưởng bởi một lỗ hổng mới được công bố hay không. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

Công cụ này không thay thế cho việc lập mô hình mối đe dọa, nhưng vẫn hữu ích để phát hiện các cấu hình mặc định sơ suất của daemon, mount, network và runtime tích tụ theo thời gian.

Đối với Kubernetes và các môi trường sử dụng nhiều runtime, hãy kết hợp kiểm tra tĩnh với khả năng giám sát runtime:

- `Tracee` hữu ích cho việc phát hiện trong runtime có nhận biết container và điều tra nhanh khi bạn cần xác nhận workload bị xâm phạm thực sự đã truy cập những gì.
- `Inspektor Gadget` hữu ích khi quá trình đánh giá cần telemetry ở cấp kernel được ánh xạ về pod, container, hoạt động DNS, thực thi tệp hoặc hành vi mạng.

## Checks

Dùng các lệnh sau để kiểm tra sơ bộ nhanh trong quá trình đánh giá:

```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

Điều gì đáng chú ý ở đây:

- Một tiến trình root có nhiều capabilities và `Seccomp: 0` cần được chú ý ngay lập tức.
- Một tiến trình root đồng thời có **ánh xạ UID 1:1** đáng chú ý hơn nhiều so với "root" bên trong một user namespace được cô lập đúng cách.
- `cgroup2fs` thường có nghĩa là nhiều chuỗi khai thác thoát khỏi **cgroup v1** đời cũ không phải là điểm khởi đầu tốt nhất, trong khi thiếu `memory.max` hoặc `pids.max` vẫn cho thấy các biện pháp kiểm soát phạm vi ảnh hưởng còn yếu.
- Các mount đáng ngờ và socket runtime thường giúp gây tác động nhanh hơn bất kỳ kernel exploit nào.
- Sự kết hợp giữa cấu hình runtime yếu và giới hạn tài nguyên yếu thường cho thấy môi trường container nhìn chung dễ dãi, thay vì chỉ có một sai sót riêng lẻ.

## References

- [1] [Các tiêu chuẩn bảo mật Pod của Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Thông báo bảo mật Docker: Nhiều lỗ hổng trong runc, BuildKit và Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
