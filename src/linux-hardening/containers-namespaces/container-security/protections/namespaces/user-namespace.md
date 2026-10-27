# Không gian tên người dùng

{{#include ../../../../../banners/hacktricks-training.md}}

## Tổng quan

Không gian tên người dùng thay đổi ý nghĩa của ID người dùng và nhóm bằng cách cho phép kernel ánh xạ các ID bên trong không gian tên sang các ID khác bên ngoài nó. Đây là một trong những biện pháp bảo vệ container hiện đại quan trọng nhất vì nó trực tiếp giải quyết vấn đề lớn nhất trong lịch sử của container cổ điển: **root bên trong container từng gần với root trên host đến mức đáng lo ngại**. <sup>[[1]](#references)</sup>

Với không gian tên người dùng, một tiến trình có thể chạy với UID 0 bên trong container nhưng vẫn tương ứng với một dải UID không có đặc quyền trên host. Điều đó có nghĩa là tiến trình có thể hoạt động như root trong nhiều tác vụ bên trong container, nhưng ít quyền lực hơn nhiều theo góc nhìn của host. Điều này không giải quyết mọi vấn đề bảo mật của container, nhưng làm thay đổi đáng kể hậu quả của việc container bị xâm nhập.

## Cách hoạt động

Không gian tên người dùng có các tệp ánh xạ như `/proc/self/uid_map` và `/proc/self/gid_map`, mô tả cách các ID trong không gian tên được ánh xạ sang ID của không gian tên cha. Nếu root bên trong không gian tên được ánh xạ sang một UID không có đặc quyền trên host, thì các thao tác vốn cần root thực sự trên host sẽ không còn mang mức quyền tương đương. Đây là lý do không gian tên người dùng đóng vai trò cốt lõi trong **container không cần root** và là một trong những khác biệt lớn nhất giữa cấu hình mặc định dùng root của container đời cũ với các thiết kế hiện đại theo nguyên tắc đặc quyền tối thiểu. <sup>[[1]](#references)</sup>

Điểm này tinh tế nhưng rất quan trọng: root bên trong container không bị loại bỏ mà được **ánh xạ**. Tiến trình vẫn có môi trường giống root ở cục bộ, nhưng host không nên xem nó là root đầy đủ.

## Lab

Một phép thử thủ công là:

```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```

Điều này khiến user hiện tại xuất hiện dưới dạng root bên trong namespace, nhưng vẫn không phải root trên host bên ngoài namespace. Đây là một trong những ví dụ đơn giản nhất để hiểu vì sao user namespace lại hữu ích đến vậy.

Trong container, bạn có thể so sánh ánh xạ hiển thị bằng:

```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```

Kết quả chính xác phụ thuộc vào việc engine sử dụng user namespace remapping hay cấu hình rootful truyền thống hơn.

Bạn cũng có thể đọc mapping từ phía host bằng cách:

```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```

## Cách sử dụng trong runtime

Rootless Podman là một trong những ví dụ rõ ràng nhất về việc xem user namespaces như một cơ chế bảo mật cốt lõi. Rootless Docker cũng phụ thuộc vào chúng. Hỗ trợ `userns-remap` của Docker cũng tăng cường an toàn trong các triển khai daemon chạy root, dù nhiều triển khai tắt tính năng này vì lý do tương thích. Kubernetes có thể tạo user namespace cho một Pod khi hỗ trợ và bật `hostUsers: false`, nhưng mức độ áp dụng và cấu hình mặc định vẫn khác nhau tùy runtime, bản phân phối và chính sách cụm. Các hệ thống Incus và LXC cũng phụ thuộc nhiều vào việc dịch UID/GID và các khái niệm ánh xạ ID. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup>

Xu hướng chung rất rõ ràng: những môi trường sử dụng user namespaces một cách nghiêm túc thường có câu trả lời thỏa đáng hơn cho câu hỏi “root trong container thực sự có nghĩa là gì?” so với những môi trường không sử dụng chúng.

## Chi tiết ánh xạ nâng cao

Khi một tiến trình không có đặc quyền ghi vào `uid_map` hoặc `gid_map`, kernel áp dụng các quy tắc nghiêm ngặt hơn so với khi một tiến trình cha có đặc quyền namespace ghi vào đó. Chỉ cho phép các ánh xạ hạn chế, và với `gid_map`, tiến trình ghi thường cần tắt `setgroups(2)` trước:

```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```

Chi tiết này quan trọng vì nó giải thích tại sao việc thiết lập user namespace đôi khi thất bại trong các thử nghiệm rootless và tại sao runtime cần logic hỗ trợ cẩn thận khi phân quyền UID/GID.

Một tính năng nâng cao khác là **ID-mapped mount**. Thay vì thay đổi quyền sở hữu trên đĩa, ID-mapped mount áp dụng ánh xạ user namespace cho một mount để quyền sở hữu hiển thị theo cách đã được ánh xạ qua chế độ xem của mount đó. Điều này đặc biệt phù hợp với các thiết lập rootless và runtime hiện đại vì cho phép sử dụng các đường dẫn dùng chung trên host mà không cần thực hiện thao tác `chown` đệ quy. Về mặt bảo mật, tính năng này thay đổi mức độ có thể ghi của một bind mount khi nhìn từ bên trong namespace, dù nó không ghi lại metadata của filesystem bên dưới.

Cuối cùng, hãy nhớ rằng khi một tiến trình tạo hoặc vào một user namespace mới, nó nhận được đầy đủ tập capability **bên trong namespace đó**. Điều đó không có nghĩa là nó đột nhiên có quyền trên toàn host. Điều đó có nghĩa là các capability này chỉ có thể được sử dụng trong phạm vi mô hình namespace và các biện pháp bảo vệ khác cho phép. Đây là lý do `unshare -U` có thể đột nhiên cho phép thực hiện thao tác mount hoặc các thao tác đặc quyền trong phạm vi namespace mà không trực tiếp làm biến mất ranh giới root của host.

## Cấu hình sai

Điểm yếu chính đơn giản là không sử dụng user namespace trong những môi trường khả thi. Nếu root trong container được ánh xạ quá trực tiếp thành root trên host, các mount host có quyền ghi và thao tác kernel đặc quyền sẽ trở nên nguy hiểm hơn nhiều. Một vấn đề khác là buộc phải chia sẻ user namespace của host hoặc tắt ánh xạ lại vì lý do tương thích mà không nhận ra những thay đổi lớn đối với ranh giới tin cậy.

Cũng cần xem xét user namespace cùng với các phần còn lại của mô hình. Ngay cả khi chúng đang hoạt động, việc để lộ rộng rãi API runtime hoặc cấu hình runtime rất yếu vẫn có thể cho phép leo thang đặc quyền thông qua các đường khác. Tuy nhiên, nếu không có chúng, nhiều dạng khai thác thoát container kiểu cũ sẽ dễ thực hiện hơn nhiều.

## Lạm dụng

Nếu container chạy rootful mà không có sự phân tách user namespace, bind mount host có quyền ghi sẽ nguy hiểm hơn rất nhiều vì tiến trình có thể thực sự ghi với quyền root trên host. Tương tự, các capability nguy hiểm cũng có ý nghĩa lớn hơn. Kẻ tấn công không còn phải vượt qua ranh giới ánh xạ một cách vất vả vì ranh giới này hầu như không tồn tại.

Cần kiểm tra sớm sự hiện diện hay vắng mặt của user namespace khi đánh giá một đường thoát container. Việc này không trả lời mọi câu hỏi, nhưng lập tức cho thấy liệu “root trong container” có ảnh hưởng trực tiếp đến host hay không.

Mẫu lạm dụng thiết thực nhất là xác nhận ánh xạ, sau đó kiểm tra ngay liệu nội dung được mount từ host có thể ghi được bằng các quyền có liên quan đến host hay không:

```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```

Nếu tệp được tạo với quyền root thực trên host, thì cơ chế cô lập user namespace về cơ bản không còn hiệu lực đối với đường dẫn đó. Khi ấy, các cách lạm dụng tệp host kiểu cổ điển trở nên khả thi:

```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```

Một cách xác nhận an toàn hơn trong quá trình đánh giá trực tiếp là ghi một dấu đánh dấu vô hại thay vì sửa đổi các tệp quan trọng:

```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```

Các kiểm tra này quan trọng vì chúng nhanh chóng trả lời câu hỏi thực sự: root trong container này có ánh xạ đủ gần với root trên host để một mount host có quyền ghi lập tức trở thành đường dẫn chiếm quyền host hay không?

### Ví dụ đầy đủ: Lấy lại các capabilities cục bộ trong namespace

Nếu seccomp cho phép `unshare` và môi trường cho phép tạo user namespace mới, tiến trình có thể lấy lại đầy đủ bộ capabilities bên trong namespace mới đó:

```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```

Điều này tự nó không phải là host escape. Lý do vấn đề này quan trọng là user namespaces có thể kích hoạt lại các hành động đặc quyền trong phạm vi namespace, rồi kết hợp với weak mounts, kernel dễ bị tổn thương hoặc runtime surface bị phơi bày kém.

## Kiểm tra

Các lệnh này nhằm trả lời câu hỏi quan trọng nhất trên trang này: root bên trong container này được ánh xạ thành gì trên host?

```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```

Điều đáng chú ý ở đây:

- Nếu process có UID 0 và các maps cho thấy ánh xạ trực tiếp hoặc rất gần với root trên host, container nguy hiểm hơn nhiều.
- Nếu root được ánh xạ vào một dải không đặc quyền trên host, đó là baseline an toàn hơn nhiều và thường cho thấy có sự cô lập user namespace thực sự.
- Các file mapping hữu ích hơn chỉ riêng `id`, vì `id` chỉ hiển thị danh tính trong namespace.

Nếu workload chạy với UID 0 và mapping cho thấy UID này tương ứng gần như với root trên host, bạn nên đánh giá các quyền khác của container một cách nghiêm ngặt hơn nhiều.

## References

- [1] [`user_namespaces(7)` - trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [2] [Tài liệu Docker - Cô lập container bằng user namespace](https://docs.docker.com/engine/security/userns-remap/)
- [3] [Tài liệu Kubernetes - User namespaces](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)
- [4] [Tài liệu Incus - Bảo mật và container không đặc quyền](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../../banners/hacktricks-training.md}}
