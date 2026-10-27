# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Tổng quan

UTS namespace cô lập **hostname** và **tên miền NIS** mà tiến trình nhìn thấy. Thoạt nhìn, điều này có vẻ không đáng kể so với mount, PID hoặc user namespace, nhưng đây là một phần giúp container trông như một máy chủ riêng. Bên trong namespace, workload có thể nhìn thấy và đôi khi thay đổi hostname chỉ áp dụng trong namespace đó, thay vì hostname toàn cục của máy. <sup>[[1]](#references)</sup>

Bản thân điều này thường không phải là trọng tâm của một câu chuyện thoát container. Tuy nhiên, khi UTS namespace của host được chia sẻ, một tiến trình có đủ đặc quyền có thể tác động đến các thiết lập liên quan đến danh tính của host, điều này có thể ảnh hưởng đến hoạt động vận hành và đôi khi cả bảo mật.

## Lab

Bạn có thể tạo UTS namespace bằng lệnh:

```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```

Thay đổi hostname chỉ áp dụng trong namespace đó và không làm thay đổi hostname toàn cục của host. Đây là minh họa đơn giản nhưng hiệu quả về tính cô lập.

## Cách sử dụng khi chạy

Các container thông thường có UTS namespace riêng. Docker và Podman có thể tham gia UTS namespace của host thông qua `--uts=host`, còn các runtime cấp thấp hơn có thể bỏ UTS namespace khỏi cấu hình OCI để kế thừa namespace của runtime. Tuy nhiên, trong hầu hết trường hợp, UTS isolation riêng chỉ là một phần trong cấu hình container thông thường và hầu như không cần người vận hành quan tâm. <sup>[[2]](#references)</sup>

## Tác động bảo mật

Mặc dù UTS namespace thường không phải namespace nguy hiểm nhất khi được chia sẻ, nó vẫn góp phần bảo đảm tính toàn vẹn của ranh giới container. Nếu UTS namespace của host bị lộ và tiến trình có đủ đặc quyền cần thiết, tiến trình đó có thể thay đổi thông tin liên quan đến hostname của host. Điều này có thể ảnh hưởng đến việc giám sát, ghi log, các giả định vận hành hoặc những script đưa ra quyết định tin cậy dựa trên dữ liệu nhận dạng host.

## Lạm dụng

Nếu UTS namespace của host được chia sẻ, câu hỏi thực tế là liệu tiến trình có thể sửa đổi các thiết lập nhận dạng host hay chỉ có thể đọc chúng:

```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```

Nếu container cũng có đủ đặc quyền cần thiết, hãy kiểm tra xem có thể thay đổi hostname hay không:

```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```

Đây chủ yếu là vấn đề về tính toàn vẹn và ảnh hưởng đến hoạt động, chứ không phải một cuộc escape hoàn chỉnh, nhưng vẫn cho thấy container có thể trực tiếp tác động đến một thuộc tính toàn cục của host.

Tác động:

- giả mạo danh tính host
- gây nhầm lẫn cho log, hệ thống giám sát hoặc tự động hóa vốn tin cậy hostname
- thường không tự nó dẫn đến escape hoàn chỉnh, trừ khi kết hợp với các điểm yếu khác

Trong các môi trường kiểu Docker, một mẫu phát hiện hữu ích ở phía host là:

```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```

Các container hiển thị `UTSMode=host` đang dùng chung UTS namespace với máy chủ và cần được xem xét kỹ hơn nếu chúng cũng có các capability cho phép gọi `sethostname()` hoặc `setdomainname()`.

## Kiểm tra

Các lệnh này đủ để xác định workload có chế độ xem hostname riêng hay đang dùng chung UTS namespace với máy chủ.

```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```

Điều gì đáng chú ý ở đây:

- Các namespace identifier trùng với một tiến trình trên host có thể cho thấy đang dùng chung UTS với host.
- Nếu việc thay đổi hostname ảnh hưởng đến những thứ ngoài chính container, workload có ảnh hưởng đến danh tính của host nhiều hơn mức cần thiết.
- Đây thường là phát hiện có mức ưu tiên thấp hơn các vấn đề về PID, mount hoặc user namespace, nhưng vẫn xác nhận mức độ cô lập thực sự của tiến trình.

Trong hầu hết môi trường, UTS namespace nên được xem là một lớp cô lập hỗ trợ. Đây hiếm khi là điều đầu tiên bạn kiểm tra khi tìm cách breakout, nhưng vẫn là một phần trong tính nhất quán và an toàn tổng thể của góc nhìn container.

## References

- [1] [`uts_namespaces(7)` - Linux manual page](https://man7.org/linux/man-pages/man7/uts_namespaces.7.html)
- [2] [Open Container Initiative - Linux container namespaces](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#namespaces)
{{#include ../../../../../banners/hacktricks-training.md}}
