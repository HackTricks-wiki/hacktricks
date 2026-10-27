# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Tổng quan

IPC namespace cô lập **các đối tượng IPC System V** và **hàng đợi thông điệp POSIX**. Các đối tượng này bao gồm các phân đoạn bộ nhớ chia sẻ, semaphore và hàng đợi thông điệp mà nếu không được cô lập thì sẽ hiển thị với các tiến trình không liên quan khác trên host. Trên thực tế, điều này ngăn container tùy tiện gắn vào các đối tượng IPC thuộc về workload khác hoặc host. <sup>[[1]](#references)</sup>

So với mount, PID hoặc user namespace, IPC namespace ít được nhắc đến hơn, nhưng điều đó không có nghĩa là nó không quan trọng. Bộ nhớ chia sẻ và các cơ chế IPC liên quan có thể chứa dữ liệu trạng thái rất hữu ích. Nếu IPC namespace của host bị lộ, workload có thể nhìn thấy các đối tượng điều phối giữa tiến trình hoặc dữ liệu vốn không được phép vượt qua ranh giới container.

## Cách hoạt động

Khi runtime tạo một IPC namespace mới, tiến trình sẽ có một tập định danh IPC riêng biệt. Điều này có nghĩa là các lệnh như `ipcs` chỉ hiển thị những đối tượng có trong namespace đó. Nếu thay vào đó container tham gia IPC namespace của host, các đối tượng này sẽ nằm trong một chế độ xem toàn cục dùng chung. Các đối tượng bộ nhớ chia sẻ POSIX được hiển thị thông qua `tmpfs`, thường được mount tại `/dev/shm`. <sup>[[1]](#references)</sup> <sup>[[2]](#references)</sup>

Điều này đặc biệt quan trọng trong các môi trường mà ứng dụng hoặc dịch vụ sử dụng nhiều bộ nhớ chia sẻ. Ngay cả khi chỉ riêng IPC không giúp container thoát ra ngoài, namespace vẫn có thể làm lộ thông tin hoặc cho phép gây nhiễu giữa các tiến trình, qua đó hỗ trợ đáng kể cho một cuộc tấn công tiếp theo.

## Thực hành

Bạn có thể tạo một IPC namespace riêng bằng lệnh:

```bash
sudo unshare --ipc --fork bash
ipcs
```

Và so sánh hành vi khi chạy với:

```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```

## Cách sử dụng khi chạy

Docker và Podman cô lập IPC theo mặc định. Kubernetes thường cấp cho Pod một IPC namespace riêng, được các container trong cùng Pod dùng chung nhưng mặc định không dùng chung với host. Có thể chia sẻ IPC với host thông qua `hostIPC`, nhưng cần xem đây là sự suy giảm đáng kể về khả năng cô lập, chứ không phải một tùy chọn runtime nhỏ. <sup>[[3]](#references)</sup>

## Cấu hình sai

Sai lầm dễ thấy là dùng `--ipc=host` hoặc `hostIPC: true`. Việc này có thể được thực hiện để tương thích với phần mềm cũ hoặc cho tiện, nhưng làm thay đổi đáng kể mô hình tin cậy. Một vấn đề thường gặp khác là bỏ qua IPC vì nó có vẻ ít nghiêm trọng hơn host PID hoặc host networking. Trên thực tế, nếu workload xử lý trình duyệt, cơ sở dữ liệu, workload khoa học hoặc phần mềm khác sử dụng nhiều shared memory, thì bề mặt tấn công IPC có thể rất đáng lưu ý.

## Lạm dụng

Khi IPC được chia sẻ với host, kẻ tấn công có thể kiểm tra hoặc can thiệp vào các đối tượng shared memory, hiểu thêm về hoạt động của host hoặc workload lân cận, hoặc kết hợp thông tin thu được với khả năng quan sát tiến trình và các quyền kiểu ptrace. Chia sẻ IPC thường là một điểm yếu hỗ trợ chứ không phải toàn bộ con đường thoát khỏi container, nhưng các điểm yếu hỗ trợ vẫn quan trọng vì chúng rút ngắn và giúp ổn định các chuỗi tấn công thực tế.

Bước hữu ích đầu tiên là liệt kê những đối tượng IPC nào có thể nhìn thấy:

```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```

Nếu IPC namespace của host được dùng chung, các phân đoạn bộ nhớ dùng chung lớn hoặc chủ sở hữu đối tượng đáng chú ý có thể tiết lộ ngay hành vi của ứng dụng:

```bash
ipcs -m -p
ipcs -q -p
```

Trong một số môi trường, nội dung trong `/dev/shm` có thể làm lộ tên tệp, artifact hoặc token đáng kiểm tra:

```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```

IPC sharing hiếm khi tự nó giúp chiếm quyền root trên host ngay lập tức, nhưng có thể làm lộ dữ liệu và các kênh phối hợp, khiến những cuộc tấn công quy trình tiếp theo dễ dàng hơn nhiều.

### Ví dụ đầy đủ: Khôi phục bí mật từ `/dev/shm`

Trường hợp lạm dụng hoàn chỉnh thực tế nhất là đánh cắp dữ liệu thay vì thoát trực tiếp. Nếu IPC của host hoặc bố cục bộ nhớ dùng chung rộng được để lộ, đôi khi có thể khôi phục trực tiếp các tạo tác nhạy cảm:

```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```

Tác động:

- trích xuất bí mật hoặc dữ liệu phiên còn lưu trong bộ nhớ dùng chung
- hiểu rõ hơn về các ứng dụng hiện đang hoạt động trên host
- nhắm mục tiêu tốt hơn cho các cuộc tấn công sau này dựa trên PID namespace hoặc ptrace

Do đó, nên xem việc chia sẻ IPC là **yếu tố khuếch đại tấn công** hơn là một primitive độc lập để thoát khỏi host.

## Kiểm tra

Các lệnh này nhằm xác định workload có chế độ xem IPC riêng hay không, có thể nhìn thấy các đối tượng bộ nhớ dùng chung hoặc đối tượng thông điệp đáng chú ý hay không, và liệu chính `/dev/shm` có để lộ các artifact hữu ích hay không.

```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```

Điều đáng chú ý ở đây:

- Nếu `ipcs -a` hiển thị các object thuộc sở hữu của những user hoặc service không mong đợi, namespace có thể không được cô lập như dự kiến.
- Các shared memory segment lớn hoặc bất thường thường đáng để kiểm tra thêm.
- Mount `/dev/shm` rộng không tự động là lỗi, nhưng trong một số môi trường, nó leaks tên file, artifact và secret tạm thời.

IPC hiếm khi được chú ý nhiều như các loại namespace lớn hơn, nhưng trong những môi trường sử dụng IPC nhiều, việc chia sẻ nó với host rõ ràng là một quyết định về bảo mật.

## References

- [1] [`ipc_namespaces(7)` - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/ipc_namespaces.7.html)
- [2] [`shm_overview(7)` - Trang hướng dẫn Linux](https://man7.org/linux/man-pages/man7/shm_overview.7.html)
- [3] [Tài liệu tham khảo API Kubernetes - PodSpec `hostIPC`](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#PodSpec)
{{#include ../../../../../banners/hacktricks-training.md}}
