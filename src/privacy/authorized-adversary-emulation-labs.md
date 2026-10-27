# Authorized Adversary-Emulation Labs

{{#include ../banners/hacktricks-training.md}}

Các bài tập này tái tạo **kiến trúc có thể quan sát**, không phải hành vi xâm nhập trái phép. Hãy chạy chúng trên một máy chủ Linux lab chuyên dụng có Docker, không chứa thông tin xác thực nhạy cảm và không có tuyến kết nối đến mục tiêu bên thứ ba. Tên được cố định để việc dọn dẹp được rõ ràng.

{% hint style="danger" %}
Không thay thế các container, AP, router, tài khoản hoặc giao dịch tổng hợp thuộc sở hữu của bạn bên dưới bằng proxy công khai, Wi-Fi của hàng xóm, tenant CDN production mà bạn không kiểm soát hoặc tiền bất hợp pháp thật. Văn bản ủy quyền phải bao gồm mọi hệ thống và môi trường vô tuyến.
{% endhint %}

## Lab 1: Chuỗi ORB và redirector thuộc sở hữu của bạn

**Mục tiêu:** cho thấy mục tiêu chỉ ghi nhận điểm thoát, trong khi mỗi relay chỉ thấy các hop liền kề. Cách này mô phỏng cấu trúc T1090.003/T1584 mà không cần thiết bị bị xâm nhập.

**Yêu cầu:** Docker Engine và các tên container chưa được sử dụng, bắt đầu bằng `ht-orb-`.

### Dựng lab

```bash
docker network create ht-orb-entry
docker network create ht-orb-transit
docker network create ht-orb-target

docker run -d --name ht-orb-target --network ht-orb-target nginx:alpine

docker run -d --name ht-orb-r2 --network ht-orb-transit \
  alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-target:80
docker network connect ht-orb-target ht-orb-r2

docker run -d --name ht-orb-r1 --network ht-orb-entry \
  alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-r2:8080
docker network connect ht-orb-transit ht-orb-r1

docker run --rm --network ht-orb-entry curlimages/curl:latest \
  -sS http://ht-orb-r1:8080/ >/dev/null
```

### Xác minh ranh giới hiển thị

```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
  ht-orb-r1 ht-orb-r2 ht-orb-target
```

Kết quả mong đợi: Nginx ghi nhận địa chỉ `ht-orb-r2` trên `ht-orb-target`, không phải địa chỉ của client chỉ gửi một lần. Log của relay chỉ hiển thị các kết nối đến từ mạng liền kề. Việc kiểm tra control plane của Docker vẫn cho phép tái dựng toàn bộ đường đi—tương tự như bằng chứng từ nhà cung cấp/bộ điều khiển.

### Thử nghiệm phát hiện

1. Lặp lại các yêu cầu mỗi 60 giây và lập biểu đồ thời gian giữa các yêu cầu cũng như số byte.
2. Thay `ht-orb-r2` bằng container/địa chỉ mới có tên khác nhưng giữ nguyên nhịp gửi và yêu cầu ứng dụng; xác nhận quy tắc chỉ dựa trên IP không nhận ra chuỗi kết nối, trong khi hành vi vẫn liên kết được chúng.
3. Bắt gói tin trên ba Docker bridge bằng `tcpdump` trên máy chủ lab và so sánh dấu thời gian.
4. Dừng `ht-orb-r2`; xác minh không có đường dự phòng trực tiếp từ entry đến target.

### Dọn dẹp

```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```

## Lab 2: SNI/Host mismatch và logging của redirector

**Mục tiêu:** tái tạo primitive định tuyến đứng sau domain fronting trên một edge riêng tư, chạy cục bộ và cho thấy nó hiển thị ở đâu. Không sử dụng CDN công khai nào.

### Dựng một TLS edge cục bộ

```bash
ht_front_dir="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=front.lab' \
  -keyout "$ht_front_dir/key.pem" -out "$ht_front_dir/cert.pem"

cat >"$ht_front_dir/default.conf" <<'EOF'
log_format routing '$remote_addr sni=$ssl_server_name host=$host request="$request"';
server {
    listen 443 ssl;
    server_name front.lab;
    ssl_certificate /etc/nginx/tls/cert.pem;
    ssl_certificate_key /etc/nginx/tls/key.pem;
    access_log /var/log/nginx/access.log routing;
    location / {
        if ($host != origin.lab) { return 404; }
        proxy_pass http://ht-front-target:80;
    }
}
EOF

docker network create ht-front-net
docker run -d --name ht-front-target --network ht-front-net nginx:alpine
docker run -d --name ht-front-edge --network ht-front-net -p 127.0.0.1:8443:443 \
  -v "$ht_front_dir/default.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$ht_front_dir:/etc/nginx/tls:ro" nginx:alpine
```

### Gửi và quan sát sự không khớp

```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
  -H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```

Các trường log dự kiến gồm `sni=front.lab host=origin.lab`. Bản ghi gói tin từ client đến edge sẽ để lộ SNI, trừ khi đang dùng ECH; HTTP Host được mã hóa trên liên kết đó. Edge đầu cuối thấy cả hai.

Bây giờ gửi một request thông thường và xác nhận rằng policy từ chối request đó:

```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```

### Khẳng định phát hiện

Chỉ cảnh báo khi `sni != host` sau khi chuẩn hóa port/chữ hoa-thường và kiểm tra các ngoại lệ reverse-proxy đã biết. Bổ sung ngữ cảnh về process và tenant/origin trước khi xác định mức độ nghiêm trọng.

### Dọn dẹp

```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```

## Lab 3: fast-flux DNS telemetry

**Mục tiêu:** tạo một tập dữ liệu DNS an toàn có TTL thấp, tương tự nhiều ASN, và xác thực một analytic. Các địa chỉ tài liệu RFC 5737 được trả về không thể định tuyến và chỉ dùng cho mục đích này.

### Chạy một authoritative server

```bash
ht_dns_dir="$(mktemp -d)"
cat >"$ht_dns_dir/Corefile" <<'EOF'
.:53 {
    log
    errors
    file /zones/db.lab lab
}
EOF

mkdir -p "$ht_dns_dir/zones"
cat >"$ht_dns_dir/zones/db.lab" <<'EOF'
$ORIGIN lab.
@ 60 IN SOA ns.lab. hostmaster.lab. 1 60 60 60 5
@ 60 IN NS ns.lab.
ns 60 IN A 192.0.2.53
flux 5 IN A 192.0.2.10
flux 5 IN A 198.51.100.20
flux 5 IN A 203.0.113.30
EOF

docker run -d --name ht-flux-dns -p 127.0.0.1:1053:53/udp \
  -v "$ht_dns_dir/Corefile:/Corefile:ro" \
  -v "$ht_dns_dir/zones:/zones:ro" coredns/coredns:latest -conf /Corefile

for query_number in 1 2 3 4 5; do
  dig @127.0.0.1 -p 1053 flux.lab A +noall +answer
done
docker logs ht-flux-dns
```

Kết quả mong đợi: mỗi câu trả lời chứa ba IP dành cho tài liệu và TTL 5 giây. Fast flux thực sự cũng luân phiên các tập con theo thời gian; hãy thay đổi zone serial/địa chỉ và khởi động lại server dùng một lần này để tạo nhiều epoch.

### Kiểm định phân tích

Trong khoảng thời gian năm phút, tính `median(TTL)`, số câu trả lời riêng biệt, số nhãn ASN/địa lý tổng hợp riêng biệt và mức độ biến động câu trả lời. Yêu cầu có ít nhất hai chiều đáng ngờ cùng với một sự kiện tiến trình/sự kiện tiếp diễn. Chạy cùng analytic trên một mẫu CDN đã biết để đo false positive.

### Dọn dẹp

```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```

## Lab 4: nearest-neighbor wireless pivot

**Mục tiêu:** tái hiện sự không khớp ranh giới của APT28 bằng hai “tổ chức” do bạn sở hữu. Vì các lệnh Wi-Fi phụ thuộc vào phần cứng/driver, lab này xác định các vai trò và bằng chứng có thể xác minh thay vì giả định rằng một lệnh `hostapd` phù hợp với mọi radio.

### Thiết bị

- hai AP do bạn sở hữu, sử dụng các kênh/SSID lab biệt lập `HT-NEIGHBOR` và `HT-TARGET`;
- một dịch vụ mục tiêu chỉ có thể truy cập từ `HT-TARGET`;
- một pivot Linux hai radio do bạn sở hữu, có khả năng kết nối với cả hai AP;
- một workstation điều khiển từ xa nằm sau `HT-NEIGHBOR`;
- log RADIUS/NAC hoặc log kết nối AP, log DHCP và log kiểm toán/quy trình của pivot.

### Quy trình

1. Cách ly vật lý hoặc giảm công suất tín hiệu của thiết lập để không SSID nào phát ra ngoài khu vực được cấp phép. Xác nhận bằng khảo sát.
2. Cấu hình `HT-TARGET` với một danh tính dùng cho bài tập và cố ý bỏ qua bước xác thực chứng chỉ thiết bị/tư thế thiết bị trong lần chạy đầu tiên. Ghi lại đây là điều kiện đang được kiểm thử.
3. Kết nối interface thứ nhất của pivot với `HT-NEIGHBOR` và interface thứ hai với `HT-TARGET`. **Không** bật bridge tổng quát; chỉ cho phép dịch vụ/cổng mục tiêu đi qua firewall trên host.
4. Từ workstation, mở một tunnel đã xác thực tới pivot và yêu cầu dịch vụ mục tiêu thông qua tunnel đó.
5. Ghi lại quy trình/tạo interface trên pivot, kết nối với cả hai AP, sự kiện RADIUS của mục tiêu, DHCP lease và địa chỉ nguồn mà mục tiêu nhìn thấy.
6. Yêu cầu đội ngũ phát hiện dựng lại chuỗi sự kiện mà không có sơ đồ controller.
7. Bật EAP-TLS/tư thế thiết bị được quản lý trên `HT-TARGET`, xóa chứng chỉ mục tiêu đã được phê duyệt của pivot rồi chạy lại. Truy cập phải bị từ chối ở bước cho phép kết nối.
8. Chạy lại với MAC ngẫu nhiên được dùng lần đầu. Xác minh quyết định về chứng chỉ/thiết bị vẫn hoạt động và không có quy tắc nào xem riêng MAC là danh tính.

### Tiêu chí thành công

- Ban đầu, mục tiêu thấy một client Wi-Fi cục bộ thay vì workstation.
- Telemetry đã kết hợp xác định được một pivot đồng thời có đường kết nối tới mạng điều khiển lân cận và radio mục tiêu.
- Cơ chế cho phép kết nối dựa trên chứng chỉ/thiết bị chặn được lần chạy thứ hai.
- Không gói tin nào đi tới mạng bên ngoài lab biệt lập.

## Lab 5: dead-drop resolver sequence

**Mục tiêu:** phát hiện một quy trình đọc một đối tượng trông có vẻ hợp lệ, giải mã một con trỏ rồi lập tức kết nối tới dịch vụ thứ hai.

### Thiết lập

```bash
docker network create ht-ddr-net
docker run -d --name ht-ddr-c2 --network ht-ddr-net nginx:alpine

docker run -d --name ht-ddr-web --network ht-ddr-net python:3-alpine \
  sh -c 'mkdir -p /srv && printf aHR0cDovL2h0LWRkci1jMjo4MC8= > /srv/profile.txt && python -m http.server 8000 -d /srv'

docker run --rm --name ht-ddr-client --network ht-ddr-net python:3-alpine \
  python -c 'import base64,urllib.request; p=urllib.request.urlopen("http://ht-ddr-web:8000/profile.txt").read(); u=base64.b64decode(p).decode(); print(urllib.request.urlopen(u).status)'

docker logs ht-ddr-web
docker logs ht-ddr-c2
```

Nội dung đã mã hóa là `http://ht-ddr-c2:80/`. Một cơ chế phát hiện hiệu quả liên kết cùng một tiến trình/container tồn tại ngắn hạn đọc `/profile.txt`, giải mã nội dung và liên hệ với `ht-ddr-c2` trong vòng vài giây. Tạo hash và bảo toàn phản hồi của đối tượng.

### Dọn dẹp

```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```

## Lab 6: chuỗi peel tổng hợp và đồ thị bridge

**Mục tiêu:** thực hành truy vết giá trị mà không dùng tài sản, tài khoản hoặc dịch vụ thực.

### Tạo và truy vết tập dữ liệu

```bash
ht_graph_dir="$(mktemp -d)"
cat >"$ht_graph_dir/edges.csv" <<'EOF'
time,chain,source,destination,amount,label
10:00,A,theft,a1,100,source
10:10,A,a1,shop1,3,payment
10:10,A,a1,a2,96.9,change
10:20,A,a2,shop2,4,payment
10:20,A,a2,a3,92.8,change
10:30,A,a3,bridge_in,90,bridge_deposit
10:36,X,bridge_in,bridge_out,89.5,bridge_link_inference
10:36,B,bridge_out,b1,89.5,bridge_withdrawal
10:50,B,b1,exchange,89,service_deposit
EOF

python3 - "$ht_graph_dir/edges.csv" <<'PY'
import csv, sys
edges = list(csv.DictReader(open(sys.argv[1], newline="")))
frontier, seen = {"theft"}, set()
while frontier:
    src = frontier.pop()
    for e in edges:
        if e["source"] == src and (src, e["destination"]) not in seen:
            seen.add((src, e["destination"]))
            print(f'{e["time"]} {e["chain"]}: {src} -> {e["destination"]} {e["amount"]} [{e["label"]}]')
            frontier.add(e["destination"])
PY
```

Các nhà phân tích nên xác định pattern peel/change, xem liên kết bridge là một suy luận cần được hỗ trợ riêng, tính toán chênh lệch phí/giá trị và đánh dấu giao dịch là yêu cầu thu thập bằng chứng off-chain. Thay đổi một giá trị/thời điểm và ghi lại sự thay đổi về mức độ tin cậy.

### Phân tích hậu kiểm

```bash
rm -rf -- "$ht_graph_dir"
```

## Lab 7: cảm biến báo hiệu lưu lượng thụ động

**Mục tiêu:** mô phỏng dấu hiệu mạng của một implant thụ động được kích hoạt bằng giá trị ma thuật mà không tạo shell, persistence hoặc remote access. Listener chỉ bind vào loopback và ghi lại một sự kiện vô hại.

```bash
ht_signal_dir="$(mktemp -d)"
cat >"$ht_signal_dir/listener.py" <<'PY'
import hmac, socket

token = b"HT-LAB-ACTIVATE"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 45679))
for _ in range(2):
    data, peer = sock.recvfrom(1024)
    if hmac.compare_digest(data, token):
        print(f"authorized lab activation from {peer[0]}", flush=True)
PY

python3 "$ht_signal_dir/listener.py" >"$ht_signal_dir/events.log" &
ht_signal_pid=$!
sleep 1

python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"ordinary-traffic", ("127.0.0.1", 45679))
s.sendto(b"HT-LAB-ACTIVATE", ("127.0.0.1", 45679))
PY

wait "$ht_signal_pid"
cat "$ht_signal_dir/events.log"
rm -rf -- "$ht_signal_dir"
```

Kết quả mong đợi: lưu lượng thông thường không tạo ra sự kiện ứng dụng nào; chỉ token được chỉ định mới tạo sự kiện. Ghi lại lưu lượng loopback trong quá trình chạy và xác minh rằng sensor mạng vẫn có thể thấy cả hai datagram. Sau đó đánh giá các biện pháp kiểm soát trên host có khả năng phát hiện một packet listener chạy lâu bất thường hoặc một bộ lọc packet-capture. Các passive implant RedPenguin thực tế đã kiểm tra lưu lượng trên router và cung cấp chức năng nguy hiểm; lab này cố ý không làm như vậy.

## Mẫu báo cáo bài thực hành

Với mỗi lab, hãy ghi lại:

- phạm vi được ủy quyền và phạm vi cách ly;
- giả thuyết và kỹ thuật ATT&CK;
- bảng topology và observer;
- thời gian bắt đầu/kết thúc chính xác và hash cấu hình;
- sự kiện dự kiến theo từng sensor;
- sự kiện thực tế được quan sát và các khoảng trống lưu trữ;
- logic phân tích, ngưỡng và mẫu false positive;
- nhóm phụ trách mục tiêu có tái dựng được đường đi hay không;
- kết quả kiểm tra lại biện pháp giảm thiểu; và
- bằng chứng tháo gỡ/khôi phục.

Bài thực hành chưa hoàn tất cho đến khi detection được chạy lại sau khi áp dụng biện pháp giảm thiểu và mọi tài nguyên của lab đã được gỡ bỏ.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — Cuộc tấn công láng giềng gần nhất](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
