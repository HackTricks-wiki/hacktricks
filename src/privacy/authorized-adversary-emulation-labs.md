# 已授权的对手模拟实验室

这些练习复现的是**可观测的架构**，而不是未经授权的 compromise。请在安装了 Docker 的专用 Linux 实验主机上运行，不要使用敏感凭据，也不要存在通往第三方目标的路由。名称已固定，以便明确 teardown。

{% hint style="danger" %}
不要将下方自有的容器、AP、路由器、账户或 synthetic transactions 替换为公共代理、邻居的 Wi-Fi、你无权控制的 production CDN tenant，或真实的 illicit funds。书面授权必须覆盖每个系统和无线电环境。
{% endhint %}

## 实验室 1：自有 ORB 和 redirector chain

**目标：**展示目标只记录出口，而每个 relay 都能看到相邻 hops。在没有 compromised devices 的情况下，模拟 T1090.003/T1584 结构。

**要求：**Docker Engine，以及以 `ht-orb-` 开头的未使用容器名称。

### 构建
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
### 验证可见性边界
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
预期结果：Nginx 在 `ht-orb-target` 上记录 `ht-orb-r2` 的地址，而不是 one-shot client 的地址。Relay 日志仅显示来自其相邻网络的连接。Docker control-plane 检查仍可重建完整路径——类似于 provider/controller 证据。

### Detection experiments

1. 每 60 秒重复请求，并绘制到达间隔时间和字节数。
2. 将 `ht-orb-r2` 替换为新的命名容器/地址，但保持相同的 cadence 和 application request；确认仅基于 IP 的规则会丢失该链路，而行为仍能将其关联起来。
3. 在 lab host 上使用 `tcpdump` 监听三个 Docker bridge，并比较时间戳。
4. 停止 `ht-orb-r2`；验证 entry 到 target 之间不存在直接 fallback。

### Teardown
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch 和 redirector logging

**目标：** 在私有本地 edge 上复现 domain fronting 背后的 routing primitive，并展示其可见位置。不涉及 public CDN。

### 构建本地 TLS edge
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
### 发送并观察不匹配
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
预期的日志字段包括 `sni=front.lab host=origin.lab`。除非使用 ECH，否则客户端到 edge 的数据包捕获会暴露 SNI；HTTP Host 在该链路上是加密的。终止 TLS 的 edge 可以看到两者。

现在发送一个普通请求，并确认策略拒绝该请求：
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### 检测断言

仅在标准化端口和大小写，并检查已知的 reverse-proxy 例外后，对 `sni != host` 发出警报。在分配严重性之前，添加进程和 tenant/origin 上下文。

### 清理
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## 实验 3：fast-flux DNS telemetry

**目标：**生成安全的低 TTL/类似多 ASN 的 DNS 数据集，并验证一项分析规则。返回的 RFC 5737 文档地址在此用途下不可路由。

### 运行权威服务器
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
预期结果：每个回答包含三个文档 IP 和 5 秒 TTL。真正的 fast flux 还会随时间轮换子集；更改 zone serial/addresses，并重启这个临时 server，以创建多个 epoch。

### 分析验证

对于五分钟的时间窗口，计算 `median(TTL)`、不同回答的数量、不同的 synthetic ASN/geography labels 以及 answer churn。至少需要两个可疑维度，再加上一个 process/follow-on event。对已知 CDN 样本运行相同的分析，以衡量误报率。

### 拆除
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## 实验 4：nearest-neighbor wireless pivot

**目标：** 使用两个自有的“组织”复现 APT28 的边界不匹配问题。由于 Wi-Fi 硬件/driver 命令各不相同，本实验规定可验证的角色和证据，而不是假设某一条 `hostapd` 命令适用于所有无线电设备。

### 设备

- 两个由你拥有、运行在隔离实验频道/SSID `HT-NEIGHBOR` 和 `HT-TARGET` 上的 AP；
- 一个只能从 `HT-TARGET` 访问的 target service；
- 一个由你拥有、能够同时关联两个 AP 的双 radio Linux pivot；
- 一台位于 `HT-NEIGHBOR` 后方的 remote-control workstation；
- RADIUS/NAC 或 AP association logs、DHCP logs，以及 pivot audit/process logs。

### 流程

1. 对设置进行物理隔离或衰减，使两个 SSID 都不会离开授权区域。使用 survey 进行确认。
2. 为 `HT-TARGET` 配置一个 exercise identity，并在首次运行时故意省略 device-certificate/posture validation。记录该条件作为测试条件。
3. 将 pivot 的第一个 interface 加入 `HT-NEIGHBOR`，第二个 interface 加入 `HT-TARGET`。**不要**启用通用 bridge；仅允许 target service/port 通过 host firewall。
4. 从 workstation 向 pivot 打开 authenticated tunnel，并通过该 tunnel 请求 target service。
5. 记录 pivot process/interface creation、两个 AP associations、target RADIUS event、DHCP lease 和 target source address。
6. 要求 detection team 在没有 controller map 的情况下重建该链路。
7. 在 `HT-TARGET` 上启用 EAP-TLS/managed-device posture，移除 pivot 获准使用的 target certificate 并重复测试。访问应在 admission 阶段失败。
8. 使用首次出现的 randomized MAC 重复测试。验证 certificate/device decision 仍然有效，并确认没有任何规则仅将 MAC 视为 identity。

### 成功标准

- target 最初看到的是本地 Wi-Fi client，而不是 workstation。
- Joined telemetry 识别出一个同时具有 neighbor-control 和 target-radio 路径的 pivot。
- Certificate/device-backed admission 阻止第二次运行。
- 没有数据包到达隔离实验环境之外的 network。

## 实验 5：dead-drop resolver sequence

**目标：** 检测一个读取看似合法的 object、解码 pointer，并立即联系第二个 service 的 process。

### 构建
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
编码内容为 `http://ht-ddr-c2:80/`。有效的检测会将同一个短生命周期进程/容器读取 `/profile.txt`、解码内容并在数秒内连接 `ht-ddr-c2` 这几个事件关联起来。对对象响应进行哈希并保留。

### 拆除
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## 实验室 6：合成 peel-chain 与 bridge graph

**目标：** 在不使用真实资产、账户或服务的情况下练习价值追踪。

### 创建并追踪数据集
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
分析人员应识别 peel/change 模式，将 bridge link 视为一项需要单独支持的推断，计算 fee/value 差异，并将该 exchange 标记为 off-chain evidence request。更改一个 value/time，并记录 confidence 如何变化。

### 拆解
```bash
rm -rf -- "$ht_graph_dir"
```
## 实验 7：被动流量信号传感器

**目标：** 在不创建 shell、persistence 或 remote access 的情况下，模拟被动、由 magic value 激活的 implant 的网络特征。监听器仅绑定到 loopback，并记录一个无害事件。
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
预期结果：普通流量不会产生 application event；只有指定的 token 会产生事件。在运行期间捕获 loopback 流量，并验证 network sensor 仍能看到两个 datagram。然后评估能够检测异常的长时间运行 packet listener 或 packet-capture filter 的主机控制措施。真正的 RedPenguin passive implants 会在 router 上检查流量并提供危险功能；本 lab 特意不执行这些操作。

## Exercise report template

对于每个 lab，记录：

- authorization 和隔离范围；
- hypothesis 和 ATT&CK technique；
- topology 和 observer table；
- 准确的开始/结束时间以及 configuration hashes；
- 每个 sensor 的预期 events；
- 实际观察到的 events 和 retention gaps；
- analytic logic、threshold 和 false-positive sample；
- target team 是否重建了该路径；
- mitigation retest result；以及
- teardown/recovery evidence。

在 mitigation 后重新运行 detection，并移除每个 lab resource 之前，exercise 均不完整。

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — 最近邻攻击](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
