# Authorized Adversary-Emulation Labs

{{#include ../banners/hacktricks-training.md}}

这些练习复现的是**可观测的架构**，而不是未经授权的入侵。请在专用的 Linux lab 主机上运行，并使用 Docker；不要配置敏感凭据，也不要设置通往第三方目标的路由。名称是固定的，以便明确执行 teardown。

{% hint style="danger" %}
不要将下方的自有容器、AP、路由器、账户或 synthetic transactions 替换为公共代理、邻居的 Wi-Fi、你无权控制的生产 CDN tenant，或真实的非法资金。书面授权必须涵盖每个系统和 radio environment。
{% endhint %}

## Lab 1: owned ORB and redirector chain

**目标：**展示 target 只记录出口，而每个 relay 都能看到相邻 hops。在没有被入侵设备的情况下，复现 T1090.003/T1584 结构。

**要求：**Docker Engine，以及名称以 `ht-orb-` 开头的未使用容器名称。

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
预期结果：Nginx 在 `ht-orb-target` 上记录的是 `ht-orb-r2` 的地址，而不是 one-shot client 的地址。Relay 日志显示，连接仅来自其相邻网络。Docker control-plane inspection 仍可重建完整路径——类似于 provider/controller 证据。

### 检测实验

1. 每隔 60 秒重复请求，并绘制请求间隔时间和字节数的图表。
2. 将 `ht-orb-r2` 替换为新的命名容器/地址，但保持相同的请求频率和应用请求；确认仅基于 IP 的规则无法保持关联链，而行为仍能将其关联起来。
3. 在 lab host 上对三个 Docker bridge 使用 `tcpdump` 抓包，并比较时间戳。
4. 停止 `ht-orb-r2`；确认 entry 到 target 之间不存在直接 fallback。

### 拆除
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch 和 redirector logging

**目标：**在私有本地 edge 上复现 domain fronting 背后的路由原语，并展示其可见位置。不涉及公共 CDN。

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
预期的日志字段包括 `sni=front.lab host=origin.lab`。除非使用 ECH，否则 client-to-edge 的数据包捕获会暴露 SNI；HTTP Host 在该链路上是加密的。终止 TLS 的 edge 可以看到两者。

现在发送一个普通请求，并确认 policy 拒绝该请求：
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### 检测断言

仅在标准化端口和大小写并检查已知的 reverse-proxy 例外后，针对 `sni != host` 发出告警。在分配严重性之前，添加进程以及 tenant/origin 上下文。

### 清理
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**目标：**生成一个安全的低 TTL/类似 multi-ASN 的 DNS 数据集，并验证一项分析规则。返回的 RFC 5737 文档地址在此用途下不可路由。

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
预期结果：每个应答都包含三个 documentation IP，且 TTL 为 5 秒。真正的 fast flux 也会随时间轮换子集；修改 zone serial/地址并重启此 disposable server，以创建多个 epoch。

### 分析验证

对于五分钟的时间窗口，计算 `median(TTL)`、不同应答数量、不同的 synthetic ASN/geography 标签以及应答 churn。至少需要两个可疑维度，以及一个 process/follow-on event。使用已知 CDN 样本运行相同的分析，以测量误报率。

### 拆除
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## 实验 4：近邻无线 pivot

**目标：** 使用两个自有的“组织”复现 APT28 的边界失配。由于 Wi-Fi 硬件/driver 命令各不相同，本实验规定可验证的角色和证据，而不是假设某一条 `hostapd` 命令适用于所有无线电设备。

### 设备

- 两个由你拥有的 AP，运行在隔离的实验信道/SSID `HT-NEIGHBOR` 和 `HT-TARGET` 上；
- 一个只能从 `HT-TARGET` 访问的目标服务；
- 一个由你拥有、能够关联到两个 AP 的双无线电 Linux pivot；
- 一台位于 `HT-NEIGHBOR` 后方的远程控制工作站；
- RADIUS/NAC 或 AP 关联日志、DHCP 日志以及 pivot 审计/进程日志。

### 步骤

1. 对环境进行物理隔离或衰减，使两个 SSID 都不会超出授权区域。使用 survey 进行确认。
2. 为 `HT-TARGET` 配置一个演练身份，并在首次运行时故意省略设备证书/posture 验证。将其记录为本次测试的条件。
3. 将 pivot 的第一个接口加入 `HT-NEIGHBOR`，第二个接口加入 `HT-TARGET`。**不要**启用通用 bridge；仅通过主机防火墙放行目标服务/端口。
4. 从工作站向 pivot 打开一个 authenticated tunnel，并通过该 tunnel 请求目标服务。
5. 记录 pivot 进程/接口的创建、与两个 AP 的关联、目标 RADIUS 事件、DHCP lease 以及目标端的源地址。
6. 要求 detection team 在没有 controller map 的情况下重建整个链路。
7. 在 `HT-TARGET` 上启用 EAP-TLS/managed-device posture，移除 pivot 获准使用的目标证书并重复测试。访问应在 admission 阶段失败。
8. 使用首次出现的 randomized MAC 重复测试。验证证书/设备决策仍然有效，并确认没有任何规则仅将 MAC 视为身份。

### 成功标准

- 目标最初看到的是本地 Wi-Fi client，而不是工作站。
- 关联的 telemetry 能识别出一个同时具有邻居控制路径和目标无线电路径的 pivot。
- 基于证书/设备的 admission 会阻止第二次运行。
- 没有数据包到达隔离实验环境之外的网络。

## 实验 5：dead-drop resolver sequence

**目标：** 检测一个读取外观合法的对象、解码指针并立即联系第二个服务的进程。

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
编码内容为 `http://ht-ddr-c2:80/`。有效的 detection 会将同一个短生命周期的 process/container 读取 `/profile.txt`、解码内容并在数秒内连接 `ht-ddr-c2` 关联起来。对对象响应执行 Hash 并予以保留。

### Teardown
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## 实验室 6：synthetic peel-chain 和 bridge graph

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
分析人员应识别 peel/change pattern，将 bridge link 作为单独支持的推断，计算 fee/value difference，并将该 exchange 标记为 off-chain 证据请求。更改一个 value/time，并记录置信度如何变化。

### 拆解
```bash
rm -rf -- "$ht_graph_dir"
```
## 实验 7：被动流量信号传感器

**目标：**模拟被动、由 magic value 激活的 implant 的网络特征，但不创建 shell、persistence 或 remote access。监听器仅绑定到 loopback，并记录一个无害事件。
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
预期结果：普通流量不会产生 application event；只有指定 token 会产生事件。在运行期间捕获 loopback traffic，并验证 network sensor 仍能看到两个 datagrams。然后评估能够检测意外的长期运行 packet listener 或 packet-capture filter 的 host controls。真实的 RedPenguin passive implants 会在路由器上检查流量并提供危险功能；本实验刻意不执行这两项操作。

## Exercise report template

对于每个实验，记录：

- authorization 和隔离范围；
- hypothesis 和 ATT&CK technique；
- topology 和 observer table；
- 确切的 start/end time 以及 configuration hashes；
- 每个 sensor 的预期事件；
- 实际观察到的事件和 retention gaps；
- analytic logic、threshold 以及 false-positive sample；
- target team 是否重建了该路径；
- mitigation retest result；以及
- teardown/recovery evidence。

在 mitigation 后重新运行 detection 并移除所有 lab resource 之前，实验均不完整。

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — 最近邻攻击：俄罗斯 APT 如何将附近 Wi-Fi 网络武器化以实现隐蔽访问](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
