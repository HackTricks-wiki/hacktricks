# Authorized Adversary-Emulation Labs

이 exercise는 unauthorized compromise가 아니라 **관찰 가능한 architecture**를 재현합니다. Docker가 설치된 전용 Linux lab host에서 실행하고, 민감한 credentials를 사용하지 않으며, third-party targets로 향하는 route를 두지 마세요. teardown을 명시적으로 수행할 수 있도록 이름을 고정합니다.

{% hint style="danger" %}
아래의 소유한 containers, APs, routers, accounts 또는 synthetic transactions를 public proxies, 이웃의 Wi-Fi, 자신이 제어하지 않는 production CDN tenant 또는 실제 illicit funds로 대체하지 마세요. 서면 authorization에는 모든 system과 radio environment가 포함되어야 합니다.
{% endhint %}

## Lab 1: owned ORB and redirector chain

**Objective:** target에는 exit만 기록되고 각 relay는 인접한 hops를 확인한다는 것을 보여줍니다. 이는 compromised devices 없이 T1090.003/T1584 structure를 emulate합니다.

**Requirements:** Docker Engine 및 `ht-orb-`로 시작하는 사용하지 않는 container names.

### Build
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
### 가시성 경계 확인
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
예상 결과: Nginx는 일회성 client가 아닌 `ht-orb-target`의 `ht-orb-r2` address를 기록합니다. Relay logs에는 인접한 network에서의 connection만 표시됩니다. Docker control-plane inspection을 통해 전체 경로를 여전히 재구성할 수 있으며, 이는 provider/controller evidence와 유사합니다.

### 탐지 실험

1. 60초마다 request를 반복하고 inter-arrival time과 bytes를 graph로 표시합니다.
2. `ht-orb-r2`를 새로운 named container/address로 교체하되 동일한 cadence와 application request를 유지합니다. IP-only rule이 chain을 놓치는 반면 behavior는 여전히 이를 연결하는지 확인합니다.
3. lab host에서 세 Docker bridge를 `tcpdump`로 capture하고 timestamps를 비교합니다.
4. `ht-orb-r2`를 중지하고 entry에서 target으로의 direct fallback이 없는지 확인합니다.

### 해체
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch 및 redirector logging

**Objective:** private local edge에서 domain fronting의 기반이 되는 routing primitive를 재현하고, 이것이 어디에서 확인되는지 보여 줍니다. Public CDN은 사용하지 않습니다.

### 로컬 TLS edge 구축
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
### 불일치를 전송하고 관찰하기
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
예상되는 로그 필드에는 `sni=front.lab host=origin.lab`이 포함됩니다. ECH가 사용되지 않는 한 client-to-edge packet capture에서 SNI가 노출되며, 해당 링크에서는 HTTP Host가 암호화됩니다. 연결을 종료하는 edge는 두 값을 모두 확인합니다.

이제 일반 요청을 보내고 정책이 이를 거부하는지 확인합니다:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### 탐지 판정

포트와 대소문자를 정규화하고 알려진 reverse-proxy 예외를 확인한 후에만 `sni != host`에 대해 alert를 발생시킵니다. 심각도를 할당하기 전에 프로세스와 tenant/origin context를 추가합니다.

### 정리
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**목표:** 안전한 low-TTL/multi-ASN-like DNS dataset을 생성하고 analytic을 검증합니다. 반환되는 RFC 5737 documentation addresses는 이 목적에 한해 routable하지 않습니다.

### authoritative server 실행
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
예상 결과: 각 응답에는 3개의 documentation IP와 5초 TTL이 포함됩니다. 실제 fast flux는 시간에 따라 하위 집합도 교체하므로, zone serial/주소를 변경하고 이 disposable server를 재시작하여 여러 epoch를 생성합니다.

### 분석 검증

5분간의 window에 대해 `median(TTL)`, distinct answers, distinct synthetic ASN/geography labels 및 answer churn을 계산합니다. 최소 2개의 의심스러운 차원과 process/follow-on event를 요구합니다. 동일한 analytic을 알려진 CDN sample에 실행하여 false positives를 측정합니다.

### 정리
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: nearest-neighbor wireless pivot

**목표:** 두 개의 자체 소유 “조직”을 사용해 APT28 boundary mismatch를 재현합니다. Wi-Fi hardware/driver 명령은 서로 다르므로, 이 lab에서는 모든 radio에 하나의 `hostapd` 명령이 적용되는 것처럼 가장하지 않고 검증 가능한 역할과 증거를 지정합니다.

### 장비

- 서로 소유하고 있으며 격리된 lab 채널/SSID `HT-NEIGHBOR` 및 `HT-TARGET`에서 동작하는 AP 2개;
- `HT-TARGET`에서만 접근할 수 있는 target service 1개;
- 두 AP에 모두 associate할 수 있는 자체 소유 dual-radio Linux pivot 1개;
- `HT-NEIGHBOR` 뒤에 있는 remote-control workstation 1개;
- RADIUS/NAC 또는 AP association logs, DHCP logs 및 pivot audit/process logs.

### 절차

1. 두 SSID가 authorized area 밖으로 유출되지 않도록 설정을 물리적으로 격리하거나 감쇠합니다. survey를 통해 확인합니다.
2. `HT-TARGET`을 exercise identity로 구성하고, 첫 번째 실행에서는 의도적으로 device-certificate/posture validation을 생략합니다. 이를 테스트 대상 조건으로 기록합니다.
3. pivot의 첫 번째 interface를 `HT-NEIGHBOR`에, 두 번째 interface를 `HT-TARGET`에 join합니다. 일반 bridge는 활성화하지 **마십시오**. host firewall을 통해 target service/port만 허용합니다.
4. workstation에서 pivot으로 authenticated tunnel을 열고, 이를 통해 target service를 요청합니다.
5. pivot process/interface 생성, 두 AP association, target RADIUS event, DHCP lease 및 target source address를 기록합니다.
6. controller map 없이 detection team에 chain을 재구성하도록 요청합니다.
7. `HT-TARGET`에서 EAP-TLS/managed-device posture를 활성화하고 pivot의 승인된 target certificate를 제거한 뒤 반복합니다. admission 단계에서 access가 실패해야 합니다.
8. 처음 확인된 randomized MAC을 사용해 반복합니다. certificate/device decision이 계속 작동하고, 어떤 rule도 MAC만을 identity로 취급하지 않는지 확인합니다.

### 성공 기준

- target은 처음에 workstation이 아닌 local Wi-Fi client를 확인합니다.
- joined telemetry에서 neighbor-control 및 target-radio path에 동시에 연결된 하나의 pivot을 식별합니다.
- certificate/device 기반 admission이 두 번째 실행을 차단합니다.
- 격리된 lab 외부의 어떤 network에도 packet이 도달하지 않습니다.

## Lab 5: dead-drop resolver sequence

**목표:** 정상적으로 보이는 object를 읽고, pointer를 decode한 직후 두 번째 service에 contact하는 process를 탐지합니다.

### Build
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
인코딩된 콘텐츠는 `http://ht-ddr-c2:80/`입니다. 작동하는 detection은 `/profile.txt`를 읽고 콘텐츠를 decoding한 후 몇 초 이내에 `ht-ddr-c2`에 접속하는 동일한 단기 프로세스/컨테이너를 연결합니다. 객체 응답을 hash하고 보존합니다.

### Teardown
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: synthetic peel-chain 및 bridge graph

**목표:** 실제 assets, accounts 또는 services 없이 value tracing을 연습합니다.

### 데이터셋 생성 및 추적
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
분석가는 peel/change 패턴을 식별하고, bridge link를 별도로 뒷받침해야 하는 추론으로 취급하며, 수수료/가치 차이를 계산하고, 해당 exchange를 off-chain 증거 요청으로 표시해야 합니다. 값/시간 중 하나를 변경하고 confidence가 어떻게 변하는지 기록합니다.

### Teardown
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: passive traffic-signaling sensor

**Objective:** shell, persistence 또는 remote access를 생성하지 않고 passive, magic-value-activated implant의 network signature를 emulate합니다. listener는 loopback에만 bind하며 benign event를 기록합니다.
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
예상 결과: 일반 트래픽에서는 애플리케이션 이벤트가 발생하지 않고, 지정된 토큰에서만 발생합니다. 실행 중 loopback 트래픽을 캡처하고 네트워크 센서가 두 datagram을 모두 여전히 볼 수 있는지 확인합니다. 그런 다음 예상치 못한 장시간 실행 packet listener 또는 packet-capture filter를 탐지하는 host controls를 평가합니다. 실제 RedPenguin passive implants는 router에서 트래픽을 검사하고 위험한 기능을 제공했지만, 이 lab에서는 의도적으로 어느 것도 수행하지 않습니다.

## Exercise report template

모든 lab에 대해 다음을 기록합니다:

- authorization 및 격리된 scope;
- hypothesis 및 ATT&CK technique;
- topology 및 observer table;
- 정확한 시작/종료 시간과 configuration hashes;
- 각 sensor에서 예상되는 events;
- 실제로 관찰된 events 및 retention gaps;
- analytic logic, threshold 및 false-positive sample;
- target team이 path를 재구성했는지 여부;
- mitigation retest 결과; 및
- teardown/recovery evidence.

mitigation 후 detection을 다시 실행하고 모든 lab resource가 제거되기 전까지 exercise는 완료되지 않은 것으로 간주합니다.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — 가장 가까운 이웃 공격](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
