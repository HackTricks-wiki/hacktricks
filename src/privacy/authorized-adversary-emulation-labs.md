# Authorized Adversary-Emulation Labs

{{#include ../banners/hacktricks-training.md}}

これらの演習では、未承認の侵害ではなく、**観測可能なアーキテクチャ**を再現します。Docker を使用する専用の Linux lab host 上で、機密性の高い認証情報を配置せず、第三者の target への route も設定せずに実行してください。teardown を明示的に行えるよう、名前は固定されています。

{% hint style="danger" %}
以下の所有コンテナ、AP、router、account、または synthetic transaction を、public proxy、近隣住民の Wi-Fi、管理権限のない production CDN tenant、または実在する不正資金に置き換えないでください。書面による authorization には、すべての system および radio environment を含める必要があります。
{% endhint %}

## Lab 1: 所有する ORB と redirector の chain

**Objective:** target に記録されるのは exit のみであり、各 relay は隣接する hop を認識することを示します。これは、compromised device を使用せずに T1090.003/T1584 の構造を emulation します。

**Requirements:** Docker Engine、および `ht-orb-` で始まる未使用の container name。

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
### 可視性の境界を確認する
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
期待される結果: Nginx は one-shot client ではなく、`ht-orb-target` 上の `ht-orb-r2` アドレスを記録します。Relay のログには、隣接するネットワークからの接続のみが表示されます。Docker control-plane の検査では、provider/controller の証拠と同様に、経路全体を再構成できます。

### Detection experiments

1. 60 秒ごとにリクエストを繰り返し、到着間隔とバイト数をグラフ化します。
2. `ht-orb-r2` を新しい名前付きコンテナ/アドレスに置き換えます。ただし、同じ cadence と application request は維持します。IP のみの rule では chain を追跡できなくなる一方、挙動によって関連付けられることを確認します。
3. lab host 上で `tcpdump` を使用して 3 つの Docker bridge 上を capture し、timestamp を比較します。
4. `ht-orb-r2` を停止し、entry から target への直接 fallback が存在しないことを確認します。

### Teardown
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch と redirector logging

**Objective:** private local edge 上で domain fronting の背後にある routing primitive を再現し、どこで可視化されるかを確認します。public CDN は使用しません。

### local TLS edge を構築する
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
### 送信して不一致を観察する
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
想定されるログフィールドには `sni=front.lab host=origin.lab` が含まれます。ECH が使用されていない限り、client-to-edge のパケットキャプチャには SNI が露出します。このリンク上では HTTP Host は暗号化されています。終端する edge では両方が確認できます。

次に通常のリクエストを送信し、policy によって拒否されることを確認します：
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### 検知アサーション

ポートと大文字・小文字を正規化し、既知の reverse-proxy 例外を確認した後にのみ `sni != host` をアラートします。severity を割り当てる前に、プロセスと tenant/origin のコンテキストを追加します。

### ティアダウン
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## ラボ 3: fast-flux DNS telemetry

**目的:** 安全な low-TTL/multi-ASN-like DNS データセットを生成し、analytic を検証する。返される RFC 5737 documentation addresses は、この目的では routable ではない。

### authoritative server を実行する
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
期待される結果: 各回答には3つのdocumentation IPと5秒のTTLが含まれます。実際のfast fluxでは、時間の経過に伴ってサブセットもローテーションされます。ゾーンシリアル/アドレスを変更し、この使い捨てサーバーを再起動して複数のエポックを作成します。

### 分析による検証

5分間のウィンドウについて、`median(TTL)`、異なる回答数、異なるsynthetic ASN/地理ラベル数、回答の変化量を計算します。少なくとも2つの疑わしい要素に加えて、プロセスまたは後続イベントが存在することを必須とします。同じ分析を既知のCDNサンプルに対して実行し、false positiveを測定します。

### 撤去
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: nearest-neighbor wireless pivot

**Objective:** 2つの所有する「organization」を使って、APT28の境界ミスマッチを再現する。Wi-Fi hardware/driver commandsは異なるため、すべてのradioに1つの`hostapd`コマンドが適用できるかのように装うのではなく、このLabでは検証可能な役割と証拠を指定する。

### Equipment

- 隔離されたlabのchannels/SSIDs `HT-NEIGHBOR` と `HT-TARGET` 上にある、所有する2台のAP；
- `HT-TARGET` からのみ到達可能な1つのtarget service；
- 両方のAPにassociate可能な、所有するdual-radio Linux pivot；
- `HT-NEIGHBOR` 配下にある1台のremote-control workstation；
- RADIUS/NACまたはAP association logs、DHCP logs、pivot audit/process logs。

### Procedure

1. 物理的に隔離するか、電波を減衰させて、どちらのSSIDもauthorized areaの外に出ないようにする。surveyで確認する。
2. `HT-TARGET` をexercise identityで構成し、最初のrunではdevice-certificate/posture validationを意図的に省略する。これをテスト対象のconditionとして記録する。
3. pivotの1つ目のinterfaceを`HT-NEIGHBOR`に、2つ目のinterfaceを`HT-TARGET`にjoinさせる。general bridgeは有効にせず、host firewallを通じてtarget service/portのみを許可する。
4. workstationからpivotへのauthenticated tunnelを開き、その経由でtarget serviceにアクセスする。
5. pivot process/interfaceの作成、両方のAP association、target RADIUS event、DHCP lease、target source addressを記録する。
6. controller mapなしでchainを再構成するよう、detection teamに依頼する。
7. `HT-TARGET`でEAP-TLS/managed-device postureを有効にし、pivotのapproved target certificateを削除して再実行する。admission時点でアクセスが失敗するはずである。
8. first-seen randomized MACを使って再実行する。certificate/deviceのdecisionが引き続き機能し、MACだけをidentityとして扱うruleがないことを確認する。

### Success criteria

- targetが最初に認識するのはworkstationではなく、local Wi-Fi clientである。
- Joined telemetryから、neighbor-control pathとtarget-radio pathを同時に持つ1つのpivotを特定できる。
- certificate/device-backed admissionによって2回目のrunがblockされる。
- isolated labの外部にあるnetworkへpacketが到達しない。

## Lab 5: dead-drop resolver sequence

**Objective:** 正規に見えるobjectを読み取り、pointerをdecodeして直ちに2つ目のserviceへcontactするprocessを検出する。

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
エンコードされたコンテンツは `http://ht-ddr-c2:80/` です。検出では、同じ短命のプロセス/コンテナが `/profile.txt` を読み取り、コンテンツをデコードして数秒以内に `ht-ddr-c2` に接続していることを関連付けます。オブジェクトのレスポンスをハッシュ化して保持します。

### Teardown
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: 合成 peel-chain と bridge graph

**Objective:** 実際の assets、accounts、services を使わずに、value tracing を練習する。

### データセットの作成と追跡
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
アナリストは peel/change pattern を特定し、bridge link は個別に裏付けが必要な推論として扱い、手数料と価値の差を計算し、その交換を off-chain evidence request として記録すること。1つの値または時刻を変更し、信頼度がどのように変化するかを記録する。

### Teardown
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: passive traffic-signaling sensor

**Objective:** shell、persistence、remote access を作成せず、passive な magic-value-activated implant の network signature をエミュレートする。listener は loopback のみに bind し、benign な event を記録する。
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
期待される結果：通常のトラフィックではアプリケーションイベントは生成されず、指定された token のみが生成される。実行中の loopback トラフィックをキャプチャし、network sensor が両方の datagram を引き続き確認できることを検証する。次に、予期しない長時間稼働の packet listener または packet-capture filter を検出する host controls を評価する。実際の RedPenguin passive implants は router 上のトラフィックを検査し、危険な機能を提供していた。この lab では意図的にそのどちらも行わない。

## Exercise report template

すべての lab について、以下を記録する：

- authorization と隔離された scope；
- hypothesis と ATT&CK technique；
- topology と observer table；
- 正確な開始・終了時刻と configuration hashes；
- sensor ごとの expected events；
- 実際に観測された events と retention gaps；
- analytic logic、threshold、false-positive sample；
- target team が path を再構築できたか；
- mitigation retest の結果；および
- teardown/recovery の証拠。

mitigation 後に detection を再実行し、すべての lab resource を削除するまで、exercise は完了とはみなされない。

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — 最近隣攻撃](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
