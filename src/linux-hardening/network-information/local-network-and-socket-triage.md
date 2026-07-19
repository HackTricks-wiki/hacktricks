# ローカルネットワークとソケットのトリアージ

{{#include ../../banners/hacktricks-training.md}}

Linux host で shell を取得した後、最も有用な network target は、外部には公開されていないことが多くあります。loopback 専用サービス、veth network、Unix socket、一時的な listener、packet capture、ローカル firewall rule から、credential やローカル限定の attack surface が露出する可能性があります。

このページでは、一般的なリモート network pentesting ではなく、実践的なローカル post-exploitation technique に焦点を当てます。

## Loopback とローカルサービスの Enumeration

まず、listening service、その bind address、そして権限が許可する場合は所有 process を特定します。
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
重要なパターン:

- `127.0.0.1:<port>` または `[::1]:<port>`: デフォルトではホストからのみ到達可能。
- `0.0.0.0:<port>`: フィルタリングされていない限り、すべての IPv4 インターフェースから到達可能。
- `veth*`、`docker*`、`br-*`、`cni*` 上の `172.x`、`10.x`、`192.168.x`: コンテナまたはローカルラボネットワークの可能性が高い。
- `/run`、`/var/run`、`/tmp`、またはアプリケーションディレクトリ下の Unix sockets: ローカル IPC surfaces。

軽量な probe でローカルポートをマッピングします:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
利用可能な場合は、ローカルで `nmap` を使用します。
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Hidden veth と Container サブネット

Container 化された環境や lab 環境では、bridge または veth サブネット上でのみサービスが公開されていることがよくあります。サービスに到達できないと判断する前に、interface と route を列挙してください:
```bash
ip -br addr
ip route
ip neigh
```
可能性の高いローカルサブネットを特定する：
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
発見したサブネットを慎重にプローブする:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
この technique は、web panel、debug endpoint、または helper service が外部スキャンからは隠れているものの、compromised host または container network から到達可能な場合に有用です。

## socat または SSH を使用した Local Pivot

service が loopback に bind されている場合は、service 自体を変更するのではなく、許可された channel を通じて公開します。

SSH を使用して local-only HTTP service を forward します：
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
すでに shell access を取得している場合、`socat` でローカルポートをブリッジする：
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
ローカルテスト用にUnix socketをTCPへ転送する:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
これは、それ自体で何かを exploit するものではありません。local-only の surface を tooling から到達可能にし、通常の service と同じように操作できるようにします。

## Banner Grabbing と Simple Protocols

すべての service が HTTP であるとは限りません。多くの local service は、banner または 1 行の protocol を通じて、十分な情報を leak します。

Basic probes:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
ブラウザを使わないHTTPチェック:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
TLSの場合:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
目的は、protocol、authentication scheme、version、およびserviceがlocal clientsを信頼するかどうかを特定することです。

## Loopback Trafficのキャプチャ

Local trafficには、headers、bearer tokens、Basic Auth credentials、またはapplication-specific secretsが含まれている可能性があります。認可された環境でのみキャプチャしてください。

Loopback HTTP trafficをキャプチャします：
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
特定のローカルサービスをキャプチャする：
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
捕捉またはログ記録されたヘッダーからBasic Authをデコードする：
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
テキストキャプチャで探すと役立つ文字列：
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

ラボで client process の環境を制御できる場合、`SSLKEYLOGFILE` を使うと、TLS sessions を Wireshark または互換性のある tooling で復号可能にできます。これは、TLS 自体を攻撃せずに local HTTPS traffic を把握するのに役立ちます。

key logging を有効にして client を実行します：
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
同時にトラフィックをキャプチャする:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
その後、`/tmp/tls.pcap` と `/tmp/sslkeys.log` を Wireshark に読み込みます。これは、client library が NSS-style key logging をサポートしており、接続が確立される前に環境を設定できる場合にのみ機能します。

## Unix Socket Interaction と Command Injection

Unix sockets はローカル IPC endpoint です。HTTP APIs、custom protocols、または安全でない command handlers を公開している可能性があります。

Sockets を見つける:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix socket 経由で HTTP と通信する:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
raw socket を操作する：
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
ユーザーが制御する socket input が shell または privileged helper に渡されると、command injection につながる可能性があります。具体的な例については、[Socket Command Injection](socket-command-injection.md) を参照してください。

## nftables Review and Authorized Rule Changes

Local firewall rules により、ある service がローカルでは表示される一方で remote からはブロックされる理由や、high port がある interface から到達不能に見える理由を説明できる場合があります。

ルールを確認します：
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
対象ポートに影響するドロップを探す:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
認可されたラボ環境で、handle を指定して特定のブロッキングルールを削除します：
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
完全なテーブルをフラッシュするよりも、正確なハンドルを削除することを優先します。この technique では、動作の原因となっている正確なフィルターを特定し、そのルールだけを変更します。

## Quick Workflow
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
ローカル専用である、より高い権限を持つユーザーとして実行される、管理者用/デバッグ機能を公開している、またはループバック/コンテナネットワークのクライアントを信頼するサービスを優先します。
