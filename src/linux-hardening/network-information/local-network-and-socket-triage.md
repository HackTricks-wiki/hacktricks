# Local Network and Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Linux host 上で shell を取得した後、最も有用な network target は、外部に公開されていないことがよくあります。Loopback-only service、veth network、Unix socket、一時的な listener、packet capture、local firewall rule から、credential や local-only attack surface が露出する可能性があります。

このページでは、一般的な remote network pentesting ではなく、実践的な local post-exploitation technique に焦点を当てます。

## Loopback と Local Service Enumeration

まず、listening service、その bind address、そして権限が許可する場合は所有する process を特定します:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
重要なパターン:

- `127.0.0.1:<port>` または `[::1]:<port>`: デフォルトではホストからのみ到達可能。
- `0.0.0.0:<port>`: フィルタリングされていない限り、すべての IPv4 インターフェースから到達可能。
- `veth*`、`docker*`、`br-*`、`cni*` 上の `172.x`、`10.x`、または `192.168.x`: コンテナまたはローカルラボネットワークの可能性が高い。
- `/run`、`/var/run`、`/tmp`、またはアプリケーションディレクトリ下の Unix ソケット: ローカル IPC サーフェス。

軽量なプローブでローカルポートをマッピングします:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
利用可能な場合は、ローカルで `nmap` を使用します：
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Hidden veth と Container Subnets

Container 化された環境や lab 環境では、サービスが bridge または veth サブネット上でのみ公開されていることがよくあります。サービスに到達できないと判断する前に、インターフェースとルートを列挙します。
```bash
ip -br addr
ip route
ip neigh
```
可能性の高いローカルサブネットを特定する：
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
発見されたサブネットを慎重にプローブする：
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
この technique は、web panel、debug endpoint、または helper service が外部スキャンからは隠されているものの、侵害されたホストまたはコンテナネットワークから到達可能な場合に有用です。

## socat または SSH を使った Local Pivot

service 自体を変更するのではなく、許可された channel を通じて loopback に bind された service を公開します。

SSH で local-only HTTP service を forward します：
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
すでに shell access がある場合に、`socat` でローカルポートを bridge する:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
ローカルテスト用にUnix socketをTCPへ転送する：
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
これは、それ自体で何かを exploit するものではありません。ローカル限定の surface を tooling から到達可能にし、通常の service と同じように操作できるようにします。

## Banner Grabbing and Simple Protocols

すべての service が HTTP とは限りません。多くのローカル service は、banner や一行プロトコルを通じて十分な情報を leak します。

Basic probes:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
ブラウザを使わないHTTPチェック：
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
TLSの場合：
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
目的は、protocol、authentication scheme、version、およびその service が local client を信頼するかどうかを特定することです。

## Loopback Traffic のキャプチャ

Local traffic から headers、bearer tokens、Basic Auth credentials、または application-specific secrets が露見する可能性があります。許可された環境でのみ capture してください。

Loopback HTTP traffic を capture します：
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
特定のローカルサービスをキャプチャする：
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
捕捉またはログに記録されたヘッダーから Basic Auth をデコードする:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
テキストキャプチャ内で探すと役立つ文字列:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

ラボで client process の environment を制御できる場合、`SSLKEYLOGFILE` を使用すると、TLS sessions を Wireshark または互換性のある tooling で decrypt 可能にできます。これは、TLS 自体を攻撃せずに local HTTPS traffic を理解するのに役立ちます。

key logging を有効にして client を実行します：
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
同時にトラフィックをキャプチャする：
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
次に、`/tmp/tls.pcap` と `/tmp/sslkeys.log` を Wireshark に読み込みます。これは、クライアントライブラリが NSS-style key logging をサポートし、接続が確立される前に環境を設定できる場合にのみ機能します。

## Unix Socket の操作と Command Injection

Unix socket はローカル IPC endpoint です。HTTP API、custom protocol、または安全でない command handler が公開されている可能性があります。

socket を検索します：
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix socket 経由で HTTP と通信する:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
raw socket を操作する:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
ユーザーが制御する socket の入力が shell または privileged helper に渡されると、command injection につながる可能性があります。具体的な例については、[Socket Command Injection](socket-command-injection.md) を参照してください。

## nftables の確認と承認済みルールの変更

ローカル firewall のルールによって、あるサービスがローカルでは見えるのにリモートからはブロックされる理由や、高いポート番号が特定のインターフェースから到達不能に見える理由を説明できる場合があります。

ルールを確認します：
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
target port に影響する drop を探す:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
認可されたラボ環境で、handle を指定して特定のブロッキングルールを削除します：
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
完全なテーブルを flush するより、正確な handle を削除することを優先します。この technique では、動作の原因となっている正確な filter を特定し、その rule だけを変更します。

## クイックワークフロー
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
local-only で、より高い権限を持つユーザーとして実行され、admin/debug 機能を公開し、または loopback/container-network クライアントを信頼する services を優先します。

{{#include ../../banners/hacktricks-training.md}}
