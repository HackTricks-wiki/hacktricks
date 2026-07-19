# ローカルネットワークとソケットのトリアージ

{{#include ../../banners/hacktricks-training.md}}

Linux host 上で shell を取得した後、最も有用な network target は、外部に公開されていないことがよくあります。Loopback 専用サービス、veth network、Unix socket、一時的な listener、packet capture、ローカル firewall ルールから、credential やローカル限定の attack surface が漏洩する可能性があります。

このページでは、一般的な remote network pentesting ではなく、実践的なローカル post-exploitation technique に焦点を当てます。

## Loopback とローカルサービスの列挙

まず、listening service、その bind address、そして権限が許す場合は所有 process を特定します：
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
- `/run`、`/var/run`、`/tmp`、またはアプリケーションディレクトリ配下の Unix ソケット: ローカル IPC サーフェス。

軽量なプローブでローカルポートをマッピングします:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
利用可能な場合は、ローカルで `nmap` を使用します:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## 非表示の veth とコンテナサブネット

コンテナ化された環境や lab 環境では、サービスが bridge または veth サブネット上でのみ公開されていることがよくあります。サービスに到達できないと判断する前に、インターフェースとルートを列挙してください：
```bash
ip -br addr
ip route
ip neigh
```
推定されるローカルサブネットを特定する:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
発見したサブネットを慎重にプローブする:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
このtechniqueは、Webパネル、debug endpoint、またはhelper serviceが外部スキャンからは隠れているものの、侵害されたhostまたはcontainer networkから到達可能な場合に有用です。

## socatまたはSSHによるLocal Pivot

service自体を変更する代わりに、許可されたチャネルを介してloopbackにbindされたserviceを公開します。

SSHでローカル専用HTTP serviceをforwardします：
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
すでに shell access がある場合に、`socat` でローカルポートをブリッジする：
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
ローカルテスト用にUnixソケットをTCPへ転送:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
これは、それ自体で何かを exploit するものではありません。ローカル限定の surface を tooling から到達可能にし、通常の service と同じように対話できるようにします。

## Banner Grabbing と Simple Protocols

すべての service が HTTP とは限りません。多くのローカル service は、banner や 1 行の protocol を通じて十分な情報を leak します。

Basic probes:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
ブラウザを使わない HTTP チェック：
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
TLSの場合：
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
目的は、protocol、authentication scheme、version、および service が local clients を信頼するかどうかを特定することです。

## ループバックトラフィックのキャプチャ

Local traffic から、headers、bearer tokens、Basic Auth credentials、または application-specific secrets が漏洩する可能性があります。承認された環境でのみキャプチャしてください。

ループバック HTTP トラフィックをキャプチャします：
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
特定のローカルサービスをキャプチャする：
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
キャプチャまたはログに記録されたヘッダーから Basic Auth をデコードする：
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
テキストキャプチャで探すと役立つ文字列：
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

ラボ環境でクライアントプロセスの環境を制御できる場合、`SSLKEYLOGFILE` を使用すると、TLS セッションを Wireshark または互換ツールで復号可能にできます。これは、TLS 自体を攻撃せずにローカルの HTTPS トラフィックを理解するのに役立ちます。

Key logging を有効にしてクライアントを実行します：
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
同時にトラフィックをキャプチャします:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
その後、`/tmp/tls.pcap` と `/tmp/sslkeys.log` を Wireshark に読み込みます。これは、client library が NSS-style key logging をサポートし、接続が確立される前に環境を設定できる場合にのみ機能します。

## Unix Socket Interaction and Command Injection

Unix ソケットはローカル IPC endpoint です。HTTP API、custom protocol、または安全でない command handler を公開している可能性があります。

ソケットを検索:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix socket 経由で HTTP を操作する:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Raw socket を操作する:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
ユーザーが制御する socket 入力が shell または特権 helper に渡されると、command injection につながる可能性があります。対象を絞った例については、[Socket Command Injection](socket-command-injection.md) を参照してください。

## nftables Review and Authorized Rule Changes

ローカル firewall ルールは、あるサービスがローカルでは表示される一方でリモートからはブロックされる理由や、高いポート番号が一方の interface から到達不能に見える理由を説明できる場合があります。

ルールを確認します：
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
対象ポートに影響する drop を確認する:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
認可されたラボ環境で、handle を指定して特定のブロッキングルールを削除します：
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
完全なテーブルをフラッシュするよりも、正確なハンドルを削除することを優先します。この technique では、動作の原因となっている正確なフィルターを特定し、そのルールだけを変更します。

## 簡易ワークフロー
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
local-only で、より高い権限を持つユーザーとして実行され、管理者/デバッグ機能を公開している、または loopback/container-network クライアントを信頼するサービスを優先します。
{{#include ../../banners/hacktricks-training.md}}
