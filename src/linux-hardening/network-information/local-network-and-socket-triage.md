# Local Network and Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Linux host 上で shell を取得した後、最も有用な network target は、外部からは公開されていないことがよくあります。Loopback-only service、veth network、Unix socket、一時的な listener、packet capture、local firewall rule によって、credential や local-only attack surface が露出する可能性があります。

このページでは、一般的な remote network pentesting ではなく、実践的な local post-exploitation technique に焦点を当てます。

## Loopback and Local Service Enumeration

まず、listening service、その bind address、そして権限が許す場合は所有 process を特定します。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
重要なパターン:

- `127.0.0.1:<port>` または `[::1]:<port>`: デフォルトではホストからのみ到達可能。<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: フィルタリングされていない限り、すべての IPv4 インターフェースで到達可能。<sup>[[3]](#references)</sup>
- `veth*`、`docker*`、`br-*`、`cni*` 上の `10.0.0.0/8`、`172.16.0.0/12`、または `192.168.0.0/16`: コンテナまたはローカルラボネットワークの可能性が高い。<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`、`/var/run`、`/tmp`、またはアプリケーションディレクトリ下の Unix ソケット: ローカル IPC サーフェス。<sup>[[5]](#references)</sup>

軽量な probe でローカルポートをマッピングする。<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
利用可能な場合は、ローカルで `nmap` を使用します。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Hidden veth と Container Subnets

Containerized または lab 環境では、bridge または veth subnet 上でのみ services が公開されていることがよくあります。service に到達できないと判断する前に、interfaces と routes を列挙してください。<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
ローカルサブネットの候補を特定する。<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
発見したサブネットを慎重に探査する。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
この technique は、web panel、debug endpoint、または helper service が外部スキャンからは隠されているものの、compromised host または container network から到達可能な場合に有用です。

## socat または SSH を使用した Local Pivot

service 自体を変更する代わりに、許可された channel 経由で loopback に bind された service を公開します。

SSH を使用して local-only HTTP service を forward します。<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
すでに shell access を取得している場合は、`socat` でローカルポートを bridge します。<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
ローカルテスト用にUnixソケットをTCPへフォワードします。<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
これは単独では何も exploit しません。local-only の surface を tooling から到達可能にし、通常の service と同じように操作できるようにします。

## Banner Grabbing と Simple Protocols

すべての service が HTTP とは限りません。多くの local service は、banner または 1 行の protocol を通じて十分な情報を leak します。

基本的な probe。<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
ブラウザを使用しないHTTPチェック。<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
TLSの場合。<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
目的は、protocol、authentication scheme、version、および service が local clients を信頼するかどうかを特定することです。

## Loopback Traffic のキャプチャ

Local traffic からは、headers、bearer tokens、Basic Auth credentials、または application-specific secrets が漏えいする可能性があります。<sup>[[17]](#references)[[25]](#references)</sup> 認可された環境でのみ capture してください。

Loopback HTTP traffic を capture します。<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
特定のローカルサービスをキャプチャする。<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
キャプチャまたはログに記録されたヘッダーから Basic Auth をデコードする。<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
テキストキャプチャで探すと有用な文字列：
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

ラボで client process の環境を制御できる場合、`SSLKEYLOGFILE` によって TLS セッションを Wireshark または互換ツールで復号可能にできます。<sup>[[19]](#references)[[20]](#references)</sup> これは、TLS 自体を攻撃せずにローカルの HTTPS トラフィックを把握する際に役立ちます。

key logging を有効にして client を実行します。<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
同時にトラフィックをキャプチャします。<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
その後、`/tmp/tls.pcap` と `/tmp/sslkeys.log` を Wireshark に読み込みます。これは、client library が NSS-style key logging をサポートし、接続が確立される前に環境を設定できる場合にのみ機能します。<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket Interaction と Command Injection

Unix sockets はローカル IPC endpoints です。<sup>[[5]](#references)</sup> HTTP APIs、custom protocols、または安全でない command handlers を公開している可能性があります。<sup>[[12]](#references)[[14]](#references)</sup>

sockets を探します。<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix socket 経由で HTTP と通信する。<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Raw socketを操作する。<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
ユーザーが制御する socket の入力が shell や privileged helper に渡されると、command injection につながる可能性があります。<sup>[[26]](#references)</sup> 集中的な例については、[Socket Command Injection](socket-command-injection.md) を参照してください。

## nftables の確認と承認済みルールの変更

ローカル firewall のルールによって、サービスがローカルでは表示されるもののリモートからはブロックされる理由や、高いポートがあるインターフェースから到達不能に見える理由を説明できる場合があります。<sup>[[22]](#references)</sup>

ルールを確認します。<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
対象ポートに影響する drop を探します。<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
認可されたラボ環境で、ハンドルを指定して特定のブロッキングルールを削除します。<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
完全なテーブルをフラッシュするよりも、正確なハンドルを削除することを優先します。この technique では、挙動の原因となっている正確な filter を特定し、その rule だけを変更します。<sup>[[22]](#references)</sup>

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
ローカルのみで利用可能なサービス、より高い権限を持つユーザーとして実行されるサービス、admin/debug 機能を公開するサービス、または loopback/container-network クライアントを信頼するサービスを優先します。

## References

- [1] [ss(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux マニュアルページ](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP Version 6 アドレス体系](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux マニュアルページ](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [リダイレクト（Bash リファレンスマニュアル）](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout の呼び出し（GNU Coreutils）](https://www.gnu.org/s/coreutils/timeout)
- [8] [ポートスキャン技術（Nmap リファレンスガイド）](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [ホスト検出（Nmap リファレンスガイド）](https://nmap.org/book/man-host-discovery.html)
- [10] [ポート指定とスキャン順序（Nmap リファレンスガイド）](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux マニュアルページ](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD マニュアルページ](https://man.openbsd.org/nc.1)
- [14] [curl コマンドラインツールマニュアル](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL ドキュメント](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: 「Basic」HTTP 認証スキーム](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 の呼び出し（GNU Coreutils）](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL ドキュメント](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark ユーザーズガイド](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables マニュアル](https://netfilter.org/projects/nftables/manpage.html)
- [23] [プライベートインターネット向けアドレス割り当て（RFC 1918）](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 認可フレームワーク: Bearer Token の使用（RFC 6750）](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: OS コマンドで使用される特殊要素の不適切な無害化](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
