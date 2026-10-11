# ローカルネットワークとソケットのトリアージ

{{#include ../../banners/hacktricks-training.md}}

Linux ホスト上で shell を取得した後、最も有用なネットワーク上の標的は、外部に公開されていないことがよくあります。loopback のみで待ち受けるサービス、veth ネットワーク、Unix ソケット、一時的な listener、パケットキャプチャ、ローカルのファイアウォールルールから、認証情報やローカル限定の攻撃対象領域が見つかることがあります。

このページでは、一般的なリモートネットワークの pentesting ではなく、実践的なローカルでの post-exploitation 手法に焦点を当てます。

## Loopback とローカルサービスの列挙

まず、待ち受け中のサービス、その bind アドレス、権限が許す場合は所有プロセスを特定します。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

重要なパターン:

- `127.0.0.1:<port>` または `[::1]:<port>`: デフォルトではホストからのみ到達可能。<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: フィルタリングされていない限り、すべての IPv4 インターフェースから到達可能。<sup>[[3]](#references)</sup>
- `veth*`、`docker*`、`br-*`、`cni*` 上の `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`: コンテナまたはローカルラボのネットワークである可能性が高い。<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`、`/var/run`、`/tmp`、またはアプリケーションディレクトリ内の Unix ソケット: ローカル IPC の攻撃対象領域。<sup>[[5]](#references)</sup>

過去の [snapd socket parsing issue, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing) については、稼働中のデーモン、そのローカル API ソケット、およびインストール済みパッケージまたは snap のリビジョンを、そのディストリビューション向けの修正と照合してください。このバグは snapd における peer のソケットアドレス検証にあり、`snap-confine` の問題ではありません。set-user-ID の `snap-confine` ファイルや upstream のバージョン文字列だけでは、影響の有無を判断できません。Ubuntu はリリースごとのパッケージバージョンで修正を提供しており、snapd はディストリビューションのパッケージとは別に snap から更新されている可能性があります。特権 API の境界を評価する前に、実際に稼働しているビルドとローカルソケットへの到達性を確認してください。Passive enumeration では、細工したソケットリクエストを送信したり、snap をインストールしたりしないでください。

[`socat` の `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) を使って起動した loopback listener は、ローカルクライアントからの入力を別のプログラムに渡すことができます。root 所有のカスタムサービスを privilege-escalation の手掛かりと見なす前に、listener のコマンド、実行ファイルのパス、子プロセスの実効 identity、ローカルからの到達性、および認証を関連付けて確認してください。メモリ安全性の欠陥や、安全でない入力からコマンドへの経路については、対象のバイナリとビルドに関する証拠が必要です。ポート番号、`socat` プロセス、または root 所有であることだけでは、欠陥の存在を証明できません。Passive enumeration は、サービスに入力を送信せず、プロセス、ソケット、ファイルのメタデータの確認にとどめてください。

ローカルの Salt master は、loopback またはコンテナから公開されたホストポートを含め、TCP 4505 と 4506 で listen する場合があります。[Salt の 3000.2 release notes](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) には、CVE-2020-11651 の認証不要な method-access の欠陥が記載されており、この問題は upstream の 2019.2.4 と 3000.2 で修正されています。listener を privilege-escalation の手掛かりと見なす前に、実際の `salt-master` プロセス、到達可能なインターフェース、インストール済みパッケージとベンダーによるパッチ、およびコンテナまたはホスト上での実効 identity を関連付けて確認してください。ポートや upstream のバージョンだけでは、問題の存在を証明できません。master がコンテナ内で稼働している場合、ホスト root への影響は別の境界の問題です。そのコンテナに、利用可能なホスト runtime API ソケットがマウントされ、アクセス可能であることを確認してください。影響の有無を判断するために、Passive enumeration で Salt request server に問い合わせたり、コンテナを作成したりしないでください。[Salt の port documentation](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) と [runtime API triage](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) を参照してください。

軽量な probe でローカルポートをマッピングします。<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

利用可能な場合は、ローカルで `nmap` を使用してください。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## 隠れた veth とコンテナサブネット

コンテナ環境やラボ環境では、bridge または veth サブネット上でのみサービスが公開されていることがあります。サービスに到達できないと判断する前に、インターフェースとルートを列挙してください。<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

可能性の高いローカルサブネットを特定します。<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

発見したサブネットを慎重にプローブする。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

この手法は、Webパネル、デバッグエンドポイント、またはヘルパーサービスが外部スキャンからは隠れているものの、侵害されたホストやコンテナネットワークから到達できる場合に役立ちます。

ループバック上のノートブックサービスは、起動時にプロセス出力へ表示されるトークンで認証する場合があります。その出力が別のローカルアカウントから読み取り可能なログにリダイレクトされていると、トークンがユーザー境界を越えて漏えいし、ノートブックサーバーのアカウントでコード実行できる可能性があります。ログパスを権限昇格の手がかりとみなす前に、リスニングプロセスの所有者、ログの保存先と権限、現在のトークン設定、ノートブックのアクセス制御を照合してください。パッシブな列挙ではログのメタデータを確認し、ホストを分類するだけの目的でトークンを表示したり、サービスに接続したりしないでください。

## socat または SSH を使ったローカル Pivot

サービスがループバックにバインドされている場合は、サービス自体を変更せず、許可されたチャネルを通じて公開します。

SSHを使ってローカル限定のHTTPサービスを転送します。<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

すでに shell access がある場合は、`socat` でローカルポートをブリッジします。<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

ローカルテスト用に Unix socket を TCP に転送する。<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

これは単独では何も exploit しません。ローカル限定の surface をツールから到達可能にし、通常のサービスと同じように操作できるようにします。

## Banner Grabbing とシンプルなプロトコル

すべてのサービスが HTTP とは限りません。多くのローカルサービスは、banner や1行のプロトコルを通じて十分な情報を leak します。

基本的な probe。<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

ブラウザーを使わないHTTPチェック。<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

TLSの場合。<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

目的は、プロトコル、認証方式、バージョン、およびサービスがローカルクライアントを信頼しているかどうかを特定することです。

aiohttp listener では、バージョンだけでなく静的ルートの設定も確認してください。CVE-2024-23334 は、`follow_symlinks=True` が有効な静的ルートを使用する aiohttp 3.9.2 未満に影響します。このルートへのリクエストによって、静的ルートのルートディレクトリ外のファイルを読み取られる可能性があります。サービスが root で実行されている場合、ルートディレクトリからアクセス可能なファイルが漏えいする可能性があります。ただし、ルートにアクセスできることが前提です。バージョンバナーやループバックへのバインドだけでは、脆弱な設定やファイルへのアクセスが確認されたことにはなりません。<sup>[[27]](#references)</sup>

## ループバックトラフィックのキャプチャ

ローカルトラフィックには、ヘッダー、ベアラートークン、Basic Auth の認証情報、アプリケーション固有のシークレットが含まれる場合があります。<sup>[[17]](#references)[[25]](#references)</sup> 許可された環境でのみキャプチャしてください。

ループバックの HTTP トラフィックをキャプチャします。<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

特定のローカルサービスをキャプチャする。<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

キャプチャまたはログに記録されたヘッダーから Basic Auth をデコードします。<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

テキストキャプチャで探すと役立つ文字列:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS Key Logging

ラボで client process の環境を制御できる場合、`SSLKEYLOGFILE` を使うと、Wireshark または互換ツールで TLS セッションを復号できます。<sup>[[19]](#references)[[20]](#references)</sup> TLS 自体を攻撃せずにローカルの HTTPS トラフィックを把握するのに役立ちます。

key logging を有効にして client を実行します。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

同時にトラフィックをキャプチャしてください。<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

次に、`/tmp/tls.pcap` と `/tmp/sslkeys.log` を Wireshark に読み込みます。これは、クライアントライブラリが NSS 形式の鍵ログに対応し、接続前に環境を設定できる場合にのみ機能します。<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socketとのやり取りとCommand Injection

Unix socketはローカルの IPC エンドポイントです。<sup>[[5]](#references)</sup> HTTP API、独自プロトコル、または安全でないコマンドハンドラーを公開している場合があります。<sup>[[12]](#references)[[14]](#references)</sup>

グループに書き込み権限があるroot所有のsocketは、認可境界であり、それ自体が脆弱性というわけではありません。リスクを判断する前に、グループとモードを現在のアカウントと照合し、待ち受けているプロセスを特定して、そのプロセスがクライアントから受け付ける内容を確認してください。特に、送信されたPHPを実行する特権サービスが、呼び出し元の指定した`php.ini`パスも信頼していたり、呼び出し元が`disable_functions`や`open_basedir`を変更できたりする場合、別の境界を越える可能性があります。有効な設定とサービスの検証処理を調べてください。[PHP configuration guide](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md)では、これらのディレクティブについて説明しています。socketのメタデータだけでは、コード実行が可能だとは判断できません。

socketを見つけます。<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Unix socket を介して HTTP とやり取りする。<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

raw socketを操作します。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

ユーザーが制御できる socket 入力が shell や特権 helper に渡されると、command injection につながる可能性があります。<sup>[[26]](#references)</sup> 具体例については、[Socket Command Injection](socket-command-injection.md) を参照してください。

## nftables の確認と許可されたルール変更

ローカルの firewall ルールは、サービスがローカルでは見えるのにリモートからはブロックされる理由や、あるインターフェースから高位ポートに到達できない理由を説明できる場合があります。<sup>[[22]](#references)</sup>

ルールを確認してください。<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

対象ポートに影響するパケット破棄を探します。<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

認可されたラボ環境で、handle を指定して特定のブロッキングルールを削除します。<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

テーブル全体を flush するより、該当する handle を削除することを優先してください。この手法では、挙動の原因となっているフィルターを正確に特定し、そのルールだけを変更します。<sup>[[22]](#references)</sup>

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

ローカルからのみアクセスできるサービス、より高い権限のユーザーで実行されるサービス、admin/debug 機能を公開するサービス、または loopback/container-network のクライアントを信頼するサービスを優先してください。

## References

- [1] [ss(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux マニュアルページ](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP バージョン 6 アドレス体系](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux マニュアルページ](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [リダイレクト (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout の呼び出し (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [ポートスキャンの手法 (Nmap Reference Guide)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [ホストの検出 (Nmap Reference Guide)](https://nmap.org/book/man-host-discovery.html)
- [10] [ポートの指定とスキャン順序 (Nmap Reference Guide)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux マニュアルページ](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD マニュアルページ](https://man.openbsd.org/nc.1)
- [14] [curl コマンドラインツールのマニュアル](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL ドキュメント](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: 「Basic」HTTP 認証スキーム](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 の呼び出し (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL ドキュメント](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark ユーザーガイド](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables マニュアル](https://netfilter.org/projects/nftables/manpage.html)
- [23] [プライベートインターネットのアドレス割り当て (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 認可フレームワーク: Bearer Token の使用 (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: OS コマンドで使用される特殊要素の不適切な無害化](https://cwe.mitre.org/data/definitions/78.html)
- [27] [aiohttp メンテナーによる勧告: follow_symlinks を使用した静的ルートのトラバーサル](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
{{#include ../../banners/hacktricks-training.md}}
