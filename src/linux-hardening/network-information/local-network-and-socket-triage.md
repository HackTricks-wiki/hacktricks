# ローカルネットワークとソケットのトリアージ

{{#include ../../banners/hacktricks-training.md}}

Linuxホストでシェルを取得した後、最も有用なネットワーク上の標的は、外部に公開されていないことがよくあります。Loopback限定のサービス、vethネットワーク、Unixソケット、一時的なリスナー、パケットキャプチャ、ローカルファイアウォールのルールから、認証情報やローカル限定の攻撃対象領域が見つかることがあります。

このページでは、一般的なリモートネットワークのpentestingではなく、実践的なローカルpost-exploitationテクニックに焦点を当てます。

## Loopbackとローカルサービスの列挙

まず、リスニング中のサービス、そのバインドアドレス、権限が許す場合は所有プロセスを特定します。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

重要なパターン:

- `127.0.0.1:<port>` または `[::1]:<port>`: デフォルトではホストからのみ到達可能です。<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: フィルタリングされていない限り、すべての IPv4 インターフェースから到達可能です。<sup>[[3]](#references)</sup>
- `veth*`、`docker*`、`br-*`、`cni*` 上の `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`: コンテナまたはローカルラボのネットワークである可能性が高いです。<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`、`/var/run`、`/tmp`、またはアプリケーションのディレクトリ下にある Unix ソケット: ローカル IPC の攻撃対象です。<sup>[[5]](#references)</sup>

過去の [snapd socket parsing issue, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing) については、実行中のデーモン、そのローカル API ソケット、インストール済みパッケージまたは snap のリビジョンを、そのディストリビューション向けの修正と照らし合わせて調査してください。このバグは、`snap-confine` ではなく、snapd がピアのソケットアドレスを検証する処理にありました。set-user-ID の `snap-confine` ファイルや上流のバージョン文字列だけでは、脆弱性の有無を判断できません。Ubuntu はリリースごとに異なるパッケージバージョンで修正を提供しており、snapd はディストリビューションのパッケージとは別に snap から更新されている場合があります。特権 API の境界を評価する前に、実際に実行中のビルドとローカルソケットへの到達可能性を確認してください。パッシブな列挙では、細工したソケットリクエストを送信したり、snap をインストールしたりしないでください。

[`socat` の `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) を介して起動された loopback リスナーは、ローカルクライアントからの入力を別のプログラムに渡すことができます。root 所有のカスタムサービスを権限昇格の手掛かりとみなす前に、リスナーのコマンド、実行ファイルのパス、子プロセスの実効ユーザー ID、ローカルからの到達可能性、認証を照合してください。メモリ安全性の欠陥や、入力からコマンドに至る危険な経路については、特定のバイナリとビルドに関する証拠が必要です。ポート番号、`socat` プロセス、root 所有であることだけでは、その存在を確認できません。パッシブな列挙では、サービスに入力を送信せず、プロセス、ソケット、ファイルのメタデータの確認にとどめてください。

ローカルの Salt master は、loopback やコンテナからホストに公開されたポートを含め、TCP 4505 および 4506 でリッスンすることがあります。[Salt の 3000.2 リリースノート](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) には、認証なしでメソッドにアクセスできる脆弱性 CVE-2020-11651 と、上流バージョン 2019.2.4 および 3000.2 での修正について記載されています。権限昇格の手掛かりとみなす前に、リスナーが実際の `salt-master` プロセスに対応していること、到達可能なインターフェース、インストール済みパッケージとベンダーによる修正、実効的なコンテナまたはホストの ID を照合してください。ポートや上流バージョンだけでは証拠になりません。master がコンテナ内で動作している場合、ホストの root への影響は別の境界の問題です。そのコンテナに、利用可能なホストのランタイム API ソケットがマウントされ、アクセス可能であることを確認してください。露出の有無を判断するために、パッシブな列挙で Salt のリクエストサーバーに問い合わせたり、コンテナを作成したりしないでください。[Salt のポートに関するドキュメント](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) および [runtime API triage](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) を参照してください。

軽量なプローブでローカルポートをマッピングします。<sup>[[6]](#references)[[7]](#references)</sup>

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

## 隠れた veth とコンテナのサブネット

コンテナ化された環境やラボ環境では、サービスが bridge または veth のサブネット上でのみ公開されていることがあります。サービスに到達できないと決めつける前に、インターフェースとルートを列挙してください。<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

可能性の高いローカルサブネットを特定する。<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

検出したサブネットを慎重にプローブする。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

この手法は、Web パネル、デバッグエンドポイント、またはヘルパーサービスが外部スキャンからは隠れているものの、侵害したホストやコンテナネットワークから到達できる場合に有用です。

## ユーザー境界をまたぐ Notebook サービストークン

loopback 上の notebook サービスは、起動時にプロセス出力へ出力されるトークンで認証する場合があります。その出力が別のローカルアカウントから読み取り可能なログにリダイレクトされていると、トークンがユーザー境界を越え、notebook サーバーのアカウントでコード実行できる可能性があります。ログパスを権限昇格の手掛かりとみなす前に、待ち受けプロセスの所有者、ログの保存先と権限、現在のトークン設定、notebook のアクセス制御を照合してください。受動的な列挙ではログのメタデータを確認し、トークンを出力したり、ホストを分類する目的だけでサービスに接続したりしないでください。

Jupyter Lab サービスでは、起動ログだけでなく、読み取り可能な systemd `ExecStart` や実行中のコマンドライン（`ps auxww`）にトークンが含まれている場合もあります。報告された例では、`User=analyst` と `--ServerApp.token` により、認証情報と `127.0.0.1:8888` の待ち受けプロセスを実行するアカウントの両方が特定されました。ホストにアクセスできる場合、トークンと `ssh -L 8888:127.0.0.1:8888 user@host` を使うことで、そのサービスユーザーとして Jupyter Lab の Terminal にアクセスできました。unit の実効ユーザー、プロセス引数、待ち受けポート、トークンの有効性をまとめて確認してください。loopback へのバインドだけでは、認可の境界になりません。<sup>[[28]](#references)</sup>

## socat または SSH によるローカルピボット

サービスが loopback にバインドされている場合は、サービス自体を変更せず、許可されたチャネル経由で公開します。

SSH でローカル限定の HTTP サービスを転送します。<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

シェルアクセスがすでにある場合は、`socat`でローカルポートをブリッジします。<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

ローカルテスト用に Unix ソケットを TCP に転送する。<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

これは単独では何も exploit しません。ローカル限定のサーフェスにツールからアクセスできるようにし、通常のサービスのようにやり取りできるようにします。

## Banner Grabbing とシンプルなプロトコル

すべてのサービスが HTTP とは限りません。多くのローカルサービスは、banner や1行のプロトコルを通じて十分な情報を leak します。

基本的なプローブ。<sup>[[13]](#references)</sup>

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

目的は、プロトコル、認証方式、バージョン、およびサービスがローカルクライアントを信頼するかどうかを特定することです。

aiohttp listener では、バージョンだけでなく static-route の設定も確認してください。CVE-2024-23334 は、`follow_symlinks=True` を有効にした static route がある場合、aiohttp 3.9.2 より前のバージョンに影響します。その route へのリクエストによって、static root の外部にあるファイルを読み取られる可能性があります。サービスが root で実行されている場合、route に到達できれば、root が読み取り可能なファイルが露出するおそれがあります。バージョンバナーや loopback bind だけでは、脆弱な設定やファイルへのアクセスがあるとは判断できません。<sup>[[27]](#references)</sup>

## ループバックトラフィックのキャプチャ

ローカルトラフィックから、ヘッダー、bearer token、Basic Auth の認証情報、またはアプリケーション固有のシークレットが漏れる可能性があります。<sup>[[17]](#references)[[25]](#references)</sup> 許可された環境でのみキャプチャしてください。

ループバック HTTP トラフィックをキャプチャします。<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

特定のローカルサービスをキャプチャする。<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

取得またはログに記録されたヘッダーからBasic Authをデコードします。<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

テキストキャプチャ内で探すと役立つ文字列:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS Key Logging

ラボ環境でクライアントプロセスの環境を制御できる場合、`SSLKEYLOGFILE`を使うと、Wiresharkや互換ツールでTLSセッションを復号できます。<sup>[[19]](#references)[[20]](#references)</sup> TLS自体を攻撃せずに、ローカルのHTTPSトラフィックを把握するのに役立ちます。

key loggingを有効にしてクライアントを実行します。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

同時にトラフィックをキャプチャしてください。<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

次に、`/tmp/tls.pcap` と `/tmp/sslkeys.log` を Wireshark に読み込みます。これは、クライアントライブラリが NSS 形式のキー記録に対応し、接続前に環境変数を設定できる場合にのみ機能します。<sup>[[20]](#references)[[21]](#references)</sup>

## Unixソケットの操作と Command Injection

UnixソケットはローカルIPCエンドポイントです。<sup>[[5]](#references)</sup> HTTP API、独自プロトコル、安全でないコマンドハンドラーを公開している場合があります。<sup>[[12]](#references)[[14]](#references)</sup>

グループに書き込み権限があるroot所有のソケットは、認可の境界であり、それ自体が脆弱性ではありません。リスクを判断する前に、そのグループとモードを現在のアカウントと照合し、待ち受けているプロセスを特定し、そのプロセスがクライアントから受け付ける内容を確認してください。特に、特権サービスが送信されたPHPを実行し、呼び出し元が指定した `php.ini` のパスを信頼したり、呼び出し元が `disable_functions` や `open_basedir` を変更できたりする場合、2つ目の境界を越える可能性があります。有効な設定とサービスの検証処理を確認してください。[PHP configuration guide](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md)では、これらのディレクティブについて説明しています。ソケットのメタデータだけでは、コード実行が可能だとは判断できません。

ソケットを見つけます。<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Unix socket経由でHTTPとやり取りする。<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

raw socketを操作する。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

ユーザー制御のsocket入力がshellまたは特権ヘルパーに渡されると、command injectionにつながる可能性があります。<sup>[[26]](#references)</sup> 焦点を絞った例については、[Socket Command Injection](socket-command-injection.md)を参照してください。

## nftablesの確認と許可されたルール変更

ローカルファイアウォールのルールは、サービスがローカルでは見えるのにリモートからはブロックされる理由や、あるインターフェースから高位ポートに到達できない理由を説明できる場合があります。<sup>[[22]](#references)</sup>

ルールを確認します。<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

対象ポートに影響するパケット破棄を探します。<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

認可されたラボ環境で、handleを指定して特定のブロックルールを削除します。<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

完全なテーブルをフラッシュするより、該当するハンドルを正確に削除することを優先してください。この手法では、挙動の原因となっているフィルターを特定し、そのルールだけを変更します。<sup>[[22]](#references)</sup>

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

ローカル限定で稼働する、より高い権限のユーザーで実行される、管理者向け・デバッグ機能を公開する、またはループバックやコンテナネットワークのクライアントを信頼するサービスを優先してください。

## References

- [1] [ss(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux マニュアルページ](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP バージョン 6 アドレス体系](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux マニュアルページ](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [リダイレクト (Bash リファレンスマニュアル)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout の呼び出し (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [ポートスキャンの手法 (Nmap リファレンスガイド)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [ホスト検出 (Nmap リファレンスガイド)](https://nmap.org/book/man-host-discovery.html)
- [10] [ポートの指定とスキャン順序 (Nmap リファレンスガイド)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux マニュアルページ](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD マニュアルページ](https://man.openbsd.org/nc.1)
- [14] [curl コマンドラインツールのマニュアル](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL ドキュメント](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: 「Basic」HTTP 認証方式](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 の呼び出し (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL ドキュメント](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark ユーザーガイド](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables マニュアル](https://netfilter.org/projects/nftables/manpage.html)
- [23] [プライベートインターネット向けアドレス割り当て (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 認可フレームワーク: Bearer トークンの使用 (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: OS コマンドで使用される特殊要素の不適切な無害化](https://cwe.mitre.org/data/definitions/78.html)
- [27] [aiohttp メンテナーのアドバイザリ: follow_symlinks を使用した静的ルートのトラバーサル](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — systemd とプロセス引数を介した Jupyter トークンの露出](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
