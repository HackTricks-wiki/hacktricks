# 本地网络和 Socket 排查

{{#include ../../banners/hacktricks-training.md}}

在 Linux 主机上获取 shell 后，最有用的网络目标往往并未对外暴露。仅监听 loopback 的服务、veth 网络、Unix socket、临时监听器、数据包捕获以及本地防火墙规则，都可能泄露凭据或暴露仅限本地访问的攻击面。

本页聚焦于实用的本地 post-exploitation 技术，而非一般的远程网络 pentesting。

## Loopback 和本地服务枚举

首先识别正在监听的服务、它们的绑定地址，以及权限允许时对应的进程。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

重要模式：

- `127.0.0.1:<port>` 或 `[::1]:<port>`：默认情况下只能由主机本身访问。<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`：除非受到过滤，否则所有 IPv4 接口均可访问。<sup>[[3]](#references)</sup>
- `veth*`、`docker*`、`br-*`、`cni*` 上的 `10.0.0.0/8`、`172.16.0.0/12` 或 `192.168.0.0/16`：很可能是容器或本地实验网络。<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`、`/var/run`、`/tmp` 或应用目录下的 Unix socket：本地 IPC 攻击面。<sup>[[5]](#references)</sup>

对于历史上的 [snapd socket 解析问题，CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing)，应检查正在运行的守护进程、本地 API socket，以及已安装的软件包或 snap 修订版本是否包含针对该发行版的修复。该漏洞出在 snapd 对对端 socket 地址的验证中，而不在 `snap-confine`；仅凭设置了 set-user-ID 的 `snap-confine` 文件或上游版本字符串，无法确定是否存在风险。Ubuntu 按发行版版本提供了相应的软件包修复，而 snapd 也可能通过 snap 独立更新，不依赖发行版软件包。评估特权 API 边界之前，应确认实际运行的构建版本以及本地 socket 的可达性。被动枚举不应发送特制 socket 请求，也不应安装 snap。

通过 [`socat` 的 `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) 启动的 loopback 监听器，可以将本地客户端输入传递给另一个程序。在将 root 所有的自定义服务视为提权线索之前，应关联检查监听器的命令、可执行文件路径、子进程的有效身份、本地可达性和认证机制。内存安全缺陷或不安全的输入到命令执行路径，需要有针对特定二进制文件及其构建版本的证据；仅凭端口号、`socat` 进程或 root 所有者身份无法证明存在此类问题。被动枚举应止于进程、socket 和文件元数据，不应向服务发送输入。

本地 Salt master 可以监听 TCP 4505 和 4506，包括监听 loopback 或容器发布到主机的端口。[Salt 的 3000.2 发行说明](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html)介绍了一个未认证的方法访问漏洞 CVE-2020-11651，该漏洞已在上游版本 2019.2.4 和 3000.2 中修复。在将其视为提权线索之前，应关联确认监听器对应的实际 `salt-master` 进程、可访问的接口、已安装的软件包及供应商补丁，以及其有效的容器或主机身份；仅凭端口或上游版本无法证明存在漏洞。如果 master 运行在容器内，影响主机 root 权限涉及另一道边界：应确认容器已挂载可用的主机运行时 API socket，且该容器可以访问它。被动枚举不应查询 Salt 请求服务器，也不应创建容器来判断是否存在风险。参见 [Salt 的端口文档](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html)和[运行时 API 分诊](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md)。

使用轻量级探测映射本地端口。<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

本地有 `nmap` 时使用。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## 隐藏的 veth 和容器子网

容器化或实验环境通常只在 bridge 或 veth 子网上暴露服务。在认定服务无法访问之前，先枚举网络接口和路由。<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

查找可能的本地子网。<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

谨慎地探测已发现的子网。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

当 Web 面板、调试端点或辅助服务对外部扫描隐藏，但可从已失陷主机或容器网络访问时，这种技术很有用。

## 跨用户边界的 Notebook 服务令牌

本地回环 notebook 服务可能使用启动时打印到进程输出中的 token 进行身份验证。如果该输出被重定向到其他本地账户可读取的日志中，token 就可能跨越用户边界，使攻击者能够以 notebook 服务器所属账户的身份执行代码。在将日志路径视为提权线索之前，应先核对监听进程的所有者、日志位置及权限、当前 token 配置和 notebook 访问控制。在被动枚举期间列出日志元数据；不要打印 token，也不要仅为判断主机类型而连接服务。

Jupyter Lab 服务也可能在可读取的 systemd `ExecStart` 中或运行中的命令行（`ps auxww`）中暴露 token，而不只是在启动日志中。报告的示例中，`User=analyst` 和 `--ServerApp.token` 标明了凭据以及 `127.0.0.1:8888` 监听端口背后的账户。获得主机访问权限后，token 和 `ssh -L 8888:127.0.0.1:8888 user@host` 可用于以该服务用户身份访问 Jupyter Lab 的 Terminal。应一并检查有效的 unit 用户、进程参数、监听端口和 token 有效性；仅绑定到回环地址并不构成授权边界。<sup>[[28]](#references)</sup>

## 使用 socat 或 SSH 进行本地 Pivot

如果服务绑定到回环地址，可通过允许的通道转发访问，而不要修改服务本身。

使用 SSH 转发仅限本地访问的 HTTP 服务。<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

已有 shell 访问权限时，使用 `socat` 桥接本地端口。<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

将 Unix socket 转发到 TCP，以便进行本地测试。<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

这本身不会利用任何东西。它会让仅限本地访问的攻击面可通过你的工具访问，以便你像与普通服务交互一样与其交互。

## Banner Grabbing 和简单协议

并非所有服务都是 HTTP。许多本地服务会通过 banner 或单行协议泄露足够的信息。

基础探测。<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

不使用浏览器进行 HTTP 检查。<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

对于 TLS。<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

目标是识别协议、身份验证方案、版本，以及该服务是否信任本地客户端。

对于 aiohttp 监听器，请检查其静态路由配置和版本。CVE-2024-23334 影响 3.9.2 之前的 aiohttp 版本；当静态路由启用 `follow_symlinks=True` 时，向该路由发送请求可能读取静态根目录之外的文件。如果服务以 root 身份运行，且该路由可访问，则可能暴露 root 有权读取的文件。版本 banner 或仅绑定到 loopback 并不能证明配置存在漏洞，也不能证明可以访问文件。<sup>[[27]](#references)</sup>

## 捕获 Loopback 流量

本地流量可能暴露 headers、bearer tokens、Basic Auth 凭据或应用专属机密。<sup>[[17]](#references)[[25]](#references)</sup> 仅在获授权的环境中进行捕获。

捕获 loopback HTTP 流量。<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

捕获特定的本地服务。<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

从捕获或记录的标头中解码 Basic Auth。<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

文本捕获中值得查找的字符串：

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS 密钥日志记录

如果你能在实验环境中控制客户端进程的环境变量，`SSLKEYLOGFILE` 可以让 TLS 会话能够在 Wireshark 或兼容工具中解密。<sup>[[19]](#references)[[20]](#references)</sup> 这有助于了解本地 HTTPS 流量，而无需攻击 TLS 本身。

启用密钥日志记录后运行客户端。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

同时捕获流量。<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

然后将 `/tmp/tls.pcap` 和 `/tmp/sslkeys.log` 加载到 Wireshark 中。只有当客户端库支持 NSS 风格的密钥日志记录，并且你能在建立连接前设置环境时，这种方法才有效。<sup>[[20]](#references)[[21]](#references)</sup>

## Unix 套接字交互与命令注入

Unix 套接字是本地 IPC 端点。<sup>[[5]](#references)</sup> 它们可能暴露 HTTP API、自定义协议或不安全的命令处理程序。<sup>[[12]](#references)[[14]](#references)</sup>

由 root 拥有且具有组写权限的套接字是一道授权边界，本身并不构成漏洞。将其组和模式与当前账户进行比较，找出监听进程，并检查该进程接受客户端提供的哪些内容，然后再评估风险。尤其是，如果一个特权服务会执行提交的 PHP，同时还信任调用方指定的 `php.ini` 路径，或允许调用方更改 `disable_functions` 或 `open_basedir`，那么它可能越过第二道边界；请检查生效的配置和服务验证流程。[PHP 配置指南](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md)介绍了这些指令。仅凭套接字元数据无法证明存在代码执行。

查找套接字。<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

通过 Unix socket 与 HTTP 交互。<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

与 raw socket 交互。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

如果用户可控的 socket 输入被传递给 shell 或特权辅助程序，就可能导致 command injection。<sup>[[26]](#references)</sup> 有关具体示例，请参阅 [Socket Command Injection](socket-command-injection.md)。

## nftables 审查与授权规则更改

本地防火墙规则可能解释为什么某项服务在本地可见、但从远程访问时被阻止，或者为什么某个高端口从某个接口看起来无法访问。<sup>[[22]](#references)</sup>

检查规则。<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

查找影响目标端口的丢弃规则。<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

在授权实验环境中，按句柄移除特定的阻止规则。<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

优先删除确切的 handle，而不是清空整个表。该技术旨在找出导致该行为的确切筛选规则，并且只修改该规则。<sup>[[22]](#references)</sup>

## 快速工作流

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

优先关注仅限本地访问、以权限更高的用户身份运行、暴露管理/调试功能，或信任 loopback/容器网络客户端的服务。

## References

- [1] [ss(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux 手册页](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291：IP Version 6 寻址架构](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux 手册页](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [重定向（Bash 参考手册）](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout 调用方式（GNU Coreutils）](https://www.gnu.org/s/coreutils/timeout)
- [8] [端口扫描技术（Nmap 参考指南）](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [主机发现（Nmap 参考指南）](https://nmap.org/book/man-host-discovery.html)
- [10] [端口指定与扫描顺序（Nmap 参考指南）](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux 手册页](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD 手册页](https://man.openbsd.org/nc.1)
- [14] [curl 命令行工具手册](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL 文档](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617：“Basic” HTTP 身份验证方案](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 调用方式（GNU Coreutils）](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL 文档](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark 用户指南](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables 手册](https://netfilter.org/projects/nftables/manpage.html)
- [23] [私有 Internet 的地址分配（RFC 1918）](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 授权框架：Bearer Token 用法（RFC 6750）](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78：未正确 neutralize 操作系统命令中使用的特殊元素](https://cwe.mitre.org/data/definitions/78.html)
- [27] [aiohttp 维护者安全公告：启用 follow_symlinks 时的静态路由路径遍历](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB：DevHub — 通过 systemd 和进程参数暴露 Jupyter token](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
