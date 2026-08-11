# 本地网络与 Socket 排查

在 Linux 主机上获取 shell 后，最有价值的网络目标通常并未暴露在外部。仅限 loopback 的服务、veth 网络、Unix sockets、临时监听器、数据包捕获以及本地防火墙规则，都可能暴露凭据或仅限本地访问的攻击面。

本页面重点介绍实用的本地 post-exploitation 技巧，而不是一般的远程网络 pentesting。

## Loopback 与本地服务枚举

首先识别正在监听的服务、其绑定地址，以及在权限允许时确定所属进程。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
重要模式：

- `127.0.0.1:<port>` 或 `[::1]:<port>`：默认只能由主机访问。<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`：除非受到过滤，否则所有 IPv4 接口均可访问。<sup>[[3]](#references)</sup>
- `10.0.0.0/8`、`172.16.0.0/12` 或 `192.168.0.0/16` 出现在 `veth*`、`docker*`、`br-*`、`cni*` 上：可能是 container 或本地 lab 网络。<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`、`/var/run`、`/tmp` 或应用目录下的 Unix sockets：本地 IPC surfaces。<sup>[[5]](#references)</sup>

使用轻量级 probes 映射本地端口。<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
在本地可用时使用 `nmap`。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## 隐藏的 veth 和容器子网

容器化或实验环境通常仅在 bridge 或 veth 子网上暴露服务。在假设某项服务无法访问之前，先枚举接口和路由。<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
查找可能的本地子网。<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
仔细探测已发现的子网。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
当 Web panel、debug endpoint 或 helper service 对外部扫描隐藏，但可从已 compromised 的主机或 container network 访问时，此 technique 很有用。

## 使用 socat 或 SSH 进行 Local Pivot

如果某个 service 绑定到 loopback，请通过允许的 channel 暴露它，而不是修改 service 本身。

使用 SSH 转发仅限本地的 HTTP service。<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
在已有 shell 访问权限时，使用 `socat` 桥接本地端口。<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
将 Unix socket 转发到 TCP 以进行本地测试。<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
This does not exploit anything by itself. It makes a local-only surface reachable from your tooling so you can interact with it like a normal service.

## Banner Grabbing 和简单协议

并非每个服务都是 HTTP。许多本地服务会通过 banner 或单行协议 leak 足够的信息。

基本探测。<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
无需浏览器的 HTTP 检查。<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
对于 TLS。<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
目标是识别协议、authentication scheme、版本，以及服务是否信任本地客户端。

## 捕获 Loopback 流量

本地流量可能暴露 headers、bearer tokens、Basic Auth 凭据或特定于应用程序的 secrets。<sup>[[17]](#references)[[25]](#references)</sup> 仅在获得授权的环境中进行捕获。

捕获 Loopback HTTP 流量。<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
捕获特定的本地服务。<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
从捕获或记录的 header 中解码 Basic Auth。<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
在文本捕获中值得查找的有用字符串：
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

如果你能在实验环境中控制 client process 的环境，`SSLKEYLOGFILE` 可以使 TLS 会话能够在 Wireshark 或兼容工具中解密。<sup>[[19]](#references)[[20]](#references)</sup> 这对于了解本地 HTTPS 流量很有用，无需直接攻击 TLS。

启用 key logging 后运行一个 client。<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
同时捕获流量。<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
然后将 `/tmp/tls.pcap` 和 `/tmp/sslkeys.log` 加载到 Wireshark 中。只有在客户端库支持 NSS 风格的密钥记录，并且你能在建立连接之前设置环境时，这种方法才有效。<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket 交互与命令注入

Unix sockets 是本地 IPC 端点。<sup>[[5]](#references)</sup>它们可能暴露 HTTP API、自定义协议或不安全的命令处理程序。<sup>[[12]](#references)[[14]](#references)</sup>

查找 sockets。<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
通过 Unix socket 与 HTTP 交互。<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
与 raw socket 进行交互。<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
如果用户可控的 socket 输入被传递给 shell 或 privileged helper，可能导致 command injection。<sup>[[26]](#references)</sup> 如需查看一个聚焦示例，请参阅 [Socket Command Injection](socket-command-injection.md)。

## nftables Review and Authorized Rule Changes

本地 firewall 规则可能解释某项服务为何在本地可见却被远程阻止，或为何某个高端口从一个接口看似无法访问。<sup>[[22]](#references)</sup>

Review rules。<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
查找影响目标端口的丢弃规则。<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
在经授权的实验环境中，根据句柄移除特定的阻止规则。<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
相比清空完整表，优先删除确切的 handle。该技术的关键是识别导致该行为的精确 filter，并仅更改该规则。<sup>[[22]](#references)</sup>

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
优先关注仅限本地的服务、以更高权限用户运行的服务、暴露 admin/debug 功能的服务，或信任 loopback/container-network 客户端的服务。

## References

- [1] [ss(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux 手册页](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291：IP Version 6 Addressing Architecture](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux 手册页](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirections（Bash Reference Manual）](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout invocation（GNU Coreutils）](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port Scanning Techniques（Nmap Reference Guide）](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host Discovery（Nmap Reference Guide）](https://nmap.org/book/man-host-discovery.html)
- [10] [Port Specification and Scan Order（Nmap Reference Guide）](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux 手册页](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD 手册页](https://man.openbsd.org/nc.1)
- [14] [curl 命令行工具手册](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL 文档](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617：“Basic” HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 invocation（GNU Coreutils）](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL 文档](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables 手册](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Address Allocation for Private Internets（RFC 1918）](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [The OAuth 2.0 Authorization Framework: Bearer Token Usage（RFC 6750）](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78：Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
