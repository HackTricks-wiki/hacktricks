# 本地网络和 Socket Triage

{{#include ../../banners/hacktricks-training.md}}

在 Linux 主机上获取 shell 后，最有价值的 network targets 往往不会对外暴露。仅限 loopback 的服务、veth networks、Unix sockets、temporary listeners、packet captures 和本地 firewall rules，可能暴露 credentials 或仅限本地的 attack surfaces。

本页面重点介绍实用的本地 post-exploitation techniques，而不是常规的远程网络 pentesting。

## Loopback 和本地服务枚举

首先确定 listening services、它们的 bind addresses，以及在权限允许时确定所属的 process。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
重要模式：

- `127.0.0.1:<port>` 或 `[::1]:<port>`：默认情况下仅可由主机访问。<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`：除非受到过滤，否则所有 IPv4 接口均可访问。<sup>[[3]](#references)</sup>
- `veth*`、`docker*`、`br-*`、`cni*` 上的 `10.0.0.0/8`、`172.16.0.0/12` 或 `192.168.0.0/16`：很可能是 container 或本地 lab 网络。<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`、`/var/run`、`/tmp` 或应用程序目录下的 Unix sockets：本地 IPC 接口。<sup>[[5]](#references)</sup>

使用轻量级探测来映射本地端口。<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
在可用时在本地使用 `nmap`。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## 隐藏的 veth 和容器子网

容器化或实验环境通常只在 bridge 或 veth 子网上暴露服务。在假设某项服务无法访问之前，先枚举接口和路由。<sup>[[2]](#references)</sup>
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
当 web panel、debug endpoint 或 helper service 对外部扫描隐藏，但可从已入侵的主机或容器网络访问时，该技术非常有用。

## 使用 socat 或 SSH 进行本地 Pivot

如果某项服务绑定到 loopback，可通过允许的 channel 转发它，而不是直接修改服务本身。

使用 SSH 转发仅限本地访问的 HTTP 服务。<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
当你已经获得 shell 访问权限时，使用 `socat` 桥接本地端口。<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
将 Unix socket 转发到 TCP 以进行本地测试。<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
这本身不会利用任何漏洞。它会让一个仅限本地的攻击面可通过你的 tooling 访问，以便你像与普通服务交互一样与其交互。

## Banner Grabbing 和简单协议

并非所有服务都是 HTTP。许多本地服务会通过 banner 或单行协议泄露足够的信息。

基本探测。<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
无需浏览器进行 HTTP 检查。<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
对于 TLS.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
目标是识别协议、authentication scheme、版本，以及该服务是否信任本地客户端。

## 捕获 Loopback 流量

本地流量可能暴露 headers、bearer tokens、Basic Auth 凭据或应用程序特定的 secrets。<sup>[[17]](#references)[[25]](#references)</sup> 仅在获得授权的环境中进行捕获。

捕获 loopback HTTP 流量。<sup>[[16]](#references)</sup>
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
文本捕获中值得查找的实用字符串：
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

如果你能在实验环境中控制 client process 的环境，`SSLKEYLOGFILE` 可以使 TLS sessions 能够在 Wireshark 或兼容的 tooling 中解密。<sup>[[19]](#references)[[20]](#references)</sup>这对于了解本地 HTTPS 流量很有用，无需直接攻击 TLS。

启用 key logging 后运行 client。<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
同时捕获流量。<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
然后将 `/tmp/tls.pcap` 和 `/tmp/sslkeys.log` 加载到 Wireshark 中。只有在客户端库支持 NSS-style key logging，并且你能在建立连接前设置环境的情况下，此方法才有效。<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket 交互与命令注入

Unix sockets 是本地 IPC endpoints。<sup>[[5]](#references)</sup>它们可能暴露 HTTP APIs、自定义协议或不安全的命令处理程序。<sup>[[12]](#references)[[14]](#references)</sup>

查找 sockets。<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
通过 Unix socket 与 HTTP 进行交互。<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
与原始套接字交互。<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
如果用户控制的 socket 输入被传递给 shell 或 privileged helper，可能导致 command injection。<sup>[[26]](#references)</sup> 如需查看一个聚焦示例，请参阅 [Socket Command Injection](socket-command-injection.md)。

## nftables 审查与授权规则更改

本地防火墙规则可能解释某项服务为何在本地可见但被远程阻止，或者为何从某个接口访问时某个高端口似乎无法到达。<sup>[[22]](#references)</sup>

审查规则。<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
查找影响目标端口的丢弃项。<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
在经授权的实验室中，通过 handle 移除特定的阻止规则。<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
优先删除确切的 handle，而不是清空整个表。该技术的关键是识别导致该行为的精确过滤器，并仅更改该规则。<sup>[[22]](#references)</sup>

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
优先关注以下服务：仅限本地访问的服务、以更高权限用户运行的服务、暴露管理/调试功能的服务，或信任 loopback/container-network 客户端的服务。

## References

- [1] [ss(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux 手册页](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291：IP Version 6 地址架构](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux 手册页](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [重定向（Bash 参考手册）](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout 调用（GNU Coreutils）](https://www.gnu.org/s/coreutils/timeout)
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
- [18] [base64 调用（GNU Coreutils）](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL 文档](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark 用户指南](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables 手册](https://netfilter.org/projects/nftables/manpage.html)
- [23] [私有 Internet 的地址分配（RFC 1918）](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 授权框架：Bearer Token 使用（RFC 6750）](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78：用于 OS Command 的特殊元素未正确中和](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
