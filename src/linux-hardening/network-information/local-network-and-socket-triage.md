# 本地网络和 Socket 排查

{{#include ../../banners/hacktricks-training.md}}

在 Linux 主机上获取 shell 后，最有价值的网络目标通常并未对外暴露。仅限 loopback 的服务、veth 网络、Unix socket、临时监听器、数据包捕获以及本地防火墙规则，都可能暴露 credentials 或仅限本地访问的攻击面。

本页面重点介绍实用的本地 post-exploitation 技术，而非一般的远程网络 pentesting。

## Loopback 和本地服务枚举

首先识别监听服务、其绑定地址，以及在权限允许的情况下获取其所属进程：
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
重要模式：

- `127.0.0.1:<port>` 或 `[::1]:<port>`：默认情况下只能从主机访问。
- `0.0.0.0:<port>`：除非经过过滤，否则可通过所有 IPv4 接口访问。
- `veth*`、`docker*`、`br-*`、`cni*` 上的 `172.x`、`10.x` 或 `192.168.x`：很可能是容器或本地实验网络。
- `/run`、`/var/run`、`/tmp` 或应用程序目录下的 Unix sockets：本地 IPC 攻击面。

使用轻量级 probes 映射本地端口：
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
如果可用，请在本地使用 `nmap`：
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## 隐藏的 veth 和容器子网

容器化或实验环境通常仅在 bridge 或 veth 子网上暴露服务。在假设某项服务无法访问之前，请先枚举接口和路由：
```bash
ip -br addr
ip route
ip neigh
```
查找可能的本地子网：
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
谨慎地探测已发现的子网：
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
当 web panel、debug endpoint 或 helper service 对外部 scans 隐藏，但可从已被攻陷的主机或 container network 访问时，该 technique 很有用。

## 使用 socat 或 SSH 进行 Local Pivot

如果某个 service 绑定到 loopback，可以通过允许的 channel 暴露它，而无需修改 service 本身。

使用 SSH 转发仅限本地访问的 HTTP service：
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
当你已经拥有 shell 访问权限时，使用 `socat` 桥接本地端口：
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
将 Unix socket 转发到 TCP 以进行本地测试：
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
这本身不会利用任何漏洞。它只是让一个仅限本地的攻击面能够从你的 tooling 访问，使你可以像与普通 service 交互一样与其交互。

## Banner Grabbing 和简单协议

并非所有 service 都是 HTTP。许多本地 service 会通过 banner 或单行协议泄露足够的信息。

基本探测：
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
不使用浏览器进行 HTTP 检查：
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
对于 TLS：
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
目标是识别协议、身份验证方案、版本，以及该服务是否信任本地客户端。

## 捕获 Loopback 流量

本地流量可能暴露 headers、bearer tokens、Basic Auth 凭据或特定于应用程序的 secrets。仅在获得授权的环境中进行捕获。

捕获 Loopback HTTP 流量：
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
捕获特定的本地服务：
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
从捕获或记录的 header 中解码 Basic Auth：
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
文本捕获中值得查找的字符串：
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

如果你能在实验环境中控制客户端进程的环境变量，`SSLKEYLOGFILE` 可以使 TLS 会话能够在 Wireshark 或兼容工具中解密。这对于了解本地 HTTPS 流量很有帮助，而无需直接攻击 TLS。

运行启用 key logging 的客户端：
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
同时捕获流量：
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
然后将 `/tmp/tls.pcap` 和 `/tmp/sslkeys.log` 加载到 Wireshark 中。此方法仅适用于支持 NSS-style key logging 的 client library，并且你可以在建立连接前设置环境。

## Unix Socket Interaction and Command Injection

Unix sockets 是本地 IPC endpoints。它们可能暴露 HTTP APIs、custom protocols 或不安全的 command handlers。

查找 sockets：
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
通过 Unix socket 与 HTTP 交互：
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
与 raw socket 交互：
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
如果用户可控的 socket 输入被传递给 shell 或 privileged helper，就可能导致 command injection。有关具体示例，请参阅 [Socket Command Injection](socket-command-injection.md)。

## nftables Review and Authorized Rule Changes

本地 firewall 规则可能解释某个服务为何在本地可见但从远程被阻止，或为何某个高端口从一个接口看起来无法访问。

Review rules:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
查找影响目标端口的丢弃规则：
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
在获得授权的实验室中，使用 handle 移除特定的阻止规则：
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
优先删除 exact handle，而不是清空整个表。该技术的核心是识别导致此行为的精确 filter，并仅修改该规则。

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
优先关注仅限本地访问、以更高权限用户运行、暴露 admin/debug 功能，或信任 loopback/容器网络客户端的服务。
{{#include ../../banners/hacktricks-training.md}}
