# 流量捕获、防火墙与出站流量排查

{{#include ../../banners/hacktricks-training.md}}

找到[本地监听器和 Unix 套接字](local-network-and-socket-triage.md)后，检查哪些接口承载这些流量，以及哪些防火墙或代理规则会影响其可达性。即使其他主机无法访问，仅限 loopback 的服务也可能承载敏感的 HTTP 标头。

## 检查捕获权限并选择接口

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

即使当前用户没有 sudo 访问权限，`dumpcap` 也可能具备数据包捕获能力。检查该可执行文件的实际能力和组权限。选择最小且有用的网络接口、持续时间和过滤器；捕获内容可能包含凭据或个人数据。

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` 可重建明文 TCP 流；`tshark` 可筛选捕获数据并提取字段。对于 TLS 流量，解密需要端点密钥，或需要在连接建立前配置了 `SSLKEYLOGFILE` 的受支持客户端。[本地网络排查页面](local-network-and-socket-triage.md#tls-key-logging)展示了该流程。不要将加密的捕获数据视为可读明文。

已存储的事件调查工件可能会改变这一判断。[Linux core dump 是进程内存的映像](https://man7.org/linux/man-pages/man5/core.5.html)，可能会保留会话密钥；如果可读取的转储文件和数据包捕获来自同一进程和会话，分析人员或许能够解密这些流量。先盘点工件路径和权限，再分别核实进程身份、捕获时间、协议和密钥格式。解密后的流量或恢复的归档文件只能作为信息泄露线索，不能证明其他账户曾访问过这些内容：任何不完整的 SSH 密钥材料仍需重建、与对应的公钥匹配，并通过该账户的 SSH 策略验证。避免在宽泛的枚举输出中转储 core 内容或捕获数据的负载。

## 识别防火墙层

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` 和 `iptables` 可能通过 UFW 或 firewalld 等发行版封装工具提供。读取当前生效的规则和封装工具持久化的配置；某种表示中可见的规则可能是由另一个工具生成的。在将某项服务被阻止归因于特定规则之前，请检查接口、方向、源、目标、协议、端口和连接状态。请参阅 [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) 中的具体示例。

## 测试出站流量和代理行为

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

区分 DNS 故障与 TCP、TLS 或代理故障。测试与评估相关的特定目标和协议；ICMP 可达并不意味着允许 TCP 或 UDP。如果配置了代理，请比较预期的代理请求与根据适用的 `no_proxy` 规则直接访问同一目标的请求。本地端口转发也可能让其他位置能够访问 loopback 服务，因此如果防火墙视图与实际观察到的暴露情况不符，请检查活动监听端口和 SSH 隧道。
{{#include ../../banners/hacktricks-training.md}}
