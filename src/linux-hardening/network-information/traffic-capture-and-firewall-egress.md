# 流量捕获、防火墙与出口流量排查

{{#include ../../banners/hacktricks-training.md}}

找到[本地监听器和 Unix 套接字](local-network-and-socket-triage.md)后，检查哪些接口承载其流量，以及哪些防火墙或代理规则会影响其可达性。即使其他主机无法访问，仅限 loopback 的服务也可能承载敏感的 HTTP 头。

## 检查捕获权限并选择接口

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

即使当前用户没有 sudo 权限，`dumpcap` 也可能具备数据包捕获能力。检查该可执行文件的实际 capabilities 和组权限。尽量缩小捕获范围，选择最少的接口、时长和过滤条件；捕获内容可能包含凭据或个人数据。

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` 可重建 plaintext TCP 流；`tshark` 可对抓包进行筛选并提取字段。对于 TLS 流量，解密需要端点密钥，或需要在连接建立前配置支持 `SSLKEYLOGFILE` 的客户端。[本地网络分诊页面](local-network-and-socket-triage.md#tls-key-logging)展示了这一工作流程。不要把加密抓包当作可读的 plaintext。

已存储的事件响应工件可能改变这一判断。[Linux core dump 是进程内存的映像](https://man7.org/linux/man-pages/man5/core.5.html)，其中可能保留会话密钥；如果可读取的 dump 和抓包来自同一进程及同一会话，分析人员或许能够解密该流量。首先盘点工件路径和权限，然后分别核实进程身份、抓包时间、协议和密钥格式。解密后的流量或恢复出的归档文件只能作为信息泄露线索，不能证明其他账户曾访问过这些内容：任何不完整的 SSH 密钥材料仍需重建、与对应的公钥匹配，并符合该账户的 SSH 策略。避免在大范围枚举输出中转储 core 内容或抓包载荷。

## Identify firewall layers

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` 和 `iptables` 可能通过 UFW 或 firewalld 等发行版封装工具暴露。读取生效规则和封装工具持久化的配置；某种表示中可见的规则可能由另一种工具生成。在将服务被阻止归因于特定规则之前，请检查接口、方向、源、目标、协议、端口和连接状态。有关具体示例，请参阅 [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes)。

## 测试出站流量和代理行为

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

区分 DNS 故障与 TCP、TLS 或 proxy 故障。测试与评估相关的特定目标和协议；ICMP 可达并不意味着允许 TCP 或 UDP。如果配置了 proxy，请比较预期的 proxied 请求与遵循适用 `no_proxy` 规则、发往同一目标的请求。本地端口转发也可能让其他位置访问 loopback 服务，因此，当防火墙视图与观测到的暴露情况不一致时，请检查活动监听器和 SSH 隧道。
{{#include ../../banners/hacktricks-training.md}}
