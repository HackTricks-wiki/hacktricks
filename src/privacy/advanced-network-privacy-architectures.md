# 高级网络隐私架构

{{#include ../banners/hacktricks-training.md}}

复杂性只有在消除特定观察者或故障模式时才有价值。独特的 tunnel stack、自定义 packet shape、罕见的 user agent 或频繁轮换的基础设施，都可能比数千人使用的标准配置更容易形成 fingerprint。

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) 提供了通用的 `Pros`/`Cons`/`Procedure`/`Detection` schema。本页面扩展介绍更复杂的架构和 trust boundary。

因此，高级目标是**知识分离**：任何普通组件都不应同时拥有用户身份、目标地址、明文和长期活动历史。这并不等于隐身；collusion、法律程序、endpoint compromise 或端到端 traffic correlation 仍可能重建整个路径。

## 架构选择

| 模式 | 获得的属性 | 新的 trust/failure | 适用场景 |
|---|---|---|---|
| Standard Tor Browser | 共享的 browser fingerprint 和多 relay 路径 | 低延迟允许进行 traffic correlation | 通用 anonymous web browsing |
| Tor bridge + pluggable transport | 使直接阻断/分类 Tor 变得更加困难 | bridge/transport 仍可能被检测；bridge 可获知 source | 受审查的网络 |
| Onion service | 隐藏 service IP；避免 exit；验证 onion identity | Onion key 和 server endpoint 成为关键资产 | Private publishing、intake 或 administration |
| Independent ingress + egress relays | 通常没有单个 relay 能同时看到 source 和 destination | Operators 可能 collude；timing 会穿过两端 | 高性能的受支持应用 |
| Oblivious HTTP | 将 source IP 与加密的 stateless HTTP request 分离 | 需要 application、relay 和 gateway 支持 | 无需 session state 的 telemetry、queries、submissions |
| VPN-only workload namespace | 由 kernel 强制不存在 clear-network route | VPN 仍能看到两端；host/root 仍需信任 | Authorized engagement tools 和固定 egress |
| Disposable remote browser | destination 与本地 browser/endpoint 隔离 | Workspace provider 可看到 activity 和 login identity | 不受信任的网站/文件及受控 research |
| I2P internal service | 分离的 inbound/outbound overlay tunnels；没有官方 exits | 生态规模更小/不同；长期运行的 peer behavior | 原生适用于 I2P 的 services，而非普通 web replacement |
| Mixnet/asynchronous delivery | delay、batching 和 cover traffic 可抵抗 timing analysis | 高延迟、应用和成熟度有限 | 不需要交互的 messages/tasks |

## Split-knowledge relays

对于特定应用，双 operator relay 模式可能优于单一 VPN：
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay 是一个已部署的示例：Apple 负责 ingress，而不同的 content provider 负责 egress，因此通常双方都不会同时看到客户端 IP 和浏览目标。<sup>[[1]](#references)</sup> 这是面向特定产品的 Safari/DNS 隐私服务，并非覆盖所有设备的 anonymity network，而且会有意保留粗略区域信息。

Oblivious HTTP（OHTTP）标准化了一种更狭窄的 application 模式。relay 能看到客户端以及加密的 gateway 流量；gateway 会解密 HTTP 消息，但看到的是 relay，而不是客户端。RFC 9458 警告称，它需要 relay/gateway 支持，最适合不包含 cookies/authentication/session state 的请求，并且其保证不涵盖 traffic analysis。<sup>[[2]](#references)</sup>

### Design checklist

1. 明确定义需要保护的 application 消息；不要在未明确说明的情况下代理任意经过 authentication 的 web session。
2. 尽可能使用由不同组织独立运营的 ingress 和 egress，并将 administration、credentials、logging 和 legal control 分开。
3. 将 application request 加密发送至 gateway，使 ingress 无法读取。
4. 在适当层级移除源自客户端的 forwarding headers、TLS identifiers 和稳定的 per-user tokens。
5. 避免使用 unique keys、cookies 或 payload fields，使 gateway 能够绕过传输层分离重新关联请求。
6. 在两端聚合、最小化并设置日志过期；记录 collusion 和 compelled-disclosure risk。
7. 仅根据经过审查的 protocol 进行 padding 或 batching。自制的 traffic shaping 可能在无法阻止关联的情况下产生独特 signature。
8. 使用受控的 canary requests 进行测试，并比较 client、ingress、gateway 和 target 各自记录的内容。

对于普通的交互式 browsing，请使用 Tor Browser，而不是自行设计 private OHTTP proxy。OHTTP 保护的是受支持的 application transaction，而不是完整的 browser identity。

## Enforce the route per workload

仅基于可变 host routes 的 kill switch 可能在 DHCP renewal、sleep/wake、IPv6 changes 或 tunnel crash 期间失效。更强的 Linux 模式是只为 container 或 network namespace 提供 loopback interface 和 tunnel interface。WireGuard 说明，interface 可以在 physical namespace 中创建，再移动到 workload namespace，同时将其 encrypted UDP socket 保留在原始 namespace 中。<sup>[[3]](#references)</sup>

### Deployment pattern

1. 首先在 disposable/local-console host 上构建；namespace 配置错误可能导致远程访问中断。
2. 将 physical Ethernet/Wi-Fi interface 以及 DHCP/supplicant 放入 **physical** namespace。
3. 在其中创建 WireGuard interface，使其 encrypted transport socket 能访问 physical network。
4. 仅将 WireGuard interface 移入 **workload** namespace，并将其设为唯一的 default route。
5. 为 workload 提供仅能通过 tunnel 访问的 namespace-specific resolver。明确处理 IPv6。
6. 在该 namespace 中运行 browser/tool container，不使用 host networking、privileged capability、shared browser directory 或 personal credential agent。
7. 停止 tunnel，并验证 workload 无法解析或连接到受控的 IPv4 或 IPv6 endpoint。
8. 在 workload namespace 外测试 endpoint roaming、DHCP renewal、suspend/resume 和 captive-portal handling。
9. 记录 namespace/tunnel configuration hash 和 approved egress address，以便 engagement accountability。

这提供的是 **route enforcement**，而不是让你对 VPN 或 engagement bastion 实现 anonymity。被 compromise 的 host/root 可以检查或修改 namespaces。

## Tor bridges and pluggable transports

Bridges 是非公开的 Tor entry relays。Pluggable transports 会改变 first-hop traffic，使简单的 blocking 或 protocol classification 更加困难。它们不会在 entry 之后增加 anonymous relay layers，也无法抵御能够进行更广泛 timing correlation 的 observer。

| Transport | First-hop approach | Practical tradeoff |
|---|---|---|
| **obfs4** | 使流量看起来是随机数据，并抵抗 active probing | 已知的 bridge address 仍可能被 blocking |
| **Snowflake** | 使用短期 volunteer WebRTC proxies 连接到 bridge | 性能不稳定；存在 broker/STUN/WebRTC patterns |
| **WebTunnel** | 通过类似 HTTPS 的 WebSocket tunnel 携带 bridge traffic | 依赖可访问的 web front，且仍可能被 classification |

Tor Project 将 Snowflake 和 WebTunnel 描述为 censorship-circumvention transports，而不是完美的 indistinguishability。<sup>[[4]](#references)</sup>

### Safe workflow

1. 从 Tor Browser 的 direct connection 开始。仅当 local observer model 中的 blocking 或 visibility 需要使用 bridge 时才添加。
2. 使用内置 transports，或通过 Tor Project channels 获取 bridge lines。不要从论坛下载随机的 transport binaries 或 public bridge lists。
3. 尝试能够可靠连接的、复杂度最低的 supported option；记录选择它的原因。
4. 其他方面保持 Tor Browser 的 standard 配置。bridge 不会使 custom extensions、account logins 或 unusual browser settings 变得安全。
5. 测试 reconnect 和 clock correctness。不要以会向同一 local observer 发送 distinctive sequence 的方式反复切换 transports。
6. 如果 censor 或 network policy 发生变化，重新评估；在某些地区，使用本身可能敏感或受到限制。

## Onion services as a private rendezvous

Onion service 会向 introduction points 和 rendezvous relays 建立 outbound Tor circuits，因此不需要 public inbound port，也不会通过 onion protocol 暴露其 server IP。Client-to-service traffic 始终在 Tor 内传输，而 onion address 会对 service key 进行 authentication。<sup>[[5]](#references)</sup>

对于合法的 intake portal、private repository、administrative interface 或 engagement evidence drop：

1. 在 dedicated host/VM 上运行 application，并将其绑定到 loopback 或隔离的 Unix socket。
2. 从其 official repository 安装 Tor，并遵循 official v3 onion-service setup；绝不要使用过时的 v2 instructions。
3. 像保护 TLS/signing key 一样保护 onion service private key。只有在需要稳定 identity 时才进行备份。
4. 为封闭群组添加 onion-service client authorization，并通过 independently authenticated channel 交付 credentials。<sup>[[6]](#references)</sup>
5. 防止 origin 获取会暴露其 public IP 或 operator account 的 third-party fonts、analytics、updates 或 webhooks。
6. 也要在 application 中实现 authentication 和 authorization；拥有 onion address 不等于拥有 access control。
7. 对 service 进行 patch、rate-limit 和 monitoring，但不要嵌入 third-party telemetry。
8. 从独立的 test context 确认 DNS、email、error pages、file metadata 和 response headers 不会泄露 origin。
9. 对于 red-team 使用，在 ROE 中列出 service、owner、purpose 和 shutdown time。不要使用它隐藏 out-of-scope C2。

## Remote browser and disposable workspace

Remote browser 会将 rendering 和 risky content 移出 local endpoint，并可提供 engagement-specific cloud egress。它能保护 local device 免受部分 content 和 persistence 的影响；但不会让 operator 对 workspace provider 保持 anonymous。例如，AWS 记录了 portal、identity、policy、preference 和 session-log data 的收集，即使 disposable browser instance 会在 session 结束时被丢弃。<sup>[[7]](#references)</sup>

每个 engagement 使用一个由组织控制的 workspace，限制 downloads/uploads/clipboard，禁用 personal identity providers，使其 fixed egress 通过 approved bastion，并在 evidence export 后使 workspace 过期。将 provider console、IdP 和 administrator 视为 observers。

## I2P and internal overlays

I2P 会建立独立的单向 inbound 和 outbound tunnels，并且没有 official network-layer exits；它主要用于 I2P 内部的 services。<sup>[[8]](#references)</sup> 它不是一种可直接替代、更快速浏览 public Internet 的方案。Outproxies 会引入 trust point，而其 official threat model 明确要求更多 research，并不宣称 perfect anonymity。

仅在两端都明确支持 I2P 时使用它；将其 long-lived router 与 personal applications 隔离，并理解 peers/local networks 可以观察到 I2P participation。不要在没有证据的情况下增加 hop counts 或调整 peer selection：异常设置可能降低性能并缩小 anonymity set。

## Correlation-resistant operations

- 优先使用常见且受支持的 client configuration，而不是 unique build。
- 在 endpoint 上分离 identities；任何 routing topology 都无法修复 account、payment、recovery 或 content reuse 问题。
- 对于 non-interactive tasks，优先使用经过审查的 asynchronous protocol/mixnet，而不是手动添加 sleeps 或 fake traffic。
- 避免从同一 physical context 以 synchronized pattern 操作所谓独立的 identities。
- 使用 one-way export gate：untrusted content 进入 disposable renderer；只有经过审查和 sanitized 的结果才能离开。
- 为 protocol security 保持正确的 clocks，但从 published artifacts 中移除不必要的 precise timestamps。
- 缩短 session duration，并清理 stale infrastructure；不要进行快速的 “fast-flux” rotation，因为这很显眼，也会损害 accountability。

## Techniques that cannot use uninvolved third parties

这些是真实的 adversary techniques，并非虚构或无关紧要的技术。其 mechanics 和 detection 见 [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md)、[Covert Physical and Wireless Access](covert-physical-wireless-access.md) 以及 [APT case studies](government-and-apt-case-studies.md)。在经过授权的 exercise 中，使用自有替代物复现其可观察行为：

- 使用受控的 relay pools 模拟 residential/mobile exit churn，绝不要使用 consent 不明确的 markets；
- 使用自有的 VMs/routers 模拟 open proxies、compromised routers 和 botnets；
- 使用指定的 exercise tenant 和 synthetic victim identity 模拟 stolen cloud accounts；
- 在自有 reverse proxy 上模拟 domain fronting，而不是使用不知情的 CDN；
- 使用实验室自有的两个隔离 AP 模拟 third-party Wi-Fi；
- 将 custom encryption、multi-VPN chains 和 identifier rotation 视为 test hypotheses，并确保其 flow、account 和 endpoint artifacts 仍可被 detection。

对于经授权的 red team，任何使 traffic less recognizable 的尝试都必须在 ROE 中明确列为 detection objective，拥有由 controller 保管的 attribution map，并包含 stop/deconfliction mechanism。

## Verification matrix

| Test | Expected result | Failure means |
|---|---|---|
| Tunnel/bridge stopped | Workload 没有 direct IPv4/IPv6/DNS path | Route enforcement 不完整 |
| Target log inspected | 仅出现计划中的 egress/application identity | Header、route 或 account leak |
| Ingress log inspected | 存在 source；不存在 clear target/request | Trust split 在 ingress 处失败 |
| Egress log inspected | 存在 relay/request；不存在 source identity | Trust split 在 egress 处失败 |
| Onion origin scanned externally | 无法访问或关联到 public origin service | Origin leaked 或处于 dual-homed 状态 |
| Disposable session ended | Instance state 消失；approved evidence 被单独保留 | Persistence boundary 失败 |
| Controller lookup exercised | Activity 能及时映射到 engagement/operator | Red-team accountability 失败 |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — How Onion Services work](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service advanced settings and client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
