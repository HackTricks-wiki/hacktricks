# Offensive Infrastructure and Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

操作员很少能通过单个 proxy 获得真正有意义的匿名性。真实行动会构建一张**隔离图**：操作员连接到 access node，traversal nodes 将该节点与出口隔离，redirectors 保护真实的 C2，而 disposable names 则指向公共边缘。

使用[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)查看每条路径经过规范化整理的优缺点、部署方式和检测方法。本页面将深入介绍对抗性基础设施的组合方式。
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
因此，目标最后看到的地址只能证明一条路径，而不能证明是谁控制了键盘。MITRE 将主要组件映射到 Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568) 和 Web Service (T1102)。<sup>[[1]](#references)</sup>

## 基础设施类别

| 类别 | 行为者使用它的原因 | 持久暴露面 | 防御者最佳切入点 |
|---|---|---|---|
| 租用的 VPS/cloud | 快速、可预测、可路由且易于重建 | 租户、计费、控制台、源登录和镜像历史 | 账户/控制平面事件以及重复的服务器指纹 |
| Commercial VPN/Tor | 大型共享出口集合；无需管理服务器 | provider/guard 可见性和端到端时序 | 目标行为、端点证据和流量关联 |
| Residential/mobile proxy | 消费者 ASN 和地理位置合理性 | broker/客户记录；proxyware 或受感染主机行为 | 不可能的旅行、proxy 协议以及按会话变化的地址 |
| Compromised server/router/IoT | 借用受害者的声誉和司法辖区 | implant、管理流量和反复出现的上游控制器 | 设备遥测和 ORB 拓扑，而不是单个出口 IP |
| CDN/redirector | 将公共边缘与后端 C2 分离 | TLS/HTTP 语法、证书、路由和 cloud 账户痕迹 | 边缘到源站的关联以及请求形态聚类 |
| Legitimate web service | 混入被允许的 GitHub/cloud/social 流量 | API token、租户/对象标识符和异常进程血缘 | 端点进程加 service/API 语义 |
| Physical/cellular/satellite path | 改变表面上的物理来源 | RF、运营商、订户、设备和位置记录 | 综合 radio/physical 与网络证据 |

## Operational relay box 网络

**ORB network** 是一种作为中间服务使用的托管 proxy fleet。Mandiant 将其分为由租用服务器组成的 provisioned networks、由受感染路由器/IoT 组成的 non-provisioned networks，以及混合网络。成熟的拓扑包含四种逻辑角色：<sup>[[2]](#references)</sup>

1. **Administration server (ACOS)：** 维护清单、凭据、健康状态和路由策略。
2. **Access/relay node：** 对客户或操作员进行身份验证；它是进入不断变化的 mesh 的稳定入口。
3. **Traversal nodes：** 一个或多个租用或受感染系统转发不透明连接。
4. **Exit/staging node：** 向侦察、利用或 C2 目标呈现最终源地址。

该 mesh 可以按国家、ASN、延迟或可用性选择出口，并轮换不健康的节点。多个威胁组织可能租用同一网络。Mandiant 观察到，某些 ORB 的 IPv4 地址与其关联的时间短至 31 天；因此，它建议将**网络视为不断演化的、类似行为者的实体**，而不是封锁一份过时的 IP 列表。<sup>[[2]](#references)</sup>

### 这能带来什么——又会泄露什么

- 目标看到的出口可能在地理位置上很近，并且表面上属于 residential 网络。
- 出口能看到目标和前一跳，但不一定能看到操作员。
- access service 能看到客户和路由请求。独立管理的 mesh 可以将客户与出口隔离，但也会产生强大的对手方记录。
- 即使 IP 不断轮换，重复的端口、握手顺序、服务器 banners、证书、运行时间窗口和控制器关系仍可能暴露整个 fleet。
- 受感染的路由器通常缺少端点遥测，但其 ISP 仍拥有订户和流量数据；一旦被扣押，就会暴露 implant/configuration 痕迹。

{% hint style="info" %}
对于经授权的演练，请使用组织自有的 VM 或路由器复现该拓扑，并保留控制器的归因映射。不要招募开放 proxy 或第三方设备。[lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) 会创建相同的、对防御者可见的跳转结构，同时不会使中间方成为受害者。
{% endhint %}

## Residential 和 mobile proxy 网络

Residential proxy 服务会将会话分配到消费者宽带地址；mobile proxy 则通过运营商 NAT 池出站。供应来源可能包括明确注册的设备、捆绑在消费者应用中的 SDK/proxyware、reseller 或 malware。这些来源并不等价：缺乏知情同意会使隐私服务变成 compromised infrastructure。

轮换模式会影响检测：

- **per-request rotation** 会在 IP、ASN 和地理位置之间产生快速不连续变化，而更高层的身份保持稳定；
- **sticky sessions** 会让一个出口保持数分钟或数小时，看起来像普通订户；
- **backconnect gateways** 向客户暴露一个 broker endpoint，并在内部选择出口；
- **mobile pools** 会让许多真实订户共享少量运营商 NAT 地址，因此封锁单个 IP 的代价很高。

防御者应将 IP 与 authenticated session、TLS/client fingerprint、HTTP 顺序、设备 cookie 和行为进行关联。一个 supposedly local 的 residential 登录随后变为另一个国家，而所有更高层特征保持相同，这比单独依赖 reputation 更有说服力。反过来，地址共享和 mobile handoff 也会造成合法的变化，因此绝不要将 residential/proxy 分类视为结论。

## Multi-hop proxy 链

MITRE 将 external proxies 与 **multi-hop proxies (T1090.003)** 区分开来。关键属性不是跳数，而是知识和管理权限的分离。<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
如果一方同时运营 A 和 B，共享日志或流量时序就可以重建该 circuit。从同一 endpoint/account 依次添加商业 VPN，可能会增加延迟，但仍会留下共同的身份、支付和时序证据。Tor 通过独立选择 relay 以及共享的 client 设计，降低了这一问题，但低延迟交互式网络无法向同时测量两端的观察者保证抵抗能力。

常见故障包括 DNS 或 IPv6 bypass、应用自行打开 socket、管理流量直接到达 relay、活动同步、重复使用 SSH keys，以及登录可识别身份的 accounts。正确的验证方式是进行 failure test：依次停止每个 relay，并证明 workload 无法回退到 clear path。

## Redirector 层级与流量整形

公共 **redirector** 接受符合特定 operation grammar 的流量，并将其转发到受保护的 team server。其他所有流量都可以被拒绝或提供无害内容。
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
多个层级可以限制暴露范围：烧掉一个 public domain 不必暴露 team server。CDN 提供 anycast 容量和一个信誉良好的外层 domain，但 CDN 账户和 edge 日志会成为 attribution points。TLS fingerprints、证书历史、独特的路径/header 顺序、响应大小、redirect 行为和 origin allowlists 可能将所谓无关的 fronts 聚类到一起。

在检测方面，应在 normalization 前记录 reverse-proxy 字段，比较 SNI/Host/authority，检查罕见的 header 组合，对响应正文和 TLS fingerprints 进行聚类，并在 cloud/CDN audit logs 中搜索配置重叠。对于经过授权的 red teams，应避免复制真实品牌，也不要将 credential collection 放在无关的第三方之后。

## Domain fronting and domainless fronting

在经典的 **domain fronting (T1090.004)** 中，TLS 连接在 SNI 中声明一个获准的 front domain，而加密的 HTTP `Host` 或 HTTP/2 `:authority` 请求另一个 back-end domain。协作的 CDN 根据内部值进行路由。无法解密 TLS 的网络观察者只能看到 front；CDN 则能看到两个值和 origin。在 domainless 变体中，SNI 可能为空，而另一个 routing 字段选择 destination。<sup>[[4]](#references)</sup>

这并不是神奇的 impersonation：只有当 intermediary 有意或意外允许这种不匹配，并且知道如何路由内部名称时，它才会生效。主要 providers 已限制跨账户 fronting。Encrypted ClientHello (ECH) 会改变链路上的观察者能够看到的内容，但不会消除 CDN、endpoint 或 application records。

检测点包括：

- endpoint process ancestry 以及该 application 不应访问的 destination；
- 在 TLS inspection 合法且可用的情况下，比较 SNI 与 HTTP authority 是否不匹配；
- CDN logs 显示某个 tenant/front 将流量路由到另一个 authority/origin；
- 对通常为交互式的 service 建立异常的长连接或周期性 session；
- 在不断变化的 front domains 之间，具有稳定加密流量大小和节奏的连接。

安全的 lab 应在自有的 reverse proxy 上模拟 routing mismatch，而不是滥用 public CDN。

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution 将逻辑 service 与固定 infrastructure 解耦：

- **DDNS：**经过认证的 client 在 address 变化后更新稳定名称。
- **DGA：**endpoint 和 controller 都根据时间/密钥 seed 推导候选 domain names；operator 只注册其中一小部分。
- **Fast flux：**一个名称返回一组快速变化的 compromised/proxy addresses，通常使用较低的 TTL。
- **Double flux：**service addresses 和 authoritative name-server addresses 都会轮换，从而进一步隐藏 control layer。

Fast flux 是一种被对手滥用的 load-distribution pattern，并不只是“许多 DNS answers”。更有力的证据应结合低 TTL、高 unique-address count、广泛的 ASN/地理分散度、较短的 node lifetime、重复的 application behavior 和可疑的 registration history。CDN 也会合法地具备其中若干属性。MITRE 建议将 DNS behavior 与 process 及后续 connections 进行关联。<sup>[[5]](#references)</sup>

可以通过 lexical entropy、辅音/数字模式、NXDOMAIN bursts、同步的 first-seen domains 和 process context 检测 DGA。Wordlist DGAs 和 generative models 会绕过简单的 entropy rules，因此 fleet-wide temporal clustering 和 endpoint lineage 更为重要。

## Compromised domains and domain shadowing

攻击者可能劫持 registrar/DNS account、接管 dangling subdomain，或在原本信誉良好的 domain 下添加 records。**Domain shadowing** 保留合法 apex，同时让大量 attacker-controlled subdomains 指向不断变化的 delivery 或 C2 hosts。它借用 domain 的 age 和 reputation，并可能绕过针对整个 domain 的 blocking。<sup>[[6]](#references)</sup>

防御者需要 registrar 和 authoritative-DNS audit logs、MFA、registry/registrar locks、针对新 delegations/API tokens/name servers 的 alerts、certificate-transparency monitoring，以及 DNS 所引用 cloud resources 的 inventory。应独立于 apex reputation 调查 subdomain 的 resolution 和 certificate history。

## Web services and dead-drop resolvers

**dead-drop resolver (T1102.001)** 会在合法的 post、profile、document、repository、cloud object 或 blockchain field 中存储指向当前 C2 的 encoded pointer。Malware 获取 public object，解码出 domain/IP，然后连接到 next stage。Bidirectional variants 会通过 service APIs 交换 commands 或 files。<sup>[[7]](#references)</sup>

这能提高 resilience，并将 back-end C2 隐藏在 static binary analysis 之外。但它也会产生稳定的 object、tenant、repository、API 和 access-pattern identifiers。防御者应关联：

1. 访问该 service 的 process；
2. 精确的 API path/object 和 response hash；
3. decoding 或 string-processing activity；
4. 随后不久发生的新 outbound connection；以及
5. fleet 中其他位置的相同行为。

阻止所有 GitHub、cloud storage 或 social media 通常不可行。Service-aware egress policy 和 process-level correlation 的效果优于仅基于 domain 的 blocking。

## Personas, accounts and procurement compartments

当 persona、recovery email、phone、payment、browser 或 admin IP 连接起不同 compartments 时，infrastructure anonymity 就会失效。与国家有关联的 operations 早在使用前很久就已培养 social profiles、email identities 和 cloud accounts；ATT&CK 将其记录为 Establish Accounts (T1585)，其中包括 social、email 和 cloud sub-techniques。<sup>[[8]](#references)</sup>

防御者或 investigator 会从以下信息构建 graph：

- creation 和 first-login time、locale、time zone 以及 working schedule；
- recovery fields、MFA devices、identity documents 和 payment instruments；
- browser/TLS fingerprints 和 source-network history；
- avatar reuse、image provenance、writing style 和 social-graph growth；
- 共享的 domain registrant、name server、certificate、analytics ID 或 repository commit；
- 绕过 public relay architecture 的 management-plane actions。

对于经过授权的 red team，synthetic personas 应向 exercise controller 备案，使用组织自有的 recovery/payment channels，避免冒充真实且无关的个人，并制定 retirement 计划。SOC 可以保持 blind；但 operation 不能变得不可问责。

## Emerging compound patterns to threat-model

以下是**由 defender 驱动的组合**，并非声称某个已命名的 actor 已部署了每一种精确设计。它们组合了已经观察到的 primitives，可作为 purple-team hypotheses。

### Asymmetric one-way tasking

Commands 通过 public、broadcast 或 append-only source 到达，而 results 在延迟后通过无关 channel 发出。该 primitive 的示例包括 web-service one-way communication 和 dead drops。分离两者可以避免单个 flow 呈现双向特征，并阻碍简单的 request/response correlation。<sup>[[9]](#references)</sup>

**Detection：**保留 object-level reads，然后在更宽的时间窗口内关联 process state changes 和之后的 outbound transfers。即使没有立即 reply，也要 hunting 读取同一 public object 的罕见 process。

### Multi-stage channel promotion

安静的 first stage 执行 inventory，并只将选定的 systems promote 到无关的 second-stage channel。second endpoint、protocol 和 process 可能与 first stage 不共享任何 infrastructure。这会限制 capable infrastructure 的暴露，并在 ATT&CK 中明确建模为 T1104。<sup>[[10]](#references)</sup>

**Detection：**关联 `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`；不要在 blocking first domain 后就结束 incident。

### Cross-protocol relay translation

不同 hops 会转换 HTTPS、QUIC、WebSocket、DNS、SSH 或 message-queue API，而不是透明转发 packets。转换会移除单一的端到端 protocol fingerprint，但会产生具有独特 timing、buffering 和 semantic conversion 特征的 gateways。Protocol tunneling (T1572) 可以与 proxies 和 service impersonation 结合。<sup>[[11]](#references)</sup>

**Detection：**寻找接收一种 protocol 并发起另一种 protocol、且 byte/time behavior 紧密耦合的 gateway hosts；比较 endpoint intent 与实际承载的 protocol。

### Passive activation on edge devices

implant 不进行 beaconing，而是监视已经到达 router/VPN 的 traffic，仅在 magic value、source-port pattern 或 authenticated token 出现时激活。正常 traffic 继续流向真实 service。ATT&CK 将其称为 Traffic Signaling (T1205)，并记录了 network-device 和 APT examples。<sup>[[12]](#references)</sup>

**Detection：**检查 firmware/file integrity，在 authorized hunt 期间执行 raw packet capture，检查意外的 socket filters 和差异化 service behavior。不存在 periodic beacon 并不能证明 edge device 是 clean 的。

### Serverless and ephemeral origin rotation

一个 front 保持稳定的逻辑 identity，而短生命周期的 functions/containers 在多个 regions/accounts 中处理各个 stages。这会减少 disk lifetime 和固定 origin IPs，但 control-plane creation、image/layer、role、secret、request ID 和 billing telemetry 会成为持久的 graph。

**Detection：**将 cloud audit 和 invocation logs 保存在 workload 之外；对 deployment templates、roles、environment keys 以及 front-to-origin relationships 进行 clustering。

### Privacy-layer diversity

一个 operation 可能会刻意避免使用单一的同质链路：例如，一个 channel 使用 leased relay，tasking 使用 public object，exit 来自自有 lab cellular link，而 administration 使用独立的 organization network。这会降低攻陷单一 provider 的价值，但增加跨层 timing 和 operational-error risk。

**Detection：**跨 identity、DNS、SaaS、network 和 cloud sensors 构建 campaign timelines。搜索同步的 state transitions，而不是相同的 indicators。

### Decentralized or transparency-log dead drops

攻击者可以在任何持久的 public append-only system、content-addressed store 或类似 transparency 的 feed 中放置小型 encrypted pointer。public object 具有 resilience，但其 exact index/content hash 和 client polling behavior 会成为稳定 identifiers。

**Detection：**记录完整的 API/object identifiers 和 response hashes；对 polling immutable objects、随后进行 decoding 或建立新 connections 的 nonstandard processes 发出 alerts。

### Delayed store-and-forward operations

Interactive C2 会产生明显的 timing correlation。Store-and-forward design 会批量处理 encrypted jobs，并在数分钟或数小时后通过不同的 queue 或 physical transfer 返回 results。它牺牲 responsiveness，以换取较弱的端到端 timing。

**Detection：**延长 correlation windows，建立 periodic queue access 模型，并检查 endpoint staging。Batching 会将 signal 从 packet timing 转移到 scheduled process/file behavior；它不会将 signal 消除。

## Design review: think in observers

对于每条 path，在 deployment 前和 collection 后填写此表：

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

如果某个普通 provider 可以填满每一列，那么该 architecture 只能向 target 提供 concealment，并不能提供 robust separation。如果没有任何 internal controller 能将 activity 映射回某项 engagement，那么它就不适合 professional red teaming。

## References

- [1] [MITRE ATT&CK — 获取基础设施 (T1583)、攻陷基础设施 (T1584) 和 Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — 中国关联的 espionage actors 使用 ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — 建立账户 (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
