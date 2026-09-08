# Offensive Infrastructure and Attribution Evasion

操作人员很少能从单个 proxy 中获得有意义的匿名性。真正的 campaign 会构建一个**分离图**：操作人员连接到 access node，traversal nodes 将该节点与 exit 隔离，redirectors 保护真正的 C2，而 disposable names 则指向公共边缘。

请使用 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)，以标准化方式查看每条路径的优点、缺点、部署方式和检测方法。本页面将深入介绍对抗性基础设施的组合方式。
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
因此，目标最后看到的地址只能证明一条路径，而不能证明是谁控制了键盘。MITRE 将主要组件映射为 Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568) 和 Web Service (T1102)。<sup>[[1]](#references)</sup>

## Infrastructure classes

| Class | Why an actor uses it | Durable exposure | Defender's best pivot |
|---|---|---|---|
| 租用的 VPS/cloud | 快速、可预测、可路由且易于重建 | 租户、计费、控制台、源登录和镜像历史 | 账户/控制平面事件以及重复的服务器指纹 |
| Commercial VPN/Tor | 大型共享出口集合；无需管理服务器 | provider/guard 可见性以及端到端时序 | 目标行为、端点证据和流量关联 |
| Residential/mobile proxy | 消费者 ASN 和地理位置合理性 | broker/客户记录；proxyware 或受感染主机行为 | 不可能的旅行、proxy 协议以及按会话变化的地址 |
| Compromised server/router/IoT | 借用受害者的信誉和司法管辖区 | implant、管理流量以及重复出现的上游 controller | 设备遥测和 ORB 拓扑，而不是单个出口 IP |
| CDN/redirector | 将公共 edge 与后端 C2 分离 | TLS/HTTP 语法、证书、路由和 cloud 账户痕迹 | edge 到 origin 的关联以及请求形态聚类 |
| Legitimate web service | 融入允许的 GitHub/cloud/social 流量 | API token、租户/对象标识符以及异常进程谱系 | 端点进程加 service/API 语义 |
| Physical/cellular/satellite path | 改变表面上的物理来源 | RF、运营商、订户、设备和位置记录 | 结合 radio/physical 与网络证据 |

## Operational relay box networks

**ORB network** 是一种作为中间服务使用的受管 proxy fleet。Mandiant 将其分为由租用服务器组成的 provisioned networks、由受感染 router/IoT 组成的 non-provisioned networks，以及 hybrid networks。成熟的拓扑包含四种逻辑角色：<sup>[[2]](#references)</sup>

1. **Administration server (ACOS)：**维护 inventory、凭据、健康状态和路由策略。
2. **Access/relay node：**对客户或 operator 进行身份验证；它是进入不断变化的 mesh 的稳定入口。
3. **Traversal nodes：**一个或多个租用或受感染系统转发 opaque connections。
4. **Exit/staging node：**向 reconnaissance、exploitation 或 C2 目标呈现最终源地址。

该 mesh 可以按国家、ASN、延迟或可用性选择 exits，并轮换不健康的节点。多个 threat groups 可能租用同一个 network。Mandiant 观察到，某些 ORB 的 IPv4 地址与其关联的时间短至 31 天；因此，它建议将 **network 视为不断演化的、类似 actor 的实体**，而不是封锁一份过时的 IP 列表。<sup>[[2]](#references)</sup>

### What this buys—and what it leaks

- 目标看到的可能是地理位置接近且表面上属于 residential 的 exit。
- exit 能看到目标和前一跳，但不一定能看到 operator。
- access service 能看到客户和 route request。独立管理的 mesh 可能将客户与 exits 隔离，但会产生一份强大的 counterparty record。
- 即使 IP 不断轮换，重复出现的端口、handshake 顺序、server banners、证书、uptime 窗口和 controller 关系仍可能暴露整个 fleet。
- 受感染的 router 通常缺少 endpoint telemetry，但其 ISP 仍持有订户和流量数据；扣押设备后还可暴露 implant/configuration artifacts。

{% hint style="info" %}
对于经授权的演练，请使用组织自有的 VM 或 router 复现该拓扑，并保留 controller 的 attribution map。不要招募开放 proxy 或第三方设备。[lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) 会创建相同的、对 defender 可见的跳转结构，而不会使中间方成为受害者。
{% endhint %}

## Residential and mobile proxy networks

Residential proxy services 会将会话分配给 consumer broadband 地址；mobile proxies 则通过 carrier NAT pools 进行出口。供应来源可能包括明确注册的 appliances、捆绑在 consumer applications 中的 SDK/proxyware、resellers 或 malware。这些来源并不等价：缺乏知情同意会使 privacy service 变成 compromised infrastructure。

Rotation 模式会影响 detection：

- **per-request rotation** 会产生快速的 IP 以及 ASN/地理位置不连续，而更高层的 identity 保持稳定；
- **sticky sessions** 会让一个 exit 保持数分钟或数小时，看起来像普通 subscriber；
- **backconnect gateways** 向客户暴露一个 broker endpoint，并在内部选择 exits；
- **mobile pools** 会让许多真实 subscribers 共享少量 carrier NAT 地址，因此封禁 IP 的代价很高。

Defenders 应将 IP 与 authenticated session、TLS/client fingerprint、HTTP ordering、device cookie 和行为进行关联。一个看似本地的 residential login 随后出现在另一个国家，而所有更高层特征仍完全相同，这比单独依赖 reputation 更有说服力。相反，地址共享和 mobile handoff 会造成合法的 churn，因此绝不要将 residential/proxy classification 视为结论。

## Multi-hop proxy chains

MITRE 将 external proxies 与 **multi-hop proxies (T1090.003)** 区分开来。关键属性不在于 hop 数量，而在于 knowledge 和 administration 的分离。<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
如果同一方运营 A 和 B，共享日志或流量时序就可能重建该 circuit。从同一 endpoint/account 依次添加商业 VPN，可能增加延迟，却仍会留下共同的身份、支付和时序证据。Tor 通过独立选择 relay 和共享 client 设计降低了这一问题，但低延迟交互式网络无法向同时测量两端的观察者保证抗性。

常见故障包括 DNS 或 IPv6 bypass、应用自行打开 socket、管理流量直接到达 relay、活动同步、复用 SSH key，以及登录可识别身份的 account。正确的验证方式是进行故障测试：依次停止每个 relay，并证明 workload 无法回退到明文路径。

## Redirector tiers and traffic shaping

公共 **redirector** 接受符合特定 operation grammar 的流量，并将其转发到受保护的 team server。其他所有流量都可以被拒绝，或提供无害内容。
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
多个层级可以限制暴露范围：销毁一个 public domain 不必暴露 team server。CDN 提供 anycast 容量和一个信誉良好的外层域名，但 CDN 账户和 edge logs 会成为归因点。TLS fingerprints、证书历史、独特的路径/header 顺序、响应大小、重定向行为以及 origin allowlists，可能将表面上无关的 fronts 聚类起来。

为了检测，应在 normalization 之前记录 reverse-proxy 字段，比较 SNI/Host/authority，检查罕见的 header 组合，对响应正文和 TLS fingerprints 进行聚类，并在 cloud/CDN audit logs 中查找配置重叠。对于获得授权的 red teams，应避免复制真实品牌，也不要将 credential collection 放在无关的第三方之后。

## Domain fronting and domainless fronting

在经典的 **domain fronting (T1090.004)** 中，TLS 连接会在 SNI 中声明一个获准的 front domain，同时加密的 HTTP `Host` 或 HTTP/2 `:authority` 请求另一个 back-end domain。配合的 CDN 会根据内部值进行路由。没有 TLS decryption 的网络观察者只能看到 front；CDN 则可以看到这两个值以及 origin。在 domainless 变体中，SNI 可能为空，而另一个 routing 字段会选择目标。<sup>[[4]](#references)</sup>

这并不是神奇的 impersonation：只有当 intermediary 有意或无意地允许这种不匹配，并且知道如何根据内部名称进行路由时，它才会生效。主要 providers 已经限制了跨账户 fronting。Encrypted ClientHello (ECH) 会改变链路观察者能够看到的内容，但不会消除 CDN、endpoint 或 application records。

检测点包括：

- endpoint process ancestry，以及该 application 不应连接的 destination；
- 在 TLS inspection 合法且可用的情况下，比较 SNI 与 HTTP authority 是否不匹配；
- CDN logs 显示一个 tenant/front 正在将流量路由到另一个 authority/origin；
- 对于通常交互式的 service，存在异常的长连接或周期性 session；
- 在不断变化的 front domains 之间，存在稳定的加密流大小和通信节奏。

安全的 lab 会在自有的 reverse proxy 上模拟 routing mismatch，而不会滥用 public CDN。

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution 将逻辑 service 与固定 infrastructure 解耦：

- **DDNS：**经过认证的 client 会在 address 变化后更新一个稳定名称。
- **DGA：**endpoint 和 controller 都根据时间/密钥 seed 推导候选 domain names；operator 只注册其中一小部分。
- **Fast flux：**一个名称会返回一组快速变化的 compromised/proxy addresses，通常使用较低的 TTL。
- **Double flux：**service addresses 和 authoritative name-server addresses 都会轮换，从而进一步隐藏 control layer。

Fast flux 是一种被 adversary 利用的 load-distribution pattern，而不只是“许多 DNS answers”。更强的证据应结合低 TTL、高 unique-address count、广泛的 ASN/geography dispersion、较短的 node lifetime、重复的 application behavior 以及可疑的 registration history。CDN 合法地拥有其中若干特征。MITRE 建议将 DNS behavior 与 process 及后续 connections 关联起来。<sup>[[5]](#references)</sup>

可以通过 lexical entropy、辅音/数字模式、NXDOMAIN bursts、同步的 first-seen domains 以及 process context 检测 DGA。Wordlist DGAs 和 generative models 能够规避简单的 entropy rules，因此 fleet-wide temporal clustering 和 endpoint lineage 变得更加重要。

## Compromised domains and domain shadowing

攻击者可能劫持 registrar/DNS account、接管 dangling subdomain，或在一个原本信誉良好的 domain 下添加 records。**Domain shadowing** 保留合法的 apex，同时让大量 attacker-controlled subdomains 指向不断变化的 delivery 或 C2 hosts。它借用 domain 的 age 和 reputation，并可能规避针对整个 domain 的 blocking。<sup>[[6]](#references)</sup>

防御者需要 registrar 和 authoritative-DNS audit logs、MFA、registry/registrar locks，以及针对新 delegations/API tokens/name servers 的 alerts；还需要进行 certificate-transparency monitoring，并维护 DNS 所引用 cloud resources 的 inventory。应独立调查 subdomain 的 resolution 和 certificate history，而不能只依赖 apex 的 reputation。

## Web services and dead-drop resolvers

**dead-drop resolver (T1102.001)** 会将指向当前 C2 的 encoded pointer 存储在合法的 post、profile、document、repository、cloud object 或 blockchain field 中。Malware 获取 public object，解码 domain/IP，然后连接下一个 stage。Bidirectional variants 会通过 service APIs 交换 commands 或 files。<sup>[[7]](#references)</sup>

这种方式能够提高 resilience，并将 back-end C2 隐藏在 static binary analysis 之外。但它也会产生稳定的 object、tenant、repository、API 和 access-pattern identifiers。防御者应关联：

1. 联系该 service 的 process；
2. exact API path/object 和 response hash；
3. decoding 或 string-processing activity；
4. 随后不久出现的新 outbound connection；以及
5. fleet 中其他位置的相同行为。

阻止所有 GitHub、cloud storage 或 social media 通常不可行。Service-aware egress policy 和 process-level correlation 的效果优于仅基于 domain 的 blocking。

## Personas, accounts and procurement compartments

当 persona、recovery email、phone、payment、browser 或 admin IP 连接起不同 compartments 时，infrastructure anonymity 就会失效。与国家有关联的 operations 早在使用之前很久就会培养 social profiles、email identities 和 cloud accounts；ATT&CK 将其记录为 Establish Accounts (T1585)，其中包括 social、email 和 cloud sub-techniques。<sup>[[8]](#references)</sup>

防御者或 investigator 可以从以下信息构建 graph：

- creation 和 first-login time、locale、time zone 以及 working schedule；
- recovery fields、MFA devices、identity documents 和 payment instruments；
- browser/TLS fingerprints 以及 source-network history；
- avatar reuse、image provenance、writing style 和 social-graph growth；
- 共享的 domain registrant、name server、certificate、analytics ID 或 repository commit；
- 绕过 public relay architecture 的 management-plane actions。

对于获得授权的 red team，synthetic personas 应向 exercise controller 备案，使用组织自有的 recovery/payment channels，避免 impersonating 真实且无关的人员，并制定 retirement 计划。SOC 可能仍然无法发现活动，但 operation 不能因此变得无法追责。

## Emerging compound patterns to threat-model

以下是**由 defender 驱动的 compositions**，并不表示某个 named actor 已经部署了每一种确切设计。它们组合了已经观察到的 primitives，可作为 purple-team hypotheses。

### Asymmetric one-way tasking

Commands 通过 public、broadcast 或 append-only source 到达，而 results 在延迟后通过无关 channel 发出。该 primitive 的例子包括 web-service one-way communication 和 dead drops。这种分离可以避免单一 flow 呈现双向特征，并阻碍简单的 request/response correlation。<sup>[[9]](#references)</sup>

**Detection：**保留 object-level reads，然后在更宽的时间窗口内关联 process state changes 和后续 outbound transfers。即使没有立即 reply，也应搜索某个罕见 process 是否读取了同一个 public object。

### Multi-stage channel promotion

一个安静的 first stage 执行 inventory，并仅将选定的 systems 提升到无关的 second-stage channel。second endpoint、protocol 和 process 可能与 first stage 不共享任何 infrastructure。这可以限制 capable infrastructure 的暴露，并在 ATT&CK 中明确建模为 T1104。<sup>[[10]](#references)</sup>

**Detection：**关联 `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`；不要在阻止 first domain 后就结束 incident。

### Cross-protocol relay translation

不同 hops 会转换 HTTPS、QUIC、WebSocket、DNS、SSH 或 message-queue API，而不是透明地转发 packets。转换会移除单一的 end-to-end protocol fingerprint，但会产生具有独特 timing、buffering 和 semantic conversion 特征的 gateways。Protocol tunneling (T1572) 可以与 proxies 和 service impersonation 结合。<sup>[[11]](#references)</sup>

**Detection：**查找接收一种 protocol 并发起另一种 protocol、且 byte/time behavior 紧密关联的 gateway hosts；比较 endpoint intent 与实际承载的 protocol 是否一致。

### Passive activation on edge devices

implant 不进行 beaconing，而是监控已经到达 router/VPN 的 traffic，仅在出现 magic value、source-port pattern 或 authenticated token 时激活。正常 traffic 会继续发送到真实 service。ATT&CK 将其称为 Traffic Signaling (T1205)，并记录了 network-device 和 APT examples。<sup>[[12]](#references)</sup>

**Detection：**检查 firmware/file integrity，在授权 hunt 期间进行 raw packet capture，检查意外的 socket filters 和差异化 service behavior。不存在周期性 beacon 并不能证明 edge device 是干净的。

### Serverless and ephemeral origin rotation

一个 front 保持稳定的逻辑身份，同时由多个 regions/accounts 中的短生命周期 functions/containers 处理各个 stages。这会减少 disk lifetime 和固定 origin IPs，但 control-plane creation、image/layer、role、secret、request ID 以及 billing telemetry 会成为持久的 graph。

**Detection：**将 cloud audit 和 invocation logs 保留在 workload 之外；对 deployment templates、roles、environment keys 以及 front-to-origin relationships 进行聚类。

### Privacy-layer diversity

一个 operation 可能会有意避免使用单一的 homogeneous chain：例如，一个 channel 使用 leased relay，tasking 使用 public object，exit 来自自有 lab cellular link，而 administration 使用独立的 organization network。这会降低攻陷单一 provider 的价值，但会增加跨层 timing 和 operational-error risk。

**Detection：**在 identity、DNS、SaaS、network 和 cloud sensors 之间构建 campaign timelines。搜索同步的 state transitions，而不是相同的 indicators。

### Decentralized or transparency-log dead drops

攻击者可以在任何持久的 public append-only system、content-addressed store 或类似 transparency 的 feed 中放置一个小型 encrypted pointer。public object 具有 resilience，但其 exact index/content hash 以及 client polling behavior 会成为稳定 identifiers。

**Detection：**记录完整的 API/object identifiers 和 response hashes；对于 polling immutable objects、随后进行 decoding 或建立新 connections 的 nonstandard processes 发出 alerts。

### Delayed store-and-forward operations

Interactive C2 会产生明显的 timing correlation。Store-and-forward design 会批量处理 encrypted jobs，并在数分钟或数小时后通过不同的 queue 或 physical transfer 返回 results。它牺牲 responsiveness，以削弱 end-to-end timing。

**Detection：**延长 correlation windows，建立 periodic queue access 模型，并检查 endpoint staging。Batching 会将 signal 从 packet timing 转移到 scheduled process/file behavior；它并不会消除 signal。

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

如果某个普通 provider 能够填满所有列，那么该 architecture 只能对 target 提供 concealment，而不能提供稳健的 separation。如果没有任何 internal controller 能够将 activity 映射回某项 engagement，则它不适合 professional red teaming。

## References

- [1] [MITRE ATT&CK — 获取 Infrastructure（T1583）、Compromise Infrastructure（T1584）和 Proxy（T1090）](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors 使用 ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy（T1090.003）](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting（T1090.004）](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS（T1568.001）](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure：Domains（T1584.001）](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service：Dead Drop Resolver（T1102.001）](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts（T1585）](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service：One-Way Communication（T1102.003）](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels（T1104）](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling（T1572）](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling（T1205）](https://attack.mitre.org/techniques/T1205/)
