# Offensive Infrastructure and Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

operator 很少能通过单个 proxy 获得有意义的匿名性。真正的行动会构建一张**分离图**：operator 连接到 access node，traversal nodes 将该节点隐藏在 exit 之前，redirectors 保护真正的 C2，而 disposable names 则指向 public edge。

使用 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) 查看每条路径经过标准化整理的优缺点、部署方式和检测视角。本页将进一步深入介绍对抗性基础设施的组合。
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
因此，目标看到的最后一个地址只能证明一条路径，而不能证明是谁在操控键盘。MITRE 将主要组件映射到 Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568) 和 Web Service (T1102)。<sup>[[1]](#references)</sup>

## Infrastructure 类别

| 类别 | Actor 使用它的原因 | 持久暴露面 | Defender 最佳切入点 |
|---|---|---|---|
| 租用的 VPS/cloud | 快速、可预测、可路由且易于重建 | tenant、计费、console、source-login 和 image 历史 | account/control-plane 事件和重复的 server fingerprint |
| Commercial VPN/Tor | 大型共享出口集合；无需管理 server | provider/guard 可见性和端到端 timing | destination 行为、endpoint 证据和 flow correlation |
| Residential/mobile proxy | Consumer ASN 和地理位置合理性 | broker/customer 记录；proxyware 或 infected-host 行为 | impossible travel、proxy protocols 和按 session 变化的 address churn |
| Compromised server/router/IoT | 借用 victim reputation 和管辖区 | implant、management flow 和重复出现的 upstream controller | device telemetry 和 ORB topology，而不是单个 exit IP |
| CDN/redirector | 将 public edge 与后端 C2 分离 | TLS/HTTP grammar、certificate、routing 和 cloud-account artifacts | edge-to-origin correlation 和 request-shape clustering |
| Legitimate web service | 融入允许的 GitHub/cloud/social traffic | API token、tenant/object identifiers 和异常的 process lineage | endpoint process 加 service/API semantics |
| Physical/cellular/satellite path | 改变表面上的物理来源 | RF、carrier、subscriber、device 和 location 记录 | 结合 radio/physical 与 network 证据 |

## Operational relay box networks

**ORB network** 是一种作为中间服务使用的 managed proxy fleet。Mandiant 将其分为由租用 server 组成的 provisioned networks、由 compromised routers/IoT 组成的 non-provisioned networks，以及 hybrid networks。成熟的 topology 具有四种逻辑角色：<sup>[[2]](#references)</sup>

1. **Administration server (ACOS)：**维护 inventory、credentials、health 和 routing policy。
2. **Access/relay node：**对 customers 或 operators 进行 authentication；它是通往不断变化 mesh 的稳定入口。
3. **Traversal nodes：**一个或多个租用或 compromised systems relay opaque connections。
4. **Exit/staging node：**向 reconnaissance、exploitation 或 C2 targets 呈现最终 source address。

该 mesh 可以根据 country、ASN、latency 或 availability 选择 exits，并轮换不健康的 nodes。多个 threat groups 可能租用同一个 network。Mandiant 观察到某些 ORB 的 IPv4 address 与其保持关联的时间短至 31 天；因此，它建议将 **network 视为一个不断演化、类似 actor 的实体**，而不是封禁一份过时的 IP 列表。<sup>[[2]](#references)</sup>

### 这能带来什么——又会泄露什么

- 目标看到的是一个可能在地理位置上很近、表面上属于 residential 的 exit。
- exit 能看到目标和前一跳，但不一定能看到 operator。
- access service 能看到 customer 和 route request。独立管理的 mesh 可能将 customer 与 exits 隔离，但这会产生一份强有力的 counterparty 记录。
- 即使 IP 在轮换，重复出现的 ports、handshake order、server banners、certificates、uptime windows 和 controller relationships 仍可能暴露整个 fleet。
- compromised router 通常缺少 endpoint telemetry，但其 ISP 仍拥有 subscriber 和 flow data；一旦被扣押，还会暴露 implant/configuration artifacts。

{% hint style="info" %}
对于经过授权的 exercise，应使用组织自有的 VMs 或 routers 复现该 topology，并保留 controller 的 attribution map。不要招募开放 proxies 或第三方 devices。[lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) 会创建相同的、对 defender 可见的 hop structure，而不会使中间方成为受害者。
{% endhint %}

## Residential 和 mobile proxy networks

Residential proxy services 将 sessions 分配给 consumer broadband addresses；mobile proxies 则通过 carrier NAT pools 出口。供应来源可能包括明确注册的 appliances、捆绑在 consumer applications 中的 SDK/proxyware、resellers 或 malware。这些来源并不等价：缺乏知情同意会使 privacy service 变成 compromised infrastructure。

Rotation modes 会影响 detection：

- **per-request rotation** 会在 IP、ASN 和 geography 之间产生快速 discontinuities，而 higher-layer identity 保持稳定；
- **sticky sessions** 会让一个 exit 保持数分钟或数小时，看起来像普通 subscriber；
- **backconnect gateways** 向 customer 暴露一个 broker endpoint，并在内部选择 exits；
- **mobile pools** 会让大量 genuine subscribers 位于少量 carrier NAT addresses 后方，因此封禁一个 IP 的代价很高。

Defenders 应将 IP 与 authenticated session、TLS/client fingerprint、HTTP ordering、device cookie 和 behavior 进行 correlation。一个 supposedly local 的 residential login 随后出现在另一个 country，而所有 higher-layer features 都保持不变，这比单独依赖 reputation 更有说服力。相反，address sharing 和 mobile handoff 会造成 legitimate churn，因此绝不能将 residential/proxy classification 视为结论。

### Proxyware control planes 和 reseller overlap

不要将 residential pool 建模为一份扁平的 exits 列表。对 IPIDEA ecosystem 的分析揭示了一个可复用的 **two-tier control plane**：embedded SDK 首先向 Tier One domain 报告 device/enrollment metadata，并接收 scheduling 以及 Tier Two `connect`/`proxy` IP:port pairs。该 node 会定期轮询 Tier Two connect port 获取 encoded task，向配对的 proxy port 开启第二条 connection，并将提供的 bytes relay 到 requested destination。名义上不同的 SDK 和 proxy brands 拥有独立的 discovery domains，但通过共同的 ownership 和 reseller relationships，最终汇聚到共享的 Tier Two infrastructure 和重叠的 exit pools。<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
这比封锁一个 residential IP 能产生更持久的 hunting pivots：<sup>[[13]](#references)</sup>

- 一个出乎意料的 utility、VPN、游戏或嵌入式设备进程发送稳定的设备 ID/客户密钥，并接收不断变化的服务器列表；
- endpoint 轮询一个位于异常端口上的 direct IP，随后立即连接同一地址上的另一个端口，然后打开一个新的目标 socket；
- 多个表面上不同的品牌共用 Tier Two 地址、协议语法、SDK 代码或出口节点重叠；
- 不同的应用联系不同的 Tier One 域名，却从同一个 Tier Two 地址池接收地址。

这种重叠也限制了 attribution：在某个 vendor 宣传的地址池中看到一个 IP，并不能证明在相关时间使用它的是哪个 reseller、客户或 threat actor。保留流量时间戳、进程溯源、Tier One 响应正文和 Tier Two 任务标识符。<sup>[[13]](#references)</sup> 在经过授权的演练中，只能使用组织自有的 endpoints 模拟这一层级；绝不要注册消费者设备或第三方 proxyware。

## 多跳代理链

MITRE 将外部代理与**多跳代理（T1090.003）**区分开来。重要的属性不是跳数，而是知识和管理权限的分离。<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
如果同一方同时运营 A 和 B，共享日志或流量时序就可能重建该 circuit。从同一 endpoint/account 依次叠加 commercial VPN，可能增加延迟，却仍会留下共同的身份、支付和时序证据。Tor 通过独立选择 relay 和共享 client design 减少了这一问题，但低延迟交互式网络无法向同时测量两端的 observer 保证抗追踪能力。

常见故障包括 DNS 或 IPv6 bypass、applications 自行打开 sockets、management traffic 直接到达 relays、活动同步、复用 SSH keys，以及登录可识别身份的 accounts。正确的验证方式是进行故障测试：依次停止每个 relay，并证明 workload 无法回退到明文路径。

### Tunnel collapse and upstream leakage

relay architecture 往往在发生故障时最容易被归因。Unit 42 记录了一条多层 espionage path，使用面向 victim 的 VPSs、relay VPSs、residential proxies、Tor 和其他 proxy services；当某个 tunnel 被遗漏或 collapse 时，隐藏的 upstream infrastructure 会直接连接到 relay 和面向 victim 的系统。该调查还利用 upstream infrastructure 上短暂暴露的 X.509 certificate 作为跨层 pivot。<sup>[[14]](#references)</sup>

保持 **data plane**（`victim <-> exit`）与 **control plane**（`operator/upstream -> relay administration`）分离。在每个自有 tier 保留 ingress 和 authentication logs、certificate histories 以及短暂的失败连接记录，而不仅仅是成功的 C2 sessions。仅在 relay outages 期间出现，或直接管理多个面向 victim 的 nodes 的 source，比普通 exit 更可能是 upstream candidate，但其 ASN/geolocation 仍只是 hypothesis，并不能证明 operator 的身份。

经授权的 lab 应让 workload fail closed。对于隔离在 Linux network namespace 中的 workload，第一条 route 必须使用 tunnel；移除 tunnel 后，request 和 route lookup 都必须失败，而不能选择 physical uplink：
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
在 DNS 和 IPv6 上重复测试，并在每个 relay 边界处进行测试。如果任何探针成功，在修复 policy routing 或防火墙之前，记录实际的接口/源地址；该观察结果就是调查人员能够看到的 attribution leak。

## Redirector 层级与流量整形

公共 **redirector** 接受符合特定于 operation 的 grammar 的流量，并将其转发到受保护的 team server。其他所有流量都可以被拒绝，或返回无害内容。
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
多层级架构可以限制暴露面：burn 一个 public domain 不必暴露 team server。CDN 增加 anycast capacity 和一个信誉良好的外层 domain，但 CDN account 和 edge logs 会成为归因点。TLS fingerprints、certificate histories、distinctive paths/header order、response sizes、redirect behavior 以及 origin allowlists，可能将原本看似无关的 fronts 聚类起来。

对于检测，应在 normalization 前记录 reverse-proxy fields，对比 SNI/Host/authority，检查罕见的 header 组合，对 response bodies 和 TLS fingerprints 进行聚类，并在 cloud/CDN audit logs 中搜索配置重叠。对于经过授权的 red teams，应避免复制真实品牌，或将 credential collection 放置在无关的第三方之后。

## Domain fronting and domainless fronting

在经典的 **domain fronting (T1090.004)** 中，TLS connection 在 SNI 中声明一个获准的 front domain，而加密的 HTTP `Host` 或 HTTP/2 `:authority` 请求另一个 back-end domain。协作的 CDN 根据内部值进行路由。没有 TLS decryption 的 network observer 只能看到 front；CDN 则能看到这两个值以及 origin。在 domainless 变体中，SNI 可能为空，而另一个 routing field 会选择 destination。<sup>[[4]](#references)</sup>

这并不是神奇的 impersonation：只有当 intermediary 有意或意外地允许这种不匹配，并且知道如何根据内部名称进行路由时，它才会生效。主要 provider 已限制 cross-account fronting。Encrypted ClientHello (ECH) 会改变 on-path observer 能看到的内容，但不会消除 CDN、endpoint 或 application records。

检测点包括：

- endpoint process ancestry，以及该 application 不应访问的 destination；
- 在 TLS inspection 合法且可用时，检查 SNI 与 HTTP authority 是否不匹配；
- CDN logs 显示一个 tenant/front 将流量路由到另一个 authority/origin；
- 与通常的 interactive service 建立异常的长连接或周期性 sessions；
- 在不断变化的 front domains 之间，存在稳定的 encrypted flow sizes 和 cadence。

安全的 lab 应在自有 reverse proxy 上模拟 routing mismatch；不要滥用 public CDN。

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution 将逻辑 service 与固定 infrastructure 解耦：

- **DDNS：**经过 authentication 的 client 会在其 address 变化后更新一个稳定名称。
- **DGA：**endpoint 和 controller 都根据 time/key seed 推导候选 domain names；operator 只注册其中一小部分。
- **Fast flux：**一个 name 返回一组快速变化的 compromised/proxy addresses，通常使用较低的 TTL。
- **Double flux：**service addresses 和 authoritative name-server addresses 都会轮换，从而也隐藏 control layer。

Fast flux 是一种被 adversary 利用的 load-distribution pattern，并不只是“许多 DNS answers”。更强的证据需要结合 low TTL、较高的 unique-address count、广泛的 ASN/geography dispersion、较短的 node lifetime、重复的 application behavior 以及可疑的 registration history。CDN 也会合法地具备其中若干特征。MITRE 建议将 DNS behavior 与 process 及后续 connections 关联起来。<sup>[[5]](#references)</sup>

DGA 可以通过 lexical entropy、consonant/digit patterns、NXDOMAIN bursts、同步的 first-seen domains 以及 process context 进行检测。Wordlist DGAs 和 generative models 会击败简单的 entropy rules，因此 fleet-wide temporal clustering 和 endpoint lineage 更为重要。

## Compromised domains and domain shadowing

攻击者可能劫持 registrar/DNS account、接管 dangling subdomain，或在一个原本信誉良好的 domain 下添加 records。**Domain shadowing** 保留合法的 apex，同时让大量 attacker-controlled subdomains 指向不断变化的 delivery 或 C2 hosts。它借用 domain 的 age 和 reputation，并可能规避以 domain-wide 为范围的 blocking。<sup>[[6]](#references)</sup>

Defenders 需要 registrar 和 authoritative-DNS audit logs、MFA、registry/registrar locks，以及针对新 delegations/API tokens/name servers 的 alerts；还需要进行 certificate-transparency monitoring，并盘点 DNS 所引用的 cloud resources。应独立于 apex reputation，调查 subdomain 的 resolution 和 certificate history。

## Web services and dead-drop resolvers

**dead-drop resolver (T1102.001)** 会在合法的 post、profile、document、repository、cloud object 或 blockchain field 中存储指向当前 C2 的 encoded pointer。Malware 获取 public object，解码出 domain/IP，然后连接到下一阶段。Bidirectional variants 会通过 service APIs 交换 commands 或 files。<sup>[[7]](#references)</sup>

这能提供 resilience，并隐藏 static binary analysis 中的 back-end C2。它也会创建稳定的 object、tenant、repository、API 和 access-pattern identifiers。Defenders 应关联：

1. 访问该 service 的 process；
2. 确切的 API path/object 和 response hash；
3. decoding 或 string-processing activity；
4. 随后不久出现的新 outbound connection；以及
5. fleet 中其他位置的相同行为。

完全封锁 GitHub、cloud storage 或 social media 通常不可行。Service-aware egress policy 和 process-level correlation 的效果优于仅基于 domain 的 blocking。

## Personas, accounts and procurement compartments

当 persona、recovery email、phone、payment、browser 或 admin IP 连接起不同 compartments 时，infrastructure anonymity 就会失效。State-linked operations 早在使用前很久就会培育 social profiles、email identities 和 cloud accounts；ATT&CK 将其记录为 Establish Accounts (T1585)，其中包括 social、email 和 cloud sub-techniques。<sup>[[8]](#references)</sup>

Defender 或 investigator 会从以下信息构建 graph：

- creation 和 first-login time、locale、time zone 以及 working schedule；
- recovery fields、MFA devices、identity documents 和 payment instruments；
- browser/TLS fingerprints 及 source-network history；
- avatar reuse、image provenance、writing style 以及 social-graph growth；
- 共享的 domain registrant、name server、certificate、analytics ID 或 repository commit；
- 绕过 public relay architecture 的 management-plane actions。

对于经过授权的 red team，synthetic personas 应向 exercise controller 备案，使用 organization-owned recovery/payment channels，避免冒充真实且无关的人员，并制定 retirement 计划。SOC 可能仍然无法看见活动，但 operation 不能因此变得无法问责。

## Emerging compound patterns to threat-model

以下是**由 defender 驱动的组合**，并不表示某个已命名 actor 已部署了每一种完全相同的 design。它们结合了已经观察到的 primitives，可作为 purple-team hypotheses。

### Asymmetric one-way tasking

Commands 通过 public、broadcast 或 append-only source 到达，而 results 在延迟后通过无关 channel 离开。该 primitive 的例子包括 web-service one-way communication 和 dead drops。分离两者可以防止单一 flow 呈现 bidirectional 特征，并妨碍简单的 request/response correlation。<sup>[[9]](#references)</sup>

**Detection：**保留 object-level reads，然后在更宽的时间窗口内关联 process state changes 和后续 outbound transfers。即使没有立即 reply，也要搜寻读取同一 public object 的罕见 process。

### Multi-stage channel promotion

一个安静的 first stage 执行 inventory，并仅将选定 systems 提升到无关的 second-stage channel。第二个 endpoint、protocol 和 process 可能与第一个完全不共享 infrastructure。这会限制高能力 infrastructure 的暴露，并被 ATT&CK 明确建模为 T1104。<sup>[[10]](#references)</sup>

**Detection：**关联 `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`；不要在封锁第一个 domain 后就关闭 incident。

### Cross-protocol relay translation

不同 hops 会对 HTTPS、QUIC、WebSocket、DNS、SSH 或 message-queue API 进行 translation，而不是透明地 forwarding packets。Translation 会移除单一的 end-to-end protocol fingerprint，但会创建具有独特 timing、buffering 和 semantic conversion 特征的 gateways。Protocol tunneling (T1572) 可以与 proxies 和 service impersonation 结合。<sup>[[11]](#references)</sup>

**Detection：**寻找接收一种 protocol 并发起另一种 protocol 的 gateway hosts，检查其 byte/time behavior 是否紧密耦合；将 endpoint intent 与实际承载的 protocol 进行比较。

### Passive activation on edge devices

implant 不进行 beaconing，而是监视已经到达 router/VPN 的 traffic，仅在 magic value、source-port pattern 或 authenticated token 出现时激活。正常 traffic 仍会继续到达真实 service。ATT&CK 将其称为 Traffic Signaling (T1205)，并记录了 network-device 和 APT examples。<sup>[[12]](#references)</sup>

**Detection：**检查 firmware/file integrity，在授权 hunt 期间执行 raw packet capture，寻找意外的 socket filters 和差异化 service behavior。不存在 periodic beacon 并不能证明 edge device 是干净的。

### Serverless and ephemeral origin rotation

一个 front 保持稳定的逻辑 identity，而短生命周期的 functions/containers 在多个 regions/accounts 中处理各个 stages。这会减少 disk lifetime 和固定 origin IPs，但 control-plane creation、image/layer、role、secret、request ID 和 billing telemetry 会成为持久的 graph。

**Detection：**将 cloud audit 和 invocation logs 保留在 workload 之外；对 deployment templates、roles、environment keys 以及 front-to-origin relationships 进行聚类。

### Privacy-layer diversity

一个 operation 可能会有意避免使用单一的同质化 chain：例如，一个 channel 使用 leased relay，tasking 使用 public object，exit 来自自有 lab cellular link，而 administration 使用独立的 organization network。这会降低攻陷单一 provider 的价值，但会增加跨层 timing 和 operational-error 风险。

**Detection：**在 identity、DNS、SaaS、network 和 cloud sensors 之间构建 campaign timelines。搜寻 synchronized state transitions，而不是相同的 indicators。

### Decentralized or transparency-log dead drops

攻击者可以在任何持久的 public append-only system、content-addressed store 或类似 transparency 的 feed 中放置一个小型 encrypted pointer。Public object 具有 resilience，但其确切的 index/content hash 以及 client polling behavior 会成为稳定 identifiers。

**Detection：**记录完整的 API/object identifiers 和 response hashes；对 polling immutable objects 的 nonstandard processes 发出 alerts，并检查其后是否出现 decoding 或新 connections。

### Delayed store-and-forward operations

Interactive C2 会产生明显的 timing correlation。Store-and-forward design 会批量处理 encrypted jobs，并在几分钟或几小时后通过不同的 queue 或 physical transfer 返回 results。它牺牲 responsiveness，以换取较弱的 end-to-end timing。

**Detection：**延长 correlation windows，建立 periodic queue access 模型，并检查 endpoint staging。Batching 会将 signal 从 packet timing 转移到 scheduled process/file behavior；但不会将其消除。

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

如果一个普通 provider 能填满每一列，那么该 architecture 只能向 target 提供 concealment，而不能提供 robust separation。如果没有任何 internal controller 能将 activity 映射回某次 engagement，那么它不适合 professional red teaming。

## References

- [1] [MITRE ATT&CK — 获取基础设施 (T1583)、攻陷基础设施 (T1584) 和 Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors 使用 ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Disrupting the World's Largest Residential Proxy Network](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: Uncovering Global Espionage](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
