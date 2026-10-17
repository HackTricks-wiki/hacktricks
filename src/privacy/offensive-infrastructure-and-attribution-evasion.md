# 攻击性基础设施与归因规避

{{#include ../banners/hacktricks-training.md}}

操作人员很少能仅靠一个 proxy 获得实质性的匿名性。真正的行动会构建一张**隔离图**：操作人员连接到一个接入节点，转发节点将该节点与出口隔开，redirector 保护真实的 C2，而一次性域名则指向公网边缘。

使用[匿名互联网访问技术目录](anonymous-internet-access-techniques.md)，查看每种路径的标准化优缺点、部署和检测方式。本页将深入探讨对抗性基础设施的组合方式。

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

目标最后看到的地址因此是路径的证据，而不是谁在操作键盘的证明。MITRE 将主要组成部分映射为 Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568) 和 Web Service (T1102)。<sup>[[1]](#references)</sup>

## 基础设施类别

| 类别 | 行为者使用它的原因 | 持久性暴露 | 防御者最好的关联线索 |
|---|---|---|---|
| 租用的 VPS/cloud | 快速、可预测、可路由且易于重建 | 租户、账单、控制台、源登录记录和镜像历史 | 账户/控制平面事件及重复出现的服务器指纹 |
| 商业 VPN/Tor | 大型共享出口集合；无需管理服务器 | 服务商/监控方可见性及端到端时序 | 目标行为、端点证据和流量关联 |
| 住宅/移动代理 | 消费者 ASN 和地理位置看似合理 | 经纪商/客户记录；代理软件或受感染主机行为 | 不可能的旅行、代理协议和按会话变化的地址 |
| 受感染的服务器/路由器/IoT | 借用受害者的信誉和司法管辖区 | 植入程序、管理流量和重复出现的上游控制器 | 设备遥测和 ORB 拓扑，而非单个出口 IP |
| CDN/redirector | 将公共边缘与后端 C2 分离 | TLS/HTTP 语法、证书、路由和云账户痕迹 | 边缘到源站的关联及请求形态聚类 |
| 合法 Web 服务 | 融入获准的 GitHub/cloud/社交流量 | API token、租户/对象标识符和异常进程来源链 | 端点进程与服务/API 语义 |
| 物理/蜂窝/卫星路径 | 改变表面上的物理来源 | RF、运营商、用户、设备和位置记录 | 结合无线电/物理证据与网络证据 |

## 运营中继盒网络

**ORB network** 是用作中间服务的托管代理集群。Mandiant 将其分为租用服务器组成的预置网络、受感染路由器/IoT 组成的非预置网络，以及混合网络。成熟的拓扑包含四种逻辑角色：<sup>[[2]](#references)</sup>

1. **管理服务器 (ACOS)：** 维护清单、凭据、健康状态和路由策略。
2. **接入/中继节点：** 对客户或操作员进行身份验证；它是进入不断变化的网状网络的稳定入口。
3. **遍历节点：** 一个或多个租用或受感染的系统中继不透明连接。
4. **出口/暂存节点：** 向侦察、利用或 C2 目标呈现最终源地址。

该网状网络可以按国家、ASN、延迟或可用性选择出口，并轮换不健康的节点。多个威胁组织可能租用同一网络。Mandiant 观察到，某些 ORB 关联的 IPv4 地址持续时间短至 31 天；因此，它建议将**网络视为不断演变的、类似行为者的实体**，而不是封锁过时的 IP 列表。<sup>[[2]](#references)</sup>

### 这种做法带来的好处，以及它的 leak

- 目标看到的出口可能在地理位置上较近，且看起来像住宅网络。
- 出口能看到目标和前一跳，但未必能看到操作员。
- 接入服务能看到客户和路由请求。独立管理的网状网络可以将客户与出口隔离，但也会留下有价值的第三方记录。
- 即使 IP 不断轮换，重复出现的端口、握手顺序、服务器横幅、证书、在线时段和控制器关系仍可能暴露整个集群。
- 受感染的路由器通常缺乏端点遥测，但其 ISP 仍保有用户和流量数据；设备被查扣后，则会暴露植入程序/配置痕迹。

{% hint style="info" %}
对于经授权的演练，可使用组织自有的 VM 或路由器复现该拓扑，并保留控制器的归属映射。不要招募开放代理或第三方设备。[实验指南](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)会创建相同的、对防御者可见的跳转结构，而不会让中间节点成为受害者。
{% endhint %}

## 住宅和移动代理网络

住宅代理服务将会话分配给消费者宽带地址；移动代理则通过运营商 NAT 地址池出网。其供给来源包括明确加入的设备、捆绑在消费者应用中的 SDK/代理软件、转售商或恶意软件。这些来源并不等同：缺乏知情同意会使隐私服务沦为受感染基础设施。

轮换模式会影响检测：

- **按请求轮换**会导致 IP 和 ASN/地理位置快速变化，而更高层的身份特征保持稳定；
- **粘性会话**会让出口保持数分钟或数小时，看起来像普通用户；
- **backconnect 网关**向客户暴露一个经纪商端点，并在内部选择出口；
- **移动池**会让许多真实用户共享少量运营商 NAT 地址，因此封锁 IP 的代价很高。

防御者应将 IP 与经过身份验证的会话、TLS/客户端指纹、HTTP 顺序、设备 cookie 和行为进行关联。若一个号称本地的住宅登录随后转到另一个国家，同时所有更高层特征都保持不变，那么这比单靠信誉判断更有力。反过来，地址共享和移动网络切换也会造成正常变化，因此切勿仅凭住宅/代理分类就下结论。

### 代理软件控制平面与转售商重叠

不要将住宅代理池视为一份扁平的出口列表。对 IPIDEA 生态系统的分析揭示了一个可复用的**两层控制平面**：嵌入式 SDK 首先向 Tier One 域名报告设备/注册元数据，并获取调度信息以及 Tier Two 的 `connect`/`proxy` IP:port 对。节点会定期轮询 Tier Two connect 端口以获取编码任务，随后与配对的 proxy 端口建立第二条连接，并将提供的字节中继到请求的目标。名义上不同的 SDK 和代理品牌虽然使用不同的发现域名，却通过共同所有权和转售关系汇聚到共享的 Tier Two 基础设施和重叠的出口池。<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

这会产生比住宅 IP 网段更持久的 hunting pivots：<sup>[[13]](#references)</sup>

- 一个异常的 utility、VPN、game 或 embedded-device 进程发送稳定的设备 ID/customer key，并接收不断变化的服务器列表；
- 端点先轮询一个使用非常规端口的直接 IP，随后立即连接同一地址上的另一个端口，然后才打开一个新的目标 socket；
- 多个表面上不同的品牌共用 Tier Two 地址、协议语法、SDK 代码或 exit-node 重叠；
- 联系不同 Tier One 域名的不同应用收到来自同一 Tier Two 池的地址。

这种重叠也限制了归因：在某个供应商公布的地址池中看到一个 IP，并不能证明相关时间内是哪个 reseller、客户或 threat actor 使用了它。保留流量时间戳、进程谱系、Tier One 响应正文和 Tier Two 任务标识符。<sup>[[13]](#references)</sup> 在经授权的演练中，只能使用组织自有端点模拟这一层级；切勿注册消费者设备或第三方 proxyware。

## Multi-hop proxy chains

MITRE 将外部代理与 **multi-hop proxies (T1090.003)** 区分开来。重要的不是跳数，而是知识和管理的分离。<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

如果同一方同时运营 A 和 B，共享日志或流量时序就可能还原出整个链路。在同一端点/账户上依次添加多个商业 VPN，可能只会增加延迟，却仍留下共同的身份、付款和时序证据。Tor 通过独立选择中继节点和共享客户端设计来降低这一问题，但低延迟交互式网络无法保证抵御同时监测通信两端的观察者。

常见故障包括 DNS 或 IPv6 绕过、应用自行创建套接字、管理流量直接连接中继、活动同步、重复使用 SSH 密钥，以及登录可识别身份的账户。正确的验证方式是进行故障测试：依次停止每个中继，并确认工作负载无法回退到明文路径。

### 隧道坍塌与上游泄漏

中继架构在发生故障时往往最容易被追溯。Unit 42 记录了一条多层间谍活动路径，其中使用了面向受害者的 VPS、中继 VPS、住宅代理、Tor 和其他代理服务；当隧道被遗漏或坍塌时，隐藏的上游基础设施会直接连接中继和面向受害者的系统。该调查还利用一张曾短暂暴露在上游基础设施上的 X.509 证书，作为跨层关联线索。<sup>[[14]](#references)</sup>

将**数据平面**（`victim <-> exit`）与**控制平面**（`operator/upstream -> relay administration`）分开。在每个自有层级保留入口和身份验证日志、证书历史记录以及短暂的失败连接记录，而不只是成功的 C2 会话。若某个来源仅在中继中断期间出现，或直接管理多个面向受害者的节点，那么它比普通出口节点更有可能是上游节点；但其 ASN/地理位置仍只是推测，并不能证明操作者的身份。

经授权的实验环境应确保工作负载在故障时默认关闭。对于隔离在 Linux 网络命名空间中的工作负载，首选路由必须通过隧道；移除隧道后，请求和路由查询都必须失败，而不能改用物理上行链路：

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

再次测试 DNS 和 IPv6，并在每个 relay 边界重复测试。如果任何探测成功，在修复 policy routing 或防火墙之前，记录实际的接口/源地址；这是调查人员会看到的 attribution leak。

## Redirector tiers and traffic shaping

公共 **redirector** 接受符合特定操作语法的流量，并将其转发到受保护的 team server。其他所有流量都可以被拒绝或返回无害内容。

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

多个层级可限制暴露：烧掉一个公开域名不一定会暴露 team server。CDN 提供 anycast 容量和信誉良好的外层域名，但 CDN 账户和边缘日志会成为归因线索。TLS 指纹、证书历史、独特路径/标头顺序、响应大小、重定向行为和源站允许列表，都可能将看似无关的前端关联起来。

为了检测，应在规范化之前记录反向代理字段，比较 SNI/Host/authority，检查罕见的标头组合，对响应正文和 TLS 指纹进行聚类，并在云端/CDN 审计日志中查找配置重叠。对于经授权的 red team，不要仿冒真实品牌，也不要将凭据收集放在无关的第三方服务之后。

## Domain fronting and domainless fronting

在经典的 **domain fronting (T1090.004)** 中，TLS 连接在 SNI 中声明一个获准的前端域名，而加密的 HTTP `Host` 或 HTTP/2 `:authority` 则请求另一个后端域名。配合的 CDN 会根据内层值进行路由。无法解密 TLS 的网络观察者只能看到前端；CDN 则能看到这两个值和源站。在无域名变体中，SNI 可能为空，而其他路由字段会选择目标。<sup>[[4]](#references)</sup>

这并非神奇的伪装：只有当中间方有意或无意地允许这种不匹配，并且知道如何路由内层名称时，它才会起作用。主要服务商已限制跨账户 fronting。Encrypted ClientHello (ECH) 会改变链路上的观察者能看到的内容，但不会抹去 CDN、端点或应用程序记录。

检测点包括：

- 端点进程的祖先进程，以及该应用程序不应访问的目标；
- 在合法且可用 TLS 检查的情况下，比较 SNI 与 HTTP authority 是否不匹配；
- CDN 日志显示某个租户/前端将流量路由到另一个 authority/源站；
- 通常用于交互的服务出现异常的长连接或周期性会话；
- 即使前端域名变化，加密流量的大小和频率仍保持稳定。

安全的实验环境应在自有反向代理上模拟路由不匹配，而不是滥用公共 CDN。

## Dynamic resolution: DDNS, DGA and fast flux

动态解析将逻辑服务与固定基础设施解耦：

- **DDNS：**经过身份验证的客户端在地址变化后更新稳定名称。
- **DGA：**端点和控制器都根据时间/密钥种子推导候选域名；操作人员只注册其中少量域名。
- **Fast flux：**一个名称会返回一组快速变化的受感染/代理地址，通常 TTL 较低。
- **Double flux：**服务地址和权威名称服务器地址都会轮换，控制层也因此被隐藏。

Fast flux 是一种被用于对抗性目的的负载分配模式，而不只是“有很多 DNS 应答”。更有力的证据包括低 TTL、大量唯一地址、ASN/地理位置分布广、节点存活时间短、重复的应用行为以及可疑的注册历史。CDN 也会合法地具备其中若干特征。MITRE 建议将 DNS 行为与进程及后续连接关联分析。<sup>[[5]](#references)</sup>

可以通过词汇熵、辅音/数字模式、NXDOMAIN 激增、首次出现域名的同步性以及进程上下文检测 DGA。基于词表的 DGA 和生成模型会绕过简单的熵规则，因此全车队的时间聚类和端点沿袭关系更加重要。

## Compromised domains and domain shadowing

攻击者可能劫持注册商/DNS 账户、接管悬空子域，或在原本信誉良好的域名下添加记录。**Domain shadowing** 保留合法的顶级域名，同时让大量由攻击者控制的子域指向不断变化的投递或 C2 主机。它借用域名的历史和信誉，也可能绕过针对整个域名的封锁。<sup>[[6]](#references)</sup>

防御者需要注册商和权威 DNS 审计日志、MFA、注册局/注册商锁定、针对新委派/API 令牌/名称服务器的告警、证书透明度监控，以及 DNS 所引用云资源的清单。应独立调查子域的解析和证书历史，而不能依赖顶级域名的信誉。

## Web services and dead-drop resolvers

**dead-drop resolver (T1102.001)** 会将经过编码的当前 C2 指针存放在合法的帖子、个人资料、文档、代码库、云对象或区块链字段中。恶意软件获取该公开对象，解码出域名/IP，然后连接到下一阶段。双向变体会通过服务 API 交换命令或文件。<sup>[[7]](#references)</sup>

一种特定于 GitHub 的 resolver 变体，仅在经过身份验证的代码库通信通道失效时使用 Issues Search API。客户端会搜索符合当前日期、代码库和 issue 类型的 issues，跟进每个 issue 的评论 URL，并提取 `<!--` 与 `-->` 标记之间的密文。按主机和日期派生的密钥解密后，`Owner`、`LicRepo` 和 `LicToken` 等字段会替换主要代码库的所有者、路径和令牌。这让操作人员可以轮换凭据和端点，而无需替换客户端；issue 评论充当 resolver，而代码库文件仍是 tasking 通道。<sup>[[15]](#references)</sup>

一种 Android 变体会在启动时从两个公开的 Telegram 页面中选取一个，并提取 APK 中嵌入标记的两次出现之间的密文。它会对该值进行 Base64URL 解码，并使用 AES-128-CBC 解密：`SHA-256(marker)` 的前 16 个字节是密钥，后 16 个字节是 IV。明文是实际的 C2 基础 URL，而非 Telegram 页面 URL。复现解析过程时，应保留页面内容和确切的标记；更改公开页面即可轮换端点，无需重建 APK。<sup>[[16]](#references)</sup>

这种方式具有韧性，并能从静态二进制分析中隐藏后端 C2。但它也会留下稳定的对象、租户、代码库、API 和访问模式标识符。防御者应关联：

1. 联系该服务的进程；
2. 确切的 API 路径/对象及响应哈希；
3. 解码或字符串处理活动；
4. 随后发起的新出站连接；以及
5. 车队其他系统中的相同行为。

封锁所有 GitHub、云存储或社交媒体通常不可行。了解服务的出口策略和进程级关联分析，比仅按域名封锁更有效。

## Personas, accounts and procurement compartments

如果 persona、恢复邮箱、电话、支付方式、浏览器或管理员 IP 跨越不同隔离区，基础设施匿名性就会失效。国家支持的行动在使用相关资源前很久，就会培育社交资料、电子邮件身份和云账户；ATT&CK 将此记录为 Establish Accounts (T1585)，包括社交、电子邮件和云相关子技术。<sup>[[8]](#references)</sup>

防御者或调查人员会根据以下信息构建关联图：

- 创建和首次登录时间、地区设置、时区及工作时间；
- 恢复信息、MFA 设备、身份证件和支付工具；
- 浏览器/TLS 指纹及源网络历史；
- 头像复用、图片来源、写作风格和社交关系增长；
- 共享的域名注册人、名称服务器、证书、分析 ID 或代码库提交；
- 绕过公共中继架构的管理平面操作。

对于经授权的 red team，合成人设应向演练控制方备案，使用组织自有的恢复/支付渠道，避免冒充无关的真实人员，并制定退役计划。SOC 可以继续处于盲测状态，但行动本身不能失去问责机制。

## Emerging compound patterns to threat-model

以下是**由防御者提出的组合模式**，并非声称某个具名攻击者已部署了每一种确切设计。它们组合了已观察到的原语，可作为 purple team 假设。

### Asymmetric one-way tasking

命令通过公共、广播或只追加数据源进入，而结果则延迟后通过无关通道发出。这类原语包括 Web 服务单向通信和 dead drop。通道分离可以避免单个流量呈现双向特征，并妨碍简单的请求/响应关联分析。<sup>[[9]](#references)</sup>

**检测：**保留对象级读取记录，然后在更长的时间窗口内关联进程状态变化和后续出站传输。即使没有立即回复，也要搜寻读取相同公共对象的罕见进程。

### Multi-stage channel promotion

安静的第一阶段先执行清点，只将选定系统提升到无关的第二阶段通道。第二阶段的端点、协议和进程可能与第一阶段没有任何基础设施关联。这样可以限制高能力基础设施的暴露；ATT&CK 明确将其建模为 T1104。<sup>[[10]](#references)</sup>

**检测：**关联 `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`；不要在封锁第一个域名后就结束事件调查。

### Cross-protocol relay translation

不同跳点会在 HTTPS、QUIC、WebSocket、DNS、SSH 或消息队列 API 之间进行转换，而非透明地转发数据包。转换会消除单一的端到端协议指纹，但会在网关留下独特的时序、缓冲和语义转换特征。Protocol tunneling (T1572) 可以与代理和服务仿冒结合使用。<sup>[[11]](#references)</sup>

**检测：**寻找接收一种协议、随后以另一种协议发起连接，且字节数/时间行为紧密相关的网关主机；比较端点意图与实际承载的协议。

### Passive activation on edge devices

植入程序不发送 beacon，而是监视已到达路由器/VPN 的流量，只在出现 magic value、源端口模式或经过身份验证的令牌时激活。正常流量会继续发送到真实服务。ATT&CK 将其称为 Traffic Signaling (T1205)，并记录了网络设备和 APT 相关示例。<sup>[[12]](#references)</sup>

**检测：**检查固件/文件完整性，在经授权的调查期间捕获原始数据包，查找异常 socket filter，并对比服务行为。没有周期性 beacon 并不能证明边缘设备没有问题。

### Serverless and ephemeral origin rotation

前端维持稳定的逻辑身份，同时由短生命周期函数/容器在多个区域/账户中处理单个阶段。这会缩短磁盘留存时间，减少固定源站 IP，但控制平面创建记录、镜像/层、角色、密钥、请求 ID 和计费遥测会成为持久关联图。

**检测：**在工作负载之外保留云端审计和调用日志；对部署模板、角色、环境密钥以及前端到源站的关系进行聚类。

### Privacy-layer diversity

行动可能会刻意避免使用单一、同质的链路：例如，一个通道使用租用的中继，tasking 使用公共对象，出口来自自有实验室蜂窝链路，管理则使用独立的组织网络。这样可以降低攻陷单一服务商的影响，但会增加跨层时序和操作失误风险。

**检测：**通过身份、DNS、SaaS、网络和云端传感器构建行动时间线。查找同步的状态转换，而非相同的指标。

### Decentralized or transparency-log dead drops

攻击者可以在任何持久的公共只追加系统、内容寻址存储或类似透明日志的 feed 中放置小型加密指针。公共对象具有韧性，但其确切索引/内容哈希和客户端轮询行为会成为稳定标识符。

**检测：**记录完整的 API/对象标识符和响应哈希；对轮询不可变对象、随后进行解码或发起新连接的非标准进程发出告警。

### Delayed store-and-forward operations

交互式 C2 会产生强烈的时序关联。store-and-forward 设计会批量处理加密任务，并在几分钟或几小时后通过不同的队列或物理传输返回结果。它牺牲响应速度，以降低端到端时序关联性。

**检测：**延长关联窗口，建模队列的周期性访问，并检查端点暂存行为。批处理会将信号从数据包时序转移到计划任务/文件行为上，但不会将其消除。

## Design review: think in observers

在部署之前和收集数据之后，为每条路径填写此表：

| 层 | 能看到来源？ | 能看到目的地？ | 能看到内容？ | 稳定标识符 | 保留/法律责任方 |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

如果某个普通服务商能填满所有列，那么该架构只能对目标隐藏信息，却无法实现稳健隔离。如果没有内部控制方能够将活动映射回某次演练，那么它就不适合专业 red teaming。

## References

- [1] [MITRE ATT&CK — 获取基础设施 (T1583)、攻陷基础设施 (T1584) 和代理 (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — 中国关联的间谍活动组织使用 ORB 网络](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — 多跳代理 (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — 攻陷基础设施：域名 (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service：Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — 建立账户 (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service：单向通信 (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — 多阶段通道 (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — 协议隧道 (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — 流量信令 (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — 瓦解全球最大的住宅代理网络](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — 影子行动：揭露全球间谍活动](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaign 瞄准伊拉克基础设施](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl：AI 构建了覆盖层，受害者丢失 PIN 码](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
